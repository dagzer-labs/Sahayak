use crate::{
    Database, JobLease, LeaseOutcome, OutboundQueueOutcome, PersistenceError, QueueOutboundMessage,
};
use sahayak_cryptography::{EncryptedValue, EncryptionPurpose};
use sahayak_domain::{
    AccountId, AuditEventId, AvailabilityConsumptionId, AvailabilityDuration, AvailabilityEpochId,
    AvailabilityEpochState, ChannelIdentityId, CorrelationId, InboundEventId, OutboundMessageId,
    OutboxJobId, ProfileRevisionId, PublicProfileId,
};
use serde_json::json;
use sqlx::{FromRow, PgConnection};
use std::str::FromStr;
use time::{Date, OffsetDateTime};
use uuid::Uuid;

pub const REMIND_AVAILABILITY_JOB: &str = "remind_professional_availability";
pub const ADVANCE_AVAILABILITY_JOB: &str = "advance_professional_availability";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailabilityIneligibility {
    ProfessionalRoleRequired,
    ApprovedProfileRequired,
    AccountUnavailable,
    InvalidTimeZone,
    MutationThrottled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvailabilityLocalExpiry {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvailabilityEpochSnapshot {
    pub id: AvailabilityEpochId,
    pub generation: i64,
    pub version: i64,
    pub state: AvailabilityEpochState,
    pub duration: AvailabilityDuration,
    pub expires_at: OffsetDateTime,
    pub expires_local: AvailabilityLocalExpiry,
    pub contact_count: i16,
    pub contact_limit: i16,
    pub successor_duration: Option<AvailabilityDuration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AvailabilityConversationSnapshot {
    Ineligible(AvailabilityIneligibility),
    Unavailable,
    Current(AvailabilityEpochSnapshot),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailabilityMutationOutcome {
    Applied(AvailabilityEpochSnapshot),
    AlreadyApplied(AvailabilityEpochSnapshot),
    Ineligible(AvailabilityIneligibility),
    Conflict,
    CapacityPaused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailabilityTimerPurpose {
    Reminder,
    Advance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvailabilityTimerContext {
    pub epoch_id: AvailabilityEpochId,
    pub generation: i64,
    pub account_id: AccountId,
    pub state: AvailabilityEpochState,
    pub expires_at: OffsetDateTime,
    pub expires_local: AvailabilityLocalExpiry,
    pub purpose: AvailabilityTimerPurpose,
}

#[derive(Clone)]
pub struct AvailabilityNotificationTarget {
    pub account_id: AccountId,
    pub channel_identity_id: ChannelIdentityId,
    pub provider_namespace: String,
    pub locale: String,
    pub encrypted_phone: EncryptedValue,
}

impl std::fmt::Debug for AvailabilityNotificationTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AvailabilityNotificationTarget")
            .field("account_id", &self.account_id)
            .field("channel_identity_id", &self.channel_identity_id)
            .field("provider_namespace", &self.provider_namespace)
            .field("locale", &self.locale)
            .field("encrypted_phone", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailabilityTimerOutcome {
    Applied,
    Stale,
    RetryAt(OffsetDateTime),
    LostLease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityConsumptionOutcome {
    Consumed {
        consumption_id: AvailabilityConsumptionId,
        count: i16,
        limit: i16,
        auto_paused: bool,
    },
    AlreadyConsumed,
    Denied,
}

#[derive(Clone, Copy, Debug)]
pub struct AvailabilityEffectContext<'a> {
    pub account_id: AccountId,
    pub channel_identity_id: ChannelIdentityId,
    pub inbound_event_id: InboundEventId,
    pub provider_namespace: &'a str,
    pub correlation_id: CorrelationId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailabilityTurnOperation {
    Start {
        epoch_id: AvailabilityEpochId,
        duration: AvailabilityDuration,
    },
    Resume {
        expected_generation: i64,
        expected_version: i64,
    },
    Stop {
        expected_generation: i64,
        expected_version: i64,
    },
    Renew {
        successor_epoch_id: AvailabilityEpochId,
        duration: AvailabilityDuration,
        expected_generation: i64,
        expected_version: i64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvailabilityTurnEffect {
    pub operation: AvailabilityTurnOperation,
}

#[derive(FromRow)]
struct EligibilityRow {
    account_status: String,
    risk_state: String,
    time_zone: String,
    has_professional_role: bool,
    channel_eligible: bool,
    profile_id: Option<Uuid>,
    published_revision_id: Option<Uuid>,
    profile_visibility: Option<String>,
    revision_state: Option<String>,
    publishable: bool,
    contact_limit: Option<i16>,
}

#[derive(FromRow)]
struct EpochRow {
    id: Uuid,
    generation: i64,
    version: i64,
    state: String,
    duration_code: String,
    expires_at: OffsetDateTime,
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
    contact_count: i16,
    contact_limit: i16,
    successor_duration: Option<String>,
}

#[derive(FromRow)]
struct WindowRow {
    database_now: OffsetDateTime,
    starts_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    local_end_date: Option<Date>,
    reminder_at: OffsetDateTime,
}

#[derive(FromRow)]
struct NotificationTargetRow {
    account_id: Uuid,
    channel_identity_id: Uuid,
    provider_namespace: String,
    locale: String,
    phone_e164_ciphertext: Vec<u8>,
    phone_e164_nonce: Vec<u8>,
    encryption_key_version: i16,
}

#[derive(FromRow)]
struct TimerContextRow {
    account_id: Uuid,
    state: String,
    expires_at: OffsetDateTime,
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
}

#[derive(Clone, Debug)]
pub struct AvailabilityRepository {
    database: Database,
}

impl AvailabilityRepository {
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    pub async fn load_conversation_snapshot(
        &self,
        account_id: AccountId,
        channel_identity_id: ChannelIdentityId,
        provider_namespace: &str,
    ) -> Result<AvailabilityConversationSnapshot, PersistenceError> {
        let eligibility = load_eligibility(
            self.database.pool(),
            account_id,
            channel_identity_id,
            provider_namespace,
        )
        .await?;
        if let Some(reason) = eligibility_reason(&eligibility) {
            return Ok(AvailabilityConversationSnapshot::Ineligible(reason));
        }
        let profile_id = PublicProfileId::from_uuid(eligibility.profile_id.ok_or_else(|| {
            PersistenceError::Invariant("eligible account has no profile".to_owned())
        })?);
        let snapshot = load_current_snapshot(self.database.pool(), profile_id).await?;
        Ok(match snapshot {
            Some(value)
                if matches!(
                    value.state,
                    AvailabilityEpochState::CancelledManual
                        | AvailabilityEpochState::CancelledIneligible
                ) =>
            {
                AvailabilityConversationSnapshot::Unavailable
            }
            Some(value) => AvailabilityConversationSnapshot::Current(value),
            None => AvailabilityConversationSnapshot::Unavailable,
        })
    }

    pub async fn timer_context(
        &self,
        epoch_id: AvailabilityEpochId,
        generation: i64,
        purpose: AvailabilityTimerPurpose,
    ) -> Result<Option<AvailabilityTimerContext>, PersistenceError> {
        let row = sqlx::query_as::<_, TimerContextRow>(
            r#"
            SELECT epoch.account_id, epoch.state, epoch.expires_at,
                   EXTRACT(YEAR FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS year,
                   EXTRACT(MONTH FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS month,
                   EXTRACT(DAY FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS day,
                   EXTRACT(HOUR FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS hour,
                   EXTRACT(MINUTE FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS minute
            FROM availability.epochs AS epoch
            WHERE epoch.id = $1 AND epoch.generation = $2
            "#,
        )
        .bind(epoch_id.into_uuid())
        .bind(generation)
        .fetch_optional(self.database.pool())
        .await?;
        row.map(|row| {
            Ok(AvailabilityTimerContext {
                epoch_id,
                generation,
                account_id: AccountId::from_uuid(row.account_id),
                state: AvailabilityEpochState::from_str(&row.state).map_err(|error| {
                    PersistenceError::Invariant(format!(
                        "availability timer state is invalid: {error}"
                    ))
                })?,
                expires_at: row.expires_at,
                expires_local: local_expiry(row.year, row.month, row.day, row.hour, row.minute)?,
                purpose,
            })
        })
        .transpose()
    }

    pub async fn notification_target(
        &self,
        epoch_id: AvailabilityEpochId,
    ) -> Result<Option<AvailabilityNotificationTarget>, PersistenceError> {
        let row = sqlx::query_as::<_, NotificationTargetRow>(
            r#"
            SELECT account.id AS account_id, channel.id AS channel_identity_id,
                   channel.provider_namespace, account.preferred_locale AS locale,
                   whatsapp.phone_e164_ciphertext, whatsapp.phone_e164_nonce,
                   whatsapp.encryption_key_version
            FROM availability.epochs AS epoch
            JOIN identity.accounts AS account ON account.id = epoch.account_id
            JOIN identity.channel_identities AS channel
              ON channel.account_id = account.id AND channel.provider_code = 'whatsapp'
             AND channel.status = 'active' AND channel.verified_at IS NOT NULL
            JOIN private_data.whatsapp_identities AS whatsapp
              ON whatsapp.channel_identity_id = channel.id
             AND whatsapp.opt_in_status <> 'opted_out'
             AND whatsapp.delivery_state <> 'unreachable'
             AND whatsapp.blocked_at IS NULL
            WHERE epoch.id = $1 AND account.status = 'active'
              AND account.risk_state = 'normal'
            ORDER BY channel.last_seen_at DESC, channel.id
            LIMIT 1
            "#,
        )
        .bind(epoch_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        row.map(|row| {
            let nonce = row.phone_e164_nonce.try_into().map_err(|_| {
                PersistenceError::Invariant(
                    "availability notification phone nonce has invalid length".to_owned(),
                )
            })?;
            Ok(AvailabilityNotificationTarget {
                account_id: AccountId::from_uuid(row.account_id),
                channel_identity_id: ChannelIdentityId::from_uuid(row.channel_identity_id),
                provider_namespace: row.provider_namespace,
                locale: row.locale,
                encrypted_phone: EncryptedValue {
                    purpose: EncryptionPurpose::Contact,
                    key_version: row.encryption_key_version,
                    nonce,
                    ciphertext: row.phone_e164_ciphertext,
                },
            })
        })
        .transpose()
    }

    pub async fn process_timer(
        &self,
        lease: JobLease,
        epoch_id: AvailabilityEpochId,
        generation: i64,
        purpose: AvailabilityTimerPurpose,
        correlation_id: CorrelationId,
        notification: Option<&QueueOutboundMessage>,
    ) -> Result<AvailabilityTimerOutcome, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query("SELECT set_config('sahayak.availability_mutation', 'on', true)")
            .execute(&mut *transaction)
            .await?;
        let owner: Option<Uuid> = sqlx::query_scalar(
            "SELECT account_id FROM availability.epochs WHERE id = $1 AND generation = $2",
        )
        .bind(epoch_id.into_uuid())
        .bind(generation)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(account_id) = owner {
            sqlx::query("SELECT id FROM identity.accounts WHERE id = $1 FOR UPDATE")
                .bind(account_id)
                .execute(&mut *transaction)
                .await?;
        }
        let locked: Option<(String, OffsetDateTime, Uuid)> = sqlx::query_as(
            "SELECT state, expires_at, account_id FROM availability.epochs WHERE id = $1 AND generation = $2 FOR UPDATE",
        )
        .bind(epoch_id.into_uuid())
        .bind(generation)
        .fetch_optional(&mut *transaction)
        .await?;
        if !lease_is_current(&mut transaction, lease, epoch_id, generation, purpose).await? {
            transaction.rollback().await?;
            return Ok(AvailabilityTimerOutcome::LostLease);
        }
        let Some((state, expires_at, account_id)) = locked else {
            complete_timer_job(&mut transaction, lease).await?;
            transaction.commit().await?;
            return Ok(AvailabilityTimerOutcome::Stale);
        };
        match purpose {
            AvailabilityTimerPurpose::Reminder => {
                let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
                    .fetch_one(&mut *transaction)
                    .await?;
                let has_successor: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM availability.epochs WHERE predecessor_epoch_id = $1 AND state = 'scheduled')",
                )
                .bind(epoch_id.into_uuid())
                .fetch_one(&mut *transaction)
                .await?;
                let effective: bool =
                    sqlx::query_scalar("SELECT availability.epoch_is_effective($1)")
                        .bind(epoch_id.into_uuid())
                        .fetch_one(&mut *transaction)
                        .await?;
                if state != "available"
                    || now >= expires_at
                    || has_successor
                    || !effective
                    || notification.is_none()
                {
                    complete_timer_job(&mut transaction, lease).await?;
                    transaction.commit().await?;
                    return Ok(AvailabilityTimerOutcome::Stale);
                }
                let throttled: bool = sqlx::query_scalar(
                    r#"
                    SELECT EXISTS (
                        SELECT 1 FROM availability.notification_events
                        WHERE account_id = $1 AND purpose = 'expiry_reminder'
                          AND occurred_at > clock_timestamp() - INTERVAL '4 hours'
                    ) OR (
                        SELECT count(*) FROM availability.notification_events
                        WHERE account_id = $1 AND purpose = 'expiry_reminder'
                          AND occurred_at > clock_timestamp() - INTERVAL '24 hours'
                    ) >= 2
                    "#,
                )
                .bind(account_id)
                .fetch_one(&mut *transaction)
                .await?;
                if throttled {
                    complete_timer_job(&mut transaction, lease).await?;
                    transaction.commit().await?;
                    return Ok(AvailabilityTimerOutcome::Stale);
                }
                let outbound = notification.ok_or_else(|| {
                    PersistenceError::Invariant("availability reminder is missing".to_owned())
                })?;
                validate_notification_target(&mut transaction, account_id, outbound).await?;
                let outbound_id = queue_availability_outbound(&mut transaction, outbound).await?;
                sqlx::query(
                    "INSERT INTO availability.notification_events (id, epoch_id, account_id, purpose, outbound_message_id) VALUES ($1, $2, $3, 'expiry_reminder', $4) ON CONFLICT (epoch_id, purpose) DO NOTHING",
                )
                .bind(Uuid::now_v7())
                .bind(epoch_id.into_uuid())
                .bind(account_id)
                .bind(outbound_id.into_uuid())
                .execute(&mut *transaction)
                .await?;
            }
            AvailabilityTimerPurpose::Advance => {
                let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
                    .fetch_one(&mut *transaction)
                    .await?;
                if now < expires_at {
                    reschedule_timer_job(&mut transaction, lease, expires_at).await?;
                    transaction.commit().await?;
                    return Ok(AvailabilityTimerOutcome::RetryAt(expires_at));
                }
                if !matches!(
                    state.as_str(),
                    "available" | "stopped" | "paused_contact_limit"
                ) {
                    complete_timer_job(&mut transaction, lease).await?;
                    transaction.commit().await?;
                    return Ok(AvailabilityTimerOutcome::Stale);
                }
                expire_and_activate_successor(
                    &mut transaction,
                    epoch_id,
                    account_id,
                    now,
                    notification,
                    correlation_id,
                )
                .await?;
                if state == "available"
                    && let Some(outbound) = notification
                {
                    validate_notification_target(&mut transaction, account_id, outbound).await?;
                    let outbound_id =
                        queue_availability_outbound(&mut transaction, outbound).await?;
                    sqlx::query(
                        "INSERT INTO availability.notification_events (id, epoch_id, account_id, purpose, outbound_message_id) VALUES ($1, $2, $3, 'expired', $4) ON CONFLICT (epoch_id, purpose) DO NOTHING",
                    )
                    .bind(Uuid::now_v7())
                    .bind(epoch_id.into_uuid())
                    .bind(account_id)
                    .bind(outbound_id.into_uuid())
                    .execute(&mut *transaction)
                    .await?;
                }
            }
        }
        complete_timer_job(&mut transaction, lease).await?;
        transaction.commit().await?;
        Ok(AvailabilityTimerOutcome::Applied)
    }

    pub async fn reconcile_missing_timers(&self, limit: u16) -> Result<u64, PersistenceError> {
        if !(1..=500).contains(&limit) {
            return Err(PersistenceError::InvalidCommand(
                "availability reconciliation limit must be between 1 and 500".to_owned(),
            ));
        }
        let result = sqlx::query(
            r#"
            INSERT INTO integration.outbox_jobs (
                id, availability_epoch_id, availability_generation, job_kind,
                idempotency_key, payload_version, payload, available_at,
                max_attempts, correlation_id, ordering_key
            )
            SELECT uuidv7(), epoch.id, epoch.generation,
                   'advance_professional_availability',
                   'availability-advance-repair:v1:' || epoch.id::text || ':g' ||
                       epoch.generation::text || ':' || uuidv4()::text,
                   1, jsonb_build_object('epoch_id', epoch.id::text, 'generation', epoch.generation),
                   clock_timestamp(), 8, epoch.correlation_id, NULL
            FROM availability.epochs AS epoch
            WHERE epoch.state IN ('available', 'stopped', 'paused_contact_limit')
              AND epoch.expires_at <= clock_timestamp()
              AND NOT EXISTS (
                  SELECT 1 FROM integration.outbox_jobs AS job
                  WHERE job.availability_epoch_id = epoch.id
                    AND job.availability_generation = epoch.generation
                    AND job.job_kind = 'advance_professional_availability'
                    AND job.state IN ('pending', 'leased')
              )
            ORDER BY epoch.expires_at, epoch.id
            LIMIT $1
            ON CONFLICT (job_kind, idempotency_key) DO NOTHING
            "#,
        )
        .bind(i64::from(limit))
        .execute(self.database.pool())
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn consume_capacity(
        &self,
        epoch_id: AvailabilityEpochId,
        operation_key: Uuid,
        category_code: &str,
        correlation_id: CorrelationId,
        pause_notification: Option<&QueueOutboundMessage>,
    ) -> Result<CapacityConsumptionOutcome, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let outcome = consume_capacity_in_transaction(
            &mut transaction,
            epoch_id,
            operation_key,
            category_code,
            correlation_id,
            pause_notification,
        )
        .await?;
        transaction.commit().await?;
        Ok(outcome)
    }
}

pub(crate) async fn consume_capacity_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    epoch_id: AvailabilityEpochId,
    operation_key: Uuid,
    category_code: &str,
    correlation_id: CorrelationId,
    pause_notification: Option<&QueueOutboundMessage>,
) -> Result<CapacityConsumptionOutcome, PersistenceError> {
    if category_code.is_empty()
        || category_code.len() > 32
        || !category_code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(PersistenceError::InvalidCommand(
            "availability capacity category is invalid".to_owned(),
        ));
    }
    sqlx::query("SELECT set_config('sahayak.availability_mutation', 'on', true)")
        .execute(&mut **transaction)
        .await?;
    if let Some(existing_category) = sqlx::query_scalar::<_, String>(
        "SELECT category_code FROM availability.capacity_consumptions WHERE epoch_id = $1 AND operation_key = $2",
    )
    .bind(epoch_id.into_uuid())
    .bind(operation_key)
    .fetch_optional(&mut **transaction)
    .await?
    {
        if existing_category == category_code {
            return Ok(CapacityConsumptionOutcome::AlreadyConsumed);
        }
        return Err(PersistenceError::InvalidCommand(
            "availability capacity operation key was reused for another category".to_owned(),
        ));
    }
    let source: Option<(Uuid, Uuid, Uuid, String, Option<Uuid>, OffsetDateTime)> = sqlx::query_as(
        "SELECT account_id, profile_id, profile_revision_id, state, predecessor_epoch_id, starts_at FROM availability.epochs WHERE id = $1",
    )
    .bind(epoch_id.into_uuid())
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((
        source_account_id,
        source_profile_id,
        source_revision_id,
        source_state,
        predecessor_id,
        _starts_at,
    )) = source
    else {
        return Ok(CapacityConsumptionOutcome::Denied);
    };
    sqlx::query("SELECT id FROM identity.accounts WHERE id = $1 FOR UPDATE")
        .bind(source_account_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT id FROM profile.public_profiles WHERE id = $1 FOR UPDATE")
        .bind(source_profile_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT id FROM profile.profile_revisions WHERE id = $1 FOR UPDATE")
        .bind(source_revision_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT code FROM profile.service_categories WHERE code = $1 FOR SHARE")
        .bind(category_code)
        .execute(&mut **transaction)
        .await?;
    if source_state == "scheduled" {
        let Some(predecessor_id) = predecessor_id else {
            return Err(PersistenceError::Invariant(
                "scheduled availability epoch has no predecessor".to_owned(),
            ));
        };
        let predecessor: Option<(Uuid, OffsetDateTime)> = sqlx::query_as(
            "SELECT account_id, expires_at FROM availability.epochs WHERE id = $1 FOR UPDATE",
        )
        .bind(predecessor_id)
        .fetch_optional(&mut **transaction)
        .await?;
        if let Some((owner_id, predecessor_expiry)) = predecessor {
            let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut **transaction)
                .await?;
            if now >= predecessor_expiry {
                expire_and_activate_successor(
                    transaction,
                    AvailabilityEpochId::from_uuid(predecessor_id),
                    owner_id,
                    now,
                    None,
                    correlation_id,
                )
                .await?;
            }
        }
    }
    if sqlx::query_scalar::<_, bool>(
        "SELECT true FROM availability.epochs WHERE id = $1 FOR UPDATE",
    )
    .bind(epoch_id.into_uuid())
    .fetch_optional(&mut **transaction)
    .await?
    .is_none()
    {
        return Ok(CapacityConsumptionOutcome::Denied);
    }
    if let Some(existing_category) = sqlx::query_scalar::<_, String>(
        "SELECT category_code FROM availability.capacity_consumptions WHERE epoch_id = $1 AND operation_key = $2",
    )
    .bind(epoch_id.into_uuid())
    .bind(operation_key)
    .fetch_optional(&mut **transaction)
    .await?
    {
        if existing_category == category_code {
            return Ok(CapacityConsumptionOutcome::AlreadyConsumed);
        }
        return Err(PersistenceError::InvalidCommand(
            "availability capacity operation key was reused for another category".to_owned(),
        ));
    }
    let row: Option<(Uuid, i16, i16)> = sqlx::query_as(
        r#"
        SELECT epoch.account_id, epoch.contact_count, epoch.contact_limit
        FROM availability.epochs AS epoch
        JOIN profile.professional_services AS service
          ON service.revision_id = epoch.profile_revision_id
         AND service.category_code = $2
        JOIN profile.service_categories AS category
          ON category.code = service.category_code AND category.state = 'active'
        WHERE epoch.id = $1 AND availability.epoch_is_effective(epoch.id)
        "#,
    )
    .bind(epoch_id.into_uuid())
    .bind(category_code)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((account_id, count, limit)) = row else {
        return Ok(CapacityConsumptionOutcome::Denied);
    };
    let next_count = count + 1;
    let auto_paused = next_count == limit;
    let audit_id = append_audit(
        transaction,
        None,
        None,
        "availability.capacity_consumed",
        epoch_id,
        if auto_paused {
            "contact_limit_reached"
        } else {
            "contact_consumed"
        },
        correlation_id,
        json!({"count": next_count, "limit": limit, "category_code": category_code}),
    )
    .await?;
    let consumption_id = AvailabilityConsumptionId::new();
    sqlx::query(
        "INSERT INTO availability.capacity_consumptions (id, epoch_id, operation_key, category_code, audit_event_id) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(consumption_id.into_uuid())
    .bind(epoch_id.into_uuid())
    .bind(operation_key)
    .bind(category_code)
    .bind(audit_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE availability.epochs SET contact_count = $2, state = CASE WHEN $3 THEN 'paused_contact_limit' ELSE state END, paused_at = CASE WHEN $3 THEN clock_timestamp() ELSE paused_at END WHERE id = $1",
    )
    .bind(epoch_id.into_uuid())
    .bind(next_count)
    .bind(auto_paused)
    .execute(&mut **transaction)
    .await?;
    if auto_paused {
        append_audit(
            transaction,
            None,
            None,
            "availability.auto_paused",
            epoch_id,
            "contact_limit_reached",
            correlation_id,
            json!({"count": next_count, "limit": limit, "category_code": category_code}),
        )
        .await?;
        let outbound = pause_notification.ok_or_else(|| {
            PersistenceError::InvalidCommand(
                "contact-limit pause requires an atomic professional notification".to_owned(),
            )
        })?;
        validate_notification_target(transaction, account_id, outbound).await?;
        let outbound_id = queue_availability_outbound(transaction, outbound).await?;
        sqlx::query(
            "INSERT INTO availability.notification_events (id, epoch_id, account_id, purpose, outbound_message_id) VALUES ($1, $2, $3, 'contact_limit_paused', $4) ON CONFLICT (epoch_id, purpose) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(epoch_id.into_uuid())
        .bind(account_id)
        .bind(outbound_id.into_uuid())
        .execute(&mut **transaction)
        .await?;
    }
    Ok(CapacityConsumptionOutcome::Consumed {
        consumption_id,
        count: next_count,
        limit,
        auto_paused,
    })
}

pub(crate) async fn reverse_capacity_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    consumption_id: AvailabilityConsumptionId,
    correlation_id: CorrelationId,
) -> Result<bool, PersistenceError> {
    sqlx::query("SELECT set_config('sahayak.availability_mutation', 'on', true)")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT set_config('sahayak.connection_mutation', 'on', true)")
        .execute(&mut **transaction)
        .await?;
    let source: Option<(Uuid, Uuid, Uuid, Uuid)> = sqlx::query_as(
        r#"
        SELECT consumption.epoch_id, epoch.account_id, epoch.profile_id, epoch.profile_revision_id
        FROM availability.capacity_consumptions AS consumption
        JOIN availability.epochs AS epoch ON epoch.id = consumption.epoch_id
        WHERE consumption.id = $1
        "#,
    )
    .bind(consumption_id.into_uuid())
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((epoch_id, account_id, profile_id, revision_id)) = source else {
        return Ok(false);
    };
    sqlx::query("SELECT id FROM identity.accounts WHERE id = $1 FOR UPDATE")
        .bind(account_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT id FROM profile.public_profiles WHERE id = $1 FOR UPDATE")
        .bind(profile_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT id FROM profile.profile_revisions WHERE id = $1 FOR UPDATE")
        .bind(revision_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT id FROM availability.epochs WHERE id = $1 FOR UPDATE")
        .bind(epoch_id)
        .execute(&mut **transaction)
        .await?;
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM availability.capacity_reversals WHERE consumption_id = $1)",
    )
    .bind(consumption_id.into_uuid())
    .fetch_one(&mut **transaction)
    .await?
    {
        return Ok(false);
    }
    let epoch = AvailabilityEpochId::from_uuid(epoch_id);
    let audit_id = append_audit(
        transaction,
        None,
        None,
        "availability.capacity_reversed",
        epoch,
        "internal_delivery_failure",
        correlation_id,
        json!({}),
    )
    .await?;
    sqlx::query(
        "INSERT INTO availability.capacity_reversals (id, consumption_id, audit_event_id) VALUES ($1, $2, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(consumption_id.into_uuid())
    .bind(audit_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        UPDATE availability.epochs
        SET contact_count = contact_count - 1,
            state = CASE WHEN state = 'paused_contact_limit' THEN 'stopped' ELSE state END,
            stopped_at = CASE WHEN state = 'paused_contact_limit' THEN clock_timestamp() ELSE stopped_at END,
            paused_at = CASE
                WHEN state = 'paused_contact_limit'
                THEN NULL ELSE paused_at END
        WHERE id = $1 AND contact_count > 0
        "#,
    )
    .bind(epoch_id)
    .execute(&mut **transaction)
    .await?;
    Ok(true)
}

pub(crate) async fn apply_availability_effect(
    connection: &mut PgConnection,
    context: AvailabilityEffectContext<'_>,
    effect: AvailabilityTurnEffect,
) -> Result<AvailabilityMutationOutcome, PersistenceError> {
    sqlx::query("SELECT set_config('sahayak.availability_mutation', 'on', true)")
        .execute(&mut *connection)
        .await?;
    lock_availability_aggregate(connection, context.account_id).await?;
    if let AvailabilityTurnOperation::Stop {
        expected_generation,
        expected_version,
    } = effect.operation
    {
        let profile_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM profile.public_profiles WHERE account_id = $1")
                .bind(context.account_id.into_uuid())
                .fetch_optional(&mut *connection)
                .await?;
        let Some(profile_id) = profile_id else {
            return Ok(AvailabilityMutationOutcome::Conflict);
        };
        return stop_epoch(
            connection,
            context,
            PublicProfileId::from_uuid(profile_id),
            expected_generation,
            expected_version,
        )
        .await;
    }
    let eligibility = load_eligibility(
        &mut *connection,
        context.account_id,
        context.channel_identity_id,
        context.provider_namespace,
    )
    .await?;
    if let Some(reason) = eligibility_reason(&eligibility) {
        return Ok(AvailabilityMutationOutcome::Ineligible(reason));
    }
    if mutation_throttled(connection, context.account_id, effect.operation).await? {
        return Ok(AvailabilityMutationOutcome::Ineligible(
            AvailabilityIneligibility::MutationThrottled,
        ));
    }
    let profile_id = PublicProfileId::from_uuid(eligibility.profile_id.ok_or_else(|| {
        PersistenceError::Invariant("eligible account has no published profile".to_owned())
    })?);
    let revision_id =
        ProfileRevisionId::from_uuid(eligibility.published_revision_id.ok_or_else(|| {
            PersistenceError::Invariant("eligible account has no published revision".to_owned())
        })?);
    materialize_due_epochs(connection, profile_id, revision_id, context.correlation_id).await?;
    match effect.operation {
        AvailabilityTurnOperation::Start { epoch_id, duration } => {
            start_epoch(
                connection,
                context,
                eligibility,
                profile_id,
                revision_id,
                epoch_id,
                duration,
            )
            .await
        }
        AvailabilityTurnOperation::Resume {
            expected_generation,
            expected_version,
        } => {
            resume_epoch(
                connection,
                context,
                profile_id,
                expected_generation,
                expected_version,
            )
            .await
        }
        AvailabilityTurnOperation::Stop { .. } => Err(PersistenceError::Invariant(
            "availability stop reached the eligibility branch".to_owned(),
        )),
        AvailabilityTurnOperation::Renew {
            successor_epoch_id,
            duration,
            expected_generation,
            expected_version,
        } => {
            schedule_successor(
                connection,
                context,
                eligibility,
                profile_id,
                revision_id,
                successor_epoch_id,
                duration,
                expected_generation,
                expected_version,
            )
            .await
        }
    }
}

pub(crate) async fn invalidate_account_epochs(
    connection: &mut PgConnection,
    account_id: AccountId,
    reason: &str,
    correlation_id: CorrelationId,
) -> Result<u64, PersistenceError> {
    invalidate_epochs(
        connection,
        "account_id",
        account_id.into_uuid(),
        reason,
        correlation_id,
    )
    .await
}

pub(crate) async fn invalidate_profile_epochs(
    connection: &mut PgConnection,
    profile_id: PublicProfileId,
    reason: &str,
    correlation_id: CorrelationId,
) -> Result<u64, PersistenceError> {
    invalidate_epochs(
        connection,
        "profile_id",
        profile_id.into_uuid(),
        reason,
        correlation_id,
    )
    .await
}

async fn invalidate_epochs(
    connection: &mut PgConnection,
    column: &'static str,
    target_id: Uuid,
    reason: &str,
    correlation_id: CorrelationId,
) -> Result<u64, PersistenceError> {
    if !matches!(
        reason,
        "account_suspended"
            | "account_deletion"
            | "role_revoked"
            | "profile_hidden"
            | "published_revision_changed"
            | "consent_revoked"
    ) {
        return Err(PersistenceError::InvalidCommand(
            "availability invalidation reason is unsupported".to_owned(),
        ));
    }
    sqlx::query("SELECT set_config('sahayak.availability_mutation', 'on', true)")
        .execute(&mut *connection)
        .await?;
    let query = match column {
        "account_id" => {
            "UPDATE availability.epochs SET state = 'cancelled_ineligible', terminal_at = clock_timestamp(), terminal_reason = $2 WHERE account_id = $1 AND state IN ('scheduled', 'available', 'stopped', 'paused_contact_limit') RETURNING id, account_id"
        }
        "profile_id" => {
            "UPDATE availability.epochs SET state = 'cancelled_ineligible', terminal_at = clock_timestamp(), terminal_reason = $2 WHERE profile_id = $1 AND state IN ('scheduled', 'available', 'stopped', 'paused_contact_limit') RETURNING id, account_id"
        }
        _ => {
            return Err(PersistenceError::Invariant(
                "availability invalidation column is unsupported".to_owned(),
            ));
        }
    };
    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(query)
        .bind(target_id)
        .bind(reason)
        .fetch_all(&mut *connection)
        .await?;
    for (epoch_id, owner_id) in &rows {
        let epoch = AvailabilityEpochId::from_uuid(*epoch_id);
        let audit_id = append_audit(
            connection,
            None,
            None,
            "availability.invalidated",
            epoch,
            reason,
            correlation_id,
            json!({}),
        )
        .await?;
        sqlx::query(
            "INSERT INTO availability.mutation_events (id, epoch_id, account_id, action, audit_event_id, correlation_id) VALUES ($1, $2, $3, 'invalidated', $4, $5)",
        )
        .bind(Uuid::now_v7())
        .bind(epoch_id)
        .bind(owner_id)
        .bind(audit_id.into_uuid())
        .bind(correlation_id.into_uuid())
        .execute(&mut *connection)
        .await?;
    }
    Ok(rows.len() as u64)
}

async fn start_epoch(
    connection: &mut PgConnection,
    context: AvailabilityEffectContext<'_>,
    eligibility: EligibilityRow,
    profile_id: PublicProfileId,
    revision_id: ProfileRevisionId,
    epoch_id: AvailabilityEpochId,
    duration: AvailabilityDuration,
) -> Result<AvailabilityMutationOutcome, PersistenceError> {
    if let Some(current) = load_current_snapshot(&mut *connection, profile_id).await? {
        match current.state {
            AvailabilityEpochState::PausedContactLimit => {
                return Ok(AvailabilityMutationOutcome::CapacityPaused);
            }
            AvailabilityEpochState::Available | AvailabilityEpochState::Stopped => {
                return Ok(AvailabilityMutationOutcome::Conflict);
            }
            AvailabilityEpochState::Scheduled
            | AvailabilityEpochState::Expired
            | AvailabilityEpochState::CancelledManual
            | AvailabilityEpochState::CancelledIneligible => {}
        }
    }
    let generation: i64 = sqlx::query_scalar(
        "SELECT COALESCE(max(generation), 0) + 1 FROM availability.epochs WHERE profile_id = $1",
    )
    .bind(profile_id.into_uuid())
    .fetch_one(&mut *connection)
    .await?;
    let window = calculate_window(connection, duration, &eligibility.time_zone, None).await?;
    let contact_limit = eligibility.contact_limit.ok_or_else(|| {
        PersistenceError::Invariant("published revision has no contact limit".to_owned())
    })?;
    sqlx::query(
        r#"
        INSERT INTO availability.epochs (
            id, account_id, profile_id, profile_revision_id,
            started_by_channel_identity_id, started_from_inbound_event_id,
            generation, state, duration_code, time_zone_snapshot, local_end_date,
            starts_at, last_confirmed_at, expires_at, contact_limit, correlation_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'available', $8, $9, $10,
                $11, $12, $13, $14, $15)
        "#,
    )
    .bind(epoch_id.into_uuid())
    .bind(context.account_id.into_uuid())
    .bind(profile_id.into_uuid())
    .bind(revision_id.into_uuid())
    .bind(context.channel_identity_id.into_uuid())
    .bind(context.inbound_event_id.into_uuid())
    .bind(generation)
    .bind(duration.as_str())
    .bind(&eligibility.time_zone)
    .bind(window.local_end_date)
    .bind(window.starts_at)
    .bind(window.database_now)
    .bind(window.expires_at)
    .bind(contact_limit)
    .bind(context.correlation_id.into_uuid())
    .execute(&mut *connection)
    .await?;
    record_mutation(
        connection,
        context,
        epoch_id,
        "started",
        Some(duration),
        json!({"generation": generation, "contact_limit": contact_limit}),
    )
    .await?;
    schedule_timer_jobs(
        connection,
        epoch_id,
        generation,
        window,
        context.correlation_id,
    )
    .await?;
    load_epoch_snapshot(connection, epoch_id)
        .await?
        .map(AvailabilityMutationOutcome::Applied)
        .ok_or_else(|| {
            PersistenceError::Invariant("started availability epoch is missing".to_owned())
        })
}

async fn resume_epoch(
    connection: &mut PgConnection,
    context: AvailabilityEffectContext<'_>,
    profile_id: PublicProfileId,
    expected_generation: i64,
    expected_version: i64,
) -> Result<AvailabilityMutationOutcome, PersistenceError> {
    let id: Option<Uuid> = sqlx::query_scalar(
        r#"
        UPDATE availability.epochs
        SET state = 'available', stopped_at = NULL, last_confirmed_at = clock_timestamp()
        WHERE profile_id = $1 AND generation = $2 AND version = $3
          AND state = 'stopped' AND contact_count < contact_limit
          AND clock_timestamp() < expires_at
        RETURNING id
        "#,
    )
    .bind(profile_id.into_uuid())
    .bind(expected_generation)
    .bind(expected_version)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(id) = id else {
        return Ok(AvailabilityMutationOutcome::Conflict);
    };
    let epoch_id = AvailabilityEpochId::from_uuid(id);
    record_mutation(connection, context, epoch_id, "resumed", None, json!({})).await?;
    load_epoch_snapshot(connection, epoch_id)
        .await?
        .map(AvailabilityMutationOutcome::Applied)
        .ok_or_else(|| {
            PersistenceError::Invariant("resumed availability epoch is missing".to_owned())
        })
}

async fn stop_epoch(
    connection: &mut PgConnection,
    context: AvailabilityEffectContext<'_>,
    profile_id: PublicProfileId,
    expected_generation: i64,
    expected_version: i64,
) -> Result<AvailabilityMutationOutcome, PersistenceError> {
    let id: Option<Uuid> = sqlx::query_scalar(
        r#"
        UPDATE availability.epochs
        SET state = 'stopped', stopped_at = clock_timestamp()
        WHERE profile_id = $1 AND generation = $2 AND version = $3
          AND state = 'available' AND clock_timestamp() < expires_at
        RETURNING id
        "#,
    )
    .bind(profile_id.into_uuid())
    .bind(expected_generation)
    .bind(expected_version)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(id) = id else {
        return Ok(AvailabilityMutationOutcome::Conflict);
    };
    let epoch_id = AvailabilityEpochId::from_uuid(id);
    let cancelled_successor: Option<Uuid> = sqlx::query_scalar(
        "UPDATE availability.epochs SET state = 'cancelled_manual', terminal_at = clock_timestamp(), terminal_reason = 'renewal_cancelled_by_stop' WHERE predecessor_epoch_id = $1 AND state = 'scheduled' RETURNING id",
    )
    .bind(id)
    .fetch_optional(&mut *connection)
    .await?;
    if let Some(successor_id) = cancelled_successor {
        append_audit(
            connection,
            Some(context.account_id),
            Some(context.channel_identity_id),
            "availability.successor_cancelled",
            AvailabilityEpochId::from_uuid(successor_id),
            "professional_stopped_current_period",
            context.correlation_id,
            json!({}),
        )
        .await?;
    }
    record_mutation(connection, context, epoch_id, "stopped", None, json!({})).await?;
    load_epoch_snapshot(connection, epoch_id)
        .await?
        .map(AvailabilityMutationOutcome::Applied)
        .ok_or_else(|| {
            PersistenceError::Invariant("stopped availability epoch is missing".to_owned())
        })
}

#[allow(clippy::too_many_arguments)]
async fn schedule_successor(
    connection: &mut PgConnection,
    context: AvailabilityEffectContext<'_>,
    eligibility: EligibilityRow,
    profile_id: PublicProfileId,
    revision_id: ProfileRevisionId,
    successor_epoch_id: AvailabilityEpochId,
    duration: AvailabilityDuration,
    expected_generation: i64,
    expected_version: i64,
) -> Result<AvailabilityMutationOutcome, PersistenceError> {
    let current: Option<(Uuid, OffsetDateTime, i16)> = sqlx::query_as(
        r#"
        SELECT id, expires_at, contact_limit
        FROM availability.epochs
        WHERE profile_id = $1 AND generation = $2 AND version = $3
          AND state IN ('available', 'stopped', 'paused_contact_limit')
          AND clock_timestamp() < expires_at
        FOR UPDATE
        "#,
    )
    .bind(profile_id.into_uuid())
    .bind(expected_generation)
    .bind(expected_version)
    .fetch_optional(&mut *connection)
    .await?;
    let Some((current_id, current_expiry, contact_limit)) = current else {
        return Ok(AvailabilityMutationOutcome::Conflict);
    };
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM availability.epochs WHERE predecessor_epoch_id = $1 AND state = 'scheduled')",
    )
    .bind(current_id)
    .fetch_one(&mut *connection)
    .await?
    {
        return Ok(AvailabilityMutationOutcome::Conflict);
    }
    let generation: i64 = sqlx::query_scalar(
        "SELECT COALESCE(max(generation), 0) + 1 FROM availability.epochs WHERE profile_id = $1",
    )
    .bind(profile_id.into_uuid())
    .fetch_one(&mut *connection)
    .await?;
    let window = calculate_window(
        connection,
        duration,
        &eligibility.time_zone,
        Some(current_expiry),
    )
    .await?;
    sqlx::query(
        r#"
        INSERT INTO availability.epochs (
            id, account_id, profile_id, profile_revision_id,
            started_by_channel_identity_id, started_from_inbound_event_id,
            predecessor_epoch_id, generation, state, duration_code,
            time_zone_snapshot, local_end_date, starts_at, last_confirmed_at,
            expires_at, contact_limit, correlation_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'scheduled', $9,
                $10, $11, $12, $13, $14, $15, $16)
        "#,
    )
    .bind(successor_epoch_id.into_uuid())
    .bind(context.account_id.into_uuid())
    .bind(profile_id.into_uuid())
    .bind(revision_id.into_uuid())
    .bind(context.channel_identity_id.into_uuid())
    .bind(context.inbound_event_id.into_uuid())
    .bind(current_id)
    .bind(generation)
    .bind(duration.as_str())
    .bind(&eligibility.time_zone)
    .bind(window.local_end_date)
    .bind(window.starts_at)
    .bind(window.database_now)
    .bind(window.expires_at)
    .bind(contact_limit)
    .bind(context.correlation_id.into_uuid())
    .execute(&mut *connection)
    .await?;
    sqlx::query("UPDATE availability.epochs SET updated_at = clock_timestamp() WHERE id = $1")
        .bind(current_id)
        .execute(&mut *connection)
        .await?;
    record_mutation(
        connection,
        context,
        AvailabilityEpochId::from_uuid(current_id),
        "successor_scheduled",
        Some(duration),
        json!({"successor_generation": generation}),
    )
    .await?;
    schedule_timer_jobs(
        connection,
        successor_epoch_id,
        generation,
        window,
        context.correlation_id,
    )
    .await?;
    load_epoch_snapshot(connection, AvailabilityEpochId::from_uuid(current_id))
        .await?
        .map(AvailabilityMutationOutcome::Applied)
        .ok_or_else(|| {
            PersistenceError::Invariant("renewed availability epoch is missing".to_owned())
        })
}

async fn load_eligibility<'e, E>(
    executor: E,
    account_id: AccountId,
    channel_identity_id: ChannelIdentityId,
    provider_namespace: &str,
) -> Result<EligibilityRow, PersistenceError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let query: &'static str = r#"
        SELECT account.status AS account_status, account.risk_state, account.time_zone,
               EXISTS (
                   SELECT 1 FROM identity.account_roles AS role
                   WHERE role.account_id = account.id AND role.role = 'professional'
                     AND role.revoked_at IS NULL
               ) AS has_professional_role,
               EXISTS (
                   SELECT 1
                   FROM identity.channel_identities AS channel
                   JOIN private_data.whatsapp_identities AS whatsapp
                     ON whatsapp.channel_identity_id = channel.id
                   WHERE channel.id = $2 AND channel.account_id = account.id
                     AND channel.provider_code = 'whatsapp'
                     AND channel.provider_namespace = $3
                     AND channel.status = 'active' AND channel.verified_at IS NOT NULL
                     AND whatsapp.opt_in_status <> 'opted_out'
                     AND whatsapp.delivery_state <> 'unreachable'
                     AND whatsapp.blocked_at IS NULL
               ) AS channel_eligible,
               root.id AS profile_id, root.published_revision_id,
               root.visibility AS profile_visibility, revision.state AS revision_state,
               COALESCE(profile.revision_is_publishable(revision.id), false) AS publishable,
               revision.contact_request_limit AS contact_limit
        FROM identity.accounts AS account
        LEFT JOIN profile.public_profiles AS root ON root.account_id = account.id
        LEFT JOIN profile.profile_revisions AS revision
          ON revision.id = root.published_revision_id AND revision.profile_id = root.id
        WHERE account.id = $1
        "#;
    sqlx::query_as::<_, EligibilityRow>(query)
        .bind(account_id.into_uuid())
        .bind(channel_identity_id.into_uuid())
        .bind(provider_namespace)
        .fetch_one(executor)
        .await
        .map_err(PersistenceError::from)
}

async fn lock_availability_aggregate(
    connection: &mut PgConnection,
    account_id: AccountId,
) -> Result<(), PersistenceError> {
    let profile: Option<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        r#"
        SELECT root.id, root.published_revision_id
        FROM identity.accounts AS account
        LEFT JOIN profile.public_profiles AS root ON root.account_id = account.id
        WHERE account.id = $1
        FOR UPDATE OF account
        "#,
    )
    .bind(account_id.into_uuid())
    .fetch_optional(&mut *connection)
    .await?;
    if let Some((Some(profile_id), published_revision_id)) = profile {
        sqlx::query("SELECT id FROM profile.public_profiles WHERE id = $1 FOR UPDATE")
            .bind(profile_id)
            .execute(&mut *connection)
            .await?;
        if let Some(revision_id) = published_revision_id {
            sqlx::query("SELECT id FROM profile.profile_revisions WHERE id = $1 FOR UPDATE")
                .bind(revision_id)
                .execute(&mut *connection)
                .await?;
            sqlx::query(
                r#"
                SELECT category.code
                FROM profile.professional_services AS service
                JOIN profile.service_categories AS category
                  ON category.code = service.category_code
                WHERE service.revision_id = $1
                ORDER BY category.code
                FOR SHARE OF service, category
                "#,
            )
            .bind(revision_id)
            .fetch_all(&mut *connection)
            .await?;
        }
    }
    Ok(())
}

fn eligibility_reason(row: &EligibilityRow) -> Option<AvailabilityIneligibility> {
    if !row.has_professional_role {
        Some(AvailabilityIneligibility::ProfessionalRoleRequired)
    } else if row.account_status != "active" || row.risk_state != "normal" || !row.channel_eligible
    {
        Some(AvailabilityIneligibility::AccountUnavailable)
    } else if row.profile_id.is_none()
        || row.profile_visibility.as_deref() != Some("published")
        || row.published_revision_id.is_none()
        || row.revision_state.as_deref() != Some("approved")
        || !row.publishable
        || row.contact_limit.is_none()
    {
        Some(AvailabilityIneligibility::ApprovedProfileRequired)
    } else {
        None
    }
}

async fn calculate_window(
    connection: &mut PgConnection,
    duration: AvailabilityDuration,
    time_zone: &str,
    starts_at: Option<OffsetDateTime>,
) -> Result<WindowRow, PersistenceError> {
    sqlx::query_as::<_, WindowRow>(
        r#"
        WITH clock AS (
            SELECT clock_timestamp() AS database_now
        ), start_value AS (
            SELECT database_now, COALESCE($3::timestamptz, database_now) AS starts_at
            FROM clock
        ), expiry AS (
            SELECT database_now, starts_at,
                   availability.calculate_expiry($1, $2, starts_at) AS expires_at
            FROM start_value
        )
        SELECT database_now, starts_at, expires_at,
               CASE WHEN $1 = 'end_of_local_day'
                    THEN (expires_at AT TIME ZONE $2)::date END AS local_end_date,
               CASE $1::text
                   WHEN 'one_hour' THEN expires_at - INTERVAL '10 minutes'
                   WHEN 'four_hours' THEN expires_at - INTERVAL '30 minutes'
                   WHEN 'end_of_local_day' THEN LEAST(
                       expires_at - INTERVAL '1 hour',
                       ((((expires_at AT TIME ZONE $2)::date - 1) + TIME '21:00') AT TIME ZONE $2)
                   )
               END AS reminder_at
        FROM expiry
        "#,
    )
    .bind(duration.as_str())
    .bind(time_zone)
    .bind(starts_at)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or_else(|| PersistenceError::InvalidCommand("account time zone is invalid".to_owned()))
}

async fn schedule_timer_jobs(
    connection: &mut PgConnection,
    epoch_id: AvailabilityEpochId,
    generation: i64,
    window: WindowRow,
    correlation_id: CorrelationId,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO integration.outbox_jobs (
            id, availability_epoch_id, availability_generation, job_kind,
            idempotency_key, payload_version, payload, available_at,
            max_attempts, correlation_id, ordering_key
        )
        VALUES (
            $1, $2, $3, 'advance_professional_availability', $4, 1,
            jsonb_build_object('epoch_id', $2::text, 'generation', $3),
            $5, 8, $6, NULL
        )
        "#,
    )
    .bind(OutboxJobId::new().into_uuid())
    .bind(epoch_id.into_uuid())
    .bind(generation)
    .bind(format!("availability-advance:v1:{epoch_id}:g{generation}"))
    .bind(window.expires_at)
    .bind(correlation_id.into_uuid())
    .execute(&mut *connection)
    .await?;
    if window.reminder_at > window.database_now + time::Duration::minutes(1)
        && window.reminder_at > window.starts_at + time::Duration::minutes(1)
    {
        sqlx::query(
            r#"
            INSERT INTO integration.outbox_jobs (
                id, availability_epoch_id, availability_generation, job_kind,
                idempotency_key, payload_version, payload, available_at,
                max_attempts, correlation_id, ordering_key
            )
            VALUES (
                $1, $2, $3, 'remind_professional_availability', $4, 1,
                jsonb_build_object('epoch_id', $2::text, 'generation', $3),
                $5, 4, $6, NULL
            )
            "#,
        )
        .bind(OutboxJobId::new().into_uuid())
        .bind(epoch_id.into_uuid())
        .bind(generation)
        .bind(format!("availability-reminder:v1:{epoch_id}:g{generation}"))
        .bind(window.reminder_at)
        .bind(correlation_id.into_uuid())
        .execute(&mut *connection)
        .await?;
    }
    Ok(())
}

async fn load_current_snapshot<'e, E>(
    executor: E,
    profile_id: PublicProfileId,
) -> Result<Option<AvailabilityEpochSnapshot>, PersistenceError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query_as::<_, EpochRow>(
        r#"
        SELECT epoch.id, epoch.generation, epoch.version,
               CASE WHEN epoch.state = 'scheduled' AND epoch.starts_at <= statement_timestamp()
                    THEN 'available' ELSE epoch.state END AS state,
               epoch.duration_code, epoch.expires_at,
               EXTRACT(YEAR FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS year,
               EXTRACT(MONTH FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS month,
               EXTRACT(DAY FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS day,
               EXTRACT(HOUR FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS hour,
               EXTRACT(MINUTE FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS minute,
               epoch.contact_count, epoch.contact_limit,
               successor.duration_code AS successor_duration
        FROM availability.epochs AS epoch
        JOIN profile.public_profiles AS root ON root.id = epoch.profile_id
        LEFT JOIN availability.epochs AS successor
          ON successor.predecessor_epoch_id = epoch.id AND successor.state = 'scheduled'
        WHERE epoch.profile_id = $1
          AND epoch.profile_revision_id = root.published_revision_id
          AND (
              (epoch.state IN ('available', 'stopped', 'paused_contact_limit')
               AND statement_timestamp() < epoch.expires_at)
              OR
              (epoch.state = 'scheduled' AND epoch.starts_at <= statement_timestamp()
               AND statement_timestamp() < epoch.expires_at)
              OR epoch.state IN ('expired', 'cancelled_manual', 'cancelled_ineligible')
          )
        ORDER BY epoch.starts_at DESC, epoch.id DESC
        LIMIT 1
        "#,
    )
    .bind(profile_id.into_uuid())
    .fetch_optional(executor)
    .await?;
    row.map(map_epoch_row).transpose()
}

async fn load_epoch_snapshot<'e, E>(
    executor: E,
    epoch_id: AvailabilityEpochId,
) -> Result<Option<AvailabilityEpochSnapshot>, PersistenceError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query_as::<_, EpochRow>(
        r#"
        SELECT epoch.id, epoch.generation, epoch.version, epoch.state,
               epoch.duration_code, epoch.expires_at,
               EXTRACT(YEAR FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS year,
               EXTRACT(MONTH FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS month,
               EXTRACT(DAY FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS day,
               EXTRACT(HOUR FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS hour,
               EXTRACT(MINUTE FROM epoch.expires_at AT TIME ZONE epoch.time_zone_snapshot)::integer AS minute,
               epoch.contact_count, epoch.contact_limit,
               successor.duration_code AS successor_duration
        FROM availability.epochs AS epoch
        LEFT JOIN availability.epochs AS successor
          ON successor.predecessor_epoch_id = epoch.id AND successor.state = 'scheduled'
        WHERE epoch.id = $1
        "#,
    )
    .bind(epoch_id.into_uuid())
    .fetch_optional(executor)
    .await?;
    row.map(map_epoch_row).transpose()
}

fn map_epoch_row(row: EpochRow) -> Result<AvailabilityEpochSnapshot, PersistenceError> {
    Ok(AvailabilityEpochSnapshot {
        id: AvailabilityEpochId::from_uuid(row.id),
        generation: row.generation,
        version: row.version,
        state: AvailabilityEpochState::from_str(&row.state).map_err(|error| {
            PersistenceError::Invariant(format!("availability state is invalid: {error}"))
        })?,
        duration: AvailabilityDuration::from_str(&row.duration_code).map_err(|error| {
            PersistenceError::Invariant(format!("availability duration is invalid: {error}"))
        })?,
        expires_at: row.expires_at,
        expires_local: local_expiry(row.year, row.month, row.day, row.hour, row.minute)?,
        contact_count: row.contact_count,
        contact_limit: row.contact_limit,
        successor_duration: row
            .successor_duration
            .map(|value| AvailabilityDuration::from_str(&value))
            .transpose()
            .map_err(|error| {
                PersistenceError::Invariant(format!("successor duration is invalid: {error}"))
            })?,
    })
}

fn local_expiry(
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
) -> Result<AvailabilityLocalExpiry, PersistenceError> {
    Ok(AvailabilityLocalExpiry {
        year,
        month: u8::try_from(month).map_err(|_| {
            PersistenceError::Invariant("availability local month is invalid".to_owned())
        })?,
        day: u8::try_from(day).map_err(|_| {
            PersistenceError::Invariant("availability local day is invalid".to_owned())
        })?,
        hour: u8::try_from(hour).map_err(|_| {
            PersistenceError::Invariant("availability local hour is invalid".to_owned())
        })?,
        minute: u8::try_from(minute).map_err(|_| {
            PersistenceError::Invariant("availability local minute is invalid".to_owned())
        })?,
    })
}

async fn mutation_throttled(
    connection: &mut PgConnection,
    account_id: AccountId,
    operation: AvailabilityTurnOperation,
) -> Result<bool, PersistenceError> {
    if matches!(operation, AvailabilityTurnOperation::Stop { .. }) {
        return Ok(false);
    }
    sqlx::query_scalar(
        r#"
        SELECT
            (SELECT count(*) FROM availability.mutation_events
             WHERE account_id = $1 AND occurred_at > clock_timestamp() - INTERVAL '1 hour'
               AND action IN ('started', 'resumed', 'successor_scheduled')) >= 12
            OR
            (SELECT count(*) FROM availability.mutation_events
             WHERE account_id = $1 AND occurred_at > clock_timestamp() - INTERVAL '24 hours'
               AND action IN ('started', 'resumed', 'successor_scheduled')) >= 40
        "#,
    )
    .bind(account_id.into_uuid())
    .fetch_one(&mut *connection)
    .await
    .map_err(PersistenceError::from)
}

async fn materialize_due_epochs(
    connection: &mut PgConnection,
    profile_id: PublicProfileId,
    published_revision_id: ProfileRevisionId,
    correlation_id: CorrelationId,
) -> Result<(), PersistenceError> {
    let invalidated: Vec<(Uuid, Uuid)> = sqlx::query_as(
        r#"
        UPDATE availability.epochs
        SET state = 'cancelled_ineligible', terminal_at = clock_timestamp(),
            terminal_reason = 'published_revision_changed'
        WHERE profile_id = $1 AND profile_revision_id <> $2
          AND state IN ('scheduled', 'available', 'stopped', 'paused_contact_limit')
        RETURNING id, account_id
        "#,
    )
    .bind(profile_id.into_uuid())
    .bind(published_revision_id.into_uuid())
    .fetch_all(&mut *connection)
    .await?;
    for (id, account_id) in invalidated {
        let epoch_id = AvailabilityEpochId::from_uuid(id);
        let audit_id = append_audit(
            connection,
            None,
            None,
            "availability.invalidated",
            epoch_id,
            "published_revision_changed",
            correlation_id,
            json!({}),
        )
        .await?;
        sqlx::query(
            "INSERT INTO availability.mutation_events (id, epoch_id, account_id, action, audit_event_id, correlation_id) VALUES ($1, $2, $3, 'invalidated', $4, $5)",
        )
        .bind(Uuid::now_v7())
        .bind(id)
        .bind(account_id)
        .bind(audit_id.into_uuid())
        .bind(correlation_id.into_uuid())
        .execute(&mut *connection)
        .await?;
    }
    let due: Option<(Uuid, Uuid)> = sqlx::query_as(
        r#"
        SELECT id, account_id FROM availability.epochs
        WHERE profile_id = $1
          AND state IN ('available', 'stopped', 'paused_contact_limit')
          AND expires_at <= clock_timestamp()
        FOR UPDATE
        "#,
    )
    .bind(profile_id.into_uuid())
    .fetch_optional(&mut *connection)
    .await?;
    if let Some((id, account_id)) = due {
        let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *connection)
            .await?;
        expire_and_activate_successor(
            connection,
            AvailabilityEpochId::from_uuid(id),
            account_id,
            now,
            None,
            correlation_id,
        )
        .await?;
    }
    Ok(())
}

async fn expire_and_activate_successor(
    connection: &mut PgConnection,
    epoch_id: AvailabilityEpochId,
    account_id: Uuid,
    now: OffsetDateTime,
    _notification: Option<&QueueOutboundMessage>,
    correlation_id: CorrelationId,
) -> Result<(), PersistenceError> {
    sqlx::query(
        "UPDATE availability.epochs SET state = 'expired', terminal_at = $2, terminal_reason = 'natural_expiry' WHERE id = $1 AND state IN ('available', 'stopped', 'paused_contact_limit')",
    )
    .bind(epoch_id.into_uuid())
    .bind(now)
    .execute(&mut *connection)
    .await?;
    let audit_id = append_audit(
        connection,
        None,
        None,
        "availability.expired",
        epoch_id,
        "natural_expiry",
        correlation_id,
        json!({}),
    )
    .await?;
    sqlx::query(
        "INSERT INTO availability.mutation_events (id, epoch_id, account_id, action, audit_event_id, correlation_id, occurred_at) VALUES ($1, $2, $3, 'expired', $4, $5, $6) ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(epoch_id.into_uuid())
    .bind(account_id)
    .bind(audit_id.into_uuid())
    .bind(correlation_id.into_uuid())
    .bind(now)
    .execute(&mut *connection)
    .await?;
    let successor: Option<(Uuid, i64)> = sqlx::query_as(
        "SELECT id, generation FROM availability.epochs WHERE predecessor_epoch_id = $1 AND state = 'scheduled' FOR UPDATE",
    )
    .bind(epoch_id.into_uuid())
    .fetch_optional(&mut *connection)
    .await?;
    if let Some((successor_id, _)) = successor {
        let eligible: bool = sqlx::query_scalar(
            r#"
            SELECT profile.revision_is_publishable(successor.profile_revision_id)
               AND root.visibility = 'published'
               AND root.published_revision_id = successor.profile_revision_id
               AND account.status = 'active' AND account.risk_state = 'normal'
            FROM availability.epochs AS successor
            JOIN profile.public_profiles AS root ON root.id = successor.profile_id
            JOIN identity.accounts AS account ON account.id = successor.account_id
            WHERE successor.id = $1
            "#,
        )
        .bind(successor_id)
        .fetch_one(&mut *connection)
        .await?;
        let next_state = if eligible {
            "available"
        } else {
            "cancelled_ineligible"
        };
        sqlx::query(
            r#"
            UPDATE availability.epochs
            SET state = $2,
                terminal_at = CASE WHEN $2 = 'cancelled_ineligible' THEN $3 ELSE NULL END,
                terminal_reason = CASE WHEN $2 = 'cancelled_ineligible' THEN 'eligibility_changed' ELSE NULL END
            WHERE id = $1
            "#,
        )
        .bind(successor_id)
        .bind(next_state)
        .bind(now)
        .execute(&mut *connection)
        .await?;
        let successor_epoch_id = AvailabilityEpochId::from_uuid(successor_id);
        let successor_action = if eligible {
            "successor_activated"
        } else {
            "invalidated"
        };
        let successor_audit = append_audit(
            connection,
            None,
            None,
            if eligible {
                "availability.successor_activated"
            } else {
                "availability.invalidated"
            },
            successor_epoch_id,
            if eligible {
                "scheduled_renewal"
            } else {
                "eligibility_changed"
            },
            correlation_id,
            json!({}),
        )
        .await?;
        sqlx::query(
            "INSERT INTO availability.mutation_events (id, epoch_id, account_id, action, audit_event_id, correlation_id, occurred_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(Uuid::now_v7())
        .bind(successor_id)
        .bind(account_id)
        .bind(successor_action)
        .bind(successor_audit.into_uuid())
        .bind(correlation_id.into_uuid())
        .bind(now)
        .execute(&mut *connection)
        .await?;
    }
    Ok(())
}

async fn queue_availability_outbound(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    outbound: &QueueOutboundMessage,
) -> Result<OutboundMessageId, PersistenceError> {
    match crate::outbound::queue_in_transaction(transaction, outbound).await? {
        OutboundQueueOutcome::Queued {
            outbound_message_id,
            ..
        }
        | OutboundQueueOutcome::Duplicate {
            outbound_message_id,
        } => Ok(outbound_message_id),
        OutboundQueueOutcome::IdentifierCollision { .. } => Err(PersistenceError::InvalidCommand(
            "availability notification idempotency collision".to_owned(),
        )),
    }
}

async fn validate_notification_target(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: Uuid,
    outbound: &QueueOutboundMessage,
) -> Result<(), PersistenceError> {
    let Some(channel_id) = outbound.recipient_channel_identity_id else {
        return Err(PersistenceError::InvalidCommand(
            "availability notification recipient is missing".to_owned(),
        ));
    };
    let valid: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM identity.channel_identities
            WHERE id = $1 AND account_id = $2 AND provider_code = 'whatsapp'
              AND provider_namespace = $3 AND status = 'active' AND verified_at IS NOT NULL
        )
        "#,
    )
    .bind(channel_id.into_uuid())
    .bind(account_id)
    .bind(&outbound.provider_namespace)
    .fetch_one(&mut **transaction)
    .await?;
    if !valid {
        return Err(PersistenceError::InvalidCommand(
            "availability notification target is not eligible".to_owned(),
        ));
    }
    Ok(())
}

async fn record_mutation(
    connection: &mut PgConnection,
    context: AvailabilityEffectContext<'_>,
    epoch_id: AvailabilityEpochId,
    action: &str,
    duration: Option<AvailabilityDuration>,
    metadata: serde_json::Value,
) -> Result<(), PersistenceError> {
    let audit_id = append_audit(
        connection,
        Some(context.account_id),
        Some(context.channel_identity_id),
        &format!("availability.{action}"),
        epoch_id,
        action,
        context.correlation_id,
        metadata,
    )
    .await?;
    sqlx::query(
        r#"
        INSERT INTO availability.mutation_events (
            id, epoch_id, account_id, source_inbound_event_id, action,
            duration_code, audit_event_id, correlation_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(epoch_id.into_uuid())
    .bind(context.account_id.into_uuid())
    .bind(context.inbound_event_id.into_uuid())
    .bind(action)
    .bind(duration.map(AvailabilityDuration::as_str))
    .bind(audit_id.into_uuid())
    .bind(context.correlation_id.into_uuid())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn append_audit(
    connection: &mut PgConnection,
    actor_account_id: Option<AccountId>,
    actor_channel_id: Option<ChannelIdentityId>,
    action: &str,
    epoch_id: AvailabilityEpochId,
    reason: &str,
    correlation_id: CorrelationId,
    metadata: serde_json::Value,
) -> Result<AuditEventId, PersistenceError> {
    let id = AuditEventId::new();
    sqlx::query(
        r#"
        INSERT INTO audit.events (
            id, actor_type, actor_account_id, actor_channel_identity_id,
            source_channel, action, target_type, target_id, reason_code,
            metadata, event_schema_version, correlation_id
        )
        VALUES (
            $1, CASE WHEN $2::uuid IS NULL THEN 'system' ELSE 'account' END,
            $2, $3, CASE WHEN $3::uuid IS NULL THEN 'system' ELSE 'whatsapp' END,
            $4, 'availability_epoch', $5, $6, $7, 1, $8
        )
        "#,
    )
    .bind(id.into_uuid())
    .bind(actor_account_id.map(AccountId::into_uuid))
    .bind(actor_channel_id.map(ChannelIdentityId::into_uuid))
    .bind(action)
    .bind(epoch_id.into_uuid())
    .bind(reason)
    .bind(metadata)
    .bind(correlation_id.into_uuid())
    .execute(&mut *connection)
    .await?;
    Ok(id)
}

async fn lease_is_current(
    connection: &mut PgConnection,
    lease: JobLease,
    epoch_id: AvailabilityEpochId,
    generation: i64,
    purpose: AvailabilityTimerPurpose,
) -> Result<bool, PersistenceError> {
    sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM integration.outbox_jobs
            WHERE id = $1 AND state = 'leased' AND lease_owner = $2
              AND lease_token = $3 AND lease_expires_at > clock_timestamp()
              AND availability_epoch_id = $4 AND availability_generation = $5
              AND job_kind = $6
        )
        "#,
    )
    .bind(lease.job_id.into_uuid())
    .bind(lease.worker_id.into_uuid())
    .bind(lease.token.into_uuid())
    .bind(epoch_id.into_uuid())
    .bind(generation)
    .bind(match purpose {
        AvailabilityTimerPurpose::Reminder => REMIND_AVAILABILITY_JOB,
        AvailabilityTimerPurpose::Advance => ADVANCE_AVAILABILITY_JOB,
    })
    .fetch_one(&mut *connection)
    .await
    .map_err(PersistenceError::from)
}

async fn complete_timer_job(
    connection: &mut PgConnection,
    lease: JobLease,
) -> Result<LeaseOutcome, PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE integration.outbox_jobs
        SET state = 'completed', lease_owner = NULL, lease_token = NULL,
            lease_started_at = NULL, lease_expires_at = NULL,
            completed_at = clock_timestamp()
        WHERE id = $1 AND state = 'leased' AND lease_owner = $2 AND lease_token = $3
          AND lease_expires_at > clock_timestamp()
        "#,
    )
    .bind(lease.job_id.into_uuid())
    .bind(lease.worker_id.into_uuid())
    .bind(lease.token.into_uuid())
    .execute(&mut *connection)
    .await?;
    Ok(if result.rows_affected() == 1 {
        LeaseOutcome::Applied
    } else {
        LeaseOutcome::LostLease
    })
}

async fn reschedule_timer_job(
    connection: &mut PgConnection,
    lease: JobLease,
    available_at: OffsetDateTime,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        UPDATE integration.outbox_jobs
        SET state = 'pending', available_at = $4, lease_owner = NULL, lease_token = NULL,
            lease_started_at = NULL, lease_expires_at = NULL,
            last_error_class = 'timer_early', last_error_code = 'not_due',
            last_error_at = clock_timestamp()
        WHERE id = $1 AND state = 'leased' AND lease_owner = $2 AND lease_token = $3
        "#,
    )
    .bind(lease.job_id.into_uuid())
    .bind(lease.worker_id.into_uuid())
    .bind(lease.token.into_uuid())
    .bind(available_at)
    .execute(&mut *connection)
    .await?;
    Ok(())
}
