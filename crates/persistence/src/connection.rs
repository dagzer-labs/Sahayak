use crate::{
    CapacityConsumptionOutcome, Database, JobLease, LeaseOutcome, PersistenceError,
    QueueOutboundMessage,
    availability::{consume_capacity_in_transaction, reverse_capacity_in_transaction},
};
use sahayak_cryptography::{EncryptedValue, EncryptionPurpose};
use sahayak_domain::{
    AccountBlockId, AccountId, AuditEventId, AvailabilityConsumptionId, AvailabilityEpochId,
    ChannelIdentityId, ConnectionRequestId, ContactMode, ContactRevealId, CorrelationId,
    CustomerAllowanceEventId, InboundEventId, OutboundMessageId, OutboxJobId, ProfilePhotoId,
    ProviderServiceId, RequestCandidateId, ServiceRequestId,
};
use sqlx::FromRow;
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

pub const EXPIRE_CONNECTION_JOB: &str = "expire_connection_request";
pub const CUSTOMER_FREE_REVEAL_LIMIT: i64 = 3;

#[derive(Clone)]
pub struct ContactTarget {
    pub account_id: AccountId,
    pub channel_identity_id: ChannelIdentityId,
    pub provider_namespace: String,
    pub locale: String,
    pub encrypted_phone: EncryptedValue,
}

impl std::fmt::Debug for ContactTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContactTarget")
            .field("account_id", &self.account_id)
            .field("channel_identity_id", &self.channel_identity_id)
            .field("provider_namespace", &self.provider_namespace)
            .field("locale", &self.locale)
            .field("encrypted_phone", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct ContactPhoto {
    pub photo_id: ProfilePhotoId,
    pub encrypted_jpeg: EncryptedValue,
}

impl std::fmt::Debug for ContactPhoto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContactPhoto")
            .field("photo_id", &self.photo_id)
            .field("encrypted_jpeg", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct SelectionContext {
    pub request_id: ServiceRequestId,
    pub request_token: String,
    pub request_version: i64,
    pub candidate_id: RequestCandidateId,
    pub candidate_token: String,
    pub provider_service_id: ProviderServiceId,
    pub availability_epoch_id: AvailabilityEpochId,
    pub professional_account_id: AccountId,
    pub category_code: String,
    pub issue_code: String,
    pub requested_time: String,
    pub distance_metres: i32,
    pub contact_mode: ContactMode,
    pub professional: ContactTarget,
    pub customer: ContactTarget,
    pub photo: Option<ContactPhoto>,
    pub contact_count: i16,
    pub contact_limit: i16,
}

#[derive(Clone, Debug)]
pub struct RepeatRevealContext {
    pub reveal_token: String,
    pub professional_account_id: AccountId,
    pub category_code: String,
    pub professional: ContactTarget,
    pub customer: ContactTarget,
    pub photo: Option<ContactPhoto>,
}

#[derive(Clone, Debug)]
pub struct PendingResponseContext {
    pub connection_id: ConnectionRequestId,
    pub request_token: String,
    pub version: i64,
    pub selection: SelectionContext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingConnectionSummary {
    pub request_token: String,
    pub version: i64,
    pub category_code: String,
    pub issue_code: String,
    pub requested_time: String,
    pub distance_label: String,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingCustomerConnection {
    pub request_token: String,
    pub version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecentContactSummary {
    pub reveal_token: String,
    pub display_name: String,
    pub public_reference: String,
    pub category_code: String,
    pub revealed_at: OffsetDateTime,
}

/// Privacy-safe qualified introduction available for review, reporting, or blocking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntroductionSummary {
    pub reveal_token: String,
    pub counterpart_account_id: AccountId,
    pub counterpart_label: Option<String>,
    pub category_code: String,
    pub current_account_is_customer: bool,
    pub already_reviewed: bool,
    pub already_reported: bool,
    pub already_blocked: bool,
    pub revealed_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct IntroductionRow {
    reveal_token: Uuid,
    counterpart_account_id: Uuid,
    counterpart_label: Option<String>,
    category_code: String,
    current_account_is_customer: bool,
    already_reviewed: bool,
    already_reported: bool,
    already_blocked: bool,
    revealed_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionOutboundIds {
    pub customer_contact: Option<OutboundMessageId>,
    pub professional_contact: Option<OutboundMessageId>,
    pub professional_notification: Option<OutboundMessageId>,
    pub photo: Option<OutboundMessageId>,
}

#[derive(Clone)]
pub enum ConnectionTurnOperation {
    Select {
        connection_id: ConnectionRequestId,
        connection_token: Uuid,
        reveal_id: ContactRevealId,
        reveal_token: Uuid,
        request_token: Uuid,
        candidate_token: Uuid,
        expected_request_version: i64,
        outbounds: ConnectionOutboundIds,
        pause_notification: Option<QueueOutboundMessage>,
    },
    Respond {
        connection_token: Uuid,
        expected_version: i64,
        accept: bool,
        reveal_id: ContactRevealId,
        reveal_token: Uuid,
        outbounds: ConnectionOutboundIds,
        pause_notification: Option<QueueOutboundMessage>,
    },
    Cancel {
        connection_token: Uuid,
        expected_version: i64,
    },
    Repeat {
        reveal_token: Uuid,
        outbounds: ConnectionOutboundIds,
    },
}

#[derive(Clone)]
pub struct ConnectionTurnEffect {
    pub operation: ConnectionTurnOperation,
}

impl ConnectionTurnEffect {
    #[must_use]
    pub const fn required_role(&self) -> sahayak_domain::AccountRole {
        match self.operation {
            ConnectionTurnOperation::Respond { .. } => sahayak_domain::AccountRole::Professional,
            ConnectionTurnOperation::Select { .. }
            | ConnectionTurnOperation::Cancel { .. }
            | ConnectionTurnOperation::Repeat { .. } => sahayak_domain::AccountRole::Customer,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ConnectionEffectContext<'a> {
    pub account_id: AccountId,
    pub channel_identity_id: ChannelIdentityId,
    pub inbound_event_id: InboundEventId,
    pub provider_namespace: &'a str,
    pub correlation_id: CorrelationId,
    pub primary_outbound_id: OutboundMessageId,
    pub primary_outbound_recipient: Option<ChannelIdentityId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionMutationOutcome {
    DirectRevealed,
    PreviouslyRevealed,
    RequestCreated,
    Accepted,
    Declined,
    Cancelled,
    LimitReached,
    ProfessionalAtCapacity,
    Conflict,
    Ineligible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionTimerOutcome {
    Expired,
    Stale,
    LostLease,
}

#[derive(FromRow)]
struct TargetRow {
    account_id: Uuid,
    channel_identity_id: Uuid,
    provider_namespace: String,
    locale: String,
    phone_e164_ciphertext: Vec<u8>,
    phone_e164_nonce: Vec<u8>,
    encryption_key_version: i16,
}

#[derive(FromRow)]
struct PhotoRow {
    id: Uuid,
    sanitized_ciphertext: Vec<u8>,
    sanitized_nonce: Vec<u8>,
    encryption_key_version: i16,
}

#[derive(FromRow)]
struct SelectionRow {
    request_id: Uuid,
    request_token: Uuid,
    request_version: i64,
    candidate_id: Uuid,
    candidate_token: Uuid,
    provider_service_id: Uuid,
    availability_epoch_id: Uuid,
    professional_account_id: Uuid,
    customer_account_id: Uuid,
    category_code: String,
    issue_code: String,
    requested_time: String,
    distance_metres: i32,
    contact_mode: String,
    profile_revision_id: Uuid,
    contact_count: i16,
    contact_limit: i16,
}

#[derive(FromRow)]
struct DeliveryLinkRow {
    reveal_id: Uuid,
    availability_consumption_id: Option<Uuid>,
    state: String,
    customer_contains_contact: bool,
    professional_contains_contact: bool,
    customer_delivered_at: Option<OffsetDateTime>,
    professional_delivered_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct ConnectionRepository {
    database: Database,
}

impl ConnectionRepository {
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    pub async fn selection_context(
        &self,
        customer_account_id: AccountId,
        candidate_token: &str,
    ) -> Result<Option<SelectionContext>, PersistenceError> {
        let candidate_token = Uuid::parse_str(candidate_token).map_err(|_| {
            PersistenceError::InvalidCommand("candidate token is invalid".to_owned())
        })?;
        let row = load_selection(
            self.database.pool(),
            customer_account_id,
            candidate_token,
            false,
        )
        .await?;
        let Some(row) = row else { return Ok(None) };
        let professional = load_contact_target(self.database.pool(), row.professional_account_id)
            .await?
            .ok_or_else(|| {
                PersistenceError::Invariant("professional contact target missing".to_owned())
            })?;
        let customer = load_contact_target(self.database.pool(), row.customer_account_id)
            .await?
            .ok_or_else(|| {
                PersistenceError::Invariant("customer contact target missing".to_owned())
            })?;
        let photo = load_contact_photo(self.database.pool(), row.profile_revision_id).await?;
        Ok(Some(SelectionContext {
            request_id: ServiceRequestId::from_uuid(row.request_id),
            request_token: row.request_token.to_string(),
            request_version: row.request_version,
            candidate_id: RequestCandidateId::from_uuid(row.candidate_id),
            candidate_token: row.candidate_token.to_string(),
            provider_service_id: ProviderServiceId::from_uuid(row.provider_service_id),
            availability_epoch_id: AvailabilityEpochId::from_uuid(row.availability_epoch_id),
            professional_account_id: AccountId::from_uuid(row.professional_account_id),
            category_code: row.category_code,
            issue_code: row.issue_code,
            requested_time: row.requested_time,
            distance_metres: row.distance_metres,
            contact_mode: ContactMode::from_str(&row.contact_mode).map_err(|error| {
                PersistenceError::Invariant(format!("candidate contact mode is invalid: {error}"))
            })?,
            professional,
            customer,
            photo,
            contact_count: row.contact_count,
            contact_limit: row.contact_limit,
        }))
    }

    pub async fn pending_for_professional(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<PendingConnectionSummary>, PersistenceError> {
        let rows: Vec<(Uuid, i64, String, String, String, i32, OffsetDateTime)> = sqlx::query_as(
            r#"
            SELECT connection.request_token, connection.version, request.category_code,
                   COALESCE(request.issue_code, 'other'),
                   COALESCE(request.requested_time, 'flexible'),
                   candidate.distance_metres, connection.expires_at
            FROM connection.connection_requests AS connection
            JOIN discovery.service_requests AS request ON request.id = connection.service_request_id
            JOIN discovery.request_candidates AS candidate ON candidate.id = connection.candidate_id
            WHERE connection.professional_account_id = $1 AND connection.status = 'pending'
              AND connection.response_deadline > statement_timestamp()
            ORDER BY connection.requested_at, connection.id
            LIMIT 10
            "#,
        )
        .bind(account_id.into_uuid())
        .fetch_all(self.database.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(token, version, category, issue, requested, distance, expiry)| {
                    PendingConnectionSummary {
                        request_token: token.to_string(),
                        version,
                        category_code: category,
                        issue_code: issue,
                        requested_time: requested,
                        distance_label: distance_label(distance),
                        expires_at: expiry,
                    }
                },
            )
            .collect())
    }

    pub async fn pending_for_customer(
        &self,
        account_id: AccountId,
    ) -> Result<Option<PendingCustomerConnection>, PersistenceError> {
        let row: Option<(Uuid, i64)> = sqlx::query_as(
            r#"
            SELECT request_token, version
            FROM connection.connection_requests
            WHERE customer_account_id = $1 AND status = 'pending'
              AND response_deadline > statement_timestamp()
            ORDER BY requested_at DESC LIMIT 1
            "#,
        )
        .bind(account_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        Ok(row.map(|(token, version)| PendingCustomerConnection {
            request_token: token.to_string(),
            version,
        }))
    }

    pub async fn recent_contacts(
        &self,
        customer_account_id: AccountId,
    ) -> Result<Vec<RecentContactSummary>, PersistenceError> {
        let rows: Vec<(Uuid, String, Uuid, String, OffsetDateTime)> = sqlx::query_as(
            r#"
            SELECT reveal.reveal_token, revision.display_name, root.public_id,
                   provider.category_code, reveal.revealed_at
            FROM connection.contact_reveals AS reveal
            JOIN profile.provider_services AS provider ON provider.id = reveal.provider_service_id
            JOIN profile.public_profiles AS root ON root.id = provider.profile_id
            JOIN profile.profile_revisions AS revision ON revision.id = root.published_revision_id
            LEFT JOIN connection.reveal_reversals AS reversal ON reversal.reveal_id = reveal.id
            WHERE reveal.customer_account_id = $1 AND reversal.id IS NULL
            ORDER BY reveal.revealed_at DESC
            LIMIT 10
            "#,
        )
        .bind(customer_account_id.into_uuid())
        .fetch_all(self.database.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, name, reference, category, revealed_at)| RecentContactSummary {
                    reveal_token: id.to_string(),
                    display_name: name,
                    public_reference: reference.to_string(),
                    category_code: category,
                    revealed_at,
                },
            )
            .collect())
    }

    pub async fn introduction_history(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<IntroductionSummary>, PersistenceError> {
        let rows: Vec<IntroductionRow> = sqlx::query_as(
            r#"
            SELECT reveal.reveal_token,
                   CASE WHEN reveal.customer_account_id = $1
                        THEN reveal.professional_account_id ELSE reveal.customer_account_id END AS counterpart_account_id,
                   CASE WHEN reveal.customer_account_id = $1 THEN revision.display_name ELSE NULL END AS counterpart_label,
                   provider.category_code,
                   reveal.customer_account_id = $1 AS current_account_is_customer,
                   EXISTS (SELECT 1 FROM review.reviews
                           WHERE reveal_id = reveal.id AND reviewer_account_id = $1) AS already_reviewed,
                   EXISTS (SELECT 1 FROM safety.reports
                           WHERE reveal_id = reveal.id AND reporter_account_id = $1) AS already_reported,
                   EXISTS (SELECT 1 FROM identity.account_blocks
                           WHERE actor_account_id = $1
                             AND blocked_account_id = CASE WHEN reveal.customer_account_id = $1
                                 THEN reveal.professional_account_id ELSE reveal.customer_account_id END
                             AND removed_at IS NULL) AS already_blocked,
                   reveal.revealed_at
            FROM connection.contact_reveals AS reveal
            JOIN connection.contact_reveal_delivery AS delivery ON delivery.reveal_id = reveal.id
            JOIN profile.provider_services AS provider ON provider.id = reveal.provider_service_id
            JOIN profile.public_profiles AS profile ON profile.id = provider.profile_id
            JOIN profile.profile_revisions AS revision ON revision.id = profile.published_revision_id
            LEFT JOIN connection.reveal_reversals AS reversal ON reversal.reveal_id = reveal.id
            WHERE $1 IN (reveal.customer_account_id, reveal.professional_account_id)
              AND delivery.qualified_state = 'qualified' AND reversal.id IS NULL
            ORDER BY reveal.revealed_at DESC, reveal.id DESC
            LIMIT 10
            "#,
        )
        .bind(account_id.into_uuid())
        .fetch_all(self.database.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| IntroductionSummary {
                reveal_token: row.reveal_token.to_string(),
                counterpart_account_id: AccountId::from_uuid(row.counterpart_account_id),
                counterpart_label: row.counterpart_label,
                category_code: row.category_code,
                current_account_is_customer: row.current_account_is_customer,
                already_reviewed: row.already_reviewed,
                already_reported: row.already_reported,
                already_blocked: row.already_blocked,
                revealed_at: row.revealed_at,
            })
            .collect())
    }

    pub async fn repeat_reveal_context(
        &self,
        customer_account_id: AccountId,
        reveal_token: &str,
    ) -> Result<Option<RepeatRevealContext>, PersistenceError> {
        let token = Uuid::parse_str(reveal_token)
            .map_err(|_| PersistenceError::InvalidCommand("reveal token is invalid".to_owned()))?;
        let row: Option<(Uuid, String, Uuid)> = sqlx::query_as(
            r#"
            SELECT reveal.professional_account_id, provider.category_code,
                   root.published_revision_id
            FROM connection.contact_reveals AS reveal
            JOIN profile.provider_services AS provider ON provider.id = reveal.provider_service_id
            JOIN profile.public_profiles AS root ON root.id = provider.profile_id
            LEFT JOIN connection.reveal_reversals AS reversal ON reversal.reveal_id = reveal.id
            WHERE reveal.reveal_token = $1 AND reveal.customer_account_id = $2
              AND reversal.id IS NULL
            "#,
        )
        .bind(token)
        .bind(customer_account_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        let Some((professional_account_id, category_code, revision_id)) = row else {
            return Ok(None);
        };
        Ok(Some(RepeatRevealContext {
            reveal_token: token.to_string(),
            professional_account_id: AccountId::from_uuid(professional_account_id),
            category_code,
            professional: load_contact_target(self.database.pool(), professional_account_id)
                .await?
                .ok_or_else(|| {
                    PersistenceError::Invariant("recent professional contact missing".to_owned())
                })?,
            customer: load_contact_target(self.database.pool(), customer_account_id.into_uuid())
                .await?
                .ok_or_else(|| {
                    PersistenceError::Invariant("recent customer contact missing".to_owned())
                })?,
            photo: load_contact_photo(self.database.pool(), revision_id).await?,
        }))
    }

    pub async fn response_context(
        &self,
        professional_account_id: AccountId,
        request_token: &str,
    ) -> Result<Option<PendingResponseContext>, PersistenceError> {
        let token = Uuid::parse_str(request_token).map_err(|_| {
            PersistenceError::InvalidCommand("connection request token is invalid".to_owned())
        })?;
        let row: Option<(Uuid, i64, Uuid, Uuid)> = sqlx::query_as(
            r#"
            SELECT connection.id, connection.version, connection.customer_account_id,
                   candidate.candidate_token
            FROM connection.connection_requests AS connection
            JOIN discovery.request_candidates AS candidate ON candidate.id = connection.candidate_id
            WHERE connection.request_token = $1
              AND connection.professional_account_id = $2
              AND connection.status = 'pending'
              AND connection.response_deadline > statement_timestamp()
            "#,
        )
        .bind(token)
        .bind(professional_account_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        let Some((connection_id, version, customer_id, candidate_token)) = row else {
            return Ok(None);
        };
        let selection = self
            .selection_context(
                AccountId::from_uuid(customer_id),
                &candidate_token.to_string(),
            )
            .await?
            .ok_or_else(|| {
                PersistenceError::Invariant("pending connection candidate is missing".to_owned())
            })?;
        Ok(Some(PendingResponseContext {
            connection_id: ConnectionRequestId::from_uuid(connection_id),
            request_token: token.to_string(),
            version,
            selection,
        }))
    }

    pub async fn process_expiry(
        &self,
        lease: JobLease,
        connection_id: ConnectionRequestId,
        generation: i64,
        correlation_id: CorrelationId,
    ) -> Result<ConnectionTimerOutcome, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query("SELECT set_config('sahayak.connection_mutation', 'on', true)")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SELECT set_config('sahayak.discovery_mutation', 'on', true)")
            .execute(&mut *transaction)
            .await?;
        let owner: Option<Uuid> = sqlx::query_scalar(
            "SELECT professional_account_id FROM connection.connection_requests WHERE id = $1",
        )
        .bind(connection_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(owner) = owner {
            sqlx::query("SELECT id FROM identity.accounts WHERE id = $1 FOR UPDATE")
                .bind(owner)
                .execute(&mut *transaction)
                .await?;
        }
        let current: Option<(String, bool, Uuid, Option<Uuid>)> = sqlx::query_as(
            "SELECT status, response_deadline <= clock_timestamp() AS due, service_request_id, candidate_id FROM connection.connection_requests WHERE id = $1 AND response_generation = $2 FOR UPDATE",
        )
        .bind(connection_id.into_uuid())
        .bind(generation)
        .fetch_optional(&mut *transaction)
        .await?;
        if !connection_lease_current(&mut transaction, lease, connection_id, generation).await? {
            transaction.rollback().await?;
            return Ok(ConnectionTimerOutcome::LostLease);
        }
        let Some((state, due, service_request_id, candidate_id)) = current else {
            complete_connection_job(&mut transaction, lease).await?;
            transaction.commit().await?;
            return Ok(ConnectionTimerOutcome::Stale);
        };
        if state != "pending" || !due {
            complete_connection_job(&mut transaction, lease).await?;
            transaction.commit().await?;
            return Ok(ConnectionTimerOutcome::Stale);
        }
        sqlx::query(
            "UPDATE connection.connection_requests SET status = 'expired', responded_at = clock_timestamp() WHERE id = $1 AND status = 'pending'",
        )
        .bind(connection_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        reset_request_after_connection(&mut transaction, service_request_id, candidate_id).await?;
        append_connection_audit(
            &mut transaction,
            None,
            None,
            "connection.expired",
            connection_id.into_uuid(),
            "response_deadline",
            correlation_id,
        )
        .await?;
        complete_connection_job(&mut transaction, lease).await?;
        transaction.commit().await?;
        Ok(ConnectionTimerOutcome::Expired)
    }

    pub async fn record_delivery(
        &self,
        outbound_message_id: OutboundMessageId,
        delivered: bool,
        failure_code: Option<&str>,
        correlation_id: CorrelationId,
    ) -> Result<bool, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query("SELECT set_config('sahayak.connection_mutation', 'on', true)")
            .execute(&mut *transaction)
            .await?;
        let recorded = record_contact_delivery_in_transaction(
            &mut transaction,
            outbound_message_id,
            delivered,
            failure_code,
            correlation_id,
        )
        .await?;
        transaction.commit().await?;
        Ok(recorded)
    }
}

pub(crate) async fn record_contact_delivery_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    outbound_message_id: OutboundMessageId,
    delivered: bool,
    failure_code: Option<&str>,
    correlation_id: CorrelationId,
) -> Result<bool, PersistenceError> {
    let reveal = sqlx::query_as::<_, DeliveryLinkRow>(
        r#"
                SELECT delivery.reveal_id, reveal.availability_consumption_id, delivery.state,
                       delivery.customer_contains_contact, delivery.professional_contains_contact,
                       delivery.customer_delivered_at, delivery.professional_delivered_at
                FROM connection.contact_reveal_delivery AS delivery
                JOIN connection.contact_reveals AS reveal ON reveal.id = delivery.reveal_id
                WHERE $1 IN (
                    delivery.customer_outbound_message_id,
                    delivery.professional_outbound_message_id,
                    delivery.photo_outbound_message_id
                )
                FOR UPDATE OF delivery
                "#,
    )
    .bind(outbound_message_id.into_uuid())
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(reveal) = reveal else {
        return Ok(false);
    };
    let reveal_id = reveal.reveal_id;
    let consumption_id = reveal.availability_consumption_id;
    let customer_contains = reveal.customer_contains_contact;
    let professional_contains = reveal.professional_contains_contact;
    let mut customer_delivered = reveal.customer_delivered_at;
    let mut professional_delivered = reveal.professional_delivered_at;
    if reveal.state == "reversed" {
        return Ok(true);
    }
    if delivered {
        sqlx::query(
                r#"
                UPDATE connection.contact_reveal_delivery
                SET customer_delivered_at = CASE WHEN customer_outbound_message_id = $2 THEN COALESCE(customer_delivered_at, clock_timestamp()) ELSE customer_delivered_at END,
                    professional_delivered_at = CASE WHEN professional_outbound_message_id = $2 THEN COALESCE(professional_delivered_at, clock_timestamp()) ELSE professional_delivered_at END,
                    photo_delivered_at = CASE WHEN photo_outbound_message_id = $2 THEN COALESCE(photo_delivered_at, clock_timestamp()) ELSE photo_delivered_at END
                WHERE reveal_id = $1
                "#,
            )
            .bind(reveal_id)
            .bind(outbound_message_id.into_uuid())
            .execute(&mut **transaction)
            .await?;
        let timestamps: (Option<OffsetDateTime>, Option<OffsetDateTime>) = sqlx::query_as(
                "SELECT customer_delivered_at, professional_delivered_at FROM connection.contact_reveal_delivery WHERE reveal_id = $1",
            )
            .bind(reveal_id)
            .fetch_one(&mut **transaction)
            .await?;
        customer_delivered = timestamps.0;
        professional_delivered = timestamps.1;
        if (!customer_contains || customer_delivered.is_some())
            && (!professional_contains || professional_delivered.is_some())
        {
            let qualified = sqlx::query(
                    "UPDATE connection.contact_reveal_delivery SET state = 'delivered', qualified_state = 'qualified', delivered_at = clock_timestamp(), failed_at = NULL, failure_code = NULL WHERE reveal_id = $1 AND qualified_state = 'pending'",
                )
                .bind(reveal_id)
                .execute(&mut **transaction)
                .await?;
            if qualified.rows_affected() == 1 {
                append_connection_audit(
                    transaction,
                    None,
                    None,
                    "contact.qualified",
                    reveal_id,
                    "contact_actions_delivered",
                    correlation_id,
                )
                .await?;
            }
        }
    } else {
        let code = failure_code.unwrap_or("provider_delivery_failed");
        if code.len() > 96 {
            return Err(PersistenceError::InvalidCommand(
                "contact delivery failure code is too long".to_owned(),
            ));
        }
        let failed_is_contact: bool = sqlx::query_scalar(
            r#"
                SELECT (customer_contains_contact AND customer_outbound_message_id = $2)
                    OR (professional_contains_contact AND professional_outbound_message_id = $2)
                FROM connection.contact_reveal_delivery WHERE reveal_id = $1
                "#,
        )
        .bind(reveal_id)
        .bind(outbound_message_id.into_uuid())
        .fetch_one(&mut **transaction)
        .await?;
        if !failed_is_contact {
            return Ok(true);
        }
        let contact_already_delivered = (customer_contains && customer_delivered.is_some())
            || (professional_contains && professional_delivered.is_some());
        if !contact_already_delivered {
            let reversal_audit = append_connection_audit(
                transaction,
                None,
                None,
                "contact.reversed",
                reveal_id,
                "internal_delivery_failure",
                correlation_id,
            )
            .await?;
            sqlx::query(
                    "INSERT INTO connection.reveal_reversals (id, reveal_id, reason_code, audit_event_id) VALUES ($1, $2, 'internal_delivery_failure', $3) ON CONFLICT (reveal_id) DO NOTHING",
                )
                .bind(Uuid::now_v7())
                .bind(reveal_id)
                .bind(reversal_audit.into_uuid())
                .execute(&mut **transaction)
                .await?;
            if let Some(consumption_id) = consumption_id {
                reverse_capacity_in_transaction(
                    transaction,
                    AvailabilityConsumptionId::from_uuid(consumption_id),
                    correlation_id,
                )
                .await?;
            }
            sqlx::query(
                    "UPDATE connection.contact_reveal_delivery SET state = 'reversed', qualified_state = 'reversed', failed_at = clock_timestamp(), failure_code = $2 WHERE reveal_id = $1",
                )
                .bind(reveal_id)
                .bind(code)
                .execute(&mut **transaction)
                .await?;
        } else {
            sqlx::query(
                    "UPDATE connection.contact_reveal_delivery SET state = 'failed', failed_at = clock_timestamp(), failure_code = $2 WHERE reveal_id = $1",
                )
                .bind(reveal_id)
                .bind(code)
                .execute(&mut **transaction)
                .await?;
        }
    }
    Ok(true)
}

#[derive(Clone, Debug)]
pub struct BlockRepository {
    database: Database,
}

impl BlockRepository {
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    pub async fn block(
        &self,
        actor: AccountId,
        actor_channel: ChannelIdentityId,
        blocked: AccountId,
        source_event: Option<InboundEventId>,
        correlation_id: CorrelationId,
    ) -> Result<bool, PersistenceError> {
        if actor == blocked {
            return Err(PersistenceError::InvalidCommand(
                "an account cannot block itself".to_owned(),
            ));
        }
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query("SELECT set_config('sahayak.connection_mutation', 'on', true)")
            .execute(&mut *transaction)
            .await?;
        lock_account_pair(&mut transaction, actor, blocked).await?;
        if pair_blocked(&mut transaction, actor.into_uuid(), blocked.into_uuid()).await? {
            transaction.rollback().await?;
            return Ok(false);
        }
        let audit = append_connection_audit(
            &mut transaction,
            Some(actor),
            Some(actor_channel),
            "account.blocked",
            blocked.into_uuid(),
            "user_block",
            correlation_id,
        )
        .await?;
        let inserted = sqlx::query(
            "INSERT INTO identity.account_blocks (id, actor_account_id, blocked_account_id, source_inbound_event_id, audit_event_id) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (actor_account_id, blocked_account_id) WHERE removed_at IS NULL DO NOTHING",
        )
        .bind(AccountBlockId::new().into_uuid())
        .bind(actor.into_uuid())
        .bind(blocked.into_uuid())
        .bind(source_event.map(InboundEventId::into_uuid))
        .bind(audit.into_uuid())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(inserted.rows_affected() == 1)
    }
}

pub(crate) async fn apply_connection_effect(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    context: ConnectionEffectContext<'_>,
    effect: &ConnectionTurnEffect,
    additional_outbound: &[QueueOutboundMessage],
) -> Result<ConnectionMutationOutcome, PersistenceError> {
    sqlx::query("SELECT set_config('sahayak.connection_mutation', 'on', true)")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT set_config('sahayak.discovery_mutation', 'on', true)")
        .execute(&mut **transaction)
        .await?;
    if !connection_command_matches_session(transaction, context, effect).await? {
        return Ok(ConnectionMutationOutcome::Ineligible);
    }
    match &effect.operation {
        ConnectionTurnOperation::Select {
            connection_id,
            connection_token,
            reveal_id,
            reveal_token,
            request_token,
            candidate_token,
            expected_request_version,
            outbounds,
            pause_notification,
        } => {
            let selection = lock_selection(
                transaction,
                context.account_id,
                *request_token,
                *candidate_token,
                *expected_request_version,
            )
            .await?;
            let Some(selection) = selection else {
                return Ok(ConnectionMutationOutcome::Conflict);
            };
            validate_outbound_ids(context.primary_outbound_id, additional_outbound, *outbounds)?;
            if ContactMode::from_str(&selection.contact_mode).map_err(|error| {
                PersistenceError::Invariant(format!("contact mode is invalid: {error}"))
            })? == ContactMode::Direct
            {
                let mut normalized_outbounds = *outbounds;
                normalized_outbounds.customer_contact = Some(context.primary_outbound_id);
                reveal_contact(
                    transaction,
                    context,
                    selection,
                    *reveal_id,
                    *reveal_token,
                    None,
                    context.inbound_event_id,
                    normalized_outbounds,
                    pause_notification.as_ref(),
                    additional_outbound,
                )
                .await
            } else {
                create_connection_request(
                    transaction,
                    context,
                    selection,
                    *connection_id,
                    *connection_token,
                    *outbounds,
                    additional_outbound,
                )
                .await
            }
        }
        ConnectionTurnOperation::Respond {
            connection_token,
            expected_version,
            accept,
            reveal_id,
            reveal_token,
            outbounds,
            pause_notification,
        } => {
            let mut normalized_outbounds = *outbounds;
            if *accept {
                normalized_outbounds.professional_contact = Some(context.primary_outbound_id);
            }
            respond(
                transaction,
                context,
                *connection_token,
                *expected_version,
                *accept,
                *reveal_id,
                *reveal_token,
                normalized_outbounds,
                pause_notification.as_ref(),
                additional_outbound,
            )
            .await
        }
        ConnectionTurnOperation::Cancel {
            connection_token,
            expected_version,
        } => cancel_connection(transaction, context, *connection_token, *expected_version).await,
        ConnectionTurnOperation::Repeat {
            reveal_token,
            outbounds,
        } => {
            repeat_reveal(
                transaction,
                context,
                *reveal_token,
                *outbounds,
                additional_outbound,
            )
            .await
        }
    }
}

async fn connection_command_matches_session(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    context: ConnectionEffectContext<'_>,
    effect: &ConnectionTurnEffect,
) -> Result<bool, PersistenceError> {
    let (workflow, state_key, token, version, decision): (
        &str,
        &str,
        String,
        Option<i64>,
        Option<bool>,
    ) = match &effect.operation {
        ConnectionTurnOperation::Select {
            request_token,
            candidate_token,
            expected_request_version,
            ..
        } => (
            "customer.discovery",
            "confirm_selection",
            format!("{}:{}", request_token, candidate_token),
            Some(*expected_request_version),
            None,
        ),
        ConnectionTurnOperation::Respond {
            connection_token,
            expected_version,
            accept,
            ..
        } => (
            "professional.requests",
            "confirm",
            connection_token.to_string(),
            Some(*expected_version),
            Some(*accept),
        ),
        ConnectionTurnOperation::Cancel {
            connection_token,
            expected_version,
        } => (
            "customer.discovery",
            "waiting",
            connection_token.to_string(),
            Some(*expected_version),
            None,
        ),
        ConnectionTurnOperation::Repeat { reveal_token, .. } => (
            "customer.discovery",
            "recent",
            reveal_token.to_string(),
            None,
            None,
        ),
    };
    sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM messaging.conversation_sessions AS session
            WHERE session.account_id = $1 AND session.channel_identity_id = $2
              AND session.status = 'active' AND session.workflow_key = $3
              AND session.state_key = $4
              AND (
                  ($3 = 'customer.discovery' AND $4 = 'confirm_selection'
                   AND (session.state_data ->> 'request_token') || ':' ||
                       (session.state_data ->> 'candidate_token') = $5
                   AND (session.state_data ->> 'request_version')::bigint = $6)
                  OR ($3 = 'professional.requests' AND $4 = 'confirm'
                      AND (session.state_data ->> 'request_token') = $5
                      AND (session.state_data ->> 'request_version')::bigint = $6
                      AND (session.state_data ->> 'accept')::boolean = $7)
                  OR ($3 = 'customer.discovery' AND $4 = 'waiting'
                      AND (session.state_data ->> 'request_token') = $5
                      AND (session.state_data ->> 'request_version')::bigint = $6)
                  OR ($3 = 'customer.discovery' AND $4 = 'recent' AND $5 IS NOT NULL)
              )
        )
        "#,
    )
    .bind(context.account_id.into_uuid())
    .bind(context.channel_identity_id.into_uuid())
    .bind(workflow)
    .bind(state_key)
    .bind(token)
    .bind(version)
    .bind(decision)
    .fetch_one(&mut **transaction)
    .await
    .map_err(PersistenceError::from)
}

async fn repeat_reveal(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    context: ConnectionEffectContext<'_>,
    reveal_token: Uuid,
    mut outbounds: ConnectionOutboundIds,
    additional_outbound: &[QueueOutboundMessage],
) -> Result<ConnectionMutationOutcome, PersistenceError> {
    let reveal: Option<(Uuid, Uuid)> = sqlx::query_as(
        r#"
        SELECT reveal.id, reveal.professional_account_id
        FROM connection.contact_reveals AS reveal
        LEFT JOIN connection.reveal_reversals AS reversal ON reversal.reveal_id = reveal.id
        WHERE reveal.reveal_token = $1 AND reveal.customer_account_id = $2
          AND reversal.id IS NULL
        "#,
    )
    .bind(reveal_token)
    .bind(context.account_id.into_uuid())
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((reveal_id, professional_id)) = reveal else {
        return Ok(ConnectionMutationOutcome::Conflict);
    };
    lock_account_pair(
        transaction,
        context.account_id,
        AccountId::from_uuid(professional_id),
    )
    .await?;
    let accounts_eligible: bool = sqlx::query_scalar(
        r#"
        SELECT
            EXISTS (SELECT 1 FROM identity.accounts WHERE id = $1
                    AND status IN ('pending','active') AND risk_state = 'normal')
            AND
            EXISTS (SELECT 1 FROM identity.accounts WHERE id = $2
                    AND status = 'active' AND risk_state = 'normal'
                    AND NOT safety.account_is_restricted(id))
        "#,
    )
    .bind(context.account_id.into_uuid())
    .bind(professional_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !accounts_eligible {
        return Ok(ConnectionMutationOutcome::Ineligible);
    }
    if pair_blocked(transaction, context.account_id.into_uuid(), professional_id).await? {
        return Ok(ConnectionMutationOutcome::Ineligible);
    }
    outbounds.customer_contact = Some(context.primary_outbound_id);
    validate_reveal_outbounds(
        context.primary_outbound_id,
        context.primary_outbound_recipient,
        additional_outbound,
        outbounds,
        context.account_id.into_uuid(),
        professional_id,
        transaction,
    )
    .await?;
    for (message_id, purpose) in [
        (outbounds.customer_contact, "contact_detail"),
        (outbounds.photo, "profile_photo"),
    ] {
        if let Some(message_id) = message_id {
            sqlx::query(
                "INSERT INTO messaging.outbound_message_subjects (outbound_message_id, account_id, purpose) VALUES ($1, $2, $3)",
            )
            .bind(message_id.into_uuid())
            .bind(professional_id)
            .bind(purpose)
            .execute(&mut **transaction)
            .await?;
        }
    }
    append_connection_audit(
        transaction,
        Some(context.account_id),
        Some(context.channel_identity_id),
        "contact.reaccessed",
        reveal_id,
        "previously_revealed",
        context.correlation_id,
    )
    .await?;
    Ok(ConnectionMutationOutcome::PreviouslyRevealed)
}

#[allow(clippy::too_many_arguments)]
async fn reveal_contact(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    context: ConnectionEffectContext<'_>,
    selection: SelectionRow,
    reveal_id: ContactRevealId,
    reveal_token: Uuid,
    connection_id: Option<ConnectionRequestId>,
    customer_consent_event_id: InboundEventId,
    outbounds: ConnectionOutboundIds,
    pause_notification: Option<&QueueOutboundMessage>,
    additional_outbound: &[QueueOutboundMessage],
) -> Result<ConnectionMutationOutcome, PersistenceError> {
    lock_account_pair(
        transaction,
        AccountId::from_uuid(selection.customer_account_id),
        AccountId::from_uuid(selection.professional_account_id),
    )
    .await?;
    let accounts_eligible: bool = sqlx::query_scalar(
        r#"
        SELECT
            EXISTS (SELECT 1 FROM identity.accounts WHERE id = $1
                    AND status IN ('pending','active') AND risk_state = 'normal')
            AND
            EXISTS (SELECT 1 FROM identity.accounts WHERE id = $2
                    AND status = 'active' AND risk_state = 'normal'
                    AND NOT safety.account_is_restricted(id)
                    AND (
                        billing.professional_is_eligible(id)
                        OR billing.reservation_matches(id, $3)
                    ))
        "#,
    )
    .bind(selection.customer_account_id)
    .bind(selection.professional_account_id)
    .bind(connection_id.map(ConnectionRequestId::into_uuid))
    .fetch_one(&mut **transaction)
    .await?;
    if !accounts_eligible {
        return Ok(ConnectionMutationOutcome::Ineligible);
    }
    if pair_blocked(
        transaction,
        selection.customer_account_id,
        selection.professional_account_id,
    )
    .await?
    {
        return Ok(ConnectionMutationOutcome::Ineligible);
    }
    validate_reveal_outbounds(
        context.primary_outbound_id,
        context.primary_outbound_recipient,
        additional_outbound,
        outbounds,
        selection.customer_account_id,
        selection.professional_account_id,
        transaction,
    )
    .await?;
    if let Some(existing) = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT reveal.id FROM connection.contact_reveals AS reveal
        LEFT JOIN connection.reveal_reversals AS reversal ON reversal.reveal_id = reveal.id
        WHERE reveal.customer_account_id = $1 AND reveal.professional_account_id = $2
          AND reversal.id IS NULL
        "#,
    )
    .bind(selection.customer_account_id)
    .bind(selection.professional_account_id)
    .fetch_optional(&mut **transaction)
    .await?
    {
        mark_request_connected(transaction, selection.request_id, selection.candidate_id).await?;
        insert_subject_links(
            transaction,
            outbounds,
            selection.customer_account_id,
            selection.professional_account_id,
        )
        .await?;
        if let Some(connection_id) = connection_id {
            sqlx::query(
                "UPDATE connection.connection_requests SET status = 'disclosed', disclosure_id = $2, responded_at = COALESCE(responded_at, clock_timestamp()) WHERE id = $1",
            )
            .bind(connection_id.into_uuid())
            .bind(existing)
            .execute(&mut **transaction)
            .await?;
        }
        return Ok(ConnectionMutationOutcome::PreviouslyRevealed);
    }
    let allowance_remaining: i16 =
        sqlx::query_scalar("SELECT connection.customer_reveal_allowance_remaining($1)")
            .bind(selection.customer_account_id)
            .fetch_one(&mut **transaction)
            .await?;
    if allowance_remaining <= 0 {
        return Ok(ConnectionMutationOutcome::LimitReached);
    }
    let consumption = consume_capacity_in_transaction(
        transaction,
        AvailabilityEpochId::from_uuid(selection.availability_epoch_id),
        reveal_id.into_uuid(),
        &selection.category_code,
        context.correlation_id,
        pause_notification,
    )
    .await?;
    let consumption_id = match consumption {
        CapacityConsumptionOutcome::Consumed { consumption_id, .. } => consumption_id,
        CapacityConsumptionOutcome::AlreadyConsumed => {
            return Err(PersistenceError::Invariant(
                "contact reveal capacity was already consumed without a reveal".to_owned(),
            ));
        }
        CapacityConsumptionOutcome::Denied => {
            return Ok(ConnectionMutationOutcome::ProfessionalAtCapacity);
        }
    };
    let audit_id = append_connection_audit(
        transaction,
        Some(context.account_id),
        Some(context.channel_identity_id),
        "contact.revealed",
        reveal_id.into_uuid(),
        if connection_id.is_some() {
            "professional_accepted"
        } else {
            "direct_contact"
        },
        context.correlation_id,
    )
    .await?;
    sqlx::query(
        r#"
        INSERT INTO connection.contact_reveals (
            id, reveal_token, customer_account_id, professional_account_id, provider_service_id,
            service_request_id, connection_request_id, availability_epoch_id,
            availability_consumption_id, disclosure_reason,
            customer_consent_inbound_event_id, professional_consent_basis,
            allowance_consumed, audit_event_id, correlation_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, true, $13, $14)
        "#,
    )
    .bind(reveal_id.into_uuid())
    .bind(reveal_token)
    .bind(selection.customer_account_id)
    .bind(selection.professional_account_id)
    .bind(selection.provider_service_id)
    .bind(selection.request_id)
    .bind(connection_id.map(ConnectionRequestId::into_uuid))
    .bind(selection.availability_epoch_id)
    .bind(consumption_id.into_uuid())
    .bind(if connection_id.is_some() {
        "professional_accepted"
    } else {
        "direct_contact"
    })
    .bind(customer_consent_event_id.into_uuid())
    .bind(if connection_id.is_some() {
        "connection_acceptance"
    } else {
        "direct_contact_consent"
    })
    .bind(audit_id.into_uuid())
    .bind(context.correlation_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    let allowance_id = CustomerAllowanceEventId::new();
    let allowance_audit = append_connection_audit(
        transaction,
        None,
        None,
        "customer.allowance_consumed",
        allowance_id.into_uuid(),
        "new_professional_reveal",
        context.correlation_id,
    )
    .await?;
    sqlx::query(
        "INSERT INTO connection.customer_allowance_events (id, customer_account_id, reveal_id, audit_event_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(allowance_id.into_uuid())
    .bind(selection.customer_account_id)
    .bind(reveal_id.into_uuid())
    .bind(allowance_audit.into_uuid())
    .execute(&mut **transaction)
    .await?;
    let customer_contains_contact = outbounds.customer_contact.is_some();
    let professional_contains_contact = outbounds.professional_contact.is_some();
    sqlx::query(
        r#"
        INSERT INTO connection.contact_reveal_delivery (
            reveal_id, customer_outbound_message_id, professional_outbound_message_id,
            photo_outbound_message_id, customer_contains_contact, professional_contains_contact
        ) VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(reveal_id.into_uuid())
    .bind(outbounds.customer_contact.map(OutboundMessageId::into_uuid))
    .bind(
        outbounds
            .professional_contact
            .map(OutboundMessageId::into_uuid),
    )
    .bind(outbounds.photo.map(OutboundMessageId::into_uuid))
    .bind(customer_contains_contact)
    .bind(professional_contains_contact)
    .execute(&mut **transaction)
    .await?;
    insert_subject_links(
        transaction,
        outbounds,
        selection.customer_account_id,
        selection.professional_account_id,
    )
    .await?;
    validate_reveal_outbounds(
        context.primary_outbound_id,
        context.primary_outbound_recipient,
        additional_outbound,
        outbounds,
        selection.customer_account_id,
        selection.professional_account_id,
        transaction,
    )
    .await?;
    mark_request_connected(transaction, selection.request_id, selection.candidate_id).await?;
    if let Some(connection_id) = connection_id {
        sqlx::query(
            "UPDATE connection.connection_requests SET status = 'disclosed', disclosure_id = $2, responded_at = COALESCE(responded_at, clock_timestamp()) WHERE id = $1",
        )
        .bind(connection_id.into_uuid())
        .bind(reveal_id.into_uuid())
        .execute(&mut **transaction)
        .await?;
    }
    Ok(ConnectionMutationOutcome::DirectRevealed)
}

async fn create_connection_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    context: ConnectionEffectContext<'_>,
    selection: SelectionRow,
    connection_id: ConnectionRequestId,
    connection_token: Uuid,
    outbounds: ConnectionOutboundIds,
    additional_outbound: &[QueueOutboundMessage],
) -> Result<ConnectionMutationOutcome, PersistenceError> {
    lock_account_pair(
        transaction,
        AccountId::from_uuid(selection.customer_account_id),
        AccountId::from_uuid(selection.professional_account_id),
    )
    .await?;
    let eligible: bool = sqlx::query_scalar(
        r#"
        SELECT
            EXISTS (SELECT 1 FROM identity.accounts WHERE id = $1
                    AND status IN ('pending','active') AND risk_state = 'normal')
            AND
            EXISTS (SELECT 1 FROM identity.accounts WHERE id = $2
                    AND status = 'active' AND risk_state = 'normal'
                    AND NOT safety.account_is_restricted(id)
                    AND billing.professional_is_eligible(id))
        "#,
    )
    .bind(selection.customer_account_id)
    .bind(selection.professional_account_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !eligible {
        return Ok(ConnectionMutationOutcome::Ineligible);
    }
    if pair_blocked(
        transaction,
        selection.customer_account_id,
        selection.professional_account_id,
    )
    .await?
    {
        return Ok(ConnectionMutationOutcome::Ineligible);
    }
    let notification_id = outbounds.professional_notification.ok_or_else(|| {
        PersistenceError::InvalidCommand(
            "approval-required request needs a professional notification".to_owned(),
        )
    })?;
    let notification = additional_outbound_by_id(additional_outbound, notification_id)?;
    validate_channel_owner(
        transaction,
        notification.recipient_channel_identity_id,
        selection.professional_account_id,
    )
    .await?;
    let deadline: OffsetDateTime =
        sqlx::query_scalar("SELECT clock_timestamp() + INTERVAL '10 minutes'")
            .fetch_one(&mut **transaction)
            .await?;
    sqlx::query(
        r#"
        INSERT INTO connection.connection_requests (
            id, request_token, service_request_id, candidate_id, provider_service_id,
            customer_account_id, professional_account_id, contact_mode,
            source_inbound_event_id, response_deadline, expires_at,
            correlation_id, request_outbound_message_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'approval_required',
                $8, $9, $9, $10, $11)
        "#,
    )
    .bind(connection_id.into_uuid())
    .bind(connection_token)
    .bind(selection.request_id)
    .bind(selection.candidate_id)
    .bind(selection.provider_service_id)
    .bind(selection.customer_account_id)
    .bind(selection.professional_account_id)
    .bind(context.inbound_event_id.into_uuid())
    .bind(deadline)
    .bind(context.correlation_id.into_uuid())
    .bind(notification_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        INSERT INTO integration.outbox_jobs (
            id, connection_request_id, connection_generation, job_kind,
            idempotency_key, payload_version, payload, available_at,
            max_attempts, correlation_id, ordering_key
        ) VALUES (
            $1, $2, 1, 'expire_connection_request', $3, 1,
            jsonb_build_object('connection_request_id', $2::text, 'generation', 1),
            $4, 8, $5, NULL
        )
        "#,
    )
    .bind(OutboxJobId::new().into_uuid())
    .bind(connection_id.into_uuid())
    .bind(format!("connection-expire:v1:{connection_id}:g1"))
    .bind(deadline)
    .bind(context.correlation_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE discovery.request_candidates SET selected_at = clock_timestamp() WHERE id = $1",
    )
    .bind(selection.candidate_id)
    .execute(&mut **transaction)
    .await?;
    sqlx::query("UPDATE discovery.service_requests SET status = 'selected' WHERE id = $1")
        .bind(selection.request_id)
        .execute(&mut **transaction)
        .await?;
    append_connection_audit(
        transaction,
        Some(context.account_id),
        Some(context.channel_identity_id),
        "connection.requested",
        connection_id.into_uuid(),
        "approval_required",
        context.correlation_id,
    )
    .await?;
    Ok(ConnectionMutationOutcome::RequestCreated)
}

#[allow(clippy::too_many_arguments)]
async fn respond(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    context: ConnectionEffectContext<'_>,
    token: Uuid,
    expected_version: i64,
    accept: bool,
    reveal_id: ContactRevealId,
    reveal_token: Uuid,
    outbounds: ConnectionOutboundIds,
    pause_notification: Option<&QueueOutboundMessage>,
    additional_outbound: &[QueueOutboundMessage],
) -> Result<ConnectionMutationOutcome, PersistenceError> {
    let connection: Option<(Uuid, Uuid, Uuid, Uuid, Uuid)> = sqlx::query_as(
        r#"
        SELECT id, customer_account_id, candidate_id, service_request_id, source_inbound_event_id
        FROM connection.connection_requests
        WHERE request_token = $1 AND professional_account_id = $2
          AND version = $3 AND status = 'pending'
          AND response_deadline > clock_timestamp()
        FOR UPDATE
        "#,
    )
    .bind(token)
    .bind(context.account_id.into_uuid())
    .bind(expected_version)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((
        connection_id,
        customer_account_id,
        candidate_id,
        service_request_id,
        customer_consent_event_id,
    )) = connection
    else {
        return Ok(ConnectionMutationOutcome::Conflict);
    };
    if !accept {
        sqlx::query(
            "UPDATE connection.connection_requests SET status = 'declined', responded_at = clock_timestamp() WHERE id = $1",
        )
        .bind(connection_id)
        .execute(&mut **transaction)
        .await?;
        reset_request_after_connection(transaction, service_request_id, Some(candidate_id)).await?;
        append_connection_audit(
            transaction,
            Some(context.account_id),
            Some(context.channel_identity_id),
            "connection.declined",
            connection_id,
            "professional_declined",
            context.correlation_id,
        )
        .await?;
        return Ok(ConnectionMutationOutcome::Declined);
    }
    let selection = load_selection_by_candidate(
        transaction,
        AccountId::from_uuid(customer_account_id),
        candidate_id,
    )
    .await?
    .ok_or_else(|| PersistenceError::Invariant("accepted candidate is missing".to_owned()))?;
    reveal_contact(
        transaction,
        context,
        selection,
        reveal_id,
        reveal_token,
        Some(ConnectionRequestId::from_uuid(connection_id)),
        InboundEventId::from_uuid(customer_consent_event_id),
        outbounds,
        pause_notification,
        additional_outbound,
    )
    .await
    .map(|outcome| match outcome {
        ConnectionMutationOutcome::DirectRevealed => ConnectionMutationOutcome::Accepted,
        other => other,
    })
}

async fn cancel_connection(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    context: ConnectionEffectContext<'_>,
    token: Uuid,
    expected_version: i64,
) -> Result<ConnectionMutationOutcome, PersistenceError> {
    let updated: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
        r#"
        UPDATE connection.connection_requests
        SET status = 'cancelled', cancelled_at = clock_timestamp(),
            cancellation_reason = 'customer_cancelled'
        WHERE request_token = $1 AND customer_account_id = $2
          AND version = $3 AND status = 'pending'
        RETURNING service_request_id, candidate_id
        "#,
    )
    .bind(token)
    .bind(context.account_id.into_uuid())
    .bind(expected_version)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((request_id, candidate_id)) = updated else {
        return Ok(ConnectionMutationOutcome::Conflict);
    };
    reset_request_after_connection(transaction, request_id, candidate_id).await?;
    Ok(ConnectionMutationOutcome::Cancelled)
}

async fn reset_request_after_connection(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: Uuid,
    candidate_id: Option<Uuid>,
) -> Result<(), PersistenceError> {
    sqlx::query(
        "UPDATE discovery.service_requests SET status = 'showing_results' WHERE id = $1 AND status = 'selected'",
    )
    .bind(request_id)
    .execute(&mut **transaction)
    .await?;
    if let Some(candidate_id) = candidate_id {
        sqlx::query("UPDATE discovery.request_candidates SET selected_at = NULL, excluded_at = clock_timestamp(), exclusion_reason = 'connection_not_accepted' WHERE id = $1")
            .bind(candidate_id)
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

async fn lock_selection(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    customer_account_id: AccountId,
    request_token: Uuid,
    candidate_token: Uuid,
    expected_request_version: i64,
) -> Result<Option<SelectionRow>, PersistenceError> {
    let candidate: Option<Uuid> = sqlx::query_scalar(
        r#"
        SELECT candidate.id
        FROM discovery.request_candidates AS candidate
        JOIN discovery.service_requests AS request ON request.id = candidate.request_id
        WHERE request.request_token = $1 AND request.customer_account_id = $2
          AND request.version = $3 AND request.status IN ('showing_results', 'selected')
          AND request.expires_at > clock_timestamp()
          AND candidate.candidate_token = $4 AND candidate.shown_at IS NOT NULL
          AND candidate.excluded_at IS NULL
        FOR UPDATE OF request, candidate
        "#,
    )
    .bind(request_token)
    .bind(customer_account_id.into_uuid())
    .bind(expected_request_version)
    .bind(candidate_token)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    load_selection_by_candidate(transaction, customer_account_id, candidate).await
}

async fn load_selection_by_candidate(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    customer_account_id: AccountId,
    candidate_id: Uuid,
) -> Result<Option<SelectionRow>, PersistenceError> {
    sqlx::query_as::<_, SelectionRow>(
        r#"
        SELECT request.id AS request_id, request.request_token, request.version AS request_version,
               candidate.id AS candidate_id, candidate.candidate_token,
               candidate.provider_service_id, candidate.availability_epoch_id,
               candidate.professional_account_id, request.customer_account_id,
               provider.category_code, COALESCE(request.issue_code, 'other') AS issue_code,
               COALESCE(request.requested_time, 'flexible') AS requested_time,
               candidate.distance_metres, service.contact_mode,
               candidate.profile_revision_id, epoch.contact_count, epoch.contact_limit
        FROM discovery.request_candidates AS candidate
        JOIN discovery.service_requests AS request ON request.id = candidate.request_id
        JOIN profile.provider_services AS provider ON provider.id = candidate.provider_service_id
        JOIN profile.professional_services AS service
          ON service.revision_id = candidate.profile_revision_id
         AND service.category_code = provider.category_code
        JOIN availability.epochs AS epoch ON epoch.id = candidate.availability_epoch_id
        WHERE candidate.id = $1 AND request.customer_account_id = $2
          AND availability.epoch_is_effective(candidate.availability_epoch_id)
        "#,
    )
    .bind(candidate_id)
    .bind(customer_account_id.into_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(PersistenceError::from)
}

async fn load_selection<'e, E>(
    executor: E,
    customer_account_id: AccountId,
    candidate_token: Uuid,
    _lock: bool,
) -> Result<Option<SelectionRow>, PersistenceError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_as::<_, SelectionRow>(
        r#"
        SELECT request.id AS request_id, request.request_token, request.version AS request_version,
               candidate.id AS candidate_id, candidate.candidate_token,
               candidate.provider_service_id, candidate.availability_epoch_id,
               candidate.professional_account_id, request.customer_account_id,
               provider.category_code, COALESCE(request.issue_code, 'other') AS issue_code,
               COALESCE(request.requested_time, 'flexible') AS requested_time,
               candidate.distance_metres, service.contact_mode,
               candidate.profile_revision_id, epoch.contact_count, epoch.contact_limit
        FROM discovery.request_candidates AS candidate
        JOIN discovery.service_requests AS request ON request.id = candidate.request_id
        JOIN profile.provider_services AS provider ON provider.id = candidate.provider_service_id
        JOIN profile.professional_services AS service
          ON service.revision_id = candidate.profile_revision_id
         AND service.category_code = provider.category_code
        JOIN availability.epochs AS epoch ON epoch.id = candidate.availability_epoch_id
        WHERE candidate.candidate_token = $1 AND request.customer_account_id = $2
          AND candidate.shown_at IS NOT NULL AND candidate.excluded_at IS NULL
          AND request.expires_at > statement_timestamp()
        "#,
    )
    .bind(candidate_token)
    .bind(customer_account_id.into_uuid())
    .fetch_optional(executor)
    .await
    .map_err(PersistenceError::from)
}

pub(crate) async fn load_contact_target<'e, E>(
    executor: E,
    account_id: Uuid,
) -> Result<Option<ContactTarget>, PersistenceError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query_as::<_, TargetRow>(
        r#"
        SELECT account.id AS account_id, channel.id AS channel_identity_id,
               channel.provider_namespace, account.preferred_locale AS locale,
               whatsapp.phone_e164_ciphertext, whatsapp.phone_e164_nonce,
               whatsapp.encryption_key_version
        FROM identity.accounts AS account
        JOIN identity.channel_identities AS channel
          ON channel.account_id = account.id AND channel.provider_code = 'whatsapp'
         AND channel.status = 'active' AND channel.verified_at IS NOT NULL
        JOIN private_data.whatsapp_identities AS whatsapp
          ON whatsapp.channel_identity_id = channel.id
         AND whatsapp.opt_in_status <> 'opted_out'
         AND whatsapp.delivery_state <> 'unreachable'
         AND whatsapp.blocked_at IS NULL
        WHERE account.id = $1 AND account.status IN ('pending','active')
          AND account.risk_state = 'normal'
        ORDER BY channel.last_seen_at DESC, channel.id LIMIT 1
        "#,
    )
    .bind(account_id)
    .fetch_optional(executor)
    .await?;
    row.map(map_target).transpose()
}

async fn load_contact_photo<'e, E>(
    executor: E,
    revision_id: Uuid,
) -> Result<Option<ContactPhoto>, PersistenceError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query_as::<_, PhotoRow>(
        r#"
        SELECT photo.id, photo.sanitized_ciphertext, photo.sanitized_nonce,
               photo.encryption_key_version
        FROM profile.profile_revision_photos AS link
        JOIN private_data.profile_photos AS photo ON photo.id = link.photo_id
        WHERE link.revision_id = $1 AND photo.state = 'ready'
        "#,
    )
    .bind(revision_id)
    .fetch_optional(executor)
    .await?;
    row.map(|row| {
        Ok(ContactPhoto {
            photo_id: ProfilePhotoId::from_uuid(row.id),
            encrypted_jpeg: EncryptedValue {
                purpose: EncryptionPurpose::Media,
                key_version: row.encryption_key_version,
                nonce: row.sanitized_nonce.try_into().map_err(|_| {
                    PersistenceError::Invariant("contact photo nonce is invalid".to_owned())
                })?,
                ciphertext: row.sanitized_ciphertext,
            },
        })
    })
    .transpose()
}

fn map_target(row: TargetRow) -> Result<ContactTarget, PersistenceError> {
    Ok(ContactTarget {
        account_id: AccountId::from_uuid(row.account_id),
        channel_identity_id: ChannelIdentityId::from_uuid(row.channel_identity_id),
        provider_namespace: row.provider_namespace,
        locale: row.locale,
        encrypted_phone: EncryptedValue {
            purpose: EncryptionPurpose::Contact,
            key_version: row.encryption_key_version,
            nonce: row.phone_e164_nonce.try_into().map_err(|_| {
                PersistenceError::Invariant("contact phone nonce is invalid".to_owned())
            })?,
            ciphertext: row.phone_e164_ciphertext,
        },
    })
}

async fn lock_account_pair(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    first: AccountId,
    second: AccountId,
) -> Result<(), PersistenceError> {
    let (low, high) = if first.into_uuid() < second.into_uuid() {
        (first, second)
    } else {
        (second, first)
    };
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("{}:{}", low, high))
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT id FROM identity.accounts WHERE id = ANY($1) ORDER BY id FOR UPDATE")
        .bind(vec![low.into_uuid(), high.into_uuid()])
        .fetch_all(&mut **transaction)
        .await?;
    Ok(())
}

async fn pair_blocked(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    first: Uuid,
    second: Uuid,
) -> Result<bool, PersistenceError> {
    sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM identity.account_blocks
            WHERE removed_at IS NULL
              AND ((actor_account_id = $1 AND blocked_account_id = $2)
                OR (actor_account_id = $2 AND blocked_account_id = $1))
        )
        "#,
    )
    .bind(first)
    .bind(second)
    .fetch_one(&mut **transaction)
    .await
    .map_err(PersistenceError::from)
}

fn validate_outbound_ids(
    primary: OutboundMessageId,
    additional: &[QueueOutboundMessage],
    ids: ConnectionOutboundIds,
) -> Result<(), PersistenceError> {
    for id in [
        ids.customer_contact,
        ids.professional_contact,
        ids.professional_notification,
        ids.photo,
    ]
    .into_iter()
    .flatten()
    {
        if id != primary && !additional.iter().any(|message| message.id == id) {
            return Err(PersistenceError::InvalidCommand(
                "connection outbound reference is not part of the atomic turn".to_owned(),
            ));
        }
    }
    Ok(())
}

fn additional_outbound_by_id(
    additional: &[QueueOutboundMessage],
    id: OutboundMessageId,
) -> Result<&QueueOutboundMessage, PersistenceError> {
    additional
        .iter()
        .find(|message| message.id == id)
        .ok_or_else(|| {
            PersistenceError::InvalidCommand(
                "connection notification is not part of the atomic turn".to_owned(),
            )
        })
}

async fn validate_channel_owner(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    channel_id: Option<ChannelIdentityId>,
    account_id: Uuid,
) -> Result<(), PersistenceError> {
    let channel_id = channel_id.ok_or_else(|| {
        PersistenceError::InvalidCommand("connection recipient is missing".to_owned())
    })?;
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM identity.channel_identities WHERE id = $1 AND account_id = $2 AND status = 'active')",
    )
    .bind(channel_id.into_uuid())
    .bind(account_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !valid {
        return Err(PersistenceError::InvalidCommand(
            "connection recipient does not belong to its account".to_owned(),
        ));
    }
    Ok(())
}

async fn validate_reveal_outbounds(
    primary: OutboundMessageId,
    primary_recipient: Option<ChannelIdentityId>,
    additional: &[QueueOutboundMessage],
    ids: ConnectionOutboundIds,
    customer_account_id: Uuid,
    professional_account_id: Uuid,
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), PersistenceError> {
    validate_outbound_ids(primary, additional, ids)?;
    if ids.customer_contact.is_none() {
        return Err(PersistenceError::InvalidCommand(
            "contact reveal requires a customer delivery".to_owned(),
        ));
    }
    for (id, expected_account) in [
        (ids.customer_contact, customer_account_id),
        (ids.professional_contact, professional_account_id),
        (ids.professional_notification, professional_account_id),
        (ids.photo, customer_account_id),
    ] {
        if let Some(id) = id {
            let message = if id == primary {
                if primary_recipient.is_none() {
                    return Err(PersistenceError::InvalidCommand(
                        "primary connection recipient is missing".to_owned(),
                    ));
                }
                None
            } else {
                additional.iter().find(|value| value.id == id)
            };
            let channel = if id == primary {
                primary_recipient
            } else {
                message.and_then(|value| value.recipient_channel_identity_id)
            };
            let channel = channel.ok_or_else(|| {
                PersistenceError::InvalidCommand("connection recipient is missing".to_owned())
            })?;
            let valid: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM identity.channel_identities WHERE id = $1 AND account_id = $2)",
            )
            .bind(channel.into_uuid())
            .bind(expected_account)
            .fetch_one(&mut **transaction)
            .await?;
            if !valid {
                return Err(PersistenceError::InvalidCommand(
                    "connection outbound recipient does not match its subject".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

async fn insert_subject_links(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    outbounds: ConnectionOutboundIds,
    customer_account_id: Uuid,
    professional_account_id: Uuid,
) -> Result<(), PersistenceError> {
    for (message_id, subject_id, purpose) in [
        (
            outbounds.customer_contact,
            professional_account_id,
            "contact_detail",
        ),
        (
            outbounds.professional_contact,
            customer_account_id,
            "contact_detail",
        ),
        (outbounds.photo, professional_account_id, "profile_photo"),
    ] {
        if let Some(message_id) = message_id {
            sqlx::query(
                "INSERT INTO messaging.outbound_message_subjects (outbound_message_id, account_id, purpose) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            )
            .bind(message_id.into_uuid())
            .bind(subject_id)
            .bind(purpose)
            .execute(&mut **transaction)
            .await?;
        }
    }
    Ok(())
}

async fn mark_request_connected(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: Uuid,
    candidate_id: Uuid,
) -> Result<(), PersistenceError> {
    sqlx::query("UPDATE discovery.request_candidates SET selected_at = COALESCE(selected_at, clock_timestamp()) WHERE id = $1")
        .bind(candidate_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("UPDATE discovery.service_requests SET status = 'connected' WHERE id = $1")
        .bind(request_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn append_connection_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_account_id: Option<AccountId>,
    actor_channel_id: Option<ChannelIdentityId>,
    action: &str,
    target_id: Uuid,
    reason: &str,
    correlation_id: CorrelationId,
) -> Result<AuditEventId, PersistenceError> {
    let id = AuditEventId::new();
    sqlx::query(
        r#"
        INSERT INTO audit.events (
            id, actor_type, actor_account_id, actor_channel_identity_id,
            source_channel, action, target_type, target_id, reason_code,
            metadata, event_schema_version, correlation_id
        ) VALUES (
            $1, CASE WHEN $2::uuid IS NULL THEN 'system' ELSE 'account' END,
            $2, $3, CASE
                WHEN $3::uuid IS NOT NULL THEN 'whatsapp'
                WHEN $2::uuid IS NOT NULL THEN 'internal_cli'
                ELSE 'system'
            END,
            $4, 'connection', $5, $6, '{}'::jsonb, 1, $7
        )
        "#,
    )
    .bind(id.into_uuid())
    .bind(actor_account_id.map(AccountId::into_uuid))
    .bind(actor_channel_id.map(ChannelIdentityId::into_uuid))
    .bind(action)
    .bind(target_id)
    .bind(reason)
    .bind(correlation_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    Ok(id)
}

async fn connection_lease_current(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease: JobLease,
    connection_id: ConnectionRequestId,
    generation: i64,
) -> Result<bool, PersistenceError> {
    sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM integration.outbox_jobs
            WHERE id = $1 AND state = 'leased' AND lease_owner = $2 AND lease_token = $3
              AND lease_expires_at > clock_timestamp()
              AND connection_request_id = $4 AND connection_generation = $5
              AND job_kind = 'expire_connection_request'
        )
        "#,
    )
    .bind(lease.job_id.into_uuid())
    .bind(lease.worker_id.into_uuid())
    .bind(lease.token.into_uuid())
    .bind(connection_id.into_uuid())
    .bind(generation)
    .fetch_one(&mut **transaction)
    .await
    .map_err(PersistenceError::from)
}

async fn complete_connection_job(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease: JobLease,
) -> Result<LeaseOutcome, PersistenceError> {
    let updated = sqlx::query(
        r#"
        UPDATE integration.outbox_jobs
        SET state = 'completed', lease_owner = NULL, lease_token = NULL,
            lease_started_at = NULL, lease_expires_at = NULL,
            completed_at = clock_timestamp()
        WHERE id = $1 AND state = 'leased' AND lease_owner = $2 AND lease_token = $3
        "#,
    )
    .bind(lease.job_id.into_uuid())
    .bind(lease.worker_id.into_uuid())
    .bind(lease.token.into_uuid())
    .execute(&mut **transaction)
    .await?;
    Ok(if updated.rows_affected() == 1 {
        LeaseOutcome::Applied
    } else {
        LeaseOutcome::LostLease
    })
}

fn distance_label(distance: i32) -> String {
    if distance < 1_000 {
        "under_1_km"
    } else if distance < 5_000 {
        "under_5_km"
    } else if distance < 10_000 {
        "under_10_km"
    } else {
        "farther"
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::CUSTOMER_FREE_REVEAL_LIMIT;

    #[test]
    fn free_customer_limit_is_exactly_three_new_professionals() {
        assert_eq!(CUSTOMER_FREE_REVEAL_LIMIT, 3);
    }
}
