use crate::{
    AccountSnapshot, ConversationTurnEffects, Database, PersistenceError, QueueOutboundMessage,
    key_registry::{ensure_active_encryption_key, ensure_active_lookup_key},
    turn_effect::{EffectApplyOutcome, EffectContext},
};
use sahayak_cryptography::EncryptionPurpose;
use sahayak_domain::{
    AccountId, AccountLifecycle, AccountRole, ChannelIdentityId, ConversationSessionId,
    ConversationStatus, CorrelationId, InboundEventId, OutboundMessageId, RiskState,
};
use serde_json::Value;
use sqlx::FromRow;
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

/// Persisted active session contract loaded for pure engine decisions.
#[derive(Clone, Debug)]
pub struct PersistedConversationSession {
    pub id: ConversationSessionId,
    pub workflow_key: String,
    pub workflow_version: i16,
    pub state_key: String,
    pub state_data: Value,
    pub language: String,
    pub role_context: AccountRole,
    pub version: i64,
    pub last_inbound_event_id: Option<InboundEventId>,
    pub expected_reply_to_outbound_message_id: Option<OutboundMessageId>,
    pub workflow_correlation_id: CorrelationId,
    pub expires_at: OffsetDateTime,
}

/// Account, session, prompt resolution, and service-window state for one turn.
#[derive(Clone, Debug)]
pub struct ConversationTurnRecord {
    pub account: AccountSnapshot,
    pub active_session: Option<PersistedConversationSession>,
    pub expired_session: Option<(ConversationSessionId, i64)>,
    pub session_expired: bool,
    pub resolved_reply_to: Option<OutboundMessageId>,
    pub service_window_expires_at: OffsetDateTime,
    pub database_now: OffsetDateTime,
}

/// Session mutation committed together with one response.
#[derive(Clone, Debug)]
pub enum ConversationSessionChange {
    Create {
        session_id: ConversationSessionId,
        workflow_key: String,
        workflow_version: i16,
        state_key: String,
        state_data: Value,
        language: String,
        workflow_correlation_id: CorrelationId,
        expires_at: OffsetDateTime,
        expired_session: Option<(ConversationSessionId, i64)>,
    },
    Advance {
        session_id: ConversationSessionId,
        expected_version: i64,
        state_key: String,
        state_data: Value,
        expires_at: OffsetDateTime,
    },
    Replace {
        previous_session_id: ConversationSessionId,
        expected_version: i64,
        terminal_status: ConversationStatus,
        terminal_reason: String,
        session_id: ConversationSessionId,
        workflow_key: String,
        workflow_version: i16,
        state_key: String,
        state_data: Value,
        language: String,
        workflow_correlation_id: CorrelationId,
        expires_at: OffsetDateTime,
    },
}

/// Immutable receipt classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnDisposition {
    Applied,
    Unexpected,
    Stale,
    Recovered,
    Ignored,
}

impl TurnDisposition {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Unexpected => "unexpected",
            Self::Stale => "stale",
            Self::Recovered => "recovered",
            Self::Ignored => "ignored",
        }
    }
}

/// Every value required for an atomic conversation turn.
#[derive(Clone)]
pub struct CommitConversationTurn {
    pub lease: crate::JobLease,
    pub inbound_event_id: InboundEventId,
    pub account_id: AccountId,
    pub channel_identity_id: ChannelIdentityId,
    pub expected_account_version: i64,
    pub workflow_correlation_id: CorrelationId,
    /// Outbound prompt resolved from the provider reply context, if present.
    pub reply_to_outbound_message_id: Option<OutboundMessageId>,
    pub locale_change: Option<String>,
    pub session_change: ConversationSessionChange,
    pub outbound: QueueOutboundMessage,
    pub disposition: TurnDisposition,
}

/// Backward-compatible effectful form of `CommitConversationTurn`.
#[derive(Clone)]
pub struct CommitConversationTurnWithEffects {
    pub turn: CommitConversationTurn,
    pub effects: ConversationTurnEffects,
}

/// Idempotent turn-commit result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnCommitOutcome {
    Committed {
        session_id: ConversationSessionId,
        outbound_message_id: OutboundMessageId,
    },
    AlreadyCommitted {
        session_id: ConversationSessionId,
        outbound_message_id: OutboundMessageId,
    },
    Conflict,
    LostLease,
    ServiceWindowExpired,
}

/// Idempotent result for a turn that may include a business effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectfulTurnCommitOutcome {
    Committed {
        session_id: ConversationSessionId,
        outbound_message_id: OutboundMessageId,
    },
    AlreadyCommitted {
        session_id: ConversationSessionId,
        outbound_message_id: OutboundMessageId,
    },
    Conflict,
    Unauthorized,
    AlreadyDecided,
    Incomplete,
    CustomerLimit,
    ProfessionalCapacity,
    LostLease,
    ServiceWindowExpired,
}

#[derive(FromRow)]
struct AccountRow {
    id: Uuid,
    status: String,
    risk_state: String,
    preferred_locale: String,
    preferred_locale_confirmed_at: Option<OffsetDateTime>,
    time_zone: String,
    version: i64,
    state_changed_at: OffsetDateTime,
}

#[derive(FromRow)]
struct SessionRow {
    id: Uuid,
    workflow_key: String,
    workflow_version: i16,
    state_key: String,
    state_data: Value,
    language: String,
    role_context: String,
    version: i64,
    last_inbound_event_id: Option<Uuid>,
    expected_reply_to_outbound_message_id: Option<Uuid>,
    workflow_correlation_id: Uuid,
    expires_at: OffsetDateTime,
}

#[derive(FromRow)]
struct ReceiptRow {
    next_session_id: Option<Uuid>,
    outbound_message_id: Option<Uuid>,
}

/// Atomic conversation-turn persistence boundary.
#[derive(Clone, Debug)]
pub struct ConversationTurnRepository {
    database: Database,
}

impl ConversationTurnRepository {
    /// Creates a conversation-turn repository.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Loads account, active/expired session, resolved prompt, and service window.
    pub async fn load(
        &self,
        account_id: AccountId,
        channel_identity_id: ChannelIdentityId,
        provider_namespace: &str,
        context_provider_message_id: Option<&str>,
    ) -> Result<ConversationTurnRecord, PersistenceError> {
        let account = sqlx::query_as::<_, AccountRow>(
            r#"
            SELECT
                id, status, risk_state, preferred_locale,
                preferred_locale_confirmed_at, time_zone, version, state_changed_at
            FROM identity.accounts
            WHERE id = $1
            "#,
        )
        .bind(account_id.into_uuid())
        .fetch_one(self.database.pool())
        .await?;
        let session = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT
                id, workflow_key, workflow_version, state_key, state_data, language,
                role_context, version, last_inbound_event_id,
                expected_reply_to_outbound_message_id,
                workflow_correlation_id, expires_at
            FROM messaging.conversation_sessions
            WHERE channel_identity_id = $1
              AND status = 'active'
            "#,
        )
        .bind(channel_identity_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        let now: OffsetDateTime = sqlx::query_scalar("SELECT statement_timestamp()")
            .fetch_one(self.database.pool())
            .await?;
        let (active_session, expired_session, active_was_expired) = match session {
            Some(row) if row.expires_at > now => (Some(map_session(row)?), None, false),
            Some(row) => (
                None,
                Some((ConversationSessionId::from_uuid(row.id), row.version)),
                true,
            ),
            None => (None, None, false),
        };
        let previously_expired = if active_session.is_none() && !active_was_expired {
            sqlx::query_scalar(
                r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM messaging.conversation_sessions
                    WHERE channel_identity_id = $1
                      AND status = 'expired'
                )
                "#,
            )
            .bind(channel_identity_id.into_uuid())
            .fetch_one(self.database.pool())
            .await?
        } else {
            false
        };
        let resolved_reply_to = if let Some(provider_message_id) = context_provider_message_id {
            sqlx::query_scalar(
                r#"
                SELECT id
                FROM messaging.outbound_messages
                WHERE provider_code = 'whatsapp'
                  AND provider_namespace = $1
                  AND recipient_channel_identity_id = $2
                  AND provider_message_id = $3
                "#,
            )
            .bind(provider_namespace)
            .bind(channel_identity_id.into_uuid())
            .bind(provider_message_id)
            .fetch_optional(self.database.pool())
            .await?
            .map(OutboundMessageId::from_uuid)
        } else {
            None
        };
        let service_window_expires_at = sqlx::query_scalar(
            r#"
            SELECT service_window_expires_at
            FROM private_data.whatsapp_identities
            WHERE channel_identity_id = $1
            "#,
        )
        .bind(channel_identity_id.into_uuid())
        .fetch_one(self.database.pool())
        .await?;
        Ok(ConversationTurnRecord {
            account: map_account(account)?,
            active_session,
            expired_session,
            session_expired: active_was_expired || previously_expired,
            resolved_reply_to,
            service_window_expires_at,
            database_now: now,
        })
    }

    /// Commits session, locale, response, receipt, and processing completion atomically.
    pub async fn commit(
        &self,
        input: &CommitConversationTurn,
    ) -> Result<TurnCommitOutcome, PersistenceError> {
        let outcome = self
            .commit_with_effects(input, &ConversationTurnEffects::default())
            .await?;
        Ok(match outcome {
            EffectfulTurnCommitOutcome::Committed {
                session_id,
                outbound_message_id,
            } => TurnCommitOutcome::Committed {
                session_id,
                outbound_message_id,
            },
            EffectfulTurnCommitOutcome::AlreadyCommitted {
                session_id,
                outbound_message_id,
            } => TurnCommitOutcome::AlreadyCommitted {
                session_id,
                outbound_message_id,
            },
            EffectfulTurnCommitOutcome::LostLease => TurnCommitOutcome::LostLease,
            EffectfulTurnCommitOutcome::ServiceWindowExpired => {
                TurnCommitOutcome::ServiceWindowExpired
            }
            EffectfulTurnCommitOutcome::Conflict
            | EffectfulTurnCommitOutcome::Unauthorized
            | EffectfulTurnCommitOutcome::AlreadyDecided
            | EffectfulTurnCommitOutcome::Incomplete
            | EffectfulTurnCommitOutcome::CustomerLimit
            | EffectfulTurnCommitOutcome::ProfessionalCapacity => TurnCommitOutcome::Conflict,
        })
    }

    /// Commits an optional business effect and additional notifications with the turn.
    pub async fn commit_with_effects(
        &self,
        input: &CommitConversationTurn,
        effects: &ConversationTurnEffects,
    ) -> Result<EffectfulTurnCommitOutcome, PersistenceError> {
        validate_commit(input)?;
        validate_effect_envelope(effects)?;
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(input.channel_identity_id.to_string())
            .execute(&mut *transaction)
            .await?;
        if let Some(receipt) = sqlx::query_as::<_, ReceiptRow>(
            r#"
            SELECT next_session_id, outbound_message_id
            FROM messaging.conversation_turn_receipts
            WHERE inbound_event_id = $1
            "#,
        )
        .bind(input.inbound_event_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        {
            transaction.rollback().await?;
            let session_id = receipt.next_session_id.ok_or_else(|| {
                PersistenceError::Invariant("conversation receipt has no session".to_owned())
            })?;
            let outbound_message_id = receipt.outbound_message_id.ok_or_else(|| {
                PersistenceError::Invariant("conversation receipt has no outbound".to_owned())
            })?;
            return Ok(EffectfulTurnCommitOutcome::AlreadyCommitted {
                session_id: ConversationSessionId::from_uuid(session_id),
                outbound_message_id: OutboundMessageId::from_uuid(outbound_message_id),
            });
        }
        let lease_valid: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM integration.outbox_jobs
                WHERE id = $1
                  AND inbound_event_id = $4
                  AND state = 'leased'
                  AND lease_owner = $2
                  AND lease_token = $3
                  AND lease_expires_at > statement_timestamp()
            )
            "#,
        )
        .bind(input.lease.job_id.into_uuid())
        .bind(input.lease.worker_id.into_uuid())
        .bind(input.lease.token.into_uuid())
        .bind(input.inbound_event_id.into_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        if !lease_valid {
            transaction.rollback().await?;
            return Ok(EffectfulTurnCommitOutcome::LostLease);
        }
        let account_version: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT version
            FROM identity.accounts
            WHERE id = $1
              AND status IN ('pending', 'active')
              AND risk_state NOT IN ('restricted', 'blocked')
            FOR UPDATE
            "#,
        )
        .bind(input.account_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        if account_version != Some(input.expected_account_version) {
            transaction.rollback().await?;
            return Ok(EffectfulTurnCommitOutcome::Conflict);
        }
        let channel_ready: Option<bool> = sqlx::query_scalar(
            r#"
            SELECT whatsapp.service_window_expires_at > statement_timestamp()
            FROM identity.channel_identities AS channel
            JOIN private_data.whatsapp_identities AS whatsapp
              ON whatsapp.channel_identity_id = channel.id
            WHERE channel.id = $1
              AND channel.account_id = $2
              AND channel.provider_code = 'whatsapp'
              AND channel.provider_namespace = $3
              AND channel.status = 'active'
            FOR SHARE OF channel, whatsapp
            "#,
        )
        .bind(input.channel_identity_id.into_uuid())
        .bind(input.account_id.into_uuid())
        .bind(&input.outbound.provider_namespace)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(window_open) = channel_ready else {
            transaction.rollback().await?;
            return Ok(EffectfulTurnCommitOutcome::Conflict);
        };
        if !window_open {
            transaction.rollback().await?;
            return Ok(EffectfulTurnCommitOutcome::ServiceWindowExpired);
        }
        if !bind_and_verify_inbound_context(&mut transaction, input).await? {
            transaction.rollback().await?;
            return Ok(EffectfulTurnCommitOutcome::Unauthorized);
        }

        if let Some(effect) = &effects.effect {
            let outcome = crate::turn_effect::apply(
                &mut transaction,
                EffectContext {
                    account_id: input.account_id,
                    channel_identity_id: input.channel_identity_id,
                    inbound_event_id: input.inbound_event_id,
                    provider_namespace: &input.outbound.provider_namespace,
                    correlation_id: input.workflow_correlation_id,
                    primary_outbound_id: input.outbound.id,
                    primary_outbound_recipient: input.outbound.recipient_channel_identity_id,
                    reply_to_outbound_message_id: input.reply_to_outbound_message_id,
                },
                effect,
                &effects.additional_outbound,
            )
            .await;
            let outcome = match outcome {
                Err(PersistenceError::OptimisticConflict) => EffectApplyOutcome::Conflict,
                other => other?,
            };
            let rejection = match outcome {
                EffectApplyOutcome::Applied => None,
                EffectApplyOutcome::Conflict => Some(EffectfulTurnCommitOutcome::Conflict),
                EffectApplyOutcome::Unauthorized => Some(EffectfulTurnCommitOutcome::Unauthorized),
                EffectApplyOutcome::AlreadyDecided => {
                    Some(EffectfulTurnCommitOutcome::AlreadyDecided)
                }
                EffectApplyOutcome::Incomplete => Some(EffectfulTurnCommitOutcome::Incomplete),
                EffectApplyOutcome::CustomerLimit => {
                    Some(EffectfulTurnCommitOutcome::CustomerLimit)
                }
                EffectApplyOutcome::ProfessionalCapacity => {
                    Some(EffectfulTurnCommitOutcome::ProfessionalCapacity)
                }
            };
            if let Some(rejection) = rejection {
                transaction.rollback().await?;
                return Ok(rejection);
            }
        }
        let role_context = effects.role_context.unwrap_or(AccountRole::Customer);
        if !authorize_session_role(&mut transaction, input, role_context).await? {
            transaction.rollback().await?;
            return Ok(EffectfulTurnCommitOutcome::Unauthorized);
        }

        let (previous_session_id, previous_session_version, next_session_id, next_version) =
            match apply_session_change(&mut transaction, input, role_context).await {
                Ok(value) => value,
                Err(PersistenceError::OptimisticConflict) => {
                    transaction.rollback().await?;
                    return Ok(EffectfulTurnCommitOutcome::Conflict);
                }
                Err(error)
                    if matches!(
                        error.constraint_name(),
                        Some("conversation_sessions_one_active_idx")
                    ) =>
                {
                    transaction.rollback().await?;
                    return Ok(EffectfulTurnCommitOutcome::Conflict);
                }
                Err(error) => return Err(error),
            };
        queue_conversation_outbound(&mut transaction, input, next_session_id).await?;
        for outbound in &effects.additional_outbound {
            match crate::outbound::queue_in_transaction(&mut transaction, outbound).await? {
                crate::OutboundQueueOutcome::Queued { .. } => {}
                crate::OutboundQueueOutcome::Duplicate { .. }
                | crate::OutboundQueueOutcome::IdentifierCollision { .. } => {
                    return Err(PersistenceError::Invariant(
                        "additional turn outbound already exists without its receipt".to_owned(),
                    ));
                }
            }
        }
        if let Some(locale) = &input.locale_change {
            sqlx::query(
                r#"
                UPDATE identity.accounts
                SET
                    preferred_locale = $2,
                    preferred_locale_confirmed_at = statement_timestamp()
                WHERE id = $1
                "#,
            )
            .bind(input.account_id.into_uuid())
            .bind(locale)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                r#"
                INSERT INTO audit.events (
                    id,
                    actor_type,
                    actor_account_id,
                    actor_channel_identity_id,
                    source_channel,
                    action,
                    target_type,
                    target_id,
                    reason_code,
                    metadata,
                    event_schema_version,
                    correlation_id
                )
                VALUES (
                    uuidv7(), 'account', $1, $2, 'whatsapp',
                    'account.locale_confirmed', 'account', $1,
                    'user_confirmation',
                    jsonb_build_object('locale', $3::text),
                    1, $4
                )
                "#,
            )
            .bind(input.account_id.into_uuid())
            .bind(input.channel_identity_id.into_uuid())
            .bind(locale)
            .bind(input.workflow_correlation_id.into_uuid())
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            r#"
            INSERT INTO messaging.conversation_turn_receipts (
                inbound_event_id,
                processing_job_id,
                channel_identity_id,
                previous_session_id,
                previous_session_version,
                next_session_id,
                next_session_version,
                outbound_message_id,
                workflow_correlation_id,
                disposition
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(input.inbound_event_id.into_uuid())
        .bind(input.lease.job_id.into_uuid())
        .bind(input.channel_identity_id.into_uuid())
        .bind(previous_session_id.map(ConversationSessionId::into_uuid))
        .bind(previous_session_version)
        .bind(next_session_id.into_uuid())
        .bind(next_version)
        .bind(input.outbound.id.into_uuid())
        .bind(input.workflow_correlation_id.into_uuid())
        .bind(input.disposition.as_str())
        .execute(&mut *transaction)
        .await?;
        for (position, outbound) in effects.additional_outbound.iter().enumerate() {
            let position = i16::try_from(position).map_err(|_| {
                PersistenceError::InvalidCommand(
                    "too many additional conversation outbounds".to_owned(),
                )
            })?;
            sqlx::query(
                r#"
                INSERT INTO messaging.conversation_turn_receipt_outbounds (
                    inbound_event_id, outbound_message_id, purpose, position
                )
                VALUES ($1, $2, 'professional_review_outcome', $3)
                "#,
            )
            .bind(input.inbound_event_id.into_uuid())
            .bind(outbound.id.into_uuid())
            .bind(position)
            .execute(&mut *transaction)
            .await?;
        }
        let completed = sqlx::query(
            r#"
            UPDATE integration.outbox_jobs
            SET
                state = 'completed',
                lease_owner = NULL,
                lease_token = NULL,
                lease_started_at = NULL,
                lease_expires_at = NULL,
                completed_at = statement_timestamp()
            WHERE id = $1
              AND lease_owner = $2
              AND lease_token = $3
              AND lease_expires_at > statement_timestamp()
            "#,
        )
        .bind(input.lease.job_id.into_uuid())
        .bind(input.lease.worker_id.into_uuid())
        .bind(input.lease.token.into_uuid())
        .execute(&mut *transaction)
        .await?;
        if completed.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(EffectfulTurnCommitOutcome::LostLease);
        }
        transaction.commit().await?;
        Ok(EffectfulTurnCommitOutcome::Committed {
            session_id: next_session_id,
            outbound_message_id: input.outbound.id,
        })
    }

    /// Commits the worker-facing effectful turn envelope.
    pub async fn commit_effectful(
        &self,
        input: &CommitConversationTurnWithEffects,
    ) -> Result<EffectfulTurnCommitOutcome, PersistenceError> {
        self.commit_with_effects(&input.turn, &input.effects).await
    }
}

async fn bind_and_verify_inbound_context(
    connection: &mut sqlx::PgConnection,
    input: &CommitConversationTurn,
) -> Result<bool, PersistenceError> {
    if let Some(reply_to) = input.reply_to_outbound_message_id {
        sqlx::query("SELECT set_config('sahayak.inbound_identity_binding', $1, true)")
            .bind(input.inbound_event_id.to_string())
            .execute(&mut *connection)
            .await?;
        sqlx::query(
            r#"
            UPDATE integration.inbound_events AS inbound
            SET reply_to_outbound_message_id = reply.id
            FROM messaging.outbound_messages AS reply
            WHERE inbound.id = $1
              AND inbound.account_id = $2
              AND inbound.channel_identity_id = $3
              AND inbound.reply_to_outbound_message_id IS NULL
              AND reply.id = $4
              AND reply.recipient_channel_identity_id = inbound.channel_identity_id
              AND reply.provider_code = inbound.provider_code
              AND reply.provider_namespace = inbound.provider_namespace
            "#,
        )
        .bind(input.inbound_event_id.into_uuid())
        .bind(input.account_id.into_uuid())
        .bind(input.channel_identity_id.into_uuid())
        .bind(reply_to.into_uuid())
        .execute(&mut *connection)
        .await?;
    }
    Ok(sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM integration.inbound_events
            WHERE id = $1
              AND account_id = $2
              AND channel_identity_id = $3
              AND reply_to_outbound_message_id IS NOT DISTINCT FROM $4
        )
        "#,
    )
    .bind(input.inbound_event_id.into_uuid())
    .bind(input.account_id.into_uuid())
    .bind(input.channel_identity_id.into_uuid())
    .bind(
        input
            .reply_to_outbound_message_id
            .map(OutboundMessageId::into_uuid),
    )
    .fetch_one(connection)
    .await?)
}

async fn apply_session_change(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: &CommitConversationTurn,
    role_context: AccountRole,
) -> Result<
    (
        Option<ConversationSessionId>,
        Option<i64>,
        ConversationSessionId,
        i64,
    ),
    PersistenceError,
> {
    match &input.session_change {
        ConversationSessionChange::Create {
            session_id,
            workflow_key,
            workflow_version,
            state_key,
            state_data,
            language,
            workflow_correlation_id,
            expires_at,
            expired_session,
        } => {
            if let Some((expired_id, expected_version)) = expired_session {
                let expired = sqlx::query(
                    r#"
                    UPDATE messaging.conversation_sessions
                    SET
                        status = 'expired',
                        state_data = '{}'::jsonb,
                        expected_reply_to_outbound_message_id = NULL,
                        last_inbound_event_id = NULL,
                        ended_at = statement_timestamp(),
                        terminal_reason = 'timeout'
                    WHERE id = $1
                      AND version = $2
                      AND status = 'active'
                      AND expires_at <= statement_timestamp()
                      AND account_id = $3
                    "#,
                )
                .bind(expired_id.into_uuid())
                .bind(expected_version)
                .bind(input.account_id.into_uuid())
                .execute(&mut **transaction)
                .await?;
                if expired.rows_affected() != 1 {
                    return Err(PersistenceError::OptimisticConflict);
                }
            }
            sqlx::query(
                r#"
                INSERT INTO messaging.conversation_sessions (
                    id, account_id, channel_identity_id, role_context,
                    workflow_key, workflow_version, state_key, state_data,
                    language, expires_at, last_inbound_event_id,
                    workflow_correlation_id, expected_reply_to_outbound_message_id
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                "#,
            )
            .bind(session_id.into_uuid())
            .bind(input.account_id.into_uuid())
            .bind(input.channel_identity_id.into_uuid())
            .bind(role_context.as_str())
            .bind(workflow_key)
            .bind(workflow_version)
            .bind(state_key)
            .bind(state_data)
            .bind(language)
            .bind(expires_at)
            .bind(input.inbound_event_id.into_uuid())
            .bind(workflow_correlation_id.into_uuid())
            .bind(input.outbound.id.into_uuid())
            .execute(&mut **transaction)
            .await?;
            Ok((
                expired_session.map(|value| value.0),
                expired_session.map(|value| value.1),
                *session_id,
                1,
            ))
        }
        ConversationSessionChange::Advance {
            session_id,
            expected_version,
            state_key,
            state_data,
            expires_at,
        } => {
            let next_version = sqlx::query_scalar(
                r#"
                UPDATE messaging.conversation_sessions
                SET
                    state_key = $3,
                    state_data = $4,
                    expires_at = $5,
                    last_activity_at = statement_timestamp(),
                    last_inbound_event_id = $6,
                    expected_reply_to_outbound_message_id = $7
                WHERE id = $1
                  AND version = $2
                  AND status = 'active'
                  AND expires_at > statement_timestamp()
                  AND workflow_correlation_id = $8
                  AND account_id = $9
                RETURNING version
                "#,
            )
            .bind(session_id.into_uuid())
            .bind(expected_version)
            .bind(state_key)
            .bind(state_data)
            .bind(expires_at)
            .bind(input.inbound_event_id.into_uuid())
            .bind(input.outbound.id.into_uuid())
            .bind(input.workflow_correlation_id.into_uuid())
            .bind(input.account_id.into_uuid())
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or(PersistenceError::OptimisticConflict)?;
            Ok((
                Some(*session_id),
                Some(*expected_version),
                *session_id,
                next_version,
            ))
        }
        ConversationSessionChange::Replace {
            previous_session_id,
            expected_version,
            terminal_status,
            terminal_reason,
            session_id,
            workflow_key,
            workflow_version,
            state_key,
            state_data,
            language,
            workflow_correlation_id,
            expires_at,
        } => {
            let ended = sqlx::query(
                r#"
                UPDATE messaging.conversation_sessions
                SET
                    status = $3,
                    state_data = '{}'::jsonb,
                    expected_reply_to_outbound_message_id = NULL,
                    last_inbound_event_id = NULL,
                    ended_at = statement_timestamp(),
                    terminal_reason = $4
                WHERE id = $1
                  AND version = $2
                  AND status = 'active'
                  AND account_id = $5
                  AND expires_at > statement_timestamp()
                "#,
            )
            .bind(previous_session_id.into_uuid())
            .bind(expected_version)
            .bind(terminal_status.as_str())
            .bind(terminal_reason)
            .bind(input.account_id.into_uuid())
            .execute(&mut **transaction)
            .await?;
            if ended.rows_affected() != 1 {
                return Err(PersistenceError::OptimisticConflict);
            }
            sqlx::query(
                r#"
                INSERT INTO messaging.conversation_sessions (
                    id, account_id, channel_identity_id, role_context,
                    workflow_key, workflow_version, state_key, state_data,
                    language, expires_at, last_inbound_event_id,
                    workflow_correlation_id, expected_reply_to_outbound_message_id
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                "#,
            )
            .bind(session_id.into_uuid())
            .bind(input.account_id.into_uuid())
            .bind(input.channel_identity_id.into_uuid())
            .bind(role_context.as_str())
            .bind(workflow_key)
            .bind(workflow_version)
            .bind(state_key)
            .bind(state_data)
            .bind(language)
            .bind(expires_at)
            .bind(input.inbound_event_id.into_uuid())
            .bind(workflow_correlation_id.into_uuid())
            .bind(input.outbound.id.into_uuid())
            .execute(&mut **transaction)
            .await?;
            Ok((
                Some(*previous_session_id),
                Some(*expected_version),
                *session_id,
                1,
            ))
        }
    }
}

async fn queue_conversation_outbound(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: &CommitConversationTurn,
    session_id: ConversationSessionId,
) -> Result<(), PersistenceError> {
    let outbound = &input.outbound;
    outbound.validate()?;
    if outbound.recipient_channel_identity_id != Some(input.channel_identity_id) {
        return Err(PersistenceError::InvalidCommand(
            "conversation response recipient does not match channel identity".to_owned(),
        ));
    }
    ensure_active_encryption_key(
        transaction,
        EncryptionPurpose::Integration,
        outbound.payload.encrypted.key_version,
    )
    .await?;
    ensure_active_lookup_key(transaction, outbound.payload.fingerprint_key_version).await?;
    for fingerprint in &outbound.payload.additional_fingerprints {
        crate::key_registry::ensure_lookup_key_readable(transaction, fingerprint.key_version)
            .await?;
    }
    let inserted = sqlx::query(
        r#"
        INSERT INTO messaging.outbound_messages (
            id, provider_code, provider_namespace, recipient_channel_identity_id,
            conversation_session_id, idempotency_key, request_fingerprint,
            fingerprint_key_version, payload_schema_version, payload_ciphertext,
            payload_nonce, encryption_key_purpose, encryption_key_version,
            callback_token, correlation_id
        )
        VALUES ($1, 'whatsapp', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        ON CONFLICT (provider_code, provider_namespace, idempotency_key) DO NOTHING
        "#,
    )
    .bind(outbound.id.into_uuid())
    .bind(&outbound.provider_namespace)
    .bind(input.channel_identity_id.into_uuid())
    .bind(session_id.into_uuid())
    .bind(&outbound.idempotency_key)
    .bind(outbound.payload.request_fingerprint.as_slice())
    .bind(outbound.payload.fingerprint_key_version)
    .bind(outbound.payload.schema_version)
    .bind(&outbound.payload.encrypted.ciphertext)
    .bind(outbound.payload.encrypted.nonce.as_slice())
    .bind(outbound.payload.encrypted.purpose.as_str())
    .bind(outbound.payload.encrypted.key_version)
    .bind(outbound.callback_token.into_uuid())
    .bind(outbound.correlation_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(PersistenceError::Invariant(
            "conversation outbound idempotency key already exists without receipt".to_owned(),
        ));
    }
    for fingerprint in std::iter::once(crate::LookupDigest {
        key_version: outbound.payload.fingerprint_key_version,
        digest: outbound.payload.request_fingerprint,
    })
    .chain(outbound.payload.additional_fingerprints.iter().copied())
    {
        sqlx::query(
            r#"
            INSERT INTO messaging.outbound_message_fingerprints (
                outbound_message_id, key_version, digest
            )
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(outbound.id.into_uuid())
        .bind(fingerprint.key_version)
        .bind(fingerprint.digest.as_slice())
        .execute(&mut **transaction)
        .await?;
    }
    sqlx::query(
        r#"
        INSERT INTO integration.outbox_jobs (
            id, outbound_message_id, job_kind, idempotency_key,
            payload_version, payload, max_attempts, correlation_id, ordering_key
        )
        VALUES (
            $1, $2, 'send_whatsapp_message', $3, 1,
            jsonb_build_object('outbound_message_id', $2::text), $4, $5, $6
        )
        "#,
    )
    .bind(outbound.send_job_id.into_uuid())
    .bind(outbound.id.into_uuid())
    .bind(outbound.id.to_string())
    .bind(outbound.max_attempts)
    .bind(outbound.correlation_id.into_uuid())
    .bind(outbound.ordering_key.as_ref().map(<[u8; 32]>::as_slice))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn validate_commit(input: &CommitConversationTurn) -> Result<(), PersistenceError> {
    if input.outbound.idempotency_key != format!("conversation-turn:v1:{}", input.inbound_event_id)
    {
        return Err(PersistenceError::InvalidCommand(
            "conversation outbound idempotency key is invalid".to_owned(),
        ));
    }
    if input
        .locale_change
        .as_deref()
        .is_some_and(|locale| !matches!(locale, "en-IN" | "hi-IN" | "mr-IN"))
    {
        return Err(PersistenceError::InvalidCommand(
            "conversation locale change is unsupported".to_owned(),
        ));
    }
    Ok(())
}

fn validate_effect_envelope(effects: &ConversationTurnEffects) -> Result<(), PersistenceError> {
    if effects.effect.is_none() && !effects.additional_outbound.is_empty() {
        return Err(PersistenceError::InvalidCommand(
            "additional conversation outbounds require a turn effect".to_owned(),
        ));
    }
    if effects.additional_outbound.len() > i16::MAX as usize {
        return Err(PersistenceError::InvalidCommand(
            "too many additional conversation outbounds".to_owned(),
        ));
    }
    match (&effects.effect, effects.role_context) {
        (Some(crate::ConversationTurnEffect::Professional(_)), Some(AccountRole::Professional))
        | (Some(crate::ConversationTurnEffect::Availability(_)), Some(AccountRole::Professional))
        | (Some(crate::ConversationTurnEffect::Discovery(_)), Some(AccountRole::Customer))
        | (
            Some(crate::ConversationTurnEffect::AdministratorReview(_)),
            Some(AccountRole::Administrator),
        )
        | (None, _) => {}
        (Some(crate::ConversationTurnEffect::Connection(effect)), Some(role))
            if effect.required_role() == role => {}
        _ => {
            return Err(PersistenceError::InvalidCommand(
                "conversation effect and role context do not match".to_owned(),
            ));
        }
    }
    Ok(())
}

async fn authorize_session_role(
    connection: &mut sqlx::PgConnection,
    input: &CommitConversationTurn,
    requested_role: AccountRole,
) -> Result<bool, PersistenceError> {
    let workflow_key = match &input.session_change {
        ConversationSessionChange::Create { workflow_key, .. }
        | ConversationSessionChange::Replace { workflow_key, .. } => workflow_key.as_str(),
        ConversationSessionChange::Advance { session_id, .. } => {
            let current: Option<(String, String)> = sqlx::query_as(
                r#"
                SELECT workflow_key, role_context
                FROM messaging.conversation_sessions
                WHERE id = $1 AND account_id = $2 AND channel_identity_id = $3
                  AND status = 'active'
                "#,
            )
            .bind(session_id.into_uuid())
            .bind(input.account_id.into_uuid())
            .bind(input.channel_identity_id.into_uuid())
            .fetch_optional(&mut *connection)
            .await?;
            let Some((workflow, persisted_role)) = current else {
                return Ok(false);
            };
            if persisted_role != requested_role.as_str() {
                return Ok(false);
            }
            return role_is_active(connection, input, requested_role, &workflow).await;
        }
    };
    role_is_active(connection, input, requested_role, workflow_key).await
}

async fn role_is_active(
    connection: &mut sqlx::PgConnection,
    input: &CommitConversationTurn,
    role: AccountRole,
    workflow_key: &str,
) -> Result<bool, PersistenceError> {
    let paired = match workflow_key {
        "professional.profile" | "professional.availability" | "professional.requests" => {
            role == AccountRole::Professional
        }
        "administrator.review" => role == AccountRole::Administrator,
        _ => role == AccountRole::Customer,
    };
    if !paired {
        return Ok(false);
    }
    Ok(sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM identity.accounts AS account
            JOIN identity.account_roles AS role
              ON role.account_id = account.id
             AND role.role = $4
             AND role.revoked_at IS NULL
            WHERE account.id = $1
              AND account.status IN ('pending', 'active')
              AND account.risk_state NOT IN ('restricted', 'blocked')
              AND (
                  $4 <> 'administrator'
                  OR (
                      account.status = 'active'
                      AND EXISTS (
                          SELECT 1
                          FROM identity.administrator_allowlist AS allowlist
                          WHERE allowlist.account_id = account.id
                            AND allowlist.channel_identity_id = $2
                            AND allowlist.channel_code = 'whatsapp'
                            AND allowlist.provider_namespace = $3
                            AND allowlist.revoked_at IS NULL
                            AND allowlist.expires_at > statement_timestamp()
                      )
                  )
              )
        )
        "#,
    )
    .bind(input.account_id.into_uuid())
    .bind(input.channel_identity_id.into_uuid())
    .bind(&input.outbound.provider_namespace)
    .bind(role.as_str())
    .fetch_one(connection)
    .await?)
}

fn map_session(row: SessionRow) -> Result<PersistedConversationSession, PersistenceError> {
    Ok(PersistedConversationSession {
        id: ConversationSessionId::from_uuid(row.id),
        workflow_key: row.workflow_key,
        workflow_version: row.workflow_version,
        state_key: row.state_key,
        state_data: row.state_data,
        language: row.language,
        role_context: AccountRole::from_str(&row.role_context).map_err(|error| {
            PersistenceError::Invariant(format!("conversation contains invalid role: {error}"))
        })?,
        version: row.version,
        last_inbound_event_id: row.last_inbound_event_id.map(InboundEventId::from_uuid),
        expected_reply_to_outbound_message_id: row
            .expected_reply_to_outbound_message_id
            .map(OutboundMessageId::from_uuid),
        workflow_correlation_id: CorrelationId::from_uuid(row.workflow_correlation_id),
        expires_at: row.expires_at,
    })
}

fn map_account(row: AccountRow) -> Result<AccountSnapshot, PersistenceError> {
    Ok(AccountSnapshot {
        id: AccountId::from_uuid(row.id),
        lifecycle: AccountLifecycle::from_str(&row.status).map_err(|error| {
            PersistenceError::Invariant(format!("account contains invalid lifecycle: {error}"))
        })?,
        risk_state: RiskState::from_str(&row.risk_state).map_err(|error| {
            PersistenceError::Invariant(format!("account contains invalid risk state: {error}"))
        })?,
        preferred_locale: row.preferred_locale,
        preferred_locale_confirmed_at: row.preferred_locale_confirmed_at,
        time_zone: row.time_zone,
        version: row.version,
        state_changed_at: row.state_changed_at,
    })
}
