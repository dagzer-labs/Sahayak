use crate::{
    Database, JobLease, LookupDigest, PersistenceError,
    key_registry::{
        ensure_active_encryption_key, ensure_active_lookup_key, ensure_lookup_key_readable,
    },
};
use sahayak_cryptography::{EncryptedValue, EncryptionPurpose};
use sahayak_domain::{
    CallbackToken, ChannelIdentityId, CorrelationId, OutboundMessageId, OutboxJobId,
};
use sqlx::FromRow;
use std::{collections::BTreeSet, time::Duration};
use uuid::Uuid;

/// Encrypted, fingerprinted provider request retained for durable sending.
#[derive(Clone)]
pub struct EncryptedOutboundPayload {
    /// Provider-neutral payload schema version.
    pub schema_version: i16,
    /// Authenticated encrypted prepared message.
    pub encrypted: EncryptedValue,
    /// HMAC key version for idempotency collision detection.
    pub fingerprint_key_version: i16,
    /// HMAC-SHA-256 of the prepared message.
    pub request_fingerprint: [u8; 32],
    /// Additional request fingerprints retained during lookup-key rotation.
    pub additional_fingerprints: Vec<LookupDigest>,
}

/// Input required to queue one WhatsApp submission and one send job atomically.
#[derive(Clone)]
pub struct QueueOutboundMessage {
    /// Internal outbound submission identifier.
    pub id: OutboundMessageId,
    /// WABA and sender phone-number namespace.
    pub provider_namespace: String,
    /// Known account channel identity, when one exists.
    pub recipient_channel_identity_id: Option<ChannelIdentityId>,
    /// Stable business-action idempotency key.
    pub idempotency_key: String,
    /// Encrypted prepared Meta request.
    pub payload: EncryptedOutboundPayload,
    /// Opaque callback token sent to Meta.
    pub callback_token: CallbackToken,
    /// Workflow correlation identifier.
    pub correlation_id: CorrelationId,
    /// Optional HMAC routing key preserving per-recipient send order.
    pub ordering_key: Option<[u8; 32]>,
    /// Initial outbox job identifier.
    pub send_job_id: OutboxJobId,
    /// Maximum definitive send attempts.
    pub max_attempts: i32,
}

impl QueueOutboundMessage {
    pub(crate) fn validate(&self) -> Result<(), PersistenceError> {
        if self.provider_namespace.is_empty()
            || self.provider_namespace.len() > 128
            || self.provider_namespace.trim() != self.provider_namespace
        {
            return Err(PersistenceError::InvalidCommand(
                "outbound provider namespace is invalid".to_owned(),
            ));
        }
        if self.idempotency_key.is_empty()
            || self.idempotency_key.len() > 255
            || self.idempotency_key.trim() != self.idempotency_key
        {
            return Err(PersistenceError::InvalidCommand(
                "outbound idempotency key is invalid".to_owned(),
            ));
        }
        if self.payload.schema_version <= 0
            || self.payload.encrypted.key_version <= 0
            || self.payload.fingerprint_key_version <= 0
            || self.payload.encrypted.purpose != EncryptionPurpose::Integration
            || self.payload.encrypted.ciphertext.len() < 16
        {
            return Err(PersistenceError::InvalidCommand(
                "outbound encrypted payload is invalid".to_owned(),
            ));
        }
        let mut versions = BTreeSet::from([self.payload.fingerprint_key_version]);
        if self
            .payload
            .additional_fingerprints
            .iter()
            .any(|fingerprint| {
                fingerprint.key_version <= 0 || !versions.insert(fingerprint.key_version)
            })
        {
            return Err(PersistenceError::InvalidCommand(
                "outbound fingerprint key versions must be positive and unique".to_owned(),
            ));
        }
        if !(1..=100).contains(&self.max_attempts) {
            return Err(PersistenceError::InvalidCommand(
                "outbound max_attempts must be between 1 and 100".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Idempotent queue result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundQueueOutcome {
    /// New outbound record and send job were created.
    Queued {
        /// Outbound record identifier.
        outbound_message_id: OutboundMessageId,
        /// Durable send-job identifier.
        job_id: OutboxJobId,
    },
    /// Identical business action already exists.
    Duplicate {
        /// Existing outbound record identifier.
        outbound_message_id: OutboundMessageId,
    },
    /// Idempotency key was reused for different prepared content.
    IdentifierCollision {
        /// Existing outbound record identifier.
        outbound_message_id: OutboundMessageId,
    },
}

/// Encrypted outbound payload and callback token ready for a send attempt.
#[derive(Clone)]
pub struct EncryptedOutboundMessage {
    /// Outbound record identifier.
    pub id: OutboundMessageId,
    /// Prepared message schema version.
    pub payload_schema_version: i16,
    /// Authenticated encrypted prepared message.
    pub payload: EncryptedValue,
    /// Callback token that must be included in the Meta request.
    pub callback_token: CallbackToken,
    /// Current actual provider submission count.
    pub send_attempt_count: i32,
}

/// Recipient and policy state required immediately before provider submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundDeliveryContext {
    /// Recipient channel identity, absent only for controlled transport probes.
    pub channel_identity_id: Option<ChannelIdentityId>,
    /// Confirmed or fallback account locale.
    pub locale: Option<String>,
    /// Whether free-form service messages remain eligible at database time.
    pub service_window_open: bool,
    /// Whether account, channel, consent, and delivery state permit any send.
    pub eligible: bool,
    /// Original workflow correlation identifier.
    pub correlation_id: CorrelationId,
    /// Privacy-safe ordering key inherited by replacement sends.
    pub ordering_key: Option<[u8; 32]>,
}

impl std::fmt::Debug for EncryptedOutboundMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedOutboundMessage")
            .field("id", &self.id)
            .field("payload_schema_version", &self.payload_schema_version)
            .field("payload", &"[REDACTED]")
            .field("callback_token", &"[REDACTED]")
            .field("send_attempt_count", &self.send_attempt_count)
            .finish()
    }
}

/// Worker decision before network I/O.
#[derive(Clone, Debug)]
pub enum BeginSubmission {
    /// Lease transitioned a queued record to sending.
    Ready(EncryptedOutboundMessage),
    /// Meta already accepted the message; worker should only complete its job.
    AlreadyAccepted,
    /// A previous worker crossed the send boundary but never recorded an outcome.
    AbandonedSending,
    /// Previous attempt has an uncertain outcome and must not be resent.
    Unknown,
    /// Message was definitively rejected.
    Rejected,
    /// Account or channel state no longer permits delivery.
    Ineligible,
    /// Worker no longer owns the outbox lease.
    LostLease,
}

/// Result of a fenced outbound state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundMutation {
    /// Outbound and outbox state changed atomically.
    Applied,
    /// Worker no longer owns the send lease.
    LostLease,
}

#[derive(FromRow)]
struct ExistingOutbound {
    id: Uuid,
}

#[derive(FromRow)]
struct ExistingFingerprint {
    key_version: i16,
    digest: Vec<u8>,
}

#[derive(FromRow)]
struct BeginRow {
    id: Uuid,
    payload_schema_version: i16,
    payload_ciphertext: Vec<u8>,
    payload_nonce: Vec<u8>,
    encryption_key_version: i16,
    callback_token: Uuid,
    send_attempt_count: i32,
}

#[derive(FromRow)]
struct DeliveryContextRow {
    channel_identity_id: Option<Uuid>,
    locale: Option<String>,
    window_open: Option<bool>,
    eligible: bool,
    correlation_id: Uuid,
    ordering_key: Option<Vec<u8>>,
}

/// Durable outbound queue and fenced submission transitions.
#[derive(Clone, Debug)]
pub struct OutboundRepository {
    database: Database,
}

impl OutboundRepository {
    /// Creates an outbound repository over the shared process pool.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Atomically queues an encrypted outbound record and one send job.
    pub async fn queue(
        &self,
        input: &QueueOutboundMessage,
    ) -> Result<OutboundQueueOutcome, PersistenceError> {
        input.validate()?;
        let mut transaction = self.database.pool().begin().await?;
        let outcome = queue_in_transaction(&mut transaction, input).await?;
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Atomically replaces a rejected free-form send with its re-entry template.
    pub async fn replace_with_reentry_template(
        &self,
        lease: JobLease,
        replaced_outbound_message_id: OutboundMessageId,
        error_class: &str,
        error_code: &str,
        replacement: &QueueOutboundMessage,
    ) -> Result<OutboundMutation, PersistenceError> {
        replacement.validate()?;
        validate_error_code(error_class)?;
        validate_error_code(error_code)?;
        if error_class.len() > 64
            || replacement.recipient_channel_identity_id.is_none()
            || replacement.idempotency_key
                != format!("reentry-template:v1:{replaced_outbound_message_id}")
        {
            return Err(PersistenceError::InvalidCommand(
                "re-entry replacement metadata is invalid".to_owned(),
            ));
        }

        let mut transaction = self.database.pool().begin().await?;
        let replaced = sqlx::query(
            r#"
            UPDATE messaging.outbound_messages AS message
            SET
                submission_state = 'rejected',
                send_lease_token = NULL,
                last_error_class = $5,
                last_error_code = $6,
                rejected_at = statement_timestamp()
            FROM integration.outbox_jobs AS job
            WHERE message.id = $4
              AND message.provider_code = 'whatsapp'
              AND message.provider_namespace = $7
              AND message.recipient_channel_identity_id = $8
              AND message.submission_state IN ('queued', 'sending')
              AND (
                  message.submission_state = 'queued'
                  OR message.send_lease_token = $3
              )
              AND job.id = $1
              AND job.outbound_message_id = message.id
              AND job.ordering_key IS NOT DISTINCT FROM $9::bytea
              AND job.state = 'leased'
              AND job.lease_owner = $2
              AND job.lease_token = $3
              AND job.lease_expires_at > statement_timestamp()
            "#,
        )
        .bind(lease.job_id.into_uuid())
        .bind(lease.worker_id.into_uuid())
        .bind(lease.token.into_uuid())
        .bind(replaced_outbound_message_id.into_uuid())
        .bind(error_class)
        .bind(error_code)
        .bind(&replacement.provider_namespace)
        .bind(
            replacement
                .recipient_channel_identity_id
                .map(ChannelIdentityId::into_uuid),
        )
        .bind(replacement.ordering_key.as_ref().map(<[u8; 32]>::as_slice))
        .execute(&mut *transaction)
        .await?;
        if replaced.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(OutboundMutation::LostLease);
        }
        if !complete_job(&mut transaction, lease).await? {
            transaction.rollback().await?;
            return Ok(OutboundMutation::LostLease);
        }
        if matches!(
            queue_in_transaction(&mut transaction, replacement).await?,
            OutboundQueueOutcome::IdentifierCollision { .. }
        ) {
            transaction.rollback().await?;
            return Err(PersistenceError::InvalidCommand(
                "re-entry replacement idempotency key conflicts with another payload".to_owned(),
            ));
        }
        transaction.commit().await?;
        Ok(OutboundMutation::Applied)
    }

    /// Loads a queued payload for local authentication before crossing the send boundary.
    pub async fn find_queued_for_send(
        &self,
        outbound_message_id: OutboundMessageId,
    ) -> Result<Option<EncryptedOutboundMessage>, PersistenceError> {
        let row = sqlx::query_as::<_, BeginRow>(
            r#"
            SELECT
                id,
                payload_schema_version,
                payload_ciphertext,
                payload_nonce,
                encryption_key_version,
                callback_token,
                send_attempt_count
            FROM messaging.outbound_messages
            WHERE id = $1
              AND submission_state = 'queued'
              AND payload_purged_at IS NULL
            "#,
        )
        .bind(outbound_message_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        row.map(map_encrypted_outbound).transpose()
    }

    /// Loads recipient locale and service-window state immediately before sending.
    pub async fn delivery_context(
        &self,
        outbound_message_id: OutboundMessageId,
    ) -> Result<Option<OutboundDeliveryContext>, PersistenceError> {
        let row = sqlx::query_as::<_, DeliveryContextRow>(
            r#"
            SELECT
                message.recipient_channel_identity_id AS channel_identity_id,
                account.preferred_locale AS locale,
                whatsapp.service_window_expires_at > statement_timestamp() AS window_open,
                CASE
                    WHEN message.recipient_channel_identity_id IS NULL
                        THEN message.idempotency_key LIKE 'transport_probe:%'
                    ELSE
                        account.status IN ('pending', 'active')
                        AND account.risk_state NOT IN ('restricted', 'blocked')
                        AND channel.status = 'active'
                        AND whatsapp.channel_identity_id IS NOT NULL
                        AND whatsapp.opt_in_status <> 'opted_out'
                        AND whatsapp.delivery_state <> 'unreachable'
                        AND whatsapp.blocked_at IS NULL
                END AS eligible,
                message.correlation_id,
                (
                    SELECT job.ordering_key
                    FROM integration.outbox_jobs AS job
                    WHERE job.outbound_message_id = message.id
                    ORDER BY job.created_at
                    LIMIT 1
                ) AS ordering_key
            FROM messaging.outbound_messages AS message
            LEFT JOIN identity.channel_identities AS channel
              ON channel.id = message.recipient_channel_identity_id
            LEFT JOIN identity.accounts AS account ON account.id = channel.account_id
            LEFT JOIN private_data.whatsapp_identities AS whatsapp
              ON whatsapp.channel_identity_id = channel.id
            WHERE message.id = $1
            "#,
        )
        .bind(outbound_message_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        row.map(|row| {
            let ordering_key = row
                .ordering_key
                .map(|value| {
                    value.try_into().map_err(|_| {
                        PersistenceError::Invariant(
                            "outbound ordering key has invalid length".to_owned(),
                        )
                    })
                })
                .transpose()?;
            Ok(OutboundDeliveryContext {
                channel_identity_id: row.channel_identity_id.map(ChannelIdentityId::from_uuid),
                locale: row.locale,
                service_window_open: row.window_open.unwrap_or(false),
                eligible: row.eligible,
                correlation_id: CorrelationId::from_uuid(row.correlation_id),
                ordering_key,
            })
        })
        .transpose()
    }

    /// Rejects a locally invalid queued payload without ever marking it `sending`.
    pub async fn reject_queued_local(
        &self,
        lease: JobLease,
        outbound_message_id: OutboundMessageId,
        error_code: &str,
    ) -> Result<OutboundMutation, PersistenceError> {
        validate_error_code(error_code)?;
        let mut transaction = self.database.pool().begin().await?;
        let outbound = sqlx::query(
            r#"
            UPDATE messaging.outbound_messages AS message
            SET
                submission_state = 'rejected',
                last_error_class = 'local_invariant',
                last_error_code = $5,
                rejected_at = statement_timestamp()
            FROM integration.outbox_jobs AS job
            WHERE message.id = $4
              AND message.submission_state = 'queued'
              AND job.id = $1
              AND job.outbound_message_id = message.id
              AND job.state = 'leased'
              AND job.lease_owner = $2
              AND job.lease_token = $3
              AND job.lease_expires_at > statement_timestamp()
            "#,
        )
        .bind(lease.job_id.into_uuid())
        .bind(lease.worker_id.into_uuid())
        .bind(lease.token.into_uuid())
        .bind(outbound_message_id.into_uuid())
        .bind(error_code)
        .execute(&mut *transaction)
        .await?;
        if outbound.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(OutboundMutation::LostLease);
        }
        let dead = sqlx::query(
            r#"
            UPDATE integration.outbox_jobs
            SET
                state = 'dead_lettered',
                lease_owner = NULL,
                lease_token = NULL,
                lease_started_at = NULL,
                lease_expires_at = NULL,
                last_error_class = 'local_invariant',
                last_error_code = $4,
                last_error_at = statement_timestamp(),
                dead_lettered_at = statement_timestamp(),
                dead_letter_reason = $4
            WHERE id = $1
              AND lease_owner = $2
              AND lease_token = $3
            "#,
        )
        .bind(lease.job_id.into_uuid())
        .bind(lease.worker_id.into_uuid())
        .bind(lease.token.into_uuid())
        .bind(error_code)
        .execute(&mut *transaction)
        .await?;
        if dead.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(OutboundMutation::LostLease);
        }
        transaction.commit().await?;
        Ok(OutboundMutation::Applied)
    }

    /// Fences the send boundary by moving a queued row to `sending` before network I/O.
    pub async fn begin_submission(
        &self,
        lease: JobLease,
        outbound_message_id: OutboundMessageId,
    ) -> Result<BeginSubmission, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let metadata: Option<(Option<Uuid>, String)> = sqlx::query_as(
            r#"
            SELECT recipient_channel_identity_id, idempotency_key
            FROM messaging.outbound_messages
            WHERE id = $1
            FOR UPDATE
            "#,
        )
        .bind(outbound_message_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((recipient_channel_identity_id, idempotency_key)) = metadata else {
            transaction.rollback().await?;
            return Ok(BeginSubmission::LostLease);
        };
        let eligible = if let Some(channel_identity_id) = recipient_channel_identity_id {
            sqlx::query_scalar::<_, bool>(
                r#"
                SELECT true
                FROM identity.channel_identities AS channel
                JOIN identity.accounts AS account ON account.id = channel.account_id
                JOIN private_data.whatsapp_identities AS whatsapp
                  ON whatsapp.channel_identity_id = channel.id
                WHERE channel.id = $1
                  AND channel.status = 'active'
                  AND account.status IN ('pending', 'active')
                  AND account.risk_state NOT IN ('restricted', 'blocked')
                  AND whatsapp.opt_in_status <> 'opted_out'
                  AND whatsapp.delivery_state <> 'unreachable'
                  AND whatsapp.blocked_at IS NULL
                FOR SHARE OF channel, account, whatsapp
                "#,
            )
            .bind(channel_identity_id)
            .fetch_optional(&mut *transaction)
            .await?
            .unwrap_or(false)
        } else {
            idempotency_key.starts_with("transport_probe:")
        };
        if !eligible {
            transaction.rollback().await?;
            return Ok(BeginSubmission::Ineligible);
        }
        let row = sqlx::query_as::<_, BeginRow>(
            r#"
            UPDATE messaging.outbound_messages AS message
            SET
                submission_state = 'sending',
                send_attempt_count = message.send_attempt_count + 1,
                send_lease_token = $3,
                send_started_at = statement_timestamp()
            FROM integration.outbox_jobs AS job
            WHERE message.id = $4
              AND message.submission_state = 'queued'
              AND message.payload_purged_at IS NULL
              AND job.id = $1
              AND job.outbound_message_id = message.id
              AND job.state = 'leased'
              AND job.lease_owner = $2
              AND job.lease_token = $3
              AND job.lease_expires_at > statement_timestamp()
            RETURNING
                message.id,
                message.payload_schema_version,
                message.payload_ciphertext,
                message.payload_nonce,
                message.encryption_key_version,
                message.callback_token,
                message.send_attempt_count
            "#,
        )
        .bind(lease.job_id.into_uuid())
        .bind(lease.worker_id.into_uuid())
        .bind(lease.token.into_uuid())
        .bind(outbound_message_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(row) = row {
            let message = map_encrypted_outbound(row)?;
            transaction.commit().await?;
            return Ok(BeginSubmission::Ready(message));
        }
        let state: Option<String> = sqlx::query_scalar(
            "SELECT submission_state FROM messaging.outbound_messages WHERE id = $1",
        )
        .bind(outbound_message_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(match state.as_deref() {
            Some("accepted") => BeginSubmission::AlreadyAccepted,
            Some("sending") => BeginSubmission::AbandonedSending,
            Some("unknown") => BeginSubmission::Unknown,
            Some("rejected") => BeginSubmission::Rejected,
            _ => BeginSubmission::LostLease,
        })
    }

    /// Atomically records Meta acceptance and completes the fenced send job.
    pub async fn mark_accepted(
        &self,
        lease: JobLease,
        outbound_message_id: OutboundMessageId,
        provider_message_id: &str,
        acceptance_status: Option<&str>,
    ) -> Result<OutboundMutation, PersistenceError> {
        validate_opaque("provider_message_id", provider_message_id, 512)?;
        if acceptance_status.is_some_and(|value| value.is_empty() || value.len() > 64) {
            return Err(PersistenceError::InvalidCommand(
                "provider acceptance status is invalid".to_owned(),
            ));
        }
        let mut transaction = self.database.pool().begin().await?;
        let updated: Option<Uuid> = sqlx::query_scalar(
            r#"
            UPDATE messaging.outbound_messages
            SET
                submission_state = 'accepted',
                send_lease_token = NULL,
                provider_message_id = $3,
                provider_acceptance_status = $4,
                accepted_at = statement_timestamp()
            WHERE id = $1
              AND submission_state = 'sending'
              AND send_lease_token = $2
            RETURNING id
            "#,
        )
        .bind(outbound_message_id.into_uuid())
        .bind(lease.token.into_uuid())
        .bind(provider_message_id)
        .bind(acceptance_status)
        .fetch_optional(&mut *transaction)
        .await?;
        if updated.is_none() {
            let already_accepted: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM messaging.outbound_messages
                    WHERE id = $1
                      AND submission_state = 'accepted'
                      AND provider_message_id = $2
                )
                "#,
            )
            .bind(outbound_message_id.into_uuid())
            .bind(provider_message_id)
            .fetch_one(&mut *transaction)
            .await?;
            if !already_accepted || !complete_job(&mut transaction, lease).await? {
                transaction.rollback().await?;
                return Ok(OutboundMutation::LostLease);
            }
            transaction.commit().await?;
            return Ok(OutboundMutation::Applied);
        }
        sqlx::query(
            r#"
            UPDATE messaging.outbound_delivery_events AS delivery
            SET outbound_message_id = $1
            WHERE delivery.outbound_message_id IS NULL
              AND delivery.provider_code = 'whatsapp'
              AND delivery.provider_message_id = $2
              AND delivery.provider_namespace = (
                  SELECT provider_namespace
                  FROM messaging.outbound_messages
                  WHERE id = $1
              )
            "#,
        )
        .bind(outbound_message_id.into_uuid())
        .bind(provider_message_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r#"
            UPDATE messaging.outbound_messages AS message
            SET
                sent_at = summary.sent_at,
                delivered_at = summary.delivered_at,
                read_at = summary.read_at,
                played_at = summary.played_at,
                failed_at = summary.failed_at
            FROM (
                SELECT
                    min(provider_occurred_at) FILTER (
                        WHERE provider_status IN ('sent', 'delivered', 'read', 'played')
                    ) AS sent_at,
                    min(provider_occurred_at) FILTER (
                        WHERE provider_status IN ('delivered', 'read', 'played')
                    ) AS delivered_at,
                    min(provider_occurred_at) FILTER (
                        WHERE provider_status IN ('read', 'played')
                    ) AS read_at,
                    min(provider_occurred_at) FILTER (
                        WHERE provider_status = 'played'
                    ) AS played_at,
                    min(provider_occurred_at) FILTER (
                        WHERE provider_status = 'failed'
                    ) AS failed_at
                FROM messaging.outbound_delivery_events
                WHERE outbound_message_id = $1
            ) AS summary
            WHERE message.id = $1
            "#,
        )
        .bind(outbound_message_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        let completed = complete_job(&mut transaction, lease).await?;
        if !completed {
            transaction.rollback().await?;
            return Ok(OutboundMutation::LostLease);
        }
        transaction.commit().await?;
        Ok(OutboundMutation::Applied)
    }

    /// Atomically records an ambiguous outcome and dead-letters the send job.
    pub async fn mark_unknown(
        &self,
        lease: JobLease,
        outbound_message_id: OutboundMessageId,
        error_code: &str,
    ) -> Result<OutboundMutation, PersistenceError> {
        finalize_failure(
            self.database.pool(),
            lease,
            outbound_message_id,
            "unknown",
            "ambiguous_transport",
            error_code,
        )
        .await
    }

    /// Atomically records a definitive terminal rejection and dead-letters the job.
    pub async fn mark_rejected(
        &self,
        lease: JobLease,
        outbound_message_id: OutboundMessageId,
        error_class: &str,
        error_code: &str,
    ) -> Result<OutboundMutation, PersistenceError> {
        finalize_failure(
            self.database.pool(),
            lease,
            outbound_message_id,
            "rejected",
            error_class,
            error_code,
        )
        .await
    }

    /// Returns a definitively rejected request to the queue using database time.
    /// Exhausted jobs become rejected and dead-lettered atomically.
    pub async fn mark_retryable(
        &self,
        lease: JobLease,
        outbound_message_id: OutboundMessageId,
        error_class: &str,
        error_code: &str,
        delay: Duration,
    ) -> Result<OutboundMutation, PersistenceError> {
        validate_error_code(error_class)?;
        validate_error_code(error_code)?;
        let delay_milliseconds = i64::try_from(delay.as_millis()).map_err(|_| {
            PersistenceError::InvalidCommand("outbound retry delay is too large".to_owned())
        })?;
        if !(1_000..=86_400_000).contains(&delay_milliseconds) {
            return Err(PersistenceError::InvalidCommand(
                "outbound retry delay must be between 1 second and 24 hours".to_owned(),
            ));
        }
        let mut transaction = self.database.pool().begin().await?;
        let attempts: Option<(i32, i32)> = sqlx::query_as(
            r#"
            SELECT attempt_count, max_attempts
            FROM integration.outbox_jobs
            WHERE id = $1
              AND state = 'leased'
              AND lease_owner = $2
              AND lease_token = $3
              AND lease_expires_at > statement_timestamp()
            FOR UPDATE
            "#,
        )
        .bind(lease.job_id.into_uuid())
        .bind(lease.worker_id.into_uuid())
        .bind(lease.token.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((attempt_count, max_attempts)) = attempts else {
            transaction.rollback().await?;
            return Ok(OutboundMutation::LostLease);
        };
        let exhausted = attempt_count >= max_attempts;
        let outbound = sqlx::query(
            r#"
            UPDATE messaging.outbound_messages
            SET
                submission_state = CASE WHEN $3 THEN 'rejected' ELSE 'queued' END,
                send_lease_token = NULL,
                send_started_at = CASE WHEN $3 THEN send_started_at ELSE NULL END,
                last_error_class = $4,
                last_error_code = $5,
                rejected_at = CASE WHEN $3 THEN statement_timestamp() ELSE NULL END
            WHERE id = $1
              AND submission_state = 'sending'
              AND send_lease_token = $2
            "#,
        )
        .bind(outbound_message_id.into_uuid())
        .bind(lease.token.into_uuid())
        .bind(exhausted)
        .bind(error_class)
        .bind(error_code)
        .execute(&mut *transaction)
        .await?;
        if outbound.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(OutboundMutation::LostLease);
        }
        sqlx::query(
            r#"
            UPDATE integration.outbox_jobs
            SET
                state = CASE WHEN $4 THEN 'dead_lettered' ELSE 'pending' END,
                available_at = statement_timestamp() + ($5::bigint * INTERVAL '1 millisecond'),
                lease_owner = NULL,
                lease_token = NULL,
                lease_started_at = NULL,
                lease_expires_at = NULL,
                last_error_class = $6,
                last_error_code = $7,
                last_error_at = statement_timestamp(),
                dead_lettered_at = CASE WHEN $4 THEN statement_timestamp() ELSE NULL END,
                dead_letter_reason = CASE WHEN $4 THEN 'attempts_exhausted' ELSE NULL END
            WHERE id = $1
              AND lease_owner = $2
              AND lease_token = $3
            "#,
        )
        .bind(lease.job_id.into_uuid())
        .bind(lease.worker_id.into_uuid())
        .bind(lease.token.into_uuid())
        .bind(exhausted)
        .bind(delay_milliseconds)
        .bind(error_class)
        .bind(error_code)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(OutboundMutation::Applied)
    }

    /// Resolves a reclaimed `sending` record as unknown without resubmitting it.
    pub async fn mark_recovered_unknown(
        &self,
        lease: JobLease,
        outbound_message_id: OutboundMessageId,
    ) -> Result<OutboundMutation, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let valid_lease: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM integration.outbox_jobs
                WHERE id = $1
                  AND outbound_message_id = $4
                  AND state = 'leased'
                  AND lease_owner = $2
                  AND lease_token = $3
                  AND lease_expires_at > statement_timestamp()
            )
            "#,
        )
        .bind(lease.job_id.into_uuid())
        .bind(lease.worker_id.into_uuid())
        .bind(lease.token.into_uuid())
        .bind(outbound_message_id.into_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        if !valid_lease {
            transaction.rollback().await?;
            return Ok(OutboundMutation::LostLease);
        }
        let outbound = sqlx::query(
            r#"
            UPDATE messaging.outbound_messages
            SET
                submission_state = 'unknown',
                send_lease_token = NULL,
                last_error_class = 'ambiguous_transport',
                last_error_code = 'worker_recovered_sending_state',
                unknown_at = statement_timestamp()
            WHERE id = $1
              AND submission_state = 'sending'
            "#,
        )
        .bind(outbound_message_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        if outbound.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(OutboundMutation::LostLease);
        }
        sqlx::query(
            r#"
            UPDATE integration.outbox_jobs
            SET
                state = 'dead_lettered',
                lease_owner = NULL,
                lease_token = NULL,
                lease_started_at = NULL,
                lease_expires_at = NULL,
                last_error_class = 'ambiguous_transport',
                last_error_code = 'worker_recovered_sending_state',
                last_error_at = statement_timestamp(),
                dead_lettered_at = statement_timestamp(),
                dead_letter_reason = 'ambiguous_transport'
            WHERE id = $1
              AND lease_owner = $2
              AND lease_token = $3
            "#,
        )
        .bind(lease.job_id.into_uuid())
        .bind(lease.worker_id.into_uuid())
        .bind(lease.token.into_uuid())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(OutboundMutation::Applied)
    }

    /// Marks expired in-flight sends unknown before the generic lease reaper runs.
    pub async fn reap_abandoned_sends(&self, limit: u16) -> Result<u64, PersistenceError> {
        if !(1..=1_000).contains(&limit) {
            return Err(PersistenceError::InvalidCommand(
                "abandoned send reap limit must be between 1 and 1000".to_owned(),
            ));
        }
        let mut transaction = self.database.pool().begin().await?;
        let rows: Vec<(Uuid, Uuid, String, i32, i32)> = sqlx::query_as(
            r#"
            SELECT
                job.id,
                message.id,
                message.submission_state,
                job.attempt_count,
                job.max_attempts
            FROM integration.outbox_jobs AS job
            JOIN messaging.outbound_messages AS message
              ON message.id = job.outbound_message_id
            WHERE job.job_kind = 'send_whatsapp_message'
              AND job.state = 'leased'
              AND job.lease_expires_at <= statement_timestamp()
            ORDER BY job.lease_expires_at, job.id
            LIMIT $1
            FOR UPDATE OF job, message SKIP LOCKED
            "#,
        )
        .bind(i64::from(limit))
        .fetch_all(&mut *transaction)
        .await?;
        for (job_id, message_id, submission_state, attempt_count, max_attempts) in &rows {
            let queued_retry = submission_state == "queued" && attempt_count < max_attempts;
            match submission_state.as_str() {
                "sending" => {
                    sqlx::query(
                        r#"
                        UPDATE messaging.outbound_messages
                        SET
                            submission_state = 'unknown',
                            send_lease_token = NULL,
                            last_error_class = 'ambiguous_transport',
                            last_error_code = 'send_lease_expired',
                            unknown_at = statement_timestamp()
                        WHERE id = $1
                        "#,
                    )
                    .bind(message_id)
                    .execute(&mut *transaction)
                    .await?;
                }
                "queued" => {
                    if !queued_retry {
                        sqlx::query(
                            r#"
                            UPDATE messaging.outbound_messages
                            SET
                                submission_state = 'rejected',
                                last_error_class = 'attempts_exhausted',
                                last_error_code = 'send_never_started',
                                rejected_at = statement_timestamp()
                            WHERE id = $1
                            "#,
                        )
                        .bind(message_id)
                        .execute(&mut *transaction)
                        .await?;
                    }
                }
                "accepted" | "unknown" | "rejected" => {}
                other => {
                    return Err(PersistenceError::Invariant(format!(
                        "unsupported outbound submission state {other}"
                    )));
                }
            }
            if queued_retry {
                sqlx::query(
                    r#"
                    UPDATE integration.outbox_jobs
                    SET
                        state = 'pending',
                        available_at = statement_timestamp(),
                        lease_owner = NULL,
                        lease_token = NULL,
                        lease_started_at = NULL,
                        lease_expires_at = NULL,
                        last_error_class = 'abandoned_lease',
                        last_error_code = 'send_not_started',
                        last_error_at = statement_timestamp()
                    WHERE id = $1
                    "#,
                )
                .bind(job_id)
                .execute(&mut *transaction)
                .await?;
            } else if submission_state == "accepted" {
                sqlx::query(
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
                    "#,
                )
                .bind(job_id)
                .execute(&mut *transaction)
                .await?;
            } else {
                let (error_class, error_code, reason) = if submission_state == "sending" {
                    (
                        "ambiguous_transport",
                        "send_lease_expired",
                        "ambiguous_transport",
                    )
                } else if submission_state == "queued" {
                    (
                        "attempts_exhausted",
                        "send_never_started",
                        "attempts_exhausted",
                    )
                } else {
                    (
                        "terminal_submission",
                        "terminal_submission",
                        "terminal_submission",
                    )
                };
                sqlx::query(
                    r#"
                    UPDATE integration.outbox_jobs
                    SET
                        state = 'dead_lettered',
                        lease_owner = NULL,
                        lease_token = NULL,
                        lease_started_at = NULL,
                        lease_expires_at = NULL,
                        last_error_class = $2,
                        last_error_code = $3,
                        last_error_at = statement_timestamp(),
                        dead_lettered_at = statement_timestamp(),
                        dead_letter_reason = $4
                    WHERE id = $1
                    "#,
                )
                .bind(job_id)
                .bind(error_class)
                .bind(error_code)
                .bind(reason)
                .execute(&mut *transaction)
                .await?;
            }
        }
        transaction.commit().await?;
        Ok(rows.len() as u64)
    }
}

pub(crate) async fn queue_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: &QueueOutboundMessage,
) -> Result<OutboundQueueOutcome, PersistenceError> {
    ensure_active_encryption_key(
        transaction,
        EncryptionPurpose::Integration,
        input.payload.encrypted.key_version,
    )
    .await?;
    ensure_active_lookup_key(transaction, input.payload.fingerprint_key_version).await?;
    for fingerprint in &input.payload.additional_fingerprints {
        ensure_lookup_key_readable(transaction, fingerprint.key_version).await?;
    }
    let queued: Option<(Uuid, Uuid)> = sqlx::query_as(
        r#"
        WITH inserted AS (
            INSERT INTO messaging.outbound_messages (
                id,
                provider_code,
                provider_namespace,
                recipient_channel_identity_id,
                idempotency_key,
                request_fingerprint,
                fingerprint_key_version,
                payload_schema_version,
                payload_ciphertext,
                payload_nonce,
                encryption_key_purpose,
                encryption_key_version,
                callback_token,
                correlation_id
            )
            VALUES (
                $1, 'whatsapp', $2, $3, $4, $5, $6, $7, $8, $9,
                $10, $11, $12, $13
            )
            ON CONFLICT (provider_code, provider_namespace, idempotency_key) DO NOTHING
            RETURNING id
        )
        INSERT INTO integration.outbox_jobs (
            id,
            outbound_message_id,
            job_kind,
            idempotency_key,
            payload_version,
            payload,
            max_attempts,
            correlation_id,
            ordering_key
        )
        SELECT
            $14,
            inserted.id,
            'send_whatsapp_message',
            inserted.id::text,
            1,
            jsonb_build_object('outbound_message_id', inserted.id::text),
            $15,
            $13,
            $16
        FROM inserted
        RETURNING outbound_message_id, id
        "#,
    )
    .bind(input.id.into_uuid())
    .bind(&input.provider_namespace)
    .bind(
        input
            .recipient_channel_identity_id
            .map(ChannelIdentityId::into_uuid),
    )
    .bind(&input.idempotency_key)
    .bind(input.payload.request_fingerprint.as_slice())
    .bind(input.payload.fingerprint_key_version)
    .bind(input.payload.schema_version)
    .bind(&input.payload.encrypted.ciphertext)
    .bind(input.payload.encrypted.nonce.as_slice())
    .bind(input.payload.encrypted.purpose.as_str())
    .bind(input.payload.encrypted.key_version)
    .bind(input.callback_token.into_uuid())
    .bind(input.correlation_id.into_uuid())
    .bind(input.send_job_id.into_uuid())
    .bind(input.max_attempts)
    .bind(input.ordering_key.as_ref().map(<[u8; 32]>::as_slice))
    .fetch_optional(&mut **transaction)
    .await?;

    if let Some((outbound_id, job_id)) = queued {
        for fingerprint in std::iter::once(LookupDigest {
            key_version: input.payload.fingerprint_key_version,
            digest: input.payload.request_fingerprint,
        })
        .chain(input.payload.additional_fingerprints.iter().copied())
        {
            sqlx::query(
                r#"
                INSERT INTO messaging.outbound_message_fingerprints (
                    outbound_message_id,
                    key_version,
                    digest
                )
                VALUES ($1, $2, $3)
                "#,
            )
            .bind(outbound_id)
            .bind(fingerprint.key_version)
            .bind(fingerprint.digest.as_slice())
            .execute(&mut **transaction)
            .await?;
        }
        return Ok(OutboundQueueOutcome::Queued {
            outbound_message_id: OutboundMessageId::from_uuid(outbound_id),
            job_id: OutboxJobId::from_uuid(job_id),
        });
    }

    let existing = sqlx::query_as::<_, ExistingOutbound>(
        r#"
        SELECT id
        FROM messaging.outbound_messages
        WHERE provider_code = 'whatsapp'
          AND provider_namespace = $1
          AND idempotency_key = $2
        "#,
    )
    .bind(&input.provider_namespace)
    .bind(&input.idempotency_key)
    .fetch_one(&mut **transaction)
    .await?;
    let outbound_message_id = OutboundMessageId::from_uuid(existing.id);
    let stored = sqlx::query_as::<_, ExistingFingerprint>(
        r#"
        SELECT key_version, digest
        FROM messaging.outbound_message_fingerprints
        WHERE outbound_message_id = $1
        "#,
    )
    .bind(existing.id)
    .fetch_all(&mut **transaction)
    .await?;
    let fingerprint_matches = std::iter::once(LookupDigest {
        key_version: input.payload.fingerprint_key_version,
        digest: input.payload.request_fingerprint,
    })
    .chain(input.payload.additional_fingerprints.iter().copied())
    .any(|incoming| {
        stored.iter().any(|stored| {
            stored.key_version == incoming.key_version
                && stored.digest.as_slice() == incoming.digest
        })
    });
    if fingerprint_matches {
        Ok(OutboundQueueOutcome::Duplicate {
            outbound_message_id,
        })
    } else {
        Ok(OutboundQueueOutcome::IdentifierCollision {
            outbound_message_id,
        })
    }
}

fn map_encrypted_outbound(row: BeginRow) -> Result<EncryptedOutboundMessage, PersistenceError> {
    let nonce: [u8; 12] = row.payload_nonce.try_into().map_err(|_| {
        PersistenceError::Invariant("outbound payload nonce has invalid length".to_owned())
    })?;
    Ok(EncryptedOutboundMessage {
        id: OutboundMessageId::from_uuid(row.id),
        payload_schema_version: row.payload_schema_version,
        payload: EncryptedValue {
            purpose: EncryptionPurpose::Integration,
            key_version: row.encryption_key_version,
            nonce,
            ciphertext: row.payload_ciphertext,
        },
        callback_token: CallbackToken::from_uuid(row.callback_token),
        send_attempt_count: row.send_attempt_count,
    })
}

async fn complete_job(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease: JobLease,
) -> Result<bool, PersistenceError> {
    let result = sqlx::query(
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
          AND state = 'leased'
          AND lease_owner = $2
          AND lease_token = $3
          AND lease_expires_at > statement_timestamp()
        "#,
    )
    .bind(lease.job_id.into_uuid())
    .bind(lease.worker_id.into_uuid())
    .bind(lease.token.into_uuid())
    .execute(&mut **transaction)
    .await?;
    Ok(result.rows_affected() == 1)
}

async fn finalize_failure(
    pool: &sqlx::PgPool,
    lease: JobLease,
    outbound_message_id: OutboundMessageId,
    state: &str,
    error_class: &str,
    error_code: &str,
) -> Result<OutboundMutation, PersistenceError> {
    validate_error_code(error_class)?;
    validate_error_code(error_code)?;
    let mut transaction = pool.begin().await?;
    let outbound: Option<Uuid> = sqlx::query_scalar(
        r#"
        UPDATE messaging.outbound_messages
        SET
            submission_state = $3,
            send_lease_token = NULL,
            last_error_class = $4,
            last_error_code = $5,
            unknown_at = CASE WHEN $3 = 'unknown' THEN statement_timestamp() ELSE NULL END,
            rejected_at = CASE WHEN $3 = 'rejected' THEN statement_timestamp() ELSE NULL END
        WHERE id = $1
          AND submission_state = 'sending'
          AND send_lease_token = $2
        RETURNING id
        "#,
    )
    .bind(outbound_message_id.into_uuid())
    .bind(lease.token.into_uuid())
    .bind(state)
    .bind(error_class)
    .bind(error_code)
    .fetch_optional(&mut *transaction)
    .await?;
    if outbound.is_none() {
        transaction.rollback().await?;
        return Ok(OutboundMutation::LostLease);
    }
    let job = sqlx::query(
        r#"
        UPDATE integration.outbox_jobs
        SET
            state = 'dead_lettered',
            lease_owner = NULL,
            lease_token = NULL,
            lease_started_at = NULL,
            lease_expires_at = NULL,
            last_error_class = $4,
            last_error_code = $5,
            last_error_at = statement_timestamp(),
            dead_lettered_at = statement_timestamp(),
            dead_letter_reason = $5
        WHERE id = $1
          AND state = 'leased'
          AND lease_owner = $2
          AND lease_token = $3
          AND lease_expires_at > statement_timestamp()
        "#,
    )
    .bind(lease.job_id.into_uuid())
    .bind(lease.worker_id.into_uuid())
    .bind(lease.token.into_uuid())
    .bind(error_class)
    .bind(error_code)
    .execute(&mut *transaction)
    .await?;
    if job.rows_affected() != 1 {
        transaction.rollback().await?;
        return Ok(OutboundMutation::LostLease);
    }
    transaction.commit().await?;
    Ok(OutboundMutation::Applied)
}

fn validate_opaque(name: &str, value: &str, maximum: usize) -> Result<(), PersistenceError> {
    if value.is_empty()
        || value.len() > maximum
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(PersistenceError::InvalidCommand(format!(
            "{name} is empty, oversized, or contains control characters"
        )));
    }
    Ok(())
}

fn validate_error_code(value: &str) -> Result<(), PersistenceError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
    {
        return Err(PersistenceError::InvalidCommand(
            "outbound error code is invalid".to_owned(),
        ));
    }
    Ok(())
}
