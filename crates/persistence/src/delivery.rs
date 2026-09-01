use crate::{Database, JobLease, PersistenceError};
use sahayak_domain::{CorrelationId, DeliveryEventId, InboundEventId, OutboundMessageId};
use time::OffsetDateTime;
use uuid::Uuid;

/// Normalized Meta delivery transition processed from one inbound event.
#[derive(Clone, Debug)]
pub struct DeliveryStatusInput {
    /// New internal delivery-event identifier.
    pub id: DeliveryEventId,
    /// Source immutable inbound status event.
    pub inbound_event_id: InboundEventId,
    /// WABA and sender phone-number namespace.
    pub provider_namespace: String,
    /// Meta outbound message ID.
    pub provider_message_id: String,
    /// `sent`, `delivered`, `read`, `played`, or `failed`.
    pub status: String,
    /// Opaque callback token sent with the outbound request.
    pub callback_data: Option<String>,
    /// First numeric Meta delivery failure code.
    pub provider_error_code: Option<i64>,
    /// Internal bounded error classification.
    pub error_class: Option<String>,
    /// Provider occurrence time.
    pub provider_occurred_at: OffsetDateTime,
    /// Correlation identifier used by atomic qualification and reversal audit events.
    pub correlation_id: CorrelationId,
}

impl DeliveryStatusInput {
    fn validate(&self) -> Result<(), PersistenceError> {
        if self.provider_namespace.is_empty() || self.provider_namespace.len() > 128 {
            return Err(PersistenceError::InvalidCommand(
                "delivery provider namespace is invalid".to_owned(),
            ));
        }
        if self.provider_message_id.is_empty() || self.provider_message_id.len() > 512 {
            return Err(PersistenceError::InvalidCommand(
                "delivery provider message ID is invalid".to_owned(),
            ));
        }
        if !matches!(
            self.status.as_str(),
            "sent" | "delivered" | "read" | "played" | "failed"
        ) {
            return Err(PersistenceError::InvalidCommand(
                "delivery status is unsupported".to_owned(),
            ));
        }
        if self.status != "failed"
            && (self.provider_error_code.is_some() || self.error_class.is_some())
        {
            return Err(PersistenceError::InvalidCommand(
                "successful delivery statuses cannot carry errors".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Result of append-only delivery persistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryRecordOutcome {
    /// New transition stored and optional outbound summary updated.
    Recorded {
        /// Resolved outbound message, or `None` for an orphan status.
        outbound_message_id: Option<OutboundMessageId>,
    },
    /// This inbound status event was already processed.
    Duplicate,
    /// Worker no longer owns the processing lease.
    LostLease,
}

/// Append-only delivery status operations.
#[derive(Clone, Debug)]
pub struct DeliveryRepository {
    database: Database,
}

impl DeliveryRepository {
    /// Creates a delivery repository over the shared pool.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Stores one status, updates monotonic milestones, and completes its fenced job.
    pub async fn record(
        &self,
        lease: JobLease,
        input: &DeliveryStatusInput,
    ) -> Result<DeliveryRecordOutcome, PersistenceError> {
        input.validate()?;
        let mut transaction = self.database.pool().begin().await?;
        let outbound_id = resolve_outbound(&mut transaction, input).await?;
        let inserted: Option<Uuid> = sqlx::query_scalar(
            r#"
            INSERT INTO messaging.outbound_delivery_events (
                id,
                inbound_event_id,
                outbound_message_id,
                provider_code,
                provider_namespace,
                provider_message_id,
                provider_status,
                provider_error_code,
                error_class,
                provider_occurred_at
            )
            VALUES ($1, $2, $3, 'whatsapp', $4, $5, $6, $7, $8, $9)
            ON CONFLICT (inbound_event_id) DO NOTHING
            RETURNING id
            "#,
        )
        .bind(input.id.into_uuid())
        .bind(input.inbound_event_id.into_uuid())
        .bind(outbound_id)
        .bind(&input.provider_namespace)
        .bind(&input.provider_message_id)
        .bind(&input.status)
        .bind(input.provider_error_code)
        .bind(&input.error_class)
        .bind(input.provider_occurred_at)
        .fetch_optional(&mut *transaction)
        .await?;
        if inserted.is_none() {
            let completed = complete_processing_job(&mut transaction, lease).await?;
            if !completed {
                transaction.rollback().await?;
                return Ok(DeliveryRecordOutcome::LostLease);
            }
            transaction.commit().await?;
            return Ok(DeliveryRecordOutcome::Duplicate);
        }

        if let Some(outbound_id) = outbound_id {
            update_outbound_summary(&mut transaction, outbound_id, input).await?;
            if input.status != "sent" {
                sqlx::query("SELECT set_config('sahayak.connection_mutation', 'on', true)")
                    .execute(&mut *transaction)
                    .await?;
                crate::connection::record_contact_delivery_in_transaction(
                    &mut transaction,
                    OutboundMessageId::from_uuid(outbound_id),
                    matches!(input.status.as_str(), "delivered" | "read" | "played"),
                    input.error_class.as_deref(),
                    input.correlation_id,
                )
                .await?;
            }
        }
        if !complete_processing_job(&mut transaction, lease).await? {
            transaction.rollback().await?;
            return Ok(DeliveryRecordOutcome::LostLease);
        }
        transaction.commit().await?;
        Ok(DeliveryRecordOutcome::Recorded {
            outbound_message_id: outbound_id.map(OutboundMessageId::from_uuid),
        })
    }
}

async fn resolve_outbound(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: &DeliveryStatusInput,
) -> Result<Option<Uuid>, PersistenceError> {
    if let Some(callback) = input
        .callback_data
        .as_deref()
        .and_then(|value| Uuid::parse_str(value).ok())
    {
        let found = sqlx::query_scalar(
            "SELECT id FROM messaging.outbound_messages WHERE callback_token = $1",
        )
        .bind(callback)
        .fetch_optional(&mut **transaction)
        .await?;
        if found.is_some() {
            return Ok(found);
        }
    }
    sqlx::query_scalar(
        r#"
        SELECT id
        FROM messaging.outbound_messages
        WHERE provider_code = 'whatsapp'
          AND provider_namespace = $1
          AND provider_message_id = $2
        "#,
    )
    .bind(&input.provider_namespace)
    .bind(&input.provider_message_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(PersistenceError::from)
}

async fn update_outbound_summary(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    outbound_id: Uuid,
    input: &DeliveryStatusInput,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        UPDATE messaging.outbound_messages
        SET
            submission_state = CASE
                WHEN submission_state IN ('sending', 'unknown') THEN 'accepted'
                ELSE submission_state
            END,
            send_lease_token = CASE
                WHEN submission_state IN ('sending', 'unknown') THEN NULL
                ELSE send_lease_token
            END,
            provider_message_id = COALESCE(provider_message_id, $3),
            accepted_at = CASE
                WHEN submission_state IN ('sending', 'unknown')
                    THEN COALESCE(accepted_at, statement_timestamp())
                ELSE accepted_at
            END,
            unknown_at = CASE
                WHEN submission_state IN ('sending', 'unknown') THEN NULL
                ELSE unknown_at
            END,
            sent_at = CASE
                WHEN $2 IN ('sent', 'delivered', 'read', 'played')
                    THEN LEAST(COALESCE(sent_at, $4), $4)
                ELSE sent_at
            END,
            delivered_at = CASE
                WHEN $2 IN ('delivered', 'read', 'played')
                    THEN LEAST(COALESCE(delivered_at, $4), $4)
                ELSE delivered_at
            END,
            read_at = CASE
                WHEN $2 IN ('read', 'played') THEN LEAST(COALESCE(read_at, $4), $4)
                ELSE read_at
            END,
            played_at = CASE
                WHEN $2 = 'played' THEN LEAST(COALESCE(played_at, $4), $4)
                ELSE played_at
            END,
            failed_at = CASE
                WHEN $2 = 'failed' THEN LEAST(COALESCE(failed_at, $4), $4)
                ELSE failed_at
            END,
            last_error_class = CASE WHEN $2 = 'failed' THEN $5 ELSE last_error_class END,
            last_error_code = CASE WHEN $2 = 'failed' THEN $6 ELSE last_error_code END
        WHERE id = $1
        "#,
    )
    .bind(outbound_id)
    .bind(&input.status)
    .bind(&input.provider_message_id)
    .bind(input.provider_occurred_at)
    .bind(&input.error_class)
    .bind(input.provider_error_code.map(|code| code.to_string()))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn complete_processing_job(
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
