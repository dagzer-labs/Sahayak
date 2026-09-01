use crate::{Database, PersistenceError};
use sahayak_domain::{
    AvailabilityEpochId, ConnectionRequestId, CorrelationId, InboundEventId, JobLeaseToken,
    OutboundMessageId, OutboxJobId, WorkerId,
};
use serde_json::Value;
use sqlx::FromRow;
use std::{fmt, time::Duration};
use time::OffsetDateTime;
use uuid::Uuid;

/// Validated request to atomically lease due outbox jobs.
#[derive(Clone, Debug)]
pub struct ClaimRequest {
    worker_id: WorkerId,
    batch_size: i64,
    lease_milliseconds: i64,
    job_kinds: Vec<String>,
}

impl ClaimRequest {
    /// Creates a bounded claim request.
    pub fn new(
        worker_id: WorkerId,
        batch_size: u16,
        lease_duration: Duration,
    ) -> Result<Self, PersistenceError> {
        if !(1..=100).contains(&batch_size) {
            return Err(PersistenceError::InvalidCommand(
                "outbox claim batch size must be between 1 and 100".to_owned(),
            ));
        }
        let lease_milliseconds = duration_milliseconds(lease_duration)?;
        if !(1_000..=900_000).contains(&lease_milliseconds) {
            return Err(PersistenceError::InvalidCommand(
                "outbox lease duration must be between 1 second and 15 minutes".to_owned(),
            ));
        }

        Ok(Self {
            worker_id,
            batch_size: i64::from(batch_size),
            lease_milliseconds,
            job_kinds: Vec::new(),
        })
    }

    /// Restricts this worker to explicitly supported handler codes.
    pub fn with_job_kinds(mut self, job_kinds: &[&str]) -> Result<Self, PersistenceError> {
        if job_kinds.is_empty() || job_kinds.len() > 16 {
            return Err(PersistenceError::InvalidCommand(
                "job kind filter must contain between 1 and 16 values".to_owned(),
            ));
        }
        for value in job_kinds {
            validate_error_code("job_kind", value, 128)?;
        }
        self.job_kinds = job_kinds.iter().map(|value| (*value).to_owned()).collect();
        Ok(self)
    }
}

/// One durable job leased to a specific worker instance and fencing token.
#[derive(Clone)]
pub struct ClaimedJob {
    /// Internal job identifier.
    pub id: OutboxJobId,
    /// Source inbound event when this job processes an external event.
    pub inbound_event_id: Option<InboundEventId>,
    /// Outbound submission referenced by a send job.
    pub outbound_message_id: Option<OutboundMessageId>,
    /// Availability epoch referenced by a provider-neutral timer job.
    pub availability_epoch_id: Option<AvailabilityEpochId>,
    /// Immutable generation expected by an availability timer.
    pub availability_generation: Option<i64>,
    /// Approval-required connection referenced by an expiry timer.
    pub connection_request_id: Option<ConnectionRequestId>,
    /// Immutable connection response generation expected by the timer.
    pub connection_generation: Option<i64>,
    /// Privacy-safe key preserving per-recipient processing order.
    pub ordering_key: Option<[u8; 32]>,
    /// Stable handler code.
    pub job_kind: String,
    /// Version of the typed payload contract.
    pub payload_version: i16,
    /// Non-sensitive structured payload containing references rather than PII.
    pub payload: Value,
    /// Current claim number, including abandoned claims.
    pub attempt_count: i32,
    /// Maximum claims before dead-lettering.
    pub max_attempts: i32,
    /// Worker process holding the lease.
    pub worker_id: WorkerId,
    /// Per-claim fencing token.
    pub lease_token: JobLeaseToken,
    /// Database-authoritative lease expiration time.
    pub lease_expires_at: OffsetDateTime,
    /// Correlation identifier inherited from the originating workflow.
    pub correlation_id: CorrelationId,
}

impl ClaimedJob {
    /// Returns the fencing identity required for every subsequent mutation.
    #[must_use]
    pub const fn lease(&self) -> JobLease {
        JobLease {
            job_id: self.id,
            worker_id: self.worker_id,
            token: self.lease_token,
        }
    }
}

impl fmt::Debug for ClaimedJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedJob")
            .field("id", &self.id)
            .field("inbound_event_id", &self.inbound_event_id)
            .field("outbound_message_id", &self.outbound_message_id)
            .field("availability_epoch_id", &self.availability_epoch_id)
            .field("availability_generation", &self.availability_generation)
            .field("connection_request_id", &self.connection_request_id)
            .field("connection_generation", &self.connection_generation)
            .field("has_ordering_key", &self.ordering_key.is_some())
            .field("job_kind", &self.job_kind)
            .field("payload_version", &self.payload_version)
            .field("payload", &"[REDACTED]")
            .field("attempt_count", &self.attempt_count)
            .field("max_attempts", &self.max_attempts)
            .field("worker_id", &self.worker_id)
            .field("lease_token", &"[REDACTED]")
            .field("lease_expires_at", &self.lease_expires_at)
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}

/// Fencing identity proving ownership of one current outbox lease.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct JobLease {
    /// Leased job identifier.
    pub job_id: OutboxJobId,
    /// Worker process that claimed the job.
    pub worker_id: WorkerId,
    /// Random token replaced on every claim or reclaim.
    pub token: JobLeaseToken,
}

impl fmt::Debug for JobLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobLease")
            .field("job_id", &self.job_id)
            .field("worker_id", &self.worker_id)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Result of a fenced completion or renewal operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseOutcome {
    /// The mutation matched the current lease and was applied.
    Applied,
    /// The lease no longer belongs to the caller.
    LostLease,
}

/// Classified handler failure used to retry or terminally dead-letter a job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailureDisposition {
    /// Retry after the supplied bounded delay when attempts remain.
    Retry {
        /// Sanitized failure category.
        error_class: String,
        /// Sanitized machine-readable code.
        error_code: String,
        /// Database-relative delay before another claim.
        after: Duration,
    },
    /// Do not retry this job automatically.
    Terminal {
        /// Sanitized failure category.
        error_class: String,
        /// Sanitized machine-readable code and dead-letter reason.
        error_code: String,
    },
}

/// Result of recording a fenced handler failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureOutcome {
    /// The job returned to pending state for a future claim.
    RetryScheduled {
        /// Database-authoritative next availability time.
        available_at: OffsetDateTime,
    },
    /// The job entered its terminal dead-letter state.
    DeadLettered,
    /// The supplied fencing token no longer owns the job.
    LostLease,
}

#[derive(FromRow)]
struct ClaimedRow {
    id: Uuid,
    inbound_event_id: Option<Uuid>,
    outbound_message_id: Option<Uuid>,
    availability_epoch_id: Option<Uuid>,
    availability_generation: Option<i64>,
    connection_request_id: Option<Uuid>,
    connection_generation: Option<i64>,
    ordering_key: Option<Vec<u8>>,
    job_kind: String,
    payload_version: i16,
    payload: Value,
    attempt_count: i32,
    max_attempts: i32,
    lease_owner: Uuid,
    lease_token: Uuid,
    lease_expires_at: OffsetDateTime,
    correlation_id: Uuid,
}

#[derive(FromRow)]
struct FailureRow {
    state: String,
    available_at: OffsetDateTime,
}

/// Concrete PostgreSQL outbox operations.
#[derive(Clone, Debug)]
pub struct OutboxRepository {
    database: Database,
}

impl OutboxRepository {
    /// Creates an outbox repository over the shared process pool.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Claims due jobs without waiting for rows already locked by another worker.
    pub async fn claim(&self, request: ClaimRequest) -> Result<Vec<ClaimedJob>, PersistenceError> {
        let rows = sqlx::query_as::<_, ClaimedRow>(
            r#"
            WITH candidates AS (
                SELECT id
                FROM integration.outbox_jobs AS candidate
                WHERE candidate.attempt_count < candidate.max_attempts
                  AND (
                      (candidate.state = 'pending' AND candidate.available_at <= statement_timestamp())
                      OR
                      (candidate.state = 'leased' AND candidate.lease_expires_at <= statement_timestamp())
                  )
                  AND ($4::text[] = '{}'::text[] OR candidate.job_kind = ANY($4::text[]))
                  AND (
                      candidate.ordering_key IS NULL
                      OR NOT EXISTS (
                          SELECT 1
                          FROM integration.outbox_jobs AS earlier
                          WHERE earlier.ordering_key = candidate.ordering_key
                            AND earlier.state IN ('pending', 'leased')
                            AND (earlier.created_at, earlier.id)
                                < (candidate.created_at, candidate.id)
                      )
                  )
                ORDER BY
                    candidate.priority DESC,
                    CASE
                        WHEN candidate.state = 'pending' THEN candidate.available_at
                        ELSE candidate.lease_expires_at
                    END,
                    candidate.created_at,
                    candidate.id
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE integration.outbox_jobs AS job
            SET
                state = 'leased',
                attempt_count = job.attempt_count + 1,
                lease_owner = $2,
                lease_token = uuidv4(),
                lease_started_at = statement_timestamp(),
                lease_expires_at =
                    statement_timestamp() + ($3::bigint * INTERVAL '1 millisecond'),
                last_error_class = CASE
                    WHEN job.state = 'leased' THEN 'abandoned_lease'
                    ELSE job.last_error_class
                END,
                last_error_code = CASE
                    WHEN job.state = 'leased' THEN 'lease_expired'
                    ELSE job.last_error_code
                END,
                last_error_at = CASE
                    WHEN job.state = 'leased' THEN statement_timestamp()
                    ELSE job.last_error_at
                END
            FROM candidates
            WHERE job.id = candidates.id
            RETURNING
                job.id,
                job.inbound_event_id,
                job.outbound_message_id,
                job.availability_epoch_id,
                job.availability_generation,
                job.connection_request_id,
                job.connection_generation,
                job.ordering_key,
                job.job_kind,
                job.payload_version,
                job.payload,
                job.attempt_count,
                job.max_attempts,
                job.lease_owner,
                job.lease_token,
                job.lease_expires_at,
                job.correlation_id
            "#,
        )
        .bind(request.batch_size)
        .bind(request.worker_id.into_uuid())
        .bind(request.lease_milliseconds)
        .bind(&request.job_kinds)
        .fetch_all(self.database.pool())
        .await?;

        rows.into_iter().map(map_claimed_row).collect()
    }

    /// Extends a lease if the caller still owns its fencing token.
    pub async fn renew(
        &self,
        lease: JobLease,
        duration: Duration,
    ) -> Result<LeaseOutcome, PersistenceError> {
        let milliseconds = lease_milliseconds(duration)?;
        let result = sqlx::query(
            r#"
            UPDATE integration.outbox_jobs
            SET lease_expires_at = statement_timestamp() + ($4::bigint * INTERVAL '1 millisecond')
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
        .bind(milliseconds)
        .execute(self.database.pool())
        .await?;

        Ok(mutation_outcome(result.rows_affected()))
    }

    /// Marks a job complete if the caller still owns its fencing token.
    pub async fn complete(&self, lease: JobLease) -> Result<LeaseOutcome, PersistenceError> {
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
        .execute(self.database.pool())
        .await?;

        Ok(mutation_outcome(result.rows_affected()))
    }

    /// Records a retryable or terminal handler failure under a fencing token.
    pub async fn record_failure(
        &self,
        lease: JobLease,
        disposition: &FailureDisposition,
    ) -> Result<FailureOutcome, PersistenceError> {
        match disposition {
            FailureDisposition::Retry {
                error_class,
                error_code,
                after,
            } => {
                validate_error_code("error_class", error_class, 64)?;
                validate_error_code("error_code", error_code, 128)?;
                let milliseconds = retry_milliseconds(*after)?;
                let row = sqlx::query_as::<_, FailureRow>(
                    r#"
                    UPDATE integration.outbox_jobs
                    SET
                        state = CASE
                            WHEN attempt_count >= max_attempts THEN 'dead_lettered'
                            ELSE 'pending'
                        END,
                        available_at = statement_timestamp()
                            + ($4::bigint * INTERVAL '1 millisecond'),
                        lease_owner = NULL,
                        lease_token = NULL,
                        lease_started_at = NULL,
                        lease_expires_at = NULL,
                        last_error_class = $5,
                        last_error_code = $6,
                        last_error_at = statement_timestamp(),
                        dead_lettered_at = CASE
                            WHEN attempt_count >= max_attempts THEN statement_timestamp()
                            ELSE NULL
                        END,
                        dead_letter_reason = CASE
                            WHEN attempt_count >= max_attempts THEN 'attempts_exhausted'
                            ELSE NULL
                        END
                    WHERE id = $1
                      AND state = 'leased'
                      AND lease_owner = $2
                      AND lease_token = $3
                      AND lease_expires_at > statement_timestamp()
                    RETURNING state, available_at
                    "#,
                )
                .bind(lease.job_id.into_uuid())
                .bind(lease.worker_id.into_uuid())
                .bind(lease.token.into_uuid())
                .bind(milliseconds)
                .bind(error_class)
                .bind(error_code)
                .fetch_optional(self.database.pool())
                .await?;
                map_failure_row(row)
            }
            FailureDisposition::Terminal {
                error_class,
                error_code,
            } => {
                validate_error_code("error_class", error_class, 64)?;
                validate_error_code("error_code", error_code, 128)?;
                let row = sqlx::query_as::<_, FailureRow>(
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
                    RETURNING state, available_at
                    "#,
                )
                .bind(lease.job_id.into_uuid())
                .bind(lease.worker_id.into_uuid())
                .bind(lease.token.into_uuid())
                .bind(error_class)
                .bind(error_code)
                .fetch_optional(self.database.pool())
                .await?;
                map_failure_row(row)
            }
        }
    }

    /// Dead-letters final attempts abandoned after their lease expired.
    pub async fn reap_exhausted_leases(&self, limit: u16) -> Result<u64, PersistenceError> {
        if !(1..=1_000).contains(&limit) {
            return Err(PersistenceError::InvalidCommand(
                "expired lease reap limit must be between 1 and 1000".to_owned(),
            ));
        }
        let result = sqlx::query(
            r#"
            WITH exhausted AS (
                SELECT id
                FROM integration.outbox_jobs
                WHERE state = 'leased'
                  AND job_kind <> 'send_whatsapp_message'
                  AND lease_expires_at <= statement_timestamp()
                  AND attempt_count >= max_attempts
                ORDER BY lease_expires_at, id
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE integration.outbox_jobs AS job
            SET
                state = 'dead_lettered',
                lease_owner = NULL,
                lease_token = NULL,
                lease_started_at = NULL,
                lease_expires_at = NULL,
                last_error_class = 'abandoned_lease',
                last_error_code = 'attempts_exhausted',
                last_error_at = statement_timestamp(),
                dead_lettered_at = statement_timestamp(),
                dead_letter_reason = 'attempts_exhausted_after_abandonment'
            FROM exhausted
            WHERE job.id = exhausted.id
            "#,
        )
        .bind(i64::from(limit))
        .execute(self.database.pool())
        .await?;
        Ok(result.rows_affected())
    }
}

fn map_claimed_row(row: ClaimedRow) -> Result<ClaimedJob, PersistenceError> {
    let lease_token = JobLeaseToken::from_uuid(row.lease_token);
    if row.lease_token.get_version_num() != 4 {
        return Err(PersistenceError::Invariant(
            "claimed outbox lease token is not UUIDv4".to_owned(),
        ));
    }

    let ordering_key = row
        .ordering_key
        .map(|value| {
            value.try_into().map_err(|_| {
                PersistenceError::Invariant("outbox ordering key has invalid length".to_owned())
            })
        })
        .transpose()?;
    if row.availability_epoch_id.is_some() != row.availability_generation.is_some() {
        return Err(PersistenceError::Invariant(
            "availability timer source is incomplete".to_owned(),
        ));
    }
    if row.connection_request_id.is_some() != row.connection_generation.is_some() {
        return Err(PersistenceError::Invariant(
            "connection timer source is incomplete".to_owned(),
        ));
    }
    Ok(ClaimedJob {
        id: OutboxJobId::from_uuid(row.id),
        inbound_event_id: row.inbound_event_id.map(InboundEventId::from_uuid),
        outbound_message_id: row.outbound_message_id.map(OutboundMessageId::from_uuid),
        availability_epoch_id: row
            .availability_epoch_id
            .map(AvailabilityEpochId::from_uuid),
        availability_generation: row.availability_generation,
        connection_request_id: row
            .connection_request_id
            .map(ConnectionRequestId::from_uuid),
        connection_generation: row.connection_generation,
        ordering_key,
        job_kind: row.job_kind,
        payload_version: row.payload_version,
        payload: row.payload,
        attempt_count: row.attempt_count,
        max_attempts: row.max_attempts,
        worker_id: WorkerId::from_uuid(row.lease_owner),
        lease_token,
        lease_expires_at: row.lease_expires_at,
        correlation_id: CorrelationId::from_uuid(row.correlation_id),
    })
}

fn map_failure_row(row: Option<FailureRow>) -> Result<FailureOutcome, PersistenceError> {
    match row {
        None => Ok(FailureOutcome::LostLease),
        Some(row) if row.state == "pending" => Ok(FailureOutcome::RetryScheduled {
            available_at: row.available_at,
        }),
        Some(row) if row.state == "dead_lettered" => Ok(FailureOutcome::DeadLettered),
        Some(row) => Err(PersistenceError::Invariant(format!(
            "failure transition returned unsupported state {}",
            row.state
        ))),
    }
}

const fn mutation_outcome(rows_affected: u64) -> LeaseOutcome {
    if rows_affected == 1 {
        LeaseOutcome::Applied
    } else {
        LeaseOutcome::LostLease
    }
}

fn duration_milliseconds(duration: Duration) -> Result<i64, PersistenceError> {
    i64::try_from(duration.as_millis()).map_err(|_| {
        PersistenceError::InvalidCommand("duration exceeds PostgreSQL interval bounds".to_owned())
    })
}

fn lease_milliseconds(duration: Duration) -> Result<i64, PersistenceError> {
    let milliseconds = duration_milliseconds(duration)?;
    if !(1_000..=900_000).contains(&milliseconds) {
        return Err(PersistenceError::InvalidCommand(
            "outbox lease duration must be between 1 second and 15 minutes".to_owned(),
        ));
    }
    Ok(milliseconds)
}

fn retry_milliseconds(duration: Duration) -> Result<i64, PersistenceError> {
    let milliseconds = duration_milliseconds(duration)?;
    if !(1_000..=2_592_000_000).contains(&milliseconds) {
        return Err(PersistenceError::InvalidCommand(
            "outbox retry delay must be between 1 second and 30 days".to_owned(),
        ));
    }
    Ok(milliseconds)
}

fn validate_error_code(name: &str, value: &str, maximum: usize) -> Result<(), PersistenceError> {
    let valid = !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        });
    if !valid {
        return Err(PersistenceError::InvalidCommand(format!(
            "{name} is not a valid bounded error code"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ClaimRequest, FailureDisposition, duration_milliseconds, validate_error_code};
    use sahayak_domain::WorkerId;
    use std::time::Duration;

    #[test]
    fn claim_request_enforces_operational_bounds() {
        assert!(ClaimRequest::new(WorkerId::new(), 1, Duration::from_secs(30)).is_ok());
        assert!(ClaimRequest::new(WorkerId::new(), 0, Duration::from_secs(30)).is_err());
        assert!(ClaimRequest::new(WorkerId::new(), 1, Duration::from_millis(999)).is_err());
    }

    #[test]
    fn durations_convert_without_truncation() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(duration_milliseconds(Duration::from_millis(1_250))?, 1_250);
        Ok(())
    }

    #[test]
    fn error_codes_reject_log_injection() {
        assert!(validate_error_code("error_code", "provider_timeout", 128).is_ok());
        assert!(validate_error_code("error_code", "provider\ntimeout", 128).is_err());
    }

    #[test]
    fn failure_disposition_debug_is_bounded_data() {
        let failure = FailureDisposition::Terminal {
            error_class: "provider".to_owned(),
            error_code: "invalid_request".to_owned(),
        };
        assert!(format!("{failure:?}").contains("invalid_request"));
    }
}
