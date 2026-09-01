use crate::{Database, PersistenceError};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OperationalMetrics {
    pub outbox_ready: i64,
    pub outbox_dead_lettered: i64,
    pub oldest_ready_seconds: f64,
    pub overdue_safety_reports: i64,
    pub billing_webhooks_pending: i64,
    pub billing_webhooks_failed: i64,
}

#[derive(Clone, Debug)]
pub struct OperationsRepository {
    database: Database,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionOutcome {
    pub request_locations_purged: u64,
}

impl OperationsRepository {
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    pub async fn metrics(&self) -> Result<OperationalMetrics, PersistenceError> {
        let row: (i64, i64, f64, i64, i64, i64) = sqlx::query_as(
            r#"
            SELECT
                (SELECT count(*) FROM integration.outbox_jobs
                 WHERE state IN ('pending','retry_scheduled') AND available_at <= statement_timestamp()),
                (SELECT count(*) FROM integration.outbox_jobs WHERE state = 'dead_lettered'),
                COALESCE((SELECT EXTRACT(EPOCH FROM statement_timestamp() - min(available_at))
                          FROM integration.outbox_jobs
                          WHERE state IN ('pending','retry_scheduled') AND available_at <= statement_timestamp()), 0)::double precision,
                (SELECT count(*) FROM safety.reports
                 WHERE triage_state <> 'resolved' AND response_due_at < statement_timestamp()),
                (SELECT count(*) FROM billing.webhook_events WHERE processing_state IN ('pending','processing')),
                (SELECT count(*) FROM billing.webhook_events WHERE processing_state = 'failed')
            "#,
        ).fetch_one(self.database.pool()).await?;
        Ok(OperationalMetrics {
            outbox_ready: row.0,
            outbox_dead_lettered: row.1,
            oldest_ready_seconds: row.2.max(0.0),
            overdue_safety_reports: row.3,
            billing_webhooks_pending: row.4,
            billing_webhooks_failed: row.5,
        })
    }

    pub async fn apply_retention(
        &self,
        location_cutoff: time::OffsetDateTime,
        limit: i64,
    ) -> Result<RetentionOutcome, PersistenceError> {
        if !(1..=10_000).contains(&limit) {
            return Err(PersistenceError::InvalidCommand(
                "retention batch limit must be between 1 and 10000".to_owned(),
            ));
        }
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query("SELECT set_config('sahayak.discovery_mutation', 'on', true)")
            .execute(&mut *transaction)
            .await?;
        let purged = sqlx::query(
            r#"
            DELETE FROM private_data.service_request_locations AS location
            WHERE location.request_id IN (
                SELECT request.id
                FROM discovery.service_requests AS request
                WHERE request.created_at < $1
                  AND NOT EXISTS (
                      SELECT 1 FROM operations.legal_holds AS hold
                      WHERE hold.account_id = request.customer_account_id AND hold.ends_at IS NULL
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM safety.reports AS report
                      JOIN connection.contact_reveals AS reveal ON reveal.id = report.reveal_id
                      WHERE reveal.service_request_id = request.id AND report.triage_state <> 'resolved'
                  )
                ORDER BY request.created_at, request.id
                LIMIT $2
            )
            "#,
        )
        .bind(location_cutoff)
        .bind(limit)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO operations.retention_runs (id, policy_version, request_locations_purged, completed_at) VALUES (uuidv7(), 'pilot-v1', $1, statement_timestamp())",
        )
        .bind(i32::try_from(purged.rows_affected()).unwrap_or(i32::MAX))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(RetentionOutcome {
            request_locations_purged: purged.rows_affected(),
        })
    }
}
