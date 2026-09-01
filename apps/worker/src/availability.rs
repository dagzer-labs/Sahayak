use sahayak_domain::WorkerId;
use sahayak_persistence::{
    ADVANCE_AVAILABILITY_JOB, AvailabilityRepository, AvailabilityTimerPurpose, ClaimRequest,
    ConnectionRepository, Database, EXPIRE_CONNECTION_JOB, OutboxRepository,
    REMIND_AVAILABILITY_JOB,
};
use std::time::Duration;

/// Provider-neutral timer processing used when WhatsApp delivery is disabled.
pub(crate) struct AvailabilityTimerProcessor {
    worker_id: WorkerId,
    database: Database,
    outbox: OutboxRepository,
    availability: AvailabilityRepository,
    batch_size: u16,
    lease_duration: Duration,
}

impl AvailabilityTimerProcessor {
    pub(crate) fn new(database: Database, batch_size: u16, lease_duration: Duration) -> Self {
        Self {
            worker_id: WorkerId::new(),
            database: database.clone(),
            outbox: OutboxRepository::new(database.clone()),
            availability: AvailabilityRepository::new(database),
            batch_size,
            lease_duration,
        }
    }

    pub(crate) async fn process_batch(
        &self,
    ) -> Result<usize, sahayak_persistence::PersistenceError> {
        let jobs = self
            .outbox
            .claim(
                ClaimRequest::new(self.worker_id, self.batch_size, self.lease_duration)?
                    .with_job_kinds(&[
                        REMIND_AVAILABILITY_JOB,
                        ADVANCE_AVAILABILITY_JOB,
                        EXPIRE_CONNECTION_JOB,
                    ])?,
            )
            .await?;
        let count = jobs.len();
        for job in jobs {
            if job.job_kind == EXPIRE_CONNECTION_JOB {
                let Some(connection_id) = job.connection_request_id else {
                    self.outbox
                        .record_failure(
                            job.lease(),
                            &sahayak_persistence::FailureDisposition::Terminal {
                                error_class: "invalid_job".to_owned(),
                                error_code: "connection_request_missing".to_owned(),
                            },
                        )
                        .await?;
                    continue;
                };
                let Some(generation) = job.connection_generation else {
                    self.outbox
                        .record_failure(
                            job.lease(),
                            &sahayak_persistence::FailureDisposition::Terminal {
                                error_class: "invalid_job".to_owned(),
                                error_code: "connection_generation_missing".to_owned(),
                            },
                        )
                        .await?;
                    continue;
                };
                let _ = ConnectionRepository::new(self.database.clone())
                    .process_expiry(job.lease(), connection_id, generation, job.correlation_id)
                    .await?;
                continue;
            }
            let Some(epoch_id) = job.availability_epoch_id else {
                self.outbox
                    .record_failure(
                        job.lease(),
                        &sahayak_persistence::FailureDisposition::Terminal {
                            error_class: "invalid_job".to_owned(),
                            error_code: "availability_epoch_missing".to_owned(),
                        },
                    )
                    .await?;
                continue;
            };
            let Some(generation) = job.availability_generation else {
                self.outbox
                    .record_failure(
                        job.lease(),
                        &sahayak_persistence::FailureDisposition::Terminal {
                            error_class: "invalid_job".to_owned(),
                            error_code: "availability_generation_missing".to_owned(),
                        },
                    )
                    .await?;
                continue;
            };
            let purpose = if job.job_kind == ADVANCE_AVAILABILITY_JOB {
                AvailabilityTimerPurpose::Advance
            } else {
                AvailabilityTimerPurpose::Reminder
            };
            let _ = self
                .availability
                .process_timer(
                    job.lease(),
                    epoch_id,
                    generation,
                    purpose,
                    job.correlation_id,
                    None,
                )
                .await?;
        }
        Ok(count)
    }

    pub(crate) async fn reconcile(&self) -> Result<u64, sahayak_persistence::PersistenceError> {
        self.availability.reconcile_missing_timers(100).await
    }
}
