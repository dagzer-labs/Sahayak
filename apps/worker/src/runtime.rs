use crate::{
    WorkerError, availability::AvailabilityTimerProcessor, health::HealthFailureBudget, shutdown,
    whatsapp::WhatsAppJobProcessor,
};
use sahayak_configuration::{Settings, load_secret_file};
use sahayak_payments::RazorpayClient;
use sahayak_persistence::{
    BillingRepository, ConversationRepository, Database, OperationsRepository, OutboundRepository,
    OutboxRepository,
};
use tokio::time::{MissedTickBehavior, interval, timeout};
use tracing::{error, info, warn};

const SERVICE_NAME: &str = "sahayak-worker";

/// Runs the worker supervisor until termination or sustained dependency failure.
///
/// Durable job handlers are intentionally added only with the webhook outbox phase.
pub async fn run(settings: Settings) -> Result<(), WorkerError> {
    let database = Database::connect(&settings.database, SERVICE_NAME).await?;
    let outbox = OutboxRepository::new(database.clone());
    let outbound = OutboundRepository::new(database.clone());
    let conversations = ConversationRepository::new(database.clone());
    let operations = OperationsRepository::new(database.clone());
    let billing = if settings.razorpay.enabled {
        let secret = load_secret_file(
            &settings.razorpay.key_secret_file,
            4_096,
            settings.environment.is_production(),
        )
        .map_err(|error| WorkerError::RazorpayInitialization(error.to_string()))?;
        let client = RazorpayClient::new(
            &settings.razorpay.api_base_url,
            settings.razorpay.key_id.clone(),
            secret,
        )
        .map_err(|error| WorkerError::RazorpayInitialization(error.to_string()))?;
        Some((client, BillingRepository::new(database.clone())))
    } else {
        None
    };
    let mut health_interval = interval(settings.worker.health_interval());
    health_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut job_interval = interval(settings.worker.job_poll_interval());
    job_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut retention_interval = interval(std::time::Duration::from_secs(86_400));
    retention_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut reconciliation_interval = interval(std::time::Duration::from_secs(21_600));
    reconciliation_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let whatsapp = if settings.whatsapp.enabled {
        Some(
            WhatsAppJobProcessor::load(
                &settings.whatsapp,
                &settings.worker,
                settings.environment,
                database.clone(),
            )
            .await
            .map_err(WorkerError::WhatsAppInitialization)?,
        )
    } else {
        None
    };
    let availability = AvailabilityTimerProcessor::new(
        database.clone(),
        settings.worker.job_claim_batch_size,
        settings.worker.job_lease(),
    );
    let mut failure_budget = HealthFailureBudget::default();
    let shutdown = shutdown::wait_for_signal();
    tokio::pin!(shutdown);

    info!("worker supervisor started");

    let result = loop {
        tokio::select! {
            signal = &mut shutdown => {
                signal.map_err(WorkerError::ShutdownSignal)?;
                info!("worker shutdown requested");
                break Ok(());
            }
            _ = health_interval.tick() => {
                match maintain_foundation(
                    &database,
                    &outbox,
                    &outbound,
                    &conversations,
                    &availability,
                    settings.worker.inbound_payload_retention(),
                ).await {
                    Ok((reaped, ambiguous_sends, expired_sessions, purged_payloads, repaired)) => {
                        failure_budget.record_success();
                        if repaired > 0 {
                            info!(repaired, "repaired missing availability timer jobs");
                        }
                        if reaped > 0 {
                            info!(reaped, "dead-lettered exhausted abandoned jobs");
                        }
                        if expired_sessions > 0 {
                            info!(expired_sessions, "expired stale conversation sessions");
                        }
                        if ambiguous_sends > 0 {
                            warn!(ambiguous_sends, "marked abandoned WhatsApp sends unknown");
                        }
                        if purged_payloads > 0 {
                            info!(purged_payloads, "purged retained encrypted webhook payloads");
                        }
                    }
                    Err(error) => {
                        let exhausted = failure_budget.record_failure();
                        warn!(
                            %error,
                            failures = failure_budget.consecutive_failures(),
                            "worker database health probe failed"
                        );
                        if exhausted {
                            error!("worker database failure budget exhausted");
                            break Err(WorkerError::DatabaseUnhealthy);
                        }
                    }
                }
            }
            _ = retention_interval.tick() => {
                match operations.apply_retention(
                    time::OffsetDateTime::now_utc() - time::Duration::days(30),
                    100,
                ).await {
                    Ok(outcome) if outcome.request_locations_purged > 0 => {
                        info!(purged_locations = outcome.request_locations_purged, "purged expired exact service locations");
                    }
                    Ok(_) => {}
                    Err(error) => warn!(%error, "retention maintenance failed"),
                }
            }
            _ = reconciliation_interval.tick(), if billing.is_some() => {
                if let Some((client, repository)) = billing.as_ref() {
                    match reconcile_billing(client, repository).await {
                        Ok(exceptions) if exceptions > 0 => {
                            warn!(exceptions, "Razorpay reconciliation opened manual exceptions");
                        }
                        Ok(_) => {}
                        Err(error) => warn!(%error, "Razorpay reconciliation failed"),
                    }
                }
            }
            _ = job_interval.tick() => {
                if let Some(processor) = &whatsapp {
                    match processor.process_batch().await {
                        Ok(processed) if processed > 0 => {
                            info!(processed, "processed WhatsApp transport jobs");
                        }
                        Ok(_) => {}
                        Err(error) => warn!(%error, "WhatsApp job batch failed"),
                    }
                } else {
                    match availability.process_batch().await {
                        Ok(processed) if processed > 0 => {
                            info!(processed, "processed availability timer jobs");
                        }
                        Ok(_) => {}
                        Err(error) => warn!(%error, "availability timer batch failed"),
                    }
                }
            }
        }
    };

    if timeout(settings.worker.shutdown_grace(), database.close())
        .await
        .is_err()
    {
        warn!("database pool close exceeded worker shutdown deadline");
    }

    result
}

async fn reconcile_billing(
    client: &RazorpayClient,
    repository: &BillingRepository,
) -> Result<u64, String> {
    let candidates = repository
        .reconciliation_candidates(50)
        .await
        .map_err(|error| error.to_string())?;
    let mut exceptions = 0_u64;
    for candidate in candidates {
        let provider = client
            .fetch_subscription(&candidate.provider_subscription_id)
            .await
            .map_err(|error| error.to_string())?;
        if !repository
            .record_reconciliation(&candidate, &provider.status)
            .await
            .map_err(|error| error.to_string())?
        {
            exceptions += 1;
        }
    }
    Ok(exceptions)
}

async fn maintain_foundation(
    database: &Database,
    outbox: &OutboxRepository,
    outbound: &OutboundRepository,
    conversations: &ConversationRepository,
    availability: &AvailabilityTimerProcessor,
    inbound_retention: std::time::Duration,
) -> Result<(u64, u64, u64, u64, u64), sahayak_persistence::PersistenceError> {
    database.check_health().await?;
    let ambiguous_sends = outbound.reap_abandoned_sends(100).await?;
    let reaped = outbox.reap_exhausted_leases(100).await?;
    let expired_sessions = conversations.expire_due(100).await?;
    let retention = time::Duration::try_from(inbound_retention).map_err(|_| {
        sahayak_persistence::PersistenceError::InvalidCommand(
            "inbound retention duration is invalid".to_owned(),
        )
    })?;
    let purged_payloads = database
        .purge_inbound_payloads(time::OffsetDateTime::now_utc() - retention, 100)
        .await?;
    let repaired_availability = availability.reconcile().await?;
    Ok((
        reaped,
        ambiguous_sends,
        expired_sessions,
        purged_payloads,
        repaired_availability,
    ))
}
