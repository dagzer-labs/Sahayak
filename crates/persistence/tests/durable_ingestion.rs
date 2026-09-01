use sahayak_cryptography::{
    CryptoService, EncryptionContext, EncryptionKeySet, EncryptionNamespace, EncryptionPurpose,
    VersionedKey,
};
use sahayak_domain::{CorrelationId, InboundEventId, OutboxJobId, WorkerId};
use sahayak_persistence::{
    Acceptance, ClaimRequest, Database, EncryptedEventPayload, FailureDisposition, FailureOutcome,
    InboundEventInput, LeaseOutcome, OutboxRepository,
};
use secrecy::SecretString;
use sqlx::PgPool;
use std::{env, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::task::JoinSet;
use uuid::Uuid;

const TEST_DATABASE_ENVIRONMENT: &str = "SAHAYAK_TEST_DATABASE_URL";

#[tokio::test]
async fn inbound_acceptance_and_outbox_leases_are_durable() -> Result<(), Box<dyn std::error::Error>>
{
    let Some((database, assertion_pool)) = test_database().await? else {
        return Ok(());
    };

    reset_integration_tables(&assertion_pool).await?;
    verifies_duplicate_and_collision_handling(&database, &assertion_pool).await?;

    reset_integration_tables(&assertion_pool).await?;
    verifies_concurrent_acceptance(&database, &assertion_pool).await?;

    reset_integration_tables(&assertion_pool).await?;
    verifies_atomic_rollback_when_job_insert_fails(&database, &assertion_pool).await?;

    reset_integration_tables(&assertion_pool).await?;
    verifies_lease_fencing_and_reclaim(&database, &assertion_pool).await?;

    reset_integration_tables(&assertion_pool).await?;
    verifies_retry_and_dead_letter_transitions(&database, &assertion_pool).await?;

    reset_integration_tables(&assertion_pool).await?;
    verifies_concurrent_claims_are_disjoint(&database).await?;

    assertion_pool.close().await;
    database.close().await;
    Ok(())
}

async fn verifies_duplicate_and_collision_handling(
    database: &Database,
    assertion_pool: &PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let provider_event_id = format!("message.{}", Uuid::now_v7());
    let accepted = database
        .accept_inbound_event(&event_input(&provider_event_id, 7, 3)?)
        .await?;
    let duplicate = database
        .accept_inbound_event(&event_input(&provider_event_id, 7, 3)?)
        .await?;
    let collision = database
        .accept_inbound_event(&event_input(&provider_event_id, 8, 3)?)
        .await?;
    let mut different_type = event_input(&provider_event_id, 7, 3)?;
    different_type.event_type = "status.received".to_owned();
    let type_collision = database.accept_inbound_event(&different_type).await?;

    let accepted_event_id = match accepted {
        Acceptance::Accepted { event_id, .. } => event_id,
        outcome => return Err(format!("expected accepted event, received {outcome:?}").into()),
    };
    assert_eq!(
        duplicate,
        Acceptance::Duplicate {
            event_id: accepted_event_id
        }
    );
    assert_eq!(
        collision,
        Acceptance::IdentifierCollision {
            event_id: accepted_event_id
        }
    );
    assert_eq!(
        type_collision,
        Acceptance::IdentifierCollision {
            event_id: accepted_event_id
        }
    );

    let event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM integration.inbound_events WHERE provider_event_id = $1",
    )
    .bind(&provider_event_id)
    .fetch_one(assertion_pool)
    .await?;
    let job_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM integration.outbox_jobs
        WHERE inbound_event_id = $1
          AND job_kind = 'process_webhook'
        "#,
    )
    .bind(accepted_event_id.into_uuid())
    .fetch_one(assertion_pool)
    .await?;

    assert_eq!(event_count, 1);
    assert_eq!(job_count, 1);
    let mutation =
        sqlx::query("UPDATE integration.inbound_events SET event_type = 'tampered' WHERE id = $1")
            .bind(accepted_event_id.into_uuid())
            .execute(assertion_pool)
            .await;
    assert!(mutation.is_err());
    let deletion = sqlx::query("DELETE FROM integration.inbound_events WHERE id = $1")
        .bind(accepted_event_id.into_uuid())
        .execute(assertion_pool)
        .await;
    assert!(deletion.is_err());
    Ok(())
}

async fn verifies_concurrent_acceptance(
    database: &Database,
    assertion_pool: &PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let database = Arc::new(database.clone());
    let provider_event_id = format!("message.{}", Uuid::now_v7());
    let mut tasks = JoinSet::new();

    for _ in 0..20 {
        let database = Arc::clone(&database);
        let input = event_input(&provider_event_id, 11, 3)?;
        tasks.spawn(async move { database.accept_inbound_event(&input).await });
    }

    let mut accepted = 0;
    let mut duplicates = 0;
    while let Some(result) = tasks.join_next().await {
        match result?? {
            Acceptance::Accepted { .. } => accepted += 1,
            Acceptance::Duplicate { .. } => duplicates += 1,
            Acceptance::IdentifierCollision { .. } => {
                return Err("identical concurrent payload reported a collision".into());
            }
        }
    }

    let counts: (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            (SELECT count(*) FROM integration.inbound_events WHERE provider_event_id = $1),
            (
                SELECT count(*)
                FROM integration.outbox_jobs AS job
                JOIN integration.inbound_events AS event ON event.id = job.inbound_event_id
                WHERE event.provider_event_id = $1
            )
        "#,
    )
    .bind(&provider_event_id)
    .fetch_one(assertion_pool)
    .await?;

    assert_eq!(accepted, 1);
    assert_eq!(duplicates, 19);
    assert_eq!(counts, (1, 1));
    Ok(())
}

async fn verifies_atomic_rollback_when_job_insert_fails(
    database: &Database,
    assertion_pool: &PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let first_provider_event_id = format!("message.{}", Uuid::now_v7());
    let existing_job_id = match database
        .accept_inbound_event(&event_input(&first_provider_event_id, 13, 3)?)
        .await?
    {
        Acceptance::Accepted { job_id, .. } => job_id,
        outcome => return Err(format!("expected accepted event, received {outcome:?}").into()),
    };

    let second_provider_event_id = format!("message.{}", Uuid::now_v7());
    let mut conflicting = event_input(&second_provider_event_id, 17, 3)?;
    conflicting.processing_job_id = existing_job_id;
    assert!(database.accept_inbound_event(&conflicting).await.is_err());

    let event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM integration.inbound_events WHERE provider_event_id = $1",
    )
    .bind(&second_provider_event_id)
    .fetch_one(assertion_pool)
    .await?;
    assert_eq!(event_count, 0);
    Ok(())
}

async fn verifies_lease_fencing_and_reclaim(
    database: &Database,
    assertion_pool: &PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let provider_event_id = format!("message.{}", Uuid::now_v7());
    database
        .accept_inbound_event(&event_input(&provider_event_id, 19, 2)?)
        .await?;

    let outbox = OutboxRepository::new(database.clone());
    let first_worker = WorkerId::new();
    let first_claim = outbox
        .claim(ClaimRequest::new(first_worker, 1, Duration::from_secs(1))?)
        .await?
        .into_iter()
        .next()
        .ok_or("expected first outbox claim")?;
    assert_eq!(
        outbox
            .renew(first_claim.lease(), Duration::from_secs(30))
            .await?,
        LeaseOutcome::Applied
    );

    sqlx::query(
        r#"
        UPDATE integration.outbox_jobs
        SET
            lease_started_at = statement_timestamp() - INTERVAL '2 seconds',
            lease_expires_at = statement_timestamp() - INTERVAL '1 second'
        WHERE id = $1
        "#,
    )
    .bind(first_claim.id.into_uuid())
    .execute(assertion_pool)
    .await?;
    assert_eq!(
        outbox.complete(first_claim.lease()).await?,
        LeaseOutcome::LostLease
    );

    let second_worker = WorkerId::new();
    let second_claim = outbox
        .claim(ClaimRequest::new(
            second_worker,
            1,
            Duration::from_secs(30),
        )?)
        .await?
        .into_iter()
        .next()
        .ok_or("expected reclaimed outbox job")?;

    assert_eq!(first_claim.id, second_claim.id);
    assert_ne!(first_claim.lease_token, second_claim.lease_token);
    assert_eq!(second_claim.attempt_count, 2);
    assert_eq!(
        outbox
            .renew(first_claim.lease(), Duration::from_secs(30))
            .await?,
        LeaseOutcome::LostLease
    );
    assert_eq!(
        outbox.complete(first_claim.lease()).await?,
        LeaseOutcome::LostLease
    );
    assert_eq!(
        outbox.complete(second_claim.lease()).await?,
        LeaseOutcome::Applied
    );
    Ok(())
}

async fn verifies_retry_and_dead_letter_transitions(
    database: &Database,
    assertion_pool: &PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let outbox = OutboxRepository::new(database.clone());
    database
        .accept_inbound_event(&event_input(&format!("message.{}", Uuid::now_v7()), 23, 2)?)
        .await?;

    let first_claim = outbox
        .claim(ClaimRequest::new(
            WorkerId::new(),
            1,
            Duration::from_secs(30),
        )?)
        .await?
        .into_iter()
        .next()
        .ok_or("expected retry test claim")?;
    let failure = FailureDisposition::Retry {
        error_class: "provider".to_owned(),
        error_code: "temporary_unavailable".to_owned(),
        after: Duration::from_secs(60),
    };
    assert!(matches!(
        outbox.record_failure(first_claim.lease(), &failure).await?,
        FailureOutcome::RetryScheduled { .. }
    ));
    assert!(
        outbox
            .claim(ClaimRequest::new(
                WorkerId::new(),
                1,
                Duration::from_secs(30)
            )?)
            .await?
            .is_empty()
    );

    sqlx::query(
        "UPDATE integration.outbox_jobs SET available_at = statement_timestamp() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(first_claim.id.into_uuid())
    .execute(assertion_pool)
    .await?;
    let final_claim = outbox
        .claim(ClaimRequest::new(
            WorkerId::new(),
            1,
            Duration::from_secs(30),
        )?)
        .await?
        .into_iter()
        .next()
        .ok_or("expected final retry claim")?;
    assert_eq!(final_claim.attempt_count, 2);
    assert_eq!(
        outbox.record_failure(final_claim.lease(), &failure).await?,
        FailureOutcome::DeadLettered
    );

    let state: String =
        sqlx::query_scalar("SELECT state FROM integration.outbox_jobs WHERE id = $1")
            .bind(final_claim.id.into_uuid())
            .fetch_one(assertion_pool)
            .await?;
    assert_eq!(state, "dead_lettered");

    database
        .accept_inbound_event(&event_input(&format!("message.{}", Uuid::now_v7()), 29, 1)?)
        .await?;
    let abandoned = outbox
        .claim(ClaimRequest::new(
            WorkerId::new(),
            1,
            Duration::from_secs(1),
        )?)
        .await?
        .into_iter()
        .next()
        .ok_or("expected final-attempt claim")?;
    sqlx::query(
        r#"
        UPDATE integration.outbox_jobs
        SET
            lease_started_at = statement_timestamp() - INTERVAL '2 seconds',
            lease_expires_at = statement_timestamp() - INTERVAL '1 second'
        WHERE id = $1
        "#,
    )
    .bind(abandoned.id.into_uuid())
    .execute(assertion_pool)
    .await?;
    assert_eq!(outbox.reap_exhausted_leases(10).await?, 1);
    let abandoned_state: String =
        sqlx::query_scalar("SELECT state FROM integration.outbox_jobs WHERE id = $1")
            .bind(abandoned.id.into_uuid())
            .fetch_one(assertion_pool)
            .await?;
    assert_eq!(abandoned_state, "dead_lettered");

    database
        .accept_inbound_event(&event_input(&format!("message.{}", Uuid::now_v7()), 31, 3)?)
        .await?;
    let terminal_claim = outbox
        .claim(ClaimRequest::new(
            WorkerId::new(),
            1,
            Duration::from_secs(30),
        )?)
        .await?
        .into_iter()
        .next()
        .ok_or("expected terminal-failure claim")?;
    assert_eq!(
        outbox
            .record_failure(
                terminal_claim.lease(),
                &FailureDisposition::Terminal {
                    error_class: "payload".to_owned(),
                    error_code: "unsupported_version".to_owned(),
                },
            )
            .await?,
        FailureOutcome::DeadLettered
    );
    assert_eq!(
        outbox.complete(terminal_claim.lease()).await?,
        LeaseOutcome::LostLease
    );
    Ok(())
}

async fn verifies_concurrent_claims_are_disjoint(
    database: &Database,
) -> Result<(), Box<dyn std::error::Error>> {
    for index in 0_u8..20 {
        database
            .accept_inbound_event(&event_input(
                &format!("message.{}", Uuid::now_v7()),
                index,
                3,
            )?)
            .await?;
    }

    let outbox = Arc::new(OutboxRepository::new(database.clone()));
    let first = {
        let outbox = Arc::clone(&outbox);
        tokio::spawn(async move {
            outbox
                .claim(ClaimRequest::new(
                    WorkerId::new(),
                    10,
                    Duration::from_secs(30),
                )?)
                .await
        })
    };
    let second = {
        let outbox = Arc::clone(&outbox);
        tokio::spawn(async move {
            outbox
                .claim(ClaimRequest::new(
                    WorkerId::new(),
                    10,
                    Duration::from_secs(30),
                )?)
                .await
        })
    };

    let first_jobs = first.await??;
    let second_jobs = second.await??;
    assert_eq!(first_jobs.len(), 10);
    assert_eq!(second_jobs.len(), 10);
    assert!(first_jobs.iter().all(|first_job| {
        second_jobs
            .iter()
            .all(|second_job| first_job.id != second_job.id)
    }));
    Ok(())
}

fn event_input(
    provider_event_id: &str,
    hash_byte: u8,
    max_attempts: i32,
) -> Result<InboundEventInput, Box<dyn std::error::Error>> {
    let event_id = InboundEventId::new();
    let plaintext = vec![hash_byte; 64];
    let cryptography = CryptoService::new(
        vec![
            EncryptionKeySet::new(
                EncryptionPurpose::Contact,
                1,
                vec![VersionedKey::from_bytes(1, [59; 32])?],
            ),
            EncryptionKeySet::new(
                EncryptionPurpose::Identity,
                1,
                vec![VersionedKey::from_bytes(1, [61; 32])?],
            ),
            EncryptionKeySet::new(
                EncryptionPurpose::Integration,
                1,
                vec![VersionedKey::from_bytes(1, [63; 32])?],
            ),
        ],
        1,
        vec![VersionedKey::from_bytes(1, [67; 32])?],
    )?;
    let encrypted = cryptography.encrypt(
        EncryptionPurpose::Integration,
        EncryptionContext::new(
            EncryptionNamespace::INBOUND_EVENT_PAYLOAD,
            event_id.into_uuid(),
        ),
        &plaintext,
    )?;
    let (fingerprint_key_version, payload_fingerprint) =
        cryptography.blind_index("integration:inbound_event:fingerprint", &plaintext)?;

    Ok(InboundEventInput {
        event_id,
        provider_code: "whatsapp".to_owned(),
        provider_namespace: "test-business-account".to_owned(),
        provider_event_id: provider_event_id.to_owned(),
        event_type: "message.received".to_owned(),
        payload: EncryptedEventPayload {
            purpose: EncryptionPurpose::Integration,
            schema_version: 1,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            fingerprint_key_version,
            payload_fingerprint,
            additional_fingerprints: Vec::new(),
            key_version: encrypted.key_version,
        },
        correlation_id: CorrelationId::new(),
        signature_verified_at: OffsetDateTime::now_utc(),
        provider_occurred_at: None,
        processing_job_id: OutboxJobId::new(),
        processing_job_kind: "process_webhook".to_owned(),
        processing_ordering_key: None,
        max_attempts,
    })
}

async fn test_database() -> Result<Option<(Database, PgPool)>, Box<dyn std::error::Error>> {
    let Ok(database_url) = env::var(TEST_DATABASE_ENVIRONMENT) else {
        return Ok(None);
    };
    let settings = sahayak_configuration::DatabaseSettings {
        url: SecretString::from(database_url.clone()),
        min_connections: 1,
        max_connections: 25,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 30,
        max_lifetime_seconds: 60,
        statement_timeout_milliseconds: 10_000,
        lock_timeout_milliseconds: 5_000,
        idle_in_transaction_timeout_milliseconds: 10_000,
        require_tls: false,
    };
    let database = Database::connect(&settings, "durable-ingestion-test").await?;
    let assertion_pool = PgPool::connect(&database_url).await?;
    Ok(Some((database, assertion_pool)))
}

async fn reset_integration_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE integration.outbox_jobs
        SET
            state = 'dead_lettered',
            attempt_count = GREATEST(attempt_count, 1),
            lease_owner = NULL,
            lease_token = NULL,
            lease_started_at = NULL,
            lease_expires_at = NULL,
            last_error_class = 'test_cleanup',
            last_error_code = 'test_cleanup',
            last_error_at = statement_timestamp(),
            dead_lettered_at = statement_timestamp(),
            dead_letter_reason = 'test_cleanup'
        WHERE state IN ('pending', 'leased')
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}
