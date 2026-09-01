use sahayak_cryptography::{
    CryptoService, EncryptionContext, EncryptionKeySet, EncryptionNamespace, EncryptionPurpose,
    NormalizedPhoneNumber, VersionedKey,
};
use sahayak_domain::{
    CallbackToken, CorrelationId, DeliveryEventId, InboundEventId, OutboundMessageId, OutboxJobId,
    WorkerId,
};
use sahayak_persistence::{
    BeginSubmission, ClaimRequest, Database, DeliveryRecordOutcome, DeliveryRepository,
    DeliveryStatusInput, EncryptedEventPayload, EncryptedOutboundPayload, InboundEventInput,
    OutboundMutation, OutboundQueueOutcome, OutboundRepository, OutboxRepository,
    QueueOutboundMessage,
};
use sahayak_whatsapp::{
    NormalizedEvent, NormalizedPayload, OutboundMessage, PreparedMessage, TextMessage,
};
use secrecy::SecretString;
use sqlx::PgPool;
use std::{env, time::Duration};
use time::OffsetDateTime;

const TEST_DATABASE_ENVIRONMENT: &str = "SAHAYAK_TEST_DATABASE_URL";
const PROVIDER_NAMESPACE: &str = "phase3-waba:phase3-phone";

#[tokio::test]
async fn outbound_submission_and_delivery_are_durable_and_fenced()
-> Result<(), Box<dyn std::error::Error>> {
    let Some((database, assertion_pool)) = test_database().await? else {
        return Ok(());
    };
    let cryptography = crypto_service()?;
    let outbound = OutboundRepository::new(database.clone());
    let outbox = OutboxRepository::new(database.clone());
    cleanup_incomplete_sends(&assertion_pool).await?;

    let accepted_key = format!("transport.accepted.{}", OutboundMessageId::new());
    let (queued_input, prepared) = queue_input(&cryptography, &accepted_key, "Hello")?;
    let queued_id = queued_input.id;
    let callback_token = queued_input.callback_token;
    let provider_message_id = format!("wamid.{queued_id}");
    let queued = outbound.queue(&queued_input).await?;
    assert!(matches!(queued, OutboundQueueOutcome::Queued { .. }));

    let (duplicate_input, _) = queue_input_with_idempotency(
        &cryptography,
        &accepted_key,
        "Hello",
        OutboundMessageId::new(),
        OutboxJobId::new(),
        CallbackToken::new(),
    )?;
    assert_eq!(
        outbound.queue(&duplicate_input).await?,
        OutboundQueueOutcome::Duplicate {
            outbound_message_id: queued_id
        }
    );
    let (collision_input, _) = queue_input_with_idempotency(
        &cryptography,
        &accepted_key,
        "Different",
        OutboundMessageId::new(),
        OutboxJobId::new(),
        CallbackToken::new(),
    )?;
    assert_eq!(
        outbound.queue(&collision_input).await?,
        OutboundQueueOutcome::IdentifierCollision {
            outbound_message_id: queued_id
        }
    );

    let worker = WorkerId::new();
    let claimed = outbox
        .claim(
            ClaimRequest::new(worker, 1, Duration::from_secs(30))?
                .with_job_kinds(&["send_whatsapp_message"])?,
        )
        .await?
        .into_iter()
        .next()
        .ok_or("expected outbound send job")?;
    let begin = outbound
        .begin_submission(claimed.lease(), queued_id)
        .await?;
    let BeginSubmission::Ready(encrypted) = begin else {
        return Err("expected ready outbound submission".into());
    };
    let decrypted = cryptography.decrypt(
        EncryptionContext::new(
            EncryptionNamespace::OUTBOUND_MESSAGE_PAYLOAD,
            queued_id.into_uuid(),
        ),
        &encrypted.payload,
    )?;
    assert_eq!(
        PreparedMessage::from_persisted(decrypted.to_vec())?.expose(),
        prepared.expose()
    );
    assert_eq!(
        outbound
            .mark_accepted(
                claimed.lease(),
                queued_id,
                &provider_message_id,
                Some("accepted"),
            )
            .await?,
        OutboundMutation::Applied
    );

    let status_event = normalized_status(&provider_message_id, callback_token);
    let status_input = inbound_status_input(&cryptography, status_event.clone())?;
    let status_event_id = status_input.event_id;
    database.accept_inbound_event(&status_input).await?;
    let status_job = outbox
        .claim(
            ClaimRequest::new(WorkerId::new(), 1, Duration::from_secs(30))?
                .with_job_kinds(&["process_whatsapp_status"])?,
        )
        .await?
        .into_iter()
        .next()
        .ok_or("expected status job")?;
    let delivery = DeliveryRepository::new(database.clone())
        .record(
            status_job.lease(),
            &DeliveryStatusInput {
                id: DeliveryEventId::new(),
                inbound_event_id: status_event_id,
                provider_namespace: PROVIDER_NAMESPACE.to_owned(),
                provider_message_id: provider_message_id.clone(),
                status: "read".to_owned(),
                callback_data: Some(callback_token.to_string()),
                provider_error_code: None,
                error_class: None,
                provider_occurred_at: status_event.occurred_at.ok_or("status time missing")?,
                correlation_id: CorrelationId::new(),
            },
        )
        .await?;
    assert_eq!(
        delivery,
        DeliveryRecordOutcome::Recorded {
            outbound_message_id: Some(queued_id)
        }
    );
    let milestones: (bool, bool, bool) = sqlx::query_as(
        r#"
        SELECT sent_at IS NOT NULL, delivered_at IS NOT NULL, read_at IS NOT NULL
        FROM messaging.outbound_messages
        WHERE id = $1
        "#,
    )
    .bind(queued_id.into_uuid())
    .fetch_one(&assertion_pool)
    .await?;
    assert_eq!(milestones, (true, true, true));

    verifies_ambiguous_send_is_never_retried(&database, &assertion_pool, &cryptography).await?;
    verifies_definitive_failure_schedules_retry(&database, &assertion_pool, &cryptography).await?;

    assertion_pool.close().await;
    database.close().await;
    Ok(())
}

async fn verifies_definitive_failure_schedules_retry(
    database: &Database,
    assertion_pool: &PgPool,
    cryptography: &CryptoService,
) -> Result<(), Box<dyn std::error::Error>> {
    let outbound = OutboundRepository::new(database.clone());
    let outbox = OutboxRepository::new(database.clone());
    let retry_key = format!("transport.retry.{}", OutboundMessageId::new());
    let (input, _) = queue_input(cryptography, &retry_key, "Retry")?;
    let outbound_id = input.id;
    outbound.queue(&input).await?;
    let claim = outbox
        .claim(
            ClaimRequest::new(WorkerId::new(), 1, Duration::from_secs(30))?
                .with_job_kinds(&["send_whatsapp_message"])?,
        )
        .await?
        .into_iter()
        .next()
        .ok_or("expected retryable send job")?;
    assert!(matches!(
        outbound
            .begin_submission(claim.lease(), outbound_id)
            .await?,
        BeginSubmission::Ready(_)
    ));
    assert_eq!(
        outbound
            .mark_retryable(
                claim.lease(),
                outbound_id,
                "provider",
                "meta_130429",
                Duration::from_secs(60),
            )
            .await?,
        OutboundMutation::Applied
    );
    let states: (String, String, bool) = sqlx::query_as(
        r#"
        SELECT message.submission_state, job.state, job.available_at > statement_timestamp()
        FROM messaging.outbound_messages AS message
        JOIN integration.outbox_jobs AS job ON job.outbound_message_id = message.id
        WHERE message.id = $1
        "#,
    )
    .bind(outbound_id.into_uuid())
    .fetch_one(assertion_pool)
    .await?;
    assert_eq!(states, ("queued".to_owned(), "pending".to_owned(), true));
    Ok(())
}

async fn verifies_ambiguous_send_is_never_retried(
    database: &Database,
    assertion_pool: &PgPool,
    cryptography: &CryptoService,
) -> Result<(), Box<dyn std::error::Error>> {
    let outbound = OutboundRepository::new(database.clone());
    let outbox = OutboxRepository::new(database.clone());
    let unknown_key = format!("transport.unknown.{}", OutboundMessageId::new());
    let (input, _) = queue_input(cryptography, &unknown_key, "Unknown")?;
    let outbound_id = input.id;
    outbound.queue(&input).await?;
    let claim = outbox
        .claim(
            ClaimRequest::new(WorkerId::new(), 1, Duration::from_secs(30))?
                .with_job_kinds(&["send_whatsapp_message"])?,
        )
        .await?
        .into_iter()
        .next()
        .ok_or("expected ambiguous send job")?;
    assert!(matches!(
        outbound
            .begin_submission(claim.lease(), outbound_id)
            .await?,
        BeginSubmission::Ready(_)
    ));
    assert_eq!(
        outbound
            .mark_unknown(claim.lease(), outbound_id, "response_timeout")
            .await?,
        OutboundMutation::Applied
    );
    assert!(
        outbox
            .claim(
                ClaimRequest::new(WorkerId::new(), 10, Duration::from_secs(30))?
                    .with_job_kinds(&["send_whatsapp_message"])?
            )
            .await?
            .is_empty()
    );

    let abandoned_key = format!("transport.abandoned.{}", OutboundMessageId::new());
    let (abandoned_input, _) = queue_input(cryptography, &abandoned_key, "Abandoned")?;
    let abandoned_id = abandoned_input.id;
    outbound.queue(&abandoned_input).await?;
    let abandoned_claim = outbox
        .claim(
            ClaimRequest::new(WorkerId::new(), 1, Duration::from_secs(5))?
                .with_job_kinds(&["send_whatsapp_message"])?,
        )
        .await?
        .into_iter()
        .next()
        .ok_or("expected abandoned send job")?;
    assert!(matches!(
        outbound
            .begin_submission(abandoned_claim.lease(), abandoned_id)
            .await?,
        BeginSubmission::Ready(_)
    ));
    sqlx::query(
        r#"
        UPDATE integration.outbox_jobs
        SET
            lease_started_at = statement_timestamp() - INTERVAL '2 seconds',
            lease_expires_at = statement_timestamp() - INTERVAL '1 second'
        WHERE id = $1
        "#,
    )
    .bind(abandoned_claim.id.into_uuid())
    .execute(assertion_pool)
    .await?;
    assert_eq!(outbound.reap_abandoned_sends(10).await?, 1);
    let abandoned_state: (String, String) = sqlx::query_as(
        r#"
        SELECT message.submission_state, job.state
        FROM messaging.outbound_messages AS message
        JOIN integration.outbox_jobs AS job ON job.outbound_message_id = message.id
        WHERE message.id = $1
        "#,
    )
    .bind(abandoned_id.into_uuid())
    .fetch_one(assertion_pool)
    .await?;
    assert_eq!(
        abandoned_state,
        ("unknown".to_owned(), "dead_lettered".to_owned())
    );

    let queued_key = format!("transport.never-started.{}", OutboundMessageId::new());
    let (queued_input, _) = queue_input(cryptography, &queued_key, "Never started")?;
    let queued_id = queued_input.id;
    outbound.queue(&queued_input).await?;
    let queued_claim = outbox
        .claim(
            ClaimRequest::new(WorkerId::new(), 1, Duration::from_secs(5))?
                .with_job_kinds(&["send_whatsapp_message"])?,
        )
        .await?
        .into_iter()
        .next()
        .ok_or("expected never-started send job")?;
    sqlx::query(
        r#"
        UPDATE integration.outbox_jobs
        SET
            lease_started_at = statement_timestamp() - INTERVAL '2 seconds',
            lease_expires_at = statement_timestamp() - INTERVAL '1 second'
        WHERE id = $1
        "#,
    )
    .bind(queued_claim.id.into_uuid())
    .execute(assertion_pool)
    .await?;
    assert_eq!(outbound.reap_abandoned_sends(10).await?, 1);
    let queued_state: (String, String) = sqlx::query_as(
        r#"
        SELECT message.submission_state, job.state
        FROM messaging.outbound_messages AS message
        JOIN integration.outbox_jobs AS job ON job.outbound_message_id = message.id
        WHERE message.id = $1
        "#,
    )
    .bind(queued_id.into_uuid())
    .fetch_one(assertion_pool)
    .await?;
    assert_eq!(queued_state, ("queued".to_owned(), "pending".to_owned()));
    cleanup_incomplete_sends(assertion_pool).await?;
    Ok(())
}

fn queue_input(
    cryptography: &CryptoService,
    idempotency_key: &str,
    body: &str,
) -> Result<(QueueOutboundMessage, PreparedMessage), Box<dyn std::error::Error>> {
    queue_input_with_idempotency(
        cryptography,
        idempotency_key,
        body,
        OutboundMessageId::new(),
        OutboxJobId::new(),
        CallbackToken::new(),
    )
}

fn queue_input_with_idempotency(
    cryptography: &CryptoService,
    idempotency_key: &str,
    body: &str,
    id: OutboundMessageId,
    send_job_id: OutboxJobId,
    callback_token: CallbackToken,
) -> Result<(QueueOutboundMessage, PreparedMessage), Box<dyn std::error::Error>> {
    let recipient = NormalizedPhoneNumber::parse("+919876543210")?;
    let message = OutboundMessage::text(&recipient, TextMessage::new(body, false)?);
    let fingerprint_payload = message.prepare()?;
    let prepared = message
        .with_callback_data(&callback_token.to_string())?
        .prepare()?;
    let encrypted = cryptography.encrypt(
        EncryptionPurpose::Integration,
        EncryptionContext::new(
            EncryptionNamespace::OUTBOUND_MESSAGE_PAYLOAD,
            id.into_uuid(),
        ),
        prepared.expose(),
    )?;
    let (fingerprint_key_version, request_fingerprint) = cryptography.blind_index(
        "messaging:whatsapp:outbound_request:v1",
        fingerprint_payload.expose(),
    )?;
    Ok((
        QueueOutboundMessage {
            id,
            provider_namespace: PROVIDER_NAMESPACE.to_owned(),
            recipient_channel_identity_id: None,
            idempotency_key: format!("transport_probe:{idempotency_key}"),
            payload: EncryptedOutboundPayload {
                schema_version: 1,
                encrypted,
                fingerprint_key_version,
                request_fingerprint,
                additional_fingerprints: Vec::new(),
            },
            callback_token,
            correlation_id: CorrelationId::new(),
            ordering_key: None,
            send_job_id,
            max_attempts: 3,
        },
        prepared,
    ))
}

fn normalized_status(provider_message_id: &str, callback: CallbackToken) -> NormalizedEvent {
    NormalizedEvent {
        provider_event_id: format!("status:{provider_message_id}:read"),
        event_type: "message.status".to_owned(),
        occurred_at: Some(OffsetDateTime::now_utc()),
        payload: NormalizedPayload::Status {
            provider_message_id: provider_message_id.to_owned(),
            status: "read".to_owned(),
            recipient_id: "919876543210".to_owned(),
            participant_id: None,
            callback_data: Some(callback.to_string()),
            error_codes: Vec::new(),
        },
    }
}

fn inbound_status_input(
    cryptography: &CryptoService,
    event: NormalizedEvent,
) -> Result<InboundEventInput, Box<dyn std::error::Error>> {
    let id = InboundEventId::new();
    let serialized = serde_json::to_vec(&event)?;
    let encrypted = cryptography.encrypt(
        EncryptionPurpose::Integration,
        EncryptionContext::new(EncryptionNamespace::INBOUND_EVENT_PAYLOAD, id.into_uuid()),
        &serialized,
    )?;
    let (fingerprint_key_version, payload_fingerprint) =
        cryptography.blind_index("integration:whatsapp:event:v1", &serialized)?;
    Ok(InboundEventInput {
        event_id: id,
        provider_code: "whatsapp".to_owned(),
        provider_namespace: PROVIDER_NAMESPACE.to_owned(),
        provider_event_id: event.provider_event_id,
        event_type: event.event_type,
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
        provider_occurred_at: event.occurred_at,
        processing_job_id: OutboxJobId::new(),
        processing_job_kind: "process_whatsapp_status".to_owned(),
        processing_ordering_key: None,
        max_attempts: 3,
    })
}

fn crypto_service() -> Result<CryptoService, Box<dyn std::error::Error>> {
    Ok(CryptoService::new(
        vec![EncryptionKeySet::new(
            EncryptionPurpose::Integration,
            1,
            vec![VersionedKey::from_bytes(1, [73; 32])?],
        )],
        1,
        vec![VersionedKey::from_bytes(1, [79; 32])?],
    )?)
}

async fn test_database() -> Result<Option<(Database, PgPool)>, Box<dyn std::error::Error>> {
    let Ok(database_url) = env::var(TEST_DATABASE_ENVIRONMENT) else {
        return Ok(None);
    };
    let settings = sahayak_configuration::DatabaseSettings {
        url: SecretString::from(database_url.clone()),
        min_connections: 1,
        max_connections: 10,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 30,
        max_lifetime_seconds: 60,
        statement_timeout_milliseconds: 10_000,
        lock_timeout_milliseconds: 5_000,
        idle_in_transaction_timeout_milliseconds: 10_000,
        require_tls: false,
    };
    let database = Database::connect(&settings, "whatsapp-transport-test").await?;
    let assertion_pool = PgPool::connect(&database_url).await?;
    Ok(Some((database, assertion_pool)))
}

async fn cleanup_incomplete_sends(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE messaging.outbound_messages
        SET
            submission_state = CASE
                WHEN submission_state = 'sending' THEN 'unknown'
                ELSE 'rejected'
            END,
            send_lease_token = NULL,
            unknown_at = CASE
                WHEN submission_state = 'sending' THEN statement_timestamp()
                ELSE NULL
            END,
            rejected_at = CASE
                WHEN submission_state = 'queued' THEN statement_timestamp()
                ELSE NULL
            END,
            last_error_class = 'test_cleanup',
            last_error_code = 'test_cleanup'
        WHERE submission_state IN ('queued', 'sending')
        "#,
    )
    .execute(&mut *transaction)
    .await?;
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
        WHERE job_kind = 'send_whatsapp_message'
          AND state IN ('pending', 'leased')
        "#,
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}
