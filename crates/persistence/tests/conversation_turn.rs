use sahayak_cryptography::{
    CryptoService, EncryptedValue, EncryptionContext, EncryptionKeySet, EncryptionNamespace,
    EncryptionPurpose, VersionedKey, content_sha256,
};
use sahayak_domain::{
    AccountId, AccountRole, AdministratorGrantId, AvailabilityDuration, AvailabilityEpochId,
    AvailabilityEpochState, CallbackToken, ChannelIdentityId, ConsentAction, ContactMode,
    ConversationSessionId, CorrelationId, InboundEventId, JobLeaseToken, LocalServiceMode,
    OutboundMessageId, OutboxJobId, ProfessionalConsentEventId, ProfessionalConsentPurpose,
    ProfessionalDisplayName, ProfessionalLanguage, ProfileReviewDecision, ProfileReviewDecisionId,
    ProfileReviewReason, ProfileRevisionId, PublicProfileId, PublicProfileReference,
    ServiceRadiusKm, WorkerId,
};
use sahayak_persistence::{
    AccountMutation, AccountRepository, AdministratorAllowlistRepository,
    AdministratorReviewTurnEffect, AvailabilityConversationSnapshot, AvailabilityRepository,
    AvailabilityTimerPurpose, AvailabilityTurnEffect, AvailabilityTurnOperation,
    BeginProfessionalDraft, CapacityConsumptionOutcome, ClaimRequest, CommitConversationTurn,
    ConversationSessionChange, ConversationTurnEffect, ConversationTurnEffects,
    ConversationTurnRepository, Database, EffectfulTurnCommitOutcome, EncryptedEventPayload,
    EncryptedOutboundPayload, GrantAdministratorAccess, IdentityRepository, InboundEventInput,
    JobLease, LookupDigest, NewWhatsAppAccount, OutboundRepository, OutboxRepository,
    ProfessionalConsentRepository, ProfessionalConversationStatus, ProfessionalProfileRepository,
    ProfessionalServiceInput, ProfessionalTurnEffect, ProfessionalTurnOperation, ProfileMutation,
    QueueOutboundMessage, RecordProfessionalConsent, SubmitProfileOutcome, TurnCommitOutcome,
    TurnDisposition,
};
use sahayak_whatsapp::{Button, ButtonMessage, OutboundMessage};
use secrecy::SecretString;
use sqlx::PgPool;
use std::{env, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::sync::Barrier;

const TEST_DATABASE_ENVIRONMENT: &str = "SAHAYAK_TEST_DATABASE_URL";
const PROVIDER_NAMESPACE: &str = "conversation-waba:conversation-phone";

#[tokio::test]
async fn concurrent_turn_commits_one_session_reply_job_and_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let Some((database, assertion_pool)) = test_database().await? else {
        return Ok(());
    };
    cleanup_conversation_jobs(&assertion_pool).await?;
    let cryptography = crypto_service()?;
    let (account_id, channel_identity_id) = create_identity(&database, &cryptography).await?;
    let inbound_event_id = InboundEventId::new();
    let ordering_key = content_sha256(inbound_event_id.to_string().as_bytes());
    let normalized = br#"{"kind":"message","value":"hello"}"#;
    let inbound_encrypted = cryptography.encrypt(
        EncryptionPurpose::Integration,
        EncryptionContext::new(
            EncryptionNamespace::INBOUND_EVENT_PAYLOAD,
            inbound_event_id.into_uuid(),
        ),
        normalized,
    )?;
    let (inbound_fingerprint_version, inbound_fingerprint) =
        cryptography.blind_index("integration:whatsapp:event:v1", normalized)?;
    database
        .accept_inbound_event(&InboundEventInput {
            event_id: inbound_event_id,
            provider_code: "whatsapp".to_owned(),
            provider_namespace: PROVIDER_NAMESPACE.to_owned(),
            provider_event_id: format!("message:{inbound_event_id}"),
            event_type: "message.received".to_owned(),
            payload: EncryptedEventPayload {
                purpose: EncryptionPurpose::Integration,
                schema_version: 1,
                ciphertext: inbound_encrypted.ciphertext,
                nonce: inbound_encrypted.nonce,
                fingerprint_key_version: inbound_fingerprint_version,
                payload_fingerprint: inbound_fingerprint,
                additional_fingerprints: Vec::new(),
                key_version: inbound_encrypted.key_version,
            },
            correlation_id: CorrelationId::new(),
            signature_verified_at: OffsetDateTime::now_utc(),
            provider_occurred_at: Some(OffsetDateTime::now_utc()),
            processing_job_id: OutboxJobId::new(),
            processing_job_kind: "process_conversation_message".to_owned(),
            processing_ordering_key: Some(ordering_key),
            max_attempts: 8,
        })
        .await?;
    let wrong_identity =
        create_identity_in_namespace(&database, &cryptography, PROVIDER_NAMESPACE).await?;
    let sender_suffix = channel_identity_id.into_uuid().as_u128() % 1_000_000_000;
    let sender_digests = fingerprints(
        &cryptography,
        &format!("whatsapp:{PROVIDER_NAMESPACE}:wa_id"),
        format!("919{sender_suffix:09}").as_bytes(),
    )?;
    assert!(
        database
            .bind_inbound_event_identity(
                inbound_event_id,
                wrong_identity.0,
                wrong_identity.1,
                &sender_digests,
            )
            .await
            .is_err()
    );
    bind_event(
        &database,
        &cryptography,
        inbound_event_id,
        account_id,
        channel_identity_id,
        PROVIDER_NAMESPACE,
    )
    .await?;
    let processing_job = OutboxRepository::new(database.clone())
        .claim(
            ClaimRequest::new(WorkerId::new(), 1, Duration::from_secs(30))?
                .with_job_kinds(&["process_conversation_message"])?,
        )
        .await?
        .into_iter()
        .next()
        .ok_or("conversation processing job missing")?;

    let session_id = ConversationSessionId::new();
    let workflow_correlation_id = CorrelationId::new();
    let outbound_id = OutboundMessageId::new();
    let callback = CallbackToken::new();
    let phone = sahayak_cryptography::NormalizedPhoneNumber::parse("+919876543210")?;
    let response = OutboundMessage::buttons(
        &phone,
        ButtonMessage::new(
            "आप क्या करना चाहते हैं?",
            vec![
                Button::new("main.find", "मदद चाहिए")?,
                Button::new("main.offer", "काम करना है")?,
                Button::new("main.more", "और विकल्प")?,
            ],
            None,
            None,
        )?,
    );
    let fingerprint_payload = response.prepare()?;
    let prepared = response
        .with_callback_data(&callback.to_string())?
        .prepare()?;
    let encrypted_response = cryptography.encrypt(
        EncryptionPurpose::Integration,
        EncryptionContext::new(
            EncryptionNamespace::OUTBOUND_MESSAGE_PAYLOAD,
            outbound_id.into_uuid(),
        ),
        prepared.expose(),
    )?;
    let (fingerprint_key_version, request_fingerprint) = cryptography.blind_index(
        "messaging:whatsapp:outbound_request:v1",
        fingerprint_payload.expose(),
    )?;
    let turn = CommitConversationTurn {
        lease: processing_job.lease(),
        inbound_event_id,
        account_id,
        channel_identity_id,
        expected_account_version: 1,
        workflow_correlation_id,
        reply_to_outbound_message_id: None,
        locale_change: Some("hi-IN".to_owned()),
        session_change: ConversationSessionChange::Create {
            session_id,
            workflow_key: "main_menu".to_owned(),
            workflow_version: 1,
            state_key: "show".to_owned(),
            state_data: serde_json::json!({}),
            language: "hi-IN".to_owned(),
            workflow_correlation_id,
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(30),
            expired_session: None,
        },
        outbound: QueueOutboundMessage {
            id: outbound_id,
            provider_namespace: PROVIDER_NAMESPACE.to_owned(),
            recipient_channel_identity_id: Some(channel_identity_id),
            idempotency_key: format!("conversation-turn:v1:{inbound_event_id}"),
            payload: EncryptedOutboundPayload {
                schema_version: 1,
                encrypted: encrypted_response,
                fingerprint_key_version,
                request_fingerprint,
                additional_fingerprints: Vec::new(),
            },
            callback_token: callback,
            correlation_id: CorrelationId::new(),
            ordering_key: Some(ordering_key),
            send_job_id: OutboxJobId::new(),
            max_attempts: 8,
        },
        disposition: TurnDisposition::Applied,
    };
    let repository = Arc::new(ConversationTurnRepository::new(database.clone()));
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let repository = Arc::clone(&repository);
        let barrier = Arc::clone(&barrier);
        let turn = turn.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            repository.commit(&turn).await
        }));
    }
    barrier.wait().await;
    let outcomes = vec![tasks.remove(0).await??, tasks.remove(0).await??];
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, TurnCommitOutcome::Committed { .. })),
        "unexpected outcomes: {outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, TurnCommitOutcome::AlreadyCommitted { .. }))
    );

    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            (SELECT count(*) FROM messaging.conversation_sessions WHERE channel_identity_id = $1 AND status = 'active'),
            (SELECT count(*) FROM messaging.conversation_turn_receipts WHERE inbound_event_id = $2),
            (SELECT count(*) FROM messaging.outbound_messages WHERE conversation_session_id = $3),
            (SELECT count(*) FROM integration.outbox_jobs WHERE outbound_message_id = $4)
        "#,
    )
    .bind(channel_identity_id.into_uuid())
    .bind(inbound_event_id.into_uuid())
    .bind(session_id.into_uuid())
    .bind(outbound_id.into_uuid())
    .fetch_one(&assertion_pool)
    .await?;
    assert_eq!(counts, (1, 1, 1, 1));
    let locale: (String, bool) = sqlx::query_as(
        "SELECT preferred_locale, preferred_locale_confirmed_at IS NOT NULL FROM identity.accounts WHERE id = $1",
    )
    .bind(account_id.into_uuid())
    .fetch_one(&assertion_pool)
    .await?;
    assert_eq!(locale, ("hi-IN".to_owned(), true));
    let persisted_ordering_key: Vec<u8> =
        sqlx::query_scalar("SELECT ordering_key FROM integration.outbox_jobs WHERE id = $1")
            .bind(turn.outbound.send_job_id.into_uuid())
            .fetch_one(&assertion_pool)
            .await?;
    assert_eq!(persisted_ordering_key, ordering_key);
    sqlx::query(
        r#"
        UPDATE integration.outbox_jobs
        SET state = 'completed', attempt_count = 1,
            completed_at = statement_timestamp()
        WHERE id = $1 AND state = 'pending'
        "#,
    )
    .bind(turn.outbound.send_job_id.into_uuid())
    .execute(&assertion_pool)
    .await?;

    let racing_event_id = InboundEventId::new();
    let racing_payload = br#"{"kind":"message","value":"second"}"#;
    let racing_encrypted = cryptography.encrypt(
        EncryptionPurpose::Integration,
        EncryptionContext::new(
            EncryptionNamespace::INBOUND_EVENT_PAYLOAD,
            racing_event_id.into_uuid(),
        ),
        racing_payload,
    )?;
    let (racing_fingerprint_version, racing_fingerprint) =
        cryptography.blind_index("integration:whatsapp:event:v1", racing_payload)?;
    let racing_job_id = OutboxJobId::new();
    database
        .accept_inbound_event(&InboundEventInput {
            event_id: racing_event_id,
            provider_code: "whatsapp".to_owned(),
            provider_namespace: PROVIDER_NAMESPACE.to_owned(),
            provider_event_id: format!("message:{racing_event_id}"),
            event_type: "message.received".to_owned(),
            payload: EncryptedEventPayload {
                purpose: EncryptionPurpose::Integration,
                schema_version: 1,
                ciphertext: racing_encrypted.ciphertext,
                nonce: racing_encrypted.nonce,
                fingerprint_key_version: racing_fingerprint_version,
                payload_fingerprint: racing_fingerprint,
                additional_fingerprints: Vec::new(),
                key_version: racing_encrypted.key_version,
            },
            correlation_id: CorrelationId::new(),
            signature_verified_at: OffsetDateTime::now_utc(),
            provider_occurred_at: Some(OffsetDateTime::now_utc()),
            processing_job_id: racing_job_id,
            processing_job_kind: "process_conversation_message".to_owned(),
            processing_ordering_key: Some(ordering_key),
            max_attempts: 8,
        })
        .await?;
    bind_event(
        &database,
        &cryptography,
        racing_event_id,
        account_id,
        channel_identity_id,
        PROVIDER_NAMESPACE,
    )
    .await?;
    let racing_worker = WorkerId::new();
    let racing_token = JobLeaseToken::new();
    sqlx::query(
        r#"
        UPDATE integration.outbox_jobs
        SET state = 'leased', attempt_count = attempt_count + 1,
            lease_owner = $2, lease_token = $3,
            lease_started_at = statement_timestamp(),
            lease_expires_at = statement_timestamp() + INTERVAL '30 seconds'
        WHERE id = $1 AND state = 'pending'
        "#,
    )
    .bind(racing_job_id.into_uuid())
    .bind(racing_worker.into_uuid())
    .bind(racing_token.into_uuid())
    .execute(&assertion_pool)
    .await?;
    let mut racing_turn = turn.clone();
    racing_turn.inbound_event_id = racing_event_id;
    racing_turn.lease = JobLease {
        job_id: racing_job_id,
        worker_id: racing_worker,
        token: racing_token,
    };
    racing_turn.session_change = ConversationSessionChange::Create {
        session_id: ConversationSessionId::new(),
        workflow_key: "account.locale".to_owned(),
        workflow_version: 1,
        state_key: "choose".to_owned(),
        state_data: serde_json::json!({}),
        language: "en-IN".to_owned(),
        workflow_correlation_id: CorrelationId::new(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(30),
        expired_session: None,
    };
    racing_turn.outbound.id = OutboundMessageId::new();
    racing_turn.outbound.send_job_id = OutboxJobId::new();
    racing_turn.outbound.callback_token = CallbackToken::new();
    racing_turn.outbound.idempotency_key = format!("conversation-turn:v1:{racing_event_id}");
    assert_eq!(
        repository.commit(&racing_turn).await?,
        TurnCommitOutcome::Conflict
    );
    assertion_pool.close().await;
    database.close().await;
    Ok(())
}

#[tokio::test]
async fn professional_effect_is_atomic_idempotent_and_cas_fenced()
-> Result<(), Box<dyn std::error::Error>> {
    let Some((database, pool)) = test_database().await? else {
        return Ok(());
    };
    let cryptography = crypto_service()?;
    let namespace = format!("effect-{}", AccountId::new());
    let (account_id, channel_identity_id) =
        create_identity_in_namespace(&database, &cryptography, &namespace).await?;
    let (event_id, lease) = create_leased_event(
        &database,
        &pool,
        &cryptography,
        &namespace,
        account_id,
        channel_identity_id,
        "stage",
        41,
    )
    .await?;
    let correlation_id = CorrelationId::new();
    let session_id = ConversationSessionId::new();
    let profile_id = PublicProfileId::new();
    let revision_id = ProfileRevisionId::new();
    let turn = CommitConversationTurn {
        lease,
        inbound_event_id: event_id,
        account_id,
        channel_identity_id,
        expected_account_version: 1,
        workflow_correlation_id: correlation_id,
        reply_to_outbound_message_id: None,
        locale_change: None,
        session_change: ConversationSessionChange::Create {
            session_id,
            workflow_key: "professional.profile".to_owned(),
            workflow_version: 1,
            state_key: "display_name_confirm".to_owned(),
            state_data: serde_json::json!({"mode":"initial"}),
            language: "en-IN".to_owned(),
            workflow_correlation_id: correlation_id,
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(30),
            expired_session: None,
        },
        outbound: test_outbound(
            channel_identity_id,
            &namespace,
            event_id,
            correlation_id,
            51,
        ),
        disposition: TurnDisposition::Applied,
    };
    let effects = ConversationTurnEffects {
        effect: Some(ConversationTurnEffect::Professional(
            ProfessionalTurnEffect {
                profile_id,
                revision_id,
                expected_revision_version: None,
                operation: ProfessionalTurnOperation::StageDisplayName {
                    public_reference: PublicProfileReference::new(),
                    display_name: ProfessionalDisplayName::parse("Atomic Ravi")?,
                },
            },
        )),
        role_context: Some(AccountRole::Professional),
        additional_outbound: Vec::new(),
    };
    let repository = ConversationTurnRepository::new(database.clone());
    assert!(matches!(
        repository.commit_with_effects(&turn, &effects).await?,
        EffectfulTurnCommitOutcome::Committed { .. }
    ));
    assert!(matches!(
        repository.commit_with_effects(&turn, &effects).await?,
        EffectfulTurnCommitOutcome::AlreadyCommitted { .. }
    ));
    let persisted: (String, i64, bool, bool, String, Option<uuid::Uuid>) = sqlx::query_as(
        r#"
        SELECT revision.display_name, revision.version,
               account.status = 'active',
               EXISTS (
                   SELECT 1 FROM identity.account_roles
                   WHERE account_id = account.id AND role = 'professional'
                     AND revoked_at IS NULL
               ),
               session.role_context,
               session.last_inbound_event_id
        FROM profile.profile_revisions AS revision
        JOIN profile.public_profiles AS root ON root.id = revision.profile_id
        JOIN identity.accounts AS account ON account.id = root.account_id
        JOIN messaging.conversation_sessions AS session ON session.account_id = account.id
        WHERE revision.id = $1 AND session.id = $2
        "#,
    )
    .bind(revision_id.into_uuid())
    .bind(session_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(persisted.0, "Atomic Ravi");
    assert_eq!(persisted.1, 2);
    assert!(persisted.2 && persisted.3);
    assert_eq!(persisted.4, "professional");
    assert_eq!(persisted.5, Some(event_id.into_uuid()));

    let mut session_version = 1;
    let mut revision_version = 2;
    for (marker, operation) in [
        (
            82,
            ProfessionalTurnOperation::SetSelectedCategories {
                category_codes: vec!["plumber".to_owned()],
            },
        ),
        (
            83,
            ProfessionalTurnOperation::SetCategorySkills {
                category_code: "plumber".to_owned(),
                skill_codes: vec!["leak_repair".to_owned()],
            },
        ),
        (
            84,
            ProfessionalTurnOperation::SetLocalServiceMode {
                mode: LocalServiceMode::TravelToCustomer,
            },
        ),
        (
            85,
            ProfessionalTurnOperation::SetRadius {
                radius: ServiceRadiusKm::Five,
            },
        ),
        (
            86,
            ProfessionalTurnOperation::SetCurrentInboundLocation {
                latitude: 18.5204,
                longitude: 73.8567,
            },
        ),
        (
            87,
            ProfessionalTurnOperation::SetLanguages {
                languages: vec![ProfessionalLanguage::EnglishIndia],
            },
        ),
        (
            88,
            ProfessionalTurnOperation::SetCategoryContactMode {
                category_code: "plumber".to_owned(),
                mode: ContactMode::ApprovalRequired,
            },
        ),
        (
            89,
            ProfessionalTurnOperation::SetContactRequestLimit { limit: 3 },
        ),
    ] {
        assert!(matches!(
            commit_professional_operation(
                &database,
                &pool,
                &cryptography,
                &namespace,
                account_id,
                channel_identity_id,
                session_id,
                correlation_id,
                profile_id,
                revision_id,
                revision_version,
                session_version,
                operation,
                marker,
            )
            .await?,
            EffectfulTurnCommitOutcome::Committed { .. }
        ));
        session_version += 1;
        revision_version += 1;
    }
    let photo_id = sahayak_domain::ProfilePhotoId::new();
    let photo_bytes = b"\xff\xd8atomic-sanitized-jpeg\xff\xd9";
    let encrypted_photo = cryptography.encrypt(
        EncryptionPurpose::Media,
        EncryptionContext::new(EncryptionNamespace::PROFILE_PHOTO, photo_id.into_uuid()),
        photo_bytes,
    )?;
    assert!(matches!(
        commit_professional_operation(
            &database,
            &pool,
            &cryptography,
            &namespace,
            account_id,
            channel_identity_id,
            session_id,
            correlation_id,
            profile_id,
            revision_id,
            revision_version,
            session_version,
            ProfessionalTurnOperation::AttachSanitizedPhoto {
                photo_id,
                encrypted_jpeg: encrypted_photo,
                width_pixels: 640,
                height_pixels: 480,
                plaintext_sha256: content_sha256(photo_bytes),
                sanitizer_version: "atomic-jpeg-v1".to_owned(),
                sanitized_at: OffsetDateTime::now_utc(),
            },
            90,
        )
        .await?,
        EffectfulTurnCommitOutcome::Committed { .. }
    ));
    session_version += 1;
    revision_version += 1;
    session_version = sqlx::query_scalar(
        r#"
        UPDATE messaging.conversation_sessions
        SET state_key = 'consent', state_data = '{"mode":"initial","version":1}'::jsonb
        WHERE id = $1 AND version = $2
        RETURNING version
        "#,
    )
    .bind(session_id.into_uuid())
    .bind(session_version)
    .fetch_one(&pool)
    .await?;
    let consent_prompt_uuid: uuid::Uuid = sqlx::query_scalar(
        "SELECT expected_reply_to_outbound_message_id FROM messaging.conversation_sessions WHERE id = $1",
    )
    .bind(session_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    let consent_prompt_id = OutboundMessageId::from_uuid(consent_prompt_uuid);
    let documents = ProfessionalConsentRepository::new(database.clone())
        .current_documents(ProfessionalLanguage::EnglishIndia)
        .await?;
    let acceptances = [
        ProfessionalConsentPurpose::Terms,
        ProfessionalConsentPurpose::Privacy,
        ProfessionalConsentPurpose::ContactDisclosure,
        ProfessionalConsentPurpose::PhotoDisclosure,
    ]
    .into_iter()
    .map(|purpose| {
        let document = documents
            .iter()
            .find(|document| document.purpose == purpose)
            .ok_or("required turn consent document missing")?;
        Ok(sahayak_persistence::ProfessionalConsentAcceptance {
            id: ProfessionalConsentEventId::new(),
            purpose,
            document_version: document.version.clone(),
            document_sha256: document.sha256,
            locale: ProfessionalLanguage::EnglishIndia,
            accepted_at: OffsetDateTime::now_utc(),
        })
    })
    .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let document_set_digest =
        sahayak_persistence::professional_consent_document_set_digest(&acceptances);
    session_version = sqlx::query_scalar(
        r#"
        UPDATE messaging.conversation_sessions
        SET state_data = jsonb_build_object(
            'mode', 'initial',
            'consent_version', 1,
            'document_set_digest', encode($3::bytea, 'hex')
        )
        WHERE id = $1 AND version = $2
        RETURNING version
        "#,
    )
    .bind(session_id.into_uuid())
    .bind(session_version)
    .bind(document_set_digest.as_slice())
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        commit_professional_operation(
            &database,
            &pool,
            &cryptography,
            &namespace,
            account_id,
            channel_identity_id,
            session_id,
            correlation_id,
            profile_id,
            revision_id,
            revision_version,
            session_version,
            ProfessionalTurnOperation::AppendRequiredConsents {
                acceptances: acceptances.clone(),
                document_set_digest: [0; 32],
                prompt_session_id: session_id,
                prompt_outbound_message_id: consent_prompt_id,
            },
            190,
        )
        .await?,
        EffectfulTurnCommitOutcome::Unauthorized
    );
    let wrong_prompt_uuid: uuid::Uuid = sqlx::query_scalar(
        r#"
        SELECT id FROM messaging.outbound_messages
        WHERE recipient_channel_identity_id = $1 AND id <> $2
        ORDER BY created_at
        LIMIT 1
        "#,
    )
    .bind(channel_identity_id.into_uuid())
    .bind(consent_prompt_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        commit_professional_operation(
            &database,
            &pool,
            &cryptography,
            &namespace,
            account_id,
            channel_identity_id,
            session_id,
            correlation_id,
            profile_id,
            revision_id,
            revision_version,
            session_version,
            ProfessionalTurnOperation::AppendRequiredConsents {
                acceptances: acceptances.clone(),
                document_set_digest,
                prompt_session_id: session_id,
                prompt_outbound_message_id: OutboundMessageId::from_uuid(wrong_prompt_uuid),
            },
            91,
        )
        .await?,
        EffectfulTurnCommitOutcome::Unauthorized
    );
    assert!(matches!(
        commit_professional_operation(
            &database,
            &pool,
            &cryptography,
            &namespace,
            account_id,
            channel_identity_id,
            session_id,
            correlation_id,
            profile_id,
            revision_id,
            revision_version,
            session_version,
            ProfessionalTurnOperation::AppendRequiredConsents {
                acceptances,
                document_set_digest,
                prompt_session_id: session_id,
                prompt_outbound_message_id: consent_prompt_id,
            },
            92,
        )
        .await?,
        EffectfulTurnCommitOutcome::Committed { .. }
    ));
    session_version += 1;
    revision_version += 1;
    assert!(matches!(
        commit_professional_operation(
            &database,
            &pool,
            &cryptography,
            &namespace,
            account_id,
            channel_identity_id,
            session_id,
            correlation_id,
            profile_id,
            revision_id,
            revision_version,
            session_version,
            ProfessionalTurnOperation::SubmitCompleteDraft,
            93,
        )
        .await?,
        EffectfulTurnCommitOutcome::Committed { .. }
    ));
    session_version += 1;
    let private_area: (f64, f64, i16, i64) = sqlx::query_as(
        r#"
        SELECT ST_Y(area.exact_center::geometry), ST_X(area.exact_center::geometry),
               revision.service_radius_km,
               (SELECT count(*) FROM private_data.professional_consent_events
                WHERE revision_id = revision.id)
        FROM private_data.professional_service_areas AS area
        JOIN profile.profile_revisions AS revision ON revision.id = area.revision_id
        WHERE revision.id = $1
        "#,
    )
    .bind(revision_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(private_area, (18.5204, 73.8567, 5, 4));
    let snapshot = ProfessionalProfileRepository::new(database.clone())
        .load_conversation_snapshot(account_id, channel_identity_id)
        .await?
        .ok_or("professional snapshot missing")?;
    assert_eq!(
        snapshot.status,
        ProfessionalConversationStatus::PendingReview
    );
    assert!(!format!("{snapshot:?}").contains("73.8567"));

    let (stale_event, stale_lease) = create_leased_event(
        &database,
        &pool,
        &cryptography,
        &namespace,
        account_id,
        channel_identity_id,
        "stale",
        42,
    )
    .await?;
    let mut stale_turn = turn.clone();
    stale_turn.lease = stale_lease;
    stale_turn.inbound_event_id = stale_event;
    stale_turn.expected_account_version = 2;
    stale_turn.session_change = ConversationSessionChange::Advance {
        session_id,
        expected_version: session_version,
        state_key: "categories".to_owned(),
        state_data: serde_json::json!({"mode":"initial","category_codes":[]}),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(30),
    };
    stale_turn.outbound = test_outbound(
        channel_identity_id,
        &namespace,
        stale_event,
        correlation_id,
        52,
    );
    let stale_effects = ConversationTurnEffects {
        effect: Some(ConversationTurnEffect::Professional(
            ProfessionalTurnEffect {
                profile_id,
                revision_id,
                expected_revision_version: Some(1),
                operation: ProfessionalTurnOperation::SetSelectedCategories {
                    category_codes: vec!["plumber".to_owned()],
                },
            },
        )),
        role_context: Some(AccountRole::Professional),
        additional_outbound: Vec::new(),
    };
    assert_eq!(
        repository
            .commit_with_effects(&stale_turn, &stale_effects)
            .await?,
        EffectfulTurnCommitOutcome::Conflict
    );
    let stale_counts: (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            (SELECT count(*) FROM profile.professional_services WHERE revision_id = $1),
            (SELECT count(*) FROM messaging.conversation_turn_receipts WHERE inbound_event_id = $2),
            (SELECT count(*) FROM messaging.outbound_messages WHERE id = $3)
        "#,
    )
    .bind(revision_id.into_uuid())
    .bind(stale_event.into_uuid())
    .bind(stale_turn.outbound.id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(stale_counts, (1, 0, 0));

    let rollback_namespace = format!("rollback-{}", AccountId::new());
    let (rollback_account, rollback_channel) =
        create_identity_in_namespace(&database, &cryptography, &rollback_namespace).await?;
    let (rollback_event, rollback_lease) = create_leased_event(
        &database,
        &pool,
        &cryptography,
        &rollback_namespace,
        rollback_account,
        rollback_channel,
        "rollback",
        43,
    )
    .await?;
    let rollback_correlation = CorrelationId::new();
    let collision = test_outbound(
        rollback_channel,
        &rollback_namespace,
        rollback_event,
        rollback_correlation,
        61,
    );
    OutboundRepository::new(database.clone())
        .queue(&collision)
        .await?;
    let mut conflicting_outbound = test_outbound(
        rollback_channel,
        &rollback_namespace,
        rollback_event,
        rollback_correlation,
        62,
    );
    conflicting_outbound.idempotency_key = collision.idempotency_key.clone();
    let rollback_profile = PublicProfileId::new();
    let rollback_revision = ProfileRevisionId::new();
    let rollback_turn = CommitConversationTurn {
        lease: rollback_lease,
        inbound_event_id: rollback_event,
        account_id: rollback_account,
        channel_identity_id: rollback_channel,
        expected_account_version: 1,
        workflow_correlation_id: rollback_correlation,
        reply_to_outbound_message_id: None,
        locale_change: None,
        session_change: ConversationSessionChange::Create {
            session_id: ConversationSessionId::new(),
            workflow_key: "professional.profile".to_owned(),
            workflow_version: 1,
            state_key: "display_name_confirm".to_owned(),
            state_data: serde_json::json!({"mode":"initial"}),
            language: "en-IN".to_owned(),
            workflow_correlation_id: rollback_correlation,
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(30),
            expired_session: None,
        },
        outbound: conflicting_outbound,
        disposition: TurnDisposition::Applied,
    };
    let rollback_effects = ConversationTurnEffects {
        effect: Some(ConversationTurnEffect::Professional(
            ProfessionalTurnEffect {
                profile_id: rollback_profile,
                revision_id: rollback_revision,
                expected_revision_version: None,
                operation: ProfessionalTurnOperation::StageDisplayName {
                    public_reference: PublicProfileReference::new(),
                    display_name: ProfessionalDisplayName::parse("Rollback Ravi")?,
                },
            },
        )),
        role_context: Some(AccountRole::Professional),
        additional_outbound: Vec::new(),
    };
    assert!(
        repository
            .commit_with_effects(&rollback_turn, &rollback_effects)
            .await
            .is_err()
    );
    let rollback_state: (String, bool, i64) = sqlx::query_as(
        r#"
        SELECT account.status,
               EXISTS (SELECT 1 FROM identity.account_roles
                       WHERE account_id = account.id AND role = 'professional'),
               (SELECT count(*) FROM profile.public_profiles WHERE account_id = account.id)
        FROM identity.accounts AS account WHERE account.id = $1
        "#,
    )
    .bind(rollback_account.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(rollback_state, ("pending".to_owned(), false, 0));
    pool.close().await;
    database.close().await;
    Ok(())
}

#[tokio::test]
async fn administrator_race_commits_one_decision_audit_and_notification()
-> Result<(), Box<dyn std::error::Error>> {
    let Some((database, pool)) = test_database().await? else {
        return Ok(());
    };
    let cryptography = crypto_service()?;
    let owner_namespace = format!("review-owner-{}", AccountId::new());
    let (owner_account, owner_channel) =
        create_identity_in_namespace(&database, &cryptography, &owner_namespace).await?;
    activate_role(&pool, owner_account, AccountRole::Professional).await?;
    let (revision_id, submitted_version, target_digest) = create_complete_profile(
        &database,
        &pool,
        &cryptography,
        owner_account,
        owner_channel,
        &owner_namespace,
    )
    .await?;

    let first_namespace = format!("review-admin-1-{}", AccountId::new());
    let second_namespace = format!("review-admin-2-{}", AccountId::new());
    let first = create_identity_in_namespace(&database, &cryptography, &first_namespace).await?;
    let second = create_identity_in_namespace(&database, &cryptography, &second_namespace).await?;
    for (index, actor) in [first, second].into_iter().enumerate() {
        activate_role(&pool, actor.0, AccountRole::Administrator).await?;
        AdministratorAllowlistRepository::new(database.clone())
            .grant(&GrantAdministratorAccess {
                id: AdministratorGrantId::new(),
                account_id: actor.0,
                channel_identity_id: actor.1,
                granted_by_account_id: None,
                expires_at: OffsetDateTime::now_utc() + time::Duration::days(30),
                idempotency_key: format!("atomic-admin-grant:{index}:{}", actor.0),
                correlation_id: CorrelationId::new(),
            })
            .await?;
    }
    let profiles = ProfessionalProfileRepository::new(database.clone());
    let owner_view = profiles
        .load_conversation_snapshot(owner_account, owner_channel)
        .await?
        .ok_or("professional conversation snapshot missing")?;
    assert_eq!(
        owner_view.status,
        ProfessionalConversationStatus::PendingReview
    );
    assert_eq!(
        owner_view.current_consent_version.as_deref(),
        Some("phase5-v1")
    );
    assert_eq!(
        AvailabilityRepository::new(database.clone())
            .load_conversation_snapshot(owner_account, owner_channel, &owner_namespace)
            .await?,
        AvailabilityConversationSnapshot::Ineligible(
            sahayak_persistence::AvailabilityIneligibility::ApprovedProfileRequired
        )
    );
    let owner_debug = format!("{owner_view:?}");
    assert!(!owner_debug.contains("18.5204"));
    assert!(!owner_debug.contains("73.8567"));
    let first_view = profiles
        .load_administrator_conversation_snapshot(first.0, first.1, &first_namespace, None, 20)
        .await?
        .ok_or("first administrator was not authorized")?;
    let selected = first_view
        .pending
        .iter()
        .find(|item| item.target.revision_id == revision_id)
        .ok_or("pending review target missing")?;
    assert_eq!(selected.target.target_digest, target_digest);
    let review_token = selected.review_token.clone();
    let notification_target = profiles
        .load_active_whatsapp_notification_target(revision_id, first.0, first.1, &first_namespace)
        .await?
        .ok_or("professional notification target missing")?;
    assert_eq!(notification_target.account_id, owner_account);
    assert_eq!(notification_target.channel_identity_id, owner_channel);
    assert!(!format!("{notification_target:?}").contains("ciphertext"));

    let first_prompt = create_admin_prompt(
        &database,
        &pool,
        &cryptography,
        first,
        &first_namespace,
        &review_token,
        submitted_version,
        71,
    )
    .await?;
    let second_prompt = create_admin_prompt(
        &database,
        &pool,
        &cryptography,
        second,
        &second_namespace,
        &review_token,
        submitted_version,
        72,
    )
    .await?;
    let notification_correlation = CorrelationId::new();
    let mut notification = test_outbound(
        owner_channel,
        &owner_namespace,
        InboundEventId::new(),
        notification_correlation,
        73,
    );
    notification.idempotency_key = format!("professional-review-outcome:v1:{revision_id}");
    let first_decision = create_admin_decision_turn(
        &database,
        &pool,
        &cryptography,
        first,
        &first_namespace,
        &review_token,
        revision_id,
        submitted_version,
        target_digest,
        first_prompt,
        notification.clone(),
        notification_correlation,
        74,
    )
    .await?;
    let second_decision = create_admin_decision_turn(
        &database,
        &pool,
        &cryptography,
        second,
        &second_namespace,
        &review_token,
        revision_id,
        submitted_version,
        target_digest,
        second_prompt,
        notification,
        notification_correlation,
        75,
    )
    .await?;
    let repository = ConversationTurnRepository::new(database.clone());
    let mut substituted_effects = first_decision.1.clone();
    if let Some(ConversationTurnEffect::AdministratorReview(effect)) =
        substituted_effects.effect.as_mut()
    {
        effect.decision = ProfileReviewDecision::Reject;
        effect.reason = ProfileReviewReason::PolicyViolation;
    }
    assert_eq!(
        repository
            .commit_with_effects(&first_decision.0, &substituted_effects)
            .await?,
        EffectfulTurnCommitOutcome::Unauthorized
    );
    let (first_outcome, second_outcome) = tokio::join!(
        repository.commit_with_effects(&first_decision.0, &first_decision.1),
        repository.commit_with_effects(&second_decision.0, &second_decision.1),
    );
    let outcomes = (first_outcome?, second_outcome?);
    assert!(matches!(
        outcomes,
        (
            EffectfulTurnCommitOutcome::Committed { .. },
            EffectfulTurnCommitOutcome::AlreadyDecided
        ) | (
            EffectfulTurnCommitOutcome::AlreadyDecided,
            EffectfulTurnCommitOutcome::Committed { .. }
        )
    ));
    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            (SELECT count(*) FROM profile.profile_review_decisions WHERE revision_id = $1),
            (SELECT count(*) FROM audit.events
             WHERE target_id = $1 AND action = 'profile.review_decided'),
            (SELECT count(*) FROM messaging.conversation_turn_receipt_outbounds AS link
             JOIN messaging.outbound_messages AS message ON message.id = link.outbound_message_id
             WHERE message.idempotency_key = $2),
            (SELECT count(*) FROM messaging.conversation_turn_receipts
             WHERE inbound_event_id IN ($3, $4))
        "#,
    )
    .bind(revision_id.into_uuid())
    .bind(format!("professional-review-outcome:v1:{revision_id}"))
    .bind(first_decision.0.inbound_event_id.into_uuid())
    .bind(second_decision.0.inbound_event_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(counts, (1, 1, 1, 1));

    let (availability_event, availability_lease) = create_leased_event(
        &database,
        &pool,
        &cryptography,
        &owner_namespace,
        owner_account,
        owner_channel,
        "availability-start",
        76,
    )
    .await?;
    let account_version: i64 =
        sqlx::query_scalar("SELECT version FROM identity.accounts WHERE id = $1")
            .bind(owner_account.into_uuid())
            .fetch_one(&pool)
            .await?;
    let availability_epoch_id = AvailabilityEpochId::new();
    let availability_session_id = ConversationSessionId::new();
    let availability_turn = CommitConversationTurn {
        lease: availability_lease,
        inbound_event_id: availability_event,
        account_id: owner_account,
        channel_identity_id: owner_channel,
        expected_account_version: account_version,
        workflow_correlation_id: CorrelationId::new(),
        reply_to_outbound_message_id: None,
        locale_change: None,
        session_change: ConversationSessionChange::Create {
            session_id: availability_session_id,
            workflow_key: "professional.availability".to_owned(),
            workflow_version: 1,
            state_key: "changed".to_owned(),
            state_data: serde_json::json!({"outcome":"started","duration":"one_hour"}),
            language: "en-IN".to_owned(),
            workflow_correlation_id: CorrelationId::new(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(30),
            expired_session: None,
        },
        outbound: test_outbound(
            owner_channel,
            &owner_namespace,
            availability_event,
            CorrelationId::new(),
            77,
        ),
        disposition: TurnDisposition::Applied,
    };
    assert!(matches!(
        ConversationTurnRepository::new(database.clone())
            .commit_with_effects(
                &availability_turn,
                &ConversationTurnEffects {
                    effect: Some(ConversationTurnEffect::Availability(
                        AvailabilityTurnEffect {
                            operation: AvailabilityTurnOperation::Start {
                                epoch_id: availability_epoch_id,
                                duration: AvailabilityDuration::OneHour,
                            },
                        }
                    )),
                    role_context: Some(AccountRole::Professional),
                    additional_outbound: Vec::new(),
                },
            )
            .await?,
        EffectfulTurnCommitOutcome::Committed { .. }
    ));
    let availability = AvailabilityRepository::new(database.clone());
    let snapshot = availability
        .load_conversation_snapshot(owner_account, owner_channel, &owner_namespace)
        .await?;
    let AvailabilityConversationSnapshot::Current(snapshot) = snapshot else {
        return Err("availability session was not created".into());
    };
    assert_eq!(snapshot.state, AvailabilityEpochState::Available);
    assert_eq!(snapshot.contact_count, 0);
    assert!(
        sqlx::query("UPDATE availability.epochs SET state = 'stopped', stopped_at = clock_timestamp() WHERE id = $1")
            .bind(availability_epoch_id.into_uuid())
            .execute(&pool)
            .await
            .is_err()
    );
    let timer_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM integration.outbox_jobs WHERE availability_epoch_id = $1 AND ordering_key IS NULL",
    )
    .bind(availability_epoch_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(timer_count, 2);
    let first_capacity_key = uuid::Uuid::new_v4();
    assert!(matches!(
        availability
            .consume_capacity(
                availability_epoch_id,
                first_capacity_key,
                "plumber",
                CorrelationId::new(),
                None,
            )
            .await?,
        CapacityConsumptionOutcome::Consumed { .. }
    ));
    assert_eq!(
        availability
            .consume_capacity(
                availability_epoch_id,
                first_capacity_key,
                "plumber",
                CorrelationId::new(),
                None,
            )
            .await?,
        CapacityConsumptionOutcome::AlreadyConsumed
    );
    let after_first_contact = availability
        .load_conversation_snapshot(owner_account, owner_channel, &owner_namespace)
        .await?;
    let AvailabilityConversationSnapshot::Current(after_first_contact) = after_first_contact else {
        return Err("availability disappeared after first contact".into());
    };
    assert!(matches!(
        commit_availability_operation(
            &database,
            &pool,
            &cryptography,
            &owner_namespace,
            owner_account,
            owner_channel,
            availability_session_id,
            1,
            AvailabilityTurnOperation::Stop {
                expected_generation: after_first_contact.generation,
                expected_version: after_first_contact.version,
            },
            84,
        )
        .await?,
        EffectfulTurnCommitOutcome::Committed { .. }
    ));
    let stopped = availability
        .load_conversation_snapshot(owner_account, owner_channel, &owner_namespace)
        .await?;
    let AvailabilityConversationSnapshot::Current(stopped) = stopped else {
        return Err("stopped availability epoch missing".into());
    };
    assert_eq!(stopped.state, AvailabilityEpochState::Stopped);
    assert_eq!(stopped.contact_count, 1);
    assert!(matches!(
        commit_availability_operation(
            &database,
            &pool,
            &cryptography,
            &owner_namespace,
            owner_account,
            owner_channel,
            availability_session_id,
            2,
            AvailabilityTurnOperation::Resume {
                expected_generation: stopped.generation,
                expected_version: stopped.version,
            },
            85,
        )
        .await?,
        EffectfulTurnCommitOutcome::Committed { .. }
    ));
    let resumed = availability
        .load_conversation_snapshot(owner_account, owner_channel, &owner_namespace)
        .await?;
    let AvailabilityConversationSnapshot::Current(resumed) = resumed else {
        return Err("resumed availability epoch missing".into());
    };
    assert_eq!(resumed.state, AvailabilityEpochState::Available);
    assert_eq!(resumed.contact_count, 1);
    for _ in 1..(snapshot.contact_limit - 1) {
        let result = availability
            .consume_capacity(
                availability_epoch_id,
                uuid::Uuid::new_v4(),
                "plumber",
                CorrelationId::new(),
                None,
            )
            .await?;
        assert!(matches!(
            result,
            CapacityConsumptionOutcome::Consumed { .. }
        ));
    }
    let mut first_pause_notification = test_outbound(
        owner_channel,
        &owner_namespace,
        InboundEventId::new(),
        CorrelationId::new(),
        88,
    );
    first_pause_notification.idempotency_key =
        format!("availability-auto-pause:v1:{availability_epoch_id}");
    let mut second_pause_notification = first_pause_notification.clone();
    second_pause_notification.id = OutboundMessageId::new();
    second_pause_notification.send_job_id = OutboxJobId::new();
    second_pause_notification.callback_token = CallbackToken::new();
    let first_operation = uuid::Uuid::new_v4();
    let second_operation = uuid::Uuid::new_v4();
    let (first_capacity, second_capacity) = tokio::join!(
        availability.consume_capacity(
            availability_epoch_id,
            first_operation,
            "plumber",
            CorrelationId::new(),
            Some(&first_pause_notification),
        ),
        availability.consume_capacity(
            availability_epoch_id,
            second_operation,
            "plumber",
            CorrelationId::new(),
            Some(&second_pause_notification),
        ),
    );
    let capacity_outcomes = (first_capacity?, second_capacity?);
    assert!(matches!(
        capacity_outcomes,
        (
            CapacityConsumptionOutcome::Consumed {
                auto_paused: true,
                ..
            },
            CapacityConsumptionOutcome::Denied
        ) | (
            CapacityConsumptionOutcome::Denied,
            CapacityConsumptionOutcome::Consumed {
                auto_paused: true,
                ..
            }
        )
    ));
    let paused: (String, i16, i64) = sqlx::query_as(
        r#"
        SELECT state, contact_count,
               (SELECT count(*) FROM availability.notification_events
                WHERE epoch_id = epoch.id AND purpose = 'contact_limit_paused')
        FROM availability.epochs AS epoch WHERE id = $1
        "#,
    )
    .bind(availability_epoch_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(paused.0, "paused_contact_limit");
    assert_eq!(paused.1, snapshot.contact_limit);
    assert_eq!(paused.2, 1);

    let paused_snapshot = availability
        .load_conversation_snapshot(owner_account, owner_channel, &owner_namespace)
        .await?;
    let AvailabilityConversationSnapshot::Current(paused_snapshot) = paused_snapshot else {
        return Err("paused availability session missing".into());
    };
    let successor_id = AvailabilityEpochId::new();
    let renewal_outcome = commit_availability_operation(
        &database,
        &pool,
        &cryptography,
        &owner_namespace,
        owner_account,
        owner_channel,
        availability_session_id,
        3,
        AvailabilityTurnOperation::Renew {
            successor_epoch_id: successor_id,
            duration: AvailabilityDuration::FourHours,
            expected_generation: paused_snapshot.generation,
            expected_version: paused_snapshot.version,
        },
        90,
    )
    .await?;
    assert!(
        matches!(
            renewal_outcome,
            EffectfulTurnCommitOutcome::Committed { .. }
        ),
        "unexpected renewal outcome: {renewal_outcome:?}"
    );
    let successor_state: (String, i16, i64) = sqlx::query_as(
        "SELECT state, contact_count, generation FROM availability.epochs WHERE id = $1",
    )
    .bind(successor_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(successor_state.0, "scheduled");
    assert_eq!(successor_state.1, 0);
    assert!(successor_state.2 > paused_snapshot.generation);

    let mut force_expiry = pool.begin().await?;
    sqlx::query("SELECT set_config('sahayak.availability_mutation', 'on', true)")
        .execute(&mut *force_expiry)
        .await?;
    sqlx::query(
        "UPDATE availability.epochs SET last_confirmed_at = starts_at, expires_at = starts_at + INTERVAL '1 microsecond' WHERE id = $1",
    )
    .bind(availability_epoch_id.into_uuid())
    .execute(&mut *force_expiry)
    .await?;
    sqlx::query(
        r#"
        UPDATE availability.epochs AS successor
        SET starts_at = predecessor.expires_at,
            expires_at = predecessor.expires_at + INTERVAL '4 hours'
        FROM availability.epochs AS predecessor
        WHERE successor.id = $1 AND predecessor.id = $2
        "#,
    )
    .bind(successor_id.into_uuid())
    .bind(availability_epoch_id.into_uuid())
    .execute(&mut *force_expiry)
    .await?;
    sqlx::query(
        "UPDATE integration.outbox_jobs SET available_at = clock_timestamp() WHERE availability_epoch_id = $1 AND job_kind = 'advance_professional_availability'",
    )
    .bind(availability_epoch_id.into_uuid())
    .execute(&mut *force_expiry)
    .await?;
    force_expiry.commit().await?;
    let timer_worker = WorkerId::new();
    let timer_token = JobLeaseToken::new();
    let timer_job_id: uuid::Uuid = sqlx::query_scalar(
        r#"
        UPDATE integration.outbox_jobs
        SET state = 'leased', attempt_count = attempt_count + 1,
            lease_owner = $2, lease_token = $3,
            lease_started_at = clock_timestamp(),
            lease_expires_at = clock_timestamp() + INTERVAL '30 seconds'
        WHERE availability_epoch_id = $1 AND job_kind = 'advance_professional_availability'
          AND state = 'pending'
        RETURNING id
        "#,
    )
    .bind(availability_epoch_id.into_uuid())
    .bind(timer_worker.into_uuid())
    .bind(timer_token.into_uuid())
    .fetch_one(&pool)
    .await?;
    let mut expiry_notification = test_outbound(
        owner_channel,
        &owner_namespace,
        InboundEventId::new(),
        CorrelationId::new(),
        91,
    );
    expiry_notification.idempotency_key =
        format!("availability-expired:v1:{availability_epoch_id}");
    assert_eq!(
        availability
            .process_timer(
                JobLease {
                    job_id: OutboxJobId::from_uuid(timer_job_id),
                    worker_id: timer_worker,
                    token: timer_token,
                },
                availability_epoch_id,
                paused_snapshot.generation,
                AvailabilityTimerPurpose::Advance,
                expiry_notification.correlation_id,
                Some(&expiry_notification),
            )
            .await?,
        sahayak_persistence::AvailabilityTimerOutcome::Applied
    );
    let activated_successor = availability
        .load_conversation_snapshot(owner_account, owner_channel, &owner_namespace)
        .await?;
    let AvailabilityConversationSnapshot::Current(activated_successor) = activated_successor else {
        return Err("scheduled successor was not activated".into());
    };
    assert_eq!(activated_successor.id, successor_id);
    assert_eq!(activated_successor.state, AvailabilityEpochState::Available);
    assert_eq!(activated_successor.contact_count, 0);
    let account_repository = AccountRepository::new(database.clone());
    let account = account_repository
        .find(owner_account)
        .await?
        .ok_or("availability owner account missing")?;
    let AccountMutation::Applied { version } = account_repository
        .transition_lifecycle(
            owner_account,
            account.version,
            sahayak_domain::AccountLifecycle::Suspended,
            CorrelationId::new(),
        )
        .await?
    else {
        return Err("account suspension conflicted".into());
    };
    let invalidated_state: String =
        sqlx::query_scalar("SELECT state FROM availability.epochs WHERE id = $1")
            .bind(successor_id.into_uuid())
            .fetch_one(&pool)
            .await?;
    assert_eq!(invalidated_state, "cancelled_ineligible");
    let AccountMutation::Applied {
        version: reactivated_version,
    } = account_repository
        .transition_lifecycle(
            owner_account,
            version,
            sahayak_domain::AccountLifecycle::Active,
            CorrelationId::new(),
        )
        .await?
    else {
        return Err("account reactivation conflicted".into());
    };
    assert_eq!(
        availability
            .load_conversation_snapshot(owner_account, owner_channel, &owner_namespace)
            .await?,
        AvailabilityConversationSnapshot::Unavailable
    );
    for offset in 0..12_i64 {
        let audit_id = sahayak_domain::AuditEventId::new();
        sqlx::query(
            r#"
            INSERT INTO audit.events (
                id, actor_type, source_channel, action, target_type,
                target_id, reason_code, metadata, event_schema_version, correlation_id
            )
            VALUES ($1, 'system', 'system', 'availability.test_rate',
                    'availability_epoch', $2, 'test', '{}'::jsonb, 1, $3)
            "#,
        )
        .bind(audit_id.into_uuid())
        .bind(successor_id.into_uuid())
        .bind(CorrelationId::new().into_uuid())
        .execute(&pool)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO availability.mutation_events (
                id, epoch_id, account_id, action, audit_event_id,
                correlation_id, occurred_at
            )
            VALUES ($1, $2, $3, 'resumed', $4, $5,
                    clock_timestamp() - ($6::bigint * INTERVAL '1 millisecond'))
            "#,
        )
        .bind(uuid::Uuid::now_v7())
        .bind(successor_id.into_uuid())
        .bind(owner_account.into_uuid())
        .bind(audit_id.into_uuid())
        .bind(CorrelationId::new().into_uuid())
        .bind(offset)
        .execute(&pool)
        .await?;
    }
    assert_eq!(
        commit_availability_operation(
            &database,
            &pool,
            &cryptography,
            &owner_namespace,
            owner_account,
            owner_channel,
            availability_session_id,
            4,
            AvailabilityTurnOperation::Start {
                epoch_id: AvailabilityEpochId::new(),
                duration: AvailabilityDuration::OneHour,
            },
            92,
        )
        .await?,
        EffectfulTurnCommitOutcome::Unauthorized
    );
    let AccountMutation::Applied {
        version: deletion_version,
    } = account_repository
        .transition_lifecycle(
            owner_account,
            reactivated_version,
            sahayak_domain::AccountLifecycle::DeletionPending,
            CorrelationId::new(),
        )
        .await?
    else {
        return Err("account deletion request conflicted".into());
    };
    assert!(matches!(
        account_repository
            .transition_lifecycle(
                owner_account,
                deletion_version,
                sahayak_domain::AccountLifecycle::Deleted,
                CorrelationId::new(),
            )
            .await?,
        AccountMutation::Applied { .. }
    ));
    let remaining_epochs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM availability.epochs WHERE account_id = $1")
            .bind(owner_account.into_uuid())
            .fetch_one(&pool)
            .await?;
    assert_eq!(remaining_epochs, 0);
    pool.close().await;
    database.close().await;
    Ok(())
}

#[derive(Clone, Copy)]
struct AdminPrompt {
    session_id: ConversationSessionId,
    outbound_id: OutboundMessageId,
    correlation_id: CorrelationId,
}

#[allow(clippy::too_many_arguments)]
async fn commit_professional_operation(
    database: &Database,
    pool: &PgPool,
    cryptography: &CryptoService,
    provider_namespace: &str,
    account_id: AccountId,
    channel_identity_id: ChannelIdentityId,
    session_id: ConversationSessionId,
    correlation_id: CorrelationId,
    profile_id: PublicProfileId,
    revision_id: ProfileRevisionId,
    revision_version: i64,
    session_version: i64,
    operation: ProfessionalTurnOperation,
    marker: u8,
) -> Result<EffectfulTurnCommitOutcome, Box<dyn std::error::Error>> {
    let (event_id, lease) = create_leased_event(
        database,
        pool,
        cryptography,
        provider_namespace,
        account_id,
        channel_identity_id,
        "professional-effect",
        marker,
    )
    .await?;
    let account_version: i64 =
        sqlx::query_scalar("SELECT version FROM identity.accounts WHERE id = $1")
            .bind(account_id.into_uuid())
            .fetch_one(pool)
            .await?;
    let reply_to_outbound_message_id = match &operation {
        ProfessionalTurnOperation::AppendRequiredConsents {
            prompt_outbound_message_id,
            ..
        } => Some(*prompt_outbound_message_id),
        _ => None,
    };
    let turn = CommitConversationTurn {
        lease,
        inbound_event_id: event_id,
        account_id,
        channel_identity_id,
        expected_account_version: account_version,
        workflow_correlation_id: correlation_id,
        reply_to_outbound_message_id,
        locale_change: None,
        session_change: ConversationSessionChange::Advance {
            session_id,
            expected_version: session_version,
            state_key: "atomic_test".to_owned(),
            state_data: serde_json::json!({}),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(30),
        },
        outbound: test_outbound(
            channel_identity_id,
            provider_namespace,
            event_id,
            correlation_id,
            marker,
        ),
        disposition: TurnDisposition::Applied,
    };
    Ok(ConversationTurnRepository::new(database.clone())
        .commit_with_effects(
            &turn,
            &ConversationTurnEffects {
                effect: Some(ConversationTurnEffect::Professional(
                    ProfessionalTurnEffect {
                        profile_id,
                        revision_id,
                        expected_revision_version: Some(revision_version),
                        operation,
                    },
                )),
                role_context: Some(AccountRole::Professional),
                additional_outbound: Vec::new(),
            },
        )
        .await?)
}

#[allow(clippy::too_many_arguments)]
async fn commit_availability_operation(
    database: &Database,
    pool: &PgPool,
    cryptography: &CryptoService,
    provider_namespace: &str,
    account_id: AccountId,
    channel_identity_id: ChannelIdentityId,
    session_id: ConversationSessionId,
    session_version: i64,
    operation: AvailabilityTurnOperation,
    marker: u8,
) -> Result<EffectfulTurnCommitOutcome, Box<dyn std::error::Error>> {
    let (event_id, lease) = create_leased_event(
        database,
        pool,
        cryptography,
        provider_namespace,
        account_id,
        channel_identity_id,
        "availability-effect",
        marker,
    )
    .await?;
    let (expected_reply_to, workflow_correlation_id, persisted_session_version): (
        Option<uuid::Uuid>,
        uuid::Uuid,
        i64,
    ) = sqlx::query_as(
        "SELECT expected_reply_to_outbound_message_id, workflow_correlation_id, version FROM messaging.conversation_sessions WHERE id = $1",
    )
    .bind(session_id.into_uuid())
    .fetch_one(pool)
    .await?;
    if persisted_session_version != session_version {
        return Err("availability session version changed unexpectedly".into());
    }
    let mut binding = pool.begin().await?;
    sqlx::query("SELECT set_config('sahayak.inbound_identity_binding', $1, true)")
        .bind(event_id.to_string())
        .execute(&mut *binding)
        .await?;
    sqlx::query(
        "UPDATE integration.inbound_events SET reply_to_outbound_message_id = $2 WHERE id = $1",
    )
    .bind(event_id.into_uuid())
    .bind(expected_reply_to)
    .execute(&mut *binding)
    .await?;
    binding.commit().await?;
    let account_version: i64 =
        sqlx::query_scalar("SELECT version FROM identity.accounts WHERE id = $1")
            .bind(account_id.into_uuid())
            .fetch_one(pool)
            .await?;
    let turn = CommitConversationTurn {
        lease,
        inbound_event_id: event_id,
        account_id,
        channel_identity_id,
        expected_account_version: account_version,
        workflow_correlation_id: CorrelationId::from_uuid(workflow_correlation_id),
        reply_to_outbound_message_id: expected_reply_to.map(OutboundMessageId::from_uuid),
        locale_change: None,
        session_change: ConversationSessionChange::Advance {
            session_id,
            expected_version: session_version,
            state_key: "changed".to_owned(),
            state_data: serde_json::json!({"outcome":"successor_scheduled","duration":"four_hours"}),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(30),
        },
        outbound: test_outbound(
            channel_identity_id,
            provider_namespace,
            event_id,
            CorrelationId::from_uuid(workflow_correlation_id),
            marker,
        ),
        disposition: TurnDisposition::Applied,
    };
    Ok(ConversationTurnRepository::new(database.clone())
        .commit_with_effects(
            &turn,
            &ConversationTurnEffects {
                effect: Some(ConversationTurnEffect::Availability(
                    AvailabilityTurnEffect { operation },
                )),
                role_context: Some(AccountRole::Professional),
                additional_outbound: Vec::new(),
            },
        )
        .await?)
}

async fn activate_role(
    pool: &PgPool,
    account_id: AccountId,
    role: AccountRole,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query(
        "UPDATE identity.accounts SET status = 'active', state_changed_at = statement_timestamp() WHERE id = $1 AND status = 'pending'",
    )
    .bind(account_id.into_uuid())
    .execute(pool)
    .await?;
    sqlx::query("INSERT INTO identity.account_roles (account_id, role) VALUES ($1, $2)")
        .bind(account_id.into_uuid())
        .bind(role.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

async fn create_complete_profile(
    database: &Database,
    pool: &PgPool,
    cryptography: &CryptoService,
    account_id: AccountId,
    channel_identity_id: ChannelIdentityId,
    provider_namespace: &str,
) -> Result<(ProfileRevisionId, i64, [u8; 32]), Box<dyn std::error::Error>> {
    let profiles = ProfessionalProfileRepository::new(database.clone());
    let consents = ProfessionalConsentRepository::new(database.clone());
    let profile_id = PublicProfileId::new();
    let draft = profiles
        .begin_or_resume_draft(BeginProfessionalDraft {
            profile_id,
            public_reference: PublicProfileReference::new(),
            revision_id: ProfileRevisionId::new(),
            account_id,
        })
        .await?;
    let name = ProfessionalDisplayName::parse("Review Target")?;
    let ProfileMutation::Applied { version } = profiles
        .update_display_name(draft.revision_id, draft.version, &name)
        .await?
    else {
        return Err("display name setup conflicted".into());
    };
    let ProfileMutation::Applied { version } = profiles
        .update_service_area(
            draft.revision_id,
            version,
            18.5204,
            73.8567,
            ServiceRadiusKm::Five,
        )
        .await?
    else {
        return Err("service area setup conflicted".into());
    };
    let ProfileMutation::Applied { version } = profiles
        .update_local_service_mode(
            draft.revision_id,
            version,
            LocalServiceMode::TravelToCustomer,
        )
        .await?
    else {
        return Err("service mode setup conflicted".into());
    };
    let ProfileMutation::Applied { version } = profiles
        .replace_services(
            draft.revision_id,
            version,
            &[ProfessionalServiceInput {
                category_code: "plumber".to_owned(),
                contact_mode: ContactMode::ApprovalRequired,
                skill_codes: vec!["leak_repair".to_owned()],
            }],
        )
        .await?
    else {
        return Err("service setup conflicted".into());
    };
    let ProfileMutation::Applied { version } = profiles
        .replace_languages(
            draft.revision_id,
            version,
            &[ProfessionalLanguage::EnglishIndia],
        )
        .await?
    else {
        return Err("language setup conflicted".into());
    };
    let ProfileMutation::Applied { version } = profiles
        .update_contact_request_limit(draft.revision_id, version, 3)
        .await?
    else {
        return Err("contact limit setup conflicted".into());
    };
    let (source_event, _) = create_leased_event(
        database,
        pool,
        cryptography,
        provider_namespace,
        account_id,
        channel_identity_id,
        "profile-consent",
        81,
    )
    .await?;
    let documents = consents
        .current_documents(ProfessionalLanguage::EnglishIndia)
        .await?;
    for purpose in [
        ProfessionalConsentPurpose::Terms,
        ProfessionalConsentPurpose::Privacy,
        ProfessionalConsentPurpose::ContactDisclosure,
    ] {
        let document = documents
            .iter()
            .find(|document| document.purpose == purpose)
            .ok_or("required consent document missing")?;
        consents
            .record(&RecordProfessionalConsent {
                id: ProfessionalConsentEventId::new(),
                account_id,
                profile_id,
                revision_id: draft.revision_id,
                purpose,
                action: ConsentAction::Granted,
                document_version: document.version.clone(),
                document_sha256: document.sha256,
                locale: ProfessionalLanguage::EnglishIndia,
                channel_identity_id,
                source_inbound_event_id: source_event,
                idempotency_key: format!("atomic-review-consent:{purpose}"),
                occurred_at: OffsetDateTime::now_utc(),
            })
            .await?;
    }
    let SubmitProfileOutcome::Submitted {
        version,
        target_digest,
    } = profiles
        .submit_complete_draft(
            account_id,
            channel_identity_id,
            provider_namespace,
            draft.revision_id,
            version,
        )
        .await?
    else {
        return Err("complete profile did not submit".into());
    };
    Ok((draft.revision_id, version, target_digest))
}

#[allow(clippy::too_many_arguments)]
async fn create_admin_prompt(
    database: &Database,
    pool: &PgPool,
    cryptography: &CryptoService,
    actor: (AccountId, ChannelIdentityId),
    provider_namespace: &str,
    review_token: &str,
    target_version: i64,
    marker: u8,
) -> Result<AdminPrompt, Box<dyn std::error::Error>> {
    let (event_id, lease) = create_leased_event(
        database,
        pool,
        cryptography,
        provider_namespace,
        actor.0,
        actor.1,
        "admin-prompt",
        marker,
    )
    .await?;
    let account_version: i64 =
        sqlx::query_scalar("SELECT version FROM identity.accounts WHERE id = $1")
            .bind(actor.0.into_uuid())
            .fetch_one(pool)
            .await?;
    let correlation_id = CorrelationId::new();
    let session_id = ConversationSessionId::new();
    let outbound = test_outbound(
        actor.1,
        provider_namespace,
        event_id,
        correlation_id,
        marker,
    );
    let outbound_id = outbound.id;
    let turn = CommitConversationTurn {
        lease,
        inbound_event_id: event_id,
        account_id: actor.0,
        channel_identity_id: actor.1,
        expected_account_version: account_version,
        workflow_correlation_id: correlation_id,
        reply_to_outbound_message_id: None,
        locale_change: None,
        session_change: ConversationSessionChange::Create {
            session_id,
            workflow_key: "administrator.review".to_owned(),
            workflow_version: 1,
            state_key: "confirm".to_owned(),
            state_data: serde_json::json!({
                "target_token": review_token,
                "target_version": target_version,
                "decision_code": "approve",
                "reason_code": null,
            }),
            language: "en-IN".to_owned(),
            workflow_correlation_id: correlation_id,
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(30),
            expired_session: None,
        },
        outbound,
        disposition: TurnDisposition::Applied,
    };
    let outcome = ConversationTurnRepository::new(database.clone())
        .commit_with_effects(
            &turn,
            &ConversationTurnEffects {
                effect: None,
                role_context: Some(AccountRole::Administrator),
                additional_outbound: Vec::new(),
            },
        )
        .await?;
    if !matches!(outcome, EffectfulTurnCommitOutcome::Committed { .. }) {
        return Err(format!("administrator prompt was not committed: {outcome:?}").into());
    }
    Ok(AdminPrompt {
        session_id,
        outbound_id,
        correlation_id,
    })
}

#[allow(clippy::too_many_arguments)]
async fn create_admin_decision_turn(
    database: &Database,
    pool: &PgPool,
    cryptography: &CryptoService,
    actor: (AccountId, ChannelIdentityId),
    provider_namespace: &str,
    review_token: &str,
    revision_id: ProfileRevisionId,
    expected_version: i64,
    target_digest: [u8; 32],
    prompt: AdminPrompt,
    notification: QueueOutboundMessage,
    _notification_correlation: CorrelationId,
    marker: u8,
) -> Result<(CommitConversationTurn, ConversationTurnEffects), Box<dyn std::error::Error>> {
    let (event_id, lease) = create_leased_event(
        database,
        pool,
        cryptography,
        provider_namespace,
        actor.0,
        actor.1,
        "admin-decision",
        marker,
    )
    .await?;
    let account_version: i64 =
        sqlx::query_scalar("SELECT version FROM identity.accounts WHERE id = $1")
            .bind(actor.0.into_uuid())
            .fetch_one(pool)
            .await?;
    let turn = CommitConversationTurn {
        lease,
        inbound_event_id: event_id,
        account_id: actor.0,
        channel_identity_id: actor.1,
        expected_account_version: account_version,
        workflow_correlation_id: prompt.correlation_id,
        reply_to_outbound_message_id: Some(prompt.outbound_id),
        locale_change: None,
        session_change: ConversationSessionChange::Advance {
            session_id: prompt.session_id,
            expected_version: 1,
            state_key: "queue".to_owned(),
            state_data: serde_json::json!({"page":0}),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(30),
        },
        outbound: test_outbound(
            actor.1,
            provider_namespace,
            event_id,
            prompt.correlation_id,
            marker.wrapping_add(20),
        ),
        disposition: TurnDisposition::Applied,
    };
    let effects = ConversationTurnEffects {
        effect: Some(ConversationTurnEffect::AdministratorReview(
            AdministratorReviewTurnEffect {
                id: ProfileReviewDecisionId::new(),
                review_token: review_token.to_owned(),
                revision_id,
                expected_version,
                target_digest,
                decision: ProfileReviewDecision::Approve,
                reason: ProfileReviewReason::MeetsPolicy,
                reason_detail: None,
                idempotency_key: format!("atomic-review:{}:{}", actor.0, revision_id),
                prompt_session_id: prompt.session_id,
                prompt_outbound_message_id: prompt.outbound_id,
            },
        )),
        role_context: Some(AccountRole::Administrator),
        additional_outbound: vec![notification],
    };
    Ok((turn, effects))
}

async fn create_identity(
    database: &Database,
    cryptography: &CryptoService,
) -> Result<(AccountId, ChannelIdentityId), Box<dyn std::error::Error>> {
    create_identity_in_namespace(database, cryptography, PROVIDER_NAMESPACE).await
}

async fn create_identity_in_namespace(
    database: &Database,
    cryptography: &CryptoService,
    provider_namespace: &str,
) -> Result<(AccountId, ChannelIdentityId), Box<dyn std::error::Error>> {
    let account_id = AccountId::new();
    let channel_identity_id = ChannelIdentityId::new();
    let suffix = channel_identity_id.into_uuid().as_u128() % 1_000_000_000;
    let wa_id = format!("919{suffix:09}");
    let phone = format!("+{wa_id}");
    let encrypted_wa_id = cryptography.encrypt(
        EncryptionPurpose::Contact,
        EncryptionContext::new(
            EncryptionNamespace::WHATSAPP_WA_ID,
            channel_identity_id.into_uuid(),
        ),
        wa_id.as_bytes(),
    )?;
    let encrypted_phone = cryptography.encrypt(
        EncryptionPurpose::Contact,
        EncryptionContext::new(
            EncryptionNamespace::WHATSAPP_PHONE_E164,
            channel_identity_id.into_uuid(),
        ),
        phone.as_bytes(),
    )?;
    let wa_digests = fingerprints(
        cryptography,
        &format!("whatsapp:{provider_namespace}:wa_id"),
        wa_id.as_bytes(),
    )?;
    let phone_digests = fingerprints(
        cryptography,
        &format!("whatsapp:{provider_namespace}:phone_e164"),
        phone.as_bytes(),
    )?;
    IdentityRepository::new(database.clone())
        .create_whatsapp_account(&NewWhatsAppAccount {
            account_id,
            channel_identity_id,
            correlation_id: CorrelationId::new(),
            provider_namespace: provider_namespace.to_owned(),
            preferred_locale: "en-IN".to_owned(),
            time_zone: "Asia/Kolkata".to_owned(),
            encrypted_wa_id,
            encrypted_phone_e164: encrypted_phone,
            wa_id_digests: wa_digests,
            phone_e164_digests: phone_digests,
            active_lookup_key_version: cryptography.active_lookup_version(),
        })
        .await?;
    Ok((account_id, channel_identity_id))
}

#[allow(clippy::too_many_arguments)]
async fn create_leased_event(
    database: &Database,
    pool: &PgPool,
    cryptography: &CryptoService,
    provider_namespace: &str,
    account_id: AccountId,
    channel_identity_id: ChannelIdentityId,
    suffix: &str,
    marker: u8,
) -> Result<(InboundEventId, JobLease), Box<dyn std::error::Error>> {
    let event_id = InboundEventId::new();
    let job_id = OutboxJobId::new();
    let normalized = format!(r#"{{"kind":"message","value":"{suffix}"}}"#);
    let encrypted = cryptography.encrypt(
        EncryptionPurpose::Integration,
        EncryptionContext::new(
            EncryptionNamespace::INBOUND_EVENT_PAYLOAD,
            event_id.into_uuid(),
        ),
        normalized.as_bytes(),
    )?;
    let (fingerprint_key_version, payload_fingerprint) =
        cryptography.blind_index("integration:whatsapp:event:v1", normalized.as_bytes())?;
    database
        .accept_inbound_event(&InboundEventInput {
            event_id,
            provider_code: "whatsapp".to_owned(),
            provider_namespace: provider_namespace.to_owned(),
            provider_event_id: format!("effect:{suffix}:{event_id}"),
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
            provider_occurred_at: Some(OffsetDateTime::now_utc()),
            processing_job_id: job_id,
            processing_job_kind: "process_conversation_message".to_owned(),
            processing_ordering_key: Some([marker; 32]),
            max_attempts: 8,
        })
        .await?;
    bind_event(
        database,
        cryptography,
        event_id,
        account_id,
        channel_identity_id,
        provider_namespace,
    )
    .await?;
    let worker_id = WorkerId::new();
    let token = JobLeaseToken::new();
    sqlx::query(
        r#"
        UPDATE integration.outbox_jobs
        SET state = 'leased', attempt_count = attempt_count + 1,
            lease_owner = $2, lease_token = $3,
            lease_started_at = statement_timestamp(),
            lease_expires_at = statement_timestamp() + INTERVAL '1 minute'
        WHERE id = $1
        "#,
    )
    .bind(job_id.into_uuid())
    .bind(worker_id.into_uuid())
    .bind(token.into_uuid())
    .execute(pool)
    .await?;
    Ok((
        event_id,
        JobLease {
            job_id,
            worker_id,
            token,
        },
    ))
}

async fn bind_event(
    database: &Database,
    cryptography: &CryptoService,
    event_id: InboundEventId,
    account_id: AccountId,
    channel_identity_id: ChannelIdentityId,
    provider_namespace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let suffix = channel_identity_id.into_uuid().as_u128() % 1_000_000_000;
    let wa_id = format!("919{suffix:09}");
    let digests = fingerprints(
        cryptography,
        &format!("whatsapp:{provider_namespace}:wa_id"),
        wa_id.as_bytes(),
    )?;
    database
        .bind_inbound_event_identity(event_id, account_id, channel_identity_id, &digests)
        .await?;
    Ok(())
}

fn test_outbound(
    channel_identity_id: ChannelIdentityId,
    provider_namespace: &str,
    event_id: InboundEventId,
    correlation_id: CorrelationId,
    marker: u8,
) -> QueueOutboundMessage {
    QueueOutboundMessage {
        id: OutboundMessageId::new(),
        provider_namespace: provider_namespace.to_owned(),
        recipient_channel_identity_id: Some(channel_identity_id),
        idempotency_key: format!("conversation-turn:v1:{event_id}"),
        payload: EncryptedOutboundPayload {
            schema_version: 1,
            encrypted: EncryptedValue {
                purpose: EncryptionPurpose::Integration,
                key_version: 1,
                nonce: [marker; 12],
                ciphertext: vec![marker; 32],
            },
            fingerprint_key_version: 1,
            request_fingerprint: [marker; 32],
            additional_fingerprints: Vec::new(),
        },
        callback_token: CallbackToken::new(),
        correlation_id,
        ordering_key: Some([marker; 32]),
        send_job_id: OutboxJobId::new(),
        max_attempts: 8,
    }
}

fn fingerprints(
    cryptography: &CryptoService,
    namespace: &str,
    value: &[u8],
) -> Result<Vec<LookupDigest>, Box<dyn std::error::Error>> {
    Ok(cryptography
        .all_blind_indexes(namespace, value)?
        .into_iter()
        .map(|(key_version, digest)| LookupDigest {
            key_version,
            digest,
        })
        .collect())
}

fn crypto_service() -> Result<CryptoService, Box<dyn std::error::Error>> {
    Ok(CryptoService::new(
        vec![
            EncryptionKeySet::new(
                EncryptionPurpose::Contact,
                1,
                vec![VersionedKey::from_bytes(1, [103; 32])?],
            ),
            EncryptionKeySet::new(
                EncryptionPurpose::Integration,
                1,
                vec![VersionedKey::from_bytes(1, [107; 32])?],
            ),
            EncryptionKeySet::new(
                EncryptionPurpose::Media,
                1,
                vec![VersionedKey::from_bytes(1, [113; 32])?],
            ),
        ],
        1,
        vec![VersionedKey::from_bytes(1, [109; 32])?],
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
    let database = Database::connect(&settings, "conversation-turn-test").await?;
    let assertion_pool = PgPool::connect(&database_url).await?;
    Ok(Some((database, assertion_pool)))
}

async fn cleanup_conversation_jobs(pool: &PgPool) -> Result<(), sqlx::Error> {
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
        WHERE job_kind = 'process_conversation_message'
          AND state IN ('pending', 'leased')
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}
