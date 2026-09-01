use sahayak_cryptography::{
    CryptoService, EncryptionContext, EncryptionKeySet, EncryptionNamespace, EncryptionPurpose,
    VersionedKey, content_sha256,
};
use sahayak_domain::{
    AccountId, AccountLifecycle, AccountRole, AuditEventId, ChannelIdentityId,
    ConversationSessionId, CorrelationId,
};
use sahayak_persistence::{
    AccountMutation, AccountRepository, AuditActor, AuditRepository, ConversationRepository,
    Database, IdentityRepository, KeyRegistryRepository, LookupDigest, NewAuditEvent,
    NewConversationSession, NewWhatsAppAccount, PrivateIdentityMutation, PrivateIdentityRepository,
    SavePrivateIdentity,
};
use secrecy::SecretString;
use serde_json::json;
use sqlx::PgPool;
use std::{env, sync::Arc};
use time::OffsetDateTime;
use tokio::sync::Barrier;

const TEST_DATABASE_ENVIRONMENT: &str = "SAHAYAK_TEST_DATABASE_URL";

#[tokio::test]
async fn core_identity_profile_conversation_and_audit_invariants_hold()
-> Result<(), Box<dyn std::error::Error>> {
    let Some((database, assertion_pool)) = test_database().await? else {
        return Ok(());
    };
    let cryptography = crypto_service()?;
    let key_registry = KeyRegistryRepository::new(database.clone());
    key_registry
        .verify_active_versions(
            cryptography
                .active_encryption_version(EncryptionPurpose::Contact)
                .ok_or("contact encryption key missing")?,
            cryptography
                .active_encryption_version(EncryptionPurpose::Identity)
                .ok_or("identity encryption key missing")?,
            cryptography
                .active_encryption_version(EncryptionPurpose::Integration)
                .ok_or("integration encryption key missing")?,
            cryptography.active_lookup_version(),
        )
        .await?;
    assert!(
        key_registry
            .verify_active_versions(2, 1, 1, 1)
            .await
            .is_err()
    );
    let account_id = AccountId::new();
    let channel_identity_id = ChannelIdentityId::new();
    create_account(&database, &cryptography, account_id, channel_identity_id).await?;

    let accounts = AccountRepository::new(database.clone());
    let pending = accounts.find(account_id).await?.ok_or("account missing")?;
    assert_eq!(pending.lifecycle, AccountLifecycle::Pending);
    assert_eq!(
        accounts
            .transition_lifecycle(
                account_id,
                pending.version,
                AccountLifecycle::Active,
                CorrelationId::new(),
            )
            .await?,
        AccountMutation::Applied {
            version: pending.version + 1
        }
    );
    assert_eq!(
        accounts
            .transition_lifecycle(
                account_id,
                pending.version,
                AccountLifecycle::Suspended,
                CorrelationId::new(),
            )
            .await?,
        AccountMutation::ConflictOrMissing
    );
    accounts
        .grant_role(account_id, AccountRole::Professional, None)
        .await?;
    let invalid_verification_shape = sqlx::query(
        r#"
        INSERT INTO private_data.account_identities (
            account_id,
            payload_schema_version,
            encrypted_payload,
            payload_nonce,
            encryption_key_version,
            verification_state,
            consent_version,
            consented_at
        )
        VALUES ($1, 1, $2, $3, 1, 'expired', 'identity-v1', statement_timestamp())
        "#,
    )
    .bind(account_id.into_uuid())
    .bind(vec![1_u8; 32])
    .bind(vec![2_u8; 12])
    .execute(&assertion_pool)
    .await;
    assert!(invalid_verification_shape.is_err());
    let professional_role_active: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM identity.account_roles
            WHERE account_id = $1
              AND role = 'professional'
              AND revoked_at IS NULL
        )
        "#,
    )
    .bind(account_id.into_uuid())
    .fetch_one(&assertion_pool)
    .await?;
    assert!(professional_role_active);

    let conversations = ConversationRepository::new(database.clone());
    let session = conversations
        .start(&NewConversationSession {
            id: ConversationSessionId::new(),
            account_id,
            channel_identity_id,
            role_context: AccountRole::Customer,
            workflow_key: "customer.discovery".to_owned(),
            workflow_version: 1,
            state_key: "choose_category".to_owned(),
            state_data: json!({"page": 1}),
            language: "en-IN".to_owned(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            last_inbound_event_id: None,
            workflow_correlation_id: CorrelationId::new(),
            expected_reply_to_outbound_message_id: None,
        })
        .await?;
    let advanced = conversations
        .compare_and_set_state(
            session.id,
            session.version,
            "share_location",
            &json!({"category": "plumber"}),
            OffsetDateTime::now_utc() + time::Duration::hours(1),
            None,
            None,
            None,
        )
        .await?;
    assert_eq!(
        advanced,
        sahayak_persistence::SessionMutation::Applied {
            version: session.version + 1
        }
    );
    let active_session = conversations
        .find_active(channel_identity_id)
        .await?
        .ok_or("active conversation missing")?;
    assert!(
        active_session
            .expected_reply_to_outbound_message_id
            .is_none()
    );
    assert_eq!(
        conversations
            .compare_and_set_state(
                session.id,
                session.version,
                "stale_reply",
                &json!({}),
                OffsetDateTime::now_utc() + time::Duration::hours(1),
                None,
                None,
                None,
            )
            .await?,
        sahayak_persistence::SessionMutation::ConflictOrMissing
    );
    assert_eq!(
        conversations.complete(session.id, session.version).await?,
        sahayak_persistence::SessionMutation::ConflictOrMissing
    );
    assert_eq!(
        conversations
            .complete(session.id, session.version + 1)
            .await?,
        sahayak_persistence::SessionMutation::Applied {
            version: session.version + 2
        }
    );
    assert!(
        conversations
            .find_active(channel_identity_id)
            .await?
            .is_none()
    );
    let expiring = conversations
        .start(&NewConversationSession {
            id: ConversationSessionId::new(),
            account_id,
            channel_identity_id,
            role_context: AccountRole::Customer,
            workflow_key: "customer.discovery".to_owned(),
            workflow_version: 1,
            state_key: "choose_category".to_owned(),
            state_data: json!({}),
            language: "en-IN".to_owned(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            last_inbound_event_id: None,
            workflow_correlation_id: CorrelationId::new(),
            expected_reply_to_outbound_message_id: None,
        })
        .await?;
    sqlx::query("UPDATE messaging.conversation_sessions SET expires_at = created_at WHERE id = $1")
        .bind(expiring.id.into_uuid())
        .execute(&assertion_pool)
        .await?;
    assert!(
        conversations
            .find_active(channel_identity_id)
            .await?
            .is_none()
    );
    let replacement_session = conversations
        .start(&NewConversationSession {
            id: ConversationSessionId::new(),
            account_id,
            channel_identity_id,
            role_context: AccountRole::Customer,
            workflow_key: "customer.discovery".to_owned(),
            workflow_version: 1,
            state_key: "choose_category".to_owned(),
            state_data: json!({}),
            language: "en-IN".to_owned(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            last_inbound_event_id: None,
            workflow_correlation_id: CorrelationId::new(),
            expected_reply_to_outbound_message_id: None,
        })
        .await?;
    assert_eq!(replacement_session.version, 1);

    let private_identities = PrivateIdentityRepository::new(database.clone());
    let private_context = EncryptionContext::new(
        EncryptionNamespace::ACCOUNT_IDENTITY_PAYLOAD,
        account_id.into_uuid(),
    );
    let encrypted_identity = cryptography.encrypt(
        EncryptionPurpose::Identity,
        private_context,
        br#"{"legal_name":"Private Test Name"}"#,
    )?;
    assert_eq!(
        private_identities
            .save(&SavePrivateIdentity {
                account_id,
                payload_schema_version: 1,
                payload: encrypted_identity,
                consent_version: "identity-v1".to_owned(),
                consented_at: OffsetDateTime::now_utc(),
                expected_version: None,
            })
            .await?,
        PrivateIdentityMutation::Applied { version: 1 }
    );
    let stored_identity = private_identities
        .find(account_id)
        .await?
        .ok_or("private identity missing")?;
    let decrypted = cryptography.decrypt(private_context, &stored_identity.payload)?;
    assert!(
        decrypted
            .windows(17)
            .any(|value| value == b"Private Test Name")
    );
    let replacement = cryptography.encrypt(
        EncryptionPurpose::Identity,
        private_context,
        br#"{"legal_name":"Updated Private Name"}"#,
    )?;
    assert_eq!(
        private_identities
            .save(&SavePrivateIdentity {
                account_id,
                payload_schema_version: 1,
                payload: replacement.clone(),
                consent_version: "identity-v2".to_owned(),
                consented_at: OffsetDateTime::now_utc(),
                expected_version: Some(stored_identity.version),
            })
            .await?,
        PrivateIdentityMutation::Applied {
            version: stored_identity.version + 1
        }
    );
    assert_eq!(
        private_identities
            .save(&SavePrivateIdentity {
                account_id,
                payload_schema_version: 1,
                payload: replacement.clone(),
                consent_version: "identity-v2".to_owned(),
                consented_at: OffsetDateTime::now_utc(),
                expected_version: Some(stored_identity.version),
            })
            .await?,
        PrivateIdentityMutation::Conflict
    );

    let audits = AuditRepository::new(database.clone());
    let audit_id = audits
        .append(&NewAuditEvent {
            id: AuditEventId::new(),
            actor: AuditActor::system(),
            action: "account.activated".to_owned(),
            target_type: "account".to_owned(),
            target_id: Some(account_id.into_uuid()),
            reason_code: "onboarding_completed".to_owned(),
            before_digest: Some(content_sha256(b"pending")),
            after_digest: Some(content_sha256(b"active")),
            metadata: json!({"source": "integration_test"}),
            event_schema_version: 1,
            correlation_id: CorrelationId::new(),
        })
        .await?;
    let mutation = sqlx::query("UPDATE audit.events SET reason_code = 'tampered' WHERE id = $1")
        .bind(audit_id.into_uuid())
        .execute(&assertion_pool)
        .await;
    assert!(mutation.is_err());
    let deletion = sqlx::query("DELETE FROM audit.events WHERE id = $1")
        .bind(audit_id.into_uuid())
        .execute(&assertion_pool)
        .await;
    assert!(deletion.is_err());
    let truncation = sqlx::query("TRUNCATE audit.events")
        .execute(&assertion_pool)
        .await;
    assert!(truncation.is_err());
    assert!(
        accounts
            .revoke_role(account_id, AccountRole::Professional)
            .await?
    );
    assert!(
        !accounts
            .revoke_role(account_id, AccountRole::Professional)
            .await?
    );

    let active_account = accounts.find(account_id).await?.ok_or("account missing")?;
    assert_eq!(active_account.lifecycle, AccountLifecycle::Active);
    assert_eq!(
        accounts
            .transition_lifecycle(
                account_id,
                active_account.version,
                AccountLifecycle::DeletionPending,
                CorrelationId::new(),
            )
            .await?,
        AccountMutation::Applied {
            version: active_account.version + 1
        }
    );
    let blocked_private_write = private_identities
        .save(&SavePrivateIdentity {
            account_id,
            payload_schema_version: 1,
            payload: replacement,
            consent_version: "identity-v3".to_owned(),
            consented_at: OffsetDateTime::now_utc(),
            expected_version: Some(stored_identity.version + 1),
        })
        .await;
    assert!(blocked_private_write.is_err());
    assert_eq!(
        accounts
            .transition_lifecycle(
                account_id,
                active_account.version + 1,
                AccountLifecycle::Deleted,
                CorrelationId::new(),
            )
            .await?,
        AccountMutation::Applied {
            version: active_account.version + 2
        }
    );
    assert!(private_identities.find(account_id).await?.is_none());
    let remaining_lookup_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM private_data.channel_lookup_digests AS lookup
        JOIN identity.channel_identities AS identity
          ON identity.id = lookup.channel_identity_id
        WHERE identity.account_id = $1
        "#,
    )
    .bind(account_id.into_uuid())
    .fetch_one(&assertion_pool)
    .await?;
    assert_eq!(remaining_lookup_count, 0);

    assertion_pool.close().await;
    database.close().await;
    Ok(())
}

#[tokio::test]
async fn account_deletion_wins_against_concurrent_private_identity_write()
-> Result<(), Box<dyn std::error::Error>> {
    let Some((database, assertion_pool)) = test_database().await? else {
        return Ok(());
    };
    let cryptography = crypto_service()?;
    let account_id = AccountId::new();
    let channel_identity_id = ChannelIdentityId::new();
    create_account(&database, &cryptography, account_id, channel_identity_id).await?;
    let accounts = AccountRepository::new(database.clone());
    let pending = accounts.find(account_id).await?.ok_or("account missing")?;
    accounts
        .transition_lifecycle(
            account_id,
            pending.version,
            AccountLifecycle::Active,
            CorrelationId::new(),
        )
        .await?;
    let private_identities = PrivateIdentityRepository::new(database.clone());
    let context = EncryptionContext::new(
        EncryptionNamespace::ACCOUNT_IDENTITY_PAYLOAD,
        account_id.into_uuid(),
    );
    private_identities
        .save(&SavePrivateIdentity {
            account_id,
            payload_schema_version: 1,
            payload: cryptography.encrypt(
                EncryptionPurpose::Identity,
                context,
                br#"{"legal_name":"Initial"}"#,
            )?,
            consent_version: "identity-v1".to_owned(),
            consented_at: OffsetDateTime::now_utc(),
            expected_version: None,
        })
        .await?;

    let barrier = Arc::new(Barrier::new(3));
    let delete_task = {
        let barrier = Arc::clone(&barrier);
        let accounts = accounts.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            let pending_deletion = accounts
                .transition_lifecycle(
                    account_id,
                    pending.version + 1,
                    AccountLifecycle::DeletionPending,
                    CorrelationId::new(),
                )
                .await?;
            let AccountMutation::Applied { version } = pending_deletion else {
                return Ok::<_, sahayak_persistence::PersistenceError>(pending_deletion);
            };
            accounts
                .transition_lifecycle(
                    account_id,
                    version,
                    AccountLifecycle::Deleted,
                    CorrelationId::new(),
                )
                .await
        })
    };
    let write_task = {
        let barrier = Arc::clone(&barrier);
        let private_identities = private_identities.clone();
        let replacement = cryptography.encrypt(
            EncryptionPurpose::Identity,
            context,
            br#"{"legal_name":"Racing Write"}"#,
        )?;
        tokio::spawn(async move {
            barrier.wait().await;
            private_identities
                .save(&SavePrivateIdentity {
                    account_id,
                    payload_schema_version: 1,
                    payload: replacement,
                    consent_version: "identity-v2".to_owned(),
                    consented_at: OffsetDateTime::now_utc(),
                    expected_version: Some(1),
                })
                .await
        })
    };

    barrier.wait().await;
    let deletion = delete_task.await??;
    let _write_result = write_task.await?;
    assert!(matches!(deletion, AccountMutation::Applied { .. }));
    assert!(private_identities.find(account_id).await?.is_none());
    assert_eq!(
        accounts
            .find(account_id)
            .await?
            .ok_or("deleted account missing")?
            .lifecycle,
        AccountLifecycle::Deleted
    );

    assertion_pool.close().await;
    database.close().await;
    Ok(())
}

async fn create_account(
    database: &Database,
    cryptography: &CryptoService,
    account_id: AccountId,
    channel_identity_id: ChannelIdentityId,
) -> Result<(), Box<dyn std::error::Error>> {
    let wa_id = format!(
        "919{:09}",
        channel_identity_id.into_uuid().as_u128() % 1_000_000_000
    );
    let phone = format!("+{wa_id}");
    let encrypted_wa_id = cryptography.encrypt(
        EncryptionPurpose::Contact,
        EncryptionContext::new(
            EncryptionNamespace::WHATSAPP_WA_ID,
            channel_identity_id.into_uuid(),
        ),
        wa_id.as_bytes(),
    )?;
    let encrypted_phone_e164 = cryptography.encrypt(
        EncryptionPurpose::Contact,
        EncryptionContext::new(
            EncryptionNamespace::WHATSAPP_PHONE_E164,
            channel_identity_id.into_uuid(),
        ),
        phone.as_bytes(),
    )?;
    let (lookup_key_version, wa_id_digest) =
        cryptography.blind_index("whatsapp:core-test-business:wa_id", wa_id.as_bytes())?;
    let (_, phone_e164_digest) =
        cryptography.blind_index("whatsapp:core-test-business:phone_e164", phone.as_bytes())?;
    IdentityRepository::new(database.clone())
        .create_whatsapp_account(&NewWhatsAppAccount {
            account_id,
            channel_identity_id,
            correlation_id: CorrelationId::new(),
            provider_namespace: "core-test-business".to_owned(),
            preferred_locale: "en-IN".to_owned(),
            time_zone: "Asia/Kolkata".to_owned(),
            encrypted_wa_id,
            encrypted_phone_e164,
            wa_id_digests: vec![LookupDigest {
                key_version: lookup_key_version,
                digest: wa_id_digest,
            }],
            phone_e164_digests: vec![LookupDigest {
                key_version: lookup_key_version,
                digest: phone_e164_digest,
            }],
            active_lookup_key_version: lookup_key_version,
        })
        .await?;
    Ok(())
}

fn crypto_service() -> Result<CryptoService, Box<dyn std::error::Error>> {
    Ok(CryptoService::new(
        vec![
            EncryptionKeySet::new(
                EncryptionPurpose::Contact,
                1,
                vec![VersionedKey::from_bytes(1, [53; 32])?],
            ),
            EncryptionKeySet::new(
                EncryptionPurpose::Identity,
                1,
                vec![VersionedKey::from_bytes(1, [57; 32])?],
            ),
            EncryptionKeySet::new(
                EncryptionPurpose::Integration,
                1,
                vec![VersionedKey::from_bytes(1, [61; 32])?],
            ),
        ],
        1,
        vec![VersionedKey::from_bytes(1, [59; 32])?],
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
    let database = Database::connect(&settings, "core-persistence-test").await?;
    let assertion_pool = PgPool::connect(&database_url).await?;
    Ok(Some((database, assertion_pool)))
}
