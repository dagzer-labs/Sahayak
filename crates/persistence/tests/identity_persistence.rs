use sahayak_cryptography::{
    CryptoService, EncryptedValue, EncryptionContext, EncryptionKeySet, EncryptionNamespace,
    EncryptionPurpose, NormalizedPhoneNumber, VersionedKey,
};
use sahayak_domain::{AccountId, ChannelIdentityId, ChannelIdentityState, CorrelationId};
use sahayak_persistence::{Database, IdentityRepository, LookupDigest, NewWhatsAppAccount};
use secrecy::SecretString;
use sqlx::PgPool;
use std::{env, sync::Arc};
use time::OffsetDateTime;
use tokio::sync::Barrier;

const TEST_DATABASE_ENVIRONMENT: &str = "SAHAYAK_TEST_DATABASE_URL";

#[tokio::test]
async fn whatsapp_identity_is_encrypted_atomic_and_lookup_safe()
-> Result<(), Box<dyn std::error::Error>> {
    let Some((database, assertion_pool)) = test_database().await? else {
        return Ok(());
    };
    let cryptography = crypto_service()?;
    let repository = IdentityRepository::new(database.clone());
    let account_id = AccountId::new();
    let channel_identity_id = ChannelIdentityId::new();
    let provider_namespace = "identity-test-business";
    let wa_id = format!(
        "919{:09}",
        channel_identity_id.into_uuid().as_u128() % 1_000_000_000
    );
    let phone_value = format!("+{wa_id}");
    let phone = NormalizedPhoneNumber::parse(&phone_value)?;
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
        phone.expose().as_bytes(),
    )?;
    let lookup_namespace = format!("whatsapp:{provider_namespace}:wa_id");
    let (lookup_key_version, wa_id_digest) =
        cryptography.blind_index(&lookup_namespace, wa_id.as_bytes())?;
    let (_, phone_e164_digest) = cryptography.blind_index(
        &format!("whatsapp:{provider_namespace}:phone_e164"),
        phone.expose().as_bytes(),
    )?;
    let input = NewWhatsAppAccount {
        account_id,
        channel_identity_id,
        correlation_id: CorrelationId::new(),
        provider_namespace: provider_namespace.to_owned(),
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
    };

    let created = repository.create_whatsapp_account(&input).await?;
    assert_eq!(created.account_id, account_id);
    assert_eq!(created.channel_identity_id, channel_identity_id);

    let found = repository
        .find_whatsapp_by_wa_id_digest(lookup_key_version, &wa_id_digest)
        .await?
        .ok_or("expected blind-index lookup result")?;
    assert_eq!(found.account_id, account_id);
    assert_eq!(found.channel_identity_id, channel_identity_id);
    assert_eq!(found.state, ChannelIdentityState::Active);

    let stored: (Vec<u8>, Vec<u8>, i16) = sqlx::query_as(
        r#"
        SELECT wa_id_ciphertext, wa_id_nonce, encryption_key_version
        FROM private_data.whatsapp_identities
        WHERE channel_identity_id = $1
        "#,
    )
    .bind(channel_identity_id.into_uuid())
    .fetch_one(&assertion_pool)
    .await?;
    assert!(
        !stored
            .0
            .windows(wa_id.len())
            .any(|window| window == wa_id.as_bytes())
    );
    let nonce: [u8; 12] = stored
        .1
        .try_into()
        .map_err(|_| std::io::Error::other("stored WhatsApp nonce has invalid length"))?;
    let decrypted = cryptography.decrypt(
        EncryptionContext::new(
            EncryptionNamespace::WHATSAPP_WA_ID,
            channel_identity_id.into_uuid(),
        ),
        &EncryptedValue {
            purpose: EncryptionPurpose::Contact,
            key_version: stored.2,
            nonce,
            ciphertext: stored.0,
        },
    )?;
    assert_eq!(decrypted.as_slice(), wa_id.as_bytes());

    let conflicting_account_id = AccountId::new();
    let conflicting = NewWhatsAppAccount {
        account_id: conflicting_account_id,
        channel_identity_id: ChannelIdentityId::new(),
        ..input.clone()
    };
    assert!(
        repository
            .create_whatsapp_account(&conflicting)
            .await
            .is_err()
    );
    let orphan_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.accounts WHERE id = $1")
            .bind(conflicting_account_id.into_uuid())
            .fetch_one(&assertion_pool)
            .await?;
    assert_eq!(orphan_count, 0);

    assertion_pool.close().await;
    database.close().await;
    Ok(())
}

#[tokio::test]
async fn concurrent_first_contact_resolves_one_identity() -> Result<(), Box<dyn std::error::Error>>
{
    let Some((database, assertion_pool)) = test_database().await? else {
        return Ok(());
    };
    let cryptography = crypto_service()?;
    let unique = ChannelIdentityId::new().into_uuid().as_u128() % 1_000_000_000;
    let wa_id = format!("919{unique:09}");
    let phone = format!("+{wa_id}");
    let provider_namespace = "identity-race-business";
    let inputs = [
        build_input(&cryptography, provider_namespace, &wa_id, &phone)?,
        build_input(&cryptography, provider_namespace, &wa_id, &phone)?,
    ];
    let repository = Arc::new(IdentityRepository::new(database.clone()));
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for input in inputs {
        let repository = Arc::clone(&repository);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            repository
                .resolve_or_create_whatsapp_account(&input, OffsetDateTime::now_utc())
                .await
        }));
    }
    barrier.wait().await;
    let first = tasks.remove(0).await??;
    let second = tasks.remove(0).await??;
    let first = match first {
        sahayak_persistence::ResolveIdentityOutcome::Created(value)
        | sahayak_persistence::ResolveIdentityOutcome::Existing(value) => value,
    };
    let second = match second {
        sahayak_persistence::ResolveIdentityOutcome::Created(value)
        | sahayak_persistence::ResolveIdentityOutcome::Existing(value) => value,
    };
    assert_eq!(first, second);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity.channel_identities WHERE account_id = $1",
    )
    .bind(first.account_id.into_uuid())
    .fetch_one(&assertion_pool)
    .await?;
    assert_eq!(count, 1);
    assertion_pool.close().await;
    database.close().await;
    Ok(())
}

fn build_input(
    cryptography: &CryptoService,
    provider_namespace: &str,
    wa_id: &str,
    phone: &str,
) -> Result<NewWhatsAppAccount, Box<dyn std::error::Error>> {
    let account_id = AccountId::new();
    let channel_identity_id = ChannelIdentityId::new();
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
    let wa_indexes = cryptography.all_blind_indexes(
        &format!("whatsapp:{provider_namespace}:wa_id"),
        wa_id.as_bytes(),
    )?;
    let phone_indexes = cryptography.all_blind_indexes(
        &format!("whatsapp:{provider_namespace}:phone_e164"),
        phone.as_bytes(),
    )?;
    Ok(NewWhatsAppAccount {
        account_id,
        channel_identity_id,
        correlation_id: CorrelationId::new(),
        provider_namespace: provider_namespace.to_owned(),
        preferred_locale: "en-IN".to_owned(),
        time_zone: "Asia/Kolkata".to_owned(),
        encrypted_wa_id,
        encrypted_phone_e164: encrypted_phone,
        wa_id_digests: wa_indexes
            .into_iter()
            .map(|(key_version, digest)| LookupDigest {
                key_version,
                digest,
            })
            .collect(),
        phone_e164_digests: phone_indexes
            .into_iter()
            .map(|(key_version, digest)| LookupDigest {
                key_version,
                digest,
            })
            .collect(),
        active_lookup_key_version: cryptography.active_lookup_version(),
    })
}

fn crypto_service() -> Result<CryptoService, Box<dyn std::error::Error>> {
    Ok(CryptoService::new(
        vec![
            EncryptionKeySet::new(
                EncryptionPurpose::Contact,
                1,
                vec![VersionedKey::from_bytes(1, [31; 32])?],
            ),
            EncryptionKeySet::new(
                EncryptionPurpose::Identity,
                1,
                vec![VersionedKey::from_bytes(1, [37; 32])?],
            ),
            EncryptionKeySet::new(
                EncryptionPurpose::Integration,
                1,
                vec![VersionedKey::from_bytes(1, [41; 32])?],
            ),
        ],
        1,
        vec![VersionedKey::from_bytes(1, [47; 32])?],
    )?)
}

async fn test_database() -> Result<Option<(Database, PgPool)>, Box<dyn std::error::Error>> {
    let Ok(database_url) = env::var(TEST_DATABASE_ENVIRONMENT) else {
        return Ok(None);
    };
    let settings = sahayak_configuration::DatabaseSettings {
        url: SecretString::from(database_url.clone()),
        min_connections: 1,
        max_connections: 5,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 30,
        max_lifetime_seconds: 60,
        statement_timeout_milliseconds: 10_000,
        lock_timeout_milliseconds: 5_000,
        idle_in_transaction_timeout_milliseconds: 10_000,
        require_tls: false,
    };
    let database = Database::connect(&settings, "identity-persistence-test").await?;
    let assertion_pool = PgPool::connect(&database_url).await?;
    Ok(Some((database, assertion_pool)))
}
