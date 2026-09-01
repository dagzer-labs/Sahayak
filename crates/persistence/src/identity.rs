use crate::{
    Database, PersistenceError,
    key_registry::{ensure_active_encryption_key, ensure_active_lookup_key},
};
use sahayak_cryptography::{EncryptedValue, EncryptionPurpose};
use sahayak_domain::{
    AccountId, AuditEventId, ChannelIdentityId, ChannelIdentityState, CorrelationId,
};
use sqlx::FromRow;
use std::collections::BTreeSet;
use time::OffsetDateTime;
use uuid::Uuid;

/// One versioned HMAC digest used during lookup-key rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupDigest {
    /// Lookup HMAC key version.
    pub key_version: i16,
    /// HMAC-SHA-256 output.
    pub digest: [u8; 32],
}

/// Encrypted values and lookup digests needed to create one WhatsApp-backed account.
#[derive(Clone)]
pub struct NewWhatsAppAccount {
    /// New internal account identifier.
    pub account_id: AccountId,
    /// New channel identity identifier used as encryption associated data.
    pub channel_identity_id: ChannelIdentityId,
    /// Correlation identifier for the onboarding transaction and audit event.
    pub correlation_id: CorrelationId,
    /// Meta business or deployment namespace containing this identity.
    pub provider_namespace: String,
    /// Initial BCP-47 user language.
    pub preferred_locale: String,
    /// Initial IANA time-zone name.
    pub time_zone: String,
    /// Encrypted Meta WhatsApp identifier.
    pub encrypted_wa_id: EncryptedValue,
    /// Encrypted canonical E.164 phone number.
    pub encrypted_phone_e164: EncryptedValue,
    /// HMAC-SHA-256 digests for Meta WhatsApp identifier lookup.
    pub wa_id_digests: Vec<LookupDigest>,
    /// HMAC-SHA-256 digests for canonical phone lookup.
    pub phone_e164_digests: Vec<LookupDigest>,
    /// Key version used for new lookup writes during rotation.
    pub active_lookup_key_version: i16,
}

impl NewWhatsAppAccount {
    fn validate(&self) -> Result<(), PersistenceError> {
        if self.provider_namespace.is_empty()
            || self.provider_namespace.len() > 128
            || self.provider_namespace.trim() != self.provider_namespace
            || self
                .provider_namespace
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(PersistenceError::InvalidCommand(
                "provider namespace is empty, oversized, or contains control characters".to_owned(),
            ));
        }
        if !(2..=35).contains(&self.preferred_locale.len())
            || self.preferred_locale.trim() != self.preferred_locale
        {
            return Err(PersistenceError::InvalidCommand(
                "preferred locale must contain between 2 and 35 bytes".to_owned(),
            ));
        }
        if self.time_zone.is_empty() || self.time_zone.len() > 64 {
            return Err(PersistenceError::InvalidCommand(
                "time zone must contain between 1 and 64 bytes".to_owned(),
            ));
        }
        if self.encrypted_wa_id.key_version != self.encrypted_phone_e164.key_version {
            return Err(PersistenceError::InvalidCommand(
                "WhatsApp identifiers must use the same active encryption key version".to_owned(),
            ));
        }
        if self.encrypted_wa_id.purpose != EncryptionPurpose::Contact
            || self.encrypted_phone_e164.purpose != EncryptionPurpose::Contact
        {
            return Err(PersistenceError::InvalidCommand(
                "WhatsApp identifiers require the contact encryption key purpose".to_owned(),
            ));
        }
        validate_lookup_digests("WhatsApp ID", &self.wa_id_digests)?;
        validate_lookup_digests("phone", &self.phone_e164_digests)?;
        let wa_versions: BTreeSet<_> = self
            .wa_id_digests
            .iter()
            .map(|item| item.key_version)
            .collect();
        let phone_versions: BTreeSet<_> = self
            .phone_e164_digests
            .iter()
            .map(|item| item.key_version)
            .collect();
        if wa_versions != phone_versions {
            return Err(PersistenceError::InvalidCommand(
                "WhatsApp and phone lookups must contain the same key versions".to_owned(),
            ));
        }
        if !wa_versions.contains(&self.active_lookup_key_version) {
            return Err(PersistenceError::InvalidCommand(
                "active lookup key version is missing from supplied digests".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Identifiers created by one atomic WhatsApp account transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreatedWhatsAppAccount {
    /// New account identifier.
    pub account_id: AccountId,
    /// New WhatsApp channel identity identifier.
    pub channel_identity_id: ChannelIdentityId,
}

/// Existing channel identity located through a versioned blind index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FoundChannelIdentity {
    /// Owning account identifier.
    pub account_id: AccountId,
    /// Matching channel identity identifier.
    pub channel_identity_id: ChannelIdentityId,
    /// Current channel identity lifecycle.
    pub state: ChannelIdentityState,
}

/// Active account/channel result used by conversation processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedWhatsAppIdentity {
    /// Owning account.
    pub account_id: AccountId,
    /// Active WhatsApp channel identity.
    pub channel_identity_id: ChannelIdentityId,
    /// Whether locale was explicitly confirmed.
    pub locale_confirmed: bool,
}

/// Idempotent first-contact resolution outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveIdentityOutcome {
    /// A new pending customer account was created.
    Created(ResolvedWhatsAppIdentity),
    /// Existing active identity was reused and activity timestamps advanced.
    Existing(ResolvedWhatsAppIdentity),
}

#[derive(FromRow)]
struct FoundIdentityRow {
    account_id: Uuid,
    channel_identity_id: Uuid,
    state: String,
}

/// Concrete encrypted identity operations backed by PostgreSQL.
#[derive(Clone, Debug)]
pub struct IdentityRepository {
    database: Database,
}

impl IdentityRepository {
    /// Creates an identity repository over the shared process pool.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Creates an account, customer role, channel identity, private WhatsApp values,
    /// and both lookup digests in one transaction.
    pub async fn create_whatsapp_account(
        &self,
        input: &NewWhatsAppAccount,
    ) -> Result<CreatedWhatsAppAccount, PersistenceError> {
        input.validate()?;
        let mut transaction = self.database.pool().begin().await?;

        let active_wa_digest = input
            .wa_id_digests
            .iter()
            .find(|digest| digest.key_version == input.active_lookup_key_version)
            .ok_or_else(|| {
                PersistenceError::Invariant(
                    "validated WhatsApp input has no active lookup digest".to_owned(),
                )
            })?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1::bytea, 'hex'), 0))")
            .bind(active_wa_digest.digest.as_slice())
            .execute(&mut *transaction)
            .await?;

        ensure_active_encryption_key(
            &mut transaction,
            EncryptionPurpose::Contact,
            input.encrypted_wa_id.key_version,
        )
        .await?;
        ensure_active_lookup_key(&mut transaction, input.active_lookup_key_version).await?;

        sqlx::query(
            r#"
            INSERT INTO identity.accounts (
                id,
                subject_kind,
                status,
                risk_state,
                preferred_locale,
                time_zone
            )
            VALUES ($1, 'person', 'pending', 'normal', $2, $3)
            "#,
        )
        .bind(input.account_id.into_uuid())
        .bind(&input.preferred_locale)
        .bind(&input.time_zone)
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            "INSERT INTO identity.account_roles (account_id, role) VALUES ($1, 'customer')",
        )
        .bind(input.account_id.into_uuid())
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO identity.channel_identities (
                id,
                account_id,
                provider_code,
                provider_namespace,
                status
            )
            VALUES ($1, $2, 'whatsapp', $3, 'active')
            "#,
        )
        .bind(input.channel_identity_id.into_uuid())
        .bind(input.account_id.into_uuid())
        .bind(&input.provider_namespace)
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO private_data.whatsapp_identities (
                channel_identity_id,
                wa_id_ciphertext,
                wa_id_nonce,
                phone_e164_ciphertext,
                phone_e164_nonce,
                encryption_key_purpose,
                encryption_key_version
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(input.channel_identity_id.into_uuid())
        .bind(&input.encrypted_wa_id.ciphertext)
        .bind(input.encrypted_wa_id.nonce.as_slice())
        .bind(&input.encrypted_phone_e164.ciphertext)
        .bind(input.encrypted_phone_e164.nonce.as_slice())
        .bind(input.encrypted_wa_id.purpose.as_str())
        .bind(input.encrypted_wa_id.key_version)
        .execute(&mut *transaction)
        .await?;

        for (lookup_kind, digests) in [
            ("whatsapp_wa_id", &input.wa_id_digests),
            ("phone_e164", &input.phone_e164_digests),
        ] {
            for lookup in digests {
                sqlx::query(
                    r#"
                    INSERT INTO private_data.channel_lookup_digests (
                        channel_identity_id,
                        channel_code,
                        lookup_kind,
                        key_version,
                        digest
                    )
                    VALUES ($1, 'whatsapp', $2, $3, $4)
                    "#,
                )
                .bind(input.channel_identity_id.into_uuid())
                .bind(lookup_kind)
                .bind(lookup.key_version)
                .bind(lookup.digest.as_slice())
                .execute(&mut *transaction)
                .await?;
            }
        }

        sqlx::query(
            r#"
            INSERT INTO audit.events (
                id,
                actor_type,
                source_channel,
                action,
                target_type,
                target_id,
                reason_code,
                metadata,
                event_schema_version,
                correlation_id
            )
            VALUES (
                $1,
                'system',
                'system',
                'account.created',
                'account',
                $2,
                'whatsapp_onboarding',
                jsonb_build_object('channel', 'whatsapp'),
                1,
                $3
            )
            "#,
        )
        .bind(AuditEventId::new().into_uuid())
        .bind(input.account_id.into_uuid())
        .bind(input.correlation_id.into_uuid())
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(CreatedWhatsAppAccount {
            account_id: input.account_id,
            channel_identity_id: input.channel_identity_id,
        })
    }

    /// Resolves or creates one WhatsApp identity under concurrent first contact.
    pub async fn resolve_or_create_whatsapp_account(
        &self,
        input: &NewWhatsAppAccount,
        provider_observed_at: OffsetDateTime,
    ) -> Result<ResolveIdentityOutcome, PersistenceError> {
        input.validate()?;
        if let Some(existing) = self.resolve_matching_digests(input).await? {
            return self
                .refresh_existing_identity(
                    existing,
                    &input.provider_namespace,
                    provider_observed_at,
                )
                .await
                .map(ResolveIdentityOutcome::Existing);
        }
        match self.create_whatsapp_account(input).await {
            Ok(created) => self
                .refresh_existing_identity(
                    FoundChannelIdentity {
                        account_id: created.account_id,
                        channel_identity_id: created.channel_identity_id,
                        state: ChannelIdentityState::Active,
                    },
                    &input.provider_namespace,
                    provider_observed_at,
                )
                .await
                .map(ResolveIdentityOutcome::Created),
            Err(error)
                if matches!(
                    error.constraint_name(),
                    Some("channel_lookup_digests_unique_digest")
                ) =>
            {
                let existing = self.resolve_matching_digests(input).await?.ok_or_else(|| {
                    PersistenceError::Invariant(
                        "concurrent identity winner was not visible after unique conflict"
                            .to_owned(),
                    )
                })?;
                self.refresh_existing_identity(
                    existing,
                    &input.provider_namespace,
                    provider_observed_at,
                )
                .await
                .map(ResolveIdentityOutcome::Existing)
            }
            Err(error) => Err(error),
        }
    }

    /// Finds an account by a versioned WhatsApp identifier blind index.
    pub async fn find_whatsapp_by_wa_id_digest(
        &self,
        key_version: i16,
        digest: &[u8; 32],
    ) -> Result<Option<FoundChannelIdentity>, PersistenceError> {
        self.find_whatsapp_digest("whatsapp_wa_id", key_version, digest)
            .await
    }

    /// Finds an account by a versioned canonical-phone blind index.
    pub async fn find_whatsapp_by_phone_digest(
        &self,
        key_version: i16,
        digest: &[u8; 32],
    ) -> Result<Option<FoundChannelIdentity>, PersistenceError> {
        self.find_whatsapp_digest("phone_e164", key_version, digest)
            .await
    }

    async fn find_whatsapp_digest(
        &self,
        lookup_kind: &str,
        key_version: i16,
        digest: &[u8; 32],
    ) -> Result<Option<FoundChannelIdentity>, PersistenceError> {
        let row = sqlx::query_as::<_, FoundIdentityRow>(
            r#"
            SELECT
                identity.account_id,
                identity.id AS channel_identity_id,
                identity.status AS state
            FROM private_data.channel_lookup_digests AS lookup
            JOIN identity.channel_identities AS identity
              ON identity.id = lookup.channel_identity_id
            WHERE lookup.channel_code = 'whatsapp'
              AND lookup.lookup_kind = $1
              AND lookup.key_version = $2
              AND lookup.digest = $3
            "#,
        )
        .bind(lookup_kind)
        .bind(key_version)
        .bind(digest.as_slice())
        .fetch_optional(self.database.pool())
        .await?;

        row.map(|row| {
            Ok(FoundChannelIdentity {
                account_id: AccountId::from_uuid(row.account_id),
                channel_identity_id: ChannelIdentityId::from_uuid(row.channel_identity_id),
                state: row.state.parse().map_err(|error| {
                    PersistenceError::Invariant(format!(
                        "channel identity contains unsupported state: {error}"
                    ))
                })?,
            })
        })
        .transpose()
    }

    async fn resolve_matching_digests(
        &self,
        input: &NewWhatsAppAccount,
    ) -> Result<Option<FoundChannelIdentity>, PersistenceError> {
        let mut matches = Vec::new();
        for lookup in &input.wa_id_digests {
            if let Some(found) = self
                .find_whatsapp_by_wa_id_digest(lookup.key_version, &lookup.digest)
                .await?
            {
                matches.push(found);
            }
        }
        for lookup in &input.phone_e164_digests {
            if let Some(found) = self
                .find_whatsapp_by_phone_digest(lookup.key_version, &lookup.digest)
                .await?
            {
                matches.push(found);
            }
        }
        let Some(first) = matches.first().copied() else {
            return Ok(None);
        };
        if matches.iter().any(|found| {
            found.account_id != first.account_id
                || found.channel_identity_id != first.channel_identity_id
        }) {
            return Err(PersistenceError::Invariant(
                "WhatsApp ID and phone digests resolve to different identities".to_owned(),
            ));
        }
        Ok(Some(first))
    }

    async fn refresh_existing_identity(
        &self,
        identity: FoundChannelIdentity,
        provider_namespace: &str,
        provider_observed_at: OffsetDateTime,
    ) -> Result<ResolvedWhatsAppIdentity, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let account: Option<(String, String, Option<OffsetDateTime>)> = sqlx::query_as(
            r#"
            SELECT status, risk_state, preferred_locale_confirmed_at
            FROM identity.accounts
            WHERE id = $1
            FOR SHARE
            "#,
        )
        .bind(identity.account_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((status, risk_state, locale_confirmed_at)) = account else {
            return Err(PersistenceError::Invariant(
                "resolved WhatsApp account is missing".to_owned(),
            ));
        };
        let channel_status: Option<String> = sqlx::query_scalar(
            r#"
            SELECT status
            FROM identity.channel_identities
            WHERE id = $1
              AND account_id = $2
              AND provider_code = 'whatsapp'
              AND provider_namespace = $3
            FOR SHARE
            "#,
        )
        .bind(identity.channel_identity_id.into_uuid())
        .bind(identity.account_id.into_uuid())
        .bind(provider_namespace)
        .fetch_optional(&mut *transaction)
        .await?;
        if matches!(
            status.as_str(),
            "suspended" | "deletion_pending" | "deleted"
        ) || matches!(risk_state.as_str(), "restricted" | "blocked")
            || channel_status.as_deref() != Some("active")
        {
            return Err(PersistenceError::InvalidCommand(
                "resolved WhatsApp identity is not allowed to interact".to_owned(),
            ));
        }
        let channel_update = sqlx::query(
            r#"
            UPDATE identity.channel_identities
            SET last_seen_at = GREATEST(last_seen_at, LEAST($2, statement_timestamp()))
            WHERE id = $1
              AND status = 'active'
            "#,
        )
        .bind(identity.channel_identity_id.into_uuid())
        .bind(provider_observed_at)
        .execute(&mut *transaction)
        .await?;
        if channel_update.rows_affected() != 1 {
            transaction.rollback().await?;
            return Err(PersistenceError::OptimisticConflict);
        }
        let whatsapp_update = sqlx::query(
            r#"
            UPDATE private_data.whatsapp_identities
            SET
                last_inbound_at = GREATEST(
                    last_inbound_at,
                    LEAST($2, statement_timestamp())
                ),
                service_window_expires_at = GREATEST(
                    service_window_expires_at,
                    LEAST($2, statement_timestamp()) + INTERVAL '24 hours'
                )
            WHERE channel_identity_id = $1
            "#,
        )
        .bind(identity.channel_identity_id.into_uuid())
        .bind(provider_observed_at)
        .execute(&mut *transaction)
        .await?;
        if whatsapp_update.rows_affected() != 1 {
            transaction.rollback().await?;
            return Err(PersistenceError::OptimisticConflict);
        }
        transaction.commit().await?;
        Ok(ResolvedWhatsAppIdentity {
            account_id: identity.account_id,
            channel_identity_id: identity.channel_identity_id,
            locale_confirmed: locale_confirmed_at.is_some(),
        })
    }
}

fn validate_lookup_digests(name: &str, digests: &[LookupDigest]) -> Result<(), PersistenceError> {
    if digests.is_empty() {
        return Err(PersistenceError::InvalidCommand(format!(
            "{name} lookup requires at least one digest"
        )));
    }
    let mut versions = BTreeSet::new();
    if digests
        .iter()
        .any(|item| item.key_version <= 0 || !versions.insert(item.key_version))
    {
        return Err(PersistenceError::InvalidCommand(format!(
            "{name} lookup key versions must be positive and unique"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{LookupDigest, NewWhatsAppAccount};
    use sahayak_cryptography::{EncryptedValue, EncryptionPurpose};
    use sahayak_domain::{AccountId, ChannelIdentityId, CorrelationId};

    fn encrypted(version: i16) -> EncryptedValue {
        EncryptedValue {
            purpose: EncryptionPurpose::Contact,
            key_version: version,
            nonce: [1; 12],
            ciphertext: vec![2; 32],
        }
    }

    #[test]
    fn rejects_mixed_encryption_key_versions() {
        let input = NewWhatsAppAccount {
            account_id: AccountId::new(),
            channel_identity_id: ChannelIdentityId::new(),
            correlation_id: CorrelationId::new(),
            provider_namespace: "test-business".to_owned(),
            preferred_locale: "en-IN".to_owned(),
            time_zone: "Asia/Kolkata".to_owned(),
            encrypted_wa_id: encrypted(1),
            encrypted_phone_e164: encrypted(2),
            wa_id_digests: vec![LookupDigest {
                key_version: 1,
                digest: [3; 32],
            }],
            phone_e164_digests: vec![LookupDigest {
                key_version: 1,
                digest: [4; 32],
            }],
            active_lookup_key_version: 1,
        };

        assert!(input.validate().is_err());
    }
}
