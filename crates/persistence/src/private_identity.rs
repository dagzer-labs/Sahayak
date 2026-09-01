use crate::{Database, PersistenceError, key_registry::ensure_active_encryption_key};
use sahayak_cryptography::{EncryptedValue, EncryptionPurpose};
use sahayak_domain::AccountId;
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

/// Input for first collection or optimistic replacement of encrypted identity data.
#[derive(Clone)]
pub struct SavePrivateIdentity {
    /// Account owning the private data.
    pub account_id: AccountId,
    /// Version of the plaintext structure encrypted into the payload.
    pub payload_schema_version: i16,
    /// Record-bound authenticated encrypted payload.
    pub payload: EncryptedValue,
    /// Legal consent text version accepted by the account.
    pub consent_version: String,
    /// Time at which consent was recorded.
    pub consented_at: OffsetDateTime,
    /// Existing optimistic revision, or `None` for first collection.
    pub expected_version: Option<i64>,
}

impl SavePrivateIdentity {
    fn validate(&self) -> Result<(), PersistenceError> {
        if self.payload_schema_version <= 0 || self.payload.key_version <= 0 {
            return Err(PersistenceError::InvalidCommand(
                "private identity payload and key versions must be positive".to_owned(),
            ));
        }
        if self.payload.purpose != EncryptionPurpose::Identity {
            return Err(PersistenceError::InvalidCommand(
                "private legal identity requires the identity encryption key purpose".to_owned(),
            ));
        }
        if self.payload.ciphertext.len() < 16 {
            return Err(PersistenceError::InvalidCommand(
                "private identity ciphertext is too short".to_owned(),
            ));
        }
        if self.consent_version.is_empty() || self.consent_version.len() > 32 {
            return Err(PersistenceError::InvalidCommand(
                "consent version must contain between 1 and 32 bytes".to_owned(),
            ));
        }
        if self.expected_version.is_some_and(|version| version <= 0) {
            return Err(PersistenceError::InvalidCommand(
                "expected private identity version must be positive".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Encrypted identity record returned only to trusted verification workflows.
#[derive(Clone)]
pub struct EncryptedPrivateIdentity {
    /// Owning account.
    pub account_id: AccountId,
    /// Plaintext structure version.
    pub payload_schema_version: i16,
    /// Authenticated encrypted identity payload.
    pub payload: EncryptedValue,
    /// Optimistic concurrency revision.
    pub version: i64,
    /// Consent text version.
    pub consent_version: String,
    /// Time consent was captured.
    pub consented_at: OffsetDateTime,
}

impl std::fmt::Debug for EncryptedPrivateIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedPrivateIdentity")
            .field("account_id", &self.account_id)
            .field("payload_schema_version", &self.payload_schema_version)
            .field("payload", &"[REDACTED]")
            .field("version", &self.version)
            .field("consent_version", &self.consent_version)
            .field("consented_at", &self.consented_at)
            .finish()
    }
}

/// Result of first-write or optimistic private-identity persistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateIdentityMutation {
    /// The encrypted value was saved at this revision.
    Applied { version: i64 },
    /// The row already existed or changed concurrently.
    Conflict,
}

#[derive(FromRow)]
struct IdentityRow {
    account_id: Uuid,
    payload_schema_version: i16,
    encrypted_payload: Vec<u8>,
    payload_nonce: Vec<u8>,
    encryption_key_version: i16,
    version: i64,
    consent_version: String,
    consented_at: OffsetDateTime,
}

/// Restricted PostgreSQL operations for encrypted legal identity data.
#[derive(Clone, Debug)]
pub struct PrivateIdentityRepository {
    database: Database,
}

impl PrivateIdentityRepository {
    /// Creates a private identity repository over the shared process pool.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Saves encrypted identity data with insert-or-compare-and-set semantics.
    pub async fn save(
        &self,
        input: &SavePrivateIdentity,
    ) -> Result<PrivateIdentityMutation, PersistenceError> {
        input.validate()?;
        let mut transaction = self.database.pool().begin().await?;
        ensure_active_encryption_key(
            &mut transaction,
            EncryptionPurpose::Identity,
            input.payload.key_version,
        )
        .await?;
        let account_status: Option<String> =
            sqlx::query_scalar("SELECT status FROM identity.accounts WHERE id = $1 FOR SHARE")
                .bind(input.account_id.into_uuid())
                .fetch_optional(&mut *transaction)
                .await?;
        match account_status.as_deref() {
            Some("deletion_pending" | "deleted") => {
                transaction.rollback().await?;
                return Err(PersistenceError::InvalidCommand(
                    "private identity data cannot be written during or after deletion".to_owned(),
                ));
            }
            Some(_) => {}
            None => {
                transaction.rollback().await?;
                return Err(PersistenceError::InvalidCommand(
                    "private identity account does not exist".to_owned(),
                ));
            }
        }
        let version = match input.expected_version {
            None => {
                sqlx::query_scalar::<_, i64>(
                    r#"
                    INSERT INTO private_data.account_identities (
                        account_id,
                        payload_schema_version,
                        encrypted_payload,
                        payload_nonce,
                        encryption_key_purpose,
                        encryption_key_version,
                        consent_version,
                        consented_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (account_id) DO NOTHING
                    RETURNING version
                    "#,
                )
                .bind(input.account_id.into_uuid())
                .bind(input.payload_schema_version)
                .bind(&input.payload.ciphertext)
                .bind(input.payload.nonce.as_slice())
                .bind(input.payload.purpose.as_str())
                .bind(input.payload.key_version)
                .bind(&input.consent_version)
                .bind(input.consented_at)
                .fetch_optional(&mut *transaction)
                .await?
            }
            Some(expected_version) => {
                sqlx::query_scalar::<_, i64>(
                    r#"
                    UPDATE private_data.account_identities
                    SET
                        payload_schema_version = $3,
                        encrypted_payload = $4,
                        payload_nonce = $5,
                        encryption_key_purpose = $6,
                        encryption_key_version = $7,
                        consent_version = $8,
                        consented_at = $9,
                        verification_state = 'not_requested',
                        verified_at = NULL,
                        expires_at = NULL,
                        reviewed_by = NULL,
                        reviewed_at = NULL
                    WHERE account_id = $1
                      AND version = $2
                    RETURNING version
                    "#,
                )
                .bind(input.account_id.into_uuid())
                .bind(expected_version)
                .bind(input.payload_schema_version)
                .bind(&input.payload.ciphertext)
                .bind(input.payload.nonce.as_slice())
                .bind(input.payload.purpose.as_str())
                .bind(input.payload.key_version)
                .bind(&input.consent_version)
                .bind(input.consented_at)
                .fetch_optional(&mut *transaction)
                .await?
            }
        };

        transaction.commit().await?;

        Ok(
            version.map_or(PrivateIdentityMutation::Conflict, |version| {
                PrivateIdentityMutation::Applied { version }
            }),
        )
    }

    /// Loads encrypted data for a trusted verification or key-rotation operation.
    pub async fn find(
        &self,
        account_id: AccountId,
    ) -> Result<Option<EncryptedPrivateIdentity>, PersistenceError> {
        let row = sqlx::query_as::<_, IdentityRow>(
            r#"
            SELECT
                account_id,
                payload_schema_version,
                encrypted_payload,
                payload_nonce,
                encryption_key_version,
                version,
                consent_version,
                consented_at
            FROM private_data.account_identities
            WHERE account_id = $1
            "#,
        )
        .bind(account_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        row.map(map_identity).transpose()
    }

    /// Explicitly erases private identity ciphertext for account deletion workflows.
    pub async fn erase(&self, account_id: AccountId) -> Result<bool, PersistenceError> {
        let result =
            sqlx::query("DELETE FROM private_data.account_identities WHERE account_id = $1")
                .bind(account_id.into_uuid())
                .execute(self.database.pool())
                .await?;
        Ok(result.rows_affected() == 1)
    }
}

fn map_identity(row: IdentityRow) -> Result<EncryptedPrivateIdentity, PersistenceError> {
    let nonce: [u8; 12] = row.payload_nonce.try_into().map_err(|_| {
        PersistenceError::Invariant("private identity nonce has invalid length".to_owned())
    })?;
    Ok(EncryptedPrivateIdentity {
        account_id: AccountId::from_uuid(row.account_id),
        payload_schema_version: row.payload_schema_version,
        payload: EncryptedValue {
            purpose: EncryptionPurpose::Identity,
            key_version: row.encryption_key_version,
            nonce,
            ciphertext: row.encrypted_payload,
        },
        version: row.version,
        consent_version: row.consent_version,
        consented_at: row.consented_at,
    })
}

#[cfg(test)]
mod tests {
    use super::SavePrivateIdentity;
    use sahayak_cryptography::{EncryptedValue, EncryptionPurpose};
    use sahayak_domain::AccountId;
    use time::OffsetDateTime;

    #[test]
    fn rejects_missing_consent_version() {
        let input = SavePrivateIdentity {
            account_id: AccountId::new(),
            payload_schema_version: 1,
            payload: EncryptedValue {
                purpose: EncryptionPurpose::Identity,
                key_version: 1,
                nonce: [1; 12],
                ciphertext: vec![2; 32],
            },
            consent_version: String::new(),
            consented_at: OffsetDateTime::now_utc(),
            expected_version: None,
        };
        assert!(input.validate().is_err());
    }
}
