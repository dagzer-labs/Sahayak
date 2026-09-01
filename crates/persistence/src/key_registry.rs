use crate::{Database, PersistenceError};
use sahayak_cryptography::EncryptionPurpose;
use sqlx::PgConnection;

/// Validates external key configuration against non-secret database metadata.
#[derive(Clone, Debug)]
pub struct KeyRegistryRepository {
    database: Database,
}

pub(crate) async fn ensure_active_encryption_key(
    connection: &mut PgConnection,
    purpose: EncryptionPurpose,
    version: i16,
) -> Result<(), PersistenceError> {
    let active: Option<i16> = sqlx::query_scalar(
        r#"
        SELECT version
        FROM private_data.key_versions
        WHERE purpose = $1
          AND version = $2
          AND algorithm = 'aes-256-gcm'
          AND state = 'active'
        FOR SHARE
        "#,
    )
    .bind(purpose.as_str())
    .bind(version)
    .fetch_optional(connection)
    .await?;
    if active.is_none() {
        return Err(PersistenceError::Invariant(format!(
            "new encrypted data must use the active {purpose} key version"
        )));
    }
    Ok(())
}

pub(crate) async fn ensure_active_lookup_key(
    connection: &mut PgConnection,
    version: i16,
) -> Result<(), PersistenceError> {
    let active: Option<i16> = sqlx::query_scalar(
        r#"
        SELECT version
        FROM private_data.key_versions
        WHERE purpose = 'lookup_hmac'
          AND version = $1
          AND algorithm = 'hmac-sha-256'
          AND state = 'active'
        FOR SHARE
        "#,
    )
    .bind(version)
    .fetch_optional(connection)
    .await?;
    if active.is_none() {
        return Err(PersistenceError::Invariant(
            "new blind indexes must include the active lookup key version".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) async fn ensure_lookup_key_readable(
    connection: &mut PgConnection,
    version: i16,
) -> Result<(), PersistenceError> {
    let readable: Option<i16> = sqlx::query_scalar(
        r#"
        SELECT version
        FROM private_data.key_versions
        WHERE purpose = 'lookup_hmac'
          AND version = $1
          AND algorithm = 'hmac-sha-256'
          AND state IN ('active', 'decrypt_only')
        FOR SHARE
        "#,
    )
    .bind(version)
    .fetch_optional(connection)
    .await?;
    if readable.is_none() {
        return Err(PersistenceError::Invariant(
            "event fingerprint key version is not readable".to_owned(),
        ));
    }
    Ok(())
}

impl KeyRegistryRepository {
    /// Creates a key registry repository over the shared process pool.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Verifies that configured active key versions match the database registry.
    pub async fn verify_active_versions(
        &self,
        contact_key_version: i16,
        identity_key_version: i16,
        integration_key_version: i16,
        lookup_key_version: i16,
    ) -> Result<(), PersistenceError> {
        if contact_key_version <= 0
            || identity_key_version <= 0
            || integration_key_version <= 0
            || lookup_key_version <= 0
        {
            return Err(PersistenceError::InvalidCommand(
                "configured cryptographic key versions must be positive".to_owned(),
            ));
        }
        let matches: bool = sqlx::query_scalar(
            r#"
            SELECT
                EXISTS (
                    SELECT 1
                    FROM private_data.key_versions
                    WHERE purpose = 'contact_encryption'
                      AND version = $1
                      AND algorithm = 'aes-256-gcm'
                      AND state = 'active'
                )
                AND EXISTS (
                    SELECT 1
                    FROM private_data.key_versions
                    WHERE purpose = 'identity_encryption'
                      AND version = $2
                      AND algorithm = 'aes-256-gcm'
                      AND state = 'active'
                )
                AND EXISTS (
                    SELECT 1
                    FROM private_data.key_versions
                    WHERE purpose = 'integration_encryption'
                      AND version = $3
                      AND algorithm = 'aes-256-gcm'
                      AND state = 'active'
                )
                AND EXISTS (
                    SELECT 1
                    FROM private_data.key_versions
                    WHERE purpose = 'lookup_hmac'
                      AND version = $4
                      AND algorithm = 'hmac-sha-256'
                      AND state = 'active'
                )
            "#,
        )
        .bind(contact_key_version)
        .bind(identity_key_version)
        .bind(integration_key_version)
        .bind(lookup_key_version)
        .fetch_one(self.database.pool())
        .await?;

        if !matches {
            return Err(PersistenceError::Invariant(
                "configured active cryptographic keys do not match database metadata".to_owned(),
            ));
        }
        Ok(())
    }

    /// Verifies the additional key purpose required by professional profile media.
    pub async fn verify_media_version(
        &self,
        media_key_version: i16,
    ) -> Result<(), PersistenceError> {
        if media_key_version <= 0 {
            return Err(PersistenceError::InvalidCommand(
                "configured media key version must be positive".to_owned(),
            ));
        }
        let active: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM private_data.key_versions
                WHERE purpose = 'media_encryption'
                  AND version = $1
                  AND algorithm = 'aes-256-gcm'
                  AND state = 'active'
            )
            "#,
        )
        .bind(media_key_version)
        .fetch_one(self.database.pool())
        .await?;
        if !active {
            return Err(PersistenceError::Invariant(
                "configured active media encryption key does not match database metadata"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Verifies only the key purposes mounted into one least-privilege process.
    pub async fn verify_required_versions(
        &self,
        encryption_keys: &[(EncryptionPurpose, i16)],
        lookup_key_version: Option<i16>,
    ) -> Result<(), PersistenceError> {
        for (purpose, version) in encryption_keys {
            if *version <= 0 {
                return Err(PersistenceError::InvalidCommand(
                    "required encryption key version must be positive".to_owned(),
                ));
            }
            let active: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM private_data.key_versions
                    WHERE purpose = $1
                      AND version = $2
                      AND algorithm = 'aes-256-gcm'
                      AND state = 'active'
                )
                "#,
            )
            .bind(purpose.as_str())
            .bind(*version)
            .fetch_one(self.database.pool())
            .await?;
            if !active {
                return Err(PersistenceError::Invariant(format!(
                    "configured active {purpose} key does not match database metadata"
                )));
            }
        }
        if let Some(version) = lookup_key_version {
            if version <= 0 {
                return Err(PersistenceError::InvalidCommand(
                    "required lookup key version must be positive".to_owned(),
                ));
            }
            let active: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM private_data.key_versions
                    WHERE purpose = 'lookup_hmac'
                      AND version = $1
                      AND algorithm = 'hmac-sha-256'
                      AND state = 'active'
                )
                "#,
            )
            .bind(version)
            .fetch_one(self.database.pool())
            .await?;
            if !active {
                return Err(PersistenceError::Invariant(
                    "configured active lookup key does not match database metadata".to_owned(),
                ));
            }
        }
        Ok(())
    }
}
