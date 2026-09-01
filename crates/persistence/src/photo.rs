use crate::{Database, PersistenceError, key_registry::ensure_active_encryption_key};
use sahayak_cryptography::{EncryptedValue, EncryptionPurpose};
use sahayak_domain::{
    AccountId, ChannelIdentityId, InboundEventId, ProfilePhotoId, ProfileRevisionId,
    PublicProfileId,
};
use sqlx::FromRow;
use time::OffsetDateTime;

const MAX_ENCRYPTED_JPEG_BYTES: usize = 2_097_168;

/// Already-sanitized encrypted JPEG supplied by a trusted media worker.
#[derive(Clone)]
pub struct AttachSanitizedProfilePhoto {
    pub id: ProfilePhotoId,
    pub account_id: AccountId,
    pub profile_id: PublicProfileId,
    pub revision_id: ProfileRevisionId,
    pub expected_revision_version: i64,
    pub encrypted_jpeg: EncryptedValue,
    pub width_pixels: i32,
    pub height_pixels: i32,
    pub plaintext_sha256: [u8; 32],
    pub sanitizer_version: String,
    pub sanitized_at: OffsetDateTime,
    pub source_inbound_event_id: InboundEventId,
}

impl std::fmt::Debug for AttachSanitizedProfilePhoto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttachSanitizedProfilePhoto")
            .field("id", &self.id)
            .field("account_id", &self.account_id)
            .field("profile_id", &self.profile_id)
            .field("revision_id", &self.revision_id)
            .field("expected_revision_version", &self.expected_revision_version)
            .field("encrypted_jpeg", &"[REDACTED]")
            .field("width_pixels", &self.width_pixels)
            .field("height_pixels", &self.height_pixels)
            .field("plaintext_sha256", &"[REDACTED]")
            .field("sanitizer_version", &self.sanitizer_version)
            .field("sanitized_at", &self.sanitized_at)
            .field("source_inbound_event_id", &self.source_inbound_event_id)
            .finish()
    }
}

/// Result of a photo and draft-version transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfilePhotoMutation {
    Applied { revision_version: i64 },
    ConflictOrMissing,
}

/// Encrypted photo available only to an authorized administrator reviewing its revision.
#[derive(Clone)]
pub struct AdministratorReviewPhoto {
    pub photo_id: ProfilePhotoId,
    pub encrypted_jpeg: EncryptedValue,
}

impl std::fmt::Debug for AdministratorReviewPhoto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdministratorReviewPhoto")
            .field("photo_id", &self.photo_id)
            .field("encrypted_jpeg", &"[REDACTED]")
            .finish()
    }
}

#[derive(FromRow)]
struct ReviewPhotoRow {
    photo_id: uuid::Uuid,
    sanitized_ciphertext: Vec<u8>,
    sanitized_nonce: Vec<u8>,
    encryption_key_version: i16,
}

/// Restricted profile-media operations. No method returns photo bytes to public discovery.
#[derive(Clone, Debug)]
pub struct ProfilePhotoRepository {
    database: Database,
}

impl ProfilePhotoRepository {
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Attaches an encrypted, already-sanitized JPEG and replaces only the
    /// draft's association. A photo still used by an approved revision is retained.
    pub async fn attach_sanitized(
        &self,
        input: &AttachSanitizedProfilePhoto,
    ) -> Result<ProfilePhotoMutation, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let outcome = attach_sanitized_in_transaction(&mut transaction, input, None).await?;
        if outcome == ProfilePhotoMutation::ConflictOrMissing {
            transaction.rollback().await?;
            return Ok(outcome);
        };
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Removes the draft association. Bytes are erased only when no other
    /// revision, including the currently approved revision, uses the asset.
    pub async fn remove(
        &self,
        account_id: AccountId,
        revision_id: ProfileRevisionId,
        expected_revision_version: i64,
    ) -> Result<ProfilePhotoMutation, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let outcome = remove_in_transaction(
            &mut transaction,
            account_id,
            revision_id,
            expected_revision_version,
        )
        .await?;
        if outcome == ProfilePhotoMutation::ConflictOrMissing {
            transaction.rollback().await?;
            return Ok(outcome);
        }
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Loads a pending revision's sanitized photo only for an active allowlisted reviewer.
    pub async fn load_for_administrator_review(
        &self,
        revision_id: ProfileRevisionId,
        reviewer_account_id: AccountId,
        reviewer_channel_identity_id: ChannelIdentityId,
        provider_namespace: &str,
    ) -> Result<Option<AdministratorReviewPhoto>, PersistenceError> {
        let row = sqlx::query_as::<_, ReviewPhotoRow>(
            r#"
            SELECT photo.id AS photo_id, photo.sanitized_ciphertext,
                   photo.sanitized_nonce, photo.encryption_key_version
            FROM profile.profile_revisions AS revision
            JOIN profile.profile_revision_photos AS link ON link.revision_id = revision.id
            JOIN private_data.profile_photos AS photo
              ON photo.id = link.photo_id AND photo.state = 'ready'
            WHERE revision.id = $1 AND revision.state = 'pending_review'
              AND EXISTS (
                  SELECT 1
                  FROM identity.accounts AS reviewer
                  JOIN identity.account_roles AS role
                    ON role.account_id = reviewer.id AND role.role = 'administrator'
                   AND role.revoked_at IS NULL
                  JOIN identity.channel_identities AS channel
                    ON channel.id = $3 AND channel.account_id = reviewer.id
                   AND channel.provider_code = 'whatsapp'
                   AND channel.provider_namespace = $4
                   AND channel.status = 'active' AND channel.verified_at IS NOT NULL
                  JOIN identity.administrator_allowlist AS allowlist
                    ON allowlist.account_id = reviewer.id
                   AND allowlist.channel_identity_id = channel.id
                   AND allowlist.channel_code = channel.provider_code
                   AND allowlist.provider_namespace = channel.provider_namespace
                   AND allowlist.revoked_at IS NULL
                   AND allowlist.expires_at > statement_timestamp()
                  WHERE reviewer.id = $2 AND reviewer.status = 'active'
                    AND reviewer.risk_state NOT IN ('restricted', 'blocked')
              )
            "#,
        )
        .bind(revision_id.into_uuid())
        .bind(reviewer_account_id.into_uuid())
        .bind(reviewer_channel_identity_id.into_uuid())
        .bind(provider_namespace)
        .fetch_optional(self.database.pool())
        .await?;
        row.map(|row| {
            let nonce = row.sanitized_nonce.try_into().map_err(|_| {
                PersistenceError::Invariant("profile photo nonce has invalid length".to_owned())
            })?;
            Ok(AdministratorReviewPhoto {
                photo_id: ProfilePhotoId::from_uuid(row.photo_id),
                encrypted_jpeg: EncryptedValue {
                    purpose: EncryptionPurpose::Media,
                    key_version: row.encryption_key_version,
                    nonce,
                    ciphertext: row.sanitized_ciphertext,
                },
            })
        })
        .transpose()
    }
}

pub(crate) async fn attach_sanitized_in_transaction(
    connection: &mut sqlx::PgConnection,
    input: &AttachSanitizedProfilePhoto,
    required_channel: Option<sahayak_domain::ChannelIdentityId>,
) -> Result<ProfilePhotoMutation, PersistenceError> {
    validate_photo(input)?;
    ensure_active_encryption_key(
        &mut *connection,
        EncryptionPurpose::Media,
        input.encrypted_jpeg.key_version,
    )
    .await?;
    let owner: Option<AccountId> = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"
        SELECT root.account_id
        FROM profile.profile_revisions AS revision
        JOIN profile.public_profiles AS root ON root.id = revision.profile_id
        WHERE revision.id = $1 AND revision.profile_id = $2
          AND revision.state = 'draft' AND revision.version = $3
        FOR UPDATE OF revision, root
        "#,
    )
    .bind(input.revision_id.into_uuid())
    .bind(input.profile_id.into_uuid())
    .bind(input.expected_revision_version)
    .fetch_optional(&mut *connection)
    .await?
    .map(AccountId::from_uuid);
    if owner != Some(input.account_id) {
        return Ok(ProfilePhotoMutation::ConflictOrMissing);
    }
    let source_matches: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM integration.inbound_events AS inbound
            JOIN identity.channel_identities AS channel
              ON channel.id = inbound.channel_identity_id
             AND channel.account_id = inbound.account_id
             AND channel.account_id = $2
             AND channel.provider_code = inbound.provider_code
             AND channel.provider_namespace = inbound.provider_namespace
             AND channel.status = 'active'
            WHERE inbound.id = $1
              AND inbound.account_id = $2
              AND ($3::uuid IS NULL OR inbound.channel_identity_id = $3)
        )
        "#,
    )
    .bind(input.source_inbound_event_id.into_uuid())
    .bind(input.account_id.into_uuid())
    .bind(required_channel.map(sahayak_domain::ChannelIdentityId::into_uuid))
    .fetch_one(&mut *connection)
    .await?;
    if !source_matches {
        return Err(PersistenceError::InvalidCommand(
            "profile photo source event does not belong to the active account channel".to_owned(),
        ));
    }
    let previous_photo_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "DELETE FROM profile.profile_revision_photos WHERE revision_id = $1 RETURNING photo_id",
    )
    .bind(input.revision_id.into_uuid())
    .fetch_optional(&mut *connection)
    .await?;
    if let Some(previous_photo_id) = previous_photo_id {
        erase_unlinked_photo(connection, previous_photo_id, "replaced").await?;
    }
    sqlx::query(
        r#"
        INSERT INTO private_data.profile_photos (
            id, account_id, profile_id, state,
            sanitized_ciphertext, sanitized_nonce, encryption_key_purpose,
            encryption_key_version, trusted_mime, width_pixels, height_pixels,
            plaintext_sha256, sanitizer_version, sanitized_at, source_inbound_event_id
        )
        VALUES ($1, $2, $3, 'ready', $4, $5, $6, $7, 'image/jpeg',
                $8, $9, $10, $11, $12, $13)
        "#,
    )
    .bind(input.id.into_uuid())
    .bind(input.account_id.into_uuid())
    .bind(input.profile_id.into_uuid())
    .bind(&input.encrypted_jpeg.ciphertext)
    .bind(input.encrypted_jpeg.nonce.as_slice())
    .bind(input.encrypted_jpeg.purpose.as_str())
    .bind(input.encrypted_jpeg.key_version)
    .bind(input.width_pixels)
    .bind(input.height_pixels)
    .bind(input.plaintext_sha256.as_slice())
    .bind(&input.sanitizer_version)
    .bind(input.sanitized_at)
    .bind(input.source_inbound_event_id.into_uuid())
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO profile.profile_revision_photos (revision_id, profile_id, photo_id) VALUES ($1, $2, $3)",
    )
    .bind(input.revision_id.into_uuid())
    .bind(input.profile_id.into_uuid())
    .bind(input.id.into_uuid())
    .execute(&mut *connection)
    .await?;
    let version = touch_revision(
        connection,
        input.revision_id,
        input.expected_revision_version,
    )
    .await?;
    Ok(version.map_or(
        ProfilePhotoMutation::ConflictOrMissing,
        |revision_version| ProfilePhotoMutation::Applied { revision_version },
    ))
}

pub(crate) async fn remove_in_transaction(
    connection: &mut sqlx::PgConnection,
    account_id: AccountId,
    revision_id: ProfileRevisionId,
    expected_revision_version: i64,
) -> Result<ProfilePhotoMutation, PersistenceError> {
    let locked: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM profile.profile_revisions AS revision
            JOIN profile.public_profiles AS root ON root.id = revision.profile_id
            WHERE revision.id = $1 AND revision.state = 'draft'
              AND revision.version = $2 AND root.account_id = $3
            FOR UPDATE OF revision
        )
        "#,
    )
    .bind(revision_id.into_uuid())
    .bind(expected_revision_version)
    .bind(account_id.into_uuid())
    .fetch_one(&mut *connection)
    .await?;
    if !locked {
        return Ok(ProfilePhotoMutation::ConflictOrMissing);
    }
    let photo_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "DELETE FROM profile.profile_revision_photos WHERE revision_id = $1 RETURNING photo_id",
    )
    .bind(revision_id.into_uuid())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(photo_id) = photo_id else {
        return Ok(ProfilePhotoMutation::ConflictOrMissing);
    };
    erase_unlinked_photo(connection, photo_id, "deleted").await?;
    let version = touch_revision(connection, revision_id, expected_revision_version)
        .await?
        .ok_or_else(|| {
            PersistenceError::Invariant("locked photo draft changed unexpectedly".to_owned())
        })?;
    Ok(ProfilePhotoMutation::Applied {
        revision_version: version,
    })
}

async fn erase_unlinked_photo(
    connection: &mut sqlx::PgConnection,
    photo_id: uuid::Uuid,
    next_state: &str,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        UPDATE private_data.profile_photos AS photo
        SET state = $2, sanitized_ciphertext = NULL, sanitized_nonce = NULL,
            removed_at = statement_timestamp()
        WHERE photo.id = $1 AND photo.state = 'ready'
          AND NOT EXISTS (
              SELECT 1 FROM profile.profile_revision_photos AS link
              WHERE link.photo_id = photo.id
          )
        "#,
    )
    .bind(photo_id)
    .bind(next_state)
    .execute(connection)
    .await?;
    Ok(())
}

fn validate_photo(input: &AttachSanitizedProfilePhoto) -> Result<(), PersistenceError> {
    if input.expected_revision_version <= 0
        || input.encrypted_jpeg.purpose != EncryptionPurpose::Media
        || !(16..=MAX_ENCRYPTED_JPEG_BYTES).contains(&input.encrypted_jpeg.ciphertext.len())
        || !(1..=12_000).contains(&input.width_pixels)
        || !(1..=12_000).contains(&input.height_pixels)
        || input.sanitizer_version.is_empty()
        || input.sanitizer_version.len() > 32
        || input.sanitizer_version.trim() != input.sanitizer_version
    {
        return Err(PersistenceError::InvalidCommand(
            "sanitized profile photo metadata is invalid".to_owned(),
        ));
    }
    Ok(())
}

async fn touch_revision(
    connection: &mut sqlx::PgConnection,
    revision_id: ProfileRevisionId,
    expected_version: i64,
) -> Result<Option<i64>, PersistenceError> {
    Ok(sqlx::query_scalar(
        r#"
        UPDATE profile.profile_revisions
        SET updated_at = clock_timestamp()
        WHERE id = $1 AND version = $2 AND state = 'draft'
        RETURNING version
        "#,
    )
    .bind(revision_id.into_uuid())
    .bind(expected_version)
    .fetch_optional(connection)
    .await?)
}
