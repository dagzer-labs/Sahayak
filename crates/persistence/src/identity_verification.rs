use crate::{
    Database, PersistenceError,
    key_registry::{ensure_active_encryption_key, ensure_lookup_key_readable},
};
use sahayak_cryptography::{EncryptedValue, EncryptionPurpose};
use sahayak_domain::{
    AccountId, IdentityVerificationAttemptId, IdentityVerificationCallbackReceiptId,
    IdentityVerificationState, ProfessionalConsentEventId,
};
use sqlx::FromRow;
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

/// Starts one provider-neutral attempt using only an encrypted random opaque reference.
#[derive(Clone)]
pub struct StartIdentityVerificationAttempt {
    pub id: IdentityVerificationAttemptId,
    pub account_id: AccountId,
    pub adapter_instance_code: String,
    pub consent_event_id: ProfessionalConsentEventId,
    pub encrypted_provider_reference: EncryptedValue,
    pub idempotency_key: String,
    pub expires_at: OffsetDateTime,
}

impl std::fmt::Debug for StartIdentityVerificationAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StartIdentityVerificationAttempt")
            .field("id", &self.id)
            .field("account_id", &self.account_id)
            .field("adapter_instance_code", &self.adapter_instance_code)
            .field("consent_event_id", &self.consent_event_id)
            .field("encrypted_provider_reference", &"[REDACTED]")
            .field("idempotency_key", &self.idempotency_key)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityAttemptOutcome {
    Started,
    AlreadyStarted,
    ActiveAttemptExists,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityAttemptMutation {
    Applied { version: i64 },
    ConflictOrMissing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationCallbackKind {
    ServerCallback,
    BrowserReturn,
}

impl VerificationCallbackKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ServerCallback => "server_callback",
            Self::BrowserReturn => "browser_return",
        }
    }
}

/// Scalar-only callback receipt and requested monotonic transition.
#[derive(Clone, Debug)]
pub struct RecordIdentityVerificationCallback {
    pub id: IdentityVerificationCallbackReceiptId,
    pub attempt_id: IdentityVerificationAttemptId,
    pub adapter_instance_code: String,
    pub callback_kind: VerificationCallbackKind,
    pub reported_state: IdentityVerificationState,
    pub callback_event_key_digest: [u8; 32],
    pub callback_event_digest: [u8; 32],
    pub digest_key_version: i16,
    pub signature_verified_at: Option<OffsetDateTime>,
    pub provider_occurred_at: Option<OffsetDateTime>,
    pub assertion_valid_until: Option<OffsetDateTime>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationCallbackOutcome {
    Applied,
    AlreadyRecorded,
    ReceiptRecorded,
    ConflictOrMissing,
}

/// Literal badge projection returned only for a current passed assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityBadgeProjection {
    pub label: String,
    pub valid_until: OffsetDateTime,
}

#[derive(FromRow)]
struct ExistingAttemptRow {
    id: Uuid,
    account_id: Uuid,
    adapter_instance_code: String,
    consent_event_id: Uuid,
    provider_reference_ciphertext: Vec<u8>,
    provider_reference_nonce: Vec<u8>,
    encryption_key_version: i16,
    expires_at: OffsetDateTime,
}

#[derive(FromRow)]
struct AttemptStateRow {
    adapter_instance_code: String,
    state: String,
    expires_at: OffsetDateTime,
    adapter_active: bool,
    consent_current: bool,
}

#[derive(FromRow)]
struct ExistingCallbackRow {
    attempt_id: Uuid,
    callback_kind: String,
    reported_state: String,
    callback_event_digest: Vec<u8>,
}

/// Restricted optional identity-verification persistence.
#[derive(Clone, Debug)]
pub struct IdentityVerificationRepository {
    database: Database,
}

impl IdentityVerificationRepository {
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    pub async fn start_attempt(
        &self,
        input: &StartIdentityVerificationAttempt,
    ) -> Result<IdentityAttemptOutcome, PersistenceError> {
        validate_attempt(input)?;
        let mut transaction = self.database.pool().begin().await?;
        ensure_active_encryption_key(
            &mut transaction,
            EncryptionPurpose::Identity,
            input.encrypted_provider_reference.key_version,
        )
        .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("identity-verification:{}", input.account_id))
            .execute(&mut *transaction)
            .await?;
        if let Some(existing) = sqlx::query_as::<_, ExistingAttemptRow>(
            r#"
            SELECT id, account_id, adapter_instance_code, consent_event_id,
                   provider_reference_ciphertext, provider_reference_nonce,
                   encryption_key_version, expires_at
            FROM private_data.identity_verification_attempts
            WHERE account_id = $1 AND idempotency_key = $2
            "#,
        )
        .bind(input.account_id.into_uuid())
        .bind(&input.idempotency_key)
        .fetch_optional(&mut *transaction)
        .await?
        {
            transaction.rollback().await?;
            if attempt_matches(&existing, input) {
                return Ok(IdentityAttemptOutcome::AlreadyStarted);
            }
            return Err(PersistenceError::InvalidCommand(
                "identity attempt idempotency key was reused".to_owned(),
            ));
        }
        sqlx::query(
            r#"
            UPDATE private_data.identity_verification_attempts
            SET state = 'expired', expired_at = statement_timestamp()
            WHERE account_id = $1
              AND state = 'pending'
              AND expires_at <= statement_timestamp()
            "#,
        )
        .bind(input.account_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        let allowed: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM identity.accounts AS account
                JOIN identity.identity_provider_adapters AS adapter
                  ON adapter.code = $2 AND adapter.state = 'active'
                JOIN private_data.professional_consent_events AS consent
                  ON consent.id = $3
                 AND consent.account_id = account.id
                 AND consent.purpose = 'identity_verification'
                 AND consent.action = 'granted'
                JOIN profile.consent_documents AS document
                  ON document.purpose = consent.purpose
                 AND document.locale = consent.locale
                 AND document.document_version = consent.document_version
                 AND document.document_sha256 = consent.document_sha256
                 AND document.is_current
                WHERE account.id = $1
                  AND account.status = 'active'
                   AND account.risk_state NOT IN ('restricted', 'blocked')
                  AND private_data.has_current_professional_consent(
                      consent.revision_id,
                      'identity_verification'
                  )
                  AND $4 > statement_timestamp()
                  AND $4 <= statement_timestamp() + INTERVAL '30 days'
            )
            "#,
        )
        .bind(input.account_id.into_uuid())
        .bind(&input.adapter_instance_code)
        .bind(input.consent_event_id.into_uuid())
        .bind(input.expires_at)
        .fetch_one(&mut *transaction)
        .await?;
        if !allowed {
            transaction.rollback().await?;
            return Err(PersistenceError::InvalidCommand(
                "identity attempt account, adapter, consent, or expiry is invalid".to_owned(),
            ));
        }
        let active_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM private_data.identity_verification_attempts WHERE account_id = $1 AND state = 'pending')",
        )
        .bind(input.account_id.into_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        if active_exists {
            transaction.rollback().await?;
            return Ok(IdentityAttemptOutcome::ActiveAttemptExists);
        }
        sqlx::query(
            r#"
            INSERT INTO private_data.identity_verification_attempts (
                id, account_id, adapter_instance_code, consent_event_id,
                state, provider_reference_ciphertext, provider_reference_nonce,
                encryption_key_purpose, encryption_key_version,
                idempotency_key, expires_at
            )
            VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(input.id.into_uuid())
        .bind(input.account_id.into_uuid())
        .bind(&input.adapter_instance_code)
        .bind(input.consent_event_id.into_uuid())
        .bind(&input.encrypted_provider_reference.ciphertext)
        .bind(input.encrypted_provider_reference.nonce.as_slice())
        .bind(input.encrypted_provider_reference.purpose.as_str())
        .bind(input.encrypted_provider_reference.key_version)
        .bind(&input.idempotency_key)
        .bind(input.expires_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(IdentityAttemptOutcome::Started)
    }

    /// Explicitly expires or revokes an attempt under optimistic concurrency.
    pub async fn end_attempt(
        &self,
        attempt_id: IdentityVerificationAttemptId,
        expected_version: i64,
        next: IdentityVerificationState,
    ) -> Result<IdentityAttemptMutation, PersistenceError> {
        if !matches!(
            next,
            IdentityVerificationState::Expired | IdentityVerificationState::Revoked
        ) || expected_version <= 0
        {
            return Err(PersistenceError::InvalidCommand(
                "identity attempt may be ended only as expired or revoked".to_owned(),
            ));
        }
        let version = match next {
            IdentityVerificationState::Expired => {
                sqlx::query_scalar(
                    r#"
                    UPDATE private_data.identity_verification_attempts
                    SET state = 'expired', expired_at = statement_timestamp()
                    WHERE id = $1 AND version = $2 AND state IN ('pending', 'passed')
                    RETURNING version
                    "#,
                )
                .bind(attempt_id.into_uuid())
                .bind(expected_version)
                .fetch_optional(self.database.pool())
                .await?
            }
            IdentityVerificationState::Revoked => {
                sqlx::query_scalar(
                    r#"
                    UPDATE private_data.identity_verification_attempts
                    SET state = 'revoked', revoked_at = statement_timestamp()
                    WHERE id = $1 AND version = $2 AND state IN ('pending', 'passed')
                    RETURNING version
                    "#,
                )
                .bind(attempt_id.into_uuid())
                .bind(expected_version)
                .fetch_optional(self.database.pool())
                .await?
            }
            _ => None,
        };
        Ok(
            version.map_or(IdentityAttemptMutation::ConflictOrMissing, |version| {
                IdentityAttemptMutation::Applied { version }
            }),
        )
    }

    /// Records a payload-free callback. Browser returns are receipts only and can
    /// never establish a passed assertion.
    pub async fn record_callback(
        &self,
        input: &RecordIdentityVerificationCallback,
    ) -> Result<VerificationCallbackOutcome, PersistenceError> {
        validate_callback(input)?;
        let reported_state = callback_state(input.reported_state)?;
        let mut transaction = self.database.pool().begin().await?;
        ensure_lookup_key_readable(&mut transaction, input.digest_key_version).await?;
        let duplicate = sqlx::query_as::<_, ExistingCallbackRow>(
            r#"
            SELECT attempt_id, callback_kind, reported_state, callback_event_digest
            FROM private_data.identity_verification_callback_receipts
            WHERE adapter_instance_code = $1
              AND digest_key_version = $2
              AND callback_event_key_digest = $3
            "#,
        )
        .bind(&input.adapter_instance_code)
        .bind(input.digest_key_version)
        .bind(input.callback_event_key_digest.as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(existing) = duplicate {
            transaction.rollback().await?;
            if existing.attempt_id == input.attempt_id.into_uuid()
                && existing.callback_kind == input.callback_kind.as_str()
                && existing.reported_state == reported_state
                && existing.callback_event_digest.as_slice() == input.callback_event_digest
            {
                return Ok(VerificationCallbackOutcome::AlreadyRecorded);
            }
            return Err(PersistenceError::InvalidCommand(
                "verification callback event key was reused with different scalar facts".to_owned(),
            ));
        }
        let attempt = sqlx::query_as::<_, AttemptStateRow>(
            r#"
            SELECT attempt.adapter_instance_code, attempt.state, attempt.expires_at,
                   adapter.state = 'active' AS adapter_active,
                   consent.action = 'granted'
                     AND private_data.has_current_professional_consent(
                         consent.revision_id, 'identity_verification'
                     ) AS consent_current
            FROM private_data.identity_verification_attempts AS attempt
            JOIN identity.identity_provider_adapters AS adapter
              ON adapter.code = attempt.adapter_instance_code
            JOIN private_data.professional_consent_events AS consent
              ON consent.id = attempt.consent_event_id
            WHERE attempt.id = $1
            FOR UPDATE OF attempt, adapter
            "#,
        )
        .bind(input.attempt_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(attempt) = attempt else {
            transaction.rollback().await?;
            return Ok(VerificationCallbackOutcome::ConflictOrMissing);
        };
        if attempt.adapter_instance_code != input.adapter_instance_code {
            transaction.rollback().await?;
            return Ok(VerificationCallbackOutcome::ConflictOrMissing);
        }
        if !attempt.adapter_active || !attempt.consent_current {
            transaction.rollback().await?;
            return Ok(VerificationCallbackOutcome::ConflictOrMissing);
        }
        let inserted = sqlx::query(
            r#"
            INSERT INTO private_data.identity_verification_callback_receipts (
                id, attempt_id, adapter_instance_code, callback_kind,
                reported_state, callback_event_key_digest, callback_event_digest,
                digest_key_version, signature_verified_at, provider_occurred_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(input.id.into_uuid())
        .bind(input.attempt_id.into_uuid())
        .bind(&input.adapter_instance_code)
        .bind(input.callback_kind.as_str())
        .bind(reported_state)
        .bind(input.callback_event_key_digest.as_slice())
        .bind(input.callback_event_digest.as_slice())
        .bind(input.digest_key_version)
        .bind(input.signature_verified_at)
        .bind(input.provider_occurred_at)
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() == 0 {
            let existing = sqlx::query_as::<_, ExistingCallbackRow>(
                r#"
                SELECT attempt_id, callback_kind, reported_state, callback_event_digest
                FROM private_data.identity_verification_callback_receipts
                WHERE adapter_instance_code = $1
                  AND digest_key_version = $2
                  AND callback_event_key_digest = $3
                "#,
            )
            .bind(&input.adapter_instance_code)
            .bind(input.digest_key_version)
            .bind(input.callback_event_key_digest.as_slice())
            .fetch_optional(&mut *transaction)
            .await?;
            transaction.rollback().await?;
            if existing.as_ref().is_some_and(|existing| {
                existing.attempt_id == input.attempt_id.into_uuid()
                    && existing.callback_kind == input.callback_kind.as_str()
                    && existing.reported_state == reported_state
                    && existing.callback_event_digest.as_slice() == input.callback_event_digest
            }) {
                return Ok(VerificationCallbackOutcome::AlreadyRecorded);
            }
            return Err(PersistenceError::InvalidCommand(
                "verification callback event key was reused with different scalar facts".to_owned(),
            ));
        }
        if input.callback_kind == VerificationCallbackKind::BrowserReturn
            || input.reported_state == IdentityVerificationState::Pending
        {
            transaction.commit().await?;
            return Ok(VerificationCallbackOutcome::ReceiptRecorded);
        }
        let current = IdentityVerificationState::from_str(&attempt.state).map_err(|error| {
            PersistenceError::Invariant(format!("identity attempt has invalid state: {error}"))
        })?;
        if !current.can_transition_to(input.reported_state) {
            transaction.rollback().await?;
            return Ok(VerificationCallbackOutcome::ConflictOrMissing);
        }
        if input.reported_state == IdentityVerificationState::Passed
            && OffsetDateTime::now_utc() >= attempt.expires_at
        {
            transaction.rollback().await?;
            return Ok(VerificationCallbackOutcome::ConflictOrMissing);
        }
        let changed = match input.reported_state {
            IdentityVerificationState::Passed => {
                sqlx::query(
                    r#"
                    UPDATE private_data.identity_verification_attempts
                    SET
                        state = 'passed',
                        verified_at = statement_timestamp(),
                        assertion_valid_until = $2
                    WHERE id = $1 AND state = 'pending' AND expires_at > statement_timestamp()
                    "#,
                )
                .bind(input.attempt_id.into_uuid())
                .bind(input.assertion_valid_until)
                .execute(&mut *transaction)
                .await?
            }
            IdentityVerificationState::Failed => {
                sqlx::query(
                    r#"
                    UPDATE private_data.identity_verification_attempts
                    SET state = 'failed', failed_at = statement_timestamp()
                    WHERE id = $1 AND state = 'pending'
                    "#,
                )
                .bind(input.attempt_id.into_uuid())
                .execute(&mut *transaction)
                .await?
            }
            _ => {
                transaction.rollback().await?;
                return Err(PersistenceError::InvalidCommand(
                    "callbacks may report only pending, passed, or failed".to_owned(),
                ));
            }
        };
        if changed.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(VerificationCallbackOutcome::ConflictOrMissing);
        }
        transaction.commit().await?;
        Ok(VerificationCallbackOutcome::Applied)
    }

    /// Returns only the literal current badge projection, never provider details.
    pub async fn badge_projection(
        &self,
        account_id: AccountId,
    ) -> Result<Option<IdentityBadgeProjection>, PersistenceError> {
        let row: Option<(String, OffsetDateTime)> = sqlx::query_as(
            r#"
            SELECT badge_text, assertion_valid_until
            FROM profile.identity_badge_projection
            WHERE account_id = $1
            ORDER BY assertion_valid_until DESC
            LIMIT 1
            "#,
        )
        .bind(account_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        Ok(row.map(|(label, valid_until)| IdentityBadgeProjection { label, valid_until }))
    }
}

fn validate_attempt(input: &StartIdentityVerificationAttempt) -> Result<(), PersistenceError> {
    if input.encrypted_provider_reference.purpose != EncryptionPurpose::Identity
        || !(16..=1024).contains(&input.encrypted_provider_reference.ciphertext.len())
        || input.adapter_instance_code.is_empty()
        || input.adapter_instance_code.len() > 48
        || input.idempotency_key.is_empty()
        || input.idempotency_key.len() > 255
        || input.idempotency_key.trim() != input.idempotency_key
    {
        return Err(PersistenceError::InvalidCommand(
            "identity verification attempt metadata is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_callback(input: &RecordIdentityVerificationCallback) -> Result<(), PersistenceError> {
    if input.digest_key_version <= 0
        || input.adapter_instance_code.is_empty()
        || input.adapter_instance_code.len() > 48
        || (input.callback_kind == VerificationCallbackKind::ServerCallback
            && input.signature_verified_at.is_none())
        || (input.callback_kind == VerificationCallbackKind::BrowserReturn
            && (input.signature_verified_at.is_some()
                || input.reported_state == IdentityVerificationState::Passed))
        || (input.reported_state == IdentityVerificationState::Passed
            && input.assertion_valid_until.is_none())
        || (input.reported_state != IdentityVerificationState::Passed
            && input.assertion_valid_until.is_some())
    {
        return Err(PersistenceError::InvalidCommand(
            "identity verification callback metadata is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn callback_state(state: IdentityVerificationState) -> Result<&'static str, PersistenceError> {
    match state {
        IdentityVerificationState::Pending
        | IdentityVerificationState::Passed
        | IdentityVerificationState::Failed => Ok(state.as_str()),
        IdentityVerificationState::Expired | IdentityVerificationState::Revoked => {
            Err(PersistenceError::InvalidCommand(
                "callback state must be pending, passed, or failed".to_owned(),
            ))
        }
    }
}

fn attempt_matches(row: &ExistingAttemptRow, input: &StartIdentityVerificationAttempt) -> bool {
    row.id == input.id.into_uuid()
        && row.account_id == input.account_id.into_uuid()
        && row.adapter_instance_code == input.adapter_instance_code
        && row.consent_event_id == input.consent_event_id.into_uuid()
        && row.provider_reference_ciphertext == input.encrypted_provider_reference.ciphertext
        && row.provider_reference_nonce.as_slice() == input.encrypted_provider_reference.nonce
        && row.encryption_key_version == input.encrypted_provider_reference.key_version
        && same_postgres_timestamp(row.expires_at, input.expires_at)
}

fn same_postgres_timestamp(left: OffsetDateTime, right: OffsetDateTime) -> bool {
    left.unix_timestamp_nanos() / 1_000 == right.unix_timestamp_nanos() / 1_000
}
