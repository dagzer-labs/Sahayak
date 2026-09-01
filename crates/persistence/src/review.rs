use crate::{Database, PersistenceError, key_registry::ensure_active_encryption_key};
use sahayak_cryptography::{
    CryptoService, EncryptionContext, EncryptionNamespace, EncryptionPurpose,
};
use sahayak_domain::{
    AccountId, AuditEventId, ChannelIdentityId, ContactRevealId, CorrelationId, ReviewId,
    ReviewRevisionId,
};
use uuid::Uuid;

/// Ratings attached to one qualified introduction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewRatings {
    pub connection_experience: i16,
    pub responsiveness: i16,
    pub completion: i16,
}

impl ReviewRatings {
    fn validate(self) -> Result<(), PersistenceError> {
        if [
            self.connection_experience,
            self.responsiveness,
            self.completion,
        ]
        .into_iter()
        .all(|rating| (1..=5).contains(&rating))
        {
            Ok(())
        } else {
            Err(PersistenceError::InvalidCommand(
                "review ratings must be between one and five".to_owned(),
            ))
        }
    }
}

/// Direction of feedback across an introduction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewDirection {
    CustomerToProfessional,
    ProfessionalToCustomer,
}

impl ReviewDirection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CustomerToProfessional => "customer_to_professional",
            Self::ProfessionalToCustomer => "professional_to_customer",
        }
    }
}

/// Validated command for creating a review and its first immutable revision.
pub struct SubmitReview<'a> {
    pub review_id: ReviewId,
    pub review_token: Uuid,
    pub revision_id: ReviewRevisionId,
    pub reveal_id: ContactRevealId,
    pub reviewer_account_id: AccountId,
    pub reviewer_channel_identity_id: ChannelIdentityId,
    pub subject_account_id: AccountId,
    pub direction: ReviewDirection,
    pub ratings: ReviewRatings,
    pub written_feedback: Option<&'a str>,
    pub source_inbound_event_id: Option<Uuid>,
    pub correlation_id: CorrelationId,
}

/// Result of an idempotent review mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewMutation {
    Applied { version: i64 },
    ConflictOrIneligible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewModerationState {
    Published,
    PendingReview,
    Hidden,
    Removed,
}

impl ReviewModerationState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::PendingReview => "pending_review",
            Self::Hidden => "hidden",
            Self::Removed => "removed",
        }
    }
}

/// Public rating projection; averages are hidden until three reviews exist.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RatingSummary {
    pub rating_count: i32,
    pub average_rating: Option<f64>,
}

/// Transactional review persistence.
#[derive(Clone, Debug)]
pub struct ReviewRepository {
    database: Database,
    cryptography: CryptoService,
}

impl ReviewRepository {
    #[must_use]
    pub const fn new(database: Database, cryptography: CryptoService) -> Self {
        Self {
            database,
            cryptography,
        }
    }

    pub async fn submit(
        &self,
        command: SubmitReview<'_>,
    ) -> Result<ReviewMutation, PersistenceError> {
        command.ratings.validate()?;
        validate_optional_text(command.written_feedback, 1_000, "review feedback")?;
        let encrypted = command
            .written_feedback
            .map(|feedback| {
                self.cryptography.encrypt(
                    EncryptionPurpose::Integration,
                    EncryptionContext::new(
                        EncryptionNamespace::REVIEW_FEEDBACK,
                        command.revision_id.into_uuid(),
                    ),
                    feedback.as_bytes(),
                )
            })
            .transpose()
            .map_err(|error| PersistenceError::InvalidCommand(error.to_string()))?;
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query("SELECT set_config('sahayak.review_mutation', 'on', true)")
            .execute(&mut *transaction)
            .await?;
        if let Some(value) = encrypted.as_ref() {
            ensure_active_encryption_key(&mut transaction, value.purpose, value.key_version)
                .await?;
        }
        let inserted = sqlx::query(
            r#"
            INSERT INTO review.reviews (
                id, review_token, reveal_id, reviewer_account_id, subject_account_id, direction
            ) VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (reveal_id, reviewer_account_id) DO NOTHING
            "#,
        )
        .bind(command.review_id.into_uuid())
        .bind(command.review_token)
        .bind(command.reveal_id.into_uuid())
        .bind(command.reviewer_account_id.into_uuid())
        .bind(command.subject_account_id.into_uuid())
        .bind(command.direction.as_str())
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(ReviewMutation::ConflictOrIneligible);
        }
        let audit_id = insert_account_audit(
            &mut transaction,
            command.reviewer_account_id,
            command.reviewer_channel_identity_id,
            "review.submitted",
            "review",
            command.review_id.into_uuid(),
            "qualified_introduction_feedback",
            command.correlation_id,
        )
        .await?;
        sqlx::query(
            r#"
            INSERT INTO review.review_revisions (
                id, review_id, revision_number, connection_experience, responsiveness,
                completion, encrypted_feedback, feedback_nonce, encryption_key_version,
                source_inbound_event_id, audit_event_id
            ) VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(command.revision_id.into_uuid())
        .bind(command.review_id.into_uuid())
        .bind(command.ratings.connection_experience)
        .bind(command.ratings.responsiveness)
        .bind(command.ratings.completion)
        .bind(encrypted.as_ref().map(|value| value.ciphertext.as_slice()))
        .bind(encrypted.as_ref().map(|value| value.nonce.as_slice()))
        .bind(encrypted.as_ref().map(|value| value.key_version))
        .bind(command.source_inbound_event_id)
        .bind(audit_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(ReviewMutation::Applied { version: 1 })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn edit(
        &self,
        review_token: Uuid,
        reviewer_account_id: AccountId,
        reviewer_channel_identity_id: ChannelIdentityId,
        expected_version: i64,
        revision_id: ReviewRevisionId,
        ratings: ReviewRatings,
        written_feedback: Option<&str>,
        source_inbound_event_id: Option<Uuid>,
        correlation_id: CorrelationId,
    ) -> Result<ReviewMutation, PersistenceError> {
        ratings.validate()?;
        validate_optional_text(written_feedback, 1_000, "review feedback")?;
        let encrypted = written_feedback
            .map(|feedback| {
                self.cryptography.encrypt(
                    EncryptionPurpose::Integration,
                    EncryptionContext::new(
                        EncryptionNamespace::REVIEW_FEEDBACK,
                        revision_id.into_uuid(),
                    ),
                    feedback.as_bytes(),
                )
            })
            .transpose()
            .map_err(|error| PersistenceError::InvalidCommand(error.to_string()))?;
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query("SELECT set_config('sahayak.review_mutation', 'on', true)")
            .execute(&mut *transaction)
            .await?;
        let row: Option<(Uuid, i32)> = sqlx::query_as(
            r#"
            UPDATE review.reviews SET current_revision_number = current_revision_number + 1
            WHERE review_token = $1 AND reviewer_account_id = $2 AND version = $3
              AND moderation_state <> 'removed'
            RETURNING id, current_revision_number
            "#,
        )
        .bind(review_token)
        .bind(reviewer_account_id.into_uuid())
        .bind(expected_version)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((review_id, revision_number)) = row else {
            transaction.rollback().await?;
            return Ok(ReviewMutation::ConflictOrIneligible);
        };
        if let Some(value) = encrypted.as_ref() {
            ensure_active_encryption_key(&mut transaction, value.purpose, value.key_version)
                .await?;
        }
        let audit_id = insert_account_audit(
            &mut transaction,
            reviewer_account_id,
            reviewer_channel_identity_id,
            "review.edited",
            "review",
            review_id,
            "author_edit",
            correlation_id,
        )
        .await?;
        sqlx::query(
            r#"
            INSERT INTO review.review_revisions (
                id, review_id, revision_number, connection_experience, responsiveness,
                completion, encrypted_feedback, feedback_nonce, encryption_key_version,
                source_inbound_event_id, audit_event_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(revision_id.into_uuid())
        .bind(review_id)
        .bind(revision_number)
        .bind(ratings.connection_experience)
        .bind(ratings.responsiveness)
        .bind(ratings.completion)
        .bind(encrypted.as_ref().map(|value| value.ciphertext.as_slice()))
        .bind(encrypted.as_ref().map(|value| value.nonce.as_slice()))
        .bind(encrypted.as_ref().map(|value| value.key_version))
        .bind(source_inbound_event_id)
        .bind(audit_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(ReviewMutation::Applied {
            version: expected_version + 1,
        })
    }

    pub async fn rating_summary(
        &self,
        subject: AccountId,
    ) -> Result<RatingSummary, PersistenceError> {
        let row: Option<(i32, Option<f64>, bool)> = sqlx::query_as(
            "SELECT rating_count, average_rating::double precision, publicly_visible FROM review.rating_aggregates WHERE subject_account_id = $1",
        )
        .bind(subject.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        Ok(match row {
            Some((rating_count, average, true)) => RatingSummary {
                rating_count,
                average_rating: average,
            },
            Some((rating_count, _, false)) => RatingSummary {
                rating_count,
                average_rating: None,
            },
            None => RatingSummary {
                rating_count: 0,
                average_rating: None,
            },
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn moderate(
        &self,
        administrator_account_id: AccountId,
        administrator_channel_identity_id: ChannelIdentityId,
        review_token: Uuid,
        expected_version: i64,
        state: ReviewModerationState,
        reason_code: &str,
        correlation_id: CorrelationId,
    ) -> Result<ReviewMutation, PersistenceError> {
        if reason_code.is_empty()
            || reason_code.len() > 64
            || !reason_code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(PersistenceError::InvalidCommand(
                "review moderation reason is invalid".to_owned(),
            ));
        }
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query("SELECT set_config('sahayak.review_mutation', 'on', true)")
            .execute(&mut *transaction)
            .await?;
        let authorized: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM identity.administrator_allowlist AS allowlist
                JOIN identity.account_roles AS role ON role.account_id = allowlist.account_id
                  AND role.role = 'administrator' AND role.revoked_at IS NULL
                WHERE allowlist.account_id = $1 AND allowlist.channel_identity_id = $2
                  AND allowlist.revoked_at IS NULL AND allowlist.expires_at > statement_timestamp()
            )
            "#,
        )
        .bind(administrator_account_id.into_uuid())
        .bind(administrator_channel_identity_id.into_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        if !authorized {
            transaction.rollback().await?;
            return Ok(ReviewMutation::ConflictOrIneligible);
        }
        let review_id: Option<Uuid> = sqlx::query_scalar(
            "UPDATE review.reviews SET moderation_state = $2 WHERE review_token = $1 AND version = $3 RETURNING id",
        )
        .bind(review_token)
        .bind(state.as_str())
        .bind(expected_version)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(review_id) = review_id else {
            transaction.rollback().await?;
            return Ok(ReviewMutation::ConflictOrIneligible);
        };
        let audit_id = AuditEventId::new().into_uuid();
        sqlx::query(
            r#"
            INSERT INTO audit.events (
                id, actor_type, actor_account_id, actor_channel_identity_id, source_channel,
                action, target_type, target_id, reason_code, metadata,
                event_schema_version, correlation_id
            ) VALUES ($1, 'administrator', $2, $3, 'whatsapp', 'review.moderated',
                      'review', $4, $5, jsonb_build_object('state', $6::text), 1, $7)
            "#,
        )
        .bind(audit_id)
        .bind(administrator_account_id.into_uuid())
        .bind(administrator_channel_identity_id.into_uuid())
        .bind(review_id)
        .bind(reason_code)
        .bind(state.as_str())
        .bind(correlation_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(ReviewMutation::Applied {
            version: expected_version + 1,
        })
    }
}

fn validate_optional_text(
    value: Option<&str>,
    maximum: usize,
    field: &str,
) -> Result<(), PersistenceError> {
    if value.is_some_and(|text| {
        text.is_empty() || text.len() > maximum || text.chars().any(char::is_control)
    }) {
        return Err(PersistenceError::InvalidCommand(format!(
            "{field} must be non-empty, bounded, and free of control characters"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_account_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: AccountId,
    channel_identity_id: ChannelIdentityId,
    action: &str,
    target_type: &str,
    target_id: Uuid,
    reason_code: &str,
    correlation_id: CorrelationId,
) -> Result<Uuid, PersistenceError> {
    let audit_id = AuditEventId::new().into_uuid();
    sqlx::query(
        r#"
        INSERT INTO audit.events (
            id, actor_type, actor_account_id, actor_channel_identity_id, source_channel,
            action, target_type, target_id, reason_code, metadata,
            event_schema_version, correlation_id
        ) VALUES ($1, 'account', $2, $3, 'whatsapp', $4, $5, $6, $7, '{}'::jsonb, 1, $8)
        "#,
    )
    .bind(audit_id)
    .bind(account_id.into_uuid())
    .bind(channel_identity_id.into_uuid())
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(reason_code)
    .bind(correlation_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    Ok(audit_id)
}
