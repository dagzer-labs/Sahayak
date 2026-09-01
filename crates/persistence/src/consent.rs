use crate::{Database, PersistenceError};
use sahayak_domain::{
    AccountId, ChannelIdentityId, ConsentAction, CorrelationId, InboundEventId,
    ProfessionalConsentEventId, ProfessionalConsentPurpose, ProfessionalLanguage,
    ProfileRevisionId, PublicProfileId,
};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

/// Current localized legal text and its immutable evidence hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentDocument {
    pub purpose: ProfessionalConsentPurpose,
    pub locale: ProfessionalLanguage,
    pub version: String,
    pub text: String,
    pub sha256: [u8; 32],
}

/// Exact immutable facts for one purpose-specific consent event.
#[derive(Clone, Debug)]
pub struct RecordProfessionalConsent {
    pub id: ProfessionalConsentEventId,
    pub account_id: AccountId,
    pub profile_id: PublicProfileId,
    pub revision_id: ProfileRevisionId,
    pub purpose: ProfessionalConsentPurpose,
    pub action: ConsentAction,
    pub document_version: String,
    pub document_sha256: [u8; 32],
    pub locale: ProfessionalLanguage,
    pub channel_identity_id: ChannelIdentityId,
    pub source_inbound_event_id: InboundEventId,
    pub idempotency_key: String,
    pub occurred_at: OffsetDateTime,
}

/// Idempotent consent append result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsentRecordOutcome {
    Recorded,
    AlreadyRecorded,
}

#[derive(FromRow)]
struct DocumentRow {
    purpose: String,
    document_version: String,
    document_text: String,
    document_sha256: Vec<u8>,
    locale: String,
}

#[derive(FromRow)]
struct ExistingConsentRow {
    id: Uuid,
    account_id: Uuid,
    profile_id: Uuid,
    revision_id: Uuid,
    purpose: String,
    action: String,
    document_version: String,
    document_sha256: Vec<u8>,
    locale: String,
    channel_identity_id: Uuid,
    source_inbound_event_id: Uuid,
    occurred_at: OffsetDateTime,
}

/// Append-only professional consent ledger operations.
#[derive(Clone, Debug)]
pub struct ProfessionalConsentRepository {
    database: Database,
}

impl ProfessionalConsentRepository {
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Lists exact current localized text, versions, and hashes that may be accepted.
    pub async fn current_documents(
        &self,
        locale: ProfessionalLanguage,
    ) -> Result<Vec<ConsentDocument>, PersistenceError> {
        let rows = sqlx::query_as::<_, DocumentRow>(
            r#"
            SELECT purpose, locale, document_version, document_text, document_sha256
            FROM profile.consent_documents
            WHERE is_current AND locale = $1
            ORDER BY purpose
            "#,
        )
        .bind(locale.as_str())
        .fetch_all(self.database.pool())
        .await?;
        rows.into_iter().map(map_document).collect()
    }

    /// Records consent only when the document, account channel, and source event agree.
    pub async fn record(
        &self,
        input: &RecordProfessionalConsent,
    ) -> Result<ConsentRecordOutcome, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let outcome = record_in_transaction(&mut transaction, input).await?;
        transaction.commit().await?;
        Ok(outcome)
    }
}

pub(crate) async fn record_in_transaction(
    connection: &mut sqlx::PgConnection,
    input: &RecordProfessionalConsent,
) -> Result<ConsentRecordOutcome, PersistenceError> {
    validate_input(input)?;
    if let Some(existing) = sqlx::query_as::<_, ExistingConsentRow>(
        r#"
        SELECT id, account_id, profile_id, revision_id, purpose, action, document_version,
               document_sha256, locale, channel_identity_id,
               source_inbound_event_id, occurred_at
        FROM private_data.professional_consent_events
        WHERE revision_id = $1 AND purpose = $2 AND idempotency_key = $3
        "#,
    )
    .bind(input.revision_id.into_uuid())
    .bind(input.purpose.as_str())
    .bind(&input.idempotency_key)
    .fetch_optional(&mut *connection)
    .await?
    {
        if consent_matches(&existing, input) {
            return Ok(ConsentRecordOutcome::AlreadyRecorded);
        }
        return Err(PersistenceError::InvalidCommand(
            "consent idempotency key was reused with different input".to_owned(),
        ));
    }
    let authorized: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM identity.accounts AS account
            JOIN identity.channel_identities AS channel
              ON channel.id = $2
             AND channel.account_id = account.id
             AND channel.status = 'active'
             AND channel.verified_at IS NOT NULL
            JOIN integration.inbound_events AS inbound
              ON inbound.id = $3
             AND inbound.account_id = account.id
             AND inbound.channel_identity_id = channel.id
            JOIN profile.public_profiles AS root
              ON root.id = $7 AND root.account_id = account.id
            JOIN profile.profile_revisions AS revision
              ON revision.id = $8 AND revision.profile_id = root.id
            JOIN profile.consent_documents AS document
              ON document.purpose = $4
             AND document.document_version = $5
             AND document.document_sha256 = $6
             AND document.locale = $9
             AND document.is_current
            WHERE account.id = $1
               AND account.status NOT IN ('deletion_pending', 'deleted')
               AND account.risk_state NOT IN ('restricted', 'blocked')
               AND ($10 = 'revoked' OR revision.state IN ('draft', 'approved'))
        )
        "#,
    )
    .bind(input.account_id.into_uuid())
    .bind(input.channel_identity_id.into_uuid())
    .bind(input.source_inbound_event_id.into_uuid())
    .bind(input.purpose.as_str())
    .bind(&input.document_version)
    .bind(input.document_sha256.as_slice())
    .bind(input.profile_id.into_uuid())
    .bind(input.revision_id.into_uuid())
    .bind(input.locale.as_str())
    .bind(input.action.as_str())
    .fetch_one(&mut *connection)
    .await?;
    if !authorized {
        return Err(PersistenceError::InvalidCommand(
            "consent source, channel, account, or document is not current".to_owned(),
        ));
    }
    let inserted = sqlx::query(
        r#"
        INSERT INTO private_data.professional_consent_events (
            id, account_id, profile_id, revision_id, purpose, action, document_version,
            document_sha256, locale, channel_identity_id, channel_code,
            revision_digest, source_inbound_event_id, idempotency_key, occurred_at
        )
        SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'whatsapp',
               profile.reviewable_revision_digest($4), $11, $12, $13
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(input.id.into_uuid())
    .bind(input.account_id.into_uuid())
    .bind(input.profile_id.into_uuid())
    .bind(input.revision_id.into_uuid())
    .bind(input.purpose.as_str())
    .bind(input.action.as_str())
    .bind(&input.document_version)
    .bind(input.document_sha256.as_slice())
    .bind(input.locale.as_str())
    .bind(input.channel_identity_id.into_uuid())
    .bind(input.source_inbound_event_id.into_uuid())
    .bind(&input.idempotency_key)
    .bind(input.occurred_at)
    .execute(&mut *connection)
    .await?;
    if inserted.rows_affected() == 1 {
        if input.action == ConsentAction::Revoked
            && input.purpose != ProfessionalConsentPurpose::IdentityVerification
        {
            crate::availability::invalidate_profile_epochs(
                connection,
                input.profile_id,
                "consent_revoked",
                CorrelationId::new(),
            )
            .await?;
        }
        return Ok(ConsentRecordOutcome::Recorded);
    }
    let existing = sqlx::query_as::<_, ExistingConsentRow>(
        r#"
        SELECT id, account_id, profile_id, revision_id, purpose, action, document_version,
               document_sha256, locale, channel_identity_id,
               source_inbound_event_id, occurred_at
        FROM private_data.professional_consent_events
        WHERE (revision_id = $1 AND purpose = $2 AND idempotency_key = $3)
           OR (source_inbound_event_id = $4 AND revision_id = $1 AND purpose = $2)
        "#,
    )
    .bind(input.revision_id.into_uuid())
    .bind(input.purpose.as_str())
    .bind(&input.idempotency_key)
    .bind(input.source_inbound_event_id.into_uuid())
    .fetch_optional(connection)
    .await?;
    if existing
        .as_ref()
        .is_some_and(|row| consent_matches(row, input))
    {
        return Ok(ConsentRecordOutcome::AlreadyRecorded);
    }
    Err(PersistenceError::InvalidCommand(
        "consent source or idempotency key was reused with different input".to_owned(),
    ))
}

fn validate_input(input: &RecordProfessionalConsent) -> Result<(), PersistenceError> {
    if input.document_version.is_empty()
        || input.document_version.len() > 32
        || input.document_version.trim() != input.document_version
        || input.idempotency_key.is_empty()
        || input.idempotency_key.len() > 255
        || input.idempotency_key.trim() != input.idempotency_key
    {
        return Err(PersistenceError::InvalidCommand(
            "consent document version or idempotency key is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn consent_matches(row: &ExistingConsentRow, input: &RecordProfessionalConsent) -> bool {
    row.id == input.id.into_uuid()
        && row.account_id == input.account_id.into_uuid()
        && row.profile_id == input.profile_id.into_uuid()
        && row.revision_id == input.revision_id.into_uuid()
        && row.purpose == input.purpose.as_str()
        && row.action == input.action.as_str()
        && row.document_version == input.document_version
        && row.document_sha256.as_slice() == input.document_sha256
        && row.locale == input.locale.as_str()
        && row.channel_identity_id == input.channel_identity_id.into_uuid()
        && row.source_inbound_event_id == input.source_inbound_event_id.into_uuid()
        && same_postgres_timestamp(row.occurred_at, input.occurred_at)
}

fn same_postgres_timestamp(left: OffsetDateTime, right: OffsetDateTime) -> bool {
    left.unix_timestamp_nanos() / 1_000 == right.unix_timestamp_nanos() / 1_000
}

fn map_document(row: DocumentRow) -> Result<ConsentDocument, PersistenceError> {
    let sha256 = row.document_sha256.try_into().map_err(|_| {
        PersistenceError::Invariant("consent document hash has invalid length".to_owned())
    })?;
    let purpose = row.purpose.parse().map_err(|error| {
        PersistenceError::Invariant(format!("consent document has invalid purpose: {error}"))
    })?;
    Ok(ConsentDocument {
        purpose,
        locale: ProfessionalLanguage::parse(&row.locale).ok_or_else(|| {
            PersistenceError::Invariant("consent document has invalid locale".to_owned())
        })?,
        version: row.document_version,
        text: row.document_text,
        sha256,
    })
}
