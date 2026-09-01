use crate::{Database, PersistenceError};
use sahayak_cryptography::{EncryptedValue, EncryptionPurpose};
use sahayak_domain::{
    AccountId, AuditEventId, ChannelIdentityId, ContactMode, CorrelationId, LocalServiceMode,
    ProfessionalConsentPurpose, ProfessionalDisplayName, ProfessionalLanguage,
    ProfileReviewDecision, ProfileReviewDecisionId, ProfileReviewReason, ProfileRevisionId,
    ProfileRevisionState, PublicProfileId, PublicProfileReference, ServiceRadiusKm,
};
use sqlx::{FromRow, PgConnection};
use std::{collections::BTreeSet, str::FromStr};
use time::OffsetDateTime;
use uuid::Uuid;

/// IDs supplied when starting a professional aggregate for the first time.
#[derive(Clone, Copy, Debug)]
pub struct BeginProfessionalDraft {
    pub profile_id: PublicProfileId,
    pub public_reference: PublicProfileReference,
    pub revision_id: ProfileRevisionId,
    pub account_id: AccountId,
}

/// Draft details that are safe to retain in conversation workflow state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfessionalDraftSnapshot {
    pub profile_id: PublicProfileId,
    pub public_reference: PublicProfileReference,
    pub revision_id: ProfileRevisionId,
    pub revision_number: i32,
    pub state: ProfileRevisionState,
    pub display_name: Option<String>,
    pub local_service_mode: Option<LocalServiceMode>,
    pub has_service_area: bool,
    pub service_radius: Option<ServiceRadiusKm>,
    pub contact_request_limit: Option<i16>,
    pub has_ready_photo: bool,
    pub version: i64,
}

/// Current non-sensitive prerequisites used by a professional onboarding worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfessionalOnboardingContext {
    pub account_active: bool,
    pub account_not_blocked: bool,
    pub professional_role_active: bool,
    pub whatsapp_identity_active_and_verified: bool,
    pub draft: Option<ProfessionalDraftSnapshot>,
    pub current_consents: BTreeSet<ProfessionalConsentPurpose>,
}

/// Privacy-safe profile status consumed by a conversation worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfessionalConversationStatus {
    NotStarted,
    Draft,
    PendingReview,
    ChangesRequested,
    Approved,
    Rejected,
    Hidden,
}

/// Complete reviewable profile fields without exact coordinates or media references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfessionalConversationSummary {
    pub display_name: Option<String>,
    pub local_service_mode: Option<LocalServiceMode>,
    pub has_service_area: bool,
    pub service_radius: Option<ServiceRadiusKm>,
    pub contact_request_limit: Option<i16>,
    pub services: Vec<ProfessionalServiceSnapshot>,
    pub languages: Vec<ProfessionalLanguage>,
    pub has_ready_photo: bool,
    pub identity_badge: bool,
}

/// Revision-scoped professional state safe to place in an engine context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfessionalConversationSnapshot {
    pub status: ProfessionalConversationStatus,
    pub profile_id: Option<PublicProfileId>,
    pub revision_id: Option<ProfileRevisionId>,
    pub version: Option<i64>,
    pub summary: Option<ProfessionalConversationSummary>,
    pub missing_requirements: Vec<ProfessionalRequirement>,
    pub current_consent_version: Option<String>,
    pub requested_change_fields: Vec<String>,
    pub review_reason: Option<String>,
    pub review_reason_detail: Option<String>,
}

/// Opaque pending-review item shown to an authorized administrator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministratorConversationTarget {
    pub review_token: String,
    pub target: ProfileReviewTarget,
    pub current_consent_version: Option<String>,
    pub identity_badge: bool,
}

/// Account-, channel-, and namespace-authorized administrator queue projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministratorConversationSnapshot {
    pub pending: Vec<AdministratorConversationTarget>,
    pub selected: Option<AdministratorConversationTarget>,
}

/// Restricted active WhatsApp destination for a professional review outcome.
#[derive(Clone)]
pub struct ProfessionalNotificationTarget {
    pub account_id: AccountId,
    pub channel_identity_id: ChannelIdentityId,
    pub provider_namespace: String,
    pub locale: String,
    pub encrypted_phone_e164: EncryptedValue,
}

impl std::fmt::Debug for ProfessionalNotificationTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProfessionalNotificationTarget")
            .field("account_id", &self.account_id)
            .field("channel_identity_id", &self.channel_identity_id)
            .field("provider_namespace", &self.provider_namespace)
            .field("locale", &self.locale)
            .field("encrypted_phone_e164", &"[REDACTED]")
            .finish()
    }
}

/// One category selection and its category-specific skills.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfessionalServiceInput {
    pub category_code: String,
    pub contact_mode: ContactMode,
    pub skill_codes: Vec<String>,
}

/// One reviewable service selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfessionalServiceSnapshot {
    pub category_code: String,
    pub contact_mode: ContactMode,
    pub skill_codes: Vec<String>,
}

/// Result of an optimistic profile draft mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileMutation {
    Applied { version: i64 },
    ConflictOrMissing,
}

/// A concrete missing prerequisite. Identity verification is intentionally absent.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProfessionalRequirement {
    ActiveAccount,
    NonBlockedAccount,
    ActiveProfessionalRole,
    VerifiedWhatsAppIdentity,
    DisplayName,
    ActiveService,
    ServiceSkill,
    LocalServiceMode,
    ServiceArea,
    ProfessionalLanguage,
    ContactRequestLimit,
    TermsConsent,
    PrivacyConsent,
    ContactDisclosureConsent,
    DirectContactConsent,
    PhotoDisclosureConsent,
}

/// Submission result with explicit completeness failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmitProfileOutcome {
    Submitted {
        version: i64,
        target_digest: [u8; 32],
    },
    Incomplete {
        missing: Vec<ProfessionalRequirement>,
    },
    ConflictOrMissing,
}

/// Privacy-safe submitted target shown to an administrator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileReviewTarget {
    pub profile_id: PublicProfileId,
    pub revision_id: ProfileRevisionId,
    pub revision_number: i32,
    pub owner_account_id: AccountId,
    pub display_name: String,
    pub local_service_mode: LocalServiceMode,
    pub service_radius: ServiceRadiusKm,
    pub contact_request_limit: i16,
    pub services: Vec<ProfessionalServiceSnapshot>,
    pub languages: Vec<ProfessionalLanguage>,
    pub has_ready_photo: bool,
    pub submitted_at: OffsetDateTime,
    pub target_digest: [u8; 32],
    pub version: i64,
}

/// Authorized administrative review command.
#[derive(Clone, Debug)]
pub struct ApplyProfileDecision {
    pub id: ProfileReviewDecisionId,
    pub revision_id: ProfileRevisionId,
    pub expected_version: i64,
    pub target_digest: [u8; 32],
    pub reviewer_account_id: AccountId,
    pub reviewer_channel_identity_id: ChannelIdentityId,
    pub provider_namespace: String,
    pub decision: ProfileReviewDecision,
    pub reason: ProfileReviewReason,
    pub reason_detail: Option<String>,
    pub idempotency_key: String,
    pub correlation_id: CorrelationId,
}

/// Idempotent result of a safe review decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyProfileDecisionOutcome {
    Applied,
    AlreadyApplied,
    ConflictOrMissing,
    Unauthorized,
    SelfReviewForbidden,
    PublicationPrerequisitesChanged,
}

/// Public profile projection. It intentionally has no coordinates, address, media bytes, or URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedProfessionalProfile {
    pub profile_id: PublicProfileId,
    pub public_reference: PublicProfileReference,
    pub display_name: String,
    pub local_service_mode: LocalServiceMode,
    pub service_radius: ServiceRadiusKm,
    pub contact_request_limit: i16,
    pub services: Vec<ProfessionalServiceSnapshot>,
    pub languages: Vec<ProfessionalLanguage>,
    pub identity_badge: Option<String>,
    pub published_at: OffsetDateTime,
}

#[derive(FromRow)]
struct RootRow {
    id: Uuid,
}

#[derive(FromRow)]
struct DraftRow {
    profile_id: Uuid,
    public_id: Uuid,
    id: Uuid,
    revision_number: i32,
    state: String,
    display_name: Option<String>,
    local_service_mode: Option<String>,
    has_service_area: bool,
    service_radius_km: Option<i16>,
    contact_request_limit: Option<i16>,
    has_ready_photo: bool,
    version: i64,
}

pub(crate) async fn begin_or_resume_draft_in_transaction(
    connection: &mut PgConnection,
    input: BeginProfessionalDraft,
) -> Result<ProfessionalDraftSnapshot, PersistenceError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(input.account_id.to_string())
        .execute(&mut *connection)
        .await?;
    let root = sqlx::query_as::<_, RootRow>(
        r#"
        SELECT id
        FROM profile.public_profiles
        WHERE account_id = $1
        FOR UPDATE
        "#,
    )
    .bind(input.account_id.into_uuid())
    .fetch_optional(&mut *connection)
    .await?;
    let root = if let Some(root) = root {
        root
    } else {
        sqlx::query_as::<_, RootRow>(
            r#"
            INSERT INTO profile.public_profiles (id, public_id, account_id, visibility)
            VALUES ($1, $2, $3, 'hidden')
            RETURNING id
            "#,
        )
        .bind(input.profile_id.into_uuid())
        .bind(input.public_reference.into_uuid())
        .bind(input.account_id.into_uuid())
        .fetch_one(&mut *connection)
        .await?
    };
    if let Some(draft) = find_draft(connection, root.id).await? {
        return map_draft(draft);
    }
    let pending_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM profile.profile_revisions WHERE profile_id = $1 AND state = 'pending_review')",
    )
    .bind(root.id)
    .fetch_one(&mut *connection)
    .await?;
    if pending_exists {
        return Err(PersistenceError::InvalidCommand(
            "a submitted profile revision is still pending review".to_owned(),
        ));
    }
    let revision_number: i32 = sqlx::query_scalar(
        "SELECT COALESCE(max(revision_number), 0) + 1 FROM profile.profile_revisions WHERE profile_id = $1",
    )
    .bind(root.id)
    .fetch_one(&mut *connection)
    .await?;
    let source_revision_id: Option<Uuid> = sqlx::query_scalar(
        r#"
        SELECT id
        FROM profile.profile_revisions
        WHERE profile_id = $1
          AND state IN ('approved', 'changes_requested', 'rejected')
        ORDER BY revision_number DESC
        LIMIT 1
        "#,
    )
    .bind(root.id)
    .fetch_optional(&mut *connection)
    .await?;
    sqlx::query(
        r#"
        INSERT INTO profile.profile_revisions (
            id, profile_id, revision_number, display_name,
            local_service_mode, service_radius_km, contact_request_limit
        )
        SELECT $1, $2, $3, source.display_name,
               source.local_service_mode, source.service_radius_km,
               source.contact_request_limit
        FROM (SELECT 1) AS singleton
        LEFT JOIN profile.profile_revisions AS source ON source.id = $4
        "#,
    )
    .bind(input.revision_id.into_uuid())
    .bind(root.id)
    .bind(revision_number)
    .bind(source_revision_id)
    .execute(&mut *connection)
    .await?;
    if let Some(source_revision_id) = source_revision_id {
        sqlx::query(
            r#"
            INSERT INTO profile.professional_services (revision_id, category_code, contact_mode)
            SELECT $1, category_code, contact_mode
            FROM profile.professional_services WHERE revision_id = $2
            "#,
        )
        .bind(input.revision_id.into_uuid())
        .bind(source_revision_id)
        .execute(&mut *connection)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO profile.professional_service_skills (
                revision_id, category_code, skill_code
            )
            SELECT $1, category_code, skill_code
            FROM profile.professional_service_skills WHERE revision_id = $2
            "#,
        )
        .bind(input.revision_id.into_uuid())
        .bind(source_revision_id)
        .execute(&mut *connection)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO profile.professional_languages (revision_id, locale)
            SELECT $1, locale FROM profile.professional_languages WHERE revision_id = $2
            "#,
        )
        .bind(input.revision_id.into_uuid())
        .bind(source_revision_id)
        .execute(&mut *connection)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO private_data.professional_service_areas (
                revision_id, profile_id, account_id, exact_center
            )
            SELECT $1, area.profile_id, area.account_id, area.exact_center
            FROM private_data.professional_service_areas AS area
            WHERE area.revision_id = $2
            "#,
        )
        .bind(input.revision_id.into_uuid())
        .bind(source_revision_id)
        .execute(&mut *connection)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO profile.profile_revision_photos (revision_id, profile_id, photo_id)
            SELECT $1, link.profile_id, link.photo_id
            FROM profile.profile_revision_photos AS link
            JOIN private_data.profile_photos AS photo ON photo.id = link.photo_id
            WHERE link.revision_id = $2 AND photo.state = 'ready'
            "#,
        )
        .bind(input.revision_id.into_uuid())
        .bind(source_revision_id)
        .execute(&mut *connection)
        .await?;
    }
    let draft = find_draft(connection, root.id)
        .await?
        .ok_or_else(|| PersistenceError::Invariant("new profile draft is missing".to_owned()))?;
    map_draft(draft)
}

pub(crate) async fn submit_complete_draft_in_transaction(
    connection: &mut PgConnection,
    revision_id: ProfileRevisionId,
    expected_version: i64,
    owner: Option<(AccountId, PublicProfileId)>,
) -> Result<SubmitProfileOutcome, PersistenceError> {
    let locked = if let Some((account_id, profile_id)) = owner {
        let version: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT revision.version
            FROM profile.profile_revisions AS revision
            JOIN profile.public_profiles AS root ON root.id = revision.profile_id
            WHERE revision.id = $1 AND revision.profile_id = $2
              AND root.account_id = $3 AND revision.state = 'draft'
            FOR UPDATE OF revision, root
            "#,
        )
        .bind(revision_id.into_uuid())
        .bind(profile_id.into_uuid())
        .bind(account_id.into_uuid())
        .fetch_optional(&mut *connection)
        .await?;
        version == Some(expected_version)
    } else {
        lock_draft(connection, revision_id, expected_version).await?
    };
    if !locked {
        return Ok(SubmitProfileOutcome::ConflictOrMissing);
    }
    let missing = missing_submission_requirements(connection, revision_id).await?;
    if !missing.is_empty() {
        return Ok(SubmitProfileOutcome::Incomplete { missing });
    }
    let display_name: String =
        sqlx::query_scalar("SELECT display_name FROM profile.profile_revisions WHERE id = $1")
            .bind(revision_id.into_uuid())
            .fetch_one(&mut *connection)
            .await?;
    ProfessionalDisplayName::parse(display_name).map_err(|error| {
        PersistenceError::InvalidCommand(format!("profile display name is invalid: {error}"))
    })?;
    let digest = calculate_revision_digest(connection, revision_id).await?;
    sqlx::query("SELECT set_config('sahayak.profile_submission', $1, true)")
        .bind(revision_id.to_string())
        .execute(&mut *connection)
        .await?;
    let version = sqlx::query_scalar::<_, i64>(
        r#"
        UPDATE profile.profile_revisions
        SET state = 'pending_review', submitted_digest = $3,
            submitted_at = statement_timestamp()
        WHERE id = $1 AND version = $2 AND state = 'draft'
        RETURNING version
        "#,
    )
    .bind(revision_id.into_uuid())
    .bind(expected_version)
    .bind(digest.as_slice())
    .fetch_optional(connection)
    .await?;
    Ok(
        version.map_or(SubmitProfileOutcome::ConflictOrMissing, |version| {
            SubmitProfileOutcome::Submitted {
                version,
                target_digest: digest,
            }
        }),
    )
}

pub(crate) async fn missing_submission_requirements(
    connection: &mut PgConnection,
    revision_id: ProfileRevisionId,
) -> Result<Vec<ProfessionalRequirement>, PersistenceError> {
    Ok(load_eligibility(connection, revision_id).await?.missing())
}

#[derive(FromRow)]
struct ContextRow {
    account_active: bool,
    account_not_blocked: bool,
    professional_role_active: bool,
    whatsapp_identity_active_and_verified: bool,
}

#[derive(FromRow)]
struct EligibilityRow {
    account_active: bool,
    account_not_blocked: bool,
    professional_role_active: bool,
    whatsapp_identity_active_and_verified: bool,
    has_display_name: bool,
    has_active_service: bool,
    every_service_has_active_skill: bool,
    has_local_service_mode: bool,
    has_service_area: bool,
    has_language: bool,
    has_contact_request_limit: bool,
    has_terms_consent: bool,
    has_privacy_consent: bool,
    has_contact_disclosure_consent: bool,
    needs_direct_contact_consent: bool,
    has_direct_contact_consent: bool,
    needs_photo_consent: bool,
    has_photo_consent: bool,
}

#[derive(FromRow)]
struct ServiceRow {
    category_code: String,
    contact_mode: String,
}

#[derive(FromRow)]
struct PublishedRow {
    profile_id: Uuid,
    public_id: Uuid,
    revision_id: Uuid,
    display_name: String,
    local_service_mode: String,
    service_radius_km: i16,
    contact_request_limit: i16,
    badge_text: Option<String>,
    published_at: OffsetDateTime,
}

#[derive(FromRow)]
struct ConversationProfileRow {
    profile_id: Uuid,
    revision_id: Uuid,
    state: String,
    visibility: String,
    display_name: Option<String>,
    local_service_mode: Option<String>,
    has_service_area: bool,
    service_radius_km: Option<i16>,
    contact_request_limit: Option<i16>,
    has_ready_photo: bool,
    identity_badge: bool,
    version: i64,
    reason_code: Option<String>,
    reason_detail: Option<String>,
}

#[derive(FromRow)]
struct AdministratorTargetRow {
    review_token: Uuid,
    profile_id: Uuid,
    revision_id: Uuid,
    revision_number: i32,
    account_id: Uuid,
    display_name: String,
    local_service_mode: String,
    service_radius_km: i16,
    contact_request_limit: i16,
    has_ready_photo: bool,
    identity_badge: bool,
    submitted_at: OffsetDateTime,
    submitted_digest: Vec<u8>,
    version: i64,
}

#[derive(FromRow)]
struct NotificationTargetRow {
    account_id: Uuid,
    channel_identity_id: Uuid,
    provider_namespace: String,
    locale: String,
    phone_e164_ciphertext: Vec<u8>,
    phone_e164_nonce: Vec<u8>,
    encryption_key_version: i16,
}

/// Transactional PostgreSQL boundary for the professional aggregate.
#[derive(Clone, Debug)]
pub struct ProfessionalProfileRepository {
    database: Database,
}

impl ProfessionalProfileRepository {
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Resumes the one mutable draft or creates a new revision, copying the currently
    /// published reviewable fields while leaving that approved revision published.
    pub async fn begin_or_resume_draft(
        &self,
        input: BeginProfessionalDraft,
    ) -> Result<ProfessionalDraftSnapshot, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let draft = begin_or_resume_draft_in_transaction(&mut transaction, input).await?;
        transaction.commit().await?;
        Ok(draft)
    }

    /// Loads onboarding prerequisites without returning exact coordinates or private media.
    pub async fn find_privacy_safe_onboarding_context(
        &self,
        account_id: AccountId,
        channel_identity_id: ChannelIdentityId,
    ) -> Result<Option<ProfessionalOnboardingContext>, PersistenceError> {
        let context = sqlx::query_as::<_, ContextRow>(
            r#"
            SELECT
                account.status = 'active' AS account_active,
                account.risk_state NOT IN ('restricted', 'blocked') AS account_not_blocked,
                EXISTS (
                    SELECT 1 FROM identity.account_roles
                    WHERE account_id = account.id
                      AND role = 'professional'
                      AND revoked_at IS NULL
                ) AS professional_role_active,
                EXISTS (
                    SELECT 1 FROM identity.channel_identities
                    WHERE id = $2
                      AND account_id = account.id
                      AND provider_code = 'whatsapp'
                      AND status = 'active'
                      AND verified_at IS NOT NULL
                ) AS whatsapp_identity_active_and_verified
            FROM identity.accounts AS account
            WHERE account.id = $1
            "#,
        )
        .bind(account_id.into_uuid())
        .bind(channel_identity_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        let Some(context) = context else {
            return Ok(None);
        };
        let draft = sqlx::query_as::<_, DraftRow>(
            r#"
            SELECT
                root.id AS profile_id, root.public_id, revision.id,
                revision.revision_number, revision.state, revision.display_name,
                revision.local_service_mode,
                EXISTS (
                    SELECT 1 FROM private_data.professional_service_areas
                    WHERE revision_id = revision.id
                ) AS has_service_area,
                revision.service_radius_km, revision.contact_request_limit,
                EXISTS (
                    SELECT 1
                    FROM profile.profile_revision_photos AS link
                    JOIN private_data.profile_photos AS photo ON photo.id = link.photo_id
                    WHERE link.revision_id = revision.id AND photo.state = 'ready'
                ) AS has_ready_photo,
                revision.version
            FROM profile.public_profiles AS root
            JOIN profile.profile_revisions AS revision ON revision.profile_id = root.id
            WHERE root.account_id = $1 AND revision.state = 'draft'
            "#,
        )
        .bind(account_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?
        .map(map_draft)
        .transpose()?;
        let draft_revision_id = draft.as_ref().map(|value| value.revision_id.into_uuid());
        let current_consents: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT purpose
            FROM unnest(ARRAY[
                'terms', 'privacy', 'contact_disclosure', 'direct_contact',
                'photo_disclosure', 'identity_verification'
            ]::text[]) AS purpose
            WHERE private_data.has_current_professional_consent($1, purpose)
            ORDER BY purpose
            "#,
        )
        .bind(draft_revision_id)
        .fetch_all(self.database.pool())
        .await?;
        Ok(Some(ProfessionalOnboardingContext {
            account_active: context.account_active,
            account_not_blocked: context.account_not_blocked,
            professional_role_active: context.professional_role_active,
            whatsapp_identity_active_and_verified: context.whatsapp_identity_active_and_verified,
            draft,
            current_consents: current_consents
                .into_iter()
                .map(|purpose| {
                    ProfessionalConsentPurpose::from_str(&purpose).map_err(|error| {
                        PersistenceError::Invariant(format!(
                            "consent projection has invalid purpose: {error}"
                        ))
                    })
                })
                .collect::<Result<_, _>>()?,
        }))
    }

    /// Loads the professional workflow projection for this exact account and channel.
    pub async fn load_conversation_snapshot(
        &self,
        account_id: AccountId,
        channel_identity_id: ChannelIdentityId,
    ) -> Result<Option<ProfessionalConversationSnapshot>, PersistenceError> {
        let channel_allowed: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM identity.accounts AS account
                JOIN identity.channel_identities AS channel
                  ON channel.id = $2 AND channel.account_id = account.id
                 AND channel.provider_code = 'whatsapp'
                 AND channel.status = 'active' AND channel.verified_at IS NOT NULL
                WHERE account.id = $1
                  AND account.status IN ('pending', 'active')
                  AND account.risk_state NOT IN ('restricted', 'blocked')
            )
            "#,
        )
        .bind(account_id.into_uuid())
        .bind(channel_identity_id.into_uuid())
        .fetch_one(self.database.pool())
        .await?;
        if !channel_allowed {
            return Ok(None);
        }
        let row = sqlx::query_as::<_, ConversationProfileRow>(
            r#"
            SELECT
                root.id AS profile_id, revision.id AS revision_id, revision.state,
                root.visibility, revision.display_name, revision.local_service_mode,
                EXISTS (
                    SELECT 1 FROM private_data.professional_service_areas
                    WHERE revision_id = revision.id
                ) AS has_service_area,
                revision.service_radius_km, revision.contact_request_limit,
                EXISTS (
                    SELECT 1
                    FROM profile.profile_revision_photos AS link
                    JOIN private_data.profile_photos AS photo ON photo.id = link.photo_id
                    WHERE link.revision_id = revision.id AND photo.state = 'ready'
                ) AS has_ready_photo,
                EXISTS (
                    SELECT 1 FROM profile.identity_badge_projection AS badge
                    WHERE badge.account_id = root.account_id
                      AND badge.profile_revision_id = revision.id
                ) AS identity_badge,
                revision.version,
                CASE WHEN revision.state IN ('draft', 'changes_requested')
                     THEN decision.reason_code END AS reason_code,
                CASE WHEN revision.state IN ('draft', 'changes_requested')
                     THEN decision.reason_detail END AS reason_detail
            FROM profile.public_profiles AS root
            JOIN profile.profile_revisions AS revision ON revision.profile_id = root.id
            LEFT JOIN LATERAL (
                SELECT review.reason_code, review.reason_detail
                FROM profile.profile_review_decisions AS review
                JOIN profile.profile_revisions AS reviewed
                  ON reviewed.id = review.revision_id
                 AND reviewed.profile_id = root.id
                WHERE review.decision = 'changes_requested'
                ORDER BY review.decided_at DESC, review.id DESC
                LIMIT 1
            ) AS decision ON true
            WHERE root.account_id = $1
            ORDER BY
                CASE WHEN revision.state IN ('draft', 'pending_review') THEN 0 ELSE 1 END,
                revision.revision_number DESC
            LIMIT 1
            "#,
        )
        .bind(account_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        let Some(row) = row else {
            return Ok(Some(ProfessionalConversationSnapshot {
                status: ProfessionalConversationStatus::NotStarted,
                profile_id: None,
                revision_id: None,
                version: None,
                summary: None,
                missing_requirements: Vec::new(),
                current_consent_version: None,
                requested_change_fields: Vec::new(),
                review_reason: None,
                review_reason_detail: None,
            }));
        };
        let services = load_services(self.database.pool(), row.revision_id).await?;
        let languages = load_languages(self.database.pool(), row.revision_id).await?;
        let revision_id = ProfileRevisionId::from_uuid(row.revision_id);
        let missing_requirements = if row.state == "draft" {
            missing_submission_requirements_from_pool(self.database.pool(), revision_id).await?
        } else {
            Vec::new()
        };
        let current_consent_version =
            current_submission_consent_version(self.database.pool(), row.revision_id).await?;
        let status = conversation_status(&row.state, &row.visibility)?;
        let requested_change_fields = row
            .reason_code
            .as_deref()
            .map(requested_change_fields)
            .unwrap_or_default();
        Ok(Some(ProfessionalConversationSnapshot {
            status,
            profile_id: Some(PublicProfileId::from_uuid(row.profile_id)),
            revision_id: Some(revision_id),
            version: Some(row.version),
            summary: Some(ProfessionalConversationSummary {
                display_name: row.display_name,
                local_service_mode: row
                    .local_service_mode
                    .as_deref()
                    .map(parse_local_service_mode)
                    .transpose()?,
                has_service_area: row.has_service_area,
                service_radius: row.service_radius_km.map(parse_radius).transpose()?,
                contact_request_limit: row.contact_request_limit,
                services,
                languages,
                has_ready_photo: row.has_ready_photo,
                identity_badge: row.identity_badge,
            }),
            missing_requirements,
            current_consent_version,
            requested_change_fields,
            review_reason: row.reason_code,
            review_reason_detail: row.reason_detail,
        }))
    }

    /// Loads a stable pending queue only after exact administrator authorization.
    pub async fn load_administrator_conversation_snapshot(
        &self,
        account_id: AccountId,
        channel_identity_id: ChannelIdentityId,
        provider_namespace: &str,
        selected_review_token: Option<&str>,
        limit: u16,
    ) -> Result<Option<AdministratorConversationSnapshot>, PersistenceError> {
        if !(1..=100).contains(&limit) {
            return Err(PersistenceError::InvalidCommand(
                "administrator queue limit must be between 1 and 100".to_owned(),
            ));
        }
        let authorized: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM identity.accounts AS account
                JOIN identity.account_roles AS role
                  ON role.account_id = account.id AND role.role = 'administrator'
                 AND role.revoked_at IS NULL
                JOIN identity.channel_identities AS channel
                  ON channel.id = $2 AND channel.account_id = account.id
                 AND channel.provider_code = 'whatsapp'
                 AND channel.provider_namespace = $3
                 AND channel.status = 'active' AND channel.verified_at IS NOT NULL
                JOIN identity.administrator_allowlist AS allowlist
                  ON allowlist.account_id = account.id
                 AND allowlist.channel_identity_id = channel.id
                 AND allowlist.channel_code = channel.provider_code
                 AND allowlist.provider_namespace = $3
                 AND allowlist.revoked_at IS NULL
                 AND allowlist.expires_at > statement_timestamp()
                WHERE account.id = $1 AND account.status = 'active'
                  AND account.risk_state NOT IN ('restricted', 'blocked')
            )
            "#,
        )
        .bind(account_id.into_uuid())
        .bind(channel_identity_id.into_uuid())
        .bind(provider_namespace)
        .fetch_one(self.database.pool())
        .await?;
        if !authorized {
            return Ok(None);
        }
        let rows = sqlx::query_as::<_, AdministratorTargetRow>(ADMIN_TARGET_SELECT)
            .bind(Option::<Uuid>::None)
            .bind(i64::from(limit))
            .fetch_all(self.database.pool())
            .await?;
        let mut pending = Vec::with_capacity(rows.len());
        for row in rows {
            pending.push(map_administrator_target(self.database.pool(), row).await?);
        }
        let selected = if let Some(token) = selected_review_token {
            let token = Uuid::parse_str(token).map_err(|_| {
                PersistenceError::InvalidCommand("administrator review token is invalid".to_owned())
            })?;
            let row = sqlx::query_as::<_, AdministratorTargetRow>(ADMIN_TARGET_SELECT)
                .bind(Some(token))
                .bind(1_i64)
                .fetch_optional(self.database.pool())
                .await?;
            match row {
                Some(row) => Some(map_administrator_target(self.database.pool(), row).await?),
                None => None,
            }
        } else {
            None
        };
        Ok(Some(AdministratorConversationSnapshot {
            pending,
            selected,
        }))
    }

    /// Loads an encrypted active WhatsApp notification target without plaintext contact data.
    pub async fn load_active_whatsapp_notification_target(
        &self,
        revision_id: ProfileRevisionId,
        reviewer_account_id: AccountId,
        reviewer_channel_identity_id: ChannelIdentityId,
        reviewer_provider_namespace: &str,
    ) -> Result<Option<ProfessionalNotificationTarget>, PersistenceError> {
        let row = sqlx::query_as::<_, NotificationTargetRow>(
            r#"
            SELECT
                account.id AS account_id, channel.id AS channel_identity_id,
                channel.provider_namespace, account.preferred_locale AS locale,
                whatsapp.phone_e164_ciphertext, whatsapp.phone_e164_nonce,
                whatsapp.encryption_key_version
            FROM profile.profile_revisions AS revision
            JOIN profile.public_profiles AS root ON root.id = revision.profile_id
            JOIN identity.accounts AS account ON account.id = root.account_id
            JOIN identity.channel_identities AS channel
              ON channel.account_id = account.id AND channel.provider_code = 'whatsapp'
             AND channel.status = 'active' AND channel.verified_at IS NOT NULL
            JOIN private_data.whatsapp_identities AS whatsapp
              ON whatsapp.channel_identity_id = channel.id
             AND whatsapp.opt_in_status <> 'opted_out'
             AND whatsapp.delivery_state <> 'unreachable'
             AND whatsapp.blocked_at IS NULL
            WHERE revision.id = $1 AND account.status = 'active'
              AND account.risk_state NOT IN ('restricted', 'blocked')
              AND EXISTS (
                  SELECT 1
                  FROM identity.accounts AS reviewer
                  JOIN identity.account_roles AS reviewer_role
                    ON reviewer_role.account_id = reviewer.id
                   AND reviewer_role.role = 'administrator'
                   AND reviewer_role.revoked_at IS NULL
                  JOIN identity.channel_identities AS reviewer_channel
                    ON reviewer_channel.id = $3
                   AND reviewer_channel.account_id = reviewer.id
                   AND reviewer_channel.provider_code = 'whatsapp'
                   AND reviewer_channel.provider_namespace = $4
                   AND reviewer_channel.status = 'active'
                   AND reviewer_channel.verified_at IS NOT NULL
                  JOIN identity.administrator_allowlist AS allowlist
                    ON allowlist.account_id = reviewer.id
                   AND allowlist.channel_identity_id = reviewer_channel.id
                   AND allowlist.channel_code = reviewer_channel.provider_code
                   AND allowlist.provider_namespace = reviewer_channel.provider_namespace
                   AND allowlist.revoked_at IS NULL
                   AND allowlist.expires_at > statement_timestamp()
                  WHERE reviewer.id = $2
                    AND reviewer.status = 'active'
                    AND reviewer.risk_state NOT IN ('restricted', 'blocked')
              )
            ORDER BY channel.last_seen_at DESC, channel.id
            LIMIT 1
            "#,
        )
        .bind(revision_id.into_uuid())
        .bind(reviewer_account_id.into_uuid())
        .bind(reviewer_channel_identity_id.into_uuid())
        .bind(reviewer_provider_namespace)
        .fetch_optional(self.database.pool())
        .await?;
        row.map(map_notification_target).transpose()
    }

    /// Selects how this professional delivers local, in-person services.
    pub async fn update_local_service_mode(
        &self,
        revision_id: ProfileRevisionId,
        expected_version: i64,
        mode: LocalServiceMode,
    ) -> Result<ProfileMutation, PersistenceError> {
        mutate_revision(
            self.database.pool(),
            r#"
            UPDATE profile.profile_revisions
            SET local_service_mode = $3
            WHERE id = $1 AND version = $2 AND state = 'draft'
            RETURNING version
            "#,
            revision_id,
            expected_version,
            Some(mode.as_str()),
        )
        .await
    }

    /// Updates the display name under revision-level optimistic concurrency.
    pub async fn update_display_name(
        &self,
        revision_id: ProfileRevisionId,
        expected_version: i64,
        display_name: &ProfessionalDisplayName,
    ) -> Result<ProfileMutation, PersistenceError> {
        mutate_revision(
            self.database.pool(),
            r#"
            UPDATE profile.profile_revisions
            SET display_name = $3
            WHERE id = $1 AND version = $2 AND state = 'draft'
            RETURNING version
            "#,
            revision_id,
            expected_version,
            Some(display_name.as_str()),
        )
        .await
    }

    /// Replaces the exact private service center and allowed public radius.
    pub async fn update_service_area(
        &self,
        revision_id: ProfileRevisionId,
        expected_version: i64,
        latitude: f64,
        longitude: f64,
        radius: ServiceRadiusKm,
    ) -> Result<ProfileMutation, PersistenceError> {
        if !latitude.is_finite()
            || !longitude.is_finite()
            || !(-90.0..=90.0).contains(&latitude)
            || !(-180.0..=180.0).contains(&longitude)
        {
            return Err(PersistenceError::InvalidCommand(
                "service center coordinates are outside WGS84 bounds".to_owned(),
            ));
        }
        let mut transaction = self.database.pool().begin().await?;
        if !lock_draft(&mut transaction, revision_id, expected_version).await? {
            transaction.rollback().await?;
            return Ok(ProfileMutation::ConflictOrMissing);
        }
        let stored = sqlx::query(
            r#"
            INSERT INTO private_data.professional_service_areas (
                revision_id, profile_id, account_id, exact_center
            )
            SELECT
                revision.id, revision.profile_id, root.account_id,
                ST_SetSRID(ST_MakePoint($3, $2), 4326)::geography
            FROM profile.profile_revisions AS revision
            JOIN profile.public_profiles AS root ON root.id = revision.profile_id
            WHERE revision.id = $1 AND revision.state = 'draft'
            ON CONFLICT (revision_id) DO UPDATE
            SET exact_center = EXCLUDED.exact_center
            "#,
        )
        .bind(revision_id.into_uuid())
        .bind(latitude)
        .bind(longitude)
        .execute(&mut *transaction)
        .await?;
        if stored.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(ProfileMutation::ConflictOrMissing);
        }
        let version = sqlx::query_scalar::<_, i64>(
            r#"
            UPDATE profile.profile_revisions
            SET service_radius_km = $3
            WHERE id = $1 AND version = $2 AND state = 'draft'
            RETURNING version
            "#,
        )
        .bind(revision_id.into_uuid())
        .bind(expected_version)
        .bind(radius.value())
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(mutation(version))
    }

    /// Atomically replaces all selected categories and category-specific skills.
    pub async fn replace_services(
        &self,
        revision_id: ProfileRevisionId,
        expected_version: i64,
        services: &[ProfessionalServiceInput],
    ) -> Result<ProfileMutation, PersistenceError> {
        validate_services(services)?;
        let mut transaction = self.database.pool().begin().await?;
        if !lock_draft(&mut transaction, revision_id, expected_version).await? {
            transaction.rollback().await?;
            return Ok(ProfileMutation::ConflictOrMissing);
        }
        sqlx::query("DELETE FROM profile.professional_services WHERE revision_id = $1")
            .bind(revision_id.into_uuid())
            .execute(&mut *transaction)
            .await?;
        for service in services {
            let inserted = sqlx::query(
                r#"
                INSERT INTO profile.professional_services (
                    revision_id, category_code, contact_mode
                )
                SELECT $1, category.code, $3
                FROM profile.service_categories AS category
                WHERE category.code = $2 AND category.state = 'active'
                "#,
            )
            .bind(revision_id.into_uuid())
            .bind(&service.category_code)
            .bind(service.contact_mode.as_str())
            .execute(&mut *transaction)
            .await?;
            if inserted.rows_affected() != 1 {
                transaction.rollback().await?;
                return Err(PersistenceError::InvalidCommand(
                    "professional service category is not active".to_owned(),
                ));
            }
            for skill_code in &service.skill_codes {
                let inserted = sqlx::query(
                    r#"
                    INSERT INTO profile.professional_service_skills (
                        revision_id, category_code, skill_code
                    )
                    SELECT $1, skill.category_code, skill.code
                    FROM profile.service_skills AS skill
                    WHERE skill.category_code = $2
                      AND skill.code = $3
                      AND skill.state = 'active'
                    "#,
                )
                .bind(revision_id.into_uuid())
                .bind(&service.category_code)
                .bind(skill_code)
                .execute(&mut *transaction)
                .await?;
                if inserted.rows_affected() != 1 {
                    transaction.rollback().await?;
                    return Err(PersistenceError::InvalidCommand(
                        "professional skill is not active for the selected category".to_owned(),
                    ));
                }
            }
        }
        let version = touch_draft(&mut transaction, revision_id, expected_version).await?;
        transaction.commit().await?;
        Ok(mutation(version))
    }

    /// Updates the aggregate contact-session limit shared by selected categories.
    pub async fn update_contact_request_limit(
        &self,
        revision_id: ProfileRevisionId,
        expected_version: i64,
        contact_request_limit: i16,
    ) -> Result<ProfileMutation, PersistenceError> {
        if !(1..=10).contains(&contact_request_limit) {
            return Err(PersistenceError::InvalidCommand(
                "contact request limit must be between 1 and 10".to_owned(),
            ));
        }
        let version = sqlx::query_scalar::<_, i64>(
            r#"
            UPDATE profile.profile_revisions
            SET contact_request_limit = $3
            WHERE id = $1 AND version = $2 AND state = 'draft'
            RETURNING version
            "#,
        )
        .bind(revision_id.into_uuid())
        .bind(expected_version)
        .bind(contact_request_limit)
        .fetch_optional(self.database.pool())
        .await?;
        Ok(mutation(version))
    }

    /// Atomically replaces the supported professional languages.
    pub async fn replace_languages(
        &self,
        revision_id: ProfileRevisionId,
        expected_version: i64,
        languages: &[ProfessionalLanguage],
    ) -> Result<ProfileMutation, PersistenceError> {
        let unique: BTreeSet<_> = languages.iter().copied().collect();
        if unique.len() != languages.len() {
            return Err(PersistenceError::InvalidCommand(
                "professional languages must be unique".to_owned(),
            ));
        }
        let mut transaction = self.database.pool().begin().await?;
        if !lock_draft(&mut transaction, revision_id, expected_version).await? {
            transaction.rollback().await?;
            return Ok(ProfileMutation::ConflictOrMissing);
        }
        sqlx::query("DELETE FROM profile.professional_languages WHERE revision_id = $1")
            .bind(revision_id.into_uuid())
            .execute(&mut *transaction)
            .await?;
        for language in languages {
            sqlx::query(
                "INSERT INTO profile.professional_languages (revision_id, locale) VALUES ($1, $2)",
            )
            .bind(revision_id.into_uuid())
            .bind(language.as_str())
            .execute(&mut *transaction)
            .await?;
        }
        let version = touch_draft(&mut transaction, revision_id, expected_version).await?;
        transaction.commit().await?;
        Ok(mutation(version))
    }

    /// Submits only a complete draft and stores a digest covering every reviewable field.
    pub async fn submit_complete_draft(
        &self,
        account_id: AccountId,
        channel_identity_id: ChannelIdentityId,
        provider_namespace: &str,
        revision_id: ProfileRevisionId,
        expected_version: i64,
    ) -> Result<SubmitProfileOutcome, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let channel_authorized: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM identity.accounts AS account
                JOIN identity.channel_identities AS channel
                  ON channel.id = $2
                 AND channel.account_id = account.id
                 AND channel.provider_code = 'whatsapp'
                 AND channel.provider_namespace = $3
                 AND channel.status = 'active'
                 AND channel.verified_at IS NOT NULL
                WHERE account.id = $1
                  AND account.status = 'active'
                  AND account.risk_state NOT IN ('restricted', 'blocked')
            )
            "#,
        )
        .bind(account_id.into_uuid())
        .bind(channel_identity_id.into_uuid())
        .bind(provider_namespace)
        .fetch_one(&mut *transaction)
        .await?;
        if !channel_authorized {
            transaction.rollback().await?;
            return Ok(SubmitProfileOutcome::ConflictOrMissing);
        }
        let profile_id: Option<Uuid> =
            sqlx::query_scalar("SELECT profile_id FROM profile.profile_revisions WHERE id = $1")
                .bind(revision_id.into_uuid())
                .fetch_optional(&mut *transaction)
                .await?;
        let Some(profile_id) = profile_id else {
            transaction.rollback().await?;
            return Ok(SubmitProfileOutcome::ConflictOrMissing);
        };
        let outcome = submit_complete_draft_in_transaction(
            &mut transaction,
            revision_id,
            expected_version,
            Some((account_id, PublicProfileId::from_uuid(profile_id))),
        )
        .await?;
        if !matches!(outcome, SubmitProfileOutcome::Submitted { .. }) {
            transaction.rollback().await?;
            return Ok(outcome);
        }
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Applies one authorization-checked, CAS-protected, audited review decision.
    pub async fn apply_authorized_decision(
        &self,
        input: &ApplyProfileDecision,
    ) -> Result<ApplyProfileDecisionOutcome, PersistenceError> {
        validate_decision(input)?;
        let mut transaction = self.database.pool().begin().await?;
        if !reviewer_authorized(&mut transaction, input).await? {
            transaction.rollback().await?;
            return Ok(ApplyProfileDecisionOutcome::Unauthorized);
        }
        if let Some(existing) =
            sqlx::query_as::<_, (Uuid, Uuid, Uuid, String, String, Option<String>, Vec<u8>)>(
                r#"
            SELECT id, revision_id, reviewer_account_id, decision, reason_code,
                   reason_detail, target_digest
            FROM profile.profile_review_decisions
            WHERE idempotency_key = $1
            "#,
            )
            .bind(&input.idempotency_key)
            .fetch_optional(&mut *transaction)
            .await?
        {
            transaction.rollback().await?;
            if existing.0 == input.id.into_uuid()
                && existing.1 == input.revision_id.into_uuid()
                && existing.2 == input.reviewer_account_id.into_uuid()
                && existing.3 == input.decision.as_str()
                && existing.4 == input.reason.as_str()
                && existing.5 == input.reason_detail
                && existing.6.as_slice() == input.target_digest
            {
                return Ok(ApplyProfileDecisionOutcome::AlreadyApplied);
            }
            return Err(PersistenceError::InvalidCommand(
                "review idempotency key was reused with different input".to_owned(),
            ));
        }

        let target = sqlx::query_as::<_, (Uuid, Uuid, String, i64, Option<Vec<u8>>)>(
            r#"
            SELECT root.id, root.account_id, revision.state, revision.version,
                   revision.submitted_digest
            FROM profile.profile_revisions AS revision
            JOIN profile.public_profiles AS root ON root.id = revision.profile_id
            WHERE revision.id = $1
            FOR UPDATE OF revision, root
            "#,
        )
        .bind(input.revision_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((profile_id, owner_account_id, state, version, submitted_digest)) = target else {
            transaction.rollback().await?;
            return Ok(ApplyProfileDecisionOutcome::ConflictOrMissing);
        };
        if state != "pending_review"
            || version != input.expected_version
            || submitted_digest.as_deref() != Some(input.target_digest.as_slice())
        {
            transaction.rollback().await?;
            return Ok(ApplyProfileDecisionOutcome::ConflictOrMissing);
        }
        if owner_account_id == input.reviewer_account_id.into_uuid() {
            transaction.rollback().await?;
            return Ok(ApplyProfileDecisionOutcome::SelfReviewForbidden);
        }
        if input.decision == ProfileReviewDecision::Approve {
            let eligibility = load_eligibility(&mut transaction, input.revision_id).await?;
            if !eligibility.missing().is_empty() {
                transaction.rollback().await?;
                return Ok(ApplyProfileDecisionOutcome::PublicationPrerequisitesChanged);
            }
            let current_digest =
                calculate_revision_digest(&mut transaction, input.revision_id).await?;
            if current_digest != input.target_digest {
                transaction.rollback().await?;
                return Ok(ApplyProfileDecisionOutcome::ConflictOrMissing);
            }
        }

        let next_state = match input.decision {
            ProfileReviewDecision::Approve => "approved",
            ProfileReviewDecision::ChangesRequested => "changes_requested",
            ProfileReviewDecision::Reject => "rejected",
        };
        let audit_id = AuditEventId::new();
        sqlx::query(
            r#"
            INSERT INTO audit.events (
                id, actor_type, actor_account_id, actor_channel_identity_id,
                source_channel, action, target_type, target_id, reason_code,
                before_digest, after_digest, metadata, event_schema_version,
                correlation_id
            )
            VALUES (
                $1, 'administrator', $2, $3, 'whatsapp',
                'profile.review_decided', 'profile_revision', $4, $5,
                $6, $6,
                jsonb_build_object('decision', $7::text, 'profile_id', $8::text),
                1, $9
            )
            "#,
        )
        .bind(audit_id.into_uuid())
        .bind(input.reviewer_account_id.into_uuid())
        .bind(input.reviewer_channel_identity_id.into_uuid())
        .bind(input.revision_id.into_uuid())
        .bind(input.reason.as_str())
        .bind(input.target_digest.as_slice())
        .bind(input.decision.as_str())
        .bind(profile_id)
        .bind(input.correlation_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO profile.profile_review_decisions (
                id, revision_id, reviewer_account_id, reviewer_channel_identity_id,
                decision, reason_code, reason_detail, target_digest,
                idempotency_key, audit_event_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(input.id.into_uuid())
        .bind(input.revision_id.into_uuid())
        .bind(input.reviewer_account_id.into_uuid())
        .bind(input.reviewer_channel_identity_id.into_uuid())
        .bind(input.decision.as_str())
        .bind(input.reason.as_str())
        .bind(input.reason_detail.as_deref())
        .bind(input.target_digest.as_slice())
        .bind(&input.idempotency_key)
        .bind(audit_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        sqlx::query("SELECT set_config('sahayak.profile_review_decision', $1, true)")
            .bind(input.id.to_string())
            .execute(&mut *transaction)
            .await?;
        let changed = sqlx::query(
            r#"
            UPDATE profile.profile_revisions
            SET state = $3, decided_at = statement_timestamp()
            WHERE id = $1 AND version = $2 AND state = 'pending_review'
            "#,
        )
        .bind(input.revision_id.into_uuid())
        .bind(input.expected_version)
        .bind(next_state)
        .execute(&mut *transaction)
        .await?;
        if changed.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(ApplyProfileDecisionOutcome::ConflictOrMissing);
        }
        if input.decision == ProfileReviewDecision::Approve {
            sqlx::query(
                r#"
                UPDATE profile.profile_revisions AS previous
                SET state = 'superseded'
                FROM profile.public_profiles AS root
                WHERE root.id = $1
                  AND previous.id = root.published_revision_id
                  AND previous.state = 'approved'
                "#,
            )
            .bind(profile_id)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                r#"
                UPDATE profile.public_profiles
                SET
                    visibility = 'published',
                    published_revision_id = $2,
                    published_at = statement_timestamp(),
                    hidden_at = NULL
                WHERE id = $1
                "#,
            )
            .bind(profile_id)
            .bind(input.revision_id.into_uuid())
            .execute(&mut *transaction)
            .await?;
            crate::availability::invalidate_profile_epochs(
                &mut transaction,
                PublicProfileId::from_uuid(profile_id),
                "published_revision_changed",
                input.correlation_id,
            )
            .await?;
        }
        if input.decision != ProfileReviewDecision::ChangesRequested {
            crate::turn_effect::cleanup_unreferenced_revision_private_data(
                &mut transaction,
                profile_id,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(ApplyProfileDecisionOutcome::Applied)
    }

    /// Finds a currently discoverable profile by its non-sequential reference.
    pub async fn find_published_by_reference(
        &self,
        reference: PublicProfileReference,
    ) -> Result<Option<PublishedProfessionalProfile>, PersistenceError> {
        let row = sqlx::query_as::<_, PublishedRow>(
            r#"
            SELECT
                root.id AS profile_id,
                root.public_id,
                revision.id AS revision_id,
                revision.display_name,
                revision.local_service_mode,
                revision.service_radius_km,
                revision.contact_request_limit,
                badge.badge_text,
                root.published_at
            FROM profile.public_profiles AS root
            JOIN profile.profile_revisions AS revision
              ON revision.id = root.published_revision_id
             AND revision.profile_id = root.id
             AND revision.state = 'approved'
            JOIN identity.accounts AS account
              ON account.id = root.account_id
             AND account.status = 'active'
             AND account.risk_state NOT IN ('restricted', 'blocked')
            JOIN identity.account_roles AS role
              ON role.account_id = account.id
             AND role.role = 'professional'
             AND role.revoked_at IS NULL
            LEFT JOIN profile.identity_badge_projection AS badge
              ON badge.account_id = account.id
             AND badge.profile_revision_id = revision.id
            WHERE root.public_id = $1
              AND root.visibility = 'published'
              AND EXISTS (
                  SELECT 1
                  FROM profile.professional_services AS service
                  JOIN profile.service_categories AS category
                    ON category.code = service.category_code
                   AND category.state = 'active'
                  WHERE service.revision_id = revision.id
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM profile.professional_services AS service
                  LEFT JOIN profile.service_categories AS category
                    ON category.code = service.category_code
                   AND category.state = 'active'
                  WHERE service.revision_id = revision.id
                    AND (
                        category.code IS NULL
                        OR NOT EXISTS (
                            SELECT 1
                            FROM profile.professional_service_skills AS selected
                            JOIN profile.service_skills AS skill
                              ON skill.category_code = selected.category_code
                             AND skill.code = selected.skill_code
                             AND skill.state = 'active'
                            WHERE selected.revision_id = service.revision_id
                              AND selected.category_code = service.category_code
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM profile.professional_service_skills AS selected
                            LEFT JOIN profile.service_skills AS skill
                              ON skill.category_code = selected.category_code
                             AND skill.code = selected.skill_code
                             AND skill.state = 'active'
                            WHERE selected.revision_id = service.revision_id
                              AND selected.category_code = service.category_code
                              AND skill.code IS NULL
                        )
                    )
              )
              AND private_data.has_current_professional_consent(revision.id, 'terms')
              AND private_data.has_current_professional_consent(revision.id, 'privacy')
              AND private_data.has_current_professional_consent(revision.id, 'contact_disclosure')
              AND (
                  NOT EXISTS (
                      SELECT 1 FROM profile.professional_services
                      WHERE revision_id = revision.id AND contact_mode = 'direct'
                  )
                  OR private_data.has_current_professional_consent(revision.id, 'direct_contact')
              )
              AND (
                  NOT EXISTS (
                      SELECT 1
                      FROM profile.profile_revision_photos AS link
                      JOIN private_data.profile_photos AS photo ON photo.id = link.photo_id
                      WHERE link.revision_id = revision.id AND photo.state = 'ready'
                  )
                  OR private_data.has_current_professional_consent(revision.id, 'photo_disclosure')
              )
              AND EXISTS (
                  SELECT 1 FROM identity.channel_identities
                  WHERE account_id = account.id
                    AND provider_code = 'whatsapp'
                    AND status = 'active'
                    AND verified_at IS NOT NULL
              )
            "#,
        )
        .bind(reference.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let services = load_services(self.database.pool(), row.revision_id).await?;
        let languages = load_languages(self.database.pool(), row.revision_id).await?;
        Ok(Some(PublishedProfessionalProfile {
            profile_id: PublicProfileId::from_uuid(row.profile_id),
            public_reference: PublicProfileReference::from_uuid(row.public_id),
            display_name: row.display_name,
            local_service_mode: parse_local_service_mode(&row.local_service_mode)?,
            service_radius: parse_radius(row.service_radius_km)?,
            contact_request_limit: row.contact_request_limit,
            services,
            languages,
            identity_badge: row.badge_text,
            published_at: row.published_at,
        }))
    }

    /// Hides a profile and clears its published pointer under optimistic concurrency.
    pub async fn hide(
        &self,
        profile_id: PublicProfileId,
        expected_version: i64,
    ) -> Result<ProfileMutation, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let owner_account_id: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT account_id FROM profile.public_profiles WHERE id = $1")
                .bind(profile_id.into_uuid())
                .fetch_optional(&mut *transaction)
                .await?;
        if let Some(owner_account_id) = owner_account_id {
            sqlx::query("SELECT id FROM identity.accounts WHERE id = $1 FOR UPDATE")
                .bind(owner_account_id)
                .execute(&mut *transaction)
                .await?;
        }
        let version = sqlx::query_scalar::<_, i64>(
            r#"
            UPDATE profile.public_profiles
            SET
                visibility = 'hidden',
                published_revision_id = NULL,
                hidden_at = statement_timestamp()
            WHERE id = $1 AND version = $2 AND visibility = 'published'
            RETURNING version
            "#,
        )
        .bind(profile_id.into_uuid())
        .bind(expected_version)
        .fetch_optional(&mut *transaction)
        .await?;
        if version.is_some() {
            crate::availability::invalidate_profile_epochs(
                &mut transaction,
                profile_id,
                "profile_hidden",
                CorrelationId::new(),
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(mutation(version))
    }
}

const ADMIN_TARGET_SELECT: &str = r#"
    SELECT
        revision.review_token, root.id AS profile_id, revision.id AS revision_id,
        revision.revision_number, root.account_id, revision.display_name,
        revision.local_service_mode, revision.service_radius_km,
        revision.contact_request_limit,
        EXISTS (
            SELECT 1
            FROM profile.profile_revision_photos AS link
            JOIN private_data.profile_photos AS photo ON photo.id = link.photo_id
            WHERE link.revision_id = revision.id AND photo.state = 'ready'
        ) AS has_ready_photo,
        EXISTS (
            SELECT 1 FROM profile.identity_badge_projection AS badge
            WHERE badge.account_id = root.account_id
              AND badge.profile_revision_id = revision.id
        ) AS identity_badge,
        revision.submitted_at, revision.submitted_digest, revision.version
    FROM profile.profile_revisions AS revision
    JOIN profile.public_profiles AS root ON root.id = revision.profile_id
    JOIN identity.accounts AS account
      ON account.id = root.account_id
     AND account.status = 'active'
     AND account.risk_state NOT IN ('restricted', 'blocked')
    JOIN identity.account_roles AS role
      ON role.account_id = account.id
     AND role.role = 'professional'
     AND role.revoked_at IS NULL
    WHERE revision.state = 'pending_review'
      AND ($1::uuid IS NULL OR revision.review_token = $1)
      AND EXISTS (
          SELECT 1 FROM identity.channel_identities AS channel
          WHERE channel.account_id = account.id
            AND channel.provider_code = 'whatsapp'
            AND channel.status = 'active'
            AND channel.verified_at IS NOT NULL
      )
      AND NOT EXISTS (
          SELECT 1
          FROM profile.professional_services AS service
          LEFT JOIN profile.service_categories AS category
            ON category.code = service.category_code AND category.state = 'active'
          WHERE service.revision_id = revision.id
            AND (
                category.code IS NULL
                OR NOT EXISTS (
                    SELECT 1
                    FROM profile.professional_service_skills AS selected
                    JOIN profile.service_skills AS skill
                      ON skill.category_code = selected.category_code
                     AND skill.code = selected.skill_code
                     AND skill.state = 'active'
                    WHERE selected.revision_id = revision.id
                      AND selected.category_code = service.category_code
                )
                OR EXISTS (
                    SELECT 1
                    FROM profile.professional_service_skills AS selected
                    LEFT JOIN profile.service_skills AS skill
                      ON skill.category_code = selected.category_code
                     AND skill.code = selected.skill_code
                     AND skill.state = 'active'
                    WHERE selected.revision_id = revision.id
                      AND selected.category_code = service.category_code
                      AND skill.code IS NULL
                )
            )
      )
      AND private_data.has_current_professional_consent(revision.id, 'terms')
      AND private_data.has_current_professional_consent(revision.id, 'privacy')
      AND private_data.has_current_professional_consent(revision.id, 'contact_disclosure')
      AND (
          NOT EXISTS (
              SELECT 1 FROM profile.professional_services
              WHERE revision_id = revision.id AND contact_mode = 'direct'
          )
          OR private_data.has_current_professional_consent(revision.id, 'direct_contact')
      )
      AND (
          NOT EXISTS (
              SELECT 1
              FROM profile.profile_revision_photos AS link
              JOIN private_data.profile_photos AS photo ON photo.id = link.photo_id
              WHERE link.revision_id = revision.id AND photo.state = 'ready'
          )
          OR private_data.has_current_professional_consent(revision.id, 'photo_disclosure')
      )
    ORDER BY revision.submitted_at, revision.id
    LIMIT $2
"#;

async fn map_administrator_target(
    pool: &sqlx::PgPool,
    row: AdministratorTargetRow,
) -> Result<AdministratorConversationTarget, PersistenceError> {
    let services = load_services(pool, row.revision_id).await?;
    let languages = load_languages(pool, row.revision_id).await?;
    let current_consent_version = current_submission_consent_version(pool, row.revision_id).await?;
    let target_digest = row.submitted_digest.try_into().map_err(|_| {
        PersistenceError::Invariant("submitted profile digest has invalid length".to_owned())
    })?;
    Ok(AdministratorConversationTarget {
        review_token: row.review_token.to_string(),
        current_consent_version,
        identity_badge: row.identity_badge,
        target: ProfileReviewTarget {
            profile_id: PublicProfileId::from_uuid(row.profile_id),
            revision_id: ProfileRevisionId::from_uuid(row.revision_id),
            revision_number: row.revision_number,
            owner_account_id: AccountId::from_uuid(row.account_id),
            display_name: row.display_name,
            local_service_mode: parse_local_service_mode(&row.local_service_mode)?,
            service_radius: parse_radius(row.service_radius_km)?,
            contact_request_limit: row.contact_request_limit,
            services,
            languages,
            has_ready_photo: row.has_ready_photo,
            submitted_at: row.submitted_at,
            target_digest,
            version: row.version,
        },
    })
}

fn map_notification_target(
    row: NotificationTargetRow,
) -> Result<ProfessionalNotificationTarget, PersistenceError> {
    let nonce = row.phone_e164_nonce.try_into().map_err(|_| {
        PersistenceError::Invariant("encrypted phone nonce has invalid length".to_owned())
    })?;
    Ok(ProfessionalNotificationTarget {
        account_id: AccountId::from_uuid(row.account_id),
        channel_identity_id: ChannelIdentityId::from_uuid(row.channel_identity_id),
        provider_namespace: row.provider_namespace,
        locale: row.locale,
        encrypted_phone_e164: EncryptedValue {
            purpose: EncryptionPurpose::Contact,
            key_version: row.encryption_key_version,
            nonce,
            ciphertext: row.phone_e164_ciphertext,
        },
    })
}

async fn missing_submission_requirements_from_pool(
    pool: &sqlx::PgPool,
    revision_id: ProfileRevisionId,
) -> Result<Vec<ProfessionalRequirement>, PersistenceError> {
    let mut connection = pool.acquire().await?;
    missing_submission_requirements(&mut connection, revision_id).await
}

async fn current_submission_consent_version(
    pool: &sqlx::PgPool,
    revision_id: Uuid,
) -> Result<Option<String>, PersistenceError> {
    Ok(sqlx::query_scalar(
        r#"
        WITH required(purpose) AS (
            VALUES ('terms'::text), ('privacy'::text), ('contact_disclosure'::text)
            UNION ALL
            SELECT 'direct_contact'
            WHERE EXISTS (
                SELECT 1 FROM profile.professional_services
                WHERE revision_id = $1 AND contact_mode = 'direct'
            )
            UNION ALL
            SELECT 'photo_disclosure'
            WHERE EXISTS (
                SELECT 1
                FROM profile.profile_revision_photos AS link
                JOIN private_data.profile_photos AS photo ON photo.id = link.photo_id
                WHERE link.revision_id = $1 AND photo.state = 'ready'
            )
        ), accepted AS (
            SELECT required.purpose,
                   CASE WHEN latest.action = 'granted'
                          AND latest.revision_digest = profile.reviewable_revision_digest($1)
                        THEN latest.document_version END AS document_version
            FROM required
            LEFT JOIN LATERAL (
                SELECT event.action, event.document_version, event.revision_digest
                FROM private_data.professional_consent_events AS event
                JOIN profile.consent_documents AS document
                  ON document.purpose = event.purpose
                 AND document.locale = event.locale
                 AND document.document_version = event.document_version
                 AND document.document_sha256 = event.document_sha256
                 AND document.is_current
                WHERE event.revision_id = $1
                  AND event.purpose = required.purpose
                ORDER BY event.created_at DESC, event.recorded_sequence DESC
                LIMIT 1
            ) AS latest ON true
        )
        SELECT CASE
            WHEN count(document_version) = count(*)
             AND count(DISTINCT document_version) = 1
            THEN min(document_version)
            ELSE NULL
        END
        FROM accepted
        "#,
    )
    .bind(revision_id)
    .fetch_one(pool)
    .await?)
}

fn conversation_status(
    state: &str,
    visibility: &str,
) -> Result<ProfessionalConversationStatus, PersistenceError> {
    match (state, visibility) {
        ("draft", _) => Ok(ProfessionalConversationStatus::Draft),
        ("pending_review", _) => Ok(ProfessionalConversationStatus::PendingReview),
        ("changes_requested", _) => Ok(ProfessionalConversationStatus::ChangesRequested),
        ("rejected", _) => Ok(ProfessionalConversationStatus::Rejected),
        ("approved", "published") => Ok(ProfessionalConversationStatus::Approved),
        ("approved" | "superseded", "hidden") => Ok(ProfessionalConversationStatus::Hidden),
        ("superseded", "published") => Ok(ProfessionalConversationStatus::Approved),
        _ => Err(PersistenceError::Invariant(format!(
            "profile conversation status is invalid: {state}/{visibility}"
        ))),
    }
}

fn requested_change_fields(reason: &str) -> Vec<String> {
    let fields: &[&str] = match reason {
        "invalid_display_name" => &["display_name"],
        "unsupported_service" => &["services"],
        "service_area_issue" => &["service_area"],
        "photo_issue" => &["photo"],
        "incomplete_profile" => &[
            "display_name",
            "services",
            "service_area",
            "languages",
            "contact",
            "photo",
        ],
        _ => &[],
    };
    fields.iter().map(|value| (*value).to_owned()).collect()
}

impl EligibilityRow {
    fn missing(&self) -> Vec<ProfessionalRequirement> {
        let mut missing = Vec::new();
        for (present, requirement) in [
            (self.account_active, ProfessionalRequirement::ActiveAccount),
            (
                self.account_not_blocked,
                ProfessionalRequirement::NonBlockedAccount,
            ),
            (
                self.professional_role_active,
                ProfessionalRequirement::ActiveProfessionalRole,
            ),
            (
                self.whatsapp_identity_active_and_verified,
                ProfessionalRequirement::VerifiedWhatsAppIdentity,
            ),
            (self.has_display_name, ProfessionalRequirement::DisplayName),
            (
                self.has_active_service,
                ProfessionalRequirement::ActiveService,
            ),
            (
                self.every_service_has_active_skill,
                ProfessionalRequirement::ServiceSkill,
            ),
            (
                self.has_local_service_mode,
                ProfessionalRequirement::LocalServiceMode,
            ),
            (self.has_service_area, ProfessionalRequirement::ServiceArea),
            (
                self.has_language,
                ProfessionalRequirement::ProfessionalLanguage,
            ),
            (
                self.has_contact_request_limit,
                ProfessionalRequirement::ContactRequestLimit,
            ),
            (
                self.has_terms_consent,
                ProfessionalRequirement::TermsConsent,
            ),
            (
                self.has_privacy_consent,
                ProfessionalRequirement::PrivacyConsent,
            ),
            (
                self.has_contact_disclosure_consent,
                ProfessionalRequirement::ContactDisclosureConsent,
            ),
            (
                !self.needs_direct_contact_consent || self.has_direct_contact_consent,
                ProfessionalRequirement::DirectContactConsent,
            ),
            (
                !self.needs_photo_consent || self.has_photo_consent,
                ProfessionalRequirement::PhotoDisclosureConsent,
            ),
        ] {
            if !present {
                missing.push(requirement);
            }
        }
        missing
    }
}

async fn find_draft(
    connection: &mut PgConnection,
    profile_id: Uuid,
) -> Result<Option<DraftRow>, PersistenceError> {
    Ok(sqlx::query_as::<_, DraftRow>(
        r#"
        SELECT
            root.id AS profile_id, root.public_id, revision.id,
            revision.revision_number, revision.state, revision.display_name,
            revision.local_service_mode,
            EXISTS (
                SELECT 1 FROM private_data.professional_service_areas
                WHERE revision_id = revision.id
            ) AS has_service_area,
            revision.service_radius_km, revision.contact_request_limit,
            EXISTS (
                SELECT 1
                FROM profile.profile_revision_photos AS link
                JOIN private_data.profile_photos AS photo ON photo.id = link.photo_id
                WHERE link.revision_id = revision.id AND photo.state = 'ready'
            ) AS has_ready_photo,
            revision.version
        FROM profile.public_profiles AS root
        JOIN profile.profile_revisions AS revision ON revision.profile_id = root.id
        WHERE root.id = $1 AND revision.state = 'draft'
        "#,
    )
    .bind(profile_id)
    .fetch_optional(connection)
    .await?)
}

fn map_draft(row: DraftRow) -> Result<ProfessionalDraftSnapshot, PersistenceError> {
    Ok(ProfessionalDraftSnapshot {
        profile_id: PublicProfileId::from_uuid(row.profile_id),
        public_reference: PublicProfileReference::from_uuid(row.public_id),
        revision_id: ProfileRevisionId::from_uuid(row.id),
        revision_number: row.revision_number,
        state: ProfileRevisionState::from_str(&row.state).map_err(|error| {
            PersistenceError::Invariant(format!("profile revision has invalid state: {error}"))
        })?,
        display_name: row.display_name,
        local_service_mode: row
            .local_service_mode
            .as_deref()
            .map(parse_local_service_mode)
            .transpose()?,
        has_service_area: row.has_service_area,
        service_radius: row.service_radius_km.map(parse_radius).transpose()?,
        contact_request_limit: row.contact_request_limit,
        has_ready_photo: row.has_ready_photo,
        version: row.version,
    })
}

async fn mutate_revision(
    pool: &sqlx::PgPool,
    query: &'static str,
    revision_id: ProfileRevisionId,
    expected_version: i64,
    value: Option<&str>,
) -> Result<ProfileMutation, PersistenceError> {
    let version = sqlx::query_scalar::<_, i64>(query)
        .bind(revision_id.into_uuid())
        .bind(expected_version)
        .bind(value)
        .fetch_optional(pool)
        .await?;
    Ok(mutation(version))
}

const fn mutation(version: Option<i64>) -> ProfileMutation {
    match version {
        Some(version) => ProfileMutation::Applied { version },
        None => ProfileMutation::ConflictOrMissing,
    }
}

pub(crate) async fn lock_draft(
    connection: &mut PgConnection,
    revision_id: ProfileRevisionId,
    expected_version: i64,
) -> Result<bool, PersistenceError> {
    let version: Option<i64> = sqlx::query_scalar(
        r#"
        SELECT version
        FROM profile.profile_revisions
        WHERE id = $1 AND state = 'draft'
        FOR UPDATE
        "#,
    )
    .bind(revision_id.into_uuid())
    .fetch_optional(connection)
    .await?;
    Ok(version == Some(expected_version))
}

pub(crate) async fn touch_draft(
    connection: &mut PgConnection,
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

fn validate_services(services: &[ProfessionalServiceInput]) -> Result<(), PersistenceError> {
    let mut categories = BTreeSet::new();
    for service in services {
        if !categories.insert(service.category_code.as_str()) {
            return Err(PersistenceError::InvalidCommand(
                "professional service categories must be unique".to_owned(),
            ));
        }
        let skills: BTreeSet<_> = service.skill_codes.iter().map(String::as_str).collect();
        if skills.len() != service.skill_codes.len() {
            return Err(PersistenceError::InvalidCommand(
                "professional service skills must be unique".to_owned(),
            ));
        }
    }
    Ok(())
}

async fn load_eligibility(
    connection: &mut PgConnection,
    revision_id: ProfileRevisionId,
) -> Result<EligibilityRow, PersistenceError> {
    Ok(sqlx::query_as::<_, EligibilityRow>(
        r#"
        SELECT
            account.status = 'active' AS account_active,
            account.risk_state NOT IN ('restricted', 'blocked') AS account_not_blocked,
            EXISTS (
                SELECT 1 FROM identity.account_roles
                WHERE account_id = account.id
                  AND role = 'professional'
                  AND revoked_at IS NULL
            ) AS professional_role_active,
            EXISTS (
                SELECT 1 FROM identity.channel_identities
                WHERE account_id = account.id
                  AND provider_code = 'whatsapp'
                  AND status = 'active'
                  AND verified_at IS NOT NULL
            ) AS whatsapp_identity_active_and_verified,
            revision.display_name IS NOT NULL AS has_display_name,
            EXISTS (
                SELECT 1
                FROM profile.professional_services AS service
                JOIN profile.service_categories AS category
                  ON category.code = service.category_code
                 AND category.state = 'active'
                WHERE service.revision_id = revision.id
            ) AS has_active_service,
            NOT EXISTS (
                SELECT 1
                FROM profile.professional_services AS service
                WHERE service.revision_id = revision.id
                  AND (
                      NOT EXISTS (
                          SELECT 1 FROM profile.service_categories AS category
                          WHERE category.code = service.category_code
                            AND category.state = 'active'
                      )
                      OR NOT EXISTS (
                          SELECT 1
                          FROM profile.professional_service_skills AS selected
                          JOIN profile.service_skills AS skill
                            ON skill.category_code = selected.category_code
                           AND skill.code = selected.skill_code
                           AND skill.state = 'active'
                          WHERE selected.revision_id = service.revision_id
                            AND selected.category_code = service.category_code
                      )
                      OR EXISTS (
                          SELECT 1
                          FROM profile.professional_service_skills AS selected
                          LEFT JOIN profile.service_skills AS skill
                            ON skill.category_code = selected.category_code
                           AND skill.code = selected.skill_code
                           AND skill.state = 'active'
                          WHERE selected.revision_id = service.revision_id
                            AND selected.category_code = service.category_code
                            AND skill.code IS NULL
                      )
                  )
            ) AS every_service_has_active_skill,
            revision.local_service_mode IS NOT NULL AS has_local_service_mode,
            revision.service_radius_km IS NOT NULL
                AND EXISTS (
                    SELECT 1 FROM private_data.professional_service_areas
                    WHERE revision_id = revision.id
                ) AS has_service_area,
            EXISTS (
                SELECT 1 FROM profile.professional_languages
                WHERE revision_id = revision.id
            ) AS has_language,
            revision.contact_request_limit IS NOT NULL AS has_contact_request_limit,
            private_data.has_current_professional_consent(revision.id, 'terms') AS has_terms_consent,
            private_data.has_current_professional_consent(revision.id, 'privacy') AS has_privacy_consent,
            private_data.has_current_professional_consent(revision.id, 'contact_disclosure') AS has_contact_disclosure_consent,
            EXISTS (
                SELECT 1 FROM profile.professional_services
                WHERE revision_id = revision.id AND contact_mode = 'direct'
            ) AS needs_direct_contact_consent,
            private_data.has_current_professional_consent(revision.id, 'direct_contact') AS has_direct_contact_consent,
            EXISTS (
                SELECT 1
                FROM profile.profile_revision_photos AS link
                JOIN private_data.profile_photos AS photo ON photo.id = link.photo_id
                WHERE link.revision_id = revision.id AND photo.state = 'ready'
            ) AS needs_photo_consent,
            private_data.has_current_professional_consent(revision.id, 'photo_disclosure') AS has_photo_consent
        FROM profile.profile_revisions AS revision
        JOIN profile.public_profiles AS root ON root.id = revision.profile_id
        JOIN identity.accounts AS account ON account.id = root.account_id
        WHERE revision.id = $1
        "#,
    )
    .bind(revision_id.into_uuid())
    .fetch_one(connection)
    .await?)
}

pub(crate) async fn calculate_revision_digest(
    connection: &mut PgConnection,
    revision_id: ProfileRevisionId,
) -> Result<[u8; 32], PersistenceError> {
    let digest: Vec<u8> = sqlx::query_scalar("SELECT profile.reviewable_revision_digest($1)")
        .bind(revision_id.into_uuid())
        .fetch_one(connection)
        .await?;
    digest.try_into().map_err(|_| {
        PersistenceError::Invariant("profile target digest has invalid length".to_owned())
    })
}

async fn reviewer_authorized(
    connection: &mut PgConnection,
    input: &ApplyProfileDecision,
) -> Result<bool, PersistenceError> {
    Ok(sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM identity.accounts AS account
            JOIN identity.account_roles AS role
              ON role.account_id = account.id
             AND role.role = 'administrator'
             AND role.revoked_at IS NULL
            JOIN identity.channel_identities AS channel
              ON channel.id = $2
             AND channel.account_id = account.id
             AND channel.provider_code = 'whatsapp'
             AND channel.provider_namespace = $3
             AND channel.status = 'active'
             AND channel.verified_at IS NOT NULL
            JOIN identity.administrator_allowlist AS allowlist
              ON allowlist.account_id = account.id
             AND allowlist.channel_identity_id = channel.id
             AND allowlist.channel_code = channel.provider_code
             AND allowlist.provider_namespace = $3
             AND allowlist.revoked_at IS NULL
             AND allowlist.expires_at > statement_timestamp()
            WHERE account.id = $1
               AND account.status = 'active'
               AND account.risk_state NOT IN ('restricted', 'blocked')
        )
        "#,
    )
    .bind(input.reviewer_account_id.into_uuid())
    .bind(input.reviewer_channel_identity_id.into_uuid())
    .bind(&input.provider_namespace)
    .fetch_one(connection)
    .await?)
}

fn validate_decision(input: &ApplyProfileDecision) -> Result<(), PersistenceError> {
    if input.expected_version <= 0
        || !input.decision.accepts_reason(input.reason)
        || input.provider_namespace.is_empty()
        || input.provider_namespace.len() > 128
        || input.provider_namespace.trim() != input.provider_namespace
    {
        return Err(PersistenceError::InvalidCommand(
            "review decision, reason, or expected version is invalid".to_owned(),
        ));
    }
    if input.idempotency_key.is_empty()
        || input.idempotency_key.len() > 255
        || input.idempotency_key.trim() != input.idempotency_key
    {
        return Err(PersistenceError::InvalidCommand(
            "review idempotency key must contain between 1 and 255 trimmed bytes".to_owned(),
        ));
    }
    if input.decision == ProfileReviewDecision::Approve && input.reason_detail.is_some() {
        return Err(PersistenceError::InvalidCommand(
            "approval cannot contain free-form reason detail".to_owned(),
        ));
    }
    if input.reason_detail.as_deref().is_some_and(|detail| {
        detail.trim() != detail || detail.is_empty() || detail.chars().count() > 500
    }) {
        return Err(PersistenceError::InvalidCommand(
            "review reason detail must contain 1 to 500 trimmed characters".to_owned(),
        ));
    }
    Ok(())
}

async fn load_services<'e, E>(
    executor: E,
    revision_id: Uuid,
) -> Result<Vec<ProfessionalServiceSnapshot>, PersistenceError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres> + Copy,
{
    let rows = sqlx::query_as::<_, ServiceRow>(
        r#"
        SELECT category_code, contact_mode
        FROM profile.professional_services
        WHERE revision_id = $1
        ORDER BY category_code
        "#,
    )
    .bind(revision_id)
    .fetch_all(executor)
    .await?;
    let mut services = Vec::with_capacity(rows.len());
    for row in rows {
        let skill_codes = sqlx::query_scalar(
            r#"
            SELECT skill_code
            FROM profile.professional_service_skills
            WHERE revision_id = $1 AND category_code = $2
            ORDER BY skill_code
            "#,
        )
        .bind(revision_id)
        .bind(&row.category_code)
        .fetch_all(executor)
        .await?;
        services.push(ProfessionalServiceSnapshot {
            category_code: row.category_code,
            contact_mode: ContactMode::from_str(&row.contact_mode).map_err(|error| {
                PersistenceError::Invariant(format!(
                    "service contains invalid contact mode: {error}"
                ))
            })?,
            skill_codes,
        });
    }
    Ok(services)
}

async fn load_languages<'e, E>(
    executor: E,
    revision_id: Uuid,
) -> Result<Vec<ProfessionalLanguage>, PersistenceError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let values: Vec<String> = sqlx::query_scalar(
        "SELECT locale FROM profile.professional_languages WHERE revision_id = $1 ORDER BY locale",
    )
    .bind(revision_id)
    .fetch_all(executor)
    .await?;
    values
        .into_iter()
        .map(|value| {
            ProfessionalLanguage::parse(&value).ok_or_else(|| {
                PersistenceError::Invariant(format!(
                    "professional language contains unsupported locale: {value}"
                ))
            })
        })
        .collect()
}

fn parse_radius(value: i16) -> Result<ServiceRadiusKm, PersistenceError> {
    ServiceRadiusKm::from_value(value).ok_or_else(|| {
        PersistenceError::Invariant(format!("profile contains unsupported radius: {value}"))
    })
}

fn parse_local_service_mode(value: &str) -> Result<LocalServiceMode, PersistenceError> {
    LocalServiceMode::from_str(value).map_err(|error| {
        PersistenceError::Invariant(format!(
            "profile contains invalid local service mode: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{ApplyProfileDecision, validate_decision};
    use sahayak_domain::{
        AccountId, ChannelIdentityId, CorrelationId, ProfileReviewDecision,
        ProfileReviewDecisionId, ProfileReviewReason, ProfileRevisionId,
    };

    #[test]
    fn approval_requires_the_fixed_reason_and_no_detail() {
        let command = ApplyProfileDecision {
            id: ProfileReviewDecisionId::new(),
            revision_id: ProfileRevisionId::new(),
            expected_version: 1,
            target_digest: [1; 32],
            reviewer_account_id: AccountId::new(),
            reviewer_channel_identity_id: ChannelIdentityId::new(),
            provider_namespace: "test-admin".to_owned(),
            decision: ProfileReviewDecision::Approve,
            reason: ProfileReviewReason::FraudRisk,
            reason_detail: None,
            idempotency_key: "review-1".to_owned(),
            correlation_id: CorrelationId::new(),
        };
        assert!(validate_decision(&command).is_err());
    }
}
