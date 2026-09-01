use crate::{
    AttachSanitizedProfilePhoto, AvailabilityEffectContext, AvailabilityMutationOutcome,
    AvailabilityTurnEffect, BeginProfessionalDraft, ConnectionEffectContext,
    ConnectionMutationOutcome, ConnectionTurnEffect, DiscoveryEffectContext,
    DiscoveryMutationOutcome, DiscoveryTurnEffect, PersistenceError, ProfilePhotoMutation,
    QueueOutboundMessage, RecordProfessionalConsent, SubmitProfileOutcome,
};
use sahayak_cryptography::EncryptedValue;
use sahayak_domain::{
    AccountId, AuditEventId, ChannelIdentityId, ConsentAction, ContactMode, ConversationSessionId,
    CorrelationId, InboundEventId, OutboundMessageId, ProfessionalConsentEventId,
    ProfessionalConsentPurpose, ProfessionalDisplayName, ProfessionalLanguage, ProfilePhotoId,
    ProfileReviewDecision, ProfileReviewDecisionId, ProfileReviewReason, ProfileRevisionId,
    PublicProfileId, PublicProfileReference, ServiceRadiusKm,
};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use std::collections::BTreeSet;
use time::OffsetDateTime;

/// Optional business effects and non-session messages committed with one turn.
#[derive(Clone, Default)]
pub struct ConversationTurnEffects {
    pub effect: Option<ConversationTurnEffect>,
    pub role_context: Option<sahayak_domain::AccountRole>,
    pub additional_outbound: Vec<QueueOutboundMessage>,
}

/// Persistence-owned business effect; this crate has no conversation-engine dependency.
#[derive(Clone)]
pub enum ConversationTurnEffect {
    Professional(ProfessionalTurnEffect),
    AdministratorReview(AdministratorReviewTurnEffect),
    Availability(AvailabilityTurnEffect),
    Discovery(DiscoveryTurnEffect),
    Connection(Box<ConnectionTurnEffect>),
    Trust(crate::TrustTurnEffect),
}

/// One revision-scoped professional mutation.
#[derive(Clone)]
pub struct ProfessionalTurnEffect {
    pub profile_id: PublicProfileId,
    pub revision_id: ProfileRevisionId,
    /// `None` is accepted only while creating the first draft or starting an edit draft.
    pub expected_revision_version: Option<i64>,
    pub operation: ProfessionalTurnOperation,
}

/// Supported professional aggregate mutations emitted by a conversation worker.
#[derive(Clone)]
pub enum ProfessionalTurnOperation {
    StartOrResumeDraft {
        public_reference: PublicProfileReference,
    },
    StageDisplayName {
        public_reference: PublicProfileReference,
        display_name: ProfessionalDisplayName,
    },
    SetSelectedCategories {
        category_codes: Vec<String>,
    },
    SetCategorySkills {
        category_code: String,
        skill_codes: Vec<String>,
    },
    SetLocalServiceMode {
        mode: sahayak_domain::LocalServiceMode,
    },
    SetRadius {
        radius: ServiceRadiusKm,
    },
    SetCurrentInboundLocation {
        latitude: f64,
        longitude: f64,
    },
    SetLanguages {
        languages: Vec<ProfessionalLanguage>,
    },
    SetCategoryContactMode {
        category_code: String,
        mode: ContactMode,
    },
    SetContactRequestLimit {
        limit: i16,
    },
    AttachSanitizedPhoto {
        photo_id: ProfilePhotoId,
        encrypted_jpeg: EncryptedValue,
        width_pixels: i32,
        height_pixels: i32,
        plaintext_sha256: [u8; 32],
        sanitizer_version: String,
        sanitized_at: OffsetDateTime,
    },
    RemoveDraftPhoto,
    AppendRequiredConsents {
        acceptances: Vec<ProfessionalConsentAcceptance>,
        document_set_digest: [u8; 32],
        prompt_session_id: ConversationSessionId,
        prompt_outbound_message_id: OutboundMessageId,
    },
    SubmitCompleteDraft,
}

/// Exact current legal document accepted for one required profile purpose.
#[derive(Clone, Debug)]
pub struct ProfessionalConsentAcceptance {
    pub id: ProfessionalConsentEventId,
    pub purpose: ProfessionalConsentPurpose,
    pub document_version: String,
    pub document_sha256: [u8; 32],
    pub locale: ProfessionalLanguage,
    pub accepted_at: OffsetDateTime,
}

/// Stable digest of the exact localized consent documents rendered in one prompt.
#[must_use]
pub fn professional_consent_document_set_digest(
    acceptances: &[ProfessionalConsentAcceptance],
) -> [u8; 32] {
    let mut documents: Vec<_> = acceptances.iter().collect();
    documents.sort_by_key(|acceptance| acceptance.purpose.as_str());
    let mut digest = Sha256::new();
    for acceptance in documents {
        digest.update(acceptance.purpose.as_str().as_bytes());
        digest.update([0]);
        digest.update(acceptance.locale.as_str().as_bytes());
        digest.update([0]);
        digest.update(acceptance.document_version.as_bytes());
        digest.update([0]);
        digest.update(acceptance.document_sha256);
    }
    digest.finalize().into()
}

/// One prompt-bound administrator decision.
#[derive(Clone, Debug)]
pub struct AdministratorReviewTurnEffect {
    pub id: ProfileReviewDecisionId,
    pub review_token: String,
    pub revision_id: ProfileRevisionId,
    pub expected_version: i64,
    pub target_digest: [u8; 32],
    pub decision: ProfileReviewDecision,
    pub reason: ProfileReviewReason,
    pub reason_detail: Option<String>,
    pub idempotency_key: String,
    pub prompt_session_id: ConversationSessionId,
    pub prompt_outbound_message_id: OutboundMessageId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectApplyOutcome {
    Applied,
    Conflict,
    Unauthorized,
    AlreadyDecided,
    Incomplete,
    CustomerLimit,
    ProfessionalCapacity,
}

pub(crate) struct EffectContext<'a> {
    pub account_id: AccountId,
    pub channel_identity_id: ChannelIdentityId,
    pub inbound_event_id: InboundEventId,
    pub provider_namespace: &'a str,
    pub correlation_id: CorrelationId,
    pub primary_outbound_id: OutboundMessageId,
    pub primary_outbound_recipient: Option<ChannelIdentityId>,
    pub reply_to_outbound_message_id: Option<OutboundMessageId>,
}

#[derive(sqlx::FromRow)]
struct LockedReviewTarget {
    profile_id: uuid::Uuid,
    owner_account_id: uuid::Uuid,
    state: String,
    version: i64,
    submitted_digest: Option<Vec<u8>>,
}

#[derive(sqlx::FromRow)]
struct ExistingReviewDecision {
    id: uuid::Uuid,
    revision_id: uuid::Uuid,
    reviewer_account_id: uuid::Uuid,
    reviewer_channel_identity_id: uuid::Uuid,
    decision: String,
    reason_code: String,
    reason_detail: Option<String>,
    target_digest: Vec<u8>,
}

pub(crate) async fn apply(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    context: EffectContext<'_>,
    effect: &ConversationTurnEffect,
    additional_outbound: &[QueueOutboundMessage],
) -> Result<EffectApplyOutcome, PersistenceError> {
    let source_matches: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM integration.inbound_events AS inbound
            JOIN identity.channel_identities AS channel ON channel.id = $2
            WHERE inbound.id = $1
              AND inbound.account_id = $3
              AND inbound.channel_identity_id = channel.id
              AND channel.account_id = inbound.account_id
              AND channel.provider_code = inbound.provider_code
              AND channel.provider_namespace = inbound.provider_namespace
              AND channel.provider_namespace = $4
              AND channel.status = 'active'
              AND inbound.reply_to_outbound_message_id IS NOT DISTINCT FROM $5
        )
        "#,
    )
    .bind(context.inbound_event_id.into_uuid())
    .bind(context.channel_identity_id.into_uuid())
    .bind(context.account_id.into_uuid())
    .bind(context.provider_namespace)
    .bind(
        context
            .reply_to_outbound_message_id
            .map(OutboundMessageId::into_uuid),
    )
    .fetch_one(&mut **transaction)
    .await?;
    if !source_matches {
        return Ok(EffectApplyOutcome::Unauthorized);
    }
    match effect {
        ConversationTurnEffect::Professional(effect) => {
            if !additional_outbound.is_empty() {
                return Err(PersistenceError::InvalidCommand(
                    "professional mutation cannot queue review notifications".to_owned(),
                ));
            }
            apply_professional(transaction, context, effect).await
        }
        ConversationTurnEffect::AdministratorReview(effect) => {
            let [notification] = additional_outbound else {
                return Err(PersistenceError::InvalidCommand(
                    "administrator decision requires exactly one professional notification"
                        .to_owned(),
                ));
            };
            apply_administrator_review(transaction, context, effect, notification).await
        }
        ConversationTurnEffect::Availability(effect) => {
            if !additional_outbound.is_empty() {
                return Err(PersistenceError::InvalidCommand(
                    "availability mutation cannot queue unrelated notifications".to_owned(),
                ));
            }
            match crate::availability::apply_availability_effect(
                transaction,
                AvailabilityEffectContext {
                    account_id: context.account_id,
                    channel_identity_id: context.channel_identity_id,
                    inbound_event_id: context.inbound_event_id,
                    provider_namespace: context.provider_namespace,
                    correlation_id: context.correlation_id,
                },
                *effect,
            )
            .await?
            {
                AvailabilityMutationOutcome::Applied(_)
                | AvailabilityMutationOutcome::AlreadyApplied(_) => Ok(EffectApplyOutcome::Applied),
                AvailabilityMutationOutcome::Conflict => Ok(EffectApplyOutcome::Conflict),
                AvailabilityMutationOutcome::Ineligible(_) => Ok(EffectApplyOutcome::Unauthorized),
                AvailabilityMutationOutcome::CapacityPaused => Ok(EffectApplyOutcome::Incomplete),
            }
        }
        ConversationTurnEffect::Discovery(effect) => {
            if !additional_outbound.is_empty() {
                return Err(PersistenceError::InvalidCommand(
                    "discovery mutation cannot queue unrelated notifications".to_owned(),
                ));
            }
            match crate::discovery::apply_discovery_effect(
                transaction,
                DiscoveryEffectContext {
                    account_id: context.account_id,
                    channel_identity_id: context.channel_identity_id,
                    inbound_event_id: context.inbound_event_id,
                    provider_namespace: context.provider_namespace,
                    correlation_id: context.correlation_id,
                },
                effect.clone(),
            )
            .await?
            {
                DiscoveryMutationOutcome::Applied => Ok(EffectApplyOutcome::Applied),
                DiscoveryMutationOutcome::Conflict | DiscoveryMutationOutcome::NoMoreResults => {
                    Ok(EffectApplyOutcome::Conflict)
                }
                DiscoveryMutationOutcome::Ineligible => Ok(EffectApplyOutcome::Unauthorized),
            }
        }
        ConversationTurnEffect::Connection(effect) => {
            match crate::connection::apply_connection_effect(
                transaction,
                ConnectionEffectContext {
                    account_id: context.account_id,
                    channel_identity_id: context.channel_identity_id,
                    inbound_event_id: context.inbound_event_id,
                    provider_namespace: context.provider_namespace,
                    correlation_id: context.correlation_id,
                    primary_outbound_id: context.primary_outbound_id,
                    primary_outbound_recipient: context.primary_outbound_recipient,
                },
                effect,
                additional_outbound,
            )
            .await?
            {
                ConnectionMutationOutcome::DirectRevealed
                | ConnectionMutationOutcome::PreviouslyRevealed
                | ConnectionMutationOutcome::RequestCreated
                | ConnectionMutationOutcome::Accepted
                | ConnectionMutationOutcome::Declined
                | ConnectionMutationOutcome::Cancelled => Ok(EffectApplyOutcome::Applied),
                ConnectionMutationOutcome::LimitReached => Ok(EffectApplyOutcome::CustomerLimit),
                ConnectionMutationOutcome::ProfessionalAtCapacity => {
                    Ok(EffectApplyOutcome::ProfessionalCapacity)
                }
                ConnectionMutationOutcome::Conflict => Ok(EffectApplyOutcome::Conflict),
                ConnectionMutationOutcome::Ineligible => Ok(EffectApplyOutcome::Unauthorized),
            }
        }
        ConversationTurnEffect::Trust(effect) => {
            let expected_notifications = 2 * usize::from(matches!(
                effect.operation,
                crate::TrustTurnOperation::ResolveReport { .. }
            ));
            if additional_outbound.len() != expected_notifications {
                return Err(PersistenceError::InvalidCommand(
                    "trust mutation notification count is invalid".to_owned(),
                ));
            }
            if crate::trust_effect::apply_trust_effect(
                transaction,
                crate::trust_effect::TrustEffectContext {
                    account_id: context.account_id,
                    channel_identity_id: context.channel_identity_id,
                    inbound_event_id: context.inbound_event_id.into_uuid(),
                    correlation_id: context.correlation_id,
                },
                effect,
            )
            .await?
            {
                Ok(EffectApplyOutcome::Applied)
            } else {
                Ok(EffectApplyOutcome::Conflict)
            }
        }
    }
}

async fn apply_professional(
    connection: &mut PgConnection,
    context: EffectContext<'_>,
    effect: &ProfessionalTurnEffect,
) -> Result<EffectApplyOutcome, PersistenceError> {
    match &effect.operation {
        ProfessionalTurnOperation::StartOrResumeDraft { public_reference } => {
            activate_professional(connection, &context).await?;
            let draft = crate::profile::begin_or_resume_draft_in_transaction(
                connection,
                BeginProfessionalDraft {
                    profile_id: effect.profile_id,
                    public_reference: *public_reference,
                    revision_id: effect.revision_id,
                    account_id: context.account_id,
                },
            )
            .await?;
            if draft.profile_id != effect.profile_id
                || draft.revision_id != effect.revision_id
                || effect
                    .expected_revision_version
                    .is_some_and(|version| version != draft.version)
            {
                return Ok(EffectApplyOutcome::Conflict);
            }
            Ok(EffectApplyOutcome::Applied)
        }
        ProfessionalTurnOperation::StageDisplayName {
            public_reference,
            display_name,
        } => {
            activate_professional(connection, &context).await?;
            let draft = crate::profile::begin_or_resume_draft_in_transaction(
                connection,
                BeginProfessionalDraft {
                    profile_id: effect.profile_id,
                    public_reference: *public_reference,
                    revision_id: effect.revision_id,
                    account_id: context.account_id,
                },
            )
            .await?;
            let expected = effect.expected_revision_version.unwrap_or(draft.version);
            if draft.profile_id != effect.profile_id
                || draft.revision_id != effect.revision_id
                || draft.version != expected
            {
                return Ok(EffectApplyOutcome::Conflict);
            }
            mutation_outcome(
                update_scalar(
                    connection,
                    &context,
                    effect,
                    expected,
                    "display_name",
                    display_name.as_str(),
                )
                .await?,
            )
        }
        ProfessionalTurnOperation::SetSelectedCategories { category_codes } => {
            set_categories(connection, &context, effect, category_codes).await
        }
        ProfessionalTurnOperation::SetCategorySkills {
            category_code,
            skill_codes,
        } => set_skills(connection, &context, effect, category_code, skill_codes).await,
        ProfessionalTurnOperation::SetLocalServiceMode { mode } => {
            let Some(expected) = required_version(effect)? else {
                return Ok(EffectApplyOutcome::Conflict);
            };
            mutation_outcome(
                update_scalar(
                    connection,
                    &context,
                    effect,
                    expected,
                    "local_service_mode",
                    mode.as_str(),
                )
                .await?,
            )
        }
        ProfessionalTurnOperation::SetRadius { radius } => {
            let Some(expected) = required_version(effect)? else {
                return Ok(EffectApplyOutcome::Conflict);
            };
            let version = sqlx::query_scalar(
                r#"
                UPDATE profile.profile_revisions AS revision
                SET service_radius_km = $5
                FROM profile.public_profiles AS root
                WHERE revision.id = $1
                  AND revision.profile_id = $2
                  AND revision.version = $3
                  AND revision.state = 'draft'
                  AND root.id = revision.profile_id
                  AND root.account_id = $4
                RETURNING revision.version
                "#,
            )
            .bind(effect.revision_id.into_uuid())
            .bind(effect.profile_id.into_uuid())
            .bind(expected)
            .bind(context.account_id.into_uuid())
            .bind(radius.value())
            .fetch_optional(connection)
            .await?;
            mutation_outcome(version)
        }
        ProfessionalTurnOperation::SetCurrentInboundLocation {
            latitude,
            longitude,
        } => set_location(connection, &context, effect, *latitude, *longitude).await,
        ProfessionalTurnOperation::SetLanguages { languages } => {
            set_languages(connection, &context, effect, languages).await
        }
        ProfessionalTurnOperation::SetCategoryContactMode {
            category_code,
            mode,
        } => set_contact_mode(connection, &context, effect, category_code, *mode).await,
        ProfessionalTurnOperation::SetContactRequestLimit { limit } => {
            if !(1..=10).contains(limit) {
                return Err(PersistenceError::InvalidCommand(
                    "contact request limit must be between 1 and 10".to_owned(),
                ));
            }
            let Some(expected) = required_version(effect)? else {
                return Ok(EffectApplyOutcome::Conflict);
            };
            let version = sqlx::query_scalar(
                r#"
                UPDATE profile.profile_revisions AS revision
                SET contact_request_limit = $5
                FROM profile.public_profiles AS root
                WHERE revision.id = $1
                  AND revision.profile_id = $2
                  AND revision.version = $3
                  AND revision.state = 'draft'
                  AND root.id = revision.profile_id
                  AND root.account_id = $4
                RETURNING revision.version
                "#,
            )
            .bind(effect.revision_id.into_uuid())
            .bind(effect.profile_id.into_uuid())
            .bind(expected)
            .bind(context.account_id.into_uuid())
            .bind(limit)
            .fetch_optional(connection)
            .await?;
            mutation_outcome(version)
        }
        ProfessionalTurnOperation::AttachSanitizedPhoto {
            photo_id,
            encrypted_jpeg,
            width_pixels,
            height_pixels,
            plaintext_sha256,
            sanitizer_version,
            sanitized_at,
        } => {
            let Some(expected) = required_version(effect)? else {
                return Ok(EffectApplyOutcome::Conflict);
            };
            let outcome = crate::photo::attach_sanitized_in_transaction(
                connection,
                &AttachSanitizedProfilePhoto {
                    id: *photo_id,
                    account_id: context.account_id,
                    profile_id: effect.profile_id,
                    revision_id: effect.revision_id,
                    expected_revision_version: expected,
                    encrypted_jpeg: encrypted_jpeg.clone(),
                    width_pixels: *width_pixels,
                    height_pixels: *height_pixels,
                    plaintext_sha256: *plaintext_sha256,
                    sanitizer_version: sanitizer_version.clone(),
                    sanitized_at: *sanitized_at,
                    source_inbound_event_id: context.inbound_event_id,
                },
                Some(context.channel_identity_id),
            )
            .await?;
            Ok(match outcome {
                ProfilePhotoMutation::Applied { .. } => EffectApplyOutcome::Applied,
                ProfilePhotoMutation::ConflictOrMissing => EffectApplyOutcome::Conflict,
            })
        }
        ProfessionalTurnOperation::RemoveDraftPhoto => {
            let Some(expected) = required_version(effect)? else {
                return Ok(EffectApplyOutcome::Conflict);
            };
            let outcome = crate::photo::remove_in_transaction(
                connection,
                context.account_id,
                effect.revision_id,
                expected,
            )
            .await?;
            Ok(match outcome {
                ProfilePhotoMutation::Applied { .. } => EffectApplyOutcome::Applied,
                ProfilePhotoMutation::ConflictOrMissing => EffectApplyOutcome::Conflict,
            })
        }
        ProfessionalTurnOperation::AppendRequiredConsents {
            acceptances,
            document_set_digest,
            prompt_session_id,
            prompt_outbound_message_id,
        } => {
            append_required_consents(
                connection,
                &context,
                effect,
                acceptances,
                *document_set_digest,
                *prompt_session_id,
                *prompt_outbound_message_id,
            )
            .await
        }
        ProfessionalTurnOperation::SubmitCompleteDraft => {
            let Some(expected) = required_version(effect)? else {
                return Ok(EffectApplyOutcome::Conflict);
            };
            match crate::profile::submit_complete_draft_in_transaction(
                connection,
                effect.revision_id,
                expected,
                Some((context.account_id, effect.profile_id)),
            )
            .await?
            {
                SubmitProfileOutcome::Submitted { .. } => Ok(EffectApplyOutcome::Applied),
                SubmitProfileOutcome::Incomplete { .. } => Ok(EffectApplyOutcome::Incomplete),
                SubmitProfileOutcome::ConflictOrMissing => Ok(EffectApplyOutcome::Conflict),
            }
        }
    }
}

async fn activate_professional(
    connection: &mut PgConnection,
    context: &EffectContext<'_>,
) -> Result<(), PersistenceError> {
    let status: Option<String> = sqlx::query_scalar(
        r#"
        SELECT account.status
        FROM identity.accounts AS account
        JOIN identity.channel_identities AS channel
          ON channel.id = $2
         AND channel.account_id = account.id
         AND channel.provider_code = 'whatsapp'
         AND channel.provider_namespace = $3
         AND channel.status = 'active'
         AND channel.verified_at IS NOT NULL
        WHERE account.id = $1
          AND account.status IN ('pending', 'active')
          AND account.risk_state NOT IN ('restricted', 'blocked')
        FOR UPDATE OF account, channel
        "#,
    )
    .bind(context.account_id.into_uuid())
    .bind(context.channel_identity_id.into_uuid())
    .bind(context.provider_namespace)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(status) = status else {
        return Err(PersistenceError::OptimisticConflict);
    };
    if status == "pending" {
        sqlx::query(
            r#"
            UPDATE identity.accounts
            SET status = 'active', state_changed_at = statement_timestamp()
            WHERE id = $1 AND status = 'pending'
            "#,
        )
        .bind(context.account_id.into_uuid())
        .execute(&mut *connection)
        .await?;
        append_professional_audit(connection, context, "account.phone_verified_activated").await?;
    }
    let role_changed = sqlx::query(
        r#"
        INSERT INTO identity.account_roles (account_id, role)
        VALUES ($1, 'professional')
        ON CONFLICT (account_id, role) DO UPDATE
        SET granted_at = statement_timestamp(), granted_by = NULL, revoked_at = NULL
        WHERE identity.account_roles.revoked_at IS NOT NULL
        "#,
    )
    .bind(context.account_id.into_uuid())
    .execute(&mut *connection)
    .await?;
    if role_changed.rows_affected() == 1 {
        append_professional_audit(connection, context, "account.professional_role_granted").await?;
    }
    Ok(())
}

async fn append_professional_audit(
    connection: &mut PgConnection,
    context: &EffectContext<'_>,
    action: &str,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO audit.events (
            id, actor_type, actor_account_id, actor_channel_identity_id,
            source_channel, action, target_type, target_id, reason_code,
            metadata, event_schema_version, correlation_id
        )
        VALUES ($1, 'account', $2, $3, 'whatsapp', $4, 'account', $2,
                'phone_verified_professional_onboarding', '{}'::jsonb, 1, $5)
        "#,
    )
    .bind(AuditEventId::new().into_uuid())
    .bind(context.account_id.into_uuid())
    .bind(context.channel_identity_id.into_uuid())
    .bind(action)
    .bind(context.correlation_id.into_uuid())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn update_scalar(
    connection: &mut PgConnection,
    context: &EffectContext<'_>,
    effect: &ProfessionalTurnEffect,
    expected: i64,
    column: &str,
    value: &str,
) -> Result<Option<i64>, PersistenceError> {
    let query = match column {
        "display_name" => {
            r#"
            UPDATE profile.profile_revisions AS revision
            SET display_name = $5
            FROM profile.public_profiles AS root
            WHERE revision.id = $1 AND revision.profile_id = $2
              AND revision.version = $3 AND revision.state = 'draft'
              AND root.id = revision.profile_id AND root.account_id = $4
            RETURNING revision.version
            "#
        }
        "local_service_mode" => {
            r#"
            UPDATE profile.profile_revisions AS revision
            SET local_service_mode = $5
            FROM profile.public_profiles AS root
            WHERE revision.id = $1 AND revision.profile_id = $2
              AND revision.version = $3 AND revision.state = 'draft'
              AND root.id = revision.profile_id AND root.account_id = $4
            RETURNING revision.version
            "#
        }
        _ => {
            return Err(PersistenceError::Invariant(
                "unsupported professional scalar mutation".to_owned(),
            ));
        }
    };
    Ok(sqlx::query_scalar(query)
        .bind(effect.revision_id.into_uuid())
        .bind(effect.profile_id.into_uuid())
        .bind(expected)
        .bind(context.account_id.into_uuid())
        .bind(value)
        .fetch_optional(connection)
        .await?)
}

async fn set_categories(
    connection: &mut PgConnection,
    context: &EffectContext<'_>,
    effect: &ProfessionalTurnEffect,
    category_codes: &[String],
) -> Result<EffectApplyOutcome, PersistenceError> {
    let unique: BTreeSet<_> = category_codes.iter().map(String::as_str).collect();
    if unique.is_empty() || unique.len() != category_codes.len() {
        return Err(PersistenceError::InvalidCommand(
            "professional categories must be non-empty and unique".to_owned(),
        ));
    }
    let Some(expected) = required_version(effect)? else {
        return Ok(EffectApplyOutcome::Conflict);
    };
    if !lock_owned_draft(connection, context.account_id, effect, expected).await? {
        return Ok(EffectApplyOutcome::Conflict);
    }
    for code in category_codes {
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM profile.service_categories WHERE code = $1 AND state = 'active')",
        )
        .bind(code)
        .fetch_one(&mut *connection)
        .await?;
        if !active {
            return Err(PersistenceError::InvalidCommand(
                "professional service category is not active".to_owned(),
            ));
        }
    }
    sqlx::query(
        "DELETE FROM profile.professional_services WHERE revision_id = $1 AND NOT (category_code = ANY($2))",
    )
    .bind(effect.revision_id.into_uuid())
    .bind(category_codes)
    .execute(&mut *connection)
    .await?;
    for code in category_codes {
        sqlx::query(
            r#"
            INSERT INTO profile.professional_services (revision_id, category_code, contact_mode)
            VALUES ($1, $2, 'approval_required')
            ON CONFLICT (revision_id, category_code) DO NOTHING
            "#,
        )
        .bind(effect.revision_id.into_uuid())
        .bind(code)
        .execute(&mut *connection)
        .await?;
    }
    touch_outcome(connection, effect.revision_id, expected).await
}

async fn set_skills(
    connection: &mut PgConnection,
    context: &EffectContext<'_>,
    effect: &ProfessionalTurnEffect,
    category_code: &str,
    skill_codes: &[String],
) -> Result<EffectApplyOutcome, PersistenceError> {
    let unique: BTreeSet<_> = skill_codes.iter().map(String::as_str).collect();
    if unique.len() != skill_codes.len() {
        return Err(PersistenceError::InvalidCommand(
            "professional service skills must be unique".to_owned(),
        ));
    }
    let Some(expected) = required_version(effect)? else {
        return Ok(EffectApplyOutcome::Conflict);
    };
    if !lock_owned_draft(connection, context.account_id, effect, expected).await? {
        return Ok(EffectApplyOutcome::Conflict);
    }
    let selected: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM profile.professional_services WHERE revision_id = $1 AND category_code = $2)",
    )
    .bind(effect.revision_id.into_uuid())
    .bind(category_code)
    .fetch_one(&mut *connection)
    .await?;
    if !selected {
        return Err(PersistenceError::InvalidCommand(
            "professional skill category is not selected".to_owned(),
        ));
    }
    for skill in skill_codes {
        let active: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM profile.service_skills
                WHERE category_code = $1 AND code = $2 AND state = 'active'
            )
            "#,
        )
        .bind(category_code)
        .bind(skill)
        .fetch_one(&mut *connection)
        .await?;
        if !active {
            return Err(PersistenceError::InvalidCommand(
                "professional skill is not active for the selected category".to_owned(),
            ));
        }
    }
    sqlx::query(
        "DELETE FROM profile.professional_service_skills WHERE revision_id = $1 AND category_code = $2",
    )
    .bind(effect.revision_id.into_uuid())
    .bind(category_code)
    .execute(&mut *connection)
    .await?;
    for skill in skill_codes {
        sqlx::query(
            "INSERT INTO profile.professional_service_skills (revision_id, category_code, skill_code) VALUES ($1, $2, $3)",
        )
        .bind(effect.revision_id.into_uuid())
        .bind(category_code)
        .bind(skill)
        .execute(&mut *connection)
        .await?;
    }
    touch_outcome(connection, effect.revision_id, expected).await
}

async fn set_location(
    connection: &mut PgConnection,
    context: &EffectContext<'_>,
    effect: &ProfessionalTurnEffect,
    latitude: f64,
    longitude: f64,
) -> Result<EffectApplyOutcome, PersistenceError> {
    if !latitude.is_finite()
        || !longitude.is_finite()
        || !(-90.0..=90.0).contains(&latitude)
        || !(-180.0..=180.0).contains(&longitude)
    {
        return Err(PersistenceError::InvalidCommand(
            "service center coordinates are outside WGS84 bounds".to_owned(),
        ));
    }
    let Some(expected) = required_version(effect)? else {
        return Ok(EffectApplyOutcome::Conflict);
    };
    if !lock_owned_draft(connection, context.account_id, effect, expected).await? {
        return Ok(EffectApplyOutcome::Conflict);
    }
    let has_radius: bool = sqlx::query_scalar(
        "SELECT service_radius_km IS NOT NULL FROM profile.profile_revisions WHERE id = $1",
    )
    .bind(effect.revision_id.into_uuid())
    .fetch_one(&mut *connection)
    .await?;
    if !has_radius {
        return Ok(EffectApplyOutcome::Incomplete);
    }
    sqlx::query(
        r#"
        INSERT INTO private_data.professional_service_areas (
            revision_id, profile_id, account_id, exact_center
        )
        VALUES ($1, $2, $3, ST_SetSRID(ST_MakePoint($5, $4), 4326)::geography)
        ON CONFLICT (revision_id) DO UPDATE SET exact_center = EXCLUDED.exact_center
        "#,
    )
    .bind(effect.revision_id.into_uuid())
    .bind(effect.profile_id.into_uuid())
    .bind(context.account_id.into_uuid())
    .bind(latitude)
    .bind(longitude)
    .execute(&mut *connection)
    .await?;
    touch_outcome(connection, effect.revision_id, expected).await
}

async fn set_languages(
    connection: &mut PgConnection,
    context: &EffectContext<'_>,
    effect: &ProfessionalTurnEffect,
    languages: &[ProfessionalLanguage],
) -> Result<EffectApplyOutcome, PersistenceError> {
    let unique: BTreeSet<_> = languages.iter().copied().collect();
    if unique.is_empty() || unique.len() != languages.len() {
        return Err(PersistenceError::InvalidCommand(
            "professional languages must be non-empty and unique".to_owned(),
        ));
    }
    let Some(expected) = required_version(effect)? else {
        return Ok(EffectApplyOutcome::Conflict);
    };
    if !lock_owned_draft(connection, context.account_id, effect, expected).await? {
        return Ok(EffectApplyOutcome::Conflict);
    }
    sqlx::query("DELETE FROM profile.professional_languages WHERE revision_id = $1")
        .bind(effect.revision_id.into_uuid())
        .execute(&mut *connection)
        .await?;
    for language in languages {
        sqlx::query(
            "INSERT INTO profile.professional_languages (revision_id, locale) VALUES ($1, $2)",
        )
        .bind(effect.revision_id.into_uuid())
        .bind(language.as_str())
        .execute(&mut *connection)
        .await?;
    }
    touch_outcome(connection, effect.revision_id, expected).await
}

async fn set_contact_mode(
    connection: &mut PgConnection,
    context: &EffectContext<'_>,
    effect: &ProfessionalTurnEffect,
    category_code: &str,
    mode: ContactMode,
) -> Result<EffectApplyOutcome, PersistenceError> {
    let Some(expected) = required_version(effect)? else {
        return Ok(EffectApplyOutcome::Conflict);
    };
    if !lock_owned_draft(connection, context.account_id, effect, expected).await? {
        return Ok(EffectApplyOutcome::Conflict);
    }
    let changed = sqlx::query(
        r#"
        UPDATE profile.professional_services
        SET contact_mode = $3
        WHERE revision_id = $1 AND category_code = $2
        "#,
    )
    .bind(effect.revision_id.into_uuid())
    .bind(category_code)
    .bind(mode.as_str())
    .execute(&mut *connection)
    .await?;
    if changed.rows_affected() != 1 {
        return Ok(EffectApplyOutcome::Conflict);
    }
    touch_outcome(connection, effect.revision_id, expected).await
}

async fn append_required_consents(
    connection: &mut PgConnection,
    context: &EffectContext<'_>,
    effect: &ProfessionalTurnEffect,
    acceptances: &[ProfessionalConsentAcceptance],
    document_set_digest: [u8; 32],
    prompt_session_id: ConversationSessionId,
    prompt_outbound_message_id: OutboundMessageId,
) -> Result<EffectApplyOutcome, PersistenceError> {
    let Some(expected) = required_version(effect)? else {
        return Ok(EffectApplyOutcome::Conflict);
    };
    if !lock_owned_draft(connection, context.account_id, effect, expected).await? {
        return Ok(EffectApplyOutcome::Conflict);
    }
    let session_locale: Option<String> = sqlx::query_scalar(
        r#"
        SELECT language
        FROM messaging.conversation_sessions
        WHERE id = $1 AND account_id = $2 AND channel_identity_id = $3
          AND role_context = 'professional' AND workflow_key = 'professional.profile'
          AND state_key = 'consent'
          AND status = 'active' AND expires_at > statement_timestamp()
          AND workflow_correlation_id = $4
           AND expected_reply_to_outbound_message_id = $5
           AND state_data ->> 'document_set_digest' = encode($6::bytea, 'hex')
        "#,
    )
    .bind(prompt_session_id.into_uuid())
    .bind(context.account_id.into_uuid())
    .bind(context.channel_identity_id.into_uuid())
    .bind(context.correlation_id.into_uuid())
    .bind(prompt_outbound_message_id.into_uuid())
    .bind(document_set_digest.as_slice())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(session_locale) = session_locale else {
        return Ok(EffectApplyOutcome::Unauthorized);
    };
    if context.reply_to_outbound_message_id != Some(prompt_outbound_message_id) {
        return Ok(EffectApplyOutcome::Unauthorized);
    }
    if acceptances
        .iter()
        .any(|acceptance| acceptance.locale.as_str() != session_locale)
    {
        return Err(PersistenceError::InvalidCommand(
            "consent locale does not match the active professional session".to_owned(),
        ));
    }
    if professional_consent_document_set_digest(acceptances) != document_set_digest {
        return Err(PersistenceError::InvalidCommand(
            "consent document set does not match the rendered prompt".to_owned(),
        ));
    }
    let requirements: (bool, bool) = sqlx::query_as(
        r#"
        SELECT
            EXISTS (SELECT 1 FROM profile.professional_services
                    WHERE revision_id = $1 AND contact_mode = 'direct'),
            EXISTS (
                SELECT 1 FROM profile.profile_revision_photos AS link
                JOIN private_data.profile_photos AS photo ON photo.id = link.photo_id
                WHERE link.revision_id = $1 AND photo.state = 'ready'
            )
        "#,
    )
    .bind(effect.revision_id.into_uuid())
    .fetch_one(&mut *connection)
    .await?;
    let mut required = BTreeSet::from([
        ProfessionalConsentPurpose::Terms,
        ProfessionalConsentPurpose::Privacy,
        ProfessionalConsentPurpose::ContactDisclosure,
    ]);
    if requirements.0 {
        required.insert(ProfessionalConsentPurpose::DirectContact);
    }
    if requirements.1 {
        required.insert(ProfessionalConsentPurpose::PhotoDisclosure);
    }
    let supplied: BTreeSet<_> = acceptances.iter().map(|value| value.purpose).collect();
    if supplied != required || supplied.len() != acceptances.len() {
        return Err(PersistenceError::InvalidCommand(
            "consent acceptance must contain each required profile purpose exactly once".to_owned(),
        ));
    }
    for acceptance in acceptances {
        if acceptance.purpose == ProfessionalConsentPurpose::IdentityVerification {
            return Err(PersistenceError::InvalidCommand(
                "identity verification consent is not a profile submission consent".to_owned(),
            ));
        }
        crate::consent::record_in_transaction(
            connection,
            &RecordProfessionalConsent {
                id: acceptance.id,
                account_id: context.account_id,
                profile_id: effect.profile_id,
                revision_id: effect.revision_id,
                purpose: acceptance.purpose,
                action: ConsentAction::Granted,
                document_version: acceptance.document_version.clone(),
                document_sha256: acceptance.document_sha256,
                locale: acceptance.locale,
                channel_identity_id: context.channel_identity_id,
                source_inbound_event_id: context.inbound_event_id,
                idempotency_key: format!(
                    "conversation-consent:v1:{}:{}",
                    context.inbound_event_id, acceptance.purpose
                ),
                occurred_at: acceptance.accepted_at,
            },
        )
        .await?;
    }
    touch_outcome(connection, effect.revision_id, expected).await
}

async fn apply_administrator_review(
    connection: &mut PgConnection,
    context: EffectContext<'_>,
    effect: &AdministratorReviewTurnEffect,
    notification: &QueueOutboundMessage,
) -> Result<EffectApplyOutcome, PersistenceError> {
    validate_review(effect)?;
    let prompt_reason =
        (effect.decision != ProfileReviewDecision::Approve).then_some(effect.reason.as_str());
    let prompt_bound: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM messaging.conversation_sessions
            WHERE id = $1
              AND account_id = $2
              AND channel_identity_id = $3
              AND role_context = 'administrator'
              AND workflow_key = 'administrator.review'
              AND state_key = 'confirm'
              AND status = 'active'
              AND expires_at > statement_timestamp()
              AND workflow_correlation_id = $4
              AND expected_reply_to_outbound_message_id = $5
              AND state_data ->> 'target_token' = $6
              AND state_data ->> 'target_version' = $7::text
              AND state_data ->> 'decision_code' = $8
              AND (state_data ->> 'reason_code') IS NOT DISTINCT FROM $9::text
        )
        "#,
    )
    .bind(effect.prompt_session_id.into_uuid())
    .bind(context.account_id.into_uuid())
    .bind(context.channel_identity_id.into_uuid())
    .bind(context.correlation_id.into_uuid())
    .bind(effect.prompt_outbound_message_id.into_uuid())
    .bind(&effect.review_token)
    .bind(effect.expected_version)
    .bind(effect.decision.as_str())
    .bind(prompt_reason)
    .fetch_one(&mut *connection)
    .await?;
    if context.reply_to_outbound_message_id != Some(effect.prompt_outbound_message_id)
        || !prompt_bound
        || !reviewer_authorized(connection, &context).await?
    {
        return Ok(EffectApplyOutcome::Unauthorized);
    }
    let existing = sqlx::query_as::<_, ExistingReviewDecision>(
        r#"
        SELECT id, revision_id, reviewer_account_id, reviewer_channel_identity_id,
               decision, reason_code, reason_detail, target_digest
        FROM profile.profile_review_decisions WHERE idempotency_key = $1
        "#,
    )
    .bind(&effect.idempotency_key)
    .fetch_optional(&mut *connection)
    .await?;
    if let Some(existing) = existing {
        if existing.id == effect.id.into_uuid()
            && existing.revision_id == effect.revision_id.into_uuid()
            && existing.reviewer_account_id == context.account_id.into_uuid()
            && existing.reviewer_channel_identity_id == context.channel_identity_id.into_uuid()
            && existing.decision == effect.decision.as_str()
            && existing.reason_code == effect.reason.as_str()
            && existing.reason_detail == effect.reason_detail
            && existing.target_digest.as_slice() == effect.target_digest
        {
            return Ok(EffectApplyOutcome::AlreadyDecided);
        }
        return Err(PersistenceError::InvalidCommand(
            "administrator review idempotency key was reused".to_owned(),
        ));
    }
    let target = sqlx::query_as::<_, LockedReviewTarget>(
        r#"
        SELECT root.id AS profile_id, root.account_id AS owner_account_id,
               revision.state, revision.version, revision.submitted_digest
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
        WHERE revision.id = $1 AND revision.review_token::text = $2
        FOR UPDATE OF revision, root
        "#,
    )
    .bind(effect.revision_id.into_uuid())
    .bind(&effect.review_token)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(target) = target else {
        return Ok(EffectApplyOutcome::Conflict);
    };
    if target.owner_account_id == context.account_id.into_uuid() {
        return Ok(EffectApplyOutcome::Unauthorized);
    }
    if target.state != "pending_review" {
        return Ok(EffectApplyOutcome::AlreadyDecided);
    }
    if target.version != effect.expected_version
        || target.submitted_digest.as_deref() != Some(effect.target_digest.as_slice())
    {
        return Ok(EffectApplyOutcome::Conflict);
    }
    if effect.decision == ProfileReviewDecision::Approve {
        let missing =
            crate::profile::missing_submission_requirements(connection, effect.revision_id).await?;
        if !missing.is_empty() {
            return Ok(EffectApplyOutcome::Incomplete);
        }
        if crate::profile::calculate_revision_digest(connection, effect.revision_id).await?
            != effect.target_digest
        {
            return Ok(EffectApplyOutcome::Conflict);
        }
    }
    validate_notification(connection, target.owner_account_id, effect, notification).await?;
    let next_state = match effect.decision {
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
            before_digest, after_digest, metadata, event_schema_version, correlation_id
        )
        VALUES ($1, 'administrator', $2, $3, 'whatsapp',
                'profile.review_decided', 'profile_revision', $4, $5, $6, $6,
                jsonb_build_object('decision', $7::text, 'profile_id', $8::text), 1, $9)
        "#,
    )
    .bind(audit_id.into_uuid())
    .bind(context.account_id.into_uuid())
    .bind(context.channel_identity_id.into_uuid())
    .bind(effect.revision_id.into_uuid())
    .bind(effect.reason.as_str())
    .bind(effect.target_digest.as_slice())
    .bind(effect.decision.as_str())
    .bind(target.profile_id)
    .bind(context.correlation_id.into_uuid())
    .execute(&mut *connection)
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
    .bind(effect.id.into_uuid())
    .bind(effect.revision_id.into_uuid())
    .bind(context.account_id.into_uuid())
    .bind(context.channel_identity_id.into_uuid())
    .bind(effect.decision.as_str())
    .bind(effect.reason.as_str())
    .bind(effect.reason_detail.as_deref())
    .bind(effect.target_digest.as_slice())
    .bind(&effect.idempotency_key)
    .bind(audit_id.into_uuid())
    .execute(&mut *connection)
    .await?;
    sqlx::query("SELECT set_config('sahayak.profile_review_decision', $1, true)")
        .bind(effect.id.to_string())
        .execute(&mut *connection)
        .await?;
    let changed = sqlx::query(
        r#"
        UPDATE profile.profile_revisions
        SET state = $3, decided_at = statement_timestamp()
        WHERE id = $1 AND version = $2 AND state = 'pending_review'
        "#,
    )
    .bind(effect.revision_id.into_uuid())
    .bind(effect.expected_version)
    .bind(next_state)
    .execute(&mut *connection)
    .await?;
    if changed.rows_affected() != 1 {
        return Ok(EffectApplyOutcome::AlreadyDecided);
    }
    if effect.decision == ProfileReviewDecision::Approve {
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
        .bind(target.profile_id)
        .execute(&mut *connection)
        .await?;
        sqlx::query(
            r#"
            UPDATE profile.public_profiles
            SET visibility = 'published', published_revision_id = $2,
                published_at = statement_timestamp(), hidden_at = NULL
            WHERE id = $1
            "#,
        )
        .bind(target.profile_id)
        .bind(effect.revision_id.into_uuid())
        .execute(&mut *connection)
        .await?;
        crate::availability::invalidate_profile_epochs(
            connection,
            PublicProfileId::from_uuid(target.profile_id),
            "published_revision_changed",
            context.correlation_id,
        )
        .await?;
    }
    if effect.decision != ProfileReviewDecision::ChangesRequested {
        cleanup_unreferenced_revision_private_data(connection, target.profile_id).await?;
    }
    Ok(EffectApplyOutcome::Applied)
}

pub(crate) async fn cleanup_unreferenced_revision_private_data(
    connection: &mut PgConnection,
    profile_id: uuid::Uuid,
) -> Result<(), PersistenceError> {
    sqlx::query("SELECT set_config('sahayak.profile_cleanup', 'on', true)")
        .execute(&mut *connection)
        .await?;
    let photo_ids: Vec<uuid::Uuid> = sqlx::query_scalar(
        r#"
        DELETE FROM profile.profile_revision_photos AS link
        USING profile.profile_revisions AS revision, profile.public_profiles AS root
        WHERE link.revision_id = revision.id
          AND revision.profile_id = $1
          AND root.id = revision.profile_id
          AND revision.id IS DISTINCT FROM root.published_revision_id
          AND revision.state IN ('changes_requested', 'rejected', 'superseded')
        RETURNING link.photo_id
        "#,
    )
    .bind(profile_id)
    .fetch_all(&mut *connection)
    .await?;
    for photo_id in photo_ids {
        sqlx::query(
            r#"
            UPDATE private_data.profile_photos AS photo
            SET state = 'replaced', sanitized_ciphertext = NULL,
                sanitized_nonce = NULL, removed_at = statement_timestamp()
            WHERE photo.id = $1 AND photo.state = 'ready'
              AND NOT EXISTS (
                  SELECT 1 FROM profile.profile_revision_photos AS link
                  WHERE link.photo_id = photo.id
              )
            "#,
        )
        .bind(photo_id)
        .execute(&mut *connection)
        .await?;
    }
    sqlx::query(
        r#"
        DELETE FROM private_data.professional_service_areas AS area
        USING profile.profile_revisions AS revision, profile.public_profiles AS root
        WHERE area.revision_id = revision.id
          AND revision.profile_id = $1
          AND root.id = revision.profile_id
          AND revision.id IS DISTINCT FROM root.published_revision_id
          AND revision.state IN ('changes_requested', 'rejected', 'superseded')
        "#,
    )
    .bind(profile_id)
    .execute(connection)
    .await?;
    Ok(())
}

async fn reviewer_authorized(
    connection: &mut PgConnection,
    context: &EffectContext<'_>,
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
    .bind(context.account_id.into_uuid())
    .bind(context.channel_identity_id.into_uuid())
    .bind(context.provider_namespace)
    .fetch_one(connection)
    .await?)
}

async fn validate_notification(
    connection: &mut PgConnection,
    owner_account_id: uuid::Uuid,
    effect: &AdministratorReviewTurnEffect,
    notification: &QueueOutboundMessage,
) -> Result<(), PersistenceError> {
    notification.validate()?;
    if notification.idempotency_key
        != format!("professional-review-outcome:v1:{}", effect.revision_id)
        || notification.ordering_key.is_none()
        || notification.recipient_channel_identity_id.is_none()
    {
        return Err(PersistenceError::InvalidCommand(
            "professional review notification idempotency or ordering is invalid".to_owned(),
        ));
    }
    let target_matches: bool = sqlx::query_scalar(
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
            JOIN private_data.whatsapp_identities AS whatsapp
              ON whatsapp.channel_identity_id = channel.id
             AND whatsapp.opt_in_status <> 'opted_out'
             AND whatsapp.delivery_state <> 'unreachable'
             AND whatsapp.blocked_at IS NULL
            WHERE account.id = $1
              AND account.status = 'active'
              AND account.risk_state NOT IN ('restricted', 'blocked')
        )
        "#,
    )
    .bind(owner_account_id)
    .bind(
        notification
            .recipient_channel_identity_id
            .map(ChannelIdentityId::into_uuid),
    )
    .bind(&notification.provider_namespace)
    .fetch_one(connection)
    .await?;
    if !target_matches {
        return Err(PersistenceError::InvalidCommand(
            "professional review notification target is not eligible".to_owned(),
        ));
    }
    Ok(())
}

fn validate_review(effect: &AdministratorReviewTurnEffect) -> Result<(), PersistenceError> {
    if effect.expected_version <= 0
        || !effect.decision.accepts_reason(effect.reason)
        || effect.review_token.parse::<uuid::Uuid>().is_err()
        || effect.idempotency_key.is_empty()
        || effect.idempotency_key.len() > 255
        || effect.idempotency_key.trim() != effect.idempotency_key
        || (effect.decision == ProfileReviewDecision::Approve && effect.reason_detail.is_some())
        || effect.reason_detail.as_deref().is_some_and(|detail| {
            detail.is_empty() || detail.trim() != detail || detail.chars().count() > 500
        })
    {
        return Err(PersistenceError::InvalidCommand(
            "administrator review effect is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn required_version(effect: &ProfessionalTurnEffect) -> Result<Option<i64>, PersistenceError> {
    if effect
        .expected_revision_version
        .is_some_and(|value| value <= 0)
    {
        return Err(PersistenceError::InvalidCommand(
            "professional expected revision version must be positive".to_owned(),
        ));
    }
    Ok(effect.expected_revision_version)
}

async fn lock_owned_draft(
    connection: &mut PgConnection,
    account_id: AccountId,
    effect: &ProfessionalTurnEffect,
    expected: i64,
) -> Result<bool, PersistenceError> {
    let version: Option<i64> = sqlx::query_scalar(
        r#"
        SELECT revision.version
        FROM profile.profile_revisions AS revision
        JOIN profile.public_profiles AS root ON root.id = revision.profile_id
        WHERE revision.id = $1
          AND revision.profile_id = $2
          AND root.account_id = $3
          AND revision.state = 'draft'
        FOR UPDATE OF revision, root
        "#,
    )
    .bind(effect.revision_id.into_uuid())
    .bind(effect.profile_id.into_uuid())
    .bind(account_id.into_uuid())
    .fetch_optional(connection)
    .await?;
    Ok(version == Some(expected))
}

async fn touch_outcome(
    connection: &mut PgConnection,
    revision_id: ProfileRevisionId,
    expected: i64,
) -> Result<EffectApplyOutcome, PersistenceError> {
    mutation_outcome(crate::profile::touch_draft(connection, revision_id, expected).await?)
}

const fn mutation_outcome(version: Option<i64>) -> Result<EffectApplyOutcome, PersistenceError> {
    Ok(if version.is_some() {
        EffectApplyOutcome::Applied
    } else {
        EffectApplyOutcome::Conflict
    })
}
