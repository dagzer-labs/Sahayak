use sahayak_cryptography::{
    CryptoService, EncryptedValue, EncryptionContext, EncryptionKeySet, EncryptionNamespace,
    EncryptionPurpose, VersionedKey, content_sha256,
};
use sahayak_domain::{
    AccountId, AccountLifecycle, AccountRole, AdministratorGrantId, ChannelIdentityId,
    ConsentAction, ContactMode, CorrelationId, IdentityVerificationAttemptId,
    IdentityVerificationCallbackReceiptId, IdentityVerificationState, InboundEventId,
    LocalServiceMode, ProfessionalConsentEventId, ProfessionalConsentPurpose,
    ProfessionalDisplayName, ProfessionalLanguage, ProfilePhotoId, ProfileReviewDecision,
    ProfileReviewDecisionId, ProfileReviewReason, ProfileRevisionId, PublicProfileId,
    PublicProfileReference, ServiceRadiusKm,
};
use sahayak_persistence::{
    AccountMutation, AccountRepository, AdministratorAllowlistRepository,
    AdministratorGrantOutcome, ApplyProfileDecision, ApplyProfileDecisionOutcome,
    AttachSanitizedProfilePhoto, BeginProfessionalDraft, ConsentRecordOutcome, Database,
    GrantAdministratorAccess, IdentityAttemptOutcome, IdentityVerificationRepository,
    ProfessionalConsentRepository, ProfessionalProfileRepository, ProfessionalRequirement,
    ProfessionalServiceInput, ProfileMutation, ProfilePhotoMutation, ProfilePhotoRepository,
    RecordIdentityVerificationCallback, RecordProfessionalConsent,
    StartIdentityVerificationAttempt, SubmitProfileOutcome, VerificationCallbackKind,
    VerificationCallbackOutcome,
};
use secrecy::SecretString;
use sqlx::PgPool;
use std::{collections::BTreeMap, env};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const TEST_DATABASE_ENVIRONMENT: &str = "SAHAYAK_TEST_DATABASE_URL";

#[tokio::test]
async fn professional_profile_policy_and_privacy_invariants_hold()
-> Result<(), Box<dyn std::error::Error>> {
    let Some((database, pool)) = test_database().await? else {
        return Ok(());
    };
    let crypto = crypto_service()?;
    let owner = create_actor(&pool, AccountRole::Professional, "profile-owner").await?;
    let first_admin = create_actor(&pool, AccountRole::Administrator, "profile-admin-1").await?;
    let second_admin = create_actor(&pool, AccountRole::Administrator, "profile-admin-2").await?;
    let inbound = create_inbound(&pool, owner, "profile-owner", "consent").await?;

    let profiles = ProfessionalProfileRepository::new(database.clone());
    let profile_id = PublicProfileId::new();
    let public_reference = PublicProfileReference::new();
    let draft = profiles
        .begin_or_resume_draft(BeginProfessionalDraft {
            profile_id,
            public_reference,
            revision_id: ProfileRevisionId::new(),
            account_id: owner.0,
        })
        .await?;
    assert!(
        sqlx::query(
            r#"
            UPDATE profile.profile_revisions
            SET state = 'pending_review', submitted_at = statement_timestamp()
            WHERE id = $1
            "#,
        )
        .bind(draft.revision_id.into_uuid())
        .execute(&pool)
        .await
        .is_err()
    );
    assert!(
        sqlx::query(
            r#"
            UPDATE profile.profile_revisions
            SET service_radius_km = 3
            WHERE id = $1
            "#,
        )
        .bind(draft.revision_id.into_uuid())
        .execute(&pool)
        .await
        .is_err()
    );
    assert!(
        sqlx::query(
            "UPDATE profile.profile_revisions SET contact_request_limit = 11 WHERE id = $1",
        )
        .bind(draft.revision_id.into_uuid())
        .execute(&pool)
        .await
        .is_err()
    );
    assert!(
        sqlx::query(
            "INSERT INTO profile.professional_languages (revision_id, locale) VALUES ($1, 'bn-IN')",
        )
        .bind(draft.revision_id.into_uuid())
        .execute(&pool)
        .await
        .is_err()
    );
    let display_name = ProfessionalDisplayName::parse("Ravi")?;
    assert_eq!(
        profiles
            .update_display_name(draft.revision_id, draft.version, &display_name)
            .await?,
        ProfileMutation::Applied {
            version: draft.version + 1
        }
    );
    assert_eq!(
        profiles
            .update_service_area(
                draft.revision_id,
                draft.version + 1,
                18.5204,
                73.8567,
                ServiceRadiusKm::Five,
            )
            .await?,
        ProfileMutation::Applied {
            version: draft.version + 2
        }
    );
    assert_eq!(
        profiles
            .update_local_service_mode(
                draft.revision_id,
                draft.version + 2,
                LocalServiceMode::TravelToCustomer,
            )
            .await?,
        ProfileMutation::Applied {
            version: draft.version + 3
        }
    );
    assert_eq!(
        profiles
            .replace_services(
                draft.revision_id,
                draft.version + 3,
                &[ProfessionalServiceInput {
                    category_code: "plumber".to_owned(),
                    contact_mode: ContactMode::ApprovalRequired,
                    skill_codes: vec!["leak_repair".to_owned()],
                }],
            )
            .await?,
        ProfileMutation::Applied {
            version: draft.version + 4
        }
    );
    assert_eq!(
        profiles
            .replace_languages(
                draft.revision_id,
                draft.version + 4,
                &[ProfessionalLanguage::MarathiIndia],
            )
            .await?,
        ProfileMutation::Applied {
            version: draft.version + 5
        }
    );
    assert_eq!(
        profiles
            .update_contact_request_limit(draft.revision_id, draft.version + 5, 3)
            .await?,
        ProfileMutation::Applied {
            version: draft.version + 6
        }
    );

    let incomplete = profiles
        .submit_complete_draft(
            owner.0,
            owner.1,
            "profile-owner",
            draft.revision_id,
            draft.version + 6,
        )
        .await?;
    let SubmitProfileOutcome::Incomplete { missing } = incomplete else {
        return Err("draft without consent unexpectedly submitted".into());
    };
    assert!(missing.contains(&ProfessionalRequirement::TermsConsent));
    assert!(missing.contains(&ProfessionalRequirement::PrivacyConsent));
    assert!(missing.contains(&ProfessionalRequirement::ContactDisclosureConsent));
    assert!(!missing.contains(&ProfessionalRequirement::DirectContactConsent));

    let consents = ProfessionalConsentRepository::new(database.clone());
    let documents: BTreeMap<_, _> = consents
        .current_documents(ProfessionalLanguage::EnglishIndia)
        .await?
        .into_iter()
        .map(|document| (document.purpose, document))
        .collect();
    assert_eq!(documents.len(), 6);
    for document in documents.values() {
        assert_eq!(document.locale, ProfessionalLanguage::EnglishIndia);
        assert_eq!(content_sha256(document.text.as_bytes()), document.sha256);
    }
    let rendered_consent = [
        ProfessionalConsentPurpose::Terms,
        ProfessionalConsentPurpose::Privacy,
        ProfessionalConsentPurpose::ContactDisclosure,
        ProfessionalConsentPurpose::DirectContact,
        ProfessionalConsentPurpose::PhotoDisclosure,
    ]
    .into_iter()
    .filter_map(|purpose| {
        documents
            .get(&purpose)
            .map(|document| document.text.as_str())
    })
    .collect::<Vec<_>>()
    .join("\n\n");
    assert!(rendered_consent.encode_utf16().count() <= 1_024);
    let photo_document = documents
        .get(&ProfessionalConsentPurpose::PhotoDisclosure)
        .ok_or("photo consent document missing")?;
    let photo_source = create_inbound(&pool, owner, "profile-owner", "photo").await?;
    let photo_id = ProfilePhotoId::new();
    let photo_plaintext = b"\xff\xd8sanitized-jpeg\xff\xd9";
    let encrypted_photo = crypto.encrypt(
        EncryptionPurpose::Media,
        EncryptionContext::new(EncryptionNamespace::PROFILE_PHOTO, photo_id.into_uuid()),
        photo_plaintext,
    )?;
    let photos = ProfilePhotoRepository::new(database.clone());
    let ProfilePhotoMutation::Applied {
        revision_version: ready_version,
    } = photos
        .attach_sanitized(&AttachSanitizedProfilePhoto {
            id: photo_id,
            account_id: owner.0,
            profile_id,
            revision_id: draft.revision_id,
            expected_revision_version: draft.version + 6,
            encrypted_jpeg: encrypted_photo,
            width_pixels: 640,
            height_pixels: 480,
            plaintext_sha256: content_sha256(photo_plaintext),
            sanitizer_version: "jpeg-sanitizer-v1".to_owned(),
            sanitized_at: OffsetDateTime::now_utc(),
            source_inbound_event_id: photo_source,
        })
        .await?
    else {
        return Err("sanitized photo was not attached".into());
    };
    let terms_input = RecordProfessionalConsent {
        id: ProfessionalConsentEventId::new(),
        account_id: owner.0,
        profile_id,
        revision_id: draft.revision_id,
        purpose: ProfessionalConsentPurpose::Terms,
        action: ConsentAction::Granted,
        document_version: documents
            .get(&ProfessionalConsentPurpose::Terms)
            .ok_or("terms consent document missing")?
            .version
            .clone(),
        document_sha256: documents
            .get(&ProfessionalConsentPurpose::Terms)
            .ok_or("terms consent document missing")?
            .sha256,
        locale: ProfessionalLanguage::EnglishIndia,
        channel_identity_id: owner.1,
        source_inbound_event_id: inbound,
        idempotency_key: "consent:terms".to_owned(),
        occurred_at: OffsetDateTime::now_utc(),
    };
    let (first_consent, duplicate_consent) =
        tokio::join!(consents.record(&terms_input), consents.record(&terms_input),);
    let consent_outcomes = (first_consent?, duplicate_consent?);
    assert!(matches!(
        consent_outcomes,
        (
            ConsentRecordOutcome::Recorded,
            ConsentRecordOutcome::AlreadyRecorded
        ) | (
            ConsentRecordOutcome::AlreadyRecorded,
            ConsentRecordOutcome::Recorded
        )
    ));
    let mut conflicting_source_consent = terms_input.clone();
    conflicting_source_consent.id = ProfessionalConsentEventId::new();
    conflicting_source_consent.action = ConsentAction::Revoked;
    conflicting_source_consent.idempotency_key = "consent:terms:conflict".to_owned();
    assert!(consents.record(&conflicting_source_consent).await.is_err());
    for purpose in [
        ProfessionalConsentPurpose::Privacy,
        ProfessionalConsentPurpose::ContactDisclosure,
        ProfessionalConsentPurpose::PhotoDisclosure,
    ] {
        let document = documents.get(&purpose).ok_or("consent document missing")?;
        assert_eq!(
            consents
                .record(&RecordProfessionalConsent {
                    id: ProfessionalConsentEventId::new(),
                    account_id: owner.0,
                    profile_id,
                    revision_id: draft.revision_id,
                    purpose,
                    action: ConsentAction::Granted,
                    document_version: document.version.clone(),
                    document_sha256: document.sha256,
                    locale: ProfessionalLanguage::EnglishIndia,
                    channel_identity_id: owner.1,
                    source_inbound_event_id: inbound,
                    idempotency_key: format!("consent:{purpose}"),
                    occurred_at: OffsetDateTime::now_utc(),
                })
                .await?,
            ConsentRecordOutcome::Recorded
        );
    }
    let future_source = create_inbound(&pool, owner, "profile-owner", "future-consent").await?;
    let terms_document = documents
        .get(&ProfessionalConsentPurpose::Terms)
        .ok_or("terms consent document missing")?;
    assert!(
        consents
            .record(&RecordProfessionalConsent {
                id: ProfessionalConsentEventId::new(),
                account_id: owner.0,
                profile_id,
                revision_id: draft.revision_id,
                purpose: ProfessionalConsentPurpose::Terms,
                action: ConsentAction::Granted,
                document_version: terms_document.version.clone(),
                document_sha256: terms_document.sha256,
                locale: ProfessionalLanguage::EnglishIndia,
                channel_identity_id: owner.1,
                source_inbound_event_id: future_source,
                idempotency_key: "consent:future".to_owned(),
                occurred_at: OffsetDateTime::now_utc() + Duration::hours(1),
            })
            .await
            .is_err()
    );
    let ProfileMutation::Applied {
        version: consent_invalidated_version,
    } = profiles
        .update_contact_request_limit(draft.revision_id, ready_version, 5)
        .await?
    else {
        return Err("post-consent profile mutation conflicted".into());
    };
    let SubmitProfileOutcome::Incomplete { missing } = profiles
        .submit_complete_draft(
            owner.0,
            owner.1,
            "profile-owner",
            draft.revision_id,
            consent_invalidated_version,
        )
        .await?
    else {
        return Err("stale snapshot consent unexpectedly allowed submission".into());
    };
    assert!(missing.contains(&ProfessionalRequirement::TermsConsent));
    let refreshed_source =
        create_inbound(&pool, owner, "profile-owner", "refreshed-consent").await?;
    for purpose in [
        ProfessionalConsentPurpose::Terms,
        ProfessionalConsentPurpose::Privacy,
        ProfessionalConsentPurpose::ContactDisclosure,
        ProfessionalConsentPurpose::PhotoDisclosure,
    ] {
        let document = documents.get(&purpose).ok_or("consent document missing")?;
        consents
            .record(&RecordProfessionalConsent {
                id: ProfessionalConsentEventId::new(),
                account_id: owner.0,
                profile_id,
                revision_id: draft.revision_id,
                purpose,
                action: ConsentAction::Granted,
                document_version: document.version.clone(),
                document_sha256: document.sha256,
                locale: ProfessionalLanguage::EnglishIndia,
                channel_identity_id: owner.1,
                source_inbound_event_id: refreshed_source,
                idempotency_key: format!("refreshed-consent:{purpose}"),
                occurred_at: OffsetDateTime::now_utc(),
            })
            .await?;
    }
    sqlx::query("UPDATE identity.accounts SET risk_state = 'restricted' WHERE id = $1")
        .bind(owner.0.into_uuid())
        .execute(&pool)
        .await?;
    assert_eq!(
        profiles
            .submit_complete_draft(
                owner.0,
                owner.1,
                "profile-owner",
                draft.revision_id,
                consent_invalidated_version,
            )
            .await?,
        SubmitProfileOutcome::ConflictOrMissing
    );
    sqlx::query("UPDATE identity.accounts SET risk_state = 'normal' WHERE id = $1")
        .bind(owner.0.into_uuid())
        .execute(&pool)
        .await?;
    assert!(
        sqlx::query(
            r#"
            UPDATE profile.profile_revisions
            SET state = 'pending_review',
                submitted_digest = profile.reviewable_revision_digest(id),
                submitted_at = statement_timestamp()
            WHERE id = $1
            "#,
        )
        .bind(draft.revision_id.into_uuid())
        .execute(&pool)
        .await
        .is_err()
    );
    let submitted = profiles
        .submit_complete_draft(
            owner.0,
            owner.1,
            "profile-owner",
            draft.revision_id,
            consent_invalidated_version,
        )
        .await?;
    let SubmitProfileOutcome::Submitted {
        version: submitted_version,
        target_digest,
    } = submitted
    else {
        return Err("complete draft was not submitted".into());
    };
    let mut bypass = pool.begin().await?;
    sqlx::query("SELECT set_config('sahayak.profile_review_decision', $1, true)")
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *bypass)
        .await?;
    assert!(
        sqlx::query(
            "UPDATE profile.profile_revisions SET state = 'approved', decided_at = statement_timestamp() WHERE id = $1",
        )
        .bind(draft.revision_id.into_uuid())
        .execute(&mut *bypass)
        .await
        .is_err()
    );
    bypass.rollback().await?;
    assert!(
        sqlx::query(
            r#"
            UPDATE profile.public_profiles
            SET visibility = 'published', published_revision_id = $2,
                published_at = statement_timestamp()
            WHERE id = $1
            "#,
        )
        .bind(profile_id.into_uuid())
        .bind(draft.revision_id.into_uuid())
        .execute(&pool)
        .await
        .is_err()
    );
    assert!(
        profiles
            .begin_or_resume_draft(BeginProfessionalDraft {
                profile_id: PublicProfileId::new(),
                public_reference: PublicProfileReference::new(),
                revision_id: ProfileRevisionId::new(),
                account_id: owner.0,
            })
            .await
            .is_err()
    );
    let guard_owner = create_actor(&pool, AccountRole::Professional, "child-guard-owner").await?;
    let guard_draft = profiles
        .begin_or_resume_draft(BeginProfessionalDraft {
            profile_id: PublicProfileId::new(),
            public_reference: PublicProfileReference::new(),
            revision_id: ProfileRevisionId::new(),
            account_id: guard_owner.0,
        })
        .await?;
    assert!(
        sqlx::query(
            "UPDATE profile.professional_languages SET revision_id = $2 WHERE revision_id = $1",
        )
        .bind(draft.revision_id.into_uuid())
        .bind(guard_draft.revision_id.into_uuid())
        .execute(&pool)
        .await
        .is_err()
    );
    sqlx::query(
        "INSERT INTO profile.professional_languages (revision_id, locale) VALUES ($1, 'en-IN')",
    )
    .bind(guard_draft.revision_id.into_uuid())
    .execute(&pool)
    .await?;
    assert!(
        sqlx::query(
            "UPDATE profile.professional_languages SET revision_id = $2 WHERE revision_id = $1",
        )
        .bind(guard_draft.revision_id.into_uuid())
        .bind(draft.revision_id.into_uuid())
        .execute(&pool)
        .await
        .is_err()
    );

    let exact_center: (f64, f64) = sqlx::query_as(
        r#"
        SELECT ST_Y(exact_center::geometry), ST_X(exact_center::geometry)
        FROM private_data.professional_service_areas
        WHERE revision_id = $1
        "#,
    )
    .bind(draft.revision_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(exact_center, (18.5204, 73.8567));
    let digest_definition: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('profile.reviewable_revision_digest(uuid)'::regprocedure)",
    )
    .fetch_one(&pool)
    .await?;
    assert!(!digest_definition.contains("exact_center"));
    assert!(!digest_definition.contains("ST_AsEWKB"));
    assert_eq!(target_digest.len(), 32);

    let allowlist = AdministratorAllowlistRepository::new(database.clone());
    for (index, administrator) in [first_admin, second_admin].into_iter().enumerate() {
        assert_eq!(
            allowlist
                .grant(&GrantAdministratorAccess {
                    id: AdministratorGrantId::new(),
                    account_id: administrator.0,
                    channel_identity_id: administrator.1,
                    granted_by_account_id: None,
                    expires_at: OffsetDateTime::now_utc() + Duration::days(30),
                    idempotency_key: format!("admin-grant-{index}-{}", administrator.0),
                    correlation_id: CorrelationId::new(),
                })
                .await?,
            AdministratorGrantOutcome::Applied
        );
    }
    sqlx::query("UPDATE identity.accounts SET risk_state = 'restricted' WHERE id = $1")
        .bind(owner.0.into_uuid())
        .execute(&pool)
        .await?;
    assert_eq!(
        profiles
            .apply_authorized_decision(&decision(
                draft.revision_id,
                submitted_version,
                target_digest,
                first_admin,
                "restricted-owner-review",
            ))
            .await?,
        ApplyProfileDecisionOutcome::PublicationPrerequisitesChanged
    );
    sqlx::query("UPDATE identity.accounts SET risk_state = 'normal' WHERE id = $1")
        .bind(owner.0.into_uuid())
        .execute(&pool)
        .await?;
    let unauthorized = create_actor(&pool, AccountRole::Administrator, "not-allowlisted").await?;
    let unauthorized_decision = decision(
        draft.revision_id,
        submitted_version,
        target_digest,
        unauthorized,
        "unauthorized-review",
    );
    assert_eq!(
        profiles
            .apply_authorized_decision(&unauthorized_decision)
            .await?,
        ApplyProfileDecisionOutcome::Unauthorized
    );
    sqlx::query(
        "INSERT INTO identity.account_roles (account_id, role) VALUES ($1, 'administrator')",
    )
    .bind(owner.0.into_uuid())
    .execute(&pool)
    .await?;
    let owner_admin_grant = AdministratorGrantId::new();
    assert_eq!(
        allowlist
            .grant(&GrantAdministratorAccess {
                id: owner_admin_grant,
                account_id: owner.0,
                channel_identity_id: owner.1,
                granted_by_account_id: None,
                expires_at: OffsetDateTime::now_utc() + Duration::days(30),
                idempotency_key: format!("owner-admin-grant:{}", owner.0),
                correlation_id: CorrelationId::new(),
            })
            .await?,
        AdministratorGrantOutcome::Applied
    );
    let self_decision = decision(
        draft.revision_id,
        submitted_version,
        target_digest,
        owner,
        "self-review",
    );
    assert_eq!(
        profiles.apply_authorized_decision(&self_decision).await?,
        ApplyProfileDecisionOutcome::SelfReviewForbidden
    );

    let first_decision = decision(
        draft.revision_id,
        submitted_version,
        target_digest,
        first_admin,
        "review-race-first",
    );
    let second_decision = decision(
        draft.revision_id,
        submitted_version,
        target_digest,
        second_admin,
        "review-race-second",
    );
    let (first_outcome, second_outcome) = tokio::join!(
        profiles.apply_authorized_decision(&first_decision),
        profiles.apply_authorized_decision(&second_decision)
    );
    let first_outcome = first_outcome?;
    let second_outcome = second_outcome?;
    assert!(matches!(
        (first_outcome, second_outcome),
        (
            ApplyProfileDecisionOutcome::Applied,
            ApplyProfileDecisionOutcome::ConflictOrMissing
        ) | (
            ApplyProfileDecisionOutcome::ConflictOrMissing,
            ApplyProfileDecisionOutcome::Applied
        )
    ));
    let winner = if first_outcome == ApplyProfileDecisionOutcome::Applied {
        &first_decision
    } else {
        &second_decision
    };
    assert_eq!(
        profiles.apply_authorized_decision(winner).await?,
        ApplyProfileDecisionOutcome::AlreadyApplied
    );

    let published = profiles
        .find_published_by_reference(public_reference)
        .await?
        .ok_or("phone-verified profile was not published")?;
    assert_eq!(published.display_name, "Ravi");
    assert!(published.identity_badge.is_none());

    let edit = profiles
        .begin_or_resume_draft(BeginProfessionalDraft {
            profile_id: PublicProfileId::new(),
            public_reference: PublicProfileReference::new(),
            revision_id: ProfileRevisionId::new(),
            account_id: owner.0,
        })
        .await?;
    assert_eq!(edit.revision_number, 2);
    assert!(edit.has_ready_photo);
    let edited_name = ProfessionalDisplayName::parse("Ravi P")?;
    let ProfileMutation::Applied {
        version: edit_version,
    } = profiles
        .update_display_name(edit.revision_id, edit.version, &edited_name)
        .await?
    else {
        return Err("edit display name was not updated".into());
    };
    let SubmitProfileOutcome::Incomplete { missing } = profiles
        .submit_complete_draft(
            owner.0,
            owner.1,
            "profile-owner",
            edit.revision_id,
            edit_version,
        )
        .await?
    else {
        return Err("an edited revision reused consent from its predecessor".into());
    };
    assert!(missing.contains(&ProfessionalRequirement::TermsConsent));
    assert!(missing.contains(&ProfessionalRequirement::PhotoDisclosureConsent));
    consents
        .record(&RecordProfessionalConsent {
            id: ProfessionalConsentEventId::new(),
            account_id: owner.0,
            profile_id,
            revision_id: edit.revision_id,
            purpose: ProfessionalConsentPurpose::PhotoDisclosure,
            action: ConsentAction::Granted,
            document_version: photo_document.version.clone(),
            document_sha256: photo_document.sha256,
            locale: ProfessionalLanguage::EnglishIndia,
            channel_identity_id: owner.1,
            source_inbound_event_id: inbound,
            idempotency_key: "consent:photo".to_owned(),
            occurred_at: OffsetDateTime::now_utc(),
        })
        .await?;
    for purpose in [
        ProfessionalConsentPurpose::Terms,
        ProfessionalConsentPurpose::Privacy,
        ProfessionalConsentPurpose::ContactDisclosure,
    ] {
        let document = documents.get(&purpose).ok_or("consent document missing")?;
        consents
            .record(&RecordProfessionalConsent {
                id: ProfessionalConsentEventId::new(),
                account_id: owner.0,
                profile_id,
                revision_id: edit.revision_id,
                purpose,
                action: ConsentAction::Granted,
                document_version: document.version.clone(),
                document_sha256: document.sha256,
                locale: ProfessionalLanguage::EnglishIndia,
                channel_identity_id: owner.1,
                source_inbound_event_id: inbound,
                idempotency_key: format!("edit-consent:{purpose}"),
                occurred_at: OffsetDateTime::now_utc(),
            })
            .await?;
    }
    let stored_photo: (Vec<u8>, Vec<u8>, i16) = sqlx::query_as(
        r#"
        SELECT sanitized_ciphertext, sanitized_nonce, encryption_key_version
        FROM private_data.profile_photos WHERE id = $1
        "#,
    )
    .bind(photo_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_ne!(stored_photo.0.as_slice(), photo_plaintext);
    let nonce: [u8; 12] = stored_photo
        .1
        .try_into()
        .map_err(|_| "stored photo nonce has invalid length")?;
    let decrypted_photo = crypto.decrypt(
        EncryptionContext::new(EncryptionNamespace::PROFILE_PHOTO, photo_id.into_uuid()),
        &EncryptedValue {
            purpose: EncryptionPurpose::Media,
            key_version: stored_photo.2,
            nonce,
            ciphertext: stored_photo.0,
        },
    )?;
    assert_eq!(decrypted_photo.as_slice(), photo_plaintext);

    let edit_submission = profiles
        .submit_complete_draft(
            owner.0,
            owner.1,
            "profile-owner",
            edit.revision_id,
            edit_version,
        )
        .await?;
    let SubmitProfileOutcome::Submitted {
        version: edit_submitted_version,
        target_digest: edit_digest,
    } = edit_submission
    else {
        return Err("complete edit was not submitted".into());
    };
    assert_eq!(
        profiles
            .find_published_by_reference(public_reference)
            .await?
            .ok_or("old revision disappeared while edit was pending")?
            .display_name,
        "Ravi"
    );
    let changes_requested = ApplyProfileDecision {
        id: ProfileReviewDecisionId::new(),
        revision_id: edit.revision_id,
        expected_version: edit_submitted_version,
        target_digest: edit_digest,
        reviewer_account_id: first_admin.0,
        reviewer_channel_identity_id: first_admin.1,
        provider_namespace: "profile-admin-1".to_owned(),
        decision: ProfileReviewDecision::ChangesRequested,
        reason: ProfileReviewReason::PhotoIssue,
        reason_detail: Some("Please provide a clearer sanitized photo".to_owned()),
        idempotency_key: "edit-changes-requested".to_owned(),
        correlation_id: CorrelationId::new(),
    };
    assert_eq!(
        profiles
            .apply_authorized_decision(&changes_requested)
            .await?,
        ApplyProfileDecisionOutcome::Applied
    );
    assert_eq!(
        profiles
            .find_published_by_reference(public_reference)
            .await?
            .ok_or("old revision disappeared after edit rejection")?
            .display_name,
        "Ravi"
    );

    let removal = profiles
        .begin_or_resume_draft(BeginProfessionalDraft {
            profile_id: PublicProfileId::new(),
            public_reference: PublicProfileReference::new(),
            revision_id: ProfileRevisionId::new(),
            account_id: owner.0,
        })
        .await?;
    assert!(removal.has_ready_photo);
    let ProfilePhotoMutation::Applied {
        revision_version: removal_version,
    } = photos
        .remove(owner.0, removal.revision_id, removal.version)
        .await?
    else {
        return Err("reusable photo association was not removed from the draft".into());
    };
    for purpose in [
        ProfessionalConsentPurpose::Terms,
        ProfessionalConsentPurpose::Privacy,
        ProfessionalConsentPurpose::ContactDisclosure,
    ] {
        let document = documents.get(&purpose).ok_or("consent document missing")?;
        consents
            .record(&RecordProfessionalConsent {
                id: ProfessionalConsentEventId::new(),
                account_id: owner.0,
                profile_id,
                revision_id: removal.revision_id,
                purpose,
                action: ConsentAction::Granted,
                document_version: document.version.clone(),
                document_sha256: document.sha256,
                locale: ProfessionalLanguage::EnglishIndia,
                channel_identity_id: owner.1,
                source_inbound_event_id: inbound,
                idempotency_key: format!("removal-consent:{purpose}"),
                occurred_at: OffsetDateTime::now_utc(),
            })
            .await?;
    }
    let SubmitProfileOutcome::Submitted {
        version: removal_submitted_version,
        target_digest: removal_digest,
    } = profiles
        .submit_complete_draft(
            owner.0,
            owner.1,
            "profile-owner",
            removal.revision_id,
            removal_version,
        )
        .await?
    else {
        return Err("photo-removal revision was not submitted".into());
    };
    let removal_decision = decision(
        removal.revision_id,
        removal_submitted_version,
        removal_digest,
        first_admin,
        "approve-photo-removal",
    );
    assert_eq!(
        profiles
            .apply_authorized_decision(&removal_decision)
            .await?,
        ApplyProfileDecisionOutcome::Applied
    );
    let published_photo_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM profile.public_profiles AS root
        JOIN profile.profile_revision_photos AS link
          ON link.revision_id = root.published_revision_id
        WHERE root.id = $1
        "#,
    )
    .bind(profile_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(published_photo_count, 0);
    let retired_photo: (String, bool, bool) = sqlx::query_as(
        "SELECT state, sanitized_ciphertext IS NULL, sanitized_nonce IS NULL FROM private_data.profile_photos WHERE id = $1",
    )
    .bind(photo_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(retired_photo, ("replaced".to_owned(), true, true));
    let obsolete_area_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM private_data.professional_service_areas AS area
        JOIN profile.profile_revisions AS revision ON revision.id = area.revision_id
        JOIN profile.public_profiles AS root ON root.id = revision.profile_id
        WHERE root.id = $1 AND revision.id <> root.published_revision_id
          AND revision.state IN ('changes_requested', 'rejected', 'superseded')
        "#,
    )
    .bind(profile_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(obsolete_area_count, 0);
    sqlx::query("UPDATE identity.accounts SET risk_state = 'restricted' WHERE id = $1")
        .bind(owner.0.into_uuid())
        .execute(&pool)
        .await?;
    assert!(
        profiles
            .find_published_by_reference(public_reference)
            .await?
            .is_none()
    );
    sqlx::query("UPDATE identity.accounts SET risk_state = 'normal' WHERE id = $1")
        .bind(owner.0.into_uuid())
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE profile.service_categories SET state = 'inactive' WHERE code = 'plumber'")
        .execute(&pool)
        .await?;
    assert!(
        profiles
            .find_published_by_reference(public_reference)
            .await?
            .is_none()
    );
    sqlx::query("UPDATE profile.service_categories SET state = 'active' WHERE code = 'plumber'")
        .execute(&pool)
        .await?;
    sqlx::query(
        "UPDATE profile.service_skills SET state = 'inactive' WHERE category_code = 'plumber' AND code = 'leak_repair'",
    )
    .execute(&pool)
    .await?;
    assert!(
        profiles
            .find_published_by_reference(public_reference)
            .await?
            .is_none()
    );
    sqlx::query(
        "UPDATE profile.service_skills SET state = 'active' WHERE category_code = 'plumber' AND code = 'leak_repair'",
    )
    .execute(&pool)
    .await?;

    let identity_document = documents
        .get(&ProfessionalConsentPurpose::IdentityVerification)
        .ok_or("identity consent document missing")?;
    consents
        .record(&RecordProfessionalConsent {
            id: ProfessionalConsentEventId::new(),
            account_id: owner.0,
            profile_id,
            revision_id: removal.revision_id,
            purpose: ProfessionalConsentPurpose::IdentityVerification,
            action: ConsentAction::Granted,
            document_version: identity_document.version.clone(),
            document_sha256: identity_document.sha256,
            locale: ProfessionalLanguage::EnglishIndia,
            channel_identity_id: owner.1,
            source_inbound_event_id: inbound,
            idempotency_key: "consent:identity".to_owned(),
            occurred_at: OffsetDateTime::now_utc(),
        })
        .await?;
    let consent_event_id: Uuid = sqlx::query_scalar(
        r#"
        SELECT id FROM private_data.professional_consent_events
        WHERE account_id = $1 AND purpose = 'identity_verification'
        "#,
    )
    .bind(owner.0.into_uuid())
    .fetch_one(&pool)
    .await?;
    let attempt_id = IdentityVerificationAttemptId::new();
    let encrypted_reference = crypto.encrypt(
        EncryptionPurpose::Identity,
        EncryptionContext::new(
            EncryptionNamespace::IDENTITY_PROVIDER_REFERENCE,
            attempt_id.into_uuid(),
        ),
        b"random-opaque-reference-7dV3yT",
    )?;
    let verification = IdentityVerificationRepository::new(database.clone());
    sqlx::query(
        "UPDATE identity.identity_provider_adapters SET state = 'active' WHERE code = 'pilot_identity_v1'",
    )
    .execute(&pool)
    .await?;
    assert_eq!(
        verification
            .start_attempt(&StartIdentityVerificationAttempt {
                id: attempt_id,
                account_id: owner.0,
                adapter_instance_code: "pilot_identity_v1".to_owned(),
                consent_event_id: ProfessionalConsentEventId::from_uuid(consent_event_id),
                encrypted_provider_reference: encrypted_reference,
                idempotency_key: "identity-attempt-1".to_owned(),
                expires_at: OffsetDateTime::now_utc() + Duration::days(1),
            })
            .await?,
        IdentityAttemptOutcome::Started
    );
    let (digest_key_version, event_key_digest) =
        crypto.blind_index("identity:callback:event-key", b"provider-event-1")?;
    let (_, event_digest) = crypto.blind_index("identity:callback:event", b"passed")?;
    assert!(
        verification
            .record_callback(&RecordIdentityVerificationCallback {
                id: IdentityVerificationCallbackReceiptId::new(),
                attempt_id,
                adapter_instance_code: "pilot_identity_v1".to_owned(),
                callback_kind: VerificationCallbackKind::BrowserReturn,
                reported_state: IdentityVerificationState::Passed,
                callback_event_key_digest: [8; 32],
                callback_event_digest: [9; 32],
                digest_key_version,
                signature_verified_at: None,
                provider_occurred_at: None,
                assertion_valid_until: Some(OffsetDateTime::now_utc() + Duration::days(30)),
            })
            .await
            .is_err()
    );
    let callback = RecordIdentityVerificationCallback {
        id: IdentityVerificationCallbackReceiptId::new(),
        attempt_id,
        adapter_instance_code: "pilot_identity_v1".to_owned(),
        callback_kind: VerificationCallbackKind::ServerCallback,
        reported_state: IdentityVerificationState::Passed,
        callback_event_key_digest: event_key_digest,
        callback_event_digest: event_digest,
        digest_key_version,
        signature_verified_at: Some(OffsetDateTime::now_utc()),
        provider_occurred_at: Some(OffsetDateTime::now_utc()),
        assertion_valid_until: Some(OffsetDateTime::now_utc() + Duration::days(30)),
    };
    sqlx::query(
        "UPDATE identity.identity_provider_adapters SET state = 'disabled' WHERE code = 'pilot_identity_v1'",
    )
    .execute(&pool)
    .await?;
    assert_eq!(
        verification.record_callback(&callback).await?,
        VerificationCallbackOutcome::ConflictOrMissing
    );
    sqlx::query(
        "UPDATE identity.identity_provider_adapters SET state = 'active' WHERE code = 'pilot_identity_v1'",
    )
    .execute(&pool)
    .await?;
    let (first_callback, duplicate_callback) = tokio::join!(
        verification.record_callback(&callback),
        verification.record_callback(&callback),
    );
    let callback_outcomes = (first_callback?, duplicate_callback?);
    assert!(matches!(
        callback_outcomes,
        (
            VerificationCallbackOutcome::Applied,
            VerificationCallbackOutcome::AlreadyRecorded
        ) | (
            VerificationCallbackOutcome::AlreadyRecorded,
            VerificationCallbackOutcome::Applied
        )
    ));
    assert_eq!(
        verification
            .badge_projection(owner.0)
            .await?
            .ok_or("passed identity badge missing")?
            .label,
        "Identity checked"
    );
    assert_eq!(
        profiles
            .find_published_by_reference(public_reference)
            .await?
            .ok_or("identity verification changed publication")?
            .identity_badge
            .as_deref(),
        Some("Identity checked")
    );
    let revocation_source =
        create_inbound(&pool, owner, "profile-owner", "identity-revoke").await?;
    consents
        .record(&RecordProfessionalConsent {
            id: ProfessionalConsentEventId::new(),
            account_id: owner.0,
            profile_id,
            revision_id: removal.revision_id,
            purpose: ProfessionalConsentPurpose::IdentityVerification,
            action: ConsentAction::Revoked,
            document_version: identity_document.version.clone(),
            document_sha256: identity_document.sha256,
            locale: ProfessionalLanguage::EnglishIndia,
            channel_identity_id: owner.1,
            source_inbound_event_id: revocation_source,
            idempotency_key: "consent:identity:revoke".to_owned(),
            occurred_at: OffsetDateTime::now_utc(),
        })
        .await?;
    assert!(verification.badge_projection(owner.0).await?.is_none());
    let (_, revoked_event_key) = crypto.blind_index(
        "identity:callback:event-key",
        b"provider-event-after-revoke",
    )?;
    assert_eq!(
        verification
            .record_callback(&RecordIdentityVerificationCallback {
                id: IdentityVerificationCallbackReceiptId::new(),
                attempt_id,
                adapter_instance_code: "pilot_identity_v1".to_owned(),
                callback_kind: VerificationCallbackKind::ServerCallback,
                reported_state: IdentityVerificationState::Passed,
                callback_event_key_digest: revoked_event_key,
                callback_event_digest: event_digest,
                digest_key_version,
                signature_verified_at: Some(OffsetDateTime::now_utc()),
                provider_occurred_at: Some(OffsetDateTime::now_utc()),
                assertion_valid_until: Some(OffsetDateTime::now_utc() + Duration::days(30)),
            })
            .await?,
        VerificationCallbackOutcome::ConflictOrMissing
    );
    let attempt_state: String = sqlx::query_scalar(
        "SELECT state FROM private_data.identity_verification_attempts WHERE id = $1",
    )
    .bind(attempt_id.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(attempt_state, "revoked");
    assert!(
        profiles
            .find_published_by_reference(public_reference)
            .await?
            .ok_or("consent revocation changed publication")?
            .identity_badge
            .is_none()
    );

    assert_no_prohibited_new_columns(&pool).await?;

    let outbound_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO messaging.outbound_messages (
            provider_code, provider_namespace, recipient_channel_identity_id,
            idempotency_key, request_fingerprint, fingerprint_key_version,
            payload_schema_version, payload_ciphertext, payload_nonce,
            encryption_key_version, callback_token, correlation_id,
            submission_state, provider_message_id, accepted_at
        )
        VALUES (
            'whatsapp', 'profile-owner', $1, $2, $3, 1, 1, $4, $5, 1,
            gen_random_uuid(), uuidv7(), 'accepted', $6, statement_timestamp()
        )
        RETURNING id
        "#,
    )
    .bind(owner.1.into_uuid())
    .bind(format!("deletion-payload-{profile_id}"))
    .bind(vec![21_u8; 32])
    .bind(vec![22_u8; 32])
    .bind(vec![23_u8; 12])
    .bind(format!("wamid.deletion.{profile_id}"))
    .fetch_one(&pool)
    .await?;
    sqlx::query(
        r#"
        INSERT INTO messaging.outbound_delivery_events (
            inbound_event_id, outbound_message_id, provider_code,
            provider_namespace, provider_message_id, provider_status,
            provider_occurred_at
        )
        VALUES ($1, $2, 'whatsapp', 'profile-owner', $3, 'delivered', statement_timestamp())
        "#,
    )
    .bind(photo_source.into_uuid())
    .bind(outbound_id)
    .bind(format!("wamid.deletion.{profile_id}"))
    .execute(&pool)
    .await?;

    let accounts = AccountRepository::new(database.clone());
    let active = accounts.find(owner.0).await?.ok_or("owner missing")?;
    let AccountMutation::Applied { version } = accounts
        .transition_lifecycle(
            owner.0,
            active.version,
            AccountLifecycle::DeletionPending,
            CorrelationId::new(),
        )
        .await?
    else {
        return Err("owner deletion was not requested".into());
    };
    assert!(matches!(
        accounts
            .transition_lifecycle(
                owner.0,
                version,
                AccountLifecycle::Deleted,
                CorrelationId::new(),
            )
            .await?,
        AccountMutation::Applied { .. }
    ));
    let owner_grant_revoked: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM identity.administrator_allowlist WHERE id = $1",
    )
    .bind(owner_admin_grant.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert!(owner_grant_revoked);
    assert!(
        profiles
            .find_published_by_reference(public_reference)
            .await?
            .is_none()
    );
    let private_count: i64 = sqlx::query_scalar(
        r#"
        SELECT
            (SELECT count(*) FROM private_data.professional_consent_events WHERE account_id = $1)
          + (SELECT count(*) FROM private_data.professional_service_areas WHERE account_id = $1)
          + (SELECT count(*) FROM private_data.profile_photos WHERE account_id = $1)
          + (SELECT count(*) FROM private_data.identity_verification_attempts WHERE account_id = $1)
        "#,
    )
    .bind(owner.0.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(private_count, 0);
    let transport_redacted: (bool, bool, bool, bool) = sqlx::query_as(
        r#"
        SELECT
            inbound.payload_ciphertext IS NULL AND inbound.payload_nonce IS NULL,
            outbound.payload_ciphertext IS NULL AND outbound.payload_nonce IS NULL,
            outbound.provider_message_id IS NULL,
            delivery.provider_message_id IS NULL
        FROM integration.inbound_events AS inbound
        JOIN messaging.outbound_delivery_events AS delivery
          ON delivery.inbound_event_id = inbound.id
        JOIN messaging.outbound_messages AS outbound
          ON outbound.id = delivery.outbound_message_id
        WHERE inbound.id = $1
        "#,
    )
    .bind(photo_source.into_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(transport_redacted, (true, true, true, true));

    pool.close().await;
    database.close().await;
    Ok(())
}

fn decision(
    revision_id: ProfileRevisionId,
    expected_version: i64,
    target_digest: [u8; 32],
    reviewer: (AccountId, ChannelIdentityId),
    idempotency_key: &str,
) -> ApplyProfileDecision {
    let provider_namespace = if idempotency_key.contains("second") {
        "profile-admin-2"
    } else if idempotency_key == "self-review" {
        "profile-owner"
    } else if idempotency_key == "unauthorized-review" {
        "not-allowlisted"
    } else {
        "profile-admin-1"
    };
    ApplyProfileDecision {
        id: ProfileReviewDecisionId::new(),
        revision_id,
        expected_version,
        target_digest,
        reviewer_account_id: reviewer.0,
        reviewer_channel_identity_id: reviewer.1,
        provider_namespace: provider_namespace.to_owned(),
        decision: ProfileReviewDecision::Approve,
        reason: ProfileReviewReason::MeetsPolicy,
        reason_detail: None,
        idempotency_key: idempotency_key.to_owned(),
        correlation_id: CorrelationId::new(),
    }
}

async fn create_actor(
    pool: &PgPool,
    role: AccountRole,
    namespace: &str,
) -> Result<(AccountId, ChannelIdentityId), Box<dyn std::error::Error>> {
    let account_id = AccountId::new();
    let channel_identity_id = ChannelIdentityId::new();
    sqlx::query(
        "INSERT INTO identity.accounts (id, status, preferred_locale) VALUES ($1, 'active', 'en-IN')",
    )
    .bind(account_id.into_uuid())
    .execute(pool)
    .await?;
    sqlx::query("INSERT INTO identity.account_roles (account_id, role) VALUES ($1, $2)")
        .bind(account_id.into_uuid())
        .bind(role.as_str())
        .execute(pool)
        .await?;
    sqlx::query(
        r#"
        INSERT INTO identity.channel_identities (
            id, account_id, provider_code, provider_namespace, status
        )
        VALUES ($1, $2, 'whatsapp', $3, 'active')
        "#,
    )
    .bind(channel_identity_id.into_uuid())
    .bind(account_id.into_uuid())
    .bind(namespace)
    .execute(pool)
    .await?;
    Ok((account_id, channel_identity_id))
}

async fn create_inbound(
    pool: &PgPool,
    actor: (AccountId, ChannelIdentityId),
    namespace: &str,
    suffix: &str,
) -> Result<InboundEventId, Box<dyn std::error::Error>> {
    let id = InboundEventId::new();
    sqlx::query(
        r#"
        INSERT INTO integration.inbound_events (
            id, provider_code, provider_namespace, provider_event_id,
            event_type, payload_version, payload_ciphertext, payload_nonce,
            payload_fingerprint, encryption_key_version,
            fingerprint_key_version, signature_verified_at, account_id, channel_identity_id
        )
        VALUES ($1, 'whatsapp', $2, $3, 'profile.test', 1, $4, $5, $6, 1, 1,
                statement_timestamp(), $7, $8)
        "#,
    )
    .bind(id.into_uuid())
    .bind(namespace)
    .bind(format!("{suffix}-{id}"))
    .bind(vec![1_u8; 32])
    .bind(vec![2_u8; 12])
    .bind(vec![3_u8; 32])
    .bind(actor.0.into_uuid())
    .bind(actor.1.into_uuid())
    .execute(pool)
    .await?;
    Ok(id)
}

async fn assert_no_prohibited_new_columns(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let prohibited: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM information_schema.columns
        WHERE table_schema IN ('profile', 'private_data', 'identity')
          AND table_name IN (
              'profile_revisions',
              'professional_service_areas',
              'professional_consent_events',
              'profile_photos',
              'profile_revision_photos',
              'identity_verification_attempts',
              'identity_verification_callback_receipts'
          )
          AND column_name ~ '(aadhaar|legal_name|selfie|biometric|score|url|provider_response)'
        "#,
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(prohibited, 0);
    let public_schema_geographies: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM information_schema.columns
        WHERE table_schema = 'profile' AND udt_name = 'geography'
        "#,
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(public_schema_geographies, 0);
    let generic_callback_columns: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM information_schema.columns
        WHERE table_schema = 'private_data'
          AND table_name = 'identity_verification_callback_receipts'
          AND column_name IN ('payload', 'raw_payload', 'response', 'metadata')
        "#,
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(generic_callback_columns, 0);
    Ok(())
}

fn crypto_service() -> Result<CryptoService, Box<dyn std::error::Error>> {
    Ok(CryptoService::new(
        vec![
            EncryptionKeySet::new(
                EncryptionPurpose::Identity,
                1,
                vec![VersionedKey::from_bytes(1, [13; 32])?],
            ),
            EncryptionKeySet::new(
                EncryptionPurpose::Media,
                1,
                vec![VersionedKey::from_bytes(1, [23; 32])?],
            ),
        ],
        1,
        vec![VersionedKey::from_bytes(1, [29; 32])?],
    )?)
}

async fn test_database() -> Result<Option<(Database, PgPool)>, Box<dyn std::error::Error>> {
    let Ok(database_url) = env::var(TEST_DATABASE_ENVIRONMENT) else {
        return Ok(None);
    };
    let settings = sahayak_configuration::DatabaseSettings {
        url: SecretString::from(database_url.clone()),
        min_connections: 1,
        max_connections: 10,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 30,
        max_lifetime_seconds: 60,
        statement_timeout_milliseconds: 10_000,
        lock_timeout_milliseconds: 5_000,
        idle_in_transaction_timeout_milliseconds: 10_000,
        require_tls: false,
    };
    let database = Database::connect(&settings, "professional-profile-test").await?;
    let pool = PgPool::connect(&database_url).await?;
    Ok(Some((database, pool)))
}
