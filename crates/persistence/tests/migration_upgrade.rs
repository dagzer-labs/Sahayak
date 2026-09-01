use sqlx::{Connection, PgConnection, Row};
use std::env;
use url::Url;
use uuid::Uuid;

const TEST_DATABASE_ENVIRONMENT: &str = "SAHAYAK_TEST_DATABASE_URL";

#[tokio::test]
async fn migrations_backfill_legacy_conversations_and_hide_all_legacy_profiles()
-> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = env::var(TEST_DATABASE_ENVIRONMENT) else {
        return Ok(());
    };
    let mut admin_url = Url::parse(&database_url)?;
    admin_url.set_path("/postgres");
    let database_name = format!("sahayak_upgrade_{}", Uuid::new_v4().simple());
    let mut admin = PgConnection::connect(admin_url.as_str()).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE \"{database_name}\""
    )))
    .execute(&mut admin)
    .await?;

    let mut upgrade_url = Url::parse(&database_url)?;
    upgrade_url.set_path(&format!("/{database_name}"));
    let result = run_upgrade_assertion(upgrade_url.as_str()).await;

    sqlx::query(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
    )
    .bind(&database_name)
    .execute(&mut admin)
    .await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE \"{database_name}\""
    )))
    .execute(&mut admin)
    .await?;
    admin.close().await?;
    result
}

async fn run_upgrade_assertion(database_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = PgConnection::connect(database_url).await?;
    sqlx::raw_sql(include_str!("../../../migrations/0001_enable_postgis.sql"))
        .execute(&mut connection)
        .await?;
    sqlx::raw_sql(include_str!(
        "../../../migrations/0002_create_identity_messaging_and_operations.sql"
    ))
    .execute(&mut connection)
    .await?;
    sqlx::raw_sql(include_str!(
        "../../../migrations/0003_create_whatsapp_transport.sql"
    ))
    .execute(&mut connection)
    .await?;
    let account_id: Uuid =
        sqlx::query_scalar("INSERT INTO identity.accounts DEFAULT VALUES RETURNING id")
            .fetch_one(&mut connection)
            .await?;
    let channel_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO identity.channel_identities (
            account_id, provider_code, provider_namespace
        )
        VALUES ($1, 'whatsapp', 'upgrade-test')
        RETURNING id
        "#,
    )
    .bind(account_id)
    .fetch_one(&mut connection)
    .await?;
    let session_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO messaging.conversation_sessions (
            account_id,
            channel_identity_id,
            role_context,
            workflow_key,
            workflow_version,
            state_key,
            state_data,
            language,
            status,
            expires_at
        )
        VALUES (
            $1, $2, 'customer', 'legacy', 1, 'finished',
            '{"temporary":"value"}'::jsonb, 'en-IN', 'completed',
            statement_timestamp() + INTERVAL '1 hour'
        )
        RETURNING id
        "#,
    )
    .bind(account_id)
    .bind(channel_id)
    .fetch_one(&mut connection)
    .await?;
    let mismatched_session_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO messaging.conversation_sessions (
            account_id, channel_identity_id, role_context, workflow_key,
            workflow_version, state_key, state_data, language, status, expires_at
        )
        VALUES ($1, $2, 'customer', 'professional.profile', 1, 'display_name_input',
                '{"mode":"initial"}'::jsonb, 'en-IN', 'active',
                statement_timestamp() + INTERVAL '1 hour')
        RETURNING id
        "#,
    )
    .bind(account_id)
    .bind(channel_id)
    .fetch_one(&mut connection)
    .await?;
    let mut legacy_profiles = Vec::new();
    for (status, display_name) in [
        ("draft", "Sahayak Admin"),
        ("pending_review", "Legacy pending_review"),
        ("published", "Legacy published"),
        ("hidden", "Legacy hidden"),
        ("rejected", "Legacy rejected"),
    ] {
        let profile_account_id: Uuid =
            sqlx::query_scalar("INSERT INTO identity.accounts DEFAULT VALUES RETURNING id")
                .fetch_one(&mut connection)
                .await?;
        let profile_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO profile.public_profiles (
                account_id, display_name, status, reviewed_by,
                reviewed_at, published_at
            )
            VALUES (
                $1, $2, $3,
                CASE WHEN $3 IN ('published', 'hidden', 'rejected') THEN $4 ELSE NULL END,
                CASE WHEN $3 IN ('published', 'hidden', 'rejected') THEN statement_timestamp() ELSE NULL END,
                CASE WHEN $3 IN ('published', 'hidden') THEN statement_timestamp() ELSE NULL END
            )
            RETURNING id
            "#,
        )
        .bind(profile_account_id)
        .bind(display_name)
        .bind(status)
        .bind(account_id)
        .fetch_one(&mut connection)
        .await?;
        legacy_profiles.push((profile_id, display_name));
    }

    sqlx::raw_sql(include_str!(
        "../../../migrations/0004_create_conversation_engine.sql"
    ))
    .execute(&mut connection)
    .await?;
    let row = sqlx::query(
        r#"
        SELECT ended_at IS NOT NULL AS ended, terminal_reason, state_data
        FROM messaging.conversation_sessions
        WHERE id = $1
        "#,
    )
    .bind(session_id)
    .fetch_one(&mut connection)
    .await?;
    assert!(row.try_get::<bool, _>("ended")?);
    assert_eq!(
        row.try_get::<String, _>("terminal_reason")?,
        "completed_before_v1"
    );
    assert_eq!(
        row.try_get::<serde_json::Value, _>("state_data")?,
        serde_json::json!({})
    );
    sqlx::raw_sql(include_str!(
        "../../../migrations/0005_create_professional_profile_foundation.sql"
    ))
    .execute(&mut connection)
    .await?;
    sqlx::raw_sql(include_str!(
        "../../../migrations/0006_create_availability_management.sql"
    ))
    .execute(&mut connection)
    .await?;
    sqlx::raw_sql(include_str!(
        "../../../migrations/0007_create_discovery_and_connections.sql"
    ))
    .execute(&mut connection)
    .await?;
    let migrated_mismatch: (String, String) = sqlx::query_as(
        "SELECT status, terminal_reason FROM messaging.conversation_sessions WHERE id = $1",
    )
    .bind(mismatched_session_id)
    .fetch_one(&mut connection)
    .await?;
    assert_eq!(
        migrated_mismatch,
        ("abandoned".to_owned(), "role_context_migration".to_owned())
    );
    let first_legacy_id = legacy_profiles[0].0;
    for (profile_id, legacy_display_name) in legacy_profiles {
        let root = sqlx::query(
            r#"
            SELECT visibility, published_revision_id, published_at
            FROM profile.public_profiles WHERE id = $1
            "#,
        )
        .bind(profile_id)
        .fetch_one(&mut connection)
        .await?;
        assert_eq!(root.try_get::<String, _>("visibility")?, "hidden");
        assert!(
            root.try_get::<Option<Uuid>, _>("published_revision_id")?
                .is_none()
        );
        assert!(
            root.try_get::<Option<time::OffsetDateTime>, _>("published_at")?
                .is_none()
        );
        let revision = sqlx::query(
            r#"
            SELECT
                state,
                display_name,
                NOT EXISTS (
                    SELECT 1 FROM private_data.professional_service_areas
                    WHERE revision_id = profile.profile_revisions.id
                ) AS missing_area
            FROM profile.profile_revisions WHERE profile_id = $1
            "#,
        )
        .bind(profile_id)
        .fetch_one(&mut connection)
        .await?;
        assert_eq!(revision.try_get::<String, _>("state")?, "draft");
        let migrated_name = revision.try_get::<Option<String>, _>("display_name")?;
        if legacy_display_name == "Sahayak Admin" {
            assert!(migrated_name.is_none());
        } else {
            assert_eq!(migrated_name.as_deref(), Some(legacy_display_name));
        }
        assert!(revision.try_get::<bool, _>("missing_area")?);
        let preserved: (Uuid, String, Option<Uuid>, bool) = sqlx::query_as(
            r#"
            SELECT account_id, legacy_status, legacy_reviewed_by,
                   legacy_reviewed_at IS NOT NULL
            FROM profile.legacy_profile_review_migration_audit
            WHERE profile_id = $1
            "#,
        )
        .bind(profile_id)
        .fetch_one(&mut connection)
        .await?;
        assert_eq!(
            preserved.1,
            match legacy_display_name {
                "Sahayak Admin" => "draft",
                "Legacy pending_review" => "pending_review",
                "Legacy published" => "published",
                "Legacy hidden" => "hidden",
                "Legacy rejected" => "rejected",
                _ => return Err("unexpected legacy fixture".into()),
            }
        );
        assert_eq!(preserved.2.is_some(), preserved.3);
    }
    assert!(
        sqlx::query(
            "UPDATE profile.legacy_profile_review_migration_audit SET legacy_status = 'draft' WHERE profile_id = $1",
        )
        .bind(first_legacy_id)
        .execute(&mut connection)
        .await
        .is_err()
    );
    let profile_coordinate_column_exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'profile'
              AND table_name = 'profile_revisions'
              AND column_name IN ('service_area_center', 'exact_center')
        )
        "#,
    )
    .fetch_one(&mut connection)
    .await?;
    assert!(!profile_coordinate_column_exists);
    let placeholder_adapter_state: String = sqlx::query_scalar(
        "SELECT state FROM identity.identity_provider_adapters WHERE code = 'pilot_identity_v1'",
    )
    .fetch_one(&mut connection)
    .await?;
    assert_eq!(placeholder_adapter_state, "disabled");
    let all_review_tokens_are_random: bool = sqlx::query_scalar(
        "SELECT bool_and(uuid_extract_version(review_token) = 4) FROM profile.profile_revisions",
    )
    .fetch_one(&mut connection)
    .await?;
    assert!(all_review_tokens_are_random);
    let terms_hash_uses_policy_text: bool = sqlx::query_scalar(
        r#"
        SELECT document_sha256 <> sha256(convert_to('sahayak:terms:phase5-v1', 'UTF8'))
        FROM profile.consent_documents
        WHERE purpose = 'terms' AND locale = 'en-IN' AND is_current
        "#,
    )
    .fetch_one(&mut connection)
    .await?;
    assert!(terms_hash_uses_policy_text);
    let availability_is_empty_and_ready: bool = sqlx::query_scalar(
        r#"
        SELECT NOT EXISTS (SELECT 1 FROM availability.epochs)
           AND to_regclass('availability.current_professional_services') IS NOT NULL
        "#,
    )
    .fetch_one(&mut connection)
    .await?;
    assert!(availability_is_empty_and_ready);
    let discovery_is_empty_and_ready: bool = sqlx::query_scalar(
        r#"
        SELECT NOT EXISTS (SELECT 1 FROM discovery.service_requests)
           AND NOT EXISTS (SELECT 1 FROM connection.contact_reveals)
           AND to_regclass('discovery.request_candidates') IS NOT NULL
        "#,
    )
    .fetch_one(&mut connection)
    .await?;
    assert!(discovery_is_empty_and_ready);
    let localized_documents_valid: bool = sqlx::query_scalar(
        r#"
        SELECT count(*) = 18
           AND bool_and(document_sha256 = sha256(convert_to(document_text, 'UTF8')))
           AND (
               SELECT max(rendered_units) <= 1024
               FROM (
                   SELECT sum(length(document_text)) + (count(*) - 1) * 2 AS rendered_units
                   FROM profile.consent_documents
                   WHERE purpose <> 'identity_verification'
                   GROUP BY locale
               ) AS localized
           )
        FROM profile.consent_documents
        "#,
    )
    .fetch_one(&mut connection)
    .await?;
    assert!(localized_documents_valid);
    connection.close().await?;
    Ok(())
}
