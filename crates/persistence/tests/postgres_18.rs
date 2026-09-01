use sqlx::postgres::PgPoolOptions;
use std::env;

const TEST_DATABASE_ENVIRONMENT: &str = "SAHAYAK_TEST_DATABASE_URL";

#[tokio::test]
async fn supports_postgresql_18_and_postgis_36() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = env::var(TEST_DATABASE_ENVIRONMENT) else {
        return Ok(());
    };

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;

    let version: String = sqlx::query_scalar("SHOW server_version_num")
        .fetch_one(&pool)
        .await?;
    let version_number: u32 = version.parse()?;
    assert!(version_number >= 180_000, "expected PostgreSQL 18 or newer");

    let postgis_version: String = sqlx::query_scalar("SELECT postgis_version()")
        .fetch_one(&pool)
        .await?;
    assert!(
        postgis_version.starts_with("3.6"),
        "expected PostGIS 3.6, received {postgis_version}"
    );

    let foundation_exists: bool = sqlx::query_scalar(
        r#"
        SELECT
            to_regclass('identity.accounts') IS NOT NULL
            AND to_regclass('identity.account_roles') IS NOT NULL
            AND to_regclass('identity.channel_providers') IS NOT NULL
            AND to_regclass('identity.channel_identities') IS NOT NULL
            AND to_regclass('private_data.key_versions') IS NOT NULL
            AND to_regclass('private_data.whatsapp_identities') IS NOT NULL
            AND to_regclass('private_data.channel_lookup_digests') IS NOT NULL
            AND to_regclass('private_data.account_identities') IS NOT NULL
            AND to_regclass('profile.public_profiles') IS NOT NULL
            AND to_regclass('profile.legacy_profile_review_migration_audit') IS NOT NULL
            AND to_regclass('profile.profile_revisions') IS NOT NULL
            AND to_regclass('profile.service_categories') IS NOT NULL
            AND to_regclass('profile.service_skills') IS NOT NULL
            AND to_regclass('profile.professional_services') IS NOT NULL
            AND to_regclass('profile.professional_service_skills') IS NOT NULL
            AND to_regclass('profile.professional_languages') IS NOT NULL
            AND to_regclass('private_data.professional_service_areas') IS NOT NULL
            AND to_regclass('profile.consent_documents') IS NOT NULL
            AND to_regclass('profile.profile_review_decisions') IS NOT NULL
            AND to_regclass('private_data.professional_consent_events') IS NOT NULL
            AND to_regclass('private_data.profile_photos') IS NOT NULL
            AND to_regclass('profile.profile_revision_photos') IS NOT NULL
            AND to_regclass('identity.administrator_allowlist') IS NOT NULL
            AND to_regclass('identity.identity_provider_adapters') IS NOT NULL
            AND to_regclass('private_data.identity_verification_attempts') IS NOT NULL
            AND to_regclass('private_data.identity_verification_callback_receipts') IS NOT NULL
            AND to_regclass('messaging.conversation_sessions') IS NOT NULL
            AND to_regclass('messaging.conversation_turn_receipts') IS NOT NULL
            AND to_regclass('messaging.conversation_turn_receipt_outbounds') IS NOT NULL
            AND to_regclass('messaging.outbound_messages') IS NOT NULL
            AND to_regclass('messaging.outbound_message_fingerprints') IS NOT NULL
            AND to_regclass('messaging.outbound_delivery_events') IS NOT NULL
            AND to_regclass('integration.inbound_events') IS NOT NULL
            AND to_regclass('integration.inbound_event_fingerprints') IS NOT NULL
            AND to_regclass('integration.outbox_jobs') IS NOT NULL
            AND to_regclass('availability.epochs') IS NOT NULL
            AND to_regclass('availability.mutation_events') IS NOT NULL
            AND to_regclass('availability.capacity_consumptions') IS NOT NULL
            AND to_regclass('availability.notification_events') IS NOT NULL
            AND to_regclass('availability.current_professional_services') IS NOT NULL
            AND to_regclass('profile.provider_services') IS NOT NULL
            AND to_regclass('discovery.service_requests') IS NOT NULL
            AND to_regclass('private_data.service_request_locations') IS NOT NULL
            AND to_regclass('discovery.request_candidates') IS NOT NULL
            AND to_regclass('connection.connection_requests') IS NOT NULL
            AND to_regclass('connection.contact_reveals') IS NOT NULL
            AND to_regclass('connection.customer_allowance_events') IS NOT NULL
            AND to_regclass('connection.contact_reveal_delivery') IS NOT NULL
            AND to_regclass('connection.reveal_reversals') IS NOT NULL
            AND to_regclass('availability.capacity_reversals') IS NOT NULL
            AND to_regclass('messaging.outbound_message_subjects') IS NOT NULL
            AND to_regclass('identity.account_blocks') IS NOT NULL
            AND to_regclass('review.reviews') IS NOT NULL
            AND to_regclass('review.review_revisions') IS NOT NULL
            AND to_regclass('review.rating_aggregates') IS NOT NULL
            AND to_regclass('safety.reports') IS NOT NULL
            AND to_regclass('safety.report_evidence') IS NOT NULL
            AND to_regclass('safety.report_state_events') IS NOT NULL
            AND to_regclass('safety.restrictions') IS NOT NULL
            AND to_regclass('safety.moderation_actions') IS NOT NULL
            AND to_regclass('billing.plans') IS NOT NULL
            AND to_regclass('billing.subscriptions') IS NOT NULL
            AND to_regclass('billing.professional_entitlements') IS NOT NULL
            AND to_regclass('billing.payments') IS NOT NULL
            AND to_regclass('billing.tax_documents') IS NOT NULL
            AND to_regclass('billing.payment_reminders') IS NOT NULL
            AND to_regclass('billing.webhook_events') IS NOT NULL
            AND to_regclass('billing.reconciliation_runs') IS NOT NULL
            AND to_regclass('billing.reconciliation_exceptions') IS NOT NULL
            AND to_regclass('audit.events') IS NOT NULL
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert!(foundation_exists, "foundation schema is incomplete");
    let spatial_indexes_exist: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE schemaname = 'private_data'
              AND indexname = 'request_locations_gist_idx'
              AND indexdef ILIKE '%USING gist%'
        ) AND EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE schemaname = 'private_data'
              AND indexname = 'professional_service_areas_gist_idx'
              AND indexdef ILIKE '%USING gist%'
        )
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        spatial_indexes_exist,
        "required PostGIS indexes are missing"
    );

    let india_midnight: bool = sqlx::query_scalar(
        r#"
        SELECT availability.calculate_expiry(
            'end_of_local_day', 'Asia/Kolkata', TIMESTAMPTZ '2026-08-31 17:30:00+00'
        ) = TIMESTAMPTZ '2026-08-31 18:30:00+00'
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert!(india_midnight, "end-of-local-day conversion is incorrect");
    assert!(
        sqlx::query("INSERT INTO identity.accounts (time_zone) VALUES ('Mars/Olympus')")
            .execute(&pool)
            .await
            .is_err(),
        "invalid IANA time zone was accepted"
    );

    pool.close().await;
    Ok(())
}
