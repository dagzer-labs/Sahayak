use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sahayak_api::{AppState, build_router};
use sahayak_configuration::{DatabaseSettings, HttpSettings};
use sahayak_persistence::Database;
use secrecy::SecretString;
use std::{env, net::IpAddr, time::Duration};
use tower::ServiceExt;

const TEST_DATABASE_ENVIRONMENT: &str = "SAHAYAK_TEST_DATABASE_URL";

#[tokio::test]
async fn readiness_succeeds_against_supported_database() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = env::var(TEST_DATABASE_ENVIRONMENT) else {
        return Ok(());
    };

    let database_settings = DatabaseSettings {
        url: SecretString::from(database_url),
        min_connections: 1,
        max_connections: 2,
        acquire_timeout_seconds: 2,
        idle_timeout_seconds: 30,
        max_lifetime_seconds: 60,
        statement_timeout_milliseconds: 5_000,
        lock_timeout_milliseconds: 2_000,
        idle_in_transaction_timeout_milliseconds: 10_000,
        require_tls: false,
    };
    let http_settings = HttpSettings {
        host: IpAddr::from([127, 0, 0, 1]),
        port: 8080,
        request_timeout_seconds: 2,
        readiness_timeout_seconds: 1,
        shutdown_grace_seconds: 5,
        max_request_body_bytes: 1_024,
    };
    let database = Database::connect(&database_settings, "readiness-integration-test").await?;
    let app = build_router(
        AppState::new(database.clone(), Duration::from_secs(1)),
        &http_settings,
    );

    let response = app
        .oneshot(Request::get("/health/ready").body(Body::empty())?)
        .await?;

    database.close().await;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}
