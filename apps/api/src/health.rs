use crate::AppState;
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use serde::Serialize;
use tokio::time::timeout;

/// Builds process and dependency health routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        .route("/metrics", get(metrics))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse { status: "alive" })
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    match sahayak_persistence::OperationsRepository::new(state.database().clone()).metrics().await {
        Ok(metrics) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            format!(
                "# TYPE sahayak_outbox_ready gauge\nsahayak_outbox_ready {}\n\
                 # TYPE sahayak_outbox_dead_lettered gauge\nsahayak_outbox_dead_lettered {}\n\
                 # TYPE sahayak_outbox_oldest_ready_seconds gauge\nsahayak_outbox_oldest_ready_seconds {}\n\
                 # TYPE sahayak_safety_reports_overdue gauge\nsahayak_safety_reports_overdue {}\n\
                 # TYPE sahayak_billing_webhooks_pending gauge\nsahayak_billing_webhooks_pending {}\n\
                 # TYPE sahayak_billing_webhooks_failed gauge\nsahayak_billing_webhooks_failed {}\n",
                metrics.outbox_ready,
                metrics.outbox_dead_lettered,
                metrics.oldest_ready_seconds,
                metrics.overdue_safety_reports,
                metrics.billing_webhooks_pending,
                metrics.billing_webhooks_failed,
            ),
        ).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn readiness(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    if !state.is_accepting_traffic() {
        return unavailable("draining");
    }

    match timeout(state.readiness_timeout(), state.database().check_health()).await {
        Ok(Ok(())) => (StatusCode::OK, Json(HealthResponse { status: "ready" })),
        Ok(Err(_)) => unavailable("database_unavailable"),
        Err(_) => unavailable("database_timeout"),
    }
}

fn unavailable(status: &'static str) -> (StatusCode, Json<HealthResponse>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(HealthResponse { status }),
    )
}

#[cfg(test)]
mod tests {
    use crate::{AppState, build_router};
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use sahayak_configuration::{DatabaseSettings, HttpSettings};
    use sahayak_persistence::Database;
    use secrecy::SecretString;
    use std::{net::IpAddr, time::Duration};
    use tower::ServiceExt;

    fn settings() -> (DatabaseSettings, HttpSettings) {
        (
            DatabaseSettings {
                url: SecretString::from(
                    "postgres://user:password@127.0.0.1:55432/database".to_owned(),
                ),
                min_connections: 0,
                max_connections: 1,
                acquire_timeout_seconds: 1,
                idle_timeout_seconds: 30,
                max_lifetime_seconds: 60,
                statement_timeout_milliseconds: 5_000,
                lock_timeout_milliseconds: 2_000,
                idle_in_transaction_timeout_milliseconds: 10_000,
                require_tls: false,
            },
            HttpSettings {
                host: IpAddr::from([127, 0, 0, 1]),
                port: 8080,
                request_timeout_seconds: 2,
                readiness_timeout_seconds: 1,
                shutdown_grace_seconds: 5,
                max_request_body_bytes: 1_024,
            },
        )
    }

    #[tokio::test]
    async fn liveness_does_not_depend_on_database() -> Result<(), Box<dyn std::error::Error>> {
        let (database_settings, http_settings) = settings();
        let database = Database::connect_lazy(&database_settings, "test")?;
        let app = build_router(
            AppState::new(database, Duration::from_secs(1)),
            &http_settings,
        );

        let response = app
            .oneshot(Request::get("/health/live").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_024).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?["status"],
            "alive"
        );
        Ok(())
    }

    #[tokio::test]
    async fn readiness_fails_immediately_while_draining() -> Result<(), Box<dyn std::error::Error>>
    {
        let (database_settings, http_settings) = settings();
        let database = Database::connect_lazy(&database_settings, "test")?;
        let state = AppState::new(database, Duration::from_secs(1));
        state.begin_shutdown();
        let app = build_router(state, &http_settings);

        let response = app
            .oneshot(Request::get("/health/ready").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        Ok(())
    }

    #[tokio::test]
    async fn responses_include_a_generated_request_id() -> Result<(), Box<dyn std::error::Error>> {
        let (database_settings, http_settings) = settings();
        let database = Database::connect_lazy(&database_settings, "test")?;
        let app = build_router(
            AppState::new(database, Duration::from_secs(1)),
            &http_settings,
        );

        let response = app
            .oneshot(
                Request::get("/health/live")
                    .header("x-request-id", "attacker-controlled")
                    .body(Body::empty())?,
            )
            .await?;

        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .ok_or("response request ID missing")?;
        assert_ne!(request_id, "attacker-controlled");
        assert!(request_id.parse::<uuid::Uuid>().is_ok());
        Ok(())
    }
}
