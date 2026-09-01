use crate::{AppState, billing_routes, health, request_id, whatsapp_routes};
use axum::{
    Json, Router,
    body::Body,
    http::{Request, StatusCode},
    middleware,
};
use sahayak_configuration::HttpSettings;
use serde::Serialize;
use tower::ServiceBuilder;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    catch_panic::CatchPanicLayer,
    limit::RequestBodyLimitLayer,
    timeout::{RequestBodyDeadlineLayer, TimeoutLayer},
    trace::{DefaultOnResponse, TraceLayer},
};
use tracing::Level;

/// Builds the complete HTTP router and defensive middleware stack.
pub fn build_router(state: AppState, settings: &HttpSettings) -> Router {
    let middleware = ServiceBuilder::new()
        .layer(ConcurrencyLimitLayer::new(256))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<Body>| {
                    let request_id = request
                        .headers()
                        .get("x-request-id")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("missing");

                    tracing::info_span!(
                        "http.request",
                        %request_id,
                        method = %request.method(),
                        path = request.uri().path(),
                    )
                })
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(CatchPanicLayer::new())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            settings.request_timeout(),
        ))
        .layer(RequestBodyDeadlineLayer::new(settings.request_timeout()))
        .layer(RequestBodyLimitLayer::new(settings.max_request_body_bytes));

    Router::new()
        .merge(health::router())
        .merge(whatsapp_routes::router())
        .merge(billing_routes::router())
        .fallback(not_found)
        .with_state(state)
        .layer(middleware)
        .layer(middleware::from_fn(request_id::assign))
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: &'static str,
}

async fn not_found() -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            code: "not_found",
            message: "the requested resource does not exist",
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::not_found;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn unknown_routes_use_stable_error_code() {
        let (status, body) = not_found().await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body.0.code, "not_found");
    }
}
