use crate::{AppState, billing::BillingWebhookError};
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{
        HeaderMap, StatusCode,
        header::{CONTENT_ENCODING, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
    routing::post,
};

const SIGNATURE: &str = "x-razorpay-signature";
const EVENT_ID: &str = "x-razorpay-event-id";

pub fn router() -> Router<AppState> {
    Router::new().route("/webhooks/razorpay", post(receive))
}

async fn receive(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(service) = state.razorpay() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| !value.to_ascii_lowercase().starts_with("application/json"))
        || headers
            .get(CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    if body.len() > service.maximum_body_bytes() {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Some(signature) = single_header(&headers, SIGNATURE) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(event_id) = single_header(&headers, EVENT_ID) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !service.verify(signature, &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match service.accept(event_id, &body).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(BillingWebhookError::Invalid) => StatusCode::BAD_REQUEST.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(first)
}

#[cfg(test)]
mod tests {
    use super::{EVENT_ID, SIGNATURE};
    use crate::{AppState, billing::RazorpayWebhookService, build_router};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use hmac::{Hmac, Mac, digest::KeyInit};
    use sahayak_configuration::{DatabaseSettings, HttpSettings};
    use sahayak_payments::RazorpaySecrets;
    use sahayak_persistence::Database;
    use secrecy::SecretString;
    use sha2::Sha256;
    use std::{env, net::IpAddr, time::Duration};
    use tower::ServiceExt;

    #[tokio::test]
    async fn verifies_and_deduplicates_exact_webhook_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let Ok(url) = env::var("SAHAYAK_TEST_DATABASE_URL") else {
            return Ok(());
        };
        let database = Database::connect(&database_settings(url), "billing-webhook-test").await?;
        let body = br#"{"entity":"event","event":"subscription.updated","payload":{}}"#;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"webhook-secret")?;
        mac.update(body);
        let signature = hex::encode(mac.finalize().into_bytes());
        let service = RazorpayWebhookService::from_parts(
            RazorpaySecrets::new(SecretString::from("webhook-secret"), None),
            database.clone(),
            262_144,
        );
        let app = build_router(
            AppState::new(database.clone(), Duration::from_secs(1)).with_razorpay(service),
            &http_settings(),
        );
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/webhooks/razorpay")
                        .header("content-type", "application/json")
                        .header(SIGNATURE, &signature)
                        .header(EVENT_ID, "event_test_123")
                        .body(Body::from(body.as_slice()))?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
        }
        let invalid = app
            .oneshot(
                Request::post("/webhooks/razorpay")
                    .header("content-type", "application/json")
                    .header(SIGNATURE, "00")
                    .header(EVENT_ID, "event_invalid")
                    .body(Body::from(body.as_slice()))?,
            )
            .await?;
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
        database.close().await;
        Ok(())
    }

    fn database_settings(url: String) -> DatabaseSettings {
        DatabaseSettings {
            url: SecretString::from(url),
            min_connections: 1,
            max_connections: 3,
            acquire_timeout_seconds: 5,
            idle_timeout_seconds: 30,
            max_lifetime_seconds: 60,
            statement_timeout_milliseconds: 10_000,
            lock_timeout_milliseconds: 5_000,
            idle_in_transaction_timeout_milliseconds: 10_000,
            require_tls: false,
        }
    }

    fn http_settings() -> HttpSettings {
        HttpSettings {
            host: IpAddr::from([127, 0, 0, 1]),
            port: 8080,
            request_timeout_seconds: 5,
            readiness_timeout_seconds: 1,
            shutdown_grace_seconds: 5,
            max_request_body_bytes: 3_145_728,
        }
    }
}
