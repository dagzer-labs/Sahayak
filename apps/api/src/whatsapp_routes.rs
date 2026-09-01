use crate::{AppState, whatsapp::WebhookServiceError};
use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    http::{
        HeaderMap, StatusCode,
        header::{CONTENT_ENCODING, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use tracing::{error, info, warn};

const SIGNATURE_HEADER: &str = "x-hub-signature-256";

/// Builds Meta webhook verification and event routes.
pub fn router() -> Router<AppState> {
    Router::new().route(
        "/webhooks/whatsapp",
        get(verify_subscription).post(receive_webhook),
    )
}

#[derive(Deserialize)]
struct SubscriptionQuery {
    #[serde(rename = "hub.mode")]
    mode: String,
    #[serde(rename = "hub.verify_token")]
    verify_token: String,
    #[serde(rename = "hub.challenge")]
    challenge: String,
}

async fn verify_subscription(
    State(state): State<AppState>,
    Query(query): Query<SubscriptionQuery>,
) -> Response {
    let Some(service) = state.whatsapp() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match service.verify_subscription(&query.mode, &query.verify_token, &query.challenge) {
        Some(challenge) => (StatusCode::OK, challenge.to_owned()).into_response(),
        None => StatusCode::FORBIDDEN.into_response(),
    }
}

async fn receive_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(service) = state.whatsapp() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if !is_json(&headers) || !has_identity_encoding(&headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    if body.len() > service.maximum_body_bytes() {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let mut signatures = headers.get_all(SIGNATURE_HEADER).iter();
    let Some(signature) = signatures.next().and_then(|value| value.to_str().ok()) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if signatures.next().is_some() || !service.verify_signature(signature, &body) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    match service.accept(&body).await {
        Ok(outcome) => {
            info!(
                accepted = outcome.accepted,
                duplicates = outcome.duplicates,
                collisions = outcome.collisions,
                "accepted WhatsApp webhook"
            );
            if outcome.collisions > 0 {
                error!(
                    collisions = outcome.collisions,
                    "WhatsApp event identifier collision"
                );
            }
            StatusCode::OK.into_response()
        }
        Err(WebhookServiceError::Webhook(error)) => {
            warn!(%error, "rejected signed WhatsApp webhook");
            match error {
                sahayak_whatsapp::WebhookError::UnexpectedAccount => {
                    StatusCode::FORBIDDEN.into_response()
                }
                sahayak_whatsapp::WebhookError::TooManyEvents => {
                    StatusCode::PAYLOAD_TOO_LARGE.into_response()
                }
                sahayak_whatsapp::WebhookError::Malformed => {
                    StatusCode::BAD_REQUEST.into_response()
                }
            }
        }
        Err(error) => {
            error!(%error, "failed to durably accept WhatsApp webhook");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("application/json")
                || value.to_ascii_lowercase().starts_with("application/json;")
        })
}

fn has_identity_encoding(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| value.eq_ignore_ascii_case("identity"))
}

#[cfg(test)]
mod tests {
    use super::{SIGNATURE_HEADER, has_identity_encoding, is_json};
    use crate::{AppState, build_router, whatsapp::WhatsAppWebhookService};
    use axum::{
        body::{Body, to_bytes},
        http::{
            HeaderMap, HeaderValue, Request, StatusCode,
            header::{CONTENT_ENCODING, CONTENT_TYPE},
        },
    };
    use hmac::{Hmac, Mac, digest::KeyInit};
    use sahayak_configuration::{DatabaseSettings, HttpSettings};
    use sahayak_cryptography::{CryptoService, EncryptionKeySet, EncryptionPurpose, VersionedKey};
    use sahayak_persistence::Database;
    use sahayak_whatsapp::WebhookSecrets;
    use secrecy::SecretString;
    use sha2::Sha256;
    use std::{env, net::IpAddr, time::Duration};
    use tower::ServiceExt;

    const TEST_DATABASE_ENVIRONMENT: &str = "SAHAYAK_TEST_DATABASE_URL";

    #[test]
    fn requires_json_and_identity_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert!(is_json(&headers));
        assert!(has_identity_encoding(&headers));
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(!has_identity_encoding(&headers));
    }

    #[tokio::test]
    async fn verifies_and_deduplicates_signed_callbacks() -> Result<(), Box<dyn std::error::Error>>
    {
        let Ok(database_url) = env::var(TEST_DATABASE_ENVIRONMENT) else {
            return Ok(());
        };
        let assertion_pool = sqlx::PgPool::connect(&database_url).await?;
        let database =
            Database::connect(&database_settings(database_url), "webhook-route-test").await?;
        let cryptography = CryptoService::new(
            vec![EncryptionKeySet::new(
                EncryptionPurpose::Integration,
                1,
                vec![VersionedKey::from_bytes(1, [83; 32])?],
            )],
            1,
            vec![VersionedKey::from_bytes(1, [89; 32])?],
        )?;
        let service = WhatsAppWebhookService::from_parts(
            WebhookSecrets::new(
                SecretString::from("app-secret".to_owned()),
                None,
                SecretString::from("verify-token".to_owned()),
            ),
            cryptography,
            database.clone(),
            "123456".to_owned(),
            "789012".to_owned(),
            3_145_728,
            true,
        );
        let app = build_router(
            AppState::new(database.clone(), Duration::from_secs(1)).with_whatsapp(service),
            &http_settings(),
        );
        let verification = app
            .clone()
            .oneshot(Request::get("/webhooks/whatsapp?hub.mode=subscribe&hub.verify_token=verify-token&hub.challenge=challenge-123").body(Body::empty())?)
            .await?;
        assert_eq!(verification.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(verification.into_body(), 1_024).await?,
            "challenge-123"
        );

        let body = webhook_body();
        let valid_signature = signature(b"app-secret", body)?;
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/webhooks/whatsapp")
                        .header(CONTENT_TYPE, "application/json")
                        .header(SIGNATURE_HEADER, &valid_signature)
                        .body(Body::from(body))?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
        }
        let event_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM integration.inbound_events WHERE provider_namespace = '123456:789012' AND provider_event_id = 'message:wamid.route-test'",
        )
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(event_count, 1);
        let job_kind: String = sqlx::query_scalar(
            r#"
            SELECT job.job_kind
            FROM integration.outbox_jobs AS job
            JOIN integration.inbound_events AS event ON event.id = job.inbound_event_id
            WHERE event.provider_event_id = 'message:wamid.route-test'
            "#,
        )
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(job_kind, "process_whatsapp_probe");

        let invalid = app
            .clone()
            .oneshot(
                Request::post("/webhooks/whatsapp")
                    .header(CONTENT_TYPE, "application/json")
                    .header(
                        SIGNATURE_HEADER,
                        "sha256=0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .body(Body::from(invalid_signature_body()))?,
            )
            .await?;
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
        let invalid_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM integration.inbound_events WHERE provider_event_id = 'message:wamid.invalid-signature'",
        )
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(invalid_count, 0);

        let malformed_batch = malformed_batch_body();
        let malformed_response = app
            .oneshot(
                Request::post("/webhooks/whatsapp")
                    .header(CONTENT_TYPE, "application/json")
                    .header(SIGNATURE_HEADER, signature(b"app-secret", malformed_batch)?)
                    .body(Body::from(malformed_batch))?,
            )
            .await?;
        assert_eq!(malformed_response.status(), StatusCode::BAD_REQUEST);
        let rolled_back_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM integration.inbound_events WHERE provider_event_id = 'message:wamid.batch-valid'",
        )
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(rolled_back_count, 0);
        assertion_pool.close().await;
        database.close().await;
        Ok(())
    }

    fn signature(secret: &[u8], body: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret)?;
        mac.update(body);
        Ok(format!(
            "sha256={}",
            hex::encode(mac.finalize().into_bytes())
        ))
    }

    fn webhook_body() -> &'static [u8] {
        br#"{"object":"whatsapp_business_account","entry":[{"id":"123456","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"789012"},"messages":[{"from":"919876543210","id":"wamid.route-test","timestamp":"1750000000","type":"text","text":{"body":"__sahayak_transport_probe__"}}]}}]}]}"#
    }

    fn invalid_signature_body() -> &'static [u8] {
        br#"{"object":"whatsapp_business_account","entry":[{"id":"123456","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"789012"},"messages":[{"from":"919876543210","id":"wamid.invalid-signature","timestamp":"1750000000","type":"text","text":{"body":"Hello"}}]}}]}]}"#
    }

    fn malformed_batch_body() -> &'static [u8] {
        br#"{"object":"whatsapp_business_account","entry":[{"id":"123456","changes":[{"field":"messages","value":{"messaging_product":"whatsapp","metadata":{"phone_number_id":"789012"},"messages":[{"from":"919876543210","id":"wamid.batch-valid","timestamp":"1750000000","type":"text","text":{"body":"Hello"}},{"from":"919876543210","id":"wamid.batch-invalid","timestamp":"not-a-time","type":"text","text":{"body":"Broken"}}]}}]}]}"#
    }

    fn database_settings(url: String) -> DatabaseSettings {
        DatabaseSettings {
            url: SecretString::from(url),
            min_connections: 1,
            max_connections: 5,
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
