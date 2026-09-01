use crate::{ApiFailure, OutboundMessage, PreparedMessage, WhatsAppError};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use reqwest::{
    Client, Response, Url,
    header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue},
    multipart::{Form, Part},
    redirect::Policy,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fmt, time::Duration};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAX_RESPONSE_BYTES: usize = 65_536;

/// Non-secret endpoint configuration plus protected Meta access token.
#[derive(Clone)]
pub struct WhatsAppClientConfig {
    /// Graph API origin, normally `https://graph.facebook.com`.
    pub base_url: String,
    /// Explicit Graph API version such as `v26.0`.
    pub graph_api_version: String,
    /// Sender business phone-number object ID.
    pub phone_number_id: String,
    /// System-user access token with `whatsapp_business_messaging`.
    pub access_token: SecretString,
    /// Complete request deadline.
    pub timeout: Duration,
}

impl fmt::Debug for WhatsAppClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WhatsAppClientConfig")
            .field("base_url", &self.base_url)
            .field("graph_api_version", &self.graph_api_version)
            .field("phone_number_id", &self.phone_number_id)
            .field("access_token", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Meta acceptance receipt. Delivery is confirmed only by later status webhooks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendReceipt {
    /// Meta-generated message ID repeated in status webhooks.
    pub provider_message_id: String,
    /// Optional paced-template state returned synchronously by Meta.
    pub message_status: Option<String>,
}

/// Authenticated media bytes retrieved from Meta and verified against its digest.
#[derive(Clone)]
pub struct DownloadedMedia {
    /// Meta's declared media type, used only as an additional validation signal.
    media_type: String,
    /// Complete bounded source bytes. Callers must decode and sanitize before storage.
    bytes: Zeroizing<Vec<u8>>,
    /// SHA-256 verified against Meta's media metadata.
    sha256: [u8; 32],
}

impl DownloadedMedia {
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

impl fmt::Debug for DownloadedMedia {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DownloadedMedia")
            .field("media_type", &self.media_type)
            .field(
                "bytes",
                &format_args!("[REDACTED; {} bytes]", self.bytes.len()),
            )
            .field("sha256", &"[REDACTED]")
            .finish()
    }
}

/// Reusable WhatsApp Cloud API client with redacted authorization state.
#[derive(Clone)]
pub struct WhatsAppClient {
    http: Client,
    graph_root: Url,
    messages_endpoint: Url,
    media_endpoint: Url,
    authorization: HeaderValue,
}

impl WhatsAppClient {
    /// Builds a pinned Graph API client.
    pub fn new(config: &WhatsAppClientConfig) -> Result<Self, WhatsAppError> {
        validate_config(config)?;
        let endpoint = format!(
            "{}/{}/{}/messages",
            config.base_url.trim_end_matches('/'),
            config.graph_api_version,
            config.phone_number_id
        );
        let messages_endpoint = Url::parse(&endpoint).map_err(|_| {
            WhatsAppError::InvalidConfiguration("messages endpoint is not a valid URL".to_owned())
        })?;
        let graph_root = Url::parse(&format!(
            "{}/{}/",
            config.base_url.trim_end_matches('/'),
            config.graph_api_version
        ))
        .map_err(|_| {
            WhatsAppError::InvalidConfiguration("Graph API endpoint is not a valid URL".to_owned())
        })?;
        let media_endpoint = graph_root
            .join(&format!("{}/media", config.phone_number_id))
            .map_err(|_| {
                WhatsAppError::InvalidConfiguration("media upload endpoint is invalid".to_owned())
            })?;
        let mut authorization =
            HeaderValue::from_str(&format!("Bearer {}", config.access_token.expose_secret()))
                .map_err(|_| {
                    WhatsAppError::InvalidConfiguration(
                        "access token is not header-safe".to_owned(),
                    )
                })?;
        authorization.set_sensitive(true);
        let http = Client::builder()
            .redirect(Policy::none())
            .timeout(config.timeout)
            .user_agent("sahayak-whatsapp/0.1")
            .build()
            .map_err(|_| {
                WhatsAppError::InvalidConfiguration("HTTP client construction failed".to_owned())
            })?;
        Ok(Self {
            http,
            graph_root,
            messages_endpoint,
            media_endpoint,
            authorization,
        })
    }

    /// Submits a message to Meta and returns only an acceptance receipt.
    pub async fn send(&self, message: &OutboundMessage) -> Result<SendReceipt, WhatsAppError> {
        let prepared = message
            .prepare()
            .map_err(|error| WhatsAppError::InvalidConfiguration(error.to_string()))?;
        self.send_prepared(&prepared).await
    }

    /// Submits a previously validated and authenticated decrypted message payload.
    pub async fn send_prepared(
        &self,
        message: &PreparedMessage,
    ) -> Result<SendReceipt, WhatsAppError> {
        let response = self
            .http
            .post(self.messages_endpoint.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .body(message.expose().to_vec())
            .send()
            .await
            .map_err(classify_transport_error)?;
        let status = response.status();
        let retry_after_seconds = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let bytes =
            read_bounded(response, MAX_RESPONSE_BYTES)
                .await
                .map_err(|error| match error {
                    WhatsAppError::MediaTransport => WhatsAppError::AmbiguousTransport,
                    _ => WhatsAppError::InvalidSuccessResponse,
                })?;

        if status.is_success() {
            let success: SendResponse = serde_json::from_slice(&bytes)
                .map_err(|_| WhatsAppError::InvalidSuccessResponse)?;
            let message = success
                .messages
                .into_iter()
                .next()
                .filter(|message| !message.id.is_empty())
                .ok_or(WhatsAppError::InvalidSuccessResponse)?;
            return Ok(SendReceipt {
                provider_message_id: message.id,
                message_status: message.message_status,
            });
        }

        let graph_error: Option<GraphErrorEnvelope> = serde_json::from_slice(&bytes).ok();
        let code = graph_error.as_ref().map(|error| error.error.code);
        Err(WhatsAppError::Api(ApiFailure {
            http_status: status.as_u16(),
            code,
            class: ApiFailure::classify(status.as_u16(), code),
            trace_id: graph_error.and_then(|error| error.error.fbtrace_id),
            retry_after_seconds,
        }))
    }

    /// Resolves and downloads one Meta-hosted media object without following redirects.
    pub async fn download_media(
        &self,
        media_id: &str,
        maximum_bytes: usize,
    ) -> Result<DownloadedMedia, WhatsAppError> {
        if media_id.is_empty()
            || media_id.len() > 128
            || !media_id.bytes().all(|byte| byte.is_ascii_digit())
            || !(1..=16 * 1_024 * 1_024).contains(&maximum_bytes)
        {
            return Err(WhatsAppError::InvalidConfiguration(
                "media ID or download size limit is invalid".to_owned(),
            ));
        }

        let metadata_endpoint = self.graph_root.join(media_id).map_err(|_| {
            WhatsAppError::InvalidConfiguration("media endpoint is not a valid URL".to_owned())
        })?;
        let metadata_response = self
            .http
            .get(metadata_endpoint)
            .header(AUTHORIZATION, self.authorization.clone())
            .send()
            .await
            .map_err(|_| WhatsAppError::MediaTransport)?;
        if !metadata_response.status().is_success() {
            return Err(media_api_error(metadata_response).await);
        }
        let metadata_bytes = read_bounded(metadata_response, MAX_RESPONSE_BYTES).await?;
        let metadata: MediaMetadata = serde_json::from_slice(&metadata_bytes)
            .map_err(|_| WhatsAppError::InvalidMediaResponse)?;
        if metadata.id != media_id
            || metadata.file_size == 0
            || metadata.file_size > maximum_bytes as u64
            || !matches!(metadata.mime_type.as_str(), "image/jpeg" | "image/png")
        {
            return Err(if metadata.file_size > maximum_bytes as u64 {
                WhatsAppError::MediaTooLarge
            } else {
                WhatsAppError::InvalidMediaResponse
            });
        }
        let expected_digest = decode_media_digest(&metadata.sha256)?;
        let download_url =
            Url::parse(&metadata.url).map_err(|_| WhatsAppError::InvalidMediaResponse)?;
        if !media_url_allowed(&self.graph_root, &download_url) {
            return Err(WhatsAppError::UnsafeMediaUrl);
        }

        let response = self
            .http
            .get(download_url)
            .header(AUTHORIZATION, self.authorization.clone())
            .send()
            .await
            .map_err(|_| WhatsAppError::MediaTransport)?;
        if !response.status().is_success() {
            return Err(media_api_error(response).await);
        }
        if response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > maximum_bytes)
        {
            return Err(WhatsAppError::MediaTooLarge);
        }
        let bytes = read_bounded(response, maximum_bytes).await?;
        if bytes.len() != metadata.file_size as usize {
            return Err(WhatsAppError::InvalidMediaResponse);
        }
        let actual_digest: [u8; 32] = Sha256::digest(&bytes).into();
        if !bool::from(actual_digest.ct_eq(&expected_digest)) {
            return Err(WhatsAppError::InvalidMediaResponse);
        }
        Ok(DownloadedMedia {
            media_type: metadata.mime_type,
            bytes,
            sha256: actual_digest,
        })
    }

    /// Uploads one sanitized JPEG for an authorized WhatsApp delivery.
    pub async fn upload_sanitized_image(&self, jpeg: &[u8]) -> Result<String, WhatsAppError> {
        if jpeg.is_empty() || jpeg.len() > 5 * 1_024 * 1_024 {
            return Err(WhatsAppError::MediaTooLarge);
        }
        let part = Part::bytes(jpeg.to_vec())
            .file_name("profile.jpg")
            .mime_str("image/jpeg")
            .map_err(|_| WhatsAppError::InvalidMediaResponse)?;
        let response = self
            .http
            .post(self.media_endpoint.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .multipart(
                Form::new()
                    .text("messaging_product", "whatsapp")
                    .part("file", part),
            )
            .send()
            .await
            .map_err(|_| WhatsAppError::MediaTransport)?;
        if !response.status().is_success() {
            return Err(media_api_error(response).await);
        }
        let bytes = read_bounded(response, MAX_RESPONSE_BYTES).await?;
        let uploaded: MediaUploadResponse =
            serde_json::from_slice(&bytes).map_err(|_| WhatsAppError::InvalidMediaResponse)?;
        if uploaded.id.is_empty()
            || uploaded.id.len() > 128
            || !uploaded.id.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(WhatsAppError::InvalidMediaResponse);
        }
        Ok(uploaded.id)
    }
}

impl fmt::Debug for WhatsAppClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WhatsAppClient")
            .field("graph_root", &self.graph_root)
            .field("messages_endpoint", &self.messages_endpoint)
            .field("media_endpoint", &self.media_endpoint)
            .finish_non_exhaustive()
    }
}

fn validate_config(config: &WhatsAppClientConfig) -> Result<(), WhatsAppError> {
    let base_url = Url::parse(&config.base_url).map_err(|_| {
        WhatsAppError::InvalidConfiguration("Graph API base URL is invalid".to_owned())
    })?;
    let loopback_http = base_url.scheme() == "http"
        && matches!(base_url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if (base_url.scheme() != "https" && !loopback_http)
        || base_url.host_str().is_none()
        || !base_url.username().is_empty()
        || base_url.password().is_some()
        || base_url.query().is_some()
        || base_url.fragment().is_some()
    {
        return Err(WhatsAppError::InvalidConfiguration(
            "Graph API base URL must be a safe HTTPS origin".to_owned(),
        ));
    }
    let version = config.graph_api_version.as_bytes();
    let version_valid = version.len() >= 4
        && version.first() == Some(&b'v')
        && version[1..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b'.')
        && config.graph_api_version.contains('.');
    if !version_valid {
        return Err(WhatsAppError::InvalidConfiguration(
            "Graph API version must look like v26.0".to_owned(),
        ));
    }
    if config.phone_number_id.is_empty()
        || !config
            .phone_number_id
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err(WhatsAppError::InvalidConfiguration(
            "phone-number ID must contain only digits".to_owned(),
        ));
    }
    if config.access_token.expose_secret().trim().is_empty() {
        return Err(WhatsAppError::InvalidConfiguration(
            "access token cannot be empty".to_owned(),
        ));
    }
    if config.timeout.is_zero() || config.timeout > Duration::from_secs(120) {
        return Err(WhatsAppError::InvalidConfiguration(
            "request timeout must be between 1 millisecond and 120 seconds".to_owned(),
        ));
    }
    Ok(())
}

fn classify_transport_error(error: reqwest::Error) -> WhatsAppError {
    if error.is_connect() {
        WhatsAppError::Connection
    } else {
        WhatsAppError::AmbiguousTransport
    }
}

async fn read_bounded(
    mut response: Response,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, WhatsAppError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(maximum_bytes.min(64 * 1_024)));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| WhatsAppError::MediaTransport)?
    {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > maximum_bytes)
        {
            return Err(WhatsAppError::MediaTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn media_api_error(response: Response) -> WhatsAppError {
    let status = response.status();
    let retry_after_seconds = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let bytes = read_bounded(response, MAX_RESPONSE_BYTES)
        .await
        .unwrap_or_default();
    let graph_error: Option<GraphErrorEnvelope> = serde_json::from_slice(&bytes).ok();
    let code = graph_error.as_ref().map(|error| error.error.code);
    WhatsAppError::Api(ApiFailure {
        http_status: status.as_u16(),
        code,
        class: ApiFailure::classify(status.as_u16(), code),
        trace_id: graph_error.and_then(|error| error.error.fbtrace_id),
        retry_after_seconds,
    })
}

fn decode_media_digest(value: &str) -> Result<[u8; 32], WhatsAppError> {
    let decoded = hex::decode(value)
        .or_else(|_| BASE64_STANDARD.decode(value))
        .map_err(|_| WhatsAppError::InvalidMediaResponse)?;
    decoded
        .try_into()
        .map_err(|_| WhatsAppError::InvalidMediaResponse)
}

fn media_url_allowed(graph_root: &Url, candidate: &Url) -> bool {
    if !candidate.username().is_empty()
        || candidate.password().is_some()
        || candidate.fragment().is_some()
    {
        return false;
    }
    let same_origin = graph_root.scheme() == candidate.scheme()
        && graph_root.host_str() == candidate.host_str()
        && graph_root.port_or_known_default() == candidate.port_or_known_default();
    if graph_root.scheme() == "http" {
        return same_origin;
    }
    if candidate.scheme() != "https" || candidate.port_or_known_default() != Some(443) {
        return false;
    }
    let Some(host) = candidate.host_str() else {
        return false;
    };
    same_origin || host == "lookaside.fbsbx.com"
}

#[derive(Deserialize)]
struct SendResponse {
    messages: Vec<SentMessage>,
}

#[derive(Deserialize)]
struct SentMessage {
    id: String,
    message_status: Option<String>,
}

#[derive(Deserialize)]
struct GraphErrorEnvelope {
    error: GraphError,
}

#[derive(Deserialize)]
struct GraphError {
    code: i64,
    fbtrace_id: Option<String>,
}

#[derive(Deserialize)]
struct MediaMetadata {
    id: String,
    url: String,
    mime_type: String,
    sha256: String,
    file_size: u64,
}

#[derive(Deserialize)]
struct MediaUploadResponse {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::{WhatsAppClient, WhatsAppClientConfig};
    use crate::{FailureClass, OutboundMessage, TextMessage, WhatsAppError};
    use sahayak_cryptography::NormalizedPhoneNumber;
    use secrecy::SecretString;
    use sha2::{Digest, Sha256};
    use std::time::Duration;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    fn config(server: &MockServer) -> WhatsAppClientConfig {
        WhatsAppClientConfig {
            base_url: server.uri(),
            graph_api_version: "v26.0".to_owned(),
            phone_number_id: "123456789".to_owned(),
            access_token: SecretString::from("test-token".to_owned()),
            timeout: Duration::from_secs(5),
        }
    }

    fn message() -> Result<OutboundMessage, Box<dyn std::error::Error>> {
        let recipient = NormalizedPhoneNumber::parse("+919876543210")?;
        Ok(OutboundMessage::text(
            &recipient,
            TextMessage::new("Hello", false)?,
        ))
    }

    #[tokio::test]
    async fn returns_meta_acceptance_receipt() -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v26.0/123456789/messages"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{"messaging_product":"whatsapp","contacts":[{"input":"+919876543210","wa_id":"919876543210"}],"messages":[{"id":"wamid.test"}]}"#,
                "application/json",
            ))
            .mount(&server)
            .await;
        let client = WhatsAppClient::new(&config(&server))?;
        let receipt = client.send(&message()?).await?;
        assert_eq!(receipt.provider_message_id, "wamid.test");
        Ok(())
    }

    #[tokio::test]
    async fn classifies_meta_throttling_by_code() -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_raw(
                r#"{"error":{"message":"rate limited","type":"OAuthException","code":130429,"fbtrace_id":"trace"}}"#,
                "application/json",
            ))
            .mount(&server)
            .await;
        let client = WhatsAppClient::new(&config(&server))?;
        let error = client
            .send(&message()?)
            .await
            .err()
            .ok_or("expected failure")?;
        match error {
            WhatsAppError::Api(failure) => assert_eq!(failure.class, FailureClass::Retryable),
            other => return Err(format!("unexpected error: {other:?}").into()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn meta_outage_is_ambiguous_and_reveals_no_provider_body()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_string("temporary private detail"))
            .mount(&server)
            .await;
        let client = WhatsAppClient::new(&config(&server))?;
        let error = client
            .send(&message()?)
            .await
            .err()
            .ok_or("expected outage failure")?;
        match error {
            WhatsAppError::Api(failure) => {
                assert_eq!(failure.class, FailureClass::Ambiguous);
                assert!(!format!("{failure:?}").contains("temporary private detail"));
            }
            other => return Err(format!("unexpected error: {other:?}").into()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn downloads_bounded_media_and_verifies_digest() -> Result<(), Box<dyn std::error::Error>>
    {
        let server = MockServer::start().await;
        let source = b"not-yet-decoded-image";
        let digest = hex::encode(Sha256::digest(source));
        Mock::given(method("GET"))
            .and(path("/v26.0/98765"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "98765",
                "url": format!("{}/media", server.uri()),
                "mime_type": "image/jpeg",
                "sha256": digest,
                "file_size": source.len()
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/media"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(source))
            .mount(&server)
            .await;

        let media = WhatsAppClient::new(&config(&server))?
            .download_media("98765", 1_024)
            .await?;
        let expected_digest: [u8; 32] = Sha256::digest(source).into();
        assert_eq!(media.media_type(), "image/jpeg");
        assert_eq!(media.bytes(), source);
        assert_eq!(media.sha256(), expected_digest);
        assert!(!format!("{media:?}").contains("not-yet-decoded-image"));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_unsafe_or_oversized_media_metadata() -> Result<(), Box<dyn std::error::Error>>
    {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v26.0/98765"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "98765",
                "url": "https://attacker.example/media",
                "mime_type": "image/jpeg",
                "sha256": hex::encode([1_u8; 32]),
                "file_size": 10
            })))
            .mount(&server)
            .await;
        let error = WhatsAppClient::new(&config(&server))?
            .download_media("98765", 1_024)
            .await
            .err()
            .ok_or("expected unsafe URL failure")?;
        assert!(matches!(error, WhatsAppError::UnsafeMediaUrl));

        let oversized_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v26.0/98765"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "98765",
                "url": format!("{}/media", oversized_server.uri()),
                "mime_type": "image/png",
                "sha256": hex::encode([1_u8; 32]),
                "file_size": 2048
            })))
            .mount(&oversized_server)
            .await;
        let error = WhatsAppClient::new(&config(&oversized_server))?
            .download_media("98765", 1_024)
            .await
            .err()
            .ok_or("expected size failure")?;
        assert!(matches!(error, WhatsAppError::MediaTooLarge));
        Ok(())
    }

    #[tokio::test]
    async fn uploads_sanitized_image_with_authenticated_multipart()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v26.0/123456789/media"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "77777"
            })))
            .mount(&server)
            .await;
        let media_id = WhatsAppClient::new(&config(&server))?
            .upload_sanitized_image(&[0xff, 0xd8, 0xff, 0xd9])
            .await?;
        assert_eq!(media_id, "77777");
        Ok(())
    }
}
