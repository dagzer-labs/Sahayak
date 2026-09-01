use hmac::{Hmac, Mac, digest::KeyInit};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::OffsetDateTime;

type HmacSha256 = Hmac<Sha256>;
const MAX_LOGICAL_EVENTS: usize = 1_000;

/// Current and previous app secrets plus the independent webhook verification token.
pub struct WebhookSecrets {
    current_app_secret: SecretString,
    previous_app_secret: Option<SecretString>,
    verify_token: SecretString,
}

impl WebhookSecrets {
    /// Creates a rotation-aware verifier.
    #[must_use]
    pub fn new(
        current_app_secret: SecretString,
        previous_app_secret: Option<SecretString>,
        verify_token: SecretString,
    ) -> Self {
        Self {
            current_app_secret,
            previous_app_secret,
            verify_token,
        }
    }

    /// Validates Meta's GET subscription challenge without exposing the token.
    #[must_use]
    pub fn verify_subscription<'a>(
        &self,
        mode: &str,
        token: &str,
        challenge: &'a str,
    ) -> Option<&'a str> {
        let expected = self.verify_token.expose_secret().as_bytes();
        let supplied = token.as_bytes();
        let token_matches =
            expected.len() == supplied.len() && bool::from(expected.ct_eq(supplied));
        let challenge_valid = !challenge.is_empty()
            && challenge.len() <= 512
            && !challenge.chars().any(char::is_control);
        (mode == "subscribe" && token_matches && challenge_valid).then_some(challenge)
    }

    /// Verifies one exact `X-Hub-Signature-256` value against raw body bytes.
    #[must_use]
    pub fn verify_signature(&self, signature: &str, raw_body: &[u8]) -> bool {
        let Some(encoded_digest) = signature.strip_prefix("sha256=") else {
            return false;
        };
        if encoded_digest.len() != 64 {
            return false;
        }
        let Ok(expected_digest) = hex::decode(encoded_digest) else {
            return false;
        };
        verify_hmac(
            self.current_app_secret.expose_secret().as_bytes(),
            raw_body,
            &expected_digest,
        ) || self.previous_app_secret.as_ref().is_some_and(|secret| {
            verify_hmac(
                secret.expose_secret().as_bytes(),
                raw_body,
                &expected_digest,
            )
        })
    }
}

impl fmt::Debug for WebhookSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookSecrets")
            .field("current_app_secret", &"[REDACTED]")
            .field(
                "previous_app_secret",
                &self.previous_app_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("verify_token", &"[REDACTED]")
            .finish()
    }
}

/// Signed webhook parsing or account-routing failure.
#[derive(Debug, Error)]
pub enum WebhookError {
    /// JSON does not satisfy the pinned Meta envelope contract.
    #[error("signed webhook payload is malformed")]
    Malformed,
    /// Callback belongs to another WABA or business phone-number resource.
    #[error("signed webhook payload targets an unexpected Meta account")]
    UnexpectedAccount,
    /// Callback contains more logical updates than the supported Meta maximum.
    #[error("signed webhook exceeds the logical event limit")]
    TooManyEvents,
}

/// One logical message, status, or provider-error event extracted from a callback.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct NormalizedEvent {
    /// Stable provider event key used for deduplication.
    pub provider_event_id: String,
    /// Versioned internal event category.
    pub event_type: String,
    /// Provider occurrence time when available.
    pub occurred_at: Option<OffsetDateTime>,
    /// Provider-neutral encrypted-at-rest event data.
    pub payload: NormalizedPayload,
}

/// Provider-neutral payload retained for later workflow processing.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NormalizedPayload {
    /// Incoming user message.
    Message {
        provider_message_id: String,
        sender_wa_id: String,
        sender_phone_e164: String,
        context_message_id: Option<String>,
        content: NormalizedContent,
        error_codes: Vec<i64>,
    },
    /// Outbound delivery transition.
    Status {
        provider_message_id: String,
        status: String,
        recipient_id: String,
        participant_id: Option<String>,
        callback_data: Option<String>,
        error_codes: Vec<i64>,
    },
    /// App, account, or provider processing error without a stable Meta event ID.
    ProviderError { error_codes: Vec<i64> },
}

/// Normalized incoming content variants needed by Sahayak workflows.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NormalizedContent {
    /// Plain text.
    Text { body: String },
    /// Interactive or template-button selection.
    Action {
        source: String,
        id: String,
        title: Option<String>,
        description: Option<String>,
    },
    /// Exact user-shared location.
    Location {
        latitude: f64,
        longitude: f64,
        name: Option<String>,
        address: Option<String>,
    },
    /// Media reference resolved separately through Meta's Media API.
    Media {
        media_type: String,
        media_id: String,
        mime_type: Option<String>,
        sha256: Option<String>,
        caption: Option<String>,
        filename: Option<String>,
    },
    /// Signed message shape that is intentionally unsupported by current workflows.
    Unsupported { original_type: String },
}

/// Parses every logical message, status, and value-level error from a signed envelope.
pub fn parse_webhook(
    raw_body: &[u8],
    expected_waba_id: &str,
    expected_phone_number_id: &str,
) -> Result<Vec<NormalizedEvent>, WebhookError> {
    let envelope: Envelope =
        serde_json::from_slice(raw_body).map_err(|_| WebhookError::Malformed)?;
    let envelope_hash = Sha256::digest(raw_body);
    if envelope.object != "whatsapp_business_account" {
        return Err(WebhookError::Malformed);
    }
    let mut events = Vec::new();
    for entry in envelope.entry {
        if entry.id != expected_waba_id {
            return Err(WebhookError::UnexpectedAccount);
        }
        for change in entry.changes {
            if change.field != "messages"
                || change.value.messaging_product.as_deref() != Some("whatsapp")
                || change.value.metadata.phone_number_id != expected_phone_number_id
            {
                return Err(WebhookError::UnexpectedAccount);
            }
            let contact_wa_id = change
                .value
                .contacts
                .first()
                .map(|contact| contact.wa_id.as_str());
            for message in change.value.messages {
                events.push(normalize_message(message, contact_wa_id)?);
                enforce_event_limit(events.len())?;
            }
            for status in change.value.statuses {
                events.push(normalize_status(status)?);
                enforce_event_limit(events.len())?;
            }
            if !change.value.errors.is_empty() {
                events.push(normalize_provider_error(
                    &entry.id,
                    expected_phone_number_id,
                    change.value.errors,
                    &envelope_hash,
                ));
                enforce_event_limit(events.len())?;
            }
        }
    }
    Ok(events)
}

fn normalize_message(
    message: Message,
    contact_wa_id: Option<&str>,
) -> Result<NormalizedEvent, WebhookError> {
    validate_opaque(&message.id, 512)?;
    validate_opaque(&message.from, 64)?;
    let occurred_at = parse_timestamp(&message.timestamp)?;
    let sender_wa_id = bounded(contact_wa_id.unwrap_or(&message.from).to_owned(), 64)?;
    let sender_phone_e164 = if message.from.starts_with('+') {
        bounded(message.from.clone(), 16)?
    } else {
        bounded(format!("+{}", message.from), 16)?
    };
    let context_message_id = message
        .context
        .map(|context| bounded(context.id, 512))
        .transpose()?;
    let content = match message.kind.as_str() {
        "text" => NormalizedContent::Text {
            body: bounded(message.text.ok_or(WebhookError::Malformed)?.body, 4_096)?,
        },
        "interactive" => {
            normalize_interactive(message.interactive.ok_or(WebhookError::Malformed)?)?
        }
        "button" => {
            let button = message.button.ok_or(WebhookError::Malformed)?;
            NormalizedContent::Action {
                source: "template_button".to_owned(),
                id: bounded(button.payload, 256)?,
                title: optional_bounded(button.text, 20)?,
                description: None,
            }
        }
        "location" => normalize_location(message.location.ok_or(WebhookError::Malformed)?)?,
        "image" => normalize_media("image", message.image.ok_or(WebhookError::Malformed)?)?,
        "audio" => normalize_media("audio", message.audio.ok_or(WebhookError::Malformed)?)?,
        "document" => {
            normalize_media("document", message.document.ok_or(WebhookError::Malformed)?)?
        }
        "video" => normalize_media("video", message.video.ok_or(WebhookError::Malformed)?)?,
        "sticker" => normalize_media("sticker", message.sticker.ok_or(WebhookError::Malformed)?)?,
        other => NormalizedContent::Unsupported {
            original_type: bounded(other.to_owned(), 64)?,
        },
    };
    Ok(NormalizedEvent {
        provider_event_id: format!("message:{}", message.id),
        event_type: "message.received".to_owned(),
        occurred_at: Some(occurred_at),
        payload: NormalizedPayload::Message {
            provider_message_id: message.id,
            sender_wa_id,
            sender_phone_e164,
            context_message_id,
            content,
            error_codes: message.errors.into_iter().map(|error| error.code).collect(),
        },
    })
}

fn normalize_status(status: Status) -> Result<NormalizedEvent, WebhookError> {
    validate_opaque(&status.id, 512)?;
    validate_opaque(&status.recipient_id, 64)?;
    validate_machine_code(&status.status, 32)?;
    let occurred_at = parse_timestamp(&status.timestamp)?;
    let key_material = format!(
        "{}\0{}\0{}\0{}\0{}",
        status.id,
        status.status,
        status.timestamp,
        status.recipient_id,
        status.recipient_participant_id.as_deref().unwrap_or("")
    );
    let provider_event_id = format!(
        "status:{}",
        hex::encode(Sha256::digest(key_material.as_bytes()))
    );
    Ok(NormalizedEvent {
        provider_event_id,
        event_type: "message.status".to_owned(),
        occurred_at: Some(occurred_at),
        payload: NormalizedPayload::Status {
            provider_message_id: status.id,
            status: status.status,
            recipient_id: status.recipient_id,
            participant_id: status.recipient_participant_id,
            callback_data: optional_bounded(status.biz_opaque_callback_data, 512)?,
            error_codes: status.errors.into_iter().map(|error| error.code).collect(),
        },
    })
}

fn normalize_provider_error(
    waba_id: &str,
    phone_number_id: &str,
    errors: Vec<ProviderError>,
    envelope_hash: &[u8],
) -> NormalizedEvent {
    let mut codes: Vec<_> = errors.into_iter().map(|error| error.code).collect();
    codes.sort_unstable();
    let material = format!(
        "{waba_id}\0{phone_number_id}\0{codes:?}\0{}",
        hex::encode(envelope_hash)
    );
    NormalizedEvent {
        provider_event_id: format!("error:{}", hex::encode(Sha256::digest(material.as_bytes()))),
        event_type: "provider.error".to_owned(),
        occurred_at: None,
        payload: NormalizedPayload::ProviderError { error_codes: codes },
    }
}

fn normalize_interactive(interactive: Interactive) -> Result<NormalizedContent, WebhookError> {
    match interactive.kind.as_str() {
        "button_reply" => {
            let reply = interactive.button_reply.ok_or(WebhookError::Malformed)?;
            Ok(NormalizedContent::Action {
                source: "button_reply".to_owned(),
                id: bounded(reply.id, 256)?,
                title: optional_bounded(reply.title, 20)?,
                description: None,
            })
        }
        "list_reply" => {
            let reply = interactive.list_reply.ok_or(WebhookError::Malformed)?;
            Ok(NormalizedContent::Action {
                source: "list_reply".to_owned(),
                id: bounded(reply.id, 200)?,
                title: optional_bounded(reply.title, 24)?,
                description: optional_bounded(reply.description, 72)?,
            })
        }
        other => Ok(NormalizedContent::Unsupported {
            original_type: bounded(other.to_owned(), 64)?,
        }),
    }
}

fn normalize_location(location: Location) -> Result<NormalizedContent, WebhookError> {
    if !location.latitude.is_finite()
        || !location.longitude.is_finite()
        || !(-90.0..=90.0).contains(&location.latitude)
        || !(-180.0..=180.0).contains(&location.longitude)
    {
        return Err(WebhookError::Malformed);
    }
    Ok(NormalizedContent::Location {
        latitude: location.latitude,
        longitude: location.longitude,
        name: optional_bounded(location.name, 1_024)?,
        address: optional_bounded(location.address, 1_024)?,
    })
}

fn normalize_media(kind: &str, media: Media) -> Result<NormalizedContent, WebhookError> {
    Ok(NormalizedContent::Media {
        media_type: kind.to_owned(),
        media_id: bounded(media.id, 512)?,
        mime_type: optional_bounded(media.mime_type, 128)?,
        sha256: optional_bounded(media.sha256, 128)?,
        caption: optional_bounded(media.caption, 1_024)?,
        filename: optional_bounded(media.filename, 255)?,
    })
}

fn parse_timestamp(value: &str) -> Result<OffsetDateTime, WebhookError> {
    let timestamp: i64 = value.parse().map_err(|_| WebhookError::Malformed)?;
    OffsetDateTime::from_unix_timestamp(timestamp).map_err(|_| WebhookError::Malformed)
}

fn enforce_event_limit(count: usize) -> Result<(), WebhookError> {
    if count > MAX_LOGICAL_EVENTS {
        Err(WebhookError::TooManyEvents)
    } else {
        Ok(())
    }
}

fn bounded(value: String, maximum: usize) -> Result<String, WebhookError> {
    if value.is_empty() || value.chars().count() > maximum || value.chars().any(char::is_control) {
        Err(WebhookError::Malformed)
    } else {
        Ok(value)
    }
}

fn optional_bounded(value: Option<String>, maximum: usize) -> Result<Option<String>, WebhookError> {
    value.map(|value| bounded(value, maximum)).transpose()
}

fn validate_opaque(value: &str, maximum: usize) -> Result<(), WebhookError> {
    bounded(value.to_owned(), maximum).map(|_| ())
}

fn validate_machine_code(value: &str, maximum: usize) -> Result<(), WebhookError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err(WebhookError::Malformed);
    }
    Ok(())
}

fn verify_hmac(secret: &[u8], body: &[u8], expected_digest: &[u8]) -> bool {
    let Ok(mut mac) = <HmacSha256 as KeyInit>::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(expected_digest).is_ok()
}

#[derive(Deserialize)]
struct Envelope {
    object: String,
    #[serde(default)]
    entry: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    id: String,
    #[serde(default)]
    changes: Vec<Change>,
}

#[derive(Deserialize)]
struct Change {
    field: String,
    value: Value,
}

#[derive(Deserialize)]
struct Value {
    messaging_product: Option<String>,
    metadata: Metadata,
    #[serde(default)]
    contacts: Vec<Contact>,
    #[serde(default)]
    messages: Vec<Message>,
    #[serde(default)]
    statuses: Vec<Status>,
    #[serde(default)]
    errors: Vec<ProviderError>,
}

#[derive(Deserialize)]
struct Contact {
    wa_id: String,
}

#[derive(Deserialize)]
struct Metadata {
    phone_number_id: String,
}

#[derive(Deserialize)]
struct Message {
    from: String,
    id: String,
    timestamp: String,
    #[serde(rename = "type")]
    kind: String,
    context: Option<MessageContext>,
    text: Option<Text>,
    interactive: Option<Interactive>,
    button: Option<LegacyButton>,
    location: Option<Location>,
    image: Option<Media>,
    audio: Option<Media>,
    document: Option<Media>,
    video: Option<Media>,
    sticker: Option<Media>,
    #[serde(default)]
    errors: Vec<ProviderError>,
}

#[derive(Deserialize)]
struct MessageContext {
    id: String,
}

#[derive(Deserialize)]
struct Text {
    body: String,
}

#[derive(Deserialize)]
struct Interactive {
    #[serde(rename = "type")]
    kind: String,
    button_reply: Option<InteractiveReply>,
    list_reply: Option<ListReply>,
}

#[derive(Deserialize)]
struct InteractiveReply {
    id: String,
    title: Option<String>,
}

#[derive(Deserialize)]
struct ListReply {
    id: String,
    title: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize)]
struct LegacyButton {
    payload: String,
    text: Option<String>,
}

#[derive(Deserialize)]
struct Location {
    latitude: f64,
    longitude: f64,
    name: Option<String>,
    address: Option<String>,
}

#[derive(Deserialize)]
struct Media {
    id: String,
    mime_type: Option<String>,
    sha256: Option<String>,
    caption: Option<String>,
    filename: Option<String>,
}

#[derive(Deserialize)]
struct Status {
    id: String,
    status: String,
    timestamp: String,
    recipient_id: String,
    recipient_participant_id: Option<String>,
    biz_opaque_callback_data: Option<String>,
    #[serde(default)]
    errors: Vec<ProviderError>,
}

#[derive(Deserialize)]
struct ProviderError {
    code: i64,
}

#[cfg(test)]
mod tests {
    use super::{NormalizedContent, NormalizedPayload, WebhookSecrets, parse_webhook};
    use hmac::{Hmac, Mac, digest::KeyInit};
    use secrecy::SecretString;
    use sha2::Sha256;

    fn signature(secret: &[u8], body: &[u8]) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret)
            .unwrap_or_else(|_| unreachable!("test key is valid"));
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn verifies_raw_body_and_rotation_secret() {
        let body = br#"{"entry":[]}"#;
        let secrets = WebhookSecrets::new(
            SecretString::from("current".to_owned()),
            Some(SecretString::from("previous".to_owned())),
            SecretString::from("verify".to_owned()),
        );
        assert!(secrets.verify_signature(&signature(b"current", body), body));
        assert!(secrets.verify_signature(&signature(b"previous", body), body));
        assert!(!secrets.verify_signature(&signature(b"current", b"changed"), body));
    }

    #[test]
    fn parses_multiple_message_and_status_events() -> Result<(), Box<dyn std::error::Error>> {
        let body = br#"{
            "object":"whatsapp_business_account",
            "entry":[{"id":"waba-1","changes":[{"field":"messages","value":{
                "messaging_product":"whatsapp",
                "metadata":{"phone_number_id":"phone-1"},
                "messages":[
                    {"from":"919876543210","id":"wamid.1","timestamp":"1750000000","type":"text","text":{"body":"Hello"}},
                    {"from":"919876543210","id":"wamid.2","timestamp":"1750000001","type":"interactive","interactive":{"type":"button_reply","button_reply":{"id":"plumber","title":"Plumber"}}}
                ],
                "statuses":[{"id":"wamid.out","status":"read","timestamp":"1750000002","recipient_id":"919876543210","biz_opaque_callback_data":"callback-1"}]
            }}]}]
        }"#;
        let events = parse_webhook(body, "waba-1", "phone-1")?;
        assert_eq!(events.len(), 3);
        assert!(matches!(
            &events[0].payload,
            NormalizedPayload::Message {
                content: NormalizedContent::Text { body }, ..
            } if body == "Hello"
        ));
        assert!(matches!(
            &events[1].payload,
            NormalizedPayload::Message {
                content: NormalizedContent::Action { id, .. }, ..
            } if id == "plumber"
        ));
        assert!(matches!(
            events[2].payload,
            NormalizedPayload::Status { .. }
        ));
        Ok(())
    }

    #[test]
    fn parses_location_and_media_references() -> Result<(), Box<dyn std::error::Error>> {
        let body = br#"{
            "object":"whatsapp_business_account",
            "entry":[{"id":"waba-1","changes":[{"field":"messages","value":{
                "messaging_product":"whatsapp",
                "metadata":{"phone_number_id":"phone-1"},
                "messages":[
                    {"from":"919876543210","id":"wamid.location","timestamp":"1750000000","type":"location","location":{"latitude":21.1458,"longitude":79.0882,"name":"Nagpur"}},
                    {"from":"919876543210","id":"wamid.image","timestamp":"1750000001","type":"image","image":{"id":"media-1","mime_type":"image/jpeg","sha256":"digest","caption":"photo"}}
                ]
            }}]}]
        }"#;
        let events = parse_webhook(body, "waba-1", "phone-1")?;
        assert!(matches!(
            events[0].payload,
            NormalizedPayload::Message {
                content: NormalizedContent::Location { .. },
                ..
            }
        ));
        assert!(matches!(
            events[1].payload,
            NormalizedPayload::Message {
                content: NormalizedContent::Media { .. },
                ..
            }
        ));
        Ok(())
    }
}
