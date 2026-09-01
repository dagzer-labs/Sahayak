use sahayak_cryptography::NormalizedPhoneNumber;
use serde::{Serialize, Serializer};
use std::{collections::HashSet, fmt};
use thiserror::Error;
use zeroize::Zeroizing;

const TEXT_MAX: usize = 4_096;
const INTERACTIVE_BODY_MAX: usize = 1_024;
const LIST_BODY_MAX: usize = 1_024;

/// Error returned when an outbound message violates a Meta contract limit.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("invalid WhatsApp message: {0}")]
pub struct MessageValidationError(String);

/// Fully validated outbound WhatsApp message.
#[derive(Clone, Serialize)]
pub struct OutboundMessage {
    messaging_product: &'static str,
    recipient_type: &'static str,
    to: Recipient,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<MessageContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    biz_opaque_callback_data: Option<String>,
    #[serde(flatten)]
    content: OutboundContent,
}

impl OutboundMessage {
    /// Creates a direct individual message.
    #[must_use]
    fn new(recipient: &NormalizedPhoneNumber, content: OutboundContent) -> Self {
        Self {
            messaging_product: "whatsapp",
            recipient_type: "individual",
            to: Recipient(Zeroizing::new(recipient.expose().to_owned())),
            context: None,
            biz_opaque_callback_data: None,
            content,
        }
    }

    /// Creates a free-form text message.
    #[must_use]
    pub fn text(recipient: &NormalizedPhoneNumber, message: TextMessage) -> Self {
        Self::new(recipient, message.into())
    }

    /// Creates an interactive reply-button message.
    #[must_use]
    pub fn buttons(recipient: &NormalizedPhoneNumber, message: ButtonMessage) -> Self {
        Self::new(recipient, message.into())
    }

    /// Creates an interactive list message.
    #[must_use]
    pub fn list(recipient: &NormalizedPhoneNumber, message: ListMessage) -> Self {
        Self::new(recipient, message.into())
    }

    /// Creates an approved template invocation.
    #[must_use]
    pub fn template(recipient: &NormalizedPhoneNumber, message: TemplateMessage) -> Self {
        Self::new(recipient, message.into())
    }

    /// Creates a standalone media message.
    #[must_use]
    pub fn media(recipient: &NormalizedPhoneNumber, message: MediaMessage) -> Self {
        Self::new(recipient, message.into())
    }

    /// Creates a location message.
    #[must_use]
    pub fn location(recipient: &NormalizedPhoneNumber, message: LocationMessage) -> Self {
        Self::new(recipient, message.into())
    }

    /// Quotes a previously received or sent WhatsApp message.
    pub fn with_context(mut self, message_id: &str) -> Result<Self, MessageValidationError> {
        validate_bounded("context message ID", message_id, 1, 512)?;
        self.context = Some(MessageContext {
            message_id: message_id.to_owned(),
        });
        Ok(self)
    }

    /// Adds a non-PII callback token repeated in delivery-status webhooks.
    pub fn with_callback_data(mut self, value: &str) -> Result<Self, MessageValidationError> {
        validate_trimmed("callback data", value, 1, 512)?;
        self.biz_opaque_callback_data = Some(value.to_owned());
        Ok(self)
    }

    /// Serializes a validated message for authenticated encrypted persistence.
    pub fn prepare(&self) -> Result<PreparedMessage, MessageValidationError> {
        let bytes = serde_json::to_vec(self).map_err(|_| {
            MessageValidationError("message serialization unexpectedly failed".to_owned())
        })?;
        PreparedMessage::from_persisted(bytes)
    }
}

/// Validated serialized Meta request retained only in encrypted storage.
#[derive(Clone)]
pub struct PreparedMessage(Zeroizing<Vec<u8>>);

impl PreparedMessage {
    /// Revalidates an authenticated decrypted payload before sending it to Meta.
    pub fn from_persisted(bytes: Vec<u8>) -> Result<Self, MessageValidationError> {
        if bytes.is_empty() || bytes.len() > 131_072 {
            return Err(MessageValidationError(
                "prepared message size is outside supported bounds".to_owned(),
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| MessageValidationError("prepared message is not valid JSON".to_owned()))?;
        let object = value.as_object().ok_or_else(|| {
            MessageValidationError("prepared message must be a JSON object".to_owned())
        })?;
        let recipient = object.get("to").and_then(|value| value.as_str());
        if object
            .get("messaging_product")
            .and_then(|value| value.as_str())
            != Some("whatsapp")
            || object
                .get("recipient_type")
                .and_then(|value| value.as_str())
                != Some("individual")
            || recipient.is_none()
            || object
                .get("type")
                .and_then(|value| value.as_str())
                .is_none()
        {
            return Err(MessageValidationError(
                "prepared message is missing required Meta fields".to_owned(),
            ));
        }
        NormalizedPhoneNumber::parse(recipient.unwrap_or_default()).map_err(|_| {
            MessageValidationError("prepared message recipient is not canonical".to_owned())
        })?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Exposes serialized bytes only to encryption or the authenticated HTTP client.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the persisted callback token when present.
    pub fn callback_data(&self) -> Option<String> {
        serde_json::from_slice::<serde_json::Value>(&self.0)
            .ok()
            .and_then(|value| {
                value
                    .get("biz_opaque_callback_data")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
            })
    }

    /// Returns the validated recipient for send-time policy checks.
    pub fn recipient(&self) -> Result<NormalizedPhoneNumber, MessageValidationError> {
        let value: serde_json::Value = serde_json::from_slice(&self.0)
            .map_err(|_| MessageValidationError("prepared message is not valid JSON".to_owned()))?;
        let recipient = value
            .get("to")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                MessageValidationError("prepared message recipient is missing".to_owned())
            })?;
        NormalizedPhoneNumber::parse(recipient).map_err(|_| {
            MessageValidationError("prepared message recipient is not canonical".to_owned())
        })
    }

    /// Returns the Meta message type.
    pub fn message_type(&self) -> Result<String, MessageValidationError> {
        let value: serde_json::Value = serde_json::from_slice(&self.0)
            .map_err(|_| MessageValidationError("prepared message is not valid JSON".to_owned()))?;
        value
            .get("type")
            .and_then(|value| value.as_str())
            .map(str::to_owned)
            .ok_or_else(|| MessageValidationError("prepared message type is missing".to_owned()))
    }
}

impl fmt::Debug for PreparedMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedMessage")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for OutboundMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundMessage")
            .field("recipient", &"[REDACTED]")
            .field("content", &self.content.kind())
            .field("has_context", &self.context.is_some())
            .finish()
    }
}

#[derive(Clone)]
struct Recipient(Zeroizing<String>);

impl Serialize for Recipient {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

#[derive(Clone, Serialize)]
struct MessageContext {
    message_id: String,
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OutboundContent {
    Text { text: TextPayload },
    Interactive { interactive: InteractivePayload },
    Template { template: TemplatePayload },
    Image { image: MediaPayload },
    Video { video: MediaPayload },
    Document { document: MediaPayload },
    Audio { audio: MediaPayload },
    Sticker { sticker: MediaPayload },
    Location { location: LocationPayload },
}

impl OutboundContent {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Text { .. } => "text",
            Self::Interactive { .. } => "interactive",
            Self::Template { .. } => "template",
            Self::Image { .. } => "image",
            Self::Video { .. } => "video",
            Self::Document { .. } => "document",
            Self::Audio { .. } => "audio",
            Self::Sticker { .. } => "sticker",
            Self::Location { .. } => "location",
        }
    }
}

/// Validated free-form text message.
#[derive(Clone)]
pub struct TextMessage(TextPayload);

impl TextMessage {
    /// Creates text content of at most 4,096 characters.
    pub fn new(body: &str, preview_url: bool) -> Result<Self, MessageValidationError> {
        validate_bounded("text body", body, 1, TEXT_MAX)?;
        Ok(Self(TextPayload {
            body: body.to_owned(),
            preview_url,
        }))
    }
}

impl From<TextMessage> for OutboundContent {
    fn from(message: TextMessage) -> Self {
        Self::Text { text: message.0 }
    }
}

#[derive(Clone, Serialize)]
struct TextPayload {
    preview_url: bool,
    body: String,
}

/// One interactive reply button.
#[derive(Clone, Serialize)]
pub struct Button {
    #[serde(rename = "type")]
    kind: &'static str,
    reply: ButtonReply,
}

impl Button {
    /// Creates a reply button with bounded ID and title.
    pub fn new(id: &str, title: &str) -> Result<Self, MessageValidationError> {
        validate_trimmed("button ID", id, 1, 256)?;
        validate_trimmed("button title", title, 1, 20)?;
        Ok(Self {
            kind: "reply",
            reply: ButtonReply {
                id: id.to_owned(),
                title: title.to_owned(),
            },
        })
    }
}

#[derive(Clone, Serialize)]
struct ButtonReply {
    id: String,
    title: String,
}

/// Validated interactive message containing one to three reply buttons.
#[derive(Clone)]
pub struct ButtonMessage(InteractivePayload);

impl ButtonMessage {
    /// Creates a reply-button message.
    pub fn new(
        body: &str,
        buttons: Vec<Button>,
        header: Option<&str>,
        footer: Option<&str>,
    ) -> Result<Self, MessageValidationError> {
        validate_bounded("button body", body, 1, INTERACTIVE_BODY_MAX)?;
        if !(1..=3).contains(&buttons.len()) {
            return Err(MessageValidationError(
                "reply-button messages require one to three buttons".to_owned(),
            ));
        }
        let mut ids = HashSet::new();
        let mut titles = HashSet::new();
        if buttons.iter().any(|button| {
            !ids.insert(button.reply.id.as_str()) || !titles.insert(button.reply.title.as_str())
        }) {
            return Err(MessageValidationError(
                "reply-button IDs and titles must be unique".to_owned(),
            ));
        }
        let header = optional_text("button header", header, 60)?;
        let footer = optional_body("button footer", footer, 60)?;
        Ok(Self(InteractivePayload {
            kind: "button",
            header,
            body: InteractiveBody {
                text: body.to_owned(),
            },
            footer,
            action: InteractiveAction::Buttons { buttons },
        }))
    }

    /// Replaces the optional text header with one already-uploaded Meta image.
    #[must_use]
    pub fn with_image_header(mut self, image: MediaReference) -> Self {
        self.0.header = Some(InteractiveHeader::Image { image });
        self
    }
}

impl From<ButtonMessage> for OutboundContent {
    fn from(message: ButtonMessage) -> Self {
        Self::Interactive {
            interactive: message.0,
        }
    }
}

/// One row in an interactive list section.
#[derive(Clone, Serialize)]
pub struct ListRow {
    id: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

impl ListRow {
    /// Creates a list row.
    pub fn new(
        id: &str,
        title: &str,
        description: Option<&str>,
    ) -> Result<Self, MessageValidationError> {
        validate_trimmed("list row ID", id, 1, 200)?;
        validate_trimmed("list row title", title, 1, 24)?;
        let description =
            optional_body("list row description", description, 72)?.map(|value| value.text);
        Ok(Self {
            id: id.to_owned(),
            title: title.to_owned(),
            description,
        })
    }
}

/// One titled section in an interactive list.
#[derive(Clone, Serialize)]
pub struct ListSection {
    title: String,
    rows: Vec<ListRow>,
}

impl ListSection {
    /// Creates a non-empty list section.
    pub fn new(title: &str, rows: Vec<ListRow>) -> Result<Self, MessageValidationError> {
        validate_trimmed("list section title", title, 1, 24)?;
        if rows.is_empty() {
            return Err(MessageValidationError(
                "list sections require at least one row".to_owned(),
            ));
        }
        Ok(Self {
            title: title.to_owned(),
            rows,
        })
    }
}

/// Validated interactive list message.
#[derive(Clone)]
pub struct ListMessage(InteractivePayload);

impl ListMessage {
    /// Creates a list containing at most ten total rows.
    pub fn new(
        body: &str,
        button: &str,
        sections: Vec<ListSection>,
        header: Option<&str>,
        footer: Option<&str>,
    ) -> Result<Self, MessageValidationError> {
        validate_bounded("list body", body, 1, LIST_BODY_MAX)?;
        validate_trimmed("list action button", button, 1, 20)?;
        if sections.is_empty() || sections.len() > 10 {
            return Err(MessageValidationError(
                "list messages require one to ten sections".to_owned(),
            ));
        }
        let rows: Vec<_> = sections
            .iter()
            .flat_map(|section| section.rows.iter())
            .collect();
        if rows.len() > 10 {
            return Err(MessageValidationError(
                "list messages allow at most ten total rows".to_owned(),
            ));
        }
        let mut ids = HashSet::new();
        if rows.iter().any(|row| !ids.insert(row.id.as_str())) {
            return Err(MessageValidationError(
                "list row IDs must be unique".to_owned(),
            ));
        }
        Ok(Self(InteractivePayload {
            kind: "list",
            header: optional_text("list header", header, 60)?,
            body: InteractiveBody {
                text: body.to_owned(),
            },
            footer: optional_body("list footer", footer, 60)?,
            action: InteractiveAction::List {
                button: button.to_owned(),
                sections,
            },
        }))
    }
}

impl From<ListMessage> for OutboundContent {
    fn from(message: ListMessage) -> Self {
        Self::Interactive {
            interactive: message.0,
        }
    }
}

#[derive(Clone, Serialize)]
struct InteractivePayload {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<InteractiveHeader>,
    body: InteractiveBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    footer: Option<InteractiveBody>,
    action: InteractiveAction,
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum InteractiveHeader {
    Text { text: String },
    Image { image: MediaReference },
}

#[derive(Clone, Serialize)]
struct InteractiveBody {
    text: String,
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
enum InteractiveAction {
    Buttons {
        buttons: Vec<Button>,
    },
    List {
        button: String,
        sections: Vec<ListSection>,
    },
}

/// Approved template invocation.
#[derive(Clone)]
pub struct TemplateMessage(TemplatePayload);

impl TemplateMessage {
    /// Creates a template invocation whose components must match Meta approval.
    pub fn new(
        name: &str,
        language_code: &str,
        components: Vec<TemplateComponent>,
    ) -> Result<Self, MessageValidationError> {
        validate_code("template name", name, 512)?;
        validate_trimmed("template language", language_code, 2, 35)?;
        Ok(Self(TemplatePayload {
            name: name.to_owned(),
            language: TemplateLanguage {
                code: language_code.to_owned(),
            },
            components,
        }))
    }
}

impl From<TemplateMessage> for OutboundContent {
    fn from(message: TemplateMessage) -> Self {
        Self::Template {
            template: message.0,
        }
    }
}

#[derive(Clone, Serialize)]
struct TemplatePayload {
    name: String,
    language: TemplateLanguage,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    components: Vec<TemplateComponent>,
}

#[derive(Clone, Serialize)]
struct TemplateLanguage {
    code: String,
}

/// Template component and its ordered parameters.
#[derive(Clone, Serialize)]
pub struct TemplateComponent {
    #[serde(rename = "type")]
    kind: &'static str,
    parameters: Vec<TemplateParameter>,
}

impl TemplateComponent {
    /// Creates a body component.
    #[must_use]
    pub fn body(parameters: Vec<TemplateParameter>) -> Self {
        Self {
            kind: "body",
            parameters,
        }
    }

    /// Creates a header component.
    #[must_use]
    pub fn header(parameters: Vec<TemplateParameter>) -> Self {
        Self {
            kind: "header",
            parameters,
        }
    }
}

/// Supported template parameter types.
#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TemplateParameter {
    /// Text parameter, optionally named for named-variable templates.
    Text {
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        parameter_name: Option<String>,
    },
    /// Image header parameter.
    Image { image: MediaReference },
    /// Video header parameter.
    Video { video: MediaReference },
    /// Document header parameter.
    Document { document: MediaReference },
}

impl TemplateParameter {
    /// Creates a bounded text parameter.
    pub fn text(value: &str, name: Option<&str>) -> Result<Self, MessageValidationError> {
        validate_bounded("template text parameter", value, 1, TEXT_MAX)?;
        if let Some(name) = name {
            validate_code("template parameter name", name, 128)?;
        }
        Ok(Self::Text {
            text: value.to_owned(),
            parameter_name: name.map(str::to_owned),
        })
    }
}

/// Uploaded Meta media ID or public HTTP/HTTPS media URL.
#[derive(Clone, Serialize)]
#[serde(untagged)]
pub enum MediaReference {
    /// Meta-uploaded media ID.
    Id { id: String },
    /// Publicly retrievable media URL.
    Link { link: String },
}

impl MediaReference {
    /// Creates an uploaded media reference.
    pub fn id(id: &str) -> Result<Self, MessageValidationError> {
        validate_trimmed("media ID", id, 1, 512)?;
        Ok(Self::Id { id: id.to_owned() })
    }

    /// Creates a hosted HTTP or HTTPS media reference.
    pub fn link(link: &str) -> Result<Self, MessageValidationError> {
        validate_trimmed("media link", link, 1, 2_048)?;
        if !(link.starts_with("https://") || link.starts_with("http://")) {
            return Err(MessageValidationError(
                "media link must use HTTP or HTTPS".to_owned(),
            ));
        }
        Ok(Self::Link {
            link: link.to_owned(),
        })
    }
}

/// Supported standalone media message category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaKind {
    /// Image message.
    Image,
    /// Video message.
    Video,
    /// Document message.
    Document,
    /// Audio message.
    Audio,
    /// Sticker message.
    Sticker,
}

/// Validated standalone media message.
#[derive(Clone)]
pub struct MediaMessage {
    kind: MediaKind,
    payload: MediaPayload,
}

impl MediaMessage {
    /// Creates a media message with optional caption and document filename.
    pub fn new(
        kind: MediaKind,
        reference: MediaReference,
        caption: Option<&str>,
        filename: Option<&str>,
    ) -> Result<Self, MessageValidationError> {
        if matches!(kind, MediaKind::Audio | MediaKind::Sticker) && caption.is_some() {
            return Err(MessageValidationError(
                "audio and sticker messages do not support captions".to_owned(),
            ));
        }
        if kind != MediaKind::Document && filename.is_some() {
            return Err(MessageValidationError(
                "only document messages support filenames".to_owned(),
            ));
        }
        Ok(Self {
            kind,
            payload: MediaPayload {
                reference,
                caption: optional_string("media caption", caption, 1_024)?,
                filename: optional_string("document filename", filename, 255)?,
            },
        })
    }
}

impl From<MediaMessage> for OutboundContent {
    fn from(message: MediaMessage) -> Self {
        match message.kind {
            MediaKind::Image => Self::Image {
                image: message.payload,
            },
            MediaKind::Video => Self::Video {
                video: message.payload,
            },
            MediaKind::Document => Self::Document {
                document: message.payload,
            },
            MediaKind::Audio => Self::Audio {
                audio: message.payload,
            },
            MediaKind::Sticker => Self::Sticker {
                sticker: message.payload,
            },
        }
    }
}

#[derive(Clone, Serialize)]
struct MediaPayload {
    #[serde(flatten)]
    reference: MediaReference,
    #[serde(skip_serializing_if = "Option::is_none")]
    caption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
}

/// Validated location message.
#[derive(Clone)]
pub struct LocationMessage(LocationPayload);

impl LocationMessage {
    /// Creates a location using decimal degrees.
    pub fn new(
        latitude: f64,
        longitude: f64,
        name: Option<&str>,
        address: Option<&str>,
    ) -> Result<Self, MessageValidationError> {
        if !latitude.is_finite()
            || !longitude.is_finite()
            || !(-90.0..=90.0).contains(&latitude)
            || !(-180.0..=180.0).contains(&longitude)
        {
            return Err(MessageValidationError(
                "location coordinates are outside valid decimal-degree bounds".to_owned(),
            ));
        }
        Ok(Self(LocationPayload {
            latitude,
            longitude,
            name: optional_string("location name", name, 1_024)?,
            address: optional_string("location address", address, 1_024)?,
        }))
    }
}

impl From<LocationMessage> for OutboundContent {
    fn from(message: LocationMessage) -> Self {
        Self::Location {
            location: message.0,
        }
    }
}

#[derive(Clone, Serialize)]
struct LocationPayload {
    latitude: f64,
    longitude: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
}

fn optional_text(
    name: &str,
    value: Option<&str>,
    maximum: usize,
) -> Result<Option<InteractiveHeader>, MessageValidationError> {
    optional_string(name, value, maximum)
        .map(|value| value.map(|text| InteractiveHeader::Text { text }))
}

fn optional_body(
    name: &str,
    value: Option<&str>,
    maximum: usize,
) -> Result<Option<InteractiveBody>, MessageValidationError> {
    optional_string(name, value, maximum).map(|value| value.map(|text| InteractiveBody { text }))
}

fn optional_string(
    name: &str,
    value: Option<&str>,
    maximum: usize,
) -> Result<Option<String>, MessageValidationError> {
    value
        .map(|value| {
            validate_bounded(name, value, 1, maximum)?;
            Ok(value.to_owned())
        })
        .transpose()
}

fn validate_bounded(
    name: &str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), MessageValidationError> {
    let count = value.chars().count();
    if !(minimum..=maximum).contains(&count)
        || value
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(MessageValidationError(format!(
            "{name} must contain {minimum} to {maximum} non-control characters"
        )));
    }
    Ok(())
}

fn validate_trimmed(
    name: &str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), MessageValidationError> {
    validate_bounded(name, value, minimum, maximum)?;
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(MessageValidationError(format!("{name} must be trimmed")));
    }
    Ok(())
}

fn validate_code(name: &str, value: &str, maximum: usize) -> Result<(), MessageValidationError> {
    validate_trimmed(name, value, 1, maximum)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(MessageValidationError(format!(
            "{name} must contain lowercase ASCII letters, digits, or underscores"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Button, ButtonMessage, ListMessage, ListRow, ListSection, LocationMessage, MediaKind,
        MediaMessage, MediaReference, OutboundMessage, TemplateComponent, TemplateMessage,
        TemplateParameter, TextMessage,
    };
    use sahayak_cryptography::NormalizedPhoneNumber;
    use serde_json::json;

    #[test]
    fn serializes_text_contract_without_debug_disclosure() -> Result<(), Box<dyn std::error::Error>>
    {
        let recipient = NormalizedPhoneNumber::parse("+919876543210")?;
        let message = OutboundMessage::text(&recipient, TextMessage::new("Hello", false)?);
        assert_eq!(
            serde_json::to_value(&message)?,
            json!({
                "messaging_product": "whatsapp",
                "recipient_type": "individual",
                "to": "+919876543210",
                "type": "text",
                "text": {"preview_url": false, "body": "Hello"}
            })
        );
        assert!(!format!("{message:?}").contains("9876543210"));
        Ok(())
    }

    #[test]
    fn enforces_button_count_and_uniqueness() -> Result<(), Box<dyn std::error::Error>> {
        let duplicate = Button::new("same", "Same")?;
        assert!(
            ButtonMessage::new("Choose", vec![duplicate.clone(), duplicate], None, None).is_err()
        );
        assert!(ButtonMessage::new("Choose", Vec::new(), None, None).is_err());
        Ok(())
    }

    #[test]
    fn enforces_ten_total_list_rows() -> Result<(), Box<dyn std::error::Error>> {
        let rows = (0..11)
            .map(|index| ListRow::new(&format!("row_{index}"), "Choice", None))
            .collect::<Result<Vec<_>, _>>()?;
        let section = ListSection::new("Options", rows)?;
        assert!(ListMessage::new("Choose", "Open", vec![section], None, None).is_err());
        Ok(())
    }

    #[test]
    fn serializes_interactive_and_location_contracts() -> Result<(), Box<dyn std::error::Error>> {
        let recipient = NormalizedPhoneNumber::parse("+919876543210")?;
        let buttons = ButtonMessage::new(
            "Choose help",
            vec![Button::new("plumber", "Plumber")?],
            Some("Sahayak"),
            None,
        )?;
        let button_json = serde_json::to_value(OutboundMessage::buttons(&recipient, buttons))?;
        assert_eq!(button_json["interactive"]["type"], "button");
        assert_eq!(
            button_json["interactive"]["action"]["buttons"][0]["reply"]["id"],
            "plumber"
        );

        let list = ListMessage::new(
            "Choose help",
            "Open",
            vec![ListSection::new(
                "Services",
                vec![ListRow::new("electrician", "Electrician", None)?],
            )?],
            None,
            None,
        )?;
        let list_json = serde_json::to_value(OutboundMessage::list(&recipient, list))?;
        assert_eq!(list_json["interactive"]["type"], "list");

        let location = LocationMessage::new(21.1458, 79.0882, Some("Nagpur"), None)?;
        let location_json = serde_json::to_value(OutboundMessage::location(&recipient, location))?;
        assert_eq!(location_json["type"], "location");
        assert_eq!(location_json["location"]["latitude"], 21.1458);
        assert_eq!(location_json["location"]["longitude"], 79.0882);
        Ok(())
    }

    #[test]
    fn serializes_template_and_media_contracts() -> Result<(), Box<dyn std::error::Error>> {
        let recipient = NormalizedPhoneNumber::parse("+919876543210")?;
        let template = TemplateMessage::new(
            "service_request",
            "en_US",
            vec![TemplateComponent::body(vec![TemplateParameter::text(
                "Ravi",
                Some("first_name"),
            )?])],
        )?;
        let template_json = serde_json::to_value(OutboundMessage::template(&recipient, template))?;
        assert_eq!(template_json["template"]["name"], "service_request");
        assert_eq!(template_json["type"], "template");

        let media = MediaMessage::new(
            MediaKind::Image,
            MediaReference::id("media-123")?,
            Some("Profile photo"),
            None,
        )?;
        let media_json = serde_json::to_value(OutboundMessage::media(&recipient, media))?;
        assert_eq!(media_json["image"]["id"], "media-123");
        assert_eq!(media_json["type"], "image");
        Ok(())
    }
}
