//! Meta WhatsApp Cloud API transport models, validation, and client behavior.

mod client;
mod error;
mod outbound;
mod webhook;

pub use client::{DownloadedMedia, SendReceipt, WhatsAppClient, WhatsAppClientConfig};
pub use error::{ApiFailure, FailureClass, WhatsAppError};
pub use outbound::{
    Button, ButtonMessage, ListMessage, ListRow, ListSection, LocationMessage, MediaKind,
    MediaMessage, MediaReference, MessageValidationError, OutboundMessage, PreparedMessage,
    TemplateComponent, TemplateMessage, TemplateParameter, TextMessage,
};
pub use webhook::{
    NormalizedContent, NormalizedEvent, NormalizedPayload, WebhookError, WebhookSecrets,
    parse_webhook,
};
