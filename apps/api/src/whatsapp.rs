use sahayak_configuration::{RuntimeEnvironment, WhatsAppSettings, load_secret_file};
use sahayak_cryptography::{
    CryptoService, EncryptionContext, EncryptionNamespace, EncryptionPurpose,
};
use sahayak_domain::{CorrelationId, InboundEventId, OutboxJobId};
use sahayak_persistence::{
    Acceptance, Database, EncryptedEventPayload, InboundEventInput, KeyRegistryRepository,
    LookupDigest,
};
use sahayak_whatsapp::{
    NormalizedContent, NormalizedPayload, WebhookError, WebhookSecrets, parse_webhook,
};
use secrecy::ExposeSecret;
use std::fmt;
use thiserror::Error;
use time::OffsetDateTime;

/// Outcome of one durably accepted signed callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebhookOutcome {
    /// Logical events newly accepted.
    pub accepted: usize,
    /// Logical events already accepted earlier.
    pub duplicates: usize,
    /// Reused provider IDs whose normalized payload changed.
    pub collisions: usize,
}

/// Webhook validation, encryption, or persistence failure.
#[derive(Debug, Error)]
pub enum WebhookServiceError {
    /// Signed envelope is malformed or targets another Meta account.
    #[error(transparent)]
    Webhook(#[from] WebhookError),
    /// Normalized event serialization failed.
    #[error("normalized webhook serialization failed")]
    Serialization,
    /// Event encryption or fingerprinting failed.
    #[error("normalized webhook encryption failed")]
    Cryptography,
    /// Durable event acceptance failed.
    #[error("durable webhook acceptance failed")]
    Persistence(#[from] sahayak_persistence::PersistenceError),
    /// Mounted secrets could not be loaded safely.
    #[error("WhatsApp secret file could not be loaded")]
    Secret,
    /// Mounted keyring is missing or invalid.
    #[error("WhatsApp cryptographic keyring is invalid")]
    Keyring,
}

/// Rotation-aware webhook verifier and durable logical-event processor.
pub struct WhatsAppWebhookService {
    secrets: WebhookSecrets,
    cryptography: CryptoService,
    database: Database,
    waba_id: String,
    phone_number_id: String,
    provider_namespace: String,
    maximum_body_bytes: usize,
    transport_probe_enabled: bool,
}

impl WhatsAppWebhookService {
    pub(crate) fn from_parts(
        secrets: WebhookSecrets,
        cryptography: CryptoService,
        database: Database,
        waba_id: String,
        phone_number_id: String,
        maximum_body_bytes: usize,
        transport_probe_enabled: bool,
    ) -> Self {
        Self {
            secrets,
            cryptography,
            database,
            provider_namespace: format!("{waba_id}:{phone_number_id}"),
            waba_id,
            phone_number_id,
            maximum_body_bytes,
            transport_probe_enabled,
        }
    }

    /// Loads process-scoped secrets and verifies key metadata before serving traffic.
    pub async fn load(
        settings: &WhatsAppSettings,
        environment: RuntimeEnvironment,
        database: Database,
    ) -> Result<Self, WebhookServiceError> {
        let strict_permissions = environment.is_production();
        let current_app_secret =
            load_secret_file(&settings.app_secret_current_file, 4_096, strict_permissions)
                .map_err(|_| WebhookServiceError::Secret)?;
        let previous_app_secret = settings
            .previous_app_secret_path()
            .map(|path| load_secret_file(path, 4_096, strict_permissions))
            .transpose()
            .map_err(|_| WebhookServiceError::Secret)?;
        let verify_token = load_secret_file(&settings.verify_token_file, 4_096, strict_permissions)
            .map_err(|_| WebhookServiceError::Secret)?;
        let keyring = load_secret_file(&settings.crypto_keyring_file, 65_536, strict_permissions)
            .map_err(|_| WebhookServiceError::Secret)?;
        let cryptography = CryptoService::from_keyring_text(keyring.expose_secret())
            .map_err(|_| WebhookServiceError::Keyring)?;
        let integration_version = cryptography
            .active_encryption_version(EncryptionPurpose::Integration)
            .ok_or(WebhookServiceError::Keyring)?;
        KeyRegistryRepository::new(database.clone())
            .verify_required_versions(
                &[(EncryptionPurpose::Integration, integration_version)],
                Some(cryptography.active_lookup_version()),
            )
            .await?;
        Ok(Self::from_parts(
            WebhookSecrets::new(current_app_secret, previous_app_secret, verify_token),
            cryptography,
            database,
            settings.waba_id.clone(),
            settings.phone_number_id.clone(),
            settings.webhook_max_body_bytes,
            settings.transport_probe_enabled,
        ))
    }

    /// Returns the route-level body limit.
    #[must_use]
    pub const fn maximum_body_bytes(&self) -> usize {
        self.maximum_body_bytes
    }

    /// Validates Meta's GET subscription challenge.
    #[must_use]
    pub fn verify_subscription<'a>(
        &self,
        mode: &str,
        token: &str,
        challenge: &'a str,
    ) -> Option<&'a str> {
        self.secrets.verify_subscription(mode, token, challenge)
    }

    /// Verifies one raw-body signature.
    #[must_use]
    pub fn verify_signature(&self, signature: &str, body: &[u8]) -> bool {
        self.secrets.verify_signature(signature, body)
    }

    /// Parses, encrypts, fingerprints, and atomically accepts every logical event.
    pub async fn accept(&self, body: &[u8]) -> Result<WebhookOutcome, WebhookServiceError> {
        let events = parse_webhook(body, &self.waba_id, &self.phone_number_id)?;
        if events.is_empty() {
            return Ok(WebhookOutcome {
                accepted: 0,
                duplicates: 0,
                collisions: 0,
            });
        }
        let correlation_id = CorrelationId::new();
        let active_lookup_version = self.cryptography.active_lookup_version();
        let mut inputs = Vec::with_capacity(events.len());
        for event in events {
            let processing_ordering_key = match &event.payload {
                NormalizedPayload::Message { sender_wa_id, .. } => Some(
                    self.cryptography
                        .blind_index(
                            "integration:whatsapp:conversation-order:v1",
                            sender_wa_id.as_bytes(),
                        )
                        .map_err(|_| WebhookServiceError::Cryptography)?
                        .1,
                ),
                NormalizedPayload::Status { .. } | NormalizedPayload::ProviderError { .. } => None,
            };
            let is_transport_probe = self.transport_probe_enabled
                && matches!(
                    &event.payload,
                    NormalizedPayload::Message {
                        content: NormalizedContent::Text { body }, ..
                    } if body == "__sahayak_transport_probe__"
                );
            let event_id = InboundEventId::new();
            let normalized =
                serde_json::to_vec(&event).map_err(|_| WebhookServiceError::Serialization)?;
            let encrypted = self
                .cryptography
                .encrypt(
                    EncryptionPurpose::Integration,
                    EncryptionContext::new(
                        EncryptionNamespace::INBOUND_EVENT_PAYLOAD,
                        event_id.into_uuid(),
                    ),
                    &normalized,
                )
                .map_err(|_| WebhookServiceError::Cryptography)?;
            let fingerprints = self
                .cryptography
                .all_blind_indexes("integration:whatsapp:event:v1", &normalized)
                .map_err(|_| WebhookServiceError::Cryptography)?;
            let active = fingerprints
                .iter()
                .find(|(version, _)| *version == active_lookup_version)
                .copied()
                .ok_or(WebhookServiceError::Keyring)?;
            let additional_fingerprints = fingerprints
                .into_iter()
                .filter(|(version, _)| *version != active_lookup_version)
                .map(|(key_version, digest)| LookupDigest {
                    key_version,
                    digest,
                })
                .collect();
            inputs.push(InboundEventInput {
                event_id,
                provider_code: "whatsapp".to_owned(),
                provider_namespace: self.provider_namespace.clone(),
                provider_event_id: event.provider_event_id,
                event_type: event.event_type.clone(),
                processing_job_kind: if event.event_type == "message.status" {
                    "process_whatsapp_status".to_owned()
                } else if event.event_type == "provider.error" {
                    "process_provider_error".to_owned()
                } else if is_transport_probe {
                    "process_whatsapp_probe".to_owned()
                } else {
                    "process_conversation_message".to_owned()
                },
                processing_ordering_key,
                payload: EncryptedEventPayload {
                    purpose: EncryptionPurpose::Integration,
                    schema_version: 1,
                    ciphertext: encrypted.ciphertext,
                    nonce: encrypted.nonce,
                    fingerprint_key_version: active.0,
                    payload_fingerprint: active.1,
                    additional_fingerprints,
                    key_version: encrypted.key_version,
                },
                correlation_id,
                signature_verified_at: OffsetDateTime::now_utc(),
                provider_occurred_at: event.occurred_at,
                processing_job_id: OutboxJobId::new(),
                max_attempts: 8,
            });
        }
        let outcomes = self.database.accept_inbound_events(&inputs).await?;
        let mut result = WebhookOutcome {
            accepted: 0,
            duplicates: 0,
            collisions: 0,
        };
        for outcome in outcomes {
            match outcome {
                Acceptance::Accepted { .. } => result.accepted += 1,
                Acceptance::Duplicate { .. } => result.duplicates += 1,
                Acceptance::IdentifierCollision { .. } => result.collisions += 1,
            }
        }
        Ok(result)
    }
}

impl fmt::Debug for WhatsAppWebhookService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WhatsAppWebhookService")
            .field("waba_id", &self.waba_id)
            .field("phone_number_id", &self.phone_number_id)
            .field("secrets", &"[REDACTED]")
            .field("cryptography", &"[REDACTED]")
            .finish()
    }
}
