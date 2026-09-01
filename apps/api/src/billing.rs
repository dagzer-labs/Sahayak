use sahayak_configuration::{RazorpaySettings, RuntimeEnvironment, load_secret_file};
use sahayak_domain::BillingWebhookEventId;
use sahayak_payments::{RazorpaySecrets, RazorpayWebhook};
use sahayak_persistence::{
    AcceptBillingWebhook, BillingRepository, BillingWebhookAcceptance, Database,
};
use secrecy::ExposeSecret;
use std::fmt;
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum BillingWebhookError {
    #[error("invalid Razorpay webhook")]
    Invalid,
    #[error("Razorpay secret could not be loaded")]
    Secret,
    #[error("billing persistence failed")]
    Persistence(#[from] sahayak_persistence::PersistenceError),
}

pub struct RazorpayWebhookService {
    secrets: RazorpaySecrets,
    repository: BillingRepository,
    maximum_body_bytes: usize,
}

impl RazorpayWebhookService {
    pub(crate) const fn from_parts(
        secrets: RazorpaySecrets,
        database: Database,
        maximum_body_bytes: usize,
    ) -> Self {
        Self {
            secrets,
            repository: BillingRepository::new(database),
            maximum_body_bytes,
        }
    }

    pub fn load(
        settings: &RazorpaySettings,
        environment: RuntimeEnvironment,
        database: Database,
    ) -> Result<Self, BillingWebhookError> {
        let current = load_secret_file(
            &settings.webhook_secret_current_file,
            4_096,
            environment.is_production(),
        )
        .map_err(|_| BillingWebhookError::Secret)?;
        let previous = settings
            .previous_webhook_secret_path()
            .as_deref()
            .map(|path| load_secret_file(path, 4_096, environment.is_production()))
            .transpose()
            .map_err(|_| BillingWebhookError::Secret)?;
        let _key_secret = load_secret_file(
            &settings.key_secret_file,
            4_096,
            environment.is_production(),
        )
        .map_err(|_| BillingWebhookError::Secret)?;
        if current.expose_secret().is_empty() {
            return Err(BillingWebhookError::Secret);
        }
        Ok(Self::from_parts(
            RazorpaySecrets::new(current, previous),
            database,
            settings.webhook_max_body_bytes,
        ))
    }

    #[must_use]
    pub const fn maximum_body_bytes(&self) -> usize {
        self.maximum_body_bytes
    }
    #[must_use]
    pub fn verify(&self, signature: &str, body: &[u8]) -> bool {
        self.secrets.verify(signature, body)
    }

    pub async fn accept(
        &self,
        event_id: &str,
        body: &[u8],
    ) -> Result<BillingWebhookAcceptance, BillingWebhookError> {
        let parsed = RazorpayWebhook::parse(body).map_err(|_| BillingWebhookError::Invalid)?;
        let normalized = serde_json::to_value(&parsed).map_err(|_| BillingWebhookError::Invalid)?;
        let accepted = self
            .repository
            .accept_webhook(AcceptBillingWebhook {
                id: BillingWebhookEventId::new(),
                provider_event_id: event_id,
                event_type: &parsed.event,
                normalized_payload: &normalized,
            })
            .await?;
        if accepted == BillingWebhookAcceptance::Accepted {
            let subscription = parsed
                .payload
                .subscription
                .as_ref()
                .map(|value| &value.entity);
            let payment = parsed.payload.payment.as_ref().map(|value| &value.entity);
            let invoice = parsed.payload.invoice.as_ref().map(|value| &value.entity);
            let subscription_id = subscription
                .map(|value| value.id.as_str())
                .or_else(|| invoice.and_then(|value| value.subscription_id.as_deref()));
            if let Some(subscription_id) = subscription_id {
                self.repository
                    .apply_provider_event(
                        event_id,
                        subscription_id,
                        &parsed.event,
                        payment.map(|value| value.id.as_str()),
                        payment
                            .and_then(|value| value.invoice_id.as_deref())
                            .or_else(|| invoice.map(|value| value.id.as_str())),
                        payment.and_then(|value| value.order_id.as_deref()),
                        payment.map(|value| value.amount),
                        payment.map(|value| value.currency.as_str()),
                        timestamp(subscription.and_then(|value| value.current_start))?,
                        timestamp(subscription.and_then(|value| value.current_end))?,
                    )
                    .await?;
            } else {
                self.repository
                    .fail_webhook(event_id, "missing_subscription")
                    .await?;
            }
        }
        Ok(accepted)
    }
}

impl fmt::Debug for RazorpayWebhookService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RazorpayWebhookService")
            .field("secrets", &"[REDACTED]")
            .field("repository", &self.repository)
            .field("maximum_body_bytes", &self.maximum_body_bytes)
            .finish()
    }
}

fn timestamp(value: Option<i64>) -> Result<Option<OffsetDateTime>, BillingWebhookError> {
    value
        .map(OffsetDateTime::from_unix_timestamp)
        .transpose()
        .map_err(|_| BillingWebhookError::Invalid)
}
