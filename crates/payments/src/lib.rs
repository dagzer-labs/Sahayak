//! Razorpay protocol adapter. Provider payloads terminate at this boundary.

use hmac::{Hmac, Mac, digest::KeyInit};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum PaymentProviderError {
    #[error("invalid payment provider configuration")]
    Configuration,
    #[error("payment provider request failed")]
    Transport(#[from] reqwest::Error),
    #[error("payment provider returned an invalid response")]
    InvalidResponse,
}

#[derive(Clone)]
pub struct RazorpaySecrets {
    current_webhook_secret: SecretString,
    previous_webhook_secret: Option<SecretString>,
}

impl RazorpaySecrets {
    #[must_use]
    pub fn new(current: SecretString, previous: Option<SecretString>) -> Self {
        Self {
            current_webhook_secret: current,
            previous_webhook_secret: previous,
        }
    }

    #[must_use]
    pub fn verify(&self, signature: &str, raw_body: &[u8]) -> bool {
        let Ok(candidate) = hex::decode(signature) else {
            return false;
        };
        [
            &self.current_webhook_secret,
            self.previous_webhook_secret
                .as_ref()
                .unwrap_or(&self.current_webhook_secret),
        ]
        .into_iter()
        .any(|secret| {
            signature_for(secret.expose_secret().as_bytes(), raw_body)
                .is_some_and(|expected| expected.ct_eq(&candidate).into())
        })
    }
}

fn signature_for(secret: &[u8], body: &[u8]) -> Option<Vec<u8>> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).ok()?;
    mac.update(body);
    Some(mac.finalize().into_bytes().to_vec())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RazorpayWebhook {
    #[serde(rename = "entity")]
    pub envelope: String,
    pub event: String,
    pub payload: WebhookPayload,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct WebhookPayload {
    pub subscription: Option<EntityEnvelope<SubscriptionEntity>>,
    pub payment: Option<EntityEnvelope<PaymentEntity>>,
    pub invoice: Option<EntityEnvelope<InvoiceEntity>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EntityEnvelope<T> {
    pub entity: T,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriptionEntity {
    pub id: String,
    pub plan_id: String,
    pub status: String,
    pub customer_id: Option<String>,
    pub current_start: Option<i64>,
    pub current_end: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PaymentEntity {
    pub id: String,
    pub invoice_id: Option<String>,
    pub order_id: Option<String>,
    pub amount: i64,
    pub currency: String,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvoiceEntity {
    pub id: String,
    pub subscription_id: Option<String>,
    pub payment_id: Option<String>,
    pub receipt: Option<String>,
    pub invoice_number: Option<String>,
}

impl RazorpayWebhook {
    pub fn parse(raw: &[u8]) -> Result<Self, PaymentProviderError> {
        let event: Self =
            serde_json::from_slice(raw).map_err(|_| PaymentProviderError::InvalidResponse)?;
        if event.envelope != "event" || event.event.len() > 96 || !event.event.is_ascii() {
            return Err(PaymentProviderError::InvalidResponse);
        }
        Ok(event)
    }
}

#[derive(Serialize)]
struct CreateSubscriptionRequest<'a> {
    plan_id: &'a str,
    total_count: u16,
    quantity: u8,
    customer_notify: bool,
    expire_by: i64,
    notes: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct HostedSubscription {
    pub id: String,
    pub status: String,
    pub short_url: String,
}

#[derive(Clone)]
pub struct RazorpayClient {
    client: reqwest::Client,
    base_url: Url,
    key_id: String,
    key_secret: SecretString,
}

impl RazorpayClient {
    pub fn new(
        base_url: &str,
        key_id: String,
        key_secret: SecretString,
    ) -> Result<Self, PaymentProviderError> {
        let base_url = Url::parse(base_url).map_err(|_| PaymentProviderError::Configuration)?;
        let test_loopback = cfg!(test)
            && base_url.scheme() == "http"
            && base_url
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost"));
        if (base_url.scheme() != "https" && !test_loopback)
            || key_id.is_empty()
            || key_secret.expose_secret().is_empty()
        {
            return Err(PaymentProviderError::Configuration);
        }
        Ok(Self {
            client: reqwest::Client::new(),
            base_url,
            key_id,
            key_secret,
        })
    }

    pub async fn create_subscription(
        &self,
        plan_id: &str,
        account_id: &str,
        attempt_id: &str,
        expire_by: i64,
    ) -> Result<HostedSubscription, PaymentProviderError> {
        let url = self
            .base_url
            .join("v1/subscriptions")
            .map_err(|_| PaymentProviderError::Configuration)?;
        let response = self.client.post(url).basic_auth(&self.key_id, Some(self.key_secret.expose_secret())).json(&CreateSubscriptionRequest {
            plan_id,
            total_count: 120,
            quantity: 1,
            customer_notify: true,
            expire_by,
            notes: serde_json::json!({"account_id": account_id, "purchase_attempt_id": attempt_id}),
        }).send().await?.error_for_status()?;
        let subscription: HostedSubscription = response.json().await?;
        if !subscription.id.starts_with("sub_") || !subscription.short_url.starts_with("https://") {
            return Err(PaymentProviderError::InvalidResponse);
        }
        Ok(subscription)
    }

    pub async fn fetch_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<SubscriptionEntity, PaymentProviderError> {
        validate_subscription_id(subscription_id)?;
        let url = self
            .base_url
            .join(&format!("v1/subscriptions/{subscription_id}"))
            .map_err(|_| PaymentProviderError::Configuration)?;
        self.client
            .get(url)
            .basic_auth(&self.key_id, Some(self.key_secret.expose_secret()))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(PaymentProviderError::from)
    }

    pub async fn cancel_subscription(
        &self,
        subscription_id: &str,
        at_cycle_end: bool,
    ) -> Result<SubscriptionEntity, PaymentProviderError> {
        validate_subscription_id(subscription_id)?;
        let url = self
            .base_url
            .join(&format!("v1/subscriptions/{subscription_id}/cancel"))
            .map_err(|_| PaymentProviderError::Configuration)?;
        self.client
            .post(url)
            .basic_auth(&self.key_id, Some(self.key_secret.expose_secret()))
            .json(&serde_json::json!({ "cancel_at_cycle_end": at_cycle_end }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(PaymentProviderError::from)
    }
}

fn validate_subscription_id(value: &str) -> Result<(), PaymentProviderError> {
    if value.starts_with("sub_")
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        Ok(())
    } else {
        Err(PaymentProviderError::Configuration)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PaymentProviderError, RazorpayClient, RazorpaySecrets, RazorpayWebhook, signature_for,
    };
    use secrecy::SecretString;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[test]
    fn verifies_exact_raw_webhook_and_rejects_changes() -> Result<(), Box<dyn std::error::Error>> {
        let body = br#"{"entity":"event","event":"subscription.activated","payload":{}}"#;
        let signature = hex::encode(signature_for(b"secret", body).ok_or("invalid HMAC key")?);
        let secrets = RazorpaySecrets::new(SecretString::from("secret"), None);
        assert!(secrets.verify(&signature, body));
        assert!(!secrets.verify(&signature, b"{}"));
        assert_eq!(
            RazorpayWebhook::parse(body)?.event,
            "subscription.activated"
        );
        Ok(())
    }

    #[tokio::test]
    async fn provider_outage_never_returns_a_payment_link() -> Result<(), Box<dyn std::error::Error>>
    {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/subscriptions"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let client = RazorpayClient::new(
            &format!("{}/", server.uri()),
            "rzp_test_key".to_owned(),
            SecretString::from("test-secret"),
        )?;
        let result = client
            .create_subscription("plan_test", "account", "attempt", 2_000_000_000)
            .await;
        assert!(matches!(result, Err(PaymentProviderError::Transport(_))));
        Ok(())
    }
}
