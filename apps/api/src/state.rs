use crate::billing::RazorpayWebhookService;
use crate::whatsapp::WhatsAppWebhookService;
use sahayak_persistence::Database;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Shared, immutable application dependencies and process readiness state.
#[derive(Clone, Debug)]
pub struct AppState {
    database: Database,
    accepting_traffic: Arc<AtomicBool>,
    readiness_timeout: Duration,
    whatsapp: Option<Arc<WhatsAppWebhookService>>,
    razorpay: Option<Arc<RazorpayWebhookService>>,
}

impl AppState {
    /// Creates API state in the ready-to-accept-traffic state.
    #[must_use]
    pub fn new(database: Database, readiness_timeout: Duration) -> Self {
        Self {
            database,
            accepting_traffic: Arc::new(AtomicBool::new(true)),
            readiness_timeout,
            whatsapp: None,
            razorpay: None,
        }
    }

    #[must_use]
    pub fn with_razorpay(mut self, service: RazorpayWebhookService) -> Self {
        self.razorpay = Some(Arc::new(service));
        self
    }

    #[must_use]
    pub fn razorpay(&self) -> Option<&Arc<RazorpayWebhookService>> {
        self.razorpay.as_ref()
    }

    /// Adds an initialized WhatsApp webhook service.
    #[must_use]
    pub fn with_whatsapp(mut self, service: WhatsAppWebhookService) -> Self {
        self.whatsapp = Some(Arc::new(service));
        self
    }

    /// Returns the WhatsApp service when transport is enabled.
    #[must_use]
    pub fn whatsapp(&self) -> Option<&Arc<WhatsAppWebhookService>> {
        self.whatsapp.as_ref()
    }

    /// Returns the database handle used by dependency checks and repositories.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Returns the maximum duration of a readiness dependency check.
    #[must_use]
    pub const fn readiness_timeout(&self) -> Duration {
        self.readiness_timeout
    }

    /// Returns whether the process may receive new traffic.
    #[must_use]
    pub fn is_accepting_traffic(&self) -> bool {
        self.accepting_traffic.load(Ordering::Acquire)
    }

    /// Marks the process unready before graceful draining begins.
    pub fn begin_shutdown(&self) {
        self.accepting_traffic.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::AppState;
    use sahayak_configuration::DatabaseSettings;
    use sahayak_persistence::Database;
    use secrecy::SecretString;
    use std::time::Duration;

    fn state() -> Result<AppState, Box<dyn std::error::Error>> {
        let settings = DatabaseSettings {
            url: SecretString::from("postgres://user:password@127.0.0.1:55432/database".to_owned()),
            min_connections: 0,
            max_connections: 1,
            acquire_timeout_seconds: 1,
            idle_timeout_seconds: 30,
            max_lifetime_seconds: 60,
            statement_timeout_milliseconds: 5_000,
            lock_timeout_milliseconds: 2_000,
            idle_in_transaction_timeout_milliseconds: 10_000,
            require_tls: false,
        };
        let database = Database::connect_lazy(&settings, "test")?;
        Ok(AppState::new(database, Duration::from_secs(1)))
    }

    #[tokio::test]
    async fn shutdown_transition_is_visible_to_all_clones() -> Result<(), Box<dyn std::error::Error>>
    {
        let state = state()?;
        let clone = state.clone();

        assert!(clone.is_accepting_traffic());
        state.begin_shutdown();
        assert!(!clone.is_accepting_traffic());
        Ok(())
    }
}
