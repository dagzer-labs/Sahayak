use crate::{RuntimeEnvironment, SettingsError};
use config::{Config, Environment as EnvironmentSource};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::{fmt, net::IpAddr, path::PathBuf, time::Duration};

const ENVIRONMENT_PREFIX: &str = "SAHAYAK";

/// Complete process configuration loaded from environment variables.
#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    /// Current runtime environment.
    pub environment: RuntimeEnvironment,
    /// HTTP server limits and binding details.
    pub http: HttpSettings,
    /// PostgreSQL connection-pool settings.
    pub database: DatabaseSettings,
    /// Background worker scheduling settings.
    pub worker: WorkerSettings,
    /// Logging and telemetry settings.
    pub observability: ObservabilitySettings,
    /// Optional WhatsApp Cloud API transport configuration.
    pub whatsapp: WhatsAppSettings,
    /// Optional Razorpay subscription and webhook configuration.
    pub razorpay: RazorpaySettings,
}

impl Settings {
    /// Loads settings from `SAHAYAK__...` environment variables and validates them.
    pub fn load() -> Result<Self, SettingsError> {
        let config = Self::builder()?.build()?;
        let settings: Self = config.try_deserialize()?;
        settings.validate()?;
        Ok(settings)
    }

    fn builder() -> Result<config::ConfigBuilder<config::builder::DefaultState>, config::ConfigError>
    {
        let builder = Config::builder()
            .set_default("environment", "development")?
            .set_default("http.host", "0.0.0.0")?
            .set_default("http.port", 8080)?
            .set_default("http.request_timeout_seconds", 10)?
            .set_default("http.readiness_timeout_seconds", 2)?
            .set_default("http.shutdown_grace_seconds", 25)?
            .set_default("http.max_request_body_bytes", 3_145_728)?
            .set_default(
                "database.url",
                "postgres://sahayak_app:sahayak_dev@127.0.0.1:55432/sahayak",
            )?
            .set_default("database.min_connections", 1)?
            .set_default("database.max_connections", 10)?
            .set_default("database.acquire_timeout_seconds", 5)?
            .set_default("database.idle_timeout_seconds", 600)?
            .set_default("database.max_lifetime_seconds", 1_800)?
            .set_default("database.statement_timeout_milliseconds", 5_000)?
            .set_default("database.lock_timeout_milliseconds", 2_000)?
            .set_default("database.idle_in_transaction_timeout_milliseconds", 10_000)?
            .set_default("database.require_tls", false)?
            .set_default("worker.health_interval_seconds", 30)?
            .set_default("worker.shutdown_grace_seconds", 10)?
            .set_default("worker.job_poll_interval_milliseconds", 250)?
            .set_default("worker.job_claim_batch_size", 10)?
            .set_default("worker.job_lease_seconds", 30)?
            .set_default("worker.inbound_payload_retention_days", 14)?
            .set_default("observability.log_filter", "info,sahayak=debug")?
            .set_default("observability.log_format", "pretty")?
            .set_default("observability.sentry_enabled", false)?
            .set_default("observability.sentry_dsn_file", "/run/secrets/sentry_dsn")?
            .set_default("whatsapp.enabled", false)?
            .set_default("whatsapp.graph_api_base_url", "https://graph.facebook.com")?
            .set_default("whatsapp.graph_api_version", "v26.0")?
            .set_default("whatsapp.waba_id", "")?
            .set_default("whatsapp.phone_number_id", "")?
            .set_default(
                "whatsapp.app_secret_current_file",
                "/run/secrets/meta_app_secret_current",
            )?
            .set_default("whatsapp.app_secret_previous_file", "")?
            .set_default(
                "whatsapp.verify_token_file",
                "/run/secrets/meta_verify_token",
            )?
            .set_default(
                "whatsapp.access_token_file",
                "/run/secrets/meta_access_token",
            )?
            .set_default(
                "whatsapp.crypto_keyring_file",
                "/run/secrets/sahayak_crypto_keyring",
            )?
            .set_default("whatsapp.webhook_max_body_bytes", 3_145_728)?
            .set_default("whatsapp.request_timeout_seconds", 20)?
            .set_default("whatsapp.transport_probe_enabled", false)?
            .set_default("whatsapp.reentry_template_name", "sahayak_reentry")?
            .set_default(
                "whatsapp.payment_reminder_template_name",
                "sahayak_payment_reminder",
            )?;
        let builder = builder
            .set_default("razorpay.enabled", false)?
            .set_default("razorpay.api_base_url", "https://api.razorpay.com")?
            .set_default("razorpay.key_id", "")?
            .set_default(
                "razorpay.key_secret_file",
                "/run/secrets/razorpay_key_secret",
            )?
            .set_default(
                "razorpay.webhook_secret_current_file",
                "/run/secrets/razorpay_webhook_secret_current",
            )?
            .set_default("razorpay.webhook_secret_previous_file", "")?
            .set_default("razorpay.plan_id", "")?
            .set_default("razorpay.webhook_max_body_bytes", 262_144)?;

        Ok(builder.add_source(
            EnvironmentSource::with_prefix(ENVIRONMENT_PREFIX)
                .prefix_separator("__")
                .separator("__")
                .try_parsing(true),
        ))
    }

    fn validate(&self) -> Result<(), SettingsError> {
        self.http.validate()?;
        self.database.validate(self.environment)?;
        self.worker.validate()?;
        self.observability.validate(self.environment)?;
        self.whatsapp.validate(self.environment)?;
        self.razorpay.validate(self.environment)
    }
}

/// Razorpay API and webhook settings. Secret values are loaded from mounted files.
#[derive(Clone, Debug, Deserialize)]
pub struct RazorpaySettings {
    pub enabled: bool,
    pub api_base_url: String,
    pub key_id: String,
    pub key_secret_file: PathBuf,
    pub webhook_secret_current_file: PathBuf,
    pub webhook_secret_previous_file: String,
    pub plan_id: String,
    pub webhook_max_body_bytes: usize,
}

impl RazorpaySettings {
    #[must_use]
    pub fn previous_webhook_secret_path(&self) -> Option<PathBuf> {
        (!self.webhook_secret_previous_file.is_empty())
            .then(|| PathBuf::from(&self.webhook_secret_previous_file))
    }

    fn validate(&self, environment: RuntimeEnvironment) -> Result<(), SettingsError> {
        if !(1_024..=1_048_576).contains(&self.webhook_max_body_bytes) {
            return Err(SettingsError::Invalid(
                "razorpay.webhook_max_body_bytes must be between 1024 and 1048576".to_owned(),
            ));
        }
        if self.enabled {
            if self.key_id.is_empty() || self.plan_id.is_empty() {
                return Err(SettingsError::Invalid(
                    "enabled Razorpay requires key_id and plan_id".to_owned(),
                ));
            }
            let url = url::Url::parse(&self.api_base_url).map_err(|_| {
                SettingsError::Invalid("razorpay.api_base_url must be a valid URL".to_owned())
            })?;
            if environment.is_production() && url.scheme() != "https" {
                return Err(SettingsError::Invalid(
                    "production Razorpay API requires HTTPS".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// HTTP listener and defensive request limits.
#[derive(Clone, Debug, Deserialize)]
pub struct HttpSettings {
    /// Interface on which the API listens.
    pub host: IpAddr,
    /// TCP port on which the API listens.
    pub port: u16,
    /// Maximum time allowed for one HTTP request.
    pub request_timeout_seconds: u64,
    /// Maximum duration of one readiness dependency check.
    pub readiness_timeout_seconds: u64,
    /// Maximum time allowed to drain requests during shutdown.
    pub shutdown_grace_seconds: u64,
    /// Maximum accepted request body size.
    pub max_request_body_bytes: usize,
}

impl HttpSettings {
    /// Returns the configured request timeout.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_seconds)
    }

    /// Returns the configured readiness dependency timeout.
    #[must_use]
    pub const fn readiness_timeout(&self) -> Duration {
        Duration::from_secs(self.readiness_timeout_seconds)
    }

    /// Returns the configured graceful-shutdown deadline.
    #[must_use]
    pub const fn shutdown_grace(&self) -> Duration {
        Duration::from_secs(self.shutdown_grace_seconds)
    }

    fn validate(&self) -> Result<(), SettingsError> {
        if self.port == 0 {
            return Err(SettingsError::Invalid(
                "http.port must be between 1 and 65535".to_owned(),
            ));
        }
        if !(1..=120).contains(&self.request_timeout_seconds) {
            return Err(SettingsError::Invalid(
                "http.request_timeout_seconds must be between 1 and 120".to_owned(),
            ));
        }
        if !(1..=10).contains(&self.readiness_timeout_seconds) {
            return Err(SettingsError::Invalid(
                "http.readiness_timeout_seconds must be between 1 and 10".to_owned(),
            ));
        }
        if !(5..=120).contains(&self.shutdown_grace_seconds) {
            return Err(SettingsError::Invalid(
                "http.shutdown_grace_seconds must be between 5 and 120".to_owned(),
            ));
        }
        if !(1_024..=10_485_760).contains(&self.max_request_body_bytes) {
            return Err(SettingsError::Invalid(
                "http.max_request_body_bytes must be between 1024 and 10485760".to_owned(),
            ));
        }
        Ok(())
    }
}

/// PostgreSQL connection-pool limits and credentials.
#[derive(Clone, Deserialize)]
pub struct DatabaseSettings {
    /// Secret PostgreSQL connection URL.
    pub url: SecretString,
    /// Connections kept open even while idle.
    pub min_connections: u32,
    /// Hard upper bound for process database connections.
    pub max_connections: u32,
    /// Maximum wait for a connection from the pool.
    pub acquire_timeout_seconds: u64,
    /// Maximum time an idle connection remains in the pool.
    pub idle_timeout_seconds: u64,
    /// Maximum lifetime of one pooled connection.
    pub max_lifetime_seconds: u64,
    /// Maximum execution time for one database statement.
    pub statement_timeout_milliseconds: u64,
    /// Maximum wait for a database lock.
    pub lock_timeout_milliseconds: u64,
    /// Maximum idle time allowed inside an open transaction.
    pub idle_in_transaction_timeout_milliseconds: u64,
    /// Requires certificate and hostname verification for PostgreSQL connections.
    pub require_tls: bool,
}

impl DatabaseSettings {
    /// Exposes the database URL only at the integration boundary that needs it.
    #[must_use]
    pub fn expose_url(&self) -> &str {
        self.url.expose_secret()
    }

    /// Returns the configured pool acquisition timeout.
    #[must_use]
    pub const fn acquire_timeout(&self) -> Duration {
        Duration::from_secs(self.acquire_timeout_seconds)
    }

    /// Returns the configured idle connection timeout.
    #[must_use]
    pub const fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_seconds)
    }

    /// Returns the configured maximum connection lifetime.
    #[must_use]
    pub const fn max_lifetime(&self) -> Duration {
        Duration::from_secs(self.max_lifetime_seconds)
    }

    /// Returns the configured statement timeout as a PostgreSQL setting value.
    #[must_use]
    pub fn statement_timeout_value(&self) -> String {
        format!("{}ms", self.statement_timeout_milliseconds)
    }

    /// Returns the configured lock timeout as a PostgreSQL setting value.
    #[must_use]
    pub fn lock_timeout_value(&self) -> String {
        format!("{}ms", self.lock_timeout_milliseconds)
    }

    /// Returns the configured idle-in-transaction timeout as a PostgreSQL setting value.
    #[must_use]
    pub fn idle_in_transaction_timeout_value(&self) -> String {
        format!("{}ms", self.idle_in_transaction_timeout_milliseconds)
    }

    fn validate(&self, environment: RuntimeEnvironment) -> Result<(), SettingsError> {
        let url = self.expose_url();
        if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
            return Err(SettingsError::Invalid(
                "database.url must use the postgres or postgresql scheme".to_owned(),
            ));
        }
        if self.max_connections == 0 || self.max_connections > 100 {
            return Err(SettingsError::Invalid(
                "database.max_connections must be between 1 and 100".to_owned(),
            ));
        }
        if self.min_connections > self.max_connections {
            return Err(SettingsError::Invalid(
                "database.min_connections cannot exceed database.max_connections".to_owned(),
            ));
        }
        if !(1..=60).contains(&self.acquire_timeout_seconds) {
            return Err(SettingsError::Invalid(
                "database.acquire_timeout_seconds must be between 1 and 60".to_owned(),
            ));
        }
        if self.idle_timeout_seconds == 0 || self.max_lifetime_seconds == 0 {
            return Err(SettingsError::Invalid(
                "database connection lifetimes must be greater than zero".to_owned(),
            ));
        }
        if self.statement_timeout_milliseconds == 0
            || self.lock_timeout_milliseconds == 0
            || self.idle_in_transaction_timeout_milliseconds == 0
        {
            return Err(SettingsError::Invalid(
                "database statement and transaction timeouts must be greater than zero".to_owned(),
            ));
        }
        if environment.is_production() && !self.require_tls {
            return Err(SettingsError::Invalid(
                "production requires verified PostgreSQL TLS".to_owned(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for DatabaseSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseSettings")
            .field("url", &"[REDACTED]")
            .field("min_connections", &self.min_connections)
            .field("max_connections", &self.max_connections)
            .field("acquire_timeout_seconds", &self.acquire_timeout_seconds)
            .field("idle_timeout_seconds", &self.idle_timeout_seconds)
            .field("max_lifetime_seconds", &self.max_lifetime_seconds)
            .field(
                "statement_timeout_milliseconds",
                &self.statement_timeout_milliseconds,
            )
            .field("lock_timeout_milliseconds", &self.lock_timeout_milliseconds)
            .field(
                "idle_in_transaction_timeout_milliseconds",
                &self.idle_in_transaction_timeout_milliseconds,
            )
            .field("require_tls", &self.require_tls)
            .finish()
    }
}

/// Background worker timing configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct WorkerSettings {
    /// Frequency of the foundation database-health probe.
    pub health_interval_seconds: u64,
    /// Maximum time allowed to close worker resources during shutdown.
    pub shutdown_grace_seconds: u64,
    /// Delay between durable job claim attempts while no work is available.
    pub job_poll_interval_milliseconds: u64,
    /// Maximum jobs claimed in one short transaction.
    pub job_claim_batch_size: u16,
    /// Duration of one worker lease.
    pub job_lease_seconds: u64,
    /// Days encrypted normalized webhook payloads remain after processing.
    pub inbound_payload_retention_days: u16,
}

impl WorkerSettings {
    /// Returns the health-probe interval.
    #[must_use]
    pub const fn health_interval(&self) -> Duration {
        Duration::from_secs(self.health_interval_seconds)
    }

    /// Returns the configured graceful-shutdown deadline.
    #[must_use]
    pub const fn shutdown_grace(&self) -> Duration {
        Duration::from_secs(self.shutdown_grace_seconds)
    }

    /// Returns the idle durable-job polling interval.
    #[must_use]
    pub const fn job_poll_interval(&self) -> Duration {
        Duration::from_millis(self.job_poll_interval_milliseconds)
    }

    /// Returns the durable-job lease duration.
    #[must_use]
    pub const fn job_lease(&self) -> Duration {
        Duration::from_secs(self.job_lease_seconds)
    }

    /// Returns the configured encrypted webhook-payload retention period.
    #[must_use]
    pub const fn inbound_payload_retention(&self) -> Duration {
        Duration::from_secs(self.inbound_payload_retention_days as u64 * 86_400)
    }

    fn validate(&self) -> Result<(), SettingsError> {
        if !(5..=3_600).contains(&self.health_interval_seconds) {
            return Err(SettingsError::Invalid(
                "worker.health_interval_seconds must be between 5 and 3600".to_owned(),
            ));
        }
        if !(5..=120).contains(&self.shutdown_grace_seconds) {
            return Err(SettingsError::Invalid(
                "worker.shutdown_grace_seconds must be between 5 and 120".to_owned(),
            ));
        }
        if !(50..=60_000).contains(&self.job_poll_interval_milliseconds) {
            return Err(SettingsError::Invalid(
                "worker.job_poll_interval_milliseconds must be between 50 and 60000".to_owned(),
            ));
        }
        if !(1..=100).contains(&self.job_claim_batch_size) {
            return Err(SettingsError::Invalid(
                "worker.job_claim_batch_size must be between 1 and 100".to_owned(),
            ));
        }
        if !(5..=900).contains(&self.job_lease_seconds) {
            return Err(SettingsError::Invalid(
                "worker.job_lease_seconds must be between 5 and 900".to_owned(),
            ));
        }
        if !(7..=365).contains(&self.inbound_payload_retention_days) {
            return Err(SettingsError::Invalid(
                "worker.inbound_payload_retention_days must be between 7 and 365".to_owned(),
            ));
        }
        Ok(())
    }
}

/// WhatsApp Cloud API endpoint identifiers and secret-file locations.
#[derive(Clone, Debug, Deserialize)]
pub struct WhatsAppSettings {
    /// Enables webhook routes and worker delivery.
    pub enabled: bool,
    /// Graph API origin.
    pub graph_api_base_url: String,
    /// Pinned Graph API version.
    pub graph_api_version: String,
    /// Expected WhatsApp Business Account ID.
    pub waba_id: String,
    /// Sender business phone-number object ID.
    pub phone_number_id: String,
    /// Current Meta app-secret file.
    pub app_secret_current_file: PathBuf,
    /// Previous app-secret file accepted during rotation, or an empty path.
    pub app_secret_previous_file: PathBuf,
    /// Webhook verification-token file.
    pub verify_token_file: PathBuf,
    /// Cloud API access-token file.
    pub access_token_file: PathBuf,
    /// Versioned cryptographic keyring file.
    pub crypto_keyring_file: PathBuf,
    /// Maximum accepted signed webhook body.
    pub webhook_max_body_bytes: usize,
    /// Cloud API request deadline.
    pub request_timeout_seconds: u64,
    /// Enables only the exact internal transport-probe message in controlled environments.
    pub transport_probe_enabled: bool,
    /// Approved localized template used to reopen a closed service window.
    pub reentry_template_name: String,
    /// Approved localized template used for payment-required and past-due reminders.
    pub payment_reminder_template_name: String,
}

impl WhatsAppSettings {
    /// Returns the Cloud API request timeout.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_seconds)
    }

    /// Returns the previous app-secret path only when configured.
    #[must_use]
    pub fn previous_app_secret_path(&self) -> Option<&std::path::Path> {
        (!self.app_secret_previous_file.as_os_str().is_empty())
            .then_some(self.app_secret_previous_file.as_path())
    }

    fn validate(&self, environment: RuntimeEnvironment) -> Result<(), SettingsError> {
        if !self.enabled {
            return Ok(());
        }
        if self.graph_api_version != "v26.0" {
            return Err(SettingsError::Invalid(
                "WhatsApp Graph API version must be explicitly pinned to v26.0".to_owned(),
            ));
        }
        if !(self.graph_api_base_url.starts_with("https://")
            || (!environment.is_production() && self.graph_api_base_url.starts_with("http://")))
        {
            return Err(SettingsError::Invalid(
                "WhatsApp Graph API URL must use HTTPS outside tests".to_owned(),
            ));
        }
        if self.waba_id.is_empty()
            || !self.waba_id.bytes().all(|byte| byte.is_ascii_digit())
            || self.phone_number_id.is_empty()
            || !self
                .phone_number_id
                .bytes()
                .all(|byte| byte.is_ascii_digit())
        {
            return Err(SettingsError::Invalid(
                "WhatsApp WABA and phone-number IDs must contain only digits".to_owned(),
            ));
        }
        if !(1_024..=3_145_728).contains(&self.webhook_max_body_bytes) {
            return Err(SettingsError::Invalid(
                "WhatsApp webhook body limit must be between 1024 and 3145728".to_owned(),
            ));
        }
        if !(1..=120).contains(&self.request_timeout_seconds) {
            return Err(SettingsError::Invalid(
                "WhatsApp request timeout must be between 1 and 120 seconds".to_owned(),
            ));
        }
        if self.reentry_template_name.is_empty()
            || self.reentry_template_name.len() > 512
            || !self
                .reentry_template_name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(SettingsError::Invalid(
                "WhatsApp re-entry template name is invalid".to_owned(),
            ));
        }
        if self.payment_reminder_template_name.is_empty()
            || self.payment_reminder_template_name.len() > 512
            || !self
                .payment_reminder_template_name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(SettingsError::Invalid(
                "WhatsApp payment reminder template name is invalid".to_owned(),
            ));
        }
        for (name, path) in [
            ("app secret", &self.app_secret_current_file),
            ("verify token", &self.verify_token_file),
            ("access token", &self.access_token_file),
            ("crypto keyring", &self.crypto_keyring_file),
        ] {
            if path.as_os_str().is_empty() || (environment.is_production() && !path.is_absolute()) {
                return Err(SettingsError::Invalid(format!(
                    "WhatsApp {name} file path is missing or not absolute"
                )));
            }
        }
        if environment.is_production()
            && !self.app_secret_previous_file.as_os_str().is_empty()
            && !self.app_secret_previous_file.is_absolute()
        {
            return Err(SettingsError::Invalid(
                "previous WhatsApp app-secret file path must be absolute".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Output format used for application logs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// Human-readable logs intended for local development.
    Pretty,
    /// Structured logs intended for machines and production ingestion.
    Json,
}

/// Logging configuration shared by API and worker processes.
#[derive(Clone, Debug, Deserialize)]
pub struct ObservabilitySettings {
    /// Tracing filter directive.
    pub log_filter: String,
    /// Selected log encoding.
    pub log_format: LogFormat,
    /// Enables privacy-filtered Sentry error reporting.
    pub sentry_enabled: bool,
    /// Mounted Sentry DSN secret file.
    pub sentry_dsn_file: PathBuf,
}

impl ObservabilitySettings {
    fn validate(&self, environment: RuntimeEnvironment) -> Result<(), SettingsError> {
        if self.log_filter.trim().is_empty() {
            return Err(SettingsError::Invalid(
                "observability.log_filter cannot be empty".to_owned(),
            ));
        }
        if environment.is_production() && self.log_format != LogFormat::Json {
            return Err(SettingsError::Invalid(
                "production requires JSON log output".to_owned(),
            ));
        }
        if self.sentry_enabled
            && (self.sentry_dsn_file.as_os_str().is_empty()
                || (environment.is_production() && !self.sentry_dsn_file.is_absolute()))
        {
            return Err(SettingsError::Invalid(
                "Sentry DSN file must be an absolute path in production".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{DatabaseSettings, LogFormat, Settings};
    use secrecy::SecretString;

    #[test]
    fn default_settings_are_valid() -> Result<(), Box<dyn std::error::Error>> {
        let settings: Settings = Settings::builder()?.build()?.try_deserialize()?;
        settings.validate()?;
        Ok(())
    }

    #[test]
    fn production_requires_json_logs() -> Result<(), Box<dyn std::error::Error>> {
        let settings: Settings = Settings::builder()?
            .set_override("environment", "production")?
            .set_override("database.require_tls", true)?
            .set_override("observability.log_format", "pretty")?
            .build()?
            .try_deserialize()?;

        let error = settings
            .validate()
            .err()
            .ok_or("expected validation failure")?;
        assert!(error.to_string().contains("production requires JSON"));
        Ok(())
    }

    #[test]
    fn production_requires_verified_database_tls() -> Result<(), Box<dyn std::error::Error>> {
        let settings: Settings = Settings::builder()?
            .set_override("environment", "production")?
            .set_override("database.require_tls", false)?
            .set_override("observability.log_format", "json")?
            .build()?
            .try_deserialize()?;

        let error = settings
            .validate()
            .err()
            .ok_or("expected validation failure")?;
        assert!(error.to_string().contains("verified PostgreSQL TLS"));
        Ok(())
    }

    #[test]
    fn rejects_pool_minimum_above_maximum() -> Result<(), Box<dyn std::error::Error>> {
        let settings: Settings = Settings::builder()?
            .set_override("database.min_connections", 11)?
            .set_override("database.max_connections", 10)?
            .build()?
            .try_deserialize()?;

        let error = settings
            .validate()
            .err()
            .ok_or("expected validation failure")?;
        assert!(error.to_string().contains("min_connections"));
        Ok(())
    }

    #[test]
    fn database_debug_output_redacts_url() {
        let settings = DatabaseSettings {
            url: SecretString::from("postgres://user:secret@localhost/database".to_owned()),
            min_connections: 1,
            max_connections: 5,
            acquire_timeout_seconds: 5,
            idle_timeout_seconds: 60,
            max_lifetime_seconds: 600,
            statement_timeout_milliseconds: 5_000,
            lock_timeout_milliseconds: 2_000,
            idle_in_transaction_timeout_milliseconds: 10_000,
            require_tls: false,
        };

        let output = format!("{settings:?}");
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("secret"));
    }

    #[test]
    fn parses_json_log_format() -> Result<(), serde_json::Error> {
        let format: LogFormat = serde_json::from_str("\"json\"")?;
        assert_eq!(format, LogFormat::Json);
        Ok(())
    }
}
