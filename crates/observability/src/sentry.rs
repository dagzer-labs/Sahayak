use crate::ObservabilityError;
use sahayak_configuration::{ObservabilitySettings, RuntimeEnvironment, load_secret_file};
use secrecy::ExposeSecret;
use std::str::FromStr;

/// Initializes Sentry without default PII collection and keeps its client alive.
pub fn init_sentry(
    settings: &ObservabilitySettings,
    environment: RuntimeEnvironment,
) -> Result<Option<::sentry::ClientInitGuard>, ObservabilityError> {
    if !settings.sentry_enabled {
        return Ok(None);
    }
    let dsn = load_secret_file(
        &settings.sentry_dsn_file,
        4_096,
        environment.is_production(),
    )
    .map_err(|_| ObservabilityError::Sentry)?;
    let dsn = ::sentry::types::Dsn::from_str(dsn.expose_secret())
        .map_err(|_| ObservabilityError::Sentry)?;
    let mut options = ::sentry::ClientOptions::default();
    options.dsn = Some(dsn);
    options.environment = Some(environment.to_string().into());
    options.release = ::sentry::release_name!();
    options.send_default_pii = false;
    Ok(Some(::sentry::init(options)))
}
