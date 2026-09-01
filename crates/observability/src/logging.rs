use crate::ObservabilityError;
use sahayak_configuration::{LogFormat, ObservabilitySettings, RuntimeEnvironment};
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Installs the process-wide tracing subscriber.
///
/// This function must be called exactly once, before application tasks are spawned.
pub fn init_logging(
    service_name: &'static str,
    environment: RuntimeEnvironment,
    settings: &ObservabilitySettings,
) -> Result<(), ObservabilityError> {
    let filter = parse_filter(&settings.log_filter)?;

    match settings.log_format {
        LogFormat::Pretty => tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_line_number(true),
            )
            .try_init()
            .map_err(|error| ObservabilityError::Subscriber(error.to_string()))?,
        LogFormat::Json => tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(true)
                    .with_target(true),
            )
            .try_init()
            .map_err(|error| ObservabilityError::Subscriber(error.to_string()))?,
    }

    info!(service = service_name, %environment, "observability initialized");
    Ok(())
}

fn parse_filter(value: &str) -> Result<EnvFilter, ObservabilityError> {
    EnvFilter::try_new(value).map_err(|error| ObservabilityError::InvalidFilter(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::parse_filter;

    #[test]
    fn accepts_valid_filter_directives() {
        assert!(parse_filter("info,sahayak_api=debug").is_ok());
    }

    #[test]
    fn rejects_invalid_filter_directives() {
        assert!(parse_filter("not a valid[filter").is_err());
    }
}
