use sahayak_api::run;
use sahayak_configuration::Settings;
use sahayak_observability::{init_logging, init_sentry, install_panic_hook};

const SERVICE_NAME: &str = "sahayak-api";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = Settings::load()?;
    let _sentry = init_sentry(&settings.observability, settings.environment)?;
    init_logging(SERVICE_NAME, settings.environment, &settings.observability)?;
    install_panic_hook();
    run(settings).await?;
    Ok(())
}
