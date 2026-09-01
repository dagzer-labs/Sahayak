use sahayak_configuration::Settings;
use sahayak_observability::{init_logging, init_sentry, install_panic_hook};
use sahayak_persistence::Database;
use tracing::info;

const SERVICE_NAME: &str = "sahayak-migrator";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = Settings::load()?;
    let _sentry = init_sentry(&settings.observability, settings.environment)?;
    init_logging(SERVICE_NAME, settings.environment, &settings.observability)?;
    install_panic_hook();

    let database = Database::connect(&settings.database, SERVICE_NAME).await?;
    database.migrate().await?;
    database.close().await;

    info!("database migrations completed");
    Ok(())
}
