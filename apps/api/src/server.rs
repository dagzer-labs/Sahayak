use crate::{
    ApiError, AppState, billing::RazorpayWebhookService, build_router, shutdown,
    whatsapp::WhatsAppWebhookService,
};
use sahayak_configuration::Settings;
use sahayak_persistence::Database;
use std::{future::IntoFuture, net::SocketAddr};
use tokio::{net::TcpListener, sync::oneshot, time::timeout};
use tracing::{error, info, warn};

const SERVICE_NAME: &str = "sahayak-api";

/// Runs the API until termination and drains in-flight requests within a deadline.
pub async fn run(settings: Settings) -> Result<(), ApiError> {
    let database = Database::connect_lazy(&settings.database, SERVICE_NAME)?;
    let mut state = AppState::new(database.clone(), settings.http.readiness_timeout());
    if settings.whatsapp.enabled {
        let whatsapp = WhatsAppWebhookService::load(
            &settings.whatsapp,
            settings.environment,
            database.clone(),
        )
        .await
        .map_err(|error| ApiError::WhatsAppInitialization(error.to_string()))?;
        state = state.with_whatsapp(whatsapp);
    }
    if settings.razorpay.enabled {
        let razorpay = RazorpayWebhookService::load(
            &settings.razorpay,
            settings.environment,
            database.clone(),
        )
        .map_err(|error| ApiError::RazorpayInitialization(error.to_string()))?;
        state = state.with_razorpay(razorpay);
    }
    let app = build_router(state.clone(), &settings.http);
    let address = SocketAddr::new(settings.http.host, settings.http.port);
    let listener = TcpListener::bind(address).await.map_err(ApiError::Bind)?;
    let local_address = listener.local_addr().map_err(ApiError::Bind)?;

    let (graceful_tx, graceful_rx) = oneshot::channel();
    let (shutdown_started_tx, mut shutdown_started_rx) = oneshot::channel();
    let readiness = state.clone();
    let signal_task = tokio::spawn(async move {
        if let Err(error) = shutdown::wait_for_signal().await {
            error!(%error, "failed to listen for shutdown signal");
        }
        readiness.begin_shutdown();
        let _ = shutdown_started_tx.send(());
        let _ = graceful_tx.send(());
    });

    info!(address = %local_address, "API listening");

    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = graceful_rx.await;
        })
        .into_future();
    tokio::pin!(server);

    let result = tokio::select! {
        result = &mut server => result.map_err(ApiError::Serve),
        _ = &mut shutdown_started_rx => {
            info!("API draining in-flight requests");
            match timeout(settings.http.shutdown_grace(), &mut server).await {
                Ok(result) => result.map_err(ApiError::Serve),
                Err(_) => Err(ApiError::ShutdownTimeout(settings.http.shutdown_grace())),
            }
        }
    };

    signal_task.abort();
    if timeout(settings.http.readiness_timeout(), database.close())
        .await
        .is_err()
    {
        warn!("database pool close exceeded deadline");
    }

    result
}
