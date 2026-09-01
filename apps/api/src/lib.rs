//! Sahayak's public HTTP ingress process.

mod app;
mod billing;
mod billing_routes;
mod error;
mod health;
mod request_id;
mod server;
mod shutdown;
mod state;
mod whatsapp;
mod whatsapp_routes;

pub use app::build_router;
pub use error::ApiError;
pub use server::run;
pub use state::AppState;
