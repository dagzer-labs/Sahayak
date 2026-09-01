//! Sahayak's durable background-work process.

mod availability;
mod error;
mod health;
mod photo;
mod runtime;
mod shutdown;
mod whatsapp;

pub use error::WorkerError;
pub use runtime::run;
