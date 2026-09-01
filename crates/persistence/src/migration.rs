use sqlx::migrate::Migrator;

/// Compile-time embedded, checksummed migration set used by the migrator process.
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");
