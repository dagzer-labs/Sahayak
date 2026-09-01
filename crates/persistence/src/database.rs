use crate::{PersistenceError, migration::MIGRATOR};
use sahayak_configuration::DatabaseSettings;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{fmt, str::FromStr};

/// Cloneable handle to the process PostgreSQL connection pool.
#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    pub(crate) const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Creates a lazy pool suitable for an API that exposes readiness separately.
    ///
    /// No network connection is attempted until the first database operation.
    pub fn connect_lazy(
        settings: &DatabaseSettings,
        application_name: &str,
    ) -> Result<Self, PersistenceError> {
        let options = connect_options(settings, application_name)?;
        let pool = pool_options(settings).connect_lazy_with(options);
        Ok(Self { pool })
    }

    /// Creates a pool and verifies that PostgreSQL is reachable before returning.
    pub async fn connect(
        settings: &DatabaseSettings,
        application_name: &str,
    ) -> Result<Self, PersistenceError> {
        let options = connect_options(settings, application_name)?;
        let pool = pool_options(settings).connect_with(options).await?;
        Ok(Self { pool })
    }

    /// Checks that a connection can be acquired and a trivial query can complete.
    pub async fn check_health(&self) -> Result<(), PersistenceError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Applies every pending checksummed migration in order.
    ///
    /// Production runtime credentials must not have permission to call this method;
    /// deployments run it through the dedicated migrator process and role.
    pub async fn migrate(&self) -> Result<(), PersistenceError> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    /// Closes the pool and waits for checked-out connections to return.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Returns the number of currently open pool connections.
    #[must_use]
    pub fn size(&self) -> u32 {
        self.pool.size()
    }

    /// Returns the number of idle pool connections.
    #[must_use]
    pub fn idle_connections(&self) -> usize {
        self.pool.num_idle()
    }
}

impl fmt::Debug for Database {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Database")
            .field("size", &self.size())
            .field("idle_connections", &self.idle_connections())
            .field("closed", &self.pool.is_closed())
            .finish()
    }
}

fn connect_options(
    settings: &DatabaseSettings,
    application_name: &str,
) -> Result<PgConnectOptions, PersistenceError> {
    PgConnectOptions::from_str(settings.expose_url())
        .map(|options| {
            let options = options.application_name(application_name);
            if settings.require_tls {
                options.ssl_mode(PgSslMode::VerifyFull)
            } else {
                options
            }
        })
        .map_err(PersistenceError::InvalidConfiguration)
}

fn pool_options(settings: &DatabaseSettings) -> PgPoolOptions {
    let statement_timeout = settings.statement_timeout_value();
    let lock_timeout = settings.lock_timeout_value();
    let transaction_timeout = settings.idle_in_transaction_timeout_value();

    PgPoolOptions::new()
        .min_connections(settings.min_connections)
        .max_connections(settings.max_connections)
        .acquire_timeout(settings.acquire_timeout())
        .idle_timeout(Some(settings.idle_timeout()))
        .max_lifetime(Some(settings.max_lifetime()))
        .after_connect(move |connection, _metadata| {
            let statement_timeout = statement_timeout.clone();
            let lock_timeout = lock_timeout.clone();
            let transaction_timeout = transaction_timeout.clone();

            Box::pin(async move {
                sqlx::query("SELECT set_config('statement_timeout', $1, false)")
                    .bind(statement_timeout)
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SELECT set_config('lock_timeout', $1, false)")
                    .bind(lock_timeout)
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SELECT set_config('idle_in_transaction_session_timeout', $1, false)")
                    .bind(transaction_timeout)
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SET TIME ZONE 'UTC'")
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
}

#[cfg(test)]
mod tests {
    use super::Database;
    use sahayak_configuration::DatabaseSettings;
    use secrecy::SecretString;

    fn settings(url: &str) -> DatabaseSettings {
        DatabaseSettings {
            url: SecretString::from(url.to_owned()),
            min_connections: 0,
            max_connections: 2,
            acquire_timeout_seconds: 1,
            idle_timeout_seconds: 30,
            max_lifetime_seconds: 60,
            statement_timeout_milliseconds: 5_000,
            lock_timeout_milliseconds: 2_000,
            idle_in_transaction_timeout_milliseconds: 10_000,
            require_tls: false,
        }
    }

    #[test]
    fn rejects_invalid_database_url() {
        assert!(Database::connect_lazy(&settings("not-a-url"), "test").is_err());
    }

    #[tokio::test]
    async fn debug_output_does_not_include_database_url() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = Database::connect_lazy(
            &settings("postgres://user:secret@127.0.0.1:55432/database"),
            "test",
        )?;

        let output = format!("{database:?}");
        assert!(!output.contains("secret"));
        assert!(!output.contains("postgres://"));
        Ok(())
    }
}
