use thiserror::Error;

/// Error returned by the persistence boundary.
#[derive(Debug, Error)]
pub enum PersistenceError {
    /// PostgreSQL connection settings could not be parsed.
    #[error("invalid PostgreSQL configuration: {0}")]
    InvalidConfiguration(#[source] sqlx::Error),

    /// PostgreSQL could not be reached or rejected an operation.
    #[error("PostgreSQL operation failed: {0}")]
    Database(#[from] sqlx::Error),

    /// A versioned database migration could not be applied.
    #[error("database migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// A repository command violated a precondition before reaching PostgreSQL.
    #[error("invalid persistence command: {0}")]
    InvalidCommand(String),

    /// Durable state contradicted an invariant expected by the repository.
    #[error("persistence invariant violated: {0}")]
    Invariant(String),

    /// Optimistic state changed before the requested transaction could commit.
    #[error("optimistic persistence conflict")]
    OptimisticConflict,
}

impl PersistenceError {
    /// Returns whether retrying the complete database transaction is appropriate.
    ///
    /// Serialization failures, deadlocks, and lock timeouts are transient. Callers
    /// must never retry only part of a transaction or repeat an external side effect.
    #[must_use]
    pub fn is_retryable_transaction(&self) -> bool {
        let Self::Database(sqlx::Error::Database(error)) = self else {
            return false;
        };
        matches!(error.code().as_deref(), Some("40001" | "40P01" | "55P03"))
    }

    /// Returns the named PostgreSQL constraint associated with a database error.
    #[must_use]
    pub fn constraint_name(&self) -> Option<&str> {
        let Self::Database(sqlx::Error::Database(error)) = self else {
            return None;
        };
        error.constraint()
    }
}
