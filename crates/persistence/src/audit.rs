use crate::{Database, PersistenceError};
use sahayak_domain::{AccountId, AuditActorType, AuditEventId, ChannelIdentityId, CorrelationId};
use serde_json::Value;
use std::fmt;

/// Trusted origin through which an auditable action was requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditSource {
    /// Administrator interaction through WhatsApp.
    WhatsApp,
    /// Restricted internal command-line operation.
    InternalCli,
    /// Future authenticated operations interface.
    AdminUi,
    /// Automated system decision without a human actor.
    System,
}

impl AuditSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::WhatsApp => "whatsapp",
            Self::InternalCli => "internal_cli",
            Self::AdminUi => "admin_ui",
            Self::System => "system",
        }
    }
}

/// Validated actor identity attached to an immutable audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditActor {
    actor_type: AuditActorType,
    account_id: Option<AccountId>,
    channel_identity_id: Option<ChannelIdentityId>,
    source: AuditSource,
}

impl AuditActor {
    /// Creates an automated system actor.
    #[must_use]
    pub const fn system() -> Self {
        Self {
            actor_type: AuditActorType::System,
            account_id: None,
            channel_identity_id: None,
            source: AuditSource::System,
        }
    }

    /// Creates an account actor using a known channel identity.
    #[must_use]
    pub const fn account(
        account_id: AccountId,
        channel_identity_id: ChannelIdentityId,
        source: AuditSource,
    ) -> Self {
        Self {
            actor_type: AuditActorType::Account,
            account_id: Some(account_id),
            channel_identity_id: Some(channel_identity_id),
            source,
        }
    }

    /// Creates an authenticated administrator actor.
    #[must_use]
    pub const fn administrator(
        account_id: AccountId,
        channel_identity_id: Option<ChannelIdentityId>,
        source: AuditSource,
    ) -> Self {
        Self {
            actor_type: AuditActorType::Administrator,
            account_id: Some(account_id),
            channel_identity_id,
            source,
        }
    }

    fn validate(self) -> Result<(), PersistenceError> {
        let valid = match self.actor_type {
            AuditActorType::System => self.source == AuditSource::System,
            AuditActorType::Account | AuditActorType::Administrator => {
                self.source != AuditSource::System
                    && self.account_id.is_some()
                    && (self.source != AuditSource::WhatsApp || self.channel_identity_id.is_some())
            }
        };
        if !valid {
            return Err(PersistenceError::InvalidCommand(
                "audit actor and source are inconsistent".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Input for one append-only administrative or security audit event.
#[derive(Clone)]
pub struct NewAuditEvent {
    /// Application-generated event identifier.
    pub id: AuditEventId,
    /// Trusted actor context.
    pub actor: AuditActor,
    /// Stable machine-readable action code.
    pub action: String,
    /// Stable target category.
    pub target_type: String,
    /// Target identifier when the target has one.
    pub target_id: Option<uuid::Uuid>,
    /// Required machine-readable reason.
    pub reason_code: String,
    /// Optional SHA-256 digest of state before the action.
    pub before_digest: Option<[u8; 32]>,
    /// Optional SHA-256 digest of state after the action.
    pub after_digest: Option<[u8; 32]>,
    /// Bounded non-sensitive structured facts.
    pub metadata: Value,
    /// Version of this event contract.
    pub event_schema_version: i16,
    /// Request or workflow correlation identifier.
    pub correlation_id: CorrelationId,
}

impl NewAuditEvent {
    fn validate(&self) -> Result<(), PersistenceError> {
        self.actor.validate()?;
        validate_code("audit action", &self.action, 128)?;
        validate_code("audit target type", &self.target_type, 128)?;
        validate_code("audit reason", &self.reason_code, 128)?;
        if self.event_schema_version <= 0 {
            return Err(PersistenceError::InvalidCommand(
                "audit event schema version must be positive".to_owned(),
            ));
        }
        if !self.metadata.is_object() {
            return Err(PersistenceError::InvalidCommand(
                "audit metadata must be a JSON object".to_owned(),
            ));
        }
        let metadata_size = serde_json::to_vec(&self.metadata)
            .map_err(|error| PersistenceError::InvalidCommand(error.to_string()))?
            .len();
        if metadata_size > 32_768 {
            return Err(PersistenceError::InvalidCommand(
                "audit metadata exceeds 32768 bytes".to_owned(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for NewAuditEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewAuditEvent")
            .field("id", &self.id)
            .field("actor", &self.actor)
            .field("action", &self.action)
            .field("target_type", &self.target_type)
            .field("target_id", &self.target_id)
            .field("reason_code", &self.reason_code)
            .field("before_digest", &self.before_digest.map(|_| "[REDACTED]"))
            .field("after_digest", &self.after_digest.map(|_| "[REDACTED]"))
            .field("metadata", &"[REDACTED]")
            .field("event_schema_version", &self.event_schema_version)
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}

/// Append-only PostgreSQL audit operations.
#[derive(Clone, Debug)]
pub struct AuditRepository {
    database: Database,
}

impl AuditRepository {
    /// Creates an audit repository over the shared process pool.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Appends one immutable audit event.
    pub async fn append(&self, event: &NewAuditEvent) -> Result<AuditEventId, PersistenceError> {
        event.validate()?;
        let id = sqlx::query_scalar::<_, uuid::Uuid>(
            r#"
            INSERT INTO audit.events (
                id,
                actor_type,
                actor_account_id,
                actor_channel_identity_id,
                source_channel,
                action,
                target_type,
                target_id,
                reason_code,
                before_digest,
                after_digest,
                metadata,
                event_schema_version,
                correlation_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING id
            "#,
        )
        .bind(event.id.into_uuid())
        .bind(event.actor.actor_type.as_str())
        .bind(event.actor.account_id.map(AccountId::into_uuid))
        .bind(
            event
                .actor
                .channel_identity_id
                .map(ChannelIdentityId::into_uuid),
        )
        .bind(event.actor.source.as_str())
        .bind(&event.action)
        .bind(&event.target_type)
        .bind(event.target_id)
        .bind(&event.reason_code)
        .bind(event.before_digest.as_ref().map(<[u8; 32]>::as_slice))
        .bind(event.after_digest.as_ref().map(<[u8; 32]>::as_slice))
        .bind(&event.metadata)
        .bind(event.event_schema_version)
        .bind(event.correlation_id.into_uuid())
        .fetch_one(self.database.pool())
        .await?;
        Ok(AuditEventId::from_uuid(id))
    }
}

fn validate_code(name: &str, value: &str, maximum: usize) -> Result<(), PersistenceError> {
    let mut bytes = value.bytes();
    let valid_first = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
    let valid_rest = bytes.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
    });
    if !valid_first || !valid_rest || value.len() > maximum {
        return Err(PersistenceError::InvalidCommand(format!(
            "{name} is not a valid bounded code"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AuditActor, AuditSource, NewAuditEvent};
    use sahayak_domain::{AuditEventId, CorrelationId};
    use serde_json::json;

    #[test]
    fn system_actor_is_internally_consistent() {
        assert!(AuditActor::system().validate().is_ok());
    }

    #[test]
    fn audit_metadata_must_be_structured_and_bounded() {
        let event = NewAuditEvent {
            id: AuditEventId::new(),
            actor: AuditActor::system(),
            action: "account.created".to_owned(),
            target_type: "account".to_owned(),
            target_id: None,
            reason_code: "whatsapp_onboarding".to_owned(),
            before_digest: None,
            after_digest: None,
            metadata: json!([]),
            event_schema_version: 1,
            correlation_id: CorrelationId::new(),
        };
        assert!(event.validate().is_err());
    }

    #[test]
    fn administrator_cannot_use_system_source() {
        let actor =
            AuditActor::administrator(sahayak_domain::AccountId::new(), None, AuditSource::System);
        assert!(actor.validate().is_err());
    }
}
