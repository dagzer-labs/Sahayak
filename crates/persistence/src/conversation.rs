use crate::{Database, PersistenceError};
use sahayak_domain::{
    AccountId, AccountRole, ChannelIdentityId, ConversationSessionId, ConversationStatus,
    CorrelationId, InboundEventId, OutboundMessageId,
};
use serde_json::Value;
use sqlx::FromRow;
use std::{fmt, str::FromStr};
use time::OffsetDateTime;
use uuid::Uuid;

/// Input required to start one channel-independent conversation workflow.
#[derive(Clone)]
pub struct NewConversationSession {
    /// New internal session identifier.
    pub id: ConversationSessionId,
    /// Account participating in the workflow.
    pub account_id: AccountId,
    /// Channel identity carrying messages for the account.
    pub channel_identity_id: ChannelIdentityId,
    /// Role in which the account entered this workflow.
    pub role_context: AccountRole,
    /// Stable workflow code.
    pub workflow_key: String,
    /// Version of the workflow definition.
    pub workflow_version: i16,
    /// Initial state within the workflow.
    pub state_key: String,
    /// Non-sensitive, versioned state values.
    pub state_data: Value,
    /// BCP-47 interaction language.
    pub language: String,
    /// Database timestamp after which the session may be expired.
    pub expires_at: OffsetDateTime,
    /// Last inbound event incorporated into this state, if one exists.
    pub last_inbound_event_id: Option<InboundEventId>,
    /// Correlation identifier retained through workflow replacement.
    pub workflow_correlation_id: CorrelationId,
    /// Internal prompt that may accept the next interactive reply.
    pub expected_reply_to_outbound_message_id: Option<OutboundMessageId>,
}

impl NewConversationSession {
    fn validate(&self) -> Result<(), PersistenceError> {
        validate_code("workflow_key", &self.workflow_key, 64)?;
        validate_code("state_key", &self.state_key, 64)?;
        if self.workflow_version <= 0 {
            return Err(PersistenceError::InvalidCommand(
                "workflow version must be positive".to_owned(),
            ));
        }
        if !workflow_role_matches(&self.workflow_key, self.role_context) {
            return Err(PersistenceError::InvalidCommand(
                "conversation workflow and role context do not match".to_owned(),
            ));
        }
        validate_state_data(&self.state_data)?;
        if !(2..=35).contains(&self.language.len()) {
            return Err(PersistenceError::InvalidCommand(
                "conversation language must contain between 2 and 35 bytes".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Current persisted conversation state.
#[derive(Clone)]
pub struct ConversationSession {
    /// Internal session identifier.
    pub id: ConversationSessionId,
    /// Account participating in the workflow.
    pub account_id: AccountId,
    /// Channel identity carrying the workflow.
    pub channel_identity_id: ChannelIdentityId,
    /// Role context captured when the workflow started.
    pub role_context: AccountRole,
    /// Stable workflow code.
    pub workflow_key: String,
    /// Workflow definition version.
    pub workflow_version: i16,
    /// Current workflow state code.
    pub state_key: String,
    /// Non-sensitive workflow state.
    pub state_data: Value,
    /// Interaction language.
    pub language: String,
    /// Current session lifecycle.
    pub status: ConversationStatus,
    /// Optimistic concurrency revision.
    pub version: i64,
    /// Session expiry.
    pub expires_at: OffsetDateTime,
    /// Last activity according to PostgreSQL.
    pub last_activity_at: OffsetDateTime,
    /// Last incorporated inbound event.
    pub last_inbound_event_id: Option<InboundEventId>,
    /// Workflow-level correlation identifier.
    pub workflow_correlation_id: CorrelationId,
    /// Internal prompt expected by the next interactive reply.
    pub expected_reply_to_outbound_message_id: Option<OutboundMessageId>,
}

impl fmt::Debug for ConversationSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConversationSession")
            .field("id", &self.id)
            .field("account_id", &self.account_id)
            .field("channel_identity_id", &self.channel_identity_id)
            .field("role_context", &self.role_context)
            .field("workflow_key", &self.workflow_key)
            .field("workflow_version", &self.workflow_version)
            .field("state_key", &self.state_key)
            .field("state_data", &"[REDACTED]")
            .field("language", &self.language)
            .field("status", &self.status)
            .field("version", &self.version)
            .field("expires_at", &self.expires_at)
            .field("last_activity_at", &self.last_activity_at)
            .field("last_inbound_event_id", &self.last_inbound_event_id)
            .field("workflow_correlation_id", &self.workflow_correlation_id)
            .field(
                "expected_reply_to_outbound_message_id",
                &self.expected_reply_to_outbound_message_id,
            )
            .finish()
    }
}

/// Result of an optimistic session mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionMutation {
    /// The mutation applied and produced this new revision.
    Applied { version: i64 },
    /// The session was absent, terminal, or changed concurrently.
    ConflictOrMissing,
}

#[derive(FromRow)]
struct SessionRow {
    id: Uuid,
    account_id: Uuid,
    channel_identity_id: Uuid,
    role_context: String,
    workflow_key: String,
    workflow_version: i16,
    state_key: String,
    state_data: Value,
    language: String,
    status: String,
    version: i64,
    expires_at: OffsetDateTime,
    last_activity_at: OffsetDateTime,
    last_inbound_event_id: Option<Uuid>,
    workflow_correlation_id: Uuid,
    expected_reply_to_outbound_message_id: Option<Uuid>,
}

/// Concrete PostgreSQL conversation-session operations.
#[derive(Clone, Debug)]
pub struct ConversationRepository {
    database: Database,
}

impl ConversationRepository {
    /// Creates a conversation repository over the shared process pool.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Starts a session, relying on the partial unique index to reject a second active session.
    pub async fn start(
        &self,
        input: &NewConversationSession,
    ) -> Result<ConversationSession, PersistenceError> {
        input.validate()?;
        let mut transaction = self.database.pool().begin().await?;
        let role_active: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM identity.accounts AS account
                JOIN identity.account_roles AS role
                  ON role.account_id = account.id
                 AND role.role = $3
                 AND role.revoked_at IS NULL
                JOIN identity.channel_identities AS channel
                  ON channel.id = $2 AND channel.account_id = account.id
                 AND channel.status = 'active'
                WHERE account.id = $1
                  AND account.status IN ('pending', 'active')
                  AND account.risk_state NOT IN ('restricted', 'blocked')
                  AND (
                      $3 <> 'administrator'
                      OR EXISTS (
                          SELECT 1
                          FROM identity.administrator_allowlist AS allowlist
                          WHERE allowlist.account_id = account.id
                            AND allowlist.channel_identity_id = channel.id
                            AND allowlist.channel_code = channel.provider_code
                            AND allowlist.provider_namespace = channel.provider_namespace
                            AND allowlist.revoked_at IS NULL
                            AND allowlist.expires_at > statement_timestamp()
                      )
                  )
            )
            "#,
        )
        .bind(input.account_id.into_uuid())
        .bind(input.channel_identity_id.into_uuid())
        .bind(input.role_context.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        if !role_active {
            transaction.rollback().await?;
            return Err(PersistenceError::InvalidCommand(
                "conversation role is not active for this channel".to_owned(),
            ));
        }
        sqlx::query(
            r#"
            UPDATE messaging.conversation_sessions
            SET
                status = 'expired',
                state_data = '{}'::jsonb,
                expected_reply_to_outbound_message_id = NULL,
                last_inbound_event_id = NULL,
                ended_at = statement_timestamp(),
                terminal_reason = 'timeout'
            WHERE channel_identity_id = $1
              AND status = 'active'
              AND expires_at <= statement_timestamp()
            "#,
        )
        .bind(input.channel_identity_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            INSERT INTO messaging.conversation_sessions (
                id,
                account_id,
                channel_identity_id,
                role_context,
                workflow_key,
                workflow_version,
                state_key,
                state_data,
                language,
                expires_at,
                last_inbound_event_id,
                workflow_correlation_id,
                expected_reply_to_outbound_message_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING
                id,
                account_id,
                channel_identity_id,
                role_context,
                workflow_key,
                workflow_version,
                state_key,
                state_data,
                language,
                status,
                version,
                expires_at,
                last_activity_at,
                last_inbound_event_id,
                workflow_correlation_id,
                expected_reply_to_outbound_message_id
            "#,
        )
        .bind(input.id.into_uuid())
        .bind(input.account_id.into_uuid())
        .bind(input.channel_identity_id.into_uuid())
        .bind(input.role_context.as_str())
        .bind(&input.workflow_key)
        .bind(input.workflow_version)
        .bind(&input.state_key)
        .bind(&input.state_data)
        .bind(&input.language)
        .bind(input.expires_at)
        .bind(input.last_inbound_event_id.map(InboundEventId::into_uuid))
        .bind(input.workflow_correlation_id.into_uuid())
        .bind(
            input
                .expected_reply_to_outbound_message_id
                .map(OutboundMessageId::into_uuid),
        )
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        map_session(row)
    }

    /// Loads the active session for one channel identity.
    pub async fn find_active(
        &self,
        channel_identity_id: ChannelIdentityId,
    ) -> Result<Option<ConversationSession>, PersistenceError> {
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT
                id,
                account_id,
                channel_identity_id,
                role_context,
                workflow_key,
                workflow_version,
                state_key,
                state_data,
                language,
                status,
                version,
                expires_at,
                last_activity_at,
                last_inbound_event_id,
                workflow_correlation_id,
                expected_reply_to_outbound_message_id
            FROM messaging.conversation_sessions
            WHERE channel_identity_id = $1
              AND status = 'active'
              AND expires_at > statement_timestamp()
            "#,
        )
        .bind(channel_identity_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        row.map(map_session).transpose()
    }

    /// Advances active state only when the caller holds the expected revision.
    #[allow(clippy::too_many_arguments)]
    pub async fn compare_and_set_state(
        &self,
        id: ConversationSessionId,
        expected_version: i64,
        state_key: &str,
        state_data: &Value,
        expires_at: OffsetDateTime,
        last_inbound_event_id: Option<InboundEventId>,
        expected_reply_to_outbound_message_id: Option<OutboundMessageId>,
        next_reply_to_outbound_message_id: Option<OutboundMessageId>,
    ) -> Result<SessionMutation, PersistenceError> {
        validate_code("state_key", state_key, 64)?;
        validate_state_data(state_data)?;
        let version = sqlx::query_scalar::<_, i64>(
            r#"
            UPDATE messaging.conversation_sessions
            SET
                state_key = $3,
                state_data = $4,
                expires_at = $5,
                last_activity_at = statement_timestamp(),
                last_inbound_event_id = $6,
                expected_reply_to_outbound_message_id = $8
            WHERE id = $1
              AND version = $2
              AND status = 'active'
              AND expires_at > statement_timestamp()
              AND expected_reply_to_outbound_message_id IS NOT DISTINCT FROM $7
            RETURNING version
            "#,
        )
        .bind(id.into_uuid())
        .bind(expected_version)
        .bind(state_key)
        .bind(state_data)
        .bind(expires_at)
        .bind(last_inbound_event_id.map(InboundEventId::into_uuid))
        .bind(expected_reply_to_outbound_message_id.map(OutboundMessageId::into_uuid))
        .bind(next_reply_to_outbound_message_id.map(OutboundMessageId::into_uuid))
        .fetch_optional(self.database.pool())
        .await?;
        Ok(
            version.map_or(SessionMutation::ConflictOrMissing, |version| {
                SessionMutation::Applied { version }
            }),
        )
    }

    /// Completes an active session under optimistic concurrency control.
    pub async fn complete(
        &self,
        id: ConversationSessionId,
        expected_version: i64,
    ) -> Result<SessionMutation, PersistenceError> {
        let version = sqlx::query_scalar::<_, i64>(
            r#"
            UPDATE messaging.conversation_sessions
            SET
                status = 'completed',
                state_data = '{}'::jsonb,
                expected_reply_to_outbound_message_id = NULL,
                ended_at = statement_timestamp(),
                terminal_reason = 'completed',
                last_activity_at = statement_timestamp()
            WHERE id = $1
              AND version = $2
              AND status = 'active'
              AND expires_at > statement_timestamp()
            RETURNING version
            "#,
        )
        .bind(id.into_uuid())
        .bind(expected_version)
        .fetch_optional(self.database.pool())
        .await?;
        Ok(
            version.map_or(SessionMutation::ConflictOrMissing, |version| {
                SessionMutation::Applied { version }
            }),
        )
    }

    /// Expires due active sessions in bounded batches.
    pub async fn expire_due(&self, limit: u16) -> Result<u64, PersistenceError> {
        if !(1..=1_000).contains(&limit) {
            return Err(PersistenceError::InvalidCommand(
                "session expiration limit must be between 1 and 1000".to_owned(),
            ));
        }
        let result = sqlx::query(
            r#"
            WITH due AS (
                SELECT id
                FROM messaging.conversation_sessions
                WHERE status = 'active'
                  AND expires_at <= statement_timestamp()
                ORDER BY expires_at, id
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE messaging.conversation_sessions AS session
            SET
                status = 'expired',
                state_data = '{}'::jsonb,
                expected_reply_to_outbound_message_id = NULL,
                last_inbound_event_id = NULL,
                ended_at = statement_timestamp(),
                terminal_reason = 'timeout'
            FROM due
            WHERE session.id = due.id
            "#,
        )
        .bind(i64::from(limit))
        .execute(self.database.pool())
        .await?;
        Ok(result.rows_affected())
    }
}

fn map_session(row: SessionRow) -> Result<ConversationSession, PersistenceError> {
    Ok(ConversationSession {
        id: ConversationSessionId::from_uuid(row.id),
        account_id: AccountId::from_uuid(row.account_id),
        channel_identity_id: ChannelIdentityId::from_uuid(row.channel_identity_id),
        role_context: AccountRole::from_str(&row.role_context).map_err(|error| {
            PersistenceError::Invariant(format!("conversation contains invalid role: {error}"))
        })?,
        workflow_key: row.workflow_key,
        workflow_version: row.workflow_version,
        state_key: row.state_key,
        state_data: row.state_data,
        language: row.language,
        status: ConversationStatus::from_str(&row.status).map_err(|error| {
            PersistenceError::Invariant(format!("conversation contains invalid status: {error}"))
        })?,
        version: row.version,
        expires_at: row.expires_at,
        last_activity_at: row.last_activity_at,
        last_inbound_event_id: row.last_inbound_event_id.map(InboundEventId::from_uuid),
        workflow_correlation_id: CorrelationId::from_uuid(row.workflow_correlation_id),
        expected_reply_to_outbound_message_id: row
            .expected_reply_to_outbound_message_id
            .map(OutboundMessageId::from_uuid),
    })
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

fn workflow_role_matches(workflow_key: &str, role: AccountRole) -> bool {
    match workflow_key {
        "professional.profile" | "professional.availability" | "professional.requests" => {
            role == AccountRole::Professional
        }
        "administrator.review" | "administrator.safety" => role == AccountRole::Administrator,
        "trust.safety" => matches!(role, AccountRole::Customer | AccountRole::Professional),
        _ => role == AccountRole::Customer,
    }
}

fn validate_state_data(value: &Value) -> Result<(), PersistenceError> {
    if !value.is_object() {
        return Err(PersistenceError::InvalidCommand(
            "conversation state data must be a JSON object".to_owned(),
        ));
    }
    let size = serde_json::to_vec(value)
        .map_err(|error| PersistenceError::InvalidCommand(error.to_string()))?
        .len();
    if size > 65_536 {
        return Err(PersistenceError::InvalidCommand(
            "conversation state data exceeds 65536 bytes".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_code, validate_state_data};
    use serde_json::json;

    #[test]
    fn rejects_unversioned_or_unbounded_state_data() {
        assert!(validate_state_data(&json!([])).is_err());
        assert!(validate_state_data(&json!({"selection": "plumber"})).is_ok());
    }

    #[test]
    fn workflow_codes_are_machine_safe() {
        assert!(validate_code("workflow", "customer.discovery-v1", 64).is_ok());
        assert!(validate_code("workflow", "Customer Discovery", 64).is_err());
    }
}
