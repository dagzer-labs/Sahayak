use crate::{Database, PersistenceError};
use sahayak_domain::{
    AccountId, AdministratorGrantId, AuditEventId, ChannelIdentityId, CorrelationId,
};
use time::OffsetDateTime;
use uuid::Uuid;

/// Transactional channel-bound administrator grant command.
#[derive(Clone, Debug)]
pub struct GrantAdministratorAccess {
    pub id: AdministratorGrantId,
    pub account_id: AccountId,
    pub channel_identity_id: ChannelIdentityId,
    pub granted_by_account_id: Option<AccountId>,
    pub expires_at: OffsetDateTime,
    pub idempotency_key: String,
    pub correlation_id: CorrelationId,
}

/// Transactional grant revocation command.
#[derive(Clone, Debug)]
pub struct RevokeAdministratorAccess {
    pub grant_id: AdministratorGrantId,
    pub revoked_by_account_id: Option<AccountId>,
    pub idempotency_key: String,
    pub correlation_id: CorrelationId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdministratorGrantOutcome {
    Applied,
    AlreadyApplied,
    Ineligible,
    Missing,
}

/// Audited administrator allowlist operations. The administrator role remains a
/// separate prerequisite and is never implied by an allowlist row.
#[derive(Clone, Debug)]
pub struct AdministratorAllowlistRepository {
    database: Database,
}

impl AdministratorAllowlistRepository {
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    pub async fn grant(
        &self,
        input: &GrantAdministratorAccess,
    ) -> Result<AdministratorGrantOutcome, PersistenceError> {
        validate_idempotency(&input.idempotency_key)?;
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "admin:{}:{}",
                input.account_id, input.channel_identity_id
            ))
            .execute(&mut *transaction)
            .await?;
        if let Some(existing) = sqlx::query_as::<_, (Uuid, Uuid, Uuid, OffsetDateTime)>(
            r#"
            SELECT id, account_id, channel_identity_id, expires_at
            FROM identity.administrator_allowlist
            WHERE grant_idempotency_key = $1
            "#,
        )
        .bind(&input.idempotency_key)
        .fetch_optional(&mut *transaction)
        .await?
        {
            transaction.rollback().await?;
            if existing.0 == input.id.into_uuid()
                && existing.1 == input.account_id.into_uuid()
                && existing.2 == input.channel_identity_id.into_uuid()
                && same_postgres_timestamp(existing.3, input.expires_at)
            {
                return Ok(AdministratorGrantOutcome::AlreadyApplied);
            }
            return Err(PersistenceError::InvalidCommand(
                "administrator grant idempotency key was reused".to_owned(),
            ));
        }
        let channel: Option<(String, String)> = sqlx::query_as(
            r#"
            SELECT channel.provider_code, channel.provider_namespace
            FROM identity.accounts AS account
            JOIN identity.account_roles AS role
              ON role.account_id = account.id
             AND role.role = 'administrator'
             AND role.revoked_at IS NULL
            JOIN identity.channel_identities AS channel
              ON channel.id = $2
             AND channel.account_id = account.id
             AND channel.status = 'active'
             AND channel.verified_at IS NOT NULL
            WHERE account.id = $1
              AND account.status = 'active'
               AND account.risk_state NOT IN ('restricted', 'blocked')
              AND $3 > statement_timestamp()
              AND $3 <= statement_timestamp() + INTERVAL '366 days'
            FOR SHARE OF account, role, channel
            "#,
        )
        .bind(input.account_id.into_uuid())
        .bind(input.channel_identity_id.into_uuid())
        .bind(input.expires_at)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((channel_code, provider_namespace)) = channel else {
            transaction.rollback().await?;
            return Ok(AdministratorGrantOutcome::Ineligible);
        };
        let already_active: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM identity.administrator_allowlist
                WHERE account_id = $1 AND channel_identity_id = $2
                  AND revoked_at IS NULL AND expires_at > statement_timestamp()
            )
            "#,
        )
        .bind(input.account_id.into_uuid())
        .bind(input.channel_identity_id.into_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        if already_active {
            transaction.rollback().await?;
            return Ok(AdministratorGrantOutcome::AlreadyApplied);
        }
        let audit_id = AuditEventId::new();
        append_allowlist_audit(
            &mut transaction,
            audit_id,
            input.granted_by_account_id,
            "administrator.allowlist_granted",
            input.id,
            "authorized_grant",
            input.correlation_id,
        )
        .await?;
        sqlx::query(
            r#"
            INSERT INTO identity.administrator_allowlist (
                id, account_id, channel_identity_id, channel_code,
                provider_namespace, granted_by_account_id, grant_audit_event_id,
                grant_idempotency_key, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(input.id.into_uuid())
        .bind(input.account_id.into_uuid())
        .bind(input.channel_identity_id.into_uuid())
        .bind(channel_code)
        .bind(provider_namespace)
        .bind(input.granted_by_account_id.map(AccountId::into_uuid))
        .bind(audit_id.into_uuid())
        .bind(&input.idempotency_key)
        .bind(input.expires_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(AdministratorGrantOutcome::Applied)
    }

    pub async fn revoke(
        &self,
        input: &RevokeAdministratorAccess,
    ) -> Result<AdministratorGrantOutcome, PersistenceError> {
        validate_idempotency(&input.idempotency_key)?;
        let mut transaction = self.database.pool().begin().await?;
        let grant: Option<(Option<OffsetDateTime>, Option<String>)> = sqlx::query_as(
            r#"
            SELECT revoked_at, revocation_idempotency_key
            FROM identity.administrator_allowlist
            WHERE id = $1
            FOR UPDATE
            "#,
        )
        .bind(input.grant_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((revoked_at, prior_key)) = grant else {
            transaction.rollback().await?;
            return Ok(AdministratorGrantOutcome::Missing);
        };
        if revoked_at.is_some() {
            transaction.rollback().await?;
            if prior_key.as_deref() == Some(input.idempotency_key.as_str()) {
                return Ok(AdministratorGrantOutcome::AlreadyApplied);
            }
            return Ok(AdministratorGrantOutcome::AlreadyApplied);
        }
        let audit_id = AuditEventId::new();
        append_allowlist_audit(
            &mut transaction,
            audit_id,
            input.revoked_by_account_id,
            "administrator.allowlist_revoked",
            input.grant_id,
            "authorized_revocation",
            input.correlation_id,
        )
        .await?;
        sqlx::query(
            r#"
            UPDATE identity.administrator_allowlist
            SET
                revoked_at = statement_timestamp(),
                revoked_by_account_id = $2,
                revocation_audit_event_id = $3,
                revocation_idempotency_key = $4
            WHERE id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(input.grant_id.into_uuid())
        .bind(input.revoked_by_account_id.map(AccountId::into_uuid))
        .bind(audit_id.into_uuid())
        .bind(&input.idempotency_key)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(AdministratorGrantOutcome::Applied)
    }
}

async fn append_allowlist_audit(
    connection: &mut sqlx::PgConnection,
    audit_id: AuditEventId,
    actor: Option<AccountId>,
    action: &str,
    grant_id: AdministratorGrantId,
    reason: &str,
    correlation_id: CorrelationId,
) -> Result<(), PersistenceError> {
    let (actor_type, source) = if actor.is_some() {
        ("administrator", "internal_cli")
    } else {
        ("system", "system")
    };
    sqlx::query(
        r#"
        INSERT INTO audit.events (
            id, actor_type, actor_account_id, source_channel,
            action, target_type, target_id, reason_code,
            metadata, event_schema_version, correlation_id
        )
        VALUES ($1, $2, $3, $4, $5, 'administrator_allowlist', $6, $7, '{}'::jsonb, 1, $8)
        "#,
    )
    .bind(audit_id.into_uuid())
    .bind(actor_type)
    .bind(actor.map(AccountId::into_uuid))
    .bind(source)
    .bind(action)
    .bind(grant_id.into_uuid())
    .bind(reason)
    .bind(correlation_id.into_uuid())
    .execute(connection)
    .await?;
    Ok(())
}

fn validate_idempotency(value: &str) -> Result<(), PersistenceError> {
    if value.is_empty() || value.len() > 255 || value.trim() != value {
        return Err(PersistenceError::InvalidCommand(
            "administrator idempotency key must contain between 1 and 255 trimmed bytes".to_owned(),
        ));
    }
    Ok(())
}

fn same_postgres_timestamp(left: OffsetDateTime, right: OffsetDateTime) -> bool {
    left.unix_timestamp_nanos() / 1_000 == right.unix_timestamp_nanos() / 1_000
}
