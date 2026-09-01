use crate::{Database, PersistenceError};
use sahayak_domain::{
    AccountId, AccountLifecycle, AccountRole, AuditEventId, CorrelationId, RiskState,
};
use sqlx::FromRow;
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

/// Current non-sensitive account state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountSnapshot {
    /// Internal account identifier.
    pub id: AccountId,
    /// Account lifecycle.
    pub lifecycle: AccountLifecycle,
    /// Current risk treatment.
    pub risk_state: RiskState,
    /// BCP-47 preferred language.
    pub preferred_locale: String,
    /// Time the account explicitly confirmed this locale.
    pub preferred_locale_confirmed_at: Option<OffsetDateTime>,
    /// IANA time-zone name.
    pub time_zone: String,
    /// Optimistic concurrency revision.
    pub version: i64,
    /// Last lifecycle transition time.
    pub state_changed_at: OffsetDateTime,
}

/// Result of a conditional account mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountMutation {
    /// Mutation applied with the returned new revision.
    Applied { version: i64 },
    /// Account was absent or changed concurrently.
    ConflictOrMissing,
    /// Requested lifecycle transition is not permitted.
    InvalidTransition,
}

#[derive(FromRow)]
struct AccountRow {
    id: Uuid,
    status: String,
    risk_state: String,
    preferred_locale: String,
    preferred_locale_confirmed_at: Option<OffsetDateTime>,
    time_zone: String,
    version: i64,
    state_changed_at: OffsetDateTime,
}

/// Concrete PostgreSQL account lifecycle and role operations.
#[derive(Clone, Debug)]
pub struct AccountRepository {
    database: Database,
}

impl AccountRepository {
    /// Creates an account repository over the shared process pool.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Loads current non-sensitive account state.
    pub async fn find(
        &self,
        account_id: AccountId,
    ) -> Result<Option<AccountSnapshot>, PersistenceError> {
        let row = sqlx::query_as::<_, AccountRow>(
            r#"
            SELECT
                id,
                status,
                risk_state,
                preferred_locale,
                preferred_locale_confirmed_at,
                time_zone,
                version,
                state_changed_at
            FROM identity.accounts
            WHERE id = $1
            "#,
        )
        .bind(account_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        row.map(map_account).transpose()
    }

    /// Applies a valid lifecycle transition under optimistic concurrency control.
    pub async fn transition_lifecycle(
        &self,
        account_id: AccountId,
        expected_version: i64,
        next: AccountLifecycle,
        correlation_id: CorrelationId,
    ) -> Result<AccountMutation, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let row = sqlx::query_as::<_, AccountRow>(
            r#"
            SELECT
                id,
                status,
                risk_state,
                preferred_locale,
                preferred_locale_confirmed_at,
                time_zone,
                version,
                state_changed_at
            FROM identity.accounts
            WHERE id = $1
            FOR UPDATE
            "#,
        )
        .bind(account_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(current) = row.map(map_account).transpose()? else {
            transaction.rollback().await?;
            return Ok(AccountMutation::ConflictOrMissing);
        };
        if current.version != expected_version {
            transaction.rollback().await?;
            return Ok(AccountMutation::ConflictOrMissing);
        }
        if !current.lifecycle.can_transition_to(next) {
            transaction.rollback().await?;
            return Ok(AccountMutation::InvalidTransition);
        }

        if next == AccountLifecycle::Deleted {
            erase_account_private_data(&mut transaction, account_id, correlation_id).await?;
        }

        let version = sqlx::query_scalar::<_, i64>(
            r#"
            UPDATE identity.accounts
            SET
                status = $3,
                state_changed_at = statement_timestamp(),
                suspended_at = CASE
                    WHEN $3 = 'suspended' THEN statement_timestamp()
                    ELSE NULL
                END,
                deletion_requested_at = CASE
                    WHEN $3 IN ('deletion_pending', 'deleted')
                        THEN COALESCE(deletion_requested_at, statement_timestamp())
                    ELSE NULL
                END,
                deleted_at = CASE
                    WHEN $3 = 'deleted' THEN statement_timestamp()
                    ELSE NULL
                END
            WHERE id = $1
              AND version = $2
              AND status = $4
            RETURNING version
            "#,
        )
        .bind(account_id.into_uuid())
        .bind(expected_version)
        .bind(next.as_str())
        .bind(current.lifecycle.as_str())
        .fetch_optional(&mut *transaction)
        .await?;
        let outcome = version.map_or(AccountMutation::ConflictOrMissing, |version| {
            AccountMutation::Applied { version }
        });
        if matches!(outcome, AccountMutation::Applied { .. }) {
            if matches!(
                next,
                AccountLifecycle::Suspended | AccountLifecycle::DeletionPending
            ) {
                crate::availability::invalidate_account_epochs(
                    &mut transaction,
                    account_id,
                    if next == AccountLifecycle::Suspended {
                        "account_suspended"
                    } else {
                        "account_deletion"
                    },
                    correlation_id,
                )
                .await?;
            }
            sqlx::query(
                r#"
                INSERT INTO audit.events (
                    id,
                    actor_type,
                    source_channel,
                    action,
                    target_type,
                    target_id,
                    reason_code,
                    metadata,
                    event_schema_version,
                    correlation_id
                )
                VALUES (
                    $1,
                    'system',
                    'system',
                    'account.lifecycle_changed',
                    'account',
                    $2,
                    $3,
                    jsonb_build_object('from', $4::text, 'to', $5::text),
                    1,
                    $6
                )
                "#,
            )
            .bind(AuditEventId::new().into_uuid())
            .bind(account_id.into_uuid())
            .bind(if next == AccountLifecycle::Deleted {
                "account_deletion_completed"
            } else {
                "account_lifecycle_transition"
            })
            .bind(current.lifecycle.as_str())
            .bind(next.as_str())
            .bind(correlation_id.into_uuid())
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Grants or restores a role without creating duplicate role records.
    pub async fn grant_role(
        &self,
        account_id: AccountId,
        role: AccountRole,
        granted_by: Option<AccountId>,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO identity.account_roles (account_id, role, granted_by)
            VALUES ($1, $2, $3)
            ON CONFLICT (account_id, role)
            DO UPDATE SET
                granted_at = statement_timestamp(),
                granted_by = EXCLUDED.granted_by,
                revoked_at = NULL
            "#,
        )
        .bind(account_id.into_uuid())
        .bind(role.as_str())
        .bind(granted_by.map(AccountId::into_uuid))
        .execute(self.database.pool())
        .await?;
        Ok(())
    }

    /// Revokes an active role and reports whether a row changed.
    pub async fn revoke_role(
        &self,
        account_id: AccountId,
        role: AccountRole,
    ) -> Result<bool, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query("SELECT id FROM identity.accounts WHERE id = $1 FOR UPDATE")
            .bind(account_id.into_uuid())
            .execute(&mut *transaction)
            .await?;
        let result = sqlx::query(
            r#"
            UPDATE identity.account_roles
            SET revoked_at = statement_timestamp()
            WHERE account_id = $1
              AND role = $2
              AND revoked_at IS NULL
            "#,
        )
        .bind(account_id.into_uuid())
        .bind(role.as_str())
        .execute(&mut *transaction)
        .await?;
        let changed = result.rows_affected() == 1;
        if changed && role == AccountRole::Professional {
            crate::availability::invalidate_account_epochs(
                &mut transaction,
                account_id,
                "role_revoked",
                CorrelationId::new(),
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(changed)
    }
}

async fn erase_account_private_data(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: AccountId,
    correlation_id: CorrelationId,
) -> Result<(), PersistenceError> {
    sqlx::query("SELECT set_config('sahayak.account_erasure', 'on', true)")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT set_config('sahayak.review_mutation', 'on', true)")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT set_config('sahayak.safety_mutation', 'on', true)")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        r#"
        UPDATE integration.inbound_events
        SET payload_ciphertext = NULL,
            payload_nonce = NULL,
            payload_purged_at = COALESCE(payload_purged_at, statement_timestamp())
        WHERE payload_purged_at IS NULL
          AND (
              account_id = $1
              OR id IN (
                  SELECT delivery.inbound_event_id
                  FROM messaging.outbound_delivery_events AS delivery
                  JOIN messaging.outbound_messages AS message
                    ON message.id = delivery.outbound_message_id
                  JOIN identity.channel_identities AS channel
                    ON channel.id = message.recipient_channel_identity_id
                  WHERE channel.account_id = $1
              )
          )
        "#,
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        UPDATE review.review_revisions AS revision
        SET encrypted_feedback = NULL, feedback_nonce = NULL, encryption_key_version = NULL
        FROM review.reviews AS root
        WHERE revision.review_id = root.id
          AND (root.reviewer_account_id = $1 OR root.subject_account_id = $1)
          AND revision.encrypted_feedback IS NOT NULL
        "#,
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        UPDATE safety.reports
        SET encrypted_description = NULL, description_nonce = NULL, encryption_key_version = NULL
        WHERE reporter_account_id = $1 AND encrypted_description IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM operations.legal_holds
              WHERE account_id = $1 AND ends_at IS NULL
          )
        "#,
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE billing.subscriptions SET hosted_payment_url = NULL WHERE professional_account_id = $1",
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        UPDATE messaging.outbound_messages AS message
        SET payload_ciphertext = NULL,
            payload_nonce = NULL,
            payload_purged_at = COALESCE(payload_purged_at, statement_timestamp()),
            provider_message_id = NULL,
            provider_trace_id = NULL
        WHERE EXISTS (
            SELECT 1 FROM messaging.outbound_message_subjects AS subject
            WHERE subject.outbound_message_id = message.id
              AND subject.account_id = $1
        )
          AND (
              message.payload_purged_at IS NULL
              OR message.provider_message_id IS NOT NULL
              OR message.provider_trace_id IS NOT NULL
          )
        "#,
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        UPDATE messaging.outbound_delivery_events AS delivery
        SET provider_message_id = NULL
        WHERE delivery.provider_message_id IS NOT NULL
          AND delivery.outbound_message_id IN (
              SELECT message.id
              FROM messaging.outbound_messages AS message
              JOIN identity.channel_identities AS channel
                ON channel.id = message.recipient_channel_identity_id
              WHERE channel.account_id = $1
          )
        "#,
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        UPDATE messaging.outbound_messages AS message
        SET payload_ciphertext = NULL,
            payload_nonce = NULL,
            payload_purged_at = COALESCE(payload_purged_at, statement_timestamp()),
            provider_message_id = NULL,
            provider_trace_id = NULL
        FROM identity.channel_identities AS channel
        WHERE channel.id = message.recipient_channel_identity_id
          AND channel.account_id = $1
          AND (
              message.payload_purged_at IS NULL
              OR message.provider_message_id IS NOT NULL
              OR message.provider_trace_id IS NOT NULL
          )
        "#,
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        WITH active_grants AS (
            SELECT id, uuidv7() AS audit_id
            FROM identity.administrator_allowlist
            WHERE account_id = $1 AND revoked_at IS NULL
            FOR UPDATE
        ), inserted_audits AS (
            INSERT INTO audit.events (
                id, actor_type, source_channel, action, target_type,
                target_id, reason_code, metadata, event_schema_version,
                correlation_id
            )
            SELECT
                audit_id, 'system', 'system', 'administrator.allowlist_revoked',
                'administrator_allowlist', id, 'account_deleted', '{}'::jsonb, 1, $2
            FROM active_grants
            RETURNING id, target_id
        )
        UPDATE identity.administrator_allowlist AS allowlist
        SET
            revoked_at = statement_timestamp(),
            revoked_by_account_id = NULL,
            revocation_audit_event_id = audit.id,
            revocation_idempotency_key = 'account-deletion:' || $2::text || ':' || allowlist.id::text
        FROM inserted_audits AS audit
        WHERE allowlist.id = audit.target_id
        "#,
    )
    .bind(account_id.into_uuid())
    .bind(correlation_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        DELETE FROM private_data.identity_verification_callback_receipts
        WHERE attempt_id IN (
            SELECT id FROM private_data.identity_verification_attempts WHERE account_id = $1
        )
        "#,
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query("DELETE FROM private_data.identity_verification_attempts WHERE account_id = $1")
        .bind(account_id.into_uuid())
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM private_data.professional_consent_events WHERE account_id = $1")
        .bind(account_id.into_uuid())
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM private_data.profile_photos WHERE account_id = $1")
        .bind(account_id.into_uuid())
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "DELETE FROM private_data.service_request_locations WHERE customer_account_id = $1",
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        DELETE FROM private_data.channel_lookup_digests
        WHERE channel_identity_id IN (
            SELECT id FROM identity.channel_identities WHERE account_id = $1
        )
        "#,
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        DELETE FROM private_data.whatsapp_identities
        WHERE channel_identity_id IN (
            SELECT id FROM identity.channel_identities WHERE account_id = $1
        )
        "#,
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query("DELETE FROM private_data.account_identities WHERE account_id = $1")
        .bind(account_id.into_uuid())
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        r#"
        UPDATE profile.public_profiles
        SET
            visibility = 'deleted',
            published_revision_id = NULL,
            hidden_at = statement_timestamp()
        WHERE account_id = $1
        "#,
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query("DELETE FROM profile.public_profiles WHERE account_id = $1")
        .bind(account_id.into_uuid())
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        r#"
        UPDATE messaging.conversation_sessions
        SET
            status = CASE WHEN status = 'active' THEN 'abandoned' ELSE status END,
            state_data = '{}'::jsonb,
            expected_reply_to_outbound_message_id = NULL,
            last_inbound_event_id = NULL,
            ended_at = CASE
                WHEN status = 'active' THEN statement_timestamp()
                ELSE ended_at
            END,
            terminal_reason = CASE
                WHEN status = 'active' THEN 'account_deleted'
                ELSE terminal_reason
            END
        WHERE account_id = $1
        "#,
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r#"
        UPDATE identity.channel_identities
        SET
            status = 'revoked',
            disabled_at = statement_timestamp()
        WHERE account_id = $1
          AND status <> 'revoked'
        "#,
    )
    .bind(account_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn map_account(row: AccountRow) -> Result<AccountSnapshot, PersistenceError> {
    Ok(AccountSnapshot {
        id: AccountId::from_uuid(row.id),
        lifecycle: AccountLifecycle::from_str(&row.status).map_err(|error| {
            PersistenceError::Invariant(format!("account contains invalid lifecycle: {error}"))
        })?,
        risk_state: RiskState::from_str(&row.risk_state).map_err(|error| {
            PersistenceError::Invariant(format!("account contains invalid risk state: {error}"))
        })?,
        preferred_locale: row.preferred_locale,
        preferred_locale_confirmed_at: row.preferred_locale_confirmed_at,
        time_zone: row.time_zone,
        version: row.version,
        state_changed_at: row.state_changed_at,
    })
}

#[cfg(test)]
mod tests {
    use sahayak_domain::AccountLifecycle;

    #[test]
    fn lifecycle_rules_prevent_reactivating_deleted_accounts() {
        assert!(AccountLifecycle::Pending.can_transition_to(AccountLifecycle::Active));
        assert!(!AccountLifecycle::Deleted.can_transition_to(AccountLifecycle::Active));
    }
}
