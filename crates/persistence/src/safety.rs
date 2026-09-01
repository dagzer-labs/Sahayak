use crate::{
    Database, PersistenceError, key_registry::ensure_active_encryption_key,
    review::insert_account_audit,
};
use sahayak_cryptography::{
    CryptoService, EncryptionContext, EncryptionNamespace, EncryptionPurpose,
};
use sahayak_domain::{
    AccountBlockId, AccountId, AuditEventId, ChannelIdentityId, ContactRevealId, CorrelationId,
    ReportId, SafetyRestrictionId,
};
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct AdministratorReportItem {
    pub report_token: Uuid,
    pub version: i64,
    pub category: String,
    pub severity: String,
    pub created_at: OffsetDateTime,
    pub subject: crate::ContactTarget,
    pub reporter: crate::ContactTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportCategory {
    Spam,
    Harassment,
    Fraud,
    UnsafeBehavior,
    IdentityMisrepresentation,
    NoShow,
    Other,
}

impl ReportCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Spam => "spam",
            Self::Harassment => "harassment",
            Self::Fraud => "fraud",
            Self::UnsafeBehavior => "unsafe_behavior",
            Self::IdentityMisrepresentation => "identity_misrepresentation",
            Self::NoShow => "no_show",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReportSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl ReportSeverity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    const fn response_window(self) -> Duration {
        match self {
            Self::Critical => Duration::hours(1),
            Self::High => Duration::hours(4),
            Self::Medium => Duration::hours(24),
            Self::Low => Duration::hours(72),
        }
    }
}

pub struct SubmitReport<'a> {
    pub report_id: ReportId,
    pub report_token: Uuid,
    pub reveal_id: ContactRevealId,
    pub reporter_account_id: AccountId,
    pub reporter_channel_identity_id: ChannelIdentityId,
    pub subject_account_id: AccountId,
    pub category: ReportCategory,
    pub severity: ReportSeverity,
    pub description: Option<&'a str>,
    pub evidence_references: Value,
    pub block_subject: bool,
    pub source_inbound_event_id: Option<Uuid>,
    pub correlation_id: CorrelationId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafetyMutation {
    Applied { version: i64 },
    ConflictOrIneligible,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectReportStatus {
    pub report_token: Uuid,
    pub category: String,
    pub severity: String,
    pub triage_state: String,
    pub action_state: String,
    pub resolution_code: Option<String>,
    pub resolution_summary: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModerationAction {
    NoAction,
    Warning,
    TemporarySuspension,
    PermanentRemoval,
}

impl ModerationAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NoAction => "no_action",
            Self::Warning => "warning",
            Self::TemporarySuspension => "temporary_suspension",
            Self::PermanentRemoval => "permanent_removal",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SafetyRepository {
    database: Database,
    cryptography: CryptoService,
}

impl SafetyRepository {
    #[must_use]
    pub const fn new(database: Database, cryptography: CryptoService) -> Self {
        Self {
            database,
            cryptography,
        }
    }

    pub async fn submit_report(
        &self,
        command: SubmitReport<'_>,
    ) -> Result<SafetyMutation, PersistenceError> {
        validate_description(command.description)?;
        if !command.evidence_references.is_array()
            || command
                .evidence_references
                .as_array()
                .is_some_and(|items| items.len() > 10)
        {
            return Err(PersistenceError::InvalidCommand(
                "report evidence must be an array of at most ten references".to_owned(),
            ));
        }
        let encrypted = command
            .description
            .map(|description| {
                self.cryptography.encrypt(
                    EncryptionPurpose::Integration,
                    EncryptionContext::new(
                        EncryptionNamespace::SAFETY_REPORT_DESCRIPTION,
                        command.report_id.into_uuid(),
                    ),
                    description.as_bytes(),
                )
            })
            .transpose()
            .map_err(|error| PersistenceError::InvalidCommand(error.to_string()))?;
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query("SELECT set_config('sahayak.safety_mutation', 'on', true)")
            .execute(&mut *transaction)
            .await?;
        if let Some(value) = encrypted.as_ref() {
            ensure_active_encryption_key(&mut transaction, value.purpose, value.key_version)
                .await?;
        }
        let audit_id = insert_account_audit(
            &mut transaction,
            command.reporter_account_id,
            command.reporter_channel_identity_id,
            "safety.report_submitted",
            "safety_report",
            command.report_id.into_uuid(),
            command.category.as_str(),
            command.correlation_id,
        )
        .await?;
        let inserted = sqlx::query(
            r#"
            INSERT INTO safety.reports (
                id, report_token, reporter_account_id, subject_account_id, reveal_id,
                category, severity, encrypted_description, description_nonce,
                encryption_key_version, evidence_references, response_due_at,
                source_inbound_event_id, audit_event_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                      statement_timestamp() + $12::interval, $13, $14)
            ON CONFLICT (reveal_id, reporter_account_id) DO NOTHING
            "#,
        )
        .bind(command.report_id.into_uuid())
        .bind(command.report_token)
        .bind(command.reporter_account_id.into_uuid())
        .bind(command.subject_account_id.into_uuid())
        .bind(command.reveal_id.into_uuid())
        .bind(command.category.as_str())
        .bind(command.severity.as_str())
        .bind(encrypted.as_ref().map(|value| value.ciphertext.as_slice()))
        .bind(encrypted.as_ref().map(|value| value.nonce.as_slice()))
        .bind(encrypted.as_ref().map(|value| value.key_version))
        .bind(&command.evidence_references)
        .bind(format!(
            "{} seconds",
            command.severity.response_window().whole_seconds()
        ))
        .bind(command.source_inbound_event_id)
        .bind(audit_id)
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(SafetyMutation::ConflictOrIneligible);
        }
        if command.block_subject {
            let block_audit = insert_account_audit(
                &mut transaction,
                command.reporter_account_id,
                command.reporter_channel_identity_id,
                "account.blocked",
                "account",
                command.subject_account_id.into_uuid(),
                "safety_report",
                command.correlation_id,
            )
            .await?;
            sqlx::query("SELECT set_config('sahayak.connection_mutation', 'on', true)")
                .execute(&mut *transaction)
                .await?;
            sqlx::query(
                r#"
                INSERT INTO identity.account_blocks (
                    id, actor_account_id, blocked_account_id, source_inbound_event_id,
                    audit_event_id, report_id
                ) VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (actor_account_id, blocked_account_id) WHERE removed_at IS NULL
                DO NOTHING
                "#,
            )
            .bind(AccountBlockId::new().into_uuid())
            .bind(command.reporter_account_id.into_uuid())
            .bind(command.subject_account_id.into_uuid())
            .bind(command.source_inbound_event_id)
            .bind(block_audit)
            .bind(command.report_id.into_uuid())
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(SafetyMutation::Applied { version: 1 })
    }

    pub async fn subject_status(
        &self,
        subject: AccountId,
        report_token: Uuid,
    ) -> Result<Option<SubjectReportStatus>, PersistenceError> {
        sqlx::query_as::<
            _,
            (
                Uuid,
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
            ),
        >(
            r#"
            SELECT report_token, category, severity, triage_state, action_state,
                   resolution_code, resolution_summary
            FROM safety.subject_report_status
            WHERE subject_account_id = $1 AND report_token = $2
            "#,
        )
        .bind(subject.into_uuid())
        .bind(report_token)
        .fetch_optional(self.database.pool())
        .await
        .map(|row| {
            row.map(|row| SubjectReportStatus {
                report_token: row.0,
                category: row.1,
                severity: row.2,
                triage_state: row.3,
                action_state: row.4,
                resolution_code: row.5,
                resolution_summary: row.6,
            })
        })
        .map_err(PersistenceError::from)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn resolve_report(
        &self,
        administrator_account_id: AccountId,
        administrator_channel_identity_id: ChannelIdentityId,
        report_token: Uuid,
        expected_version: i64,
        action: ModerationAction,
        reason_code: &str,
        resolution_summary: &str,
        suspension_duration: Option<Duration>,
        correlation_id: CorrelationId,
    ) -> Result<SafetyMutation, PersistenceError> {
        validate_code(reason_code, 64, "moderation reason")?;
        if resolution_summary.is_empty()
            || resolution_summary.len() > 500
            || resolution_summary.chars().any(char::is_control)
        {
            return Err(PersistenceError::InvalidCommand(
                "resolution summary must be non-empty, bounded, and free of control characters"
                    .to_owned(),
            ));
        }
        if action == ModerationAction::TemporarySuspension
            && suspension_duration
                .is_none_or(|duration| duration <= Duration::ZERO || duration > Duration::days(90))
        {
            return Err(PersistenceError::InvalidCommand(
                "temporary suspension must be between one second and 90 days".to_owned(),
            ));
        }
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query("SELECT set_config('sahayak.safety_mutation', 'on', true)")
            .execute(&mut *transaction)
            .await?;
        let authorized: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM identity.administrator_allowlist AS allowlist
                JOIN identity.account_roles AS role
                  ON role.account_id = allowlist.account_id
                 AND role.role = 'administrator' AND role.revoked_at IS NULL
                WHERE allowlist.account_id = $1 AND allowlist.channel_identity_id = $2
                  AND allowlist.revoked_at IS NULL AND allowlist.expires_at > statement_timestamp()
            )
            "#,
        )
        .bind(administrator_account_id.into_uuid())
        .bind(administrator_channel_identity_id.into_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        if !authorized {
            transaction.rollback().await?;
            return Ok(SafetyMutation::ConflictOrIneligible);
        }
        let report: Option<(Uuid, Uuid, String)> = sqlx::query_as(
            r#"
            SELECT id, subject_account_id, triage_state FROM safety.reports
            WHERE report_token = $1 AND version = $2 AND triage_state <> 'resolved'
            FOR UPDATE
            "#,
        )
        .bind(report_token)
        .bind(expected_version)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((report_id, subject_id, from_state)) = report else {
            transaction.rollback().await?;
            return Ok(SafetyMutation::ConflictOrIneligible);
        };
        if subject_id == administrator_account_id.into_uuid() {
            transaction.rollback().await?;
            return Ok(SafetyMutation::ConflictOrIneligible);
        }
        let audit_id = AuditEventId::new().into_uuid();
        sqlx::query(
            r#"
            INSERT INTO audit.events (
                id, actor_type, actor_account_id, actor_channel_identity_id, source_channel,
                action, target_type, target_id, reason_code, metadata,
                event_schema_version, correlation_id
            ) VALUES ($1, 'administrator', $2, $3, 'whatsapp', 'safety.report_resolved',
                      'safety_report', $4, $5, '{}'::jsonb, 1, $6)
            "#,
        )
        .bind(audit_id)
        .bind(administrator_account_id.into_uuid())
        .bind(administrator_channel_identity_id.into_uuid())
        .bind(report_id)
        .bind(reason_code)
        .bind(correlation_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r#"
            UPDATE safety.restrictions
            SET ended_at = statement_timestamp(), ended_audit_event_id = $2
            WHERE report_id = $1 AND ended_at IS NULL
            "#,
        )
        .bind(report_id)
        .bind(audit_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r#"
            UPDATE safety.reports SET triage_state = 'resolved', action_state = $2,
                assigned_administrator_id = $3, first_triaged_at = COALESCE(first_triaged_at, statement_timestamp()),
                resolution_code = $4, resolution_summary = $5, resolved_at = statement_timestamp()
            WHERE id = $1
            "#,
        )
        .bind(report_id)
        .bind(action.as_str())
        .bind(administrator_account_id.into_uuid())
        .bind(reason_code)
        .bind(resolution_summary)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO safety.moderation_actions (id, report_id, administrator_account_id, action, reason_code, audit_event_id) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::now_v7())
        .bind(report_id)
        .bind(administrator_account_id.into_uuid())
        .bind(action.as_str())
        .bind(reason_code)
        .bind(audit_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO safety.report_state_events (id, report_id, from_state, to_state, action_state, actor_account_id, audit_event_id) VALUES ($1, $2, $3, 'resolved', $4, $5, $6)",
        )
        .bind(Uuid::now_v7())
        .bind(report_id)
        .bind(from_state)
        .bind(action.as_str())
        .bind(administrator_account_id.into_uuid())
        .bind(audit_id)
        .execute(&mut *transaction)
        .await?;
        if matches!(
            action,
            ModerationAction::TemporarySuspension | ModerationAction::PermanentRemoval
        ) {
            sqlx::query(
                r#"
                INSERT INTO safety.restrictions (
                    id, account_id, report_id, restriction_type, reason_code, expires_at, audit_event_id
                ) VALUES ($1, $2, $3, $4, $5,
                          CASE WHEN $4 = 'temporary_suspension' THEN statement_timestamp() + $6::interval ELSE NULL END,
                          $7)
                ON CONFLICT (account_id, restriction_type) WHERE ended_at IS NULL DO NOTHING
                "#,
            )
            .bind(SafetyRestrictionId::new().into_uuid())
            .bind(subject_id)
            .bind(report_id)
            .bind(action.as_str())
            .bind(reason_code)
            .bind(suspension_duration.map(|duration| format!("{} seconds", duration.whole_seconds())))
            .bind(audit_id)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(SafetyMutation::Applied {
            version: expected_version + 1,
        })
    }

    pub async fn administrator_queue(
        &self,
        administrator_account_id: AccountId,
        administrator_channel_identity_id: ChannelIdentityId,
    ) -> Result<Option<Vec<AdministratorReportItem>>, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let authorized: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM identity.administrator_allowlist AS allowlist
                JOIN identity.account_roles AS role ON role.account_id = allowlist.account_id
                  AND role.role = 'administrator' AND role.revoked_at IS NULL
                WHERE allowlist.account_id = $1 AND allowlist.channel_identity_id = $2
                  AND allowlist.revoked_at IS NULL AND allowlist.expires_at > statement_timestamp()
            )
            "#,
        )
        .bind(administrator_account_id.into_uuid())
        .bind(administrator_channel_identity_id.into_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        if !authorized {
            transaction.rollback().await?;
            return Ok(None);
        }
        let rows: Vec<(Uuid, i64, String, String, OffsetDateTime, Uuid, Uuid)> = sqlx::query_as(
            r#"
            SELECT report_token, version, category, severity, created_at,
                   subject_account_id, reporter_account_id
            FROM safety.reports WHERE triage_state <> 'resolved'
            ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                   WHEN 'medium' THEN 2 ELSE 3 END,
                     response_due_at, created_at, id
            LIMIT 20
            "#,
        )
        .fetch_all(&mut *transaction)
        .await?;
        let mut queue = Vec::with_capacity(rows.len());
        for (report_token, version, category, severity, created_at, subject_id, reporter_id) in rows
        {
            let subject = crate::connection::load_contact_target(&mut *transaction, subject_id)
                .await?
                .ok_or_else(|| {
                    PersistenceError::Invariant("report subject contact is unavailable".to_owned())
                })?;
            let reporter = crate::connection::load_contact_target(&mut *transaction, reporter_id)
                .await?
                .ok_or_else(|| {
                    PersistenceError::Invariant("reporter contact is unavailable".to_owned())
                })?;
            queue.push(AdministratorReportItem {
                report_token,
                version,
                category,
                severity,
                created_at,
                subject,
                reporter,
            });
        }
        transaction.commit().await?;
        Ok(Some(queue))
    }

    pub async fn overdue_report_count(&self, now: OffsetDateTime) -> Result<i64, PersistenceError> {
        sqlx::query_scalar(
            "SELECT count(*) FROM safety.reports WHERE triage_state <> 'resolved' AND response_due_at < $1",
        )
        .bind(now)
        .fetch_one(self.database.pool())
        .await
        .map_err(PersistenceError::from)
    }
}

fn validate_description(value: Option<&str>) -> Result<(), PersistenceError> {
    if value.is_some_and(|text| {
        text.is_empty() || text.len() > 2_000 || text.chars().any(char::is_control)
    }) {
        return Err(PersistenceError::InvalidCommand(
            "report description must be non-empty, bounded, and free of control characters"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_code(value: &str, maximum: usize, field: &str) -> Result<(), PersistenceError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(PersistenceError::InvalidCommand(format!(
            "{field} is invalid"
        )));
    }
    Ok(())
}
