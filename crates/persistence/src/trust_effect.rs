use crate::{
    PersistenceError, key_registry::ensure_active_encryption_key, review::insert_account_audit,
};
use sahayak_cryptography::EncryptedValue;
use sahayak_domain::{
    AccountBlockId, AccountId, ChannelIdentityId, CorrelationId, ReportId, ReviewId,
    ReviewRevisionId,
};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone)]
pub struct TrustTurnEffect {
    pub operation: TrustTurnOperation,
}

#[derive(Clone)]
pub enum TrustTurnOperation {
    SubmitReview {
        review_id: ReviewId,
        review_token: Uuid,
        revision_id: ReviewRevisionId,
        reveal_token: Uuid,
        connection: i16,
        responsiveness: i16,
        completion: i16,
        encrypted_feedback: Option<EncryptedValue>,
    },
    SubmitReport {
        report_id: ReportId,
        report_token: Uuid,
        reveal_token: Uuid,
        category: String,
        severity: String,
        block_subject: bool,
        encrypted_description: Option<EncryptedValue>,
        evidence_references: Value,
    },
    Block {
        reveal_token: Uuid,
    },
    ResolveReport {
        report_token: Uuid,
        expected_version: i64,
        action: String,
        restriction_id: Uuid,
        reason_code: String,
        resolution_summary: String,
    },
}

#[derive(Clone, Copy)]
pub(crate) struct TrustEffectContext {
    pub account_id: AccountId,
    pub channel_identity_id: ChannelIdentityId,
    pub inbound_event_id: Uuid,
    pub correlation_id: CorrelationId,
}

pub(crate) async fn apply_trust_effect(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    context: TrustEffectContext,
    effect: &TrustTurnEffect,
) -> Result<bool, PersistenceError> {
    sqlx::query("SELECT set_config('sahayak.review_mutation', 'on', true)")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT set_config('sahayak.safety_mutation', 'on', true)")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT set_config('sahayak.connection_mutation', 'on', true)")
        .execute(&mut **transaction)
        .await?;
    match &effect.operation {
        TrustTurnOperation::SubmitReview {
            review_id,
            review_token,
            revision_id,
            reveal_token,
            connection,
            responsiveness,
            completion,
            encrypted_feedback,
        } => {
            let Some((reveal_id, customer_id, professional_id)) =
                lock_introduction(transaction, context.account_id, *reveal_token).await?
            else {
                return Ok(false);
            };
            if [*connection, *responsiveness, *completion]
                .into_iter()
                .any(|value| !(1..=5).contains(&value))
            {
                return Err(PersistenceError::InvalidCommand(
                    "review rating is invalid".to_owned(),
                ));
            }
            if let Some(value) = encrypted_feedback {
                ensure_active_encryption_key(transaction, value.purpose, value.key_version).await?;
            }
            let subject_id = if context.account_id.into_uuid() == customer_id {
                professional_id
            } else {
                customer_id
            };
            let direction = if context.account_id.into_uuid() == customer_id {
                "customer_to_professional"
            } else {
                "professional_to_customer"
            };
            let inserted = sqlx::query("INSERT INTO review.reviews (id, review_token, reveal_id, reviewer_account_id, subject_account_id, direction) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (reveal_id, reviewer_account_id) DO NOTHING")
                .bind(review_id.into_uuid()).bind(review_token).bind(reveal_id).bind(context.account_id.into_uuid()).bind(subject_id).bind(direction).execute(&mut **transaction).await?;
            if inserted.rows_affected() == 0 {
                return Ok(false);
            }
            let audit_id = insert_account_audit(
                transaction,
                context.account_id,
                context.channel_identity_id,
                "review.submitted",
                "review",
                review_id.into_uuid(),
                "qualified_introduction_feedback",
                context.correlation_id,
            )
            .await?;
            sqlx::query("INSERT INTO review.review_revisions (id, review_id, revision_number, connection_experience, responsiveness, completion, encrypted_feedback, feedback_nonce, encryption_key_version, source_inbound_event_id, audit_event_id) VALUES ($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10)")
                .bind(revision_id.into_uuid()).bind(review_id.into_uuid()).bind(connection).bind(responsiveness).bind(completion)
                .bind(encrypted_feedback.as_ref().map(|value| value.ciphertext.as_slice())).bind(encrypted_feedback.as_ref().map(|value| value.nonce.as_slice())).bind(encrypted_feedback.as_ref().map(|value| value.key_version))
                .bind(context.inbound_event_id).bind(audit_id).execute(&mut **transaction).await?;
            Ok(true)
        }
        TrustTurnOperation::SubmitReport {
            report_id,
            report_token,
            reveal_token,
            category,
            severity,
            block_subject,
            encrypted_description,
            evidence_references,
        } => {
            let Some((reveal_id, customer_id, professional_id)) =
                lock_introduction(transaction, context.account_id, *reveal_token).await?
            else {
                return Ok(false);
            };
            if let Some(value) = encrypted_description {
                ensure_active_encryption_key(transaction, value.purpose, value.key_version).await?;
            }
            let subject_id = if context.account_id.into_uuid() == customer_id {
                professional_id
            } else {
                customer_id
            };
            let audit_id = insert_account_audit(
                transaction,
                context.account_id,
                context.channel_identity_id,
                "safety.report_submitted",
                "safety_report",
                report_id.into_uuid(),
                category,
                context.correlation_id,
            )
            .await?;
            let inserted = sqlx::query("INSERT INTO safety.reports (id, report_token, reporter_account_id, subject_account_id, reveal_id, category, severity, encrypted_description, description_nonce, encryption_key_version, evidence_references, response_due_at, source_inbound_event_id, audit_event_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,statement_timestamp() + CASE $7 WHEN 'critical' THEN INTERVAL '1 hour' WHEN 'high' THEN INTERVAL '4 hours' WHEN 'medium' THEN INTERVAL '24 hours' ELSE INTERVAL '72 hours' END,$12,$13) ON CONFLICT (reveal_id, reporter_account_id) DO NOTHING")
                .bind(report_id.into_uuid()).bind(report_token).bind(context.account_id.into_uuid()).bind(subject_id).bind(reveal_id).bind(category).bind(severity)
                .bind(encrypted_description.as_ref().map(|value| value.ciphertext.as_slice())).bind(encrypted_description.as_ref().map(|value| value.nonce.as_slice())).bind(encrypted_description.as_ref().map(|value| value.key_version))
                .bind(evidence_references).bind(context.inbound_event_id).bind(audit_id).execute(&mut **transaction).await?;
            if inserted.rows_affected() == 0 {
                return Ok(false);
            }
            if *block_subject {
                insert_block(
                    transaction,
                    context,
                    subject_id,
                    Some(report_id.into_uuid()),
                )
                .await?;
            }
            Ok(true)
        }
        TrustTurnOperation::Block { reveal_token } => {
            let Some((_, customer_id, professional_id)) =
                lock_introduction(transaction, context.account_id, *reveal_token).await?
            else {
                return Ok(false);
            };
            let subject_id = if context.account_id.into_uuid() == customer_id {
                professional_id
            } else {
                customer_id
            };
            insert_block(transaction, context, subject_id, None).await
        }
        TrustTurnOperation::ResolveReport {
            report_token,
            expected_version,
            action,
            restriction_id,
            reason_code,
            resolution_summary,
        } => {
            let authorized: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM identity.administrator_allowlist AS allowlist JOIN identity.account_roles AS role ON role.account_id = allowlist.account_id AND role.role = 'administrator' AND role.revoked_at IS NULL WHERE allowlist.account_id = $1 AND allowlist.channel_identity_id = $2 AND allowlist.revoked_at IS NULL AND allowlist.expires_at > statement_timestamp())")
                .bind(context.account_id.into_uuid()).bind(context.channel_identity_id.into_uuid()).fetch_one(&mut **transaction).await?;
            if !authorized {
                return Ok(false);
            }
            let report: Option<(Uuid, Uuid, String)> = sqlx::query_as("SELECT id, subject_account_id, triage_state FROM safety.reports WHERE report_token = $1 AND version = $2 AND triage_state <> 'resolved' FOR UPDATE")
                .bind(report_token).bind(expected_version).fetch_optional(&mut **transaction).await?;
            let Some((report_id, subject_id, from_state)) = report else {
                return Ok(false);
            };
            if subject_id == context.account_id.into_uuid() {
                return Ok(false);
            }
            let audit_id = sahayak_domain::AuditEventId::new().into_uuid();
            sqlx::query("INSERT INTO audit.events (id, actor_type, actor_account_id, actor_channel_identity_id, source_channel, action, target_type, target_id, reason_code, metadata, event_schema_version, correlation_id) VALUES ($1,'administrator',$2,$3,'whatsapp','safety.report_resolved','safety_report',$4,$5,'{}'::jsonb,1,$6)")
                .bind(audit_id).bind(context.account_id.into_uuid()).bind(context.channel_identity_id.into_uuid()).bind(report_id).bind(reason_code).bind(context.correlation_id.into_uuid()).execute(&mut **transaction).await?;
            sqlx::query("UPDATE safety.reports SET triage_state='resolved', action_state=$2, assigned_administrator_id=$3, first_triaged_at=COALESCE(first_triaged_at,statement_timestamp()), resolution_code=$4, resolution_summary=$5, resolved_at=statement_timestamp() WHERE id=$1")
                .bind(report_id).bind(action).bind(context.account_id.into_uuid()).bind(reason_code).bind(resolution_summary).execute(&mut **transaction).await?;
            sqlx::query("UPDATE safety.restrictions SET ended_at=statement_timestamp(), ended_audit_event_id=$2 WHERE report_id=$1 AND ended_at IS NULL")
                .bind(report_id).bind(audit_id).execute(&mut **transaction).await?;
            sqlx::query("INSERT INTO safety.moderation_actions (id,report_id,administrator_account_id,action,reason_code,audit_event_id) VALUES (uuidv7(),$1,$2,$3,$4,$5)")
                .bind(report_id).bind(context.account_id.into_uuid()).bind(action).bind(reason_code).bind(audit_id).execute(&mut **transaction).await?;
            sqlx::query("INSERT INTO safety.report_state_events (id,report_id,from_state,to_state,action_state,actor_account_id,audit_event_id) VALUES (uuidv7(),$1,$2,'resolved',$3,$4,$5)")
                .bind(report_id).bind(from_state).bind(action).bind(context.account_id.into_uuid()).bind(audit_id).execute(&mut **transaction).await?;
            if matches!(
                action.as_str(),
                "temporary_suspension" | "permanent_removal"
            ) {
                sqlx::query("INSERT INTO safety.restrictions (id,account_id,report_id,restriction_type,reason_code,expires_at,audit_event_id) VALUES ($1,$2,$3,$4,$5,CASE WHEN $4='temporary_suspension' THEN statement_timestamp()+INTERVAL '7 days' ELSE NULL END,$6)")
                    .bind(restriction_id).bind(subject_id).bind(report_id).bind(action).bind(reason_code).bind(audit_id).execute(&mut **transaction).await?;
            }
            Ok(true)
        }
    }
}

async fn lock_introduction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: AccountId,
    reveal_token: Uuid,
) -> Result<Option<(Uuid, Uuid, Uuid)>, PersistenceError> {
    sqlx::query_as("SELECT reveal.id, reveal.customer_account_id, reveal.professional_account_id FROM connection.contact_reveals AS reveal JOIN connection.contact_reveal_delivery AS delivery ON delivery.reveal_id = reveal.id LEFT JOIN connection.reveal_reversals AS reversal ON reversal.reveal_id = reveal.id WHERE reveal.reveal_token = $1 AND $2 IN (reveal.customer_account_id, reveal.professional_account_id) AND delivery.qualified_state = 'qualified' AND reversal.id IS NULL FOR UPDATE OF reveal")
        .bind(reveal_token).bind(account_id.into_uuid()).fetch_optional(&mut **transaction).await.map_err(PersistenceError::from)
}

async fn insert_block(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    context: TrustEffectContext,
    subject_id: Uuid,
    report_id: Option<Uuid>,
) -> Result<bool, PersistenceError> {
    let audit_id = insert_account_audit(
        transaction,
        context.account_id,
        context.channel_identity_id,
        "account.blocked",
        "account",
        subject_id,
        if report_id.is_some() {
            "safety_report"
        } else {
            "user_requested"
        },
        context.correlation_id,
    )
    .await?;
    let inserted = sqlx::query("INSERT INTO identity.account_blocks (id, actor_account_id, blocked_account_id, source_inbound_event_id, audit_event_id, report_id) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (actor_account_id, blocked_account_id) WHERE removed_at IS NULL DO NOTHING")
        .bind(AccountBlockId::new().into_uuid()).bind(context.account_id.into_uuid()).bind(subject_id).bind(context.inbound_event_id).bind(audit_id).bind(report_id).execute(&mut **transaction).await?;
    Ok(inserted.rows_affected() == 1)
}
