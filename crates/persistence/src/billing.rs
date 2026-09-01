use crate::{
    ContactTarget, Database, OutboundQueueOutcome, PersistenceError, QueueOutboundMessage,
};
use sahayak_domain::{
    AccountId, AuditEventId, BillingWebhookEventId, ChannelIdentityId, CorrelationId, PaymentId,
    SubscriptionId,
};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct SubscriptionStatusRow {
    status: String,
    hosted_payment_url: Option<String>,
    billing_period_end: Option<OffsetDateTime>,
    grace_period_end: Option<OffsetDateTime>,
    cancel_at_cycle_end: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BillingWebhookAcceptance {
    Accepted,
    Duplicate,
}

pub struct AcceptBillingWebhook<'a> {
    pub id: BillingWebhookEventId,
    pub provider_event_id: &'a str,
    pub event_type: &'a str,
    pub normalized_payload: &'a Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionStatus {
    pub status: String,
    pub payment_required: bool,
    pub hosted_payment_url: Option<String>,
    pub billing_period_end: Option<OffsetDateTime>,
    pub grace_period_end: Option<OffsetDateTime>,
    pub cancel_at_cycle_end: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BillingReconciliationCandidate {
    pub subscription_id: SubscriptionId,
    pub provider_subscription_id: String,
    pub local_status: String,
}

#[derive(Clone, Debug)]
pub struct PaymentReminder {
    pub id: Uuid,
    pub claim_token: Uuid,
    pub reminder_kind: String,
    pub target: ContactTarget,
}

#[derive(Clone, Debug)]
pub struct BillingRepository {
    database: Database,
}

impl BillingRepository {
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    pub async fn accept_webhook(
        &self,
        input: AcceptBillingWebhook<'_>,
    ) -> Result<BillingWebhookAcceptance, PersistenceError> {
        validate_external_id(input.provider_event_id, 128, "event")?;
        validate_event_type(input.event_type)?;
        if !input.normalized_payload.is_object()
            || serde_json::to_vec(input.normalized_payload)
                .map_err(|error| PersistenceError::InvalidCommand(error.to_string()))?
                .len()
                > 32_768
        {
            return Err(PersistenceError::InvalidCommand(
                "billing webhook payload is invalid".to_owned(),
            ));
        }
        let inserted = sqlx::query(
            "INSERT INTO billing.webhook_events (id, provider_event_id, event_type, signature_verified, normalized_payload) VALUES ($1, $2, $3, true, $4) ON CONFLICT (provider, provider_event_id) DO NOTHING",
        )
        .bind(input.id.into_uuid())
        .bind(input.provider_event_id)
        .bind(input.event_type)
        .bind(input.normalized_payload)
        .execute(self.database.pool())
        .await?;
        Ok(if inserted.rows_affected() == 1 {
            BillingWebhookAcceptance::Accepted
        } else {
            BillingWebhookAcceptance::Duplicate
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_hosted_subscription(
        &self,
        id: SubscriptionId,
        professional: AccountId,
        provider_plan_id: &str,
        provider_subscription_id: &str,
        hosted_payment_url: &str,
    ) -> Result<bool, PersistenceError> {
        validate_provider_id(provider_plan_id, "plan")?;
        validate_provider_id(provider_subscription_id, "sub_")?;
        if !hosted_payment_url.starts_with("https://") || hosted_payment_url.len() > 2_048 {
            return Err(PersistenceError::InvalidCommand(
                "hosted payment URL is invalid".to_owned(),
            ));
        }
        let mut transaction = self.database.pool().begin().await?;
        let plan_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM billing.plans WHERE provider_plan_id = $1 AND state = 'active'",
        )
        .bind(provider_plan_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(plan_id) = plan_id else {
            transaction.rollback().await?;
            return Ok(false);
        };
        let inserted = sqlx::query(
            r#"INSERT INTO billing.subscriptions (
                id, professional_account_id, plan_id, provider_subscription_id,
                hosted_payment_url, status
            ) VALUES ($1, $2, $3, $4, $5, 'pending_payment')
            ON CONFLICT (professional_account_id) WHERE status IN
                ('pending_payment','authenticated','active','past_due','halted') DO NOTHING"#,
        )
        .bind(id.into_uuid())
        .bind(professional.into_uuid())
        .bind(plan_id)
        .bind(provider_subscription_id)
        .bind(hosted_payment_url)
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() == 1 {
            sqlx::query(
                "INSERT INTO billing.professional_entitlements (professional_account_id, subscription_id, status) VALUES ($1, $2, 'pending_payment') ON CONFLICT (professional_account_id) DO UPDATE SET subscription_id = EXCLUDED.subscription_id, status = 'pending_payment', manually_waived_until = NULL",
            ).bind(professional.into_uuid()).bind(id.into_uuid()).execute(&mut *transaction).await?;
        }
        transaction.commit().await?;
        Ok(inserted.rows_affected() == 1)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn apply_provider_event(
        &self,
        provider_event_id: &str,
        provider_subscription_id: &str,
        event_type: &str,
        provider_payment_id: Option<&str>,
        provider_invoice_id: Option<&str>,
        provider_order_id: Option<&str>,
        amount_minor: Option<i64>,
        currency: Option<&str>,
        period_start: Option<OffsetDateTime>,
        period_end: Option<OffsetDateTime>,
    ) -> Result<bool, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let event: Option<Uuid> = sqlx::query_scalar(
            "UPDATE billing.webhook_events SET processing_state = 'processing', attempt_count = attempt_count + 1 WHERE provider_event_id = $1 AND processing_state = 'pending' RETURNING id",
        ).bind(provider_event_id).fetch_optional(&mut *transaction).await?;
        if event.is_none() {
            transaction.rollback().await?;
            return Ok(false);
        }
        let subscription: Option<(Uuid, Uuid, Uuid, String)> = sqlx::query_as(
            "SELECT id, professional_account_id, plan_id, status FROM billing.subscriptions WHERE provider_subscription_id = $1 FOR UPDATE",
        ).bind(provider_subscription_id).fetch_optional(&mut *transaction).await?;
        let Some((subscription_id, professional_id, plan_id, current_status)) = subscription else {
            sqlx::query("UPDATE billing.webhook_events SET processing_state = 'failed', processed_at = statement_timestamp(), terminal_failure_code = 'unknown_subscription' WHERE provider_event_id = $1")
                .bind(provider_event_id).execute(&mut *transaction).await?;
            transaction.commit().await?;
            return Ok(false);
        };
        if matches!(current_status.as_str(), "cancelled" | "expired")
            && !matches!(
                event_type,
                "subscription.cancelled" | "subscription.completed"
            )
        {
            sqlx::query(
                "UPDATE billing.webhook_events SET processing_state = 'processed', processed_at = statement_timestamp() WHERE provider_event_id = $1",
            )
            .bind(provider_event_id)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            return Ok(true);
        }
        let transition = match event_type {
            "subscription.authenticated" => Some(("authenticated", "pending_payment")),
            "subscription.activated" | "subscription.charged" | "invoice.paid" => {
                Some(("active", "active"))
            }
            "subscription.pending" | "payment.failed" => Some(("past_due", "past_due")),
            "subscription.halted" => Some(("halted", "expired")),
            "subscription.cancelled" => Some(("cancelled", "expired")),
            "subscription.completed" => Some(("expired", "expired")),
            _ => None,
        };
        let Some((subscription_status, entitlement_status)) = transition else {
            sqlx::query(
                "UPDATE billing.webhook_events SET processing_state = 'processed', processed_at = statement_timestamp() WHERE provider_event_id = $1",
            )
            .bind(provider_event_id)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            return Ok(true);
        };
        sqlx::query(
            r#"UPDATE billing.subscriptions SET status = $2,
               billing_period_start = COALESCE($3, billing_period_start),
               billing_period_end = COALESCE($4, billing_period_end),
               grace_period_end = CASE WHEN $2 = 'past_due' THEN COALESCE($4, statement_timestamp()) + INTERVAL '3 days' ELSE NULL END,
               cancelled_at = CASE WHEN $2 IN ('cancelled','expired') THEN statement_timestamp() ELSE NULL END
               WHERE id = $1"#,
        ).bind(subscription_id).bind(subscription_status).bind(period_start).bind(period_end)
            .execute(&mut *transaction).await?;
        sqlx::query("UPDATE billing.professional_entitlements SET status = $2 WHERE professional_account_id = $1")
            .bind(professional_id).bind(entitlement_status).execute(&mut *transaction).await?;
        if let (Some(payment), Some(amount), Some(currency)) =
            (provider_payment_id, amount_minor, currency)
        {
            let plan: (i64, String, String) = sqlx::query_as("SELECT amount_minor, currency::text, tax_treatment FROM billing.plans WHERE id = $1")
                .bind(plan_id).fetch_one(&mut *transaction).await?;
            if amount != plan.0 || currency != plan.1 {
                return Err(PersistenceError::Invariant(
                    "payment amount or currency does not match plan".to_owned(),
                ));
            }
            sqlx::query(
                r#"INSERT INTO billing.payments (
                    id, subscription_id, provider_payment_id, provider_invoice_id,
                    provider_order_id, amount_minor, currency, tax_treatment, status,
                    invoice_reference, receipt_reference, failure_code, paid_at
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$4,$5,
                          CASE WHEN $9 = 'failed' THEN 'provider_payment_failed' ELSE NULL END,
                          CASE WHEN $9 = 'captured' THEN statement_timestamp() ELSE NULL END)
                ON CONFLICT (provider_payment_id) DO NOTHING"#,
            )
            .bind(PaymentId::new().into_uuid())
            .bind(subscription_id)
            .bind(payment)
            .bind(provider_invoice_id)
            .bind(provider_order_id)
            .bind(amount)
            .bind(currency)
            .bind(plan.2)
            .bind(if event_type == "payment.failed" {
                "failed"
            } else {
                "captured"
            })
            .execute(&mut *transaction)
            .await?;
            if event_type != "payment.failed"
                && let Some(invoice_id) = provider_invoice_id
            {
                sqlx::query(
                    r#"
                    INSERT INTO billing.tax_documents (
                        id, payment_id, provider_invoice_id, invoice_reference, gst_treatment
                    )
                    SELECT uuidv7(), payment.id, $2, $2, payment.tax_treatment
                    FROM billing.payments AS payment
                    WHERE payment.provider_payment_id = $1
                    ON CONFLICT (payment_id) DO NOTHING
                    "#,
                )
                .bind(payment)
                .bind(invoice_id)
                .execute(&mut *transaction)
                .await?;
            }
        }
        sqlx::query("UPDATE billing.webhook_events SET processing_state = 'processed', processed_at = statement_timestamp() WHERE provider_event_id = $1")
            .bind(provider_event_id).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub async fn fail_webhook(
        &self,
        provider_event_id: &str,
        failure_code: &str,
    ) -> Result<(), PersistenceError> {
        validate_external_id(provider_event_id, 128, "event")?;
        if failure_code.is_empty()
            || failure_code.len() > 96
            || !failure_code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return Err(PersistenceError::InvalidCommand(
                "billing webhook failure code is invalid".to_owned(),
            ));
        }
        sqlx::query(
            r#"
            UPDATE billing.webhook_events
            SET processing_state = 'failed', attempt_count = attempt_count + 1,
                processed_at = statement_timestamp(), terminal_failure_code = $2
            WHERE provider_event_id = $1 AND processing_state = 'pending'
            "#,
        )
        .bind(provider_event_id)
        .bind(failure_code)
        .execute(self.database.pool())
        .await?;
        Ok(())
    }

    pub async fn status(
        &self,
        professional: AccountId,
    ) -> Result<SubscriptionStatus, PersistenceError> {
        let row: Option<SubscriptionStatusRow> = sqlx::query_as(
            r#"SELECT entitlement.status, subscription.hosted_payment_url,
                      subscription.billing_period_end, subscription.grace_period_end,
                      COALESCE(subscription.cancel_at_cycle_end, false) AS cancel_at_cycle_end
               FROM billing.professional_entitlements AS entitlement
               LEFT JOIN billing.subscriptions AS subscription ON subscription.id = entitlement.subscription_id
               WHERE entitlement.professional_account_id = $1"#,
        ).bind(professional.into_uuid()).fetch_optional(self.database.pool()).await?;
        Ok(match row {
            Some(row) => SubscriptionStatus {
                payment_required: row.status == "payment_required",
                status: row.status,
                hosted_payment_url: row.hosted_payment_url,
                billing_period_end: row.billing_period_end,
                grace_period_end: row.grace_period_end,
                cancel_at_cycle_end: row.cancel_at_cycle_end,
            },
            None => SubscriptionStatus {
                status: "not_required_during_free_value".to_owned(),
                payment_required: false,
                hosted_payment_url: None,
                billing_period_end: None,
                grace_period_end: None,
                cancel_at_cycle_end: false,
            },
        })
    }

    pub async fn reconciliation_candidates(
        &self,
        limit: i64,
    ) -> Result<Vec<BillingReconciliationCandidate>, PersistenceError> {
        if !(1..=100).contains(&limit) {
            return Err(PersistenceError::InvalidCommand(
                "reconciliation limit must be between 1 and 100".to_owned(),
            ));
        }
        let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
            r#"
            SELECT id, provider_subscription_id, status
            FROM billing.subscriptions
            WHERE provider_subscription_id IS NOT NULL
              AND status IN ('pending_payment','authenticated','active','past_due','halted')
            ORDER BY updated_at, id LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(self.database.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| BillingReconciliationCandidate {
                subscription_id: SubscriptionId::from_uuid(row.0),
                provider_subscription_id: row.1,
                local_status: row.2,
            })
            .collect())
    }

    pub async fn record_reconciliation(
        &self,
        candidate: &BillingReconciliationCandidate,
        provider_status: &str,
    ) -> Result<bool, PersistenceError> {
        let expected = match provider_status {
            "created" => "pending_payment",
            "authenticated" => "authenticated",
            "active" => "active",
            "pending" => "past_due",
            "halted" => "halted",
            "cancelled" => "cancelled",
            "completed" => "expired",
            _ => "unknown",
        };
        let mut transaction = self.database.pool().begin().await?;
        let run_id = Uuid::now_v7();
        let mismatch = expected == "unknown" || expected != candidate.local_status;
        sqlx::query(
            "INSERT INTO billing.reconciliation_runs (id, completed_at, checked_count, exception_count, status) VALUES ($1, statement_timestamp(), 1, $2, 'completed')",
        )
        .bind(run_id)
        .bind(i32::from(mismatch))
        .execute(&mut *transaction)
        .await?;
        if mismatch {
            sqlx::query(
                "INSERT INTO billing.reconciliation_exceptions (id, run_id, subscription_id, reason_code) VALUES (uuidv7(), $1, $2, 'provider_status_mismatch')",
            )
            .bind(run_id)
            .bind(candidate.subscription_id.into_uuid())
            .execute(&mut *transaction)
            .await?;
        } else {
            sqlx::query(
                "UPDATE billing.subscriptions SET updated_at = statement_timestamp() WHERE id = $1",
            )
            .bind(candidate.subscription_id.into_uuid())
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(!mismatch)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn resolve_reconciliation_exception(
        &self,
        exception_id: Uuid,
        administrator_account_id: AccountId,
        administrator_channel_identity_id: ChannelIdentityId,
        resolution_summary: &str,
        correlation_id: CorrelationId,
    ) -> Result<bool, PersistenceError> {
        if resolution_summary.is_empty()
            || resolution_summary.len() > 500
            || resolution_summary.chars().any(char::is_control)
        {
            return Err(PersistenceError::InvalidCommand(
                "billing exception resolution is invalid".to_owned(),
            ));
        }
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
            return Ok(false);
        }
        let audit_id = AuditEventId::new().into_uuid();
        sqlx::query(
            r#"
            INSERT INTO audit.events (
                id, actor_type, actor_account_id, actor_channel_identity_id, source_channel,
                action, target_type, target_id, reason_code, metadata,
                event_schema_version, correlation_id
            ) VALUES ($1, 'administrator', $2, $3, 'whatsapp', 'billing.exception_resolved',
                      'billing_reconciliation_exception', $4, 'manual_reconciliation',
                      '{}'::jsonb, 1, $5)
            "#,
        )
        .bind(audit_id)
        .bind(administrator_account_id.into_uuid())
        .bind(administrator_channel_identity_id.into_uuid())
        .bind(exception_id)
        .bind(correlation_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        let updated = sqlx::query(
            r#"
            UPDATE billing.reconciliation_exceptions
            SET state = 'resolved', assigned_administrator_id = $2,
                resolution_summary = $3, resolved_at = statement_timestamp(), audit_event_id = $4
            WHERE id = $1 AND state IN ('open','investigating')
            "#,
        )
        .bind(exception_id)
        .bind(administrator_account_id.into_uuid())
        .bind(resolution_summary)
        .bind(audit_id)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(false);
        }
        transaction.commit().await?;
        Ok(true)
    }

    pub async fn claim_payment_reminders(
        &self,
        limit: i64,
    ) -> Result<Vec<PaymentReminder>, PersistenceError> {
        if !(1..=50).contains(&limit) {
            return Err(PersistenceError::InvalidCommand(
                "payment reminder claim limit must be between 1 and 50".to_owned(),
            ));
        }
        let claim_token = Uuid::new_v4();
        let mut transaction = self.database.pool().begin().await?;
        sqlx::query(
            "UPDATE billing.payment_reminders SET state='pending', claim_token=NULL, claimed_at=NULL WHERE state='processing' AND claimed_at < statement_timestamp() - INTERVAL '10 minutes'",
        )
        .execute(&mut *transaction)
        .await?;
        let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
            r#"
            WITH selected AS (
                SELECT id FROM billing.payment_reminders
                WHERE state = 'pending' AND due_at <= statement_timestamp()
                ORDER BY due_at, id FOR UPDATE SKIP LOCKED LIMIT $1
            )
            UPDATE billing.payment_reminders AS reminder
            SET state = 'processing', claim_token = $2, claimed_at = statement_timestamp()
            FROM selected WHERE reminder.id = selected.id
            RETURNING reminder.id, reminder.professional_account_id, reminder.reminder_kind
            "#,
        )
        .bind(limit)
        .bind(claim_token)
        .fetch_all(&mut *transaction)
        .await?;
        let mut reminders = Vec::with_capacity(rows.len());
        for (id, account_id, reminder_kind) in rows {
            let Some(target) =
                crate::connection::load_contact_target(&mut *transaction, account_id).await?
            else {
                sqlx::query(
                    "UPDATE billing.payment_reminders SET state='cancelled', claim_token=NULL, claimed_at=NULL WHERE id=$1 AND claim_token=$2",
                )
                .bind(id)
                .bind(claim_token)
                .execute(&mut *transaction)
                .await?;
                continue;
            };
            reminders.push(PaymentReminder {
                id,
                claim_token,
                reminder_kind,
                target,
            });
        }
        transaction.commit().await?;
        Ok(reminders)
    }

    pub async fn complete_payment_reminder(
        &self,
        reminder: &PaymentReminder,
        outbound: &QueueOutboundMessage,
    ) -> Result<bool, PersistenceError> {
        let mut transaction = self.database.pool().begin().await?;
        let outbound_id =
            match crate::outbound::queue_in_transaction(&mut transaction, outbound).await? {
                OutboundQueueOutcome::Queued {
                    outbound_message_id,
                    ..
                }
                | OutboundQueueOutcome::Duplicate {
                    outbound_message_id,
                } => outbound_message_id,
                OutboundQueueOutcome::IdentifierCollision { .. } => {
                    transaction.rollback().await?;
                    return Err(PersistenceError::Invariant(
                        "payment reminder idempotency collision".to_owned(),
                    ));
                }
            };
        let updated = sqlx::query(
            r#"
            UPDATE billing.payment_reminders
            SET state = 'sent', claim_token = NULL, claimed_at = NULL,
                outbound_message_id = $3, completed_at = statement_timestamp()
            WHERE id = $1 AND state = 'processing' AND claim_token = $2
            "#,
        )
        .bind(reminder.id)
        .bind(reminder.claim_token)
        .bind(outbound_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(false);
        }
        transaction.commit().await?;
        Ok(true)
    }

    pub async fn release_payment_reminder(
        &self,
        reminder: &PaymentReminder,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            "UPDATE billing.payment_reminders SET state = 'pending', claim_token = NULL, claimed_at = NULL, due_at = statement_timestamp() + INTERVAL '5 minutes' WHERE id = $1 AND state = 'processing' AND claim_token = $2",
        )
        .bind(reminder.id)
        .bind(reminder.claim_token)
        .execute(self.database.pool())
        .await?;
        Ok(())
    }
}

fn validate_provider_id(value: &str, prefix: &str) -> Result<(), PersistenceError> {
    if value.len() > 128
        || !value.starts_with(prefix)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(PersistenceError::InvalidCommand(
            "payment provider identifier is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_external_id(value: &str, maximum: usize, field: &str) -> Result<(), PersistenceError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(PersistenceError::InvalidCommand(format!(
            "payment provider {field} identifier is invalid"
        )));
    }
    Ok(())
}

fn validate_event_type(value: &str) -> Result<(), PersistenceError> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'.' || byte == b'_')
    {
        return Err(PersistenceError::InvalidCommand(
            "payment event type is invalid".to_owned(),
        ));
    }
    Ok(())
}
