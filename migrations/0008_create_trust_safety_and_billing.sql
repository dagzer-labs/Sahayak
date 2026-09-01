CREATE SCHEMA IF NOT EXISTS review;
CREATE SCHEMA IF NOT EXISTS safety;
CREATE SCHEMA IF NOT EXISTS billing;
CREATE SCHEMA IF NOT EXISTS operations;

CREATE OR REPLACE FUNCTION review.reject_direct_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('sahayak.review_mutation', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'review records require the guarded application path';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE OR REPLACE FUNCTION safety.reject_direct_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('sahayak.safety_mutation', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'safety records require the guarded application path';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TABLE operations.legal_holds (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES identity.accounts(id),
    reason_code varchar(64) COLLATE "C" NOT NULL,
    case_reference varchar(128) NOT NULL,
    starts_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    ends_at timestamptz,
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit.events(id),
    CONSTRAINT legal_holds_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT legal_holds_reason_check CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT legal_holds_case_check CHECK (length(case_reference) BETWEEN 1 AND 128),
    CONSTRAINT legal_holds_end_check CHECK (ends_at IS NULL OR ends_at > starts_at)
);

CREATE UNIQUE INDEX legal_holds_active_account_idx
    ON operations.legal_holds(account_id) WHERE ends_at IS NULL;

CREATE TABLE operations.retention_runs (
    id uuid PRIMARY KEY,
    policy_version varchar(32) COLLATE "C" NOT NULL,
    inbound_payloads_purged integer NOT NULL DEFAULT 0,
    outbound_payloads_purged integer NOT NULL DEFAULT 0,
    request_locations_purged integer NOT NULL DEFAULT 0,
    started_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    completed_at timestamptz,
    CONSTRAINT retention_runs_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT retention_runs_counts_check CHECK (
        inbound_payloads_purged >= 0 AND outbound_payloads_purged >= 0
        AND request_locations_purged >= 0
    )
);

CREATE TABLE review.reviews (
    id uuid PRIMARY KEY,
    review_token uuid NOT NULL UNIQUE,
    reveal_id uuid NOT NULL REFERENCES connection.contact_reveals(id),
    reviewer_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    subject_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    direction text COLLATE "C" NOT NULL,
    moderation_state text COLLATE "C" NOT NULL DEFAULT 'published',
    current_revision_number integer NOT NULL DEFAULT 1,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT reviews_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT reviews_token_uuid_v4_check CHECK (uuid_extract_version(review_token) = 4),
    CONSTRAINT reviews_accounts_distinct_check CHECK (reviewer_account_id <> subject_account_id),
    CONSTRAINT reviews_direction_check CHECK (
        direction IN ('customer_to_professional', 'professional_to_customer')
    ),
    CONSTRAINT reviews_moderation_state_check CHECK (
        moderation_state IN ('published', 'pending_review', 'hidden', 'removed')
    ),
    CONSTRAINT reviews_revision_positive_check CHECK (current_revision_number > 0),
    CONSTRAINT reviews_once_per_direction UNIQUE (reveal_id, reviewer_account_id)
);

CREATE INDEX reviews_subject_idx
    ON review.reviews(subject_account_id, created_at DESC, id)
    WHERE moderation_state = 'published';

CREATE TRIGGER reviews_touch_version
BEFORE UPDATE ON review.reviews
FOR EACH ROW EXECUTE FUNCTION identity.touch_versioned_row();

CREATE TABLE review.review_revisions (
    id uuid PRIMARY KEY,
    review_id uuid NOT NULL REFERENCES review.reviews(id) ON DELETE CASCADE,
    revision_number integer NOT NULL,
    connection_experience smallint NOT NULL,
    responsiveness smallint NOT NULL,
    completion smallint NOT NULL,
    encrypted_feedback bytea,
    feedback_nonce bytea,
    encryption_key_version smallint,
    source_inbound_event_id uuid REFERENCES integration.inbound_events(id),
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit.events(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT review_revisions_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT review_revisions_number_check CHECK (revision_number > 0),
    CONSTRAINT review_revisions_rating_check CHECK (
        connection_experience BETWEEN 1 AND 5
        AND responsiveness BETWEEN 1 AND 5
        AND completion BETWEEN 1 AND 5
    ),
    CONSTRAINT review_revisions_feedback_shape_check CHECK (
        (encrypted_feedback IS NULL AND feedback_nonce IS NULL AND encryption_key_version IS NULL)
        OR (
            encrypted_feedback IS NOT NULL AND octet_length(encrypted_feedback) BETWEEN 17 AND 4096
            AND feedback_nonce IS NOT NULL AND octet_length(feedback_nonce) = 12
            AND encryption_key_version > 0
        )
    ),
    CONSTRAINT review_revisions_number_unique UNIQUE (review_id, revision_number)
);

CREATE TABLE review.rating_aggregates (
    subject_account_id uuid PRIMARY KEY REFERENCES identity.accounts(id),
    rating_count integer NOT NULL,
    connection_experience_sum bigint NOT NULL,
    responsiveness_sum bigint NOT NULL,
    completion_sum bigint NOT NULL,
    average_rating numeric(3,2),
    publicly_visible boolean NOT NULL,
    recalculated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT rating_aggregates_count_check CHECK (rating_count >= 0),
    CONSTRAINT rating_aggregates_sums_check CHECK (
        connection_experience_sum >= 0 AND responsiveness_sum >= 0 AND completion_sum >= 0
    ),
    CONSTRAINT rating_aggregates_visibility_check CHECK (publicly_visible = (rating_count >= 3)),
    CONSTRAINT rating_aggregates_average_check CHECK (
        (rating_count = 0 AND average_rating IS NULL)
        OR (rating_count > 0 AND average_rating BETWEEN 1.00 AND 5.00)
    )
);

CREATE OR REPLACE FUNCTION review.validate_review_revision()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, review, connection
AS $$
DECLARE
    target review.reviews%ROWTYPE;
    reveal_customer_id uuid;
    reveal_professional_id uuid;
    qualified text;
BEGIN
    SELECT * INTO target FROM review.reviews WHERE id = NEW.review_id FOR UPDATE;
    IF NOT FOUND OR NEW.revision_number <> target.current_revision_number THEN
        RAISE EXCEPTION 'review revision does not match current review version';
    END IF;
    SELECT contact.customer_account_id, contact.professional_account_id,
           delivery.qualified_state
    INTO reveal_customer_id, reveal_professional_id, qualified
    FROM connection.contact_reveals AS contact
    JOIN connection.contact_reveal_delivery AS delivery ON delivery.reveal_id = contact.id
    WHERE contact.id = target.reveal_id;
    IF NOT FOUND OR qualified <> 'qualified' THEN
        RAISE EXCEPTION 'reviews require a qualified introduction';
    END IF;
    IF NOT (
        (target.direction = 'customer_to_professional'
         AND target.reviewer_account_id = reveal_customer_id
         AND target.subject_account_id = reveal_professional_id)
        OR
        (target.direction = 'professional_to_customer'
         AND target.reviewer_account_id = reveal_professional_id
         AND target.subject_account_id = reveal_customer_id)
    ) THEN
        RAISE EXCEPTION 'review participants do not match introduction';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER review_revisions_validate
BEFORE INSERT ON review.review_revisions
FOR EACH ROW EXECUTE FUNCTION review.validate_review_revision();

CREATE OR REPLACE FUNCTION review.recalculate_rating(candidate_subject_id uuid)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, review
AS $$
BEGIN
    INSERT INTO review.rating_aggregates (
        subject_account_id, rating_count, connection_experience_sum,
        responsiveness_sum, completion_sum, average_rating, publicly_visible
    )
    SELECT candidate_subject_id,
           count(*)::integer,
           COALESCE(sum(revision.connection_experience), 0)::bigint,
           COALESCE(sum(revision.responsiveness), 0)::bigint,
           COALESCE(sum(revision.completion), 0)::bigint,
           CASE WHEN count(*) = 0 THEN NULL ELSE
               round(avg((revision.connection_experience + revision.responsiveness + revision.completion)::numeric / 3), 2)
           END,
           count(*) >= 3
    FROM review.reviews AS root
    JOIN review.review_revisions AS revision
      ON revision.review_id = root.id
     AND revision.revision_number = root.current_revision_number
    WHERE root.subject_account_id = candidate_subject_id
      AND root.moderation_state = 'published'
    ON CONFLICT (subject_account_id) DO UPDATE SET
        rating_count = EXCLUDED.rating_count,
        connection_experience_sum = EXCLUDED.connection_experience_sum,
        responsiveness_sum = EXCLUDED.responsiveness_sum,
        completion_sum = EXCLUDED.completion_sum,
        average_rating = EXCLUDED.average_rating,
        publicly_visible = EXCLUDED.publicly_visible,
        recalculated_at = statement_timestamp();
END;
$$;

CREATE OR REPLACE FUNCTION review.refresh_rating_aggregate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_subject uuid;
BEGIN
    SELECT subject_account_id INTO target_subject
    FROM review.reviews WHERE id = COALESCE(NEW.review_id, OLD.review_id);
    PERFORM review.recalculate_rating(target_subject);
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER review_revisions_refresh_aggregate
AFTER INSERT OR UPDATE OR DELETE ON review.review_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION review.refresh_rating_aggregate();

CREATE OR REPLACE FUNCTION review.refresh_rating_after_moderation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM review.recalculate_rating(NEW.subject_account_id);
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER reviews_refresh_aggregate
AFTER UPDATE OF moderation_state, current_revision_number ON review.reviews
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION review.refresh_rating_after_moderation();

CREATE TRIGGER reviews_guard
BEFORE INSERT OR UPDATE OR DELETE ON review.reviews
FOR EACH ROW EXECUTE FUNCTION review.reject_direct_mutation();

CREATE TRIGGER review_revisions_guard
BEFORE INSERT OR UPDATE OR DELETE ON review.review_revisions
FOR EACH ROW EXECUTE FUNCTION review.reject_direct_mutation();

CREATE TRIGGER rating_aggregates_guard
BEFORE INSERT OR UPDATE OR DELETE ON review.rating_aggregates
FOR EACH ROW EXECUTE FUNCTION review.reject_direct_mutation();

CREATE TABLE safety.reports (
    id uuid PRIMARY KEY,
    report_token uuid NOT NULL UNIQUE,
    reporter_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    subject_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    reveal_id uuid NOT NULL REFERENCES connection.contact_reveals(id),
    category text COLLATE "C" NOT NULL,
    severity text COLLATE "C" NOT NULL,
    encrypted_description bytea,
    description_nonce bytea,
    encryption_key_version smallint,
    evidence_references jsonb NOT NULL DEFAULT '[]'::jsonb,
    triage_state text COLLATE "C" NOT NULL DEFAULT 'submitted',
    assigned_administrator_id uuid REFERENCES identity.accounts(id),
    action_state text COLLATE "C" NOT NULL DEFAULT 'none',
    resolution_code varchar(64) COLLATE "C",
    resolution_summary varchar(500),
    response_due_at timestamptz NOT NULL,
    first_triaged_at timestamptz,
    resolved_at timestamptz,
    source_inbound_event_id uuid REFERENCES integration.inbound_events(id),
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit.events(id),
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT reports_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT reports_token_uuid_v4_check CHECK (uuid_extract_version(report_token) = 4),
    CONSTRAINT reports_accounts_distinct_check CHECK (reporter_account_id <> subject_account_id),
    CONSTRAINT reports_category_check CHECK (
        category IN ('spam', 'harassment', 'fraud', 'unsafe_behavior', 'identity_misrepresentation', 'no_show', 'other')
    ),
    CONSTRAINT reports_severity_check CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT reports_description_shape_check CHECK (
        (encrypted_description IS NULL AND description_nonce IS NULL AND encryption_key_version IS NULL)
        OR (
            encrypted_description IS NOT NULL AND octet_length(encrypted_description) BETWEEN 17 AND 8192
            AND description_nonce IS NOT NULL AND octet_length(description_nonce) = 12
            AND encryption_key_version > 0
        )
    ),
    CONSTRAINT reports_evidence_shape_check CHECK (
        jsonb_typeof(evidence_references) = 'array'
        AND jsonb_array_length(evidence_references) <= 10
        AND octet_length(evidence_references::text) <= 8192
    ),
    CONSTRAINT reports_triage_state_check CHECK (
        triage_state IN ('submitted', 'triaged', 'investigating', 'resolved')
    ),
    CONSTRAINT reports_action_state_check CHECK (
        action_state IN ('none', 'low_risk_review', 'restricted_pending_review',
                         'suspended_pending_review', 'no_action', 'warning',
                         'temporary_suspension', 'permanent_removal')
    ),
    CONSTRAINT reports_resolution_shape_check CHECK (
        (triage_state = 'resolved' AND resolved_at IS NOT NULL AND resolution_code IS NOT NULL)
        OR (triage_state <> 'resolved' AND resolved_at IS NULL)
    ),
    CONSTRAINT reports_due_after_create_check CHECK (response_due_at > created_at),
    CONSTRAINT reports_once_per_pair_introduction UNIQUE (reveal_id, reporter_account_id)
);

CREATE INDEX reports_triage_queue_idx
    ON safety.reports(severity DESC, response_due_at, created_at, id)
    WHERE triage_state <> 'resolved';

CREATE INDEX reports_subject_idx
    ON safety.reports(subject_account_id, created_at DESC, id);

CREATE TRIGGER reports_touch_version
BEFORE UPDATE ON safety.reports
FOR EACH ROW EXECUTE FUNCTION identity.touch_versioned_row();

CREATE TABLE safety.report_evidence (
    id uuid PRIMARY KEY,
    report_id uuid NOT NULL REFERENCES safety.reports(id) ON DELETE CASCADE,
    evidence_type text COLLATE "C" NOT NULL,
    restricted_reference varchar(255) NOT NULL,
    content_digest bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT report_evidence_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT report_evidence_type_check CHECK (
        evidence_type IN ('message', 'image', 'document', 'external_case')
    ),
    CONSTRAINT report_evidence_reference_check CHECK (
        length(restricted_reference) BETWEEN 1 AND 255
        AND restricted_reference !~ '[[:cntrl:]]'
    ),
    CONSTRAINT report_evidence_digest_check CHECK (octet_length(content_digest) = 32),
    CONSTRAINT report_evidence_unique UNIQUE (report_id, content_digest)
);

CREATE TABLE safety.report_state_events (
    id uuid PRIMARY KEY,
    report_id uuid NOT NULL REFERENCES safety.reports(id),
    from_state text COLLATE "C",
    to_state text COLLATE "C" NOT NULL,
    action_state text COLLATE "C" NOT NULL,
    actor_account_id uuid REFERENCES identity.accounts(id),
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit.events(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT report_state_events_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT report_state_events_from_check CHECK (
        from_state IS NULL OR from_state IN ('submitted', 'triaged', 'investigating', 'resolved')
    ),
    CONSTRAINT report_state_events_to_check CHECK (
        to_state IN ('submitted', 'triaged', 'investigating', 'resolved')
    )
);

CREATE TRIGGER report_state_events_reject_update
BEFORE UPDATE OR DELETE ON safety.report_state_events
FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

CREATE TABLE safety.restrictions (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES identity.accounts(id),
    report_id uuid REFERENCES safety.reports(id),
    restriction_type text COLLATE "C" NOT NULL,
    reason_code varchar(64) COLLATE "C" NOT NULL,
    starts_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at timestamptz,
    ended_at timestamptz,
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit.events(id),
    ended_audit_event_id uuid UNIQUE REFERENCES audit.events(id),
    CONSTRAINT restrictions_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT restrictions_type_check CHECK (
        restriction_type IN ('discovery_block', 'temporary_suspension', 'permanent_removal')
    ),
    CONSTRAINT restrictions_expiry_check CHECK (
        (restriction_type = 'temporary_suspension' AND expires_at IS NOT NULL AND expires_at > starts_at)
        OR (restriction_type <> 'temporary_suspension' AND expires_at IS NULL)
    ),
    CONSTRAINT restrictions_end_shape_check CHECK (
        (ended_at IS NULL AND ended_audit_event_id IS NULL)
        OR (ended_at IS NOT NULL AND ended_audit_event_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX restrictions_active_type_idx
    ON safety.restrictions(account_id, restriction_type)
    WHERE ended_at IS NULL;

CREATE INDEX restrictions_active_account_idx
    ON safety.restrictions(account_id, expires_at)
    WHERE ended_at IS NULL;

ALTER TABLE identity.account_blocks
    ADD COLUMN report_id uuid REFERENCES safety.reports(id);

CREATE TABLE safety.moderation_actions (
    id uuid PRIMARY KEY,
    report_id uuid NOT NULL REFERENCES safety.reports(id),
    administrator_account_id uuid REFERENCES identity.accounts(id),
    action text COLLATE "C" NOT NULL,
    reason_code varchar(64) COLLATE "C" NOT NULL,
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit.events(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT moderation_actions_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT moderation_actions_action_check CHECK (
        action IN ('triaged', 'assigned', 'warning', 'temporary_suspension',
                   'permanent_removal', 'no_action', 'resolved', 'restriction_lifted')
    )
);

CREATE VIEW safety.subject_report_status AS
SELECT id, report_token, subject_account_id, category, severity, triage_state,
       action_state, resolution_code, resolution_summary, created_at, resolved_at
FROM safety.reports;

CREATE OR REPLACE FUNCTION safety.report_participants_match()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, safety, connection
AS $$
DECLARE
    customer_id uuid;
    professional_id uuid;
BEGIN
    SELECT customer_account_id, professional_account_id
    INTO customer_id, professional_id
    FROM connection.contact_reveals WHERE id = NEW.reveal_id;
    IF NOT FOUND OR NOT (
        (NEW.reporter_account_id = customer_id AND NEW.subject_account_id = professional_id)
        OR (NEW.reporter_account_id = professional_id AND NEW.subject_account_id = customer_id)
    ) THEN
        RAISE EXCEPTION 'report participants do not match introduction';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER reports_validate_participants
BEFORE INSERT ON safety.reports
FOR EACH ROW EXECUTE FUNCTION safety.report_participants_match();

CREATE OR REPLACE FUNCTION safety.account_is_restricted(candidate_account_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, safety
AS $$
    SELECT EXISTS (
        SELECT 1 FROM safety.restrictions
        WHERE account_id = candidate_account_id
          AND ended_at IS NULL
          AND (expires_at IS NULL OR expires_at > statement_timestamp())
    )
$$;

CREATE TABLE billing.plans (
    id uuid PRIMARY KEY,
    code varchar(64) COLLATE "C" NOT NULL UNIQUE,
    provider_plan_id varchar(64) COLLATE "C" UNIQUE,
    name varchar(96) NOT NULL,
    amount_minor bigint NOT NULL,
    currency char(3) COLLATE "C" NOT NULL,
    interval_unit text COLLATE "C" NOT NULL,
    interval_count smallint NOT NULL,
    tax_treatment text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'configured',
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT plans_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT plans_amount_check CHECK (amount_minor > 0),
    CONSTRAINT plans_currency_check CHECK (currency = 'INR'),
    CONSTRAINT plans_interval_check CHECK (interval_unit = 'monthly' AND interval_count = 1),
    CONSTRAINT plans_tax_check CHECK (tax_treatment IN ('pending_accountant_confirmation', 'inclusive', 'exclusive')),
    CONSTRAINT plans_state_check CHECK (state IN ('configured', 'active', 'retired'))
);

INSERT INTO billing.plans (
    id, code, name, amount_minor, currency, interval_unit, interval_count, tax_treatment
) VALUES (
    uuidv7(), 'professional_monthly_inr_99', 'Sahayak Professional Monthly',
    9900, 'INR', 'monthly', 1, 'pending_accountant_confirmation'
);

CREATE TABLE billing.subscriptions (
    id uuid PRIMARY KEY,
    professional_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    plan_id uuid NOT NULL REFERENCES billing.plans(id),
    provider_customer_id varchar(64) COLLATE "C",
    provider_subscription_id varchar(64) COLLATE "C" UNIQUE,
    hosted_payment_url varchar(2048),
    status text COLLATE "C" NOT NULL,
    billing_period_start timestamptz,
    billing_period_end timestamptz,
    grace_period_end timestamptz,
    cancel_at_cycle_end boolean NOT NULL DEFAULT false,
    cancelled_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT subscriptions_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT subscriptions_status_check CHECK (
        status IN ('pending_payment', 'authenticated', 'active', 'past_due',
                   'halted', 'cancelled', 'expired')
    ),
    CONSTRAINT subscriptions_period_check CHECK (
        billing_period_end IS NULL OR (
            billing_period_start IS NOT NULL AND billing_period_end > billing_period_start
        )
    ),
    CONSTRAINT subscriptions_grace_check CHECK (
        grace_period_end IS NULL OR billing_period_end IS NULL OR grace_period_end >= billing_period_end
    ),
    CONSTRAINT subscriptions_cancel_check CHECK (
        cancelled_at IS NULL OR status IN ('cancelled', 'expired')
    )
);

CREATE UNIQUE INDEX subscriptions_one_current_idx
    ON billing.subscriptions(professional_account_id)
    WHERE status IN ('pending_payment', 'authenticated', 'active', 'past_due', 'halted');

CREATE INDEX subscriptions_reconcile_idx
    ON billing.subscriptions(updated_at, id)
    WHERE status IN ('pending_payment', 'authenticated', 'active', 'past_due', 'halted');

CREATE TRIGGER subscriptions_touch_version
BEFORE UPDATE ON billing.subscriptions
FOR EACH ROW EXECUTE FUNCTION identity.touch_versioned_row();

CREATE TABLE billing.professional_entitlements (
    professional_account_id uuid PRIMARY KEY REFERENCES identity.accounts(id),
    free_reservation_connection_request_id uuid UNIQUE
        REFERENCES connection.connection_requests(id),
    free_qualified_introduction_reveal_id uuid UNIQUE REFERENCES connection.contact_reveals(id),
    subscription_id uuid REFERENCES billing.subscriptions(id),
    status text COLLATE "C" NOT NULL DEFAULT 'not_required_during_free_value',
    manually_waived_until timestamptz,
    version bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT professional_entitlements_status_check CHECK (
        status IN ('not_required_during_free_value', 'payment_required', 'pending_payment',
                   'active', 'past_due', 'expired', 'manually_waived')
    ),
    CONSTRAINT professional_entitlements_free_shape_check CHECK (
        free_reservation_connection_request_id IS NULL
        OR free_qualified_introduction_reveal_id IS NULL
    ),
    CONSTRAINT professional_entitlements_waiver_check CHECK (
        (status = 'manually_waived' AND manually_waived_until IS NOT NULL)
        OR (status <> 'manually_waived' AND manually_waived_until IS NULL)
    )
);

CREATE TRIGGER professional_entitlements_touch_version
BEFORE UPDATE ON billing.professional_entitlements
FOR EACH ROW EXECUTE FUNCTION identity.touch_versioned_row();

CREATE TABLE billing.payments (
    id uuid PRIMARY KEY,
    subscription_id uuid NOT NULL REFERENCES billing.subscriptions(id),
    provider_payment_id varchar(64) COLLATE "C" NOT NULL UNIQUE,
    provider_invoice_id varchar(64) COLLATE "C" UNIQUE,
    provider_order_id varchar(64) COLLATE "C",
    amount_minor bigint NOT NULL,
    currency char(3) COLLATE "C" NOT NULL,
    tax_treatment text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL,
    invoice_reference varchar(128),
    receipt_reference varchar(128),
    failure_code varchar(96) COLLATE "C",
    paid_at timestamptz,
    reconciled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT payments_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT payments_amount_check CHECK (amount_minor > 0),
    CONSTRAINT payments_currency_check CHECK (currency = 'INR'),
    CONSTRAINT payments_tax_check CHECK (tax_treatment IN ('pending_accountant_confirmation', 'inclusive', 'exclusive')),
    CONSTRAINT payments_status_check CHECK (status IN ('created', 'authorized', 'captured', 'failed', 'refunded')),
    CONSTRAINT payments_paid_shape_check CHECK (
        (status = 'captured' AND paid_at IS NOT NULL AND failure_code IS NULL)
        OR (status = 'failed' AND paid_at IS NULL AND failure_code IS NOT NULL)
        OR status IN ('created', 'authorized', 'refunded')
    )
);

CREATE INDEX payments_subscription_idx
    ON billing.payments(subscription_id, created_at DESC, id);

CREATE TABLE billing.tax_documents (
    id uuid PRIMARY KEY,
    payment_id uuid NOT NULL UNIQUE REFERENCES billing.payments(id),
    provider_invoice_id varchar(64) COLLATE "C" NOT NULL UNIQUE,
    invoice_reference varchar(128) NOT NULL,
    gst_treatment text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'provider_reference_recorded',
    reconciled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT tax_documents_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT tax_documents_gst_check CHECK (
        gst_treatment IN ('pending_accountant_confirmation', 'inclusive', 'exclusive')
    ),
    CONSTRAINT tax_documents_status_check CHECK (
        status IN ('provider_reference_recorded', 'issued', 'reconciled', 'exception')
    ),
    CONSTRAINT tax_documents_reconciled_check CHECK (
        (status = 'reconciled' AND reconciled_at IS NOT NULL)
        OR (status <> 'reconciled' AND reconciled_at IS NULL)
    )
);

CREATE TABLE billing.webhook_events (
    id uuid PRIMARY KEY,
    provider text COLLATE "C" NOT NULL DEFAULT 'razorpay',
    provider_event_id varchar(128) COLLATE "C" NOT NULL,
    event_type varchar(96) COLLATE "C" NOT NULL,
    signature_verified boolean NOT NULL,
    normalized_payload jsonb NOT NULL,
    processing_state text COLLATE "C" NOT NULL DEFAULT 'pending',
    attempt_count smallint NOT NULL DEFAULT 0,
    processed_at timestamptz,
    terminal_failure_code varchar(96) COLLATE "C",
    received_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT billing_webhook_events_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT billing_webhook_provider_check CHECK (provider = 'razorpay'),
    CONSTRAINT billing_webhook_signature_check CHECK (signature_verified),
    CONSTRAINT billing_webhook_payload_check CHECK (
        jsonb_typeof(normalized_payload) = 'object'
        AND octet_length(normalized_payload::text) <= 32768
    ),
    CONSTRAINT billing_webhook_state_check CHECK (
        processing_state IN ('pending', 'processing', 'processed', 'failed')
    ),
    CONSTRAINT billing_webhook_attempt_check CHECK (attempt_count BETWEEN 0 AND 20),
    CONSTRAINT billing_webhook_completion_check CHECK (
        (processing_state = 'processed' AND processed_at IS NOT NULL AND terminal_failure_code IS NULL)
        OR (processing_state = 'failed' AND processed_at IS NOT NULL AND terminal_failure_code IS NOT NULL)
        OR (processing_state IN ('pending', 'processing') AND processed_at IS NULL)
    ),
    CONSTRAINT billing_webhook_event_unique UNIQUE (provider, provider_event_id)
);

CREATE INDEX billing_webhook_pending_idx
    ON billing.webhook_events(received_at, id)
    WHERE processing_state = 'pending';

CREATE TABLE billing.reconciliation_runs (
    id uuid PRIMARY KEY,
    started_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    completed_at timestamptz,
    checked_count integer NOT NULL DEFAULT 0,
    exception_count integer NOT NULL DEFAULT 0,
    status text COLLATE "C" NOT NULL DEFAULT 'running',
    CONSTRAINT reconciliation_runs_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT reconciliation_runs_counts_check CHECK (checked_count >= 0 AND exception_count >= 0),
    CONSTRAINT reconciliation_runs_status_check CHECK (status IN ('running', 'completed', 'failed')),
    CONSTRAINT reconciliation_runs_completion_check CHECK (
        (status = 'running' AND completed_at IS NULL)
        OR (status <> 'running' AND completed_at IS NOT NULL)
    )
);

CREATE TABLE billing.reconciliation_exceptions (
    id uuid PRIMARY KEY,
    run_id uuid REFERENCES billing.reconciliation_runs(id),
    subscription_id uuid REFERENCES billing.subscriptions(id),
    payment_id uuid REFERENCES billing.payments(id),
    reason_code varchar(96) COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'open',
    assigned_administrator_id uuid REFERENCES identity.accounts(id),
    resolution_summary varchar(500),
    resolved_at timestamptz,
    audit_event_id uuid REFERENCES audit.events(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT reconciliation_exceptions_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT reconciliation_exceptions_target_check CHECK (
        subscription_id IS NOT NULL OR payment_id IS NOT NULL
    ),
    CONSTRAINT reconciliation_exceptions_state_check CHECK (state IN ('open', 'investigating', 'resolved')),
    CONSTRAINT reconciliation_exceptions_resolution_check CHECK (
        (state = 'resolved' AND resolved_at IS NOT NULL AND audit_event_id IS NOT NULL)
        OR (state <> 'resolved' AND resolved_at IS NULL)
    )
);

CREATE TABLE billing.payment_reminders (
    id uuid PRIMARY KEY,
    professional_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    subscription_id uuid REFERENCES billing.subscriptions(id),
    reminder_kind text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'pending',
    due_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    claim_token uuid,
    claimed_at timestamptz,
    outbound_message_id uuid REFERENCES messaging.outbound_messages(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    completed_at timestamptz,
    CONSTRAINT payment_reminders_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT payment_reminders_kind_check CHECK (reminder_kind IN ('payment_required', 'past_due')),
    CONSTRAINT payment_reminders_state_check CHECK (state IN ('pending', 'processing', 'sent', 'cancelled')),
    CONSTRAINT payment_reminders_claim_check CHECK (
        (state = 'processing' AND claim_token IS NOT NULL AND claimed_at IS NOT NULL)
        OR (state <> 'processing' AND claim_token IS NULL AND claimed_at IS NULL)
    ),
    CONSTRAINT payment_reminders_completion_check CHECK (
        (state = 'sent' AND completed_at IS NOT NULL AND outbound_message_id IS NOT NULL)
        OR (state <> 'sent' AND completed_at IS NULL)
    )
);

CREATE UNIQUE INDEX payment_reminders_one_actionable_idx
    ON billing.payment_reminders(professional_account_id, reminder_kind)
    WHERE state IN ('pending', 'processing');

CREATE INDEX payment_reminders_due_idx
    ON billing.payment_reminders(due_at, id) WHERE state = 'pending';

CREATE OR REPLACE FUNCTION billing.schedule_payment_reminder()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IN ('payment_required', 'past_due')
       AND (TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM NEW.status) THEN
        INSERT INTO billing.payment_reminders (
            id, professional_account_id, subscription_id, reminder_kind
        ) VALUES (uuidv7(), NEW.professional_account_id, NEW.subscription_id, NEW.status)
        ON CONFLICT (professional_account_id, reminder_kind)
            WHERE state IN ('pending', 'processing') DO NOTHING;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER professional_entitlements_schedule_reminder
AFTER INSERT OR UPDATE OF status ON billing.professional_entitlements
FOR EACH ROW EXECUTE FUNCTION billing.schedule_payment_reminder();

CREATE OR REPLACE FUNCTION billing.professional_is_eligible(candidate_account_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, billing
AS $$
    SELECT COALESCE((
        SELECT (status = 'not_required_during_free_value'
                AND free_reservation_connection_request_id IS NULL
                AND free_qualified_introduction_reveal_id IS NULL)
            OR status = 'active'
            OR (status = 'past_due' AND EXISTS (
                SELECT 1 FROM billing.subscriptions
                WHERE id = entitlement.subscription_id
                  AND grace_period_end > statement_timestamp()
            ))
            OR (status = 'manually_waived' AND manually_waived_until > statement_timestamp())
        FROM billing.professional_entitlements AS entitlement
        WHERE professional_account_id = candidate_account_id
    ), true)
$$;

CREATE OR REPLACE FUNCTION billing.reservation_matches(
    candidate_account_id uuid,
    candidate_connection_request_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, billing
AS $$
    SELECT EXISTS (
        SELECT 1 FROM billing.professional_entitlements
        WHERE professional_account_id = candidate_account_id
          AND status = 'not_required_during_free_value'
          AND free_reservation_connection_request_id = candidate_connection_request_id
    )
$$;

CREATE OR REPLACE FUNCTION billing.reserve_free_connection()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, billing, connection
AS $$
BEGIN
    IF NEW.contact_mode = 'approval_required' AND NEW.status = 'pending' THEN
        INSERT INTO billing.professional_entitlements (
            professional_account_id, free_reservation_connection_request_id, status
        ) VALUES (
            NEW.professional_account_id, NEW.id, 'not_required_during_free_value'
        ) ON CONFLICT (professional_account_id) DO NOTHING;
        IF NOT billing.reservation_matches(NEW.professional_account_id, NEW.id)
           AND NOT billing.professional_is_eligible(NEW.professional_account_id) THEN
            RAISE EXCEPTION 'professional free introduction is already reserved';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER connection_request_reserve_free_value
AFTER INSERT ON connection.connection_requests
DEFERRABLE INITIALLY IMMEDIATE
FOR EACH ROW EXECUTE FUNCTION billing.reserve_free_connection();

CREATE OR REPLACE FUNCTION billing.attach_free_reveal()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, billing
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM billing.professional_entitlements
        WHERE professional_account_id = NEW.professional_account_id
          AND status <> 'not_required_during_free_value'
    ) THEN
        RETURN NULL;
    END IF;
    INSERT INTO billing.professional_entitlements (
        professional_account_id, free_qualified_introduction_reveal_id, status
    ) VALUES (
        NEW.professional_account_id, NEW.id, 'not_required_during_free_value'
    ) ON CONFLICT (professional_account_id) DO UPDATE SET
        free_reservation_connection_request_id = NULL,
        free_qualified_introduction_reveal_id = CASE
            WHEN billing.professional_entitlements.status = 'not_required_during_free_value'
             AND (
                 billing.professional_entitlements.free_reservation_connection_request_id = NEW.connection_request_id
                 OR billing.professional_entitlements.free_qualified_introduction_reveal_id IS NULL
             )
            THEN NEW.id
            ELSE billing.professional_entitlements.free_qualified_introduction_reveal_id
        END;
    IF NOT EXISTS (
        SELECT 1 FROM billing.professional_entitlements
        WHERE professional_account_id = NEW.professional_account_id
          AND free_qualified_introduction_reveal_id = NEW.id
    ) THEN
        RAISE EXCEPTION 'professional free introduction reservation does not match reveal';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER contact_reveal_attach_free_value
AFTER INSERT ON connection.contact_reveals
DEFERRABLE INITIALLY IMMEDIATE
FOR EACH ROW EXECUTE FUNCTION billing.attach_free_reveal();

CREATE OR REPLACE FUNCTION billing.release_unused_reservation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, billing
AS $$
BEGIN
    IF OLD.status = 'pending' AND NEW.status IN ('declined', 'expired', 'cancelled')
       AND NEW.disclosure_id IS NULL THEN
        DELETE FROM billing.professional_entitlements
        WHERE professional_account_id = NEW.professional_account_id
          AND status = 'not_required_during_free_value'
          AND free_reservation_connection_request_id = NEW.id
          AND free_qualified_introduction_reveal_id IS NULL;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER connection_request_release_free_value
AFTER UPDATE OF status ON connection.connection_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION billing.release_unused_reservation();

CREATE OR REPLACE FUNCTION billing.consume_first_qualified_introduction()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, billing, connection
AS $$
DECLARE
    professional_id uuid;
BEGIN
    IF NEW.qualified_state = 'qualified'
       AND OLD.qualified_state IS DISTINCT FROM NEW.qualified_state THEN
        SELECT professional_account_id INTO professional_id
        FROM connection.contact_reveals WHERE id = NEW.reveal_id;
        INSERT INTO billing.professional_entitlements (
            professional_account_id, free_qualified_introduction_reveal_id, status
        ) VALUES (professional_id, NEW.reveal_id, 'payment_required')
        ON CONFLICT (professional_account_id) DO UPDATE SET
            free_reservation_connection_request_id = NULL,
            free_qualified_introduction_reveal_id = NEW.reveal_id,
            status = 'payment_required'
        WHERE billing.professional_entitlements.status = 'not_required_during_free_value'
          AND billing.professional_entitlements.free_qualified_introduction_reveal_id = NEW.reveal_id;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER contact_delivery_consume_free_value
AFTER UPDATE OF qualified_state ON connection.contact_reveal_delivery
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION billing.consume_first_qualified_introduction();

CREATE OR REPLACE FUNCTION billing.release_reversed_free_value()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, billing
AS $$
BEGIN
    DELETE FROM billing.professional_entitlements
    WHERE free_qualified_introduction_reveal_id = NEW.reveal_id
      AND status = 'not_required_during_free_value';
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER reveal_reversal_release_free_value
AFTER INSERT ON connection.reveal_reversals
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION billing.release_reversed_free_value();

CREATE OR REPLACE FUNCTION safety.classify_severe_report()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.severity IN ('high', 'critical') THEN
        NEW.action_state := CASE
            WHEN NEW.severity = 'critical' THEN 'suspended_pending_review'
            ELSE 'restricted_pending_review'
        END;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER reports_classify_severe
BEFORE INSERT ON safety.reports
FOR EACH ROW EXECUTE FUNCTION safety.classify_severe_report();

CREATE OR REPLACE FUNCTION safety.apply_severe_report_restriction()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, safety, audit
AS $$
DECLARE
    restriction_audit_id uuid := uuidv7();
BEGIN
    IF NEW.severity IN ('high', 'critical') THEN
        INSERT INTO audit.events (
            id, actor_type, source_channel, action, target_type, target_id,
            reason_code, metadata, event_schema_version, correlation_id
        ) VALUES (
            restriction_audit_id, 'system', 'system', 'safety.auto_restrict',
            'account', NEW.subject_account_id, 'severe_report',
            jsonb_build_object('report_id', NEW.id, 'severity', NEW.severity), 1, uuidv7()
        );
        INSERT INTO safety.restrictions (
            id, account_id, report_id, restriction_type, reason_code, expires_at, audit_event_id
        ) VALUES (
            uuidv7(), NEW.subject_account_id, NEW.id,
            CASE WHEN NEW.severity = 'critical' THEN 'temporary_suspension' ELSE 'discovery_block' END,
            'severe_report',
            CASE WHEN NEW.severity = 'critical' THEN statement_timestamp() + INTERVAL '24 hours' ELSE NULL END,
            restriction_audit_id
        ) ON CONFLICT (account_id, restriction_type) WHERE ended_at IS NULL DO NOTHING;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER reports_apply_severe_restriction
AFTER INSERT ON safety.reports
FOR EACH ROW EXECUTE FUNCTION safety.apply_severe_report_restriction();

CREATE TRIGGER reports_guard
BEFORE INSERT OR UPDATE OR DELETE ON safety.reports
FOR EACH ROW EXECUTE FUNCTION safety.reject_direct_mutation();

CREATE TRIGGER report_evidence_guard
BEFORE INSERT OR UPDATE OR DELETE ON safety.report_evidence
FOR EACH ROW EXECUTE FUNCTION safety.reject_direct_mutation();

CREATE TRIGGER restrictions_guard
BEFORE INSERT OR UPDATE OR DELETE ON safety.restrictions
FOR EACH ROW EXECUTE FUNCTION safety.reject_direct_mutation();

CREATE TRIGGER moderation_actions_guard
BEFORE INSERT OR UPDATE OR DELETE ON safety.moderation_actions
FOR EACH ROW EXECUTE FUNCTION safety.reject_direct_mutation();

COMMENT ON VIEW safety.subject_report_status IS
    'Subject-safe report projection that intentionally excludes reporter identity and private evidence.';
COMMENT ON COLUMN billing.plans.amount_minor IS
    'Exact integer minor units; INR 99 is stored as 9900 paise.';

ALTER TABLE messaging.conversation_sessions
    DROP CONSTRAINT conversation_sessions_workflow_role_check;

ALTER TABLE messaging.conversation_sessions
    ADD CONSTRAINT conversation_sessions_workflow_role_check
    CHECK (
        status <> 'active'
        OR (
            (workflow_key IN ('professional.profile', 'professional.availability', 'professional.requests')
             AND role_context = 'professional')
            OR (workflow_key IN ('administrator.review', 'administrator.safety')
                AND role_context = 'administrator')
            OR (workflow_key = 'trust.safety' AND role_context IN ('customer', 'professional'))
            OR (
                workflow_key NOT IN (
                    'professional.profile', 'professional.availability',
                    'professional.requests', 'administrator.review',
                    'administrator.safety', 'trust.safety'
                )
                AND role_context = 'customer'
            )
        )
    );
