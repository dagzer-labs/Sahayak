CREATE SCHEMA IF NOT EXISTS availability;

CREATE OR REPLACE FUNCTION availability.calculate_expiry(
    duration_code text,
    time_zone_name text,
    starts_at timestamptz
)
RETURNS timestamptz
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = time_zone_name) THEN
        RAISE EXCEPTION 'availability time zone is not a recognized IANA zone';
    END IF;
    IF duration_code = 'one_hour' THEN
        RETURN starts_at + INTERVAL '1 hour';
    ELSIF duration_code = 'four_hours' THEN
        RETURN starts_at + INTERVAL '4 hours';
    ELSIF duration_code = 'end_of_local_day' THEN
        RETURN (((starts_at AT TIME ZONE time_zone_name)::date + 1)::timestamp
            AT TIME ZONE time_zone_name);
    END IF;
    RAISE EXCEPTION 'availability duration is unsupported' USING ERRCODE = '22023';
END;
$$;

CREATE TABLE availability.epochs (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    profile_revision_id uuid NOT NULL,
    started_by_channel_identity_id uuid NOT NULL,
    started_from_inbound_event_id uuid NOT NULL,
    predecessor_epoch_id uuid,
    generation bigint NOT NULL,
    state text COLLATE "C" NOT NULL,
    duration_code text COLLATE "C" NOT NULL,
    time_zone_snapshot varchar(64) NOT NULL,
    local_end_date date,
    starts_at timestamptz NOT NULL,
    last_confirmed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    contact_limit smallint NOT NULL,
    contact_count smallint NOT NULL DEFAULT 0,
    stopped_at timestamptz,
    paused_at timestamptz,
    terminal_at timestamptz,
    terminal_reason text COLLATE "C",
    correlation_id uuid NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT availability_epochs_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT availability_epochs_profile_fk
        FOREIGN KEY (account_id, profile_id)
        REFERENCES profile.public_profiles(account_id, id)
        ON DELETE CASCADE,
    CONSTRAINT availability_epochs_revision_fk
        FOREIGN KEY (profile_id, profile_revision_id)
        REFERENCES profile.profile_revisions(profile_id, id)
        ON DELETE CASCADE,
    CONSTRAINT availability_epochs_channel_fk
        FOREIGN KEY (account_id, started_by_channel_identity_id)
        REFERENCES identity.channel_identities(account_id, id),
    CONSTRAINT availability_epochs_inbound_fk
        FOREIGN KEY (started_from_inbound_event_id)
        REFERENCES integration.inbound_events(id),
    CONSTRAINT availability_epochs_predecessor_fk
        FOREIGN KEY (predecessor_epoch_id)
        REFERENCES availability.epochs(id),
    CONSTRAINT availability_epochs_source_unique UNIQUE (started_from_inbound_event_id),
    CONSTRAINT availability_epochs_generation_unique UNIQUE (profile_id, generation),
    CONSTRAINT availability_epochs_successor_unique UNIQUE (predecessor_epoch_id),
    CONSTRAINT availability_epochs_state_check CHECK (
        state IN (
            'scheduled', 'available', 'stopped', 'paused_contact_limit',
            'expired', 'cancelled_manual', 'cancelled_ineligible'
        )
    ),
    CONSTRAINT availability_epochs_duration_check CHECK (
        duration_code IN ('one_hour', 'four_hours', 'end_of_local_day')
    ),
    CONSTRAINT availability_epochs_time_zone_check CHECK (
        time_zone_snapshot = btrim(time_zone_snapshot)
        AND octet_length(time_zone_snapshot) BETWEEN 1 AND 64
    ),
    CONSTRAINT availability_epochs_time_check CHECK (
        starts_at < expires_at
        AND last_confirmed_at < expires_at
        AND expires_at <= starts_at + INTERVAL '26 hours'
    ),
    CONSTRAINT availability_epochs_end_of_day_check CHECK (
        (duration_code = 'end_of_local_day' AND local_end_date IS NOT NULL)
        OR (duration_code <> 'end_of_local_day' AND local_end_date IS NULL)
    ),
    CONSTRAINT availability_epochs_capacity_check CHECK (
        contact_limit BETWEEN 1 AND 10
        AND contact_count BETWEEN 0 AND contact_limit
    ),
    CONSTRAINT availability_epochs_generation_check CHECK (generation > 0),
    CONSTRAINT availability_epochs_state_shape_check CHECK (
        (
            state = 'scheduled'
            AND predecessor_epoch_id IS NOT NULL
            AND contact_count = 0
            AND stopped_at IS NULL AND paused_at IS NULL
            AND terminal_at IS NULL AND terminal_reason IS NULL
        )
        OR (
            state = 'available'
            AND contact_count < contact_limit
            AND stopped_at IS NULL AND paused_at IS NULL
            AND terminal_at IS NULL AND terminal_reason IS NULL
        )
        OR (
            state = 'stopped'
            AND stopped_at IS NOT NULL
            AND paused_at IS NULL
            AND terminal_at IS NULL AND terminal_reason IS NULL
        )
        OR (
            state = 'paused_contact_limit'
            AND contact_count = contact_limit
            AND paused_at IS NOT NULL
            AND stopped_at IS NULL
            AND terminal_at IS NULL AND terminal_reason IS NULL
        )
        OR (
            state = 'expired'
            AND terminal_at IS NOT NULL
            AND terminal_reason = 'natural_expiry'
        )
        OR (
            state IN ('cancelled_manual', 'cancelled_ineligible')
            AND terminal_at IS NOT NULL
            AND terminal_reason IS NOT NULL
        )
    ),
    CONSTRAINT availability_epochs_terminal_reason_check CHECK (
        terminal_reason IS NULL
        OR terminal_reason IN (
            'natural_expiry', 'renewal_cancelled_by_stop', 'eligibility_changed',
            'published_revision_changed', 'account_suspended', 'account_deletion',
            'role_revoked', 'profile_hidden', 'consent_revoked'
        )
    )
);

CREATE UNIQUE INDEX availability_epochs_one_current_idx
    ON availability.epochs(profile_id)
    WHERE state IN ('available', 'stopped', 'paused_contact_limit');

CREATE UNIQUE INDEX availability_epochs_one_scheduled_idx
    ON availability.epochs(profile_id)
    WHERE state = 'scheduled';

CREATE INDEX availability_epochs_due_idx
    ON availability.epochs(expires_at, id)
    WHERE state IN ('available', 'stopped', 'paused_contact_limit');

CREATE INDEX availability_epochs_effective_revision_idx
    ON availability.epochs(profile_revision_id, starts_at, expires_at)
    INCLUDE (id, profile_id, generation, contact_count, contact_limit)
    WHERE state IN ('scheduled', 'available');

CREATE INDEX availability_epochs_account_history_idx
    ON availability.epochs(account_id, created_at DESC, id DESC);

CREATE TRIGGER availability_epochs_set_updated_at
BEFORE UPDATE ON availability.epochs
FOR EACH ROW EXECUTE FUNCTION identity.touch_versioned_row();

CREATE TABLE availability.mutation_events (
    id uuid PRIMARY KEY,
    epoch_id uuid NOT NULL REFERENCES availability.epochs(id) ON DELETE CASCADE,
    account_id uuid NOT NULL REFERENCES identity.accounts(id),
    source_inbound_event_id uuid REFERENCES integration.inbound_events(id),
    action text COLLATE "C" NOT NULL,
    duration_code text COLLATE "C",
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit.events(id),
    correlation_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT availability_mutation_events_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT availability_mutation_events_action_check CHECK (
        action IN (
            'started', 'resumed', 'stopped', 'successor_scheduled',
            'successor_replaced', 'successor_cancelled', 'expired',
            'successor_activated', 'auto_paused', 'invalidated'
        )
    ),
    CONSTRAINT availability_mutation_events_duration_check CHECK (
        (
            action IN ('started', 'successor_scheduled', 'successor_replaced')
            AND duration_code IN ('one_hour', 'four_hours', 'end_of_local_day')
        )
        OR (
            action NOT IN ('started', 'successor_scheduled', 'successor_replaced')
            AND duration_code IS NULL
        )
    ),
    CONSTRAINT availability_mutation_events_source_unique UNIQUE (source_inbound_event_id),
    CONSTRAINT availability_mutation_events_epoch_action_unique UNIQUE (epoch_id, action, occurred_at)
);

CREATE INDEX availability_mutation_events_rate_idx
    ON availability.mutation_events(account_id, occurred_at DESC)
    WHERE action IN ('started', 'resumed', 'successor_scheduled', 'successor_replaced');

CREATE TABLE availability.capacity_consumptions (
    id uuid PRIMARY KEY,
    epoch_id uuid NOT NULL REFERENCES availability.epochs(id) ON DELETE CASCADE,
    operation_key uuid NOT NULL,
    category_code varchar(32) COLLATE "C" NOT NULL
        REFERENCES profile.service_categories(code) ON DELETE RESTRICT,
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit.events(id),
    consumed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT availability_capacity_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT availability_capacity_operation_unique UNIQUE (epoch_id, operation_key)
);

CREATE INDEX availability_capacity_consumed_idx
    ON availability.capacity_consumptions(epoch_id, category_code, consumed_at, id);

CREATE TABLE availability.notification_events (
    id uuid PRIMARY KEY,
    epoch_id uuid NOT NULL REFERENCES availability.epochs(id) ON DELETE CASCADE,
    account_id uuid NOT NULL REFERENCES identity.accounts(id),
    purpose text COLLATE "C" NOT NULL,
    outbound_message_id uuid UNIQUE REFERENCES messaging.outbound_messages(id),
    occurred_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT availability_notifications_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT availability_notifications_purpose_check CHECK (
        purpose IN ('expiry_reminder', 'expired', 'contact_limit_paused')
    ),
    CONSTRAINT availability_notifications_once_unique UNIQUE (epoch_id, purpose)
);

CREATE INDEX availability_notifications_throttle_idx
    ON availability.notification_events(account_id, purpose, occurred_at DESC);

CREATE OR REPLACE FUNCTION availability.reject_direct_epoch_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('sahayak.account_erasure', true) = 'on' THEN
        RETURN OLD;
    END IF;
    IF current_setting('sahayak.availability_mutation', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'availability epochs require the guarded domain transaction';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER availability_epochs_guard_mutation
BEFORE INSERT OR UPDATE OR DELETE ON availability.epochs
FOR EACH ROW EXECUTE FUNCTION availability.reject_direct_epoch_mutation();

CREATE TRIGGER availability_mutation_events_reject_mutation
BEFORE UPDATE OR DELETE ON availability.mutation_events
FOR EACH ROW EXECUTE FUNCTION private_data.reject_mutation_except_account_erasure();

CREATE TRIGGER availability_capacity_reject_mutation
BEFORE UPDATE OR DELETE ON availability.capacity_consumptions
FOR EACH ROW EXECUTE FUNCTION private_data.reject_mutation_except_account_erasure();

CREATE TRIGGER availability_notifications_reject_mutation
BEFORE UPDATE OR DELETE ON availability.notification_events
FOR EACH ROW EXECUTE FUNCTION private_data.reject_mutation_except_account_erasure();

CREATE TRIGGER availability_mutation_events_reject_truncate
BEFORE TRUNCATE ON availability.mutation_events
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER availability_capacity_reject_truncate
BEFORE TRUNCATE ON availability.capacity_consumptions
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER availability_notifications_reject_truncate
BEFORE TRUNCATE ON availability.notification_events
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

CREATE OR REPLACE FUNCTION availability.capacity_count_matches_epoch()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_epoch_id uuid;
    persisted_count integer;
    ledger_count integer;
BEGIN
    IF TG_TABLE_NAME = 'epochs' THEN
        target_epoch_id := COALESCE(NEW.id, OLD.id);
    ELSE
        target_epoch_id := COALESCE(NEW.epoch_id, OLD.epoch_id);
    END IF;
    SELECT contact_count INTO persisted_count
    FROM availability.epochs
    WHERE id = target_epoch_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT count(*) INTO ledger_count
    FROM availability.capacity_consumptions
    WHERE epoch_id = target_epoch_id;
    IF persisted_count <> ledger_count THEN
        RAISE EXCEPTION 'availability capacity ledger does not match epoch count';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER availability_capacity_count_constraint
AFTER INSERT OR DELETE ON availability.capacity_consumptions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION availability.capacity_count_matches_epoch();

CREATE CONSTRAINT TRIGGER availability_epoch_count_constraint
AFTER UPDATE OF contact_count ON availability.epochs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION availability.capacity_count_matches_epoch();

CREATE OR REPLACE FUNCTION availability.epoch_is_effective(candidate_epoch_id uuid)
RETURNS boolean
LANGUAGE sql
VOLATILE
SET search_path = pg_catalog, availability, profile, identity, private_data
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM availability.epochs AS epoch
        JOIN profile.public_profiles AS root
          ON root.id = epoch.profile_id AND root.account_id = epoch.account_id
        JOIN profile.profile_revisions AS revision
          ON revision.id = epoch.profile_revision_id AND revision.profile_id = root.id
        JOIN identity.accounts AS account ON account.id = epoch.account_id
        WHERE epoch.id = candidate_epoch_id
          AND epoch.state IN ('available', 'scheduled')
          AND epoch.starts_at <= clock_timestamp()
          AND clock_timestamp() < epoch.expires_at
          AND epoch.contact_count < epoch.contact_limit
          AND root.visibility = 'published'
          AND root.published_revision_id = epoch.profile_revision_id
          AND revision.state = 'approved'
          AND account.status = 'active'
          AND account.risk_state = 'normal'
          AND EXISTS (
              SELECT 1
              FROM identity.channel_identities AS channel
              JOIN private_data.whatsapp_identities AS whatsapp
                ON whatsapp.channel_identity_id = channel.id
              WHERE channel.account_id = account.id
                AND channel.provider_code = 'whatsapp'
                AND channel.status = 'active'
                AND channel.verified_at IS NOT NULL
                AND whatsapp.opt_in_status <> 'opted_out'
                AND whatsapp.delivery_state <> 'unreachable'
                AND whatsapp.blocked_at IS NULL
          )
          AND profile.revision_is_publishable(revision.id)
    )
$$;

CREATE VIEW availability.current_professional_services
WITH (security_invoker = true) AS
SELECT
    epoch.id AS availability_epoch_id,
    epoch.profile_id,
    epoch.profile_revision_id,
    service.category_code,
    service.contact_mode,
    epoch.last_confirmed_at,
    epoch.expires_at,
    epoch.contact_limit,
    epoch.contact_count
FROM availability.epochs AS epoch
JOIN profile.public_profiles AS root ON root.id = epoch.profile_id
JOIN profile.profile_revisions AS revision ON revision.id = epoch.profile_revision_id
JOIN profile.professional_services AS service ON service.revision_id = revision.id
JOIN profile.service_categories AS category ON category.code = service.category_code
JOIN identity.accounts AS account ON account.id = epoch.account_id
WHERE epoch.state IN ('available', 'scheduled')
  AND epoch.starts_at <= statement_timestamp()
  AND statement_timestamp() < epoch.expires_at
  AND epoch.contact_count < epoch.contact_limit
  AND root.visibility = 'published'
  AND root.published_revision_id = epoch.profile_revision_id
  AND revision.state = 'approved'
  AND account.status = 'active'
  AND account.risk_state = 'normal'
  AND EXISTS (
      SELECT 1
      FROM identity.channel_identities AS channel
      JOIN private_data.whatsapp_identities AS whatsapp
        ON whatsapp.channel_identity_id = channel.id
      WHERE channel.account_id = account.id
        AND channel.provider_code = 'whatsapp'
        AND channel.status = 'active'
        AND channel.verified_at IS NOT NULL
        AND whatsapp.opt_in_status <> 'opted_out'
        AND whatsapp.delivery_state <> 'unreachable'
        AND whatsapp.blocked_at IS NULL
  )
  AND category.state = 'active'
  AND profile.revision_is_publishable(revision.id);

CREATE INDEX professional_services_category_revision_idx
    ON profile.professional_services(category_code, revision_id);

CREATE INDEX professional_service_skills_lookup_idx
    ON profile.professional_service_skills(category_code, skill_code, revision_id);

CREATE OR REPLACE FUNCTION identity.validate_account_time_zone()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = NEW.time_zone) THEN
        RAISE EXCEPTION 'account time zone is not a recognized IANA zone';
    END IF;
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM identity.accounts AS account
        WHERE NOT EXISTS (
            SELECT 1 FROM pg_timezone_names WHERE name = account.time_zone
        )
    ) THEN
        RAISE EXCEPTION 'existing account contains an unrecognized IANA time zone';
    END IF;
END;
$$;

CREATE TRIGGER accounts_validate_time_zone
BEFORE INSERT OR UPDATE OF time_zone ON identity.accounts
FOR EACH ROW EXECUTE FUNCTION identity.validate_account_time_zone();

ALTER TABLE integration.outbox_jobs
    ADD COLUMN availability_epoch_id uuid REFERENCES availability.epochs(id) ON DELETE CASCADE,
    ADD COLUMN availability_generation bigint;

ALTER TABLE integration.outbox_jobs
    DROP CONSTRAINT outbox_jobs_source_shape_check;

ALTER TABLE integration.outbox_jobs
    ADD CONSTRAINT outbox_jobs_source_shape_check
    CHECK (
        (
            job_kind IN (
                'process_conversation_message', 'process_provider_error',
                'process_webhook', 'process_whatsapp_probe', 'process_whatsapp_status'
            )
            AND inbound_event_id IS NOT NULL
            AND outbound_message_id IS NULL
            AND availability_epoch_id IS NULL
            AND availability_generation IS NULL
        )
        OR (
            job_kind = 'send_whatsapp_message'
            AND inbound_event_id IS NULL
            AND outbound_message_id IS NOT NULL
            AND availability_epoch_id IS NULL
            AND availability_generation IS NULL
        )
        OR (
            job_kind IN ('remind_professional_availability', 'advance_professional_availability')
            AND inbound_event_id IS NULL
            AND outbound_message_id IS NULL
            AND availability_epoch_id IS NOT NULL
            AND availability_generation > 0
            AND ordering_key IS NULL
        )
    );

CREATE INDEX outbox_jobs_availability_idx
    ON integration.outbox_jobs(availability_epoch_id, created_at, id)
    WHERE availability_epoch_id IS NOT NULL;

ALTER TABLE messaging.conversation_sessions
    DROP CONSTRAINT conversation_sessions_workflow_role_check;

ALTER TABLE messaging.conversation_sessions
    ADD CONSTRAINT conversation_sessions_workflow_role_check
    CHECK (
        status <> 'active'
        OR (
            (workflow_key IN ('professional.profile', 'professional.availability') AND role_context = 'professional')
            OR (workflow_key = 'administrator.review' AND role_context = 'administrator')
            OR (
                workflow_key NOT IN (
                    'professional.profile', 'professional.availability', 'administrator.review'
                )
                AND role_context = 'customer'
            )
        )
    );

COMMENT ON TABLE availability.epochs IS 'Profile-wide non-resettable availability quota epochs bound to an approved revision.';
COMMENT ON TABLE availability.capacity_consumptions IS 'Immutable idempotent capacity debits for future contact disclosure transactions.';
COMMENT ON VIEW availability.current_professional_services IS 'Privacy-safe database-time availability input for future search; never an authorization cache.';
