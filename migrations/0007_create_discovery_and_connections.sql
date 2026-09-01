CREATE SCHEMA IF NOT EXISTS discovery;
CREATE SCHEMA IF NOT EXISTS connection;

CREATE TABLE profile.provider_services (
    id uuid PRIMARY KEY,
    profile_id uuid REFERENCES profile.public_profiles(id) ON DELETE SET NULL,
    category_code varchar(32) COLLATE "C" NOT NULL
        REFERENCES profile.service_categories(code) ON DELETE RESTRICT,
    state text COLLATE "C" NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    retired_at timestamptz,
    CONSTRAINT provider_services_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT provider_services_profile_category_unique UNIQUE (profile_id, category_code),
    CONSTRAINT provider_services_state_check CHECK (state IN ('active', 'retired')),
    CONSTRAINT provider_services_state_shape_check CHECK (
        (state = 'active' AND retired_at IS NULL)
        OR (state = 'retired' AND retired_at IS NOT NULL)
    )
);

CREATE INDEX provider_services_category_idx
    ON profile.provider_services(category_code, profile_id)
    WHERE state = 'active';

INSERT INTO profile.provider_services (id, profile_id, category_code)
SELECT uuidv7(), root.id, service.category_code
FROM profile.public_profiles AS root
JOIN profile.profile_revisions AS revision ON revision.id = root.published_revision_id
JOIN profile.professional_services AS service ON service.revision_id = revision.id
ON CONFLICT (profile_id, category_code) DO NOTHING;

CREATE TABLE identity.account_blocks (
    id uuid PRIMARY KEY,
    actor_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    blocked_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    source_inbound_event_id uuid REFERENCES integration.inbound_events(id),
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit.events(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    removed_at timestamptz,
    removal_audit_event_id uuid UNIQUE REFERENCES audit.events(id),
    CONSTRAINT account_blocks_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT account_blocks_distinct_check CHECK (actor_account_id <> blocked_account_id),
    CONSTRAINT account_blocks_removal_shape_check CHECK (
        (removed_at IS NULL AND removal_audit_event_id IS NULL)
        OR (removed_at IS NOT NULL AND removal_audit_event_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX account_blocks_active_pair_idx
    ON identity.account_blocks(actor_account_id, blocked_account_id)
    WHERE removed_at IS NULL;

CREATE INDEX account_blocks_reverse_idx
    ON identity.account_blocks(blocked_account_id, actor_account_id)
    WHERE removed_at IS NULL;

CREATE TABLE discovery.service_requests (
    id uuid PRIMARY KEY,
    request_token uuid NOT NULL UNIQUE,
    customer_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    customer_channel_identity_id uuid NOT NULL REFERENCES identity.channel_identities(id),
    category_code varchar(32) COLLATE "C" NOT NULL
        REFERENCES profile.service_categories(code) ON DELETE RESTRICT,
    service_mode text COLLATE "C" NOT NULL DEFAULT 'local',
    requested_time text COLLATE "C",
    issue_code varchar(48) COLLATE "C",
    requested_radius_km smallint NOT NULL DEFAULT 5,
    maximum_radius_km smallint NOT NULL DEFAULT 25,
    customer_locale varchar(16) NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'draft',
    matching_version varchar(32) COLLATE "C" NOT NULL DEFAULT 'local-v1',
    shown_cursor integer NOT NULL DEFAULT 0,
    result_round smallint NOT NULL DEFAULT 1,
    source_inbound_event_id uuid NOT NULL UNIQUE REFERENCES integration.inbound_events(id),
    correlation_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    cancelled_at timestamptz,
    cancellation_reason varchar(64) COLLATE "C",
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT service_requests_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT service_requests_token_uuid_v4_check CHECK (uuid_extract_version(request_token) = 4),
    CONSTRAINT service_requests_customer_channel_fk
        FOREIGN KEY (customer_account_id, customer_channel_identity_id)
        REFERENCES identity.channel_identities(account_id, id),
    CONSTRAINT service_requests_mode_check CHECK (service_mode = 'local'),
    CONSTRAINT service_requests_time_check CHECK (
        requested_time IS NULL OR requested_time IN ('now', 'today', 'flexible')
    ),
    CONSTRAINT service_requests_issue_check CHECK (
        issue_code IS NULL OR issue_code ~ '^[a-z][a-z0-9_]{0,47}$'
    ),
    CONSTRAINT service_requests_radius_check CHECK (
        requested_radius_km IN (2, 5, 10, 25)
        AND maximum_radius_km IN (2, 5, 10, 25)
        AND requested_radius_km <= maximum_radius_km
    ),
    CONSTRAINT service_requests_locale_check CHECK (
        customer_locale IN ('en-IN', 'hi-IN', 'mr-IN')
    ),
    CONSTRAINT service_requests_status_check CHECK (
        status IN (
            'draft', 'collecting_requirements', 'searching', 'showing_results',
            'no_results', 'selected', 'connected', 'cancelled', 'expired'
        )
    ),
    CONSTRAINT service_requests_expiry_check CHECK (
        expires_at > created_at AND expires_at <= created_at + INTERVAL '24 hours'
    ),
    CONSTRAINT service_requests_cursor_check CHECK (shown_cursor >= 0 AND result_round > 0),
    CONSTRAINT service_requests_cancel_shape_check CHECK (
        (status = 'cancelled' AND cancelled_at IS NOT NULL AND cancellation_reason IS NOT NULL)
        OR (status <> 'cancelled' AND cancelled_at IS NULL AND cancellation_reason IS NULL)
    )
);

CREATE UNIQUE INDEX service_requests_one_open_idx
    ON discovery.service_requests(customer_account_id)
    WHERE status IN (
        'draft', 'collecting_requirements', 'searching', 'showing_results',
        'no_results', 'selected'
    );

CREATE INDEX service_requests_customer_history_idx
    ON discovery.service_requests(customer_account_id, created_at DESC, id DESC);

CREATE TRIGGER service_requests_touch_version
BEFORE UPDATE ON discovery.service_requests
FOR EACH ROW EXECUTE FUNCTION identity.touch_versioned_row();

CREATE TABLE private_data.service_request_locations (
    request_id uuid PRIMARY KEY REFERENCES discovery.service_requests(id) ON DELETE CASCADE,
    customer_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    location geography(Point, 4326) NOT NULL,
    source_inbound_event_id uuid NOT NULL UNIQUE REFERENCES integration.inbound_events(id),
    captured_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT request_location_valid_check CHECK (
        ST_IsValid(location::geometry) AND NOT ST_IsEmpty(location::geometry)
    )
);

CREATE INDEX request_locations_gist_idx
    ON private_data.service_request_locations USING gist(location);

CREATE INDEX professional_service_areas_gist_idx
    ON private_data.professional_service_areas USING gist(exact_center);

CREATE TABLE discovery.request_candidates (
    id uuid PRIMARY KEY,
    candidate_token uuid NOT NULL UNIQUE,
    request_id uuid NOT NULL REFERENCES discovery.service_requests(id) ON DELETE CASCADE,
    provider_service_id uuid NOT NULL REFERENCES profile.provider_services(id),
    professional_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    profile_id uuid NOT NULL REFERENCES profile.public_profiles(id) ON DELETE CASCADE,
    profile_revision_id uuid NOT NULL REFERENCES profile.profile_revisions(id) ON DELETE CASCADE,
    availability_epoch_id uuid REFERENCES availability.epochs(id) ON DELETE SET NULL,
    distance_metres integer NOT NULL,
    language_score smallint NOT NULL,
    freshness_score integer NOT NULL,
    reliability_score integer NOT NULL,
    fair_distribution_score integer NOT NULL,
    final_score bigint NOT NULL,
    final_rank integer NOT NULL,
    result_round smallint NOT NULL,
    shown_batch integer,
    shown_at timestamptz,
    selected_at timestamptz,
    excluded_at timestamptz,
    exclusion_reason varchar(64) COLLATE "C",
    matching_version varchar(32) COLLATE "C" NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT request_candidates_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT request_candidates_token_uuid_v4_check CHECK (uuid_extract_version(candidate_token) = 4),
    CONSTRAINT request_candidates_request_service_unique UNIQUE (request_id, provider_service_id),
    CONSTRAINT request_candidates_rank_unique UNIQUE (request_id, final_rank),
    CONSTRAINT request_candidates_distance_check CHECK (distance_metres >= 0),
    CONSTRAINT request_candidates_score_check CHECK (
        language_score >= 0 AND freshness_score >= 0 AND reliability_score >= 0
    ),
    CONSTRAINT request_candidates_rank_check CHECK (final_rank > 0 AND result_round > 0),
    CONSTRAINT request_candidates_show_shape_check CHECK (
        (shown_at IS NULL AND shown_batch IS NULL)
        OR (shown_at IS NOT NULL AND shown_batch IS NOT NULL AND shown_batch > 0)
    ),
    CONSTRAINT request_candidates_exclusion_shape_check CHECK (
        (excluded_at IS NULL AND exclusion_reason IS NULL)
        OR (excluded_at IS NOT NULL AND exclusion_reason IS NOT NULL)
    )
);

CREATE INDEX request_candidates_page_idx
    ON discovery.request_candidates(request_id, shown_at, final_rank, id)
    WHERE excluded_at IS NULL;

CREATE INDEX request_candidates_professional_load_idx
    ON discovery.request_candidates(professional_account_id, created_at DESC);

CREATE TABLE connection.connection_requests (
    id uuid PRIMARY KEY,
    request_token uuid NOT NULL UNIQUE,
    service_request_id uuid NOT NULL REFERENCES discovery.service_requests(id),
    candidate_id uuid REFERENCES discovery.request_candidates(id) ON DELETE SET NULL,
    provider_service_id uuid NOT NULL REFERENCES profile.provider_services(id),
    customer_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    professional_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    contact_mode text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'pending',
    source_inbound_event_id uuid NOT NULL UNIQUE REFERENCES integration.inbound_events(id),
    response_generation bigint NOT NULL DEFAULT 1,
    requested_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    response_deadline timestamptz NOT NULL,
    responded_at timestamptz,
    expires_at timestamptz NOT NULL,
    cancelled_at timestamptz,
    cancellation_reason varchar(64) COLLATE "C",
    disclosure_id uuid,
    request_outbound_message_id uuid
        REFERENCES messaging.outbound_messages(id) DEFERRABLE INITIALLY DEFERRED,
    correlation_id uuid NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT connection_requests_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT connection_requests_token_uuid_v4_check CHECK (uuid_extract_version(request_token) = 4),
    CONSTRAINT connection_requests_accounts_distinct_check CHECK (
        customer_account_id <> professional_account_id
    ),
    CONSTRAINT connection_requests_mode_check CHECK (contact_mode IN ('direct', 'approval_required')),
    CONSTRAINT connection_requests_status_check CHECK (
        status IN (
            'pending', 'accepted', 'declined', 'expired', 'cancelled',
            'disclosure_pending', 'disclosed', 'disclosure_failed'
        )
    ),
    CONSTRAINT connection_requests_time_check CHECK (
        response_deadline > requested_at
        AND expires_at >= response_deadline
        AND expires_at <= requested_at + INTERVAL '24 hours'
    ),
    CONSTRAINT connection_requests_response_shape_check CHECK (
        (status = 'pending' AND responded_at IS NULL)
        OR (status <> 'pending')
    ),
    CONSTRAINT connection_requests_generation_check CHECK (response_generation > 0)
);

CREATE UNIQUE INDEX connection_requests_one_open_candidate_idx
    ON connection.connection_requests(service_request_id, provider_service_id)
    WHERE status IN ('pending', 'accepted', 'disclosure_pending');

CREATE INDEX connection_requests_professional_pending_idx
    ON connection.connection_requests(professional_account_id, response_deadline, id)
    WHERE status = 'pending';

CREATE INDEX connection_requests_customer_history_idx
    ON connection.connection_requests(customer_account_id, requested_at DESC, id DESC);

CREATE TRIGGER connection_requests_touch_version
BEFORE UPDATE ON connection.connection_requests
FOR EACH ROW EXECUTE FUNCTION identity.touch_versioned_row();

CREATE TABLE connection.contact_reveals (
    id uuid PRIMARY KEY,
    reveal_token uuid NOT NULL UNIQUE,
    customer_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    professional_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    provider_service_id uuid NOT NULL REFERENCES profile.provider_services(id),
    service_request_id uuid NOT NULL REFERENCES discovery.service_requests(id),
    connection_request_id uuid REFERENCES connection.connection_requests(id),
    availability_epoch_id uuid REFERENCES availability.epochs(id) ON DELETE SET NULL,
    availability_consumption_id uuid UNIQUE
        REFERENCES availability.capacity_consumptions(id) ON DELETE SET NULL,
    disclosure_reason text COLLATE "C" NOT NULL,
    customer_consent_inbound_event_id uuid NOT NULL REFERENCES integration.inbound_events(id),
    professional_consent_basis text COLLATE "C" NOT NULL,
    allowance_consumed boolean NOT NULL,
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit.events(id),
    correlation_id uuid NOT NULL,
    revealed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT contact_reveals_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT contact_reveals_token_uuid_v4_check CHECK (uuid_extract_version(reveal_token) = 4),
    CONSTRAINT contact_reveals_accounts_distinct_check CHECK (
        customer_account_id <> professional_account_id
    ),
    CONSTRAINT contact_reveals_reason_check CHECK (
        disclosure_reason IN ('direct_contact', 'professional_accepted', 'previously_revealed')
    ),
    CONSTRAINT contact_reveals_consent_basis_check CHECK (
        professional_consent_basis IN ('direct_contact_consent', 'connection_acceptance')
    ),
    CONSTRAINT contact_reveals_once_unique UNIQUE (customer_account_id, professional_account_id)
);

ALTER TABLE connection.connection_requests
    ADD CONSTRAINT connection_requests_disclosure_fk
    FOREIGN KEY (disclosure_id) REFERENCES connection.contact_reveals(id);

CREATE TABLE connection.contact_reveal_delivery (
    reveal_id uuid PRIMARY KEY REFERENCES connection.contact_reveals(id) ON DELETE CASCADE,
    state text COLLATE "C" NOT NULL DEFAULT 'pending',
    qualified_state text COLLATE "C" NOT NULL DEFAULT 'pending',
    customer_outbound_message_id uuid
        REFERENCES messaging.outbound_messages(id) DEFERRABLE INITIALLY DEFERRED,
    professional_outbound_message_id uuid
        REFERENCES messaging.outbound_messages(id) DEFERRABLE INITIALLY DEFERRED,
    photo_outbound_message_id uuid
        REFERENCES messaging.outbound_messages(id) DEFERRABLE INITIALLY DEFERRED,
    customer_contains_contact boolean NOT NULL,
    professional_contains_contact boolean NOT NULL,
    customer_delivered_at timestamptz,
    professional_delivered_at timestamptz,
    photo_delivered_at timestamptz,
    delivered_at timestamptz,
    failed_at timestamptz,
    failure_code varchar(96) COLLATE "C",
    version bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT reveal_delivery_state_check CHECK (
        state IN ('pending', 'delivered', 'failed', 'reversed')
    ),
    CONSTRAINT reveal_qualified_state_check CHECK (
        qualified_state IN ('pending', 'qualified', 'reversed')
    ),
    CONSTRAINT reveal_delivery_failure_shape_check CHECK (
        (state = 'failed' AND failed_at IS NOT NULL AND failure_code IS NOT NULL)
        OR state <> 'failed'
    )
);

CREATE TABLE messaging.outbound_message_subjects (
    outbound_message_id uuid NOT NULL
        REFERENCES messaging.outbound_messages(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    account_id uuid NOT NULL REFERENCES identity.accounts(id),
    purpose text COLLATE "C" NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (outbound_message_id, account_id, purpose),
    CONSTRAINT outbound_message_subjects_purpose_check CHECK (
        purpose IN ('contact_detail', 'profile_photo')
    )
);

CREATE INDEX outbound_message_subjects_account_idx
    ON messaging.outbound_message_subjects(account_id, outbound_message_id);

CREATE TRIGGER contact_reveal_delivery_touch_version
BEFORE UPDATE ON connection.contact_reveal_delivery
FOR EACH ROW EXECUTE FUNCTION identity.touch_versioned_row();

CREATE TABLE connection.customer_allowance_events (
    id uuid PRIMARY KEY,
    customer_account_id uuid NOT NULL REFERENCES identity.accounts(id),
    reveal_id uuid NOT NULL UNIQUE REFERENCES connection.contact_reveals(id),
    occurred_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit.events(id),
    CONSTRAINT allowance_events_uuid_v7_check CHECK (uuid_extract_version(id) = 7)
);

CREATE INDEX customer_allowance_rolling_idx
    ON connection.customer_allowance_events(customer_account_id, occurred_at DESC, id);

CREATE TABLE connection.reveal_reversals (
    id uuid PRIMARY KEY,
    reveal_id uuid NOT NULL UNIQUE REFERENCES connection.contact_reveals(id),
    reason_code varchar(64) COLLATE "C" NOT NULL,
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit.events(id),
    reversed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT reveal_reversals_uuid_v7_check CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT reveal_reversals_reason_check CHECK (
        reason_code IN ('internal_delivery_failure', 'operator_correction')
    )
);

CREATE OR REPLACE FUNCTION connection.customer_reveal_allowance_remaining(
    candidate_customer_id uuid
)
RETURNS smallint
LANGUAGE sql
VOLATILE
SET search_path = pg_catalog, connection
AS $$
    SELECT GREATEST(0, 3 - count(*))::smallint
    FROM connection.customer_allowance_events AS allowance
    JOIN connection.contact_reveals AS reveal ON reveal.id = allowance.reveal_id
    LEFT JOIN connection.reveal_reversals AS reversal ON reversal.reveal_id = reveal.id
    WHERE allowance.customer_account_id = candidate_customer_id
      AND allowance.occurred_at > clock_timestamp() - INTERVAL '24 hours'
      AND reversal.id IS NULL
$$;

CREATE TABLE availability.capacity_reversals (
    id uuid PRIMARY KEY,
    consumption_id uuid NOT NULL UNIQUE
        REFERENCES availability.capacity_consumptions(id) ON DELETE CASCADE,
    audit_event_id uuid NOT NULL UNIQUE REFERENCES audit.events(id),
    reversed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT capacity_reversals_uuid_v7_check CHECK (uuid_extract_version(id) = 7)
);

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
    ELSIF TG_TABLE_NAME = 'capacity_reversals' THEN
        SELECT epoch_id INTO target_epoch_id
        FROM availability.capacity_consumptions
        WHERE id = COALESCE(NEW.consumption_id, OLD.consumption_id);
    ELSE
        target_epoch_id := COALESCE(NEW.epoch_id, OLD.epoch_id);
    END IF;
    SELECT contact_count INTO persisted_count
    FROM availability.epochs WHERE id = target_epoch_id;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT count(*) FILTER (WHERE reversal.id IS NULL) INTO ledger_count
    FROM availability.capacity_consumptions AS consumption
    LEFT JOIN availability.capacity_reversals AS reversal
      ON reversal.consumption_id = consumption.id
    WHERE consumption.epoch_id = target_epoch_id;
    IF persisted_count <> ledger_count THEN
        RAISE EXCEPTION 'availability capacity ledger does not match epoch count';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER availability_capacity_reversal_count_constraint
AFTER INSERT OR DELETE ON availability.capacity_reversals
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION availability.capacity_count_matches_epoch();

CREATE OR REPLACE FUNCTION discovery.reject_direct_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('sahayak.account_erasure', true) = 'on' THEN
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    END IF;
    IF current_setting('sahayak.discovery_mutation', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'discovery records require a guarded domain transaction';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE OR REPLACE FUNCTION connection.reject_direct_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('sahayak.account_erasure', true) = 'on' THEN
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    END IF;
    IF current_setting('sahayak.connection_mutation', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'connection records require a guarded domain transaction';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE OR REPLACE FUNCTION connection.reject_contact_reveal_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('sahayak.account_erasure', true) = 'on'
       AND (to_jsonb(NEW) - ARRAY['availability_epoch_id', 'availability_consumption_id'])
           = (to_jsonb(OLD) - ARRAY['availability_epoch_id', 'availability_consumption_id'])
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'contact reveal records are immutable';
END;
$$;

CREATE OR REPLACE FUNCTION connection.validate_connection_request_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM discovery.request_candidates AS candidate
        JOIN discovery.service_requests AS request ON request.id = candidate.request_id
        JOIN profile.provider_services AS provider ON provider.id = candidate.provider_service_id
        JOIN profile.public_profiles AS root ON root.id = provider.profile_id
        WHERE candidate.id = NEW.candidate_id
          AND request.id = NEW.service_request_id
          AND provider.id = NEW.provider_service_id
          AND request.customer_account_id = NEW.customer_account_id
          AND root.account_id = NEW.professional_account_id
          AND provider.category_code = request.category_code
    ) THEN
        RAISE EXCEPTION 'connection request aggregate references do not match';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION connection.validate_contact_reveal_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM discovery.service_requests AS request
        JOIN profile.provider_services AS provider ON provider.id = NEW.provider_service_id
        JOIN profile.public_profiles AS root ON root.id = provider.profile_id
        JOIN availability.epochs AS epoch ON epoch.id = NEW.availability_epoch_id
        JOIN availability.capacity_consumptions AS consumption
          ON consumption.id = NEW.availability_consumption_id
         AND consumption.epoch_id = epoch.id
         AND consumption.category_code = provider.category_code
        WHERE request.id = NEW.service_request_id
          AND request.customer_account_id = NEW.customer_account_id
          AND root.account_id = NEW.professional_account_id
          AND epoch.account_id = NEW.professional_account_id
          AND epoch.profile_id = root.id
          AND request.category_code = provider.category_code
          AND (
              NEW.connection_request_id IS NULL
              OR EXISTS (
                  SELECT 1 FROM connection.connection_requests AS connection
                  WHERE connection.id = NEW.connection_request_id
                    AND connection.service_request_id = request.id
                    AND connection.customer_account_id = NEW.customer_account_id
                    AND connection.professional_account_id = NEW.professional_account_id
              )
          )
    ) THEN
        RAISE EXCEPTION 'contact reveal aggregate references do not match';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION connection.validate_allowance_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM connection.contact_reveals AS reveal
        WHERE reveal.id = NEW.reveal_id
          AND reveal.customer_account_id = NEW.customer_account_id
          AND reveal.allowance_consumed
    ) THEN
        RAISE EXCEPTION 'allowance event does not match its contact reveal';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER capacity_reversals_guard
BEFORE INSERT OR DELETE ON availability.capacity_reversals
FOR EACH ROW EXECUTE FUNCTION connection.reject_direct_mutation();

CREATE TRIGGER capacity_reversals_reject_update
BEFORE UPDATE ON availability.capacity_reversals
FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER service_requests_guard
BEFORE INSERT OR UPDATE OR DELETE ON discovery.service_requests
FOR EACH ROW EXECUTE FUNCTION discovery.reject_direct_mutation();

CREATE TRIGGER provider_services_guard
BEFORE INSERT OR UPDATE OR DELETE ON profile.provider_services
FOR EACH ROW EXECUTE FUNCTION discovery.reject_direct_mutation();

CREATE TRIGGER request_locations_guard
BEFORE INSERT OR UPDATE OR DELETE ON private_data.service_request_locations
FOR EACH ROW EXECUTE FUNCTION discovery.reject_direct_mutation();

CREATE TRIGGER request_candidates_guard
BEFORE INSERT OR UPDATE OR DELETE ON discovery.request_candidates
FOR EACH ROW EXECUTE FUNCTION discovery.reject_direct_mutation();

CREATE TRIGGER connection_requests_guard
BEFORE INSERT OR UPDATE OR DELETE ON connection.connection_requests
FOR EACH ROW EXECUTE FUNCTION connection.reject_direct_mutation();

CREATE TRIGGER connection_requests_validate_insert
BEFORE INSERT ON connection.connection_requests
FOR EACH ROW EXECUTE FUNCTION connection.validate_connection_request_insert();

CREATE TRIGGER account_blocks_guard
BEFORE INSERT OR UPDATE OR DELETE ON identity.account_blocks
FOR EACH ROW EXECUTE FUNCTION connection.reject_direct_mutation();

CREATE TRIGGER contact_reveals_guard
BEFORE INSERT OR DELETE ON connection.contact_reveals
FOR EACH ROW EXECUTE FUNCTION connection.reject_direct_mutation();

CREATE TRIGGER contact_reveals_validate_insert
BEFORE INSERT ON connection.contact_reveals
FOR EACH ROW EXECUTE FUNCTION connection.validate_contact_reveal_insert();

CREATE TRIGGER contact_reveal_delivery_guard
BEFORE INSERT OR UPDATE OR DELETE ON connection.contact_reveal_delivery
FOR EACH ROW EXECUTE FUNCTION connection.reject_direct_mutation();

CREATE TRIGGER allowance_events_guard
BEFORE INSERT OR DELETE ON connection.customer_allowance_events
FOR EACH ROW EXECUTE FUNCTION connection.reject_direct_mutation();

CREATE TRIGGER allowance_events_validate_insert
BEFORE INSERT ON connection.customer_allowance_events
FOR EACH ROW EXECUTE FUNCTION connection.validate_allowance_insert();

CREATE TRIGGER reveal_reversals_guard
BEFORE INSERT OR DELETE ON connection.reveal_reversals
FOR EACH ROW EXECUTE FUNCTION connection.reject_direct_mutation();

CREATE TRIGGER contact_reveals_reject_update
BEFORE UPDATE ON connection.contact_reveals
FOR EACH ROW EXECUTE FUNCTION connection.reject_contact_reveal_update();

CREATE TRIGGER allowance_events_reject_update
BEFORE UPDATE ON connection.customer_allowance_events
FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

ALTER TABLE integration.outbox_jobs
    ADD COLUMN connection_request_id uuid
        REFERENCES connection.connection_requests(id) ON DELETE CASCADE,
    ADD COLUMN connection_generation bigint;

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
            AND connection_request_id IS NULL
            AND connection_generation IS NULL
        )
        OR (
            job_kind = 'send_whatsapp_message'
            AND inbound_event_id IS NULL
            AND outbound_message_id IS NOT NULL
            AND availability_epoch_id IS NULL
            AND availability_generation IS NULL
            AND connection_request_id IS NULL
            AND connection_generation IS NULL
        )
        OR (
            job_kind IN ('remind_professional_availability', 'advance_professional_availability')
            AND inbound_event_id IS NULL
            AND outbound_message_id IS NULL
            AND availability_epoch_id IS NOT NULL
            AND availability_generation > 0
            AND connection_request_id IS NULL
            AND connection_generation IS NULL
            AND ordering_key IS NULL
        )
        OR (
            job_kind = 'expire_connection_request'
            AND inbound_event_id IS NULL
            AND outbound_message_id IS NULL
            AND availability_epoch_id IS NULL
            AND availability_generation IS NULL
            AND connection_request_id IS NOT NULL
            AND connection_generation > 0
            AND ordering_key IS NULL
        )
    );

CREATE INDEX outbox_jobs_connection_idx
    ON integration.outbox_jobs(connection_request_id, created_at, id)
    WHERE connection_request_id IS NOT NULL;

ALTER TABLE messaging.conversation_sessions
    DROP CONSTRAINT conversation_sessions_workflow_role_check;

ALTER TABLE messaging.conversation_sessions
    ADD CONSTRAINT conversation_sessions_workflow_role_check
    CHECK (
        status <> 'active'
        OR (
            (workflow_key IN ('professional.profile', 'professional.availability', 'professional.requests')
             AND role_context = 'professional')
            OR (workflow_key = 'administrator.review' AND role_context = 'administrator')
            OR (
                workflow_key NOT IN (
                    'professional.profile', 'professional.availability',
                    'professional.requests', 'administrator.review'
                )
                AND role_context = 'customer'
            )
        )
    );

COMMENT ON TABLE discovery.request_candidates IS 'Deterministic privacy-safe candidate snapshots; exact locations and phones are excluded.';
COMMENT ON TABLE connection.contact_reveals IS 'Immutable contact-disclosure business events containing references only, never phone values.';
