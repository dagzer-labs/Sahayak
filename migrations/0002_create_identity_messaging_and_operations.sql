-- Establish durable identity, messaging, integration, and audit boundaries.
-- Service discovery, verification, and billing belong to dedicated migrations.

CREATE SCHEMA IF NOT EXISTS identity;
CREATE SCHEMA IF NOT EXISTS profile;
CREATE SCHEMA IF NOT EXISTS private_data;
CREATE SCHEMA IF NOT EXISTS messaging;
CREATE SCHEMA IF NOT EXISTS integration;
CREATE SCHEMA IF NOT EXISTS audit;

CREATE OR REPLACE FUNCTION identity.touch_versioned_row()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = clock_timestamp();
    NEW.version = OLD.version + 1;
    RETURN NEW;
END;
$$;

CREATE TABLE private_data.key_versions (
    purpose text NOT NULL,
    version smallint NOT NULL,
    key_reference text NOT NULL,
    algorithm varchar(32) NOT NULL,
    state text NOT NULL DEFAULT 'active',
    activated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    retired_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (purpose, version),
    CONSTRAINT key_versions_purpose_check
        CHECK (purpose IN ('contact_encryption', 'identity_encryption', 'integration_encryption', 'lookup_hmac')),
    CONSTRAINT key_versions_version_check
        CHECK (version > 0),
    CONSTRAINT key_versions_reference_check
        CHECK (length(btrim(key_reference)) BETWEEN 1 AND 255),
    CONSTRAINT key_versions_algorithm_check
        CHECK (
            (purpose IN ('contact_encryption', 'identity_encryption', 'integration_encryption') AND algorithm = 'aes-256-gcm')
            OR (purpose = 'lookup_hmac' AND algorithm = 'hmac-sha-256')
        ),
    CONSTRAINT key_versions_state_check
        CHECK (state IN ('active', 'decrypt_only', 'retired', 'destroyed')),
    CONSTRAINT key_versions_retirement_check
        CHECK ((state IN ('retired', 'destroyed')) = (retired_at IS NOT NULL)),
    CONSTRAINT key_versions_reference_unique
        UNIQUE (purpose, key_reference)
);

CREATE UNIQUE INDEX key_versions_one_active_per_purpose_idx
    ON private_data.key_versions (purpose)
    WHERE state = 'active';

INSERT INTO private_data.key_versions (purpose, version, key_reference, algorithm)
VALUES
    ('contact_encryption', 1, 'secret:contact-key-v1', 'aes-256-gcm'),
    ('identity_encryption', 1, 'secret:identity-key-v1', 'aes-256-gcm'),
    ('integration_encryption', 1, 'secret:integration-key-v1', 'aes-256-gcm'),
    ('lookup_hmac', 1, 'secret:lookup-key-v1', 'hmac-sha-256');

CREATE TABLE identity.accounts (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    subject_kind text NOT NULL DEFAULT 'person',
    status text NOT NULL DEFAULT 'pending',
    risk_state text NOT NULL DEFAULT 'normal',
    preferred_locale varchar(35) NOT NULL DEFAULT 'en',
    time_zone varchar(64) NOT NULL DEFAULT 'Asia/Kolkata',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    state_changed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    suspended_at timestamptz,
    deletion_requested_at timestamptz,
    deleted_at timestamptz,
    CONSTRAINT accounts_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT accounts_subject_kind_check
        CHECK (subject_kind IN ('person', 'organization')),
    CONSTRAINT accounts_status_check
        CHECK (status IN ('pending', 'active', 'suspended', 'deletion_pending', 'deleted')),
    CONSTRAINT accounts_risk_state_check
        CHECK (risk_state IN ('normal', 'under_review', 'restricted', 'blocked')),
    CONSTRAINT accounts_locale_check
        CHECK (preferred_locale ~ '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$'),
    CONSTRAINT accounts_time_zone_check
        CHECK (length(btrim(time_zone)) BETWEEN 1 AND 64),
    CONSTRAINT accounts_version_check
        CHECK (version > 0),
    CONSTRAINT accounts_deleted_state_check
        CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
    CONSTRAINT accounts_deletion_requested_check
        CHECK (status NOT IN ('deletion_pending', 'deleted') OR deletion_requested_at IS NOT NULL),
    CONSTRAINT accounts_suspended_check
        CHECK (status <> 'suspended' OR suspended_at IS NOT NULL),
    CONSTRAINT accounts_timestamp_order_check
        CHECK (
            state_changed_at >= created_at
            AND (deletion_requested_at IS NULL OR deletion_requested_at >= created_at)
            AND (deleted_at IS NULL OR deleted_at >= deletion_requested_at)
        )
);

CREATE TRIGGER accounts_touch_version
BEFORE UPDATE ON identity.accounts
FOR EACH ROW
EXECUTE FUNCTION identity.touch_versioned_row();

CREATE INDEX accounts_status_idx
    ON identity.accounts (status, created_at);

CREATE INDEX accounts_risk_review_idx
    ON identity.accounts (risk_state, updated_at)
    WHERE risk_state <> 'normal';

CREATE TABLE identity.account_roles (
    account_id uuid NOT NULL REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    role text NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    granted_by uuid REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    revoked_at timestamptz,
    PRIMARY KEY (account_id, role),
    CONSTRAINT account_roles_role_check
        CHECK (role IN ('customer', 'professional', 'administrator')),
    CONSTRAINT account_roles_revocation_check
        CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);

CREATE INDEX account_roles_active_role_idx
    ON identity.account_roles (role, account_id)
    WHERE revoked_at IS NULL;

CREATE TABLE identity.channel_providers (
    code varchar(32) PRIMARY KEY,
    display_name varchar(64) NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT channel_providers_code_check
        CHECK (code ~ '^[a-z][a-z0-9_]{1,31}$'),
    CONSTRAINT channel_providers_display_name_check
        CHECK (length(btrim(display_name)) BETWEEN 1 AND 64),
    CONSTRAINT channel_providers_state_check
        CHECK (state IN ('active', 'disabled'))
);

INSERT INTO identity.channel_providers (code, display_name)
VALUES ('whatsapp', 'WhatsApp');

CREATE TABLE identity.channel_identities (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    account_id uuid NOT NULL REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    provider_code varchar(32) NOT NULL
        REFERENCES identity.channel_providers (code) ON DELETE RESTRICT,
    provider_namespace varchar(128) COLLATE "C" NOT NULL,
    status text NOT NULL DEFAULT 'active',
    verified_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    first_seen_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    last_seen_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    disabled_at timestamptz,
    CONSTRAINT channel_identities_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT channel_identities_namespace_check
        CHECK (octet_length(btrim(provider_namespace)) BETWEEN 1 AND 128),
    CONSTRAINT channel_identities_status_check
        CHECK (status IN ('active', 'disabled', 'revoked')),
    CONSTRAINT channel_identities_disabled_check
        CHECK ((status = 'active') = (disabled_at IS NULL)),
    CONSTRAINT channel_identities_seen_order_check
        CHECK (last_seen_at >= first_seen_at),
    CONSTRAINT channel_identities_version_check
        CHECK (version > 0),
    CONSTRAINT channel_identities_account_id_unique
        UNIQUE (account_id, id),
    CONSTRAINT channel_identities_id_provider_unique
        UNIQUE (id, provider_code)
);

CREATE TRIGGER channel_identities_touch_version
BEFORE UPDATE ON identity.channel_identities
FOR EACH ROW
EXECUTE FUNCTION identity.touch_versioned_row();

CREATE INDEX channel_identities_account_idx
    ON identity.channel_identities (account_id, provider_code, status);

CREATE TABLE private_data.channel_lookup_digests (
    channel_identity_id uuid NOT NULL,
    channel_code varchar(32) NOT NULL,
    lookup_kind varchar(32) NOT NULL,
    key_purpose text NOT NULL DEFAULT 'lookup_hmac',
    key_version smallint NOT NULL,
    digest bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (channel_identity_id, lookup_kind, key_version),
    FOREIGN KEY (channel_identity_id, channel_code)
        REFERENCES identity.channel_identities (id, provider_code) ON DELETE CASCADE,
    FOREIGN KEY (key_purpose, key_version)
        REFERENCES private_data.key_versions (purpose, version) ON DELETE RESTRICT,
    CONSTRAINT channel_lookup_digests_kind_check
        CHECK (lookup_kind IN ('whatsapp_wa_id', 'phone_e164')),
    CONSTRAINT channel_lookup_digests_key_purpose_check
        CHECK (key_purpose = 'lookup_hmac'),
    CONSTRAINT channel_lookup_digests_digest_check
        CHECK (octet_length(digest) = 32),
    CONSTRAINT channel_lookup_digests_unique_digest
        UNIQUE (channel_code, lookup_kind, key_version, digest)
);

CREATE TABLE private_data.whatsapp_identities (
    channel_identity_id uuid PRIMARY KEY,
    channel_code varchar(32) GENERATED ALWAYS AS ('whatsapp') STORED,
    wa_id_ciphertext bytea NOT NULL,
    wa_id_nonce bytea NOT NULL,
    phone_e164_ciphertext bytea NOT NULL,
    phone_e164_nonce bytea NOT NULL,
    encryption_key_purpose text NOT NULL DEFAULT 'contact_encryption',
    encryption_key_version smallint NOT NULL,
    opt_in_status text NOT NULL DEFAULT 'unknown',
    opt_in_version varchar(32),
    opted_in_at timestamptz,
    opted_out_at timestamptz,
    last_inbound_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    service_window_expires_at timestamptz NOT NULL DEFAULT transaction_timestamp() + interval '24 hours',
    delivery_state text NOT NULL DEFAULT 'unknown',
    blocked_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (channel_identity_id, channel_code)
        REFERENCES identity.channel_identities (id, provider_code) ON DELETE CASCADE,
    FOREIGN KEY (encryption_key_purpose, encryption_key_version)
        REFERENCES private_data.key_versions (purpose, version) ON DELETE RESTRICT,
    CONSTRAINT whatsapp_identities_wa_id_ciphertext_check
        CHECK (octet_length(wa_id_ciphertext) >= 16),
    CONSTRAINT whatsapp_identities_wa_id_nonce_check
        CHECK (octet_length(wa_id_nonce) = 12),
    CONSTRAINT whatsapp_identities_phone_ciphertext_check
        CHECK (octet_length(phone_e164_ciphertext) >= 16),
    CONSTRAINT whatsapp_identities_phone_nonce_check
        CHECK (octet_length(phone_e164_nonce) = 12),
    CONSTRAINT whatsapp_identities_key_purpose_check
        CHECK (encryption_key_purpose = 'contact_encryption'),
    CONSTRAINT whatsapp_identities_opt_in_status_check
        CHECK (opt_in_status IN ('unknown', 'opted_in', 'opted_out')),
    CONSTRAINT whatsapp_identities_opt_in_check
        CHECK (
            (opt_in_status = 'unknown' AND opt_in_version IS NULL AND opted_in_at IS NULL AND opted_out_at IS NULL)
            OR
            (opt_in_status = 'opted_in' AND opt_in_version IS NOT NULL AND opted_in_at IS NOT NULL AND opted_out_at IS NULL)
            OR
            (opt_in_status = 'opted_out' AND opt_in_version IS NOT NULL AND opted_in_at IS NOT NULL AND opted_out_at IS NOT NULL)
        ),
    CONSTRAINT whatsapp_identities_delivery_state_check
        CHECK (delivery_state IN ('unknown', 'reachable', 'temporarily_unavailable', 'unreachable')),
    CONSTRAINT whatsapp_identities_window_check
        CHECK (service_window_expires_at >= last_inbound_at),
    CONSTRAINT whatsapp_identities_version_check
        CHECK (version > 0)
);

CREATE TRIGGER whatsapp_identities_touch_version
BEFORE UPDATE ON private_data.whatsapp_identities
FOR EACH ROW
EXECUTE FUNCTION identity.touch_versioned_row();

CREATE INDEX whatsapp_identities_service_window_idx
    ON private_data.whatsapp_identities (service_window_expires_at)
    WHERE opt_in_status = 'opted_in';

CREATE TABLE profile.public_profiles (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    public_id uuid NOT NULL DEFAULT uuidv4() UNIQUE,
    account_id uuid NOT NULL UNIQUE
        REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    display_name varchar(80) NOT NULL,
    status text NOT NULL DEFAULT 'draft',
    reviewed_by uuid REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    reviewed_at timestamptz,
    published_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT public_profiles_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT public_profiles_public_id_version_check
        CHECK (uuid_extract_version(public_id) = 4),
    CONSTRAINT public_profiles_display_name_check
        CHECK (length(btrim(display_name)) BETWEEN 1 AND 80),
    CONSTRAINT public_profiles_status_check
        CHECK (status IN ('draft', 'pending_review', 'published', 'hidden', 'rejected')),
    CONSTRAINT public_profiles_review_check
        CHECK (
            (
                status IN ('published', 'hidden', 'rejected')
                AND reviewed_by IS NOT NULL
                AND reviewed_at IS NOT NULL
            )
            OR (
                status IN ('draft', 'pending_review')
                AND reviewed_by IS NULL
                AND reviewed_at IS NULL
            )
        ),
    CONSTRAINT public_profiles_publish_check
        CHECK (
            (status IN ('published', 'hidden') AND published_at IS NOT NULL)
            OR (status IN ('draft', 'pending_review', 'rejected') AND published_at IS NULL)
        ),
    CONSTRAINT public_profiles_version_check
        CHECK (version > 0)
);

CREATE TRIGGER public_profiles_touch_version
BEFORE UPDATE ON profile.public_profiles
FOR EACH ROW
EXECUTE FUNCTION identity.touch_versioned_row();

CREATE INDEX public_profiles_review_queue_idx
    ON profile.public_profiles (created_at, id)
    WHERE status = 'pending_review';

CREATE TABLE private_data.account_identities (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    account_id uuid NOT NULL UNIQUE
        REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    payload_schema_version smallint NOT NULL,
    encrypted_payload bytea NOT NULL,
    payload_nonce bytea NOT NULL,
    encryption_key_purpose text NOT NULL DEFAULT 'identity_encryption',
    encryption_key_version smallint NOT NULL,
    verification_state text NOT NULL DEFAULT 'not_requested',
    consent_version varchar(32) NOT NULL,
    consented_at timestamptz NOT NULL,
    verified_at timestamptz,
    expires_at timestamptz,
    reviewed_by uuid REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    reviewed_at timestamptz,
    collected_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (encryption_key_purpose, encryption_key_version)
        REFERENCES private_data.key_versions (purpose, version) ON DELETE RESTRICT,
    CONSTRAINT account_identities_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT account_identities_schema_version_check
        CHECK (payload_schema_version > 0),
    CONSTRAINT account_identities_payload_check
        CHECK (octet_length(encrypted_payload) >= 16),
    CONSTRAINT account_identities_nonce_check
        CHECK (octet_length(payload_nonce) = 12),
    CONSTRAINT account_identities_key_purpose_check
        CHECK (encryption_key_purpose = 'identity_encryption'),
    CONSTRAINT account_identities_verification_state_check
        CHECK (verification_state IN ('not_requested', 'pending', 'verified', 'rejected', 'expired', 'revoked')),
    CONSTRAINT account_identities_consent_version_check
        CHECK (octet_length(btrim(consent_version)) BETWEEN 1 AND 32),
    CONSTRAINT account_identities_verification_time_check
        CHECK (
            (
                verification_state IN ('not_requested', 'pending')
                AND verified_at IS NULL
                AND expires_at IS NULL
                AND reviewed_by IS NULL
                AND reviewed_at IS NULL
            )
            OR (
                verification_state = 'verified'
                AND verified_at IS NOT NULL
                AND (expires_at IS NULL OR expires_at >= verified_at)
                AND (reviewed_by IS NULL) = (reviewed_at IS NULL)
            )
            OR (
                verification_state = 'rejected'
                AND verified_at IS NULL
                AND expires_at IS NULL
                AND reviewed_by IS NOT NULL
                AND reviewed_at IS NOT NULL
            )
            OR (
                verification_state = 'expired'
                AND verified_at IS NOT NULL
                AND expires_at IS NOT NULL
                AND expires_at >= verified_at
                AND (reviewed_by IS NULL) = (reviewed_at IS NULL)
            )
            OR (
                verification_state = 'revoked'
                AND verified_at IS NOT NULL
                AND reviewed_by IS NOT NULL
                AND reviewed_at IS NOT NULL
            )
        ),
    CONSTRAINT account_identities_version_check
        CHECK (version > 0)
);

CREATE TRIGGER account_identities_touch_version
BEFORE UPDATE ON private_data.account_identities
FOR EACH ROW
EXECUTE FUNCTION identity.touch_versioned_row();

CREATE TABLE messaging.conversation_sessions (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    account_id uuid NOT NULL,
    channel_identity_id uuid NOT NULL,
    role_context text NOT NULL,
    workflow_key varchar(64) NOT NULL,
    workflow_version smallint NOT NULL,
    state_key varchar(64) NOT NULL,
    state_data jsonb NOT NULL DEFAULT '{}'::jsonb,
    language varchar(35) NOT NULL,
    status text NOT NULL DEFAULT 'active',
    expires_at timestamptz NOT NULL,
    last_activity_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    last_inbound_event_id uuid,
    last_provider_message_id varchar(512),
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (account_id, channel_identity_id)
        REFERENCES identity.channel_identities (account_id, id) ON DELETE RESTRICT,
    CONSTRAINT conversation_sessions_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT conversation_sessions_role_check
        CHECK (role_context IN ('customer', 'professional', 'administrator')),
    CONSTRAINT conversation_sessions_workflow_key_check
        CHECK (workflow_key ~ '^[a-z][a-z0-9_.-]{1,63}$'),
    CONSTRAINT conversation_sessions_workflow_version_check
        CHECK (workflow_version > 0),
    CONSTRAINT conversation_sessions_state_key_check
        CHECK (state_key ~ '^[a-z][a-z0-9_.-]{1,63}$'),
    CONSTRAINT conversation_sessions_state_data_check
        CHECK (jsonb_typeof(state_data) = 'object' AND octet_length(state_data::text) <= 65536),
    CONSTRAINT conversation_sessions_language_check
        CHECK (octet_length(btrim(language)) BETWEEN 2 AND 35),
    CONSTRAINT conversation_sessions_status_check
        CHECK (status IN ('active', 'completed', 'expired', 'abandoned')),
    CONSTRAINT conversation_sessions_expiry_check
        CHECK (expires_at >= created_at),
    CONSTRAINT conversation_sessions_activity_check
        CHECK (last_activity_at >= created_at),
    CONSTRAINT conversation_sessions_version_check
        CHECK (version > 0)
);

CREATE TRIGGER conversation_sessions_touch_version
BEFORE UPDATE ON messaging.conversation_sessions
FOR EACH ROW
EXECUTE FUNCTION identity.touch_versioned_row();

CREATE INDEX conversation_sessions_expiry_idx
    ON messaging.conversation_sessions (expires_at)
    WHERE status = 'active';

CREATE UNIQUE INDEX conversation_sessions_one_active_idx
    ON messaging.conversation_sessions (channel_identity_id)
    WHERE status = 'active';

CREATE TABLE integration.inbound_events (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    provider_code varchar(32) NOT NULL
        REFERENCES identity.channel_providers (code) ON DELETE RESTRICT,
    provider_namespace varchar(128) COLLATE "C" NOT NULL,
    provider_event_id varchar(512) COLLATE "C" NOT NULL,
    event_type varchar(128) COLLATE "C" NOT NULL,
    payload_version smallint NOT NULL,
    payload_ciphertext bytea,
    payload_nonce bytea,
    payload_purged_at timestamptz,
    payload_fingerprint bytea NOT NULL,
    encryption_key_purpose text NOT NULL DEFAULT 'integration_encryption',
    encryption_key_version smallint NOT NULL,
    fingerprint_key_purpose text NOT NULL DEFAULT 'lookup_hmac',
    fingerprint_key_version smallint NOT NULL,
    correlation_id uuid NOT NULL DEFAULT uuidv7(),
    signature_verified_at timestamptz NOT NULL,
    provider_occurred_at timestamptz,
    received_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (encryption_key_purpose, encryption_key_version)
        REFERENCES private_data.key_versions (purpose, version) ON DELETE RESTRICT,
    FOREIGN KEY (fingerprint_key_purpose, fingerprint_key_version)
        REFERENCES private_data.key_versions (purpose, version) ON DELETE RESTRICT,
    CONSTRAINT inbound_events_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT inbound_events_namespace_check
        CHECK (octet_length(btrim(provider_namespace)) BETWEEN 1 AND 128),
    CONSTRAINT inbound_events_provider_event_id_check
        CHECK (length(btrim(provider_event_id)) BETWEEN 1 AND 512),
    CONSTRAINT inbound_events_event_type_check
        CHECK (event_type ~ '^[a-z][a-z0-9_.-]{1,127}$'),
    CONSTRAINT inbound_events_payload_version_check
        CHECK (payload_version > 0),
    CONSTRAINT inbound_events_payload_state_check
        CHECK (
            (
                payload_ciphertext IS NOT NULL
                AND octet_length(payload_ciphertext) >= 16
                AND payload_nonce IS NOT NULL
                AND octet_length(payload_nonce) = 12
                AND payload_purged_at IS NULL
            )
            OR (
                payload_ciphertext IS NULL
                AND payload_nonce IS NULL
                AND payload_purged_at IS NOT NULL
            )
        ),
    CONSTRAINT inbound_events_fingerprint_check
        CHECK (octet_length(payload_fingerprint) = 32),
    CONSTRAINT inbound_events_correlation_version_check
        CHECK (uuid_extract_version(correlation_id) = 7),
    CONSTRAINT inbound_events_key_purpose_check
        CHECK (encryption_key_purpose = 'integration_encryption'),
    CONSTRAINT inbound_events_fingerprint_key_purpose_check
        CHECK (fingerprint_key_purpose = 'lookup_hmac'),
    CONSTRAINT inbound_events_provider_event_unique
        UNIQUE (provider_code, provider_namespace, provider_event_id)
);

ALTER TABLE messaging.conversation_sessions
    ADD CONSTRAINT conversation_sessions_last_inbound_event_fk
    FOREIGN KEY (last_inbound_event_id)
    REFERENCES integration.inbound_events (id)
    ON DELETE SET NULL;

CREATE INDEX inbound_events_received_brin_idx
    ON integration.inbound_events USING brin (received_at);

CREATE INDEX inbound_events_correlation_idx
    ON integration.inbound_events (correlation_id, received_at);

CREATE TABLE integration.inbound_event_fingerprints (
    inbound_event_id uuid NOT NULL
        REFERENCES integration.inbound_events (id) ON DELETE CASCADE,
    key_purpose text NOT NULL DEFAULT 'lookup_hmac',
    key_version smallint NOT NULL,
    digest bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (inbound_event_id, key_version),
    FOREIGN KEY (key_purpose, key_version)
        REFERENCES private_data.key_versions (purpose, version) ON DELETE RESTRICT,
    CONSTRAINT inbound_event_fingerprints_key_purpose_check
        CHECK (key_purpose = 'lookup_hmac'),
    CONSTRAINT inbound_event_fingerprints_digest_check
        CHECK (octet_length(digest) = 32)
);

CREATE INDEX inbound_event_fingerprints_lookup_idx
    ON integration.inbound_event_fingerprints (key_version, digest, inbound_event_id);

CREATE TABLE integration.outbox_jobs (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    inbound_event_id uuid REFERENCES integration.inbound_events (id) ON DELETE RESTRICT,
    job_kind varchar(128) COLLATE "C" NOT NULL,
    idempotency_key varchar(255) COLLATE "C" NOT NULL,
    payload_version smallint NOT NULL,
    payload jsonb NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'pending',
    priority smallint NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    attempt_count integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 10,
    lease_owner uuid,
    lease_token uuid,
    lease_started_at timestamptz,
    lease_expires_at timestamptz,
    last_error_class varchar(64) COLLATE "C",
    last_error_code varchar(128) COLLATE "C",
    last_error_at timestamptz,
    completed_at timestamptz,
    dead_lettered_at timestamptz,
    dead_letter_reason varchar(128) COLLATE "C",
    correlation_id uuid NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT outbox_jobs_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT outbox_jobs_kind_check
        CHECK (job_kind ~ '^[a-z][a-z0-9_.-]{1,127}$'),
    CONSTRAINT outbox_jobs_idempotency_key_check
        CHECK (length(btrim(idempotency_key)) BETWEEN 1 AND 255),
    CONSTRAINT outbox_jobs_payload_version_check
        CHECK (payload_version > 0),
    CONSTRAINT outbox_jobs_payload_check
        CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 65536),
    CONSTRAINT outbox_jobs_state_check
        CHECK (state IN ('pending', 'leased', 'completed', 'dead_lettered')),
    CONSTRAINT outbox_jobs_priority_check
        CHECK (priority BETWEEN -100 AND 100),
    CONSTRAINT outbox_jobs_attempt_check
        CHECK (max_attempts BETWEEN 1 AND 100 AND attempt_count BETWEEN 0 AND max_attempts),
    CONSTRAINT outbox_jobs_state_shape_check
        CHECK (
            (
                state = 'pending'
                AND attempt_count < max_attempts
                AND lease_owner IS NULL
                AND lease_token IS NULL
                AND lease_started_at IS NULL
                AND lease_expires_at IS NULL
                AND completed_at IS NULL
                AND dead_lettered_at IS NULL
                AND dead_letter_reason IS NULL
            )
            OR (
                state = 'leased'
                AND attempt_count >= 1
                AND lease_owner IS NOT NULL
                AND lease_token IS NOT NULL
                AND lease_started_at IS NOT NULL
                AND lease_expires_at > lease_started_at
                AND completed_at IS NULL
                AND dead_lettered_at IS NULL
                AND dead_letter_reason IS NULL
            )
            OR (
                state = 'completed'
                AND attempt_count >= 1
                AND lease_owner IS NULL
                AND lease_token IS NULL
                AND lease_started_at IS NULL
                AND lease_expires_at IS NULL
                AND completed_at IS NOT NULL
                AND dead_lettered_at IS NULL
                AND dead_letter_reason IS NULL
            )
            OR (
                state = 'dead_lettered'
                AND attempt_count >= 1
                AND lease_owner IS NULL
                AND lease_token IS NULL
                AND lease_started_at IS NULL
                AND lease_expires_at IS NULL
                AND completed_at IS NULL
                AND dead_lettered_at IS NOT NULL
                AND dead_letter_reason IS NOT NULL
            )
        ),
    CONSTRAINT outbox_jobs_lease_token_version_check
        CHECK (lease_token IS NULL OR uuid_extract_version(lease_token) = 4),
    CONSTRAINT outbox_jobs_lease_owner_version_check
        CHECK (lease_owner IS NULL OR uuid_extract_version(lease_owner) = 7),
    CONSTRAINT outbox_jobs_correlation_version_check
        CHECK (uuid_extract_version(correlation_id) = 7),
    CONSTRAINT outbox_jobs_idempotency_unique
        UNIQUE (job_kind, idempotency_key)
);

CREATE TRIGGER outbox_jobs_touch_version
BEFORE UPDATE ON integration.outbox_jobs
FOR EACH ROW
EXECUTE FUNCTION identity.touch_versioned_row();

CREATE INDEX outbox_jobs_claim_idx
    ON integration.outbox_jobs (priority DESC, available_at, created_at, id)
    WHERE state = 'pending';

CREATE INDEX outbox_jobs_expired_lease_idx
    ON integration.outbox_jobs (lease_expires_at, created_at, id)
    WHERE state = 'leased';

CREATE INDEX outbox_jobs_inbound_event_idx
    ON integration.outbox_jobs (inbound_event_id)
    WHERE inbound_event_id IS NOT NULL;

CREATE INDEX outbox_jobs_created_brin_idx
    ON integration.outbox_jobs USING brin (created_at);

CREATE UNIQUE INDEX outbox_jobs_one_inbound_processing_job_idx
    ON integration.outbox_jobs (inbound_event_id)
    WHERE inbound_event_id IS NOT NULL;

CREATE INDEX outbox_jobs_dead_letter_idx
    ON integration.outbox_jobs (dead_lettered_at, id)
    WHERE state = 'dead_lettered';

CREATE TABLE audit.events (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    actor_type text NOT NULL,
    actor_account_id uuid REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    actor_channel_identity_id uuid,
    source_channel text NOT NULL,
    action varchar(128) NOT NULL,
    target_type varchar(128) NOT NULL,
    target_id uuid,
    reason_code varchar(128) NOT NULL,
    before_digest bytea,
    after_digest bytea,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    event_schema_version smallint NOT NULL DEFAULT 1,
    correlation_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (actor_account_id, actor_channel_identity_id)
        REFERENCES identity.channel_identities (account_id, id) ON DELETE RESTRICT,
    CONSTRAINT audit_events_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT audit_events_correlation_version_check
        CHECK (uuid_extract_version(correlation_id) = 7),
    CONSTRAINT audit_events_actor_type_check
        CHECK (actor_type IN ('account', 'administrator', 'system')),
    CONSTRAINT audit_events_actor_check
        CHECK (
            (actor_type = 'system') = (actor_account_id IS NULL)
            AND (actor_account_id IS NOT NULL OR actor_channel_identity_id IS NULL)
            AND (actor_type <> 'account' OR actor_channel_identity_id IS NOT NULL)
            AND (source_channel <> 'whatsapp' OR actor_channel_identity_id IS NOT NULL)
        ),
    CONSTRAINT audit_events_source_channel_check
        CHECK (source_channel IN ('whatsapp', 'internal_cli', 'admin_ui', 'system')),
    CONSTRAINT audit_events_source_actor_check
        CHECK ((source_channel = 'system') = (actor_type = 'system')),
    CONSTRAINT audit_events_action_check
        CHECK (action ~ '^[a-z][a-z0-9_.-]{1,127}$'),
    CONSTRAINT audit_events_target_type_check
        CHECK (target_type ~ '^[a-z][a-z0-9_.-]{1,127}$'),
    CONSTRAINT audit_events_reason_code_check
        CHECK (reason_code ~ '^[a-z][a-z0-9_.-]{1,127}$'),
    CONSTRAINT audit_events_before_digest_check
        CHECK (before_digest IS NULL OR octet_length(before_digest) = 32),
    CONSTRAINT audit_events_after_digest_check
        CHECK (after_digest IS NULL OR octet_length(after_digest) = 32),
    CONSTRAINT audit_events_schema_version_check
        CHECK (event_schema_version > 0),
    CONSTRAINT audit_events_metadata_check
        CHECK (jsonb_typeof(metadata) = 'object' AND octet_length(metadata::text) <= 32768)
);

CREATE INDEX audit_events_target_idx
    ON audit.events (target_type, target_id, occurred_at DESC)
    WHERE target_id IS NOT NULL;

CREATE INDEX audit_events_actor_idx
    ON audit.events (actor_account_id, occurred_at DESC)
    WHERE actor_account_id IS NOT NULL;

CREATE INDEX audit_events_occurred_brin_idx
    ON audit.events USING brin (occurred_at);

CREATE OR REPLACE FUNCTION audit.reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit events are immutable';
END;
$$;

CREATE TRIGGER audit_events_reject_update
BEFORE UPDATE ON audit.events
FOR EACH ROW
EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER audit_events_reject_delete
BEFORE DELETE ON audit.events
FOR EACH ROW
EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER audit_events_reject_truncate
BEFORE TRUNCATE ON audit.events
FOR EACH STATEMENT
EXECUTE FUNCTION audit.reject_mutation();

CREATE OR REPLACE FUNCTION audit.guard_inbound_event_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.payload_ciphertext IS NOT NULL
       AND OLD.payload_nonce IS NOT NULL
       AND OLD.payload_purged_at IS NULL
       AND NEW.payload_ciphertext IS NULL
       AND NEW.payload_nonce IS NULL
       AND NEW.payload_purged_at IS NOT NULL
       AND NEW.id = OLD.id
       AND NEW.provider_code = OLD.provider_code
       AND NEW.provider_namespace = OLD.provider_namespace
       AND NEW.provider_event_id = OLD.provider_event_id
       AND NEW.event_type = OLD.event_type
       AND NEW.payload_version = OLD.payload_version
       AND NEW.payload_fingerprint = OLD.payload_fingerprint
       AND NEW.encryption_key_purpose = OLD.encryption_key_purpose
       AND NEW.encryption_key_version = OLD.encryption_key_version
       AND NEW.fingerprint_key_purpose = OLD.fingerprint_key_purpose
       AND NEW.fingerprint_key_version = OLD.fingerprint_key_version
       AND NEW.correlation_id = OLD.correlation_id
       AND NEW.signature_verified_at = OLD.signature_verified_at
       AND NEW.provider_occurred_at IS NOT DISTINCT FROM OLD.provider_occurred_at
       AND NEW.received_at = OLD.received_at
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'inbound events are immutable except for payload purge';
END;
$$;

CREATE TRIGGER inbound_events_guard_update
BEFORE UPDATE ON integration.inbound_events
FOR EACH ROW
EXECUTE FUNCTION audit.guard_inbound_event_update();

CREATE TRIGGER inbound_events_reject_delete
BEFORE DELETE ON integration.inbound_events
FOR EACH ROW
EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER inbound_events_reject_truncate
BEFORE TRUNCATE ON integration.inbound_events
FOR EACH STATEMENT
EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER inbound_event_fingerprints_reject_update
BEFORE UPDATE ON integration.inbound_event_fingerprints
FOR EACH ROW
EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER inbound_event_fingerprints_reject_delete
BEFORE DELETE ON integration.inbound_event_fingerprints
FOR EACH ROW
EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER inbound_event_fingerprints_reject_truncate
BEFORE TRUNCATE ON integration.inbound_event_fingerprints
FOR EACH STATEMENT
EXECUTE FUNCTION audit.reject_mutation();

COMMENT ON SCHEMA private_data IS 'Restricted encrypted identity data and cryptographic metadata.';
COMMENT ON TABLE private_data.key_versions IS 'Non-secret metadata for externally managed encryption and lookup keys.';
COMMENT ON TABLE identity.accounts IS 'Channel-independent account lifecycle and risk state.';
COMMENT ON TABLE identity.account_roles IS 'Current capabilities granted to an account.';
COMMENT ON TABLE identity.channel_providers IS 'Registered communication channel types supported by the platform.';
COMMENT ON TABLE identity.channel_identities IS 'Channel-neutral account ownership and lifecycle metadata.';
COMMENT ON TABLE private_data.whatsapp_identities IS 'Encrypted WhatsApp identifiers, consent, and delivery-window state.';
COMMENT ON TABLE private_data.channel_lookup_digests IS 'Versioned keyed lookup digests supporting rotation without plaintext identifiers.';
COMMENT ON TABLE profile.public_profiles IS 'Privacy-safe profile data that may be presented during discovery.';
COMMENT ON TABLE private_data.account_identities IS 'Encrypted legal identity payload and verification lifecycle.';
COMMENT ON TABLE messaging.conversation_sessions IS 'Current recoverable workflow state; sensitive identity data is prohibited.';
COMMENT ON TABLE integration.inbound_events IS 'Immutable encrypted external events deduplicated by provider identifier.';
COMMENT ON TABLE integration.inbound_event_fingerprints IS 'Versioned keyed fingerprints supporting collision checks through lookup-key rotation.';
COMMENT ON TABLE integration.outbox_jobs IS 'Durable leased work queue created atomically with business changes.';
COMMENT ON TABLE audit.events IS 'Append-only administrative and security-relevant audit trail.';
