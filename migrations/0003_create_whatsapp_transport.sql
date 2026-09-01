-- Add durable WhatsApp submission and delivery records without coupling
-- product workflows to Meta request or webhook structures.

CREATE TABLE messaging.outbound_messages (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    provider_code varchar(32) COLLATE "C" NOT NULL
        REFERENCES identity.channel_providers (code) ON DELETE RESTRICT,
    provider_namespace varchar(128) COLLATE "C" NOT NULL,
    recipient_channel_identity_id uuid
        REFERENCES identity.channel_identities (id) ON DELETE RESTRICT,
    idempotency_key varchar(255) COLLATE "C" NOT NULL,
    request_fingerprint bytea NOT NULL,
    fingerprint_key_purpose text NOT NULL DEFAULT 'lookup_hmac',
    fingerprint_key_version smallint NOT NULL,
    payload_schema_version smallint NOT NULL,
    payload_ciphertext bytea NOT NULL,
    payload_nonce bytea NOT NULL,
    encryption_key_purpose text NOT NULL DEFAULT 'integration_encryption',
    encryption_key_version smallint NOT NULL,
    callback_token uuid NOT NULL DEFAULT uuidv4(),
    correlation_id uuid NOT NULL,
    submission_state text COLLATE "C" NOT NULL DEFAULT 'queued',
    send_attempt_count integer NOT NULL DEFAULT 0,
    send_lease_token uuid,
    send_started_at timestamptz,
    provider_message_id varchar(512) COLLATE "C",
    provider_acceptance_status varchar(64) COLLATE "C",
    accepted_at timestamptz,
    last_error_class varchar(64) COLLATE "C",
    last_error_code varchar(128) COLLATE "C",
    provider_trace_id varchar(255) COLLATE "C",
    unknown_at timestamptz,
    rejected_at timestamptz,
    sent_at timestamptz,
    delivered_at timestamptz,
    read_at timestamptz,
    played_at timestamptz,
    failed_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (fingerprint_key_purpose, fingerprint_key_version)
        REFERENCES private_data.key_versions (purpose, version) ON DELETE RESTRICT,
    FOREIGN KEY (encryption_key_purpose, encryption_key_version)
        REFERENCES private_data.key_versions (purpose, version) ON DELETE RESTRICT,
    CONSTRAINT outbound_messages_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT outbound_messages_namespace_check
        CHECK (octet_length(btrim(provider_namespace)) BETWEEN 1 AND 128),
    CONSTRAINT outbound_messages_idempotency_key_check
        CHECK (octet_length(btrim(idempotency_key)) BETWEEN 1 AND 255),
    CONSTRAINT outbound_messages_fingerprint_check
        CHECK (octet_length(request_fingerprint) = 32),
    CONSTRAINT outbound_messages_fingerprint_purpose_check
        CHECK (fingerprint_key_purpose = 'lookup_hmac'),
    CONSTRAINT outbound_messages_payload_version_check
        CHECK (payload_schema_version > 0),
    CONSTRAINT outbound_messages_payload_check
        CHECK (octet_length(payload_ciphertext) >= 16),
    CONSTRAINT outbound_messages_nonce_check
        CHECK (octet_length(payload_nonce) = 12),
    CONSTRAINT outbound_messages_encryption_purpose_check
        CHECK (encryption_key_purpose = 'integration_encryption'),
    CONSTRAINT outbound_messages_callback_version_check
        CHECK (uuid_extract_version(callback_token) = 4),
    CONSTRAINT outbound_messages_correlation_version_check
        CHECK (uuid_extract_version(correlation_id) = 7),
    CONSTRAINT outbound_messages_state_check
        CHECK (submission_state IN ('queued', 'sending', 'accepted', 'unknown', 'rejected')),
    CONSTRAINT outbound_messages_attempt_check
        CHECK (send_attempt_count >= 0),
    CONSTRAINT outbound_messages_submission_shape_check
        CHECK (
            (
                submission_state = 'queued'
                AND send_lease_token IS NULL
                AND send_started_at IS NULL
                AND provider_message_id IS NULL
                AND accepted_at IS NULL
                AND unknown_at IS NULL
                AND rejected_at IS NULL
            )
            OR (
                submission_state = 'sending'
                AND send_lease_token IS NOT NULL
                AND uuid_extract_version(send_lease_token) = 4
                AND send_started_at IS NOT NULL
                AND provider_message_id IS NULL
                AND accepted_at IS NULL
                AND unknown_at IS NULL
                AND rejected_at IS NULL
            )
            OR (
                submission_state = 'accepted'
                AND send_lease_token IS NULL
                AND provider_message_id IS NOT NULL
                AND accepted_at IS NOT NULL
                AND unknown_at IS NULL
                AND rejected_at IS NULL
            )
            OR (
                submission_state = 'unknown'
                AND send_lease_token IS NULL
                AND accepted_at IS NULL
                AND unknown_at IS NOT NULL
                AND rejected_at IS NULL
            )
            OR (
                submission_state = 'rejected'
                AND send_lease_token IS NULL
                AND provider_message_id IS NULL
                AND accepted_at IS NULL
                AND unknown_at IS NULL
                AND rejected_at IS NOT NULL
            )
        ),
    CONSTRAINT outbound_messages_idempotency_unique
        UNIQUE (provider_code, provider_namespace, idempotency_key),
    CONSTRAINT outbound_messages_callback_unique
        UNIQUE (callback_token)
);

CREATE UNIQUE INDEX outbound_messages_provider_message_unique_idx
    ON messaging.outbound_messages (provider_code, provider_namespace, provider_message_id)
    WHERE provider_message_id IS NOT NULL;

CREATE INDEX outbound_messages_submission_state_idx
    ON messaging.outbound_messages (submission_state, created_at, id);

CREATE INDEX outbound_messages_recipient_idx
    ON messaging.outbound_messages (recipient_channel_identity_id, created_at DESC)
    WHERE recipient_channel_identity_id IS NOT NULL;

CREATE TRIGGER outbound_messages_touch_version
BEFORE UPDATE ON messaging.outbound_messages
FOR EACH ROW
EXECUTE FUNCTION identity.touch_versioned_row();

CREATE TABLE messaging.outbound_message_fingerprints (
    outbound_message_id uuid NOT NULL
        REFERENCES messaging.outbound_messages (id) ON DELETE CASCADE,
    key_purpose text NOT NULL DEFAULT 'lookup_hmac',
    key_version smallint NOT NULL,
    digest bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (outbound_message_id, key_version),
    FOREIGN KEY (key_purpose, key_version)
        REFERENCES private_data.key_versions (purpose, version) ON DELETE RESTRICT,
    CONSTRAINT outbound_message_fingerprints_key_purpose_check
        CHECK (key_purpose = 'lookup_hmac'),
    CONSTRAINT outbound_message_fingerprints_digest_check
        CHECK (octet_length(digest) = 32)
);

CREATE INDEX outbound_message_fingerprints_lookup_idx
    ON messaging.outbound_message_fingerprints (key_version, digest, outbound_message_id);

CREATE TRIGGER outbound_message_fingerprints_reject_update
BEFORE UPDATE ON messaging.outbound_message_fingerprints
FOR EACH ROW
EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER outbound_message_fingerprints_reject_delete
BEFORE DELETE ON messaging.outbound_message_fingerprints
FOR EACH ROW
EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER outbound_message_fingerprints_reject_truncate
BEFORE TRUNCATE ON messaging.outbound_message_fingerprints
FOR EACH STATEMENT
EXECUTE FUNCTION audit.reject_mutation();

CREATE TABLE messaging.outbound_delivery_events (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    inbound_event_id uuid NOT NULL UNIQUE
        REFERENCES integration.inbound_events (id) ON DELETE RESTRICT,
    outbound_message_id uuid
        REFERENCES messaging.outbound_messages (id) ON DELETE RESTRICT,
    provider_code varchar(32) COLLATE "C" NOT NULL
        REFERENCES identity.channel_providers (code) ON DELETE RESTRICT,
    provider_namespace varchar(128) COLLATE "C" NOT NULL,
    provider_message_id varchar(512) COLLATE "C" NOT NULL,
    provider_status varchar(32) COLLATE "C" NOT NULL,
    provider_error_code bigint,
    error_class varchar(64) COLLATE "C",
    provider_occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT outbound_delivery_events_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT outbound_delivery_events_namespace_check
        CHECK (octet_length(btrim(provider_namespace)) BETWEEN 1 AND 128),
    CONSTRAINT outbound_delivery_events_message_id_check
        CHECK (octet_length(btrim(provider_message_id)) BETWEEN 1 AND 512),
    CONSTRAINT outbound_delivery_events_status_check
        CHECK (provider_status IN ('sent', 'delivered', 'read', 'played', 'failed')),
    CONSTRAINT outbound_delivery_events_error_shape_check
        CHECK (
            (provider_status = 'failed')
            OR (provider_error_code IS NULL AND error_class IS NULL)
        )
);

CREATE INDEX outbound_delivery_events_message_idx
    ON messaging.outbound_delivery_events (
        provider_code,
        provider_namespace,
        provider_message_id,
        provider_occurred_at
    );

CREATE INDEX outbound_delivery_events_orphan_idx
    ON messaging.outbound_delivery_events (received_at, id)
    WHERE outbound_message_id IS NULL;

CREATE OR REPLACE FUNCTION audit.guard_delivery_event_link()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.outbound_message_id IS NULL
       AND NEW.outbound_message_id IS NOT NULL
       AND NEW.id = OLD.id
       AND NEW.inbound_event_id = OLD.inbound_event_id
       AND NEW.provider_code = OLD.provider_code
       AND NEW.provider_namespace = OLD.provider_namespace
       AND NEW.provider_message_id = OLD.provider_message_id
       AND NEW.provider_status = OLD.provider_status
       AND NEW.provider_error_code IS NOT DISTINCT FROM OLD.provider_error_code
       AND NEW.error_class IS NOT DISTINCT FROM OLD.error_class
       AND NEW.provider_occurred_at = OLD.provider_occurred_at
       AND NEW.received_at = OLD.received_at
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'delivery events are immutable except for orphan linking';
END;
$$;

CREATE TRIGGER outbound_delivery_events_guard_update
BEFORE UPDATE ON messaging.outbound_delivery_events
FOR EACH ROW
EXECUTE FUNCTION audit.guard_delivery_event_link();

CREATE TRIGGER outbound_delivery_events_reject_delete
BEFORE DELETE ON messaging.outbound_delivery_events
FOR EACH ROW
EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER outbound_delivery_events_reject_truncate
BEFORE TRUNCATE ON messaging.outbound_delivery_events
FOR EACH STATEMENT
EXECUTE FUNCTION audit.reject_mutation();

ALTER TABLE integration.outbox_jobs
    ADD COLUMN outbound_message_id uuid
        REFERENCES messaging.outbound_messages (id) ON DELETE RESTRICT;

ALTER TABLE integration.outbox_jobs
    ADD CONSTRAINT outbox_jobs_source_shape_check
    CHECK (
        (
            job_kind IN ('process_webhook', 'process_whatsapp_status', 'process_whatsapp_probe')
            AND inbound_event_id IS NOT NULL
            AND outbound_message_id IS NULL
        )
        OR (
            job_kind = 'send_whatsapp_message'
            AND inbound_event_id IS NULL
            AND outbound_message_id IS NOT NULL
        )
    );

CREATE UNIQUE INDEX outbox_jobs_one_outbound_send_idx
    ON integration.outbox_jobs (outbound_message_id)
    WHERE job_kind = 'send_whatsapp_message';

CREATE INDEX outbox_jobs_outbound_message_idx
    ON integration.outbox_jobs (outbound_message_id)
    WHERE outbound_message_id IS NOT NULL;

COMMENT ON TABLE messaging.outbound_messages IS 'Encrypted WhatsApp submission ledger separated from delivery milestones.';
COMMENT ON TABLE messaging.outbound_message_fingerprints IS 'Versioned request fingerprints supporting idempotency checks through key rotation.';
COMMENT ON TABLE messaging.outbound_delivery_events IS 'Append-only Meta delivery transitions, including unmatched orphan statuses.';
