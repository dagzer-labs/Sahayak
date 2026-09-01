-- Add durable workflow state, internal prompt correlation, and idempotent turn receipts.

ALTER TABLE identity.accounts
    ADD COLUMN preferred_locale_confirmed_at timestamptz;

ALTER TABLE identity.accounts
    ADD CONSTRAINT accounts_locale_confirmation_check
    CHECK (
        preferred_locale_confirmed_at IS NULL
        OR preferred_locale_confirmed_at >= created_at
    );

ALTER TABLE identity.channel_identities
    ADD CONSTRAINT channel_identities_provider_namespace_unique
    UNIQUE (id, provider_code, provider_namespace);

ALTER TABLE messaging.conversation_sessions
    DROP COLUMN last_provider_message_id;

ALTER TABLE messaging.conversation_sessions
    ADD COLUMN workflow_correlation_id uuid NOT NULL DEFAULT uuidv7(),
    ADD COLUMN expected_reply_to_outbound_message_id uuid,
    ADD COLUMN ended_at timestamptz,
    ADD COLUMN terminal_reason varchar(64) COLLATE "C";

UPDATE messaging.conversation_sessions
SET
    ended_at = COALESCE(updated_at, created_at),
    terminal_reason = CASE status
        WHEN 'completed' THEN 'completed_before_v1'
        WHEN 'expired' THEN 'timeout_before_v1'
        WHEN 'abandoned' THEN 'abandoned_before_v1'
        ELSE terminal_reason
    END,
    state_data = CASE
        WHEN status IN ('completed', 'expired', 'abandoned') THEN '{}'::jsonb
        ELSE state_data
    END,
    last_inbound_event_id = CASE
        WHEN status IN ('completed', 'expired', 'abandoned') THEN NULL
        ELSE last_inbound_event_id
    END
WHERE status IN ('completed', 'expired', 'abandoned');

ALTER TABLE messaging.conversation_sessions
    ADD CONSTRAINT conversation_sessions_id_channel_unique
    UNIQUE (id, channel_identity_id),
    ADD CONSTRAINT conversation_sessions_correlation_version_check
    CHECK (uuid_extract_version(workflow_correlation_id) = 7),
    ADD CONSTRAINT conversation_sessions_terminal_reason_check
    CHECK (
        terminal_reason IS NULL
        OR terminal_reason ~ '^[a-z][a-z0-9_.-]{1,63}$'
    ),
    ADD CONSTRAINT conversation_sessions_terminal_shape_check
    CHECK (
        (
            status = 'active'
            AND ended_at IS NULL
            AND terminal_reason IS NULL
        )
        OR (
            status IN ('completed', 'expired', 'abandoned')
            AND ended_at IS NOT NULL
            AND terminal_reason IS NOT NULL
        )
    );

CREATE INDEX conversation_sessions_workflow_correlation_idx
    ON messaging.conversation_sessions (workflow_correlation_id, created_at);

ALTER TABLE messaging.outbound_messages
    DROP CONSTRAINT outbound_messages_recipient_channel_identity_id_fkey,
    ADD COLUMN conversation_session_id uuid,
    ADD CONSTRAINT outbound_messages_recipient_channel_provider_fk
        FOREIGN KEY (
            recipient_channel_identity_id,
            provider_code,
            provider_namespace
        )
        REFERENCES identity.channel_identities (
            id,
            provider_code,
            provider_namespace
        )
        ON DELETE RESTRICT,
    ADD CONSTRAINT outbound_messages_recipient_id_unique
        UNIQUE (recipient_channel_identity_id, id),
    ADD CONSTRAINT outbound_messages_conversation_channel_fk
        FOREIGN KEY (conversation_session_id, recipient_channel_identity_id)
        REFERENCES messaging.conversation_sessions (id, channel_identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT outbound_messages_conversation_recipient_check
        CHECK (
            conversation_session_id IS NULL
            OR recipient_channel_identity_id IS NOT NULL
        );

ALTER TABLE messaging.conversation_sessions
    ADD CONSTRAINT conversation_sessions_expected_reply_fk
    FOREIGN KEY (channel_identity_id, expected_reply_to_outbound_message_id)
    REFERENCES messaging.outbound_messages (recipient_channel_identity_id, id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX outbound_messages_conversation_idx
    ON messaging.outbound_messages (conversation_session_id, created_at)
    WHERE conversation_session_id IS NOT NULL;

CREATE TABLE messaging.conversation_turn_receipts (
    inbound_event_id uuid PRIMARY KEY
        REFERENCES integration.inbound_events (id) ON DELETE RESTRICT,
    processing_job_id uuid NOT NULL UNIQUE
        REFERENCES integration.outbox_jobs (id) ON DELETE RESTRICT,
    channel_identity_id uuid NOT NULL
        REFERENCES identity.channel_identities (id) ON DELETE RESTRICT,
    previous_session_id uuid
        REFERENCES messaging.conversation_sessions (id) ON DELETE RESTRICT,
    previous_session_version bigint,
    next_session_id uuid
        REFERENCES messaging.conversation_sessions (id) ON DELETE RESTRICT,
    next_session_version bigint,
    outbound_message_id uuid
        REFERENCES messaging.outbound_messages (id) ON DELETE RESTRICT,
    workflow_correlation_id uuid NOT NULL,
    disposition text COLLATE "C" NOT NULL,
    completed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT conversation_turn_receipts_session_versions_check
        CHECK (
            (previous_session_id IS NULL) = (previous_session_version IS NULL)
            AND (next_session_id IS NULL) = (next_session_version IS NULL)
        ),
    CONSTRAINT conversation_turn_receipts_versions_positive_check
        CHECK (
            (previous_session_version IS NULL OR previous_session_version > 0)
            AND (next_session_version IS NULL OR next_session_version > 0)
        ),
    CONSTRAINT conversation_turn_receipts_correlation_version_check
        CHECK (uuid_extract_version(workflow_correlation_id) = 7),
    CONSTRAINT conversation_turn_receipts_disposition_check
        CHECK (disposition IN ('applied', 'unexpected', 'stale', 'recovered', 'ignored'))
);

CREATE INDEX conversation_turn_receipts_channel_idx
    ON messaging.conversation_turn_receipts (channel_identity_id, completed_at DESC);

CREATE INDEX conversation_turn_receipts_correlation_idx
    ON messaging.conversation_turn_receipts (workflow_correlation_id, completed_at);

CREATE TRIGGER conversation_turn_receipts_reject_update
BEFORE UPDATE ON messaging.conversation_turn_receipts
FOR EACH ROW
EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER conversation_turn_receipts_reject_delete
BEFORE DELETE ON messaging.conversation_turn_receipts
FOR EACH ROW
EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER conversation_turn_receipts_reject_truncate
BEFORE TRUNCATE ON messaging.conversation_turn_receipts
FOR EACH STATEMENT
EXECUTE FUNCTION audit.reject_mutation();

ALTER TABLE integration.outbox_jobs
    DROP CONSTRAINT outbox_jobs_source_shape_check;

ALTER TABLE integration.outbox_jobs
    ADD COLUMN ordering_key bytea;

ALTER TABLE integration.outbox_jobs
    ADD CONSTRAINT outbox_jobs_ordering_key_check
    CHECK (ordering_key IS NULL OR octet_length(ordering_key) = 32);

CREATE INDEX outbox_jobs_ordering_idx
    ON integration.outbox_jobs (ordering_key, created_at, id)
    WHERE ordering_key IS NOT NULL
      AND state IN ('pending', 'leased');

UPDATE integration.outbox_jobs AS job
SET job_kind = CASE event.event_type
    WHEN 'message.received' THEN 'process_conversation_message'
    WHEN 'provider.error' THEN 'process_provider_error'
    ELSE job.job_kind
END
FROM integration.inbound_events AS event
WHERE event.id = job.inbound_event_id
  AND job.job_kind = 'process_webhook'
  AND job.state = 'pending';

ALTER TABLE integration.outbox_jobs
    ADD CONSTRAINT outbox_jobs_source_shape_check
    CHECK (
        (
            job_kind IN (
                'process_conversation_message',
                'process_provider_error',
                'process_webhook',
                'process_whatsapp_probe',
                'process_whatsapp_status'
            )
            AND inbound_event_id IS NOT NULL
            AND outbound_message_id IS NULL
        )
        OR (
            job_kind = 'send_whatsapp_message'
            AND inbound_event_id IS NULL
            AND outbound_message_id IS NOT NULL
        )
    );

COMMENT ON TABLE messaging.conversation_turn_receipts IS 'Immutable proof that one inbound event committed at most one conversation outcome.';
