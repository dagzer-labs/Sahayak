-- Build the reviewable professional-profile aggregate and its restricted
-- consent, media, administrator, and optional identity-verification records.

ALTER TABLE private_data.key_versions
    DROP CONSTRAINT key_versions_purpose_check,
    DROP CONSTRAINT key_versions_algorithm_check;

ALTER TABLE private_data.key_versions
    ADD CONSTRAINT key_versions_purpose_check
        CHECK (purpose IN (
            'contact_encryption',
            'identity_encryption',
            'integration_encryption',
            'media_encryption',
            'lookup_hmac'
        )),
    ADD CONSTRAINT key_versions_algorithm_check
        CHECK (
            (
                purpose IN (
                    'contact_encryption',
                    'identity_encryption',
                    'integration_encryption',
                    'media_encryption'
                )
                AND algorithm = 'aes-256-gcm'
            )
            OR (purpose = 'lookup_hmac' AND algorithm = 'hmac-sha-256')
        );

INSERT INTO private_data.key_versions (purpose, version, key_reference, algorithm)
VALUES ('media_encryption', 1, 'secret:media-key-v1', 'aes-256-gcm');

CREATE TABLE profile.legacy_profile_review_migration_audit (
    profile_id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    legacy_status text NOT NULL,
    legacy_reviewed_by uuid,
    legacy_reviewed_at timestamptz,
    legacy_published_at timestamptz,
    migrated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

INSERT INTO profile.legacy_profile_review_migration_audit (
    profile_id, account_id, legacy_status, legacy_reviewed_by,
    legacy_reviewed_at, legacy_published_at
)
SELECT id, account_id, status, reviewed_by, reviewed_at, published_at
FROM profile.public_profiles;

CREATE TRIGGER legacy_profile_review_migration_audit_reject_update
BEFORE UPDATE ON profile.legacy_profile_review_migration_audit
FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER legacy_profile_review_migration_audit_reject_delete
BEFORE DELETE ON profile.legacy_profile_review_migration_audit
FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER legacy_profile_review_migration_audit_reject_truncate
BEFORE TRUNCATE ON profile.legacy_profile_review_migration_audit
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

ALTER TABLE integration.inbound_events
    ADD COLUMN account_id uuid REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    ADD COLUMN channel_identity_id uuid REFERENCES identity.channel_identities (id) ON DELETE RESTRICT,
    ADD COLUMN reply_to_outbound_message_id uuid
        REFERENCES messaging.outbound_messages (id) ON DELETE RESTRICT,
    ADD CONSTRAINT inbound_events_identity_shape_check
        CHECK ((account_id IS NULL) = (channel_identity_id IS NULL)),
    ADD CONSTRAINT inbound_events_account_channel_fk
        FOREIGN KEY (account_id, channel_identity_id)
        REFERENCES identity.channel_identities (account_id, id)
        ON DELETE RESTRICT;

CREATE INDEX inbound_events_account_idx
    ON integration.inbound_events (account_id, received_at)
    WHERE account_id IS NOT NULL;

ALTER TABLE messaging.outbound_messages
    DROP CONSTRAINT outbound_messages_payload_check,
    DROP CONSTRAINT outbound_messages_nonce_check,
    DROP CONSTRAINT outbound_messages_submission_shape_check,
    ALTER COLUMN payload_ciphertext DROP NOT NULL,
    ALTER COLUMN payload_nonce DROP NOT NULL,
    ADD COLUMN payload_purged_at timestamptz,
    ADD CONSTRAINT outbound_messages_payload_state_check
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
    ADD CONSTRAINT outbound_messages_submission_shape_check
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
                AND (provider_message_id IS NOT NULL OR payload_purged_at IS NOT NULL)
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
        );

ALTER TABLE messaging.outbound_delivery_events
    DROP CONSTRAINT outbound_delivery_events_message_id_check,
    ALTER COLUMN provider_message_id DROP NOT NULL,
    ADD CONSTRAINT outbound_delivery_events_message_id_check
        CHECK (
            provider_message_id IS NULL
            OR octet_length(btrim(provider_message_id)) BETWEEN 1 AND 512
        );

CREATE OR REPLACE FUNCTION audit.guard_inbound_event_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id = OLD.id
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
       AND (
           (
               OLD.account_id IS NULL
               AND OLD.channel_identity_id IS NULL
               AND NEW.account_id IS NOT NULL
               AND NEW.channel_identity_id IS NOT NULL
               AND current_setting('sahayak.inbound_identity_binding', true) = NEW.id::text
               AND NEW.reply_to_outbound_message_id IS NOT DISTINCT FROM OLD.reply_to_outbound_message_id
               AND NEW.payload_ciphertext IS NOT DISTINCT FROM OLD.payload_ciphertext
               AND NEW.payload_nonce IS NOT DISTINCT FROM OLD.payload_nonce
               AND NEW.payload_purged_at IS NOT DISTINCT FROM OLD.payload_purged_at
           )
           OR (
               NEW.account_id IS NOT DISTINCT FROM OLD.account_id
               AND NEW.channel_identity_id IS NOT DISTINCT FROM OLD.channel_identity_id
               AND OLD.reply_to_outbound_message_id IS NULL
               AND NEW.reply_to_outbound_message_id IS NOT NULL
               AND current_setting('sahayak.inbound_identity_binding', true) = NEW.id::text
               AND NEW.payload_ciphertext IS NOT DISTINCT FROM OLD.payload_ciphertext
               AND NEW.payload_nonce IS NOT DISTINCT FROM OLD.payload_nonce
               AND NEW.payload_purged_at IS NOT DISTINCT FROM OLD.payload_purged_at
           )
           OR (
               NEW.account_id IS NOT DISTINCT FROM OLD.account_id
               AND NEW.channel_identity_id IS NOT DISTINCT FROM OLD.channel_identity_id
               AND NEW.reply_to_outbound_message_id IS NOT DISTINCT FROM OLD.reply_to_outbound_message_id
               AND OLD.payload_ciphertext IS NOT NULL
               AND OLD.payload_nonce IS NOT NULL
               AND OLD.payload_purged_at IS NULL
               AND NEW.payload_ciphertext IS NULL
               AND NEW.payload_nonce IS NULL
               AND NEW.payload_purged_at IS NOT NULL
           )
       )
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'inbound events are immutable except for identity binding and payload purge';
END;
$$;

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
    IF current_setting('sahayak.account_erasure', true) = 'on'
       AND OLD.provider_message_id IS NOT NULL
       AND NEW.provider_message_id IS NULL
       AND NEW.id = OLD.id
       AND NEW.inbound_event_id = OLD.inbound_event_id
       AND NEW.outbound_message_id IS NOT DISTINCT FROM OLD.outbound_message_id
       AND NEW.provider_code = OLD.provider_code
       AND NEW.provider_namespace = OLD.provider_namespace
       AND NEW.provider_status = OLD.provider_status
       AND NEW.provider_error_code IS NOT DISTINCT FROM OLD.provider_error_code
       AND NEW.error_class IS NOT DISTINCT FROM OLD.error_class
       AND NEW.provider_occurred_at = OLD.provider_occurred_at
       AND NEW.received_at = OLD.received_at
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'delivery events are immutable except for orphan linking or account erasure';
END;
$$;

DROP INDEX profile.public_profiles_review_queue_idx;

ALTER TABLE profile.public_profiles
    DROP CONSTRAINT public_profiles_status_check,
    DROP CONSTRAINT public_profiles_review_check,
    DROP CONSTRAINT public_profiles_publish_check;

ALTER TABLE profile.public_profiles
    ADD COLUMN visibility text NOT NULL DEFAULT 'hidden',
    ADD COLUMN published_revision_id uuid,
    ADD COLUMN hidden_at timestamptz;

UPDATE profile.public_profiles
SET
    visibility = 'hidden',
    published_revision_id = NULL,
    published_at = NULL,
    hidden_at = transaction_timestamp();

ALTER TABLE profile.public_profiles
    ADD CONSTRAINT public_profiles_visibility_check
        CHECK (visibility IN ('hidden', 'published', 'deleted')),
    ADD CONSTRAINT public_profiles_visibility_shape_check
        CHECK (
            (visibility = 'published' AND published_revision_id IS NOT NULL AND published_at IS NOT NULL)
            OR (visibility IN ('hidden', 'deleted') AND published_revision_id IS NULL)
        );

CREATE TABLE profile.profile_revisions (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    review_token uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    profile_id uuid NOT NULL
        REFERENCES profile.public_profiles (id) ON DELETE CASCADE,
    revision_number integer NOT NULL,
    state text NOT NULL DEFAULT 'draft',
    display_name varchar(80),
    local_service_mode text,
    service_radius_km smallint,
    contact_request_limit smallint,
    submitted_digest bytea,
    submitted_at timestamptz,
    decided_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT profile_revisions_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT profile_revisions_review_token_version_check
        CHECK (uuid_extract_version(review_token) = 4),
    CONSTRAINT profile_revisions_number_check
        CHECK (revision_number > 0),
    CONSTRAINT profile_revisions_state_check
        CHECK (state IN (
            'draft',
            'pending_review',
            'approved',
            'changes_requested',
            'rejected',
            'superseded'
        )),
    CONSTRAINT profile_revisions_display_name_check
        CHECK (
            display_name IS NULL
            OR (
                length(display_name) BETWEEN 1 AND 80
                AND display_name = btrim(display_name)
                AND display_name !~ '[[:cntrl:]]'
                AND position(chr(1564) IN display_name) = 0
                AND position(chr(8206) IN display_name) = 0
                AND position(chr(8207) IN display_name) = 0
                AND position(chr(8234) IN display_name) = 0
                AND position(chr(8235) IN display_name) = 0
                AND position(chr(8236) IN display_name) = 0
                AND position(chr(8237) IN display_name) = 0
                AND position(chr(8238) IN display_name) = 0
                AND position(chr(8294) IN display_name) = 0
                AND position(chr(8295) IN display_name) = 0
                AND position(chr(8296) IN display_name) = 0
                AND position(chr(8297) IN display_name) = 0
                AND lower(display_name) !~ '(^|[^[:alnum:]])(sahayak|admin|administrator|moderator|support)($|[^[:alnum:]])'
                AND lower(display_name) !~ '(https?://|www\.|\.(com|org|net|in|co))'
                AND display_name !~ '[0-9][0-9 +().-]{5,}[0-9]'
            )
        ),
    CONSTRAINT profile_revisions_radius_check
        CHECK (service_radius_km IS NULL OR service_radius_km IN (2, 5, 10, 25)),
    CONSTRAINT profile_revisions_local_service_mode_check
        CHECK (
            local_service_mode IS NULL
            OR local_service_mode IN ('travel_to_customer', 'customer_visits', 'both')
        ),
    CONSTRAINT profile_revisions_contact_limit_check
        CHECK (contact_request_limit IS NULL OR contact_request_limit BETWEEN 1 AND 10),
    CONSTRAINT profile_revisions_submission_shape_check
        CHECK (
            (
                state = 'draft'
                AND submitted_digest IS NULL
                AND submitted_at IS NULL
                AND decided_at IS NULL
            )
            OR (
                state = 'pending_review'
                AND submitted_digest IS NOT NULL
                AND octet_length(submitted_digest) = 32
                AND submitted_at IS NOT NULL
                AND decided_at IS NULL
            )
            OR (
                state IN ('approved', 'changes_requested', 'rejected', 'superseded')
                AND submitted_digest IS NOT NULL
                AND octet_length(submitted_digest) = 32
                AND submitted_at IS NOT NULL
                AND decided_at IS NOT NULL
            )
        ),
    CONSTRAINT profile_revisions_version_check
        CHECK (version > 0),
    CONSTRAINT profile_revisions_profile_number_unique
        UNIQUE (profile_id, revision_number),
    CONSTRAINT profile_revisions_profile_id_unique
        UNIQUE (profile_id, id)
);

CREATE TRIGGER profile_revisions_touch_version
BEFORE UPDATE ON profile.profile_revisions
FOR EACH ROW
EXECUTE FUNCTION identity.touch_versioned_row();

CREATE UNIQUE INDEX profile_revisions_one_open_idx
    ON profile.profile_revisions (profile_id)
    WHERE state IN ('draft', 'pending_review');

CREATE INDEX profile_revisions_review_queue_idx
    ON profile.profile_revisions (submitted_at, id)
    WHERE state = 'pending_review';

INSERT INTO profile.profile_revisions (
    id,
    profile_id,
    revision_number,
    state,
    display_name,
    created_at,
    updated_at
)
SELECT
    uuidv7(),
    id,
    1,
    'draft',
    CASE
        WHEN display_name = btrim(display_name)
         AND display_name !~ '[[:cntrl:]]'
         AND position(chr(1564) IN display_name) = 0
         AND position(chr(8206) IN display_name) = 0
         AND position(chr(8207) IN display_name) = 0
         AND position(chr(8234) IN display_name) = 0
         AND position(chr(8235) IN display_name) = 0
         AND position(chr(8236) IN display_name) = 0
         AND position(chr(8237) IN display_name) = 0
         AND position(chr(8238) IN display_name) = 0
         AND position(chr(8294) IN display_name) = 0
         AND position(chr(8295) IN display_name) = 0
         AND position(chr(8296) IN display_name) = 0
         AND position(chr(8297) IN display_name) = 0
         AND lower(display_name) !~ '(^|[^[:alnum:]])(sahayak|admin|administrator|moderator|support)($|[^[:alnum:]])'
         AND lower(display_name) !~ '(https?://|www\.|\.(com|org|net|in|co))'
         AND display_name !~ '[0-9][0-9 +().-]{5,}[0-9]'
        THEN display_name
        ELSE NULL
    END,
    created_at,
    updated_at
FROM profile.public_profiles;

ALTER TABLE profile.public_profiles
    DROP COLUMN display_name,
    DROP COLUMN status,
    DROP COLUMN reviewed_by,
    DROP COLUMN reviewed_at;

ALTER TABLE profile.public_profiles
    ADD CONSTRAINT public_profiles_published_revision_fk
        FOREIGN KEY (id, published_revision_id)
        REFERENCES profile.profile_revisions (profile_id, id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT public_profiles_account_id_unique
        UNIQUE (account_id, id);

CREATE TABLE profile.service_categories (
    code varchar(32) COLLATE "C" PRIMARY KEY,
    display_name varchar(64) NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT service_categories_code_check
        CHECK (code ~ '^[a-z][a-z0-9_]{1,31}$'),
    CONSTRAINT service_categories_name_check
        CHECK (length(btrim(display_name)) BETWEEN 1 AND 64),
    CONSTRAINT service_categories_state_check
        CHECK (state IN ('active', 'inactive'))
);

INSERT INTO profile.service_categories (code, display_name)
VALUES
    ('plumber', 'Plumber'),
    ('electrician', 'Electrician');

CREATE TABLE profile.service_skills (
    category_code varchar(32) COLLATE "C" NOT NULL
        REFERENCES profile.service_categories (code) ON DELETE RESTRICT,
    code varchar(48) COLLATE "C" NOT NULL,
    display_name varchar(64) NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (category_code, code),
    CONSTRAINT service_skills_code_check
        CHECK (code ~ '^[a-z][a-z0-9_]{1,47}$'),
    CONSTRAINT service_skills_name_check
        CHECK (length(btrim(display_name)) BETWEEN 1 AND 64),
    CONSTRAINT service_skills_state_check
        CHECK (state IN ('active', 'inactive'))
);

INSERT INTO profile.service_skills (category_code, code, display_name)
VALUES
    ('plumber', 'leak_repair', 'Leak repair'),
    ('plumber', 'tap_and_fixture', 'Tap and fixture work'),
    ('plumber', 'drain_clearing', 'Drain clearing'),
    ('electrician', 'home_wiring', 'Home wiring'),
    ('electrician', 'switch_and_socket', 'Switch and socket work'),
    ('electrician', 'fan_installation', 'Fan installation');

CREATE TABLE profile.professional_services (
    revision_id uuid NOT NULL
        REFERENCES profile.profile_revisions (id) ON DELETE CASCADE,
    category_code varchar(32) COLLATE "C" NOT NULL
        REFERENCES profile.service_categories (code) ON DELETE RESTRICT,
    contact_mode text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (revision_id, category_code),
    CONSTRAINT professional_services_contact_mode_check
        CHECK (contact_mode IN ('direct', 'approval_required')),
    CONSTRAINT professional_services_revision_category_unique
        UNIQUE (revision_id, category_code)
);

CREATE TABLE profile.professional_service_skills (
    revision_id uuid NOT NULL,
    category_code varchar(32) COLLATE "C" NOT NULL,
    skill_code varchar(48) COLLATE "C" NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (revision_id, category_code, skill_code),
    FOREIGN KEY (revision_id, category_code)
        REFERENCES profile.professional_services (revision_id, category_code)
        ON DELETE CASCADE,
    FOREIGN KEY (category_code, skill_code)
        REFERENCES profile.service_skills (category_code, code)
        ON DELETE RESTRICT
);

CREATE TABLE profile.professional_languages (
    revision_id uuid NOT NULL
        REFERENCES profile.profile_revisions (id) ON DELETE CASCADE,
    locale varchar(5) COLLATE "C" NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (revision_id, locale),
    CONSTRAINT professional_languages_locale_check
        CHECK (locale IN ('en-IN', 'hi-IN', 'mr-IN'))
);

CREATE TABLE private_data.professional_service_areas (
    revision_id uuid PRIMARY KEY,
    profile_id uuid NOT NULL,
    account_id uuid NOT NULL,
    exact_center geography(Point, 4326) NOT NULL,
    digest_token uuid NOT NULL DEFAULT gen_random_uuid(),
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (profile_id, revision_id)
        REFERENCES profile.profile_revisions (profile_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, profile_id)
        REFERENCES profile.public_profiles (account_id, id) ON DELETE CASCADE,
    CONSTRAINT professional_service_areas_version_check
        CHECK (version > 0),
    CONSTRAINT professional_service_areas_digest_token_version_check
        CHECK (uuid_extract_version(digest_token) = 4)
);

CREATE TRIGGER professional_service_areas_touch_version
BEFORE UPDATE ON private_data.professional_service_areas
FOR EACH ROW
EXECUTE FUNCTION identity.touch_versioned_row();

CREATE OR REPLACE FUNCTION private_data.refresh_service_area_digest_token()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.exact_center IS DISTINCT FROM OLD.exact_center THEN
        NEW.digest_token := gen_random_uuid();
    ELSIF NEW.digest_token IS DISTINCT FROM OLD.digest_token THEN
        RAISE EXCEPTION 'service area digest token is managed by the database';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER professional_service_areas_refresh_digest_token
BEFORE UPDATE ON private_data.professional_service_areas
FOR EACH ROW
EXECUTE FUNCTION private_data.refresh_service_area_digest_token();

CREATE OR REPLACE FUNCTION profile.guard_draft_revision_child()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate_revision_id uuid;
    candidate_state text;
BEGIN
    IF TG_OP = 'DELETE'
       AND current_setting('sahayak.account_erasure', true) = 'on'
    THEN
        RETURN OLD;
    END IF;
    IF TG_OP = 'DELETE'
       AND current_setting('sahayak.profile_cleanup', true) = 'on'
    THEN
        RETURN OLD;
    END IF;
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        SELECT state INTO candidate_state
        FROM profile.profile_revisions
        WHERE id = OLD.revision_id;
        IF candidate_state IS DISTINCT FROM 'draft' THEN
            RAISE EXCEPTION 'submitted profile revisions are immutable';
        END IF;
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        candidate_revision_id := NEW.revision_id;
        SELECT state INTO candidate_state
        FROM profile.profile_revisions
        WHERE id = candidate_revision_id;
        IF candidate_state IS DISTINCT FROM 'draft' THEN
            RAISE EXCEPTION 'submitted profile revisions are immutable';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER professional_services_draft_only
BEFORE INSERT OR UPDATE OR DELETE ON profile.professional_services
FOR EACH ROW EXECUTE FUNCTION profile.guard_draft_revision_child();

CREATE TRIGGER professional_service_skills_draft_only
BEFORE INSERT OR UPDATE OR DELETE ON profile.professional_service_skills
FOR EACH ROW EXECUTE FUNCTION profile.guard_draft_revision_child();

CREATE TRIGGER professional_languages_draft_only
BEFORE INSERT OR UPDATE OR DELETE ON profile.professional_languages
FOR EACH ROW EXECUTE FUNCTION profile.guard_draft_revision_child();

CREATE TRIGGER professional_service_areas_draft_only
BEFORE INSERT OR UPDATE OR DELETE ON private_data.professional_service_areas
FOR EACH ROW EXECUTE FUNCTION profile.guard_draft_revision_child();

CREATE OR REPLACE FUNCTION profile.guard_revision_reviewable_fields()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.state <> 'draft'
       AND (
           NEW.display_name IS DISTINCT FROM OLD.display_name
           OR NEW.local_service_mode IS DISTINCT FROM OLD.local_service_mode
           OR NEW.service_radius_km IS DISTINCT FROM OLD.service_radius_km
           OR NEW.contact_request_limit IS DISTINCT FROM OLD.contact_request_limit
           OR NEW.submitted_digest IS DISTINCT FROM OLD.submitted_digest
           OR NEW.submitted_at IS DISTINCT FROM OLD.submitted_at
       )
    THEN
        RAISE EXCEPTION 'submitted profile revision fields are immutable';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state THEN
        IF OLD.state = 'draft'
           AND NEW.state = 'pending_review'
           AND current_setting('sahayak.profile_submission', true) = NEW.id::text
        THEN
            RETURN NEW;
        END IF;
        IF OLD.state IN ('pending_review', 'approved')
           AND current_setting('sahayak.profile_review_decision', true) IS NOT NULL
        THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'profile revision transition requires a transaction capability';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER profile_revisions_guard_reviewable_fields
BEFORE UPDATE ON profile.profile_revisions
FOR EACH ROW EXECUTE FUNCTION profile.guard_revision_reviewable_fields();

CREATE OR REPLACE FUNCTION profile.guard_revision_insert_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state <> 'draft'
       OR NEW.submitted_digest IS NOT NULL
       OR NEW.submitted_at IS NOT NULL
       OR NEW.decided_at IS NOT NULL
    THEN
        RAISE EXCEPTION 'profile revisions must be created as drafts';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER profile_revisions_guard_insert_state
BEFORE INSERT ON profile.profile_revisions
FOR EACH ROW EXECUTE FUNCTION profile.guard_revision_insert_state();

CREATE TABLE profile.consent_documents (
    purpose text NOT NULL,
    locale varchar(5) COLLATE "C" NOT NULL,
    document_version varchar(32) COLLATE "C" NOT NULL,
    document_text text NOT NULL,
    document_sha256 bytea NOT NULL,
    is_current boolean NOT NULL DEFAULT true,
    activated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    retired_at timestamptz,
    PRIMARY KEY (purpose, locale, document_version),
    CONSTRAINT consent_documents_purpose_check
        CHECK (purpose IN (
            'terms',
            'privacy',
            'contact_disclosure',
            'direct_contact',
            'photo_disclosure',
            'identity_verification'
        )),
    CONSTRAINT consent_documents_version_check
        CHECK (octet_length(document_version) BETWEEN 1 AND 32),
    CONSTRAINT consent_documents_locale_check
        CHECK (locale IN ('en-IN', 'hi-IN', 'mr-IN')),
    CONSTRAINT consent_documents_text_check
        CHECK (
            length(btrim(document_text)) BETWEEN 1 AND 600
            AND document_sha256 = sha256(convert_to(document_text, 'UTF8'))
        ),
    CONSTRAINT consent_documents_digest_check
        CHECK (octet_length(document_sha256) = 32),
    CONSTRAINT consent_documents_retirement_check
        CHECK ((is_current AND retired_at IS NULL) OR (NOT is_current AND retired_at IS NOT NULL)),
    CONSTRAINT consent_documents_reference_unique
        UNIQUE (purpose, locale, document_version, document_sha256)
);

CREATE UNIQUE INDEX consent_documents_one_current_idx
    ON profile.consent_documents (purpose, locale)
    WHERE is_current;

INSERT INTO profile.consent_documents (
    purpose, locale, document_version, document_text, document_sha256
)
SELECT purpose, locale, 'phase5-v1', document_text, sha256(convert_to(document_text, 'UTF8'))
FROM (VALUES
    ('terms', 'en-IN', 'Terms: I confirm my profile is accurate and I may lawfully offer the selected services.'),
    ('privacy', 'en-IN', 'Privacy: Approved profile details may be published; exact location and private records are not public.'),
    ('contact_disclosure', 'en-IN', 'Contact: Customers may request contact using my selected mode and session limit.'),
    ('direct_contact', 'en-IN', 'Direct contact: While available, eligible customers may receive my verified contact details.'),
    ('photo_disclosure', 'en-IN', 'Photo: My sanitized profile photo may be displayed and recipients may save or screenshot it.'),
    ('identity_verification', 'en-IN', 'Identity check: I authorize the active provider to perform an optional check and return only a verification result.'),
    ('terms', 'hi-IN', 'शर्तें: मैं पुष्टि करता/करती हूं कि मेरी प्रोफ़ाइल सही है और मैं चुनी सेवाएं कानूनी रूप से दे सकता/सकती हूं।'),
    ('privacy', 'hi-IN', 'गोपनीयता: मंज़ूर प्रोफ़ाइल विवरण प्रकाशित हो सकते हैं; सटीक स्थान और निजी रिकॉर्ड सार्वजनिक नहीं हैं।'),
    ('contact_disclosure', 'hi-IN', 'संपर्क: ग्राहक मेरे चुने तरीके और सत्र सीमा के अनुसार संपर्क मांग सकते हैं।'),
    ('direct_contact', 'hi-IN', 'सीधा संपर्क: उपलब्ध रहने पर योग्य ग्राहक मेरे सत्यापित संपर्क विवरण पा सकते हैं।'),
    ('photo_disclosure', 'hi-IN', 'फ़ोटो: मेरी साफ़ की गई प्रोफ़ाइल फ़ोटो दिखाई जा सकती है और लोग उसे सेव या स्क्रीनशॉट कर सकते हैं।'),
    ('identity_verification', 'hi-IN', 'पहचान जांच: मैं सक्रिय प्रदाता को वैकल्पिक जांच और केवल सत्यापन परिणाम लौटाने की अनुमति देता/देती हूं।'),
    ('terms', 'mr-IN', 'अटी: माझे प्रोफाइल अचूक आहे आणि निवडलेल्या सेवा मी कायदेशीररीत्या देऊ शकतो/शकते याची खात्री देतो/देते.'),
    ('privacy', 'mr-IN', 'गोपनीयता: मंजूर प्रोफाइल तपशील प्रकाशित होऊ शकतात; अचूक स्थान आणि खासगी नोंदी सार्वजनिक नाहीत.'),
    ('contact_disclosure', 'mr-IN', 'संपर्क: ग्राहक माझी निवडलेली पद्धत आणि सत्र मर्यादेनुसार संपर्क मागू शकतात.'),
    ('direct_contact', 'mr-IN', 'थेट संपर्क: मी उपलब्ध असताना पात्र ग्राहकांना माझे सत्यापित संपर्क तपशील मिळू शकतात.'),
    ('photo_disclosure', 'mr-IN', 'फोटो: माझा स्वच्छ केलेला प्रोफाइल फोटो दाखवला जाऊ शकतो आणि लोक तो सेव किंवा स्क्रीनशॉट करू शकतात.'),
    ('identity_verification', 'mr-IN', 'ओळख तपासणी: सक्रिय प्रदात्याला ऐच्छिक तपासणी करून फक्त सत्यापन निकाल देण्याची परवानगी देतो/देते.')
) AS policy(purpose, locale, document_text);

CREATE TRIGGER consent_documents_reject_update
BEFORE UPDATE ON profile.consent_documents
FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER consent_documents_reject_delete
BEFORE DELETE ON profile.consent_documents
FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER consent_documents_reject_truncate
BEFORE TRUNCATE ON profile.consent_documents
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

CREATE TABLE private_data.professional_consent_events (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    account_id uuid NOT NULL
        REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    profile_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    purpose text NOT NULL,
    action text NOT NULL,
    document_version varchar(32) COLLATE "C" NOT NULL,
    document_sha256 bytea NOT NULL,
    locale varchar(5) COLLATE "C" NOT NULL,
    revision_digest bytea NOT NULL,
    channel_identity_id uuid NOT NULL,
    channel_code varchar(32) COLLATE "C" NOT NULL,
    source_inbound_event_id uuid NOT NULL
        REFERENCES integration.inbound_events (id) ON DELETE RESTRICT,
    idempotency_key varchar(255) COLLATE "C" NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    recorded_sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    FOREIGN KEY (purpose, locale, document_version, document_sha256)
        REFERENCES profile.consent_documents (purpose, locale, document_version, document_sha256)
        ON DELETE RESTRICT,
    FOREIGN KEY (account_id, channel_identity_id)
        REFERENCES identity.channel_identities (account_id, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (account_id, profile_id)
        REFERENCES profile.public_profiles (account_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (profile_id, revision_id)
        REFERENCES profile.profile_revisions (profile_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (channel_identity_id, channel_code)
        REFERENCES identity.channel_identities (id, provider_code)
        ON DELETE RESTRICT,
    CONSTRAINT professional_consent_events_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT professional_consent_events_action_check
        CHECK (action IN ('granted', 'revoked')),
    CONSTRAINT professional_consent_events_locale_check
        CHECK (locale IN ('en-IN', 'hi-IN', 'mr-IN')),
    CONSTRAINT professional_consent_events_revision_digest_check
        CHECK (octet_length(revision_digest) = 32),
    CONSTRAINT professional_consent_events_idempotency_check
        CHECK (octet_length(btrim(idempotency_key)) BETWEEN 1 AND 255),
    CONSTRAINT professional_consent_events_idempotency_unique
        UNIQUE (revision_id, purpose, idempotency_key),
    CONSTRAINT professional_consent_events_source_unique
        UNIQUE (source_inbound_event_id, revision_id, purpose),
    CONSTRAINT professional_consent_events_identity_reference_unique
        UNIQUE (id, account_id, purpose)
);

CREATE INDEX professional_consent_events_current_idx
    ON private_data.professional_consent_events (
        revision_id, purpose, created_at DESC, recorded_sequence DESC
    );

CREATE TABLE private_data.profile_photos (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    account_id uuid NOT NULL
        REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    profile_id uuid NOT NULL,
    state text NOT NULL DEFAULT 'ready',
    sanitized_ciphertext bytea,
    sanitized_nonce bytea,
    encryption_key_purpose text NOT NULL DEFAULT 'media_encryption',
    encryption_key_version smallint NOT NULL,
    trusted_mime varchar(32) COLLATE "C" NOT NULL,
    width_pixels integer NOT NULL,
    height_pixels integer NOT NULL,
    plaintext_sha256 bytea NOT NULL,
    sanitizer_version varchar(32) COLLATE "C" NOT NULL,
    sanitized_at timestamptz NOT NULL,
    source_inbound_event_id uuid NOT NULL UNIQUE
        REFERENCES integration.inbound_events (id) ON DELETE RESTRICT,
    removed_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (account_id, profile_id)
        REFERENCES profile.public_profiles (account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (encryption_key_purpose, encryption_key_version)
        REFERENCES private_data.key_versions (purpose, version) ON DELETE RESTRICT,
    CONSTRAINT profile_photos_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT profile_photos_state_check
        CHECK (state IN ('ready', 'replaced', 'deleted')),
    CONSTRAINT profile_photos_ciphertext_check
        CHECK (
            (
                state = 'ready'
                AND sanitized_ciphertext IS NOT NULL
                AND octet_length(sanitized_ciphertext) BETWEEN 16 AND 2097168
                AND sanitized_nonce IS NOT NULL
                AND octet_length(sanitized_nonce) = 12
                AND removed_at IS NULL
            )
            OR (
                state IN ('replaced', 'deleted')
                AND sanitized_ciphertext IS NULL
                AND sanitized_nonce IS NULL
                AND removed_at IS NOT NULL
            )
        ),
    CONSTRAINT profile_photos_key_purpose_check
        CHECK (encryption_key_purpose = 'media_encryption'),
    CONSTRAINT profile_photos_mime_check
        CHECK (trusted_mime = 'image/jpeg'),
    CONSTRAINT profile_photos_dimensions_check
        CHECK (width_pixels BETWEEN 1 AND 12000 AND height_pixels BETWEEN 1 AND 12000),
    CONSTRAINT profile_photos_digest_check
        CHECK (octet_length(plaintext_sha256) = 32),
    CONSTRAINT profile_photos_sanitizer_check
        CHECK (octet_length(btrim(sanitizer_version)) BETWEEN 1 AND 32),
    CONSTRAINT profile_photos_version_check
        CHECK (version > 0),
    CONSTRAINT profile_photos_timestamp_check
        CHECK (
            sanitized_at <= created_at + INTERVAL '5 minutes'
            AND (removed_at IS NULL OR removed_at >= created_at)
        ),
    CONSTRAINT profile_photos_profile_id_unique
        UNIQUE (profile_id, id)
);

CREATE INDEX profile_photos_account_idx
    ON private_data.profile_photos (account_id, created_at DESC);

CREATE TRIGGER profile_photos_touch_version
BEFORE UPDATE ON private_data.profile_photos
FOR EACH ROW
EXECUTE FUNCTION identity.touch_versioned_row();

CREATE OR REPLACE FUNCTION private_data.guard_profile_photo_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.state = 'ready'
       AND NEW.state IN ('replaced', 'deleted')
       AND NEW.sanitized_ciphertext IS NULL
       AND NEW.sanitized_nonce IS NULL
       AND NEW.removed_at IS NOT NULL
       AND NEW.id = OLD.id
       AND NEW.account_id = OLD.account_id
       AND NEW.profile_id = OLD.profile_id
       AND NEW.encryption_key_purpose = OLD.encryption_key_purpose
       AND NEW.encryption_key_version = OLD.encryption_key_version
       AND NEW.trusted_mime = OLD.trusted_mime
       AND NEW.width_pixels = OLD.width_pixels
       AND NEW.height_pixels = OLD.height_pixels
       AND NEW.plaintext_sha256 = OLD.plaintext_sha256
       AND NEW.sanitizer_version = OLD.sanitizer_version
       AND NEW.sanitized_at = OLD.sanitized_at
       AND NEW.source_inbound_event_id = OLD.source_inbound_event_id
       AND NEW.created_at = OLD.created_at
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'profile photo metadata and ciphertext are immutable';
END;
$$;

CREATE TRIGGER profile_photos_guard_update
BEFORE UPDATE ON private_data.profile_photos
FOR EACH ROW
EXECUTE FUNCTION private_data.guard_profile_photo_update();

CREATE TABLE profile.profile_revision_photos (
    revision_id uuid PRIMARY KEY,
    profile_id uuid NOT NULL,
    photo_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (profile_id, revision_id)
        REFERENCES profile.profile_revisions (profile_id, id) ON DELETE CASCADE,
    FOREIGN KEY (profile_id, photo_id)
        REFERENCES private_data.profile_photos (profile_id, id) ON DELETE CASCADE
);

CREATE INDEX profile_revision_photos_photo_idx
    ON profile.profile_revision_photos (photo_id, revision_id);

CREATE TRIGGER profile_revision_photos_draft_only
BEFORE INSERT OR UPDATE OR DELETE ON profile.profile_revision_photos
FOR EACH ROW EXECUTE FUNCTION profile.guard_draft_revision_child();

CREATE OR REPLACE FUNCTION profile.reviewable_revision_digest(candidate_revision_id uuid)
RETURNS bytea
LANGUAGE sql
STABLE
AS $$
    SELECT sha256(convert_to(jsonb_build_object(
        'display_name', revision.display_name,
        'local_service_mode', revision.local_service_mode,
        'service_area_token', (
            SELECT area.digest_token::text
            FROM private_data.professional_service_areas AS area
            WHERE area.revision_id = revision.id
        ),
        'service_radius_km', revision.service_radius_km,
        'contact_request_limit', revision.contact_request_limit,
        'services', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'category', service.category_code,
                'contact_mode', service.contact_mode,
                'skills', COALESCE((
                    SELECT jsonb_agg(selected.skill_code ORDER BY selected.skill_code)
                    FROM profile.professional_service_skills AS selected
                    WHERE selected.revision_id = service.revision_id
                      AND selected.category_code = service.category_code
                ), '[]'::jsonb)
            ) ORDER BY service.category_code)
            FROM profile.professional_services AS service
            WHERE service.revision_id = revision.id
        ), '[]'::jsonb),
        'languages', COALESCE((
            SELECT jsonb_agg(language.locale ORDER BY language.locale)
            FROM profile.professional_languages AS language
            WHERE language.revision_id = revision.id
        ), '[]'::jsonb),
        'photo_digest', (
            SELECT encode(photo.plaintext_sha256, 'hex')
            FROM profile.profile_revision_photos AS link
            JOIN private_data.profile_photos AS photo ON photo.id = link.photo_id
            WHERE link.revision_id = revision.id AND photo.state = 'ready'
        )
    )::text, 'UTF8'))
    FROM profile.profile_revisions AS revision
    WHERE revision.id = candidate_revision_id;
$$;

CREATE OR REPLACE FUNCTION private_data.has_current_professional_consent(
    candidate_revision_id uuid,
    candidate_purpose text
)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT COALESCE((
        SELECT event.action = 'granted'
           AND event.revision_digest = profile.reviewable_revision_digest(candidate_revision_id)
        FROM private_data.professional_consent_events AS event
        JOIN profile.consent_documents AS document
          ON document.purpose = event.purpose
         AND document.locale = event.locale
         AND document.document_version = event.document_version
         AND document.document_sha256 = event.document_sha256
         AND document.is_current
        WHERE event.revision_id = candidate_revision_id
          AND event.purpose = candidate_purpose
        ORDER BY event.created_at DESC, event.recorded_sequence DESC
        LIMIT 1
    ), false);
$$;

CREATE OR REPLACE FUNCTION profile.revision_is_publishable(candidate_revision_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT COALESCE((
        SELECT account.status = 'active'
           AND account.risk_state NOT IN ('restricted', 'blocked')
           AND revision.display_name IS NOT NULL
           AND revision.local_service_mode IS NOT NULL
           AND revision.service_radius_km IS NOT NULL
           AND revision.contact_request_limit IS NOT NULL
           AND EXISTS (
               SELECT 1 FROM identity.account_roles AS role
               WHERE role.account_id = account.id
                 AND role.role = 'professional'
                 AND role.revoked_at IS NULL
           )
           AND EXISTS (
               SELECT 1 FROM identity.channel_identities AS channel
               WHERE channel.account_id = account.id
                 AND channel.provider_code = 'whatsapp'
                 AND channel.status = 'active'
                 AND channel.verified_at IS NOT NULL
           )
           AND EXISTS (
               SELECT 1 FROM private_data.professional_service_areas AS area
               WHERE area.revision_id = revision.id
           )
           AND EXISTS (
               SELECT 1 FROM profile.professional_languages AS language
               WHERE language.revision_id = revision.id
           )
           AND EXISTS (
               SELECT 1
               FROM profile.professional_services AS service
               JOIN profile.service_categories AS category
                 ON category.code = service.category_code
                AND category.state = 'active'
               WHERE service.revision_id = revision.id
           )
           AND NOT EXISTS (
               SELECT 1
               FROM profile.professional_services AS service
               LEFT JOIN profile.service_categories AS category
                 ON category.code = service.category_code
                AND category.state = 'active'
               WHERE service.revision_id = revision.id
                 AND (
                     category.code IS NULL
                     OR NOT EXISTS (
                         SELECT 1
                         FROM profile.professional_service_skills AS selected
                         JOIN profile.service_skills AS skill
                           ON skill.category_code = selected.category_code
                          AND skill.code = selected.skill_code
                          AND skill.state = 'active'
                         WHERE selected.revision_id = service.revision_id
                           AND selected.category_code = service.category_code
                     )
                     OR EXISTS (
                         SELECT 1
                         FROM profile.professional_service_skills AS selected
                         LEFT JOIN profile.service_skills AS skill
                           ON skill.category_code = selected.category_code
                          AND skill.code = selected.skill_code
                          AND skill.state = 'active'
                         WHERE selected.revision_id = service.revision_id
                           AND selected.category_code = service.category_code
                           AND skill.code IS NULL
                     )
                 )
           )
           AND private_data.has_current_professional_consent(revision.id, 'terms')
           AND private_data.has_current_professional_consent(revision.id, 'privacy')
           AND private_data.has_current_professional_consent(revision.id, 'contact_disclosure')
           AND (
               NOT EXISTS (
                   SELECT 1 FROM profile.professional_services
                   WHERE revision_id = revision.id AND contact_mode = 'direct'
               )
               OR private_data.has_current_professional_consent(revision.id, 'direct_contact')
           )
           AND (
               NOT EXISTS (
                   SELECT 1
                   FROM profile.profile_revision_photos AS link
                   JOIN private_data.profile_photos AS photo ON photo.id = link.photo_id
                   WHERE link.revision_id = revision.id AND photo.state = 'ready'
               )
               OR private_data.has_current_professional_consent(revision.id, 'photo_disclosure')
           )
        FROM profile.profile_revisions AS revision
        JOIN profile.public_profiles AS root ON root.id = revision.profile_id
        JOIN identity.accounts AS account ON account.id = root.account_id
        WHERE revision.id = candidate_revision_id
    ), false);
$$;

CREATE OR REPLACE FUNCTION private_data.guard_professional_consent_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.occurred_at > statement_timestamp() + INTERVAL '5 minutes' THEN
        RAISE EXCEPTION 'consent occurrence time is materially in the future';
    END IF;
    IF NEW.revision_digest IS DISTINCT FROM profile.reviewable_revision_digest(NEW.revision_id) THEN
        RAISE EXCEPTION 'consent revision digest is stale';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER professional_consent_events_guard_insert
BEFORE INSERT ON private_data.professional_consent_events
FOR EACH ROW EXECUTE FUNCTION private_data.guard_professional_consent_insert();

CREATE TABLE identity.administrator_allowlist (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    account_id uuid NOT NULL,
    channel_identity_id uuid NOT NULL,
    channel_code varchar(32) COLLATE "C" NOT NULL,
    provider_namespace varchar(128) COLLATE "C" NOT NULL,
    granted_by_account_id uuid
        REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    grant_audit_event_id uuid NOT NULL UNIQUE
        REFERENCES audit.events (id) ON DELETE RESTRICT,
    grant_idempotency_key varchar(255) COLLATE "C" NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_by_account_id uuid
        REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    revocation_audit_event_id uuid UNIQUE
        REFERENCES audit.events (id) ON DELETE RESTRICT,
    revocation_idempotency_key varchar(255) COLLATE "C" UNIQUE,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (account_id, channel_identity_id)
        REFERENCES identity.channel_identities (account_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (channel_identity_id, channel_code, provider_namespace)
        REFERENCES identity.channel_identities (id, provider_code, provider_namespace)
        ON DELETE RESTRICT,
    CONSTRAINT administrator_allowlist_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT administrator_allowlist_expiry_check
        CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '366 days'),
    CONSTRAINT administrator_allowlist_grant_idempotency_check
        CHECK (octet_length(btrim(grant_idempotency_key)) BETWEEN 1 AND 255),
    CONSTRAINT administrator_allowlist_revocation_shape_check
        CHECK (
            (revoked_at IS NULL AND revoked_by_account_id IS NULL AND revocation_audit_event_id IS NULL AND revocation_idempotency_key IS NULL)
            OR (
                revoked_at IS NOT NULL
                AND revoked_at >= created_at
                AND revocation_audit_event_id IS NOT NULL
                AND revocation_idempotency_key IS NOT NULL
                AND octet_length(btrim(revocation_idempotency_key)) BETWEEN 1 AND 255
            )
        )
);

CREATE INDEX administrator_allowlist_authorization_idx
    ON identity.administrator_allowlist (account_id, channel_identity_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE OR REPLACE FUNCTION identity.guard_administrator_allowlist_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.revoked_at IS NULL
       AND NEW.revoked_at IS NOT NULL
       AND NEW.id = OLD.id
       AND NEW.account_id = OLD.account_id
       AND NEW.channel_identity_id = OLD.channel_identity_id
       AND NEW.channel_code = OLD.channel_code
       AND NEW.provider_namespace = OLD.provider_namespace
       AND NEW.granted_by_account_id IS NOT DISTINCT FROM OLD.granted_by_account_id
       AND NEW.grant_audit_event_id = OLD.grant_audit_event_id
       AND NEW.grant_idempotency_key = OLD.grant_idempotency_key
       AND NEW.expires_at = OLD.expires_at
       AND NEW.created_at = OLD.created_at
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'administrator allowlist grants are immutable except for revocation';
END;
$$;

CREATE TRIGGER administrator_allowlist_guard_update
BEFORE UPDATE ON identity.administrator_allowlist
FOR EACH ROW EXECUTE FUNCTION identity.guard_administrator_allowlist_update();

CREATE TABLE profile.profile_review_decisions (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    revision_id uuid NOT NULL UNIQUE
        REFERENCES profile.profile_revisions (id) ON DELETE CASCADE,
    reviewer_account_id uuid NOT NULL,
    reviewer_channel_identity_id uuid NOT NULL,
    decision text NOT NULL,
    reason_code varchar(64) COLLATE "C" NOT NULL,
    reason_detail varchar(500),
    target_digest bytea NOT NULL,
    idempotency_key varchar(255) COLLATE "C" NOT NULL UNIQUE,
    audit_event_id uuid NOT NULL UNIQUE
        REFERENCES audit.events (id) ON DELETE RESTRICT,
    transaction_id xid8 NOT NULL DEFAULT pg_current_xact_id(),
    decided_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (reviewer_account_id, reviewer_channel_identity_id)
        REFERENCES identity.channel_identities (account_id, id) ON DELETE RESTRICT,
    CONSTRAINT profile_review_decisions_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT profile_review_decisions_decision_check
        CHECK (decision IN ('approve', 'changes_requested', 'reject')),
    CONSTRAINT profile_review_decisions_reason_check
        CHECK (
            (decision = 'approve' AND reason_code = 'meets_policy' AND reason_detail IS NULL)
            OR (
                decision = 'changes_requested'
                AND reason_code IN (
                    'incomplete_profile',
                    'invalid_display_name',
                    'unsupported_service',
                    'service_area_issue',
                    'photo_issue'
                )
            )
            OR (
                decision = 'reject'
                AND reason_code IN ('policy_violation', 'fraud_risk', 'prohibited_content')
            )
        ),
    CONSTRAINT profile_review_decisions_detail_check
        CHECK (reason_detail IS NULL OR length(btrim(reason_detail)) BETWEEN 1 AND 500),
    CONSTRAINT profile_review_decisions_digest_check
        CHECK (octet_length(target_digest) = 32),
    CONSTRAINT profile_review_decisions_idempotency_check
        CHECK (octet_length(btrim(idempotency_key)) BETWEEN 1 AND 255)
);

CREATE OR REPLACE FUNCTION profile.guard_review_decision_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM profile.profile_revisions AS revision
        JOIN profile.public_profiles AS root ON root.id = revision.profile_id
        JOIN audit.events AS event ON event.id = NEW.audit_event_id
        JOIN identity.accounts AS reviewer ON reviewer.id = NEW.reviewer_account_id
        JOIN identity.account_roles AS role
          ON role.account_id = reviewer.id
         AND role.role = 'administrator'
         AND role.revoked_at IS NULL
        JOIN identity.channel_identities AS channel
          ON channel.id = NEW.reviewer_channel_identity_id
         AND channel.account_id = reviewer.id
         AND channel.provider_code = 'whatsapp'
         AND channel.status = 'active'
         AND channel.verified_at IS NOT NULL
        JOIN identity.administrator_allowlist AS allowlist
          ON allowlist.account_id = reviewer.id
         AND allowlist.channel_identity_id = channel.id
         AND allowlist.channel_code = channel.provider_code
         AND allowlist.provider_namespace = channel.provider_namespace
         AND allowlist.revoked_at IS NULL
         AND allowlist.expires_at > statement_timestamp()
        WHERE revision.id = NEW.revision_id
          AND revision.state = 'pending_review'
          AND revision.submitted_digest = NEW.target_digest
          AND reviewer.status = 'active'
          AND reviewer.risk_state NOT IN ('restricted', 'blocked')
          AND reviewer.id <> root.account_id
          AND NEW.transaction_id = pg_current_xact_id()
          AND (NEW.decision <> 'approve' OR profile.revision_is_publishable(NEW.revision_id))
          AND event.actor_type = 'administrator'
          AND event.actor_account_id = NEW.reviewer_account_id
          AND event.actor_channel_identity_id = NEW.reviewer_channel_identity_id
          AND event.source_channel = 'whatsapp'
          AND event.action = 'profile.review_decided'
          AND event.target_type = 'profile_revision'
          AND event.target_id = NEW.revision_id
          AND event.reason_code = NEW.reason_code
          AND event.before_digest = NEW.target_digest
          AND event.after_digest = NEW.target_digest
          AND event.metadata ->> 'decision' = NEW.decision
    ) THEN
        RAISE EXCEPTION 'review decision requires its matching immutable audit event';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER profile_review_decisions_guard_insert
BEFORE INSERT ON profile.profile_review_decisions
FOR EACH ROW EXECUTE FUNCTION profile.guard_review_decision_insert();

CREATE OR REPLACE FUNCTION profile.guard_revision_reviewable_fields()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    capability_id uuid;
BEGIN
    IF OLD.state <> 'draft'
       AND (
           NEW.display_name IS DISTINCT FROM OLD.display_name
           OR NEW.local_service_mode IS DISTINCT FROM OLD.local_service_mode
           OR NEW.service_radius_km IS DISTINCT FROM OLD.service_radius_km
           OR NEW.contact_request_limit IS DISTINCT FROM OLD.contact_request_limit
           OR NEW.submitted_digest IS DISTINCT FROM OLD.submitted_digest
           OR NEW.submitted_at IS DISTINCT FROM OLD.submitted_at
       )
    THEN
        RAISE EXCEPTION 'submitted profile revision fields are immutable';
    END IF;
    IF NEW.state IS NOT DISTINCT FROM OLD.state THEN
        IF NEW.decided_at IS DISTINCT FROM OLD.decided_at THEN
            RAISE EXCEPTION 'profile review decision timestamp is immutable';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'draft'
       AND NEW.state = 'pending_review'
       AND current_setting('sahayak.profile_submission', true) = NEW.id::text
       AND NEW.submitted_digest = profile.reviewable_revision_digest(NEW.id)
       AND profile.revision_is_publishable(NEW.id)
       AND NEW.submitted_at IS NOT NULL
       AND NEW.decided_at IS NULL
    THEN
        RETURN NEW;
    END IF;
    capability_id := NULLIF(current_setting('sahayak.profile_review_decision', true), '')::uuid;
    IF OLD.state = 'pending_review'
       AND NEW.state IN ('approved', 'changes_requested', 'rejected')
       AND NEW.decided_at IS NOT NULL
       AND EXISTS (
           SELECT 1
           FROM profile.profile_review_decisions AS decision
           WHERE decision.id = capability_id
             AND decision.transaction_id = pg_current_xact_id()
             AND decision.revision_id = OLD.id
             AND decision.target_digest = OLD.submitted_digest
             AND decision.decision = CASE NEW.state
                 WHEN 'approved' THEN 'approve'
                 WHEN 'changes_requested' THEN 'changes_requested'
                 ELSE 'reject'
             END
       )
    THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'approved'
       AND NEW.state = 'superseded'
       AND NEW.decided_at = OLD.decided_at
       AND EXISTS (
           SELECT 1
           FROM profile.profile_review_decisions AS decision
           JOIN profile.profile_revisions AS replacement
             ON replacement.id = decision.revision_id
            AND replacement.profile_id = OLD.profile_id
            AND replacement.state = 'approved'
           JOIN profile.public_profiles AS root
             ON root.id = OLD.profile_id
            AND root.published_revision_id = OLD.id
           WHERE decision.id = capability_id
             AND decision.transaction_id = pg_current_xact_id()
             AND decision.decision = 'approve'
       )
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'profile revision transition is not authorized';
END;
$$;

CREATE OR REPLACE FUNCTION profile.guard_public_profile_publication()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    capability_id uuid;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.visibility <> 'hidden'
           OR NEW.published_revision_id IS NOT NULL
           OR NEW.published_at IS NOT NULL
        THEN
            RAISE EXCEPTION 'profile roots must be created hidden';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id
       OR NEW.public_id <> OLD.public_id
       OR NEW.account_id <> OLD.account_id
       OR NEW.created_at <> OLD.created_at
    THEN
        RAISE EXCEPTION 'profile root identity is immutable';
    END IF;
    IF OLD.visibility = 'published'
       AND NEW.visibility = 'published'
       AND NEW.published_revision_id IS NOT DISTINCT FROM OLD.published_revision_id
       AND NEW.published_at IS DISTINCT FROM OLD.published_at
    THEN
        RAISE EXCEPTION 'profile publication timestamp is immutable';
    END IF;
    IF current_setting('sahayak.account_erasure', true) = 'on' THEN
        RETURN NEW;
    END IF;
    IF NEW.visibility = 'published'
       AND (
           OLD.visibility IS DISTINCT FROM 'published'
           OR NEW.published_revision_id IS DISTINCT FROM OLD.published_revision_id
       )
    THEN
        capability_id := NULLIF(current_setting('sahayak.profile_review_decision', true), '')::uuid;
        IF NOT EXISTS (
            SELECT 1
            FROM profile.profile_review_decisions AS decision
            JOIN profile.profile_revisions AS revision
              ON revision.id = decision.revision_id
             AND revision.profile_id = NEW.id
             AND revision.state = 'approved'
            WHERE decision.id = capability_id
              AND decision.transaction_id = pg_current_xact_id()
              AND decision.revision_id = NEW.published_revision_id
              AND decision.decision = 'approve'
              AND decision.target_digest = revision.submitted_digest
        ) THEN
            RAISE EXCEPTION 'profile publication requires its authorized review decision';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER public_profiles_guard_publication
BEFORE INSERT OR UPDATE ON profile.public_profiles
FOR EACH ROW EXECUTE FUNCTION profile.guard_public_profile_publication();

CREATE OR REPLACE FUNCTION profile.enforce_published_review_relationship()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    candidate_profile_id uuid;
    row_data jsonb;
BEGIN
    row_data := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
    candidate_profile_id := COALESCE(
        (row_data ->> 'profile_id')::uuid,
        (row_data ->> 'id')::uuid
    );
    IF EXISTS (
        SELECT 1
        FROM profile.public_profiles AS root
        WHERE root.id = candidate_profile_id
          AND root.visibility = 'published'
          AND NOT EXISTS (
              SELECT 1
              FROM profile.profile_revisions AS revision
              JOIN profile.profile_review_decisions AS decision
                ON decision.revision_id = revision.id
               AND decision.decision = 'approve'
               AND decision.target_digest = revision.submitted_digest
              JOIN audit.events AS event ON event.id = decision.audit_event_id
              WHERE revision.id = root.published_revision_id
                AND revision.profile_id = root.id
                AND revision.state = 'approved'
                AND event.action = 'profile.review_decided'
                AND event.target_id = revision.id
          )
    ) THEN
        RAISE EXCEPTION 'published profile must reference an approved audited revision';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER public_profiles_enforce_review_relationship
AFTER INSERT OR UPDATE ON profile.public_profiles
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION profile.enforce_published_review_relationship();

CREATE CONSTRAINT TRIGGER profile_revisions_enforce_review_relationship
AFTER UPDATE OR DELETE ON profile.profile_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION profile.enforce_published_review_relationship();

CREATE TABLE messaging.conversation_turn_receipt_outbounds (
    inbound_event_id uuid NOT NULL
        REFERENCES messaging.conversation_turn_receipts (inbound_event_id) ON DELETE RESTRICT,
    outbound_message_id uuid NOT NULL UNIQUE
        REFERENCES messaging.outbound_messages (id) ON DELETE RESTRICT,
    purpose text COLLATE "C" NOT NULL,
    position smallint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (inbound_event_id, position),
    CONSTRAINT conversation_turn_receipt_outbounds_purpose_check
        CHECK (purpose = 'professional_review_outcome'),
    CONSTRAINT conversation_turn_receipt_outbounds_position_check
        CHECK (position >= 0)
);

CREATE TRIGGER conversation_turn_receipt_outbounds_reject_update
BEFORE UPDATE ON messaging.conversation_turn_receipt_outbounds
FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER conversation_turn_receipt_outbounds_reject_delete
BEFORE DELETE ON messaging.conversation_turn_receipt_outbounds
FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER conversation_turn_receipt_outbounds_reject_truncate
BEFORE TRUNCATE ON messaging.conversation_turn_receipt_outbounds
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

UPDATE messaging.conversation_sessions
SET
    status = 'abandoned',
    state_data = '{}'::jsonb,
    expected_reply_to_outbound_message_id = NULL,
    last_inbound_event_id = NULL,
    ended_at = statement_timestamp(),
    terminal_reason = 'role_context_migration'
WHERE status = 'active'
  AND (
      (workflow_key = 'professional.profile' AND role_context <> 'professional')
      OR (workflow_key = 'administrator.review' AND role_context <> 'administrator')
      OR (
          workflow_key NOT IN ('professional.profile', 'administrator.review')
          AND role_context <> 'customer'
      )
  );

ALTER TABLE messaging.conversation_sessions
    ADD CONSTRAINT conversation_sessions_workflow_role_check
    CHECK (
        status <> 'active'
        OR (
            (workflow_key = 'professional.profile' AND role_context = 'professional')
            OR (workflow_key = 'administrator.review' AND role_context = 'administrator')
            OR (
                workflow_key NOT IN ('professional.profile', 'administrator.review')
                AND role_context = 'customer'
            )
        )
    );

CREATE TABLE identity.identity_provider_adapters (
    code varchar(48) COLLATE "C" PRIMARY KEY,
    provider_code varchar(32) COLLATE "C" NOT NULL,
    state text NOT NULL DEFAULT 'disabled',
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT identity_provider_adapters_code_check
        CHECK (code ~ '^[a-z][a-z0-9_]{1,47}$'),
    CONSTRAINT identity_provider_adapters_provider_check
        CHECK (provider_code ~ '^[a-z][a-z0-9_]{1,31}$'),
    CONSTRAINT identity_provider_adapters_state_check
        CHECK (state IN ('active', 'disabled'))
);

INSERT INTO identity.identity_provider_adapters (code, provider_code, state)
VALUES ('pilot_identity_v1', 'pilot', 'disabled');

CREATE TABLE private_data.identity_verification_attempts (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    account_id uuid NOT NULL
        REFERENCES identity.accounts (id) ON DELETE RESTRICT,
    adapter_instance_code varchar(48) COLLATE "C" NOT NULL
        REFERENCES identity.identity_provider_adapters (code) ON DELETE RESTRICT,
    consent_event_id uuid NOT NULL,
    consent_purpose text GENERATED ALWAYS AS ('identity_verification') STORED,
    state text NOT NULL DEFAULT 'pending',
    provider_reference_ciphertext bytea NOT NULL,
    provider_reference_nonce bytea NOT NULL,
    encryption_key_purpose text NOT NULL DEFAULT 'identity_encryption',
    encryption_key_version smallint NOT NULL,
    idempotency_key varchar(255) COLLATE "C" NOT NULL,
    expires_at timestamptz NOT NULL,
    verified_at timestamptz,
    assertion_valid_until timestamptz,
    failed_at timestamptz,
    revoked_at timestamptz,
    expired_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (consent_event_id, account_id, consent_purpose)
        REFERENCES private_data.professional_consent_events (id, account_id, purpose)
        ON DELETE RESTRICT,
    FOREIGN KEY (encryption_key_purpose, encryption_key_version)
        REFERENCES private_data.key_versions (purpose, version) ON DELETE RESTRICT,
    CONSTRAINT identity_verification_attempts_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT identity_verification_attempts_state_check
        CHECK (state IN ('pending', 'passed', 'failed', 'expired', 'revoked')),
    CONSTRAINT identity_verification_attempts_reference_check
        CHECK (octet_length(provider_reference_ciphertext) BETWEEN 16 AND 1024),
    CONSTRAINT identity_verification_attempts_nonce_check
        CHECK (octet_length(provider_reference_nonce) = 12),
    CONSTRAINT identity_verification_attempts_key_purpose_check
        CHECK (encryption_key_purpose = 'identity_encryption'),
    CONSTRAINT identity_verification_attempts_idempotency_check
        CHECK (octet_length(btrim(idempotency_key)) BETWEEN 1 AND 255),
    CONSTRAINT identity_verification_attempts_expiry_check
        CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '30 days'),
    CONSTRAINT identity_verification_attempts_state_shape_check
        CHECK (
            (state = 'pending' AND verified_at IS NULL AND assertion_valid_until IS NULL AND failed_at IS NULL AND revoked_at IS NULL AND expired_at IS NULL)
            OR (
                state = 'passed'
                AND verified_at IS NOT NULL
                AND assertion_valid_until IS NOT NULL
                AND assertion_valid_until > verified_at
                AND assertion_valid_until <= verified_at + INTERVAL '366 days'
                AND failed_at IS NULL AND revoked_at IS NULL AND expired_at IS NULL
            )
            OR (state = 'failed' AND failed_at IS NOT NULL AND verified_at IS NULL AND assertion_valid_until IS NULL AND revoked_at IS NULL AND expired_at IS NULL)
            OR (
                state = 'expired'
                AND expired_at IS NOT NULL
                AND failed_at IS NULL
                AND revoked_at IS NULL
                AND (
                    (verified_at IS NULL AND assertion_valid_until IS NULL)
                    OR (
                        verified_at IS NOT NULL
                        AND assertion_valid_until IS NOT NULL
                        AND assertion_valid_until > verified_at
                        AND assertion_valid_until <= verified_at + INTERVAL '366 days'
                    )
                )
            )
            OR (
                state = 'revoked'
                AND revoked_at IS NOT NULL
                AND failed_at IS NULL
                AND expired_at IS NULL
                AND (
                    (verified_at IS NULL AND assertion_valid_until IS NULL)
                    OR (
                        verified_at IS NOT NULL
                        AND assertion_valid_until IS NOT NULL
                        AND assertion_valid_until > verified_at
                        AND assertion_valid_until <= verified_at + INTERVAL '366 days'
                    )
                )
            )
        ),
    CONSTRAINT identity_verification_attempts_version_check
        CHECK (version > 0),
    CONSTRAINT identity_verification_attempts_idempotency_unique
        UNIQUE (account_id, idempotency_key),
    CONSTRAINT identity_verification_attempts_adapter_id_unique
        UNIQUE (id, adapter_instance_code)
);

CREATE UNIQUE INDEX identity_verification_attempts_one_active_idx
    ON private_data.identity_verification_attempts (account_id)
    WHERE state = 'pending';

CREATE INDEX identity_verification_attempts_badge_idx
    ON private_data.identity_verification_attempts (account_id, assertion_valid_until DESC)
    WHERE state = 'passed';

CREATE TRIGGER identity_verification_attempts_touch_version
BEFORE UPDATE ON private_data.identity_verification_attempts
FOR EACH ROW
EXECUTE FUNCTION identity.touch_versioned_row();

CREATE OR REPLACE FUNCTION private_data.guard_identity_verification_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id <> OLD.id
       OR NEW.account_id <> OLD.account_id
       OR NEW.adapter_instance_code <> OLD.adapter_instance_code
       OR NEW.consent_event_id <> OLD.consent_event_id
       OR NEW.provider_reference_ciphertext <> OLD.provider_reference_ciphertext
       OR NEW.provider_reference_nonce <> OLD.provider_reference_nonce
       OR NEW.encryption_key_purpose <> OLD.encryption_key_purpose
       OR NEW.encryption_key_version <> OLD.encryption_key_version
       OR NEW.idempotency_key <> OLD.idempotency_key
       OR NEW.expires_at <> OLD.expires_at
       OR NEW.created_at <> OLD.created_at
    THEN
        RAISE EXCEPTION 'identity verification attempt identity is immutable';
    END IF;
    IF NOT (
        (OLD.state = 'pending' AND NEW.state IN ('passed', 'failed', 'expired', 'revoked'))
        OR (OLD.state = 'passed' AND NEW.state IN ('expired', 'revoked'))
    ) THEN
        RAISE EXCEPTION 'identity verification state transition is not monotonic';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_verification_attempts_guard_transition
BEFORE UPDATE ON private_data.identity_verification_attempts
FOR EACH ROW
EXECUTE FUNCTION private_data.guard_identity_verification_transition();

CREATE OR REPLACE FUNCTION private_data.revoke_identity_attempts_with_consent()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.purpose = 'identity_verification' AND NEW.action = 'revoked' THEN
        UPDATE private_data.identity_verification_attempts AS attempt
        SET state = 'revoked', revoked_at = statement_timestamp()
        FROM private_data.professional_consent_events AS granted
        WHERE granted.id = attempt.consent_event_id
          AND granted.account_id = NEW.account_id
          AND granted.revision_id = NEW.revision_id
          AND attempt.state IN ('pending', 'passed');
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER professional_consent_events_revoke_identity_attempts
AFTER INSERT ON private_data.professional_consent_events
FOR EACH ROW EXECUTE FUNCTION private_data.revoke_identity_attempts_with_consent();

CREATE TABLE private_data.identity_verification_callback_receipts (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    attempt_id uuid NOT NULL,
    adapter_instance_code varchar(48) COLLATE "C" NOT NULL,
    callback_kind text NOT NULL,
    reported_state text NOT NULL,
    callback_event_key_digest bytea NOT NULL,
    callback_event_digest bytea NOT NULL,
    digest_key_purpose text NOT NULL DEFAULT 'lookup_hmac',
    digest_key_version smallint NOT NULL,
    signature_verified_at timestamptz,
    provider_occurred_at timestamptz,
    received_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (attempt_id, adapter_instance_code)
        REFERENCES private_data.identity_verification_attempts (id, adapter_instance_code)
        ON DELETE RESTRICT,
    FOREIGN KEY (digest_key_purpose, digest_key_version)
        REFERENCES private_data.key_versions (purpose, version) ON DELETE RESTRICT,
    CONSTRAINT identity_verification_callback_receipts_id_version_check
        CHECK (uuid_extract_version(id) = 7),
    CONSTRAINT identity_verification_callback_receipts_kind_check
        CHECK (callback_kind IN ('server_callback', 'browser_return')),
    CONSTRAINT identity_verification_callback_receipts_state_check
        CHECK (reported_state IN ('pending', 'passed', 'failed')),
    CONSTRAINT identity_verification_callback_receipts_browser_check
        CHECK (callback_kind <> 'browser_return' OR reported_state <> 'passed'),
    CONSTRAINT identity_verification_callback_receipts_signature_check
        CHECK (
            (callback_kind = 'server_callback' AND signature_verified_at IS NOT NULL)
            OR (callback_kind = 'browser_return' AND signature_verified_at IS NULL)
        ),
    CONSTRAINT identity_verification_callback_receipts_event_key_check
        CHECK (octet_length(callback_event_key_digest) = 32),
    CONSTRAINT identity_verification_callback_receipts_event_digest_check
        CHECK (octet_length(callback_event_digest) = 32),
    CONSTRAINT identity_verification_callback_receipts_key_purpose_check
        CHECK (digest_key_purpose = 'lookup_hmac'),
    CONSTRAINT identity_verification_callback_receipts_event_unique
        UNIQUE (adapter_instance_code, digest_key_version, callback_event_key_digest)
);

CREATE VIEW profile.identity_badge_projection AS
SELECT DISTINCT ON (attempt.account_id, consent.revision_id)
    attempt.account_id,
    consent.revision_id AS profile_revision_id,
    'Identity checked'::text AS badge_text,
    attempt.assertion_valid_until
FROM private_data.identity_verification_attempts AS attempt
JOIN private_data.professional_consent_events AS consent
  ON consent.id = attempt.consent_event_id
WHERE attempt.state = 'passed'
  AND attempt.assertion_valid_until > statement_timestamp()
  AND attempt.revoked_at IS NULL
  AND private_data.has_current_professional_consent(consent.revision_id, 'identity_verification')
ORDER BY
    attempt.account_id,
    consent.revision_id,
    attempt.assertion_valid_until DESC,
    attempt.id DESC;

CREATE OR REPLACE FUNCTION private_data.reject_mutation_except_account_erasure()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('sahayak.account_erasure', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% records are immutable', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER professional_consent_events_reject_mutation
BEFORE UPDATE OR DELETE ON private_data.professional_consent_events
FOR EACH ROW EXECUTE FUNCTION private_data.reject_mutation_except_account_erasure();

CREATE TRIGGER profile_review_decisions_reject_mutation
BEFORE UPDATE OR DELETE ON profile.profile_review_decisions
FOR EACH ROW EXECUTE FUNCTION private_data.reject_mutation_except_account_erasure();

CREATE TRIGGER identity_verification_callback_receipts_reject_mutation
BEFORE UPDATE OR DELETE ON private_data.identity_verification_callback_receipts
FOR EACH ROW EXECUTE FUNCTION private_data.reject_mutation_except_account_erasure();

CREATE TRIGGER professional_consent_events_reject_truncate
BEFORE TRUNCATE ON private_data.professional_consent_events
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER profile_review_decisions_reject_truncate
BEFORE TRUNCATE ON profile.profile_review_decisions
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER identity_verification_callback_receipts_reject_truncate
BEFORE TRUNCATE ON private_data.identity_verification_callback_receipts
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER administrator_allowlist_reject_delete
BEFORE DELETE ON identity.administrator_allowlist
FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER administrator_allowlist_reject_truncate
BEFORE TRUNCATE ON identity.administrator_allowlist
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER profile_photos_reject_delete
BEFORE DELETE ON private_data.profile_photos
FOR EACH ROW EXECUTE FUNCTION private_data.reject_mutation_except_account_erasure();

CREATE TRIGGER profile_photos_reject_truncate
BEFORE TRUNCATE ON private_data.profile_photos
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER identity_verification_attempts_reject_delete
BEFORE DELETE ON private_data.identity_verification_attempts
FOR EACH ROW EXECUTE FUNCTION private_data.reject_mutation_except_account_erasure();

CREATE TRIGGER identity_verification_attempts_reject_truncate
BEFORE TRUNCATE ON private_data.identity_verification_attempts
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER professional_service_areas_reject_truncate
BEFORE TRUNCATE ON private_data.professional_service_areas
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();

COMMENT ON TABLE profile.public_profiles IS 'Stable professional aggregate root containing no reviewable profile fields.';
COMMENT ON TABLE profile.profile_revisions IS 'Immutable-after-submission review snapshot containing no exact coordinates.';
COMMENT ON TABLE profile.professional_services IS 'Normalized local service selections and contact-disclosure policy per revision.';
COMMENT ON TABLE private_data.professional_service_areas IS 'Restricted exact service centers scoped to profile revisions.';
COMMENT ON TABLE private_data.professional_consent_events IS 'Immutable purpose-specific and revision-scoped professional consent ledger.';
COMMENT ON TABLE private_data.profile_photos IS 'Reusable restricted encrypted sanitized JPEG assets; never exposed through public profile projections.';
COMMENT ON TABLE profile.profile_revision_photos IS 'Reviewable per-revision selection of a private profile photo asset.';
COMMENT ON TABLE identity.administrator_allowlist IS 'Channel-bound administrator grants with retained grant and revocation history.';
COMMENT ON TABLE profile.profile_review_decisions IS 'One immutable authorized decision for each submitted profile revision.';
COMMENT ON TABLE messaging.conversation_turn_receipt_outbounds IS 'Additional non-session outbounds committed atomically with one conversation turn.';
COMMENT ON TABLE private_data.identity_verification_attempts IS 'Provider-neutral optional identity assertions without government identifiers or biometric material.';
COMMENT ON TABLE private_data.identity_verification_callback_receipts IS 'Payload-free idempotent identity callback receipts.';
