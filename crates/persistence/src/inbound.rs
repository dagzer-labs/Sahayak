use crate::{
    Database, LookupDigest, PersistenceError,
    key_registry::{ensure_active_encryption_key, ensure_lookup_key_readable},
};
use sahayak_cryptography::EncryptionPurpose;
use sahayak_domain::{AccountId, ChannelIdentityId, CorrelationId, InboundEventId, OutboxJobId};
use sqlx::{FromRow, PgConnection};
use std::collections::BTreeSet;
use time::OffsetDateTime;
use uuid::Uuid;

/// Versioned encrypted representation of a normalized provider event.
#[derive(Clone)]
pub struct EncryptedEventPayload {
    /// Independent key purpose for retained integration payloads.
    pub purpose: EncryptionPurpose,
    /// Schema version used before encryption.
    pub schema_version: i16,
    /// Authenticated ciphertext including its authentication tag.
    pub ciphertext: Vec<u8>,
    /// Unique 96-bit nonce used for this encryption operation.
    pub nonce: [u8; 12],
    /// Key version used for the collision-detection fingerprint.
    pub fingerprint_key_version: i16,
    /// HMAC-SHA-256 fingerprint of normalized plaintext used for collision detection.
    pub payload_fingerprint: [u8; 32],
    /// Additional key-version fingerprints retained during lookup-key rotation.
    pub additional_fingerprints: Vec<LookupDigest>,
    /// Active application encryption key version.
    pub key_version: i16,
}

/// Fully validated input required to durably accept one logical provider event.
#[derive(Clone)]
pub struct InboundEventInput {
    /// Application-generated internal event identifier.
    pub event_id: InboundEventId,
    /// Communication provider code, such as `whatsapp`.
    pub provider_code: String,
    /// Business-account or deployment namespace supplied by the integration.
    pub provider_namespace: String,
    /// Stable provider identifier for one logical event.
    pub provider_event_id: String,
    /// Versioned normalized event category.
    pub event_type: String,
    /// Encrypted normalized event body.
    pub payload: EncryptedEventPayload,
    /// Internal correlation identifier propagated through processing.
    pub correlation_id: CorrelationId,
    /// Time at which the provider signature was successfully verified.
    pub signature_verified_at: OffsetDateTime,
    /// Provider-declared event time when present and trustworthy enough to retain.
    pub provider_occurred_at: Option<OffsetDateTime>,
    /// Application-generated processing job identifier.
    pub processing_job_id: OutboxJobId,
    /// Durable worker handler selected from the normalized event type.
    pub processing_job_kind: String,
    /// Optional HMAC routing key used to preserve per-sender processing order.
    pub processing_ordering_key: Option<[u8; 32]>,
    /// Maximum processing claims before dead-lettering.
    pub max_attempts: i32,
}

/// Encrypted normalized event loaded for a trusted worker handler.
#[derive(Clone)]
pub struct EncryptedInboundEvent {
    /// Internal event identifier.
    pub id: InboundEventId,
    /// Stable normalized event category.
    pub event_type: String,
    /// Normalized payload schema version.
    pub payload_schema_version: i16,
    /// Authenticated encrypted normalized payload.
    pub payload: sahayak_cryptography::EncryptedValue,
    /// Provider occurrence time.
    pub provider_occurred_at: Option<OffsetDateTime>,
    /// Workflow correlation identifier.
    pub correlation_id: CorrelationId,
}

impl std::fmt::Debug for EncryptedInboundEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedInboundEvent")
            .field("id", &self.id)
            .field("event_type", &self.event_type)
            .field("payload_schema_version", &self.payload_schema_version)
            .field("payload", &"[REDACTED]")
            .field("provider_occurred_at", &self.provider_occurred_at)
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}

impl InboundEventInput {
    fn validate(&self) -> Result<(), PersistenceError> {
        validate_code("provider_code", &self.provider_code, 32)?;
        validate_opaque("provider_namespace", &self.provider_namespace, 128)?;
        validate_opaque("provider_event_id", &self.provider_event_id, 512)?;
        validate_code("event_type", &self.event_type, 128)?;
        validate_code("processing_job_kind", &self.processing_job_kind, 128)?;
        if self.payload.schema_version <= 0
            || self.payload.key_version <= 0
            || self.payload.fingerprint_key_version <= 0
        {
            return Err(PersistenceError::InvalidCommand(
                "payload schema and key versions must be positive".to_owned(),
            ));
        }
        if self.payload.purpose != EncryptionPurpose::Integration {
            return Err(PersistenceError::InvalidCommand(
                "inbound events require the integration encryption key purpose".to_owned(),
            ));
        }
        let mut fingerprint_versions = BTreeSet::from([self.payload.fingerprint_key_version]);
        if self
            .payload
            .additional_fingerprints
            .iter()
            .any(|fingerprint| {
                fingerprint.key_version <= 0
                    || !fingerprint_versions.insert(fingerprint.key_version)
            })
        {
            return Err(PersistenceError::InvalidCommand(
                "event fingerprint key versions must be positive and unique".to_owned(),
            ));
        }
        if self.payload.ciphertext.len() < 16 {
            return Err(PersistenceError::InvalidCommand(
                "encrypted event payload is too short".to_owned(),
            ));
        }
        if !(1..=100).contains(&self.max_attempts) {
            return Err(PersistenceError::InvalidCommand(
                "max_attempts must be between 1 and 100".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Result of idempotently accepting one provider event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Acceptance {
    /// This call inserted the event and its initial processing job.
    Accepted {
        /// Persisted event identifier.
        event_id: InboundEventId,
        /// Persisted processing job identifier.
        job_id: OutboxJobId,
    },
    /// An identical event was already durably accepted.
    Duplicate {
        /// Existing event identifier.
        event_id: InboundEventId,
    },
    /// The provider reused an event key for different normalized content.
    IdentifierCollision {
        /// Existing event identifier owning the provider key.
        event_id: InboundEventId,
    },
}

/// Result of durably associating a decrypted sender event with its resolved identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundIdentityBinding {
    Bound,
    AlreadyBound,
}

#[derive(FromRow)]
struct AcceptedRow {
    event_id: Uuid,
    job_id: Uuid,
}

#[derive(FromRow)]
struct ExistingRow {
    id: Uuid,
    event_type: String,
    payload_version: i16,
}

#[derive(FromRow)]
struct ExistingFingerprintRow {
    key_version: i16,
    digest: Vec<u8>,
}

#[derive(FromRow)]
struct EncryptedInboundRow {
    id: Uuid,
    event_type: String,
    payload_version: i16,
    payload_ciphertext: Option<Vec<u8>>,
    payload_nonce: Option<Vec<u8>>,
    encryption_key_version: i16,
    provider_occurred_at: Option<OffsetDateTime>,
    correlation_id: Uuid,
}

impl Database {
    /// Binds an inbound event only when a supplied WhatsApp-ID blind index belongs
    /// to the exact account/channel in the event's provider namespace.
    pub async fn bind_inbound_event_identity(
        &self,
        event_id: InboundEventId,
        account_id: AccountId,
        channel_identity_id: ChannelIdentityId,
        wa_id_digests: &[LookupDigest],
    ) -> Result<InboundIdentityBinding, PersistenceError> {
        if wa_id_digests.is_empty() {
            return Err(PersistenceError::InvalidCommand(
                "inbound identity binding requires a WhatsApp lookup digest".to_owned(),
            ));
        }
        let mut versions = BTreeSet::new();
        if wa_id_digests
            .iter()
            .any(|value| value.key_version <= 0 || !versions.insert(value.key_version))
        {
            return Err(PersistenceError::InvalidCommand(
                "inbound identity lookup versions must be positive and unique".to_owned(),
            ));
        }
        let key_versions: Vec<i16> = wa_id_digests
            .iter()
            .map(|value| value.key_version)
            .collect();
        let digests: Vec<Vec<u8>> = wa_id_digests
            .iter()
            .map(|value| value.digest.to_vec())
            .collect();
        let mut transaction = self.pool().begin().await?;
        let current: Option<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
            r#"
            SELECT account_id, channel_identity_id
            FROM integration.inbound_events
            WHERE id = $1
            FOR UPDATE
            "#,
        )
        .bind(event_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((current_account, current_channel)) = current else {
            transaction.rollback().await?;
            return Err(PersistenceError::InvalidCommand(
                "inbound event does not exist".to_owned(),
            ));
        };
        if current_account.is_some() || current_channel.is_some() {
            transaction.rollback().await?;
            if current_account == Some(account_id.into_uuid())
                && current_channel == Some(channel_identity_id.into_uuid())
            {
                return Ok(InboundIdentityBinding::AlreadyBound);
            }
            return Err(PersistenceError::InvalidCommand(
                "inbound event is already bound to another identity".to_owned(),
            ));
        }
        sqlx::query("SELECT set_config('sahayak.inbound_identity_binding', $1, true)")
            .bind(event_id.to_string())
            .execute(&mut *transaction)
            .await?;
        let bound = sqlx::query(
            r#"
            UPDATE integration.inbound_events AS inbound
            SET account_id = $2, channel_identity_id = $3
            FROM identity.channel_identities AS channel
            WHERE inbound.id = $1
              AND inbound.account_id IS NULL
              AND inbound.channel_identity_id IS NULL
              AND channel.id = $3
              AND channel.account_id = $2
              AND channel.provider_code = inbound.provider_code
              AND channel.provider_namespace = inbound.provider_namespace
              AND channel.status = 'active'
              AND EXISTS (
                  SELECT 1
                  FROM private_data.channel_lookup_digests AS lookup
                  JOIN unnest($4::smallint[], $5::bytea[])
                    AS supplied(key_version, digest)
                    ON supplied.key_version = lookup.key_version
                   AND supplied.digest = lookup.digest
                  WHERE lookup.channel_identity_id = channel.id
                    AND lookup.channel_code = 'whatsapp'
                    AND lookup.lookup_kind = 'whatsapp_wa_id'
              )
            "#,
        )
        .bind(event_id.into_uuid())
        .bind(account_id.into_uuid())
        .bind(channel_identity_id.into_uuid())
        .bind(&key_versions)
        .bind(&digests)
        .execute(&mut *transaction)
        .await?;
        if bound.rows_affected() != 1 {
            transaction.rollback().await?;
            return Err(PersistenceError::InvalidCommand(
                "inbound sender digest does not match the resolved identity".to_owned(),
            ));
        }
        transaction.commit().await?;
        Ok(InboundIdentityBinding::Bound)
    }

    /// Purges encrypted payload bytes after every related job reaches a terminal state.
    pub async fn purge_inbound_payloads(
        &self,
        received_before: OffsetDateTime,
        limit: u16,
    ) -> Result<u64, PersistenceError> {
        if !(1..=1_000).contains(&limit) {
            return Err(PersistenceError::InvalidCommand(
                "inbound payload purge limit must be between 1 and 1000".to_owned(),
            ));
        }
        let result = sqlx::query(
            r#"
            WITH purgeable AS (
                SELECT event.id
                FROM integration.inbound_events AS event
                WHERE event.received_at < $1
                  AND event.payload_purged_at IS NULL
                  AND NOT EXISTS (
                      SELECT 1
                      FROM integration.outbox_jobs AS job
                      WHERE job.inbound_event_id = event.id
                        AND job.state NOT IN ('completed', 'dead_lettered')
                  )
                ORDER BY event.received_at, event.id
                LIMIT $2
                FOR UPDATE OF event SKIP LOCKED
            )
            UPDATE integration.inbound_events AS event
            SET
                payload_ciphertext = NULL,
                payload_nonce = NULL,
                payload_purged_at = statement_timestamp()
            FROM purgeable
            WHERE event.id = purgeable.id
            "#,
        )
        .bind(received_before)
        .bind(i64::from(limit))
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }

    /// Loads an unpurged encrypted event for a trusted worker handler.
    pub async fn find_encrypted_inbound_event(
        &self,
        event_id: InboundEventId,
    ) -> Result<Option<EncryptedInboundEvent>, PersistenceError> {
        let row = sqlx::query_as::<_, EncryptedInboundRow>(
            r#"
            SELECT
                id,
                event_type,
                payload_version,
                payload_ciphertext,
                payload_nonce,
                encryption_key_version,
                provider_occurred_at,
                correlation_id
            FROM integration.inbound_events
            WHERE id = $1
            "#,
        )
        .bind(event_id.into_uuid())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            let ciphertext = row.payload_ciphertext.ok_or_else(|| {
                PersistenceError::Invariant("inbound event payload was already purged".to_owned())
            })?;
            let nonce: [u8; 12] = row
                .payload_nonce
                .ok_or_else(|| {
                    PersistenceError::Invariant("inbound event nonce was already purged".to_owned())
                })?
                .try_into()
                .map_err(|_| {
                    PersistenceError::Invariant("inbound event nonce has invalid length".to_owned())
                })?;
            Ok(EncryptedInboundEvent {
                id: InboundEventId::from_uuid(row.id),
                event_type: row.event_type,
                payload_schema_version: row.payload_version,
                payload: sahayak_cryptography::EncryptedValue {
                    purpose: EncryptionPurpose::Integration,
                    key_version: row.encryption_key_version,
                    nonce,
                    ciphertext,
                },
                provider_occurred_at: row.provider_occurred_at,
                correlation_id: CorrelationId::from_uuid(row.correlation_id),
            })
        })
        .transpose()
    }

    /// Atomically stores a new provider event and its initial processing job.
    pub async fn accept_inbound_event(
        &self,
        input: &InboundEventInput,
    ) -> Result<Acceptance, PersistenceError> {
        let mut outcomes = self
            .accept_inbound_events(std::slice::from_ref(input))
            .await?;
        outcomes.pop().ok_or_else(|| {
            PersistenceError::Invariant("single-event acceptance returned no outcome".to_owned())
        })
    }

    /// Atomically stores every logical event extracted from one signed webhook envelope.
    pub async fn accept_inbound_events(
        &self,
        inputs: &[InboundEventInput],
    ) -> Result<Vec<Acceptance>, PersistenceError> {
        if inputs.is_empty() || inputs.len() > 1_000 {
            return Err(PersistenceError::InvalidCommand(
                "inbound event batch must contain between 1 and 1000 events".to_owned(),
            ));
        }
        let correlation_id = inputs[0].correlation_id;
        for input in inputs {
            input.validate()?;
            if input.correlation_id != correlation_id {
                return Err(PersistenceError::InvalidCommand(
                    "one webhook envelope must use one correlation identifier".to_owned(),
                ));
            }
        }
        let mut transaction = self.pool().begin().await?;
        let encryption_versions: BTreeSet<_> = inputs
            .iter()
            .map(|input| input.payload.key_version)
            .collect();
        let fingerprint_versions: BTreeSet<_> = inputs
            .iter()
            .flat_map(|input| {
                std::iter::once(input.payload.fingerprint_key_version).chain(
                    input
                        .payload
                        .additional_fingerprints
                        .iter()
                        .map(|fingerprint| fingerprint.key_version),
                )
            })
            .collect();
        for version in encryption_versions {
            ensure_active_encryption_key(&mut transaction, EncryptionPurpose::Integration, version)
                .await?;
        }
        for version in fingerprint_versions {
            ensure_lookup_key_readable(&mut transaction, version).await?;
        }
        let mut outcomes = Vec::with_capacity(inputs.len());
        for input in inputs {
            let outcome = self
                .accept_inbound_event_in_transaction(&mut transaction, input)
                .await?;
            if let Acceptance::IdentifierCollision { event_id } = outcome {
                sqlx::query(
                    r#"
                    INSERT INTO audit.events (
                        id,
                        actor_type,
                        source_channel,
                        action,
                        target_type,
                        target_id,
                        reason_code,
                        metadata,
                        event_schema_version,
                        correlation_id
                    )
                    VALUES (
                        uuidv7(), 'system', 'system', 'webhook.identifier_collision',
                        'inbound_event', $1, 'provider_event_key_reused', '{}'::jsonb, 1, $2
                    )
                    "#,
                )
                .bind(event_id.into_uuid())
                .bind(input.correlation_id.into_uuid())
                .execute(&mut *transaction)
                .await?;
            }
            outcomes.push(outcome);
        }
        transaction.commit().await?;
        Ok(outcomes)
    }

    async fn accept_inbound_event_in_transaction(
        &self,
        connection: &mut PgConnection,
        input: &InboundEventInput,
    ) -> Result<Acceptance, PersistenceError> {
        let inserted = sqlx::query_as::<_, AcceptedRow>(
            r#"
            WITH accepted_event AS (
                INSERT INTO integration.inbound_events (
                    id,
                    provider_code,
                    provider_namespace,
                    provider_event_id,
                    event_type,
                    payload_version,
                    payload_ciphertext,
                    payload_nonce,
                    payload_fingerprint,
                    encryption_key_purpose,
                    encryption_key_version,
                    fingerprint_key_version,
                    correlation_id,
                    signature_verified_at,
                    provider_occurred_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                ON CONFLICT (provider_code, provider_namespace, provider_event_id) DO NOTHING
                RETURNING id
            )
            INSERT INTO integration.outbox_jobs (
                id,
                inbound_event_id,
                job_kind,
                idempotency_key,
                payload_version,
                payload,
                max_attempts,
                correlation_id,
                ordering_key
            )
            SELECT
                $16,
                accepted_event.id,
                $18,
                accepted_event.id::text,
                1,
                jsonb_build_object('inbound_event_id', accepted_event.id::text),
                $17,
                $13,
                $19
            FROM accepted_event
            RETURNING inbound_event_id AS event_id, id AS job_id
            "#,
        )
        .bind(input.event_id.into_uuid())
        .bind(&input.provider_code)
        .bind(&input.provider_namespace)
        .bind(&input.provider_event_id)
        .bind(&input.event_type)
        .bind(input.payload.schema_version)
        .bind(&input.payload.ciphertext)
        .bind(input.payload.nonce.as_slice())
        .bind(input.payload.payload_fingerprint.as_slice())
        .bind(input.payload.purpose.as_str())
        .bind(input.payload.key_version)
        .bind(input.payload.fingerprint_key_version)
        .bind(input.correlation_id.into_uuid())
        .bind(input.signature_verified_at)
        .bind(input.provider_occurred_at)
        .bind(input.processing_job_id.into_uuid())
        .bind(input.max_attempts)
        .bind(&input.processing_job_kind)
        .bind(
            input
                .processing_ordering_key
                .as_ref()
                .map(<[u8; 32]>::as_slice),
        )
        .fetch_optional(&mut *connection)
        .await?;

        let outcome = if let Some(row) = inserted {
            for fingerprint in std::iter::once(LookupDigest {
                key_version: input.payload.fingerprint_key_version,
                digest: input.payload.payload_fingerprint,
            })
            .chain(input.payload.additional_fingerprints.iter().copied())
            {
                sqlx::query(
                    r#"
                    INSERT INTO integration.inbound_event_fingerprints (
                        inbound_event_id,
                        key_version,
                        digest
                    )
                    VALUES ($1, $2, $3)
                    "#,
                )
                .bind(row.event_id)
                .bind(fingerprint.key_version)
                .bind(fingerprint.digest.as_slice())
                .execute(&mut *connection)
                .await?;
            }
            Acceptance::Accepted {
                event_id: InboundEventId::from_uuid(row.event_id),
                job_id: OutboxJobId::from_uuid(row.job_id),
            }
        } else {
            let existing = sqlx::query_as::<_, ExistingRow>(
                r#"
                SELECT id, event_type, payload_version
                FROM integration.inbound_events
                WHERE provider_code = $1
                  AND provider_namespace = $2
                  AND provider_event_id = $3
                "#,
            )
            .bind(&input.provider_code)
            .bind(&input.provider_namespace)
            .bind(&input.provider_event_id)
            .fetch_optional(&mut *connection)
            .await?
            .ok_or_else(|| {
                PersistenceError::Invariant(
                    "conflicting inbound event disappeared before inspection".to_owned(),
                )
            })?;
            let event_id = InboundEventId::from_uuid(existing.id);
            let existing_fingerprints = sqlx::query_as::<_, ExistingFingerprintRow>(
                r#"
                SELECT key_version, digest
                FROM integration.inbound_event_fingerprints
                WHERE inbound_event_id = $1
                "#,
            )
            .bind(existing.id)
            .fetch_all(&mut *connection)
            .await?;
            let fingerprint_matches = std::iter::once(LookupDigest {
                key_version: input.payload.fingerprint_key_version,
                digest: input.payload.payload_fingerprint,
            })
            .chain(input.payload.additional_fingerprints.iter().copied())
            .any(|incoming| {
                existing_fingerprints.iter().any(|stored| {
                    stored.key_version == incoming.key_version
                        && stored.digest.as_slice() == incoming.digest
                })
            });
            let same_payload = existing.event_type == input.event_type
                && existing.payload_version == input.payload.schema_version
                && fingerprint_matches;

            if same_payload {
                Acceptance::Duplicate { event_id }
            } else {
                Acceptance::IdentifierCollision { event_id }
            }
        };

        Ok(outcome)
    }
}

fn validate_code(name: &str, value: &str, maximum: usize) -> Result<(), PersistenceError> {
    let mut bytes = value.bytes();
    let valid_first = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
    let valid_rest = bytes.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
    });
    if !valid_first || !valid_rest || value.len() > maximum {
        return Err(PersistenceError::InvalidCommand(format!(
            "{name} is not a valid bounded code"
        )));
    }
    Ok(())
}

fn validate_opaque(name: &str, value: &str, maximum: usize) -> Result<(), PersistenceError> {
    if value.is_empty()
        || value.len() > maximum
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(PersistenceError::InvalidCommand(format!(
            "{name} is empty, oversized, or contains control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_code, validate_opaque};

    #[test]
    fn validates_machine_codes() {
        assert!(validate_code("event_type", "message.received-v1", 128).is_ok());
        assert!(validate_code("event_type", "Message Received", 128).is_err());
    }

    #[test]
    fn rejects_control_characters_in_provider_identifiers() {
        assert!(validate_opaque("provider_event_id", "message-123", 512).is_ok());
        assert!(validate_opaque("provider_event_id", "message\n123", 512).is_err());
    }
}
