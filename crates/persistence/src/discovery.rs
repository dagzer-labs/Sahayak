use crate::{Database, PersistenceError};
use sahayak_domain::{
    AccountId, ChannelIdentityId, CorrelationId, InboundEventId, RequestedTimeWindow,
    ServiceRequestId, ServiceRequestState,
};
use sqlx::{FromRow, PgConnection};
use std::str::FromStr;
use uuid::Uuid;

pub const MATCHING_VERSION: &str = "local-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryCategory {
    Plumber,
    Electrician,
}

impl DiscoveryCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plumber => "plumber",
            Self::Electrician => "electrician",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryCard {
    pub candidate_token: String,
    pub display_name: String,
    pub public_reference: String,
    pub category_code: String,
    pub distance_metres: i32,
    pub distance_label: String,
    pub language_compatible: bool,
    pub availability_label: String,
    pub identity_checked: bool,
    pub contact_mode: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryRequestSnapshot {
    pub request_id: ServiceRequestId,
    pub request_token: String,
    pub version: i64,
    pub state: ServiceRequestState,
    pub category_code: String,
    pub requested_time: Option<RequestedTimeWindow>,
    pub issue_code: Option<String>,
    pub radius_km: i16,
    pub maximum_radius_km: i16,
    pub has_location: bool,
    pub result_round: i16,
    pub has_more: bool,
    pub cards: Vec<DiscoveryCard>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryConversationSnapshot {
    None,
    Current(DiscoveryRequestSnapshot),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryMutationOutcome {
    Applied,
    Conflict,
    Ineligible,
    NoMoreResults,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DiscoveryTurnOperation {
    Begin {
        request_id: ServiceRequestId,
        request_token: Uuid,
        category: DiscoveryCategory,
    },
    CaptureLocation {
        request_token: Uuid,
        expected_version: i64,
        latitude: f64,
        longitude: f64,
    },
    Search {
        request_token: Uuid,
        expected_version: i64,
        requested_time: RequestedTimeWindow,
        issue_code: String,
    },
    ShowMore {
        request_token: Uuid,
        expected_version: i64,
    },
    ExpandRadius {
        request_token: Uuid,
        expected_version: i64,
    },
    Cancel {
        request_token: Uuid,
        expected_version: i64,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiscoveryTurnEffect {
    pub operation: DiscoveryTurnOperation,
}

#[derive(Clone, Copy, Debug)]
pub struct DiscoveryEffectContext<'a> {
    pub account_id: AccountId,
    pub channel_identity_id: ChannelIdentityId,
    pub inbound_event_id: InboundEventId,
    pub provider_namespace: &'a str,
    pub correlation_id: CorrelationId,
}

#[derive(FromRow)]
struct RequestRow {
    id: Uuid,
    request_token: Uuid,
    version: i64,
    status: String,
    category_code: String,
    requested_time: Option<String>,
    issue_code: Option<String>,
    requested_radius_km: i16,
    maximum_radius_km: i16,
    result_round: i16,
    has_location: bool,
}

#[derive(FromRow)]
struct CardRow {
    candidate_token: Uuid,
    display_name: String,
    public_reference: Uuid,
    category_code: String,
    distance_metres: i32,
    language_score: i16,
    freshness_score: i32,
    identity_checked: bool,
    contact_mode: String,
}

#[derive(Clone, Debug)]
pub struct DiscoveryRepository {
    database: Database,
}

impl DiscoveryRepository {
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    pub async fn load_conversation_snapshot(
        &self,
        account_id: AccountId,
        channel_identity_id: ChannelIdentityId,
    ) -> Result<DiscoveryConversationSnapshot, PersistenceError> {
        let request = sqlx::query_as::<_, RequestRow>(
            r#"
            SELECT request.id, request.request_token, request.version, request.status,
                   request.category_code, request.requested_time, request.issue_code,
                   request.requested_radius_km, request.maximum_radius_km,
                   request.result_round,
                   EXISTS (SELECT 1 FROM private_data.service_request_locations AS location
                           WHERE location.request_id = request.id) AS has_location
            FROM discovery.service_requests AS request
            WHERE request.customer_account_id = $1
              AND request.customer_channel_identity_id = $2
              AND request.status IN (
                  'draft', 'collecting_requirements', 'searching', 'showing_results',
                  'no_results', 'selected'
              )
              AND request.expires_at > statement_timestamp()
            ORDER BY request.created_at DESC
            LIMIT 1
            "#,
        )
        .bind(account_id.into_uuid())
        .bind(channel_identity_id.into_uuid())
        .fetch_optional(self.database.pool())
        .await?;
        let Some(request) = request else {
            return Ok(DiscoveryConversationSnapshot::None);
        };
        let cards = sqlx::query_as::<_, CardRow>(
            r#"
            SELECT candidate.candidate_token, revision.display_name,
                   root.public_id AS public_reference, service.category_code,
                   candidate.distance_metres, candidate.language_score,
                   candidate.freshness_score,
                   (badge.badge_text IS NOT NULL) AS identity_checked,
                   service.contact_mode
            FROM discovery.request_candidates AS candidate
            JOIN profile.provider_services AS provider_service
              ON provider_service.id = candidate.provider_service_id
            JOIN profile.public_profiles AS root ON root.id = candidate.profile_id
            JOIN profile.profile_revisions AS revision ON revision.id = candidate.profile_revision_id
            JOIN profile.professional_services AS service
              ON service.revision_id = revision.id
             AND service.category_code = provider_service.category_code
            LEFT JOIN profile.identity_badge_projection AS badge
              ON badge.account_id = candidate.professional_account_id
            WHERE candidate.request_id = $1
              AND candidate.shown_batch = $2
              AND candidate.excluded_at IS NULL
            ORDER BY candidate.final_rank, candidate.id
            "#,
        )
        .bind(request.id)
        .bind(i32::from(request.result_round))
        .fetch_all(self.database.pool())
        .await?;
        let has_more: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM discovery.request_candidates WHERE request_id = $1 AND shown_at IS NULL AND excluded_at IS NULL)",
        )
        .bind(request.id)
        .fetch_one(self.database.pool())
        .await?;
        Ok(DiscoveryConversationSnapshot::Current(
            DiscoveryRequestSnapshot {
                request_id: ServiceRequestId::from_uuid(request.id),
                request_token: request.request_token.to_string(),
                version: request.version,
                state: ServiceRequestState::from_str(&request.status).map_err(|error| {
                    PersistenceError::Invariant(format!(
                        "service request state is invalid: {error}"
                    ))
                })?,
                category_code: request.category_code,
                requested_time: request
                    .requested_time
                    .map(|value| RequestedTimeWindow::from_str(&value))
                    .transpose()
                    .map_err(|error| {
                        PersistenceError::Invariant(format!("requested time is invalid: {error}"))
                    })?,
                issue_code: request.issue_code,
                radius_km: request.requested_radius_km,
                maximum_radius_km: request.maximum_radius_km,
                has_location: request.has_location,
                result_round: request.result_round,
                has_more,
                cards: cards.into_iter().map(map_card).collect(),
            },
        ))
    }
}

pub(crate) async fn apply_discovery_effect(
    connection: &mut PgConnection,
    context: DiscoveryEffectContext<'_>,
    effect: DiscoveryTurnEffect,
) -> Result<DiscoveryMutationOutcome, PersistenceError> {
    sqlx::query("SELECT set_config('sahayak.discovery_mutation', 'on', true)")
        .execute(&mut *connection)
        .await?;
    if !customer_is_eligible(connection, context).await? {
        return Ok(DiscoveryMutationOutcome::Ineligible);
    }
    match effect.operation {
        DiscoveryTurnOperation::Begin {
            request_id,
            request_token,
            category,
        } => begin_request(connection, context, request_id, request_token, category).await,
        DiscoveryTurnOperation::CaptureLocation {
            request_token,
            expected_version,
            latitude,
            longitude,
        } => {
            capture_location(
                connection,
                context,
                request_token,
                expected_version,
                latitude,
                longitude,
            )
            .await
        }
        DiscoveryTurnOperation::Search {
            request_token,
            expected_version,
            requested_time,
            issue_code,
        } => {
            search(
                connection,
                context,
                request_token,
                expected_version,
                requested_time,
                &issue_code,
            )
            .await
        }
        DiscoveryTurnOperation::ShowMore {
            request_token,
            expected_version,
        } => show_more(connection, context, request_token, expected_version, false).await,
        DiscoveryTurnOperation::ExpandRadius {
            request_token,
            expected_version,
        } => show_more(connection, context, request_token, expected_version, true).await,
        DiscoveryTurnOperation::Cancel {
            request_token,
            expected_version,
        } => cancel_request(connection, context, request_token, expected_version).await,
    }
}

async fn customer_is_eligible(
    connection: &mut PgConnection,
    context: DiscoveryEffectContext<'_>,
) -> Result<bool, PersistenceError> {
    sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM identity.accounts AS account
            JOIN identity.channel_identities AS channel
              ON channel.id = $2 AND channel.account_id = account.id
             AND channel.provider_code = 'whatsapp'
             AND channel.provider_namespace = $3
             AND channel.status = 'active' AND channel.verified_at IS NOT NULL
            JOIN private_data.whatsapp_identities AS whatsapp
              ON whatsapp.channel_identity_id = channel.id
             AND whatsapp.opt_in_status <> 'opted_out'
             AND whatsapp.delivery_state <> 'unreachable'
             AND whatsapp.blocked_at IS NULL
            WHERE account.id = $1 AND account.status IN ('pending', 'active')
              AND account.risk_state = 'normal'
        )
        "#,
    )
    .bind(context.account_id.into_uuid())
    .bind(context.channel_identity_id.into_uuid())
    .bind(context.provider_namespace)
    .fetch_one(&mut *connection)
    .await
    .map_err(PersistenceError::from)
}

async fn begin_request(
    connection: &mut PgConnection,
    context: DiscoveryEffectContext<'_>,
    request_id: ServiceRequestId,
    request_token: Uuid,
    category: DiscoveryCategory,
) -> Result<DiscoveryMutationOutcome, PersistenceError> {
    expire_customer_requests(connection, context.account_id).await?;
    let throttled: bool = sqlx::query_scalar(
        r#"
        SELECT
            (SELECT count(*) FROM discovery.service_requests
             WHERE customer_account_id = $1
               AND created_at > clock_timestamp() - INTERVAL '1 hour') >= 20
            OR
            (SELECT count(*) FROM discovery.service_requests
             WHERE customer_account_id = $1
               AND created_at > clock_timestamp() - INTERVAL '24 hours') >= 60
        "#,
    )
    .bind(context.account_id.into_uuid())
    .fetch_one(&mut *connection)
    .await?;
    if throttled {
        return Ok(DiscoveryMutationOutcome::Ineligible);
    }
    let inserted = sqlx::query(
        r#"
        INSERT INTO discovery.service_requests (
            id, request_token, customer_account_id, customer_channel_identity_id,
            category_code, customer_locale, status, source_inbound_event_id,
            correlation_id, expires_at
        )
        SELECT $1, $2, account.id, $3, $4, account.preferred_locale,
               'collecting_requirements', $5, $6,
               clock_timestamp() + INTERVAL '2 hours'
        FROM identity.accounts AS account
        JOIN profile.service_categories AS category
          ON category.code = $4 AND category.state = 'active'
        WHERE account.id = $7
        ON CONFLICT (source_inbound_event_id) DO NOTHING
        "#,
    )
    .bind(request_id.into_uuid())
    .bind(request_token)
    .bind(context.channel_identity_id.into_uuid())
    .bind(category.as_str())
    .bind(context.inbound_event_id.into_uuid())
    .bind(context.correlation_id.into_uuid())
    .bind(context.account_id.into_uuid())
    .execute(&mut *connection)
    .await?;
    if inserted.rows_affected() == 1 {
        Ok(DiscoveryMutationOutcome::Applied)
    } else {
        Ok(DiscoveryMutationOutcome::Conflict)
    }
}

#[allow(clippy::too_many_arguments)]
async fn capture_location(
    connection: &mut PgConnection,
    context: DiscoveryEffectContext<'_>,
    request_token: Uuid,
    expected_version: i64,
    latitude: f64,
    longitude: f64,
) -> Result<DiscoveryMutationOutcome, PersistenceError> {
    if !latitude.is_finite()
        || !longitude.is_finite()
        || !(-90.0..=90.0).contains(&latitude)
        || !(-180.0..=180.0).contains(&longitude)
    {
        return Err(PersistenceError::InvalidCommand(
            "service request location is invalid".to_owned(),
        ));
    }
    let request_id: Option<Uuid> = sqlx::query_scalar(
        r#"
        SELECT id FROM discovery.service_requests
        WHERE request_token = $1 AND customer_account_id = $2
          AND version = $3 AND status = 'collecting_requirements'
          AND expires_at > clock_timestamp()
        FOR UPDATE
        "#,
    )
    .bind(request_token)
    .bind(context.account_id.into_uuid())
    .bind(expected_version)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(request_id) = request_id else {
        return Ok(DiscoveryMutationOutcome::Conflict);
    };
    sqlx::query(
        r#"
        INSERT INTO private_data.service_request_locations (
            request_id, customer_account_id, location, source_inbound_event_id
        )
        VALUES ($1, $2, ST_SetSRID(ST_MakePoint($3, $4), 4326)::geography, $5)
        ON CONFLICT (request_id) DO UPDATE
        SET location = EXCLUDED.location,
            source_inbound_event_id = EXCLUDED.source_inbound_event_id,
            captured_at = statement_timestamp()
        "#,
    )
    .bind(request_id)
    .bind(context.account_id.into_uuid())
    .bind(longitude)
    .bind(latitude)
    .bind(context.inbound_event_id.into_uuid())
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE discovery.service_requests SET updated_at = clock_timestamp() WHERE id = $1",
    )
    .bind(request_id)
    .execute(&mut *connection)
    .await?;
    Ok(DiscoveryMutationOutcome::Applied)
}

async fn search(
    connection: &mut PgConnection,
    context: DiscoveryEffectContext<'_>,
    request_token: Uuid,
    expected_version: i64,
    requested_time: RequestedTimeWindow,
    issue_code: &str,
) -> Result<DiscoveryMutationOutcome, PersistenceError> {
    if issue_code.is_empty()
        || issue_code.len() > 48
        || !issue_code
            .bytes()
            .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == b'_')
    {
        return Err(PersistenceError::InvalidCommand(
            "service request issue code is invalid".to_owned(),
        ));
    }
    let request_id: Option<Uuid> = sqlx::query_scalar(
        r#"
        UPDATE discovery.service_requests AS request
        SET requested_time = $4, issue_code = $5, status = 'searching'
        WHERE request.request_token = $1 AND request.customer_account_id = $2
          AND request.version = $3 AND request.status = 'collecting_requirements'
          AND request.expires_at > clock_timestamp()
          AND EXISTS (SELECT 1 FROM private_data.service_request_locations AS location
                      WHERE location.request_id = request.id)
        RETURNING request.id
        "#,
    )
    .bind(request_token)
    .bind(context.account_id.into_uuid())
    .bind(expected_version)
    .bind(requested_time.as_str())
    .bind(issue_code)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(request_id) = request_id else {
        return Ok(DiscoveryMutationOutcome::Conflict);
    };
    materialize_candidates(connection, request_id).await?;
    show_batch(connection, request_id, 1).await?;
    Ok(DiscoveryMutationOutcome::Applied)
}

async fn show_more(
    connection: &mut PgConnection,
    context: DiscoveryEffectContext<'_>,
    request_token: Uuid,
    expected_version: i64,
    expand: bool,
) -> Result<DiscoveryMutationOutcome, PersistenceError> {
    let request: Option<(Uuid, i16, i16, i16)> = sqlx::query_as(
        r#"
        SELECT id, requested_radius_km, maximum_radius_km, result_round
        FROM discovery.service_requests
        WHERE request_token = $1 AND customer_account_id = $2
          AND version = $3 AND status IN ('showing_results', 'no_results')
          AND expires_at > clock_timestamp()
        FOR UPDATE
        "#,
    )
    .bind(request_token)
    .bind(context.account_id.into_uuid())
    .bind(expected_version)
    .fetch_optional(&mut *connection)
    .await?;
    let Some((request_id, radius, maximum, round)) = request else {
        return Ok(DiscoveryMutationOutcome::Conflict);
    };
    if expand {
        let next_radius = match radius {
            2 => 5,
            5 => 10,
            10 => 25,
            _ => radius,
        };
        if next_radius <= radius || next_radius > maximum {
            return Ok(DiscoveryMutationOutcome::NoMoreResults);
        }
        sqlx::query(
            "UPDATE discovery.service_requests SET requested_radius_km = $2, result_round = result_round + 1 WHERE id = $1",
        )
        .bind(request_id)
        .bind(next_radius)
        .execute(&mut *connection)
        .await?;
        materialize_candidates(connection, request_id).await?;
    }
    let next_round = round + 1;
    let shown = show_batch(connection, request_id, next_round).await?;
    if shown == 0 {
        Ok(DiscoveryMutationOutcome::NoMoreResults)
    } else {
        Ok(DiscoveryMutationOutcome::Applied)
    }
}

async fn cancel_request(
    connection: &mut PgConnection,
    context: DiscoveryEffectContext<'_>,
    request_token: Uuid,
    expected_version: i64,
) -> Result<DiscoveryMutationOutcome, PersistenceError> {
    let updated = sqlx::query(
        r#"
        UPDATE discovery.service_requests
        SET status = 'cancelled', cancelled_at = clock_timestamp(),
            cancellation_reason = 'customer_cancelled'
        WHERE request_token = $1 AND customer_account_id = $2 AND version = $3
          AND status IN ('draft', 'collecting_requirements', 'searching',
                         'showing_results', 'no_results', 'selected')
        "#,
    )
    .bind(request_token)
    .bind(context.account_id.into_uuid())
    .bind(expected_version)
    .execute(&mut *connection)
    .await?;
    Ok(if updated.rows_affected() == 1 {
        DiscoveryMutationOutcome::Applied
    } else {
        DiscoveryMutationOutcome::Conflict
    })
}

async fn materialize_candidates(
    connection: &mut PgConnection,
    request_id: Uuid,
) -> Result<u64, PersistenceError> {
    sync_provider_services(connection).await?;
    let result = sqlx::query(
        r#"
        WITH request_data AS (
            SELECT request.*, location.location
            FROM discovery.service_requests AS request
            JOIN private_data.service_request_locations AS location
              ON location.request_id = request.id
            WHERE request.id = $1
        ), base AS (
            SELECT
                provider_service.id AS provider_service_id,
                epoch.id AS availability_epoch_id,
                epoch.account_id AS professional_account_id,
                root.id AS profile_id,
                root.published_revision_id AS profile_revision_id,
                ROUND(ST_Distance(request.location, area.exact_center))::integer AS distance_metres,
                CASE
                    WHEN EXISTS (
                        SELECT 1 FROM profile.professional_languages AS language
                        WHERE language.revision_id = root.published_revision_id
                          AND language.locale = request.customer_locale
                    ) THEN 2 ELSE 1
                END::smallint AS language_score,
                GREATEST(0, 86400 - EXTRACT(EPOCH FROM
                    (clock_timestamp() - epoch.last_confirmed_at))::integer) AS freshness_score,
                COALESCE((
                    SELECT (count(*) FILTER (WHERE status IN ('accepted','disclosed')) * 1000 /
                            NULLIF(count(*), 0))::integer
                    FROM connection.connection_requests AS response
                    WHERE response.professional_account_id = epoch.account_id
                      AND response.requested_at > clock_timestamp() - INTERVAL '90 days'
                ), 500) AS reliability_score,
                GREATEST(0, 1000 - 100 * (
                    SELECT count(*) FROM connection.contact_reveals AS reveal
                    WHERE reveal.professional_account_id = epoch.account_id
                      AND reveal.revealed_at > clock_timestamp() - INTERVAL '7 days'
                ))::integer AS fair_distribution_score,
                root.public_id AS public_reference
            FROM request_data AS request
            JOIN availability.current_professional_services AS available
              ON available.category_code = request.category_code
            JOIN availability.epochs AS epoch ON epoch.id = available.availability_epoch_id
            JOIN profile.public_profiles AS root ON root.id = available.profile_id
            JOIN profile.provider_services AS provider_service
              ON provider_service.profile_id = root.id
             AND provider_service.category_code = request.category_code
             AND provider_service.state = 'active'
            JOIN profile.profile_revisions AS revision ON revision.id = root.published_revision_id
            JOIN private_data.professional_service_areas AS area
              ON area.revision_id = revision.id
            WHERE epoch.account_id <> request.customer_account_id
              AND NOT safety.account_is_restricted(epoch.account_id)
              AND billing.professional_is_eligible(epoch.account_id)
              AND ST_DWithin(
                    request.location,
                    area.exact_center,
                    LEAST(request.requested_radius_km, revision.service_radius_km) * 1000.0
              )
              AND (
                  request.issue_code = 'other'
                  OR EXISTS (
                      SELECT 1
                      FROM profile.professional_service_skills AS selected_skill
                      WHERE selected_skill.revision_id = revision.id
                        AND selected_skill.category_code = request.category_code
                        AND selected_skill.skill_code = CASE request.issue_code
                            WHEN 'leak_repair' THEN 'leak_repair'
                            WHEN 'drain_blockage' THEN 'drain_clearing'
                            WHEN 'power_outage' THEN 'switch_and_socket'
                            WHEN 'wiring' THEN 'home_wiring'
                            WHEN 'installation' THEN CASE request.category_code
                                WHEN 'plumber' THEN 'tap_and_fixture'
                                ELSE 'fan_installation'
                            END
                        END
                  )
              )
              AND NOT EXISTS (
                  SELECT 1 FROM identity.account_blocks AS block
                  WHERE block.removed_at IS NULL
                    AND ((block.actor_account_id = request.customer_account_id
                          AND block.blocked_account_id = epoch.account_id)
                      OR (block.actor_account_id = epoch.account_id
                          AND block.blocked_account_id = request.customer_account_id))
              )
        ), scored AS (
            SELECT base.*,
                   (200000 - distance_metres)::bigint
                   + language_score * 10000
                   + freshness_score
                   + reliability_score
                   + fair_distribution_score AS final_score
            FROM base
        ), ranked AS (
            SELECT scored.*,
                   ROW_NUMBER() OVER (
                       ORDER BY final_score DESC, distance_metres,
                                public_reference, provider_service_id
                   )::integer AS relative_rank
            FROM scored
        ), rank_base AS (
            SELECT COALESCE(max(final_rank), 0) AS maximum_rank
            FROM discovery.request_candidates WHERE request_id = $1
        )
        INSERT INTO discovery.request_candidates (
            id, candidate_token, request_id, provider_service_id,
            professional_account_id, profile_id, profile_revision_id,
            availability_epoch_id, distance_metres, language_score,
            freshness_score, reliability_score, fair_distribution_score,
            final_score, final_rank, result_round, matching_version
        )
        SELECT uuidv7(), uuidv4(), $1, ranked.provider_service_id,
               ranked.professional_account_id, ranked.profile_id, ranked.profile_revision_id,
               ranked.availability_epoch_id, ranked.distance_metres, ranked.language_score,
               ranked.freshness_score, ranked.reliability_score,
               ranked.fair_distribution_score, ranked.final_score,
               rank_base.maximum_rank + ranked.relative_rank,
               request.result_round, request.matching_version
        FROM ranked CROSS JOIN rank_base
        JOIN discovery.service_requests AS request ON request.id = $1
        ON CONFLICT (request_id, provider_service_id) DO NOTHING
        "#,
    )
    .bind(request_id)
    .execute(&mut *connection)
    .await?;
    Ok(result.rows_affected())
}

async fn show_batch(
    connection: &mut PgConnection,
    request_id: Uuid,
    batch: i16,
) -> Result<u64, PersistenceError> {
    sqlx::query(
        r#"
        UPDATE discovery.request_candidates AS candidate
        SET excluded_at = clock_timestamp(), exclusion_reason = 'eligibility_changed'
        WHERE candidate.request_id = $1 AND candidate.shown_at IS NULL
          AND candidate.excluded_at IS NULL
          AND (
               NOT availability.epoch_is_effective(candidate.availability_epoch_id)
               OR safety.account_is_restricted(candidate.professional_account_id)
               OR NOT billing.professional_is_eligible(candidate.professional_account_id)
               OR EXISTS (
                  SELECT 1
                  FROM discovery.service_requests AS request
                  JOIN identity.account_blocks AS block ON block.removed_at IS NULL
                  WHERE request.id = candidate.request_id
                    AND ((block.actor_account_id = request.customer_account_id
                          AND block.blocked_account_id = candidate.professional_account_id)
                      OR (block.actor_account_id = candidate.professional_account_id
                          AND block.blocked_account_id = request.customer_account_id))
              )
          )
        "#,
    )
    .bind(request_id)
    .execute(&mut *connection)
    .await?;
    let shown = sqlx::query(
        r#"
        WITH next AS (
            SELECT id FROM discovery.request_candidates
            WHERE request_id = $1 AND shown_at IS NULL AND excluded_at IS NULL
            ORDER BY final_rank, id
            LIMIT 3
            FOR UPDATE SKIP LOCKED
        )
        UPDATE discovery.request_candidates AS candidate
        SET shown_at = clock_timestamp(), shown_batch = $2
        FROM next WHERE candidate.id = next.id
        "#,
    )
    .bind(request_id)
    .bind(i32::from(batch))
    .execute(&mut *connection)
    .await?;
    let remaining: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM discovery.request_candidates WHERE request_id = $1 AND shown_at IS NULL AND excluded_at IS NULL)",
    )
    .bind(request_id)
    .fetch_one(&mut *connection)
    .await?;
    sqlx::query(
        r#"
        UPDATE discovery.service_requests
        SET status = CASE WHEN $2 = 0 THEN 'no_results' ELSE 'showing_results' END,
            result_round = $3,
            shown_cursor = shown_cursor + $2
        WHERE id = $1
        "#,
    )
    .bind(request_id)
    .bind(i32::try_from(shown.rows_affected()).unwrap_or(i32::MAX))
    .bind(batch)
    .execute(&mut *connection)
    .await?;
    let _ = remaining;
    Ok(shown.rows_affected())
}

async fn sync_provider_services(connection: &mut PgConnection) -> Result<(), PersistenceError> {
    sqlx::query("SELECT set_config('sahayak.discovery_mutation', 'on', true)")
        .execute(&mut *connection)
        .await?;
    sqlx::query(
        r#"
        INSERT INTO profile.provider_services (id, profile_id, category_code)
        SELECT uuidv7(), root.id, service.category_code
        FROM profile.public_profiles AS root
        JOIN profile.profile_revisions AS revision ON revision.id = root.published_revision_id
        JOIN profile.professional_services AS service ON service.revision_id = revision.id
        WHERE root.visibility = 'published' AND revision.state = 'approved'
        ON CONFLICT (profile_id, category_code) DO UPDATE
        SET state = 'active', retired_at = NULL
        "#,
    )
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn expire_customer_requests(
    connection: &mut PgConnection,
    account_id: AccountId,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        UPDATE discovery.service_requests
        SET status = 'expired'
        WHERE customer_account_id = $1
          AND status IN ('draft', 'collecting_requirements', 'searching',
                         'showing_results', 'no_results', 'selected')
          AND expires_at <= clock_timestamp()
        "#,
    )
    .bind(account_id.into_uuid())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

fn map_card(row: CardRow) -> DiscoveryCard {
    DiscoveryCard {
        candidate_token: row.candidate_token.to_string(),
        display_name: row.display_name,
        public_reference: row.public_reference.to_string(),
        category_code: row.category_code,
        distance_metres: row.distance_metres,
        distance_label: if row.distance_metres < 1_000 {
            "under_1_km".to_owned()
        } else if row.distance_metres < 5_000 {
            "under_5_km".to_owned()
        } else if row.distance_metres < 10_000 {
            "under_10_km".to_owned()
        } else {
            "farther".to_owned()
        },
        language_compatible: row.language_score >= 2,
        availability_label: if row.freshness_score >= 82_800 {
            "recently_confirmed".to_owned()
        } else {
            "available_now".to_owned()
        },
        identity_checked: row.identity_checked,
        contact_mode: row.contact_mode,
    }
}
