use sahayak_configuration::{RuntimeEnvironment, WhatsAppSettings, load_secret_file};
use sahayak_conversation_engine::{
    AccountCommand, ActionId, AdminCommand, AdminQueueItem, AdminReviewDecision, AdminState,
    AdminView, AllowedAdminView, AvailabilityCommand,
    AvailabilityDuration as EngineAvailabilityDuration, AvailabilityEpochView,
    AvailabilityIneligibility as EngineAvailabilityIneligibility, AvailabilityLocalExpiry,
    AvailabilityObservationState, AvailabilityOutcome, AvailabilityState, AvailabilityView,
    BillingView, BusinessCommand, CategorySelection, ConnectionCommand, ConnectionsView,
    ContactMode as EngineContactMode, ContactSessionLimit, ConversationContext,
    ConversationDisposition, ConversationEngine, ConversationState, DiscoveryCardView,
    DiscoveryCommand, DiscoveryStatus, DiscoveryView, IdentityCheckStatus,
    LocalServiceMode as EngineLocalServiceMode, OpaqueTargetToken, PendingConnectionView,
    PendingCustomerConnectionView, ProfessionalCommand, ProfessionalResumeStep, ProfessionalStatus,
    ProfessionalSummary, ProfessionalView, ProfileFieldCode, ProfilePhotoStatus, RecentContactView,
    ReplyControls, RequestedTimeChoice, ReviewReasonCode, SafetyAdminReportView, SafetyAdminView,
    SafetyModerationCommand, ServiceCategory, ServiceContactPreference, ServiceRadius,
    ServiceSkill, SessionChange, SessionSnapshot, SessionTerminalStatus, TrustCommand,
    TrustIntroductionView, TrustView, TurnPlan, UserInput,
};
use sahayak_cryptography::{
    CryptoService, EncryptionContext, EncryptionNamespace, EncryptionPurpose, NormalizedPhoneNumber,
};
use sahayak_domain::{
    AccountId, AccountRole, AvailabilityDuration, AvailabilityEpochId, AvailabilityEpochState,
    CallbackToken, ChannelIdentityId, ConnectionRequestId, ContactMode, ContactRevealId,
    ConversationSessionId, CorrelationId, DeliveryEventId, LocalServiceMode, OutboundMessageId,
    OutboxJobId, ProfessionalConsentEventId, ProfessionalConsentPurpose, ProfessionalDisplayName,
    ProfessionalLanguage, ProfilePhotoId, ProfileReviewDecision, ProfileReviewDecisionId,
    ProfileReviewReason, ProfileRevisionId, PublicProfileId, PublicProfileReference,
    ServiceRadiusKm, WorkerId,
};
use sahayak_localization::{Locale, Localizer, MessageKey};
use sahayak_persistence::{
    ADVANCE_AVAILABILITY_JOB, AdministratorConversationSnapshot, AdministratorConversationTarget,
    AdministratorReviewTurnEffect, AvailabilityConversationSnapshot, AvailabilityIneligibility,
    AvailabilityNotificationTarget, AvailabilityRepository, AvailabilityTimerPurpose,
    AvailabilityTurnEffect, AvailabilityTurnOperation, BeginSubmission, ClaimRequest, ClaimedJob,
    CommitConversationTurn, CommitConversationTurnWithEffects, ConnectionOutboundIds,
    ConnectionRepository, ConnectionTurnEffect, ConnectionTurnOperation, ContactPhoto,
    ContactTarget, ConversationSessionChange, ConversationTurnEffect, ConversationTurnEffects,
    ConversationTurnRecord, ConversationTurnRepository, Database, DeliveryRepository,
    DeliveryStatusInput, DiscoveryCategory, DiscoveryConversationSnapshot, DiscoveryRepository,
    DiscoveryTurnEffect, DiscoveryTurnOperation, EXPIRE_CONNECTION_JOB, EffectfulTurnCommitOutcome,
    EncryptedOutboundPayload, FailureDisposition, IdentityRepository, LookupDigest,
    NewWhatsAppAccount, OutboundMutation, OutboundQueueOutcome, OutboundRepository,
    OutboxRepository, PendingConnectionSummary, PendingCustomerConnection, PendingResponseContext,
    ProfessionalConsentAcceptance, ProfessionalConsentRepository, ProfessionalConversationSnapshot,
    ProfessionalConversationStatus, ProfessionalProfileRepository, ProfessionalRequirement,
    ProfessionalServiceSnapshot, ProfessionalTurnEffect, ProfessionalTurnOperation,
    ProfilePhotoRepository, ProfileReviewTarget, QueueOutboundMessage, REMIND_AVAILABILITY_JOB,
    RecentContactSummary, RepeatRevealContext, ResolveIdentityOutcome, SelectionContext,
    TurnDisposition,
};
use sahayak_whatsapp::{
    Button, ButtonMessage, FailureClass, ListMessage, ListRow, ListSection, MediaKind,
    MediaMessage, MediaReference, NormalizedContent, NormalizedEvent, NormalizedPayload,
    OutboundMessage, PreparedMessage, TemplateMessage, TextMessage, WhatsAppClient,
    WhatsAppClientConfig, WhatsAppError,
};
use secrecy::ExposeSecret;
use std::{path::PathBuf, time::Duration};
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

const SEND_JOB: &str = "send_whatsapp_message";
const STATUS_JOB: &str = "process_whatsapp_status";
const PROBE_JOB: &str = "process_whatsapp_probe";
const CONVERSATION_JOB: &str = "process_conversation_message";
const PROVIDER_ERROR_JOB: &str = "process_provider_error";
const MAX_PROFILE_PHOTO_BYTES: usize = 5 * 1_024 * 1_024;
const ADMIN_QUEUE_LIMIT: u16 = 100;

/// Worker-side Meta sender and status processor.
pub struct WhatsAppJobProcessor {
    worker_id: WorkerId,
    cryptography: CryptoService,
    client: RwLock<WhatsAppClient>,
    client_base_url: String,
    graph_api_version: String,
    phone_number_id: String,
    access_token_file: PathBuf,
    strict_secret_permissions: bool,
    request_timeout: Duration,
    reentry_template_name: String,
    payment_reminder_template_name: String,
    database: Database,
    outbox: OutboxRepository,
    outbound: OutboundRepository,
    delivery: DeliveryRepository,
    identity: IdentityRepository,
    conversations: ConversationTurnRepository,
    engine: ConversationEngine,
    provider_namespace: String,
    batch_size: u16,
    lease_duration: Duration,
}

impl WhatsAppJobProcessor {
    /// Loads the worker-only access token and transport keyring.
    pub async fn load(
        settings: &WhatsAppSettings,
        worker_settings: &sahayak_configuration::WorkerSettings,
        environment: RuntimeEnvironment,
        database: Database,
    ) -> Result<Self, String> {
        let strict = environment.is_production();
        let access_token = load_secret_file(&settings.access_token_file, 16_384, strict)
            .map_err(|error| error.to_string())?;
        let keyring = load_secret_file(&settings.crypto_keyring_file, 65_536, strict)
            .map_err(|error| error.to_string())?;
        let cryptography = CryptoService::from_keyring_text(keyring.expose_secret())
            .map_err(|error| error.to_string())?;
        let integration_version = cryptography
            .active_encryption_version(EncryptionPurpose::Integration)
            .ok_or_else(|| "integration encryption key is missing".to_owned())?;
        let contact_version = cryptography
            .active_encryption_version(EncryptionPurpose::Contact)
            .ok_or_else(|| "contact encryption key is missing".to_owned())?;
        let media_version = cryptography
            .active_encryption_version(EncryptionPurpose::Media)
            .ok_or_else(|| "media encryption key is missing".to_owned())?;
        sahayak_persistence::KeyRegistryRepository::new(database.clone())
            .verify_required_versions(
                &[
                    (EncryptionPurpose::Contact, contact_version),
                    (EncryptionPurpose::Integration, integration_version),
                    (EncryptionPurpose::Media, media_version),
                ],
                Some(cryptography.active_lookup_version()),
            )
            .await
            .map_err(|error| error.to_string())?;
        let client = WhatsAppClient::new(&WhatsAppClientConfig {
            base_url: settings.graph_api_base_url.clone(),
            graph_api_version: settings.graph_api_version.clone(),
            phone_number_id: settings.phone_number_id.clone(),
            access_token,
            timeout: settings.request_timeout(),
        })
        .map_err(|error| error.to_string())?;
        let engine = ConversationEngine::load().map_err(|error| error.to_string())?;
        Ok(Self {
            worker_id: WorkerId::new(),
            cryptography,
            client: RwLock::new(client),
            client_base_url: settings.graph_api_base_url.clone(),
            graph_api_version: settings.graph_api_version.clone(),
            phone_number_id: settings.phone_number_id.clone(),
            access_token_file: settings.access_token_file.clone(),
            strict_secret_permissions: strict,
            request_timeout: settings.request_timeout(),
            reentry_template_name: settings.reentry_template_name.clone(),
            payment_reminder_template_name: settings.payment_reminder_template_name.clone(),
            outbox: OutboxRepository::new(database.clone()),
            outbound: OutboundRepository::new(database.clone()),
            delivery: DeliveryRepository::new(database.clone()),
            identity: IdentityRepository::new(database.clone()),
            conversations: ConversationTurnRepository::new(database.clone()),
            engine,
            database,
            provider_namespace: format!("{}:{}", settings.waba_id, settings.phone_number_id),
            batch_size: worker_settings.job_claim_batch_size,
            lease_duration: worker_settings.job_lease(),
        })
    }

    /// Claims and handles one bounded job batch.
    pub async fn process_batch(&self) -> Result<usize, sahayak_persistence::PersistenceError> {
        let request = ClaimRequest::new(self.worker_id, self.batch_size, self.lease_duration)?
            .with_job_kinds(&[
                SEND_JOB,
                STATUS_JOB,
                PROBE_JOB,
                CONVERSATION_JOB,
                PROVIDER_ERROR_JOB,
                REMIND_AVAILABILITY_JOB,
                ADVANCE_AVAILABILITY_JOB,
                EXPIRE_CONNECTION_JOB,
            ])?;
        let jobs = self.outbox.claim(request).await?;
        let count = jobs.len();
        let mut first_error = None;
        for job in jobs {
            if let Err(error) = self.process_job(&job).await {
                error!(job_id = %job.id, job_kind = %job.job_kind, %error, "WhatsApp job failed");
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        let _ = self.process_payment_reminders().await?;
        Ok(count)
    }

    async fn process_payment_reminders(
        &self,
    ) -> Result<usize, sahayak_persistence::PersistenceError> {
        let repository = sahayak_persistence::BillingRepository::new(self.database.clone());
        let reminders = repository.claim_payment_reminders(10).await?;
        let count = reminders.len();
        for reminder in reminders {
            let result = self
                .prepare_payment_reminder(&reminder)
                .map(|outbound| (outbound, reminder.clone()));
            match result {
                Ok((outbound, reminder)) => {
                    if !repository
                        .complete_payment_reminder(&reminder, &outbound)
                        .await?
                    {
                        repository.release_payment_reminder(&reminder).await?;
                    }
                }
                Err(error) => {
                    repository.release_payment_reminder(&reminder).await?;
                    return Err(error);
                }
            }
        }
        Ok(count)
    }

    fn prepare_payment_reminder(
        &self,
        reminder: &sahayak_persistence::PaymentReminder,
    ) -> Result<QueueOutboundMessage, sahayak_persistence::PersistenceError> {
        let recipient = self.decrypt_contact_phone(&reminder.target)?;
        let ordering_key = self
            .cryptography
            .blind_index(
                "integration:whatsapp:conversation-order:v1",
                recipient.expose().trim_start_matches('+').as_bytes(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "payment reminder ordering key failed".to_owned(),
                )
            })?
            .1;
        let locale = Locale::parse(&reminder.target.locale).unwrap_or(Locale::EnIn);
        self.prepare_queue_outbound(
            OutboundMessage::template(
                &recipient,
                TemplateMessage::new(
                    &self.payment_reminder_template_name,
                    locale.meta_template_code(),
                    Vec::new(),
                )
                .map_err(|_| {
                    sahayak_persistence::PersistenceError::InvalidCommand(
                        "payment reminder template configuration is invalid".to_owned(),
                    )
                })?,
            ),
            reminder.target.provider_namespace.clone(),
            Some(reminder.target.channel_identity_id),
            format!("payment-reminder:v1:{}", reminder.id),
            CorrelationId::new(),
            Some(ordering_key),
        )
    }

    async fn process_job(
        &self,
        job: &ClaimedJob,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        match job.job_kind.as_str() {
            SEND_JOB => self.process_send(job).await,
            STATUS_JOB => self.process_status(job).await,
            PROBE_JOB => self.process_probe(job).await,
            CONVERSATION_JOB => self.process_conversation_with_failure_policy(job).await,
            REMIND_AVAILABILITY_JOB => {
                self.process_availability_timer(job, AvailabilityTimerPurpose::Reminder)
                    .await
            }
            ADVANCE_AVAILABILITY_JOB => {
                self.process_availability_timer(job, AvailabilityTimerPurpose::Advance)
                    .await
            }
            EXPIRE_CONNECTION_JOB => self.process_connection_expiry(job).await,
            PROVIDER_ERROR_JOB => {
                let _ = self.outbox.complete(job.lease()).await?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn process_availability_timer(
        &self,
        job: &ClaimedJob,
        purpose: AvailabilityTimerPurpose,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        let epoch_id = job.availability_epoch_id.ok_or_else(|| {
            sahayak_persistence::PersistenceError::InvalidCommand(
                "availability timer is missing its epoch".to_owned(),
            )
        })?;
        let generation = job.availability_generation.ok_or_else(|| {
            sahayak_persistence::PersistenceError::InvalidCommand(
                "availability timer is missing its generation".to_owned(),
            )
        })?;
        let repository = AvailabilityRepository::new(self.database.clone());
        let context = repository
            .timer_context(epoch_id, generation, purpose)
            .await?;
        let notification = if let Some(context) = context {
            let should_notify = context.purpose == AvailabilityTimerPurpose::Reminder
                || context.state == AvailabilityEpochState::Available;
            if !should_notify {
                None
            } else {
                match repository.notification_target(epoch_id).await? {
                    Some(target) => {
                        match self.prepare_availability_notification(context, target, job) {
                            Ok(notification) => Some(notification),
                            Err(error) => {
                                warn!(%error, %epoch_id, generation, "availability notification preparation failed");
                                None
                            }
                        }
                    }
                    None => None,
                }
            }
        } else {
            None
        };
        let _ = repository
            .process_timer(
                job.lease(),
                epoch_id,
                generation,
                purpose,
                job.correlation_id,
                notification.as_ref(),
            )
            .await?;
        Ok(())
    }

    async fn process_connection_expiry(
        &self,
        job: &ClaimedJob,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        let connection_id = job.connection_request_id.ok_or_else(|| {
            sahayak_persistence::PersistenceError::InvalidCommand(
                "connection expiry job is missing its request".to_owned(),
            )
        })?;
        let generation = job.connection_generation.ok_or_else(|| {
            sahayak_persistence::PersistenceError::InvalidCommand(
                "connection expiry job is missing its generation".to_owned(),
            )
        })?;
        let _ = ConnectionRepository::new(self.database.clone())
            .process_expiry(job.lease(), connection_id, generation, job.correlation_id)
            .await?;
        Ok(())
    }

    fn prepare_availability_notification(
        &self,
        context: sahayak_persistence::AvailabilityTimerContext,
        target: AvailabilityNotificationTarget,
        job: &ClaimedJob,
    ) -> Result<QueueOutboundMessage, sahayak_persistence::PersistenceError> {
        if target.provider_namespace != self.provider_namespace {
            return Err(sahayak_persistence::PersistenceError::InvalidCommand(
                "availability notification namespace does not match worker".to_owned(),
            ));
        }
        let decrypted_phone = Zeroizing::new(
            self.cryptography
                .decrypt(
                    EncryptionContext::new(
                        EncryptionNamespace::WHATSAPP_PHONE_E164,
                        target.channel_identity_id.into_uuid(),
                    ),
                    &target.encrypted_phone,
                )
                .map_err(|_| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "availability notification phone authentication failed".to_owned(),
                    )
                })?,
        );
        let phone_text = std::str::from_utf8(&decrypted_phone).map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "availability notification phone encoding is invalid".to_owned(),
            )
        })?;
        let recipient = NormalizedPhoneNumber::parse(phone_text).map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "availability notification phone is invalid".to_owned(),
            )
        })?;
        let locale = Locale::parse(&target.locale).unwrap_or(Locale::EnIn);
        let localizer = Localizer::load().map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "availability notification localization failed".to_owned(),
            )
        })?;
        let body = match context.purpose {
            AvailabilityTimerPurpose::Reminder => format!(
                "{}\n{:02}-{:02}-{:04} {:02}:{:02}",
                localizer.text(locale, MessageKey::AVAILABILITY_REMINDER_BODY),
                context.expires_local.day,
                context.expires_local.month,
                context.expires_local.year,
                context.expires_local.hour,
                context.expires_local.minute,
            ),
            AvailabilityTimerPurpose::Advance => localizer
                .text(locale, MessageKey::AVAILABILITY_EXPIRED_BODY)
                .to_owned(),
        };
        let ordering_key = self
            .cryptography
            .blind_index(
                "integration:whatsapp:conversation-order:v1",
                recipient.expose().trim_start_matches('+').as_bytes(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "availability notification ordering key failed".to_owned(),
                )
            })?
            .1;
        self.prepare_queue_outbound(
            OutboundMessage::text(
                &recipient,
                TextMessage::new(&body, false).map_err(|_| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "availability notification text is invalid".to_owned(),
                    )
                })?,
            ),
            target.provider_namespace,
            Some(target.channel_identity_id),
            format!(
                "availability-{}:v1:{}:g{}",
                match context.purpose {
                    AvailabilityTimerPurpose::Reminder => "reminder",
                    AvailabilityTimerPurpose::Advance => "expired",
                },
                context.epoch_id,
                context.generation
            ),
            job.correlation_id,
            Some(ordering_key),
        )
    }

    async fn process_send(
        &self,
        job: &ClaimedJob,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        let Some(outbound_id) = job.outbound_message_id else {
            let _ = self
                .outbox
                .record_failure(
                    job.lease(),
                    &FailureDisposition::Terminal {
                        error_class: "local_invariant".to_owned(),
                        error_code: "missing_outbound_message".to_owned(),
                    },
                )
                .await?;
            return Ok(());
        };
        let prepared = if let Some(message) =
            self.outbound.find_queued_for_send(outbound_id).await?
        {
            let decrypted = match self.cryptography.decrypt(
                EncryptionContext::new(
                    EncryptionNamespace::OUTBOUND_MESSAGE_PAYLOAD,
                    message.id.into_uuid(),
                ),
                &message.payload,
            ) {
                Ok(value) => value,
                Err(_) => {
                    let _ = self
                        .outbound
                        .reject_queued_local(
                            job.lease(),
                            outbound_id,
                            "outbound_authentication_failed",
                        )
                        .await?;
                    return Ok(());
                }
            };
            let prepared = match PreparedMessage::from_persisted(decrypted.to_vec()) {
                Ok(message) => message,
                Err(_) => {
                    let _ = self
                        .outbound
                        .reject_queued_local(job.lease(), outbound_id, "invalid_prepared_message")
                        .await?;
                    return Ok(());
                }
            };
            let expected_callback = message.callback_token.to_string();
            if prepared.callback_data().as_deref() != Some(expected_callback.as_str()) {
                let _ = self
                    .outbound
                    .reject_queued_local(job.lease(), outbound_id, "callback_token_mismatch")
                    .await?;
                return Ok(());
            }
            let delivery_context = self.outbound.delivery_context(outbound_id).await?;
            if delivery_context
                .as_ref()
                .is_none_or(|context| !context.eligible)
            {
                let _ = self
                    .outbound
                    .reject_queued_local(job.lease(), outbound_id, "recipient_ineligible")
                    .await?;
                return Ok(());
            }
            if prepared.message_type().map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "prepared message type is invalid".to_owned(),
                )
            })? != "template"
                && delivery_context.as_ref().is_some_and(|context| {
                    context.channel_identity_id.is_some() && !context.service_window_open
                })
            {
                if let Some(context) = delivery_context {
                    self.replace_with_reentry_template(
                        job,
                        outbound_id,
                        &prepared,
                        context,
                        "local_policy",
                        "service_window_closed",
                    )
                    .await?;
                }
                return Ok(());
            }
            Some(prepared)
        } else {
            None
        };
        match self
            .outbound
            .begin_submission(job.lease(), outbound_id)
            .await?
        {
            BeginSubmission::Ready(_) => {
                let Some(prepared) = prepared else {
                    let _ = self
                        .outbound
                        .mark_rejected(
                            job.lease(),
                            outbound_id,
                            "local_invariant",
                            "queued_payload_disappeared",
                        )
                        .await?;
                    return Ok(());
                };
                let send_result = self.client.read().await.send_prepared(&prepared).await;
                match send_result {
                    Ok(receipt) => {
                        let outcome = self
                            .outbound
                            .mark_accepted(
                                job.lease(),
                                outbound_id,
                                &receipt.provider_message_id,
                                receipt.message_status.as_deref(),
                            )
                            .await?;
                        if outcome == OutboundMutation::LostLease {
                            warn!(job_id = %job.id, "lost send lease after Meta acceptance");
                        }
                    }
                    Err(error) => {
                        self.handle_send_error(job, outbound_id, &prepared, &error)
                            .await?;
                    }
                }
            }
            BeginSubmission::AlreadyAccepted => {
                let _ = self.outbox.complete(job.lease()).await?;
            }
            BeginSubmission::AbandonedSending => {
                let _ = self
                    .outbound
                    .mark_recovered_unknown(job.lease(), outbound_id)
                    .await?;
            }
            BeginSubmission::Unknown => {
                let _ = self
                    .outbox
                    .record_failure(
                        job.lease(),
                        &FailureDisposition::Terminal {
                            error_class: "ambiguous_transport".to_owned(),
                            error_code: "already_unknown".to_owned(),
                        },
                    )
                    .await?;
            }
            BeginSubmission::Rejected => {
                let _ = self
                    .outbox
                    .record_failure(
                        job.lease(),
                        &FailureDisposition::Terminal {
                            error_class: "provider_rejection".to_owned(),
                            error_code: "already_rejected".to_owned(),
                        },
                    )
                    .await?;
            }
            BeginSubmission::Ineligible => {
                let _ = self
                    .outbound
                    .reject_queued_local(job.lease(), outbound_id, "recipient_ineligible")
                    .await?;
            }
            BeginSubmission::LostLease => {}
        }
        Ok(())
    }

    async fn handle_send_error(
        &self,
        job: &ClaimedJob,
        outbound_id: sahayak_domain::OutboundMessageId,
        prepared: &PreparedMessage,
        error: &WhatsAppError,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        match error {
            WhatsAppError::Connection => {
                let _ = self
                    .outbound
                    .mark_retryable(
                        job.lease(),
                        outbound_id,
                        "transport",
                        "connect_failed",
                        retry_delay(job.attempt_count),
                    )
                    .await?;
            }
            WhatsAppError::Api(failure) if failure.class == FailureClass::Retryable => {
                let _ = self
                    .outbound
                    .mark_retryable(
                        job.lease(),
                        outbound_id,
                        "provider",
                        &format!("meta_{}", failure.code.unwrap_or(0)),
                        failure
                            .retry_after_seconds
                            .map(Duration::from_secs)
                            .unwrap_or_else(|| retry_delay(job.attempt_count)),
                    )
                    .await?;
            }
            WhatsAppError::Api(failure) if failure.class == FailureClass::ServiceWindowClosed => {
                let is_template = prepared.message_type().map_err(|_| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "prepared message type is invalid".to_owned(),
                    )
                })? == "template";
                let context = self.outbound.delivery_context(outbound_id).await?;
                if is_template
                    || context.as_ref().is_none_or(|context| {
                        !context.eligible || context.channel_identity_id.is_none()
                    })
                {
                    let _ = self
                        .outbound
                        .mark_rejected(
                            job.lease(),
                            outbound_id,
                            "provider",
                            &format!("meta_{}", failure.code.unwrap_or(0)),
                        )
                        .await?;
                } else if let Some(context) = context {
                    self.replace_with_reentry_template(
                        job,
                        outbound_id,
                        prepared,
                        context,
                        "provider",
                        &format!("meta_{}", failure.code.unwrap_or(0)),
                    )
                    .await?;
                }
            }
            WhatsAppError::Api(failure) if failure.class == FailureClass::Authorization => {
                if let Err(error) = self.reload_access_token().await {
                    error!(%error, "failed to reload WhatsApp access token");
                }
                let _ = self
                    .outbound
                    .mark_retryable(
                        job.lease(),
                        outbound_id,
                        "authorization",
                        &format!("meta_{}", failure.code.unwrap_or(0)),
                        Duration::from_secs(300),
                    )
                    .await?;
            }
            WhatsAppError::AmbiguousTransport | WhatsAppError::InvalidSuccessResponse => {
                let _ = self
                    .outbound
                    .mark_unknown(job.lease(), outbound_id, "ambiguous_meta_send")
                    .await?;
            }
            WhatsAppError::Api(failure) if failure.class == FailureClass::Ambiguous => {
                let _ = self
                    .outbound
                    .mark_unknown(job.lease(), outbound_id, "ambiguous_meta_response")
                    .await?;
            }
            WhatsAppError::Api(failure) => {
                let _ = self
                    .outbound
                    .mark_rejected(
                        job.lease(),
                        outbound_id,
                        "provider",
                        &format!("meta_{}", failure.code.unwrap_or(0)),
                    )
                    .await?;
            }
            WhatsAppError::InvalidConfiguration(_) => {
                let _ = self
                    .outbound
                    .mark_rejected(
                        job.lease(),
                        outbound_id,
                        "local_invariant",
                        "invalid_client_configuration",
                    )
                    .await?;
            }
            WhatsAppError::MediaTransport => {
                let _ = self
                    .outbound
                    .mark_retryable(
                        job.lease(),
                        outbound_id,
                        "media_transport",
                        "unexpected_media_transport_error",
                        retry_delay(job.attempt_count),
                    )
                    .await?;
            }
            WhatsAppError::InvalidMediaResponse
            | WhatsAppError::MediaTooLarge
            | WhatsAppError::UnsafeMediaUrl => {
                let _ = self
                    .outbound
                    .mark_rejected(
                        job.lease(),
                        outbound_id,
                        "local_invariant",
                        "unexpected_media_error",
                    )
                    .await?;
            }
            _ => {
                let _ = self
                    .outbound
                    .mark_rejected(
                        job.lease(),
                        outbound_id,
                        "local_invariant",
                        "unknown_whatsapp_error",
                    )
                    .await?;
            }
        }
        Ok(())
    }

    async fn reload_access_token(&self) -> Result<(), String> {
        let access_token = load_secret_file(
            &self.access_token_file,
            16_384,
            self.strict_secret_permissions,
        )
        .map_err(|error| error.to_string())?;
        let client = WhatsAppClient::new(&WhatsAppClientConfig {
            base_url: self.client_base_url.clone(),
            graph_api_version: self.graph_api_version.clone(),
            phone_number_id: self.phone_number_id.clone(),
            access_token,
            timeout: self.request_timeout,
        })
        .map_err(|error| error.to_string())?;
        *self.client.write().await = client;
        Ok(())
    }

    async fn replace_with_reentry_template(
        &self,
        job: &ClaimedJob,
        replaced_outbound_id: OutboundMessageId,
        previous: &PreparedMessage,
        context: sahayak_persistence::OutboundDeliveryContext,
        error_class: &str,
        error_code: &str,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        let recipient = previous.recipient().map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "re-entry recipient is invalid".to_owned(),
            )
        })?;
        let locale = context
            .locale
            .as_deref()
            .and_then(Locale::parse)
            .unwrap_or(Locale::EnIn);
        let outbound_id = OutboundMessageId::new();
        let callback = CallbackToken::new();
        let base_message = OutboundMessage::template(
            &recipient,
            TemplateMessage::new(
                &self.reentry_template_name,
                locale.meta_template_code(),
                Vec::new(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "re-entry template configuration is invalid".to_owned(),
                )
            })?,
        );
        let fingerprint_payload = base_message.prepare().map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "re-entry template fingerprint serialization failed".to_owned(),
            )
        })?;
        let prepared = base_message
            .with_callback_data(&callback.to_string())
            .and_then(|message| message.prepare())
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "re-entry template serialization failed".to_owned(),
                )
            })?;
        let encrypted = self
            .cryptography
            .encrypt(
                EncryptionPurpose::Integration,
                EncryptionContext::new(
                    EncryptionNamespace::OUTBOUND_MESSAGE_PAYLOAD,
                    outbound_id.into_uuid(),
                ),
                prepared.expose(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "re-entry template encryption failed".to_owned(),
                )
            })?;
        let active_lookup_version = self.cryptography.active_lookup_version();
        let fingerprints = self
            .cryptography
            .all_blind_indexes(
                "messaging:whatsapp:outbound_request:v1",
                fingerprint_payload.expose(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "re-entry template fingerprint failed".to_owned(),
                )
            })?;
        let active = fingerprints
            .iter()
            .find(|(version, _)| *version == active_lookup_version)
            .copied()
            .ok_or_else(|| {
                sahayak_persistence::PersistenceError::Invariant(
                    "re-entry active fingerprint is missing".to_owned(),
                )
            })?;
        let additional_fingerprints = fingerprints
            .into_iter()
            .filter(|(version, _)| *version != active_lookup_version)
            .map(|(key_version, digest)| LookupDigest {
                key_version,
                digest,
            })
            .collect();
        let _ = self
            .outbound
            .replace_with_reentry_template(
                job.lease(),
                replaced_outbound_id,
                error_class,
                error_code,
                &QueueOutboundMessage {
                    id: outbound_id,
                    provider_namespace: self.provider_namespace.clone(),
                    recipient_channel_identity_id: context.channel_identity_id,
                    idempotency_key: format!("reentry-template:v1:{replaced_outbound_id}"),
                    payload: EncryptedOutboundPayload {
                        schema_version: 1,
                        encrypted,
                        fingerprint_key_version: active.0,
                        request_fingerprint: active.1,
                        additional_fingerprints,
                    },
                    callback_token: callback,
                    correlation_id: context.correlation_id,
                    ordering_key: context.ordering_key,
                    send_job_id: OutboxJobId::new(),
                    max_attempts: 8,
                },
            )
            .await?;
        Ok(())
    }

    async fn process_status(
        &self,
        job: &ClaimedJob,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        let Some(event_id) = job.inbound_event_id else {
            let _ = self
                .outbox
                .record_failure(
                    job.lease(),
                    &FailureDisposition::Terminal {
                        error_class: "local_invariant".to_owned(),
                        error_code: "missing_inbound_event".to_owned(),
                    },
                )
                .await?;
            return Ok(());
        };
        let Some(encrypted) = self.database.find_encrypted_inbound_event(event_id).await? else {
            let _ = self
                .outbox
                .record_failure(
                    job.lease(),
                    &FailureDisposition::Terminal {
                        error_class: "local_invariant".to_owned(),
                        error_code: "inbound_event_not_found".to_owned(),
                    },
                )
                .await?;
            return Ok(());
        };
        let decrypted = self
            .cryptography
            .decrypt(
                EncryptionContext::new(
                    EncryptionNamespace::INBOUND_EVENT_PAYLOAD,
                    event_id.into_uuid(),
                ),
                &encrypted.payload,
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "inbound status authentication failed".to_owned(),
                )
            })?;
        let event: NormalizedEvent = serde_json::from_slice(&decrypted).map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "inbound status payload schema is invalid".to_owned(),
            )
        })?;
        let NormalizedPayload::Status {
            provider_message_id,
            status,
            callback_data,
            error_codes,
            ..
        } = event.payload
        else {
            let _ = self
                .outbox
                .record_failure(
                    job.lease(),
                    &FailureDisposition::Terminal {
                        error_class: "local_invariant".to_owned(),
                        error_code: "unexpected_status_payload".to_owned(),
                    },
                )
                .await?;
            return Ok(());
        };
        let contact_failed = status == "failed";
        let error_code = error_codes.first().copied();
        let contact_failure_code = contact_failed.then(|| {
            error_code.map_or_else(
                || "provider_delivery_failed".to_owned(),
                |code| format!("meta_{code}"),
            )
        });
        let outcome = self
            .delivery
            .record(
                job.lease(),
                &DeliveryStatusInput {
                    id: DeliveryEventId::new(),
                    inbound_event_id: event_id,
                    provider_namespace: self.provider_namespace.clone(),
                    provider_message_id,
                    status: status.clone(),
                    callback_data,
                    provider_error_code: error_code,
                    error_class: contact_failure_code,
                    provider_occurred_at: encrypted
                        .provider_occurred_at
                        .unwrap_or_else(OffsetDateTime::now_utc),
                    correlation_id: encrypted.correlation_id,
                },
            )
            .await?;
        info!(?outcome, "recorded WhatsApp delivery status");
        Ok(())
    }

    async fn process_conversation(
        &self,
        job: &ClaimedJob,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        let Some(event_id) = job.inbound_event_id else {
            return self
                .reject_conversation(job, "missing_conversation_event")
                .await;
        };
        let Some(encrypted_event) = self.database.find_encrypted_inbound_event(event_id).await?
        else {
            return self
                .reject_conversation(job, "conversation_event_not_found")
                .await;
        };
        let decrypted = self
            .cryptography
            .decrypt(
                EncryptionContext::new(
                    EncryptionNamespace::INBOUND_EVENT_PAYLOAD,
                    event_id.into_uuid(),
                ),
                &encrypted_event.payload,
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "conversation event authentication failed".to_owned(),
                )
            })?;
        let event: NormalizedEvent = serde_json::from_slice(&decrypted).map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "conversation event payload schema is invalid".to_owned(),
            )
        })?;
        let NormalizedPayload::Message {
            provider_message_id,
            sender_wa_id,
            sender_phone_e164,
            context_message_id,
            content,
            ..
        } = event.payload
        else {
            return self
                .reject_conversation(job, "unexpected_conversation_payload")
                .await;
        };
        let identity = self
            .resolve_identity(
                event_id,
                &sender_wa_id,
                &sender_phone_e164,
                encrypted_event.correlation_id,
                encrypted_event
                    .provider_occurred_at
                    .unwrap_or_else(OffsetDateTime::now_utc),
            )
            .await?;
        let turn = self
            .conversations
            .load(
                identity.0,
                identity.1,
                &self.provider_namespace,
                context_message_id.as_deref(),
            )
            .await?;
        let confirmed_locale = turn
            .account
            .preferred_locale_confirmed_at
            .and_then(|_| Locale::parse(&turn.account.preferred_locale));
        let mut unsupported_session = None;
        let session = turn.active_session.as_ref().and_then(|session| {
            let state = ConversationState::from_persisted(
                &session.workflow_key,
                session.workflow_version,
                &session.state_key,
                &session.state_data,
            );
            let locale = Locale::parse(&session.language);
            match (state, locale) {
                (Some(state), Some(locale)) => Some(SessionSnapshot {
                    id: session.id,
                    state,
                    locale,
                    version: session.version,
                    expected_reply_to: session.expected_reply_to_outbound_message_id,
                    workflow_correlation_id: session.workflow_correlation_id,
                }),
                _ => {
                    unsupported_session = Some((session.id, session.version));
                    None
                }
            }
        });
        let selected_review_token = session.as_ref().and_then(selected_admin_token);
        let profiles = ProfessionalProfileRepository::new(self.database.clone());
        let professional_snapshot = profiles
            .load_conversation_snapshot(identity.0, identity.1)
            .await?;
        let administrator_snapshot = profiles
            .load_administrator_conversation_snapshot(
                identity.0,
                identity.1,
                &self.provider_namespace,
                selected_review_token,
                ADMIN_QUEUE_LIMIT,
            )
            .await?;
        let professional = map_professional_view(professional_snapshot.as_ref())?;
        let administrator = map_administrator_view(administrator_snapshot.as_ref())?;
        let safety_administrator_snapshot = sahayak_persistence::SafetyRepository::new(
            self.database.clone(),
            self.cryptography.clone(),
        )
        .administrator_queue(identity.0, identity.1)
        .await?;
        let safety_administrator = match safety_administrator_snapshot.as_ref() {
            Some(reports) => SafetyAdminView::Allowed {
                reports: reports
                    .iter()
                    .map(|report| SafetyAdminReportView {
                        report_token: report.report_token.to_string(),
                        version: report.version,
                        category: report.category.clone(),
                        severity: report.severity.clone(),
                    })
                    .collect(),
            },
            None => SafetyAdminView::Denied,
        };
        let availability_snapshot = AvailabilityRepository::new(self.database.clone())
            .load_conversation_snapshot(identity.0, identity.1, &self.provider_namespace)
            .await?;
        let availability = map_availability_view(&availability_snapshot)?;
        let discovery_snapshot = DiscoveryRepository::new(self.database.clone())
            .load_conversation_snapshot(identity.0, identity.1)
            .await?;
        let discovery = map_discovery_view(&discovery_snapshot)?;
        let connection_repository = ConnectionRepository::new(self.database.clone());
        let pending_connections = connection_repository
            .pending_for_professional(identity.0)
            .await?;
        let recent_contacts = connection_repository.recent_contacts(identity.0).await?;
        let customer_pending = connection_repository
            .pending_for_customer(identity.0)
            .await?;
        let connections = map_connections_view(
            &pending_connections,
            &recent_contacts,
            customer_pending.as_ref(),
        )?;
        let billing_status = sahayak_persistence::BillingRepository::new(self.database.clone())
            .status(identity.0)
            .await?;
        let billing = match billing_status.status.as_str() {
            "payment_required" => BillingView::PaymentRequired {
                hosted_payment_url: billing_status.hosted_payment_url,
            },
            "pending_payment" => BillingView::PendingPayment {
                hosted_payment_url: billing_status.hosted_payment_url,
            },
            "active" => BillingView::Active,
            "past_due" => BillingView::GracePeriod,
            "expired" => BillingView::Expired,
            "manually_waived" => BillingView::ManuallyWaived,
            _ => BillingView::FreeValue,
        };
        let trust = TrustView {
            introductions: connection_repository
                .introduction_history(identity.0)
                .await?
                .into_iter()
                .map(|introduction| TrustIntroductionView {
                    reveal_token: introduction.reveal_token,
                    counterpart_label: introduction.counterpart_label,
                    category_code: introduction.category_code,
                    current_account_is_customer: introduction.current_account_is_customer,
                    already_reviewed: introduction.already_reviewed,
                    already_reported: introduction.already_reported,
                    already_blocked: introduction.already_blocked,
                })
                .collect(),
        };
        let context = ConversationContext {
            confirmed_locale,
            session,
            session_expired: turn.session_expired || unsupported_session.is_some(),
            professional,
            administrator,
            availability,
            discovery,
            connections,
            billing,
            trust,
            safety_administrator,
        };
        let input = canonical_input(&content, turn.resolved_reply_to);
        let mut plan = self.engine.decide(&context, &input).map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "conversation engine rejected persisted state".to_owned(),
            )
        })?;
        if administrator_command_is_stale(&plan, administrator_snapshot.as_ref()) {
            let menu =
                sahayak_conversation_engine::NormalizedText::parse("menu").map_err(|_| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "administrator recovery input is invalid".to_owned(),
                    )
                })?;
            plan = self
                .engine
                .decide(&context, &UserInput::Text(menu))
                .map_err(|_| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "administrator recovery plan failed".to_owned(),
                    )
                })?;
        }
        if let Some((session_id, expected_version)) = unsupported_session
            && let SessionChange::Create { next, locale } = plan.session_change.clone()
        {
            plan.session_change = SessionChange::Replace {
                session_id,
                expected_version,
                next,
                locale,
                terminal_status: SessionTerminalStatus::Abandoned,
                terminal_reason: "unsupported_workflow_state",
            };
            plan.disposition = ConversationDisposition::Recovered;
        }
        self.render_current_consent_prompt(
            &mut plan,
            professional_snapshot.as_ref(),
            context.session.as_ref(),
        )
        .await?;

        let recipient = NormalizedPhoneNumber::parse(&sender_phone_e164).map_err(|_| {
            sahayak_persistence::PersistenceError::InvalidCommand(
                "conversation sender is not a valid Indian mobile number".to_owned(),
            )
        })?;
        let photo_operation = if matches!(
            plan.business_command,
            Some(BusinessCommand::Professional(
                ProfessionalCommand::CurrentInboundMedia
            ))
        ) {
            match self
                .resolve_current_photo(job, &content, turn.database_now)
                .await?
            {
                PhotoResolution::Ready(operation) => Some(operation),
                PhotoResolution::PermanentFailure => {
                    plan = self
                        .engine
                        .decide(&context, &UserInput::Unsupported)
                        .map_err(|_| {
                            sahayak_persistence::PersistenceError::Invariant(
                                "conversation engine could not recover invalid media".to_owned(),
                            )
                        })?;
                    None
                }
                PhotoResolution::RetryScheduled => return Ok(()),
            }
        } else {
            None
        };
        let admin_image_header = match self
            .resolve_administrator_review_photo(
                job,
                &plan,
                administrator_snapshot.as_ref(),
                identity,
            )
            .await?
        {
            AdministratorPhotoResolution::Header(media_id) => Some(media_id),
            AdministratorPhotoResolution::None => None,
            AdministratorPhotoResolution::RetryScheduled => return Ok(()),
            AdministratorPhotoResolution::Unavailable => {
                let mut recovery_context = context.clone();
                let Some(recovery_session) = recovery_context.session.as_mut() else {
                    return Err(sahayak_persistence::PersistenceError::Invariant(
                        "administrator photo recovery session is missing".to_owned(),
                    ));
                };
                let inspect_state = match &plan.session_change {
                    SessionChange::Create { next, .. }
                    | SessionChange::Advance { next, .. }
                    | SessionChange::Replace { next, .. } => next.clone(),
                };
                recovery_session.state = inspect_state;
                let recovery_action = UserInput::Action {
                    id: ActionId::parse("admin.decision.changes").map_err(|_| {
                        sahayak_persistence::PersistenceError::Invariant(
                            "administrator photo recovery action is invalid".to_owned(),
                        )
                    })?,
                    reply_to: recovery_session.expected_reply_to,
                };
                plan = self
                    .engine
                    .decide(&recovery_context, &recovery_action)
                    .map_err(|_| {
                        sahayak_persistence::PersistenceError::Invariant(
                            "administrator photo recovery plan failed".to_owned(),
                        )
                    })?;
                let locale = context
                    .session
                    .as_ref()
                    .map_or(Locale::EnIn, |session| session.locale);
                let warning = Localizer::load()
                    .map_err(|_| {
                        sahayak_persistence::PersistenceError::Invariant(
                            "administrator photo warning localization failed".to_owned(),
                        )
                    })?
                    .text(locale, MessageKey::ADMIN_PHOTO_UNAVAILABLE_BODY)
                    .to_owned();
                let combined = format!("{warning}\n\n{}", plan.reply.body);
                plan.reply.body = if combined.encode_utf16().count() <= 1_024 {
                    combined
                } else {
                    warning
                };
                None
            }
        };
        let prepared_connection = self
            .prepare_connection_turn(job, &plan, identity, encrypted_event.correlation_id)
            .await?;
        if let Some(prepared) = prepared_connection.as_ref() {
            plan.reply.body = prepared.primary_body.clone();
            plan.reply.controls = ReplyControls::None;
            if let Some((token, version)) = prepared.next_connection.as_ref() {
                bind_waiting_connection(&mut plan.session_change, token, *version)?;
            }
        }
        let effects = self
            .map_turn_effects(
                &plan,
                professional_snapshot.as_ref(),
                administrator_snapshot.as_ref(),
                safety_administrator_snapshot.as_deref(),
                context.session.as_ref(),
                &content,
                photo_operation,
                encrypted_event
                    .provider_occurred_at
                    .unwrap_or(turn.database_now),
                event_id,
                identity,
                prepared_connection,
            )
            .await?;
        let availability_command = matches!(
            plan.business_command,
            Some(BusinessCommand::Availability(_))
        );
        let commit = self.build_turn_commit(
            job,
            event_id,
            identity,
            &turn,
            encrypted_event.correlation_id,
            &provider_message_id,
            &recipient,
            &plan,
            effects,
            admin_image_header.as_deref(),
        )?;
        match self.conversations.commit_effectful(&commit).await? {
            EffectfulTurnCommitOutcome::Committed { .. }
            | EffectfulTurnCommitOutcome::AlreadyCommitted { .. } => Ok(()),
            EffectfulTurnCommitOutcome::Conflict => {
                self.recover_rejected_turn(
                    job,
                    event_id,
                    identity,
                    &turn,
                    encrypted_event.correlation_id,
                    &provider_message_id,
                    &recipient,
                    &context,
                    availability_command,
                    "business_conflict",
                )
                .await
            }
            EffectfulTurnCommitOutcome::Unauthorized => {
                self.recover_rejected_turn(
                    job,
                    event_id,
                    identity,
                    &turn,
                    encrypted_event.correlation_id,
                    &provider_message_id,
                    &recipient,
                    &context,
                    availability_command,
                    "business_unauthorized",
                )
                .await
            }
            EffectfulTurnCommitOutcome::AlreadyDecided => {
                self.recover_rejected_turn(
                    job,
                    event_id,
                    identity,
                    &turn,
                    encrypted_event.correlation_id,
                    &provider_message_id,
                    &recipient,
                    &context,
                    availability_command,
                    "business_already_decided",
                )
                .await
            }
            EffectfulTurnCommitOutcome::Incomplete => {
                self.recover_rejected_turn(
                    job,
                    event_id,
                    identity,
                    &turn,
                    encrypted_event.correlation_id,
                    &provider_message_id,
                    &recipient,
                    &context,
                    availability_command,
                    "business_incomplete",
                )
                .await
            }
            EffectfulTurnCommitOutcome::CustomerLimit => {
                self.recover_rejected_turn(
                    job,
                    event_id,
                    identity,
                    &turn,
                    encrypted_event.correlation_id,
                    &provider_message_id,
                    &recipient,
                    &context,
                    false,
                    "customer_limit_reached",
                )
                .await
            }
            EffectfulTurnCommitOutcome::ProfessionalCapacity => {
                self.recover_rejected_turn(
                    job,
                    event_id,
                    identity,
                    &turn,
                    encrypted_event.correlation_id,
                    &provider_message_id,
                    &recipient,
                    &context,
                    false,
                    "professional_capacity_reached",
                )
                .await
            }
            EffectfulTurnCommitOutcome::ServiceWindowExpired => {
                self.reject_conversation(job, "service_window_expired")
                    .await
            }
            EffectfulTurnCommitOutcome::LostLease => Ok(()),
        }
    }

    async fn resolve_current_photo(
        &self,
        job: &ClaimedJob,
        content: &NormalizedContent,
        sanitized_at: OffsetDateTime,
    ) -> Result<PhotoResolution, sahayak_persistence::PersistenceError> {
        let NormalizedContent::Media {
            media_type,
            media_id,
            ..
        } = content
        else {
            return Ok(PhotoResolution::PermanentFailure);
        };
        if media_type != "image" {
            return Ok(PhotoResolution::PermanentFailure);
        }
        let media_lease = self
            .lease_duration
            .saturating_add(self.request_timeout.saturating_mul(2))
            .saturating_add(Duration::from_secs(10));
        if self.outbox.renew(job.lease(), media_lease).await?
            != sahayak_persistence::LeaseOutcome::Applied
        {
            return Ok(PhotoResolution::RetryScheduled);
        }
        let download_result = {
            let client = self.client.read().await;
            client
                .download_media(media_id, MAX_PROFILE_PHOTO_BYTES)
                .await
        };
        let downloaded = match download_result {
            Ok(media) => media,
            Err(error) if media_error_is_transient(&error) => {
                if matches!(
                    &error,
                    WhatsAppError::Api(failure)
                        if failure.class == FailureClass::Authorization
                ) && let Err(reload_error) = self.reload_access_token().await
                {
                    warn!(%reload_error, "failed to reload WhatsApp access token for media retry");
                }
                if job.attempt_count >= job.max_attempts {
                    return Ok(PhotoResolution::PermanentFailure);
                }
                let retry_after = match &error {
                    WhatsAppError::Api(failure) => failure
                        .retry_after_seconds
                        .map(Duration::from_secs)
                        .unwrap_or_else(|| retry_delay(job.attempt_count)),
                    _ => retry_delay(job.attempt_count),
                };
                let failure = self
                    .outbox
                    .record_failure(
                        job.lease(),
                        &FailureDisposition::Retry {
                            error_class: "media_transport".to_owned(),
                            error_code: "profile_photo_download_retry".to_owned(),
                            after: retry_after,
                        },
                    )
                    .await?;
                return Ok(match failure {
                    sahayak_persistence::FailureOutcome::RetryScheduled { .. }
                    | sahayak_persistence::FailureOutcome::LostLease => {
                        PhotoResolution::RetryScheduled
                    }
                    sahayak_persistence::FailureOutcome::DeadLettered => {
                        PhotoResolution::PermanentFailure
                    }
                });
            }
            Err(_) => return Ok(PhotoResolution::PermanentFailure),
        };
        let sanitized = match crate::photo::sanitize_profile_photo(downloaded.bytes()) {
            Ok(photo) => photo,
            Err(_) => return Ok(PhotoResolution::PermanentFailure),
        };
        drop(downloaded);
        let photo_id = ProfilePhotoId::new();
        let encrypted_jpeg = self
            .cryptography
            .encrypt(
                EncryptionPurpose::Media,
                EncryptionContext::new(EncryptionNamespace::PROFILE_PHOTO, photo_id.into_uuid()),
                &sanitized.bytes,
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "sanitized profile photo encryption failed".to_owned(),
                )
            })?;
        let width_pixels = i32::try_from(sanitized.width).map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "sanitized profile photo width is invalid".to_owned(),
            )
        })?;
        let height_pixels = i32::try_from(sanitized.height).map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "sanitized profile photo height is invalid".to_owned(),
            )
        })?;
        Ok(PhotoResolution::Ready(
            ProfessionalTurnOperation::AttachSanitizedPhoto {
                photo_id,
                encrypted_jpeg,
                width_pixels,
                height_pixels,
                plaintext_sha256: sanitized.sha256,
                sanitizer_version: crate::photo::SANITIZER_VERSION.to_owned(),
                sanitized_at,
            },
        ))
    }

    async fn resolve_administrator_review_photo(
        &self,
        job: &ClaimedJob,
        plan: &TurnPlan,
        snapshot: Option<&AdministratorConversationSnapshot>,
        reviewer: (AccountId, ChannelIdentityId),
    ) -> Result<AdministratorPhotoResolution, sahayak_persistence::PersistenceError> {
        let next = match &plan.session_change {
            SessionChange::Create { next, .. }
            | SessionChange::Advance { next, .. }
            | SessionChange::Replace { next, .. } => next,
        };
        let ConversationState::Administrator(AdminState::Inspect {
            target,
            target_version,
        }) = next
        else {
            return Ok(AdministratorPhotoResolution::None);
        };
        let Some(target) = snapshot
            .into_iter()
            .flat_map(|value| value.pending.iter().chain(value.selected.iter()))
            .find(|value| {
                value.review_token == target.as_str() && value.target.version == *target_version
            })
        else {
            return Ok(AdministratorPhotoResolution::Unavailable);
        };
        if !target.target.has_ready_photo {
            return Ok(AdministratorPhotoResolution::None);
        }
        let Some(photo) = ProfilePhotoRepository::new(self.database.clone())
            .load_for_administrator_review(
                target.target.revision_id,
                reviewer.0,
                reviewer.1,
                &self.provider_namespace,
            )
            .await?
        else {
            return Ok(AdministratorPhotoResolution::Unavailable);
        };
        let media_lease = self
            .lease_duration
            .saturating_add(self.request_timeout)
            .saturating_add(Duration::from_secs(10));
        if self.outbox.renew(job.lease(), media_lease).await?
            != sahayak_persistence::LeaseOutcome::Applied
        {
            return Ok(AdministratorPhotoResolution::RetryScheduled);
        }
        let decrypted = Zeroizing::new(
            self.cryptography
                .decrypt(
                    EncryptionContext::new(
                        EncryptionNamespace::PROFILE_PHOTO,
                        photo.photo_id.into_uuid(),
                    ),
                    &photo.encrypted_jpeg,
                )
                .map_err(|_| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "administrator review photo authentication failed".to_owned(),
                    )
                })?,
        );
        let upload_result = {
            let client = self.client.read().await;
            client.upload_sanitized_image(&decrypted).await
        };
        drop(decrypted);
        match upload_result {
            Ok(media_id) => Ok(AdministratorPhotoResolution::Header(media_id)),
            Err(error)
                if media_error_is_transient(&error) && job.attempt_count < job.max_attempts =>
            {
                if matches!(
                    &error,
                    WhatsAppError::Api(failure)
                        if failure.class == FailureClass::Authorization
                ) && let Err(reload_error) = self.reload_access_token().await
                {
                    warn!(%reload_error, "failed to reload WhatsApp access token for review photo");
                }
                let retry_after = match &error {
                    WhatsAppError::Api(failure) => failure
                        .retry_after_seconds
                        .map(Duration::from_secs)
                        .unwrap_or_else(|| retry_delay(job.attempt_count)),
                    _ => retry_delay(job.attempt_count),
                };
                let outcome = self
                    .outbox
                    .record_failure(
                        job.lease(),
                        &FailureDisposition::Retry {
                            error_class: "media_transport".to_owned(),
                            error_code: "administrator_photo_upload_retry".to_owned(),
                            after: retry_after,
                        },
                    )
                    .await?;
                Ok(match outcome {
                    sahayak_persistence::FailureOutcome::RetryScheduled { .. }
                    | sahayak_persistence::FailureOutcome::LostLease => {
                        AdministratorPhotoResolution::RetryScheduled
                    }
                    sahayak_persistence::FailureOutcome::DeadLettered => {
                        AdministratorPhotoResolution::Unavailable
                    }
                })
            }
            Err(_) => Ok(AdministratorPhotoResolution::Unavailable),
        }
    }

    async fn prepare_connection_turn(
        &self,
        _job: &ClaimedJob,
        plan: &TurnPlan,
        identity: (AccountId, ChannelIdentityId),
        correlation_id: CorrelationId,
    ) -> Result<Option<PreparedConnectionTurn>, sahayak_persistence::PersistenceError> {
        let Some(BusinessCommand::Connection(command)) = plan.business_command.as_ref() else {
            return Ok(None);
        };
        let repository = ConnectionRepository::new(self.database.clone());
        match command {
            ConnectionCommand::Select {
                request_token,
                request_version,
                candidate_token,
            } => {
                let selection = repository
                    .selection_context(identity.0, candidate_token)
                    .await?
                    .ok_or_else(|| sahayak_persistence::PersistenceError::OptimisticConflict)?;
                if selection.request_token != *request_token
                    || selection.request_version != *request_version
                {
                    return Err(sahayak_persistence::PersistenceError::OptimisticConflict);
                }
                self.prepare_selection_connection(selection, correlation_id)
                    .await
                    .map(Some)
            }
            ConnectionCommand::Respond {
                request_token,
                expected_version,
                accept,
            } => {
                let response = repository
                    .response_context(identity.0, request_token)
                    .await?
                    .ok_or_else(|| sahayak_persistence::PersistenceError::OptimisticConflict)?;
                if response.version != *expected_version {
                    return Err(sahayak_persistence::PersistenceError::OptimisticConflict);
                }
                self.prepare_response_connection(response, *accept, correlation_id)
                    .await
                    .map(Some)
            }
            ConnectionCommand::Cancel {
                request_token,
                expected_version,
            } => Ok(Some(PreparedConnectionTurn {
                effect: ConnectionTurnEffect {
                    operation: ConnectionTurnOperation::Cancel {
                        connection_token: uuid::Uuid::parse_str(request_token).map_err(|_| {
                            sahayak_persistence::PersistenceError::InvalidCommand(
                                "connection request token is invalid".to_owned(),
                            )
                        })?,
                        expected_version: *expected_version,
                    },
                },
                primary_body: plan.reply.body.clone(),
                additional_outbound: Vec::new(),
                next_connection: None,
            })),
            ConnectionCommand::RepeatReveal { reveal_token } => {
                let context = repository
                    .repeat_reveal_context(identity.0, reveal_token)
                    .await?
                    .ok_or_else(|| sahayak_persistence::PersistenceError::OptimisticConflict)?;
                self.prepare_repeat_reveal(context, correlation_id)
                    .await
                    .map(Some)
            }
        }
    }

    async fn prepare_selection_connection(
        &self,
        selection: SelectionContext,
        correlation_id: CorrelationId,
    ) -> Result<PreparedConnectionTurn, sahayak_persistence::PersistenceError> {
        let connection_id = ConnectionRequestId::new();
        let connection_token = uuid::Uuid::new_v4();
        let reveal_id = ContactRevealId::new();
        let reveal_token = uuid::Uuid::new_v4();
        let mut additional = Vec::new();
        let mut outbounds = ConnectionOutboundIds {
            customer_contact: None,
            professional_contact: None,
            professional_notification: None,
            photo: None,
        };
        let (primary_body, pause_notification) = if selection.contact_mode == ContactMode::Direct {
            let professional_phone = self.decrypt_contact_phone(&selection.professional)?;
            let primary_body = self.contact_message(
                &professional_phone,
                Locale::parse(&selection.customer.locale).unwrap_or(Locale::EnIn),
            )?;
            let notification = self.prepare_target_text(
                &selection.professional,
                Localizer::load()
                    .map_err(|_| {
                        sahayak_persistence::PersistenceError::Invariant(
                            "connection localization failed".to_owned(),
                        )
                    })?
                    .text(
                        Locale::parse(&selection.professional.locale).unwrap_or(Locale::EnIn),
                        MessageKey::CONNECTION_DIRECT_NOTIFY_BODY,
                    ),
                format!("connection-direct-notify:v1:{reveal_id}"),
                correlation_id,
            )?;
            outbounds.professional_notification = Some(notification.id);
            additional.push(notification);
            if let Some(photo) = selection.photo.as_ref()
                && let Some(photo_message) = self
                    .prepare_contact_photo(
                        photo,
                        &selection.customer,
                        format!("connection-photo:v1:{reveal_id}"),
                        correlation_id,
                    )
                    .await?
            {
                outbounds.photo = Some(photo_message.id);
                additional.push(photo_message);
            }
            let pause = if selection.contact_count + 1 == selection.contact_limit {
                Some(
                    self.prepare_target_text(
                        &selection.professional,
                        Localizer::load()
                            .map_err(|_| {
                                sahayak_persistence::PersistenceError::Invariant(
                                    "capacity notification localization failed".to_owned(),
                                )
                            })?
                            .text(
                                Locale::parse(&selection.professional.locale)
                                    .unwrap_or(Locale::EnIn),
                                MessageKey::AVAILABILITY_LIMIT_BODY,
                            ),
                        format!("connection-capacity:v1:{reveal_id}"),
                        correlation_id,
                    )?,
                )
            } else {
                None
            };
            (primary_body, pause)
        } else {
            let body = format!(
                "{}\n{} · {} · {}",
                Localizer::load()
                    .map_err(|_| sahayak_persistence::PersistenceError::Invariant(
                        "request localization failed".to_owned(),
                    ))?
                    .text(
                        Locale::parse(&selection.professional.locale).unwrap_or(Locale::EnIn),
                        MessageKey::CONNECTION_REQUEST_NOTIFY_BODY,
                    ),
                selection.category_code,
                selection.issue_code,
                distance_label_for_metres(selection.distance_metres),
            );
            let notification = self.prepare_target_text(
                &selection.professional,
                &body,
                format!("connection-request:v1:{connection_id}"),
                correlation_id,
            )?;
            outbounds.professional_notification = Some(notification.id);
            additional.push(notification);
            (
                Localizer::load()
                    .map_err(|_| {
                        sahayak_persistence::PersistenceError::Invariant(
                            "request localization failed".to_owned(),
                        )
                    })?
                    .text(
                        Locale::parse(&selection.customer.locale).unwrap_or(Locale::EnIn),
                        MessageKey::DISCOVERY_REQUEST_SENT_BODY,
                    )
                    .to_owned(),
                None,
            )
        };
        Ok(PreparedConnectionTurn {
            effect: ConnectionTurnEffect {
                operation: ConnectionTurnOperation::Select {
                    connection_id,
                    connection_token,
                    reveal_id,
                    reveal_token,
                    request_token: uuid::Uuid::parse_str(&selection.request_token).map_err(
                        |_| {
                            sahayak_persistence::PersistenceError::InvalidCommand(
                                "service request token is invalid".to_owned(),
                            )
                        },
                    )?,
                    candidate_token: uuid::Uuid::parse_str(&selection.candidate_token).map_err(
                        |_| {
                            sahayak_persistence::PersistenceError::InvalidCommand(
                                "candidate token is invalid".to_owned(),
                            )
                        },
                    )?,
                    expected_request_version: selection.request_version,
                    outbounds,
                    pause_notification,
                },
            },
            primary_body,
            additional_outbound: additional,
            next_connection: (selection.contact_mode == ContactMode::ApprovalRequired)
                .then(|| (connection_token.to_string(), 1)),
        })
    }

    async fn prepare_response_connection(
        &self,
        response: PendingResponseContext,
        accept: bool,
        correlation_id: CorrelationId,
    ) -> Result<PreparedConnectionTurn, sahayak_persistence::PersistenceError> {
        if !accept {
            return Ok(PreparedConnectionTurn {
                effect: ConnectionTurnEffect {
                    operation: ConnectionTurnOperation::Respond {
                        connection_token: uuid::Uuid::parse_str(&response.request_token).map_err(
                            |_| {
                                sahayak_persistence::PersistenceError::InvalidCommand(
                                    "connection request token is invalid".to_owned(),
                                )
                            },
                        )?,
                        expected_version: response.version,
                        accept: false,
                        reveal_id: ContactRevealId::new(),
                        reveal_token: uuid::Uuid::new_v4(),
                        outbounds: empty_connection_outbounds(),
                        pause_notification: None,
                    },
                },
                primary_body: Localizer::load()
                    .map_err(|_| {
                        sahayak_persistence::PersistenceError::Invariant(
                            "connection localization failed".to_owned(),
                        )
                    })?
                    .text(
                        Locale::parse(&response.selection.professional.locale)
                            .unwrap_or(Locale::EnIn),
                        MessageKey::REQUESTS_DECLINED_BODY,
                    )
                    .to_owned(),
                additional_outbound: Vec::new(),
                next_connection: None,
            });
        }
        let reveal_id = ContactRevealId::new();
        let customer_phone = self.decrypt_contact_phone(&response.selection.customer)?;
        let professional_phone = self.decrypt_contact_phone(&response.selection.professional)?;
        let primary_body = self.contact_message(
            &customer_phone,
            Locale::parse(&response.selection.professional.locale).unwrap_or(Locale::EnIn),
        )?;
        let customer_contact = self.prepare_target_text(
            &response.selection.customer,
            &self.contact_message(
                &professional_phone,
                Locale::parse(&response.selection.customer.locale).unwrap_or(Locale::EnIn),
            )?,
            format!("connection-customer-contact:v1:{reveal_id}"),
            correlation_id,
        )?;
        let mut outbounds = empty_connection_outbounds();
        outbounds.customer_contact = Some(customer_contact.id);
        let mut additional = vec![customer_contact];
        if let Some(photo) = response.selection.photo.as_ref()
            && let Some(photo_message) = self
                .prepare_contact_photo(
                    photo,
                    &response.selection.customer,
                    format!("connection-photo:v1:{reveal_id}"),
                    correlation_id,
                )
                .await?
        {
            outbounds.photo = Some(photo_message.id);
            additional.push(photo_message);
        }
        let pause_notification =
            if response.selection.contact_count + 1 == response.selection.contact_limit {
                Some(
                    self.prepare_target_text(
                        &response.selection.professional,
                        Localizer::load()
                            .map_err(|_| {
                                sahayak_persistence::PersistenceError::Invariant(
                                    "capacity localization failed".to_owned(),
                                )
                            })?
                            .text(
                                Locale::parse(&response.selection.professional.locale)
                                    .unwrap_or(Locale::EnIn),
                                MessageKey::AVAILABILITY_LIMIT_BODY,
                            ),
                        format!("connection-capacity:v1:{reveal_id}"),
                        correlation_id,
                    )?,
                )
            } else {
                None
            };
        Ok(PreparedConnectionTurn {
            effect: ConnectionTurnEffect {
                operation: ConnectionTurnOperation::Respond {
                    connection_token: uuid::Uuid::parse_str(&response.request_token).map_err(
                        |_| {
                            sahayak_persistence::PersistenceError::InvalidCommand(
                                "connection request token is invalid".to_owned(),
                            )
                        },
                    )?,
                    expected_version: response.version,
                    accept: true,
                    reveal_id,
                    reveal_token: uuid::Uuid::new_v4(),
                    outbounds,
                    pause_notification,
                },
            },
            primary_body,
            additional_outbound: additional,
            next_connection: None,
        })
    }

    async fn prepare_repeat_reveal(
        &self,
        context: RepeatRevealContext,
        correlation_id: CorrelationId,
    ) -> Result<PreparedConnectionTurn, sahayak_persistence::PersistenceError> {
        let professional_phone = self.decrypt_contact_phone(&context.professional)?;
        let mut outbounds = empty_connection_outbounds();
        let mut additional = Vec::new();
        if let Some(photo) = context.photo.as_ref()
            && let Some(photo_message) = self
                .prepare_contact_photo(
                    photo,
                    &context.customer,
                    format!("recent-contact-photo:v1:{}", context.reveal_token),
                    correlation_id,
                )
                .await?
        {
            outbounds.photo = Some(photo_message.id);
            additional.push(photo_message);
        }
        Ok(PreparedConnectionTurn {
            effect: ConnectionTurnEffect {
                operation: ConnectionTurnOperation::Repeat {
                    reveal_token: uuid::Uuid::parse_str(&context.reveal_token).map_err(|_| {
                        sahayak_persistence::PersistenceError::InvalidCommand(
                            "recent reveal token is invalid".to_owned(),
                        )
                    })?,
                    outbounds,
                },
            },
            primary_body: self.contact_message(
                &professional_phone,
                Locale::parse(&context.customer.locale).unwrap_or(Locale::EnIn),
            )?,
            additional_outbound: additional,
            next_connection: None,
        })
    }

    fn decrypt_contact_phone(
        &self,
        target: &ContactTarget,
    ) -> Result<NormalizedPhoneNumber, sahayak_persistence::PersistenceError> {
        let plaintext = Zeroizing::new(
            self.cryptography
                .decrypt(
                    EncryptionContext::new(
                        EncryptionNamespace::WHATSAPP_PHONE_E164,
                        target.channel_identity_id.into_uuid(),
                    ),
                    &target.encrypted_phone,
                )
                .map_err(|_| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "connection phone authentication failed".to_owned(),
                    )
                })?,
        );
        let value = std::str::from_utf8(&plaintext).map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "connection phone encoding is invalid".to_owned(),
            )
        })?;
        NormalizedPhoneNumber::parse(value).map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "connection phone is invalid".to_owned(),
            )
        })
    }

    fn contact_message(
        &self,
        phone: &NormalizedPhoneNumber,
        locale: Locale,
    ) -> Result<String, sahayak_persistence::PersistenceError> {
        let localizer = Localizer::load().map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "connection localization failed".to_owned(),
            )
        })?;
        Ok(format!(
            "{}\n{}: tel:{}\n{}: https://wa.me/{}",
            localizer.text(locale, MessageKey::CONNECTION_CONTACT_BODY),
            localizer.text(locale, MessageKey::CONNECTION_CALL_LABEL),
            phone.expose(),
            localizer.text(locale, MessageKey::CONNECTION_WHATSAPP_LABEL),
            phone.expose().trim_start_matches('+'),
        ))
    }

    fn prepare_target_text(
        &self,
        target: &ContactTarget,
        body: &str,
        idempotency_key: String,
        correlation_id: CorrelationId,
    ) -> Result<QueueOutboundMessage, sahayak_persistence::PersistenceError> {
        let recipient = self.decrypt_contact_phone(target)?;
        let ordering_key = self
            .cryptography
            .blind_index(
                "integration:whatsapp:conversation-order:v1",
                recipient.expose().trim_start_matches('+').as_bytes(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "connection ordering key failed".to_owned(),
                )
            })?
            .1;
        self.prepare_queue_outbound(
            OutboundMessage::text(
                &recipient,
                TextMessage::new(body, false).map_err(|_| {
                    sahayak_persistence::PersistenceError::InvalidCommand(
                        "connection notification text is invalid".to_owned(),
                    )
                })?,
            ),
            target.provider_namespace.clone(),
            Some(target.channel_identity_id),
            idempotency_key,
            correlation_id,
            Some(ordering_key),
        )
    }

    async fn prepare_contact_photo(
        &self,
        photo: &ContactPhoto,
        target: &ContactTarget,
        idempotency_key: String,
        correlation_id: CorrelationId,
    ) -> Result<Option<QueueOutboundMessage>, sahayak_persistence::PersistenceError> {
        let jpeg = Zeroizing::new(
            self.cryptography
                .decrypt(
                    EncryptionContext::new(
                        EncryptionNamespace::PROFILE_PHOTO,
                        photo.photo_id.into_uuid(),
                    ),
                    &photo.encrypted_jpeg,
                )
                .map_err(|_| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "contact photo authentication failed".to_owned(),
                    )
                })?,
        );
        let media_id = {
            let client = self.client.read().await;
            match client.upload_sanitized_image(&jpeg).await {
                Ok(media_id) => media_id,
                Err(error) => {
                    warn!(%error, "optional contact photo upload failed");
                    return Ok(None);
                }
            }
        };
        drop(jpeg);
        let recipient = self.decrypt_contact_phone(target)?;
        let ordering_key = self
            .cryptography
            .blind_index(
                "integration:whatsapp:conversation-order:v1",
                recipient.expose().trim_start_matches('+').as_bytes(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "contact photo ordering key failed".to_owned(),
                )
            })?
            .1;
        self.prepare_queue_outbound(
            OutboundMessage::media(
                &recipient,
                MediaMessage::new(
                    MediaKind::Image,
                    MediaReference::id(&media_id).map_err(|_| {
                        sahayak_persistence::PersistenceError::Invariant(
                            "uploaded contact photo ID is invalid".to_owned(),
                        )
                    })?,
                    None,
                    None,
                )
                .map_err(|_| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "contact photo message is invalid".to_owned(),
                    )
                })?,
            ),
            target.provider_namespace.clone(),
            Some(target.channel_identity_id),
            idempotency_key,
            correlation_id,
            Some(ordering_key),
        )
        .map(Some)
    }

    #[allow(clippy::too_many_arguments)]
    async fn map_turn_effects(
        &self,
        plan: &TurnPlan,
        professional: Option<&ProfessionalConversationSnapshot>,
        administrator: Option<&AdministratorConversationSnapshot>,
        safety_administrator: Option<&[sahayak_persistence::AdministratorReportItem]>,
        session: Option<&SessionSnapshot>,
        content: &NormalizedContent,
        photo_operation: Option<ProfessionalTurnOperation>,
        occurred_at: OffsetDateTime,
        inbound_event_id: sahayak_domain::InboundEventId,
        identity: (AccountId, ChannelIdentityId),
        prepared_connection: Option<PreparedConnectionTurn>,
    ) -> Result<ConversationTurnEffects, sahayak_persistence::PersistenceError> {
        let role_context = Some(
            if session_change_is_trust(&plan.session_change) && professional.is_some() {
                AccountRole::Professional
            } else {
                role_for_session_change(&plan.session_change)
            },
        );
        let (effect, additional_outbound) = match plan.business_command.as_ref() {
            Some(BusinessCommand::Account(AccountCommand::SetLocale { locale })) => {
                if plan.locale_change != Some(*locale) {
                    return Err(sahayak_persistence::PersistenceError::Invariant(
                        "locale command and locale projection disagree".to_owned(),
                    ));
                }
                (None, Vec::new())
            }
            Some(BusinessCommand::Professional(command)) => (
                self.map_professional_effect(
                    command,
                    professional,
                    content,
                    photo_operation,
                    session,
                    occurred_at,
                )
                .await?
                .map(ConversationTurnEffect::Professional),
                Vec::new(),
            ),
            Some(BusinessCommand::Administrator(command)) => {
                let (effect, notification) = self
                    .map_administrator_effect(
                        command,
                        administrator,
                        session,
                        inbound_event_id,
                        identity,
                    )
                    .await?;
                (
                    Some(ConversationTurnEffect::AdministratorReview(effect)),
                    vec![notification],
                )
            }
            Some(BusinessCommand::Availability(command)) => (
                Some(ConversationTurnEffect::Availability(
                    map_availability_effect(command)?,
                )),
                Vec::new(),
            ),
            Some(BusinessCommand::Discovery(command)) => (
                Some(ConversationTurnEffect::Discovery(map_discovery_effect(
                    command, content,
                )?)),
                Vec::new(),
            ),
            Some(BusinessCommand::Connection(_)) => {
                let prepared = prepared_connection.ok_or_else(|| {
                    sahayak_persistence::PersistenceError::InvalidCommand(
                        "connection command requires prepared disclosure context".to_owned(),
                    )
                })?;
                (
                    Some(ConversationTurnEffect::Connection(Box::new(
                        prepared.effect,
                    ))),
                    prepared.additional_outbound,
                )
            }
            Some(BusinessCommand::Trust(command)) => (
                Some(ConversationTurnEffect::Trust(
                    self.map_trust_effect(command)?,
                )),
                Vec::new(),
            ),
            Some(BusinessCommand::SafetyModeration(command)) => {
                let (effect, notifications) =
                    self.map_safety_moderation_effect(command, safety_administrator)?;
                (Some(ConversationTurnEffect::Trust(effect)), notifications)
            }
            None if should_start_professional_draft(plan, professional) => (
                Some(ConversationTurnEffect::Professional(
                    start_professional_effect(professional),
                )),
                Vec::new(),
            ),
            None => (None, Vec::new()),
        };
        Ok(ConversationTurnEffects {
            effect,
            role_context,
            additional_outbound,
        })
    }

    fn map_trust_effect(
        &self,
        command: &TrustCommand,
    ) -> Result<sahayak_persistence::TrustTurnEffect, sahayak_persistence::PersistenceError> {
        let parse_token = |value: &str| {
            uuid::Uuid::parse_str(value).map_err(|_| {
                sahayak_persistence::PersistenceError::InvalidCommand(
                    "reveal token is invalid".to_owned(),
                )
            })
        };
        let operation = match command {
            TrustCommand::SubmitReview {
                reveal_token,
                connection,
                responsiveness,
                completion,
                written_feedback,
            } => {
                let revision_id = sahayak_domain::ReviewRevisionId::new();
                let encrypted_feedback = written_feedback
                    .as_ref()
                    .map(|feedback| {
                        self.cryptography.encrypt(
                            EncryptionPurpose::Integration,
                            EncryptionContext::new(
                                EncryptionNamespace::REVIEW_FEEDBACK,
                                revision_id.into_uuid(),
                            ),
                            feedback.as_bytes(),
                        )
                    })
                    .transpose()
                    .map_err(|error| {
                        sahayak_persistence::PersistenceError::InvalidCommand(error.to_string())
                    })?;
                sahayak_persistence::TrustTurnOperation::SubmitReview {
                    review_id: sahayak_domain::ReviewId::new(),
                    review_token: uuid::Uuid::new_v4(),
                    revision_id,
                    reveal_token: parse_token(reveal_token)?,
                    connection: i16::from(*connection),
                    responsiveness: i16::from(*responsiveness),
                    completion: i16::from(*completion),
                    encrypted_feedback,
                }
            }
            TrustCommand::SubmitReport {
                reveal_token,
                category,
                block_subject,
                description,
            } => {
                let report_id = sahayak_domain::ReportId::new();
                let encrypted_description = description
                    .as_ref()
                    .map(|description| {
                        self.cryptography.encrypt(
                            EncryptionPurpose::Integration,
                            EncryptionContext::new(
                                EncryptionNamespace::SAFETY_REPORT_DESCRIPTION,
                                report_id.into_uuid(),
                            ),
                            description.as_bytes(),
                        )
                    })
                    .transpose()
                    .map_err(|error| {
                        sahayak_persistence::PersistenceError::InvalidCommand(error.to_string())
                    })?;
                let severity = match category.as_str() {
                    "unsafe_behavior" => "critical",
                    "fraud" | "harassment" | "identity_misrepresentation" => "high",
                    "spam" | "no_show" => "medium",
                    _ => "low",
                };
                sahayak_persistence::TrustTurnOperation::SubmitReport {
                    report_id,
                    report_token: uuid::Uuid::new_v4(),
                    reveal_token: parse_token(reveal_token)?,
                    category: category.clone(),
                    severity: severity.to_owned(),
                    block_subject: *block_subject,
                    encrypted_description,
                    evidence_references: serde_json::json!([]),
                }
            }
            TrustCommand::Block { reveal_token } => {
                sahayak_persistence::TrustTurnOperation::Block {
                    reveal_token: parse_token(reveal_token)?,
                }
            }
        };
        Ok(sahayak_persistence::TrustTurnEffect { operation })
    }

    fn map_safety_moderation_effect(
        &self,
        command: &SafetyModerationCommand,
        reports: Option<&[sahayak_persistence::AdministratorReportItem]>,
    ) -> Result<
        (
            sahayak_persistence::TrustTurnEffect,
            Vec<QueueOutboundMessage>,
        ),
        sahayak_persistence::PersistenceError,
    > {
        let report_token = uuid::Uuid::parse_str(&command.report_token).map_err(|_| {
            sahayak_persistence::PersistenceError::InvalidCommand(
                "report token is invalid".to_owned(),
            )
        })?;
        let report = reports
            .and_then(|reports| {
                reports.iter().find(|report| {
                    report.report_token == report_token
                        && report.version == command.expected_version
                })
            })
            .ok_or(sahayak_persistence::PersistenceError::OptimisticConflict)?;
        let action = command.action.as_str();
        let localizer = Localizer::load().map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "safety resolution localization failed".to_owned(),
            )
        })?;
        let locale = Locale::parse(&report.subject.locale).unwrap_or(Locale::EnIn);
        let subject_notification = self.prepare_target_text(
            &report.subject,
            localizer.text(locale, MessageKey::SAFETY_RESOLUTION_NOTICE_BODY),
            format!(
                "safety-resolution:v1:{report_token}:{}",
                command.expected_version
            ),
            CorrelationId::new(),
        )?;
        let reporter_locale = Locale::parse(&report.reporter.locale).unwrap_or(Locale::EnIn);
        let reporter_notification = self.prepare_target_text(
            &report.reporter,
            localizer.text(reporter_locale, MessageKey::SAFETY_REPORTER_RESOLUTION_BODY),
            format!(
                "safety-reporter-resolution:v1:{report_token}:{}",
                command.expected_version
            ),
            CorrelationId::new(),
        )?;
        Ok((
            sahayak_persistence::TrustTurnEffect {
                operation: sahayak_persistence::TrustTurnOperation::ResolveReport {
                    report_token,
                    expected_version: command.expected_version,
                    action: action.to_owned(),
                    restriction_id: uuid::Uuid::now_v7(),
                    reason_code: format!("administrator_{action}"),
                    resolution_summary: localizer
                        .text(locale, MessageKey::SAFETY_RESOLUTION_NOTICE_BODY)
                        .to_owned(),
                },
            },
            vec![subject_notification, reporter_notification],
        ))
    }

    async fn map_professional_effect(
        &self,
        command: &ProfessionalCommand,
        snapshot: Option<&ProfessionalConversationSnapshot>,
        content: &NormalizedContent,
        photo_operation: Option<ProfessionalTurnOperation>,
        session: Option<&SessionSnapshot>,
        occurred_at: OffsetDateTime,
    ) -> Result<Option<ProfessionalTurnEffect>, sahayak_persistence::PersistenceError> {
        if matches!(
            command,
            ProfessionalCommand::ConfirmDisplayName { .. } | ProfessionalCommand::SkipPhoto
        ) {
            return Ok(None);
        }
        let target = professional_effect_target(snapshot, command)?;
        let operation = match command {
            ProfessionalCommand::StageDisplayName { display_name } => {
                ProfessionalTurnOperation::StageDisplayName {
                    public_reference: PublicProfileReference::new(),
                    display_name: ProfessionalDisplayName::parse(display_name.clone()).map_err(
                        |_| {
                            sahayak_persistence::PersistenceError::InvalidCommand(
                                "professional display name is invalid".to_owned(),
                            )
                        },
                    )?,
                }
            }
            ProfessionalCommand::SetCategories { categories } => {
                ProfessionalTurnOperation::SetSelectedCategories {
                    category_codes: categories
                        .values()
                        .into_iter()
                        .map(|category| category.as_str().to_owned())
                        .collect(),
                }
            }
            ProfessionalCommand::SetSkills { category, skills } => {
                ProfessionalTurnOperation::SetCategorySkills {
                    category_code: category.as_str().to_owned(),
                    skill_codes: skills
                        .iter()
                        .map(|skill| skill.as_str().to_owned())
                        .collect(),
                }
            }
            ProfessionalCommand::SetLocalMode { mode } => {
                ProfessionalTurnOperation::SetLocalServiceMode {
                    mode: map_local_service_mode(*mode),
                }
            }
            ProfessionalCommand::CurrentInboundLocation => {
                let NormalizedContent::Location {
                    latitude,
                    longitude,
                    ..
                } = content
                else {
                    return Err(sahayak_persistence::PersistenceError::InvalidCommand(
                        "current location command has no current location payload".to_owned(),
                    ));
                };
                ProfessionalTurnOperation::SetCurrentInboundLocation {
                    latitude: *latitude,
                    longitude: *longitude,
                }
            }
            ProfessionalCommand::SetRadius { radius } => ProfessionalTurnOperation::SetRadius {
                radius: map_service_radius(*radius),
            },
            ProfessionalCommand::SetServiceLanguages { locales } => {
                ProfessionalTurnOperation::SetLanguages {
                    languages: locales
                        .iter()
                        .copied()
                        .map(map_professional_language)
                        .collect(),
                }
            }
            ProfessionalCommand::SetContactMode { category, mode } => {
                ProfessionalTurnOperation::SetCategoryContactMode {
                    category_code: category.as_str().to_owned(),
                    mode: map_contact_mode(*mode),
                }
            }
            ProfessionalCommand::SetContactSessionLimit { limit } => {
                ProfessionalTurnOperation::SetContactRequestLimit {
                    limit: i16::from(limit.value()),
                }
            }
            ProfessionalCommand::CurrentInboundMedia => photo_operation.ok_or_else(|| {
                sahayak_persistence::PersistenceError::Invariant(
                    "current media command has no sanitized photo".to_owned(),
                )
            })?,
            ProfessionalCommand::RemovePhoto => ProfessionalTurnOperation::RemoveDraftPhoto,
            ProfessionalCommand::AcceptConsent { version } => {
                if *version != sahayak_conversation_engine::PROFESSIONAL_CONSENT_VERSION {
                    return Err(sahayak_persistence::PersistenceError::InvalidCommand(
                        "professional consent version is unsupported".to_owned(),
                    ));
                }
                let summary = snapshot
                    .and_then(|value| value.summary.as_ref())
                    .ok_or_else(|| {
                        sahayak_persistence::PersistenceError::InvalidCommand(
                            "professional consent requires a current draft summary".to_owned(),
                        )
                    })?;
                let session = session.ok_or_else(|| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "professional consent session is missing".to_owned(),
                    )
                })?;
                let locale = session.locale;
                let prompt_session_id = session.id;
                let prompt_outbound_message_id = session.expected_reply_to.ok_or_else(|| {
                    sahayak_persistence::PersistenceError::InvalidCommand(
                        "professional consent prompt reference is missing".to_owned(),
                    )
                })?;
                let acceptances = self
                    .required_consent_acceptances(summary, locale, occurred_at)
                    .await?;
                let document_set_digest =
                    sahayak_persistence::professional_consent_document_set_digest(&acceptances);
                let rendered_digest = match session.state {
                    ConversationState::Professional(
                        sahayak_conversation_engine::ProfessionalState::Consent {
                            document_set_digest: Some(digest),
                            ..
                        },
                    ) => digest,
                    _ => {
                        return Err(sahayak_persistence::PersistenceError::InvalidCommand(
                            "professional consent prompt has no document-set binding".to_owned(),
                        ));
                    }
                };
                if rendered_digest != document_set_digest {
                    return Err(sahayak_persistence::PersistenceError::OptimisticConflict);
                }
                ProfessionalTurnOperation::AppendRequiredConsents {
                    acceptances,
                    document_set_digest,
                    prompt_session_id,
                    prompt_outbound_message_id,
                }
            }
            ProfessionalCommand::SubmitForReview {
                expected_version, ..
            } => {
                if *expected_version != target.expected_revision_version {
                    return Err(sahayak_persistence::PersistenceError::InvalidCommand(
                        "profile submission version is stale".to_owned(),
                    ));
                }
                ProfessionalTurnOperation::SubmitCompleteDraft
            }
            ProfessionalCommand::ConfirmDisplayName { .. } | ProfessionalCommand::SkipPhoto => {
                return Ok(None);
            }
        };
        Ok(Some(ProfessionalTurnEffect {
            profile_id: target.profile_id,
            revision_id: target.revision_id,
            expected_revision_version: target.expected_revision_version,
            operation,
        }))
    }

    async fn required_consent_acceptances(
        &self,
        summary: &sahayak_persistence::ProfessionalConversationSummary,
        locale: Locale,
        accepted_at: OffsetDateTime,
    ) -> Result<Vec<ProfessionalConsentAcceptance>, sahayak_persistence::PersistenceError> {
        let mut required = vec![
            ProfessionalConsentPurpose::Terms,
            ProfessionalConsentPurpose::Privacy,
            ProfessionalConsentPurpose::ContactDisclosure,
        ];
        if summary
            .services
            .iter()
            .any(|service| service.contact_mode == ContactMode::Direct)
        {
            required.push(ProfessionalConsentPurpose::DirectContact);
        }
        if summary.has_ready_photo {
            required.push(ProfessionalConsentPurpose::PhotoDisclosure);
        }
        let consent_locale = map_professional_language(locale);
        let documents = ProfessionalConsentRepository::new(self.database.clone())
            .current_documents(consent_locale)
            .await?;
        required
            .into_iter()
            .map(|purpose| {
                let document = documents
                    .iter()
                    .find(|document| document.purpose == purpose)
                    .ok_or_else(|| {
                        sahayak_persistence::PersistenceError::Invariant(
                            "required current consent document is missing".to_owned(),
                        )
                    })?;
                Ok(ProfessionalConsentAcceptance {
                    id: ProfessionalConsentEventId::new(),
                    purpose,
                    document_version: document.version.clone(),
                    document_sha256: document.sha256,
                    locale: consent_locale,
                    accepted_at,
                })
            })
            .collect()
    }

    async fn render_current_consent_prompt(
        &self,
        plan: &mut TurnPlan,
        snapshot: Option<&ProfessionalConversationSnapshot>,
        current_session: Option<&SessionSnapshot>,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        let locale = match &plan.session_change {
            SessionChange::Create {
                next:
                    ConversationState::Professional(
                        sahayak_conversation_engine::ProfessionalState::Consent { .. },
                    ),
                locale,
            }
            | SessionChange::Replace {
                next:
                    ConversationState::Professional(
                        sahayak_conversation_engine::ProfessionalState::Consent { .. },
                    ),
                locale,
                ..
            } => Some(*locale),
            SessionChange::Advance {
                next:
                    ConversationState::Professional(
                        sahayak_conversation_engine::ProfessionalState::Consent { .. },
                    ),
                ..
            } => current_session.map(|session| session.locale),
            _ => None,
        };
        let Some(locale) = locale else {
            return Ok(());
        };
        let summary = snapshot
            .and_then(|value| value.summary.as_ref())
            .ok_or_else(|| {
                sahayak_persistence::PersistenceError::Invariant(
                    "consent prompt requires a current professional summary".to_owned(),
                )
            })?;
        let acceptances = self
            .required_consent_acceptances(summary, locale, OffsetDateTime::UNIX_EPOCH)
            .await?;
        let document_set_digest =
            sahayak_persistence::professional_consent_document_set_digest(&acceptances);
        let documents = ProfessionalConsentRepository::new(self.database.clone())
            .current_documents(map_professional_language(locale))
            .await?;
        let mut rendered = Vec::with_capacity(acceptances.len());
        for acceptance in acceptances {
            let document = documents
                .iter()
                .find(|document| {
                    document.purpose == acceptance.purpose
                        && document.version == acceptance.document_version
                        && document.sha256 == acceptance.document_sha256
                })
                .ok_or_else(|| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "consent prompt document changed while rendering".to_owned(),
                    )
                })?;
            rendered.push(document.text.as_str());
        }
        let body = rendered.join("\n\n");
        if body.encode_utf16().count() > 1_024 {
            return Err(sahayak_persistence::PersistenceError::Invariant(
                "localized consent prompt exceeds 1024 body units".to_owned(),
            ));
        }
        plan.reply.body = body;
        bind_consent_document_set(&mut plan.session_change, document_set_digest)?;
        Ok(())
    }

    async fn map_administrator_effect(
        &self,
        command: &AdminCommand,
        snapshot: Option<&AdministratorConversationSnapshot>,
        session: Option<&SessionSnapshot>,
        inbound_event_id: sahayak_domain::InboundEventId,
        reviewer: (AccountId, ChannelIdentityId),
    ) -> Result<
        (AdministratorReviewTurnEffect, QueueOutboundMessage),
        sahayak_persistence::PersistenceError,
    > {
        let AdminCommand::ReviewProfile {
            target,
            expected_version,
            decision,
            reason,
        } = command;
        let selected = snapshot
            .and_then(|value| value.selected.as_ref())
            .filter(|value| {
                value.review_token == target.as_str() && value.target.version == *expected_version
            })
            .ok_or_else(|| sahayak_persistence::PersistenceError::OptimisticConflict)?;
        let session = session.ok_or_else(|| {
            sahayak_persistence::PersistenceError::Invariant(
                "administrator review session is missing".to_owned(),
            )
        })?;
        if !matches!(
            session.state,
            ConversationState::Administrator(AdminState::Confirm { .. })
        ) {
            return Err(sahayak_persistence::PersistenceError::InvalidCommand(
                "administrator review is not bound to a confirmation prompt".to_owned(),
            ));
        }
        let prompt_outbound_message_id = session.expected_reply_to.ok_or_else(|| {
            sahayak_persistence::PersistenceError::InvalidCommand(
                "administrator confirmation prompt is missing".to_owned(),
            )
        })?;
        let notification_target = ProfessionalProfileRepository::new(self.database.clone())
            .load_active_whatsapp_notification_target(
                selected.target.revision_id,
                reviewer.0,
                reviewer.1,
                &self.provider_namespace,
            )
            .await?
            .filter(|value| value.provider_namespace == self.provider_namespace)
            .ok_or_else(|| {
                sahayak_persistence::PersistenceError::InvalidCommand(
                    "professional review notification target is unavailable".to_owned(),
                )
            })?;
        let decrypted_phone = self
            .cryptography
            .decrypt(
                EncryptionContext::new(
                    EncryptionNamespace::WHATSAPP_PHONE_E164,
                    notification_target.channel_identity_id.into_uuid(),
                ),
                &notification_target.encrypted_phone_e164,
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "professional notification phone authentication failed".to_owned(),
                )
            })?;
        let phone_text = std::str::from_utf8(&decrypted_phone).map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "professional notification phone encoding is invalid".to_owned(),
            )
        })?;
        let recipient = NormalizedPhoneNumber::parse(phone_text).map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "professional notification phone is invalid".to_owned(),
            )
        })?;
        let ordering_key = self
            .cryptography
            .blind_index(
                "integration:whatsapp:conversation-order:v1",
                recipient.expose().trim_start_matches('+').as_bytes(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "professional notification ordering key failed".to_owned(),
                )
            })?
            .1;
        let locale = Locale::parse(&notification_target.locale).unwrap_or(Locale::EnIn);
        let localizer = Localizer::load().map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "professional notification localization failed".to_owned(),
            )
        })?;
        let notification_key = match decision {
            AdminReviewDecision::Approve => MessageKey::PRO_STATUS_APPROVED_BODY,
            AdminReviewDecision::ChangesRequested => MessageKey::PRO_STATUS_CHANGES_BODY,
            AdminReviewDecision::Reject => MessageKey::PRO_STATUS_REJECTED_BODY,
        };
        let notification = self.prepare_queue_outbound(
            OutboundMessage::text(
                &recipient,
                TextMessage::new(localizer.text(locale, notification_key), false).map_err(
                    |_| {
                        sahayak_persistence::PersistenceError::Invariant(
                            "professional notification text is invalid".to_owned(),
                        )
                    },
                )?,
            ),
            notification_target.provider_namespace,
            Some(notification_target.channel_identity_id),
            format!(
                "professional-review-outcome:v1:{}",
                selected.target.revision_id
            ),
            session.workflow_correlation_id,
            Some(ordering_key),
        )?;
        let (decision, reason) = map_review_decision(*decision, *reason)?;
        Ok((
            AdministratorReviewTurnEffect {
                id: ProfileReviewDecisionId::new(),
                review_token: selected.review_token.clone(),
                revision_id: selected.target.revision_id,
                expected_version: selected.target.version,
                target_digest: selected.target.target_digest,
                decision,
                reason,
                reason_detail: None,
                idempotency_key: format!(
                    "profile-review-decision:v1:{}:{}:{inbound_event_id}",
                    selected.target.revision_id, selected.target.version
                ),
                prompt_session_id: session.id,
                prompt_outbound_message_id,
            },
            notification,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_turn_commit(
        &self,
        job: &ClaimedJob,
        inbound_event_id: sahayak_domain::InboundEventId,
        identity: (AccountId, ChannelIdentityId),
        turn: &ConversationTurnRecord,
        correlation_id: CorrelationId,
        provider_message_id: &str,
        recipient: &NormalizedPhoneNumber,
        plan: &TurnPlan,
        effects: ConversationTurnEffects,
        administrator_image_header: Option<&str>,
    ) -> Result<CommitConversationTurnWithEffects, sahayak_persistence::PersistenceError> {
        let outbound = render_whatsapp_reply(recipient, &plan.reply, administrator_image_header)?
            .with_context(provider_message_id)
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "conversation reply context is invalid".to_owned(),
                )
            })?;
        let (session_change, workflow_correlation_id) = map_session_change(
            &plan.session_change,
            turn.expired_session,
            turn.active_session
                .as_ref()
                .map(|session| session.workflow_correlation_id),
            turn.database_now,
        )?;
        Ok(CommitConversationTurnWithEffects {
            turn: CommitConversationTurn {
                lease: job.lease(),
                inbound_event_id,
                account_id: identity.0,
                channel_identity_id: identity.1,
                expected_account_version: turn.account.version,
                workflow_correlation_id,
                reply_to_outbound_message_id: turn.resolved_reply_to,
                locale_change: plan.locale_change.map(|locale| locale.as_str().to_owned()),
                session_change,
                outbound: self.prepare_queue_outbound(
                    outbound,
                    self.provider_namespace.clone(),
                    Some(identity.1),
                    format!("conversation-turn:v1:{inbound_event_id}"),
                    correlation_id,
                    job.ordering_key,
                )?,
                disposition: map_disposition(plan.disposition),
            },
            effects,
        })
    }

    fn prepare_queue_outbound(
        &self,
        message: OutboundMessage,
        provider_namespace: String,
        recipient_channel_identity_id: Option<ChannelIdentityId>,
        idempotency_key: String,
        correlation_id: CorrelationId,
        ordering_key: Option<[u8; 32]>,
    ) -> Result<QueueOutboundMessage, sahayak_persistence::PersistenceError> {
        let outbound_id = OutboundMessageId::new();
        let callback = CallbackToken::new();
        let fingerprint_payload = message.prepare().map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "outbound fingerprint serialization failed".to_owned(),
            )
        })?;
        let prepared = message
            .with_callback_data(&callback.to_string())
            .and_then(|message| message.prepare())
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "outbound serialization failed".to_owned(),
                )
            })?;
        let encrypted = self
            .cryptography
            .encrypt(
                EncryptionPurpose::Integration,
                EncryptionContext::new(
                    EncryptionNamespace::OUTBOUND_MESSAGE_PAYLOAD,
                    outbound_id.into_uuid(),
                ),
                prepared.expose(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "outbound encryption failed".to_owned(),
                )
            })?;
        let active_lookup_version = self.cryptography.active_lookup_version();
        let fingerprints = self
            .cryptography
            .all_blind_indexes(
                "messaging:whatsapp:outbound_request:v1",
                fingerprint_payload.expose(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "outbound fingerprint failed".to_owned(),
                )
            })?;
        let (fingerprint_key_version, request_fingerprint) = fingerprints
            .iter()
            .find(|(version, _)| *version == active_lookup_version)
            .copied()
            .ok_or_else(|| {
                sahayak_persistence::PersistenceError::Invariant(
                    "outbound active fingerprint is missing".to_owned(),
                )
            })?;
        let additional_fingerprints = fingerprints
            .into_iter()
            .filter(|(version, _)| *version != active_lookup_version)
            .map(|(key_version, digest)| LookupDigest {
                key_version,
                digest,
            })
            .collect();
        Ok(QueueOutboundMessage {
            id: outbound_id,
            provider_namespace,
            recipient_channel_identity_id,
            idempotency_key,
            payload: EncryptedOutboundPayload {
                schema_version: 1,
                encrypted,
                fingerprint_key_version,
                request_fingerprint,
                additional_fingerprints,
            },
            callback_token: callback,
            correlation_id,
            ordering_key,
            send_job_id: OutboxJobId::new(),
            max_attempts: 8,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn recover_rejected_turn(
        &self,
        job: &ClaimedJob,
        inbound_event_id: sahayak_domain::InboundEventId,
        identity: (AccountId, ChannelIdentityId),
        turn: &ConversationTurnRecord,
        correlation_id: CorrelationId,
        provider_message_id: &str,
        recipient: &NormalizedPhoneNumber,
        context: &ConversationContext,
        availability_command: bool,
        error_code: &str,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        let mut latest_context = context.clone();
        let recovery_input = if availability_command && latest_context.session.is_some() {
            let availability = AvailabilityRepository::new(self.database.clone())
                .load_conversation_snapshot(identity.0, identity.1, &self.provider_namespace)
                .await?;
            latest_context.availability = map_availability_view(&availability)?;
            let session = latest_context.session.as_mut().ok_or_else(|| {
                sahayak_persistence::PersistenceError::Invariant(
                    "availability recovery session is missing".to_owned(),
                )
            })?;
            session.state = ConversationState::Availability(AvailabilityState::Changed {
                outcome: AvailabilityOutcome::Stopped,
            });
            UserInput::Action {
                id: ActionId::parse("availability.view_status").map_err(|_| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "availability recovery action is invalid".to_owned(),
                    )
                })?,
                reply_to: session.expected_reply_to,
            }
        } else {
            let recovery_input = sahayak_conversation_engine::NormalizedText::parse("menu")
                .map_err(|_| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "safe conversation recovery input is invalid".to_owned(),
                    )
                })?;
            UserInput::Text(recovery_input)
        };
        let mut recovery = self
            .engine
            .decide(&latest_context, &recovery_input)
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "conversation recovery decision failed".to_owned(),
                )
            })?;
        let recovery_key = match error_code {
            "customer_limit_reached" => Some(MessageKey::CONNECTION_CUSTOMER_LIMIT_BODY),
            "professional_capacity_reached" => Some(MessageKey::CONNECTION_CAPACITY_BODY),
            _ => None,
        };
        if let Some(key) = recovery_key {
            let locale = latest_context
                .session
                .as_ref()
                .map_or(Locale::EnIn, |session| session.locale);
            let prefix = Localizer::load()
                .map_err(|_| {
                    sahayak_persistence::PersistenceError::Invariant(
                        "connection recovery localization failed".to_owned(),
                    )
                })?
                .text(locale, key)
                .to_owned();
            recovery.reply.body = format!("{prefix}\n\n{}", recovery.reply.body);
        }
        recovery.disposition = ConversationDisposition::Recovered;
        let effects = ConversationTurnEffects {
            effect: None,
            role_context: Some(role_for_session_change(&recovery.session_change)),
            additional_outbound: Vec::new(),
        };
        let commit = self.build_turn_commit(
            job,
            inbound_event_id,
            identity,
            turn,
            correlation_id,
            provider_message_id,
            recipient,
            &recovery,
            effects,
            None,
        )?;
        match self.conversations.commit_effectful(&commit).await? {
            EffectfulTurnCommitOutcome::Committed { .. }
            | EffectfulTurnCommitOutcome::AlreadyCommitted { .. }
            | EffectfulTurnCommitOutcome::LostLease => Ok(()),
            EffectfulTurnCommitOutcome::ServiceWindowExpired => {
                self.reject_conversation(job, "service_window_expired")
                    .await
            }
            EffectfulTurnCommitOutcome::Conflict
            | EffectfulTurnCommitOutcome::Unauthorized
            | EffectfulTurnCommitOutcome::AlreadyDecided
            | EffectfulTurnCommitOutcome::Incomplete
            | EffectfulTurnCommitOutcome::CustomerLimit
            | EffectfulTurnCommitOutcome::ProfessionalCapacity => {
                self.reject_conversation(job, error_code).await
            }
        }
    }

    async fn process_conversation_with_failure_policy(
        &self,
        job: &ClaimedJob,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        match self.process_conversation(job).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let disposition = if error.is_retryable_transaction() {
                    FailureDisposition::Retry {
                        error_class: "database".to_owned(),
                        error_code: "conversation_transaction_retry".to_owned(),
                        after: Duration::from_secs(1),
                    }
                } else {
                    FailureDisposition::Terminal {
                        error_class: "local_invariant".to_owned(),
                        error_code: "conversation_processing_failed".to_owned(),
                    }
                };
                let _ = self
                    .outbox
                    .record_failure(job.lease(), &disposition)
                    .await?;
                warn!(job_id = %job.id, %error, "conversation message was not committed");
                Ok(())
            }
        }
    }

    async fn resolve_identity(
        &self,
        inbound_event_id: sahayak_domain::InboundEventId,
        sender_wa_id: &str,
        sender_phone_e164: &str,
        correlation_id: CorrelationId,
        provider_observed_at: OffsetDateTime,
    ) -> Result<(AccountId, ChannelIdentityId), sahayak_persistence::PersistenceError> {
        let phone = NormalizedPhoneNumber::parse(sender_phone_e164).map_err(|_| {
            sahayak_persistence::PersistenceError::InvalidCommand(
                "sender is not a canonical Indian mobile number".to_owned(),
            )
        })?;
        let account_id = AccountId::new();
        let channel_identity_id = ChannelIdentityId::new();
        let encrypted_wa_id = self
            .cryptography
            .encrypt(
                EncryptionPurpose::Contact,
                EncryptionContext::new(
                    EncryptionNamespace::WHATSAPP_WA_ID,
                    channel_identity_id.into_uuid(),
                ),
                sender_wa_id.as_bytes(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "WhatsApp ID encryption failed".to_owned(),
                )
            })?;
        let encrypted_phone = self
            .cryptography
            .encrypt(
                EncryptionPurpose::Contact,
                EncryptionContext::new(
                    EncryptionNamespace::WHATSAPP_PHONE_E164,
                    channel_identity_id.into_uuid(),
                ),
                phone.expose().as_bytes(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "phone encryption failed".to_owned(),
                )
            })?;
        let wa_digests = lookup_digests(
            &self.cryptography,
            &format!("whatsapp:{}:wa_id", self.provider_namespace),
            sender_wa_id.as_bytes(),
        )?;
        let binding_digests = wa_digests.clone();
        let phone_digests = lookup_digests(
            &self.cryptography,
            &format!("whatsapp:{}:phone_e164", self.provider_namespace),
            phone.expose().as_bytes(),
        )?;
        let active_lookup_key_version = self.cryptography.active_lookup_version();
        let resolved = self
            .identity
            .resolve_or_create_whatsapp_account(
                &NewWhatsAppAccount {
                    account_id,
                    channel_identity_id,
                    correlation_id,
                    provider_namespace: self.provider_namespace.clone(),
                    preferred_locale: "en-IN".to_owned(),
                    time_zone: "Asia/Kolkata".to_owned(),
                    encrypted_wa_id,
                    encrypted_phone_e164: encrypted_phone,
                    wa_id_digests: wa_digests,
                    phone_e164_digests: phone_digests,
                    active_lookup_key_version,
                },
                provider_observed_at,
            )
            .await?;
        let resolved = match resolved {
            ResolveIdentityOutcome::Created(identity)
            | ResolveIdentityOutcome::Existing(identity) => identity,
        };
        self.database
            .bind_inbound_event_identity(
                inbound_event_id,
                resolved.account_id,
                resolved.channel_identity_id,
                &binding_digests,
            )
            .await?;
        Ok((resolved.account_id, resolved.channel_identity_id))
    }

    async fn reject_conversation(
        &self,
        job: &ClaimedJob,
        error_code: &str,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        let _ = self
            .outbox
            .record_failure(
                job.lease(),
                &FailureDisposition::Terminal {
                    error_class: "local_invariant".to_owned(),
                    error_code: error_code.to_owned(),
                },
            )
            .await?;
        Ok(())
    }

    async fn process_probe(
        &self,
        job: &ClaimedJob,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        let Some(event_id) = job.inbound_event_id else {
            return self.reject_probe(job, "missing_probe_event").await;
        };
        let Some(encrypted) = self.database.find_encrypted_inbound_event(event_id).await? else {
            return self.reject_probe(job, "probe_event_not_found").await;
        };
        let decrypted = self
            .cryptography
            .decrypt(
                EncryptionContext::new(
                    EncryptionNamespace::INBOUND_EVENT_PAYLOAD,
                    event_id.into_uuid(),
                ),
                &encrypted.payload,
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "transport probe authentication failed".to_owned(),
                )
            })?;
        let event: NormalizedEvent = serde_json::from_slice(&decrypted).map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "transport probe payload schema is invalid".to_owned(),
            )
        })?;
        let NormalizedPayload::Message {
            sender_phone_e164,
            content: NormalizedContent::Text { body },
            ..
        } = event.payload
        else {
            return self.reject_probe(job, "unexpected_probe_payload").await;
        };
        if body != "__sahayak_transport_probe__" {
            return self.reject_probe(job, "invalid_probe_text").await;
        }
        let recipient = NormalizedPhoneNumber::parse(&sender_phone_e164).map_err(|_| {
            sahayak_persistence::PersistenceError::InvalidCommand(
                "transport probe sender is not a valid Indian mobile number".to_owned(),
            )
        })?;
        let outbound_id = OutboundMessageId::new();
        let callback = CallbackToken::new();
        let base_message = OutboundMessage::text(
            &recipient,
            TextMessage::new("Sahayak transport is ready.", false).map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "transport probe response is invalid".to_owned(),
                )
            })?,
        );
        let fingerprint_payload = base_message.prepare().map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "transport probe fingerprint serialization failed".to_owned(),
            )
        })?;
        let prepared = base_message
            .with_callback_data(&callback.to_string())
            .and_then(|message| message.prepare())
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "transport probe serialization failed".to_owned(),
                )
            })?;
        let encrypted_payload = self
            .cryptography
            .encrypt(
                EncryptionPurpose::Integration,
                EncryptionContext::new(
                    EncryptionNamespace::OUTBOUND_MESSAGE_PAYLOAD,
                    outbound_id.into_uuid(),
                ),
                prepared.expose(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "transport probe encryption failed".to_owned(),
                )
            })?;
        let active_lookup_version = self.cryptography.active_lookup_version();
        let fingerprints = self
            .cryptography
            .all_blind_indexes(
                "messaging:whatsapp:outbound_request:v1",
                fingerprint_payload.expose(),
            )
            .map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "transport probe fingerprint failed".to_owned(),
                )
            })?;
        let (fingerprint_key_version, request_fingerprint) = fingerprints
            .iter()
            .find(|(version, _)| *version == active_lookup_version)
            .copied()
            .ok_or_else(|| {
                sahayak_persistence::PersistenceError::Invariant(
                    "transport probe active fingerprint is missing".to_owned(),
                )
            })?;
        let additional_fingerprints = fingerprints
            .into_iter()
            .filter(|(version, _)| *version != active_lookup_version)
            .map(|(key_version, digest)| sahayak_persistence::LookupDigest {
                key_version,
                digest,
            })
            .collect();
        let queue_outcome = self
            .outbound
            .queue(&QueueOutboundMessage {
                id: outbound_id,
                provider_namespace: self.provider_namespace.clone(),
                recipient_channel_identity_id: None,
                idempotency_key: format!("transport_probe:{event_id}"),
                payload: EncryptedOutboundPayload {
                    schema_version: 1,
                    encrypted: encrypted_payload,
                    fingerprint_key_version,
                    request_fingerprint,
                    additional_fingerprints,
                },
                callback_token: callback,
                correlation_id: encrypted.correlation_id,
                ordering_key: job.ordering_key,
                send_job_id: OutboxJobId::new(),
                max_attempts: 8,
            })
            .await?;
        if matches!(
            queue_outcome,
            OutboundQueueOutcome::IdentifierCollision { .. }
        ) {
            return self.reject_probe(job, "probe_response_collision").await;
        }
        let _ = self.outbox.complete(job.lease()).await?;
        Ok(())
    }

    async fn reject_probe(
        &self,
        job: &ClaimedJob,
        error_code: &str,
    ) -> Result<(), sahayak_persistence::PersistenceError> {
        let _ = self
            .outbox
            .record_failure(
                job.lease(),
                &FailureDisposition::Terminal {
                    error_class: "local_invariant".to_owned(),
                    error_code: error_code.to_owned(),
                },
            )
            .await?;
        Ok(())
    }
}

enum PhotoResolution {
    Ready(ProfessionalTurnOperation),
    PermanentFailure,
    RetryScheduled,
}

enum AdministratorPhotoResolution {
    Header(String),
    None,
    Unavailable,
    RetryScheduled,
}

struct PreparedConnectionTurn {
    effect: ConnectionTurnEffect,
    primary_body: String,
    additional_outbound: Vec<QueueOutboundMessage>,
    next_connection: Option<(String, i64)>,
}

struct ProfessionalEffectTarget {
    profile_id: PublicProfileId,
    revision_id: ProfileRevisionId,
    expected_revision_version: Option<i64>,
}

fn selected_admin_token(session: &SessionSnapshot) -> Option<&str> {
    match &session.state {
        ConversationState::Administrator(AdminState::Inspect { target, .. })
        | ConversationState::Administrator(AdminState::Reason { target, .. })
        | ConversationState::Administrator(AdminState::Confirm { target, .. }) => {
            Some(target.as_str())
        }
        _ => None,
    }
}

fn administrator_command_is_stale(
    plan: &TurnPlan,
    snapshot: Option<&AdministratorConversationSnapshot>,
) -> bool {
    let Some(BusinessCommand::Administrator(AdminCommand::ReviewProfile {
        target,
        expected_version,
        ..
    })) = plan.business_command.as_ref()
    else {
        return false;
    };
    snapshot
        .and_then(|value| value.selected.as_ref())
        .is_none_or(|selected| {
            selected.review_token != target.as_str() || selected.target.version != *expected_version
        })
}

fn map_professional_view(
    snapshot: Option<&ProfessionalConversationSnapshot>,
) -> Result<ProfessionalView, sahayak_persistence::PersistenceError> {
    let Some(snapshot) = snapshot else {
        return Ok(ProfessionalView::default());
    };
    let requested_changes = snapshot
        .requested_change_fields
        .iter()
        .map(|field| {
            ProfileFieldCode::parse(field).ok_or_else(|| {
                sahayak_persistence::PersistenceError::Invariant(
                    "professional change request contains an unsupported field".to_owned(),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let summary = snapshot
        .summary
        .as_ref()
        .map(map_professional_summary)
        .transpose()?;
    Ok(ProfessionalView {
        status: match snapshot.status {
            ProfessionalConversationStatus::NotStarted => ProfessionalStatus::NotStarted,
            ProfessionalConversationStatus::Draft => ProfessionalStatus::Draft,
            ProfessionalConversationStatus::PendingReview => ProfessionalStatus::PendingReview,
            ProfessionalConversationStatus::ChangesRequested => {
                ProfessionalStatus::ChangesRequested
            }
            ProfessionalConversationStatus::Approved => ProfessionalStatus::Approved,
            ProfessionalConversationStatus::Rejected => ProfessionalStatus::Rejected,
            ProfessionalConversationStatus::Hidden => ProfessionalStatus::Hidden,
        },
        version: snapshot.version,
        summary,
        resume_step: professional_resume_step(snapshot),
        requested_changes,
        review_reason: snapshot
            .review_reason
            .as_deref()
            .map(map_review_reason_code)
            .transpose()?,
        accepted_consent_version: snapshot
            .current_consent_version
            .as_deref()
            .and_then(parse_engine_consent_version),
    })
}

fn map_availability_view(
    snapshot: &AvailabilityConversationSnapshot,
) -> Result<AvailabilityView, sahayak_persistence::PersistenceError> {
    match snapshot {
        AvailabilityConversationSnapshot::Ineligible(reason) => {
            Ok(AvailabilityView::Ineligible(match reason {
                AvailabilityIneligibility::ProfessionalRoleRequired => {
                    EngineAvailabilityIneligibility::ProfessionalRoleRequired
                }
                AvailabilityIneligibility::ApprovedProfileRequired => {
                    EngineAvailabilityIneligibility::ProfileApprovalRequired
                }
                AvailabilityIneligibility::AccountUnavailable => {
                    EngineAvailabilityIneligibility::AccountSuspended
                }
                AvailabilityIneligibility::InvalidTimeZone => {
                    EngineAvailabilityIneligibility::InvalidTimeZone
                }
                AvailabilityIneligibility::MutationThrottled => {
                    EngineAvailabilityIneligibility::TooManyChanges
                }
            }))
        }
        AvailabilityConversationSnapshot::Unavailable => Ok(AvailabilityView::Unavailable),
        AvailabilityConversationSnapshot::Current(epoch) => {
            let generation = u32::try_from(epoch.generation).map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "availability generation exceeds conversation bounds".to_owned(),
                )
            })?;
            let contacts_used = u8::try_from(epoch.contact_count).map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "availability contact count exceeds conversation bounds".to_owned(),
                )
            })?;
            let contact_limit = u8::try_from(epoch.contact_limit).map_err(|_| {
                sahayak_persistence::PersistenceError::Invariant(
                    "availability contact limit exceeds conversation bounds".to_owned(),
                )
            })?;
            let view = AvailabilityEpochView {
                generation,
                version: epoch.version,
                local_expiry: AvailabilityLocalExpiry {
                    year: epoch.expires_local.year,
                    month: epoch.expires_local.month,
                    day: epoch.expires_local.day,
                    hour: epoch.expires_local.hour,
                    minute: epoch.expires_local.minute,
                },
                contacts_used,
                contact_limit,
                successor: epoch
                    .successor_duration
                    .map(map_availability_duration_to_engine),
            };
            Ok(match epoch.state {
                AvailabilityEpochState::Available | AvailabilityEpochState::Scheduled => {
                    AvailabilityView::Available(view)
                }
                AvailabilityEpochState::Stopped => AvailabilityView::Stopped(view),
                AvailabilityEpochState::PausedContactLimit => {
                    AvailabilityView::CapacityPaused(view)
                }
                AvailabilityEpochState::Expired => AvailabilityView::Expired(view),
                AvailabilityEpochState::CancelledManual
                | AvailabilityEpochState::CancelledIneligible => AvailabilityView::Unavailable,
            })
        }
    }
}

fn map_discovery_view(
    snapshot: &DiscoveryConversationSnapshot,
) -> Result<DiscoveryView, sahayak_persistence::PersistenceError> {
    let DiscoveryConversationSnapshot::Current(request) = snapshot else {
        return Ok(DiscoveryView::default());
    };
    let status = match request.state {
        sahayak_domain::ServiceRequestState::Draft
        | sahayak_domain::ServiceRequestState::Collecting => DiscoveryStatus::Collecting,
        sahayak_domain::ServiceRequestState::Searching
        | sahayak_domain::ServiceRequestState::ShowingResults => DiscoveryStatus::Results,
        sahayak_domain::ServiceRequestState::NoResults => DiscoveryStatus::NoResults,
        sahayak_domain::ServiceRequestState::Selected => DiscoveryStatus::Waiting,
        sahayak_domain::ServiceRequestState::Connected => DiscoveryStatus::Connected,
        sahayak_domain::ServiceRequestState::Cancelled
        | sahayak_domain::ServiceRequestState::Expired => DiscoveryStatus::None,
    };
    let category = Some(map_service_category(&request.category_code)?);
    let cards = request
        .cards
        .iter()
        .map(|card| {
            Ok(DiscoveryCardView {
                candidate_token: card.candidate_token.clone(),
                display_name: card.display_name.clone(),
                public_reference: card.public_reference.clone(),
                category: map_service_category(&card.category_code)?,
                distance_label: card.distance_label.clone(),
                language_compatible: card.language_compatible,
                availability_label: card.availability_label.clone(),
                identity_checked: card.identity_checked,
                contact_mode: match card.contact_mode.as_str() {
                    "direct" => EngineContactMode::Direct,
                    "approval_required" => EngineContactMode::ApprovalRequired,
                    _ => {
                        return Err(sahayak_persistence::PersistenceError::Invariant(
                            "candidate contact mode is invalid".to_owned(),
                        ));
                    }
                },
            })
        })
        .collect::<Result<Vec<_>, sahayak_persistence::PersistenceError>>()?;
    Ok(DiscoveryView {
        status,
        request_token: Some(request.request_token.clone()),
        version: Some(request.version),
        category,
        radius_km: u8::try_from(request.radius_km).ok(),
        has_more: request.has_more,
        cards,
    })
}

fn map_connections_view(
    pending: &[PendingConnectionSummary],
    recent: &[RecentContactSummary],
    customer_pending: Option<&PendingCustomerConnection>,
) -> Result<ConnectionsView, sahayak_persistence::PersistenceError> {
    Ok(ConnectionsView {
        pending: pending
            .iter()
            .map(|request| {
                Ok(PendingConnectionView {
                    request_token: request.request_token.clone(),
                    version: request.version,
                    category: map_service_category(&request.category_code)?,
                    issue_code: request.issue_code.clone(),
                    requested_time: request.requested_time.clone(),
                    distance_label: request.distance_label.clone(),
                })
            })
            .collect::<Result<Vec<_>, sahayak_persistence::PersistenceError>>()?,
        recent: recent
            .iter()
            .map(|contact| {
                Ok(RecentContactView {
                    reveal_token: contact.reveal_token.clone(),
                    display_name: contact.display_name.clone(),
                    public_reference: contact.public_reference.clone(),
                    category: map_service_category(&contact.category_code)?,
                })
            })
            .collect::<Result<Vec<_>, sahayak_persistence::PersistenceError>>()?,
        customer_pending: customer_pending.map(|pending| PendingCustomerConnectionView {
            request_token: pending.request_token.clone(),
            version: pending.version,
        }),
    })
}

fn map_service_category(
    value: &str,
) -> Result<ServiceCategory, sahayak_persistence::PersistenceError> {
    match value {
        "plumber" => Ok(ServiceCategory::Plumber),
        "electrician" => Ok(ServiceCategory::Electrician),
        _ => Err(sahayak_persistence::PersistenceError::Invariant(
            "service category is invalid".to_owned(),
        )),
    }
}

fn map_availability_duration_to_engine(value: AvailabilityDuration) -> EngineAvailabilityDuration {
    match value {
        AvailabilityDuration::OneHour => EngineAvailabilityDuration::OneHour,
        AvailabilityDuration::FourHours => EngineAvailabilityDuration::FourHours,
        AvailabilityDuration::EndOfLocalDay => EngineAvailabilityDuration::EndOfLocalDay,
    }
}

fn map_availability_duration(value: EngineAvailabilityDuration) -> AvailabilityDuration {
    match value {
        EngineAvailabilityDuration::OneHour => AvailabilityDuration::OneHour,
        EngineAvailabilityDuration::FourHours => AvailabilityDuration::FourHours,
        EngineAvailabilityDuration::EndOfLocalDay => AvailabilityDuration::EndOfLocalDay,
    }
}

const fn empty_connection_outbounds() -> ConnectionOutboundIds {
    ConnectionOutboundIds {
        customer_contact: None,
        professional_contact: None,
        professional_notification: None,
        photo: None,
    }
}

fn distance_label_for_metres(distance: i32) -> &'static str {
    if distance < 1_000 {
        "under 1 km"
    } else if distance < 5_000 {
        "under 5 km"
    } else if distance < 10_000 {
        "under 10 km"
    } else {
        "10 km or farther"
    }
}

fn map_availability_effect(
    command: &AvailabilityCommand,
) -> Result<AvailabilityTurnEffect, sahayak_persistence::PersistenceError> {
    let operation = match command {
        AvailabilityCommand::Start { duration, expected } => {
            let valid_observation = match expected.state {
                AvailabilityObservationState::Unavailable => {
                    expected.generation.is_none() && expected.version.is_none()
                }
                AvailabilityObservationState::Expired => {
                    expected.generation.is_some() && expected.version.is_some()
                }
                _ => false,
            };
            if !valid_observation {
                return Err(sahayak_persistence::PersistenceError::InvalidCommand(
                    "availability start expected an unavailable observation".to_owned(),
                ));
            }
            AvailabilityTurnOperation::Start {
                epoch_id: AvailabilityEpochId::new(),
                duration: map_availability_duration(*duration),
            }
        }
        AvailabilityCommand::Resume { expected } => AvailabilityTurnOperation::Resume {
            expected_generation: i64::from(expected.generation.ok_or_else(|| {
                sahayak_persistence::PersistenceError::InvalidCommand(
                    "availability resume generation is missing".to_owned(),
                )
            })?),
            expected_version: expected.version.ok_or_else(|| {
                sahayak_persistence::PersistenceError::InvalidCommand(
                    "availability resume version is missing".to_owned(),
                )
            })?,
        },
        AvailabilityCommand::Stop { expected } => AvailabilityTurnOperation::Stop {
            expected_generation: i64::from(expected.generation.ok_or_else(|| {
                sahayak_persistence::PersistenceError::InvalidCommand(
                    "availability stop generation is missing".to_owned(),
                )
            })?),
            expected_version: expected.version.ok_or_else(|| {
                sahayak_persistence::PersistenceError::InvalidCommand(
                    "availability stop version is missing".to_owned(),
                )
            })?,
        },
        AvailabilityCommand::Renew { duration, expected } => AvailabilityTurnOperation::Renew {
            successor_epoch_id: AvailabilityEpochId::new(),
            duration: map_availability_duration(*duration),
            expected_generation: i64::from(expected.generation.ok_or_else(|| {
                sahayak_persistence::PersistenceError::InvalidCommand(
                    "availability renewal generation is missing".to_owned(),
                )
            })?),
            expected_version: expected.version.ok_or_else(|| {
                sahayak_persistence::PersistenceError::InvalidCommand(
                    "availability renewal version is missing".to_owned(),
                )
            })?,
        },
    };
    Ok(AvailabilityTurnEffect { operation })
}

fn map_discovery_effect(
    command: &DiscoveryCommand,
    content: &NormalizedContent,
) -> Result<DiscoveryTurnEffect, sahayak_persistence::PersistenceError> {
    let parse_token = |value: &str| {
        uuid::Uuid::parse_str(value).map_err(|_| {
            sahayak_persistence::PersistenceError::InvalidCommand(
                "discovery token is invalid".to_owned(),
            )
        })
    };
    let operation = match command {
        DiscoveryCommand::Begin { category } => DiscoveryTurnOperation::Begin {
            request_id: sahayak_domain::ServiceRequestId::new(),
            request_token: uuid::Uuid::new_v4(),
            category: match category {
                ServiceCategory::Plumber => DiscoveryCategory::Plumber,
                ServiceCategory::Electrician => DiscoveryCategory::Electrician,
            },
        },
        DiscoveryCommand::CurrentInboundLocation {
            request_token,
            expected_version,
        } => {
            let NormalizedContent::Location {
                latitude,
                longitude,
                ..
            } = content
            else {
                return Err(sahayak_persistence::PersistenceError::InvalidCommand(
                    "discovery location command requires location input".to_owned(),
                ));
            };
            DiscoveryTurnOperation::CaptureLocation {
                request_token: parse_token(request_token)?,
                expected_version: *expected_version,
                latitude: *latitude,
                longitude: *longitude,
            }
        }
        DiscoveryCommand::Search {
            request_token,
            expected_version,
            requested_time,
            issue_code,
        } => DiscoveryTurnOperation::Search {
            request_token: parse_token(request_token)?,
            expected_version: *expected_version,
            requested_time: match requested_time {
                RequestedTimeChoice::Now => sahayak_domain::RequestedTimeWindow::Now,
                RequestedTimeChoice::Today => sahayak_domain::RequestedTimeWindow::Today,
                RequestedTimeChoice::Flexible => sahayak_domain::RequestedTimeWindow::Flexible,
            },
            issue_code: issue_code.clone(),
        },
        DiscoveryCommand::ShowMore {
            request_token,
            expected_version,
        } => DiscoveryTurnOperation::ShowMore {
            request_token: parse_token(request_token)?,
            expected_version: *expected_version,
        },
        DiscoveryCommand::ExpandRadius {
            request_token,
            expected_version,
        } => DiscoveryTurnOperation::ExpandRadius {
            request_token: parse_token(request_token)?,
            expected_version: *expected_version,
        },
        DiscoveryCommand::Cancel {
            request_token,
            expected_version,
        } => DiscoveryTurnOperation::Cancel {
            request_token: parse_token(request_token)?,
            expected_version: *expected_version,
        },
    };
    Ok(DiscoveryTurnEffect { operation })
}

fn map_professional_summary(
    summary: &sahayak_persistence::ProfessionalConversationSummary,
) -> Result<ProfessionalSummary, sahayak_persistence::PersistenceError> {
    let categories = map_categories(&summary.services)?;
    Ok(ProfessionalSummary {
        display_name: summary.display_name.clone().unwrap_or_default(),
        categories,
        skills: map_skills(&summary.services)?,
        local_mode: summary
            .local_service_mode
            .map(map_engine_local_service_mode)
            .unwrap_or(EngineLocalServiceMode::TravelToCustomer),
        radius: summary
            .service_radius
            .map(map_engine_service_radius)
            .unwrap_or(ServiceRadius::Km2),
        service_languages: summary.languages.iter().copied().map(map_locale).collect(),
        contact_preferences: map_contact_preferences(&summary.services)?,
        contact_session_limit: map_engine_contact_limit(summary.contact_request_limit)?,
        photo: if summary.has_ready_photo {
            ProfilePhotoStatus::Present
        } else {
            ProfilePhotoStatus::None
        },
        identity_check: if summary.identity_badge {
            IdentityCheckStatus::Checked
        } else {
            IdentityCheckStatus::NotChecked
        },
    })
}

fn map_administrator_view(
    snapshot: Option<&AdministratorConversationSnapshot>,
) -> Result<AdminView, sahayak_persistence::PersistenceError> {
    let Some(snapshot) = snapshot else {
        return Ok(AdminView::Denied);
    };
    Ok(AdminView::Allowed(AllowedAdminView {
        pending: snapshot
            .pending
            .iter()
            .map(map_admin_queue_item)
            .collect::<Result<Vec<_>, _>>()?,
        selected: snapshot
            .selected
            .as_ref()
            .map(map_admin_queue_item)
            .transpose()?,
    }))
}

fn map_admin_queue_item(
    item: &AdministratorConversationTarget,
) -> Result<AdminQueueItem, sahayak_persistence::PersistenceError> {
    Ok(AdminQueueItem {
        target: OpaqueTargetToken::parse(&item.review_token).map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "administrator target token is invalid".to_owned(),
            )
        })?,
        version: item.target.version,
        summary: map_review_summary(&item.target, item.identity_badge)?,
    })
}

fn map_review_summary(
    target: &ProfileReviewTarget,
    identity_badge: bool,
) -> Result<ProfessionalSummary, sahayak_persistence::PersistenceError> {
    Ok(ProfessionalSummary {
        display_name: target.display_name.clone(),
        categories: map_categories(&target.services)?,
        skills: map_skills(&target.services)?,
        local_mode: map_engine_local_service_mode(target.local_service_mode),
        radius: map_engine_service_radius(target.service_radius),
        service_languages: target.languages.iter().copied().map(map_locale).collect(),
        contact_preferences: map_contact_preferences(&target.services)?,
        contact_session_limit: map_engine_contact_limit(Some(target.contact_request_limit))?,
        photo: if target.has_ready_photo {
            ProfilePhotoStatus::Present
        } else {
            ProfilePhotoStatus::None
        },
        identity_check: if identity_badge {
            IdentityCheckStatus::Checked
        } else {
            IdentityCheckStatus::NotChecked
        },
    })
}

fn map_categories(
    services: &[ProfessionalServiceSnapshot],
) -> Result<CategorySelection, sahayak_persistence::PersistenceError> {
    let mut categories = CategorySelection::default();
    for service in services {
        match service.category_code.as_str() {
            "plumber" if !categories.plumber => categories.plumber = true,
            "electrician" if !categories.electrician => categories.electrician = true,
            "plumber" | "electrician" => {
                return Err(sahayak_persistence::PersistenceError::Invariant(
                    "professional snapshot contains duplicate categories".to_owned(),
                ));
            }
            _ => {
                return Err(sahayak_persistence::PersistenceError::Invariant(
                    "professional snapshot contains an unsupported category".to_owned(),
                ));
            }
        }
    }
    Ok(categories)
}

fn map_skills(
    services: &[ProfessionalServiceSnapshot],
) -> Result<Vec<ServiceSkill>, sahayak_persistence::PersistenceError> {
    services
        .iter()
        .flat_map(|service| service.skill_codes.iter())
        .map(|skill| match skill.as_str() {
            "leak_repair" => Ok(ServiceSkill::LeakRepair),
            "tap_and_fixture" => Ok(ServiceSkill::TapAndFixture),
            "drain_clearing" => Ok(ServiceSkill::DrainClearing),
            "home_wiring" => Ok(ServiceSkill::HomeWiring),
            "switch_and_socket" => Ok(ServiceSkill::SwitchAndSocket),
            "fan_installation" => Ok(ServiceSkill::FanInstallation),
            _ => Err(sahayak_persistence::PersistenceError::Invariant(
                "professional snapshot contains an unsupported skill".to_owned(),
            )),
        })
        .collect()
}

fn map_contact_preferences(
    services: &[ProfessionalServiceSnapshot],
) -> Result<Vec<ServiceContactPreference>, sahayak_persistence::PersistenceError> {
    services
        .iter()
        .map(|service| {
            let category = match service.category_code.as_str() {
                "plumber" => ServiceCategory::Plumber,
                "electrician" => ServiceCategory::Electrician,
                _ => {
                    return Err(sahayak_persistence::PersistenceError::Invariant(
                        "professional contact preference has an unsupported category".to_owned(),
                    ));
                }
            };
            Ok(ServiceContactPreference {
                category,
                mode: match service.contact_mode {
                    ContactMode::Direct => EngineContactMode::Direct,
                    ContactMode::ApprovalRequired => EngineContactMode::ApprovalRequired,
                },
            })
        })
        .collect()
}

fn map_engine_contact_limit(
    limit: Option<i16>,
) -> Result<ContactSessionLimit, sahayak_persistence::PersistenceError> {
    match limit.unwrap_or(1) {
        1 => Ok(ContactSessionLimit::One),
        3 => Ok(ContactSessionLimit::Three),
        5 => Ok(ContactSessionLimit::Five),
        10 => Ok(ContactSessionLimit::Ten),
        _ => Err(sahayak_persistence::PersistenceError::Invariant(
            "professional snapshot contains an unsupported contact limit".to_owned(),
        )),
    }
}

const fn map_engine_local_service_mode(mode: LocalServiceMode) -> EngineLocalServiceMode {
    match mode {
        LocalServiceMode::TravelToCustomer => EngineLocalServiceMode::TravelToCustomer,
        LocalServiceMode::CustomerVisits => EngineLocalServiceMode::CustomerVisits,
        LocalServiceMode::Both => EngineLocalServiceMode::Both,
    }
}

const fn map_local_service_mode(mode: EngineLocalServiceMode) -> LocalServiceMode {
    match mode {
        EngineLocalServiceMode::TravelToCustomer => LocalServiceMode::TravelToCustomer,
        EngineLocalServiceMode::CustomerVisits => LocalServiceMode::CustomerVisits,
        EngineLocalServiceMode::Both => LocalServiceMode::Both,
    }
}

const fn map_engine_service_radius(radius: ServiceRadiusKm) -> ServiceRadius {
    match radius {
        ServiceRadiusKm::Two => ServiceRadius::Km2,
        ServiceRadiusKm::Five => ServiceRadius::Km5,
        ServiceRadiusKm::Ten => ServiceRadius::Km10,
        ServiceRadiusKm::TwentyFive => ServiceRadius::Km25,
    }
}

const fn map_service_radius(radius: ServiceRadius) -> ServiceRadiusKm {
    match radius {
        ServiceRadius::Km2 => ServiceRadiusKm::Two,
        ServiceRadius::Km5 => ServiceRadiusKm::Five,
        ServiceRadius::Km10 => ServiceRadiusKm::Ten,
        ServiceRadius::Km25 => ServiceRadiusKm::TwentyFive,
    }
}

const fn map_locale(language: ProfessionalLanguage) -> Locale {
    match language {
        ProfessionalLanguage::EnglishIndia => Locale::EnIn,
        ProfessionalLanguage::HindiIndia => Locale::HiIn,
        ProfessionalLanguage::MarathiIndia => Locale::MrIn,
    }
}

const fn map_professional_language(locale: Locale) -> ProfessionalLanguage {
    match locale {
        Locale::EnIn => ProfessionalLanguage::EnglishIndia,
        Locale::HiIn => ProfessionalLanguage::HindiIndia,
        Locale::MrIn => ProfessionalLanguage::MarathiIndia,
    }
}

const fn map_contact_mode(mode: EngineContactMode) -> ContactMode {
    match mode {
        EngineContactMode::Direct => ContactMode::Direct,
        EngineContactMode::ApprovalRequired => ContactMode::ApprovalRequired,
    }
}

fn parse_engine_consent_version(value: &str) -> Option<u16> {
    value
        .strip_prefix("phase5-v")
        .unwrap_or(value)
        .parse::<u16>()
        .ok()
}

fn professional_resume_step(
    snapshot: &ProfessionalConversationSnapshot,
) -> Option<ProfessionalResumeStep> {
    if snapshot.status != ProfessionalConversationStatus::Draft {
        return None;
    }
    let summary = snapshot.summary.as_ref();
    snapshot
        .missing_requirements
        .iter()
        .find_map(|requirement| match requirement {
            ProfessionalRequirement::DisplayName => Some(ProfessionalResumeStep::DisplayName),
            ProfessionalRequirement::ActiveService => Some(ProfessionalResumeStep::Categories),
            ProfessionalRequirement::ServiceSkill => Some(ProfessionalResumeStep::Skills),
            ProfessionalRequirement::LocalServiceMode => Some(ProfessionalResumeStep::ServiceArea),
            ProfessionalRequirement::ServiceArea => {
                if summary.and_then(|value| value.service_radius).is_some() {
                    Some(ProfessionalResumeStep::Location)
                } else {
                    Some(ProfessionalResumeStep::Radius)
                }
            }
            ProfessionalRequirement::ProfessionalLanguage => {
                Some(ProfessionalResumeStep::Languages)
            }
            ProfessionalRequirement::ContactRequestLimit => {
                Some(ProfessionalResumeStep::ContactLimit)
            }
            ProfessionalRequirement::TermsConsent
            | ProfessionalRequirement::PrivacyConsent
            | ProfessionalRequirement::ContactDisclosureConsent
            | ProfessionalRequirement::DirectContactConsent
            | ProfessionalRequirement::PhotoDisclosureConsent => {
                Some(ProfessionalResumeStep::Consent)
            }
            ProfessionalRequirement::ActiveAccount
            | ProfessionalRequirement::NonBlockedAccount
            | ProfessionalRequirement::ActiveProfessionalRole
            | ProfessionalRequirement::VerifiedWhatsAppIdentity => None,
        })
        .or(Some(ProfessionalResumeStep::Summary))
}

fn map_review_reason_code(
    value: &str,
) -> Result<ReviewReasonCode, sahayak_persistence::PersistenceError> {
    match value {
        "incomplete_profile" | "invalid_display_name" => Ok(ReviewReasonCode::IncompleteDetails),
        "unsupported_service" | "service_area_issue" => Ok(ReviewReasonCode::ServiceMismatch),
        "photo_issue" => Ok(ReviewReasonCode::PhotoConcern),
        "policy_violation" | "fraud_risk" | "prohibited_content" => {
            Ok(ReviewReasonCode::PolicyViolation)
        }
        _ => Err(sahayak_persistence::PersistenceError::Invariant(
            "professional review reason is unsupported".to_owned(),
        )),
    }
}

fn role_for_session_change(change: &SessionChange) -> AccountRole {
    let next = match change {
        SessionChange::Create { next, .. }
        | SessionChange::Advance { next, .. }
        | SessionChange::Replace { next, .. } => next,
    };
    match next {
        ConversationState::Professional(_)
        | ConversationState::Availability(_)
        | ConversationState::ProfessionalRequests(_) => AccountRole::Professional,
        ConversationState::Administrator(_) | ConversationState::SafetyAdministrator(_) => {
            AccountRole::Administrator
        }
        ConversationState::LocaleChoose
        | ConversationState::LocaleConfirm { .. }
        | ConversationState::MainShow
        | ConversationState::MoreShow
        | ConversationState::HelpShow
        | ConversationState::Discovery(_)
        | ConversationState::Trust(_) => AccountRole::Customer,
    }
}

fn session_change_is_trust(change: &SessionChange) -> bool {
    matches!(
        change,
        SessionChange::Create {
            next: ConversationState::Trust(_),
            ..
        } | SessionChange::Advance {
            next: ConversationState::Trust(_),
            ..
        } | SessionChange::Replace {
            next: ConversationState::Trust(_),
            ..
        }
    )
}

fn should_start_professional_draft(
    plan: &TurnPlan,
    snapshot: Option<&ProfessionalConversationSnapshot>,
) -> bool {
    let next = match &plan.session_change {
        SessionChange::Create { next, .. }
        | SessionChange::Advance { next, .. }
        | SessionChange::Replace { next, .. } => next,
    };
    let ConversationState::Professional(state) = next else {
        return false;
    };
    match snapshot.map(|value| value.status) {
        None | Some(ProfessionalConversationStatus::NotStarted) => true,
        Some(ProfessionalConversationStatus::Draft) => false,
        Some(
            ProfessionalConversationStatus::PendingReview
            | ProfessionalConversationStatus::ChangesRequested
            | ProfessionalConversationStatus::Approved
            | ProfessionalConversationStatus::Rejected
            | ProfessionalConversationStatus::Hidden,
        ) => !matches!(
            state,
            sahayak_conversation_engine::ProfessionalState::Status
                | sahayak_conversation_engine::ProfessionalState::EditMenu
        ),
    }
}

fn start_professional_effect(
    snapshot: Option<&ProfessionalConversationSnapshot>,
) -> ProfessionalTurnEffect {
    ProfessionalTurnEffect {
        profile_id: snapshot
            .and_then(|value| value.profile_id)
            .unwrap_or_default(),
        revision_id: ProfileRevisionId::new(),
        expected_revision_version: None,
        operation: ProfessionalTurnOperation::StartOrResumeDraft {
            public_reference: PublicProfileReference::new(),
        },
    }
}

fn professional_effect_target(
    snapshot: Option<&ProfessionalConversationSnapshot>,
    command: &ProfessionalCommand,
) -> Result<ProfessionalEffectTarget, sahayak_persistence::PersistenceError> {
    if matches!(command, ProfessionalCommand::StageDisplayName { .. })
        && snapshot.is_none_or(|value| {
            value.status == ProfessionalConversationStatus::NotStarted
                || value.profile_id.is_none()
                || value.revision_id.is_none()
        })
    {
        return Ok(ProfessionalEffectTarget {
            profile_id: PublicProfileId::new(),
            revision_id: ProfileRevisionId::new(),
            expected_revision_version: None,
        });
    }
    let snapshot = snapshot.ok_or_else(|| {
        sahayak_persistence::PersistenceError::InvalidCommand(
            "professional command has no persisted draft".to_owned(),
        )
    })?;
    if snapshot.status != ProfessionalConversationStatus::Draft {
        return Err(sahayak_persistence::PersistenceError::OptimisticConflict);
    }
    Ok(ProfessionalEffectTarget {
        profile_id: snapshot.profile_id.ok_or_else(|| {
            sahayak_persistence::PersistenceError::Invariant(
                "professional draft has no profile identifier".to_owned(),
            )
        })?,
        revision_id: snapshot.revision_id.ok_or_else(|| {
            sahayak_persistence::PersistenceError::Invariant(
                "professional draft has no revision identifier".to_owned(),
            )
        })?,
        expected_revision_version: snapshot.version,
    })
}

fn map_review_decision(
    decision: AdminReviewDecision,
    reason: Option<ReviewReasonCode>,
) -> Result<(ProfileReviewDecision, ProfileReviewReason), sahayak_persistence::PersistenceError> {
    match (decision, reason) {
        (AdminReviewDecision::Approve, None) => Ok((
            ProfileReviewDecision::Approve,
            ProfileReviewReason::MeetsPolicy,
        )),
        (AdminReviewDecision::ChangesRequested, Some(ReviewReasonCode::IncompleteDetails)) => Ok((
            ProfileReviewDecision::ChangesRequested,
            ProfileReviewReason::IncompleteProfile,
        )),
        (AdminReviewDecision::ChangesRequested, Some(ReviewReasonCode::ServiceMismatch)) => Ok((
            ProfileReviewDecision::ChangesRequested,
            ProfileReviewReason::UnsupportedService,
        )),
        (AdminReviewDecision::ChangesRequested, Some(ReviewReasonCode::PhotoConcern)) => Ok((
            ProfileReviewDecision::ChangesRequested,
            ProfileReviewReason::PhotoIssue,
        )),
        (AdminReviewDecision::Reject, Some(ReviewReasonCode::PolicyViolation)) => Ok((
            ProfileReviewDecision::Reject,
            ProfileReviewReason::PolicyViolation,
        )),
        _ => Err(sahayak_persistence::PersistenceError::InvalidCommand(
            "administrator decision and reason are incompatible".to_owned(),
        )),
    }
}

fn media_error_is_transient(error: &WhatsAppError) -> bool {
    match error {
        WhatsAppError::Connection
        | WhatsAppError::AmbiguousTransport
        | WhatsAppError::InvalidSuccessResponse
        | WhatsAppError::MediaTransport => true,
        WhatsAppError::Api(failure) => matches!(
            failure.class,
            FailureClass::Retryable | FailureClass::Authorization | FailureClass::Ambiguous
        ),
        WhatsAppError::InvalidConfiguration(_)
        | WhatsAppError::InvalidMediaResponse
        | WhatsAppError::MediaTooLarge
        | WhatsAppError::UnsafeMediaUrl => false,
        _ => false,
    }
}

fn retry_delay(attempt: i32) -> Duration {
    let exponent = u32::try_from(attempt.saturating_sub(1)).unwrap_or(0).min(8);
    Duration::from_secs((2_u64.pow(exponent)).min(300))
}

fn canonical_input(
    content: &NormalizedContent,
    resolved_reply_to: Option<OutboundMessageId>,
) -> UserInput {
    match content {
        NormalizedContent::Text { body } => {
            sahayak_conversation_engine::NormalizedText::parse(body)
                .map(UserInput::Text)
                .unwrap_or(UserInput::Unsupported)
        }
        NormalizedContent::Action { id, .. } => ActionId::parse(id)
            .map(|id| UserInput::Action {
                id,
                reply_to: resolved_reply_to,
            })
            .unwrap_or(UserInput::Unsupported),
        NormalizedContent::Location { .. } => UserInput::Location,
        NormalizedContent::Media { .. } => UserInput::Media,
        NormalizedContent::Unsupported { .. } => UserInput::Unsupported,
    }
}

fn render_whatsapp_reply(
    recipient: &NormalizedPhoneNumber,
    reply: &sahayak_conversation_engine::ReplySpec,
    image_header_media_id: Option<&str>,
) -> Result<OutboundMessage, sahayak_persistence::PersistenceError> {
    let invalid = || {
        sahayak_persistence::PersistenceError::Invariant(
            "conversation reply violates WhatsApp limits".to_owned(),
        )
    };
    match &reply.controls {
        ReplyControls::None => {
            if image_header_media_id.is_some() {
                return Err(invalid());
            }
            Ok(OutboundMessage::text(
                recipient,
                TextMessage::new(&reply.body, false).map_err(|_| invalid())?,
            ))
        }
        ReplyControls::Buttons(buttons) => {
            let buttons = buttons
                .iter()
                .map(|button| Button::new(&button.id, &button.title).map_err(|_| invalid()))
                .collect::<Result<Vec<_>, _>>()?;
            let mut message =
                ButtonMessage::new(&reply.body, buttons, None, None).map_err(|_| invalid())?;
            if let Some(media_id) = image_header_media_id {
                message =
                    message.with_image_header(MediaReference::id(media_id).map_err(|_| invalid())?);
            }
            Ok(OutboundMessage::buttons(recipient, message))
        }
        ReplyControls::List {
            open_title,
            section_title,
            rows,
        } => {
            if image_header_media_id.is_some() {
                return Err(invalid());
            }
            let rows = rows
                .iter()
                .map(|row| {
                    ListRow::new(&row.id, &row.title, row.description.as_deref())
                        .map_err(|_| invalid())
                })
                .collect::<Result<Vec<_>, _>>()?;
            let section = ListSection::new(section_title, rows).map_err(|_| invalid())?;
            Ok(OutboundMessage::list(
                recipient,
                ListMessage::new(&reply.body, open_title, vec![section], None, None)
                    .map_err(|_| invalid())?,
            ))
        }
    }
}

fn lookup_digests(
    cryptography: &CryptoService,
    namespace: &str,
    value: &[u8],
) -> Result<Vec<LookupDigest>, sahayak_persistence::PersistenceError> {
    cryptography
        .all_blind_indexes(namespace, value)
        .map_err(|_| {
            sahayak_persistence::PersistenceError::Invariant(
                "identity lookup fingerprint failed".to_owned(),
            )
        })
        .map(|items| {
            items
                .into_iter()
                .map(|(key_version, digest)| LookupDigest {
                    key_version,
                    digest,
                })
                .collect()
        })
}

fn map_session_change(
    change: &SessionChange,
    expired_session: Option<(ConversationSessionId, i64)>,
    current_workflow_correlation: Option<CorrelationId>,
    database_now: OffsetDateTime,
) -> Result<(ConversationSessionChange, CorrelationId), sahayak_persistence::PersistenceError> {
    match change {
        SessionChange::Create { next, locale } => {
            let correlation = CorrelationId::new();
            Ok((
                ConversationSessionChange::Create {
                    session_id: ConversationSessionId::new(),
                    workflow_key: next.workflow().key().to_owned(),
                    workflow_version: next.workflow().version(),
                    state_key: next.key().to_owned(),
                    state_data: next.data(),
                    language: locale.as_str().to_owned(),
                    workflow_correlation_id: correlation,
                    expires_at: database_now + time::Duration::minutes(30),
                    expired_session,
                },
                correlation,
            ))
        }
        SessionChange::Advance {
            session_id,
            expected_version,
            next,
        } => {
            let correlation = current_workflow_correlation.ok_or_else(|| {
                sahayak_persistence::PersistenceError::Invariant(
                    "active conversation is missing workflow correlation".to_owned(),
                )
            })?;
            Ok((
                ConversationSessionChange::Advance {
                    session_id: *session_id,
                    expected_version: *expected_version,
                    state_key: next.key().to_owned(),
                    state_data: next.data(),
                    expires_at: database_now + time::Duration::minutes(30),
                },
                correlation,
            ))
        }
        SessionChange::Replace {
            session_id,
            expected_version,
            next,
            locale,
            terminal_status,
            terminal_reason,
        } => {
            let correlation = CorrelationId::new();
            Ok((
                ConversationSessionChange::Replace {
                    previous_session_id: *session_id,
                    expected_version: *expected_version,
                    terminal_status: match terminal_status {
                        SessionTerminalStatus::Completed => {
                            sahayak_domain::ConversationStatus::Completed
                        }
                        SessionTerminalStatus::Abandoned => {
                            sahayak_domain::ConversationStatus::Abandoned
                        }
                    },
                    terminal_reason: (*terminal_reason).to_owned(),
                    session_id: ConversationSessionId::new(),
                    workflow_key: next.workflow().key().to_owned(),
                    workflow_version: next.workflow().version(),
                    state_key: next.key().to_owned(),
                    state_data: next.data(),
                    language: locale.as_str().to_owned(),
                    workflow_correlation_id: correlation,
                    expires_at: database_now + time::Duration::minutes(30),
                },
                correlation,
            ))
        }
    }
}

fn bind_consent_document_set(
    change: &mut SessionChange,
    digest: [u8; 32],
) -> Result<(), sahayak_persistence::PersistenceError> {
    let next = match change {
        SessionChange::Create { next, .. }
        | SessionChange::Advance { next, .. }
        | SessionChange::Replace { next, .. } => next,
    };
    let ConversationState::Professional(sahayak_conversation_engine::ProfessionalState::Consent {
        document_set_digest,
        ..
    }) = next
    else {
        return Err(sahayak_persistence::PersistenceError::Invariant(
            "consent document binding requires a consent state".to_owned(),
        ));
    };
    *document_set_digest = Some(digest);
    Ok(())
}

fn bind_waiting_connection(
    change: &mut SessionChange,
    token: &str,
    version: i64,
) -> Result<(), sahayak_persistence::PersistenceError> {
    let next = match change {
        SessionChange::Create { next, .. }
        | SessionChange::Advance { next, .. }
        | SessionChange::Replace { next, .. } => next,
    };
    let ConversationState::Discovery(sahayak_conversation_engine::DiscoveryState::Waiting {
        connection_token,
        connection_version,
    }) = next
    else {
        return Err(sahayak_persistence::PersistenceError::Invariant(
            "connection token binding requires a waiting state".to_owned(),
        ));
    };
    *connection_token = token.to_owned();
    *connection_version = version;
    Ok(())
}

const fn map_disposition(disposition: ConversationDisposition) -> TurnDisposition {
    match disposition {
        ConversationDisposition::Applied => TurnDisposition::Applied,
        ConversationDisposition::Unexpected => TurnDisposition::Unexpected,
        ConversationDisposition::Stale => TurnDisposition::Stale,
        ConversationDisposition::Recovered => TurnDisposition::Recovered,
    }
}

#[cfg(test)]
mod tests {
    use super::WhatsAppJobProcessor;
    use image::{DynamicImage, ImageFormat, RgbImage};
    use sahayak_configuration::DatabaseSettings;
    use sahayak_conversation_engine::ConversationEngine;
    use sahayak_cryptography::{
        CryptoService, EncryptedValue, EncryptionContext, EncryptionKeySet, EncryptionNamespace,
        EncryptionPurpose, NormalizedPhoneNumber, VersionedKey,
    };
    use sahayak_domain::{
        AccountId, AccountRole, AdministratorGrantId, CallbackToken, ChannelIdentityId,
        ConnectionRequestId, CorrelationId, InboundEventId, OutboundMessageId, OutboxJobId,
        WorkerId,
    };
    use sahayak_localization::{Locale, Localizer, MessageKey};
    use sahayak_persistence::{
        AccountRepository, AdministratorAllowlistRepository, BlockRepository,
        ConversationTurnRepository, Database, EncryptedEventPayload, EncryptedOutboundPayload,
        GrantAdministratorAccess, IdentityRepository, InboundEventInput, OutboundRepository,
        OutboxRepository, QueueOutboundMessage,
    };
    use sahayak_whatsapp::{
        NormalizedContent, NormalizedEvent, NormalizedPayload, OutboundMessage, TextMessage,
        WhatsAppClient, WhatsAppClientConfig,
    };
    use secrecy::SecretString;
    use sha2::{Digest, Sha256};
    use sqlx::PgPool;
    use std::{
        env,
        io::Cursor,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use time::OffsetDateTime;
    use tokio::sync::RwLock;
    use wiremock::{
        Mock, MockServer, Request as MockRequest, Respond, ResponseTemplate,
        matchers::{method, path},
    };

    const TEST_DATABASE_ENVIRONMENT: &str = "SAHAYAK_TEST_DATABASE_URL";
    static TEST_LOCK: RwLock<()> = RwLock::const_new(());

    struct SequencedMessageResponder {
        prefix: String,
        counter: AtomicUsize,
        service_window_rejection_at: usize,
    }

    impl Respond for SequencedMessageResponder {
        fn respond(&self, _request: &MockRequest) -> ResponseTemplate {
            let sequence = self.counter.fetch_add(1, Ordering::SeqCst);
            if sequence == self.service_window_rejection_at {
                return ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error": {
                        "message": "outside customer service window",
                        "type": "OAuthException",
                        "code": 131047,
                        "fbtrace_id": "trace-service-window"
                    }
                }));
            }
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messages": [{"id": format!("{}.{}", self.prefix, sequence)}]
            }))
        }
    }

    #[tokio::test]
    async fn worker_sends_and_records_meta_acceptance() -> Result<(), Box<dyn std::error::Error>> {
        let _guard = TEST_LOCK.write().await;
        let Ok(database_url) = env::var(TEST_DATABASE_ENVIRONMENT) else {
            return Ok(());
        };
        let database =
            Database::connect(&database_settings(database_url.clone()), "worker-test").await?;
        let assertion_pool = PgPool::connect(&database_url).await?;
        cleanup_incomplete_sends(&assertion_pool).await?;
        let outbound_id = OutboundMessageId::new();
        let provider_message_id = format!("wamid.{outbound_id}");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messages": [{"id": provider_message_id.clone()}]
            })))
            .mount(&server)
            .await;
        let cryptography = crypto_service()?;
        let client = WhatsAppClient::new(&WhatsAppClientConfig {
            base_url: server.uri(),
            graph_api_version: "v26.0".to_owned(),
            phone_number_id: "123456".to_owned(),
            access_token: SecretString::from("test-token".to_owned()),
            timeout: Duration::from_secs(5),
        })?;
        let callback = CallbackToken::new();
        let recipient = NormalizedPhoneNumber::parse("+919876543210")?;
        let message = OutboundMessage::text(&recipient, TextMessage::new("Hello", false)?)
            .with_callback_data(&callback.to_string())?;
        let fingerprint_payload =
            OutboundMessage::text(&recipient, TextMessage::new("Hello", false)?).prepare()?;
        let prepared = message.prepare()?;
        let encrypted = cryptography.encrypt(
            EncryptionPurpose::Integration,
            EncryptionContext::new(
                EncryptionNamespace::OUTBOUND_MESSAGE_PAYLOAD,
                outbound_id.into_uuid(),
            ),
            prepared.expose(),
        )?;
        let (fingerprint_key_version, request_fingerprint) = cryptography.blind_index(
            "messaging:whatsapp:outbound_request:v1",
            fingerprint_payload.expose(),
        )?;
        OutboundRepository::new(database.clone())
            .queue(&QueueOutboundMessage {
                id: outbound_id,
                provider_namespace: "test-waba:123456".to_owned(),
                recipient_channel_identity_id: None,
                idempotency_key: format!("transport_probe:worker-test:{outbound_id}"),
                payload: EncryptedOutboundPayload {
                    schema_version: 1,
                    encrypted,
                    fingerprint_key_version,
                    request_fingerprint,
                    additional_fingerprints: Vec::new(),
                },
                callback_token: callback,
                correlation_id: CorrelationId::new(),
                ordering_key: None,
                send_job_id: OutboxJobId::new(),
                max_attempts: 3,
            })
            .await?;
        let processor = WhatsAppJobProcessor {
            worker_id: WorkerId::new(),
            cryptography: cryptography.clone(),
            client: RwLock::new(client),
            client_base_url: server.uri(),
            graph_api_version: "v26.0".to_owned(),
            phone_number_id: "123456".to_owned(),
            access_token_file: std::env::temp_dir().join("unused-whatsapp-test-token"),
            strict_secret_permissions: false,
            request_timeout: Duration::from_secs(5),
            reentry_template_name: "sahayak_reentry".to_owned(),
            payment_reminder_template_name: "sahayak_payment_reminder".to_owned(),
            outbox: OutboxRepository::new(database.clone()),
            outbound: OutboundRepository::new(database.clone()),
            delivery: sahayak_persistence::DeliveryRepository::new(database.clone()),
            identity: IdentityRepository::new(database.clone()),
            conversations: ConversationTurnRepository::new(database.clone()),
            engine: ConversationEngine::load()?,
            database: database.clone(),
            provider_namespace: "test-waba:123456".to_owned(),
            batch_size: 1,
            lease_duration: Duration::from_secs(30),
        };
        assert!(processor.process_batch().await? >= 1);
        let state: (String, Option<String>) = sqlx::query_as(
            "SELECT submission_state, provider_message_id FROM messaging.outbound_messages WHERE id = $1",
        )
        .bind(outbound_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(
            state,
            ("accepted".to_owned(), Some(provider_message_id.clone()))
        );

        let status = NormalizedEvent {
            provider_event_id: format!("status:{provider_message_id}:read:{outbound_id}"),
            event_type: "message.status".to_owned(),
            occurred_at: Some(OffsetDateTime::now_utc()),
            payload: NormalizedPayload::Status {
                provider_message_id: provider_message_id.clone(),
                status: "read".to_owned(),
                recipient_id: "919876543210".to_owned(),
                participant_id: None,
                callback_data: Some(callback.to_string()),
                error_codes: Vec::new(),
            },
        };
        let status_id = InboundEventId::new();
        let normalized = serde_json::to_vec(&status)?;
        let status_encrypted = cryptography.encrypt(
            EncryptionPurpose::Integration,
            EncryptionContext::new(
                EncryptionNamespace::INBOUND_EVENT_PAYLOAD,
                status_id.into_uuid(),
            ),
            &normalized,
        )?;
        let (fingerprint_key_version, payload_fingerprint) =
            cryptography.blind_index("integration:whatsapp:event:v1", &normalized)?;
        database
            .accept_inbound_event(&InboundEventInput {
                event_id: status_id,
                provider_code: "whatsapp".to_owned(),
                provider_namespace: "test-waba:123456".to_owned(),
                provider_event_id: status.provider_event_id,
                event_type: status.event_type,
                payload: EncryptedEventPayload {
                    purpose: EncryptionPurpose::Integration,
                    schema_version: 1,
                    ciphertext: status_encrypted.ciphertext,
                    nonce: status_encrypted.nonce,
                    fingerprint_key_version,
                    payload_fingerprint,
                    additional_fingerprints: Vec::new(),
                    key_version: status_encrypted.key_version,
                },
                correlation_id: CorrelationId::new(),
                signature_verified_at: OffsetDateTime::now_utc(),
                provider_occurred_at: status.occurred_at,
                processing_job_id: OutboxJobId::new(),
                processing_job_kind: "process_whatsapp_status".to_owned(),
                processing_ordering_key: None,
                max_attempts: 3,
            })
            .await?;
        assert_eq!(processor.process_batch().await?, 1);
        let read_recorded: bool = sqlx::query_scalar(
            "SELECT read_at IS NOT NULL FROM messaging.outbound_messages WHERE id = $1",
        )
        .bind(outbound_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert!(read_recorded);
        assertion_pool.close().await;
        database.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn exact_transport_probe_receives_a_mocked_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = TEST_LOCK.write().await;
        let Ok(database_url) = env::var(TEST_DATABASE_ENVIRONMENT) else {
            return Ok(());
        };
        let database =
            Database::connect(&database_settings(database_url.clone()), "probe-test").await?;
        let assertion_pool = PgPool::connect(&database_url).await?;
        cleanup_incomplete_sends(&assertion_pool).await?;
        let event_id = InboundEventId::new();
        let provider_message_id = format!("wamid.probe.{event_id}");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messages": [{"id": provider_message_id.clone()}]
            })))
            .mount(&server)
            .await;
        let cryptography = crypto_service()?;
        let client = WhatsAppClient::new(&WhatsAppClientConfig {
            base_url: server.uri(),
            graph_api_version: "v26.0".to_owned(),
            phone_number_id: "123456".to_owned(),
            access_token: SecretString::from("test-token".to_owned()),
            timeout: Duration::from_secs(5),
        })?;
        let event = NormalizedEvent {
            provider_event_id: format!("message:{event_id}"),
            event_type: "message.received".to_owned(),
            occurred_at: Some(OffsetDateTime::now_utc()),
            payload: NormalizedPayload::Message {
                provider_message_id: format!("wamid.inbound.{event_id}"),
                sender_wa_id: "919876543210".to_owned(),
                sender_phone_e164: "+919876543210".to_owned(),
                context_message_id: None,
                content: NormalizedContent::Text {
                    body: "__sahayak_transport_probe__".to_owned(),
                },
                error_codes: Vec::new(),
            },
        };
        let normalized = serde_json::to_vec(&event)?;
        let encrypted = cryptography.encrypt(
            EncryptionPurpose::Integration,
            EncryptionContext::new(
                EncryptionNamespace::INBOUND_EVENT_PAYLOAD,
                event_id.into_uuid(),
            ),
            &normalized,
        )?;
        let (fingerprint_key_version, payload_fingerprint) =
            cryptography.blind_index("integration:whatsapp:event:v1", &normalized)?;
        database
            .accept_inbound_event(&InboundEventInput {
                event_id,
                provider_code: "whatsapp".to_owned(),
                provider_namespace: "test-waba:123456".to_owned(),
                provider_event_id: event.provider_event_id,
                event_type: event.event_type,
                payload: EncryptedEventPayload {
                    purpose: EncryptionPurpose::Integration,
                    schema_version: 1,
                    ciphertext: encrypted.ciphertext,
                    nonce: encrypted.nonce,
                    fingerprint_key_version,
                    payload_fingerprint,
                    additional_fingerprints: Vec::new(),
                    key_version: encrypted.key_version,
                },
                correlation_id: CorrelationId::new(),
                signature_verified_at: OffsetDateTime::now_utc(),
                provider_occurred_at: event.occurred_at,
                processing_job_id: OutboxJobId::new(),
                processing_job_kind: "process_whatsapp_probe".to_owned(),
                processing_ordering_key: Some([11; 32]),
                max_attempts: 3,
            })
            .await?;
        let processor = WhatsAppJobProcessor {
            worker_id: WorkerId::new(),
            cryptography: cryptography.clone(),
            client: RwLock::new(client),
            client_base_url: server.uri(),
            graph_api_version: "v26.0".to_owned(),
            phone_number_id: "123456".to_owned(),
            access_token_file: std::env::temp_dir().join("unused-whatsapp-probe-token"),
            strict_secret_permissions: false,
            request_timeout: Duration::from_secs(5),
            reentry_template_name: "sahayak_reentry".to_owned(),
            payment_reminder_template_name: "sahayak_payment_reminder".to_owned(),
            outbox: OutboxRepository::new(database.clone()),
            outbound: OutboundRepository::new(database.clone()),
            delivery: sahayak_persistence::DeliveryRepository::new(database.clone()),
            identity: IdentityRepository::new(database.clone()),
            conversations: ConversationTurnRepository::new(database.clone()),
            engine: ConversationEngine::load()?,
            database: database.clone(),
            provider_namespace: "test-waba:123456".to_owned(),
            batch_size: 1,
            lease_duration: Duration::from_secs(30),
        };
        assert_eq!(processor.process_batch().await?, 1);
        assert_eq!(processor.process_batch().await?, 1);
        let state: String = sqlx::query_scalar(
            "SELECT submission_state FROM messaging.outbound_messages WHERE idempotency_key = $1",
        )
        .bind(format!("transport_probe:{event_id}"))
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(state, "accepted");
        assertion_pool.close().await;
        database.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn first_message_creates_locale_workflow_and_language_prompt()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = TEST_LOCK.write().await;
        let Ok(database_url) = env::var(TEST_DATABASE_ENVIRONMENT) else {
            return Ok(());
        };
        let database =
            Database::connect(&database_settings(database_url.clone()), "locale-test").await?;
        let assertion_pool = PgPool::connect(&database_url).await?;
        cleanup_incomplete_sends(&assertion_pool).await?;
        let cryptography = crypto_service()?;
        let inbound_id = InboundEventId::new();
        let suffix = inbound_id.into_uuid().as_u128() % 1_000_000_000;
        let sender = format!("919{suffix:09}");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v26.0/123456/messages"))
            .respond_with(SequencedMessageResponder {
                prefix: format!("wamid.locale.{inbound_id}"),
                counter: AtomicUsize::new(0),
                service_window_rejection_at: 5,
            })
            .mount(&server)
            .await;
        let event = NormalizedEvent {
            provider_event_id: format!("message:{inbound_id}"),
            event_type: "message.received".to_owned(),
            occurred_at: Some(OffsetDateTime::now_utc()),
            payload: NormalizedPayload::Message {
                provider_message_id: format!("wamid.inbound.{inbound_id}"),
                sender_wa_id: sender.clone(),
                sender_phone_e164: format!("+{sender}"),
                context_message_id: None,
                content: NormalizedContent::Text {
                    body: "Hi".to_owned(),
                },
                error_codes: Vec::new(),
            },
        };
        let normalized = serde_json::to_vec(&event)?;
        let encrypted = cryptography.encrypt(
            EncryptionPurpose::Integration,
            EncryptionContext::new(
                EncryptionNamespace::INBOUND_EVENT_PAYLOAD,
                inbound_id.into_uuid(),
            ),
            &normalized,
        )?;
        let (fingerprint_key_version, payload_fingerprint) =
            cryptography.blind_index("integration:whatsapp:event:v1", &normalized)?;
        database
            .accept_inbound_event(&InboundEventInput {
                event_id: inbound_id,
                provider_code: "whatsapp".to_owned(),
                provider_namespace: "test-waba:123456".to_owned(),
                provider_event_id: event.provider_event_id,
                event_type: event.event_type,
                payload: EncryptedEventPayload {
                    purpose: EncryptionPurpose::Integration,
                    schema_version: 1,
                    ciphertext: encrypted.ciphertext,
                    nonce: encrypted.nonce,
                    fingerprint_key_version,
                    payload_fingerprint,
                    additional_fingerprints: Vec::new(),
                    key_version: encrypted.key_version,
                },
                correlation_id: CorrelationId::new(),
                signature_verified_at: OffsetDateTime::now_utc(),
                provider_occurred_at: event.occurred_at,
                processing_job_id: OutboxJobId::new(),
                processing_job_kind: "process_conversation_message".to_owned(),
                processing_ordering_key: Some([13; 32]),
                max_attempts: 3,
            })
            .await?;
        let client = WhatsAppClient::new(&WhatsAppClientConfig {
            base_url: server.uri(),
            graph_api_version: "v26.0".to_owned(),
            phone_number_id: "123456".to_owned(),
            access_token: SecretString::from("test-token".to_owned()),
            timeout: Duration::from_secs(5),
        })?;
        let processor = WhatsAppJobProcessor {
            worker_id: WorkerId::new(),
            cryptography: cryptography.clone(),
            client: RwLock::new(client),
            client_base_url: server.uri(),
            graph_api_version: "v26.0".to_owned(),
            phone_number_id: "123456".to_owned(),
            access_token_file: std::env::temp_dir().join("unused-locale-test-token"),
            strict_secret_permissions: false,
            request_timeout: Duration::from_secs(5),
            reentry_template_name: "sahayak_reentry".to_owned(),
            payment_reminder_template_name: "sahayak_payment_reminder".to_owned(),
            outbox: OutboxRepository::new(database.clone()),
            outbound: OutboundRepository::new(database.clone()),
            delivery: sahayak_persistence::DeliveryRepository::new(database.clone()),
            identity: IdentityRepository::new(database.clone()),
            conversations: ConversationTurnRepository::new(database.clone()),
            engine: ConversationEngine::load()?,
            database: database.clone(),
            provider_namespace: "test-waba:123456".to_owned(),
            batch_size: 1,
            lease_duration: Duration::from_secs(30),
        };
        assert_eq!(processor.process_batch().await?, 1);
        assert_eq!(processor.process_batch().await?, 1);
        let state: (String, String, bool, String) = sqlx::query_as(
            r#"
            SELECT
                session.workflow_key,
                session.state_key,
                account.preferred_locale_confirmed_at IS NOT NULL,
                outbound.submission_state
            FROM messaging.conversation_sessions AS session
            JOIN identity.accounts AS account ON account.id = session.account_id
            JOIN messaging.outbound_messages AS outbound
              ON outbound.conversation_session_id = session.id
            WHERE session.status = 'active'
              AND outbound.idempotency_key = $1
            "#,
        )
        .bind(format!("conversation-turn:v1:{inbound_id}"))
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(
            state,
            (
                "account.locale".to_owned(),
                "choose".to_owned(),
                false,
                "accepted".to_owned(),
            )
        );
        let first_prompt_id: String = sqlx::query_scalar(
            "SELECT provider_message_id FROM messaging.outbound_messages WHERE idempotency_key = $1",
        )
        .bind(format!("conversation-turn:v1:{inbound_id}"))
        .fetch_one(&assertion_pool)
        .await?;
        let language_event_id = accept_conversation_message(
            &database,
            &cryptography,
            &sender,
            Some(first_prompt_id),
            NormalizedContent::Action {
                source: "button_reply".to_owned(),
                id: "locale.hi".to_owned(),
                title: Some("हिंदी".to_owned()),
                description: None,
            },
        )
        .await?;
        assert_eq!(processor.process_batch().await?, 1);
        assert_eq!(processor.process_batch().await?, 1);
        let confirmation: (String, bool, String) = sqlx::query_as(
            r#"
            SELECT
                session.state_data ->> 'candidate_locale',
                account.preferred_locale_confirmed_at IS NOT NULL,
                outbound.provider_message_id
            FROM messaging.conversation_sessions AS session
            JOIN identity.accounts AS account ON account.id = session.account_id
            JOIN messaging.outbound_messages AS outbound
              ON outbound.conversation_session_id = session.id
            WHERE session.status = 'active'
              AND session.state_key = 'confirm'
            ORDER BY outbound.created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(confirmation.0, "hi-IN");
        assert!(!confirmation.1);

        let confirmation_event_id = accept_conversation_message(
            &database,
            &cryptography,
            &sender,
            Some(confirmation.2),
            NormalizedContent::Action {
                source: "button_reply".to_owned(),
                id: "locale.confirm".to_owned(),
                title: Some("हाँ".to_owned()),
                description: None,
            },
        )
        .await?;
        assert_ne!(language_event_id, confirmation_event_id);
        assert_eq!(processor.process_batch().await?, 1);
        assert_eq!(processor.process_batch().await?, 1);
        let confirmed: (String, bool, String, String) = sqlx::query_as(
            r#"
            SELECT
                account.preferred_locale,
                account.preferred_locale_confirmed_at IS NOT NULL,
                session.workflow_key,
                session.state_key
            FROM identity.accounts AS account
            JOIN messaging.conversation_sessions AS session ON session.account_id = account.id
            WHERE session.status = 'active'
            ORDER BY session.created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(
            confirmed,
            (
                "hi-IN".to_owned(),
                true,
                "main_menu".to_owned(),
                "show".to_owned(),
            )
        );
        let completed_locale_workflows: i64 = sqlx::query_scalar(
            r#"
            SELECT count(*)
            FROM messaging.conversation_sessions
            WHERE workflow_key = 'account.locale'
              AND status = 'completed'
              AND terminal_reason = 'locale_confirmed'
              AND account_id = (
                  SELECT session.account_id
                  FROM messaging.conversation_turn_receipts AS receipt
                  JOIN messaging.conversation_sessions AS session
                    ON session.id = receipt.next_session_id
                  WHERE receipt.inbound_event_id = $1
              )
            "#,
        )
        .bind(confirmation_event_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(completed_locale_workflows, 1);
        let latest_response: (uuid::Uuid, Vec<u8>, Vec<u8>, i16) = sqlx::query_as(
            r#"
            SELECT id, payload_ciphertext, payload_nonce, encryption_key_version
            FROM messaging.outbound_messages
            WHERE conversation_session_id = (
                SELECT id
                FROM messaging.conversation_sessions
                WHERE status = 'active'
                ORDER BY created_at DESC
                LIMIT 1
            )
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_one(&assertion_pool)
        .await?;
        let nonce: [u8; 12] = latest_response
            .2
            .try_into()
            .map_err(|_| std::io::Error::other("response nonce length is invalid"))?;
        let decrypted_response = cryptography.decrypt(
            EncryptionContext::new(
                EncryptionNamespace::OUTBOUND_MESSAGE_PAYLOAD,
                latest_response.0,
            ),
            &EncryptedValue {
                purpose: EncryptionPurpose::Integration,
                key_version: latest_response.3,
                nonce,
                ciphertext: latest_response.1,
            },
        )?;
        assert!(std::str::from_utf8(&decrypted_response)?.contains("आप क्या करना चाहते हैं?"));

        sqlx::query(
            r#"
            UPDATE messaging.conversation_sessions
            SET expires_at = created_at
            WHERE status = 'active'
              AND account_id = (
                  SELECT account_id
                  FROM identity.channel_identities
                  WHERE provider_namespace = 'test-waba:123456'
                  ORDER BY created_at DESC
                  LIMIT 1
              )
            "#,
        )
        .execute(&assertion_pool)
        .await?;
        accept_conversation_message(
            &database,
            &cryptography,
            &sender,
            None,
            NormalizedContent::Text {
                body: "Hi".to_owned(),
            },
        )
        .await?;
        assert_eq!(processor.process_batch().await?, 1);
        assert_eq!(processor.process_batch().await?, 1);
        let recovery: (i64, String, String, bool) = sqlx::query_as(
            r#"
            SELECT
                count(*) FILTER (WHERE status = 'expired'),
                max(language) FILTER (WHERE status = 'active'),
                max(workflow_key) FILTER (WHERE status = 'active'),
                bool_and(state_data = '{}'::jsonb) FILTER (WHERE status = 'expired')
            FROM messaging.conversation_sessions
            WHERE account_id = (
                SELECT account_id
                FROM identity.channel_identities
                WHERE provider_namespace = 'test-waba:123456'
                ORDER BY created_at DESC
                LIMIT 1
            )
            "#,
        )
        .fetch_one(&assertion_pool)
        .await?;
        assert!(recovery.0 >= 1);
        assert_eq!(recovery.1, "hi-IN");
        assert_eq!(recovery.2, "main_menu");
        assert!(recovery.3);

        let channel_identity_id: uuid::Uuid = sqlx::query_scalar(
            r#"
            SELECT id
            FROM identity.channel_identities
            WHERE provider_namespace = 'test-waba:123456'
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_one(&assertion_pool)
        .await?;
        sqlx::query(
            r#"
            UPDATE private_data.whatsapp_identities
            SET
                last_inbound_at = statement_timestamp() - INTERVAL '25 hours',
                service_window_expires_at = statement_timestamp() - INTERVAL '1 second'
            WHERE channel_identity_id = $1
            "#,
        )
        .bind(channel_identity_id)
        .execute(&assertion_pool)
        .await?;
        let closed_window_outbound = OutboundMessageId::new();
        let closed_callback = CallbackToken::new();
        let recipient = NormalizedPhoneNumber::parse(&format!("+{sender}"))?;
        let freeform = OutboundMessage::text(
            &recipient,
            TextMessage::new("This must not be sent outside the window.", false)?,
        );
        let freeform_fingerprint = freeform.prepare()?;
        let freeform_prepared = freeform
            .with_callback_data(&closed_callback.to_string())?
            .prepare()?;
        let freeform_encrypted = cryptography.encrypt(
            EncryptionPurpose::Integration,
            EncryptionContext::new(
                EncryptionNamespace::OUTBOUND_MESSAGE_PAYLOAD,
                closed_window_outbound.into_uuid(),
            ),
            freeform_prepared.expose(),
        )?;
        let (freeform_fingerprint_version, freeform_request_fingerprint) = cryptography
            .blind_index(
                "messaging:whatsapp:outbound_request:v1",
                freeform_fingerprint.expose(),
            )?;
        OutboundRepository::new(database.clone())
            .queue(&QueueOutboundMessage {
                id: closed_window_outbound,
                provider_namespace: "test-waba:123456".to_owned(),
                recipient_channel_identity_id: Some(ChannelIdentityId::from_uuid(
                    channel_identity_id,
                )),
                idempotency_key: format!("closed-window:{closed_window_outbound}"),
                payload: EncryptedOutboundPayload {
                    schema_version: 1,
                    encrypted: freeform_encrypted,
                    fingerprint_key_version: freeform_fingerprint_version,
                    request_fingerprint: freeform_request_fingerprint,
                    additional_fingerprints: Vec::new(),
                },
                callback_token: closed_callback,
                correlation_id: CorrelationId::new(),
                ordering_key: Some([13; 32]),
                send_job_id: OutboxJobId::new(),
                max_attempts: 3,
            })
            .await?;
        assert_eq!(processor.process_batch().await?, 1);
        assert_eq!(processor.process_batch().await?, 1);
        let window_states: (String, String) = sqlx::query_as(
            r#"
            SELECT
                (SELECT submission_state FROM messaging.outbound_messages WHERE id = $1),
                (
                    SELECT submission_state
                    FROM messaging.outbound_messages
                    WHERE idempotency_key = $2
                )
            "#,
        )
        .bind(closed_window_outbound.into_uuid())
        .bind(format!("reentry-template:v1:{closed_window_outbound}"))
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(
            window_states,
            ("rejected".to_owned(), "accepted".to_owned())
        );
        let template_payload: (uuid::Uuid, Vec<u8>, Vec<u8>, i16) = sqlx::query_as(
            r#"
            SELECT id, payload_ciphertext, payload_nonce, encryption_key_version
            FROM messaging.outbound_messages
            WHERE idempotency_key = $1
            "#,
        )
        .bind(format!("reentry-template:v1:{closed_window_outbound}"))
        .fetch_one(&assertion_pool)
        .await?;
        let template_nonce: [u8; 12] = template_payload
            .2
            .try_into()
            .map_err(|_| std::io::Error::other("template nonce length is invalid"))?;
        let decrypted_template = cryptography.decrypt(
            EncryptionContext::new(
                EncryptionNamespace::OUTBOUND_MESSAGE_PAYLOAD,
                template_payload.0,
            ),
            &EncryptedValue {
                purpose: EncryptionPurpose::Integration,
                key_version: template_payload.3,
                nonce: template_nonce,
                ciphertext: template_payload.1,
            },
        )?;
        let template_json: serde_json::Value = serde_json::from_slice(&decrypted_template)?;
        assert_eq!(template_json["type"], "template");
        assert_eq!(template_json["template"]["language"]["code"], "hi");

        sqlx::query(
            r#"
            UPDATE private_data.whatsapp_identities
            SET service_window_expires_at = statement_timestamp() + INTERVAL '24 hours'
            WHERE channel_identity_id = $1
            "#,
        )
        .bind(channel_identity_id)
        .execute(&assertion_pool)
        .await?;
        let provider_rejected_outbound = OutboundMessageId::new();
        let provider_rejected_callback = CallbackToken::new();
        let provider_rejected_message = OutboundMessage::text(
            &recipient,
            TextMessage::new("Meta will report a closed service window.", false)?,
        );
        let provider_rejected_fingerprint = provider_rejected_message.prepare()?;
        let provider_rejected_prepared = provider_rejected_message
            .with_callback_data(&provider_rejected_callback.to_string())?
            .prepare()?;
        let provider_rejected_encrypted = cryptography.encrypt(
            EncryptionPurpose::Integration,
            EncryptionContext::new(
                EncryptionNamespace::OUTBOUND_MESSAGE_PAYLOAD,
                provider_rejected_outbound.into_uuid(),
            ),
            provider_rejected_prepared.expose(),
        )?;
        let (provider_rejected_fingerprint_version, provider_rejected_request_fingerprint) =
            cryptography.blind_index(
                "messaging:whatsapp:outbound_request:v1",
                provider_rejected_fingerprint.expose(),
            )?;
        OutboundRepository::new(database.clone())
            .queue(&QueueOutboundMessage {
                id: provider_rejected_outbound,
                provider_namespace: "test-waba:123456".to_owned(),
                recipient_channel_identity_id: Some(ChannelIdentityId::from_uuid(
                    channel_identity_id,
                )),
                idempotency_key: format!("provider-window:{provider_rejected_outbound}"),
                payload: EncryptedOutboundPayload {
                    schema_version: 1,
                    encrypted: provider_rejected_encrypted,
                    fingerprint_key_version: provider_rejected_fingerprint_version,
                    request_fingerprint: provider_rejected_request_fingerprint,
                    additional_fingerprints: Vec::new(),
                },
                callback_token: provider_rejected_callback,
                correlation_id: CorrelationId::new(),
                ordering_key: Some([13; 32]),
                send_job_id: OutboxJobId::new(),
                max_attempts: 3,
            })
            .await?;
        assert_eq!(processor.process_batch().await?, 1);
        assert_eq!(processor.process_batch().await?, 1);
        let provider_window_states: (String, Option<String>, String, String, Vec<u8>) =
            sqlx::query_as(
                r#"
                SELECT
                    original.submission_state,
                    original.last_error_code,
                    original_job.state,
                    replacement.submission_state,
                    replacement_job.ordering_key
                FROM messaging.outbound_messages AS original
                JOIN integration.outbox_jobs AS original_job
                  ON original_job.outbound_message_id = original.id
                JOIN messaging.outbound_messages AS replacement
                  ON replacement.idempotency_key = $2
                JOIN integration.outbox_jobs AS replacement_job
                  ON replacement_job.outbound_message_id = replacement.id
                WHERE original.id = $1
                "#,
            )
            .bind(provider_rejected_outbound.into_uuid())
            .bind(format!("reentry-template:v1:{provider_rejected_outbound}"))
            .fetch_one(&assertion_pool)
            .await?;
        assert_eq!(provider_window_states.0, "rejected");
        assert_eq!(provider_window_states.1.as_deref(), Some("meta_131047"));
        assert_eq!(provider_window_states.2, "completed");
        assert_eq!(provider_window_states.3, "accepted");
        assert_eq!(provider_window_states.4, vec![13; 32]);
        assertion_pool.close().await;
        database.close().await;
        Ok(())
    }

    #[test]
    fn professional_onboarding_approval_and_availability_lifecycle_are_atomic()
    -> Result<(), Box<dyn std::error::Error>> {
        let handle = std::thread::Builder::new()
            .name("phase-7-8-e2e".to_owned())
            .stack_size(16 * 1_024 * 1_024)
            .spawn(|| {
                let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
                runtime
                    .block_on(run_professional_discovery_and_connection_flow())
                    .map_err(|error| error.to_string())
            })?;
        let result = handle
            .join()
            .map_err(|_| std::io::Error::other("Phase 7/8 test thread panicked"))?;
        result.map_err(std::io::Error::other)?;
        Ok(())
    }

    async fn run_professional_discovery_and_connection_flow()
    -> Result<(), Box<dyn std::error::Error>> {
        let _guard = TEST_LOCK.write().await;
        let Ok(database_url) = env::var(TEST_DATABASE_ENVIRONMENT) else {
            return Ok(());
        };
        let database = Database::connect(
            &database_settings(database_url.clone()),
            "phase5-worker-test",
        )
        .await?;
        let assertion_pool = PgPool::connect(&database_url).await?;
        cleanup_incomplete_sends(&assertion_pool).await?;
        let cryptography = crypto_service()?;
        let seed = InboundEventId::new();
        let suffix = seed.into_uuid().as_u128() % 1_000_000_000;
        let sender = format!("918{suffix:09}");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v26.0/123456/messages"))
            .respond_with(SequencedMessageResponder {
                prefix: format!("wamid.phase5.{seed}"),
                counter: AtomicUsize::new(0),
                service_window_rejection_at: usize::MAX,
            })
            .mount(&server)
            .await;
        let mut profile_photo = Vec::new();
        DynamicImage::ImageRgb8(RgbImage::from_pixel(16, 12, image::Rgb([40, 80, 120])))
            .write_to(&mut Cursor::new(&mut profile_photo), ImageFormat::Jpeg)?;
        let profile_photo_sha = hex::encode(Sha256::digest(&profile_photo));
        Mock::given(method("GET"))
            .and(path("/v26.0/98765"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "98765",
                "url": format!("{}/phase5-profile-photo", server.uri()),
                "mime_type": "image/jpeg",
                "sha256": profile_photo_sha,
                "file_size": profile_photo.len()
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/phase5-profile-photo"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(profile_photo.clone()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v26.0/123456/media"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "77777"
            })))
            .mount(&server)
            .await;
        let client = WhatsAppClient::new(&WhatsAppClientConfig {
            base_url: server.uri(),
            graph_api_version: "v26.0".to_owned(),
            phone_number_id: "123456".to_owned(),
            access_token: SecretString::from("test-token".to_owned()),
            timeout: Duration::from_secs(5),
        })?;
        let processor = WhatsAppJobProcessor {
            worker_id: WorkerId::new(),
            cryptography: cryptography.clone(),
            client: RwLock::new(client),
            client_base_url: server.uri(),
            graph_api_version: "v26.0".to_owned(),
            phone_number_id: "123456".to_owned(),
            access_token_file: std::env::temp_dir().join("unused-phase5-test-token"),
            strict_secret_permissions: false,
            request_timeout: Duration::from_secs(5),
            reentry_template_name: "sahayak_reentry".to_owned(),
            payment_reminder_template_name: "sahayak_payment_reminder".to_owned(),
            outbox: OutboxRepository::new(database.clone()),
            outbound: OutboundRepository::new(database.clone()),
            delivery: sahayak_persistence::DeliveryRepository::new(database.clone()),
            identity: IdentityRepository::new(database.clone()),
            conversations: ConversationTurnRepository::new(database.clone()),
            engine: ConversationEngine::load()?,
            database: database.clone(),
            provider_namespace: "test-waba:123456".to_owned(),
            batch_size: 10,
            lease_duration: Duration::from_secs(30),
        };

        let mut prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &sender,
            None,
            NormalizedContent::Text {
                body: "Hello".to_owned(),
            },
        )
        .await?;
        for action in ["locale.en", "locale.confirm", "main.offer"] {
            prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &sender,
                prompt,
                action,
            )
            .await?;
        }
        prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &sender,
            Some(prompt),
            NormalizedContent::Text {
                body: "Ravi Kumar".to_owned(),
            },
        )
        .await?;
        for action in [
            "pro.name.confirm",
            "pro.category.plumber",
            "pro.category.electrician",
            "pro.category.done",
            "pro.skill.leak",
            "pro.skill.done",
            "pro.skill.wiring",
            "pro.skill.done",
            "pro.area.travel",
            "pro.radius.5",
        ] {
            prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &sender,
                prompt,
                action,
            )
            .await?;
        }
        prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &sender,
            Some(prompt),
            NormalizedContent::Location {
                latitude: 19.076,
                longitude: 72.8777,
                name: None,
                address: None,
            },
        )
        .await?;
        for action in [
            "pro.language.en",
            "pro.language.done",
            "pro.contact.direct",
            "pro.contact.approval",
            "pro.limit.3",
        ] {
            prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &sender,
                prompt,
                action,
            )
            .await?;
        }
        prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &sender,
            Some(prompt),
            NormalizedContent::Media {
                media_type: "image".to_owned(),
                media_id: "98765".to_owned(),
                mime_type: Some("image/jpeg".to_owned()),
                sha256: Some(profile_photo_sha),
                caption: None,
                filename: None,
            },
        )
        .await?;
        for action in [
            "pro.disclosure.continue",
            "pro.summary.submit",
            "pro.consent.accept",
            "pro.summary.submit",
        ] {
            prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &sender,
                prompt,
                action,
            )
            .await?;
        }
        assert!(!prompt.is_empty());
        let (wa_key_version, wa_digest) =
            cryptography.blind_index("whatsapp:test-waba:123456:wa_id", sender.as_bytes())?;
        let professional_identity = IdentityRepository::new(database.clone())
            .find_whatsapp_by_wa_id_digest(wa_key_version, &wa_digest)
            .await?
            .ok_or("professional identity was not created")?;

        let state: (String, String, String, i64, i64, bool) = sqlx::query_as(
            r#"
            SELECT
                account.status,
                revision.state,
                session.role_context,
                (SELECT count(*) FROM identity.account_roles AS role
                 WHERE role.account_id = account.id
                   AND role.role = 'professional' AND role.revoked_at IS NULL),
                (SELECT count(*) FROM private_data.professional_consent_events AS consent
                 WHERE consent.revision_id = revision.id AND consent.action = 'granted'),
                NOT EXISTS (
                    SELECT 1 FROM private_data.identity_verification_attempts AS verification
                    WHERE verification.account_id = account.id
                )
            FROM identity.channel_identities AS channel
            JOIN identity.accounts AS account ON account.id = channel.account_id
            JOIN profile.public_profiles AS profile ON profile.account_id = account.id
            JOIN profile.profile_revisions AS revision ON revision.profile_id = profile.id
            JOIN messaging.conversation_sessions AS session
              ON session.account_id = account.id AND session.status = 'active'
            WHERE channel.provider_namespace = 'test-waba:123456'
              AND account.id = $1
              AND revision.state = 'pending_review'
              AND session.workflow_key = 'professional.profile'
            ORDER BY revision.created_at DESC
            LIMIT 1
            "#,
        )
        .bind(professional_identity.account_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(state.0, "active");
        assert_eq!(state.1, "pending_review");
        assert_eq!(state.2, "professional");
        assert_eq!(state.3, 1);
        assert_eq!(state.4, 5);
        assert!(state.5);
        let replies_are_ordered: bool = sqlx::query_scalar(
            r#"
            SELECT bool_and(job.ordering_key IS NOT NULL)
            FROM integration.outbox_jobs AS job
            JOIN messaging.outbound_messages AS message
              ON message.id = job.outbound_message_id
            WHERE message.recipient_channel_identity_id = $1
              AND message.idempotency_key LIKE 'conversation-turn:v1:%'
            "#,
        )
        .bind(professional_identity.channel_identity_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert!(replies_are_ordered);
        let private_location_exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM private_data.professional_service_areas AS area
                JOIN profile.profile_revisions AS revision ON revision.id = area.revision_id
                JOIN profile.public_profiles AS profile ON profile.id = revision.profile_id
                JOIN identity.channel_identities AS channel
                  ON channel.account_id = profile.account_id
                WHERE channel.provider_namespace = 'test-waba:123456'
                  AND profile.account_id = $1
            )
            "#,
        )
        .bind(professional_identity.account_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert!(private_location_exists);

        let revision_id: uuid::Uuid = sqlx::query_scalar(
            r#"
            SELECT revision.id
            FROM profile.profile_revisions AS revision
            JOIN profile.public_profiles AS profile ON profile.id = revision.profile_id
            WHERE profile.account_id = $1 AND revision.state = 'pending_review'
            "#,
        )
        .bind(professional_identity.account_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        let review_token: uuid::Uuid =
            sqlx::query_scalar("SELECT review_token FROM profile.profile_revisions WHERE id = $1")
                .bind(revision_id)
                .fetch_one(&assertion_pool)
                .await?;

        let admin_seed = InboundEventId::new();
        let admin_suffix = admin_seed.into_uuid().as_u128() % 1_000_000_000;
        let admin_sender = format!("917{admin_suffix:09}");
        let mut admin_prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &admin_sender,
            None,
            NormalizedContent::Text {
                body: "Hello".to_owned(),
            },
        )
        .await?;
        for action in ["locale.en", "locale.confirm"] {
            admin_prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &admin_sender,
                admin_prompt,
                action,
            )
            .await?;
        }
        let (admin_key_version, admin_digest) =
            cryptography.blind_index("whatsapp:test-waba:123456:wa_id", admin_sender.as_bytes())?;
        let admin_identity = IdentityRepository::new(database.clone())
            .find_whatsapp_by_wa_id_digest(admin_key_version, &admin_digest)
            .await?
            .ok_or("administrator identity was not created")?;
        sqlx::query(
            r#"
            UPDATE identity.accounts
            SET status = 'active', state_changed_at = statement_timestamp()
            WHERE id = $1 AND status = 'pending'
            "#,
        )
        .bind(admin_identity.account_id.into_uuid())
        .execute(&assertion_pool)
        .await?;
        AccountRepository::new(database.clone())
            .grant_role(admin_identity.account_id, AccountRole::Administrator, None)
            .await?;
        let grant = AdministratorAllowlistRepository::new(database.clone())
            .grant(&GrantAdministratorAccess {
                id: AdministratorGrantId::new(),
                account_id: admin_identity.account_id,
                channel_identity_id: admin_identity.channel_identity_id,
                granted_by_account_id: None,
                expires_at: OffsetDateTime::now_utc() + time::Duration::days(30),
                idempotency_key: format!("phase5-worker-admin:{admin_seed}"),
                correlation_id: CorrelationId::new(),
            })
            .await?;
        assert!(matches!(
            grant,
            sahayak_persistence::AdministratorGrantOutcome::Applied
        ));

        for action in ["main.more", "more.admin"] {
            admin_prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &admin_sender,
                admin_prompt,
                action,
            )
            .await?;
        }
        let preceding: i64 = sqlx::query_scalar(
            r#"
            SELECT count(*)
            FROM profile.profile_revisions AS candidate
            JOIN profile.profile_revisions AS target ON target.id = $1
            WHERE candidate.state = 'pending_review'
              AND (candidate.submitted_at, candidate.id) < (target.submitted_at, target.id)
            "#,
        )
        .bind(revision_id)
        .fetch_one(&assertion_pool)
        .await?;
        for _ in 0..(preceding / 7) {
            admin_prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &admin_sender,
                admin_prompt,
                "admin.queue.next",
            )
            .await?;
        }
        admin_prompt = process_test_action(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &admin_sender,
            admin_prompt,
            &format!("admin.queue.select:{review_token}"),
        )
        .await?;
        for action in ["admin.decision.approve", "admin.confirm.yes"] {
            admin_prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &admin_sender,
                admin_prompt,
                action,
            )
            .await?;
        }
        assert!(!admin_prompt.is_empty());
        let approved: (String, String, String, i64) = sqlx::query_as(
            r#"
            SELECT revision.state, profile.visibility, notification.submission_state,
                   (SELECT count(*) FROM audit.events
                    WHERE target_type = 'profile_revision' AND target_id = revision.id)
            FROM profile.profile_revisions AS revision
            JOIN profile.public_profiles AS profile
              ON profile.published_revision_id = revision.id
            JOIN messaging.outbound_messages AS notification
              ON notification.idempotency_key = $2
            WHERE revision.id = $1
            "#,
        )
        .bind(revision_id)
        .bind(format!("professional-review-outcome:v1:{revision_id}"))
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(approved.0, "approved");
        assert_eq!(approved.1, "published");
        assert_eq!(approved.2, "accepted");
        assert_eq!(approved.3, 1);
        let requests = server
            .received_requests()
            .await
            .ok_or("mock server did not retain requests")?;
        assert!(requests.iter().any(|request| {
            serde_json::from_slice::<serde_json::Value>(&request.body)
                .ok()
                .is_some_and(|body| body["interactive"]["header"]["image"]["id"] == "77777")
        }));
        let approved_text = Localizer::load()?
            .text(Locale::EnIn, MessageKey::PRO_STATUS_APPROVED_BODY)
            .to_owned();
        let expected_recipient = format!("+{sender}");
        assert!(requests.iter().any(|request| {
            serde_json::from_slice::<serde_json::Value>(&request.body)
                .ok()
                .is_some_and(|body| {
                    body["to"] == expected_recipient && body["text"]["body"] == approved_text
                })
        }));

        prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &sender,
            Some(prompt),
            NormalizedContent::Text {
                body: "menu".to_owned(),
            },
        )
        .await?;
        for action in [
            "main.more",
            "more.availability",
            "availability.set",
            "availability.duration.one_hour",
        ] {
            prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &sender,
                prompt,
                action,
            )
            .await?;
        }
        let availability_epoch: (uuid::Uuid, i64, i64, String) = sqlx::query_as(
            r#"
            SELECT epoch.id, epoch.generation, epoch.version, epoch.state
            FROM availability.epochs AS epoch
            WHERE epoch.account_id = $1 AND epoch.state = 'available'
            "#,
        )
        .bind(professional_identity.account_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(availability_epoch.3, "available");
        let timer_jobs: (i64, bool) = sqlx::query_as(
            r#"
            SELECT count(*), bool_and(ordering_key IS NULL)
            FROM integration.outbox_jobs
            WHERE availability_epoch_id = $1
            "#,
        )
        .bind(availability_epoch.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(timer_jobs, (2, true));
        sqlx::query(
            "UPDATE integration.outbox_jobs SET available_at = clock_timestamp() WHERE availability_epoch_id = $1 AND job_kind = 'remind_professional_availability'",
        )
        .bind(availability_epoch.0)
        .execute(&assertion_pool)
        .await?;
        assert!(processor.process_batch().await? >= 1);
        assert!(processor.process_batch().await? >= 1);
        let reminder_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM availability.notification_events WHERE epoch_id = $1 AND purpose = 'expiry_reminder'",
        )
        .bind(availability_epoch.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(reminder_count, 1);
        for action in [
            "availability.view_status",
            "availability.stop",
            "availability.stop.confirm",
            "availability.view_status",
            "availability.resume",
            "availability.view_status",
            "availability.renew",
            "availability.duration.four_hours",
        ] {
            prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &sender,
                prompt,
                action,
            )
            .await?;
        }
        assert!(!prompt.is_empty());
        let successor: (uuid::Uuid, i64, String) = sqlx::query_as(
            r#"
            SELECT id, generation, state
            FROM availability.epochs
            WHERE predecessor_epoch_id = $1
            "#,
        )
        .bind(availability_epoch.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(successor.2, "scheduled");

        let mut force_expiry = assertion_pool.begin().await?;
        sqlx::query("SELECT set_config('sahayak.availability_mutation', 'on', true)")
            .execute(&mut *force_expiry)
            .await?;
        sqlx::query(
            "UPDATE availability.epochs SET last_confirmed_at = starts_at, expires_at = starts_at + INTERVAL '1 microsecond' WHERE id = $1",
        )
        .bind(availability_epoch.0)
        .execute(&mut *force_expiry)
        .await?;
        sqlx::query(
            r#"
            UPDATE availability.epochs AS next
            SET starts_at = current.expires_at,
                expires_at = current.expires_at + INTERVAL '4 hours'
            FROM availability.epochs AS current
            WHERE next.id = $1 AND current.id = $2
            "#,
        )
        .bind(successor.0)
        .bind(availability_epoch.0)
        .execute(&mut *force_expiry)
        .await?;
        sqlx::query(
            "UPDATE integration.outbox_jobs SET available_at = clock_timestamp() WHERE availability_epoch_id = $1 AND job_kind = 'advance_professional_availability'",
        )
        .bind(availability_epoch.0)
        .execute(&mut *force_expiry)
        .await?;
        force_expiry.commit().await?;
        let stale_visibility: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM availability.current_professional_services WHERE availability_epoch_id = $1",
        )
        .bind(availability_epoch.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(stale_visibility, 0);
        assert_eq!(processor.process_batch().await?, 1);
        assert!(processor.process_batch().await? >= 1);
        let transitioned: (String, String, i16) = sqlx::query_as(
            r#"
            SELECT current.state, next.state, next.contact_count
            FROM availability.epochs AS current
            JOIN availability.epochs AS next ON next.predecessor_epoch_id = current.id
            WHERE current.id = $1
            "#,
        )
        .bind(availability_epoch.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(
            transitioned,
            ("expired".to_owned(), "available".to_owned(), 0)
        );
        let expiry_notifications: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM availability.notification_events WHERE epoch_id = $1 AND purpose = 'expired'",
        )
        .bind(availability_epoch.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(expiry_notifications, 1);
        let effective_services: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM availability.current_professional_services WHERE availability_epoch_id = $1",
        )
        .bind(successor.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(effective_services, 2);

        let customer_seed = InboundEventId::new();
        let customer_suffix = customer_seed.into_uuid().as_u128() % 1_000_000_000;
        let customer_sender = format!("916{customer_suffix:09}");
        let mut customer_prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &customer_sender,
            None,
            NormalizedContent::Text {
                body: "Hello".to_owned(),
            },
        )
        .await?;
        for action in [
            "locale.en",
            "locale.confirm",
            "main.find",
            "discovery.category.plumber",
        ] {
            customer_prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &customer_sender,
                customer_prompt,
                action,
            )
            .await?;
        }
        customer_prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &customer_sender,
            Some(customer_prompt),
            NormalizedContent::Location {
                latitude: 19.0761,
                longitude: 72.8778,
                name: None,
                address: None,
            },
        )
        .await?;
        for action in [
            "discovery.time.now",
            "discovery.issue.leak_repair",
            "discovery.view_results",
        ] {
            customer_prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &customer_sender,
                customer_prompt,
                action,
            )
            .await?;
        }
        let candidate_token: uuid::Uuid = sqlx::query_scalar(
            r#"
            SELECT candidate.candidate_token
            FROM discovery.request_candidates AS candidate
            JOIN discovery.service_requests AS request ON request.id = candidate.request_id
            WHERE request.customer_channel_identity_id = (
                SELECT channel.id
                FROM identity.channel_identities AS channel
                ORDER BY channel.created_at DESC LIMIT 1
            )
            ORDER BY candidate.final_rank LIMIT 1
            "#,
        )
        .fetch_one(&assertion_pool)
        .await?;
        customer_prompt = process_test_action(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &customer_sender,
            customer_prompt,
            &format!("discovery.select:{candidate_token}"),
        )
        .await?;
        customer_prompt = process_test_action(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &customer_sender,
            customer_prompt,
            "discovery.confirm.yes",
        )
        .await?;
        assert!(!customer_prompt.is_empty());
        let reveal: (uuid::Uuid, uuid::Uuid, uuid::Uuid, i64, i16, i64) = sqlx::query_as(
            r#"
            SELECT reveal.id, reveal.reveal_token, reveal.customer_account_id,
                   (SELECT count(*) FROM connection.customer_allowance_events
                    WHERE reveal_id = reveal.id),
                   epoch.contact_count,
                   (SELECT count(*) FROM connection.contact_reveal_delivery
                    WHERE reveal_id = reveal.id AND customer_outbound_message_id IS NOT NULL)
            FROM connection.contact_reveals AS reveal
            JOIN availability.epochs AS epoch ON epoch.id = reveal.availability_epoch_id
            WHERE reveal.professional_account_id = $1
            ORDER BY reveal.revealed_at DESC LIMIT 1
            "#,
        )
        .bind(professional_identity.account_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(reveal.3, 1);
        assert_eq!(reveal.4, 1);
        assert_eq!(reveal.5, 1);
        let allowance_after_reveal: i16 =
            sqlx::query_scalar("SELECT connection.customer_reveal_allowance_remaining($1)")
                .bind(reveal.2)
                .fetch_one(&assertion_pool)
                .await?;
        assert_eq!(allowance_after_reveal, 2);
        let photo_disclosed: bool = sqlx::query_scalar(
            "SELECT photo_outbound_message_id IS NOT NULL FROM connection.contact_reveal_delivery WHERE reveal_id = $1",
        )
        .bind(reveal.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert!(photo_disclosed);

        customer_prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &customer_sender,
            Some(customer_prompt),
            NormalizedContent::Text {
                body: "menu".to_owned(),
            },
        )
        .await?;
        for action in ["main.more", "more.contacts"] {
            customer_prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &customer_sender,
                customer_prompt,
                action,
            )
            .await?;
        }
        customer_prompt = process_test_action(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &customer_sender,
            customer_prompt,
            &format!("recent.select:{}", reveal.1),
        )
        .await?;
        let unchanged_limits: (i64, i16) = sqlx::query_as(
            r#"
            SELECT (SELECT count(*) FROM connection.customer_allowance_events
                    WHERE customer_account_id = reveal.customer_account_id),
                   epoch.contact_count
            FROM connection.contact_reveals AS reveal
            JOIN availability.epochs AS epoch ON epoch.id = reveal.availability_epoch_id
            WHERE reveal.id = $1
            "#,
        )
        .bind(reveal.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(unchanged_limits, (1, 1));
        let customer_channel_id: uuid::Uuid = sqlx::query_scalar(
            "SELECT id FROM identity.channel_identities WHERE account_id = $1 AND status = 'active' ORDER BY last_seen_at DESC LIMIT 1",
        )
        .bind(reveal.2)
        .fetch_one(&assertion_pool)
        .await?;
        assert!(
            BlockRepository::new(database.clone())
                .block(
                    AccountId::from_uuid(reveal.2),
                    ChannelIdentityId::from_uuid(customer_channel_id),
                    professional_identity.account_id,
                    None,
                    CorrelationId::new(),
                )
                .await?
        );
        customer_prompt = process_test_action(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &customer_sender,
            customer_prompt,
            &format!("recent.select:{}", reveal.1),
        )
        .await?;
        let still_one_reveal: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM connection.contact_reveals WHERE customer_account_id = $1",
        )
        .bind(reveal.2)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(still_one_reveal, 1);
        for action in ["main.find", "discovery.category.plumber"] {
            customer_prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &customer_sender,
                customer_prompt,
                action,
            )
            .await?;
        }
        customer_prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &customer_sender,
            Some(customer_prompt),
            NormalizedContent::Location {
                latitude: 19.0761,
                longitude: 72.8778,
                name: None,
                address: None,
            },
        )
        .await?;
        for action in ["discovery.time.now", "discovery.issue.leak_repair"] {
            customer_prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &customer_sender,
                customer_prompt,
                action,
            )
            .await?;
        }
        assert!(!customer_prompt.is_empty());
        let blocked_candidates: i64 = sqlx::query_scalar(
            r#"
            SELECT count(*) FROM discovery.request_candidates AS candidate
            JOIN discovery.service_requests AS request ON request.id = candidate.request_id
            WHERE request.customer_account_id = $1
              AND request.created_at = (
                  SELECT max(created_at) FROM discovery.service_requests
                  WHERE customer_account_id = $1
              )
            "#,
        )
        .bind(reveal.2)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(blocked_candidates, 0);

        let direct_customer_outbound: uuid::Uuid = sqlx::query_scalar(
            "SELECT customer_outbound_message_id FROM connection.contact_reveal_delivery WHERE reveal_id = $1",
        )
        .bind(reveal.0)
        .fetch_one(&assertion_pool)
        .await?;
        let free_reservation: (String, uuid::Uuid) = sqlx::query_as(
            "SELECT status, free_qualified_introduction_reveal_id FROM billing.professional_entitlements WHERE professional_account_id = $1",
        )
        .bind(professional_identity.account_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(
            free_reservation,
            ("not_required_during_free_value".to_owned(), reveal.0)
        );
        let connection_repository =
            sahayak_persistence::ConnectionRepository::new(database.clone());
        assert!(
            connection_repository
                .record_delivery(
                    OutboundMessageId::from_uuid(direct_customer_outbound),
                    false,
                    Some("internal_delivery_failure"),
                    CorrelationId::new(),
                )
                .await?
        );
        let reversal: (String, i64) = sqlx::query_as(
            r#"
            SELECT delivery.qualified_state,
                   (SELECT count(*) FROM connection.reveal_reversals
                    WHERE reveal_id = delivery.reveal_id)
            FROM connection.contact_reveal_delivery AS delivery
            WHERE delivery.reveal_id = $1
            "#,
        )
        .bind(reveal.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(reversal, ("reversed".to_owned(), 1));
        let reversed_accounting: (i64, i16) = sqlx::query_as(
            r#"
            SELECT (
                SELECT count(*)
                FROM connection.customer_allowance_events AS allowance
                JOIN connection.contact_reveals AS counted ON counted.id = allowance.reveal_id
                LEFT JOIN connection.reveal_reversals AS reversal
                  ON reversal.reveal_id = counted.id
                WHERE allowance.customer_account_id = reveal.customer_account_id
                  AND reversal.id IS NULL
            ), epoch.contact_count
            FROM connection.contact_reveals AS reveal
            JOIN availability.epochs AS epoch ON epoch.id = reveal.availability_epoch_id
            WHERE reveal.id = $1
            "#,
        )
        .bind(reveal.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(reversed_accounting, (0, 0));
        let allowance_after_reversal: i16 =
            sqlx::query_scalar("SELECT connection.customer_reveal_allowance_remaining($1)")
                .bind(reveal.2)
                .fetch_one(&assertion_pool)
                .await?;
        assert_eq!(allowance_after_reversal, 3);
        let released_free_reservation: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM billing.professional_entitlements WHERE professional_account_id = $1",
        )
        .bind(professional_identity.account_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(released_free_reservation, 0);

        let approval_seed = InboundEventId::new();
        let approval_suffix = approval_seed.into_uuid().as_u128() % 1_000_000_000;
        let approval_sender = format!("919{approval_suffix:09}");
        let mut approval_prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &approval_sender,
            None,
            NormalizedContent::Text {
                body: "Hello".to_owned(),
            },
        )
        .await?;
        for action in [
            "locale.en",
            "locale.confirm",
            "main.find",
            "discovery.category.electrician",
        ] {
            approval_prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &approval_sender,
                approval_prompt,
                action,
            )
            .await?;
        }
        approval_prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &approval_sender,
            Some(approval_prompt),
            NormalizedContent::Location {
                latitude: 19.0762,
                longitude: 72.8779,
                name: None,
                address: None,
            },
        )
        .await?;
        for action in [
            "discovery.time.today",
            "discovery.issue.wiring",
            "discovery.view_results",
        ] {
            approval_prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &approval_sender,
                approval_prompt,
                action,
            )
            .await?;
        }
        let approval_candidate: uuid::Uuid = sqlx::query_scalar(
            r#"
            SELECT candidate.candidate_token
            FROM discovery.request_candidates AS candidate
            JOIN discovery.service_requests AS request ON request.id = candidate.request_id
            WHERE request.category_code = 'electrician'
            ORDER BY request.created_at DESC, candidate.final_rank LIMIT 1
            "#,
        )
        .fetch_one(&assertion_pool)
        .await?;
        approval_prompt = process_test_action(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &approval_sender,
            approval_prompt,
            &format!("discovery.select:{approval_candidate}"),
        )
        .await?;
        let _ = process_test_action(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &approval_sender,
            approval_prompt,
            "discovery.confirm.yes",
        )
        .await?;
        let pending_connection: (uuid::Uuid, uuid::Uuid, String) = sqlx::query_as(
            r#"
            SELECT id, request_token, status
            FROM connection.connection_requests
            ORDER BY requested_at DESC LIMIT 1
            "#,
        )
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(pending_connection.2, "pending");
        let before_acceptance: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM connection.contact_reveals WHERE connection_request_id = $1",
        )
        .bind(pending_connection.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(before_acceptance, 0);

        prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &sender,
            Some(prompt),
            NormalizedContent::Text {
                body: "menu".to_owned(),
            },
        )
        .await?;
        for action in ["main.more", "more.requests"] {
            prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &sender,
                prompt,
                action,
            )
            .await?;
        }
        prompt = process_test_action(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &sender,
            prompt,
            &format!("request.select:{}", pending_connection.1),
        )
        .await?;
        for action in ["request.accept", "request.confirm"] {
            prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &sender,
                prompt,
                action,
            )
            .await?;
        }
        assert!(!prompt.is_empty());
        let accepted: (String, i64, i16) = sqlx::query_as(
            r#"
            SELECT connection.status,
                   (SELECT count(*) FROM connection.contact_reveals
                    WHERE connection_request_id = connection.id),
                   epoch.contact_count
            FROM connection.connection_requests AS connection
            JOIN connection.contact_reveals AS reveal
              ON reveal.connection_request_id = connection.id
            JOIN availability.epochs AS epoch ON epoch.id = reveal.availability_epoch_id
            WHERE connection.id = $1
            "#,
        )
        .bind(pending_connection.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(accepted, ("disclosed".to_owned(), 1, 1));
        let contact_requests = server
            .received_requests()
            .await
            .ok_or("mock server did not retain contact requests")?;
        assert!(contact_requests.iter().any(|request| {
            serde_json::from_slice::<serde_json::Value>(&request.body)
                .ok()
                .and_then(|body| body["text"]["body"].as_str().map(str::to_owned))
                .is_some_and(|body| body.contains("tel:+91") && body.contains("https://wa.me/"))
        }));
        let accepted_delivery: (uuid::Uuid, uuid::Uuid, uuid::Uuid) = sqlx::query_as(
            r#"
            SELECT reveal.id, delivery.customer_outbound_message_id,
                   delivery.professional_outbound_message_id
            FROM connection.contact_reveals AS reveal
            JOIN connection.contact_reveal_delivery AS delivery
              ON delivery.reveal_id = reveal.id
            WHERE reveal.connection_request_id = $1
            "#,
        )
        .bind(pending_connection.0)
        .fetch_one(&assertion_pool)
        .await?;
        let connection_repository =
            sahayak_persistence::ConnectionRepository::new(database.clone());
        assert!(
            connection_repository
                .record_delivery(
                    OutboundMessageId::from_uuid(accepted_delivery.1),
                    true,
                    None,
                    CorrelationId::new(),
                )
                .await?
        );
        assert!(
            connection_repository
                .record_delivery(
                    OutboundMessageId::from_uuid(accepted_delivery.2),
                    true,
                    None,
                    CorrelationId::new(),
                )
                .await?
        );
        let qualified_state: String = sqlx::query_scalar(
            "SELECT qualified_state FROM connection.contact_reveal_delivery WHERE reveal_id = $1",
        )
        .bind(accepted_delivery.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(qualified_state, "qualified");

        let account_repository = AccountRepository::new(database.clone());
        let direct_customer = account_repository
            .find(AccountId::from_uuid(reveal.2))
            .await?
            .ok_or("direct customer account missing before deletion")?;
        let sahayak_persistence::AccountMutation::Applied { version } = account_repository
            .transition_lifecycle(
                AccountId::from_uuid(reveal.2),
                direct_customer.version,
                sahayak_domain::AccountLifecycle::DeletionPending,
                CorrelationId::new(),
            )
            .await?
        else {
            return Err("direct customer deletion request conflicted".into());
        };
        assert!(matches!(
            account_repository
                .transition_lifecycle(
                    AccountId::from_uuid(reveal.2),
                    version,
                    sahayak_domain::AccountLifecycle::Deleted,
                    CorrelationId::new(),
                )
                .await?,
            sahayak_persistence::AccountMutation::Applied { .. }
        ));
        let retained_private_locations: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM private_data.service_request_locations WHERE customer_account_id = $1",
        )
        .bind(reveal.2)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(retained_private_locations, 0);

        let connection_source: (
            uuid::Uuid,
            uuid::Uuid,
            uuid::Uuid,
            uuid::Uuid,
            uuid::Uuid,
            uuid::Uuid,
        ) = sqlx::query_as(
            r#"
            SELECT connection.service_request_id, connection.candidate_id,
                   connection.provider_service_id, connection.customer_account_id,
                   connection.professional_account_id,
                   (SELECT inbound.id FROM integration.inbound_events AS inbound
                    WHERE inbound.account_id = connection.customer_account_id
                      AND NOT EXISTS (
                          SELECT 1 FROM connection.connection_requests AS used
                          WHERE used.source_inbound_event_id = inbound.id
                      )
                    ORDER BY inbound.received_at LIMIT 1)
            FROM connection.connection_requests AS connection
            WHERE connection.id = $1
            "#,
        )
        .bind(pending_connection.0)
        .fetch_one(&assertion_pool)
        .await?;
        let expired_connection_id = ConnectionRequestId::new();
        let expired_token = uuid::Uuid::new_v4();
        let expiry_job_id = OutboxJobId::new();
        let mut expired_setup = assertion_pool.begin().await?;
        sqlx::query("SELECT set_config('sahayak.connection_mutation', 'on', true)")
            .execute(&mut *expired_setup)
            .await?;
        sqlx::query(
            "UPDATE billing.professional_entitlements SET status = 'manually_waived', manually_waived_until = statement_timestamp() + INTERVAL '10 minutes' WHERE professional_account_id = $1",
        )
        .bind(connection_source.4)
        .execute(&mut *expired_setup)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO connection.connection_requests (
                id, request_token, service_request_id, candidate_id, provider_service_id,
                customer_account_id, professional_account_id, contact_mode,
                source_inbound_event_id, requested_at, response_deadline, expires_at,
                correlation_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'approval_required', $8,
                      clock_timestamp() - INTERVAL '20 minutes',
                      clock_timestamp() - INTERVAL '10 minutes',
                      clock_timestamp() - INTERVAL '10 minutes', $9)
            "#,
        )
        .bind(expired_connection_id.into_uuid())
        .bind(expired_token)
        .bind(connection_source.0)
        .bind(connection_source.1)
        .bind(connection_source.2)
        .bind(connection_source.3)
        .bind(connection_source.4)
        .bind(connection_source.5)
        .bind(CorrelationId::new().into_uuid())
        .execute(&mut *expired_setup)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO integration.outbox_jobs (
                id, connection_request_id, connection_generation, job_kind,
                idempotency_key, payload_version, payload, available_at,
                max_attempts, correlation_id, ordering_key
            ) VALUES ($1, $2, 1, 'expire_connection_request', $3, 1,
                      jsonb_build_object('connection_request_id', $2::text, 'generation', 1),
                      clock_timestamp(), 8, $4, NULL)
            "#,
        )
        .bind(expiry_job_id.into_uuid())
        .bind(expired_connection_id.into_uuid())
        .bind(format!("connection-expire-test:v1:{expired_connection_id}"))
        .bind(CorrelationId::new().into_uuid())
        .execute(&mut *expired_setup)
        .await?;
        expired_setup.commit().await?;
        assert!(processor.process_batch().await? >= 1);
        let expired_state: String =
            sqlx::query_scalar("SELECT status FROM connection.connection_requests WHERE id = $1")
                .bind(expired_connection_id.into_uuid())
                .fetch_one(&assertion_pool)
                .await?;
        assert_eq!(expired_state, "expired");
        let expired_reveals: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM connection.contact_reveals WHERE connection_request_id = $1",
        )
        .bind(expired_connection_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(expired_reveals, 0);
        sqlx::query(
            "UPDATE billing.professional_entitlements SET status = 'payment_required', manually_waived_until = NULL WHERE professional_account_id = $1",
        )
        .bind(connection_source.4)
        .execute(&assertion_pool)
        .await?;
        let decline_source_event: uuid::Uuid = sqlx::query_scalar(
            r#"
            SELECT inbound.id FROM integration.inbound_events AS inbound
            WHERE inbound.account_id = $1
              AND NOT EXISTS (
                  SELECT 1 FROM connection.connection_requests AS used
                  WHERE used.source_inbound_event_id = inbound.id
              )
            ORDER BY inbound.received_at LIMIT 1
            "#,
        )
        .bind(connection_source.3)
        .fetch_one(&assertion_pool)
        .await?;
        let declined_connection_id = ConnectionRequestId::new();
        let declined_token = uuid::Uuid::new_v4();
        let mut declined_setup = assertion_pool.begin().await?;
        sqlx::query("SELECT set_config('sahayak.connection_mutation', 'on', true)")
            .execute(&mut *declined_setup)
            .await?;
        sqlx::query("SELECT set_config('sahayak.discovery_mutation', 'on', true)")
            .execute(&mut *declined_setup)
            .await?;
        sqlx::query(
            "UPDATE billing.professional_entitlements SET status = 'manually_waived', manually_waived_until = statement_timestamp() + INTERVAL '10 minutes' WHERE professional_account_id = $1",
        )
        .bind(connection_source.4)
        .execute(&mut *declined_setup)
        .await?;
        sqlx::query(
            "UPDATE discovery.request_candidates SET excluded_at = NULL, exclusion_reason = NULL, selected_at = clock_timestamp() WHERE id = $1",
        )
        .bind(connection_source.1)
        .execute(&mut *declined_setup)
        .await?;
        sqlx::query("UPDATE discovery.service_requests SET status = 'selected' WHERE id = $1")
            .bind(connection_source.0)
            .execute(&mut *declined_setup)
            .await?;
        sqlx::query(
            r#"
            INSERT INTO connection.connection_requests (
                id, request_token, service_request_id, candidate_id, provider_service_id,
                customer_account_id, professional_account_id, contact_mode,
                source_inbound_event_id, response_deadline, expires_at, correlation_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'approval_required', $8,
                      clock_timestamp() + INTERVAL '10 minutes',
                      clock_timestamp() + INTERVAL '10 minutes', $9)
            "#,
        )
        .bind(declined_connection_id.into_uuid())
        .bind(declined_token)
        .bind(connection_source.0)
        .bind(connection_source.1)
        .bind(connection_source.2)
        .bind(connection_source.3)
        .bind(connection_source.4)
        .bind(decline_source_event)
        .bind(CorrelationId::new().into_uuid())
        .execute(&mut *declined_setup)
        .await?;
        declined_setup.commit().await?;
        prompt = process_test_conversation_turn(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &sender,
            Some(prompt),
            NormalizedContent::Text {
                body: "menu".to_owned(),
            },
        )
        .await?;
        for action in ["main.more", "more.requests"] {
            prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &sender,
                prompt,
                action,
            )
            .await?;
        }
        prompt = process_test_action(
            &processor,
            &database,
            &cryptography,
            &assertion_pool,
            &sender,
            prompt,
            &format!("request.select:{declined_token}"),
        )
        .await?;
        for action in ["request.decline", "request.confirm"] {
            prompt = process_test_action(
                &processor,
                &database,
                &cryptography,
                &assertion_pool,
                &sender,
                prompt,
                action,
            )
            .await?;
        }
        assert!(!prompt.is_empty());
        let declined: (String, i64) = sqlx::query_as(
            r#"
            SELECT connection.status,
                   (SELECT count(*) FROM connection.contact_reveals
                    WHERE connection_request_id = connection.id)
            FROM connection.connection_requests AS connection WHERE id = $1
            "#,
        )
        .bind(declined_connection_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(declined, ("declined".to_owned(), 0));
        sqlx::query(
            "UPDATE billing.professional_entitlements SET status = 'payment_required', manually_waived_until = NULL WHERE professional_account_id = $1",
        )
        .bind(connection_source.4)
        .execute(&assertion_pool)
        .await?;
        let qualified_participants: (uuid::Uuid, uuid::Uuid, uuid::Uuid, uuid::Uuid) =
            sqlx::query_as(
                r#"
            SELECT reveal.customer_account_id, reveal.professional_account_id, channel.id,
                   (SELECT id FROM identity.channel_identities
                    WHERE account_id = reveal.professional_account_id AND status = 'active'
                    ORDER BY last_seen_at DESC LIMIT 1)
            FROM connection.contact_reveals AS reveal
            JOIN identity.channel_identities AS channel
              ON channel.account_id = reveal.customer_account_id AND channel.status = 'active'
            WHERE reveal.id = $1
            ORDER BY channel.last_seen_at DESC LIMIT 1
            "#,
            )
            .bind(accepted_delivery.0)
            .fetch_one(&assertion_pool)
            .await?;
        let review_repository =
            sahayak_persistence::ReviewRepository::new(database.clone(), cryptography.clone());
        let review_id = sahayak_domain::ReviewId::new();
        let review_token = uuid::Uuid::new_v4();
        assert!(matches!(
            review_repository
                .submit(sahayak_persistence::SubmitReview {
                    review_id,
                    review_token,
                    revision_id: sahayak_domain::ReviewRevisionId::new(),
                    reveal_id: sahayak_domain::ContactRevealId::from_uuid(accepted_delivery.0),
                    reviewer_account_id: AccountId::from_uuid(qualified_participants.1),
                    reviewer_channel_identity_id: ChannelIdentityId::from_uuid(
                        qualified_participants.3,
                    ),
                    subject_account_id: AccountId::from_uuid(qualified_participants.0),
                    direction: sahayak_persistence::ReviewDirection::ProfessionalToCustomer,
                    ratings: sahayak_persistence::ReviewRatings {
                        connection_experience: 5,
                        responsiveness: 4,
                        completion: 5,
                    },
                    written_feedback: Some("Arrived promptly and communicated clearly"),
                    source_inbound_event_id: None,
                    correlation_id: CorrelationId::new(),
                })
                .await?,
            sahayak_persistence::ReviewMutation::Applied { version: 1 }
        ));
        let rating = review_repository
            .rating_summary(AccountId::from_uuid(qualified_participants.0))
            .await?;
        assert_eq!(rating.rating_count, 1);
        assert_eq!(rating.average_rating, None);
        assert!(matches!(
            review_repository
                .edit(
                    review_token,
                    AccountId::from_uuid(qualified_participants.1),
                    ChannelIdentityId::from_uuid(qualified_participants.3),
                    1,
                    sahayak_domain::ReviewRevisionId::new(),
                    sahayak_persistence::ReviewRatings {
                        connection_experience: 4,
                        responsiveness: 5,
                        completion: 4,
                    },
                    Some("Updated after the work was completed"),
                    None,
                    CorrelationId::new(),
                )
                .await?,
            sahayak_persistence::ReviewMutation::Applied { version: 2 }
        ));
        let revision_history: (i64, Option<i32>) = sqlx::query_as(
            "SELECT count(*), max(revision_number) FROM review.review_revisions WHERE review_id = $1",
        )
        .bind(review_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(revision_history, (2, Some(2)));
        assert!(matches!(
            review_repository
                .moderate(
                    admin_identity.account_id,
                    admin_identity.channel_identity_id,
                    review_token,
                    2,
                    sahayak_persistence::ReviewModerationState::Hidden,
                    "safety_review",
                    CorrelationId::new(),
                )
                .await?,
            sahayak_persistence::ReviewMutation::Applied { version: 3 }
        ));
        assert_eq!(
            review_repository
                .rating_summary(AccountId::from_uuid(qualified_participants.0))
                .await?
                .rating_count,
            0
        );
        assert!(matches!(
            review_repository
                .moderate(
                    admin_identity.account_id,
                    admin_identity.channel_identity_id,
                    review_token,
                    3,
                    sahayak_persistence::ReviewModerationState::Published,
                    "review_cleared",
                    CorrelationId::new(),
                )
                .await?,
            sahayak_persistence::ReviewMutation::Applied { version: 4 }
        ));
        assert!(
            review_repository
                .submit(sahayak_persistence::SubmitReview {
                    review_id: sahayak_domain::ReviewId::new(),
                    review_token: uuid::Uuid::new_v4(),
                    revision_id: sahayak_domain::ReviewRevisionId::new(),
                    reveal_id: sahayak_domain::ContactRevealId::from_uuid(reveal.0),
                    reviewer_account_id: AccountId::from_uuid(reveal.2),
                    reviewer_channel_identity_id: ChannelIdentityId::from_uuid(
                        customer_channel_id,
                    ),
                    subject_account_id: professional_identity.account_id,
                    direction: sahayak_persistence::ReviewDirection::CustomerToProfessional,
                    ratings: sahayak_persistence::ReviewRatings {
                        connection_experience: 5,
                        responsiveness: 5,
                        completion: 5,
                    },
                    written_feedback: None,
                    source_inbound_event_id: None,
                    correlation_id: CorrelationId::new(),
                })
                .await
                .is_err()
        );
        let entitlement = sahayak_persistence::BillingRepository::new(database.clone())
            .status(AccountId::from_uuid(qualified_participants.1))
            .await?;
        assert_eq!(entitlement.status, "payment_required");
        assert!(entitlement.payment_required);
        let _ = processor.process_batch().await?;
        assert!(processor.process_batch().await? >= 1);
        let payment_reminder: (String, bool) = sqlx::query_as(
            "SELECT state, outbound_message_id IS NOT NULL FROM billing.payment_reminders WHERE professional_account_id = $1 AND reminder_kind = 'payment_required' ORDER BY created_at DESC LIMIT 1",
        )
        .bind(qualified_participants.1)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(payment_reminder, ("sent".to_owned(), true));
        sqlx::query(
            "UPDATE billing.plans SET provider_plan_id = 'plan_test_monthly_99', state = 'active' WHERE code = 'professional_monthly_inr_99'",
        )
        .execute(&assertion_pool)
        .await?;
        let billing_repository = sahayak_persistence::BillingRepository::new(database.clone());
        assert!(
            billing_repository
                .record_hosted_subscription(
                    sahayak_domain::SubscriptionId::new(),
                    AccountId::from_uuid(qualified_participants.1),
                    "plan_test_monthly_99",
                    "sub_test_001",
                    "https://rzp.io/i/test-subscription",
                )
                .await?
        );
        let billing_event_id = "event_subscription_charged_001";
        assert_eq!(
            billing_repository
                .accept_webhook(sahayak_persistence::AcceptBillingWebhook {
                    id: sahayak_domain::BillingWebhookEventId::new(),
                    provider_event_id: billing_event_id,
                    event_type: "subscription.charged",
                    normalized_payload: &serde_json::json!({"subscription_id": "sub_test_001"}),
                })
                .await?,
            sahayak_persistence::BillingWebhookAcceptance::Accepted
        );
        assert!(
            billing_repository
                .apply_provider_event(
                    billing_event_id,
                    "sub_test_001",
                    "subscription.charged",
                    Some("payment_test_001"),
                    Some("invoice_test_001"),
                    Some("order_test_001"),
                    Some(9_900),
                    Some("INR"),
                    Some(OffsetDateTime::now_utc()),
                    Some(OffsetDateTime::now_utc() + time::Duration::days(30)),
                )
                .await?
        );
        assert_eq!(
            billing_repository
                .accept_webhook(sahayak_persistence::AcceptBillingWebhook {
                    id: sahayak_domain::BillingWebhookEventId::new(),
                    provider_event_id: billing_event_id,
                    event_type: "subscription.charged",
                    normalized_payload: &serde_json::json!({"subscription_id": "sub_test_001"}),
                })
                .await?,
            sahayak_persistence::BillingWebhookAcceptance::Duplicate
        );
        let active_entitlement = billing_repository
            .status(AccountId::from_uuid(qualified_participants.1))
            .await?;
        assert_eq!(active_entitlement.status, "active");
        let reconciliation_candidate = billing_repository
            .reconciliation_candidates(10)
            .await?
            .into_iter()
            .find(|candidate| candidate.provider_subscription_id == "sub_test_001")
            .ok_or("billing reconciliation candidate missing")?;
        assert!(
            billing_repository
                .record_reconciliation(&reconciliation_candidate, "active")
                .await?
        );
        assert!(
            !billing_repository
                .record_reconciliation(&reconciliation_candidate, "halted")
                .await?
        );
        let reconciliation_exception_id: uuid::Uuid = sqlx::query_scalar(
            "SELECT id FROM billing.reconciliation_exceptions WHERE subscription_id = $1 AND state = 'open' ORDER BY created_at DESC LIMIT 1",
        )
        .bind(reconciliation_candidate.subscription_id.into_uuid())
        .fetch_one(&assertion_pool)
        .await?;
        assert!(
            billing_repository
                .resolve_reconciliation_exception(
                    reconciliation_exception_id,
                    admin_identity.account_id,
                    admin_identity.channel_identity_id,
                    "Provider state reviewed against the local payment ledger",
                    CorrelationId::new(),
                )
                .await?
        );
        let captured_payments: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM billing.payments WHERE provider_payment_id = 'payment_test_001' AND amount_minor = 9900 AND currency = 'INR'",
        )
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(captured_payments, 1);
        let tax_documents: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM billing.tax_documents WHERE provider_invoice_id = 'invoice_test_001'",
        )
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(tax_documents, 1);
        let failed_event = "event_subscription_pending_001";
        assert_eq!(
            billing_repository
                .accept_webhook(sahayak_persistence::AcceptBillingWebhook {
                    id: sahayak_domain::BillingWebhookEventId::new(),
                    provider_event_id: failed_event,
                    event_type: "payment.failed",
                    normalized_payload: &serde_json::json!({"subscription_id": "sub_test_001"}),
                })
                .await?,
            sahayak_persistence::BillingWebhookAcceptance::Accepted
        );
        assert!(
            billing_repository
                .apply_provider_event(
                    failed_event,
                    "sub_test_001",
                    "payment.failed",
                    Some("payment_test_failed_001"),
                    Some("invoice_test_failed_001"),
                    Some("order_test_failed_001"),
                    Some(9_900),
                    Some("INR"),
                    None,
                    Some(OffsetDateTime::now_utc() + time::Duration::days(30)),
                )
                .await?
        );
        let grace = billing_repository
            .status(AccountId::from_uuid(qualified_participants.1))
            .await?;
        assert_eq!(grace.status, "past_due");
        assert!(grace.grace_period_end.is_some());
        let safety_repository =
            sahayak_persistence::SafetyRepository::new(database.clone(), cryptography.clone());
        let report_token = uuid::Uuid::new_v4();
        assert!(matches!(
            safety_repository
                .submit_report(sahayak_persistence::SubmitReport {
                    report_id: sahayak_domain::ReportId::new(),
                    report_token,
                    reveal_id: sahayak_domain::ContactRevealId::from_uuid(accepted_delivery.0),
                    reporter_account_id: AccountId::from_uuid(qualified_participants.0),
                    reporter_channel_identity_id: ChannelIdentityId::from_uuid(
                        qualified_participants.2,
                    ),
                    subject_account_id: AccountId::from_uuid(qualified_participants.1),
                    category: sahayak_persistence::ReportCategory::UnsafeBehavior,
                    severity: sahayak_persistence::ReportSeverity::High,
                    description: Some("Threatening conduct after the introduction"),
                    evidence_references: serde_json::json!([]),
                    block_subject: true,
                    source_inbound_event_id: None,
                    correlation_id: CorrelationId::new(),
                })
                .await?,
            sahayak_persistence::SafetyMutation::Applied { version: 1 }
        ));
        let subject_status = safety_repository
            .subject_status(AccountId::from_uuid(qualified_participants.1), report_token)
            .await?
            .ok_or("subject-safe report status missing")?;
        assert_eq!(subject_status.action_state, "restricted_pending_review");
        let active_restrictions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM safety.restrictions WHERE account_id = $1 AND ended_at IS NULL",
        )
        .bind(qualified_participants.1)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(active_restrictions, 1);
        assert!(matches!(
            safety_repository
                .resolve_report(
                    admin_identity.account_id,
                    admin_identity.channel_identity_id,
                    report_token,
                    1,
                    sahayak_persistence::ModerationAction::Warning,
                    "first_verified_incident",
                    "Warning issued and automatic restriction reviewed",
                    None,
                    CorrelationId::new(),
                )
                .await?,
            sahayak_persistence::SafetyMutation::Applied { version: 2 }
        ));
        let resolved_report: (String, String, i64, i64) = sqlx::query_as(
            r#"
            SELECT report.triage_state, report.action_state,
                   (SELECT count(*) FROM safety.moderation_actions WHERE report_id = report.id),
                   (SELECT count(*) FROM audit.events WHERE target_id = report.id
                    AND action = 'safety.report_resolved')
            FROM safety.reports AS report WHERE report_token = $1
            "#,
        )
        .bind(report_token)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(
            resolved_report,
            ("resolved".to_owned(), "warning".to_owned(), 1, 1)
        );
        let cancelled_event = "event_subscription_cancelled_001";
        assert_eq!(
            billing_repository
                .accept_webhook(sahayak_persistence::AcceptBillingWebhook {
                    id: sahayak_domain::BillingWebhookEventId::new(),
                    provider_event_id: cancelled_event,
                    event_type: "subscription.cancelled",
                    normalized_payload: &serde_json::json!({"subscription_id": "sub_test_001"}),
                })
                .await?,
            sahayak_persistence::BillingWebhookAcceptance::Accepted
        );
        assert!(
            billing_repository
                .apply_provider_event(
                    cancelled_event,
                    "sub_test_001",
                    "subscription.cancelled",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await?
        );
        assert_eq!(
            billing_repository
                .status(AccountId::from_uuid(qualified_participants.1))
                .await?
                .status,
            "expired"
        );
        let account_repository = AccountRepository::new(database.clone());
        let professional_account = account_repository
            .find(professional_identity.account_id)
            .await?
            .ok_or("professional account missing before deletion")?;
        let sahayak_persistence::AccountMutation::Applied { version } = account_repository
            .transition_lifecycle(
                professional_identity.account_id,
                professional_account.version,
                sahayak_domain::AccountLifecycle::DeletionPending,
                CorrelationId::new(),
            )
            .await?
        else {
            return Err("professional deletion request conflicted".into());
        };
        assert!(matches!(
            account_repository
                .transition_lifecycle(
                    professional_identity.account_id,
                    version,
                    sahayak_domain::AccountLifecycle::Deleted,
                    CorrelationId::new(),
                )
                .await?,
            sahayak_persistence::AccountMutation::Applied { .. }
        ));
        let erased_contact_payload: bool = sqlx::query_scalar(
            "SELECT payload_ciphertext IS NULL FROM messaging.outbound_messages WHERE id = $1",
        )
        .bind(direct_customer_outbound)
        .fetch_one(&assertion_pool)
        .await?;
        assert!(erased_contact_payload);
        let retained_reveal_without_private_links: (bool, bool) = sqlx::query_as(
            "SELECT availability_epoch_id IS NULL, availability_consumption_id IS NULL FROM connection.contact_reveals WHERE id = $1",
        )
        .bind(reveal.0)
        .fetch_one(&assertion_pool)
        .await?;
        assert_eq!(retained_reveal_without_private_links, (true, true));
        assertion_pool.close().await;
        database.close().await;
        Ok(())
    }

    async fn process_test_action(
        processor: &WhatsAppJobProcessor,
        database: &Database,
        cryptography: &CryptoService,
        pool: &PgPool,
        sender: &str,
        prompt: String,
        action: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        process_test_conversation_turn(
            processor,
            database,
            cryptography,
            pool,
            sender,
            Some(prompt),
            NormalizedContent::Action {
                source: "button_reply".to_owned(),
                id: action.to_owned(),
                title: None,
                description: None,
            },
        )
        .await
    }

    async fn process_test_conversation_turn(
        processor: &WhatsAppJobProcessor,
        database: &Database,
        cryptography: &CryptoService,
        pool: &PgPool,
        sender: &str,
        context_message_id: Option<String>,
        content: NormalizedContent,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let event_id = accept_conversation_message(
            database,
            cryptography,
            sender,
            context_message_id,
            content,
        )
        .await?;
        assert!(processor.process_batch().await? >= 1);
        assert!(processor.process_batch().await? >= 1);
        Ok(sqlx::query_scalar(
            r#"
            SELECT provider_message_id
            FROM messaging.outbound_messages
            WHERE idempotency_key = $1 AND submission_state = 'accepted'
            "#,
        )
        .bind(format!("conversation-turn:v1:{event_id}"))
        .fetch_one(pool)
        .await?)
    }

    async fn accept_conversation_message(
        database: &Database,
        cryptography: &CryptoService,
        sender: &str,
        context_message_id: Option<String>,
        content: NormalizedContent,
    ) -> Result<InboundEventId, Box<dyn std::error::Error>> {
        let event_id = InboundEventId::new();
        let event = NormalizedEvent {
            provider_event_id: format!("message:{event_id}"),
            event_type: "message.received".to_owned(),
            occurred_at: Some(OffsetDateTime::now_utc()),
            payload: NormalizedPayload::Message {
                provider_message_id: format!("wamid.inbound.{event_id}"),
                sender_wa_id: sender.to_owned(),
                sender_phone_e164: format!("+{sender}"),
                context_message_id,
                content,
                error_codes: Vec::new(),
            },
        };
        let normalized = serde_json::to_vec(&event)?;
        let encrypted = cryptography.encrypt(
            EncryptionPurpose::Integration,
            EncryptionContext::new(
                EncryptionNamespace::INBOUND_EVENT_PAYLOAD,
                event_id.into_uuid(),
            ),
            &normalized,
        )?;
        let (fingerprint_key_version, payload_fingerprint) =
            cryptography.blind_index("integration:whatsapp:event:v1", &normalized)?;
        database
            .accept_inbound_event(&InboundEventInput {
                event_id,
                provider_code: "whatsapp".to_owned(),
                provider_namespace: "test-waba:123456".to_owned(),
                provider_event_id: event.provider_event_id,
                event_type: event.event_type,
                payload: EncryptedEventPayload {
                    purpose: EncryptionPurpose::Integration,
                    schema_version: 1,
                    ciphertext: encrypted.ciphertext,
                    nonce: encrypted.nonce,
                    fingerprint_key_version,
                    payload_fingerprint,
                    additional_fingerprints: Vec::new(),
                    key_version: encrypted.key_version,
                },
                correlation_id: CorrelationId::new(),
                signature_verified_at: OffsetDateTime::now_utc(),
                provider_occurred_at: event.occurred_at,
                processing_job_id: OutboxJobId::new(),
                processing_job_kind: "process_conversation_message".to_owned(),
                processing_ordering_key: Some([13; 32]),
                max_attempts: 3,
            })
            .await?;
        Ok(event_id)
    }

    fn crypto_service() -> Result<CryptoService, Box<dyn std::error::Error>> {
        Ok(CryptoService::new(
            vec![
                EncryptionKeySet::new(
                    EncryptionPurpose::Contact,
                    1,
                    vec![VersionedKey::from_bytes(1, [97; 32])?],
                ),
                EncryptionKeySet::new(
                    EncryptionPurpose::Integration,
                    1,
                    vec![VersionedKey::from_bytes(1, [99; 32])?],
                ),
                EncryptionKeySet::new(
                    EncryptionPurpose::Media,
                    1,
                    vec![VersionedKey::from_bytes(1, [103; 32])?],
                ),
            ],
            1,
            vec![VersionedKey::from_bytes(1, [101; 32])?],
        )?)
    }

    fn database_settings(url: String) -> DatabaseSettings {
        DatabaseSettings {
            url: SecretString::from(url),
            min_connections: 1,
            max_connections: 5,
            acquire_timeout_seconds: 5,
            idle_timeout_seconds: 30,
            max_lifetime_seconds: 60,
            statement_timeout_milliseconds: 10_000,
            lock_timeout_milliseconds: 5_000,
            idle_in_transaction_timeout_milliseconds: 10_000,
            require_tls: false,
        }
    }

    async fn cleanup_incomplete_sends(pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE messaging.outbound_messages
            SET
                submission_state = CASE WHEN submission_state = 'sending' THEN 'unknown' ELSE 'rejected' END,
                send_lease_token = NULL,
                unknown_at = CASE WHEN submission_state = 'sending' THEN statement_timestamp() ELSE NULL END,
                rejected_at = CASE WHEN submission_state = 'queued' THEN statement_timestamp() ELSE NULL END,
                last_error_class = 'test_cleanup',
                last_error_code = 'test_cleanup'
            WHERE submission_state IN ('queued', 'sending')
            "#,
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r#"
            UPDATE integration.outbox_jobs
            SET
                state = 'dead_lettered',
                attempt_count = GREATEST(attempt_count, 1),
                lease_owner = NULL,
                lease_token = NULL,
                lease_started_at = NULL,
                lease_expires_at = NULL,
                last_error_class = 'test_cleanup',
                last_error_code = 'test_cleanup',
                last_error_at = statement_timestamp(),
                dead_lettered_at = statement_timestamp(),
                dead_letter_reason = 'test_cleanup'
            WHERE job_kind IN (
                'send_whatsapp_message',
                'process_whatsapp_status',
                'process_whatsapp_probe',
                'process_conversation_message',
                'process_provider_error'
            )
              AND state IN ('pending', 'leased')
            "#,
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}
