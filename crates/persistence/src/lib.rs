//! PostgreSQL repositories for identity, messaging, and professional profiles.

mod account;
mod administrator;
mod audit;
mod availability;
mod billing;
mod connection;
mod consent;
mod conversation;
mod conversation_turn;
mod database;
mod delivery;
mod discovery;
mod error;
mod identity;
mod identity_verification;
mod inbound;
mod key_registry;
mod migration;
mod operations;
mod outbound;
mod outbox;
mod photo;
mod private_identity;
mod profile;
mod review;
mod safety;
mod trust_effect;
mod turn_effect;

pub use account::{AccountMutation, AccountRepository, AccountSnapshot};
pub use administrator::{
    AdministratorAllowlistRepository, AdministratorGrantOutcome, GrantAdministratorAccess,
    RevokeAdministratorAccess,
};
pub use audit::{AuditActor, AuditRepository, AuditSource, NewAuditEvent};
pub use availability::{
    ADVANCE_AVAILABILITY_JOB, AvailabilityConversationSnapshot, AvailabilityEffectContext,
    AvailabilityEpochSnapshot, AvailabilityIneligibility, AvailabilityLocalExpiry,
    AvailabilityMutationOutcome, AvailabilityNotificationTarget, AvailabilityRepository,
    AvailabilityTimerContext, AvailabilityTimerOutcome, AvailabilityTimerPurpose,
    AvailabilityTurnEffect, AvailabilityTurnOperation, CapacityConsumptionOutcome,
    REMIND_AVAILABILITY_JOB,
};
pub use billing::{
    AcceptBillingWebhook, BillingReconciliationCandidate, BillingRepository,
    BillingWebhookAcceptance, PaymentReminder, SubscriptionStatus,
};
pub use connection::{
    BlockRepository, CUSTOMER_FREE_REVEAL_LIMIT, ConnectionEffectContext,
    ConnectionMutationOutcome, ConnectionOutboundIds, ConnectionRepository, ConnectionTimerOutcome,
    ConnectionTurnEffect, ConnectionTurnOperation, ContactPhoto, ContactTarget,
    EXPIRE_CONNECTION_JOB, IntroductionSummary, PendingConnectionSummary,
    PendingCustomerConnection, PendingResponseContext, RecentContactSummary, RepeatRevealContext,
    SelectionContext,
};
pub use consent::{
    ConsentDocument, ConsentRecordOutcome, ProfessionalConsentRepository, RecordProfessionalConsent,
};
pub use conversation::{
    ConversationRepository, ConversationSession, NewConversationSession, SessionMutation,
};
pub use conversation_turn::{
    CommitConversationTurn, CommitConversationTurnWithEffects, ConversationSessionChange,
    ConversationTurnRecord, ConversationTurnRepository, EffectfulTurnCommitOutcome,
    PersistedConversationSession, TurnCommitOutcome, TurnDisposition,
};
pub use database::Database;
pub use delivery::{DeliveryRecordOutcome, DeliveryRepository, DeliveryStatusInput};
pub use discovery::{
    DiscoveryCard, DiscoveryCategory, DiscoveryConversationSnapshot, DiscoveryEffectContext,
    DiscoveryMutationOutcome, DiscoveryRepository, DiscoveryRequestSnapshot, DiscoveryTurnEffect,
    DiscoveryTurnOperation, MATCHING_VERSION,
};
pub use error::PersistenceError;
pub use identity::{
    CreatedWhatsAppAccount, FoundChannelIdentity, IdentityRepository, LookupDigest,
    NewWhatsAppAccount, ResolveIdentityOutcome, ResolvedWhatsAppIdentity,
};
pub use identity_verification::{
    IdentityAttemptMutation, IdentityAttemptOutcome, IdentityBadgeProjection,
    IdentityVerificationRepository, RecordIdentityVerificationCallback,
    StartIdentityVerificationAttempt, VerificationCallbackKind, VerificationCallbackOutcome,
};
pub use inbound::{
    Acceptance, EncryptedEventPayload, EncryptedInboundEvent, InboundEventInput,
    InboundIdentityBinding,
};
pub use key_registry::KeyRegistryRepository;
pub use operations::{OperationalMetrics, OperationsRepository, RetentionOutcome};
pub use outbound::{
    BeginSubmission, EncryptedOutboundMessage, EncryptedOutboundPayload, OutboundDeliveryContext,
    OutboundMutation, OutboundQueueOutcome, OutboundRepository, QueueOutboundMessage,
};
pub use outbox::{
    ClaimRequest, ClaimedJob, FailureDisposition, FailureOutcome, JobLease, LeaseOutcome,
    OutboxRepository,
};
pub use photo::{AttachSanitizedProfilePhoto, ProfilePhotoMutation, ProfilePhotoRepository};
pub use private_identity::{
    EncryptedPrivateIdentity, PrivateIdentityMutation, PrivateIdentityRepository,
    SavePrivateIdentity,
};
pub use profile::{
    AdministratorConversationSnapshot, AdministratorConversationTarget, ApplyProfileDecision,
    ApplyProfileDecisionOutcome, BeginProfessionalDraft, ProfessionalConversationSnapshot,
    ProfessionalConversationStatus, ProfessionalConversationSummary, ProfessionalDraftSnapshot,
    ProfessionalNotificationTarget, ProfessionalOnboardingContext, ProfessionalProfileRepository,
    ProfessionalRequirement, ProfessionalServiceInput, ProfessionalServiceSnapshot,
    ProfileMutation, ProfileReviewTarget, PublishedProfessionalProfile, SubmitProfileOutcome,
};
pub use review::{
    RatingSummary, ReviewDirection, ReviewModerationState, ReviewMutation, ReviewRatings,
    ReviewRepository, SubmitReview,
};
pub use safety::{
    AdministratorReportItem, ModerationAction, ReportCategory, ReportSeverity, SafetyMutation,
    SafetyRepository, SubjectReportStatus, SubmitReport,
};
pub use trust_effect::{TrustTurnEffect, TrustTurnOperation};
pub use turn_effect::{
    AdministratorReviewTurnEffect, ConversationTurnEffect, ConversationTurnEffects,
    ProfessionalConsentAcceptance, ProfessionalTurnEffect, ProfessionalTurnOperation,
    professional_consent_document_set_digest,
};
