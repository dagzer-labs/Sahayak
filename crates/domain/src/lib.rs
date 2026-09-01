//! Channel-independent identifiers and business values for Sahayak.

mod identifier;
mod profile;
mod state;

pub use identifier::{
    AccountBlockId, AccountId, AdministratorGrantId, AuditEventId, AvailabilityConsumptionId,
    AvailabilityEpochId, BillingWebhookEventId, CallbackToken, ChannelIdentityId,
    ConnectionRequestId, ContactRevealId, ConversationSessionId, CorrelationId,
    CustomerAllowanceEventId, DeliveryEventId, IdentityVerificationAttemptId,
    IdentityVerificationCallbackReceiptId, InboundEventId, JobLeaseToken, OutboundMessageId,
    OutboxJobId, PaymentId, ProfessionalConsentEventId, ProfilePhotoId, ProfileReviewDecisionId,
    ProfileRevisionId, ProviderServiceId, PublicProfileId, PublicProfileReference, ReportId,
    RequestCandidateId, ReviewId, ReviewRevisionId, SafetyRestrictionId, ServiceRequestId,
    SubscriptionId, WorkerId,
};
pub use profile::{
    DisplayNameError, ProfessionalDisplayName, ProfessionalLanguage, ServiceRadiusKm,
};
pub use state::{
    AccountLifecycle, AccountRole, AuditActorType, AvailabilityDuration, AvailabilityEpochState,
    ChannelIdentityState, ConnectionRequestState, ConsentAction, ContactMode,
    ContactRevealDeliveryState, ConversationStatus, IdentityVerificationState, LocalServiceMode,
    OutboxState, ProfessionalConsentPurpose, ProfilePhotoState, ProfileReviewDecision,
    ProfileReviewReason, ProfileRevisionState, ProfileVisibility, QualifiedIntroductionState,
    RequestedTimeWindow, RiskState, ServiceRequestState, UnknownState,
};
