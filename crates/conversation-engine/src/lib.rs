//! Deterministic provider-neutral conversation decisions and reply specifications.

mod administrator;
mod availability;
mod discovery;
mod engine;
mod input;
mod model;
mod professional;
mod render;
mod requests;
mod safety_admin;
mod trust;

pub use engine::{ConversationEngine, EngineError};
pub use input::{ActionId, InputError, NormalizedText, UserInput};
pub use model::{
    AccountCommand, AdminCommand, AdminQueueItem, AdminReviewDecision, AdminState, AdminView,
    AllowedAdminView, AvailabilityCommand, AvailabilityDuration, AvailabilityEpochView,
    AvailabilityIneligibility, AvailabilityIntent, AvailabilityLocalExpiry,
    AvailabilityObservation, AvailabilityObservationState, AvailabilityOutcome, AvailabilityState,
    AvailabilityView, BillingView, BusinessCommand, ButtonSpec, CategorySelection,
    ConnectionCommand, ConnectionsView, ContactMode, ContactSessionLimit, ConversationContext,
    ConversationDisposition, ConversationState, DiscoveryCardView, DiscoveryCommand,
    DiscoveryState, DiscoveryStatus, DiscoveryView, IdentityCheckStatus, InvalidOpaqueTargetToken,
    ListRowSpec, LocalServiceMode, MAX_ADMIN_QUEUE_PAGE, OpaqueTargetToken,
    PROFESSIONAL_CONSENT_VERSION, PendingConnectionView, PendingCustomerConnectionView,
    ProfessionalCommand, ProfessionalFlowMode, ProfessionalRequestsState, ProfessionalResumeStep,
    ProfessionalState, ProfessionalStatus, ProfessionalSummary, ProfessionalView, ProfileFieldCode,
    ProfilePhotoStatus, RecentContactView, ReplyControls, ReplySpec, RequestedTimeChoice,
    ReviewReasonCode, SafetyAdminAction, SafetyAdminReportView, SafetyAdminState, SafetyAdminView,
    SafetyModerationCommand, ServiceCategory, ServiceContactPreference, ServiceRadius,
    ServiceSkill, SessionChange, SessionSnapshot, SessionTerminalStatus, TrustCommand,
    TrustIntroductionView, TrustState, TrustView, TurnPlan, Workflow,
};
