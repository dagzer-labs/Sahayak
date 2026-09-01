use sahayak_domain::{ConversationSessionId, CorrelationId, OutboundMessageId};
use sahayak_localization::Locale;
use serde::{Deserialize, Deserializer, Serialize, de};
use std::fmt;
use thiserror::Error;

/// Version of the professional publication consent shown by this engine.
pub const PROFESSIONAL_CONSENT_VERSION: u16 = 1;

/// Maximum administrator queue page accepted from persisted session state.
pub const MAX_ADMIN_QUEUE_PAGE: u8 = 99;

/// Code-defined workflow identity and version.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Workflow {
    /// First-contact or settings language selection.
    AccountLocaleV1,
    /// Safe root menu.
    MainMenuV1,
    /// Secondary account and help choices.
    MoreMenuV1,
    /// Safety and product-boundary information.
    HelpMenuV1,
    /// Professional onboarding, editing, and status.
    ProfessionalProfileV1,
    /// Administrator profile review.
    AdministratorReviewV1,
    /// Professional availability and renewal controls.
    ProfessionalAvailabilityV1,
    /// Customer service discovery and result selection.
    CustomerDiscoveryV1,
    /// Professional approval-required request decisions.
    ProfessionalRequestsV1,
    /// Two-sided review, report, and block workflows.
    TrustSafetyV1,
    /// Administrator safety-report triage.
    AdministratorSafetyV1,
}

impl Workflow {
    /// Stable database workflow code.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::AccountLocaleV1 => "account.locale",
            Self::MainMenuV1 => "main_menu",
            Self::MoreMenuV1 => "more_menu",
            Self::HelpMenuV1 => "help_menu",
            Self::ProfessionalProfileV1 => "professional.profile",
            Self::AdministratorReviewV1 => "administrator.review",
            Self::ProfessionalAvailabilityV1 => "professional.availability",
            Self::CustomerDiscoveryV1 => "customer.discovery",
            Self::ProfessionalRequestsV1 => "professional.requests",
            Self::TrustSafetyV1 => "trust.safety",
            Self::AdministratorSafetyV1 => "administrator.safety",
        }
    }

    /// Exact workflow contract version.
    #[must_use]
    pub const fn version(self) -> i16 {
        1
    }
}

/// Whether a professional is completing an initial profile or editing one.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfessionalFlowMode {
    Initial,
    Edit,
}

impl ProfessionalFlowMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Edit => "edit",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "initial" => Some(Self::Initial),
            "edit" => Some(Self::Edit),
            _ => None,
        }
    }
}

/// Seeded service category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceCategory {
    Plumber,
    Electrician,
}

impl ServiceCategory {
    /// Stable persistence and command code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plumber => "plumber",
            Self::Electrician => "electrician",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "plumber" => Some(Self::Plumber),
            "electrician" => Some(Self::Electrician),
            _ => None,
        }
    }
}

/// Bounded selection of seeded categories.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CategorySelection {
    pub plumber: bool,
    pub electrician: bool,
}

impl CategorySelection {
    /// Creates a category selection.
    #[must_use]
    pub const fn new(plumber: bool, electrician: bool) -> Self {
        Self {
            plumber,
            electrician,
        }
    }

    /// Returns whether at least one category is selected.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.plumber && !self.electrician
    }

    /// Returns selected categories in stable display order.
    #[must_use]
    pub fn values(self) -> Vec<ServiceCategory> {
        let mut categories = Vec::with_capacity(2);
        if self.plumber {
            categories.push(ServiceCategory::Plumber);
        }
        if self.electrician {
            categories.push(ServiceCategory::Electrician);
        }
        categories
    }

    pub(crate) const fn toggled(self, category: ServiceCategory) -> Self {
        match category {
            ServiceCategory::Plumber => Self::new(!self.plumber, self.electrician),
            ServiceCategory::Electrician => Self::new(self.plumber, !self.electrician),
        }
    }

    pub(crate) const fn contains(self, category: ServiceCategory) -> bool {
        match category {
            ServiceCategory::Plumber => self.plumber,
            ServiceCategory::Electrician => self.electrician,
        }
    }
}

/// Seeded category-specific skill.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceSkill {
    LeakRepair,
    TapAndFixture,
    DrainClearing,
    HomeWiring,
    SwitchAndSocket,
    FanInstallation,
}

impl ServiceSkill {
    /// Stable persistence and command code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeakRepair => "leak_repair",
            Self::TapAndFixture => "tap_and_fixture",
            Self::DrainClearing => "drain_clearing",
            Self::HomeWiring => "home_wiring",
            Self::SwitchAndSocket => "switch_and_socket",
            Self::FanInstallation => "fan_installation",
        }
    }

    /// Owning category.
    #[must_use]
    pub const fn category(self) -> ServiceCategory {
        match self {
            Self::LeakRepair | Self::TapAndFixture | Self::DrainClearing => {
                ServiceCategory::Plumber
            }
            Self::HomeWiring | Self::SwitchAndSocket | Self::FanInstallation => {
                ServiceCategory::Electrician
            }
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "leak_repair" => Some(Self::LeakRepair),
            "tap_and_fixture" => Some(Self::TapAndFixture),
            "drain_clearing" => Some(Self::DrainClearing),
            "home_wiring" => Some(Self::HomeWiring),
            "switch_and_socket" => Some(Self::SwitchAndSocket),
            "fan_installation" => Some(Self::FanInstallation),
            _ => None,
        }
    }
}

/// How a professional serves local customers.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalServiceMode {
    TravelToCustomer,
    CustomerVisits,
    Both,
}

impl LocalServiceMode {
    /// Stable command code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TravelToCustomer => "travel_to_customer",
            Self::CustomerVisits => "customer_visits",
            Self::Both => "both",
        }
    }
}

/// Seeded service radius in kilometres.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRadius {
    Km2,
    Km5,
    Km10,
    Km25,
}

impl ServiceRadius {
    /// Numeric radius in kilometres.
    #[must_use]
    pub const fn kilometres(self) -> u8 {
        match self {
            Self::Km2 => 2,
            Self::Km5 => 5,
            Self::Km10 => 10,
            Self::Km25 => 25,
        }
    }
}

/// How a customer may contact a professional for one category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactMode {
    Direct,
    ApprovalRequired,
}

impl ContactMode {
    /// Stable command code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::ApprovalRequired => "approval_required",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "direct" => Some(Self::Direct),
            "approval_required" => Some(Self::ApprovalRequired),
            _ => None,
        }
    }
}

/// Maximum introductions in one contact session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactSessionLimit {
    One,
    Three,
    Five,
    Ten,
}

impl ContactSessionLimit {
    /// Numeric limit.
    #[must_use]
    pub const fn value(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Three => 3,
            Self::Five => 5,
            Self::Ten => 10,
        }
    }
}

/// Publication-safe photo state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfilePhotoStatus {
    None,
    Present,
}

/// Publication-safe identity-check state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCheckStatus {
    NotChecked,
    Checked,
}

/// One category's contact preference.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceContactPreference {
    pub category: ServiceCategory,
    pub mode: ContactMode,
}

/// Privacy-safe fields suitable for profile previews and review.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProfessionalSummary {
    pub display_name: String,
    pub categories: CategorySelection,
    pub skills: Vec<ServiceSkill>,
    pub local_mode: LocalServiceMode,
    pub radius: ServiceRadius,
    pub service_languages: Vec<Locale>,
    pub contact_preferences: Vec<ServiceContactPreference>,
    pub contact_session_limit: ContactSessionLimit,
    pub photo: ProfilePhotoStatus,
    pub identity_check: IdentityCheckStatus,
}

/// Professional profile lifecycle as understood by the conversation layer.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfessionalStatus {
    #[default]
    NotStarted,
    Draft,
    PendingReview,
    ChangesRequested,
    Approved,
    Rejected,
    Hidden,
}

/// Fixed profile field code used for edits and requested changes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileFieldCode {
    DisplayName,
    Services,
    ServiceArea,
    Languages,
    Contact,
    Photo,
}

impl ProfileFieldCode {
    /// Stable field code used by persistence and review commands.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DisplayName => "display_name",
            Self::Services => "services",
            Self::ServiceArea => "service_area",
            Self::Languages => "languages",
            Self::Contact => "contact",
            Self::Photo => "photo",
        }
    }

    /// Parses a supported fixed field code.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "display_name" => Some(Self::DisplayName),
            "services" => Some(Self::Services),
            "service_area" => Some(Self::ServiceArea),
            "languages" => Some(Self::Languages),
            "contact" => Some(Self::Contact),
            "photo" => Some(Self::Photo),
            _ => None,
        }
    }
}

/// Resume point computed by persistence from durable draft completeness.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfessionalResumeStep {
    DisplayName,
    Categories,
    Skills,
    ServiceArea,
    Location,
    Radius,
    Languages,
    Contact,
    ContactLimit,
    Photo,
    Disclosure,
    Consent,
    Summary,
}

/// Provider-neutral, privacy-safe professional snapshot supplied by the caller.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProfessionalView {
    pub status: ProfessionalStatus,
    pub version: Option<i64>,
    pub summary: Option<ProfessionalSummary>,
    pub resume_step: Option<ProfessionalResumeStep>,
    pub requested_changes: Vec<ProfileFieldCode>,
    pub review_reason: Option<ReviewReasonCode>,
    pub accepted_consent_version: Option<u16>,
}

/// Opaque persistence lookup token safe for bounded conversation state.
#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OpaqueTargetToken(String);

/// Invalid opaque token supplied at an integration boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("opaque target token must be a bounded ASCII machine token")]
pub struct InvalidOpaqueTargetToken;

impl OpaqueTargetToken {
    /// Validates an opaque token. The token must not encode a profile ID or name.
    pub fn parse(value: &str) -> Result<Self, InvalidOpaqueTargetToken> {
        let valid = !value.is_empty()
            && value.len() <= 64
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_uppercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_')
            });
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidOpaqueTargetToken)
        }
    }

    /// Returns the opaque token for persistence lookup only.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OpaqueTargetToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueTargetToken([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for OpaqueTargetToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

/// Fixed bounded administrator review reason.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewReasonCode {
    IncompleteDetails,
    ServiceMismatch,
    PhotoConcern,
    PolicyViolation,
}

impl ReviewReasonCode {
    /// Stable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IncompleteDetails => "incomplete_details",
            Self::ServiceMismatch => "service_mismatch",
            Self::PhotoConcern => "photo_concern",
            Self::PolicyViolation => "policy_violation",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "incomplete_details" => Some(Self::IncompleteDetails),
            "service_mismatch" => Some(Self::ServiceMismatch),
            "photo_concern" => Some(Self::PhotoConcern),
            "policy_violation" => Some(Self::PolicyViolation),
            _ => None,
        }
    }
}

/// Administrator review decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminReviewDecision {
    Approve,
    ChangesRequested,
    Reject,
}

impl AdminReviewDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::ChangesRequested => "changes_requested",
            Self::Reject => "reject",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "approve" => Some(Self::Approve),
            "changes_requested" => Some(Self::ChangesRequested),
            "reject" => Some(Self::Reject),
            _ => None,
        }
    }
}

/// One privacy-safe item in the pending administrator queue.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdminQueueItem {
    pub target: OpaqueTargetToken,
    pub version: i64,
    pub summary: ProfessionalSummary,
}

/// Data available after administrator authorization succeeds.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AllowedAdminView {
    pub pending: Vec<AdminQueueItem>,
    /// Selected item loaded by opaque token for inspect/confirm states.
    pub selected: Option<AdminQueueItem>,
}

/// Provider-neutral administrator authorization and review snapshot.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminView {
    #[default]
    Denied,
    Allowed(AllowedAdminView),
}

/// Typed professional workflow state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProfessionalState {
    DisplayNameInput {
        mode: ProfessionalFlowMode,
    },
    DisplayNameConfirm {
        mode: ProfessionalFlowMode,
    },
    Categories {
        mode: ProfessionalFlowMode,
        selected: CategorySelection,
    },
    Skills {
        mode: ProfessionalFlowMode,
        categories: CategorySelection,
        category: ServiceCategory,
        selected: Vec<ServiceSkill>,
    },
    ServiceArea {
        mode: ProfessionalFlowMode,
        categories: CategorySelection,
    },
    Location {
        mode: ProfessionalFlowMode,
        categories: CategorySelection,
    },
    Radius {
        mode: ProfessionalFlowMode,
        categories: CategorySelection,
    },
    Languages {
        mode: ProfessionalFlowMode,
        categories: CategorySelection,
        selected: Vec<Locale>,
    },
    ContactMode {
        mode: ProfessionalFlowMode,
        categories: CategorySelection,
        category: ServiceCategory,
    },
    ContactLimit {
        mode: ProfessionalFlowMode,
    },
    Photo {
        mode: ProfessionalFlowMode,
    },
    Disclosure {
        mode: ProfessionalFlowMode,
    },
    Consent {
        mode: ProfessionalFlowMode,
        version: u16,
        document_set_digest: Option<[u8; 32]>,
    },
    Summary {
        mode: ProfessionalFlowMode,
    },
    Status,
    EditMenu,
}

/// Typed administrator workflow state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AdminState {
    Queue {
        page: u8,
    },
    Inspect {
        target: OpaqueTargetToken,
        target_version: i64,
    },
    Reason {
        target: OpaqueTargetToken,
        target_version: i64,
        decision: AdminReviewDecision,
    },
    Confirm {
        target: OpaqueTargetToken,
        target_version: i64,
        decision: AdminReviewDecision,
        reason: Option<ReviewReasonCode>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyAdminAction {
    NoAction,
    Warning,
    TemporarySuspension,
    PermanentRemoval,
}

impl SafetyAdminAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoAction => "no_action",
            Self::Warning => "warning",
            Self::TemporarySuspension => "temporary_suspension",
            Self::PermanentRemoval => "permanent_removal",
        }
    }
    fn parse(value: &str) -> Option<Self> {
        match value {
            "no_action" => Some(Self::NoAction),
            "warning" => Some(Self::Warning),
            "temporary_suspension" => Some(Self::TemporarySuspension),
            "permanent_removal" => Some(Self::PermanentRemoval),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SafetyAdminState {
    Queue,
    Inspect {
        report_token: String,
        version: i64,
    },
    Confirm {
        report_token: String,
        version: i64,
        action: SafetyAdminAction,
    },
    Done,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyAdminReportView {
    pub report_token: String,
    pub version: i64,
    pub category: String,
    pub severity: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum SafetyAdminView {
    #[default]
    Denied,
    Allowed {
        reports: Vec<SafetyAdminReportView>,
    },
}

/// Supported availability duration choices.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityDuration {
    OneHour,
    FourHours,
    EndOfLocalDay,
}

impl AvailabilityDuration {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OneHour => "one_hour",
            Self::FourHours => "four_hours",
            Self::EndOfLocalDay => "end_of_local_day",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "one_hour" => Some(Self::OneHour),
            "four_hours" => Some(Self::FourHours),
            "end_of_local_day" => Some(Self::EndOfLocalDay),
            _ => None,
        }
    }
}

/// Safe reason availability controls cannot currently be used.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityIneligibility {
    ProfessionalRoleRequired,
    ProfileApprovalRequired,
    AccountSuspended,
    InvalidTimeZone,
    TooManyChanges,
}

/// Numeric local expiry representation supplied by persistence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AvailabilityLocalExpiry {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
}

/// Current availability epoch fields safe to show to its professional owner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AvailabilityEpochView {
    pub generation: u32,
    pub version: i64,
    pub local_expiry: AvailabilityLocalExpiry,
    pub contacts_used: u8,
    pub contact_limit: u8,
    pub successor: Option<AvailabilityDuration>,
}

/// Current availability projection supplied by persistence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AvailabilityView {
    Ineligible(AvailabilityIneligibility),
    Unavailable,
    Expired(AvailabilityEpochView),
    Available(AvailabilityEpochView),
    Stopped(AvailabilityEpochView),
    CapacityPaused(AvailabilityEpochView),
}

impl Default for AvailabilityView {
    fn default() -> Self {
        Self::Ineligible(AvailabilityIneligibility::ProfessionalRoleRequired)
    }
}

impl AvailabilityView {
    #[must_use]
    pub const fn observation(self) -> AvailabilityObservation {
        match self {
            Self::Ineligible(_) => {
                AvailabilityObservation::new(AvailabilityObservationState::Ineligible, None, None)
            }
            Self::Unavailable => {
                AvailabilityObservation::new(AvailabilityObservationState::Unavailable, None, None)
            }
            Self::Expired(epoch) => AvailabilityObservation::new(
                AvailabilityObservationState::Expired,
                Some(epoch.generation),
                Some(epoch.version),
            ),
            Self::Available(epoch) => AvailabilityObservation::new(
                AvailabilityObservationState::Available,
                Some(epoch.generation),
                Some(epoch.version),
            ),
            Self::Stopped(epoch) => AvailabilityObservation::new(
                AvailabilityObservationState::Stopped,
                Some(epoch.generation),
                Some(epoch.version),
            ),
            Self::CapacityPaused(epoch) => AvailabilityObservation::new(
                AvailabilityObservationState::CapacityPaused,
                Some(epoch.generation),
                Some(epoch.version),
            ),
        }
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        match self {
            Self::Ineligible(_) | Self::Unavailable => true,
            Self::Available(epoch) => {
                availability_epoch_valid(epoch) && epoch.contacts_used < epoch.contact_limit
            }
            Self::Stopped(epoch) | Self::Expired(epoch) => availability_epoch_valid(epoch),
            Self::CapacityPaused(epoch) => {
                availability_epoch_valid(epoch) && epoch.contacts_used == epoch.contact_limit
            }
        }
    }
}

const fn availability_epoch_valid(epoch: AvailabilityEpochView) -> bool {
    epoch.generation > 0
        && epoch.version > 0
        && epoch.local_expiry.month >= 1
        && epoch.local_expiry.month <= 12
        && epoch.local_expiry.day >= 1
        && epoch.local_expiry.day <= 31
        && epoch.local_expiry.hour <= 23
        && epoch.local_expiry.minute <= 59
        && epoch.contact_limit >= 1
        && epoch.contact_limit <= 10
        && epoch.contacts_used <= epoch.contact_limit
}

/// Minimal optimistic state retained in non-sensitive conversation JSON.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AvailabilityObservation {
    pub state: AvailabilityObservationState,
    pub generation: Option<u32>,
    pub version: Option<i64>,
}

impl AvailabilityObservation {
    const fn new(
        state: AvailabilityObservationState,
        generation: Option<u32>,
        version: Option<i64>,
    ) -> Self {
        Self {
            state,
            generation,
            version,
        }
    }

    pub(crate) const fn is_valid(self) -> bool {
        if matches!(
            self.state,
            AvailabilityObservationState::Ineligible | AvailabilityObservationState::Unavailable
        ) {
            self.generation.is_none() && self.version.is_none()
        } else {
            self.generation.is_some() && self.version.is_some()
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AvailabilityObservationState {
    Ineligible,
    Unavailable,
    Expired,
    Available,
    Stopped,
    CapacityPaused,
}

impl AvailabilityObservationState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ineligible => "ineligible",
            Self::Unavailable => "unavailable",
            Self::Expired => "expired",
            Self::Available => "available",
            Self::Stopped => "stopped",
            Self::CapacityPaused => "capacity_paused",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "ineligible" => Some(Self::Ineligible),
            "unavailable" => Some(Self::Unavailable),
            "expired" => Some(Self::Expired),
            "available" => Some(Self::Available),
            "stopped" => Some(Self::Stopped),
            "capacity_paused" => Some(Self::CapacityPaused),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AvailabilityIntent {
    Start,
    Renew,
}

impl AvailabilityIntent {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Renew => "renew",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "start" => Some(Self::Start),
            "renew" => Some(Self::Renew),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AvailabilityOutcome {
    Started(AvailabilityDuration),
    Resumed,
    Stopped,
    RenewalScheduled(AvailabilityDuration),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoveryCardView {
    pub candidate_token: String,
    pub display_name: String,
    pub public_reference: String,
    pub category: ServiceCategory,
    pub distance_label: String,
    pub language_compatible: bool,
    pub availability_label: String,
    pub identity_checked: bool,
    pub contact_mode: ContactMode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DiscoveryStatus {
    None,
    Collecting,
    Results,
    NoResults,
    Waiting,
    Connected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoveryView {
    pub status: DiscoveryStatus,
    pub request_token: Option<String>,
    pub version: Option<i64>,
    pub category: Option<ServiceCategory>,
    pub radius_km: Option<u8>,
    pub has_more: bool,
    pub cards: Vec<DiscoveryCardView>,
}

impl Default for DiscoveryView {
    fn default() -> Self {
        Self {
            status: DiscoveryStatus::None,
            request_token: None,
            version: None,
            category: None,
            radius_km: None,
            has_more: false,
            cards: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingConnectionView {
    pub request_token: String,
    pub version: i64,
    pub category: ServiceCategory,
    pub issue_code: String,
    pub requested_time: String,
    pub distance_label: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionsView {
    pub pending: Vec<PendingConnectionView>,
    pub recent: Vec<RecentContactView>,
    pub customer_pending: Option<PendingCustomerConnectionView>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingCustomerConnectionView {
    pub request_token: String,
    pub version: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecentContactView {
    pub reveal_token: String,
    pub display_name: String,
    pub public_reference: String,
    pub category: ServiceCategory,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DiscoveryState {
    Category,
    Location {
        category: ServiceCategory,
    },
    Time {
        category: ServiceCategory,
    },
    Issue {
        category: ServiceCategory,
        requested_time: RequestedTimeChoice,
    },
    SearchComplete {
        request_token: String,
    },
    Results {
        request_token: String,
    },
    ConfirmSelection {
        request_token: String,
        request_version: i64,
        candidate_token: String,
        contact_mode: ContactMode,
    },
    Waiting {
        connection_token: String,
        connection_version: i64,
    },
    Recent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RequestedTimeChoice {
    Now,
    Today,
    Flexible,
}

impl RequestedTimeChoice {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Now => "now",
            Self::Today => "today",
            Self::Flexible => "flexible",
        }
    }
    fn parse(value: &str) -> Option<Self> {
        match value {
            "now" => Some(Self::Now),
            "today" => Some(Self::Today),
            "flexible" => Some(Self::Flexible),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProfessionalRequestsState {
    List,
    Inspect {
        request_token: String,
        version: i64,
    },
    Confirm {
        request_token: String,
        version: i64,
        accept: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TrustState {
    List,
    Actions {
        reveal_token: String,
    },
    ReviewConnection {
        reveal_token: String,
    },
    ReviewResponsiveness {
        reveal_token: String,
        connection: u8,
    },
    ReviewCompletion {
        reveal_token: String,
        connection: u8,
        responsiveness: u8,
    },
    ReviewFeedback {
        reveal_token: String,
        connection: u8,
        responsiveness: u8,
        completion: u8,
    },
    ReportCategory {
        reveal_token: String,
    },
    ReportBlock {
        reveal_token: String,
        category: String,
    },
    ReportDescription {
        reveal_token: String,
        category: String,
        block_subject: bool,
    },
    ConfirmBlock {
        reveal_token: String,
    },
    Done {
        outcome: String,
    },
}

impl AvailabilityOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Started(_) => "started",
            Self::Resumed => "resumed",
            Self::Stopped => "stopped",
            Self::RenewalScheduled(_) => "renewal_scheduled",
        }
    }

    const fn duration(self) -> Option<AvailabilityDuration> {
        match self {
            Self::Started(value) | Self::RenewalScheduled(value) => Some(value),
            Self::Resumed | Self::Stopped => None,
        }
    }

    fn parse(code: &str, duration: Option<AvailabilityDuration>) -> Option<Self> {
        match (code, duration) {
            ("started", Some(value)) => Some(Self::Started(value)),
            ("renewal_scheduled", Some(value)) => Some(Self::RenewalScheduled(value)),
            ("resumed", None) => Some(Self::Resumed),
            ("stopped", None) => Some(Self::Stopped),
            _ => None,
        }
    }
}

/// Typed professional availability workflow state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AvailabilityState {
    Status {
        observation: AvailabilityObservation,
    },
    ChooseDuration {
        observation: AvailabilityObservation,
        intent: AvailabilityIntent,
    },
    ConfirmStop {
        observation: AvailabilityObservation,
    },
    Changed {
        outcome: AvailabilityOutcome,
    },
}

impl AvailabilityState {
    /// Returns the optimistic observation bound to an actionable state.
    #[must_use]
    pub const fn observation(&self) -> Option<AvailabilityObservation> {
        match self {
            Self::Status { observation }
            | Self::ChooseDuration { observation, .. }
            | Self::ConfirmStop { observation } => Some(*observation),
            Self::Changed { .. } => None,
        }
    }
}

/// Typed states valid under the supported workflow versions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConversationState {
    LocaleChoose,
    LocaleConfirm { candidate: Locale },
    MainShow,
    MoreShow,
    HelpShow,
    Professional(ProfessionalState),
    Administrator(AdminState),
    Availability(AvailabilityState),
    Discovery(DiscoveryState),
    ProfessionalRequests(ProfessionalRequestsState),
    Trust(TrustState),
    SafetyAdministrator(SafetyAdminState),
}

impl ConversationState {
    /// Owning workflow.
    #[must_use]
    pub const fn workflow(&self) -> Workflow {
        match self {
            Self::LocaleChoose | Self::LocaleConfirm { .. } => Workflow::AccountLocaleV1,
            Self::MainShow => Workflow::MainMenuV1,
            Self::MoreShow => Workflow::MoreMenuV1,
            Self::HelpShow => Workflow::HelpMenuV1,
            Self::Professional(_) => Workflow::ProfessionalProfileV1,
            Self::Administrator(_) => Workflow::AdministratorReviewV1,
            Self::Availability(_) => Workflow::ProfessionalAvailabilityV1,
            Self::Discovery(_) => Workflow::CustomerDiscoveryV1,
            Self::ProfessionalRequests(_) => Workflow::ProfessionalRequestsV1,
            Self::Trust(_) => Workflow::TrustSafetyV1,
            Self::SafetyAdministrator(_) => Workflow::AdministratorSafetyV1,
        }
    }

    /// Stable database state code.
    #[must_use]
    pub const fn key(&self) -> &'static str {
        match self {
            Self::LocaleChoose => "choose",
            Self::LocaleConfirm { .. } => "confirm",
            Self::MainShow | Self::MoreShow | Self::HelpShow => "show",
            Self::Professional(state) => match state {
                ProfessionalState::DisplayNameInput { .. } => "display_name_input",
                ProfessionalState::DisplayNameConfirm { .. } => "display_name_confirm",
                ProfessionalState::Categories { .. } => "categories",
                ProfessionalState::Skills { .. } => "skills",
                ProfessionalState::ServiceArea { .. } => "service_area",
                ProfessionalState::Location { .. } => "location",
                ProfessionalState::Radius { .. } => "radius",
                ProfessionalState::Languages { .. } => "languages",
                ProfessionalState::ContactMode { .. } => "contact_mode",
                ProfessionalState::ContactLimit { .. } => "contact_limit",
                ProfessionalState::Photo { .. } => "photo",
                ProfessionalState::Disclosure { .. } => "disclosure",
                ProfessionalState::Consent { .. } => "consent",
                ProfessionalState::Summary { .. } => "summary",
                ProfessionalState::Status => "status",
                ProfessionalState::EditMenu => "edit_menu",
            },
            Self::Administrator(state) => match state {
                AdminState::Queue { .. } => "queue",
                AdminState::Inspect { .. } => "inspect",
                AdminState::Reason { .. } => "reason",
                AdminState::Confirm { .. } => "confirm",
            },
            Self::Availability(state) => match state {
                AvailabilityState::Status { .. } => "status",
                AvailabilityState::ChooseDuration { .. } => "choose_duration",
                AvailabilityState::ConfirmStop { .. } => "confirm_stop",
                AvailabilityState::Changed { .. } => "changed",
            },
            Self::Discovery(state) => match state {
                DiscoveryState::Category => "category",
                DiscoveryState::Location { .. } => "location",
                DiscoveryState::Time { .. } => "time",
                DiscoveryState::Issue { .. } => "issue",
                DiscoveryState::SearchComplete { .. } => "search_complete",
                DiscoveryState::Results { .. } => "results",
                DiscoveryState::ConfirmSelection { .. } => "confirm_selection",
                DiscoveryState::Waiting { .. } => "waiting",
                DiscoveryState::Recent => "recent",
            },
            Self::ProfessionalRequests(state) => match state {
                ProfessionalRequestsState::List => "list",
                ProfessionalRequestsState::Inspect { .. } => "inspect",
                ProfessionalRequestsState::Confirm { .. } => "confirm",
            },
            Self::Trust(state) => match state {
                TrustState::List => "list",
                TrustState::Actions { .. } => "actions",
                TrustState::ReviewConnection { .. } => "review_connection",
                TrustState::ReviewResponsiveness { .. } => "review_responsiveness",
                TrustState::ReviewCompletion { .. } => "review_completion",
                TrustState::ReviewFeedback { .. } => "review_feedback",
                TrustState::ReportCategory { .. } => "report_category",
                TrustState::ReportBlock { .. } => "report_block",
                TrustState::ReportDescription { .. } => "report_description",
                TrustState::ConfirmBlock { .. } => "confirm_block",
                TrustState::Done { .. } => "done",
            },
            Self::SafetyAdministrator(state) => match state {
                SafetyAdminState::Queue => "queue",
                SafetyAdminState::Inspect { .. } => "inspect",
                SafetyAdminState::Confirm { .. } => "confirm",
                SafetyAdminState::Done => "done",
            },
        }
    }

    /// Bounded non-sensitive state data.
    #[must_use]
    pub fn data(&self) -> serde_json::Value {
        match self {
            Self::LocaleConfirm { candidate } => {
                serde_json::json!({"candidate_locale": candidate.as_str()})
            }
            Self::Professional(state) => professional_state_data(state),
            Self::Administrator(state) => admin_state_data(state),
            Self::Availability(state) => availability_state_data(state),
            Self::Discovery(state) => discovery_state_data(state),
            Self::ProfessionalRequests(state) => professional_requests_state_data(state),
            Self::Trust(state) => trust_state_data(state),
            Self::SafetyAdministrator(state) => safety_admin_state_data(state),
            Self::LocaleChoose | Self::MainShow | Self::MoreShow | Self::HelpShow => {
                serde_json::json!({})
            }
        }
    }

    /// Decodes only exact supported workflow contracts and fails closed otherwise.
    #[must_use]
    pub fn from_persisted(
        workflow_key: &str,
        workflow_version: i16,
        state_key: &str,
        state_data: &serde_json::Value,
    ) -> Option<Self> {
        if workflow_version != 1 || !state_data.is_object() {
            return None;
        }
        match (workflow_key, state_key) {
            ("account.locale", "choose") if has_exact_keys(state_data, &[]) => {
                Some(Self::LocaleChoose)
            }
            ("account.locale", "confirm") if has_exact_keys(state_data, &["candidate_locale"]) => {
                state_data
                    .get("candidate_locale")
                    .and_then(serde_json::Value::as_str)
                    .and_then(Locale::parse)
                    .map(|candidate| Self::LocaleConfirm { candidate })
            }
            ("main_menu", "show") if has_exact_keys(state_data, &[]) => Some(Self::MainShow),
            ("more_menu", "show") if has_exact_keys(state_data, &[]) => Some(Self::MoreShow),
            ("help_menu", "show") if has_exact_keys(state_data, &[]) => Some(Self::HelpShow),
            ("professional.profile", key) => {
                decode_professional_state(key, state_data).map(Self::Professional)
            }
            ("administrator.review", key) => {
                decode_admin_state(key, state_data).map(Self::Administrator)
            }
            ("professional.availability", key) => {
                decode_availability_state(key, state_data).map(Self::Availability)
            }
            ("customer.discovery", key) => {
                decode_discovery_state(key, state_data).map(Self::Discovery)
            }
            ("professional.requests", key) => {
                decode_professional_requests_state(key, state_data).map(Self::ProfessionalRequests)
            }
            ("trust.safety", key) => decode_trust_state(key, state_data).map(Self::Trust),
            ("administrator.safety", key) => {
                decode_safety_admin_state(key, state_data).map(Self::SafetyAdministrator)
            }
            _ => None,
        }
    }
}

/// Active session information supplied by persistence.
#[derive(Clone, Debug)]
pub struct SessionSnapshot {
    pub id: ConversationSessionId,
    pub state: ConversationState,
    pub locale: Locale,
    pub version: i64,
    pub expected_reply_to: Option<OutboundMessageId>,
    pub workflow_correlation_id: CorrelationId,
}

/// Context needed for one pure engine decision.
#[derive(Clone, Debug)]
pub struct ConversationContext {
    pub confirmed_locale: Option<Locale>,
    pub session: Option<SessionSnapshot>,
    pub session_expired: bool,
    pub professional: ProfessionalView,
    pub administrator: AdminView,
    pub availability: AvailabilityView,
    pub discovery: DiscoveryView,
    pub connections: ConnectionsView,
    pub billing: BillingView,
    pub trust: TrustView,
    pub safety_administrator: SafetyAdminView,
}

/// Account-wide professional billing projection safe for user-facing menus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BillingView {
    FreeValue,
    PaymentRequired { hosted_payment_url: Option<String> },
    PendingPayment { hosted_payment_url: Option<String> },
    Active,
    GracePeriod,
    Expired,
    ManuallyWaived,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustView {
    pub introductions: Vec<TrustIntroductionView>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustIntroductionView {
    pub reveal_token: String,
    pub counterpart_label: Option<String>,
    pub category_code: String,
    pub current_account_is_customer: bool,
    pub already_reviewed: bool,
    pub already_reported: bool,
    pub already_blocked: bool,
}

/// One reply button independent of channel rendering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ButtonSpec {
    pub id: String,
    pub title: String,
}

/// One list row independent of channel rendering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListRowSpec {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
}

/// Supported provider-neutral reply controls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplyControls {
    None,
    Buttons(Vec<ButtonSpec>),
    List {
        open_title: String,
        section_title: String,
        rows: Vec<ListRowSpec>,
    },
}

/// Localized provider-neutral reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplySpec {
    pub body: String,
    pub controls: ReplyControls,
}

/// Persistence operation requested by the engine.
#[derive(Clone, Debug)]
pub enum SessionChange {
    Create {
        next: ConversationState,
        locale: Locale,
    },
    Advance {
        session_id: ConversationSessionId,
        expected_version: i64,
        next: ConversationState,
    },
    Replace {
        session_id: ConversationSessionId,
        expected_version: i64,
        next: ConversationState,
        locale: Locale,
        terminal_status: SessionTerminalStatus,
        terminal_reason: &'static str,
    },
}

/// Terminal state assigned to the previous workflow during replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTerminalStatus {
    Completed,
    Abandoned,
}

/// Auditable result classification for one inbound turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationDisposition {
    Applied,
    Unexpected,
    Stale,
    Recovered,
}

/// Account-level business mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AccountCommand {
    SetLocale { locale: Locale },
}

/// Professional profile business mutation. Dynamic inbound values remain markers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProfessionalCommand {
    StageDisplayName {
        display_name: String,
    },
    ConfirmDisplayName {
        expected_version: Option<i64>,
    },
    SetCategories {
        categories: CategorySelection,
    },
    SetSkills {
        category: ServiceCategory,
        skills: Vec<ServiceSkill>,
    },
    SetLocalMode {
        mode: LocalServiceMode,
    },
    CurrentInboundLocation,
    SetRadius {
        radius: ServiceRadius,
    },
    SetServiceLanguages {
        locales: Vec<Locale>,
    },
    SetContactMode {
        category: ServiceCategory,
        mode: ContactMode,
    },
    SetContactSessionLimit {
        limit: ContactSessionLimit,
    },
    CurrentInboundMedia,
    SkipPhoto,
    RemovePhoto,
    AcceptConsent {
        version: u16,
    },
    SubmitForReview {
        expected_version: Option<i64>,
        edited: bool,
    },
}

/// Administrator business mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AdminCommand {
    ReviewProfile {
        target: OpaqueTargetToken,
        expected_version: i64,
        decision: AdminReviewDecision,
        reason: Option<ReviewReasonCode>,
    },
}

/// Professional availability mutation with an exact optimistic observation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AvailabilityCommand {
    Start {
        duration: AvailabilityDuration,
        expected: AvailabilityObservation,
    },
    Resume {
        expected: AvailabilityObservation,
    },
    Stop {
        expected: AvailabilityObservation,
    },
    Renew {
        duration: AvailabilityDuration,
        expected: AvailabilityObservation,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DiscoveryCommand {
    Begin {
        category: ServiceCategory,
    },
    CurrentInboundLocation {
        request_token: String,
        expected_version: i64,
    },
    Search {
        request_token: String,
        expected_version: i64,
        requested_time: RequestedTimeChoice,
        issue_code: String,
    },
    ShowMore {
        request_token: String,
        expected_version: i64,
    },
    ExpandRadius {
        request_token: String,
        expected_version: i64,
    },
    Cancel {
        request_token: String,
        expected_version: i64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ConnectionCommand {
    Select {
        request_token: String,
        request_version: i64,
        candidate_token: String,
    },
    Respond {
        request_token: String,
        expected_version: i64,
        accept: bool,
    },
    Cancel {
        request_token: String,
        expected_version: i64,
    },
    RepeatReveal {
        reveal_token: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrustCommand {
    SubmitReview {
        reveal_token: String,
        connection: u8,
        responsiveness: u8,
        completion: u8,
        written_feedback: Option<String>,
    },
    SubmitReport {
        reveal_token: String,
        category: String,
        block_subject: bool,
        description: Option<String>,
    },
    Block {
        reveal_token: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SafetyModerationCommand {
    pub report_token: String,
    pub expected_version: i64,
    pub action: SafetyAdminAction,
}

/// Exactly one semantic business command envelope for a turn.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BusinessCommand {
    Account(AccountCommand),
    Professional(ProfessionalCommand),
    Administrator(AdminCommand),
    Availability(AvailabilityCommand),
    Discovery(DiscoveryCommand),
    Connection(ConnectionCommand),
    Trust(TrustCommand),
    SafetyModeration(SafetyModerationCommand),
}

/// Complete deterministic result of one engine decision.
#[derive(Clone, Debug)]
pub struct TurnPlan {
    pub session_change: SessionChange,
    /// Compatibility projection for Phase 4 workers.
    pub locale_change: Option<Locale>,
    pub business_command: Option<BusinessCommand>,
    pub reply: ReplySpec,
    pub disposition: ConversationDisposition,
}

fn professional_state_data(state: &ProfessionalState) -> serde_json::Value {
    match state {
        ProfessionalState::DisplayNameInput { mode }
        | ProfessionalState::DisplayNameConfirm { mode }
        | ProfessionalState::ContactLimit { mode }
        | ProfessionalState::Photo { mode }
        | ProfessionalState::Disclosure { mode }
        | ProfessionalState::Summary { mode } => serde_json::json!({"mode": mode.as_str()}),
        ProfessionalState::Categories { mode, selected } => serde_json::json!({
            "mode": mode.as_str(),
            "category_codes": category_codes(*selected),
        }),
        ProfessionalState::Skills {
            mode,
            categories,
            category,
            selected,
        } => serde_json::json!({
            "mode": mode.as_str(),
            "category_codes": category_codes(*categories),
            "category_code": category.as_str(),
            "service_codes": selected.iter().map(|skill| skill.as_str()).collect::<Vec<_>>(),
        }),
        ProfessionalState::ServiceArea { mode, categories }
        | ProfessionalState::Location { mode, categories }
        | ProfessionalState::Radius { mode, categories } => serde_json::json!({
            "mode": mode.as_str(),
            "category_codes": category_codes(*categories),
        }),
        ProfessionalState::Languages {
            mode,
            categories,
            selected,
        } => serde_json::json!({
            "mode": mode.as_str(),
            "category_codes": category_codes(*categories),
            "locale_codes": selected.iter().map(|locale| locale.as_str()).collect::<Vec<_>>(),
        }),
        ProfessionalState::ContactMode {
            mode,
            categories,
            category,
        } => serde_json::json!({
            "mode": mode.as_str(),
            "category_codes": category_codes(*categories),
            "category_code": category.as_str(),
        }),
        ProfessionalState::Consent {
            mode,
            version,
            document_set_digest,
        } => {
            serde_json::json!({
                "mode": mode.as_str(),
                "consent_version": version,
                "document_set_digest": document_set_digest.map(hex::encode),
            })
        }
        ProfessionalState::Status | ProfessionalState::EditMenu => serde_json::json!({}),
    }
}

fn admin_state_data(state: &AdminState) -> serde_json::Value {
    match state {
        AdminState::Queue { page } => serde_json::json!({"page": page}),
        AdminState::Inspect {
            target,
            target_version,
        } => serde_json::json!({
            "target_token": target.as_str(),
            "target_version": target_version,
        }),
        AdminState::Reason {
            target,
            target_version,
            decision,
        } => serde_json::json!({
            "target_token": target.as_str(),
            "target_version": target_version,
            "decision_code": decision.as_str(),
        }),
        AdminState::Confirm {
            target,
            target_version,
            decision,
            reason,
        } => serde_json::json!({
            "target_token": target.as_str(),
            "target_version": target_version,
            "decision_code": decision.as_str(),
            "reason_code": reason.map(ReviewReasonCode::as_str),
        }),
    }
}

fn availability_state_data(state: &AvailabilityState) -> serde_json::Value {
    match state {
        AvailabilityState::Status { observation }
        | AvailabilityState::ConfirmStop { observation } => observation_data(*observation),
        AvailabilityState::ChooseDuration {
            observation,
            intent,
        } => {
            let mut data = observation_data(*observation);
            if let Some(object) = data.as_object_mut() {
                object.insert(
                    "intent_code".to_owned(),
                    serde_json::Value::String(intent.as_str().to_owned()),
                );
            }
            data
        }
        AvailabilityState::Changed { outcome } => serde_json::json!({
            "outcome_code": outcome.as_str(),
            "duration_code": outcome.duration().map(AvailabilityDuration::as_str),
        }),
    }
}

fn discovery_state_data(state: &DiscoveryState) -> serde_json::Value {
    match state {
        DiscoveryState::Category | DiscoveryState::Recent => serde_json::json!({}),
        DiscoveryState::Location { category } => {
            serde_json::json!({"category": category.as_str()})
        }
        DiscoveryState::Time { category } => {
            serde_json::json!({"category": category.as_str()})
        }
        DiscoveryState::Issue {
            category,
            requested_time,
        } => serde_json::json!({
            "category": category.as_str(),
            "requested_time": requested_time.as_str(),
        }),
        DiscoveryState::SearchComplete { request_token }
        | DiscoveryState::Results { request_token } => {
            serde_json::json!({"request_token": request_token})
        }
        DiscoveryState::Waiting {
            connection_token,
            connection_version,
        } => serde_json::json!({
            "request_token": connection_token,
            "request_version": connection_version,
        }),
        DiscoveryState::ConfirmSelection {
            request_token,
            request_version,
            candidate_token,
            contact_mode,
        } => serde_json::json!({
            "request_token": request_token,
            "request_version": request_version,
            "candidate_token": candidate_token,
            "contact_mode": contact_mode.as_str(),
        }),
    }
}

fn professional_requests_state_data(state: &ProfessionalRequestsState) -> serde_json::Value {
    match state {
        ProfessionalRequestsState::List => serde_json::json!({}),
        ProfessionalRequestsState::Inspect {
            request_token,
            version,
        } => serde_json::json!({"request_token": request_token, "request_version": version}),
        ProfessionalRequestsState::Confirm {
            request_token,
            version,
            accept,
        } => serde_json::json!({
            "request_token": request_token,
            "request_version": version,
            "accept": accept,
        }),
    }
}

fn trust_state_data(state: &TrustState) -> serde_json::Value {
    match state {
        TrustState::List => serde_json::json!({}),
        TrustState::Actions { reveal_token }
        | TrustState::ReviewConnection { reveal_token }
        | TrustState::ReportCategory { reveal_token }
        | TrustState::ConfirmBlock { reveal_token } => {
            serde_json::json!({"reveal_token": reveal_token})
        }
        TrustState::ReviewResponsiveness {
            reveal_token,
            connection,
        } => {
            serde_json::json!({"reveal_token": reveal_token, "connection": connection})
        }
        TrustState::ReviewCompletion {
            reveal_token,
            connection,
            responsiveness,
        } => serde_json::json!({
            "reveal_token": reveal_token,
            "connection": connection,
            "responsiveness": responsiveness,
        }),
        TrustState::ReviewFeedback {
            reveal_token,
            connection,
            responsiveness,
            completion,
        } => serde_json::json!({
            "reveal_token": reveal_token,
            "connection": connection,
            "responsiveness": responsiveness,
            "completion": completion,
        }),
        TrustState::ReportBlock {
            reveal_token,
            category,
        } => {
            serde_json::json!({"reveal_token": reveal_token, "category": category})
        }
        TrustState::ReportDescription {
            reveal_token,
            category,
            block_subject,
        } => serde_json::json!({
            "reveal_token": reveal_token,
            "category": category,
            "block_subject": block_subject,
        }),
        TrustState::Done { outcome } => serde_json::json!({"outcome": outcome}),
    }
}

fn safety_admin_state_data(state: &SafetyAdminState) -> serde_json::Value {
    match state {
        SafetyAdminState::Queue | SafetyAdminState::Done => serde_json::json!({}),
        SafetyAdminState::Inspect {
            report_token,
            version,
        } => {
            serde_json::json!({"report_token": report_token, "report_version": version})
        }
        SafetyAdminState::Confirm {
            report_token,
            version,
            action,
        } => serde_json::json!({
            "report_token": report_token,
            "report_version": version,
            "action": action.as_str(),
        }),
    }
}

fn observation_data(observation: AvailabilityObservation) -> serde_json::Value {
    serde_json::json!({
        "observation_state": observation.state.as_str(),
        "generation": observation.generation,
        "version": observation.version,
    })
}

fn decode_professional_state(key: &str, data: &serde_json::Value) -> Option<ProfessionalState> {
    match key {
        "display_name_input" if has_exact_keys(data, &["mode"]) => {
            Some(ProfessionalState::DisplayNameInput { mode: mode(data)? })
        }
        "display_name_confirm" if has_exact_keys(data, &["mode"]) => {
            Some(ProfessionalState::DisplayNameConfirm { mode: mode(data)? })
        }
        "categories" if has_exact_keys(data, &["mode", "category_codes"]) => {
            Some(ProfessionalState::Categories {
                mode: mode(data)?,
                selected: categories(data)?,
            })
        }
        "skills"
            if has_exact_keys(
                data,
                &["mode", "category_codes", "category_code", "service_codes"],
            ) =>
        {
            let category = data
                .get("category_code")
                .and_then(serde_json::Value::as_str)
                .and_then(ServiceCategory::parse)?;
            let selected = data
                .get("service_codes")
                .and_then(serde_json::Value::as_array)?
                .iter()
                .map(|value| value.as_str().and_then(ServiceSkill::parse))
                .collect::<Option<Vec<_>>>()?;
            if selected.len() > 3
                || selected.iter().any(|skill| skill.category() != category)
                || has_duplicates(&selected)
            {
                return None;
            }
            Some(ProfessionalState::Skills {
                mode: mode(data)?,
                categories: categories(data)?,
                category,
                selected,
            })
        }
        "service_area" if has_exact_keys(data, &["mode", "category_codes"]) => {
            Some(ProfessionalState::ServiceArea {
                mode: mode(data)?,
                categories: nonempty_categories(data)?,
            })
        }
        "location" if has_exact_keys(data, &["mode", "category_codes"]) => {
            Some(ProfessionalState::Location {
                mode: mode(data)?,
                categories: nonempty_categories(data)?,
            })
        }
        "radius" if has_exact_keys(data, &["mode", "category_codes"]) => {
            Some(ProfessionalState::Radius {
                mode: mode(data)?,
                categories: nonempty_categories(data)?,
            })
        }
        "languages" if has_exact_keys(data, &["mode", "category_codes", "locale_codes"]) => {
            let selected = data
                .get("locale_codes")
                .and_then(serde_json::Value::as_array)?
                .iter()
                .map(|value| value.as_str().and_then(Locale::parse))
                .collect::<Option<Vec<_>>>()?;
            if selected.len() > Locale::ALL.len() || has_duplicates(&selected) {
                return None;
            }
            Some(ProfessionalState::Languages {
                mode: mode(data)?,
                categories: nonempty_categories(data)?,
                selected,
            })
        }
        "contact_mode" if has_exact_keys(data, &["mode", "category_codes", "category_code"]) => {
            let categories = nonempty_categories(data)?;
            let category = data
                .get("category_code")
                .and_then(serde_json::Value::as_str)
                .and_then(ServiceCategory::parse)?;
            categories
                .contains(category)
                .then_some(ProfessionalState::ContactMode {
                    mode: mode(data)?,
                    categories,
                    category,
                })
        }
        "contact_limit" if has_exact_keys(data, &["mode"]) => {
            Some(ProfessionalState::ContactLimit { mode: mode(data)? })
        }
        "photo" if has_exact_keys(data, &["mode"]) => {
            Some(ProfessionalState::Photo { mode: mode(data)? })
        }
        "disclosure" if has_exact_keys(data, &["mode"]) => {
            Some(ProfessionalState::Disclosure { mode: mode(data)? })
        }
        "consent" if has_exact_keys(data, &["mode", "consent_version", "document_set_digest"]) => {
            let version = data
                .get("consent_version")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u16::try_from(value).ok())?;
            let document_set_digest = match data.get("document_set_digest")? {
                serde_json::Value::Null => None,
                serde_json::Value::String(value) => {
                    let decoded = hex::decode(value).ok()?;
                    Some(decoded.try_into().ok()?)
                }
                _ => return None,
            };
            (version > 0).then_some(ProfessionalState::Consent {
                mode: mode(data)?,
                version,
                document_set_digest,
            })
        }
        "summary" if has_exact_keys(data, &["mode"]) => {
            Some(ProfessionalState::Summary { mode: mode(data)? })
        }
        "status" if has_exact_keys(data, &[]) => Some(ProfessionalState::Status),
        "edit_menu" if has_exact_keys(data, &[]) => Some(ProfessionalState::EditMenu),
        _ => None,
    }
}

fn decode_admin_state(key: &str, data: &serde_json::Value) -> Option<AdminState> {
    match key {
        "queue" if has_exact_keys(data, &["page"]) => {
            let page = data
                .get("page")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u8::try_from(value).ok())?;
            (page <= MAX_ADMIN_QUEUE_PAGE).then_some(AdminState::Queue { page })
        }
        "inspect" if has_exact_keys(data, &["target_token", "target_version"]) => {
            let (target, target_version) = target(data)?;
            Some(AdminState::Inspect {
                target,
                target_version,
            })
        }
        "reason" if has_exact_keys(data, &["target_token", "target_version", "decision_code"]) => {
            let (target, target_version) = target(data)?;
            let decision = decision(data)?;
            matches!(
                decision,
                AdminReviewDecision::ChangesRequested | AdminReviewDecision::Reject
            )
            .then_some(AdminState::Reason {
                target,
                target_version,
                decision,
            })
        }
        "confirm"
            if has_exact_keys(
                data,
                &[
                    "target_token",
                    "target_version",
                    "decision_code",
                    "reason_code",
                ],
            ) =>
        {
            let (target, target_version) = target(data)?;
            let decision = decision(data)?;
            let reason = match data.get("reason_code")? {
                serde_json::Value::Null => None,
                value => value.as_str().and_then(ReviewReasonCode::parse),
            };
            let valid = match decision {
                AdminReviewDecision::Approve => reason.is_none(),
                AdminReviewDecision::ChangesRequested | AdminReviewDecision::Reject => {
                    reason.is_some()
                }
            };
            valid.then_some(AdminState::Confirm {
                target,
                target_version,
                decision,
                reason,
            })
        }
        _ => None,
    }
}

fn decode_availability_state(key: &str, data: &serde_json::Value) -> Option<AvailabilityState> {
    match key {
        "status" if has_exact_keys(data, &observation_keys()) => Some(AvailabilityState::Status {
            observation: decode_observation(data)?,
        }),
        "choose_duration"
            if has_exact_keys(
                data,
                &["observation_state", "generation", "version", "intent_code"],
            ) =>
        {
            Some(AvailabilityState::ChooseDuration {
                observation: decode_observation(data)?,
                intent: data
                    .get("intent_code")
                    .and_then(serde_json::Value::as_str)
                    .and_then(AvailabilityIntent::parse)?,
            })
        }
        "confirm_stop" if has_exact_keys(data, &observation_keys()) => {
            Some(AvailabilityState::ConfirmStop {
                observation: decode_observation(data)?,
            })
        }
        "changed" if has_exact_keys(data, &["outcome_code", "duration_code"]) => {
            let code = data
                .get("outcome_code")
                .and_then(serde_json::Value::as_str)?;
            let duration = match data.get("duration_code")? {
                serde_json::Value::Null => None,
                serde_json::Value::String(value) => AvailabilityDuration::parse(value),
                _ => return None,
            };
            Some(AvailabilityState::Changed {
                outcome: AvailabilityOutcome::parse(code, duration)?,
            })
        }
        _ => None,
    }
}

fn decode_discovery_state(key: &str, data: &serde_json::Value) -> Option<DiscoveryState> {
    match key {
        "category" if has_exact_keys(data, &[]) => Some(DiscoveryState::Category),
        "recent" if has_exact_keys(data, &[]) => Some(DiscoveryState::Recent),
        "location" if has_exact_keys(data, &["category"]) => Some(DiscoveryState::Location {
            category: data
                .get("category")
                .and_then(serde_json::Value::as_str)
                .and_then(ServiceCategory::parse)?,
        }),
        "time" if has_exact_keys(data, &["category"]) => Some(DiscoveryState::Time {
            category: data
                .get("category")
                .and_then(serde_json::Value::as_str)
                .and_then(ServiceCategory::parse)?,
        }),
        "issue" if has_exact_keys(data, &["category", "requested_time"]) => {
            Some(DiscoveryState::Issue {
                category: data
                    .get("category")
                    .and_then(serde_json::Value::as_str)
                    .and_then(ServiceCategory::parse)?,
                requested_time: data
                    .get("requested_time")
                    .and_then(serde_json::Value::as_str)
                    .and_then(RequestedTimeChoice::parse)?,
            })
        }
        "search_complete" if has_exact_keys(data, &["request_token"]) => {
            Some(DiscoveryState::SearchComplete {
                request_token: safe_token(data, "request_token")?,
            })
        }
        "results" if has_exact_keys(data, &["request_token"]) => Some(DiscoveryState::Results {
            request_token: safe_token(data, "request_token")?,
        }),
        "confirm_selection"
            if has_exact_keys(
                data,
                &[
                    "request_token",
                    "request_version",
                    "candidate_token",
                    "contact_mode",
                ],
            ) =>
        {
            Some(DiscoveryState::ConfirmSelection {
                request_token: safe_token(data, "request_token")?,
                request_version: positive_i64(data, "request_version")?,
                candidate_token: safe_token(data, "candidate_token")?,
                contact_mode: data
                    .get("contact_mode")
                    .and_then(serde_json::Value::as_str)
                    .and_then(ContactMode::parse)?,
            })
        }
        "waiting" if has_exact_keys(data, &["request_token", "request_version"]) => {
            Some(DiscoveryState::Waiting {
                connection_token: safe_token(data, "request_token")?,
                connection_version: positive_i64(data, "request_version")?,
            })
        }
        _ => None,
    }
}

fn decode_professional_requests_state(
    key: &str,
    data: &serde_json::Value,
) -> Option<ProfessionalRequestsState> {
    match key {
        "list" if has_exact_keys(data, &[]) => Some(ProfessionalRequestsState::List),
        "inspect" if has_exact_keys(data, &["request_token", "request_version"]) => {
            Some(ProfessionalRequestsState::Inspect {
                request_token: safe_token(data, "request_token")?,
                version: positive_i64(data, "request_version")?,
            })
        }
        "confirm" if has_exact_keys(data, &["request_token", "request_version", "accept"]) => {
            Some(ProfessionalRequestsState::Confirm {
                request_token: safe_token(data, "request_token")?,
                version: positive_i64(data, "request_version")?,
                accept: data.get("accept")?.as_bool()?,
            })
        }
        _ => None,
    }
}

fn decode_trust_state(key: &str, data: &serde_json::Value) -> Option<TrustState> {
    let rating = |key: &str| {
        data.get(key)?
            .as_u64()
            .and_then(|value| u8::try_from(value).ok())
            .filter(|value| (1..=5).contains(value))
    };
    match key {
        "list" if has_exact_keys(data, &[]) => Some(TrustState::List),
        "actions" if has_exact_keys(data, &["reveal_token"]) => Some(TrustState::Actions {
            reveal_token: safe_token(data, "reveal_token")?,
        }),
        "review_connection" if has_exact_keys(data, &["reveal_token"]) => {
            Some(TrustState::ReviewConnection {
                reveal_token: safe_token(data, "reveal_token")?,
            })
        }
        "review_responsiveness" if has_exact_keys(data, &["reveal_token", "connection"]) => {
            Some(TrustState::ReviewResponsiveness {
                reveal_token: safe_token(data, "reveal_token")?,
                connection: rating("connection")?,
            })
        }
        "review_completion"
            if has_exact_keys(data, &["reveal_token", "connection", "responsiveness"]) =>
        {
            Some(TrustState::ReviewCompletion {
                reveal_token: safe_token(data, "reveal_token")?,
                connection: rating("connection")?,
                responsiveness: rating("responsiveness")?,
            })
        }
        "review_feedback"
            if has_exact_keys(
                data,
                &["reveal_token", "connection", "responsiveness", "completion"],
            ) =>
        {
            Some(TrustState::ReviewFeedback {
                reveal_token: safe_token(data, "reveal_token")?,
                connection: rating("connection")?,
                responsiveness: rating("responsiveness")?,
                completion: rating("completion")?,
            })
        }
        "report_category" if has_exact_keys(data, &["reveal_token"]) => {
            Some(TrustState::ReportCategory {
                reveal_token: safe_token(data, "reveal_token")?,
            })
        }
        "report_block" if has_exact_keys(data, &["reveal_token", "category"]) => {
            Some(TrustState::ReportBlock {
                reveal_token: safe_token(data, "reveal_token")?,
                category: safe_machine_code(data, "category")?,
            })
        }
        "report_description"
            if has_exact_keys(data, &["reveal_token", "category", "block_subject"]) =>
        {
            Some(TrustState::ReportDescription {
                reveal_token: safe_token(data, "reveal_token")?,
                category: safe_machine_code(data, "category")?,
                block_subject: data.get("block_subject")?.as_bool()?,
            })
        }
        "confirm_block" if has_exact_keys(data, &["reveal_token"]) => {
            Some(TrustState::ConfirmBlock {
                reveal_token: safe_token(data, "reveal_token")?,
            })
        }
        "done" if has_exact_keys(data, &["outcome"]) => Some(TrustState::Done {
            outcome: safe_machine_code(data, "outcome")?,
        }),
        _ => None,
    }
}

fn decode_safety_admin_state(key: &str, data: &serde_json::Value) -> Option<SafetyAdminState> {
    match key {
        "queue" if has_exact_keys(data, &[]) => Some(SafetyAdminState::Queue),
        "inspect" if has_exact_keys(data, &["report_token", "report_version"]) => {
            Some(SafetyAdminState::Inspect {
                report_token: safe_token(data, "report_token")?,
                version: positive_i64(data, "report_version")?,
            })
        }
        "confirm" if has_exact_keys(data, &["report_token", "report_version", "action"]) => {
            Some(SafetyAdminState::Confirm {
                report_token: safe_token(data, "report_token")?,
                version: positive_i64(data, "report_version")?,
                action: data
                    .get("action")?
                    .as_str()
                    .and_then(SafetyAdminAction::parse)?,
            })
        }
        "done" if has_exact_keys(data, &[]) => Some(SafetyAdminState::Done),
        _ => None,
    }
}

fn safe_token(data: &serde_json::Value, key: &str) -> Option<String> {
    let value = data.get(key)?.as_str()?;
    OpaqueTargetToken::parse(value)
        .ok()
        .map(|token| token.as_str().to_owned())
}

fn safe_machine_code(data: &serde_json::Value, key: &str) -> Option<String> {
    let value = data.get(key)?.as_str()?;
    (!value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
    .then(|| value.to_owned())
}

fn positive_i64(data: &serde_json::Value, key: &str) -> Option<i64> {
    let value = data.get(key)?.as_i64()?;
    (value > 0).then_some(value)
}

const fn observation_keys() -> [&'static str; 3] {
    ["observation_state", "generation", "version"]
}

fn decode_observation(data: &serde_json::Value) -> Option<AvailabilityObservation> {
    let state = data
        .get("observation_state")
        .and_then(serde_json::Value::as_str)
        .and_then(AvailabilityObservationState::parse)?;
    let generation = optional_positive_u32(data.get("generation")?)?;
    let version = optional_positive_i64(data.get("version")?)?;
    let observation = AvailabilityObservation {
        state,
        generation,
        version,
    };
    observation.is_valid().then_some(observation)
}

fn optional_positive_u32(value: &serde_json::Value) -> Option<Option<u32>> {
    match value {
        serde_json::Value::Null => Some(None),
        serde_json::Value::Number(number) => number
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
            .map(Some),
        _ => None,
    }
}

fn optional_positive_i64(value: &serde_json::Value) -> Option<Option<i64>> {
    match value {
        serde_json::Value::Null => Some(None),
        serde_json::Value::Number(number) => number.as_i64().filter(|value| *value > 0).map(Some),
        _ => None,
    }
}

fn category_codes(selection: CategorySelection) -> Vec<&'static str> {
    selection
        .values()
        .into_iter()
        .map(ServiceCategory::as_str)
        .collect()
}

fn categories(data: &serde_json::Value) -> Option<CategorySelection> {
    let values = data
        .get("category_codes")
        .and_then(serde_json::Value::as_array)?;
    if values.len() > 2 {
        return None;
    }
    let mut selection = CategorySelection::default();
    for value in values {
        let category = value.as_str().and_then(ServiceCategory::parse)?;
        if selection.contains(category) {
            return None;
        }
        selection = selection.toggled(category);
    }
    Some(selection)
}

fn nonempty_categories(data: &serde_json::Value) -> Option<CategorySelection> {
    let selection = categories(data)?;
    (!selection.is_empty()).then_some(selection)
}

fn mode(data: &serde_json::Value) -> Option<ProfessionalFlowMode> {
    data.get("mode")
        .and_then(serde_json::Value::as_str)
        .and_then(ProfessionalFlowMode::parse)
}

fn target(data: &serde_json::Value) -> Option<(OpaqueTargetToken, i64)> {
    let token = data
        .get("target_token")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| OpaqueTargetToken::parse(value).ok())?;
    let version = data
        .get("target_version")
        .and_then(serde_json::Value::as_i64)?;
    (version > 0).then_some((token, version))
}

fn decision(data: &serde_json::Value) -> Option<AdminReviewDecision> {
    data.get("decision_code")
        .and_then(serde_json::Value::as_str)
        .and_then(AdminReviewDecision::parse)
}

fn has_exact_keys(data: &serde_json::Value, expected: &[&str]) -> bool {
    let Some(object) = data.as_object() else {
        return false;
    };
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn has_duplicates<T: Eq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}
