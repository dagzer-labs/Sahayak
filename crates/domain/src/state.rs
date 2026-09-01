use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;

/// Error returned when persistence contains an unsupported lifecycle value.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("unsupported {kind} value: {value}")]
pub struct UnknownState {
    kind: &'static str,
    value: String,
}

macro_rules! define_state {
    (
        $(#[$metadata:meta])*
        $name:ident, $kind:literal, {
            $($variant:ident => $value:literal),+ $(,)?
        }
    ) => {
        $(#[$metadata])*
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            /// Returns the stable database and wire representation.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = UnknownState;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($value => Ok(Self::$variant)),+,
                    _ => Err(UnknownState {
                        kind: $kind,
                        value: value.to_owned(),
                    }),
                }
            }
        }
    };
}

define_state!(
    /// Current account lifecycle independent of any communication channel.
    AccountLifecycle,
    "account lifecycle",
    {
        Pending => "pending",
        Active => "active",
        Suspended => "suspended",
        DeletionPending => "deletion_pending",
        Deleted => "deleted",
    }
);

impl AccountLifecycle {
    /// Returns whether the requested lifecycle transition is permitted.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Pending,
                Self::Active | Self::Suspended | Self::DeletionPending
            ) | (Self::Active, Self::Suspended | Self::DeletionPending)
                | (Self::Suspended, Self::Active | Self::DeletionPending)
                | (Self::DeletionPending, Self::Active | Self::Deleted)
        )
    }
}

define_state!(
    /// Current platform risk treatment for an account.
    RiskState,
    "risk state",
    {
        Normal => "normal",
        UnderReview => "under_review",
        Restricted => "restricted",
        Blocked => "blocked",
    }
);

define_state!(
    /// Capability granted to an account.
    AccountRole,
    "account role",
    {
        Customer => "customer",
        Professional => "professional",
        Administrator => "administrator",
    }
);

define_state!(
    /// Lifecycle of an identity on one external communication channel.
    ChannelIdentityState,
    "channel identity state",
    {
        Active => "active",
        Disabled => "disabled",
        Revoked => "revoked",
    }
);

define_state!(
    /// Discovery visibility of the stable professional aggregate root.
    ProfileVisibility,
    "profile visibility",
    {
        Published => "published",
        Hidden => "hidden",
        Deleted => "deleted",
    }
);

impl ProfileVisibility {
    /// Returns whether an aggregate root may move to the requested visibility.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Hidden, Self::Published | Self::Deleted)
                | (Self::Published, Self::Hidden | Self::Deleted)
        )
    }
}

define_state!(
    /// Lifecycle of one reviewable professional profile revision.
    ProfileRevisionState,
    "profile revision state",
    {
        Draft => "draft",
        PendingReview => "pending_review",
        Approved => "approved",
        ChangesRequested => "changes_requested",
        Rejected => "rejected",
        Superseded => "superseded",
    }
);

impl ProfileRevisionState {
    /// Returns whether this state can move to the requested state.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Draft, Self::PendingReview)
                | (
                    Self::PendingReview,
                    Self::Approved | Self::ChangesRequested | Self::Rejected
                )
                | (Self::Approved, Self::Superseded)
        )
    }
}

define_state!(
    /// Administrative outcome for one submitted revision.
    ProfileReviewDecision,
    "profile review decision",
    {
        Approve => "approve",
        ChangesRequested => "changes_requested",
        Reject => "reject",
    }
);

define_state!(
    /// Machine-readable reason constrained by the selected review outcome.
    ProfileReviewReason,
    "profile review reason",
    {
        MeetsPolicy => "meets_policy",
        IncompleteProfile => "incomplete_profile",
        InvalidDisplayName => "invalid_display_name",
        UnsupportedService => "unsupported_service",
        ServiceAreaIssue => "service_area_issue",
        PhotoIssue => "photo_issue",
        PolicyViolation => "policy_violation",
        FraudRisk => "fraud_risk",
        ProhibitedContent => "prohibited_content",
    }
);

impl ProfileReviewDecision {
    /// Returns whether a fixed reason code belongs to this decision.
    #[must_use]
    pub const fn accepts_reason(self, reason: ProfileReviewReason) -> bool {
        matches!(
            (self, reason),
            (Self::Approve, ProfileReviewReason::MeetsPolicy)
                | (
                    Self::ChangesRequested,
                    ProfileReviewReason::IncompleteProfile
                        | ProfileReviewReason::InvalidDisplayName
                        | ProfileReviewReason::UnsupportedService
                        | ProfileReviewReason::ServiceAreaIssue
                        | ProfileReviewReason::PhotoIssue
                )
                | (
                    Self::Reject,
                    ProfileReviewReason::PolicyViolation
                        | ProfileReviewReason::FraudRisk
                        | ProfileReviewReason::ProhibitedContent
                )
        )
    }
}

define_state!(
    /// Contact disclosure behavior for one selected service category.
    ContactMode,
    "contact mode",
    {
        Direct => "direct",
        ApprovalRequired => "approval_required",
    }
);

define_state!(
    /// Supported ways a professional provides local, in-person services.
    LocalServiceMode,
    "local service mode",
    {
        TravelToCustomer => "travel_to_customer",
        CustomerVisits => "customer_visits",
        Both => "both",
    }
);

define_state!(
    /// Purpose represented by an immutable professional consent event.
    ProfessionalConsentPurpose,
    "professional consent purpose",
    {
        Terms => "terms",
        Privacy => "privacy",
        ContactDisclosure => "contact_disclosure",
        DirectContact => "direct_contact",
        PhotoDisclosure => "photo_disclosure",
        IdentityVerification => "identity_verification",
    }
);

define_state!(
    /// Immutable consent ledger action.
    ConsentAction,
    "consent action",
    {
        Granted => "granted",
        Revoked => "revoked",
    }
);

define_state!(
    /// Restricted profile photo lifecycle.
    ProfilePhotoState,
    "profile photo state",
    {
        Ready => "ready",
        Replaced => "replaced",
        Deleted => "deleted",
    }
);

define_state!(
    /// Monotonic lifecycle for an optional identity assertion attempt.
    IdentityVerificationState,
    "identity verification state",
    {
        Pending => "pending",
        Passed => "passed",
        Failed => "failed",
        Expired => "expired",
        Revoked => "revoked",
    }
);

impl ProfilePhotoState {
    /// Returns whether private photo bytes may make this irreversible transition.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!((self, next), (Self::Ready, Self::Replaced | Self::Deleted))
    }
}

impl IdentityVerificationState {
    /// Returns whether an identity assertion may make this transition.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Pending,
                Self::Passed | Self::Failed | Self::Expired | Self::Revoked
            ) | (Self::Passed, Self::Expired | Self::Revoked)
        )
    }
}

define_state!(
    /// Supported duration selected for one availability quota epoch.
    AvailabilityDuration,
    "availability duration",
    {
        OneHour => "one_hour",
        FourHours => "four_hours",
        EndOfLocalDay => "end_of_local_day",
    }
);

define_state!(
    /// Durable lifecycle of one profile-wide availability quota epoch.
    AvailabilityEpochState,
    "availability epoch state",
    {
        Scheduled => "scheduled",
        Available => "available",
        Stopped => "stopped",
        PausedContactLimit => "paused_contact_limit",
        Expired => "expired",
        CancelledManual => "cancelled_manual",
        CancelledIneligible => "cancelled_ineligible",
    }
);

impl AvailabilityEpochState {
    /// Returns whether this state may be effective at database time.
    #[must_use]
    pub const fn may_be_effective(self) -> bool {
        matches!(self, Self::Scheduled | Self::Available)
    }

    /// Returns whether this lifecycle transition is permitted.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Scheduled,
                Self::Available | Self::CancelledManual | Self::CancelledIneligible
            ) | (
                Self::Available,
                Self::Stopped
                    | Self::PausedContactLimit
                    | Self::Expired
                    | Self::CancelledIneligible
            ) | (
                Self::Stopped,
                Self::Available | Self::Expired | Self::CancelledIneligible
            ) | (
                Self::PausedContactLimit,
                Self::Expired | Self::CancelledIneligible
            )
        )
    }
}

define_state!(
    /// Customer-request lifecycle.
    ServiceRequestState,
    "service request state",
    {
        Draft => "draft",
        Collecting => "collecting_requirements",
        Searching => "searching",
        ShowingResults => "showing_results",
        NoResults => "no_results",
        Selected => "selected",
        Connected => "connected",
        Cancelled => "cancelled",
        Expired => "expired",
    }
);

define_state!(
    /// Customer requested-time choice.
    RequestedTimeWindow,
    "requested time window",
    {
        Now => "now",
        Today => "today",
        Flexible => "flexible",
    }
);

define_state!(
    /// Approval-required connection lifecycle.
    ConnectionRequestState,
    "connection request state",
    {
        Pending => "pending",
        Accepted => "accepted",
        Declined => "declined",
        Expired => "expired",
        Cancelled => "cancelled",
        DisclosurePending => "disclosure_pending",
        Disclosed => "disclosed",
        DisclosureFailed => "disclosure_failed",
    }
);

define_state!(
    /// Durable transport state of an immutable contact reveal.
    ContactRevealDeliveryState,
    "contact reveal delivery state",
    {
        Pending => "pending",
        Delivered => "delivered",
        Failed => "failed",
        Reversed => "reversed",
    }
);

define_state!(
    /// Qualified-introduction accounting state.
    QualifiedIntroductionState,
    "qualified introduction state",
    {
        Pending => "pending",
        Qualified => "qualified",
        Reversed => "reversed",
    }
);

define_state!(
    /// Lifecycle for recoverable channel conversation state.
    ConversationStatus,
    "conversation status",
    {
        Active => "active",
        Completed => "completed",
        Expired => "expired",
        Abandoned => "abandoned",
    }
);

define_state!(
    /// Durable outbox execution state.
    OutboxState,
    "outbox state",
    {
        Pending => "pending",
        Leased => "leased",
        Completed => "completed",
        DeadLettered => "dead_lettered",
    }
);

define_state!(
    /// Identity category recorded for an immutable audit event.
    AuditActorType,
    "audit actor type",
    {
        Account => "account",
        Administrator => "administrator",
        System => "system",
    }
);

#[cfg(test)]
mod tests {
    use super::{AccountLifecycle, AvailabilityEpochState, OutboxState};
    use std::str::FromStr;

    #[test]
    fn states_round_trip_through_database_values() -> Result<(), Box<dyn std::error::Error>> {
        let lifecycle = AccountLifecycle::from_str("deletion_pending")?;
        let outbox = OutboxState::from_str("dead_lettered")?;

        assert_eq!(lifecycle, AccountLifecycle::DeletionPending);
        assert_eq!(lifecycle.as_str(), "deletion_pending");
        assert_eq!(outbox, OutboxState::DeadLettered);
        Ok(())
    }

    #[test]
    fn unknown_values_fail_closed() {
        let error = AccountLifecycle::from_str("unexpected");
        assert!(error.is_err());
    }

    #[test]
    fn deleted_accounts_are_terminal() {
        assert!(AccountLifecycle::Pending.can_transition_to(AccountLifecycle::Active));
        assert!(AccountLifecycle::DeletionPending.can_transition_to(AccountLifecycle::Deleted));
        assert!(!AccountLifecycle::Deleted.can_transition_to(AccountLifecycle::Active));
        assert!(!AccountLifecycle::Active.can_transition_to(AccountLifecycle::Active));
    }

    #[test]
    fn availability_expiry_and_capacity_pause_do_not_reopen() {
        assert!(
            AvailabilityEpochState::Stopped.can_transition_to(AvailabilityEpochState::Available)
        );
        assert!(
            !AvailabilityEpochState::Expired.can_transition_to(AvailabilityEpochState::Available)
        );
        assert!(
            !AvailabilityEpochState::PausedContactLimit
                .can_transition_to(AvailabilityEpochState::Available)
        );
    }
}
