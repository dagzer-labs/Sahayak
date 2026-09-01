use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use uuid::Uuid;

macro_rules! define_identifier {
    ($(#[$metadata:meta])* $name:ident) => {
        $(#[$metadata])*
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a time-ordered UUIDv7 identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wraps an identifier loaded from a trusted persistence boundary.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Returns the underlying UUID value.
            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self::from_uuid(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.into_uuid()
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self::from_uuid)
            }
        }
    };
}

macro_rules! define_random_identifier {
    ($(#[$metadata:meta])* $name:ident) => {
        $(#[$metadata])*
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a cryptographically random UUIDv4 identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Wraps an identifier loaded from a trusted persistence boundary.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Returns the underlying UUID value.
            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self::from_uuid(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.into_uuid()
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self::from_uuid)
            }
        }
    };
}

define_identifier!(
    /// Stable internal identifier for one Sahayak account.
    AccountId
);
define_identifier!(
    /// Stable identifier for an account's identity on one communication channel.
    ChannelIdentityId
);
define_identifier!(
    /// Stable identifier for a privacy-safe public profile.
    PublicProfileId
);
define_identifier!(
    /// Stable identifier for one immutable-after-submission profile revision.
    ProfileRevisionId
);
define_identifier!(
    /// Stable identifier for one professional consent event.
    ProfessionalConsentEventId
);
define_identifier!(
    /// Stable identifier for encrypted sanitized profile media.
    ProfilePhotoId
);
define_identifier!(
    /// Stable identifier for one channel-bound administrator grant.
    AdministratorGrantId
);
define_identifier!(
    /// Stable identifier for one immutable profile review decision.
    ProfileReviewDecisionId
);
define_identifier!(
    /// Stable identifier for one optional identity-verification attempt.
    IdentityVerificationAttemptId
);
define_identifier!(
    /// Stable identifier for one payload-free verification callback receipt.
    IdentityVerificationCallbackReceiptId
);
define_identifier!(
    /// Stable identifier for one profile-wide availability quota epoch.
    AvailabilityEpochId
);
define_identifier!(
    /// Stable identifier for one idempotent availability capacity consumption.
    AvailabilityConsumptionId
);
define_identifier!(
    /// Stable identifier for one professional category service root.
    ProviderServiceId
);
define_identifier!(
    /// Stable identifier for one customer service request.
    ServiceRequestId
);
define_identifier!(
    /// Stable identifier for one materialized request candidate.
    RequestCandidateId
);
define_identifier!(
    /// Stable identifier for one approval-required connection request.
    ConnectionRequestId
);
define_identifier!(
    /// Stable identifier for one immutable contact disclosure.
    ContactRevealId
);
define_identifier!(
    /// Stable identifier for one customer allowance debit.
    CustomerAllowanceEventId
);
define_identifier!(
    /// Stable identifier for one directional account block.
    AccountBlockId
);
define_identifier!(
    /// Stable identifier for one two-sided introduction review.
    ReviewId
);
define_identifier!(
    /// Stable identifier for one immutable review revision.
    ReviewRevisionId
);
define_identifier!(
    /// Stable identifier for one safety report.
    ReportId
);
define_identifier!(
    /// Stable identifier for one safety restriction.
    SafetyRestrictionId
);
define_identifier!(
    /// Stable identifier for one professional subscription.
    SubscriptionId
);
define_identifier!(
    /// Stable identifier for one exact payment record.
    PaymentId
);
define_identifier!(
    /// Stable identifier for one accepted billing webhook.
    BillingWebhookEventId
);
define_random_identifier!(
    /// Non-sequential identifier safe to expose in customer-facing profile references.
    PublicProfileReference
);
define_identifier!(
    /// Stable identifier for a persisted conversation state.
    ConversationSessionId
);
define_identifier!(
    /// Stable identifier for one accepted external provider event.
    InboundEventId
);
define_identifier!(
    /// Stable identifier for one durable outbound provider submission.
    OutboundMessageId
);
define_identifier!(
    /// Stable identifier for one immutable outbound delivery transition.
    DeliveryEventId
);
define_identifier!(
    /// Correlates one request or workflow across logs and durable records.
    CorrelationId
);
define_identifier!(
    /// Stable identifier for one durable background job.
    OutboxJobId
);
define_identifier!(
    /// Stable identifier for one running worker process instance.
    WorkerId
);
define_random_identifier!(
    /// Random fencing token issued every time an outbox job is leased.
    JobLeaseToken
);
define_random_identifier!(
    /// Non-PII callback token correlated through provider delivery webhooks.
    CallbackToken
);
define_identifier!(
    /// Stable identifier for one immutable administrative audit event.
    AuditEventId
);

#[cfg(test)]
mod tests {
    use super::{AccountId, JobLeaseToken, OutboxJobId, PublicProfileReference};
    use std::str::FromStr;
    use uuid::Version;

    #[test]
    fn generated_identifiers_are_uuid_v7() {
        let identifier = AccountId::new();
        assert_eq!(
            identifier.into_uuid().get_version(),
            Some(Version::SortRand)
        );
    }

    #[test]
    fn identifiers_round_trip_through_text() -> Result<(), uuid::Error> {
        let identifier = OutboxJobId::new();
        let parsed = OutboxJobId::from_str(&identifier.to_string())?;
        assert_eq!(parsed, identifier);
        Ok(())
    }

    #[test]
    fn identifiers_serialize_as_plain_uuid_values() -> Result<(), serde_json::Error> {
        let identifier = AccountId::new();
        let encoded = serde_json::to_string(&identifier)?;
        let decoded: AccountId = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, identifier);
        Ok(())
    }

    #[test]
    fn externally_visible_and_fencing_identifiers_are_random_uuid_v4() {
        let profile_reference = PublicProfileReference::new();
        let lease_token = JobLeaseToken::new();

        assert_eq!(
            profile_reference.into_uuid().get_version(),
            Some(Version::Random)
        );
        assert_eq!(lease_token.into_uuid().get_version(), Some(Version::Random));
    }
}
