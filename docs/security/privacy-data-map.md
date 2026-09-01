# Privacy Data Map And Retention

Version: 1.0. Durations below are pilot defaults and require legal approval before production.

| Data class | Location | Purpose | Pilot retention | Deletion trigger | Legal hold |
|---|---|---|---|---|---|
| Phone and channel identity | `private_data.whatsapp_identities` | Authentication and contact disclosure | Account lifetime | Account deletion | Prohibited unless required by law |
| Legal identity | `private_data.account_identities` | Verification and disputes | Account lifetime | Account deletion | Excluded from routine purge |
| Exact service location | `private_data.service_request_locations` | Nearby matching | 30 days | Scheduled purge/account deletion | Excluded while related safety case is open |
| Sanitized profile media | `private_data.profile_photos` | Approved profile/contact display | Account lifetime | Replacement/account deletion | Excluded while required as safety evidence |
| Inbound/outbound payloads | `integration`, `messaging` | Delivery and replay handling | 14 days after terminal state | Scheduled purge | Excluded while linked to an open case |
| Contact reveal evidence | `connection` | Consent, quota, dispute evidence | 3 years | Retention expiry/anonymization | Preserved during hold |
| Reviews and feedback | `review` | Trust signals | Account lifetime or 3 years | Withdrawal/account deletion | Feedback erased; aggregate recomputed |
| Safety reports/evidence | `safety` | Incident response | 5 years after resolution | Approved purge | Hold overrides expiry |
| Billing and tax records | `billing` | Entitlement, reconciliation, tax | 8 financial years | Approved fiscal purge | Hold overrides expiry |
| Audit records | `audit.events` | Security/accountability | 5 years | Partition archive expiry | Hold overrides expiry |
| Backups | Managed database | Disaster recovery | 7 daily plus PITR window | Provider lifecycle | Holds require separate approved archive |

Reporter identity, report descriptions, evidence, phone numbers, exact coordinates, and payment-provider secrets are never public projections or metric labels. Backup expiry must eventually remove data deleted from the primary database.
