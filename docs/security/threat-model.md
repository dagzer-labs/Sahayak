# Threat Model

Version: 1.0. Owner: Security and Operations. Review cadence: quarterly and after material architecture changes.

## Assets And Trust Boundaries

Protected assets are account identifiers, phone numbers, exact locations, profile media, identity assertions, contact disclosures, reports, payment records, encryption keys, webhook secrets, and administrator grants. Trust boundaries exist at Meta and Razorpay webhooks, outbound provider APIs, operator access, PostgreSQL, secret mounts, backups, object storage, and CI/CD.

## Principal Threats And Controls

| Threat | Required controls | Residual response |
|---|---|---|
| Forged or replayed webhooks | HMAC over exact raw bytes, rotating secrets, durable provider-event uniqueness, bounded body | Disable endpoint secret and investigate collision audit |
| Unauthorized contact disclosure | Transactional account, block, availability, capacity, billing, consent, and session-version checks | Suspend affected account and preserve disclosure evidence |
| Location or phone disclosure | Private schema, authenticated encryption, privacy-safe projections, redacted debug output | Rotate keys and run breach procedure |
| Administrator takeover | Channel-bound expiring allowlist, explicit confirmation, immutable audit, self-action denial | Revoke grant and suspend affected workflows |
| Queue replay or stale command | Idempotency keys, optimistic versions, leases, session-token fencing | Dead-letter and require audited manual review |
| Payment spoofing or mismatch | Razorpay raw-body HMAC, exact minor units, plan/currency validation, provider reconciliation | Remove entitlement and open reconciliation exception |
| Backup or key theft | Provider encryption, separate key custody, least privilege, tested expiry and rotation | Revoke credentials and invoke breach procedure |
| Resource exhaustion | Request/body timeouts, size limits, bounded pools/jobs, edge rate limits | Shed load and protect webhook acknowledgement path |
| SSRF through provider URLs | Production HTTPS requirement and operator-controlled base URLs | Disable integration and rotate credentials |

No browser redirect, user-supplied identifier, payment URL, or provider status without a verified callback is authoritative.
