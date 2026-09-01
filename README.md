# Sahayak

> Find available, phone-verified and manually approved local service professionals through WhatsApp. Professionals who complete an optional approved provider-hosted identity check additionally show `Identity checked`.

## Product Vision

Sahayak is a request-based local service discovery network for people who need practical help quickly and for independent service professionals who want direct access to nearby customers.

A customer tells Sahayak what help they need and shares their location. Sahayak contacts suitable professionals nearby, confirms that one of them is available, and introduces both parties. They then discuss the work, price, payment, and service directly.

Sahayak does not take a percentage of the professional's earnings. Customers use the discovery service for free. Professionals receive their first qualified introduction for free and can then pay a small, predictable subscription to continue receiving relevant requests.

The initial product will operate through WhatsApp because it is already familiar to both customers and local professionals. A dedicated mobile application will be considered only if real usage shows that WhatsApp limits the experience.

## The Problem

Finding dependable local help is still unnecessarily difficult, especially when the need is immediate.

### For customers

- Search results and business directories often contain outdated phone numbers, unavailable providers, or businesses located too far away.
- Calling several providers to ask whether they are available wastes time.
- Marketplace applications introduce account creation, app installation, and unfamiliar booking flows at the moment help is needed.
- A listing, phone number, or star rating alone provides little confidence about who will arrive.

### For service professionals

- Commission-based marketplaces can reduce earnings or force professionals to increase customer prices.
- Generic advertising produces irrelevant calls and provides no guarantee of local demand.
- Professionals often have no simple way to advertise that they are available right now.
- New professionals struggle to build online visibility even when they provide good service.

## What Sahayak Is

Sahayak is a **local discovery and introduction service**. It coordinates availability and contact exchange; it does not manage the service itself.

Sahayak will:

- collect a customer's service request and location;
- identify eligible professionals by service category, distance, availability, and reliability;
- ask nearby professionals whether they can take the request;
- introduce the customer to an available professional;
- collect feedback and handle reports after the interaction; and
- give operators the tools to review profiles, requests, and safety incidents.

Sahayak is not:

- a police, fire, ambulance, medical, or public emergency-response service;
- the employer or agent of a listed professional;
- a guarantee of workmanship, arrival time, price, or personal safety;
- a price-setting or payment-processing marketplace in the MVP; or
- an open directory that publishes customers' or professionals' personal details.

## Initial Market

The MVP will launch in one compact city zone or PIN-code cluster. It will not open across an entire city until there is enough active supply in the pilot area.

The only pilot service categories are:

1. Plumbers for urgent leaks and water-system faults.
2. Electricians for household electrical faults.

These categories have clear intent, location-dependent demand, and a meaningful cost when customers cannot find help quickly. Medical emergencies, crime reporting, fire response, towing, and other regulated or high-risk services are outside the initial scope.

## MVP Experience

### Customer journey

1. The customer opens Sahayak from a WhatsApp link or QR code.
2. The customer selects a supported service category.
3. The customer shares a current WhatsApp location pin.
4. The customer selects either `Need help now` or `Need help today` and adds a short description.
5. Sahayak searches for eligible professionals within the configured service radius.
6. Nearby professionals receive the request without the customer's exact address or phone number.
7. When a professional accepts, the customer sees their profile and chooses whether to connect.
8. After confirmation, Sahayak shares the contact details required for the two parties to communicate directly.
9. Sahayak later asks both parties whether contact occurred, whether the interaction was completed safely, and whether either party wants to report a problem.

If nobody accepts, Sahayak expands the search within a safe configured limit. If no professional is available, it says so clearly instead of presenting stale contacts or promising a response it cannot deliver.

### Professional journey

1. The professional registers through WhatsApp and verifies ownership of their phone number.
2. They provide their name, photo, service categories, base service area, travel radius, and working hours.
3. They may complete an optional approved provider-hosted identity check. Declining or not completing it does not block profile approval or search eligibility.
4. An operator reviews and approves the profile before it can receive customer requests.
5. The professional marks themselves `Available` or `Unavailable` through WhatsApp.
6. An available professional receives nearby requests containing the category, approximate area, approximate distance, urgency, and customer notes.
7. They accept or decline without penalty. Exact customer details are not disclosed until the customer also confirms the introduction.
8. After the interaction, they can confirm the outcome and report spam, abuse, an unsafe location, or a customer no-show.

## Availability Management

- Approved professionals can choose one hour, four hours, or the end of their local day.
- Availability is bound to the currently published profile revision and is evaluated using database time.
- Each period snapshots the approved contact limit across all of the professional's categories.
- Stopping and resuming preserves the same expiry and contact count; it cannot reset capacity.
- Renewing schedules one successor period that starts only after the current period naturally ends.
- Reaching the contact limit pauses visibility atomically and notifies the professional.
- One bounded pre-expiry reminder may be sent: 10 minutes before a one-hour period, 30 minutes before a four-hour period, and no later than 21:00 local time for end-of-day periods. Reminders have a four-hour spacing and two-per-day cap.
- Expired, stopped, paused, suspended, hidden, restricted, or superseded profiles fail the availability guard even when a timer worker is delayed.
- Timer jobs contain only internal identifiers and never use recipient ordering keys; actual notifications receive an ordering key only when queued for immediate delivery.

## Matching And Dispatch

Search requests keep the customer's exact point in `private_data` and materialize deterministic, versioned candidate snapshots. Initial cards contain at most three approved public profiles and expose no phone numbers, profile photos, or exact professional/customer locations. Ranking uses category and skill fit, PostGIS distance, language compatibility, availability freshness, response history, and bounded fair-distribution load; subscriptions and identity-check completion have no ranking weight.

Selecting a direct-contact service atomically rechecks both accounts, two-way blocks, the published service, availability, the customer's rolling allowance, and the professional's remaining capacity before recording an immutable reveal. Approval-required services create a bounded pending request and reveal nothing until a version-bound acceptance. Customers receive three new professional reveals per rolling 24 hours; previously revealed contacts remain available without another debit. Contact-bearing payloads and photos are linked to every represented data subject for deletion, and definitive pre-delivery failures create compensating allowance and capacity reversals.

## Trust, Safety, And Billing

Reviews are restricted by PostgreSQL to delivered qualified introductions and retain immutable encrypted edit history. Public rating averages remain hidden until three published reviews exist. Reports are introduction-bound, encrypt reporter descriptions, expose a reporter-safe subject projection, support immediate directional blocking, synchronously restrict severe subjects, and require audited administrator outcomes.

Professional billing is account-wide: the first qualified introduction is free, after which eligibility requires an active subscription or valid grace period. Razorpay webhooks are verified over their exact raw bytes, deduplicated by provider event ID, and reconciled against exact INR minor units, payment, invoice, order, subscription, and tax-document references. Billing state is excluded from ranking scores and never deletes profile data.

Production controls include bounded request concurrency, database timeouts, JSON logging, optional privacy-safe Sentry reporting, Prometheus queue/safety/billing metrics, alert rules, secret and container scans, immutable legal-content manifests, retention/legal-hold records, and tested backup/restore scripts. Deployment and incident procedures are under `docs/operations/` and `deploy/`.

The MVP should optimize for a useful and fair introduction, not for paid placement.

A professional is eligible only when they:

- are approved for the requested category;
- have an active account or unused free introduction;
- have marked themselves available;
- serve the customer's area; and
- are not suspended or under safety review.

Eligible professionals are ranked using:

- proximity to the request;
- recent response reliability;
- relevant category and skills;
- recent workload, so requests are not always concentrated among the same few people; and
- customer feedback once enough genuine feedback exists.

Subscription price must not allow a professional to outrank a closer or more reliable professional. Identity status and safety controls must never be purchasable ranking features.

The initial dispatch policy is:

1. Contact up to three suitable professionals in the first wave.
2. If nobody accepts within 60 seconds, contact the next suitable group and gradually widen the radius.
3. Introduce only one professional at a time unless the customer explicitly asks for alternatives.
4. Stop dispatching after an introduction is confirmed, the customer cancels, or the request expires.

These values are pilot defaults and should be changed using observed response and completion data.

## Business Model

### Customers

Customer discovery is free. Sahayak does not add a service fee to the professional's price in the MVP.

### Service professionals

- Registration and profile review are free.
- The first qualified introduction is free.
- Continuing access starts with one pilot subscription: **INR 99 per month**.
- Sahayak charges no commission on work completed through an introduction.
- The subscription does not guarantee a fixed number of requests or completed jobs because local demand cannot be guaranteed.

A **qualified introduction** occurs only when:

1. the professional accepts a genuine request;
2. the customer confirms that they want to connect; and
3. Sahayak releases contact details to both parties.

Declined, expired, duplicate, fraudulent, or customer-rejected requests do not consume the free introduction. Job completion is not required because Sahayak does not control the parties' final agreement.

The INR 99 price is a pilot hypothesis. It must be tested against acquisition cost, support cost, messaging cost, professional retention, and demonstrated customer demand before additional plans are introduced.

## Trust, Safety, And Privacy

Identity checking is optional and does not gate publication. Phone-verified, manually approved professionals may be searchable when they meet the other eligibility rules. Identity checking does not prove competence, good intent, safety, background, or future behavior, so Sahayak must describe every trust signal precisely.

Possible profile labels include:

- `Phone verified`: ownership of the registered phone number was confirmed.
- `Identity checked`: an approved provider returned a current successful assertion from its hosted identity-check flow. This exact label appears only while that assertion remains valid.
- `Credential checked`: a relevant credential was reviewed for a category where credentials apply.
- `Sahayak activity`: request responses and customer feedback recorded on Sahayak.

Sahayak must not call a professional "safe," "certified," or "background checked" unless the corresponding check was actually completed and remains valid.

The MVP safety controls are:

- customer phone verification before an introduction;
- phone verification and manual profile approval for professionals;
- an optional provider-hosted identity check with a viable non-Aadhaar route, without making either route a publication requirement;
- rate limits and duplicate-request detection;
- approximate location disclosure before mutual confirmation;
- exact contact and location disclosure only when needed for the accepted request;
- two-way block and report controls;
- immediate suspension when a credible severe-safety report requires investigation;
- an operator audit trail for profile and incident decisions; and
- clear links to official emergency services when a request is outside Sahayak's scope.

For an identity check, Sahayak stores only the normalized assertion status, provider, assertion date, expiry, and an encrypted opaque dispute reference when necessary. Sahayak must not store an Aadhaar number or its last four digits, ID or card images, legal-identity source data, selfies, biometric templates or scores, provider-hosted URLs, or raw provider responses.

Phone verification plus manual approval is the non-Aadhaar path to publication. If an Aadhaar-based check can produce `Identity checked`, an equivalent provider-hosted route using accepted non-Aadhaar identity evidence, such as a driving licence, voter ID, or passport, must be offered for the same label. Outsourcing this processing does not remove Sahayak's responsibility for the flow, claims, consent, security, retention, deletion, or incident handling. The live adapter must remain disabled until the selected vendor's versioned API and callback-signature contract are confirmed and all applicable UIDAI approvals, OVSE registration, AUA or Sub-AUA arrangements, and legal approval are documented.

## Product Principles

1. **Tell the truth about availability.** Show no result rather than an unavailable or fabricated option.
2. **Earn trust with specific evidence.** Explain what was checked instead of using broad "verified" claims.
3. **Protect both sides.** Customers and professionals can both face fraud, harassment, or unsafe situations.
4. **Keep commercial terms direct.** The parties agree on price, payment, and scope without Sahayak commission in the MVP.
5. **Do not sell safety or relevance.** Payment cannot override eligibility, proximity, or reliability.
6. **Start where density can be created.** A small useful network is better than a large empty map.
7. **Automate only proven workflows.** Manual operations are acceptable during the pilot when they improve learning or safety.
8. **Add channels only when needed.** WhatsApp is the initial interface, not a reason to build abstractions for every future platform on day one.

## Pilot Plan

### Stage 1: Concierge validation

- Recruit plumbers and electricians within one compact area.
- Review and approve profiles and availability manually.
- Run customer requests with operator-assisted matching.
- Measure whether customers receive a useful introduction and whether professionals value the requests.

### Stage 2: WhatsApp MVP

- Automate request intake, availability, dispatch, acceptance, and feedback.
- Add a small operations interface for profile approval and incident handling.
- Introduce the free qualified introduction and INR 99 subscription rule.
- Keep matching decisions observable so failed requests can be explained and improved.

### Stage 3: Controlled expansion

- Expand to adjacent areas only after the pilot area meets its service targets.
- Add categories only after enough suitable professionals are recruited.
- Consider a professional mobile app only if background availability or location updates become a demonstrated limitation.
- Consider customer applications, payments, APIs, or international expansion only after the core introduction model is repeatable.

## Pilot Success Criteria

The first pilot should test the following targets rather than assume them:

- At least 100 approved professionals across the launch area, with sufficient coverage in every active category.
- At least 500 valid customer requests during the measurement period.
- At least 70% of valid requests receive a professional acceptance within 10 minutes.
- Median time to acceptance is below 5 minutes for `Need help now` requests.
- Fewer than 15% of confirmed introductions end in a professional no-show or an unreachable party.
- At least 30% of professionals who receive a free qualified introduction choose to pay for one month.
- Every severe-safety report is acknowledged and placed under operator review within the defined incident-response window.

The pilot succeeds only if customers can reliably reach available help, professionals receive economically useful introductions, and the operating cost can be supported by the subscription. Sign-ups, profile count, and message volume alone are not evidence of product-market fit.

## Decisions Required Before Launch

The following are intentionally not presented as settled facts:

- pilot city, zone, and launch date;
- final service radius and category-level coverage requirements;
- optional identity-verification provider, viable non-Aadhaar route, vendor-specific API and callback-signature contract, and applicable UIDAI approvals, OVSE registration, AUA or Sub-AUA arrangements, and legal approval before enabling the live adapter;
- WhatsApp template approval, messaging limits, and actual per-request cost;
- subscription billing, cancellation, refund, and tax handling;
- report severity levels, review process, and operator response times;
- customer and professional terms, consent, privacy policy, and liability position; and
- pilot staffing and support budget.

Official references for the identity-verification decision include the [UIDAI OVSE programme](https://uidai.gov.in/en/ovse), [Aadhaar Authentication and Offline Verification Regulations](https://backend.uidai.gov.in/get/files/media/document/2026-06/Regulation.pdf), and [UIDAI authentication ecosystem](https://uidai.gov.in/authentication-partners).

Technical architecture, detailed data models, financial forecasts, and expansion plans should be documented after these product and operating decisions are validated. They must support the product rather than define it prematurely.

## Development Foundation

The initial implementation is a Rust 2024 workspace containing:

- `apps/api`: HTTP ingress, health checks, request controls, and graceful shutdown;
- `apps/migrator`: checksummed database migrations run with deployment credentials;
- `apps/worker`: background-process supervision and future durable job execution;
- `crates/configuration`: typed environment configuration and validation;
- `crates/cryptography`: authenticated encryption, key rotation, and blind indexes;
- `crates/localization`: validated English, Hindi, and Marathi catalogs;
- `crates/conversation-engine`: provider-neutral workflows and navigation rules;
- `crates/domain`: channel-independent identifiers and business values;
- `crates/observability`: structured logging and panic reporting; and
- `crates/persistence`: PostgreSQL repositories, durable ingestion, outbox leases, migrations, and health checks;
- `crates/whatsapp`: Meta webhook contracts, normalized events, outbound models, and Cloud API client.

Future search, billing, and mobile-channel modules will be introduced only when their first real behavior is implemented.

The current data foundation includes channel-neutral accounts, versioned channel identities, encrypted WhatsApp identifiers, rotating blind indexes, privacy-safe profiles, a provider-neutral boundary for normalized identity assertions and necessary encrypted opaque dispute references, optimistic conversation sessions, idempotent inbound events, fenced outbox jobs, and immutable audit events.

The conversation engine currently supports first-contact language selection and confirmation, a localized main menu, More and Help menus, stale-selection recovery, typed back/cancel/menu commands, session-expiry recovery, and explicit future-feature boundaries. Language is never inferred from a phone number.

Initial interface locales are `en-IN`, `hi-IN`, and `mr-IN`. Proactive re-entry uses the configured `sahayak_reentry` template with separately approved Meta variants `en_IN`, `hi`, and `mr`. Free-form menus are revalidated against the 24-hour service window immediately before sending.

### Local Requirements

- Rust 1.98.0, automatically selected through `rust-toolchain.toml`
- Docker 29 or newer
- Docker Compose 5 or newer

### Local Database

Start PostgreSQL 18 with PostGIS 3.6:

```bash
docker compose up database
```

The local database is bound to `127.0.0.1:55432` to avoid conflicts with other workspace services.

Apply the foundation migration:

```bash
cargo run --locked --bin sahayak-migrator
```

### Validation

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
SAHAYAK_TEST_DATABASE_URL=postgres://sahayak_app:sahayak_dev@127.0.0.1:55432/sahayak cargo test --workspace --all-targets --locked
cargo build --workspace --release --locked
```

### Running Processes

Run the API:

```bash
cargo run --locked --bin sahayak-api
```

Run the worker supervisor:

```bash
cargo run --locked --bin sahayak-worker
```

The API exposes:

- `GET /health/live`: process-only liveness;
- `GET /health/ready`: bounded PostgreSQL readiness.

Configuration uses `SAHAYAK__...` environment variables. `.env.example` documents supported foundation settings without containing production secrets.

## WhatsApp Transport

The transport pins Meta Graph API `v26.0`. Message request contracts are covered by golden tests against Meta's current WhatsApp reference. The API accepts signed callbacks at:

```text
https://api.sahayak.dagzer.com/webhooks/whatsapp
```

WhatsApp remains disabled by default. Enabling it requires the WABA ID, business phone-number object ID, and mounted secret files documented in `.env.example`.

### Secret Files

Secret files must be regular files, contain one value, contain no NUL bytes, and use private permissions in production. The API reads the current app secret, optional previous app secret, verification token, and inbound keyring. The worker reads the access token and transport keyring. The migrator receives none of them.

The keyring file is line-oriented:

```text
integration_encryption.active=1
integration_encryption.1=<base64-encoded-32-byte-key>
lookup_hmac.active=1
lookup_hmac.1=<base64-encoded-32-byte-key>
```

The worker keyring additionally requires:

```text
contact_encryption.active=1
contact_encryption.1=<base64-encoded-32-byte-key>
media_encryption.active=1
media_encryption.1=<base64-encoded-32-byte-key>
```

Contact, media, or identity key purposes must be mounted only into processes that require them. The API does not receive contact or media keys, and the current worker does not receive identity-verification keys.

### Real Test-Number Smoke Procedure

1. Create a dedicated Meta test app, WABA, connected test phone-number ID, and test recipient.
2. Mount newly generated app-secret, verify-token, access-token, and keyring files with private permissions.
3. Set `SAHAYAK__WHATSAPP__ENABLED=true`, the WABA ID, phone-number ID, and `v26.0` configuration.
4. Start PostgreSQL, run `sahayak-migrator`, then start the API and worker.
5. Expose the callback through publicly trusted HTTPS and configure Meta's `messages` webhook subscription.
6. Confirm Meta's GET challenge returns the exact challenge text.
7. Send text, button, list, location, and image messages from the Meta test recipient.
8. Confirm each logical event appears once in `integration.inbound_events`, with no plaintext body, phone, coordinate, caption, or media reference.
9. Queue one controlled test outbound message through the transport repository and confirm one Meta `wamid` is recorded.
10. Confirm subsequent `sent`, `delivered`, and `read` callbacks create append-only delivery events and update monotonic milestones.
11. Simulate a timeout after connection and verify the outbound row becomes `unknown` and is not resent automatically.
12. Revoke every temporary token and remove the test recipient after the smoke test.

Never place real Meta credentials, phone numbers, callback payloads, or cryptographic keys in source control, command history, test fixtures, logs, or issue trackers.
