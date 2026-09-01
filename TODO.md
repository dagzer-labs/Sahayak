# Sahayak Implementation Plan

## Document Purpose

This document is the implementation source of truth for the first production version of Sahayak.

It defines:

- the finalized product rules;
- the WhatsApp user experience;
- the technical architecture;
- the production repository structure;
- the data domains and state machines;
- privacy, safety, billing, and operational requirements;
- the phase-by-phase implementation sequence;
- the acceptance criteria for every phase; and
- the conditions required before public launch.

This document intentionally contains no application code.

Implementation must not begin a later phase until the required acceptance criteria of the current phase are satisfied.

## 1. Final Product Definition

Sahayak is an availability-first people discovery and introduction network.

A person tells Sahayak what kind of professional they need, where that professional may operate, and when they need help. Sahayak returns privacy-safe profiles of suitable professionals who have recently confirmed their availability.

The customer selects a professional and receives contact access according to the professional's chosen contact mode.

Sahayak facilitates discovery and introduction only.

Sahayak does not control:

- the final price;
- the scope of work;
- payment for the work;
- service delivery;
- warranties;
- refunds between the parties; or
- the final commercial relationship.

Sahayak remains responsible for:

- platform privacy;
- account security;
- consent before contact disclosure;
- preventing obvious abuse;
- receiving reports;
- blocking and suspending accounts;
- maintaining accurate platform records; and
- complying with applicable platform and legal obligations.

## 2. Long-Term Vision And Launch Scope

### 2.1 Long-Term Vision

Sahayak should eventually support lawful professional services across India.

Examples include:

- plumbers;
- electricians;
- appliance technicians;
- roadside assistance providers;
- teachers;
- tutors;
- developers;
- designers;
- accountants;
- consultants;
- photographers;
- real-estate agents; and
- other permitted professional categories.

The platform foundation must support:

- local services;
- city-wide services;
- state-wide services;
- nationwide services;
- remote services; and
- hybrid services.

### 2.2 Pilot Scope

The pilot must activate only:

- plumbers; and
- electricians.

The pilot must operate in one compact geographic area.

Inactive future categories may exist in the taxonomy but must not appear to users.

The pilot must prove:

- professionals can onboard through WhatsApp;
- professionals keep availability current;
- customers can find available professionals;
- contact disclosure works safely;
- customers do not abuse phone-number access;
- professionals receive useful introductions;
- feedback can be collected; and
- professionals are willing to pay after receiving value.

## 3. Final Channel Strategy

### 3.1 Customer Channel

The customer experience is WhatsApp-only for the MVP.

Customers must be able to:

- select a language;
- search for a profession;
- choose geographic scope;
- share a location;
- choose urgency;
- apply simple filters;
- browse a limited result set;
- request or reveal contact details;
- call or message the professional;
- rate an introduction;
- report a problem;
- block a professional; and
- manage basic account preferences.

### 3.2 Professional Channel

The professional experience is WhatsApp-only for the MVP.

Professionals must be able to:

- register;
- select languages;
- create a privacy-safe profile;
- choose service categories;
- define a service area;
- choose local, remote, or hybrid delivery;
- choose a contact mode;
- provide an optional profile photo;
- optionally launch an approved provider-hosted identity check without sending identity data to Sahayak;
- receive approval status;
- set availability;
- accept or decline requests;
- review recent introductions;
- receive subscription information;
- report customers;
- block customers; and
- edit supported profile fields.

### 3.3 Administrative Channel

The first administrative interface may use restricted WhatsApp commands and internal command-line operations.

Only allowlisted administrator accounts may perform administrative actions.

A web operations portal is deferred until operational volume proves it is needed.

### 3.4 Required Static Web Presence

There is no public search website in the MVP.

Static pages are still required for:

- privacy policy;
- terms of service;
- contact information;
- account deletion instructions; and
- payment and cancellation terms.

These pages will live under `sahayak.dagzer.com`.

## 4. Final Product Rules

### 4.1 Identity Presentation

Phone verification and manual profile approval are the identity-related publication requirements. A professional who meets them may be searchable when the other eligibility rules are satisfied, whether or not they complete an identity check.

Identity checking is optional. Refusing, abandoning, failing, or being unable to complete it must not block publication. Phone verification plus manual approval is the non-Aadhaar publication path. If an Aadhaar-based check can produce `Identity checked`, an equivalent provider-hosted route using accepted non-Aadhaar identity evidence, such as a driving licence, voter ID, or passport, must be offered for the same label.

Public search results must not show legal names.

Search results may show:

- chosen first name;
- random Sahayak public ID;
- profession;
- relevant skills;
- approximate distance or service area;
- current availability;
- rating;
- rating count;
- confirmed introduction count;
- response reliability; and
- `Identity checked` only while a qualifying provider assertion is current and successful.

Search results must not show:

- legal name;
- phone number;
- email address;
- exact address;
- exact live location;
- an Aadhaar number or its last four digits;
- any other government identifier;
- employer details;
- external profile links;
- ID or card images;
- legal-identity source data;
- selfies or biometric templates or scores;
- provider-hosted verification URLs;
- raw provider responses; or
- profile photo.

`Identity checked` is the exact optional label. It is not a safety, skills, licence, background, conduct, or future-behavior guarantee. Phone verification or manual approval alone must not produce this label.

### 4.2 Profile Photos

Profile photos are optional.

Profile photos must not appear in initial search results.

For direct-contact professionals, the photo may be shared after the customer selects the profile and the contact reveal is recorded.

For approval-required professionals, the photo may be shared after the professional accepts the request.

Professionals must explicitly consent to this disclosure behavior during onboarding.

Professionals must be warned that recipients can save or screenshot shared photos.

Images must be stripped of unnecessary metadata before long-term storage.

### 4.3 Contact Modes

Every professional service configuration must choose one of two contact modes.

Contact mode is configured per professional service, not globally per account.

The two modes are:

- direct contact; and
- approval required.

### 4.4 Direct Contact Mode

Direct contact means the professional gives advance consent to receive direct calls or WhatsApp messages while marked available.

The customer selects the professional.

Sahayak records a contact reveal.

Sahayak sends the customer call and WhatsApp actions.

Sahayak notifies the professional that contact details were disclosed.

The professional can disable direct contact at any time.

### 4.5 Approval Required Mode

Approval required means the professional must accept before contact details are revealed.

The customer sends a connection request.

The professional receives a privacy-safe request summary.

The professional accepts or declines.

Sahayak reveals contact details only after acceptance.

Unanswered requests expire automatically.

### 4.6 Customer Usage Limits

Searching does not consume the daily allowance.

Opening result pages does not consume the daily allowance.

A new contact reveal consumes one allowance unit.

An approval-required request consumes the allowance only after acceptance and disclosure.

Customers receive three new contact reveals in a rolling 24-hour period.

Previously revealed contacts remain available without consuming another allowance unit.

Payment must never remove all safety limits.

The customer INR 99 plan is deferred until real customers demonstrate a legitimate need for more than three daily contacts.

### 4.7 Professional Free Value And Subscription

Professional registration is free.

Profile review is free.

The first qualified introduction per professional account is free.

After free introductions are consumed, the initial professional subscription is INR 99 per month for the professional account.

The MVP subscription covers all approved service categories on that professional account.

Adding another service category must not reset the free introduction balance.

Subscription status must never improve ranking.

Subscription does not guarantee a fixed number of requests or jobs.

### 4.8 Qualified Introduction

A direct-contact introduction becomes qualified when:

- the customer selects an eligible available professional;
- Sahayak records the disclosure; and
- contact actions are successfully delivered to the customer.

An approval-required introduction becomes qualified when:

- the customer requests the professional;
- the professional accepts;
- Sahayak records the disclosure; and
- contact actions are successfully delivered to both parties.

The following do not count as qualified introductions:

- searches;
- profile impressions;
- declined requests;
- expired requests;
- blocked requests;
- duplicate requests;
- fraudulent requests;
- failed message delivery; or
- disclosures reversed because of an internal system error.

### 4.9 Ratings

Only users associated with a qualified introduction may submit a rating.

One customer may submit only one active rating per qualified introduction.

Rating edits must preserve audit history.

Ratings must distinguish between:

- connection experience;
- responsiveness;
- reported completion; and
- optional written feedback.

Sahayak must not claim that a rating proves technical competence.

### 4.10 Availability

Availability is temporary and must always expire.

Supported MVP options are:

- available for one hour;
- available for four hours;
- available until the end of the local day; and
- unavailable.

The professional receives a confirmation when availability changes.

Expired availability must remove the professional from active results.

The professional may set a maximum number of contact reveals per availability session.

The system may automatically pause visibility after that maximum is reached.

## 5. User Experience Principles

All user-facing interactions must follow these principles:

- prefer buttons over typing;
- use short sentences;
- ask one decision at a time;
- show no more than three profiles in one result batch;
- provide a clear back action;
- provide a clear cancel action;
- confirm destructive or sensitive actions;
- remember the selected language;
- confirm interpreted free text or voice input;
- never claim availability that is not current;
- never expose contact details accidentally;
- make errors recoverable; and
- provide human escalation for unresolved safety reports.

## 6. Language Strategy

The pilot supports:

- English;
- Hindi; and
- the primary language of the pilot state.

Every user-facing message must use a stable translation key.

Critical translations require human review.

Critical content includes:

- consent;
- privacy notices;
- contact disclosure;
- payment terms;
- subscription status;
- reports;
- blocking;
- suspension; and
- emergency disclaimers.

Machine translation may assist drafting but must not be the final authority for critical content.

Language preference is stored on the account.

Users may change language from the main menu.

Voice-note understanding is deferred until button and text flows are reliable.

## 7. System Context Architecture

```text
+--------------------+                         +----------------------+
| Customer WhatsApp  |                         | Professional WhatsApp|
+----------+---------+                         +----------+-----------+
           |                                              |
           +----------------------+-----------------------+
                                  |
                                  v
                    +-----------------------------+
                    | Meta WhatsApp Cloud API     |
                    | Messages, media, templates  |
                    +--------------+--------------+
                                   |
                                   | HTTPS webhook
                                   v
                    +-----------------------------+
                    | api.sahayak.dagzer.com      |
                    | Rust + Axum ingress API     |
                    +--------------+--------------+
                                   |
                      validate, deduplicate, store
                                   |
                                   v
                    +-----------------------------+
                    | PostgreSQL 18 + PostGIS     |
                    | Source of truth and outbox  |
                    +--------------+--------------+
                                   |
                                   v
                    +-----------------------------+
                    | Rust background worker      |
                    | Workflows, search, delivery |
                    +-------+-------------+-------+
                            |             |
                            v             v
                  +-------------+   +-------------+
                  | Meta API    |   | Razorpay    |
                  | outbound    |   | billing     |
                  +-------------+   +-------------+
```

## 8. Webhook Processing Architecture

```text
Meta webhook
     |
     v
Verify HTTPS route and request limits
     |
     v
Verify Meta signature
     |
     v
Parse minimum envelope metadata
     |
     v
Check provider event ID
     |
     +---------------- duplicate ----------------+
     |                                           |
     v                                           v
Store webhook event and outbox job          Return success
in one database transaction                      |
     |                                           |
     v                                           +--> no repeated work
Return success immediately
     |
     v
Worker claims outbox job
     |
     v
Load conversation state
     |
     v
Apply domain transition
     |
     v
Create outbound message job
     |
     v
Send through Meta API
     |
     v
Store delivery result and retry state
```

## 9. Customer Discovery Flow

```text
[User sends Hi]
       |
       v
[Choose language]
       |
       v
[Main menu]
       |
       v
[Find a professional]
       |
       v
[Choose category]
       |
       v
[Choose local / city / state / India / remote]
       |
       v
[Share location when required]
       |
       v
[Choose now / today / scheduled]
       |
       v
[Apply category filters]
       |
       v
[Show up to three privacy-safe profiles]
       |
       +-----------------------------+
       |                             |
       v                             v
[Show more]                    [Select profile]
                                     |
                         +-----------+-----------+
                         |                       |
                         v                       v
                  [Direct contact]       [Approval required]
                         |                       |
                         v                       v
                  [Record reveal]        [Send request]
                         |                       |
                         v                       v
                  [Share actions]        [Wait for response]
                                                 |
                                      +----------+----------+
                                      |                     |
                                      v                     v
                                  [Accepted]             [Declined]
                                      |                     |
                                      v                     v
                                [Record reveal]       [Offer alternatives]
                                      |
                                      v
                                [Share actions]
```

## 10. Professional Onboarding Flow

```text
[Professional selects Offer my services]
                    |
                    v
            [Choose language]
                    |
                    v
          [Choose display name]
                    |
                    v
          [Select service category]
                    |
                    v
       [Provide category-specific skills]
                    |
                    v
       [Choose local / remote / hybrid]
                    |
                    v
          [Configure service coverage]
                    |
                    v
           [Choose contact mode]
                    |
                    v
          [Set contact-session limit]
                    |
                    v
        [Provide optional profile photo]
                    |
                    v
       [Review privacy and disclosure rules]
                    |
                    v
              [Provide consent]
                    |
                    v
       [Submit for administrative review]
                    |
            +-------+--------+
            |                |
            v                v
        [Approved]       [Changes needed]
            |                |
            v                +--> return to relevant step
     [Set availability]
            |
            v
     [Eligible for search]
```

## 11. Contact Disclosure Architecture

```text
                         [Customer selects profile]
                                      |
                         +------------+------------+
                         |                         |
                         v                         v
                 [Direct contact]         [Approval required]
                         |                         |
              check customer limit        create pending request
                         |                         |
              check provider limit        notify professional
                         |                         |
              check active blocks         wait for response
                         |                         |
              record immutable event      verify acceptance
                         |                         |
              reveal phone actions        recheck limits and blocks
                         |                         |
              notify professional         record immutable event
                                                   |
                                          reveal phone actions
                                                   |
                                          notify both parties
```

## 12. Trust Boundary Architecture

```text
+-------------------------------------------------------------------+
| Public or user-visible data                                       |
| Display name, public ID, skill, broad area, rating, availability  |
+-------------------------------+-----------------------------------+
                                |
                                | controlled domain service
                                v
+-------------------------------------------------------------------+
| Restricted operational data                                      |
| Contact reveal history, reports, moderation, subscription status  |
+-------------------------------+-----------------------------------+
                                |
                                | least-privilege repository
                                v
+-------------------------------------------------------------------+
| Highly restricted private data                                   |
| Phone number, profile media, consent evidence, encrypted opaque   |
| dispute reference when necessary                                 |
+-------------------------------+-----------------------------------+
                                |
                                | audited integration only
                                v
+-------------------------------------------------------------------+
| External processors                                               |
| Meta, Razorpay, optional verification provider, object storage    |
+-------------------------------------------------------------------+
```

## 13. Deployment Architecture

```text
Internet
   |
   v
DNS for api.sahayak.dagzer.com
   |
   v
TLS termination and request filtering
   |
   v
+----------------------+        +----------------------+
| Rust API container   |        | Rust worker container|
| Axum webhook ingress |        | Outbox processing    |
+----------+-----------+        +-----------+----------+
           |                                |
           +---------------+----------------+
                           |
                           v
              +---------------------------+
              | Managed PostgreSQL 18     |
              | PostGIS 3.6               |
              | Encrypted backups         |
              +-------------+-------------+
                            |
                            v
              +---------------------------+
              | Private object storage    |
              | Profile media only        |
              +---------------------------+

External integrations:

Meta WhatsApp Cloud API <---- API and worker ----> Razorpay API
Sentry / telemetry      <---- API and worker ----> Secret manager
```

## 14. Final Technology Baseline

The baseline was checked against live registries on August 30, 2026.

Use:

- Rust 1.98.0;
- Rust edition 2024;
- Axum 0.8.9;
- Tokio 1.53.1;
- SQLx 0.9.0;
- PostgreSQL 18.6;
- PostGIS 3.6;
- Serde 1.0.229;
- Serde JSON 1.0.151;
- Reqwest 0.13.4;
- Tower HTTP 0.7.0;
- Tracing 0.1.44;
- Tracing Subscriber 0.3.23;
- Tower 0.5.3;
- Axum Extra 0.12.6;
- Utoipa 5.5.0;
- Garde 0.23.0;
- UUID 1.26.0;
- Time 0.3.55;
- Thiserror 2.0.20;
- Secrecy 0.10.3;
- HMAC 0.13.0;
- SHA-2 0.11.0;
- Rust Decimal 1.42.1;
- Config 0.15.25;
- Sentry 0.49.2;
- Tracing OpenTelemetry 0.33.0;
- AWS SDK S3 1.144.0;
- URL 2.5.8;
- Base64 0.23.1;
- Hex 0.4.3;
- Rand 0.10.2;
- Wiremock 0.6.5; and
- Testcontainers 0.28.0.

Version rules:

- pin the Rust toolchain;
- commit the dependency lockfile;
- pin production images by immutable digest;
- do not use floating `latest` images in production;
- keep the Meta Graph API version configurable;
- review dependency updates through continuous integration;
- run migration and integration tests before upgrades; and
- document intentional version exceptions.

## 15. Domain And Endpoint Plan

Use:

- `sahayak.dagzer.com` for legal and future product pages;
- `api.sahayak.dagzer.com` for the production API;
- `api.sahayak.dagzer.com/webhooks/whatsapp` for WhatsApp events;
- `api.sahayak.dagzer.com/webhooks/razorpay` for payment events;
- `api.sahayak.dagzer.com/health/live` for liveness checks;
- `api.sahayak.dagzer.com/health/ready` for readiness checks;
- `ops.sahayak.dagzer.com` for the future operations portal; and
- `media.sahayak.dagzer.com` only if dedicated media delivery is later required.

Do not use:

- `api.dagzer.com` for Sahayak;
- public database endpoints;
- public object-storage buckets;
- environment names inside production customer URLs; or
- predictable public profile URLs.

Non-production domains may use:

- `api.dev.sahayak.dagzer.com`;
- `api.staging.sahayak.dagzer.com`;
- `dev.sahayak.dagzer.com`; and
- `staging.sahayak.dagzer.com`.

## 16. Production Repository Structure

```text
Sahayak/
|
+-- Cargo.toml
+-- Cargo.lock
+-- rust-toolchain.toml
+-- rustfmt.toml
+-- clippy.toml
+-- deny.toml
+-- Dockerfile
+-- compose.yaml
+-- .dockerignore
+-- .gitignore
+-- .env.example
+-- README.md
+-- TODO.md
|
+-- apps/
|   |
|   +-- api/
|   |   +-- Cargo.toml
|   |   +-- src/
|   |       +-- main.rs
|   |       +-- bootstrap.rs
|   |       +-- routes.rs
|   |       +-- health.rs
|   |       +-- middleware.rs
|   |       +-- shutdown.rs
|   |
|   +-- migrator/
|   |   +-- Cargo.toml
|   |   +-- src/
|   |       +-- main.rs
|   |
|   +-- worker/
|       +-- Cargo.toml
|       +-- src/
|           +-- main.rs
|           +-- bootstrap.rs
|           +-- dispatcher.rs
|           +-- scheduler.rs
|           +-- shutdown.rs
|
+-- crates/
|   |
|   +-- application/
|   |   +-- Cargo.toml
|   |   +-- src/
|   |       +-- lib.rs
|   |       +-- accounts/
|   |       +-- onboarding/
|   |       +-- profiles/
|   |       +-- taxonomy/
|   |       +-- availability/
|   |       +-- discovery/
|   |       +-- connections/
|   |       +-- reviews/
|   |       +-- safety/
|   |       +-- billing/
|   |       +-- administration/
|   |
|   +-- cryptography/
|   |   +-- Cargo.toml
|   |   +-- src/
|   |       +-- lib.rs
|   |       +-- cipher.rs
|   |       +-- context.rs
|   |       +-- hash.rs
|   |       +-- key.rs
|   |       +-- lookup.rs
|   |       +-- phone.rs
|   |       +-- error.rs
|   |
|   +-- domain/
|   |   +-- Cargo.toml
|   |   +-- src/
|   |       +-- lib.rs
|   |       +-- account.rs
|   |       +-- identity.rs
|   |       +-- profile.rs
|   |       +-- category.rs
|   |       +-- service.rs
|   |       +-- service_area.rs
|   |       +-- availability.rs
|   |       +-- conversation.rs
|   |       +-- request.rs
|   |       +-- candidate.rs
|   |       +-- connection.rs
|   |       +-- contact_reveal.rs
|   |       +-- review.rs
|   |       +-- report.rs
|   |       +-- block.rs
|   |       +-- verification.rs
|   |       +-- subscription.rs
|   |       +-- payment.rs
|   |       +-- audit.rs
|   |       +-- error.rs
|   |
|   +-- persistence/
|   |   +-- Cargo.toml
|   |   +-- src/
|   |       +-- lib.rs
|   |       +-- pool.rs
|   |       +-- transaction.rs
|   |       +-- repositories/
|   |       +-- outbox/
|   |       +-- encryption.rs
|   |       +-- health.rs
|   |
|   +-- whatsapp/
|   |   +-- Cargo.toml
|   |   +-- src/
|   |       +-- lib.rs
|   |       +-- client.rs
|   |       +-- webhook.rs
|   |       +-- signature.rs
|   |       +-- inbound.rs
|   |       +-- outbound.rs
|   |       +-- interactive.rs
|   |       +-- templates.rs
|   |       +-- flows.rs
|   |       +-- media.rs
|   |       +-- delivery_status.rs
|   |       +-- error.rs
|   |
|   +-- conversation-engine/
|   |   +-- Cargo.toml
|   |   +-- src/
|   |       +-- lib.rs
|   |       +-- state.rs
|   |       +-- transition.rs
|   |       +-- customer.rs
|   |       +-- professional.rs
|   |       +-- administrator.rs
|   |       +-- recovery.rs
|   |
|   +-- search/
|   |   +-- Cargo.toml
|   |   +-- src/
|   |       +-- lib.rs
|   |       +-- query.rs
|   |       +-- eligibility.rs
|   |       +-- ranking.rs
|   |       +-- fairness.rs
|   |       +-- pagination.rs
|   |       +-- explanation.rs
|   |
|   +-- payments/
|   |   +-- Cargo.toml
|   |   +-- src/
|   |       +-- lib.rs
|   |       +-- razorpay.rs
|   |       +-- signature.rs
|   |       +-- subscriptions.rs
|   |       +-- reconciliation.rs
|   |       +-- error.rs
|   |
|   +-- media/
|   |   +-- Cargo.toml
|   |   +-- src/
|   |       +-- lib.rs
|   |       +-- storage.rs
|   |       +-- image_policy.rs
|   |       +-- metadata.rs
|   |       +-- retention.rs
|   |
|   +-- localization/
|   |   +-- Cargo.toml
|   |   +-- src/
|   |       +-- lib.rs
|   |       +-- catalog.rs
|   |       +-- formatter.rs
|   |       +-- language.rs
|   |       +-- validation.rs
|   |
|   +-- observability/
|   |   +-- Cargo.toml
|   |   +-- src/
|   |       +-- lib.rs
|   |       +-- logging.rs
|   |       +-- metrics.rs
|   |       +-- tracing.rs
|   |       +-- redaction.rs
|   |
|   +-- configuration/
|       +-- Cargo.toml
|       +-- src/
|           +-- lib.rs
|           +-- environment.rs
|           +-- secrets.rs
|           +-- validation.rs
|
+-- migrations/
|   +-- ordered SQLx migration files
|
+-- resources/
|   +-- localization/
|   |   +-- en-IN.json
|   |   +-- hi-IN.json
|   |   +-- mr-IN.json
|   +-- taxonomy/
|   +-- templates/
|   +-- policies/
|
+-- tests/
|   +-- integration/
|   +-- contract/
|   +-- workflow/
|   +-- security/
|   +-- fixtures/
|
+-- scripts/
|   +-- development setup
|   +-- migration checks
|   +-- test orchestration
|   +-- operational maintenance
|
+-- deploy/
|   +-- local/
|   +-- staging/
|   +-- production/
|   +-- monitoring/
|
+-- .github/
    +-- workflows/
        +-- continuous integration
        +-- security audit
        +-- container build
        +-- deployment
```

Repository structure rules:

- keep business rules in domain and application crates;
- keep Axum route handlers thin;
- keep SQL inside the persistence boundary;
- keep Meta payload types inside the WhatsApp boundary;
- keep Razorpay payload types inside the payments boundary;
- do not allow external provider types to become domain models;
- avoid circular crate dependencies;
- do not create a new crate for a single helper;
- keep public APIs intentionally small;
- enforce formatting and linting in continuous integration; and
- add structure only when a real responsibility exists.

## 17. Data Domain Plan

### 17.1 Accounts

Account data must represent one human or organization identity inside Sahayak.

One account may act as:

- customer;
- professional;
- both customer and professional; or
- administrator.

Account records require:

- stable internal identifier;
- lifecycle status;
- preferred language;
- local time zone;
- creation time;
- update time;
- suspension state;
- deletion state; and
- risk state.

### 17.2 WhatsApp Accounts

WhatsApp account mappings require:

- internal account identifier;
- Meta WhatsApp user identifier;
- normalized phone lookup hash;
- encrypted phone value;
- opt-in state;
- first observed time;
- last inbound message time;
- current conversation-window expiry;
- delivery capability state; and
- block state.

### 17.3 Private Identity Assertions

Basic onboarding and publication must not require collection of a professional's legal identity. An optional identity assertion associated with an internal account may contain only:

- normalized assertion status;
- provider name;
- assertion date;
- expiration date; and
- an encrypted opaque dispute reference only when necessary.

Sahayak must not store an Aadhaar number or its last four digits, ID or card images, legal-identity source data, selfies, biometric templates or scores, provider-hosted URLs, or raw provider responses. Phone-verification and manual-approval records remain separate from optional identity assertions.

### 17.4 Public Profiles

Public profile records require:

- random public identifier;
- account identifier;
- chosen display name;
- short public description;
- profile status;
- optional private media reference;
- rating summary;
- confirmed introduction count;
- response reliability summary;
- approval status;
- creation time; and
- update time.

### 17.5 Categories

Category records require:

- stable category code;
- localized category name keys;
- optional parent category;
- activation state;
- pilot availability state;
- risk classification;
- default contact-mode options;
- provider attribute definition;
- request attribute definition;
- optional precise verification-claim definitions;
- schema version; and
- display order.

### 17.6 Provider Services

Provider service records connect a public profile to a category.

They require:

- provider profile identifier;
- category identifier;
- local, remote, or hybrid mode;
- contact mode;
- category-specific validated attributes;
- approval status;
- visibility status;
- maximum contacts per availability session;
- subscription eligibility state;
- creation time; and
- update time.

### 17.7 Service Areas

Service-area records require:

- provider service identifier;
- coverage type;
- reference location when local;
- service radius when radius-based;
- city reference when city-based;
- state reference when state-based;
- nationwide flag when permitted;
- remote flag when permitted; and
- normalized geographic identifiers.

### 17.8 Availability

Availability records require:

- professional profile identifier;
- published profile-revision identifier;
- availability start;
- availability expiry;
- one-hour, four-hour, or end-of-local-day duration code;
- time-zone snapshot and local end date where applicable;
- source of change;
- current session contact limit;
- current session contact count;
- non-resettable generation and optional scheduled successor;
- pause reason;
- manual or automatic ending reason; and
- audit timestamps.

The pilot uses one profile-wide availability quota across all approved service categories. Stopping or resuming does not reset capacity. Renewal schedules one successor period at the current period's natural expiry.

### 17.9 Conversation Sessions

Conversation sessions require:

- account identifier;
- role context;
- current workflow;
- current workflow state;
- language;
- state version;
- safe workflow data;
- expiry time;
- last inbound message identifier;
- recovery state; and
- update time.

Sensitive identity or payment data must not be copied into general conversation state.

### 17.10 Service Requests

Service requests require:

- customer identifier;
- category identifier;
- service mode;
- geographic scope;
- requested location when required;
- desired time window;
- category-specific validated attributes;
- request status;
- result-page cursor;
- expiration time;
- cancellation reason;
- creation time; and
- update time.

### 17.11 Request Candidates

Candidate records require:

- request identifier;
- provider service identifier;
- eligibility snapshot;
- ranking components;
- final rank;
- result batch;
- shown time;
- selected time;
- exclusion reason when removed; and
- deterministic matching version.

### 17.12 Connection Requests

Connection requests require:

- customer identifier;
- provider service identifier;
- originating service request;
- contact mode;
- lifecycle status;
- requested time;
- response deadline;
- accepted or declined time;
- expiration time;
- cancellation reason; and
- disclosure reference.

### 17.13 Contact Reveals

Contact-reveal records are immutable business events.

They require:

- customer identifier;
- professional identifier;
- provider service identifier;
- service request identifier;
- connection request identifier when applicable;
- disclosure reason;
- customer consent evidence;
- professional consent basis;
- delivery state;
- allowance unit consumed;
- qualified introduction state;
- reversal reference when required; and
- event time.

### 17.14 Reviews

Review records require:

- qualified introduction identifier;
- author identifier;
- subject identifier;
- rating dimensions;
- optional text;
- moderation state;
- current revision;
- creation time; and
- update time.

### 17.15 Verifications

Identity checking is optional and provider-hosted. The assertion linked to an internal account may retain only:

- normalized assertion status;
- provider name;
- assertion date;
- expiration date; and
- an encrypted opaque dispute reference only when necessary.

Only a current successful qualifying assertion may project the exact public label `Identity checked`. A refusal, abandoned attempt, failure, expiry, or lack of an assertion must not prevent a phone-verified and manually approved professional from being published or searched.

Phone verification plus manual approval must remain the non-Aadhaar publication path. If an Aadhaar-based check can produce `Identity checked`, an equivalent provider-hosted route using accepted non-Aadhaar identity evidence must offer the same label. Sahayak remains responsible for its provider's processing and for accurate claims, consent, security, retention, deletion, disputes, and incidents.

The live adapter must remain disabled until a provider is selected and its versioned session API, callback schema, signature verification, replay protection, and assertion semantics are contractually confirmed, together with all applicable UIDAI approvals, OVSE registration, AUA or Sub-AUA arrangements, and legal approval. No browser return may establish a successful assertion.

### 17.16 Reports

Report records require:

- reporter identifier;
- subject identifier;
- related introduction identifier;
- report category;
- severity;
- user-provided description;
- evidence references;
- triage state;
- assigned administrator;
- action state;
- resolution summary;
- creation time; and
- resolution time.

### 17.17 Blocks

Block records require:

- actor identifier;
- blocked account identifier;
- optional related report;
- creation time; and
- removal time when unblocked.

Blocks must affect search eligibility and connection delivery immediately.

### 17.18 Subscriptions

Subscription records require:

- professional account identifier;
- account-wide scope for the MVP;
- plan identifier;
- Razorpay subscription reference;
- lifecycle status;
- billing period start;
- billing period end;
- grace period end;
- cancellation state;
- creation time; and
- update time.

### 17.19 Payments

Payment records require:

- subscription identifier;
- Razorpay payment reference;
- amount in minor currency units;
- currency;
- tax treatment;
- payment state;
- invoice reference;
- receipt reference;
- failure reason;
- paid time; and
- reconciliation time.

Floating-point values must never represent money.

### 17.20 Webhook Events

Webhook event records require:

- provider;
- provider event identifier;
- event type;
- signature-verification state;
- minimum required payload;
- received time;
- processing state;
- attempt count;
- processed time; and
- terminal failure reason.

Identity-provider callbacks must not use generic payload retention. After signature and replay validation, Sahayak may persist only the normalized assertion fields allowed by Section 17.15; provider-hosted URLs and raw callback bodies must be discarded.

### 17.21 Outbox Jobs

Outbox jobs require:

- job type;
- aggregate reference;
- safe job payload;
- availability time;
- claim owner;
- claim expiry;
- attempt count;
- maximum attempts;
- last failure classification;
- completion time; and
- dead-letter state.

### 17.22 Audit Events

Audit events require:

- actor identifier;
- actor role;
- action type;
- target type;
- target identifier;
- reason;
- before-state digest when appropriate;
- after-state digest when appropriate;
- source channel;
- request correlation identifier; and
- event time.

## 18. State Machines

### 18.1 Professional Onboarding

```text
not_started
    |
    v
collecting_profile
    |
    v
awaiting_consent
    |
    v
submitted_for_review
    |
    +----------> changes_requested ----------+
    |                                        |
    |                                        v
    |                               collecting_profile
    |
    +----------> rejected
    |
    v
approved
    |
    v
eligible_when_available
```

### 18.2 Availability

```text
unavailable
    |
    | professional starts session
    v
available
    |
    +----------> paused_by_contact_limit
    |
    +----------> paused_by_safety_review
    |
    +----------> expired
    |
    +----------> manually_ended
                       |
                       v
                   unavailable
```

### 18.3 Service Request

```text
draft
  |
  v
collecting_requirements
  |
  v
searching
  |
  +----------> no_results
  |
  v
showing_results
  |
  +----------> searching_more
  |
  +----------> selected
  |               |
  |               v
  |          introduction_flow
  |
  +----------> cancelled
  |
  +----------> expired
```

### 18.4 Approval-Required Connection

```text
pending
  |
  +----------> declined
  |
  +----------> expired
  |
  +----------> cancelled
  |
  v
accepted
  |
  v
disclosure_pending
  |
  +----------> disclosure_failed
  |
  v
disclosed
  |
  v
feedback_eligible
```

### 18.5 Subscription

```text
not_required_during_free_value
              |
              v
payment_required
      |
      +----------> pending_payment
      |                  |
      |                  +----------> failed
      |                  |
      |                  v
      |                active
      |                  |
      |                  +----------> past_due
      |                  |
      |                  +----------> cancelled
      |                  |
      |                  +----------> expired
      |
      +----------> manually_waived
```

### 18.6 Safety Report

```text
submitted
   |
   v
triaged
   |
   +----------> low_risk_review
   |
   +----------> restricted_pending_review
   |
   +----------> suspended_pending_review
   |
   v
investigating
   |
   +----------> no_action
   |
   +----------> warning
   |
   +----------> temporary_suspension
   |
   +----------> permanent_removal
   |
   v
resolved
```

## 19. Search Eligibility And Ranking

### 19.1 Mandatory Eligibility

A provider service must be excluded unless:

- the account is active;
- the account has a phone-verified WhatsApp channel identity;
- the profile is approved;
- the provider service is approved;
- the category is active;
- availability has not expired;
- geographic scope matches;
- requested delivery mode matches;
- required category attributes match;
- the professional is not suspended;
- the professional is not under a blocking safety restriction;
- neither party has blocked the other;
- contact-session capacity remains; and
- free-value or subscription eligibility remains.

Optional identity-check status is not a publication, search-eligibility, or ranking prerequisite. Manual profile approval is the relevant approval gate.

### 19.2 Ranking Inputs

Ranking may consider:

- category relevance;
- skill relevance;
- geographic distance for local services;
- availability freshness;
- response reliability;
- rating confidence;
- confirmed introduction history;
- recent contact load;
- fair distribution; and
- language compatibility.

### 19.3 Ranking Restrictions

Ranking must not use:

- subscription price;
- payment amount;
- purchased placement;
- legal name;
- protected personal traits;
- arbitrary manual favoritism; or
- unverified claims presented as verified evidence.

### 19.4 New Professional Fairness

New approved professionals need a controlled opportunity to appear.

The system must not permanently bury profiles with no historical rating.

The system must distinguish:

- no rating yet; and
- a low rating.

Exploration must remain bounded by eligibility and safety rules.

### 19.5 Result Pagination

Return no more than three profiles in one WhatsApp batch.

Use a stable cursor for `Show more`.

Do not repeat a profile in the same service request unless the result set is intentionally reset.

Recheck eligibility before every contact disclosure because availability may change after search.

## 20. WhatsApp Conversation Design

### 20.1 Main Menu

The main menu must provide:

- find a professional;
- offer my services;
- manage availability;
- recent contacts;
- account settings;
- help and safety; and
- change language.

Options must adapt to the roles enabled on the account.

### 20.2 Input Handling

The conversation engine must support:

- text messages;
- interactive button replies;
- list replies;
- location messages;
- image uploads where requested;
- approved WhatsApp Flow responses; and
- recognized administrative commands from allowlisted accounts.

Unexpected input must not crash or silently reset the workflow.

The bot must explain what input is currently expected.

### 20.3 Session Recovery

If a conversation session expires, the bot must:

- preserve completed account data;
- discard unsafe transient data;
- explain that the previous step expired;
- return to a safe menu; and
- allow the user to restart the interrupted action.

### 20.4 Meta Conversation Window

The system must track the customer-service conversation window.

Messages outside the permitted window must use approved templates where required.

Template names and language variants must be configuration, not business logic.

Delivery failures must be recorded and retried only when retryable.

### 20.5 Message Idempotency

Every inbound Meta message ID must be processed at most once logically.

Repeated webhooks must return success without repeating business actions.

Every outbound action with financial or disclosure consequences must use an idempotency key.

## 21. Administrative Operations

MVP administrative operations must support:

- list pending professional profiles;
- inspect privacy-safe onboarding details;
- approve a profile;
- request changes;
- reject a profile with a reason;
- suspend an account;
- restore an account;
- inspect reports;
- assign report severity;
- resolve reports;
- manage category activation;
- grant a documented subscription waiver;
- inspect failed jobs;
- retry safe failed jobs;
- inspect payment reconciliation state; and
- export required audit evidence.

Administrative restrictions:

- authorize by account ID and WhatsApp allowlist;
- require step-up confirmation for destructive actions;
- never send private identity details into shared groups;
- log every administrative decision;
- require a reason for suspensions and overrides;
- prevent administrators from changing immutable contact-reveal history; and
- separate operational access from production database ownership.

## 22. Security Plan

### 22.1 Authentication And Authorization

- Treat verified Meta WhatsApp identity as the channel identity.
- Do not trust display names supplied by Meta.
- Recheck account state before sensitive actions.
- Enforce role permissions in application services.
- Protect administrator actions with an allowlist and confirmation.
- Use least-privilege database roles.
- Do not expose internal identifiers to users.

### 22.2 Data Protection

- Encrypt storage volumes and managed database storage.
- Encrypt phone values and any necessary opaque identity-dispute reference at the application boundary.
- Store a keyed lookup digest when deterministic lookup is necessary.
- Keep encryption keys outside the database.
- Rotate secrets using documented procedures.
- Redact phone numbers and tokens from logs.
- Use private object-storage buckets.
- Use short-lived signed media access where applicable.

### 22.3 Webhook Security

- Require HTTPS.
- Verify Meta request signatures.
- Verify Razorpay webhook signatures.
- Apply request-size limits.
- Apply route-specific timeouts.
- Reject unsupported content types.
- Deduplicate provider event IDs.
- Store only required payload fields.
- Return quickly after durable acceptance.

### 22.4 Abuse Controls

- Limit new contact reveals per rolling period.
- Limit search frequency separately from reveal frequency.
- Detect repeated selection of many professionals.
- Detect repeated requests that expire or are rejected.
- Detect account creation bursts.
- Respect blocks immediately.
- Pause accounts with credible severe reports.
- Allow professionals to cap contacts per session.
- Keep an absolute limit for paid users.
- Do not rely only on IP addresses because mobile networks share them.

### 22.5 Logging Safety

Logs must not contain:

- full phone numbers;
- access tokens;
- webhook secrets;
- payment secrets;
- Aadhaar numbers or their last four digits;
- ID or card images;
- legal-identity source data;
- selfies or biometric templates or scores;
- provider-hosted verification URLs;
- raw identity-provider responses;
- precise customer coordinates;
- unredacted message bodies by default; or
- signed media URLs.

Logs must contain:

- correlation identifier;
- safe account reference;
- workflow name;
- state transition;
- provider event reference;
- duration;
- result classification; and
- safe error category.

## 23. Privacy And Retention Plan

Privacy requirements:

- collect only information required for discovery and operations;
- state why each sensitive field is collected;
- record consent version and time;
- support account deletion requests;
- preserve legally required financial records separately;
- publish only approved search-safe profile fields inside Sahayak and prevent public indexing;
- disclose exact contact details only under the selected contact rule;
- do not expose exact location in search results; and
- define processor relationships with Meta, Razorpay, storage, and verification vendors.

For optional identity checking, the provider must collect identity evidence on its own hosted service. Sahayak may retain only normalized assertion status, provider, assertion date, expiry, and a necessary encrypted opaque dispute reference. Provider outsourcing does not remove Sahayak's responsibility.

Retention categories must include:

- active account data;
- inactive account data;
- conversation state;
- webhook event metadata;
- contact-reveal evidence;
- payment and tax records;
- reports and safety evidence;
- audit events;
- profile media; and
- backups.

Every category needs:

- retention purpose;
- retention duration;
- deletion trigger;
- legal hold behavior;
- backup expiration behavior; and
- responsible owner.

## 24. Billing And Razorpay Plan

The MVP business model is professional subscription revenue.

Billing rules:

- the first qualified introduction per professional account is free;
- payment is requested only after free value is consumed;
- initial plan price is INR 99 per month;
- applicable GST treatment must be confirmed with the business accountant;
- invoice and receipt requirements must be documented;
- payment does not affect ranking;
- failed payment must not delete profile data;
- past-due behavior requires a defined grace period;
- cancellation must prevent future renewal;
- refunds must follow published policy; and
- every Razorpay webhook must be idempotent.

Razorpay integration must support:

- creating or linking a customer record;
- creating the selected billing arrangement;
- generating a hosted payment action;
- processing successful payment events;
- processing failed payment events;
- processing subscription state events;
- signature verification;
- reconciliation against provider records;
- GST-aware invoice references; and
- manual exception review.

Do not use an unmaintained unofficial Rust Razorpay SDK.

Use the documented Razorpay HTTP API through the shared HTTP client boundary.

## 25. Reliability Plan

### 25.1 Delivery Guarantees

The system must provide:

- durable webhook acceptance;
- logical exactly-once handling through idempotency;
- at-least-once background job execution;
- idempotent business transitions;
- bounded retries;
- dead-letter handling;
- message delivery status tracking; and
- safe manual retry operations.

### 25.2 Database Reliability

- Use managed PostgreSQL in production.
- Enable encrypted automated backups.
- Test point-in-time recovery.
- Monitor connection-pool saturation.
- Set statement timeouts.
- Add indexes from measured query plans.
- Avoid long-running application transactions.
- Use constraints for business invariants.
- Run migrations as a controlled deployment step.
- Test backward-compatible deployment transitions.

### 25.3 Outbox Reliability

- Create jobs in the same transaction as domain changes.
- Claim jobs with bounded leases.
- Recover abandoned claims.
- Classify retryable and terminal failures.
- Use exponential backoff with jitter.
- limit maximum attempts;
- move exhausted jobs to a dead-letter state;
- alert on growing queue age; and
- retain correlation to the originating event.

## 26. Observability Plan

Required service metrics:

- inbound webhook count;
- invalid signature count;
- duplicate webhook count;
- webhook acceptance latency;
- outbox queue depth;
- oldest queued job age;
- job success rate;
- job retry rate;
- Meta API latency;
- Meta delivery failure rate;
- database query latency;
- database pool saturation;
- search result count;
- no-result rate;
- contact-reveal rate;
- approval acceptance rate;
- disclosure failure rate;
- report rate;
- payment success rate; and
- subscription conversion rate.

Required alerts:

- webhook endpoint unavailable;
- signature failures spike;
- queue age exceeds threshold;
- dead-letter count increases;
- database unavailable;
- database storage approaches threshold;
- Meta delivery failures spike;
- Razorpay webhook processing fails;
- backup fails;
- severe report misses response target; and
- contact-disclosure errors occur.

## 27. Testing Strategy

### 27.1 Domain Tests

Test:

- availability expiration;
- contact-mode rules;
- customer reveal allowance;
- provider session contact limits;
- free qualified introduction accounting;
- subscription eligibility;
- block enforcement;
- report restrictions;
- rating eligibility;
- state transition validity; and
- money calculations.

### 27.2 Integration Tests

Test against real PostgreSQL/PostGIS:

- migrations from an empty database;
- migrations from the previous production version;
- geospatial eligibility;
- concurrent allowance consumption;
- concurrent contact disclosure;
- outbox claiming;
- abandoned job recovery;
- uniqueness constraints;
- transaction rollback; and
- encrypted-field persistence.

### 27.3 Provider Contract Tests

Test:

- Meta webhook signature verification;
- inbound message parsing;
- interactive reply parsing;
- location parsing;
- outbound message formatting;
- template selection;
- Meta error classification;
- Razorpay signature verification;
- Razorpay event parsing; and
- payment reconciliation.

### 27.4 Workflow Tests

Test complete workflows:

- new customer language selection;
- existing customer language recovery;
- professional onboarding approval;
- professional changes requested;
- availability activation and expiry;
- local search with results;
- local search without results;
- direct contact disclosure;
- approval-required acceptance;
- approval-required decline;
- approval-required expiry;
- daily customer limit reached;
- provider contact limit reached;
- rating after qualified introduction;
- report and immediate block;
- free introduction exhaustion;
- payment activation; and
- subscription expiry.

### 27.5 Security Tests

Test:

- invalid Meta signature;
- invalid Razorpay signature;
- duplicate webhook delivery;
- oversized payload;
- unauthorized administrator command;
- contact disclosure after block;
- disclosure after availability expiry;
- cross-account data access;
- log redaction;
- signed media expiration;
- replayed interactive response; and
- rate-limit bypass attempts.

## 28. Environment Strategy

### 28.1 Local

Local development requires:

- pinned Rust toolchain;
- Docker and Docker Compose;
- PostgreSQL/PostGIS container;
- local environment file based on a safe example;
- mocked Meta and Razorpay services by default;
- optional secure tunnel for real webhook testing; and
- deterministic development fixtures.

### 28.2 Test

Automated tests require:

- isolated PostgreSQL/PostGIS instance;
- isolated schema or database per test group;
- no production credentials;
- deterministic clock where required;
- mocked external providers; and
- automatic cleanup.

### 28.3 Staging

Staging requires:

- separate Meta test configuration;
- Razorpay test mode;
- separate database;
- separate object-storage namespace;
- production-like deployment topology;
- synthetic accounts only unless approved; and
- restricted administrator access.

### 28.4 Production

Production requires:

- dedicated Meta business configuration;
- Razorpay live credentials;
- managed PostgreSQL/PostGIS;
- encrypted private object storage;
- secret manager;
- automated backups;
- alerts;
- audit retention;
- restricted deployment permissions; and
- documented incident ownership.

## 29. Phase 0: Product And Business Readiness

Goal: remove decisions that would otherwise block implementation or Meta approval.

Tasks:

- [ ] Select the pilot city and compact launch area.
- [ ] Confirm plumbers and electricians as the only active pilot categories.
- [x] Select Marathi (`mr-IN`) as the third pilot language.
- [ ] Define the professional approval checklist.
- [ ] Approve `Identity checked` as the exact optional verification label and its non-guarantee explanation.
- [ ] Define a viable non-Aadhaar alternative for any enabled identity-check flow.
- [ ] Confirm the vendor-specific API and callback-signature contract before enabling a live identity adapter.
- [ ] Confirm all applicable UIDAI approvals, OVSE registration, AUA or Sub-AUA arrangements, and legal approval before enabling a live identity adapter.
- [ ] Define the first-qualified-introduction-free rule in business terms.
- [ ] Confirm the INR 99 professional subscription hypothesis.
- [ ] Confirm GST invoicing requirements with the accountant.
- [ ] Define cancellation and refund policy.
- [ ] Define report severity levels.
- [ ] Define severe-report response ownership.
- [ ] Write privacy-policy content.
- [ ] Write terms-of-service content.
- [ ] Write account-deletion instructions.
- [ ] Create or confirm Meta Business Portfolio.
- [ ] Create or confirm WhatsApp Business Account.
- [ ] Create the Meta application owned by the business portfolio.
- [ ] Complete required Meta business verification.
- [ ] Reserve a dedicated WhatsApp business number.
- [ ] Create a least-privilege Meta system user and production token process.
- [ ] Define explicit WhatsApp opt-in wording and evidence.
- [ ] Inventory required WhatsApp templates.
- [ ] Prepare template translations for every pilot language.
- [ ] Confirm Razorpay live and test access.
- [ ] Configure DNS ownership for `sahayak.dagzer.com`.
- [ ] Define data-retention periods.
- [ ] Define who may access production data.
- [ ] Recruit at least ten pilot professionals before public demand testing.

Acceptance criteria:

- [ ] Pilot geography is documented.
- [ ] Pilot languages are documented.
- [ ] Legal pages have approved content.
- [ ] Meta ownership and phone-number access are available.
- [ ] Razorpay test credentials are available.
- [ ] Professional onboarding policy is approved.
- [ ] Safety escalation owner is named.

## 30. Phase 1: Repository And Toolchain Foundation

Goal: create a reproducible Rust workspace with automated quality controls.

Tasks:

- [x] Install Rust 1.98.0 through the official toolchain manager.
- [x] Pin Rust 1.98.0 in the repository.
- [x] Configure Rust edition 2024.
- [x] Initialize the Cargo workspace.
- [x] Create API and worker applications.
- [x] Create only the initial shared crates required by Phase 2.
- [x] Add formatting rules.
- [x] Add strict linting rules.
- [ ] Add dependency policy configuration.
- [ ] Add secret-scanning configuration.
- [x] Create Docker build stages.
- [x] Create local Docker Compose configuration.
- [x] Add the PostGIS 18-3.6 development image.
- [x] Pin production-intended images by digest.
- [x] Add typed environment configuration.
- [x] Add safe environment examples without secrets.
- [x] Add structured logging foundation.
- [x] Add correlation identifiers.
- [x] Add liveness endpoint.
- [x] Add readiness endpoint.
- [x] Add graceful shutdown.
- [x] Add continuous integration for format, lint, test, and build.
- [x] Add dependency vulnerability checks.
- [ ] Add license-policy checks.

Acceptance criteria:

- [x] A new developer can start the local database from documented steps.
- [x] API and worker start successfully.
- [x] Health checks report expected state.
- [ ] Continuous integration passes from a clean checkout.
- [x] No secrets exist in the repository.
- [x] Production container runs as a non-root user.

## 31. Phase 2: Database And Persistence Foundation

Goal: create the minimum durable model needed for accounts, messaging, and reliable jobs.

Tasks:

- [x] Enable required PostgreSQL extensions.
- [x] Create account lifecycle schema.
- [x] Create WhatsApp account mapping schema.
- [x] Create public profile schema.
- [x] Create private identity boundary.
- [x] Create conversation-session schema.
- [x] Create webhook-event schema.
- [x] Create outbox-job schema.
- [x] Create audit-event schema.
- [x] Create encryption-key version fields.
- [x] Add internal UUID identifiers.
- [x] Add normalized timestamp rules.
- [x] Add database constraints for lifecycle states.
- [x] Add indexes for webhook deduplication.
- [x] Add indexes for job claiming.
- [x] Add indexes for WhatsApp account lookup.
- [x] Implement transaction boundary abstraction.
- [x] Implement repository interfaces.
- [x] Implement encrypted private-field persistence.
- [x] Implement keyed phone lookup digest.
- [x] Implement migration validation in continuous integration.
- [x] Add database integration-test infrastructure.
- [x] Add backup and restore procedure draft.

Backup and restore baseline:

- use daily encrypted PostgreSQL backups stored outside the application server;
- retain seven daily backups during the pilot;
- keep database credentials and encryption keys outside backup archives;
- verify archive checksums after upload;
- restore into an isolated database, never over a running production database;
- run migrations only after the restored migration history has been inspected;
- perform and record a restore drill before public launch and monthly afterward; and
- move to managed point-in-time recovery before operating across multiple locations.

Acceptance criteria:

- [x] All migrations apply to an empty PostgreSQL 18 database.
- [x] All migrations pass in continuous integration.
- [x] Duplicate Meta event IDs are rejected safely.
- [x] Sensitive fields are unreadable without application keys.
- [x] Outbox jobs can be claimed concurrently without double completion.
- [x] A failed transaction creates neither partial domain data nor orphaned jobs.

## 32. Phase 3: WhatsApp Ingress And Outbound Messaging

Goal: reliably receive and send WhatsApp messages without implementing product workflows yet.

Tasks:

- [x] Create Meta webhook verification endpoint.
- [x] Create Meta webhook event endpoint.
- [x] Verify request signatures.
- [x] Enforce webhook body-size limits.
- [x] Parse the minimum webhook envelope.
- [x] Persist accepted webhooks durably.
- [x] Return success after durable acceptance.
- [x] Deduplicate repeated webhooks.
- [x] Implement outbox worker claiming.
- [x] Implement bounded job retries.
- [x] Implement dead-letter state.
- [x] Implement Meta outbound HTTP client.
- [x] Implement outbound text messages.
- [x] Implement outbound button messages.
- [x] Implement outbound list messages.
- [x] Implement location-message parsing.
- [x] Implement media-reference handling.
- [x] Implement delivery-status event handling.
- [x] Classify Meta errors as retryable or terminal.
- [x] Redact Meta credentials and phone values from logs.
- [x] Add mocked Meta contract tests.
- [x] Add real test-number smoke procedure.

Acceptance criteria:

- [x] Meta webhook verification succeeds.
- [x] Valid signed messages are accepted.
- [x] Invalid signatures are rejected.
- [x] Duplicate webhooks do not create duplicate work.
- [x] Inbound test messages receive an outbound test response.
- [x] Delivery status is recorded.
- [x] Retryable failures retry within bounded policy.
- [x] Terminal failures do not retry forever.

## 33. Phase 4: Conversation Engine And Localization

Goal: provide recoverable, multilingual WhatsApp workflows.

Tasks:

- [x] Define conversation workflow identifiers.
- [x] Define versioned conversation states.
- [x] Define safe state-transition rules.
- [x] Persist state after each accepted transition.
- [x] Handle stale interactive replies.
- [x] Handle unexpected input.
- [x] Add back behavior.
- [x] Add cancel behavior.
- [x] Add main-menu behavior.
- [x] Add expired-session recovery.
- [x] Add English catalog.
- [x] Add Hindi catalog.
- [x] Add pilot-state language catalog.
- [x] Validate missing translation keys in continuous integration.
- [x] Record language preference.
- [x] Add language-change flow.
- [x] Track Meta conversation-window expiry.
- [x] Add template selection by language.
- [x] Add message-length validation.
- [x] Add button and list-limit validation.
- [x] Add workflow-level correlation identifiers.

Acceptance criteria:

- [x] New users can select a language.
- [x] Returning users retain their language.
- [x] Main menu renders in all pilot languages.
- [x] Unexpected input receives a useful recovery message.
- [x] Expired sessions return safely to a known state.
- [x] Missing critical translations fail continuous integration.

## 34. Phase 5: Accounts And Professional Onboarding

Goal: onboard and administratively approve professionals entirely through WhatsApp.

Tasks:

- [x] Create accounts from verified WhatsApp channel identities.
- [x] Support customer and professional capabilities on one account.
- [x] Add public profile creation.
- [x] Add display-name rules.
- [x] Add public ID generation.
- [x] Seed only plumber and electrician categories as active pilot categories.
- [x] Add category-specific attribute definitions.
- [x] Add local service mode.
- [x] Add service-area capture.
- [x] Add radius selection.
- [x] Add professional language selection.
- [x] Add direct-contact mode selection.
- [x] Add approval-required mode selection.
- [x] Add per-session contact-limit selection.
- [x] Add optional photo upload.
- [x] Strip unnecessary photo metadata.
- [x] Store profile photos privately.
- [x] Add consent-version recording.
- [x] Keep identity checking optional and provider-hosted.
- [x] Ensure refusal, abandonment, failure, or absence of identity checking does not block approval or publication.
- [x] Keep phone verification plus manual approval as the non-Aadhaar publication path and offer an equivalent hosted non-Aadhaar credential route if Aadhaar can produce `Identity checked`.
- [x] Persist only normalized assertion status, provider, date, expiry, and a necessary encrypted opaque dispute reference.
- [x] Reject and avoid logging Aadhaar numbers or last four digits, ID or card images, legal-identity source data, selfies, biometric templates or scores, hosted URLs, and raw provider responses.
- [x] Project exactly `Identity checked` only from a current successful qualifying assertion.
- [x] Keep the live adapter disabled until the vendor-specific API and callback-signature contract and all applicable UIDAI approvals, OVSE registration, AUA or Sub-AUA arrangements, and legal approval are confirmed.
- [x] Add profile submission.
- [x] Add administrator allowlist.
- [x] Add administrator pending-profile queue.
- [x] Add approve action.
- [x] Add changes-requested action.
- [x] Add reject action.
- [x] Add administrative audit events.
- [x] Notify professionals about review outcomes.
- [x] Add profile editing for approved fields.
- [x] Require re-review for sensitive changes.

Acceptance criteria:

- [x] A professional completes onboarding without a website.
- [x] A professional can select either contact mode.
- [x] A profile cannot become searchable before phone verification and manual approval.
- [x] A phone-verified, manually approved profile can become searchable without `Identity checked`.
- [x] Only a current successful qualifying provider assertion adds exactly `Identity checked`.
- [x] Optional identity checking retains none of the prohibited identity or provider payload data.
- [x] The live identity adapter remains disabled unless its contract and applicable legal approvals are confirmed.
- [x] An administrator can approve through a restricted operation.
- [x] Every administrative decision is audited.
- [x] Search-safe data remains separated from private identity data.
- [x] Profile photos remain unavailable before permitted disclosure.

## 35. Phase 6: Availability Management

Goal: ensure search results contain only recently available professionals.

Tasks:

- [x] Add availability persistence.
- [x] Add one-hour availability option.
- [x] Add four-hour availability option.
- [x] Add end-of-day availability option.
- [x] Add unavailable action.
- [x] Reject availability for unapproved profiles.
- [x] Reject availability for suspended accounts.
- [x] Schedule expiry jobs.
- [x] Expire availability without user action.
- [x] Enforce contact-session limits.
- [x] Auto-pause visibility at the configured limit.
- [x] Notify the professional when auto-paused.
- [x] Add availability status to the professional menu.
- [x] Add safe renewal action.
- [x] Add availability audit history.
- [x] Handle race conditions between expiry and customer selection.

Acceptance criteria:

- [x] Approved professionals can become available.
- [x] Availability disappears at expiry.
- [x] Suspended professionals cannot become available.
- [x] Contact-session limits pause visibility correctly.
- [x] Provide the mandatory database-time availability and capacity recheck that search and disclosure must invoke in later phases.
- [x] Concurrent updates leave one valid current state.

## 36. Phase 7: Geospatial Search And Result Presentation

Goal: let customers find privacy-safe available plumbers and electricians nearby.

Tasks:

- [x] Create service-request schema.
- [x] Create provider-service schema.
- [x] Create service-area schema.
- [x] Add PostGIS location types.
- [x] Add spatial indexes.
- [x] Add customer category selection.
- [x] Add location-message capture.
- [x] Add requested-time selection.
- [x] Add category-specific customer questions.
- [x] Add mandatory eligibility query.
- [x] Add distance calculation.
- [x] Add language compatibility.
- [x] Add availability freshness input.
- [x] Add response reliability input.
- [x] Add fair-distribution input.
- [x] Add deterministic ranking version.
- [x] Add request-candidate records.
- [x] Add three-profile result batches.
- [x] Add stable `Show more` cursor.
- [x] Prevent duplicate results within one request.
- [x] Add no-results response.
- [x] Add safe radius-expansion option.
- [x] Add result explanations using simple labels.
- [x] Exclude profile photos from search cards.
- [x] Exclude phone numbers from search cards.
- [x] Exclude exact locations from search cards.
- [x] Test realistic spatial query plans.

Acceptance criteria:

- [x] Customer can search for a plumber or electrician.
- [x] Local search requires a usable location.
- [x] Only phone-verified, manually approved, available professionals appear; optional identity checking is not required.
- [x] Blocked pairs never appear to each other.
- [x] Result cards expose only approved public fields.
- [x] Results return in batches of at most three.
- [x] Subscription price has no ranking effect.
- [ ] Define and verify the pilot search latency target.

## 37. Phase 8: Contact Disclosure And Connection Requests

Goal: complete the core Sahayak introduction experience.

Tasks:

- [x] Create connection-request schema.
- [x] Create immutable contact-reveal schema.
- [x] Add rolling 24-hour customer allowance calculation.
- [x] Add three-reveal free limit.
- [x] Exclude previous reveals from new allowance consumption.
- [x] Recheck customer account state before disclosure.
- [x] Recheck professional account state before disclosure.
- [x] Recheck active blocks before disclosure.
- [x] Recheck availability before disclosure.
- [x] Recheck provider session capacity before disclosure.
- [x] Implement direct-contact disclosure.
- [x] Notify direct-contact professional.
- [x] Implement approval-required request.
- [x] Add accept action.
- [x] Add decline action.
- [x] Add request expiry.
- [x] Add request cancellation.
- [x] Add request-response race protection.
- [x] Add call action.
- [x] Add WhatsApp action.
- [x] Add profile-photo disclosure at the correct stage.
- [x] Add contact-delivery state.
- [x] Add qualified-introduction accounting.
- [x] Add reversal path for internal delivery failure.
- [x] Add recent-contacts menu.
- [x] Add customer-limit message.
- [x] Add professional-capacity message.
- [x] Add complete disclosure audit trail.

Acceptance criteria:

- [x] Direct-contact selection reveals details exactly once.
- [x] Approval-required selection reveals nothing before acceptance.
- [x] Declined and expired requests consume no reveal allowance.
- [x] The fourth new daily reveal is denied for a free customer.
- [x] Previously revealed contacts remain accessible.
- [x] Professional session limits are enforced.
- [x] Photo disclosure follows the selected contact mode.
- [x] Failed delivery does not consume a qualified introduction incorrectly.
- [x] Concurrent selection cannot over-consume limits.

## 38. Phase 9: Reviews, Reports, Blocks, And Moderation

Goal: establish minimum two-sided trust and incident operations.

Tasks:

- [x] Create review schema.
- [x] Restrict reviews to qualified introductions.
- [x] Add customer review request.
- [x] Add professional customer-feedback option.
- [x] Add rating dimensions.
- [x] Add optional written feedback.
- [x] Add review edit history.
- [x] Add moderation state.
- [x] Create report schema.
- [x] Add report categories.
- [x] Add severity levels.
- [x] Add customer report flow.
- [x] Add professional report flow.
- [x] Add immediate block option.
- [x] Apply blocks to discovery and connection flows.
- [x] Add severe-report automatic restriction rule.
- [x] Add administrator triage flow.
- [x] Add warning action.
- [x] Add temporary suspension action.
- [x] Add permanent removal action.
- [x] Add report resolution messages.
- [x] Add report response-time monitoring.
- [x] Add rating aggregate recalculation.
- [x] Add minimum-count treatment for ratings.

Acceptance criteria:

- [x] Unconnected users cannot review one another.
- [x] A block prevents future discovery and contact.
- [x] Severe reports trigger the configured restriction.
- [x] Administrative outcomes are audited.
- [x] Rating count and average remain consistent under edits.
- [x] Reports do not expose private reporter details to the subject.

## 39. Phase 10: Professional Subscription Billing

Goal: collect INR 99 professional subscriptions after free value is delivered.

Tasks:

- [ ] Finalize Razorpay billing model after accountant and legal approval.
- [x] Create plan configuration.
- [x] Create subscription schema.
- [x] Create payment schema.
- [x] Track one free qualified introduction per professional account.
- [x] Ensure adding a service category does not reset free value.
- [x] Transition to payment required after free value.
- [x] Generate Razorpay hosted payment action.
- [x] Add Razorpay webhook endpoint.
- [x] Verify Razorpay signatures.
- [x] Deduplicate Razorpay events.
- [x] Process successful payment.
- [x] Process failed payment.
- [x] Process cancellation.
- [x] Process expiry.
- [x] Add grace-period behavior.
- [x] Add subscription status menu.
- [x] Add payment reminder template.
- [x] Add receipt reference.
- [x] Add GST invoice reference.
- [x] Add reconciliation job.
- [x] Add manual exception review workflow.
- [x] Ensure billing never changes ranking.
- [x] Ensure failed billing never deletes profile data.

Acceptance criteria:

- [x] The first qualified introduction per professional account remains free.
- [x] Payment is requested only after free value is consumed.
- [x] Successful payment activates eligibility exactly once.
- [x] Duplicate Razorpay webhooks do not duplicate payment records.
- [x] Failed payment follows documented grace behavior.
- [x] Cancellation prevents future renewal.
- [x] Money uses exact minor units.
- [ ] Payment and GST records reconcile after accountant-approved tax configuration.

## 40. Phase 11: Production Hardening

Goal: make the system safe and observable enough for a controlled pilot.

Tasks:

- [x] Complete threat model.
- [x] Complete privacy data map.
- [x] Complete retention schedule.
- [ ] Configure production secret manager.
- [x] Configure key rotation process.
- [ ] Configure encrypted managed PostgreSQL.
- [ ] Configure automated backups.
- [x] Test database restoration.
- [ ] Configure private object storage.
- [ ] Configure TLS and DNS.
- [ ] Publish privacy, terms, contact, and deletion pages under `sahayak.dagzer.com`.
- [ ] Publish legal pages and verify deployed versions against recorded consent versions.
- [x] Configure API request limits.
- [x] Configure service timeouts.
- [x] Configure database statement timeouts.
- [x] Configure production logs.
- [x] Configure metrics.
- [x] Configure alerts.
- [x] Configure Sentry.
- [x] Add operational dashboards.
- [x] Add queue-age monitoring.
- [x] Add dead-letter monitoring.
- [x] Run load test for webhook bursts.
- [x] Run load test for local search.
- [x] Run concurrency tests for contact limits.
- [x] Run security test suite.
- [x] Run dependency audit.
- [x] Run container vulnerability scan.
- [x] Test Meta API outage behavior.
- [x] Test Razorpay outage behavior.
- [x] Write incident-response runbook.
- [x] Write rollback procedure.
- [x] Write data-breach response procedure.
- [x] Write customer-support escalation procedure.

Acceptance criteria:

- [x] Backup restoration succeeds in a non-production environment.
- [ ] Critical alerts reach the responsible operator.
- [x] No high-severity dependency findings remain unaddressed.
- [ ] No sensitive data appears in sampled logs.
- [ ] Webhook burst testing meets the agreed target.
- [x] Contact-limit concurrency tests preserve invariants.
- [x] Rollback and incident ownership are documented.

## 41. Phase 12: Controlled Pilot

Goal: validate that the service creates useful introductions in a real locality.

Tasks:

- [ ] Recruit at least twenty plumbers.
- [ ] Recruit at least twenty electricians.
- [ ] Approve profiles using the production process.
- [ ] Train professionals on availability controls.
- [ ] Verify direct-contact consent understanding.
- [ ] Verify approval-required flow understanding.
- [ ] Seed realistic service areas.
- [ ] Test all pilot languages with real users.
- [ ] Start with invitation-only customers.
- [ ] Monitor every failed search.
- [ ] Monitor every disclosure failure.
- [ ] Review every report manually.
- [ ] Interview customers after introductions.
- [ ] Interview professionals after introductions.
- [ ] Measure availability freshness.
- [ ] Measure no-result rate.
- [ ] Measure contact-reveal conversion.
- [ ] Measure approval acceptance rate.
- [ ] Measure time to accepted connection.
- [ ] Measure no-show reports.
- [ ] Measure free-to-paid professional conversion.
- [ ] Review INR 99 willingness to pay.
- [ ] Adjust result batch and radius rules from evidence.
- [ ] Keep category expansion disabled during initial measurement.

Pilot acceptance criteria:

- [ ] At least 100 valid customer requests are observed.
- [ ] At least 70 percent receive a usable introduction within ten minutes.
- [ ] Median urgent introduction time is below five minutes.
- [ ] Contact-disclosure failure rate remains below the agreed threshold.
- [ ] Severe reports receive timely operational review.
- [ ] Professionals understand and use availability correctly.
- [ ] At least 20 percent of eligible professionals demonstrate willingness to pay.
- [ ] Operating cost per qualified introduction is measured.

## 42. Phase 13: Post-Pilot Improvements

Goal: improve the proven workflow before category or geographic expansion.

Possible tasks after evidence:

- [ ] Improve onboarding drop-off points.
- [ ] Improve no-result recovery.
- [ ] Tune search radius behavior.
- [ ] Tune fairness behavior.
- [ ] Improve availability reminders.
- [ ] Add category-specific verification.
- [ ] Add voice-note intent recognition.
- [ ] Add local-language audio prompts.
- [ ] Add professional availability schedules.
- [ ] Add organization accounts.
- [ ] Add a web operations portal.
- [ ] Add customer INR 99 power-user plan only if justified.
- [ ] Add additional local categories one at a time.
- [ ] Add city and state coverage where supply exists.
- [ ] Add remote service support.
- [ ] Add teachers as the first nationwide remote category candidate.
- [ ] Add developers only after project requirement workflows are designed.
- [ ] Add real-estate agents only after regulatory and fraud controls are designed.

No post-pilot item is automatically approved by appearing in this list.

Each item needs evidence, scope, and acceptance criteria before implementation.

## 43. Future Category Admission Checklist

Before activating any new category, complete:

- [ ] Define the customer need clearly.
- [ ] Define provider eligibility.
- [ ] Define category-specific attributes.
- [ ] Define geographic behavior.
- [ ] Define remote behavior.
- [ ] Define allowed contact modes.
- [ ] Define verification claims.
- [ ] Define regulatory risk.
- [ ] Define safety risk.
- [ ] Define prohibited requests.
- [ ] Define report categories.
- [ ] Define ranking inputs.
- [ ] Translate category terminology.
- [ ] Recruit minimum viable supply.
- [ ] Test the workflow manually.
- [ ] Add category-specific integration tests.
- [ ] Obtain operational approval.

## 44. Explicitly Deferred Work

Do not build during the MVP:

- public profile website;
- customer mobile application;
- professional mobile application;
- internal customer-professional chat;
- masked calling;
- payment for professional services;
- escrow;
- commissions;
- job contracts;
- project milestones;
- service guarantees;
- live worker tracking;
- background mobile telemetry;
- Redis cluster;
- Elasticsearch;
- microservices;
- Kubernetes;
- AI ranking;
- AI-generated trust claims;
- paid ranking boosts;
- multiple subscription tiers;
- international currencies;
- international identity providers;
- public developer API;
- third-party marketplace integrations; or
- decentralized reputation technology.

## 45. Primary Risks And Mitigations

### 45.1 Supply Density

Risk: customers receive no useful results.

Mitigation:

- launch in one compact area;
- recruit before public demand;
- monitor active availability;
- show no result honestly; and
- expand geography only after density is proven.

### 45.2 Stale Availability

Risk: customers contact professionals who are no longer available.

Mitigation:

- use short availability sessions;
- expire sessions automatically;
- recheck before disclosure;
- send renewal reminders; and
- measure failed contacts.

### 45.3 Phone-Number Abuse

Risk: users collect or misuse professional numbers.

Mitigation:

- hide numbers before selection;
- limit new reveals;
- record every disclosure;
- allow approval-required mode;
- enforce blocks; and
- suspend abusive accounts.

### 45.4 Professional Overload

Risk: one professional receives too many calls.

Mitigation:

- configure session contact limits;
- distribute results fairly;
- auto-pause at capacity;
- notify before disclosure; and
- allow immediate unavailability.

### 45.5 WhatsApp Platform Dependency

Risk: policy, pricing, template, or account changes disrupt service.

Mitigation:

- comply with opt-in and template rules;
- monitor account quality;
- isolate Meta integration;
- keep canonical data in Sahayak;
- maintain exportable account records; and
- consider alternate channels only after product validation.

### 45.6 Low Willingness To Pay

Risk: professionals value introductions but reject subscriptions.

Mitigation:

- deliver free qualified introductions first;
- measure economic usefulness;
- interview professionals;
- keep pricing simple;
- avoid false lead counting; and
- stop expansion if unit economics fail.

### 45.7 Fraud And Safety

Risk: either party uses Sahayak to target or deceive the other.

Mitigation:

- verify channel ownership;
- manually approve professionals;
- use precise verification labels;
- restrict contact disclosure;
- support reports and blocks;
- quarantine severe cases; and
- maintain evidence and audit history.

### 45.8 Premature Architecture

Risk: engineering effort is spent on imagined scale rather than product value.

Mitigation:

- use a modular monolith;
- use PostgreSQL for durable state and jobs;
- avoid unused infrastructure;
- measure bottlenecks before adding systems; and
- require evidence for new services.

## 46. Pilot Metrics

Product metrics:

- valid customer requests;
- requests with at least one result;
- requests with a selected result;
- qualified introductions;
- time to direct disclosure;
- time to approval acceptance;
- no-result rate;
- request abandonment rate;
- daily reveal-limit hits;
- repeat customer rate;
- rating submission rate; and
- reported successful contact rate.

Professional metrics:

- approved professionals;
- professionals available each day;
- median availability-session length;
- contacts per availability session;
- acceptance rate;
- response time;
- contact-limit pauses;
- report rate;
- free introduction consumption; and
- free-to-paid conversion.

Operational metrics:

- profile-review time;
- report-review time;
- webhook failure rate;
- outbound delivery failure rate;
- dead-letter job count;
- support contacts;
- cost per qualified introduction;
- Meta messaging cost;
- verification cost;
- payment cost; and
- infrastructure cost.

## 47. Launch Go Or No-Go Checklist

Product readiness:

- [ ] Customer discovery workflow passes end-to-end testing.
- [ ] Professional onboarding passes end-to-end testing.
- [ ] Direct contact passes end-to-end testing.
- [ ] Approval-required contact passes end-to-end testing.
- [ ] Daily usage limits pass concurrency testing.
- [ ] Availability expiry passes testing.
- [ ] Reviews and reports pass testing.

Business readiness:

- [ ] Pilot supply is recruited.
- [ ] Professional support process exists.
- [ ] Customer support process exists.
- [ ] Subscription and GST policy is approved.
- [ ] Razorpay live configuration is verified.

Legal and privacy readiness:

- [ ] Privacy policy is published.
- [ ] Terms are published.
- [ ] Account deletion process is published.
- [ ] Consent records are versioned.
- [ ] Retention schedule is approved.
- [ ] Processor access is documented.
- [ ] Any enabled identity adapter has a confirmed vendor API and signature contract and all applicable UIDAI approvals, OVSE registration, AUA or Sub-AUA arrangements, and legal approval; otherwise it remains disabled.

Security readiness:

- [ ] Secrets are stored outside source control.
- [ ] Production database is private.
- [ ] Object storage is private.
- [ ] Backups are enabled.
- [ ] Restore was tested.
- [ ] Webhook signatures are enforced.
- [ ] Logs are sampled for sensitive data.
- [ ] Administrator allowlist is reviewed.

Operational readiness:

- [ ] Monitoring is active.
- [ ] Alerts reach a responsible person.
- [ ] Incident runbook is available.
- [ ] Severe-report owner is available.
- [ ] Deployment rollback was tested.
- [ ] Meta account quality is monitored.

Launch is blocked if any mandatory readiness item is incomplete.

## 48. Definition Of Done For Every Feature

A feature is complete only when:

- requirements are linked to product rules;
- domain behavior is explicit;
- privacy impact is reviewed;
- abuse cases are considered;
- database migration is reversible or has an approved recovery plan;
- unit tests cover business rules;
- integration tests cover persistence;
- workflow tests cover user-visible behavior;
- localization keys exist;
- logs are safe;
- metrics exist where operationally relevant;
- failure behavior is defined;
- retry behavior is defined;
- documentation is updated;
- continuous integration passes; and
- acceptance criteria are demonstrated.

## 49. Final Implementation Order

The mandatory implementation order is:

1. Product and business readiness.
2. Repository and toolchain foundation.
3. Database and persistence foundation.
4. WhatsApp ingress and outbound messaging.
5. Conversation engine and localization.
6. Accounts and professional onboarding.
7. Availability management.
8. Geospatial search and result presentation.
9. Contact disclosure and connection requests.
10. Reviews, reports, blocks, and moderation.
11. Professional subscription billing.
12. Production hardening.
13. Controlled pilot.
14. Evidence-based improvements.

Do not implement billing before qualified introduction accounting is reliable.

Do not implement search before profile approval and availability are reliable.

Do not expose contacts before disclosure consent, rate limits, and blocks are reliable.

Do not launch before reporting, suspension, monitoring, and backup restoration are operational.

## 50. First Complete Product Milestone

The first complete product milestone is:

```text
A phone-verified, manually approved plumber configures direct contact,
sets availability for one hour,
and becomes eligible in a configured local area.

A verified WhatsApp customer selects the pilot language,
chooses Plumber,
shares a location,
and receives a privacy-safe profile without a photo or phone number.

The customer selects the plumber.

Sahayak rechecks account state, availability, blocks,
daily customer allowance, and professional contact capacity.

Sahayak records an immutable contact reveal,
shares the optional photo and direct call or WhatsApp actions,
notifies the plumber,
and later requests feedback.

The flow is idempotent, localized, audited, rate-limited,
observable, and covered by automated tests.
```

Nothing is considered a working MVP until this complete path succeeds reliably in a production-like environment.
