# Professional Subscription Billing

## Product Contract

- Scope: one entitlement per professional account, never per service category.
- Free value: the first delivered qualified introduction is free.
- Paid plan: INR 99 monthly, represented as exactly `9900` paise.
- Provider: Razorpay Subscriptions using the hosted `short_url` authorization flow.
- Term: 120 monthly cycles for the initial provider arrangement.
- Ranking: subscription state is an eligibility gate only and is never a ranking input.
- Failure: `pending` starts a three-day grace period; `halted` expires eligibility without deleting profile data.
- Cancellation: cancellation prevents reactivation by stale later events; end-of-cycle cancellation remains eligible through the paid period.
- Authority: only a verified webhook or server-to-server reconciliation may activate entitlement.

## Idempotency And Reconciliation

Webhook signatures are HMAC-SHA256 over the exact raw request bytes using the dedicated webhook secret. `x-razorpay-event-id`, payment IDs, invoice IDs, and subscription IDs are independently unique. Duplicate events return success without repeating mutations. Ambiguous subscription creation must be reconciled before retry because the provider does not document an idempotency key for subscription creation.

Reconciliation compares the stored subscription with `GET /v1/subscriptions/{id}` and its invoices. Amount, currency, plan, payment, invoice, and billing period must match. Differences create a manual exception and never silently grant eligibility.

## Accounting Decisions

The schema records provider invoice, receipt, payment, order, exact amount, currency, and tax treatment. GST inclusion, GST registration, SAC/HSN, place of supply, invoice numbering, refunds, and proration remain subject to accountant and legal approval. Live billing must remain disabled until those decisions and Razorpay live-account capabilities are confirmed.
