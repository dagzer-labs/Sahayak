# Sahayak Pilot Launch Checklist

Last updated: 2026-09-01

This is the operational checklist for completing Meta WhatsApp, Razorpay, Azure, Cloudflare, tax, security, and application deployment. Check an item only after saving the listed evidence.

## Credential Safety Rules

- [ ] Never paste API keys, access tokens, app secrets, webhook secrets, private SSH keys, database passwords, or encryption keys into chat, issues, commits, screenshots, or general notes.
- [ ] Enter secrets only through a private terminal prompt or provider dashboard.
- [ ] Store local temporary secrets under `/tmp/kilo/` with permission `600`.
- [ ] Store production secrets as root-readable files under `/run/secrets/` on the VM.
- [ ] Keep only public IDs, public SSH keys, resource names, and non-secret configuration in Terraform variables.
- [ ] Rotate any credential immediately if it is accidentally exposed.

## Current Status

- [x] Azure subscription selected: `Test NVIDIA`.
- [x] Azure tenant and subscription access verified.
- [x] Azure Central India supports `Standard_B2ats_v2` for this subscription.
- [x] Cloudflare API token verified as active.
- [x] Cloudflare Dagzer Account ID and `dagzer.com` Zone ID discovered.
- [x] Terraform `1.16.0`, AzureRM `4.81.0`, and Cloudflare `5.24.0` validated.
- [x] Terraform plan generated: 14 additions, 0 changes, 0 deletions.
- [x] Cloudflare expected pilot cost: $0 within free allowances.
- [x] Azure expected fixed retail cost: approximately $11.51/month before Indian GST.
- [ ] Terraform plan approved and applied.
- [ ] Application deployed and production smoke-tested.

## Phase 1: Purchase And Prepare The WhatsApp Number

### Recommended Number

- [ ] Purchase one dedicated Indian `+91` mobile SIM or eSIM from Airtel, Jio, Vi, or BSNL.
- [ ] Prefer a business-owned postpaid number for continuity, invoice history, OTP reliability, and recovery.
- [ ] Ensure the number can receive SMS and voice OTP calls.
- [ ] Keep the number active with a long-validity recharge or postpaid plan.
- [ ] Do not use Deepak's personal WhatsApp number.
- [ ] Do not buy a temporary, shared, rented, disposable, or unsupported virtual/VoIP number.
- [ ] Do not register the number in the consumer WhatsApp or WhatsApp Business mobile app before Cloud API onboarding.
- [ ] If the number was previously used with WhatsApp, complete Meta's migration/coexistence procedure or remove the prior registration before onboarding.
- [ ] Store the SIM, carrier account, PUK, recovery email, and two-step verification PIN under company control.

Only the SIM/eSIM and normal carrier service must be purchased. Meta Cloud API does not require buying a server or a number from a BSP/reseller.

Official references:

- Meta Cloud API overview: https://developers.facebook.com/docs/whatsapp/cloud-api/
- Meta get-started guide: https://developers.facebook.com/docs/whatsapp/cloud-api/get-started
- Add a phone number: https://developers.facebook.com/docs/whatsapp/cloud-api/get-started/add-a-phone-number
- WhatsApp Business Platform pricing: https://developers.facebook.com/docs/whatsapp/pricing/

### Number Evidence

- [ ] Production phone number recorded privately: `________________`.
- [ ] Carrier recorded: `________________`.
- [ ] SIM owner/account holder matches Dagzer/Deepak Basantia.
- [ ] SMS OTP tested.
- [ ] Voice OTP tested.
- [ ] Recovery process documented.

## Phase 2: Meta Business Portfolio

Open Meta Business Settings: https://business.facebook.com/settings/

- [ ] Create or select the Dagzer Business Portfolio.
- [ ] Set legal name exactly to `DEEPAK BASANTIA`.
- [ ] Set trade/business name to `DAGZER`.
- [ ] Set the registered business address from the GST registration.
- [ ] Add a business email using the Dagzer domain.
- [ ] Add the production support phone number.
- [ ] Enable two-factor authentication for every administrator.
- [ ] Keep at least two recovery-capable administrators if another trusted operator becomes available.
- [ ] Open **Security Center** and complete business verification when Meta offers or requires it.
- [ ] Upload only documents requested by Meta; use GST registration details exactly as issued.
- [ ] Confirm Business Portfolio status is active and unrestricted.

Evidence to retain privately:

- [ ] Business Portfolio ID: `________________`.
- [ ] Verification status screenshot/reference.
- [ ] Administrator access review date.

## Phase 3: Meta Developer App And WhatsApp Product

Open Meta for Developers: https://developers.facebook.com/apps/

- [ ] Create a Meta app with app type **Business**.
- [ ] App display name: `Sahayak`.
- [ ] Connect the app to the Dagzer Business Portfolio.
- [ ] Add the **WhatsApp** product.
- [ ] Open **WhatsApp → API Setup**.
- [ ] Record the Meta App ID.
- [ ] Open **App Settings → Basic** and reveal the App Secret only in a private terminal/session.
- [ ] Configure the privacy-policy URL after legal pages are deployed.
- [ ] Configure the terms URL after legal pages are deployed.
- [ ] Configure the data-deletion URL after legal pages are deployed.
- [ ] Set the application domain to `dagzer.com`.
- [ ] Move the app to Live mode only after webhook and policy checks pass.

Identifiers and secret destinations:

| Value | Where to find it | Production destination |
|---|---|---|
| Meta App ID | App Dashboard → App Settings → Basic | Non-secret deployment setting |
| Meta App Secret | App Dashboard → App Settings → Basic → Show | `/run/secrets/meta_app_secret_current` |
| Graph API version | Application configuration | `v26.0` |

Official references:

- App dashboard: https://developers.facebook.com/apps/
- Cloud API: https://developers.facebook.com/docs/whatsapp/cloud-api/
- Access tokens: https://developers.facebook.com/docs/facebook-login/guides/access-tokens/

## Phase 4: WhatsApp Business Account And Production Number

Open WhatsApp Manager: https://business.facebook.com/wa/manage/home/

- [ ] Create or select the production WhatsApp Business Account (WABA).
- [ ] Add the dedicated production number.
- [ ] Choose SMS or voice verification.
- [ ] Enter the OTP.
- [ ] Configure and securely retain the six-digit WhatsApp two-step verification PIN.
- [ ] Submit the display name.
- [ ] Recommended display name: `Sahayak by Dagzer`.
- [ ] Ensure the Dagzer website visibly connects the names Dagzer and Sahayak before display-name review.
- [ ] Wait until the display name is approved.
- [ ] Confirm phone status is connected.
- [ ] Confirm quality rating is not restricted.
- [ ] Record the WABA ID.
- [ ] Record the Phone Number ID. This is not the visible `+91` number.

Required non-secret identifiers:

| Value | Location |
|---|---|
| WhatsApp Business Account ID | WhatsApp Manager or API Setup |
| Phone Number ID | App Dashboard → WhatsApp → API Setup |
| Visible business number | WhatsApp Manager → Phone numbers |

## Phase 5: Permanent System User Access Token

Do not use the temporary API Setup token in production; it expires.

Open: https://business.facebook.com/settings/system-users

- [ ] Open **Users → System Users**.
- [ ] Create system user `sahayak-production` with Admin role.
- [ ] Assign the Meta app to the system user with required control.
- [ ] Assign the WABA to the system user.
- [ ] Assign the production phone-number asset where shown.
- [ ] Select **Generate New Token**.
- [ ] Select the Sahayak Meta app.
- [ ] Select the longest permitted expiration, preferably **Never** for a system-user token where Meta permits it.
- [ ] Grant `whatsapp_business_messaging`.
- [ ] Grant `whatsapp_business_management`.
- [ ] Do not grant unrelated permissions.
- [ ] Copy the token once into `/run/secrets/meta_access_token` through the private deployment process.
- [ ] Record token creation date and next review date without recording the token itself.
- [ ] Test the token with `GET /{PHONE_NUMBER_ID}` before deployment.

Official references:

- Business settings: https://business.facebook.com/settings/system-users
- WhatsApp permissions: https://developers.facebook.com/docs/permissions#whatsapp
- Cloud API authentication: https://developers.facebook.com/docs/whatsapp/cloud-api/get-started#authentication

## Phase 6: WhatsApp Message Templates

Open: **WhatsApp Manager → Account tools → Message templates**.

Official template documentation: https://developers.facebook.com/docs/whatsapp/business-management-api/message-templates/

Create both templates in English India, Hindi, and Marathi. Template names must exactly match application configuration.

### Re-entry Template

- [ ] Template name: `sahayak_reentry`.
- [ ] Category: Utility, if Meta accepts the transactional wording; otherwise use Meta's assigned category.
- [ ] No variables/components are currently required by the application.
- [ ] English India (`en_IN`) approved.
- [ ] Hindi (`hi`) approved.
- [ ] Marathi (`mr`) approved.

Recommended transactional text:

English:

```text
You have an unfinished account action in Sahayak. Open WhatsApp and send Menu to continue. Ignore this message if you no longer want to continue.
```

Hindi:

```text
Sahayak में आपकी एक खाता प्रक्रिया अधूरी है। जारी रखने के लिए WhatsApp खोलकर Menu भेजें। यदि आप जारी नहीं रखना चाहते तो इस संदेश को अनदेखा करें।
```

Marathi:

```text
Sahayak मध्ये तुमची एक खाते प्रक्रिया अपूर्ण आहे. पुढे जाण्यासाठी WhatsApp उघडून Menu पाठवा. पुढे जायचे नसल्यास हा संदेश दुर्लक्षित करा.
```

### Payment Reminder Template

- [ ] Template name: `sahayak_payment_reminder`.
- [ ] Category: Utility.
- [ ] No variables/components are currently required by the application.
- [ ] English India (`en_IN`) approved.
- [ ] Hindi (`hi`) approved.
- [ ] Marathi (`mr`) approved.

Recommended transactional text:

English:

```text
Your Sahayak professional subscription needs attention. Open Sahayak in WhatsApp and choose Account to review payment status. Payment never changes search ranking.
```

Hindi:

```text
आपकी Sahayak पेशेवर सदस्यता पर ध्यान देना आवश्यक है। भुगतान स्थिति देखने के लिए WhatsApp में Sahayak खोलें और Account चुनें। भुगतान से खोज रैंकिंग नहीं बदलती।
```

Marathi:

```text
तुमच्या Sahayak व्यावसायिक सदस्यतेकडे लक्ष देणे आवश्यक आहे. देयक स्थिती पाहण्यासाठी WhatsApp मध्ये Sahayak उघडा आणि Account निवडा. देयकामुळे शोध क्रमवारी बदलत नाही.
```

Template evidence:

- [ ] Template names copied exactly.
- [ ] Every language status is Approved.
- [ ] Category and final approved wording recorded.
- [ ] Rejected templates corrected without renaming application settings unexpectedly.

## Phase 7: Meta Webhook

Official webhook documentation: https://developers.facebook.com/docs/whatsapp/cloud-api/webhooks/

Complete after infrastructure and API deployment.

- [ ] Public callback URL responds: `https://sahayak.dagzer.com/webhooks/whatsapp`.
- [ ] Generate a random webhook verify token; do not reuse any Meta secret.
- [ ] Store it in `/run/secrets/meta_verify_token`.
- [ ] Configure Callback URL in **App Dashboard → WhatsApp → Configuration**.
- [ ] Enter the same private verify token.
- [ ] Complete GET verification.
- [ ] Subscribe the WABA to the `messages` webhook field.
- [ ] Confirm inbound messages arrive.
- [ ] Confirm sent, delivered, read, and failed status events arrive.
- [ ] Confirm invalid signatures return HTTP 401.
- [ ] Confirm duplicate events are acknowledged without duplicate processing.

Production configuration mapping:

| Setting | Source |
|---|---|
| `SAHAYAK__WHATSAPP__WABA_ID` | WABA ID |
| `SAHAYAK__WHATSAPP__PHONE_NUMBER_ID` | Phone Number ID |
| `SAHAYAK__WHATSAPP__APP_SECRET_CURRENT_FILE` | Meta App Secret file |
| `SAHAYAK__WHATSAPP__VERIFY_TOKEN_FILE` | Generated verify-token file |
| `SAHAYAK__WHATSAPP__ACCESS_TOKEN_FILE` | System User token file |
| `SAHAYAK__WHATSAPP__GRAPH_API_VERSION` | `v26.0` |

## Phase 8: Razorpay Subscription Setup

Dashboard: https://dashboard.razorpay.com/

Subscriptions documentation: https://razorpay.com/docs/payments/subscriptions/

- [ ] Complete Razorpay account activation and KYC.
- [ ] Confirm Subscriptions is enabled in test mode.
- [ ] Confirm Subscriptions is enabled in live mode.
- [ ] Create monthly plan `Sahayak Professional Monthly`.
- [ ] Amount: `9900` paise.
- [ ] Currency: `INR`.
- [ ] Period: Monthly.
- [ ] Interval: `1`.
- [ ] Record test Plan ID.
- [ ] Record live Plan ID.
- [ ] Generate test API Key ID and Secret.
- [ ] Generate live API Key ID and Secret only before production activation.
- [ ] Store Key Secret in `/run/secrets/razorpay_key_secret`.
- [ ] Keep Key ID as a non-secret deployment setting.
- [ ] Create a unique webhook secret.
- [ ] Store it in `/run/secrets/razorpay_webhook_secret_current`.
- [ ] Webhook URL: `https://sahayak.dagzer.com/webhooks/razorpay`.

Enable these events:

- [ ] `subscription.authenticated`
- [ ] `subscription.activated`
- [ ] `subscription.charged`
- [ ] `subscription.pending`
- [ ] `subscription.halted`
- [ ] `subscription.cancelled`
- [ ] `subscription.completed`
- [ ] `invoice.paid`
- [ ] `payment.failed`

Complete test-mode verification before live mode:

- [ ] Hosted subscription link generated.
- [ ] Successful payment activates eligibility once.
- [ ] Duplicate webhook does not create duplicate payment.
- [ ] Failed payment starts the three-day grace period.
- [ ] Cancellation prevents later stale events from restoring access.
- [ ] Receipt and invoice references are retained.

## Phase 9: GST And Invoice Configuration

Confirmed business information:

- [x] Legal name: `DEEPAK BASANTIA`.
- [x] Trade name: `DAGZER`.
- [x] Constitution: Proprietorship.
- [x] Taxpayer type: Regular.
- [x] GST status: Active.
- [x] State: Chhattisgarh, code `22`.
- [x] Registration date: 24 April 2026.
- [x] Principal place of business supplied.
- [x] Price: ₹99 monthly, GST-inclusive.
- [x] GST rate assumption: 18%.
- [x] Provisional SAC: `998599`.
- [x] Cancellation: effective at billing-cycle end.
- [x] No ordinary prorated refunds.
- [x] Refund duplicate, failed-activation, incorrect, and legally required charges.
- [x] Invoice prefix: `DAGZER/SK/26-27/`.
- [x] Invoice sequence resets each financial year.
- [ ] Confirm SAC `998599` against the exact service description before issuing the first live GST invoice.
- [ ] Collect subscriber legal name and billing state.
- [ ] Collect optional subscriber GSTIN for B2B invoices.
- [ ] Validate GSTIN format and checksum when supplied.
- [ ] Use CGST 9% + SGST 9% for qualifying intra-state supply.
- [ ] Use IGST 18% for qualifying inter-state supply.
- [ ] Verify place-of-supply rules before first live invoice.

Do not store the GSTIN or registered address in source-controlled application configuration. Supply them through restricted production billing configuration.

## Phase 10: Azure And Cloudflare Infrastructure

Terraform directory: `deploy/terraform/pilot/`

- [x] Azure login completed.
- [x] Subscription selected: `Test NVIDIA`.
- [x] Azure subscription state verified as Enabled.
- [x] Central India `Standard_B2ats_v2` availability verified.
- [x] SSH key generated.
- [x] Cloudflare API token verified.
- [x] Cloudflare Account ID discovered.
- [x] Cloudflare Zone ID discovered.
- [x] Terraform providers initialized and pinned.
- [x] Terraform configuration validated.
- [x] Terraform plan created: 14 additions, 0 changes, 0 deletions.
- [x] Azure retail estimate corrected to `$11.51/month` before tax.
- [x] Cloudflare expected pilot cost is $0 within free allowances.
- [ ] Review and approve `pilot.tfplan`.
- [ ] Apply `pilot.tfplan`.
- [ ] Confirm Azure budget notifications.
- [ ] Confirm Cloudflare Tunnel is Healthy.
- [ ] Confirm `sahayak.dagzer.com` resolves through the Tunnel.
- [ ] Confirm R2 lifecycle rules.

## Phase 11: R2 Application Credentials

Terraform creates the bucket but not long-lived application access keys.

Open: **Cloudflare Dashboard → R2 Object Storage → Manage R2 API Tokens**.

- [ ] Create token `sahayak-pilot-r2`.
- [ ] Permission: Object Read & Write.
- [ ] Restrict to bucket `sahayak-pilot-private` only.
- [ ] Do not enable unrelated account permissions.
- [ ] Store Access Key ID privately.
- [ ] Store Secret Access Key privately.
- [ ] Record S3 endpoint: `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`.
- [ ] Configure encrypted daily backup prefix: `backups/daily/`.
- [ ] Configure encrypted weekly backup prefix: `backups/weekly/`.
- [ ] Test upload, checksum, download, restore, and deletion lifecycle.

## Phase 12: Remaining Business Contacts

- [ ] Support/billing email selected: `________________`.
- [ ] Privacy/grievance email selected: `________________`.
- [ ] Customer-support WhatsApp number selected: `________________`.
- [x] Azure budget alert email: `dbasantia55@gmail.com`.
- [ ] Sentry project created or Sentry explicitly disabled for pilot.
- [ ] Sentry DSN stored in `/run/secrets/sentry_dsn` if enabled.

## Phase 13: Secrets Generated During Deployment

The deployment process generates these values. Do not manually invent weak values.

- [ ] PostgreSQL application password.
- [ ] PostgreSQL migration-role password if separate role is enabled.
- [ ] Meta webhook verify token.
- [ ] Contact-encryption keyring.
- [ ] Identity-encryption keyring.
- [ ] Integration-payload encryption keyring.
- [ ] Media-encryption keyring.
- [ ] Lookup HMAC keyring.
- [ ] Backup encryption password/key.
- [ ] Sentry DSN file if enabled.

Required secret paths:

| Secret | Path |
|---|---|
| Meta app secret | `/run/secrets/meta_app_secret_current` |
| Meta verify token | `/run/secrets/meta_verify_token` |
| Meta access token | `/run/secrets/meta_access_token` |
| Sahayak cryptographic keyring | `/run/secrets/sahayak_crypto_keyring` |
| Razorpay key secret | `/run/secrets/razorpay_key_secret` |
| Razorpay webhook secret | `/run/secrets/razorpay_webhook_secret_current` |
| Sentry DSN | `/run/secrets/sentry_dsn` |

## Phase 14: Application Deployment

- [ ] Build final API, worker, and migrator images.
- [ ] Run formatting and strict Clippy checks.
- [ ] Run complete workspace tests against clean PostgreSQL 18/PostGIS 3.6.
- [ ] Run dependency audit.
- [ ] Scan images for high/critical vulnerabilities.
- [ ] Push images by immutable digest.
- [ ] Upload production environment files through an encrypted/private channel.
- [ ] Upload secret files with mode `600`.
- [ ] Start PostgreSQL and verify disk space.
- [ ] Run migrator once.
- [ ] Start API and worker.
- [ ] Verify `/health/live`.
- [ ] Verify `/health/ready`.
- [ ] Verify `/metrics` is reachable only through approved monitoring access.
- [ ] Verify Cloudflare Tunnel health.
- [ ] Verify no application/database ports are publicly reachable from the VM.
- [ ] Configure Meta callback and complete webhook verification.
- [ ] Configure Razorpay webhook.
- [ ] Run a real test WhatsApp conversation.
- [ ] Run direct-contact and approval-required introductions.
- [ ] Run test-mode Razorpay subscription lifecycle.
- [ ] Verify payment reminder template delivery.
- [ ] Verify report/review/block workflows.
- [ ] Verify administrator report resolution notifications.

## Phase 15: Backup And Recovery Gate

- [ ] Run encrypted database backup.
- [ ] Upload backup and checksum to R2.
- [ ] Restore into an isolated database.
- [ ] Verify all migration checksums.
- [ ] Verify encrypted records decrypt with restored keys.
- [ ] Verify account, disclosure, review, safety, and billing invariants.
- [ ] Record measured restore time.
- [ ] Confirm daily backups expire after 8 days.
- [ ] Confirm weekly backups expire after 36 days.

## Phase 16: Launch Gate

Do not enable live customer traffic until every item below is complete.

- [ ] Meta production number connected and display name approved.
- [ ] Permanent System User token installed.
- [ ] All required templates approved in all three languages.
- [ ] Meta webhook verified and signed events tested.
- [ ] Razorpay live account and subscription plan active.
- [ ] Razorpay webhook verified in live mode.
- [ ] GST invoice fields and place-of-supply behavior confirmed.
- [ ] Privacy, terms, contact, and deletion pages publicly reachable.
- [ ] Production backup and restore test passed.
- [ ] Budget alerts delivered.
- [ ] Critical safety alert delivered to the responsible operator.
- [ ] No high/critical dependency or image findings remain.
- [ ] Logs sampled with no phone, message, location, token, or secret leakage.
- [ ] Rollback procedure exercised.

## Quick Links

- Meta Business Settings: https://business.facebook.com/settings/
- WhatsApp Manager: https://business.facebook.com/wa/manage/home/
- Meta Developer Apps: https://developers.facebook.com/apps/
- WhatsApp Cloud API: https://developers.facebook.com/docs/whatsapp/cloud-api/
- WhatsApp webhooks: https://developers.facebook.com/docs/whatsapp/cloud-api/webhooks/
- WhatsApp templates: https://developers.facebook.com/docs/whatsapp/business-management-api/message-templates/
- Razorpay Dashboard: https://dashboard.razorpay.com/
- Razorpay Subscriptions: https://razorpay.com/docs/payments/subscriptions/
- Azure Portal: https://portal.azure.com/
- Cloudflare Dashboard: https://dash.cloudflare.com/
- Cloudflare API tokens: https://dash.cloudflare.com/profile/api-tokens
- Cloudflare Tunnel Terraform guide: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/deployment-guides/terraform/
- Cloudflare R2 pricing: https://developers.cloudflare.com/r2/pricing/
- Sentry: https://sentry.io/
