# Pilot Operations Runbook

## Ownership

- Incident commander: designated on-call operator.
- Safety lead: designated trust-and-safety operator.
- Privacy lead: designated data-protection contact.
- Billing lead: designated finance operator.

Names, paging destinations, and provider account IDs belong in the secret manager or incident system, not this repository.

## Deployment And Rollback

1. Build, audit, scan, and identify images by digest.
2. Verify a recent successful backup and available capacity.
3. Run the migrator with a dedicated migration role.
4. Deploy API and worker with read-only filesystems, no added capabilities, and runtime-only database roles.
5. Verify liveness, readiness, signed synthetic webhooks, queue age, and error rates before shifting traffic.
6. Roll back binaries only while schema compatibility is confirmed. Database rollback uses a reviewed forward fix or isolated restore; never run destructive down migrations on production.

## Incident Response

1. Acknowledge and assign severity without copying sensitive payloads into chat or tickets.
2. Contain by disabling affected integration credentials, restricting accounts, or draining traffic.
3. Preserve audit IDs, event IDs, timestamps, image digests, and approved evidence references.
4. Eradicate the cause, rotate affected secrets, and verify replay boundaries.
5. Restore service using readiness and synthetic transactions.
6. Record impact, timeline, decisions, notifications, and corrective actions.

## Data Breach

Immediately restrict access, preserve evidence, identify affected data classes from the privacy map, rotate credentials, notify the privacy lead, assess processor and statutory notification duties, document recipients and deadlines, and verify deletion/containment. Never include plaintext private data in general incident channels.

## Safety Escalation

Critical reports require acknowledgement within one hour and immediate temporary restriction. High reports require acknowledgement within four hours and discovery restriction. Medium reports require acknowledgement within 24 hours; low reports within 72 hours. Permanent removal requires administrator confirmation and retained audit evidence. Subject notifications must not identify the reporter.

## Billing Exceptions

Do not grant entitlement from a browser return. Reconcile subscription, invoice, payment, amount, and currency with Razorpay. Duplicate webhook IDs are acknowledged without repeating mutations. Ambiguous subscription creation is reconciled before retry. GST treatment, refunds, and invoice numbering require finance approval.

## Backup Restore Drill

Restore into an isolated network and database. Verify archive checksum, PostgreSQL/PostGIS versions, migration checksums, critical row counts and constraints, key availability, API readiness, and representative encrypted-data and disclosure workflows. Record backup identifier, operator, start/end time, achieved RPO/RTO, failures, and corrective actions.

## Encryption-Key Rotation

1. Generate the new key in the secret manager and add its metadata as active only after readers can load both versions.
2. Deploy readers with the old decrypt-only key and new key, then switch the database active version.
3. Re-encrypt bounded batches and verify the key-version inventory reaches zero for the old version.
4. Keep the old key decrypt-only through the longest backup retention window.
5. Mark it retired, perform a restore drill, and destroy it only with security approval and immutable evidence.
6. Roll back by restoring the prior active metadata while both key versions remain available; never destroy a key during an incident.

## Support Escalation

Support uses opaque public tokens and bounded audit queries. Access to report evidence, contact data, billing records, or dead letters requires least privilege, a case identifier, a reason code, and an immutable audit event. Ambiguous contact-bearing sends are never blindly replayed.
