# Controlled Pilot SLOs

These provisional targets are release gates for production-like staging. Business owners must approve them before pilot traffic.

| Signal | Target | Alert |
|---|---|---|
| Signed webhook durable acceptance | 99.9% over 30 days | 5-minute error ratio above 1% |
| Webhook acceptance latency | p95 below 500 ms | p95 above 1 second for 10 minutes |
| Oldest actionable outbox job | below 120 seconds | above 120 seconds for 5 minutes |
| Local search latency | p95 below 750 ms at pilot fixture size | p95 above 1 second |
| Contact disclosure invariant failures | zero | any occurrence |
| Critical report acknowledgement | below 1 hour | any overdue report |
| High report acknowledgement | below 4 hours | any overdue report |
| Backup success | daily | no successful backup in 26 hours |
| Restore drill freshness | within 30 days | no successful drill in 30 days |

Metrics must use bounded labels only. Account IDs, phone numbers, provider IDs, report IDs, exact locations, request IDs, and correlation IDs are prohibited as metric labels.
