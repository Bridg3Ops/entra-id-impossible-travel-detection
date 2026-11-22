# Tuning, deployment and hypercare

**Proposed operational guidance, not an account of production deployment.**

## Rule configuration proposal

| Setting | Starting proposal | Validation required |
| --- | --- | --- |
| Rule type | Microsoft Sentinel scheduled analytics | Confirm workspace connector and table support |
| Frequency / lookback | 15 minutes / 1 hour | Match the KQL `Lookback`; measure ingestion lag |
| Trigger | Result count > 0 | One returned row represents one account |
| Event grouping | Alert for each result | Verify platform limits and high-volume behaviour |
| Severity | Medium, provisional | Tune to local risk and triage capacity |
| Entity mapping | Account Name=`AccountName`, UPNSuffix=`UPNSuffix` | Test guest and unusual UPN formats |
| Incident grouping | Consider same-rule, same-account grouping over 1 hour | Verify actual incident behaviour; grouping is not alert deduplication |
| Automated response | None | Separate approval and design needed for response |

Start disabled or in a controlled lab. Configure and test before enabling. This project does not contain an importable rule template and does not create a rule in a live tenant.

## Time windows and duplicates

The rolling one-hour window evaluated every 15 minutes deliberately overlaps. The same account may recur while qualifying events remain in scope. Keep incident grouping separate from deduplication: grouped incidents can still contain repeated alerts. Avoid broad rule suppression that hides new affected accounts. If adding per-account state or ingestion-time gating, document the design and test event ordering, late arrival and scheduler gaps first.

Microsoft documents a scheduling delay for scheduled analytics; this is not a guarantee that every late event will be covered. Measure source-to-ingestion latency in the actual workspace. Events older than the one-hour event-time window can be missed even if ingested recently. Adjust both the rule lookback and query consistently, and re-test duplicates and coverage.

## Tuning decisions

- `MinimumCountries=2` and `Lookback=1h` are reconstruction assumptions. Compare alternative values with labelled positive and negative cases before changing them.
- Exclusions default to empty. `ExcludedUsers` expects lowercase full UPNs; `ExcludedIPs` supports exact addresses only. Keep real configurations in restricted deployment storage.
- Avoid blanket country allowlists: attacker activity can originate in commonly used countries.
- A known VPN is context, not automatic proof of legitimacy. Prefer exceptions scoped by account, egress, purpose and expiry in a separately reviewed implementation.
- Every exception needs an owner, reason, evidence reference, review date and rollback condition. Re-test a malicious-like case that could be hidden by it.
- Track missing countries/accounts, failed sign-ins and non-interactive telemetry independently; this query intentionally does not cover them.

## Hypercare plan

Proposed initial period: 14 days after an authorised pilot starts. This is a planning interval, not a completed observation period.

| Cadence | Review | Record |
| --- | --- | --- |
| Each day | Rule execution, connector health, latency, alert volume and triage backlog | Failures, lag distribution, unique accounts, repeated alerts, analyst workload |
| Each reviewed case | Benign/simulation/suspicious disposition and evidence quality | Explanation, investigation time, tuning candidate |
| After each change | Re-run positive, negative, missing-data and late-arrival cases | Version, expected/actual results, reviewer |
| End of pilot | Coverage, noise, operational ownership and unresolved gaps | Accept, extend pilot, revise or roll back |

Do not calculate precision from unreviewed alerts. Label the sample size and selection method for any future metric. Missed-detection estimates require a known labelled test set; alert counts alone cannot establish recall.

## Acceptance and rollback

Before broader use, require recorded query execution, the planned test matrix, privacy review, an agreed noise budget, a named operational owner, a response route and an approved exception process. Define numerical thresholds locally before the pilot; this repository supplies no measured thresholds.

If query failures, unacceptable volume, data gaps or unexplained misses occur, pause the pilot rule through the normal change process, retain evidence, restore the last reviewed version and rerun tests. Record any temporary coverage gap and compensating monitoring. Keep other identity detections active.

## Sources

[Scheduled analytics](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview) · [Ingestion delay](https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay)
