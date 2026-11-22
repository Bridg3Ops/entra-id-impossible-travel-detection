# Microsoft Entra ID — Impossible Travel Detection

**Focus:** Identity threat detection and investigation  
**Platform:** Microsoft Sentinel / Log Analytics · Microsoft Entra ID  
**Data source:** `SigninLogs`

## Overview

This detection identifies consecutive successful sign-ins for the same account where the source IP changes and the implied travel speed exceeds **900 km/h** over a distance of at least **200 km**. It provides both events, calculated distance and speed, and authentication and device context so analysts can assess the activity and investigate possible account compromise.

“Impossible travel” describes an implausible change between IP-derived locations. It does not establish the user's physical location. VPNs, proxies and mobile-network routing can produce the same signal as unauthorised account use, so each result requires investigation.

[Open the detection query](impossible_travel.kql)

## Detection logic

| Stage | Implementation | Operational purpose |
| --- | --- | --- |
| Bound the search | Read the last 24 hours; compare pairs no more than 12 hours apart | Supplies predecessor context while limiting scan size. These are configurable starting settings. |
| Select events | Successful sign-ins; interactive only by default | Focuses on user-driven authentication. Set `InteractiveOnly=false` to include other successful rows available in this table; separate tables are not added. |
| Validate data | Require directory, account and sign-in IDs, source IP, ingestion time and valid coordinate ranges | Avoids pairing unidentified accounts or calculating from unusable coordinates. Monitor excluded telemetry separately. |
| Deduplicate | Keep the latest ingested record per directory, account and sign-in ID | Prevents duplicate source records forming artificial pairs in the evaluated data. |
| Order and pair | Sort by directory, account object ID, event time and sign-in ID; use `prev()` | Compares consecutive qualifying events within the same directory/account. The sign-in ID provides deterministic ordering for tied times. |
| Select fresh pairs | At least one event was ingested during the last 15 minutes | Retains older context while allowing a late-arriving predecessor or successor to produce a result. |
| Calculate speed | Shortest geospatial distance in kilometres divided by elapsed hours | Uses sign-in initiation time (`CreatedDateTime`), falling back to `TimeGenerated`; direct timespan arithmetic retains sub-second precision. |
| Apply thresholds | Different IP, distance ≥200 km, speed >900 km/h, positive interval | Preserves the original distance and speed thresholds. Same-country pairs remain eligible. |
| Return evidence | Both sign-in IDs, both device/authentication records, distance, speed and `PairId` | Supports reproducible triage and downstream handling of repeated pairs. |

The query compares adjacent **qualifying** events, not all possible combinations. Filtering missing coordinates or non-interactive events changes which events become neighbours. Equal event times are excluded because a travel speed cannot be calculated from a zero interval.

### Example calculation

If two sign-ins are 600 km apart and 20 minutes apart:

`600 ÷ (20 / 60) = 1,800 km/h`

With different IP addresses, that pair meets both thresholds. This is an illustrative calculation, not a measured deployment outcome.

## Query parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `RuleFrequency` | `15m` | Fresh ingestion window; match the scheduled rule interval. |
| `HistoryWindow` | `24h` | Bounds both the event-time context and `TimeGenerated` scan. |
| `MaxPairGap` | `12h` | Maximum elapsed time between compared events. |
| `MinimumDistanceKm` | `200.0` | Inclusive minimum separation. |
| `MinimumSpeedKmh` | `900.0` | Exclusive minimum implied speed. |
| `InteractiveOnly` | `true` | Limits the source rows to interactive sign-ins by default. |

Keep the history window large enough for the maximum pair gap, measured ingestion latency and rule interval. The defaults provide headroom but do not guarantee coverage for every delay. No tenant-specific allowlists or identifiers are embedded in the query.

## Reading the results

- **`User`, `DirectoryId`, `AccountObjectId`:** UPN and stable identity scope for the comparison. `User` contains the UPN, not a person's display name.
- **`EventTime`, `PreviousTime`:** times used for travel calculations. `TimeGenerated` remains the later event's source timestamp for Sentinel.
- **`DistanceKm`, `TimeDifferenceHours`, `TravelSpeedKmh`:** the values that explain why the pair matched.
- **`PreviousIP`, `IPAddress`, `PreviousLocation`, `Location`:** both source addresses and country codes. Coordinates are returned separately.
- **`PreviousDeviceDetail`, `DeviceDetail`:** complete device context for each event. The convenience `Device` fields contain OS names, not unique device identifiers.
- **`PreviousAuthenticationDetails`, `AuthenticationDetails`:** both events' authentication-step details; inspect the actual step results.
- **`PreviousSignInId`, `SignInId`, `PairId`:** event references and a stable identifier for this ordered pair. The hash is for correlation, not anonymisation.
- **`PreviousIngestedAt`, `IngestedAt`:** explain freshness and help identify delayed ingestion.

A blank managed-device value means the field was unavailable; it does not prove an unmanaged device. A managed device, successful MFA or low risk score alone does not prove legitimate access.

## Analyst investigation workflow

### 1. Validate the triggering pair

Record the query version, UTC search window, pair ID and underlying events. Check the account object IDs, success status, source addresses, coordinate plausibility and calculation. Review duplicate or concurrent sign-ins and establish whether one event arrived late.

The detection filters out failures. Retrieve failed and successful attempts around the pair to understand the broader authentication sequence.

### 2. Reconstruct the timeline

Use the account object ID and directory ID from the result with a case-specific UTC interval. Replace the empty identifiers locally; do not commit populated values or query exports to this public repository.

```kusto
let StartTime = datetime(2026-01-01T00:00:00Z); // Replace locally.
let EndTime = datetime(2026-01-01T04:00:00Z);   // Exclusive end.
let Directory = "";                          // AADTenantId from result.
let AccountId = "";                          // AccountObjectId from result.
SigninLogs
| where isnotempty(Directory) and isnotempty(AccountId)
| where TimeGenerated >= StartTime and TimeGenerated < EndTime
| where AADTenantId == Directory and UserId == AccountId
| project TimeGenerated, CreatedDateTime, Id, UserPrincipalName,
    ResultType, ResultDescription, IPAddress, Location, LocationDetails,
    AppDisplayName, ResourceDisplayName, IsInteractive, DeviceDetail,
    ClientAppUsed, UserAgent, AuthenticationDetails, ConditionalAccessStatus,
    RiskLevelDuringSignIn, CorrelationId
| order by CreatedDateTime asc, TimeGenerated asc
```

Compare device identifiers, browser/OS, client, application, authentication methods, Conditional Access and available risk signals across both events. Distinguish a newly completed MFA challenge from authentication satisfied by an existing claim. Note missing telemetry explicitly.

### 3. Establish network and user context

Determine whether the addresses belong to corporate egress, VPN infrastructure, mobile carriers, hosting providers or residential networks. Compare approved routing records and location information. Reputation results provide context; a clean reputation is not a benign verdict.

Confirm the user's activity through an established contact method. Check expected travel, approved VPN use, devices and applications. Assess whether the network, device and session evidence coherently explains the apparent movement.

### 4. Seek corroboration and assess impact

Review related identity alerts and available endpoint/application audit records. Look for unrecognised sessions, changes to authentication methods, privilege changes, suspicious consent grants, mailbox changes or unusual resource access relevant to the account.

Sign-in success alone does not establish downstream data access, persistence or exfiltration. Use the appropriate audit sources to determine those outcomes and document retention or visibility gaps.

### 5. Decide and respond

| Disposition | Evidence basis | Action |
| --- | --- | --- |
| Explained benign activity | Verified user, device and routing context explains the pair | Document the rationale; consider a narrowly scoped exception if warranted. |
| Suspicious / inconclusive | Unexplained activity or incomplete evidence | Escalate and expand identity, endpoint and application investigation. |
| Corroborated compromise | Additional evidence supports unauthorised account use | Follow the incident process for session revocation, credential reset, access restrictions and wider scoping. |

Keep observed facts, interpretations and uncertainty separate. Record who, what, when, where and how, along with the evidence supporting the disposition. Do not automatically disable accounts solely on this geographic signal.

## Microsoft Sentinel deployment

The query includes operational controls for scheduled evaluation. **Tenant execution and alert-delivery validation remain required before enablement.** No production performance or coverage results are asserted in this repository.

| Rule setting | Starting configuration |
| --- | --- |
| Type | Scheduled analytics rule |
| Run every | 15 minutes, matching `RuleFrequency` |
| Lookup data | 24 hours, matching `HistoryWindow` |
| Trigger | Number of results greater than 0 |
| Severity | Medium initially; adjust to the account and corroborating context |
| Event grouping | Alert per result, subject to Sentinel's result/alert limits |
| Account entity | `AadTenantId` → `DirectoryId`; `AadUserId` → `AccountObjectId` |
| IP entities | Two IP mappings: Address → `PreviousIP`, Address → `IPAddress` |
| Custom details | `PairId`, both sign-in IDs, distance, speed, interval and applications |
| Incident grouping | Consider same-rule and same-account grouping; validate the actual grouping behaviour |
| Automated containment | None by default |

Account entity identifiers must refer to the Entra directory; `AADTenantId` is used rather than assuming the workspace `TenantId` is the directory ID.

### Freshness and repeated pairs

Freshness is applied **after** pairing. Applying a 15-minute filter before `prev()` would discard older predecessor events. Both ingestion timestamps are considered so an older event arriving after its successor can still produce a pair.

This is a stateless query. Reingestion, retries, schedule overlap or a changed event sequence can emit repeated or revised pairs. `PairId` supports downstream idempotency, but does not suppress duplicates by itself. Incident grouping is not alert deduplication. Missed runs longer than the freshness window need a controlled backfill; widen the freshness period in a separate recovery run and reconcile pair IDs against already processed alerts.

### Enablement checks

1. Confirm `SigninLogs` collection, required columns, non-null `ingestion_time()` and appropriate retention. Measure missing identities, coordinates and ingestion timestamps rather than treating absent results as healthy coverage.
2. Execute the query in the target workspace, inspect both source events and measure runtime/resource use at representative volume. Large sorts and serialization need particular attention.
3. Validate above/below-threshold cases, exact boundaries, same IP, different accounts/directories, missing/invalid coordinates, duplicate event IDs, equal timestamps and late arrival on either side. Check sign-in IDs and entity mappings in generated alerts.
4. Observe alert volume, repeated pairs and analyst dispositions over an agreed pilot period. Agree a noise budget, ownership and escalation route before broader enablement.
5. Monitor rule failures, source freshness and ingestion delay. Keep a reviewed rollback version and record any coverage gap during changes.

For a historical replay, fix `EvaluationTime` to the intended run time and ensure the query interface covers the corresponding history window. To investigate old pairs independently of their ingestion time, remove the freshness stage in a separate working copy. Do not silently deploy that historical variant as the scheduled rule.

## Tuning and coverage limits

- **IP geolocation is approximate.** VPNs, proxies, carrier routing and stale location data can create benign matches. Latitude/longitude validity does not establish accuracy; `(0,0)` can be a source placeholder and needs data-quality review.
- **Interactive scope is intentional.** Separate non-interactive and workload identity tables are not queried. Turning off `InteractiveOnly` only changes the filter within `SigninLogs`.
- **Adjacent-pair coverage is limited.** Intervening valid events may hide other suspicious combinations. Same-IP activity, missing identifiers/coordinates, zero-time pairs and activity beyond the configured windows do not qualify.
- **Late data has bounds.** Records outside either 24-hour bound are omitted. A late arrival can also change which events are neighbours; the query does not retract earlier alerts.
- **Thresholds are configurable.** Raising them can reduce noise and miss relevant activity. Requiring different countries would exclude same-country impossible-travel candidates.
- **Exceptions need ownership.** Review account/egress-specific evidence, expiry and coverage loss. Avoid blanket country, VPN-provider or managed-device exclusions.
- **This is custom logic.** It is not the Microsoft Entra ID Protection impossible-travel risk algorithm and does not reproduce its baselines or suppression mechanisms.

## Evidence and maintenance

Retain dated query versions, a sanitised event pair, the UTC interval, calculated distance/speed, expected versus actual behaviour and analyst disposition for reviewed cases. Link any future performance claims to a defined observation period, reviewed sample and supporting records.

Keep tenant/user identifiers, source addresses, device/session IDs and sensitive URLs out of public evidence. Store original records privately. Public screenshots should be irreversibly redacted and clearly distinguish illustrative values from observed results.

## References

- [Microsoft: SigninLogs schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [Microsoft: geo_distance_2points()](https://learn.microsoft.com/en-us/kusto/query/geo-distance-2points-function)
- [Microsoft: prev()](https://learn.microsoft.com/en-us/kusto/query/prev-function)
- [Microsoft: serialize operator](https://learn.microsoft.com/en-us/kusto/query/serialize-operator)
- [Microsoft: ingestion delay in scheduled analytics](https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay)
- [Microsoft: scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview)

## Repository contents

```text
README.md                  Detection explanation, investigation and deployment guide
impossible_travel.kql       Configurable impossible-travel detection query
```
