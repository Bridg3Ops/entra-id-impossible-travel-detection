# Microsoft Entra ID — Geographical Sign-in Detection

**Focus:** Identity threat detection and investigation  
**Platform:** Microsoft Sentinel / Log Analytics · Microsoft Entra ID  
**Data source:** `SigninLogs`  
**Exercise context:** MYDFIR VPN-driven simulations

## Overview

This project documents a KQL query that identifies consecutive successful sign-ins for the same account where the source IP changes and the implied travel speed exceeds **900 km/h** over a distance of at least **200 km**.

The purpose is to give analysts a practical starting point for investigating potentially unauthorised account use. The query brings both sign-in times, source IPs and country codes into one result, alongside device and authentication context for the later event. Analysts can then reconstruct what happened and distinguish suspicious access from VPN routing, proxies or other legitimate explanations.

**A result is an investigation lead, not proof of compromise.** The exercise context is MYDFIR VPN-driven simulation: changes in VPN exit location can deliberately generate this pattern without physical travel. No production validation or measured detection effectiveness is claimed.

[Open the KQL query](geographical_signin_detection.kql)

## Detection hypothesis

If the same account successfully signs in from two geographically distant IP addresses within a short interval, the implied travel speed may be inconsistent with ordinary physical movement. This can indicate credential or session misuse, but it can also reflect the location of network infrastructure rather than the user.

The distance threshold reduces matches caused by smaller geographic shifts. The speed threshold prioritises rapid changes. These are investigation thresholds in the supplied query, not empirically established boundaries between benign and malicious activity.

## KQL query

The query below is preserved as supplied, including its two commented-out filters.

```kusto
SigninLogs
| where ResultType == "0"
| extend User = UserPrincipalName
| extend ManagedDevice = tostring(DeviceDetail.isManaged)
| extend Device = tostring(DeviceDetail.operatingSystem)
| extend Latitude = todouble(LocationDetails.geoCoordinates.latitude)
| extend Longitude = todouble(LocationDetails.geoCoordinates.longitude)
//| where isnotnull(Latitude) and isnotnull(Longitude)
| sort by User asc, TimeGenerated asc
| serialize
| extend PreviousUser = prev(User),PreviousTime = prev(TimeGenerated),PreviousIP = prev(IPAddress),PreviousLocation = prev(Location),PreviousLatitude = prev(Latitude),PreviousLongitude = prev(Longitude)
| where User == PreviousUser
//| where PreviousLocation != Location
| extend TimeDifferenceHours =todouble(datetime_diff("second", TimeGenerated, PreviousTime)) / 3600.0
| where TimeDifferenceHours > 0
| extend DistanceKm = geo_distance_2points(PreviousLongitude,PreviousLatitude,Longitude,Latitude) / 1000.0
| extend TravelSpeedKmh = DistanceKm / TimeDifferenceHours
| where PreviousIP != IPAddress
| where TravelSpeedKmh > 900
| where DistanceKm >= 200
| project TimeGenerated, User,PreviousTime, PreviousIP, IPAddress,PreviousLocation, Location,Device, ManagedDevice, AuthenticationDetails
| sort by TimeGenerated asc
```

## How the query works

| Stage | Logic | Why it matters |
| --- | --- | --- |
| Select successful events | `ResultType == "0"` | Focuses on successful sign-ins. Failed attempts remain relevant during investigation but do not form the pairs here. |
| Extract context | Copies the UPN to `User`; extracts operating system, managed-device state and numeric coordinates | Prepares the location calculation and adds context for triage. Device state is not used to suppress results. |
| Order the events | Sorts by `User`, then `TimeGenerated`; serializes the result | Makes the preceding row available for a chronological comparison. `serialize` does not itself sort data. |
| Build pairs | Uses `prev()` for the preceding account, time, IP, country and coordinates | Compares adjacent successful sign-ins in the selected data, rather than every possible pair. |
| Keep the same account | `User == PreviousUser` | Removes the cross-account pair created at each account boundary. |
| Calculate elapsed time | Converts the second-based difference between timestamps into hours; requires a positive value | Excludes zero/negative intervals and avoids division by zero. |
| Calculate distance and speed | Converts geospatial distance from metres to kilometres; divides by elapsed hours | Produces an implied speed between the two IP-derived locations. |
| Apply thresholds | Different source IP, speed **>900 km/h**, distance **≥200 km** | Returns only pairs satisfying all three conditions. Exactly 900 km/h is excluded; exactly 200 km is included if the other conditions pass. |
| Present results | Projects the investigation fields and sorts oldest first | Supports chronological review of the candidate pairs. |

The country-change filter is commented out, so **same-country pairs can match**. This matters in geographically large countries. The explicit coordinate filter is also commented out: invalid or missing coordinates normally yield a null distance and do not pass the numeric thresholds. They are a coverage gap, not a benign finding.

### Illustrative calculation

Two successful sign-ins appear 600 km apart, 20 minutes apart, with different IP addresses:

`600 km ÷ (20 / 60 hours) = 1,800 km/h`

This satisfies both thresholds. It illustrates the calculation only; it is not an observed MYDFIR result or evidence of physical travel.

## Running the query and reading its output

Use a workspace where Entra sign-in events are available in `SigninLogs`. Select the investigation time range explicitly in the query interface before running it. The supplied query contains **no explicit time filter**, so the interface's time scope matters. Both events must fall inside the queried data; a preceding event outside that scope cannot be paired.

| Output | Analyst interpretation |
| --- | --- |
| `TimeGenerated`, `PreviousTime` | Later and earlier event times used in the comparison |
| `User` | Account whose adjacent successful sign-ins matched |
| `PreviousIP`, `IPAddress` | Earlier and later source addresses; investigate both |
| `PreviousLocation`, `Location` | Earlier and later country codes from `Location`, not precise physical positions |
| `Device` | Operating system reported for the later sign-in; not a unique device identifier |
| `ManagedDevice` | Managed-device value converted to text for the later sign-in; blank does not establish that a device is unmanaged |
| `AuthenticationDetails` | Authentication-step details for the later sign-in; compare with the earlier event before concluding how authentication occurred |

The final projection omits the calculated distance and speed. For investigation, replace that projection in a **working copy** with the following to make the threshold decision reviewable:

```kusto
| project TimeGenerated, User, PreviousTime, PreviousIP, IPAddress,
    PreviousLocation, Location, TimeDifferenceHours, DistanceKm, TravelSpeedKmh,
    PreviousLatitude, PreviousLongitude, Latitude, Longitude,
    Device, ManagedDevice, AuthenticationDetails
```

Keep the final `sort by TimeGenerated asc`. This is an optional display change; the downloadable query remains unchanged.

## Analyst investigation workflow

### 1. Confirm the triggering pair

Record the query version, UTC search window and the two source events in the case record. Confirm that both events belong to the same account, succeeded, and contain plausible coordinates. Recalculate the interval, distance and speed. Check for duplicated rows or concurrent sign-ins before treating the pair as a meaningful sequence.

Expand the investigation beyond successful events. Failed attempts before or around the pair may add context that the detection deliberately excludes.

### 2. Reconstruct the sign-in timeline

Use this supporting query with a case-specific UTC interval and account value. The values below are synthetic placeholders; replace them locally and keep real identifiers out of the public repository.

```kusto
let StartTime = datetime(2026-01-01T00:00:00Z);
let EndTime = datetime(2026-01-01T04:00:00Z);
let Account = "analyst@example.invalid";
SigninLogs
| where TimeGenerated >= StartTime and TimeGenerated < EndTime
| where UserPrincipalName =~ Account
| project TimeGenerated, CreatedDateTime, ResultType, ResultDescription,
    IPAddress, Location, LocationDetails, AppDisplayName, ResourceDisplayName,
    IsInteractive, DeviceDetail, ClientAppUsed, UserAgent,
    AuthenticationDetails, ConditionalAccessStatus,
    RiskLevelDuringSignIn, CorrelationId
| sort by TimeGenerated asc
```

Review the earlier and later event together: device identifiers, operating system/browser, application, client, authentication steps, Conditional Access and available risk signals. A successful result or managed-device flag alone does not establish legitimacy. An MFA requirement alone does not establish that a fresh challenge was completed; inspect the authentication-step results and session context.

### 3. Investigate the network and user context

Determine whether each IP belongs to an approved corporate gateway, VPN provider, mobile carrier, hosting service or residential network. Check geolocation consistency and approved routing information. Use reputation findings as supporting evidence: a clean reputation is not proof of benign activity, and a shared VPN exit is not automatically malicious.

Confirm the user's activity through an established contact method. Ask about approved VPN use, travel, devices and application access. For MYDFIR testing, compare the pair against the authorised exercise timeline and VPN exit changes. Label that finding **authorised simulation**, not a real compromise.

### 4. Look for corroborating activity

Review related identity alerts and, where available, endpoint and application audit records around the same interval. Investigate unfamiliar sessions, new authentication methods, privilege changes, suspicious consent grants, mailbox changes or unusual resource access as appropriate to the account.

Use additional telemetry to determine outcome: sign-in success alone does not demonstrate what data was accessed, whether persistence was established or whether information was exfiltrated. State any unavailable logs or retention gaps.

### 5. Document the decision and response

| Disposition | Supporting basis | Next step |
| --- | --- | --- |
| Authorised simulation | Test timing and known VPN changes explain the pair | Record the simulated activity and the actual query result. |
| Explained benign activity | User/device/network evidence coherently explains the change | Document the explanation; consider narrowly scoped tuning if the pattern recurs. |
| Suspicious / inconclusive | Activity remains unexplained or evidence is incomplete | Escalate for further identity and endpoint investigation. |
| Corroborated compromise | Additional evidence supports unauthorised account use | Follow the incident process for session revocation, credential reset, access restriction and wider scoping. |

Separate observed facts, interpretation and remaining uncertainty. A useful closure note answers **who, what, when, where and how**, then records the evidence supporting the disposition. Do not automatically block an account solely because this geographic threshold was met.

## False positives and limitations

- **VPNs, proxies and mobile routing:** source-IP geography can change while the user stays in one place. MYDFIR VPN simulations intentionally exercise this ambiguity.
- **Geolocation quality:** coordinates can be approximate, stale, invalid or missing. The calculation measures IP-derived locations, not a device's verified position.
- **Adjacent pairs only:** `prev()` compares each event with the preceding successful event for that account. Intervening events can change the pair and conceal other suspicious combinations.
- **Missing coordinates affect pairing:** with the coordinate filter disabled, an unusable row can sit between two usable events. Enabling it before sorting skips such rows and changes which events are paired; test this deliberately.
- **Time precision and ties:** the calculation uses second-based differences. Same-time or zero-second pairs are excluded, and tied timestamps have no additional ordering key. Very small intervals can produce extreme speeds.
- **Account identity:** the query uses the UPN as supplied and does not exclude blank UPNs. Review missing identities and consider a validated stable identifier when adapting it for operational use.
- **Table scope:** there is no explicit `IsInteractive` filter. The query processes successful rows available in `SigninLogs`; it does not union separate non-interactive, service-principal or managed-identity tables.
- **Device context:** only the later event's OS and managed state are projected. Compare the complete earlier event before claiming device continuity or change.
- **Query scope and scale:** the chosen time range affects pairing and cost. Sorting and serializing large datasets should be assessed in the target workspace.

## Tuning and operational use

Retain 900 km/h and 200 km as the supplied starting thresholds. Assess labelled benign and simulated cases before changing them. Raising thresholds can reduce noise and also miss suspicious activity. Requiring different countries would remove same-country candidates.

For recurring VPN noise, document the account, approved egress, reason, owner and expiry for any proposed exception. Avoid broad user, country or VPN-provider exclusions without reviewing the resulting coverage loss.

This repository provides the query and analyst guidance, not a deployed analytics rule. Before scheduling it, define a bounded lookback that includes the predecessor event, review ingestion delay, map account/IP entities, and decide how to manage repeated pairs across overlapping runs. Validate these behaviours and establish an analyst response route before enabling alerts. The standalone query does not deduplicate alerts or automate containment.

## Evidence and validation status

The supplied query is preserved in [geographical_signin_detection.kql](geographical_signin_detection.kql). This write-up explains its logic and an investigation method. No raw tenant data, screenshots, measured performance or production outcomes are published here, and the query was not executed against a tenant during this repository update.

For a reproducible MYDFIR case, retain a sanitised before/after sign-in pair, query version, UTC window, VPN simulation timeline, calculated distance/speed, expected versus actual result and analyst disposition. Useful controls include a same-IP pair, a below-threshold pair, a different-user boundary and a missing-coordinate case. Publish only results that were actually observed.

Remove tenant and user identifiers, source IPs, device/session IDs and sensitive URLs from any public evidence. Keep original records privately and label illustrative values separately from observed results.

## References

- [Microsoft: SigninLogs schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [Microsoft: prev()](https://learn.microsoft.com/en-us/kusto/query/prev-function)
- [Microsoft: serialize operator](https://learn.microsoft.com/en-us/kusto/query/serialize-operator)
- [Microsoft: datetime_diff()](https://learn.microsoft.com/en-us/kusto/query/datetime-diff-function)
- [Microsoft: geo_distance_2points()](https://learn.microsoft.com/en-us/kusto/query/geo-distance-2points-function)

## Repository contents

```text
README.md                             Query explanation and analyst investigation guide
geographical_signin_detection.kql     Original supplied detection query
```
