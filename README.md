# Entra ID geographical sign-in detection

A detection engineering case study for investigating successful interactive sign-ins from multiple countries using Microsoft Entra ID telemetry and Microsoft Sentinel.

**Status: reconstructed draft · MYDFIR VPN-driven simulation context · no production validation.**

[View the project page](https://bridg3ops.github.io/entra-id-geographical-signin-detection/) · [KQL](geographical_signin_detection.kql) · [Investigation playbook](INVESTIGATION.md) · [Tuning and hypercare](OPERATIONS.md) · [Evidence register](EVIDENCE.md)

## Provenance and scope

This publication follows the project brief from the “Review KQL Query” discussion. The original HTML and KQL downloads were unavailable during publication; this implementation is a **new reconstruction**, not a recovered copy of the original query. The one-hour window and two-country threshold are explicit design assumptions. They are not represented as previously agreed or empirically tuned values.

MYDFIR VPN-driven simulations are the stated exercise context. VPN exit locations can produce geographically diverse sign-ins without physical travel or account compromise. No raw exercise logs, verified test outcomes, detection rate, false-positive rate, deployment outcomes or production impact are supplied here. MYDFIR is identified as the simulation context, not an endorsement or affiliation.

## Threat hypothesis

An account used successfully from two or more countries within one hour may warrant investigation for credential or session misuse. Benign explanations include VPN routing, corporate proxies, mobile networks and legitimate travel. Country diversity alone cannot distinguish these explanations.

## Detection logic

1. Read `SigninLogs` for the rolling preceding hour.
2. Retain successful (`ResultType == "0"`) interactive sign-ins.
3. Require an account and resolved country; normalise account case and country codes.
4. Apply optional exact account/IP exclusions; defaults exclude nothing.
5. Aggregate by account and return accounts with at least two distinct countries.

This is a geographic-diversity detector, **not an impossible-travel calculation**. It does not calculate distance, velocity or a learned user baseline. The country count is based on `make_set` (bounded at 256), rather than an approximate distinct-count threshold. Event counts are raw rows, not deduplicated authentication sessions.

## Start in an isolated lab

Confirm that the Sentinel workspace receives `SigninLogs`, that the listed columns exist and that retention covers the window. Run the KQL manually first. Use [the test matrix](VALIDATION.md) and retain sanitised evidence before enabling a scheduled rule. The query has not been executed against a workspace as part of this publication.

Proposed scheduled analytics settings: every 15 minutes, look back 1 hour, alert when result count is greater than 0, provisional Medium severity. Return one alert per result/account and map Account using Name=`AccountName`, UPNSuffix=`UPNSuffix`. These settings require validation in the target workspace. Do not treat the IP array as a single IP entity. See [operations](OPERATIONS.md) for overlap, ingestion delay and incident grouping decisions. This repository does not deploy a rule or automate response.

## Coverage limits

- Failed, non-interactive, service-principal and managed-identity sign-ins are outside this query's scope.
- Unresolved countries and blank accounts are excluded and need a separate data-quality review.
- Same-country compromise, historical activity outside the window, and sufficiently late telemetry can be missed.
- VPN/proxy geolocation is not the user's physical location. A successful sign-in is not proof of subsequent resource access or malicious activity.
- Sliding windows overlap. Repeated alerts and account correlation must be tested and managed operationally.

## Project contents

| File | Purpose |
| --- | --- |
| `index.html`, `styles.css` | Accessible static project page for GitHub Pages |
| `geographical_signin_detection.kql` | Editable, parameterised detection draft |
| `INVESTIGATION.md` | Evidence-led triage and escalation workflow |
| `OPERATIONS.md` | Rule configuration, tuning, hypercare and rollback |
| `VALIDATION.md` | Planned test cases and acceptance gates |
| `EVIDENCE.md` | Evidence placeholders and sanitisation requirements |
| `CHANGELOG.md` | Publication history and provenance |

## References

- [Microsoft: SigninLogs schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [Microsoft: scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview)
- [Microsoft: create scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)
- [Microsoft: handling ingestion delay](https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay)

## Evidence and attribution

The version history records this project's publication and subsequent changes. Preserve original source provenance and attribute borrowed logic when replacing the reconstruction. No claim of independently established authorship, production adoption, organisational benefit or national impact is made. A future professional evidence portfolio can link corroborated outcomes through the evidence register; this repository does not establish immigration eligibility.
