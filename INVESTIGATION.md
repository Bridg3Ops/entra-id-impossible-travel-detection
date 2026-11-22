# Investigation playbook

**Draft workflow. MYDFIR VPN-driven simulation context; no production validation.**

## 1. Establish what actually triggered

Record the rule version, UTC alert time, query window and account in a restricted case record. Re-run the same logic with fixed start/end times for reproducibility. Obtain the underlying sign-in rows; aggregation hides event order, authentication details and individual source-to-country relationships.

Confirm that each contributing event is successful and interactive. Check timestamps, country resolution and whether duplicate rows or repeated sessions inflate event volume. The threshold is distinct countries, not the number of sign-in rows.

## 2. Reconstruct the timeline

In Entra sign-in logs, review each event's time, source IP and ASN, application/resource, device details, client, authentication steps, Conditional Access status, and available risk signals. Record unavailable telemetry explicitly. `AuthenticationRequirement` alone does not establish that a fresh MFA challenge was completed; inspect Authentication Details and token/session context.

Use the following investigation query with a restricted account value and an explicit UTC interval. Do not commit filled values or exported results to this repository.

```kusto
let InvestigationStart = datetime(2026-01-01T00:00:00Z); // Replace locally.
let InvestigationEnd = datetime(2026-01-01T02:00:00Z);   // Exclusive end.
let InvestigatedAccount = "analyst@example.invalid";    // Synthetic placeholder.
SigninLogs
| where TimeGenerated >= InvestigationStart and TimeGenerated < InvestigationEnd
| where UserPrincipalName =~ InvestigatedAccount
| project TimeGenerated, CreatedDateTime, ResultType, ResultDescription,
    IsInteractive, Location, IPAddress, AppDisplayName, ResourceDisplayName,
    DeviceDetail, ClientAppUsed, AuthenticationDetails, ConditionalAccessStatus,
    RiskLevelDuringSignIn, CorrelationId
| order by TimeGenerated asc
```

## 3. Test competing explanations

| Explanation | Evidence to seek | What remains unproven |
| --- | --- | --- |
| Authorised VPN simulation | Exercise plan, consent, UTC timings and known exit locations in a restricted record | That the rule reliably detects all intended cases |
| Corporate routing | Approved egress ownership, proxy/VPN logs and device/session consistency | That all activity from a trusted exit is benign |
| Legitimate user activity | User confirmation through an established channel, travel context and device continuity | That successful MFA alone excludes token theft |
| Credential/session misuse | Unrecognised device/session, suspicious authentication, related identity or endpoint alerts and downstream audit activity | Compromise until corroborated |

For MYDFIR exercises, label VPN-generated geographic changes as **simulated activity**. Do not describe them as real intrusions, physical travel or evidence of production efficacy. IP reputation is supporting context; a clean result is not a benign verdict.

## 4. Decide and respond

Classify as authorised simulation, explained benign activity, suspicious/inconclusive or corroborated compromise. State observed facts, supporting evidence, alternative explanations and remaining gaps separately.

Escalate according to the organisation's incident process when there is credible corroboration. Session revocation, credential reset, account restrictions and endpoint containment require appropriate incident authority and impact assessment. This playbook does not authorise automatic blocking solely on country diversity.

## 5. Close with an audit trail

Record the disposition, analyst rationale, evidence references, response actions and follow-up owner. Propose narrowly scoped tuning only after preserving the triggering case. Publish only a fully sanitised narrative; retain source logs and identifier mappings privately.
