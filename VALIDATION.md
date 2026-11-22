# Validation plan

**All cases below are planned and NOT RUN for this reconstructed query.** Publication checks are not detection validation. No live tenant query execution, lab rerun or production validation occurred during publication.

Use authorised test accounts and a documented MYDFIR exercise scope. Record UTC start/end times, query version, parameters, source event availability and the result. VPN exits change apparent source geography; they do not demonstrate physical travel or compromise.

| ID | Controlled case | Expected behaviour | Actual / evidence |
| --- | --- | --- | --- |
| T01 | Same account, successful interactive events from two resolved countries within 1h | One account row, country count >=2 | NOT RUN |
| T02 | Same account, repeated successful interactive events from one country | No row | NOT RUN |
| T03 | Different accounts, each with only one country | No row | NOT RUN |
| T04 | Second-country event fails authentication | No row if no other qualifying second country | NOT RUN |
| T05 | Second-country event is non-interactive | No row if no other qualifying second country | NOT RUN |
| T06 | Country or account missing | That row excluded; data-quality gap documented | NOT RUN |
| T07 | Two qualifying countries separated beyond 1h | No row unless another qualifying pair exists | NOT RUN |
| T08 | Qualifying pair spans a clock-hour boundary but lies inside rolling hour | Account row returned | NOT RUN |
| T09 | Exact excluded account or IP contributes to threshold | Exclusion applied; verify resulting country set | NOT RUN |
| T10 | Event arrives late, inside/outside event-time lookback | Detect only if required rows remain in queried window | NOT RUN |
| T11 | Repeat scheduled evaluations with unchanged qualifying events | Repeated rows possible; measure grouping behaviour | NOT RUN |
| T12 | Case variants of the same UPN | Combined under normalised account | NOT RUN |

## Method

First test query syntax/schema in the intended workspace. For deterministic replay, replace `ago(Lookback)` with explicit UTC start/end bounds in a versioned test copy. Keep the original deployed query and test variant separately identified. Verify results against individual source events rather than screenshots alone. Synthetic datatable fixtures may test logic but cannot validate ingestion, entity mapping or alert delivery.

Run both a genuine authorised VPN exercise and negative controls. Review exact time-boundary semantics, scheduler timing and duplicate event behaviour. Retain raw evidence privately and publish only sanitised derivatives with a redaction manifest. Do not mark a test passed until expected and actual outcomes are compared and independently reviewable.
