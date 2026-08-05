# Local test fixtures

Everything here exists so `analyze_audit.py` can be exercised end to end without
a JFrog instance, an Xray subscription, or a Maven project.

- `sample-audit.json` — a synthetic `jf audit --format=simple-json` report,
  hand-built to hit every adjudication branch at once.
- `sample-exclusions.json` — an exclusions file matched to that report,
  covering valid, expiring, expired, partial and stale entries.

## Run it

```sh
AUDIT_JSON=tests/sample-audit.json \
XRAY_EXCLUSIONS=tests/sample-exclusions.json \
python3 analyze_audit.py; echo "exit=$?"

open xray_scan_report.html
```

Expected: **exit 1**, verdict `XRAY SCAN: FAIL`, 6 blocking / 2 excluded /
1 not applicable.

Both env vars are optional overrides. With neither set the script reads
`audit.json` and `$CI_PROJECT_DIR/xray-exclusions.json`, which is what happens
in CI. `REPORT_HTML` moves the report somewhere other than
`xray_scan_report.html`.

## What each fixture row proves

| Package | Covers | Outcome |
|---|---|---|
| `org.apache.commons:commons-text` | valid exclusion (`CVE-2025-12345`, expires 2026-11-01) | excluded |
| `com.fasterxml.jackson.core:jackson-databind` | ordinary un-excluded CVE | blocking |
| `org.springframework:spring-web` | two CVEs, only one excluded | **blocking** — all CVEs on a row must be covered |
| `ch.qos.logback:logback-core` | exclusion that expired on 2026-01-15 | blocking, flagged `EXPIRED` |
| `org.yaml:snakeyaml` | JAS `not_applicable` | auto-suppressed, no exclusion needed |
| `org.eclipse.jetty:jetty-server` | exclusion expiring inside 30 days | excluded, flagged amber |
| `commons-io:commons-io` | violation with no CVE id, only `XRAY-100007` | blocking — nothing to key an exclusion off |
| `com.example:gpl-widget` | license violation | blocking, no exclusion path |
| `log4j:log4j` | operational-risk / EOL violation | blocking, no exclusion path |
| `com.google.guava:guava` | `vulnerabilities[]`, outside the watches | informational only |
| `CVE-2020-00000` in the exclusions file | matches nothing in the scan | listed as stale, does not fail |
| `secretsScanStatusCode: 1` + `errors[]` | a non-SCA scanner failed | warning banner, verdict unchanged |

## Exit-code matrix

Each of these should hold:

| Scenario | Expected |
|---|---|
| Fixture as shipped | `1` |
| Only excluded + not-applicable rows | `0` |
| `XRAY_EXCLUSIONS` pointing at a nonexistent file | `1` — no exclusions, everything blocks |
| Duplicate CVE / missing `expirationDate` / `01/11/2026` date | `2`, every problem listed at once |
| `AUDIT_JSON` missing, empty, or unparseable | `2`, report still written |
| `scansStatus.scaScanStatusCode` non-zero | `2` — no trustworthy results |
| `scansStatus.secretsScanStatusCode` non-zero | unchanged verdict + banner |
| Exclusion expiring today | `0` — expiry is inclusive, UTC |
| Same exclusion dated yesterday | `1` |

To check the two boundary cases, point `XRAY_EXCLUSIONS` at a one-line file
whose `expirationDate` is today's UTC date, then yesterday's.

## Job-log formatting

The log summary uses GitLab collapsible sections only when `GITLAB_CI` is set;
locally it prints plain headed blocks instead. To see what the job console will
actually look like:

```sh
GITLAB_CI=1 AUDIT_JSON=tests/sample-audit.json \
XRAY_EXCLUSIONS=tests/sample-exclusions.json python3 analyze_audit.py
```
