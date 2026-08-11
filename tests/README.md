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

Expected: **exit 1**, verdict `XRAY SCAN: FAIL`, 6 blocking / 3 excluded /
1 not applicable / 1 unused exclusion.

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
| `commons-io:commons-io` | `cves: []`, identified only by `XRAY-100007` | blocking — no exclusion entry for that issue id |
| `io.netty:netty-handler` | `cves: null`, excluded by issue id `XRAY-100008` | excluded — the issueId fallback |
| `com.example:gpl-widget` | license violation | blocking, no exclusion path |
| `log4j:log4j` | operational-risk / EOL violation | blocking, no exclusion path |
| `com.google.guava:guava` | `vulnerabilities[]`, outside the watches | informational only |
| `CVE-2020-00000` in the exclusions file | matches nothing in the scan | listed as unused; fails the job with exit 3 |
| `secretsScanStatusCode: 1` + `errors[]` | a non-SCA scanner failed | warning banner, verdict unchanged |

## Exclusions keyed on an Xray issue id

When Xray flags something before a CVE is published, `cves` comes back `null`
(or `[]`) and `issueId` is the only identifier. The exclusions file handles that
with no schema change — put the issue id in the `CVE` field:

```json
{"CVE": "XRAY-100008", "expirationDate": "2026-10-15", "reason": "no CVE published yet"}
```

CVEs take priority: the issue id is used only when the row has no CVE at all.
Matching is case-insensitive, and the expiry rules are identical.

**When the CVE is eventually published**, Xray reports it instead of the bare
issue id, the `XRAY-*` entry stops matching, and the row blocks again. That is
intended. To see it happen, assign a CVE to the netty row:

```sh
python3 -c "
import json; d=json.load(open('tests/sample-audit.json'))
[r.update(cves=[{'id':'CVE-2026-70001','cvssV3':'8.1'}])
 for r in d['securityViolations'] if r.get('issueId')=='XRAY-100008']
json.dump(d, open('/tmp/cve-published.json','w'))"

AUDIT_JSON=/tmp/cve-published.json XRAY_EXCLUSIONS=tests/sample-exclusions.json \
python3 analyze_audit.py; echo "exit=$?"
```

Blocking goes 4 → 5, and `XRAY-100008` shows up under **Exclusion hygiene** as
having matched nothing — the cue to re-file it under the new CVE id.

## Unused exclusions fail the job

An entry that matched nothing in the scan is dead weight, so it exits **3** to
force cleanup. "Matched nothing" outranks expiry: an entry that is both expired
and unmatched counts as unused, not as expired. The `expired` and `expiring`
lists therefore only ever hold entries that *did* match a finding.

Precedence when more than one thing is wrong: **2 beats 1 beats 3** — an
unusable scan outranks a security failure, which outranks housekeeping. The
verdict line always names every reason, so fixing the violations never surprises
you with a second red pipeline you were not told about.

To see exit 3 on its own, drop every row the exclusions file does not cover:

```sh
python3 -c "
import json; d=json.load(open('tests/sample-audit.json'))
keep={'org.apache.commons:commons-text','org.yaml:snakeyaml',
      'org.eclipse.jetty:jetty-server','io.netty:netty-handler'}
d['securityViolations']=[r for r in d['securityViolations']
                         if r['impactedPackageName'] in keep]
d['licensesViolations']=[]; d['operationalRiskViolations']=[]
json.dump(d, open('/tmp/clean-audit.json','w'))"

AUDIT_JSON=/tmp/clean-audit.json XRAY_EXCLUSIONS=tests/sample-exclusions.json \
python3 analyze_audit.py; echo "exit=$?"   # 3 — three entries now match nothing
```

Trim `sample-exclusions.json` down to the three entries that still match
(`CVE-2025-12345`, `CVE-2024-11111`, `XRAY-100008`) and the same run exits `0`.

Because of this rule the committed `xray-exclusions.json` at the repo root is an
empty array. A placeholder entry in it would fail every pipeline from day one.

## Exit-code matrix

Each of these should hold:

| Scenario | Expected |
|---|---|
| Fixture as shipped | `1` — blocking outranks the 1 unused entry, both reported |
| Only excluded + not-applicable rows | `3` — three exclusions now match nothing |
| ...with the exclusions file trimmed to what matched | `0` |
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
