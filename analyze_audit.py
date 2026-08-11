#!/usr/bin/env python3
"""Adjudicate a `jf audit --format=simple-json` report against an expiring CVE
exclusions file, then emit an HTML report, a job-log summary, and an exit code.

`jf audit` on its own cannot express "this CVE is knowingly accepted until
2026-11-01" — a watch either fails the build or it doesn't. So the CI job asks
jf not to set the exit code (`--fail=false`) and this script decides instead.

Exclusions are keyed on the CVE id, or on the Xray issue id (XRAY-123456) for
findings that have no published CVE yet. See issue_identifiers().

Exit codes
    0   no blocking findings
    1   one or more blocking findings
    2   scan or configuration error — audit.json missing/unparseable, the
        exclusions file is invalid, or the SCA scan itself failed
    3   every violation is accounted for, but the exclusions file carries
        entries that matched nothing in this scan and must be removed

Precedence when several apply: 2 beats 1 beats 3. An unusable scan outranks a
security failure, which outranks a housekeeping failure — but the report and
the log always name every reason, not just the one that set the exit code.

Environment overrides (all optional)
    AUDIT_JSON       path to the audit output      (default: audit.json)
    XRAY_EXCLUSIONS  path to the exclusions file   (default: <repo root>/xray-exclusions.json)
    REPORT_HTML      path to write the report to   (default: xray_scan_report.html)
    CI_PROJECT_DIR   repo root, set by GitLab      (default: cwd)

Python 3.8+, standard library only.
"""

import datetime
import html
import json
import os
import sys
import time

EXCLUSIONS_FILENAME = "xray-exclusions.json"
REQUIRED_KEYS = ("CVE", "expirationDate", "reason")
DATE_FORMAT = "%Y-%m-%d"
EXPIRY_WARNING_DAYS = 30

EXIT_CLEAN = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2
EXIT_UNUSED_EXCLUSIONS = 3

# Worst first. Anything unrecognised sorts last, under "Unknown".
SEVERITIES = ("Critical", "High", "Medium", "Low", "Unknown")

# Per-CVE adjudication outcomes.
EXCLUDED = "EXCLUDED"
EXPIRED = "EXPIRED"
NOT_APPLICABLE = "NOT_APPLICABLE"
BLOCKING = "BLOCKING"


class FatalError(Exception):
    """A scan or configuration error: nothing can be adjudicated. Exits 2."""

    def __init__(self, message, details=None):
        super().__init__(message)
        self.message = message
        self.details = list(details or [])


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def alnum(value):
    """Lowercase and strip non-alphanumerics.

    Applicability arrives as "Not Applicable" at row level but "not_applicable"
    inside cves[].applicability.status, depending on CLI version. Normalising
    both to "notapplicable" avoids caring which one we got.
    """
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum())


def severity_of(row):
    raw = str(row.get("severity") or "").strip()
    for known in SEVERITIES:
        if raw.lower() == known.lower():
            return known
    return raw or "Unknown"


def severity_rank(severity):
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return len(SEVERITIES)


def as_list(value):
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def package_label(row):
    name = str(row.get("impactedPackageName") or "").strip()
    version = str(row.get("impactedPackageVersion") or "").strip()
    if name and version:
        return "%s:%s" % (name, version)
    return name or version or "(unknown package)"


def component_label(node):
    """Render one node of components[] / impactPaths[][] as name:version."""
    if not isinstance(node, dict):
        return str(node or "").strip()
    name = str(node.get("name") or "").strip()
    version = str(node.get("version") or "").strip()
    if name and version:
        return "%s:%s" % (name, version)
    return name or str(node.get("id") or "").strip()


def direct_dependencies(row):
    """The direct dependency that drags in the impacted (often transitive) one.

    `components[]` is what the table renderer uses for its Direct Dependency
    column, so prefer it; fall back to element [1] of each impact path, since
    [0] is the project root and [-1] is the impacted package itself.
    """
    seen = []
    for node in as_list(row.get("components")):
        label = component_label(node)
        if label and label not in seen:
            seen.append(label)
    if seen:
        return seen
    for path in as_list(row.get("impactPaths")):
        if isinstance(path, list) and len(path) > 1:
            label = component_label(path[1])
            if label and label not in seen:
                seen.append(label)
    return seen


def watch_label(row):
    # Field was renamed across CLI versions; accept either spelling.
    watch = str(row.get("watch") or row.get("watchName") or "").strip()
    policies = [str(p).strip() for p in as_list(row.get("policies")) if str(p).strip()]
    parts = []
    if watch:
        parts.append(watch)
    if policies:
        parts.append("/".join(policies))
    return " — ".join(parts)


def cve_entries(row):
    """cves[] entries that actually carry an id."""
    out = []
    for cve in as_list(row.get("cves")):
        if isinstance(cve, dict) and str(cve.get("id") or "").strip():
            out.append(cve)
    return out


def issue_identifiers(row):
    """The ids an exclusion may be keyed on for this row, worst case empty.

    Xray flags plenty of issues before a CVE is published: `cves` comes back
    null or empty and only `issueId` (XRAY-123456) names the finding. Fall back
    to that id so those rows can still be excluded, through the same `CVE`
    field in the exclusions file — no schema change.

    Returns (entry, is_fallback) pairs. A fallback entry is a synthetic stand-in
    carrying only an id, so it has no CVSS and no per-CVE applicability; the
    row-level `applicable` field is what cve_applicability() falls back to.

    Deliberate consequence: once a CVE is published, Xray reports the CVE and
    the XRAY-* exclusion stops matching, so the pipeline fails until someone
    re-files it under the new id. The exclusion hygiene section flags the
    orphaned entry as having matched nothing, which is the cue to do that.
    """
    entries = cve_entries(row)
    if entries:
        return [(entry, False) for entry in entries]
    issue_id = str(row.get("issueId") or "").strip()
    if issue_id:
        return [({"id": issue_id}, True)]
    return []


def cve_applicability(cve, row):
    """Applicability for one CVE, falling back to the row-level field.

    An absent or empty value means unknown — for example when the project has
    no JAS entitlement — and unknown must never suppress anything.
    """
    applicability = cve.get("applicability")
    if isinstance(applicability, dict):
        status = str(applicability.get("status") or "").strip()
        if status:
            return status
    return str(row.get("applicable") or "").strip()


def cvss_of(cve):
    return str(cve.get("cvssV3") or cve.get("cvssV2") or "").strip()


# --------------------------------------------------------------------------
# exclusions file
# --------------------------------------------------------------------------

def load_exclusions(path):
    """Parse and strictly validate the exclusions file.

    Returns (by_cve, notes). A missing file is not an error — it means zero
    exclusions. Every validation problem is collected before raising, so one
    run surfaces every mistake in the file rather than only the first.
    """
    notes = []
    if not os.path.isfile(path):
        notes.append("No %s found — proceeding with zero exclusions." % path)
        return {}, notes

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise FatalError("%s could not be read as JSON." % path, [str(exc)])

    if not isinstance(data, list):
        raise FatalError(
            "%s must contain a JSON array of exclusion objects." % path,
            ["Found %s at the top level." % type(data).__name__],
        )

    problems = []
    by_cve = {}
    first_seen = {}

    for index, raw in enumerate(data):
        label = "entry #%d" % (index + 1)
        if not isinstance(raw, dict):
            problems.append("%s: expected an object, found %s."
                            % (label, type(raw).__name__))
            continue

        missing = [key for key in REQUIRED_KEYS
                   if not str(raw.get(key) or "").strip()]
        if missing:
            problems.append("%s: missing or empty required field(s): %s."
                            % (label, ", ".join(missing)))
            continue

        cve = str(raw["CVE"]).strip().upper()
        label = "%s (%s)" % (label, cve)

        unknown = sorted(set(raw) - set(REQUIRED_KEYS))
        if unknown:
            notes.append("%s: ignoring unrecognised field(s): %s."
                         % (label, ", ".join(unknown)))

        raw_date = str(raw["expirationDate"]).strip()
        try:
            expires = datetime.datetime.strptime(raw_date, DATE_FORMAT).date()
        except ValueError:
            problems.append("%s: expirationDate %r is not a valid YYYY-MM-DD date."
                            % (label, raw_date))
            continue

        if cve in first_seen:
            problems.append("%s: duplicate of entry #%d — a CVE may appear only "
                            "once, otherwise which expiry applies is ambiguous."
                            % (label, first_seen[cve]))
            continue

        first_seen[cve] = index + 1
        by_cve[cve] = {
            "cve": cve,
            "expires": expires,
            "expires_text": raw_date,
            "reason": str(raw["reason"]).strip(),
        }

    if problems:
        raise FatalError("%s is invalid." % path, problems)

    notes.append("Loaded %d exclusion(s) from %s." % (len(by_cve), path))
    return by_cve, notes


def exclusion_state(exclusion, today):
    """Inclusive through the end of the listed day, UTC."""
    if exclusion["expires"] < today:
        return EXPIRED
    return EXCLUDED


def days_left(exclusion, today):
    return (exclusion["expires"] - today).days


# --------------------------------------------------------------------------
# audit.json
# --------------------------------------------------------------------------

def load_audit(path):
    if not os.path.isfile(path):
        raise FatalError(
            "%s does not exist — the scan produced no output." % path,
            ["`jf audit` most likely failed before writing anything. Check the "
             "step above this one in the job log."],
        )

    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise FatalError("%s could not be read." % path, [str(exc)])

    if not text.strip():
        raise FatalError(
            "%s is empty — the scan produced no output." % path,
            ["`jf audit` most likely failed before writing anything. Check the "
             "step above this one in the job log."],
        )

    try:
        data = json.loads(text)
    except ValueError as exc:
        # Some jf builds interleave log lines into stdout, which corrupts an
        # otherwise valid report. Salvage the outermost JSON object.
        start, end = text.find("{"), text.rfind("}")
        data = None
        if start != -1 and end > start:
            try:
                data = json.loads(text[start:end + 1])
            except ValueError:
                data = None
        if data is None:
            raise FatalError("%s is not valid JSON." % path, [str(exc)])

    if not isinstance(data, dict):
        raise FatalError("%s must contain a JSON object at the top level." % path,
                         ["Found %s." % type(data).__name__])
    return data


def scan_status_report(audit):
    """Split scanner failures into blocking (SCA) and advisory (everything else).

    --allow-partial-results lets individual scanners fail. If SCA failed there
    are no meaningful violations to adjudicate, so the verdict would be a lie.
    Other scanners failing is worth a banner but does not change the verdict.
    """
    sca_failed = []
    other_failed = []
    status = audit.get("scansStatus")
    if isinstance(status, dict):
        for key, code in status.items():
            if not isinstance(code, int) or code == 0:
                continue
            message = "%s returned status code %d" % (key, code)
            # Prefix, not substring: every key contains "Scan", so `"sca" in key`
            # would flag secretsScanStatusCode as an SCA failure.
            if alnum(key).startswith("sca"):
                sca_failed.append(message)
            else:
                other_failed.append(message)

    for error in as_list(audit.get("errors")):
        if isinstance(error, dict):
            message = str(error.get("errorMessage") or "").strip() or "unspecified error"
            path = str(error.get("filePath") or "").strip()
            other_failed.append("%s%s" % (message, " (%s)" % path if path else ""))
        elif str(error).strip():
            other_failed.append(str(error).strip())

    return sca_failed, other_failed


# --------------------------------------------------------------------------
# adjudication
# --------------------------------------------------------------------------

def adjudicate_security(rows, exclusions, today, seen_cves):
    """Classify each security violation row.

    A row is suppressed only if it carries at least one identifier and *every*
    one of them is either excluded (valid, unexpired) or proven Not Applicable.
    One unexcluded identifier keeps the whole row blocking, and we record which.

    "Identifier" is the row's CVEs when it has any, otherwise its Xray issueId —
    see issue_identifiers().
    """
    findings = []
    for row in rows:
        if not isinstance(row, dict):
            continue

        cves = []
        for entry, is_fallback in issue_identifiers(row):
            cve_id = str(entry["id"]).strip().upper()
            seen_cves.add(cve_id)
            applicability = cve_applicability(entry, row)
            exclusion = exclusions.get(cve_id)

            if exclusion is not None:
                status = exclusion_state(exclusion, today)
            elif alnum(applicability) == "notapplicable":
                status = NOT_APPLICABLE
            else:
                status = BLOCKING

            cves.append({
                "id": cve_id,
                "status": status,
                "exclusion": exclusion,
                "applicability": applicability,
                "cvss": cvss_of(entry),
                "fallback": is_fallback,
            })

        if cves:
            suppressed = all(c["status"] in (EXCLUDED, NOT_APPLICABLE) for c in cves)
            uses_exclusion = any(c["status"] == EXCLUDED for c in cves)
        else:
            # Neither a CVE nor an issueId — nothing an exclusion could key on,
            # so the row-level applicability field is all there is to go on.
            suppressed = alnum(row.get("applicable")) == "notapplicable"
            uses_exclusion = False

        if not suppressed:
            status = BLOCKING
        elif uses_exclusion:
            status = EXCLUDED
        else:
            status = NOT_APPLICABLE

        blockers = [c for c in cves if c["status"] in (BLOCKING, EXPIRED)]
        findings.append({
            "kind": "security",
            "severity": severity_of(row),
            "package": package_label(row),
            "type": str(row.get("impactedPackageType") or "").strip(),
            "cves": cves,
            "issue_id": str(row.get("issueId") or "").strip(),
            "watch": watch_label(row),
            "fixed": [str(v).strip() for v in as_list(row.get("fixedVersions")) if str(v).strip()],
            "direct": direct_dependencies(row),
            "summary": str(row.get("summary") or "").strip(),
            "applicable": str(row.get("applicable") or "").strip(),
            "status": status,
            "blockers": blockers,
        })
    return findings


def adjudicate_licenses(rows):
    findings = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("licenseName") or "").strip()
        key = str(row.get("licenseKey") or "").strip()
        findings.append({
            "kind": "license",
            "severity": severity_of(row),
            "package": package_label(row),
            "license": key or name or "(unknown license)",
            "license_name": name if name and name != key else "",
            "watch": watch_label(row),
            "direct": direct_dependencies(row),
            "status": BLOCKING,
        })
    return findings


def adjudicate_operational_risk(rows):
    findings = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        detail = str(row.get("riskReason") or "").strip()
        if not detail:
            detail = str(row.get("endOfLifeMessage") or "").strip()
        findings.append({
            "kind": "oprisk",
            "severity": severity_of(row),
            "package": package_label(row),
            "risk_reason": detail or "(no reason given)",
            "eol": bool(row.get("isEndOfLife")),
            "latest": str(row.get("latestVersion") or "").strip(),
            "watch": watch_label(row),
            "direct": direct_dependencies(row),
            "status": BLOCKING,
        })
    return findings


def collect_informational(rows, seen_cves):
    """Non-violation findings — outside the watches, never blocking."""
    findings = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ids = []
        for entry, _ in issue_identifiers(row):
            cve_id = str(entry["id"]).strip().upper()
            ids.append(cve_id)
            seen_cves.add(cve_id)
        findings.append({
            "kind": "info",
            "severity": severity_of(row),
            "package": package_label(row),
            "cve_ids": ids,
            "issue_id": str(row.get("issueId") or "").strip(),
            "applicability": str(row.get("applicable") or "").strip(),
            "fixed": [str(v).strip() for v in as_list(row.get("fixedVersions")) if str(v).strip()],
            "direct": direct_dependencies(row),
            "status": "INFO",
        })
    return findings


def exclusion_audit(exclusions, seen_cves, today):
    """Classify every exclusion by how it fared this run.

    "Matched nothing" is the primary axis and outranks expiry: an entry nobody
    references is dead weight whether or not its date has passed, and it is what
    fails the run under EXIT_UNUSED_EXCLUSIONS.

    So `expired` and `expiring` only ever hold entries that DID match something.
    An expired-but-matched entry is already forcing its violation to block,
    which is a different problem from an entry nothing refers to.
    """
    stale, expiring, expired = [], [], []
    for exclusion in exclusions.values():
        remaining = days_left(exclusion, today)
        record = dict(exclusion, days_left=remaining, matched=exclusion["cve"] in seen_cves)
        if not record["matched"]:
            stale.append(record)
        elif remaining < 0:
            expired.append(record)
        elif remaining <= EXPIRY_WARNING_DAYS:
            expiring.append(record)
    stale.sort(key=lambda e: e["cve"])
    expiring.sort(key=lambda e: e["days_left"])
    expired.sort(key=lambda e: e["days_left"])
    return stale, expiring, expired


def sort_findings(findings):
    return sorted(findings, key=lambda f: (severity_rank(f["severity"]), f["package"]))


def severity_counts(findings):
    counts = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    ordered = [(s, counts.pop(s)) for s in SEVERITIES if s in counts]
    ordered.extend(sorted(counts.items()))
    return ordered


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------

CSS = """
:root {
  --bg: #ffffff; --fg: #1b1f24; --muted: #5c6570; --line: #d8dee4;
  --panel: #f6f8fa; --pass: #1a7f37; --fail: #b02a37; --warn: #9a6700;
  --pass-bg: #dafbe1; --fail-bg: #ffebe9; --warn-bg: #fff8c5; --info-bg: #ddf4ff;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #30363d;
    --panel: #161b22; --pass: #3fb950; --fail: #f85149; --warn: #d29922;
    --pass-bg: #12261e; --fail-bg: #2d1214; --warn-bg: #2b2413; --info-bg: #0f2740;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1.25rem 4rem; background: var(--bg); color: var(--fg);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
}
main { max-width: 1180px; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
h2 { font-size: 1.1rem; margin: 2.5rem 0 .35rem; padding-bottom: .3rem; border-bottom: 1px solid var(--line); }
h2 .count { color: var(--muted); font-weight: 400; }
p.sub { color: var(--muted); margin: 0 0 1.5rem; font-size: .875rem; }
p.note { color: var(--muted); font-size: .875rem; margin: .35rem 0 .9rem; }
.verdict { border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1.25rem; border: 1px solid; }
.verdict.pass { background: var(--pass-bg); border-color: var(--pass); }
.verdict.fail { background: var(--fail-bg); border-color: var(--fail); }
.verdict.error { background: var(--warn-bg); border-color: var(--warn); }
.verdict .headline { font-size: 1.25rem; font-weight: 700; }
.verdict.pass .headline { color: var(--pass); }
.verdict.fail .headline { color: var(--fail); }
.verdict.error .headline { color: var(--warn); }
.verdict .detail { margin-top: .35rem; font-size: .9rem; }
.banner { border-radius: 8px; padding: .8rem 1rem; margin-bottom: 1.25rem;
          background: var(--warn-bg); border: 1px solid var(--warn); font-size: .9rem; }
.banner strong { color: var(--warn); }
.banner ul { margin: .4rem 0 0; padding-left: 1.2rem; }
.tiles { display: flex; flex-wrap: wrap; gap: .6rem; margin: 1rem 0 0; }
.tile { background: var(--panel); border: 1px solid var(--line); border-radius: 6px;
        padding: .5rem .8rem; min-width: 8.5rem; }
.tile .n { font-size: 1.35rem; font-weight: 700; display: block; }
.tile .k { color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }
.scroll { overflow-x: auto; border: 1px solid var(--line); border-radius: 6px; }
table { border-collapse: collapse; width: 100%; font-size: .875rem; }
th, td { text-align: left; padding: .55rem .7rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: var(--panel); font-weight: 600; white-space: nowrap; }
tr:last-child td { border-bottom: none; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .92em; }
.dim { color: var(--muted); }
.nowrap { white-space: nowrap; }
/* Identifiers must never break mid-token — a CVE id split across three lines
   is unreadable. Package coordinates may wrap, but only between words. */
.id { white-space: nowrap; }
.wrap { word-break: break-word; }
.stack + .stack { margin-top: .45rem; padding-top: .45rem; border-top: 1px dashed var(--line); }
.stack .who { display: block; font-size: .78rem; margin-bottom: .15rem; }
.badge { display: inline-block; padding: .1rem .45rem; border-radius: 999px;
         font-size: .74rem; font-weight: 700; letter-spacing: .02em; white-space: nowrap;
         border: 1px solid currentColor; }
.sev-critical { color: var(--fail); background: var(--fail-bg); }
.sev-high     { color: var(--fail); background: var(--fail-bg); }
.sev-medium   { color: var(--warn); background: var(--warn-bg); }
.sev-low      { color: var(--muted); background: var(--panel); }
.sev-unknown  { color: var(--muted); background: var(--panel); }
.st-blocking  { color: var(--fail); background: var(--fail-bg); }
.st-expired   { color: var(--fail); background: var(--fail-bg); }
.st-excluded  { color: var(--pass); background: var(--pass-bg); }
.st-warn      { color: var(--warn); background: var(--warn-bg); }
.st-na        { color: var(--muted); background: var(--panel); }
details { margin-top: .5rem; }
summary { cursor: pointer; color: var(--muted); font-size: .9rem; padding: .3rem 0; }
footer { margin-top: 3rem; color: var(--muted); font-size: .8rem;
         border-top: 1px solid var(--line); padding-top: .8rem; }
"""


def esc(value):
    return html.escape(str(value if value is not None else ""))


def badge(text, css_class):
    return '<span class="badge %s">%s</span>' % (css_class, esc(text))


def severity_badge(severity):
    return badge(severity, "sev-%s" % (alnum(severity) or "unknown"))


def breakable(text):
    """Escape, then mark break opportunities after coordinate separators.

    Maven GAVs are long single "words", so a browser left to itself either
    overflows the column or breaks mid-token ("com.fasterxml.jacks / on.core").
    <wbr> lets it wrap at '.', ':', '-' and '/' instead.
    """
    out = []
    for char in str(text or ""):
        out.append(html.escape(char))
        if char in ".:-/":
            out.append("<wbr>")
    return "".join(out)


def joined(values, empty='<span class="dim">—</span>', render=esc):
    values = [v for v in values if v]
    if not values:
        return empty
    return "<br>".join(render(v) for v in values)


APPLICABILITY_LABELS = {
    "applicable": "Applicable",
    "notapplicable": "Not applicable",
    "undetermined": "Undetermined",
    "notcovered": "Not covered",
    "notscanned": "Not scanned",
    "rescanrequired": "Rescan required",
    "missingcontext": "Missing context",
}


def applicability_label(value):
    """Normalise for display: the row-level and per-CVE fields disagree on
    casing and separators for the same states."""
    text = str(value or "").strip()
    if not text:
        return ""
    return APPLICABILITY_LABELS.get(alnum(text), text)


def unique(values):
    out = []
    for value in values:
        if value and value not in out:
            out.append(value)
    return out


def cve_cell(cve):
    bits = ['<span class="mono id">%s</span>' % esc(cve["id"])]
    if cve["cvss"]:
        bits.append('<span class="dim id"> · CVSS %s</span>' % esc(cve["cvss"]))
    if cve.get("fallback"):
        bits.append('<br><span class="dim">Xray issue id — no CVE published yet</span>')
    return "".join(bits)


def table(headers, rows):
    if not rows:
        return ""
    head = "".join("<th>%s</th>" % esc(h) for h in headers)
    body = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % cell for cell in row)
                   for row in rows)
    return ('<div class="scroll"><table><thead><tr>%s</tr></thead>'
            "<tbody>%s</tbody></table></div>" % (head, body))


def section(title, count, body, note=None, collapsed=False):
    if not body:
        return ""
    heading = '<h2>%s <span class="count">(%d)</span></h2>' % (esc(title), count)
    note_html = '<p class="note">%s</p>' % esc(note) if note else ""
    if collapsed:
        return ("%s%s<details><summary>Show %d row(s)</summary>%s</details>"
                % (heading, note_html, count, body))
    return "%s%s%s" % (heading, note_html, body)


def cve_status_cell(cve, today, show_id=False):
    """One per-CVE status block.

    On rows carrying several CVEs the blocks cannot line up with the CVE column
    (each side wraps independently), so each block names its own CVE.
    """
    if cve["status"] == EXCLUDED:
        remaining = days_left(cve["exclusion"], today)
        css = "st-warn" if remaining <= EXPIRY_WARNING_DAYS else "st-excluded"
        body = "%s<br><span class='dim'>%s</span>" % (
            badge("excluded until %s" % cve["exclusion"]["expires_text"], css),
            esc(cve["exclusion"]["reason"]),
        )
    elif cve["status"] == EXPIRED:
        body = "%s<br><span class='dim'>expired %s — %s</span>" % (
            badge("EXPIRED", "st-expired"),
            esc(cve["exclusion"]["expires_text"]),
            esc(cve["exclusion"]["reason"]),
        )
    elif cve["status"] == NOT_APPLICABLE:
        body = badge("not applicable", "st-na")
    else:
        body = badge("blocking", "st-blocking")

    label = ('<span class="who dim mono id">%s</span>' % esc(cve["id"])) if show_id else ""
    return '<div class="stack">%s%s</div>' % (label, body)


def security_rows(findings, today):
    rows = []
    for finding in findings:
        if finding["cves"]:
            multiple = len(finding["cves"]) > 1
            cves_html = "<br>".join(cve_cell(c) for c in finding["cves"])
            status_html = "".join(cve_status_cell(c, today, show_id=multiple)
                                  for c in finding["cves"])
            applicability = joined(unique(applicability_label(c["applicability"])
                                          for c in finding["cves"]))
        else:
            # Neither a CVE nor an issueId — no exclusion could ever match.
            cves_html = '<span class="dim">no identifier</span>'
            status_html = badge(finding["status"].lower().replace("_", " "),
                                "st-na" if finding["status"] == NOT_APPLICABLE else "st-blocking")
            applicability = joined([applicability_label(finding.get("applicable"))])
        rows.append([
            severity_badge(finding["severity"]),
            cves_html,
            '<span class="mono wrap">%s</span>' % breakable(finding["package"]),
            joined(finding["fixed"]),
            '<span class="wrap mono">%s</span>' % joined(finding["direct"], render=breakable),
            applicability,
            '<span class="wrap">%s</span>' % joined([finding["watch"]], render=breakable),
            status_html,
        ])
    return rows


SECURITY_HEADERS = ("Severity", "CVE", "Impacted package", "Fixed in",
                    "Direct dependency", "Applicability", "Watch / policy", "Status")


def render_html(ctx):
    parts = ["<main>"]
    parts.append("<h1>Xray scan report</h1>")
    parts.append('<p class="sub">%s</p>' % esc(" · ".join(ctx["meta"])))

    verdict = ctx["verdict"]
    parts.append('<div class="verdict %s"><div class="headline">%s</div>'
                 '<div class="detail">%s</div></div>'
                 % (verdict["css"], esc(verdict["headline"]), esc(verdict["detail"])))

    for banner in ctx["banners"]:
        items = "".join("<li>%s</li>" % esc(item) for item in banner["items"])
        parts.append('<div class="banner"><strong>%s</strong><ul>%s</ul></div>'
                     % (esc(banner["title"]), items))

    if ctx["tiles"]:
        tiles = "".join('<div class="tile"><span class="n">%d</span>'
                        '<span class="k">%s</span></div>' % (n, esc(k))
                        for k, n in ctx["tiles"])
        parts.append('<div class="tiles">%s</div>' % tiles)

    today = ctx["today"]

    parts.append(section(
        "Blocking violations", len(ctx["blocking"]),
        table(SECURITY_HEADERS, security_rows(ctx["blocking"], today)),
        note="These fail the pipeline. Fix them, or add an entry to %s with an "
             "expiry date and a reason, keyed on the CVE id — or on the Xray "
             "issue id where no CVE has been published yet." % EXCLUSIONS_FILENAME,
    ))

    # Directly after the blocking violations: these two sections are the only
    # things that fail the job, so they belong together at the top. Everything
    # below them is context for reading them.
    stale_rows = [[
        '<span class="mono id">%s</span>' % esc(record["cve"]),
        esc(record["expires_text"]),
        badge("matched nothing", "st-blocking"),
        esc(record["reason"]),
    ] for record in ctx["stale_exclusions"]]
    parts.append(section(
        "Unused exclusions — remove them", len(stale_rows),
        table(("CVE / issue id", "Expires", "State", "Reason"), stale_rows),
        note="Nothing in this scan matches these entries. Either the finding was "
             "remediated, the id is mistyped, or a CVE has since been published "
             "for what was filed under an Xray issue id. Delete them from %s. "
             "This fails the job with exit code %d."
             % (EXCLUSIONS_FILENAME, EXIT_UNUSED_EXCLUSIONS),
    ))

    parts.append(section(
        "Excluded security violations", len(ctx["excluded"]),
        table(SECURITY_HEADERS, security_rows(ctx["excluded"], today)),
        note="Knowingly accepted for now. Each stops suppressing on the date "
             "shown, after which it blocks the pipeline again.",
    ))

    parts.append(section(
        "Auto-suppressed — not applicable", len(ctx["not_applicable"]),
        table(SECURITY_HEADERS, security_rows(ctx["not_applicable"], today)),
        note="Xray determined the vulnerable code path is not reachable from "
             "this project. No exclusion entry needed.",
        collapsed=True,
    ))

    license_rows = [[
        severity_badge(f["severity"]),
        '<span class="mono id">%s</span>' % esc(f["license"]),
        '<span class="mono wrap">%s</span>' % breakable(f["package"]),
        '<span class="wrap mono">%s</span>' % joined(f["direct"], render=breakable),
        '<span class="wrap">%s</span>' % joined([f["watch"]], render=breakable),
        badge("blocking", "st-blocking"),
    ] for f in ctx["licenses"]]
    parts.append(section(
        "License violations", len(ctx["licenses"]),
        table(("Severity", "License", "Impacted package", "Direct dependency",
               "Watch / policy", "Status"), license_rows),
        note="License violations have no exclusion mechanism — every one of "
             "these blocks the pipeline.",
    ))

    oprisk_rows = [[
        severity_badge(f["severity"]),
        '<span class="mono wrap">%s</span>' % breakable(f["package"]),
        esc(f["risk_reason"]) + (" <span class='dim'>(end of life)</span>" if f["eol"] else ""),
        joined([f["latest"]]),
        '<span class="wrap mono">%s</span>' % joined(f["direct"], render=breakable),
        '<span class="wrap">%s</span>' % joined([f["watch"]], render=breakable),
        badge("blocking", "st-blocking"),
    ] for f in ctx["oprisk"]]
    parts.append(section(
        "Operational risk violations", len(ctx["oprisk"]),
        table(("Severity", "Impacted package", "Risk", "Latest version",
               "Direct dependency", "Watch / policy", "Status"), oprisk_rows),
        note="Operational risk violations have no exclusion mechanism — every "
             "one of these blocks the pipeline.",
    ))

    expiry_rows = []
    for record in ctx["expired_exclusions"]:
        expiry_rows.append([
            '<span class="mono id">%s</span>' % esc(record["cve"]),
            esc(record["expires_text"]),
            badge("expired %d day(s) ago" % -record["days_left"], "st-expired"),
            esc(record["reason"]),
        ])
    for record in ctx["expiring_exclusions"]:
        expiry_rows.append([
            '<span class="mono id">%s</span>' % esc(record["cve"]),
            esc(record["expires_text"]),
            badge("expires in %d day(s)" % record["days_left"], "st-warn"),
            esc(record["reason"]),
        ])
    parts.append(section(
        "Exclusion expiry", len(expiry_rows),
        table(("CVE / issue id", "Expires", "State", "Reason"), expiry_rows),
        note="These still match a finding. An expired one no longer suppresses "
             "it, so its violation is in the blocking list above; renew or "
             "remediate before the others follow.",
    ))

    info_rows = [[
        severity_badge(f["severity"]),
        '<span class="mono id">%s</span>' % joined(f["cve_ids"] or [f["issue_id"]]),
        '<span class="mono wrap">%s</span>' % breakable(f["package"]),
        joined(f["fixed"]),
        '<span class="wrap mono">%s</span>' % joined(f["direct"], render=breakable),
        joined([applicability_label(f["applicability"])]),
    ] for f in ctx["informational"]]
    parts.append(section(
        "Informational vulnerabilities", len(ctx["informational"]),
        table(("Severity", "CVE", "Impacted package", "Fixed in",
               "Direct dependency", "Applicability"), info_rows),
        note="Findings reported outside the configured watches. Not policy "
             "violations, and never blocking.",
        collapsed=True,
    ))

    if ctx["notes"]:
        notes = "".join("<li>%s</li>" % esc(note) for note in ctx["notes"])
        parts.append("<h2>Run notes</h2><ul class='dim'>%s</ul>" % notes)

    parts.append("</main>")
    parts.append("<footer>Generated by analyze_audit.py from "
                 "<code>%s</code>. Exclusions: <code>%s</code>.</footer>"
                 % (esc(ctx["audit_path"]), esc(ctx["exclusions_path"])))

    return ("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
            '<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            "<title>Xray scan report</title>\n<style>%s</style>\n</head>\n<body>\n%s\n"
            "</body>\n</html>\n" % (CSS, "\n".join(p for p in parts if p)))


def write_html(path, markup):
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(markup)
    except OSError as exc:
        print("WARNING: could not write %s: %s" % (path, exc), file=sys.stderr)


def render_error_html(audit_path, exclusions_path, message, details, meta):
    ctx = {
        "meta": meta,
        "audit_path": audit_path,
        "exclusions_path": exclusions_path,
        "today": datetime.datetime.now(datetime.timezone.utc).date(),
        "verdict": {"css": "error", "headline": "XRAY SCAN: ERROR", "detail": message},
        "banners": [{"title": "The scan could not be adjudicated.", "items": details}] if details else [],
        "tiles": [],
        "blocking": [], "excluded": [], "not_applicable": [],
        "licenses": [], "oprisk": [], "informational": [],
        "stale_exclusions": [], "expiring_exclusions": [], "expired_exclusions": [],
        "notes": ["No verdict was produced. Fix the error above and re-run the scan."],
    }
    return render_html(ctx)


# --------------------------------------------------------------------------
# job log summary
# --------------------------------------------------------------------------

IN_GITLAB = bool(os.environ.get("GITLAB_CI"))


def log_section(section_id, header, lines, collapsed=True):
    """Emit a GitLab collapsible log section, or a plain block elsewhere."""
    if not lines:
        return
    if IN_GITLAB:
        flag = "[collapsed=true]" if collapsed else ""
        stamp = int(time.time())
        print("\x1b[0Ksection_start:%d:%s%s\r\x1b[0K%s" % (stamp, section_id, flag, header))
        for line in lines:
            print(line)
        print("\x1b[0Ksection_end:%d:%s\r\x1b[0K" % (int(time.time()), section_id))
    else:
        print("\n%s" % header)
        print("-" * max(len(header), 8))
        for line in lines:
            print(line)


def describe_security(finding, today):
    bits = ["  [%s] %s" % (finding["severity"], finding["package"])]
    if finding["cves"]:
        for cve in finding["cves"]:
            if cve["status"] == EXCLUDED:
                detail = "excluded until %s (%s)" % (cve["exclusion"]["expires_text"],
                                                     cve["exclusion"]["reason"])
                remaining = days_left(cve["exclusion"], today)
                if remaining <= EXPIRY_WARNING_DAYS:
                    detail += " [expires in %d day(s)]" % remaining
            elif cve["status"] == EXPIRED:
                detail = "EXCLUSION EXPIRED %s (%s)" % (cve["exclusion"]["expires_text"],
                                                        cve["exclusion"]["reason"])
            elif cve["status"] == NOT_APPLICABLE:
                detail = "not applicable"
            else:
                detail = "blocking"
            if cve.get("fallback"):
                detail += " [Xray issue id — no CVE published yet]"
            bits.append("      %-18s %s" % (cve["id"], detail))
    else:
        bits.append("      no CVE and no issue id — cannot be excluded")
    if finding["fixed"]:
        bits.append("      fixed in: %s" % ", ".join(finding["fixed"]))
    if finding["direct"]:
        bits.append("      via: %s" % ", ".join(finding["direct"]))
    return bits


def print_summary(ctx):
    today = ctx["today"]

    lines = []
    for finding in ctx["blocking"]:
        lines.extend(describe_security(finding, today))
    for finding in ctx["licenses"]:
        lines.append("  [%s] %s — license %s" % (finding["severity"], finding["package"],
                                                 finding["license"]))
    for finding in ctx["oprisk"]:
        lines.append("  [%s] %s — %s" % (finding["severity"], finding["package"],
                                         finding["risk_reason"]))
    log_section("xray_blocking",
                "Blocking violations (%d)" % ctx["blocking_total"],
                lines, collapsed=False)

    # Expanded, not collapsed, and directly under the blocking violations: these
    # fail the job, so they must be visible without anyone clicking a section.
    stale_lines = ["  %-18s expires %s — %s"
                   % (record["cve"], record["expires_text"], record["reason"])
                   for record in ctx["stale_exclusions"]]
    if stale_lines:
        stale_lines.append("")
        stale_lines.append("  Nothing in this scan matches the entries above. "
                           "Remove them from %s." % EXCLUSIONS_FILENAME)
    log_section("xray_unused_exclusions",
                "Unused exclusions — remove them (%d)" % len(ctx["stale_exclusions"]),
                stale_lines, collapsed=False)

    excluded_lines = []
    for finding in ctx["excluded"]:
        excluded_lines.extend(describe_security(finding, today))
    log_section("xray_excluded", "Excluded by %s (%d)" % (EXCLUSIONS_FILENAME, len(ctx["excluded"])),
                excluded_lines)

    na_lines = []
    for finding in ctx["not_applicable"]:
        na_lines.extend(describe_security(finding, today))
    log_section("xray_not_applicable",
                "Auto-suppressed — not applicable (%d)" % len(ctx["not_applicable"]), na_lines)

    expiry = []
    for record in ctx["expired_exclusions"]:
        expiry.append("  EXPIRED  %-18s on %s, %d day(s) ago — %s"
                      % (record["cve"], record["expires_text"], -record["days_left"],
                         record["reason"]))
    for record in ctx["expiring_exclusions"]:
        expiry.append("  EXPIRING %-18s on %s, in %d day(s) — %s"
                      % (record["cve"], record["expires_text"], record["days_left"],
                         record["reason"]))
    log_section("xray_exclusion_expiry", "Exclusion expiry (%d)" % len(expiry), expiry)

    info_lines = ["  [%s] %s — %s" % (f["severity"], f["package"],
                                      ", ".join(f["cve_ids"]) or f["issue_id"] or "no id")
                  for f in ctx["informational"]]
    log_section("xray_informational",
                "Informational vulnerabilities (%d)" % len(ctx["informational"]), info_lines)

    if ctx["notes"]:
        log_section("xray_notes", "Run notes (%d)" % len(ctx["notes"]),
                    ["  %s" % note for note in ctx["notes"]])

    for banner in ctx["banners"]:
        print("\nWARNING: %s" % banner["title"])
        for item in banner["items"]:
            print("  - %s" % item)

    print("")
    print("=" * 64)
    print("  Security violations : %d blocking, %d excluded, %d not applicable"
          % (len(ctx["blocking"]), len(ctx["excluded"]), len(ctx["not_applicable"])))
    print("  License violations  : %d blocking" % len(ctx["licenses"]))
    print("  Operational risk    : %d blocking" % len(ctx["oprisk"]))
    print("  Unused exclusions   : %d" % len(ctx["stale_exclusions"]))
    print("  Informational       : %d" % len(ctx["informational"]))
    blocking_all = ctx["blocking"] + ctx["licenses"] + ctx["oprisk"]
    if blocking_all:
        breakdown = ", ".join("%s %d" % (sev, n) for sev, n in severity_counts(blocking_all))
        print("  Blocking by severity: %s" % breakdown)
    print("  Report              : %s" % ctx["report_path"])
    print("-" * 64)
    print("  %s" % ctx["verdict"]["headline"])
    print("  %s" % ctx["verdict"]["detail"])
    print("=" * 64)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def run_meta():
    now = datetime.datetime.now(datetime.timezone.utc)
    meta = ["Generated %s UTC" % now.strftime("%Y-%m-%d %H:%M:%S")]
    for label, key in (("project", "CI_PROJECT_PATH"), ("branch", "CI_COMMIT_REF_NAME"),
                       ("commit", "CI_COMMIT_SHORT_SHA"), ("pipeline", "CI_PIPELINE_ID")):
        value = os.environ.get(key)
        if value:
            meta.append("%s %s" % (label, value))
    return meta


def main():
    audit_path = os.environ.get("AUDIT_JSON") or "audit.json"
    report_path = os.environ.get("REPORT_HTML") or "xray_scan_report.html"
    exclusions_path = os.environ.get("XRAY_EXCLUSIONS") or os.path.join(
        os.environ.get("CI_PROJECT_DIR") or os.getcwd(), EXCLUSIONS_FILENAME)
    meta = run_meta()

    try:
        exclusions, notes = load_exclusions(exclusions_path)
        audit = load_audit(audit_path)
        sca_failed, other_failed = scan_status_report(audit)
        if sca_failed:
            raise FatalError(
                "The SCA scan did not complete, so there are no trustworthy "
                "results to adjudicate.",
                sca_failed + ["Re-run the scan. --allow-partial-results cannot "
                              "make up for the scanner that produces the violations."],
            )
    except FatalError as error:
        print("ERROR: %s" % error.message, file=sys.stderr)
        for detail in error.details:
            print("  - %s" % detail, file=sys.stderr)
        write_html(report_path, render_error_html(audit_path, exclusions_path,
                                                  error.message, error.details, meta))
        print("\nXRAY SCAN: ERROR — see %s" % report_path)
        return EXIT_ERROR

    today = datetime.datetime.now(datetime.timezone.utc).date()
    seen_cves = set()

    security = adjudicate_security(as_list(audit.get("securityViolations")),
                                   exclusions, today, seen_cves)
    licenses = sort_findings(adjudicate_licenses(as_list(audit.get("licensesViolations"))))
    oprisk = sort_findings(adjudicate_operational_risk(
        as_list(audit.get("operationalRiskViolations"))))
    informational = sort_findings(collect_informational(
        as_list(audit.get("vulnerabilities")), seen_cves))

    blocking = sort_findings([f for f in security if f["status"] == BLOCKING])
    excluded = sort_findings([f for f in security if f["status"] == EXCLUDED])
    not_applicable = sort_findings([f for f in security if f["status"] == NOT_APPLICABLE])

    stale, expiring, expired = exclusion_audit(exclusions, seen_cves, today)

    banners = []
    if other_failed:
        banners.append({
            "title": "Results are incomplete — %d scanner issue(s) reported. "
                     "The SCA scan itself succeeded, so the verdict below stands."
                     % len(other_failed),
            "items": other_failed,
        })

    blocking_total = len(blocking) + len(licenses) + len(oprisk)

    # Both failure modes are named in the verdict even though only one of them
    # sets the exit code — fixing the violations should not surprise anyone with
    # a second red pipeline they were never told about.
    reasons = []
    if blocking_total:
        reasons.append("%d violation(s) are not covered by a valid exclusion"
                       % blocking_total)
    if stale:
        reasons.append("%d exclusion(s) in %s matched nothing in this scan and "
                       "must be removed" % (len(stale), EXCLUSIONS_FILENAME))

    if reasons:
        verdict = {
            "css": "fail",
            "headline": "XRAY SCAN: FAIL",
            "detail": "%s." % "; ".join(reasons),
        }
    else:
        verdict = {
            "css": "pass",
            "headline": "XRAY SCAN: PASS",
            "detail": "No violations outside of %d valid exclusion(s) and %d "
                      "not-applicable finding(s)." % (len(excluded), len(not_applicable)),
        }

    ctx = {
        "meta": meta,
        "audit_path": audit_path,
        "exclusions_path": exclusions_path,
        "report_path": report_path,
        "today": today,
        "verdict": verdict,
        "banners": banners,
        "tiles": [
            ("blocking", blocking_total),
            ("unused exclusions", len(stale)),
            ("excluded", len(excluded)),
            ("not applicable", len(not_applicable)),
            ("licenses", len(licenses)),
            ("operational risk", len(oprisk)),
            ("informational", len(informational)),
        ],
        "blocking": blocking,
        "blocking_total": blocking_total,
        "excluded": excluded,
        "not_applicable": not_applicable,
        "licenses": licenses,
        "oprisk": oprisk,
        "informational": informational,
        "stale_exclusions": stale,
        "expiring_exclusions": expiring,
        "expired_exclusions": expired,
        "notes": notes,
    }

    write_html(report_path, render_html(ctx))
    print_summary(ctx)

    if blocking_total:
        return EXIT_BLOCKED
    if stale:
        return EXIT_UNUSED_EXCLUSIONS
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
