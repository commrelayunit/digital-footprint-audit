#!/usr/bin/env python3
"""Create a local, evidence-linked public digital-footprint report.

This script is deliberately conservative: it queries only the identifiers the
operator enters, makes no login or account-existence attempts, and stores no
credentials. It is an evidence collector, not an identity-proof system.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


USER_AGENT = "digital-footprint-audit/0.1 (local personal audit)"
CLAIMED_STATUSES = {"claimed", "found"}
URL_LINE = re.compile(r"^https?://\S+$")


@dataclass
class Finding:
    query_type: str
    query: str
    source: str
    finding_type: str
    status: str
    confidence: str
    title: str
    url: str
    evidence: str


def get_json(url: str, headers: dict[str, str] | None = None) -> tuple[int, Any]:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    request_headers.update(headers or {})
    request = Request(url, headers=request_headers)
    try:
        with urlopen(request, timeout=20) as response:
            return response.status, json.load(response)
    except HTTPError as exc:
        if exc.code == 404:
            return 404, None
        if exc.code == 404:
            return 404, None
        raise RuntimeError(f"HTTP {exc.code} from {url}") from exc
    except URLError as exc:
        raise RuntimeError(f"Network error for {url}: {exc.reason}") from exc


def github_username(username: str) -> list[Finding]:
    status, data = get_json(f"https://api.github.com/users/{quote(username)}")
    if status == 404:
        return [Finding("username", username, "GitHub", "profile", "no_match", "high", "", "", "No public GitHub user with this exact handle.")]
    return [Finding(
        "username", username, "GitHub", "profile", "candidate", "high",
        data.get("login", username), data.get("html_url", ""),
        f"Public profile; name={data.get('name') or ''}; followers={data.get('followers', '')}",
    )]


def github_name(full_name: str) -> list[Finding]:
    status, data = get_json(f"https://api.github.com/search/users?q={quote(full_name)}&per_page=10")
    if status != 200 or not data.get("items"):
        return [Finding("name", full_name, "GitHub", "profile_search", "no_match", "low", "", "", "No public GitHub user-search results.")]
    return [Finding("name", full_name, "GitHub", "profile_search", "candidate", "low", item.get("login", ""), item.get("html_url", ""), "Name search only; manually confirm identity.") for item in data["items"]]


def openalex_name(full_name: str) -> list[Finding]:
    status, data = get_json(f"https://api.openalex.org/authors?search={quote(full_name)}&per-page=10")
    if status != 200 or not data.get("results"):
        return [Finding("name", full_name, "OpenAlex", "author_search", "no_match", "low", "", "", "No public author results.")]
    findings: list[Finding] = []
    for item in data["results"]:
        works = item.get("works_count", 0)
        institutions = item.get("last_known_institutions") or []
        institution = ", ".join(x.get("display_name", "") for x in institutions[:2])
        findings.append(Finding("name", full_name, "OpenAlex", "author_search", "candidate", "low", item.get("display_name", ""), item.get("id", ""), f"works={works}; institution={institution}. Manually confirm identity."))
    return findings


def hibp_email(email: str, api_key: str | None) -> list[Finding]:
    if not api_key:
        return [Finding("email", email, "Have I Been Pwned", "breach_check", "not_run", "", "", "https://haveibeenpwned.com/API/v3", "Set HAVE_I_BEEN_PWNED_API_KEY to enable; the email was not sent to Have I Been Pwned.")]
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false"
    try:
        status, data = get_json(url, {"hibp-api-key": api_key})
    except RuntimeError as exc:
        return [Finding("email", email, "Have I Been Pwned", "breach_check", "error", "", "", "", str(exc))]
    if status == 404:
        return [Finding("email", email, "Have I Been Pwned", "breach_check", "no_match", "high", "", "", "No breach records returned by Have I Been Pwned.")]
    return [Finding("email", email, "Have I Been Pwned", "breach", "confirmed", "high", breach.get("Name", ""), breach.get("Domain", ""), f"breach_date={breach.get('BreachDate', '')}; data_classes={';'.join(breach.get('DataClasses', []))}") for breach in data]


def mailaccess_report(report_path: Path) -> list[Finding]:
    """Import a *local* MailAccess JSON export without invoking MailAccess.

    MailAccess queries many public services when it runs. Keeping it as a
    report import makes that separate, explicit, and auditable; every imported
    item remains a candidate rather than an identity or account-existence fact.
    """
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [Finding("email", "", "MailAccess", "report_import", "error", "", "", "", f"Could not read local report {report_path.name}: {exc}")]
    except json.JSONDecodeError as exc:
        return [Finding("email", "", "MailAccess", "report_import", "error", "", "", "", f"Could not parse local report {report_path.name}: {exc}")]

    if not isinstance(report, dict):
        return [Finding("email", "", "MailAccess", "report_import", "error", "", "", "", f"Local report {report_path.name} is not a JSON object.")]

    email = str(report.get("email") or "")
    report_id = str(report.get("id") or report.get("investigation_id") or "unknown")
    # ``findings`` is MailAccess's run summary.  It records that a module ran,
    # often several times, but is not the evidence payload.  The export's
    # ``findings_by_module`` contains the actual normalized results.
    findings_by_module = report.get("findings_by_module")
    top_level_findings = report.get("findings")
    if not isinstance(findings_by_module, dict) and not isinstance(top_level_findings, list):
        return [Finding("email", email, "MailAccess", "report_import", "error", "", "", "", f"Local report {report_path.name} has no findings data.")]

    source_items: list[tuple[str, dict[str, Any]]] = []
    if isinstance(findings_by_module, dict):
        for module, items in findings_by_module.items():
            if isinstance(items, list):
                source_items.extend((str(module), item) for item in items if isinstance(item, dict))
    else:
        # Compatibility with small/older exports.  Do not import a row which
        # only says a module was executed.
        source_items = [
            (str(item.get("module") or item.get("source") or item.get("module_name") or "MailAccess"), item)
            for item in top_level_findings if isinstance(item, dict)
        ]

    imported: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    for module, item in source_items:
        # Older exports flatten evidence into a top-level ``data`` object;
        # current ``findings_by_module`` exports place it directly on the row.
        payload = item.get("data") if isinstance(item.get("data"), dict) else item
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        url = _mailaccess_url(payload, metadata)
        title = _mailaccess_title(payload, metadata, module)
        detail = _mailaccess_detail(payload, metadata)
        # Summary rows have no source, identity, or evidence.  Suppressing
        # them is preferable to presenting a page of false leads.
        if not (url or detail):
            continue
        signature = (module, title, url, detail)
        if signature in seen:
            continue
        seen.add(signature)
        evidence = detail[:500]
        evidence += f". MailAccess module={module}; investigation={report_id}; review manually."
        imported.append(Finding("email", email, "MailAccess", f"mailaccess/{module}", "candidate", "low", title, url, evidence))

    return imported or [Finding("email", email, "MailAccess", "report_import", "no_match", "", "", "", f"Local report {report_path.name} contained no importable findings; investigation={report_id}.")]


def _mailaccess_url(item: dict[str, Any], metadata: dict[str, Any]) -> str:
    """Select an evidence URL from MailAccess's current and legacy schemas."""
    for container in (item, metadata):
        for key in ("profile_url", "url", "link", "source_url", "photo_url", "html_url"):
            value = container.get(key)
            if isinstance(value, str) and value.startswith(("https://", "http://")):
                return value
    return ""


def _mailaccess_title(item: dict[str, Any], metadata: dict[str, Any], module: str) -> str:
    platform = ""
    for container in (item, metadata):
        for key in ("title", "platform", "name", "display_name", "signal_type", "type"):
            value = container.get(key)
            if isinstance(value, str) and value.strip():
                platform = value.strip()
                break
        if platform:
            break
    identity = str(metadata.get("username") or metadata.get("display_name") or item.get("username") or "").strip()
    label = platform or module.replace("_", " ")
    label = label.replace("_", " ").title()
    label = label.replace("Github", "GitHub").replace("Gravatar", "Gravatar")
    return f"{label}: {identity}" if identity else label


def _mailaccess_detail(item: dict[str, Any], metadata: dict[str, Any]) -> str:
    """Keep compact, human-reviewable evidence while omitting run bookkeeping."""
    fields: list[str] = []
    for container in (item, metadata):
        for key in ("evidence", "detail", "description", "value", "signal_type", "username", "display_name", "breach_name", "source", "status", "severity", "confidence"):
            value = container.get(key)
            if isinstance(value, (str, int, float)) and str(value).strip():
                rendered = f"{key}={value}"
                if rendered not in fields:
                    fields.append(rendered)
    return "; ".join(fields[:8])


def search_links(query_type: str, query: str) -> list[Finding]:
    quoted = quote(f'"{query}"')
    return [
        Finding(query_type, query, "web search", "manual_search", "review", "", "Google exact search", f"https://www.google.com/search?q={quoted}", "Open manually; not queried by this tool."),
        Finding(query_type, query, "web search", "manual_search", "review", "", "Bing exact search", f"https://www.bing.com/search?q={quoted}", "Open manually; not queried by this tool."),
        Finding(query_type, query, "Common Crawl", "manual_search", "review", "", "Common Crawl Index", f"https://index.commoncrawl.org/", "Search manually to avoid broad, unbounded crawling."),
    ]


def collector_missing(username: str, collector: str, executable: str) -> Finding:
    return Finding(
        "username", username, collector, "username_scan", "not_run", "", "", "",
        f"{executable} is not installed or not on PATH. Install project requirements first.",
    )


def maigret_username(username: str, raw_dir: Path, top_sites: int, timeout: int) -> list[Finding]:
    """Run Maigret and retain its simple JSON report as auditable local evidence."""
    if not shutil.which("maigret"):
        return [collector_missing(username, "Maigret", "maigret")]
    output_dir = raw_dir / "maigret"
    output_dir.mkdir(parents=True, exist_ok=True)
    command = [
        "maigret", username, "--top-sites", str(top_sites), "--timeout", str(timeout),
        "--no-recursion", "--no-extracting", "--no-autoupdate", "--no-progressbar",
        "--json", "simple", "--folderoutput", str(output_dir),
    ]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    report = output_dir / f"report_{username}_simple.json"
    if completed.returncode or not report.exists():
        detail = (completed.stderr or completed.stdout or "Maigret produced no report.").strip().replace("\n", " ")[:500]
        return [Finding("username", username, "Maigret", "username_scan", "error", "", "", "", detail)]
    try:
        results = json.loads(report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [Finding("username", username, "Maigret", "username_scan", "error", "", "", "", f"Could not parse {report.name}: {exc}")]
    findings: list[Finding] = []
    for site_name, result in results.items():
        status = str(result.get("status", {}).get("status", "")).lower()
        if status not in CLAIMED_STATUSES:
            continue
        profile_url = result.get("url_user") or result.get("status", {}).get("url", "")
        findings.append(Finding(
            "username", username, "Maigret", "profile", "candidate", "medium",
            str(site_name), str(profile_url),
            f"Maigret status={status}; http_status={result.get('http_status', '')}; raw=maigret/{report.name}",
        ))
    return findings or [Finding("username", username, "Maigret", "username_scan", "no_match", "", "", "", f"No claimed profiles among the top {top_sites} sites; raw=maigret/{report.name}.")]


def sherlock_username(username: str, raw_dir: Path, timeout: int, sites: list[str]) -> list[Finding]:
    """Run Sherlock and normalize its URL-only current CSV output."""
    if not shutil.which("sherlock"):
        return [collector_missing(username, "Sherlock", "sherlock")]
    output_dir = raw_dir / "sherlock"
    output_dir.mkdir(parents=True, exist_ok=True)
    report = output_dir / f"{username}.csv"
    command = ["sherlock", username, "--csv", "--output", str(report), "--timeout", str(timeout), "--no-color"]
    for site in sites:
        command.extend(["--site", site])
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode or not report.exists():
        detail = (completed.stderr or completed.stdout or "Sherlock produced no report.").strip().replace("\n", " ")[:500]
        return [Finding("username", username, "Sherlock", "username_scan", "error", "", "", "", detail)]
    urls = [line.strip() for line in report.read_text(encoding="utf-8", errors="replace").splitlines() if URL_LINE.match(line.strip())]
    findings = [Finding("username", username, "Sherlock", "profile", "candidate", "medium", url.split("/")[2], url, f"Sherlock reported profile URL; raw=sherlock/{report.name}") for url in urls]
    return findings or [Finding("username", username, "Sherlock", "username_scan", "no_match", "", "", "", f"No profile URLs reported; raw=sherlock/{report.name}.")]


def prompt_values(label: str) -> list[str]:
    raw = input(f"{label} (comma-separated; blank to skip): ").strip()
    return [value.strip() for value in raw.split(",") if value.strip()]


def write_csv(path: Path, findings: list[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(Finding.__annotations__)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(asdict(finding) for finding in findings)


def write_markdown(path: Path, findings: list[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Public digital-footprint report", "", "Candidate matches require human review. This report contains public evidence links and no credentials.", "", "| query | source | status | confidence | title | evidence |", "|---|---|---|---|---|---|"]
    for finding in findings:
        title = f"[{finding.title}]({finding.url})" if finding.url and finding.title else finding.title
        evidence = finding.evidence.replace("|", "\\|")
        lines.append(f"| `{finding.query}` | {finding.source} | {finding.status} | {finding.confidence} | {title} | {evidence} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", action="append", default=[], help="Known username; repeatable")
    parser.add_argument("--name", action="append", default=[], help="Full name; repeatable")
    parser.add_argument("--email", action="append", default=[], help="Email to check with Have I Been Pwned when configured; repeatable")
    parser.add_argument("--interactive", action="store_true", help="Prompt for identifiers")
    parser.add_argument("--maigret", action="store_true", help="Run Maigret username scanning (makes requests to third-party services)")
    parser.add_argument("--sherlock", action="store_true", help="Run Sherlock as an additional username verifier (many third-party requests)")
    parser.add_argument("--mailaccess-report", type=Path, action="append", default=[], help="Import an existing local MailAccess JSON export; does not invoke MailAccess or make requests")
    parser.add_argument("--sherlock-site", action="append", default=[], help="Restrict Sherlock to a site; repeatable")
    parser.add_argument("--maigret-top-sites", type=int, default=500, help="Maigret scope when --maigret is enabled (default: 500)")
    parser.add_argument("--scan-timeout", type=int, default=20, help="Per-site timeout for Maigret/Sherlock, in seconds (default: 20)")
    parser.add_argument("--out", type=Path, default=Path("reports/public-exposure.csv"))
    parser.add_argument("--markdown", type=Path, default=Path("reports/public-exposure.md"))
    args = parser.parse_args()
    usernames, names, emails = args.username, args.name, args.email
    if args.interactive:
        usernames += prompt_values("Usernames")
        names += prompt_values("Full names")
        emails += prompt_values("Emails")
    if not any((usernames, names, emails, args.mailaccess_report)):
        parser.error("provide an identifier, --mailaccess-report, or use --interactive")

    findings: list[Finding] = []
    raw_dir = args.out.parent / "raw"
    for username in sorted(set(usernames)):
        findings += github_username(username) + search_links("username", username)
        if args.maigret:
            findings += maigret_username(username, raw_dir, args.maigret_top_sites, args.scan_timeout)
        if args.sherlock:
            findings += sherlock_username(username, raw_dir, args.scan_timeout, args.sherlock_site)
    for name in sorted(set(names)):
        findings += github_name(name) + openalex_name(name) + search_links("name", name)
    api_key = os.environ.get("HAVE_I_BEEN_PWNED_API_KEY") or os.environ.get("HIBP_API_KEY")
    for email in sorted(set(emails)):
        findings += hibp_email(email, api_key) + search_links("email", email)
    for report_path in args.mailaccess_report:
        findings += mailaccess_report(report_path)
    write_csv(args.out, findings)
    write_markdown(args.markdown, findings)
    print(f"Wrote {len(findings)} findings to {args.out} and {args.markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
