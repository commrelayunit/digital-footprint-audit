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
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


USER_AGENT = "digital-footprint-audit/0.1 (local personal audit)"


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
        return [Finding("email", email, "Have I Been Pwned", "breach_check", "not_run", "", "", "https://haveibeenpwned.com/API/v3", "Set HIBP_API_KEY to enable; the email was not sent to HIBP.")]
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false"
    try:
        status, data = get_json(url, {"hibp-api-key": api_key})
    except RuntimeError as exc:
        return [Finding("email", email, "Have I Been Pwned", "breach_check", "error", "", "", "", str(exc))]
    if status == 404:
        return [Finding("email", email, "Have I Been Pwned", "breach_check", "no_match", "high", "", "", "No breach records returned by HIBP.")]
    return [Finding("email", email, "Have I Been Pwned", "breach", "confirmed", "high", breach.get("Name", ""), breach.get("Domain", ""), f"breach_date={breach.get('BreachDate', '')}; data_classes={';'.join(breach.get('DataClasses', []))}") for breach in data]


def search_links(query_type: str, query: str) -> list[Finding]:
    quoted = quote(f'"{query}"')
    return [
        Finding(query_type, query, "web search", "manual_search", "review", "", "Google exact search", f"https://www.google.com/search?q={quoted}", "Open manually; not queried by this tool."),
        Finding(query_type, query, "web search", "manual_search", "review", "", "Bing exact search", f"https://www.bing.com/search?q={quoted}", "Open manually; not queried by this tool."),
        Finding(query_type, query, "Common Crawl", "manual_search", "review", "", "Common Crawl Index", f"https://index.commoncrawl.org/", "Search manually to avoid broad, unbounded crawling."),
    ]


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
    parser.add_argument("--email", action="append", default=[], help="Email to check with HIBP when configured; repeatable")
    parser.add_argument("--interactive", action="store_true", help="Prompt for identifiers")
    parser.add_argument("--out", type=Path, default=Path("reports/public-exposure.csv"))
    parser.add_argument("--markdown", type=Path, default=Path("reports/public-exposure.md"))
    args = parser.parse_args()
    usernames, names, emails = args.username, args.name, args.email
    if args.interactive:
        usernames += prompt_values("Usernames")
        names += prompt_values("Full names")
        emails += prompt_values("Emails")
    if not any((usernames, names, emails)):
        parser.error("provide an identifier or use --interactive")

    findings: list[Finding] = []
    for username in sorted(set(usernames)):
        findings += github_username(username) + search_links("username", username)
    for name in sorted(set(names)):
        findings += github_name(name) + openalex_name(name) + search_links("name", name)
    api_key = os.environ.get("HIBP_API_KEY")
    for email in sorted(set(emails)):
        findings += hibp_email(email, api_key) + search_links("email", email)
    write_csv(args.out, findings)
    write_markdown(args.markdown, findings)
    print(f"Wrote {len(findings)} findings to {args.out} and {args.markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
