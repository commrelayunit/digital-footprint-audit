#!/usr/bin/env python3
"""Recheck URLs already present in a public-exposure CSV.

This is a conservative post-processing tool.  It does not discover new URLs,
log in, send cookies, or verify that a profile belongs to a person.  It only
removes clear HTTP 404/410 results from the retained CSV; every other outcome
is kept with an explicit disposition for human review.
"""

from __future__ import annotations

import argparse
import csv
import html
import re
import socket
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


TOOL_VERSION = "0.1.1"
USER_AGENT = f"digital-footprint-audit/{TOOL_VERSION} (local URL verification; no auth)"
MAX_BODY_BYTES = 65_536
SOFT_404_PATTERNS = (
    "page not found", "profile not found", "user not found", "account not found",
    "this page doesn't exist", "this page does not exist", "404 not found",
    "error 404", "sorry, this page", "content unavailable",
)
CAPTCHA_PATTERNS = ("captcha", "verify you are human", "verify you're human", "challenge-platform")


@dataclass
class Check:
    original_url: str
    final_url: str
    http_status: str
    disposition: str
    reason: str
    source: str
    query: str


def page_text(data: bytes) -> str:
    """Return a small, normalized text sample without attempting full parsing."""
    return html.unescape(data.decode("utf-8", errors="replace")).lower()


def classify_response(status: int, original_url: str, final_url: str, body: bytes) -> tuple[str, str]:
    """Classify HTTP evidence without claiming that a profile is genuine."""
    if status in {404, 410}:
        return "excluded_dead", f"HTTP {status}: clear missing/gone response."
    if status in {401, 403, 429}:
        return "ambiguous", f"HTTP {status}: access blocked or rate-limited; not evidence of a profile."
    text = page_text(body)
    if any(marker in text for marker in CAPTCHA_PATTERNS):
        return "ambiguous", "CAPTCHA or bot-check page; not evidence of a profile."
    if 200 <= status < 300 and any(marker in text for marker in SOFT_404_PATTERNS):
        return "ambiguous", "HTTP success response contains a missing/error-page marker (possible soft 404)."
    if original_url != final_url:
        return "ambiguous", f"Redirected to {final_url}; manually confirm the destination."
    if 200 <= status < 300:
        return "ambiguous", f"HTTP {status}: URL responded, but HTTP cannot verify account ownership."
    if 300 <= status < 400:
        return "ambiguous", f"HTTP {status}: redirect response could not be resolved conclusively."
    return "error", f"HTTP {status}: unexpected server/client response; retry or inspect manually."


def check_url(url: str, timeout: float) -> Check:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"})
    try:
        with urlopen(request, timeout=timeout) as response:
            final_url = response.geturl()
            body = response.read(MAX_BODY_BYTES)
            disposition, reason = classify_response(response.status, url, final_url, body)
            return Check(url, final_url, str(response.status), disposition, reason, "", "")
    except HTTPError as exc:
        body = exc.read(MAX_BODY_BYTES)
        final_url = exc.geturl() or url
        disposition, reason = classify_response(exc.code, url, final_url, body)
        return Check(url, final_url, str(exc.code), disposition, reason, "", "")
    except (URLError, socket.timeout, TimeoutError) as exc:
        return Check(url, "", "", "error", f"Network/timeout error: {exc.reason if isinstance(exc, URLError) else exc}", "", "")
    except ValueError as exc:
        return Check(url, "", "", "error", f"Invalid URL: {exc}", "", "")


def is_http_url(value: str) -> bool:
    return value.startswith("https://") or value.startswith("http://")


def should_check(row: dict[str, str], all_urls: bool) -> bool:
    if not is_http_url(row.get("url", "")):
        return False
    return all_urls or row.get("source", "") in {"Maigret", "Sherlock"}


def write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, checks: list[Check]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Public-exposure URL verification", "",
        "Only clear HTTP 404/410 results are excluded from the retained CSV. All other responses remain ambiguous or errors; a successful response does not prove account ownership.", "",
        "| source | original URL | final URL | HTTP | disposition | reason |",
        "|---|---|---|---:|---|---|",
    ]
    for item in checks:
        def link(url: str) -> str:
            return f"<{url}>" if url else ""
        reason = item.reason.replace("|", "\\|")
        lines.append(f"| {item.source} | {link(item.original_url)} | {link(item.final_url)} | {item.http_status} | {item.disposition} | {reason} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Existing public-exposure CSV to read (never overwritten).")
    parser.add_argument("--out", type=Path, default=Path("reports/public-exposure-retained.csv"), help="Retained CSV (default: reports/public-exposure-retained.csv).")
    parser.add_argument("--audit", type=Path, default=Path("reports/public-exposure-url-audit.csv"), help="All URL checks, including excluded URLs.")
    parser.add_argument("--markdown", type=Path, default=Path("reports/public-exposure-url-audit.md"), help="Human-readable audit report.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-URL timeout in seconds (default: 10).")
    parser.add_argument("--all-urls", action="store_true", help="Also check non-Maigret/Sherlock HTTP URLs; default checks only those collector results.")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if not args.input.is_file():
        parser.error(f"input CSV does not exist: {args.input}")
    if args.input.resolve() in {args.out.resolve(), args.audit.resolve()}:
        parser.error("output paths must differ from the input CSV")

    with args.input.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "url" not in reader.fieldnames:
            parser.error("input CSV must have a 'url' column")
        fields = list(reader.fieldnames)
        input_rows = list(reader)

    checks: list[Check] = []
    retained: list[dict[str, str]] = []
    for row in input_rows:
        if not should_check(row, args.all_urls):
            retained.append(row)
            continue
        checked = check_url(row["url"], args.timeout)
        checked.source = row.get("source", "")
        checked.query = row.get("query", "")
        checks.append(checked)
        if checked.disposition != "excluded_dead":
            retained.append(row)

    audit_rows = [asdict(item) for item in checks]
    write_csv(args.out, fields, retained)
    write_csv(args.audit, list(Check.__annotations__), audit_rows)
    write_markdown(args.markdown, checks)
    excluded = sum(item.disposition == "excluded_dead" for item in checks)
    print(f"Checked {len(checks)} URLs; excluded {excluded} clear 404/410 URLs; retained {len(retained)} input rows.")
    print(f"Retained: {args.out}\nAudit CSV: {args.audit}\nAudit Markdown: {args.markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
