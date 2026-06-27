#!/usr/bin/env python3
"""Create a safe account inventory from a Firefox exported logins CSV.

Firefox's export includes a plaintext `password` column. This script reads it only
as an input field name to ignore: password values are never written to CSV,
Markdown, logs, or stdout.
"""

from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from publicsuffix2 import get_sld

PASSWORD_FIELD_NAMES = {"password"}
DOMAIN_FIELD_CANDIDATES = ("url", "formActionOrigin", "httpRealm", "hostname", "origin")
TIME_FIELDS = ("timeCreated", "timeLastUsed", "timePasswordChanged")
DOMAIN_LIKE_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.I)


@dataclass
class LoginEvidence:
    service_domain: str
    username: str
    login_count: int = 0
    source_fields: set[str] = field(default_factory=set)
    url_hosts: set[str] = field(default_factory=set)
    urls_seen: int = 0
    time_created: list[datetime] = field(default_factory=list)
    time_last_used: list[datetime] = field(default_factory=list)
    time_password_changed: list[datetime] = field(default_factory=list)

    def confidence(self) -> int:
        score = 70
        if self.username:
            score += 10
        if self.source_fields & {"url", "formActionOrigin"}:
            score += 10
        if self.time_created or self.time_last_used or self.time_password_changed:
            score += 5
        if self.login_count > 1:
            score += 5
        return min(100, score)


def normalize_domain(value: str | None) -> str:
    if not value:
        return ""
    d = value.lower().strip().strip(".>")
    if d.startswith("www."):
        d = d[4:]
    try:
        return get_sld(d) or d
    except Exception:
        return d


def host_from_value(value: str | None) -> str:
    """Extract a normalized host from a URL, origin, realm, or domain-ish value."""
    if not value:
        return ""
    text = value.strip()
    if not text:
        return ""

    parsed = urlparse(text)
    host = parsed.hostname
    if not host and "://" not in text:
        parsed = urlparse(f"https://{text}")
        host = parsed.hostname
    if not host:
        match = DOMAIN_LIKE_RE.search(text)
        host = match.group(0) if match else ""
    return normalize_domain(host)


def parse_firefox_time(value: str | None) -> datetime | None:
    """Parse Firefox-exported ISO timestamps and common epoch variants."""
    if not value:
        return None
    text = value.strip()
    if not text:
        return None

    if text.isdigit():
        raw = int(text)
        # Firefox internals often use microseconds, JS APIs milliseconds. CSV
        # exports are usually ISO, but accepting all three makes imports safer.
        if raw > 10_000_000_000_000:
            raw = raw / 1_000_000
        elif raw > 10_000_000_000:
            raw = raw / 1_000
        try:
            return datetime.fromtimestamp(raw, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None

    candidate = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(candidate)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def choose_service_domain(row: dict[str, str]) -> tuple[str, set[str]]:
    sources: set[str] = set()
    first_domain = ""
    for field_name in DOMAIN_FIELD_CANDIDATES:
        domain = host_from_value(row.get(field_name))
        if not domain:
            continue
        sources.add(field_name)
        if not first_domain:
            first_domain = domain
    return first_domain or "unknown", sources


def audit_firefox_csv(path: Path) -> dict[tuple[str, str], LoginEvidence]:
    results: dict[tuple[str, str], LoginEvidence] = {}
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV has no header row")

        lowered = {name.lower() for name in reader.fieldnames}
        if lowered & PASSWORD_FIELD_NAMES:
            # Deliberately no value access/logging. Presence only documents that
            # this is a normal Firefox export and that the field was ignored.
            pass

        for row in reader:
            domain, sources = choose_service_domain(row)
            username = (row.get("username") or row.get("user") or row.get("login") or "").strip()
            key = (domain, username)
            ev = results.setdefault(key, LoginEvidence(service_domain=domain, username=username))
            ev.login_count += 1
            ev.source_fields.update(sources)
            for field_name in DOMAIN_FIELD_CANDIDATES:
                host = host_from_value(row.get(field_name))
                if host:
                    ev.url_hosts.add(host)
            ev.urls_seen = len(ev.url_hosts)

            for field_name in TIME_FIELDS:
                dt = parse_firefox_time(row.get(field_name))
                if not dt:
                    continue
                if field_name == "timeCreated":
                    ev.time_created.append(dt)
                elif field_name == "timeLastUsed":
                    ev.time_last_used.append(dt)
                elif field_name == "timePasswordChanged":
                    ev.time_password_changed.append(dt)
    return results


def iso_date(dt: datetime | None) -> str:
    return dt.date().isoformat() if dt else ""


def rows(results: dict[tuple[str, str], LoginEvidence]) -> list[dict[str, str | int]]:
    out: list[dict[str, str | int]] = []
    for ev in results.values():
        created = sorted(ev.time_created)
        last_used = sorted(ev.time_last_used)
        changed = sorted(ev.time_password_changed)
        out.append({
            "service_domain": ev.service_domain,
            "username": ev.username,
            "confidence": ev.confidence(),
            "evidence_source": "firefox_logins_csv",
            "login_count": ev.login_count,
            "url_count": ev.urls_seen,
            "source_fields": ";".join(sorted(ev.source_fields)),
            "first_seen": iso_date(created[0]) if created else "",
            "last_used": iso_date(last_used[-1]) if last_used else "",
            "password_changed": iso_date(changed[-1]) if changed else "",
            "related_domains": ";".join(sorted(ev.url_hosts)[:20]),
        })
    return sorted(out, key=lambda r: (str(r["service_domain"]), str(r["username"])))


def fieldnames() -> list[str]:
    return [
        "service_domain", "username", "confidence", "evidence_source", "login_count",
        "url_count", "source_fields", "first_seen", "last_used", "password_changed",
        "related_domains",
    ]


def write_csv(path: Path, data: list[dict[str, str | int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames())
        writer.writeheader()
        writer.writerows(data)


def _md_cell(value: object) -> str:
    return str(value).replace("|", "\\|")


def write_markdown(path: Path, data: list[dict[str, str | int]], top: int = 200) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Firefox saved-login inventory",
        "",
        "Generated locally from a Firefox logins CSV export. Password values were ignored and are not present in this report.",
        "",
        "| service | username | confidence | first | last used | password changed | count | source fields |",
        "|---|---|---:|---|---|---|---:|---|",
    ]
    for r in data[:top]:
        lines.append(
            f"| `{_md_cell(r['service_domain'])}` | {_md_cell(r['username'])} | {r['confidence']} | "
            f"{r['first_seen']} | {r['last_used']} | {r['password_changed']} | {r['login_count']} | {_md_cell(r['source_fields'])} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csv", type=Path, help="Path to Firefox exported logins CSV")
    ap.add_argument("--out", type=Path, default=Path("reports/firefox-logins.csv"), help="Safe CSV inventory output path")
    ap.add_argument("--markdown", type=Path, help="Optional Markdown output path")
    args = ap.parse_args()

    if not args.csv.exists():
        ap.error(f"CSV does not exist: {args.csv}")

    data = rows(audit_firefox_csv(args.csv))
    write_csv(args.out, data)
    if args.markdown:
        write_markdown(args.markdown, data)
    print(f"wrote {len(data)} Firefox login inventory rows to {args.out}")
    if args.markdown:
        print(f"wrote markdown report to {args.markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
