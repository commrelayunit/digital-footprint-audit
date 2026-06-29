#!/usr/bin/env python3
"""Discover likely online accounts from a local mbox export.

This is heuristic evidence gathering, not proof that an account still exists.
It intentionally avoids attachments and never sends data over the network.
"""

from __future__ import annotations

import argparse
import csv
import html
import mailbox
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

from bs4 import BeautifulSoup
from publicsuffix2 import get_sld

PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "welcome": [
        re.compile(r"\bwelcome to\b", re.I),
        re.compile(r"\bthanks for signing up\b", re.I),
        re.compile(r"\bgetting started with\b", re.I),
        re.compile(r"\byour new account\b", re.I),
    ],
    "verify": [
        re.compile(r"\bverify (your )?(email|e-mail|account)\b", re.I),
        re.compile(r"\bconfirm (your )?(email|e-mail|account)\b", re.I),
        re.compile(r"\bactivate your account\b", re.I),
        re.compile(r"\bcomplete your registration\b", re.I),
    ],
    "password": [
        re.compile(r"\breset your password\b", re.I),
        re.compile(r"\bpassword reset\b", re.I),
        re.compile(r"\bchanged your password\b", re.I),
        re.compile(r"\bpassword (has been )?changed\b", re.I),
    ],
    "login_security": [
        re.compile(r"\bnew (sign[- ]?in|login)\b", re.I),
        re.compile(r"\bsign[- ]?in alert\b", re.I),
        re.compile(r"\blogin code\b", re.I),
        re.compile(r"\bsecurity alert\b", re.I),
        re.compile(r"\bnew device\b", re.I),
    ],
    "billing": [
        re.compile(r"\binvoice\b", re.I),
        re.compile(r"\breceipt\b", re.I),
        re.compile(r"\bsubscription\b", re.I),
        re.compile(r"\bpayment (successful|received|failed)\b", re.I),
        re.compile(r"\btrial (started|ending|expired)\b", re.I),
    ],
    "closure_export": [
        re.compile(r"\baccount (deleted|closed|deactivated)\b", re.I),
        re.compile(r"\bdelete your account\b", re.I),
        re.compile(r"\byour data export\b", re.I),
        re.compile(r"\bcancellation confirmed\b", re.I),
    ],
}

NOISY_DOMAINS = {
    "google.com", "gmail.com", "calendar.google.com", "mail.google.com",
    "youtube.com", "facebookmail.com", "mailchimp.com", "sendgrid.net",
    "amazonses.com", "mandrillapp.com", "sparkpostmail.com",
}

# Gmail Takeout writes system labels into X-Gmail-Labels. These messages are
# useful for completeness but often include phishing/noise, so callers can skip
# them by default and rerun with --include-spam-trash if they want full coverage.
SPAM_TRASH_LABELS = {"spam", "trash", "bin"}

URL_RE = re.compile(r"https?://[^\s<>'\"\)]+", re.I)

@dataclass
class ServiceEvidence:
    service_domain: str
    evidence_types: set[str] = field(default_factory=set)
    sender_domains: set[str] = field(default_factory=set)
    linked_domains: set[str] = field(default_factory=set)
    gmail_labels: set[str] = field(default_factory=set)
    malformed_urls: set[str] = field(default_factory=set)
    dates: list[datetime] = field(default_factory=list)
    subjects: list[str] = field(default_factory=list)
    count: int = 0

    def confidence(self) -> int:
        score = 0
        weights = {
            "welcome": 28,
            "verify": 30,
            "password": 24,
            "login_security": 22,
            "billing": 20,
            "closure_export": 12,
        }
        for t in self.evidence_types:
            score += weights.get(t, 8)
        score += min(self.count, 10) * 2
        if len(self.evidence_types) >= 2:
            score += 10
        if "welcome" in self.evidence_types and "verify" in self.evidence_types:
            score += 10
        if self.service_domain in NOISY_DOMAINS:
            score -= 20
        if {label.lower() for label in self.gmail_labels} & SPAM_TRASH_LABELS:
            score -= 10
        return max(0, min(100, score))


def decode_mime(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def normalize_domain(domain: str | None) -> str:
    if not domain:
        return ""
    d = domain.lower().strip().strip(".>")
    if d.startswith("www."):
        d = d[4:]
    try:
        sld = get_sld(d)
        return sld or d
    except Exception:
        return d


def sender_domains(msg: Message) -> set[str]:
    domains: set[str] = set()
    for _, addr in getaddresses([msg.get("from", ""), msg.get("reply-to", "")]):
        if "@" in addr:
            domains.add(normalize_domain(addr.rsplit("@", 1)[1]))
    return {d for d in domains if d}


def gmail_labels(msg: Message) -> set[str]:
    """Return normalized Gmail Takeout labels from X-Gmail-Labels.

    Gmail's mbox export stores labels as a comma-separated header. In practice
    values may be RFC 2047-encoded, percent-escaped, quoted, and/or repeated.
    This parser is intentionally conservative: it is good enough for detecting
    system labels such as Spam/Trash and for reporting label hints.
    """
    labels: set[str] = set()
    for raw in msg.get_all("X-Gmail-Labels", []):
        decoded = unquote(decode_mime(raw))
        for part in decoded.split(","):
            label = part.strip().strip('"')
            if label:
                labels.add(label)
    return labels


def has_spam_trash_label(labels: set[str]) -> bool:
    return bool({label.lower() for label in labels} & SPAM_TRASH_LABELS)


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw_payload = part.get_payload()
        if isinstance(raw_payload, str):
            return raw_payload
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def extract_text(msg: Message, max_chars: int = 250_000) -> str:
    chunks: list[str] = []
    total = 0
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in {"text/plain", "text/html"}:
            continue
        text = _decode_part(part)
        if not text:
            continue
        if ctype == "text/html":
            text = BeautifulSoup(text, "html.parser").get_text(" ")
        remaining = max_chars - total
        if remaining <= 0:
            break
        chunks.append(text[:remaining])
        total += min(len(text), remaining)
    return html.unescape("\n".join(chunks))[:max_chars]


def link_domains(text: str) -> tuple[set[str], set[str]]:
    """Return (valid_domains, malformed_urls)."""
    out: set[str] = set()
    malformed: set[str] = set()
    for m in URL_RE.finditer(text):
        raw = m.group(0)
        try:
            host = urlparse(raw).hostname
        except ValueError:
            malformed.add(raw[:200])
            continue
        d = normalize_domain(host)
        if d:
            out.add(d)
    return out, malformed


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except Exception:
        return None


def classify(text: str) -> set[str]:
    found: set[str] = set()
    for label, patterns in PATTERNS.items():
        if any(p.search(text) for p in patterns):
            found.add(label)
    return found


def choose_service_domain(senders: set[str], links: set[str]) -> str:
    candidates = [d for d in senders if d not in NOISY_DOMAINS]
    if candidates:
        return sorted(candidates)[0]
    link_candidates = [d for d in links if d not in NOISY_DOMAINS]
    if link_candidates:
        return sorted(link_candidates)[0]
    return sorted(senders or links or {"unknown"})[0]


def short_subject(subject: str) -> str:
    return re.sub(r"\s+", " ", subject).strip()[:160]


def audit(
    mbox_path: Path,
    limit: int | None = None,
    *,
    include_spam_trash: bool = False,
    max_body_chars: int = 250_000,
) -> dict[str, ServiceEvidence]:
    results: dict[str, ServiceEvidence] = {}
    mbox = mailbox.mbox(str(mbox_path), create=False)
    for i, msg in enumerate(mbox, start=1):
        if limit and i > limit:
            break
        labels = gmail_labels(msg)
        if not include_spam_trash and has_spam_trash_label(labels):
            continue
        subject = decode_mime(msg.get("subject"))
        body = extract_text(msg, max_chars=max_body_chars)
        combined = f"{subject}\n{body}"
        evidence_types = classify(combined)
        if not evidence_types:
            continue
        senders = sender_domains(msg)
        links, malformed = link_domains(combined)
        service = choose_service_domain(senders, links)
        ev = results.setdefault(service, ServiceEvidence(service_domain=service))
        ev.count += 1
        ev.evidence_types.update(evidence_types)
        ev.sender_domains.update(senders)
        ev.linked_domains.update(links)
        ev.gmail_labels.update(labels)
        ev.malformed_urls.update(malformed)
        dt = parse_date(msg.get("date"))
        if dt:
            ev.dates.append(dt)
        if subject and len(ev.subjects) < 5:
            ev.subjects.append(short_subject(subject))
        if i % 5000 == 0:
            print(f"processed {i} messages...", file=sys.stderr)
    return results


def rows(results: dict[str, ServiceEvidence]) -> list[dict[str, str | int]]:
    out = []
    for ev in results.values():
        dates = sorted(ev.dates)
        out.append({
            "service_domain": ev.service_domain,
            "confidence": ev.confidence(),
            "evidence_types": ";".join(sorted(ev.evidence_types)),
            "first_seen": dates[0].date().isoformat() if dates else "",
            "last_seen": dates[-1].date().isoformat() if dates else "",
            "message_count": ev.count,
            "example_subjects": " | ".join(ev.subjects),
            "sender_domains": ";".join(sorted(ev.sender_domains)),
            "linked_domains": ";".join(sorted(d for d in ev.linked_domains if d not in NOISY_DOMAINS)[:20]),
            "gmail_labels": ";".join(sorted(ev.gmail_labels)[:20]),
            "malformed_urls": ";".join(sorted(ev.malformed_urls)[:20]),
        })
    return sorted(out, key=lambda r: (-int(r["confidence"]), -int(r["message_count"]), str(r["service_domain"])))


def fieldnames() -> list[str]:
    return [
        "service_domain", "confidence", "evidence_types", "first_seen", "last_seen",
        "message_count", "example_subjects", "sender_domains", "linked_domains", "gmail_labels", "malformed_urls",
    ]


def write_csv(path: Path, data: list[dict[str, str | int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames())
        writer.writeheader()
        writer.writerows(data)


def write_markdown(path: Path, data: list[dict[str, str | int]], top: int = 200) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Likely account/service inventory", "", "Generated from local mbox heuristics. Review manually before acting.", ""]
    lines.append("| service | confidence | evidence | first | last | count | labels | examples | malformed_urls |")
    lines.append("|---|---:|---|---|---|---:|---|---|---|")
    for r in data[:top]:
        examples = str(r["example_subjects"]).replace("|", "\\|")
        labels = str(r["gmail_labels"]).replace("|", "\\|")
        malformed = str(r["malformed_urls"]).replace("|", "\\|")
        lines.append(f"| `{r['service_domain']}` | {r['confidence']} | {r['evidence_types']} | {r['first_seen']} | {r['last_seen']} | {r['message_count']} | {labels} | {examples} | {malformed} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mbox", type=Path, help="Path to Gmail/Takeout mbox file")
    ap.add_argument("--out", type=Path, default=Path("reports/accounts.csv"), help="CSV output path")
    ap.add_argument("--markdown", type=Path, help="Optional Markdown output path")
    ap.add_argument("--limit", type=int, help="Process only first N messages for smoke testing")
    ap.add_argument(
        "--include-spam-trash",
        action="store_true",
        help="Include Gmail messages labelled Spam/Trash/Bin; default skips them to reduce phishing noise",
    )
    ap.add_argument(
        "--max-body-chars",
        type=int,
        default=250_000,
        help="Maximum text characters to scan per message; lower this for very large exports",
    )
    args = ap.parse_args()

    if not args.mbox.exists():
        ap.error(f"mbox does not exist: {args.mbox}")

    data = rows(audit(
        args.mbox,
        limit=args.limit,
        include_spam_trash=args.include_spam_trash,
        max_body_chars=args.max_body_chars,
    ))
    write_csv(args.out, data)
    if args.markdown:
        write_markdown(args.markdown, data)
    print(f"wrote {len(data)} candidate services to {args.out}")
    if args.markdown:
        print(f"wrote markdown report to {args.markdown}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
