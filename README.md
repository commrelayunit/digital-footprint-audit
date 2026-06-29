# Digital Footprint Audit

Local/offline tooling to discover likely accounts and services from exported mailboxes, browser/password-manager exports, OAuth app lists, and billing evidence.

Primary goal: help simplify a personal digital footprint by turning scattered account traces into a reviewable inventory.

## Privacy stance

- No mailbox contents are committed.
- No credentials, tokens, cookies, or exported passwords belong in this repo.
- Raw exports and generated inventories belong under ignored local paths such as `exports/`, `data/`, and `reports/`; do not force-add them.
- Scripts are designed to run locally against files you explicitly provide.
- Outputs should be reviewed before sharing anywhere; reports may contain personal account evidence and are private by default.

## Current workflow

### Gmail / Google Takeout mbox

Start with a Google Takeout Gmail `.mbox` file:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python scripts/audit_mbox_accounts.py "/path/to/Takeout/Mail/All mail Including Spam and Trash.mbox" --out reports/accounts.csv --markdown reports/accounts.md
```

The script scans subjects, senders, Gmail labels, and message bodies for account-related evidence such as welcome emails, email verification, password resets, login/security alerts, billing, and cancellation notices. It groups evidence by likely service domain and emits a ranked CSV/Markdown inventory. Gmail messages labelled Spam/Trash/Bin are skipped by default to reduce phishing noise; rerun with `--include-spam-trash` when you want maximum coverage.

For very large exports, first run a bounded sample:

```bash
python scripts/audit_mbox_accounts.py "/path/to/Takeout/Mail/All mail Including Spam and Trash.mbox" --limit 10000 --max-body-chars 50000 --out reports/accounts-sample.csv
```

### Firefox saved passwords CSV

Firefox can export saved logins as a plaintext CSV. Treat that file as highly sensitive: export only when needed, keep it outside the repo or under gitignored `exports/`, and delete it securely after producing the safe inventory.

In Firefox: open Passwords / Logins, use the menu to export logins, and save the CSV locally. Then run:

```bash
python scripts/import_firefox_logins.py "/path/to/firefox-logins.csv" --out reports/firefox-logins.csv --markdown reports/firefox-logins.md
```

The importer tolerates common Firefox columns including `url`, `username`, `password`, `httpRealm`, `formActionOrigin`, `guid`, `timeCreated`, `timeLastUsed`, and `timePasswordChanged`. It normalizes service domains from URL/origin/realm fields. The `password` column is ignored and never written to outputs.

## Gmail mbox output columns

- `service_domain` — normalized candidate service domain
- `confidence` — heuristic confidence, 0–100
- `evidence_types` — matched evidence classes
- `first_seen` / `last_seen` — message date range
- `message_count` — number of matching messages
- `example_subjects` — redacted-ish examples for manual review
- `sender_domains` — observed sender domains
- `linked_domains` — domains found in account-like links

## Firefox login output columns

- `service_domain` — normalized service domain from URL/origin/realm fields
- `username` — login username/email from the export, if present
- `confidence` — heuristic confidence, 0–100
- `evidence_source` — fixed source marker, `firefox_logins_csv`
- `login_count` / `url_count` — number of matching rows/domains grouped together
- `source_fields` — input fields used to identify the service
- `first_seen` / `last_used` / `password_changed` — parsed dates where Firefox supplied them
- `related_domains` — normalized domains observed in login URL/origin/realm fields

## Recommended account triage fields

After generating the inventory, track each service as:

- `status`: keep / delete / unknown / duplicate
- `login_method`: password / Google OAuth / Apple / GitHub / unknown
- `email_used`
- `2fa`: none / TOTP / passkey / hardware key / unknown
- `data_exported`: yes / no / not needed
- `deleted_or_closed`: date / no
- `notes`

See `docs/plan.md` for the broader audit plan.
