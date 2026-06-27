# Digital Footprint Audit

Local/offline tooling to discover likely accounts and services from exported mailboxes, browser/password-manager exports, OAuth app lists, and billing evidence.

Primary goal: help simplify a personal digital footprint by turning scattered account traces into a reviewable inventory.

## Privacy stance

- No mailbox contents are committed.
- No credentials, tokens, cookies, or exported passwords belong in this repo.
- Scripts are designed to run locally against files you explicitly provide.
- Outputs should be reviewed before sharing or committing; reports may contain personal account evidence.

## Current workflow

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

## Output columns

- `service_domain` — normalized candidate service domain
- `confidence` — heuristic confidence, 0–100
- `evidence_types` — matched evidence classes
- `first_seen` / `last_seen` — message date range
- `message_count` — number of matching messages
- `example_subjects` — redacted-ish examples for manual review
- `sender_domains` — observed sender domains
- `linked_domains` — domains found in account-like links

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
