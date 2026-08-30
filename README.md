# Digital Footprint Audit

Local tools for building a private inventory of online accounts and reviewing
public exposure. The workflow combines evidence you already control (mailbox
and browser-login exports) with opt-in checks for public profiles, breach
membership, and public name references.

The goal is not to prove identity automatically. It is to produce a reviewable
list of likely accounts, stale services, public traces, and security work.

## What this does — and does not do

It can:

- extract likely service/account evidence from a local Gmail Takeout `.mbox`;
- extract service domains and usernames from a Firefox saved-logins CSV without
  exporting its password values into reports;
- search public GitHub and OpenAlex records for supplied usernames and names;
- optionally check an email against [Have I Been Pwned](https://haveibeenpwned.com/API/v3);
- optionally enumerate public username profiles with [Maigret](https://github.com/soxoj/maigret)
  and [Sherlock](https://github.com/sherlock-project/sherlock).
- optionally import a local [MailAccess](https://github.com/KatrielMoses/MailAccess) JSON report as a separate, reviewable email-OSINT evidence lane.

It does not:

- test credentials, log in, reset passwords, or probe private account existence;
- send raw mailbox/browser exports anywhere;
- decide that a matching username or name belongs to a particular person.

Username reuse and common names produce false positives. Treat every public
match as `candidate` until you verify it manually.

## Privacy and safety

- Run this locally against data you explicitly choose.
- Never commit reports, raw exports, API keys, cookies, tokens, or password-manager exports. The repository ignores `exports/`, `data/`, and `reports/`.
- A Firefox login export contains plaintext passwords. Keep it briefly, outside
  the repository or under ignored `exports/`, then delete it after checking the
  safe derived report.
- Maigret and Sherlock contact many third-party websites with the usernames you
  provide. Use them deliberately and start with a bounded Maigret scan.
- A [Have I Been Pwned](https://haveibeenpwned.com/) lookup sends the supplied
  email address to that service. It is disabled unless you provide
  `HAVE_I_BEEN_PWNED_API_KEY`.
- MailAccess is **not** installed or run by this project. Its broad platform
  sweep can contact many third-party services with an email-derived query. Run
  it separately, only for addresses you are authorized to audit, then import
  its local JSON export explicitly. Imported findings remain `candidate` leads,
  never proof that an account belongs to you or still exists.

## Quick start

```bash
git clone https://github.com/commrelayunit/digital-footprint-audit.git
cd digital-footprint-audit
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Generated output belongs in `reports/`, which is ignored by Git.

## Recommended workflow

Run the evidence lanes in this order. They answer different questions and are
not substitutes for one another.

| Stage | Input | What it reveals | Output |
|---|---|---|---|
| 1. Mailbox inventory | Gmail Takeout `.mbox` | account, billing, reset, verification, and cancellation evidence | `reports/accounts.csv` / `.md` |
| 2. Browser-login inventory | Firefox saved-logins CSV | domains and usernames with saved credentials | `reports/firefox-logins.csv` / `.md` |
| 3. Public exposure | your chosen usernames, names, emails, and optional local MailAccess JSON | public profiles, public academic/code candidates, breach records, email-OSINT leads, review links | `reports/public-exposure.csv` / `.md` |
| 4. Triage | the reports above | keep, secure, export, delete, or investigate decisions | your private inventory |

### 1. Discover likely accounts from Gmail Takeout

Export Gmail using [Google Takeout](https://takeout.google.com/). Locate the
Gmail `.mbox` in the downloaded archive and run:

```bash
python scripts/audit_mbox_accounts.py \
  "/path/to/Takeout/Mail/All mail Including Spam and Trash.mbox" \
  --out reports/accounts.csv \
  --markdown reports/accounts.md
```

The collector reads message subjects, sender domains, Gmail labels, and message
bodies for account-oriented signals: welcome emails, verification, password or
login alerts, invoices, subscriptions, exports, cancellations, and closures.
It groups that evidence by likely service domain and ranks it for review.

Spam and Trash/Bin are skipped by default to reduce phishing noise. Include
them only when you want a more exhaustive, noisier pass:

```bash
python scripts/audit_mbox_accounts.py \
  "/path/to/Takeout/Mail/All mail Including Spam and Trash.mbox" \
  --include-spam-trash --out reports/accounts-full.csv
```

For a very large export, sample it first:

```bash
python scripts/audit_mbox_accounts.py \
  "/path/to/Takeout/Mail/All mail Including Spam and Trash.mbox" \
  --limit 10000 --max-body-chars 50000 --out reports/accounts-sample.csv
```

### 2. Cross-check saved browser logins

Firefox can export saved logins as CSV. In Firefox, open Passwords/Logins, use
the menu to export logins, save the file locally, then run:

```bash
python scripts/import_firefox_logins.py \
  "/path/to/firefox-logins.csv" \
  --out reports/firefox-logins.csv \
  --markdown reports/firefox-logins.md
```

The importer uses service URLs/origins and the username field. It deliberately
ignores the plaintext `password` column and never writes it to output. The
derived report is still private because usernames and account domains can be
sensitive.

Other browsers and password managers are not imported directly yet. Use their
built-in account inventory where available, or manually compare their service
domains to the CSV reports; do not force a password export into an unsupported
format.

### 3. Check public exposure

The interactive collector prompts for usernames, full names, and email
addresses. It always performs the narrow GitHub/OpenAlex evidence checks and
generates manual Google, Bing, and Common Crawl review links.

Start with Maigret over a bounded set of sites:

```bash
python scripts/audit_public_exposure.py \
  --interactive --maigret --maigret-top-sites 25
```

For the complete username pass, include Sherlock too:

```bash
python scripts/audit_public_exposure.py \
  --interactive --maigret --maigret-top-sites 500 --sherlock
```

This produces:

- `reports/public-exposure.csv` — one finding per row, suitable for filtering;
- `reports/public-exposure.md` — readable, linked summary;
- `reports/raw/maigret/` and `reports/raw/sherlock/` — raw local collector output for auditability.

### 3a. Filter clear dead profile URLs

Username scanners can report URLs that now return a normal `404` or `410`, a
soft-404 page with an HTTP `200`, a CAPTCHA page, or a generic landing page.
Run the local verifier on the existing report after a scan:

```bash
python scripts/verify_public_exposure_urls.py reports/public-exposure.csv
```

By default it rechecks only Maigret and Sherlock URLs with a descriptive
User-Agent, no cookies, no authentication, a 10-second per-URL timeout, and
redirect following. It never overwrites the input or raw collector output. It
writes three companion files:

- `reports/public-exposure-retained.csv` — input rows except clear `404`/`410` results;
- `reports/public-exposure-url-audit.csv` — every checked URL with original URL,
  final URL, HTTP status, disposition, and reason;
- `reports/public-exposure-url-audit.md` — readable audit table.

`200 OK` is deliberately **not** a verified match. Redirects, blocked `401`/
`403`/`429` pages, CAPTCHA/interstitial pages, soft-404-like `200` pages, timeouts,
and network failures remain explicit `ambiguous` or `error` audit rows for
manual review. Use `--all-urls` only if you intentionally want to recheck
other HTTP links in the report; this can include manual-search links.

Maigret is the broad first collector. Sherlock overlaps with it, so it is best
used as corroboration rather than proof. To check only selected Sherlock sites:

```bash
python scripts/audit_public_exposure.py \
  --username example_handle --sherlock \
  --sherlock-site GitHub --sherlock-site Reddit
```

To include [Have I Been Pwned](https://haveibeenpwned.com/API/v3) breach
records, set an API key only for that command:

```bash
HAVE_I_BEEN_PWNED_API_KEY='your-key' python scripts/audit_public_exposure.py \
  --username example_handle --name "Example Name" \
  --email example@example.org --maigret --maigret-top-sites 25 --sherlock
```

Without `HAVE_I_BEEN_PWNED_API_KEY`, the report records that
[Have I Been Pwned](https://haveibeenpwned.com/) was not run and does not send
the email address to that service.

### 3b. Import a local MailAccess report (optional)

MailAccess is deliberately a separate step. Install and run it according to
its own documentation, using only an address you are authorized to audit. Do
not run it as a persistent service for this workflow, and do not enable API
keys, proxies, SMTP probing, domain harvesting, or a broad sweep merely to
fill a spreadsheet.

Export its completed investigation as JSON into the ignored `reports/raw/`
directory, then import that **local file**:

```bash
mailaccess investigate you@example.org -o reports/raw/mailaccess-you-example.json

python scripts/audit_public_exposure.py \
  --mailaccess-report reports/raw/mailaccess-you-example.json
```

`--mailaccess-report` only reads the named local JSON file. It does not install
or invoke MailAccess, start its web/API service, send an address anywhere, or
need MailAccess/third-party API credentials. The imported rows preserve the
report filename, investigation ID, and module name in their evidence field and
are always labelled `candidate` with low confidence. Review them manually
alongside the other evidence lanes.

## Reading the reports

The collectors distinguish evidence from conclusions:

- `confirmed` — direct source evidence, currently used for [Have I Been Pwned](https://haveibeenpwned.com/) breach records;
- `candidate` — plausible public profile or name match needing human review;
- `no_match` — no result from that collector, not proof that no account exists;
- `review` — a deliberately manual follow-up link;
- `not_run` — an optional collector was not configured;
- `error` — a source/network/tool issue; retry later or inspect the raw output.

For mailbox evidence, key fields are `service_domain`, `confidence`,
`evidence_types`, `first_seen`, `last_seen`, `message_count`, and
`sender_domains`. For Firefox, key fields include `service_domain`, `username`,
`confidence`, and usage dates.

## Triage the resulting account inventory

For each likely service, keep a private row with:

- `status`: keep / delete / unknown / duplicate
- `login_method`: password / Google OAuth / Apple / GitHub / unknown
- `email_used`
- `2fa`: none / TOTP / passkey / hardware key / unknown
- `data_exported`: yes / no / not needed
- `deleted_or_closed`: date / no
- `notes`

Then check connected-app dashboards (Google, Apple, GitHub, Microsoft, Meta,
and other providers), payment trails, aliases, and subscriptions. Before closing
anything, export data if needed, confirm the account is not a recovery path,
and record the deletion date.

[JustDeleteMe](https://justdeleteme.xyz/) is a useful companion at this stage:
it is a directory of direct account-deletion links and notes about services
that make deletion difficult. It can save time finding the correct setting, but
still verify the target account and any export/recovery consequences yourself.
It also links an [unofficial Android app on F-Droid](https://f-droid.org/en/packages/com.amanoteam.kurt/).

[Your Digital Rights](https://yourdigitalrights.org/) is the complementary
route when a service does not offer a usable deletion path: it helps people
exercise formal data-rights requests. Keep a copy of any request, the service's
reply, and your eventual deletion/closure date in the private inventory.

See [docs/plan.md](docs/plan.md) for the broader cleanup plan.
