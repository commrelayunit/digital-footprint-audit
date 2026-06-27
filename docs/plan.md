# Digital footprint simplification plan

## Goal

Build a practical inventory of accounts and decide what to keep, secure, migrate, export, or delete.

## Sources of truth

1. Gmail / Google Takeout `.mbox` exports.
2. Password manager export or built-in inventory.
3. Browser saved passwords.
4. OAuth connected-app dashboards: Google, Apple, GitHub, Microsoft, Meta, X/Twitter.
5. Payment trails: bank/card, PayPal, Stripe receipts, app stores.
6. Email aliases and custom domains.
7. Breach datasets such as Have I Been Pwned, used only as partial hints.

## Phase 1 — Account discovery from email

- Parse Takeout mbox locally.
- Detect account-event evidence:
  - welcome/sign-up/onboarding
  - email verification/account activation
  - password reset/password changed
  - login/security alerts/login codes
  - billing/receipt/subscription/trial
  - cancellation/deletion/export notices
- Group by normalized service domain.
- Rank candidates by confidence.
- Produce CSV + Markdown review report.

## Phase 2 — Cross-check with password manager and OAuth

- Merge password-manager domains with email-derived candidates.
- Add OAuth-connected apps from Google/GitHub/Apple/etc.
- Mark login method where known.
- Identify accounts with no password-manager entry but strong email evidence.

## Phase 3 — Triage

For each account:

- Keep and secure:
  - strong unique password/passkey
  - 2FA enabled
  - recovery email current
- Delete:
  - export useful data first
  - close account
  - record deletion confirmation
- Investigate:
  - uncertain service
  - sender-only evidence
  - possible newsletter without account

## Phase 4 — Cleanup and monitoring

- Remove unused OAuth grants.
- Cancel unused subscriptions.
- Disable stale aliases where safe.
- Set calendar reminders for annual account review.
- Keep a private inventory, not in this repo unless encrypted/redacted.

## Safety rules

- Never commit mailbox exports, report outputs with personal data, password-manager exports, OAuth tokens, cookies, or API keys.
- Treat generated reports as private until manually redacted.
- Prefer local processing over cloud upload.
