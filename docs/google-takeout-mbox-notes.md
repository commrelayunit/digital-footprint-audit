# Google Takeout Gmail mbox notes

Practical notes for running `scripts/audit_mbox_accounts.py` against Gmail exports.

## Export layout and file names

- Google Takeout places Gmail exports under `Takeout/Mail/`.
- If you export all mail, the file is commonly named `All mail Including Spam and Trash.mbox`.
- If you export selected labels, Takeout may create one `.mbox` per selected label instead. Run the script once per `.mbox`, or concatenate/report-merge only after checking for duplicate messages.
- Keep the Takeout `.zip/.tgz` and extracted `.mbox` files outside git or under ignored directories such as `data/` / `exports/`.

## Gmail-specific headers

Gmail Takeout preserves useful Gmail metadata in message headers:

- `X-Gmail-Labels`: comma-separated Gmail labels. This can include user labels and system labels such as `Inbox`, `Sent`, `Spam`, and `Trash`/`Bin`.
- `X-GM-THRID` and `X-GM-MSGID`: Gmail thread/message IDs. These are useful for deduplication or debugging, but the current audit script does not need them for account discovery.
- Standard headers (`Message-ID`, `Date`, `From`, `Reply-To`, `Subject`) remain the main evidence source.

The script parses `X-Gmail-Labels`, reports observed labels, and skips `Spam`/`Trash`/`Bin` messages by default because they add phishing and account-lookalike noise. Use `--include-spam-trash` if full coverage is more important than precision.

## MBOX parsing and `From ` escaping

Takeout uses the standard mbox format: messages are separated by envelope lines beginning with `From `.
Literal body lines that start with `From ` are expected to be escaped by the mbox writer, usually as `>From `. Python's `mailbox.mbox` understands the mbox separators and is sufficient for this script's read-only scan.

Caveats:

- Do not edit large `.mbox` files in a text editor; corruption is easy and detection is annoying.
- If parsing stops early or message counts look implausible, re-extract the Takeout archive and rerun a small `--limit` smoke test first.
- The script reads message content only; it does not write back to the mbox.

## Bodies, multipart mail, and HTML

Gmail messages can be plain text, HTML-only, multipart alternatives, forwarded threads, or very large notification digests.

The script:

- scans only `text/plain` and `text/html` parts;
- ignores attachments and non-text parts;
- decodes MIME-encoded subjects and body charsets tolerantly;
- converts HTML to visible text with BeautifulSoup;
- caps scanned body text with `--max-body-chars` to keep multi-GB exports tractable.

For very large exports, start with:

```bash
python scripts/audit_mbox_accounts.py \
  "/path/to/Takeout/Mail/All mail Including Spam and Trash.mbox" \
  --limit 10000 \
  --max-body-chars 50000 \
  --out reports/accounts-sample.csv
```

Then run the full scan overnight or label-by-label if needed.

## Interpreting results

The report is evidence, not truth.

- High confidence usually means multiple account-like signals, not a guaranteed active account.
- Billing and password reset emails are strong hints but can refer to already-closed accounts.
- Spam/trash results are particularly suspect; inspect sender domains and linked domains before acting.
- Newsletter/list mail can look like account evidence if it contains generic phrases like "confirm your email".

Recommended workflow: sort by confidence, manually verify the service, then cross-check with password-manager/OAuth/payment evidence before deleting or changing anything.
