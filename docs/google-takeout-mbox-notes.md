# Google Takeout Gmail mbox notes

Working notes for Gmail Takeout-specific behavior. R2-D2 should verify and expand this.

Expected characteristics:

- Takeout usually exports one or more `.mbox` files under `Takeout/Mail/`.
- The export may be named `All mail Including Spam and Trash.mbox` depending on selected labels.
- Gmail labels are commonly stored in the `X-Gmail-Labels` header.
- Message IDs may appear in `X-GM-THRID`, `X-GM-MSGID`, and standard `Message-ID` headers.
- Dates may be malformed or timezone-varied; parsing should be tolerant.
- Bodies can be multipart, encoded, HTML-only, or very large.
- Attachments should be ignored by default.
- Spam/trash can introduce noisy phishing/account-lookalike emails; reports should include confidence and evidence, not blindly assert account existence.

Open verification questions:

- Best way to handle Gmail label filtering from Takeout mbox.
- Whether Takeout mbox escaping requires special treatment beyond Python `mailbox.mbox`.
- Performance considerations for multi-GB exports.
- Common headers worth preserving in evidence output.
