import json
import tempfile
import unittest
from pathlib import Path

from scripts.audit_public_exposure import mailaccess_report


class MailAccessReportImportTests(unittest.TestCase):
    def write_report(self, contents):
        temporary = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        with temporary:
            json.dump(contents, temporary)
        return Path(temporary.name)

    def test_imported_findings_are_candidates_with_provenance(self):
        report = self.write_report({
            "id": "investigation-123",
            "email": "me@example.org",
            "findings": [{"module": "maigret", "platform": "Example", "url": "https://example.org/me", "description": "profile candidate"}],
        })
        self.addCleanup(report.unlink)

        findings = mailaccess_report(report)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].query, "me@example.org")
        self.assertEqual(findings[0].status, "candidate")
        self.assertEqual(findings[0].confidence, "low")
        self.assertIn("Treat as a lead", findings[0].evidence)
        self.assertIn("investigation-123", findings[0].evidence)

    def test_malformed_or_incomplete_reports_are_explicit_errors(self):
        malformed = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        with malformed:
            malformed.write("not json")
        self.addCleanup(Path(malformed.name).unlink)
        self.assertEqual(mailaccess_report(Path(malformed.name))[0].status, "error")

        incomplete = self.write_report({"email": "me@example.org"})
        self.addCleanup(incomplete.unlink)
        self.assertEqual(mailaccess_report(incomplete)[0].status, "error")
