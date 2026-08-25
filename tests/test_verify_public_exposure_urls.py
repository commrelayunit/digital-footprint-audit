import unittest

from scripts.verify_public_exposure_urls import classify_response


class ClassifyResponseTests(unittest.TestCase):
    def test_clear_dead_responses_are_excluded(self):
        self.assertEqual(classify_response(404, "https://x.test/u", "https://x.test/u", b"")[0], "excluded_dead")
        self.assertEqual(classify_response(410, "https://x.test/u", "https://x.test/u", b"")[0], "excluded_dead")

    def test_success_never_claims_a_match(self):
        disposition, reason = classify_response(200, "https://x.test/u", "https://x.test/u", b"<h1>profile</h1>")
        self.assertEqual(disposition, "ambiguous")
        self.assertIn("cannot verify", reason)

    def test_soft_404_and_captcha_stay_ambiguous(self):
        self.assertEqual(classify_response(200, "https://x.test/u", "https://x.test/u", b"Page not found")[0], "ambiguous")
        self.assertEqual(classify_response(200, "https://x.test/u", "https://x.test/u", b"Please verify you are human")[0], "ambiguous")

    def test_blocked_and_redirected_responses_stay_ambiguous(self):
        self.assertEqual(classify_response(403, "https://x.test/u", "https://x.test/u", b"")[0], "ambiguous")
        self.assertEqual(classify_response(429, "https://x.test/u", "https://x.test/u", b"")[0], "ambiguous")
        self.assertEqual(classify_response(200, "https://x.test/u", "https://x.test/login", b"ok")[0], "ambiguous")
