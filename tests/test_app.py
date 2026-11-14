import unittest, re
from app import app
from rules import run_rules
from analyzer import analyze, load_model

class RuleTests(unittest.TestCase):
    def test_otp_share_is_flagged(self):
        ids = [h["id"] for h in run_rules("Please share the OTP you received to get cashback")]
        self.assertIn("asks_secret", ids)
    def test_do_not_share_otp_is_not_flagged(self):
        ids = [h["id"] for h in run_rules("Your OTP is 483920. Do not share it with anyone.")]
        self.assertNotIn("asks_secret", ids)
    def test_bad_domain_is_flagged(self):
        ids = [h["id"] for h in run_rules("Update now http://bank-kyc.xyz/login")]
        self.assertIn("odd_domain", ids)

class AnalyzerTests(unittest.TestCase):
    def setUp(self): self.model = load_model()
    def test_scam(self):
        r = analyze("URGENT: your SBI account will be blocked today. Update KYC at http://sbi-kyc.xyz and share OTP", self.model)
        self.assertEqual(r["label"], "SCAM")
    def test_normal_message(self):
        r = analyze("Hi, are we meeting at the canteen at 1 PM today?", self.model)
        self.assertEqual(r["label"], "LOOKS SAFE")

class AppTests(unittest.TestCase):
    def setUp(self): self.c = app.test_client()
    def token(self):
        html = self.c.get("/").data.decode()
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)
    def test_page_loads_with_security_headers(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Content-Security-Policy", r.headers)
    def test_post_without_csrf_is_rejected(self):
        self.assertEqual(self.c.post("/", data={"message": "hello there"}).status_code, 400)
    def test_valid_check(self):
        r = self.c.post("/", data={"message": "Share your OTP to claim lottery prize now", "csrf": self.token()})
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"SCAM", r.data)
    def test_too_short_and_too_long_rejected(self):
        t = self.token()
        self.assertIn(b"between", self.c.post("/", data={"message": "hi", "csrf": t}).data)
        self.assertIn(b"between", self.c.post("/", data={"message": "a" * 1001, "csrf": t}).data)
    def test_script_in_message_is_escaped(self):
        r = self.c.post("/", data={"message": "<script>alert(1)</script> click now", "csrf": self.token()})
        self.assertNotIn(b"<script>alert(1)</script>", r.data)

if __name__ == "__main__":
    unittest.main()
