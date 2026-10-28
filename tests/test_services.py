import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from app.core.config import Settings
from app.services.email_analyzer import EmailAnalyzer
from app.services.email_parser import EmailParser
from app.services.notification_service import NotificationService
from app.services.risk_engine import AnalysisStatus, Finding, RiskEngine, RiskLevel
from app.services.url_analyzer import UrlAnalyzer


BASIC_EMAIL = """From: security@example.com
To: user@example.net
Subject: Hello
Message-ID: <basic@example.com>
Content-Type: text/plain; charset=utf-8

Hello.
"""


class ServiceTests(unittest.TestCase):
    def test_parser_extracts_basic_email(self):
        parsed = EmailParser().parse(BASIC_EMAIL)
        self.assertEqual(parsed.sender, "security@example.com")
        self.assertEqual(parsed.message_id, "<basic@example.com>")
        self.assertEqual(parsed.text_body, "Hello.")

    def test_parser_extracts_multipart_urls_and_attachment(self):
        raw = """From: sender@example.com
To: user@example.net
Subject: Verify
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="x"

--x
Content-Type: text/plain

Visit https://example.com/login.
--x
Content-Type: text/html

<a href="https://example.com/login">Login</a>
--x
Content-Type: application/pdf
Content-Disposition: attachment; filename="invoice.pdf"

ignored
--x--
"""
        parsed = EmailParser().parse(raw)
        self.assertEqual(parsed.urls, ["https://example.com/login"])
        self.assertEqual(parsed.attachments, ["invoice.pdf"])

    def test_malformed_email_is_safe(self):
        parsed = EmailParser().parse("not an RFC 5322 message")
        self.assertEqual(parsed.subject, "")
        self.assertTrue(parsed.message_id)

    def test_url_analyzer_does_not_fetch_and_detects_restricted_host(self):
        findings = UrlAnalyzer().analyze(["http://127.0.0.1/admin"])
        self.assertEqual({finding.code for finding in findings}, {"url_ip_host", "restricted_url_host"})

    def test_no_urls_produce_no_url_findings(self):
        self.assertEqual(EmailAnalyzer().analyze(BASIC_EMAIL)[1].findings, [
            Finding("dkim_missing", "DKIM signature was not present; this is inconclusive.", "low", 0),
            Finding("dns_unavailable", "SPF and DMARC could not be verified for example.com.", "low", 0),
        ])

    def test_missing_dkim_is_inconclusive_not_malicious(self):
        result = EmailAnalyzer().analyze(BASIC_EMAIL)[1]
        self.assertEqual(result.status, AnalysisStatus.INCONCLUSIVE)
        self.assertEqual(result.level, RiskLevel.LOW)
        self.assertEqual(result.score, 0)

    def test_risk_engine_deduplicates_and_caps_score(self):
        finding = Finding("same", "same", "high", 60)
        result = RiskEngine().evaluate([finding, finding, Finding("other", "other", "critical", 60)], verification_available=True)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.level, RiskLevel.CRITICAL)

    def test_notification_threshold_and_delivery_failure(self):
        settings = Settings(
            notification_recipient="security@example.net",
            smtp_host="smtp.example.net",
            smtp_from_email="monitor@example.net",
            risk_notification_threshold=50,
        )
        email, result = EmailAnalyzer(url_analyzer=UrlAnalyzer(threat_indicators={"https://bad.example"})).analyze(
            "From: attacker@example.com\nSubject: Alert\n\nhttps://bad.example"
        )
        service = NotificationService(settings)
        self.assertTrue(service.should_notify(result, email))
        with patch("app.services.notification_service.aiosmtplib.send", new=AsyncMock(side_effect=OSError("offline"))):
            self.assertFalse(asyncio.run(service.notify(email, result)))


if __name__ == "__main__":
    unittest.main()
