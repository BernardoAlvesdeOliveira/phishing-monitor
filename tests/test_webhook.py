import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.api.webhook import processed_message_ids
from app.core.config import Settings, get_settings
from app.main import app


class WebhookTests(unittest.TestCase):
    def setUp(self):
        processed_message_ids.clear()
        get_settings.cache_clear()

    def test_rejects_unauthorized_request(self):
        with patch.dict("os.environ", {"WEBHOOK_SECRET": "secret"}, clear=False):
            get_settings.cache_clear()
            client = TestClient(app)
            response = client.post("/webhook/email", json={"raw_email": "Subject: x\n\nbody"})
        self.assertEqual(response.status_code, 401)

    def test_rejects_oversized_payload(self):
        settings = Settings(webhook_secret=None, max_email_size_bytes=10)
        with patch("app.api.webhook.get_settings", return_value=settings):
            response = TestClient(app).post("/webhook/email", json={"raw_email": "Subject: x\n\nlong body"})
        self.assertEqual(response.status_code, 413)

    def test_duplicate_message_is_not_notified_twice(self):
        raw = "Message-ID: <same@example.com>\n\nbody"
        with patch("app.api.webhook.get_settings", return_value=Settings(webhook_secret=None)):
            client = TestClient(app)
            first = client.post("/webhook/email", json={"raw_email": raw})
            second = client.post("/webhook/email", json={"raw_email": raw})
        self.assertEqual(first.status_code, 200)
        self.assertFalse(first.json()["duplicate"])
        self.assertTrue(second.json()["duplicate"])

    def test_page_analysis_returns_result_without_notification(self):
        with patch("app.api.webhook.get_settings", return_value=Settings()):
            response = TestClient(app).post(
                "/analyze/email",
                json={"raw_email": "Subject: Review\n\nNo links here."},
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("risk", response.json())
        self.assertNotIn("notification_sent", response.json())

    def test_page_analysis_does_not_require_secret_when_configured(self):
        with patch("app.api.webhook.get_settings", return_value=Settings(webhook_secret="secret")):
            response = TestClient(app).post(
                "/analyze/email",
                json={"raw_email": "Subject: Review\n\nNo links here."},
            )
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
