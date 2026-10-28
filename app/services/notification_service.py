import logging
from email.message import EmailMessage

import aiosmtplib

from app.core.config import Settings
from app.services.email_parser import ParsedEmail
from app.services.risk_engine import RiskResult

logger = logging.getLogger(__name__)


class NotificationService:
    def __init__(self, settings: Settings):
        self.settings = settings

    def should_notify(self, result: RiskResult, email: ParsedEmail) -> bool:
        return result.score >= self.settings.risk_notification_threshold and bool(self.settings.notification_recipient) and not email.is_system_alert

    async def notify(self, email: ParsedEmail, result: RiskResult) -> bool:
        if not self.should_notify(result, email):
            return False
        if not self.settings.smtp_host or not self.settings.smtp_from_email:
            logger.warning("notification skipped: SMTP configuration is incomplete")
            return False
        message = EmailMessage()
        message["From"] = self.settings.smtp_from_email
        message["To"] = self.settings.notification_recipient
        message["Subject"] = "[Security Alert] Potential Phishing Email Detected"
        message["X-Phishing-Monitor-Alert"] = "true"
        findings = "\n".join(f"- {finding.description}" for finding in result.findings if finding.points)
        message.set_content(
            f"Original Sender: {email.sender}\nOriginal Subject: {email.subject}\n\n"
            f"Risk Level: {result.level}\nRisk Score: {result.score}/100\n\n"
            f"Findings:\n{findings or '- No scored findings.'}\n\n"
            "Do not click suspicious links or provide sensitive information. "
            "Verify the message through a trusted channel."
        )
        try:
            await aiosmtplib.send(
                message, hostname=self.settings.smtp_host, port=self.settings.smtp_port,
                username=self.settings.smtp_username, password=self.settings.smtp_password,
                start_tls=self.settings.smtp_port != 465,
            )
        except (OSError, aiosmtplib.SMTPException) as exc:
            logger.error("notification delivery failed: %s", exc)
            return False
        logger.info("notification sent message_id=%s", email.message_id)
        return True