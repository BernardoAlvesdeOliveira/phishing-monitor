import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr


URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)


@dataclass
class ParsedEmail:
    sender: str
    recipient: str
    subject: str
    message_id: str
    headers: dict[str, str]
    text_body: str
    html_body: str
    urls: list[str]
    attachments: list[str] = field(default_factory=list)
    is_system_alert: bool = False


class EmailParser:
    def parse(self, raw_email: str, *, fallback_sender: str = "", fallback_recipient: str = "",
              fallback_subject: str = "") -> ParsedEmail:
        raw_bytes = raw_email.encode("utf-8", errors="replace")
        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        headers = {key.lower(): str(value) for key, value in message.items()}
        sender = parseaddr(headers.get("from", fallback_sender))[1] or fallback_sender
        recipient = parseaddr(headers.get("to", fallback_recipient))[1] or fallback_recipient
        subject = headers.get("subject", fallback_subject)
        text_parts: list[str] = []
        html_parts: list[str] = []
        attachments: list[str] = []
        parts = message.walk() if message.is_multipart() else [message]
        for part in parts:
            disposition = part.get_content_disposition()
            filename = part.get_filename()
            if disposition == "attachment" or filename:
                if filename:
                    attachments.append(filename)
                continue
            content_type = part.get_content_type()
            try:
                content = part.get_content()
            except (LookupError, UnicodeError):
                content = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
            if not isinstance(content, str):
                content = str(content)
            if content_type == "text/html":
                html_parts.append(content.strip())
            elif content_type == "text/plain":
                text_parts.append(content.strip())
        body = "\n".join(text_parts + html_parts)
        urls = list(dict.fromkeys(match.rstrip(".,;:!?)]}") for match in URL_PATTERN.findall(body)))
        message_id = headers.get("message-id", "").strip() or hashlib.sha256(raw_bytes).hexdigest()
        return ParsedEmail(
            sender=sender, recipient=recipient, subject=subject, message_id=message_id,
            headers=headers, text_body="\n".join(text_parts), html_body="\n".join(html_parts),
            urls=urls, attachments=attachments,
            is_system_alert=headers.get("x-phishing-monitor-alert", "").lower() == "true",
        )