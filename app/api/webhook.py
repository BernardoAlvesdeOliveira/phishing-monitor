import hmac
import logging
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.core.config import Settings, get_settings
from app.services.email_analyzer import EmailAnalyzer
from app.services.notification_service import NotificationService

logger = logging.getLogger(__name__)
router = APIRouter()
processed_message_ids: set[str] = set()


class WebhookEmail(BaseModel):
    sender: str = Field(default="", max_length=320)
    recipient: str = Field(default="", max_length=320)
    subject: str = Field(default="", max_length=998)
    raw_email: str = Field(min_length=1)


def _authorized(provided: str | None, configured: str | None) -> bool:
    if not configured:
        return True
    return bool(provided) and hmac.compare_digest(provided.encode(), configured.encode())


def _validate_payload(
    payload: WebhookEmail,
    request: Request,
    settings: Settings,
    secret: str | None,
    *,
    authenticate: bool = True,
) -> None:
    if authenticate and not _authorized(secret, settings.webhook_secret):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook authentication")
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > settings.max_email_size_bytes:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Payload too large")
    if len(payload.raw_email.encode("utf-8")) > settings.max_email_size_bytes:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Payload too large")


def _analyze(payload: WebhookEmail):
    return EmailAnalyzer().analyze(
        payload.raw_email, sender=payload.sender, recipient=payload.recipient, subject=payload.subject
    )


def _result_payload(email, result):
    return {
        "message_id": email.message_id,
        "risk": {"score": result.score, "level": result.level, "status": result.status},
        "findings": [finding.description for finding in result.findings],
    }


@router.post("/analyze/email")
async def analyze_email(
    payload: WebhookEmail,
    request: Request,
    x_webhook_secret: Annotated[str | None, Header()] = None,
):
    settings = get_settings()
    _validate_payload(payload, request, settings, x_webhook_secret, authenticate=False)
    email, result = _analyze(payload)
    return _result_payload(email, result)


@router.post("/webhook/email")
async def receive_email(
    payload: WebhookEmail,
    request: Request,
    x_webhook_secret: Annotated[str | None, Header()] = None,
):
    settings: Settings = get_settings()
    _validate_payload(payload, request, settings, x_webhook_secret)
    email, result = _analyze(payload)
    duplicate = email.message_id in processed_message_ids
    processed_message_ids.add(email.message_id)
    notification_sent = False
    if not duplicate:
        notification_sent = await NotificationService(settings).notify(email, result)
    logger.info("webhook processed message_id=%s duplicate=%s", email.message_id, duplicate)
    return {
        **_result_payload(email, result),
        "duplicate": duplicate,
        "notification_sent": notification_sent,
    }