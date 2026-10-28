from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)


class Settings(BaseSettings):
    app_env: str = "development"
    webhook_secret: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None
    notification_recipient: str | None = None
    threat_intelligence_api_key: str | None = None
    risk_notification_threshold: int = Field(default=50, ge=0, le=100)
    max_email_size_bytes: int = Field(default=10 * 1024 * 1024, gt=0)
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)


@lru_cache
def get_settings() -> Settings:
    return Settings()