"""
config.py — Application settings loaded from environment / .env file
"""

from __future__ import annotations

from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # ── Project meta ──────────────────────────────────────────────────────
    PROJECT_NAME: str = "PhishGuard API"
    VERSION:      str = "2.0.0"
    DESCRIPTION:  str = (
        "Industry-grade phishing URL detection API "
        "for the PhishGuard Chrome Extension"
    )

    # ── API ───────────────────────────────────────────────────────────────
    API_V1_STR: str = "/api/v1"

    # ── Security ──────────────────────────────────────────────────────────
    # In production replace "*" with the exact Chrome Extension origin:
    #   chrome-extension://<extension-id>
    BACKEND_CORS_ORIGINS: List[str] = ["*"]

    # Optional: simple bearer token gate for the /scan endpoint
    # Leave blank to disable authentication
    API_SECRET_KEY: str = ""

    # ── Rate limiting (requests per minute per IP, 0 = disabled) ─────────
    RATE_LIMIT_PER_MINUTE: int = 60

    # ── Logging ───────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"

    # ── Detector thresholds (override engine defaults if set) ─────────────
    PHISHING_THRESHOLD:   int = 60
    SUSPICIOUS_THRESHOLD: int = 30

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}")
        return upper

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
