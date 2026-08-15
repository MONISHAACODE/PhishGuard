"""
schemas.py — Pydantic models for PhishGuard API
All request/response contracts are defined here.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Verdict(str, Enum):
    SAFE       = "Safe"
    SUSPICIOUS = "Suspicious"
    PHISHING   = "Phishing"


class CheckType(str, Enum):
    FULL    = "full"
    QUICK   = "quick"
    DOMAIN  = "domain"


# ---------------------------------------------------------------------------
# Signal detail (rich per-signal audit output)
# ---------------------------------------------------------------------------

class SignalDetail(BaseModel):
    name:       str
    score:      int   = Field(..., ge=0, le=100)
    reason:     str
    category:   str
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence:   Optional[str] = None


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=4,
        max_length=2048,
        description="The URL to scan",
        json_schema_extra={"example": "https://paypa1-secure-login.xyz/verify"},
    )
    check_type: CheckType = Field(
        default=CheckType.FULL,
        description="Scan depth: full | quick | domain",
    )

    @field_validator("url")
    @classmethod
    def url_must_not_be_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL must not be blank or whitespace")
        return v

    @model_validator(mode="after")
    def normalise_url(self) -> "ScanRequest":
        """Ensure the URL carries a scheme so downstream parsing is consistent."""
        if self.url and "://" not in self.url:
            self.url = "http://" + self.url
        return self


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------

class ScanResponse(BaseModel):
    verdict:       Verdict
    confidence:    int            = Field(..., ge=0, le=100, description="Weighted threat score 0-100")
    reasons:       List[str]      = Field(default_factory=list)
    processed_url: str

    # Rich fields — populated from detector's full result
    threat_categories: List[str]          = Field(default_factory=list)
    signals:           List[SignalDetail] = Field(default_factory=list)
    domain:            Optional[str]      = None
    tld:               Optional[str]      = None
    is_ip:             bool               = False
    is_idn:            bool               = False
    subdomain_depth:   int                = 0
    entropy:           float              = 0.0
    analysis_time_ms:  float              = 0.0
    url_decoded:       Optional[str]      = None

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# Health / meta
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status:  str
    version: str
    engine:  str = "PhishingDetector/2.0"


class ErrorResponse(BaseModel):
    detail: str
    code:   int
