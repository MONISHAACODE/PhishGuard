"""
endpoints.py — PhishGuard API routes
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.models.schemas import (
    ScanRequest,
    ScanResponse,
    SignalDetail,
    HealthResponse,
    ErrorResponse,
)
from app.engine.detector import detector
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_scan_response(result: dict, processed_url: str) -> ScanResponse:
    """Map the raw detector dict → ScanResponse, safely handling missing keys."""
    signals = [
        SignalDetail(
            name=s["name"],
            score=s["score"],
            reason=s["reason"],
            category=s["category"],
            confidence=s["confidence"],
            evidence=s.get("evidence"),
        )
        for s in result.get("signals", [])
    ]

    return ScanResponse(
        verdict=result["verdict"],
        confidence=result["confidence"],
        reasons=result.get("reasons", []),
        processed_url=processed_url,
        threat_categories=result.get("threat_categories", []),
        signals=signals,
        domain=result.get("domain", ""),
        tld=result.get("tld", ""),
        is_ip=result.get("is_ip", False),
        is_idn=result.get("is_idn", False),
        subdomain_depth=result.get("subdomain_depth", 0),
        entropy=result.get("entropy", 0.0),
        analysis_time_ms=result.get("analysis_time_ms", 0.0),
        url_decoded=result.get("url_decoded", processed_url),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post(
    "/scan",
    response_model=ScanResponse,
    summary="Analyse a URL for phishing indicators",
    response_description="Verdict, confidence score, and per-signal breakdown",
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request payload"},
        422: {"description": "Validation error"},
        500: {"model": ErrorResponse, "description": "Internal analysis error"},
    },
)
async def scan_url(request: ScanRequest) -> ScanResponse:
    """
    Analyses a URL using the multi-signal PhishingDetector engine.

    Returns a structured verdict with:
    - `verdict`: Safe | Suspicious | Phishing
    - `confidence`: 0–100 weighted threat score
    - `reasons`: human-readable list of triggered signals
    - `signals`: per-signal breakdown with scores and evidence
    - `threat_categories`: deduplicated attack-type tags
    """
    logger.info("scan url=%r check_type=%s", request.url, request.check_type)

    try:
        result = detector.analyze(request.url)
    except Exception as exc:
        logger.exception("Detector failed for url=%r: %s", request.url, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal analysis error — please try again",
        ) from exc

    try:
        return _build_scan_response(result, processed_url=request.url)
    except (KeyError, ValidationError) as exc:
        logger.exception("Response mapping failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to construct analysis response",
        ) from exc


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Engine health check",
    include_in_schema=False,
)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version=settings.VERSION)
