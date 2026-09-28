"""
app.py — SentinelShield-PII  Gateway & Proxy Server
FastAPI application exposing three endpoints:
  POST /v1/sanitize  — sanitize a raw JSON payload
  POST /v1/proxy     — sanitize then forward to an upstream URL
  GET  /v1/audit     — return aggregated breach metrics
"""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from sanitizer import sanitize

# ---------------------------------------------------------------------------
# Application bootstrap
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SentinelShield-PII",
    description="Production-ready PII masking & audit proxy",
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# In-memory audit trail
# ---------------------------------------------------------------------------
# Each entry: {"timestamp", "endpoint", "breach_types": {type: count}, "target": str|None}

_audit_trail: list[dict[str, Any]] = []


def _record_audit(
    breach_summary: dict[str, int],
    endpoint: str,
    target: str | None = None,
) -> None:
    if breach_summary:  # only record if PII was actually found
        _audit_trail.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "endpoint": endpoint,
                "breach_types": breach_summary,
                "target": target,
            }
        )


# ---------------------------------------------------------------------------
# POST /v1/sanitize
# ---------------------------------------------------------------------------

@app.post("/v1/sanitize")
async def sanitize_endpoint(request: Request) -> JSONResponse:
    """Accept raw JSON, return sanitized JSON with entity counts and latency."""
    try:
        payload: Any = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    t0 = time.perf_counter()
    result = sanitize(payload)
    latency_ms = round((time.perf_counter() - t0) * 1000, 3)

    summary = result.summary()
    _record_audit(summary, endpoint="/v1/sanitize")

    return JSONResponse(
        {
            "sanitized": result.sanitized,
            "entities_detected": summary,
            "total_redactions": len(result.redactions),
            "latency_ms": latency_ms,
        }
    )


# ---------------------------------------------------------------------------
# POST /v1/proxy
# ---------------------------------------------------------------------------

@app.post("/v1/proxy")
async def proxy_endpoint(
    request: Request,
    x_target_url: str = Header(..., description="Upstream URL to forward the sanitized request to"),
) -> Response:
    """
    Sanitize the incoming payload, then forward it to *x_target_url*.
    The original body is never forwarded — only the sanitized version.
    """
    try:
        payload: Any = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Sanitize before forwarding
    result = sanitize(payload)
    summary = result.summary()
    _record_audit(summary, endpoint="/v1/proxy", target=x_target_url)

    # Forward sanitized payload to upstream
    forward_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in {"host", "content-length", "x-target-url"}
    }
    forward_headers["Content-Type"] = "application/json"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            upstream_response = await client.post(
                x_target_url,
                json=result.sanitized,
                headers=forward_headers,
            )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Upstream request failed: {exc}",
        )

    # Relay the upstream response back to the caller
    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=dict(upstream_response.headers),
        media_type=upstream_response.headers.get("content-type", "application/json"),
    )


# ---------------------------------------------------------------------------
# GET /v1/audit
# ---------------------------------------------------------------------------

@app.get("/v1/audit")
async def audit_endpoint() -> JSONResponse:
    """Return aggregated metrics on all intercepted PII breaches."""
    # Aggregate totals across all events
    totals: dict[str, int] = defaultdict(int)
    endpoint_counts: dict[str, int] = defaultdict(int)
    target_counts: dict[str, int] = defaultdict(int)

    for entry in _audit_trail:
        for pii_type, count in entry["breach_types"].items():
            totals[pii_type] += count
        endpoint_counts[entry["endpoint"]] += 1
        if entry.get("target"):
            target_counts[entry["target"]] += 1

    return JSONResponse(
        {
            "total_breach_events": len(_audit_trail),
            "pii_type_totals": dict(totals),
            "events_by_endpoint": dict(endpoint_counts),
            "events_by_target": dict(target_counts),
            "recent_events": _audit_trail[-20:],  # last 20 events
        }
    )


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "SentinelShield-PII"})
