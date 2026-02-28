"""
Sentry Agent — Project Sentinel MVP (Tier 1 : Privacy Guard)
FastAPI server that:
  1. Receives Alertmanager webhook payloads
  2. Fetches the last 20 lines of victim-app logs (shared volume)
  3. Sanitizes PII (IPs, UUIDs) via regex
  4. Forwards redacted payload to Cloud Architect using MCP-style JSON
"""

import os
import re
import logging
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CLOUD_ARCHITECT_URL = os.environ.get(
    "CLOUD_ARCHITECT_URL", "http://cloud-architect:8002/mcp/tools/call"
)
LOG_FILE_PATH = os.environ.get("VICTIM_LOG_PATH", "/app/logs/app.log")
LOG_TAIL_LINES = 10
MAX_LOG_BYTES = 2048  # 2KB hard cap to reduce token usage

app = FastAPI(title="Sentry Agent", version="1.0.0")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("sentry-agent")

# ---------------------------------------------------------------------------
# PII Sanitization — Regex-based
# ---------------------------------------------------------------------------
# IPv4: 192.168.1.100
RE_IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
# IPv6: 2001:0db8:85a3::8a2e:0370:7334  (simplified pattern)
RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
# UUID: 550e8400-e29b-41d4-a716-446655440000
RE_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


def sanitize(text: str) -> str:
    """Mask all IPv4, IPv6, and UUID occurrences in *text*."""
    text = RE_IPV4.sub("[REDACTED-IP]", text)
    text = RE_IPV6.sub("[REDACTED-IP]", text)
    text = RE_UUID.sub("[REDACTED-UUID]", text)
    return text


# ---------------------------------------------------------------------------
# Log Fetcher — reads last N lines from shared volume
# ---------------------------------------------------------------------------
def fetch_victim_logs(n: int = LOG_TAIL_LINES) -> str:
    """Return the last *n* lines from the victim-app log file."""
    try:
        if not os.path.exists(LOG_FILE_PATH):
            logger.warning("Log file not found at %s", LOG_FILE_PATH)
            return "[LOG FILE NOT FOUND]"

        with open(LOG_FILE_PATH, "r") as fh:
            lines = fh.readlines()

        tail = lines[-n:] if len(lines) >= n else lines
        result = "".join(tail)

        # Enforce 2KB payload cap
        if len(result.encode("utf-8")) > MAX_LOG_BYTES:
            result = result.encode("utf-8")[:MAX_LOG_BYTES].decode("utf-8", errors="ignore")
            logger.info("Log payload truncated to %d bytes", MAX_LOG_BYTES)

        return result
    except Exception as exc:
        logger.error("Failed to read victim logs: %s", exc)
        return f"[ERROR READING LOGS: {exc}]"


# ---------------------------------------------------------------------------
# MCP Payload Builder
# ---------------------------------------------------------------------------
def build_mcp_payload(alert_name: str, redacted_logs: str) -> dict:
    """Construct an MCP-style tool-call request for the Cloud Architect."""
    return {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": f"sentry-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
        "params": {
            "name": "analyze_incident",
            "arguments": {
                "alert_name": alert_name,
                "redacted_logs": redacted_logs,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "sentry-agent-tier1",
            },
        },
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok", "service": "sentry-agent"}


@app.post("/webhook/alert")
async def receive_alert(request: Request):
    """
    Alertmanager webhook receiver.
    Pipeline: receive alert → fetch logs → sanitize → forward to Cloud Architect.
    """
    payload = await request.json()
    logger.info("=== ALERT RECEIVED ===")
    logger.info("Payload: %s", payload)

    # Extract alert details from Alertmanager webhook format
    alerts = payload.get("alerts", [])
    if not alerts:
        logger.warning("No alerts in payload")
        return JSONResponse({"status": "ignored", "reason": "no alerts"})

    for alert in alerts:
        alert_name = alert.get("labels", {}).get("alertname", "UnknownAlert")
        alert_status = alert.get("status", "unknown")
        severity = alert.get("labels", {}).get("severity", "unknown")

        logger.info(
            "Processing alert: name=%s status=%s severity=%s",
            alert_name,
            alert_status,
            severity,
        )

        # Skip resolved alerts for the MVP
        if alert_status == "resolved":
            logger.info("Alert %s resolved — skipping", alert_name)
            continue

        # --- Step 1: Fetch raw logs ---
        raw_logs = fetch_victim_logs()
        logger.info("Fetched %d characters of raw logs", len(raw_logs))

        # --- Step 2: Sanitize PII ---
        redacted_logs = sanitize(raw_logs)
        logger.info("PII sanitization complete")
        logger.info("--- REDACTED LOGS (preview) ---")
        for line in redacted_logs.strip().split("\n")[-5:]:
            logger.info("  %s", line)

        # --- Step 3: Forward to Cloud Architect via MCP ---
        mcp_payload = build_mcp_payload(alert_name, redacted_logs)
        logger.info("Forwarding to Cloud Architect at %s", CLOUD_ARCHITECT_URL)

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(CLOUD_ARCHITECT_URL, json=mcp_payload)
                resp.raise_for_status()
                architect_response = resp.json()
                logger.info(
                    "Cloud Architect response: %s",
                    architect_response,
                )
        except httpx.HTTPError as exc:
            logger.error("Failed to reach Cloud Architect: %s", exc)
            return JSONResponse(
                {"status": "error", "detail": str(exc)}, status_code=502
            )

    return JSONResponse({"status": "processed", "alerts_count": len(alerts)})


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
