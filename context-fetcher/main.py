"""
Context Fetcher — Project Sentinel Phase 3 (Step 1)
FastAPI service that:
  1. Receives alert context requests (alert_name, service, trace_id)
  2. Queries the OTel Collector's exported log file for relevant entries
  3. Returns a standardized context bundle for the Sentry Agent

This module decouples telemetry retrieval from the Sentry's reasoning logic.
"""

import os
import json
import logging
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
OTEL_LOG_FILE = os.environ.get("OTEL_LOG_FILE", "/data/otel-logs.json")
MAX_LOG_ENTRIES = int(os.environ.get("MAX_LOG_ENTRIES", "30"))

app = FastAPI(title="Context Fetcher", version="1.0.0")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("context-fetcher")

# ---------------------------------------------------------------------------
# Alert keyword mapping (mirrors Sentry's ALERT_LOG_KEYWORDS)
# Used to filter OTel log records by alert type
# ---------------------------------------------------------------------------
ALERT_LOG_KEYWORDS = {
    "CriticalServiceFailure": ["CRITICAL FAILURE", "Stack trace context", "Recovery attempted"],
    "MemoryLeakDetected": ["MEMORY LEAK", "GC pressure", "Auto-scaling requested"],
    "HighLatencyAlert": ["HIGH LATENCY", "Database query slow", "Circuit breaker"],
    "DependencyFailure": ["CASCADE FAILURE", "Dependency unreachable", "Failover initiated"],
    "CPUSpikeDetected": ["CPU SPIKE", "Process runaway", "Throttling applied"],
}
DEFAULT_KEYWORDS = ["ERROR", "CRITICAL", "WARNING"]


# ---------------------------------------------------------------------------
# Request / Response Schema
# ---------------------------------------------------------------------------
class ContextRequest(BaseModel):
    alert_name: str
    service: str = "victim-app"
    trace_id: str | None = None


# ---------------------------------------------------------------------------
# OTel Log File Reader
# ---------------------------------------------------------------------------
def _read_otel_logs() -> list[dict]:
    """
    Read the OTel Collector's file export (JSONL format).
    Each line is a JSON object representing a log record or span.
    """
    if not os.path.exists(OTEL_LOG_FILE):
        logger.warning("OTel log file not found at %s", OTEL_LOG_FILE)
        return []

    records = []
    try:
        with open(OTEL_LOG_FILE, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception as exc:
        logger.error("Failed to read OTel logs: %s", exc)

    return records


def _extract_log_bodies(records: list[dict], alert_name: str) -> list[str]:
    """
    Extract log body strings from OTel JSONL records, filtered by alert keywords.

    OTel file exporter writes records in this structure:
    {
      "resourceLogs": [{
        "scopeLogs": [{
          "logRecords": [{
            "body": { "stringValue": "..." },
            "severityText": "ERROR",
            ...
          }]
        }]
      }]
    }
    """
    keywords = ALERT_LOG_KEYWORDS.get(alert_name, DEFAULT_KEYWORDS)
    log_bodies = []

    for record in records:
        # Navigate the OTel JSONL structure
        resource_logs = record.get("resourceLogs", [])
        for rl in resource_logs:
            scope_logs = rl.get("scopeLogs", [])
            for sl in scope_logs:
                log_records = sl.get("logRecords", [])
                for lr in log_records:
                    body = lr.get("body", {})
                    text = body.get("stringValue", "")
                    if not text:
                        continue

                    # Filter by alert keywords
                    if any(kw in text for kw in keywords):
                        severity = lr.get("severityText", "UNKNOWN")
                        timestamp = lr.get("timeUnixNano", "")
                        log_bodies.append(f"[{severity}] {text}")

    # If no matches, return all log bodies as fallback
    if not log_bodies:
        logger.warning("No keyword matches for alert=%s — returning all logs", alert_name)
        for record in records:
            resource_logs = record.get("resourceLogs", [])
            for rl in resource_logs:
                scope_logs = rl.get("scopeLogs", [])
                for sl in scope_logs:
                    log_records = sl.get("logRecords", [])
                    for lr in log_records:
                        body = lr.get("body", {})
                        text = body.get("stringValue", "")
                        if text:
                            severity = lr.get("severityText", "UNKNOWN")
                            log_bodies.append(f"[{severity}] {text}")

    return log_bodies[-MAX_LOG_ENTRIES:]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok", "service": "context-fetcher", "version": "1.0.0"}


@app.post("/fetch-context")
async def fetch_context(req: ContextRequest):
    """
    Query OTel logs for the given alert and return a structured context bundle.

    This is the standardized output format from the master migration plan:
    {
      "service": "victim-app",
      "trace_id": "...",
      "recent_logs": ["...", "..."],
      "metrics_snapshot": { "alert_name": "...", ... }
    }
    """
    logger.info(
        "Context request: alert=%s service=%s trace_id=%s",
        req.alert_name, req.service, req.trace_id,
    )

    # Read and filter OTel logs
    records = _read_otel_logs()
    logger.info("Read %d raw OTel records from %s", len(records), OTEL_LOG_FILE)

    log_bodies = _extract_log_bodies(records, req.alert_name)
    logger.info("Extracted %d filtered log entries for alert=%s", len(log_bodies), req.alert_name)

    context_bundle = {
        "service": req.service,
        "trace_id": req.trace_id,
        "recent_logs": log_bodies,
        "metrics_snapshot": {
            "alert_name": req.alert_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "otel-collector",
            "log_count": len(log_bodies),
        },
    }

    return JSONResponse(context_bundle)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
