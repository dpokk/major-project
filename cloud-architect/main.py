"""
Cloud Architect — Project Sentinel MVP (Tier 2 : The Brain)
FastAPI server that:
  1. Receives MCP-style tool-call requests from the Sentry Agent
  2. Queries Groq (Llama 3.3 70B) for a 2-sentence Root Cause Analysis
  3. Posts the RCA report + remediation button to Slack

LLM Provider: Groq Cloud (free tier — 30 RPM, 14,400 RPD)
"""

import os
import json
import logging
from datetime import datetime, timezone

import httpx
from groq import Groq
from tenacity import (
    retry,
    wait_random_exponential,
    stop_after_attempt,
    retry_if_exception_type,
    before_sleep_log,
)
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "llama-3.3-70b-versatile")
SENTINEL_OPS_WEBHOOK = os.environ.get("SENTINEL_OPS_WEBHOOK", "")
REMEDIATION_URL = os.environ.get(
    "REMEDIATION_URL", "http://localhost:8002/remediate"
)

app = FastAPI(title="Cloud Architect", version="1.0.0")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("cloud-architect")

# ---------------------------------------------------------------------------
# Groq LLM Client
# ---------------------------------------------------------------------------
_client = None

SYSTEM_PROMPT = """You are a senior Site Reliability Engineer performing Root Cause Analysis.
You will be given an alert name and redacted application logs.
Your task: provide a concise, exactly 2-sentence Root Cause Analysis.
Sentence 1: What happened (the failure mode).
Sentence 2: Why it happened (the root cause).
Be specific and reference details from the logs. Do NOT include any preamble or extra text."""


def _get_client():
    """Lazily initialize the Groq client."""
    global _client
    if _client is None:
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not configured")
        _client = Groq(api_key=GROQ_API_KEY)
        logger.info("Groq client initialized for model=%s", LLM_MODEL)
    return _client


# ---------------------------------------------------------------------------
# Retry-wrapped LLM call (exponential backoff for 429s)
# ---------------------------------------------------------------------------
@retry(
    wait=wait_random_exponential(min=1, max=10),
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type(Exception),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,
)
def _generate_rca(prompt: str) -> str:
    """Call Groq with retry logic for rate limits."""
    client = _get_client()
    response = client.chat.completions.create(
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
        max_tokens=200,
    )
    return response.choices[0].message.content.strip()


async def query_llm(alert_name: str, redacted_logs: str) -> str:
    """Send alert context to Groq and return the RCA text."""
    if not GROQ_API_KEY:
        logger.error("GROQ_API_KEY not configured")
        return "[ERROR: GROQ_API_KEY not set — cannot generate RCA]"

    prompt = (
        f"ALERT: {alert_name}\n\n"
        f"REDACTED APPLICATION LOGS:\n{redacted_logs}\n\n"
        f"Provide your 2-sentence Root Cause Analysis:"
    )

    logger.info("Querying Groq model=%s", LLM_MODEL)

    try:
        rca = _generate_rca(prompt)
        logger.info("RCA response: %s", rca)
        return rca
    except Exception as exc:
        logger.error("LLM query failed: %s", exc)
        return f"[LLM ERROR: Could not generate RCA — {exc}]"


# ---------------------------------------------------------------------------
# Slack Integration
# ---------------------------------------------------------------------------
async def post_to_slack(alert_name: str, rca: str, timestamp: str):
    """Post the RCA report to Slack with a remediation button."""
    if not SENTINEL_OPS_WEBHOOK:
        logger.warning("SENTINEL_OPS_WEBHOOK not configured — skipping Slack post")
        logger.info("=== SLACK MESSAGE (would be sent) ===")
        logger.info("Alert: %s", alert_name)
        logger.info("RCA: %s", rca)
        logger.info("Timestamp: %s", timestamp)
        return

    slack_payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Incident Alert: {alert_name}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Alert Name:*\n{alert_name}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n🔴 Critical",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Detected At:*\n{timestamp}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Status:*\nAwaiting Remediation",
                    },
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🔍 Root Cause Analysis (AI-Generated via Groq/Llama):*\n\n{rca}",
                },
            },
            {"type": "divider"},
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🔧 Execute Remediation",
                            "emoji": True,
                        },
                        "style": "danger",
                        "url": REMEDIATION_URL,
                        "action_id": "remediate_action",
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "📊 View Dashboard",
                            "emoji": True,
                        },
                        "url": "http://localhost:9090/alerts",
                        "action_id": "view_dashboard",
                    },
                ],
            },
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(SENTINEL_OPS_WEBHOOK, json=slack_payload)
            resp.raise_for_status()
            logger.info("✅ Slack notification sent successfully")
    except httpx.HTTPError as exc:
        logger.error("Failed to post to Slack: %s", exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok", "service": "cloud-architect", "llm": LLM_MODEL}


@app.post("/mcp/tools/call")
async def mcp_tools_call(request: Request):
    """
    MCP-compatible endpoint.
    Receives tool-call payload from Sentry, runs RCA via Groq, posts to Slack.
    """
    payload = await request.json()
    logger.info("=== MCP TOOL CALL RECEIVED ===")
    logger.info("Method: %s", payload.get("method"))

    params = payload.get("params", {})
    tool_name = params.get("name", "unknown")
    arguments = params.get("arguments", {})

    alert_name = arguments.get("alert_name", "UnknownAlert")
    redacted_logs = arguments.get("redacted_logs", "")
    timestamp = arguments.get("timestamp", datetime.now(timezone.utc).isoformat())

    logger.info("Tool: %s | Alert: %s", tool_name, alert_name)
    logger.info("Redacted logs length: %d chars", len(redacted_logs))

    # --- Step 1: Query Groq for RCA ---
    rca = await query_llm(alert_name, redacted_logs)

    # --- Step 2: Post to Slack ---
    await post_to_slack(alert_name, rca, timestamp)

    # --- Return MCP-style response ---
    response = {
        "jsonrpc": "2.0",
        "id": payload.get("id", "unknown"),
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({
                        "alert_name": alert_name,
                        "rca": rca,
                        "timestamp": timestamp,
                        "slack_notified": bool(SENTINEL_OPS_WEBHOOK),
                        "slack_channel": "#sentinel-ops",
                        "llm_provider": f"groq/{LLM_MODEL}",
                    }),
                }
            ],
            "isError": False,
        },
    }

    logger.info("=== RCA COMPLETE ===")
    logger.info("Result: %s", rca)
    return JSONResponse(response)


@app.post("/remediate")
async def remediate(request: Request):
    """Placeholder remediation endpoint (for Slack button)."""
    logger.info("🔧 Remediation triggered!")
    return JSONResponse({
        "status": "remediation_initiated",
        "message": "Auto-remediation workflow started (MVP stub)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
