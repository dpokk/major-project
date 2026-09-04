"""

Cloud Architect — Project Sentinel Phase 1 (Tier 2 : The Brain)
FastAPI server with agentic tool-use loop:
  1. Receives MCP-style tool-call requests from the Sentry Agent
  2. Runs an agentic investigation loop via Groq (Llama 3.3 70B)
     - LLM decides which tools to call (Prometheus, logs, health checks)
     - Tools return real live data from the Docker environment
     - LLM writes RCA after gathering evidence (max 6 tool calls)
  3. Posts the RCA report + investigation trace to Slack

LLM Provider: Groq Cloud (free tier — 30 RPM, 14,400 RPD)
"""

import os
import re
import json
import time
import logging
from datetime import datetime, timezone, timedelta

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
VICTIM_LOG_PATH = os.environ.get("VICTIM_LOG_PATH", "/app/logs/app.log")
REMEDIATION_URL = os.environ.get(
    "REMEDIATION_URL", "http://localhost:8002/remediate"
)

app = FastAPI(title="Cloud Architect", version="2.0.0")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("cloud-architect")

# ---------------------------------------------------------------------------
# PII Redaction (mirrors sentry-agent patterns)
# ---------------------------------------------------------------------------
RE_IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
RE_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


def _redact_pii(text: str) -> str:
    """Mask all IPv4, IPv6, and UUID occurrences."""
    text = RE_IPV4.sub("[REDACTED-IP]", text)
    text = RE_IPV6.sub("[REDACTED-IP]", text)
    text = RE_UUID.sub("[REDACTED-UUID]", text)
    return text


# ---------------------------------------------------------------------------
# Groq LLM Client
# ---------------------------------------------------------------------------
_client = None

SYSTEM_PROMPT = """You are a senior Site Reliability Engineer performing Root Cause Analysis.
You will be given an alert name and redacted application logs.
Provide a structured incident analysis in this exact format:

**Root Cause:** One sentence identifying what failed and why.
**Impact:** One sentence describing the user/system impact.
**Evidence:** Cite 2-3 specific details from the logs (timestamps, error codes, service names).
**Remediation:** 2-3 concrete steps to fix the issue.

Be specific, reference log details, and keep each section to 1-2 sentences maximum."""

AGENT_SYSTEM_PROMPT = """You are an autonomous Site Reliability Engineering agent for Project Sentinel.

When you receive an alert, you MUST investigate it by calling the available tools before writing any conclusions. Do not guess or summarize without evidence.

Your investigation process:
1. ALWAYS start by calling query_prometheus or get_metric_snapshot to see the actual metric data
2. Call search_logs to find relevant log lines that explain what happened  
3. Call check_service_health if you suspect multiple services may be affected
4. After gathering evidence from at least 2 tool calls, write your final RCA

Your final RCA must follow this exact format:
**Root Cause:** One sentence — what failed and why, citing specific evidence.
**Impact:** One sentence — what was affected and to what degree.
**Evidence:** 2-3 bullet points citing specific data from your tool calls (include numbers, timestamps).
**Remediation:** 2-3 concrete numbered steps to resolve the issue.

Rules:
- Never write the final RCA until you have called at least 2 tools
- Always cite specific values from tool results (e.g. "error rate spiked to 14.1/s at 16:50:45")
- If a tool returns an error, note it and try a different approach
- Maximum 6 tool calls total before writing your conclusion
"""


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
# Retry-wrapped LLM call (fallback — single-shot RCA)
# ---------------------------------------------------------------------------
@retry(
    wait=wait_random_exponential(min=1, max=10),
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type(Exception),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,
)
def _generate_rca(prompt: str) -> str:
    """Fallback: single Groq call with retry logic for rate limits."""
    client = _get_client()
    response = client.chat.completions.create(
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
        max_tokens=800,
    )
    return response.choices[0].message.content.strip()


async def query_llm(alert_name: str, redacted_logs: str) -> str:
    """Fallback: Send alert context to Groq and return the RCA text."""
    if not GROQ_API_KEY:
        logger.error("GROQ_API_KEY not configured")
        return "[ERROR: GROQ_API_KEY not set — cannot generate RCA]"

    prompt = (
        f"ALERT: {alert_name}\n\n"
        f"REDACTED APPLICATION LOGS:\n{redacted_logs}\n\n"
        f"Provide your 2-sentence Root Cause Analysis:"
    )

    logger.info("Querying Groq model=%s (fallback single-call)", LLM_MODEL)

    try:
        rca = _generate_rca(prompt)
        logger.info("RCA response: %s", rca)
        return rca
    except Exception as exc:
        logger.error("LLM query failed: %s", exc)
        return f"[LLM ERROR: Could not generate RCA — {exc}]"


# ---------------------------------------------------------------------------
# Tool 1: query_prometheus
# ---------------------------------------------------------------------------
def query_prometheus(metric: str, minutes_ago: int = 10) -> str:
    """
    Query the Prometheus HTTP API for a metric over a time range.
    Returns a plain-English summary string. Never raises exceptions.
    """
    try:
        now = datetime.now(timezone.utc)
        start = now - timedelta(minutes=minutes_ago)

        params = {
            "query": metric,
            "start": start.isoformat(),
            "end": now.isoformat(),
            "step": "5s",
        }

        with httpx.Client(timeout=8.0) as client:
            resp = client.get(
                "http://prometheus:9090/api/v1/query_range", params=params
            )
            resp.raise_for_status()
            data = resp.json()

        if data.get("status") != "success":
            return f"Prometheus query failed: status={data.get('status')}"

        results = data.get("data", {}).get("result", [])
        if not results:
            return f"Metric '{metric}': no data returned for last {minutes_ago} min."

        # Format the first result series
        series = results[0]
        values = series.get("values", [])
        if not values:
            return f"Metric '{metric}': empty value set for last {minutes_ago} min."

        # Extract key data points (sample ~10 evenly spaced points for readability)
        total = len(values)
        step = max(1, total // 10)
        sampled = values[::step]

        # Find peak
        numeric_vals = []
        for ts, val in values:
            try:
                numeric_vals.append((ts, float(val)))
            except (ValueError, TypeError):
                continue

        formatted_points = []
        for ts, val in sampled:
            time_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
            formatted_points.append(f"[{time_str}] {val}")

        summary = f"Metric '{metric}': values over last {minutes_ago} min —\n"
        summary += ", ".join(formatted_points)

        if numeric_vals:
            peak_ts, peak_val = max(numeric_vals, key=lambda x: x[1])
            peak_time = datetime.fromtimestamp(peak_ts, tz=timezone.utc).strftime("%H:%M:%S")
            min_val = min(v for _, v in numeric_vals)
            summary += f"\nPeak value: {peak_val} at {peak_time}. Baseline was {min_val} before spike."

        return summary

    except Exception as exc:
        return f"Prometheus query failed: {exc}"


# ---------------------------------------------------------------------------
# Tool 2: search_logs
# ---------------------------------------------------------------------------
def search_logs(keyword: str, limit: int = 15) -> str:
    """
    Search the victim app's log file for lines matching a keyword.
    Applies PII redaction before returning. Never raises exceptions.
    """
    try:
        limit = min(limit, 30)  # Hard cap at 30

        if not VICTIM_LOG_PATH or not os.path.exists(VICTIM_LOG_PATH):
            return f"Log file not available: {VICTIM_LOG_PATH}"

        with open(VICTIM_LOG_PATH, "r") as fh:
            all_lines = fh.readlines()

        keyword_lower = keyword.lower()
        matching = [line for line in all_lines if keyword_lower in line.lower()]

        if not matching:
            return f"No log lines matching '{keyword}' found (searched {len(all_lines)} lines)."

        # Take the last `limit` matches
        selected = matching[-limit:]

        # Apply PII redaction
        redacted = [_redact_pii(line.rstrip()) for line in selected]

        result = f"Found {len(matching)} lines matching '{keyword}' (showing last {len(selected)}):\n"
        result += "\n".join(redacted)
        return result

    except Exception as exc:
        return f"Log search failed: {exc}"


# ---------------------------------------------------------------------------
# Tool 3: check_service_health
# ---------------------------------------------------------------------------
SERVICE_HEALTH_URLS = {
    "victim-app": ["http://victim-app:5001/health", "http://victim-app:5001/metrics"],
    "prometheus": ["http://prometheus:9090/-/healthy"],
    "sentry-agent": ["http://sentry-agent:8001/health"],
    "cloud-architect": ["http://cloud-architect:8002/health"],
}


def check_service_health(service_name: str) -> str:
    """
    Check if a service inside the Docker network is responding.
    Never raises exceptions.
    """
    try:
        urls = SERVICE_HEALTH_URLS.get(service_name)
        if not urls:
            return f"Unknown service '{service_name}'. Known: {', '.join(SERVICE_HEALTH_URLS.keys())}"

        for url in urls:
            try:
                start_time = time.time()
                with httpx.Client(timeout=5.0) as client:
                    resp = client.get(url)
                elapsed_ms = int((time.time() - start_time) * 1000)

                status = resp.status_code
                if 200 <= status < 300:
                    return f"{service_name}: HTTP {status}, response_time={elapsed_ms}ms — healthy"
                elif 500 <= status < 600:
                    return f"{service_name}: HTTP {status}, response_time={elapsed_ms}ms — degraded"
                else:
                    return f"{service_name}: HTTP {status}, response_time={elapsed_ms}ms — status unknown"

            except httpx.ConnectError:
                continue  # Try next URL if available
            except httpx.TimeoutException:
                return f"{service_name}: Connection timed out (5s) — service is unresponsive"

        return f"{service_name}: Connection refused — service is down"

    except Exception as exc:
        return f"Health check failed for '{service_name}': {exc}"


# ---------------------------------------------------------------------------
# Tool 4: get_metric_snapshot
# ---------------------------------------------------------------------------
FRIENDLY_METRICS = {
    "error_rate": "rate(http_errors_total[1m])",
    "memory": "memory_usage_bytes",
    "cpu": "cpu_usage_percent",
    "disk": "disk_usage_percent",
    "latency_p95": "histogram_quantile(0.95, rate(request_duration_seconds_bucket[1m]))",
    "dep_errors": "rate(dependency_errors_total[1m])",
}


def get_metric_snapshot(metric_name: str) -> str:
    """
    Get the current (latest) value of a metric via instant Prometheus query.
    Accepts friendly names or raw PromQL. Never raises exceptions.
    """
    try:
        promql = FRIENDLY_METRICS.get(metric_name, metric_name)

        with httpx.Client(timeout=8.0) as client:
            resp = client.get(
                "http://prometheus:9090/api/v1/query",
                params={"query": promql},
            )
            resp.raise_for_status()
            data = resp.json()

        if data.get("status") != "success":
            return f"Snapshot failed: status={data.get('status')}"

        results = data.get("data", {}).get("result", [])
        if not results:
            return f"{promql} = no data (metric may not exist or have no samples)"

        # Extract value from first result
        value = results[0].get("value", [None, "N/A"])
        if len(value) >= 2:
            val = value[1]
            return f"{promql} = {val} (current snapshot)"
        else:
            return f"{promql} = N/A (unexpected response format)"

    except Exception as exc:
        return f"Snapshot failed: {exc}"


# ---------------------------------------------------------------------------
# Tool dispatch map
# ---------------------------------------------------------------------------
TOOL_DISPATCH = {
    "query_prometheus": query_prometheus,
    "search_logs": search_logs,
    "check_service_health": check_service_health,
    "get_metric_snapshot": get_metric_snapshot,
}

# ---------------------------------------------------------------------------
# Tool Schema for Groq (OpenAI-compatible)
# ---------------------------------------------------------------------------
TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "query_prometheus",
            "description": "Query a Prometheus metric over a time range. Use this to investigate whether a metric spiked, when it started, and how severe it is. Always use this first when you receive an alert.",
            "parameters": {
                "type": "object",
                "properties": {
                    "metric": {
                        "type": "string",
                        "description": "A valid PromQL expression, e.g. 'rate(http_errors_total[5m])' or 'memory_usage_bytes'",
                    },
                    "minutes_ago": {
                        "type": "integer",
                        "description": "How many minutes back to query. Default 10.",
                        "default": 10,
                    },
                },
                "required": ["metric"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_logs",
            "description": "Search the application log file for lines matching a keyword. Use this to find specific error messages, stack traces, or patterns related to the incident.",
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Case-insensitive keyword to search for in the logs",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of matching lines to return. Default 15.",
                        "default": 15,
                    },
                },
                "required": ["keyword"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_service_health",
            "description": "Check if a specific service inside the system is healthy and responding. Use this to determine if the issue is isolated or if multiple services are affected.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service_name": {
                        "type": "string",
                        "description": "Name of the service to check. Options: 'victim-app', 'prometheus', 'sentry-agent', 'cloud-architect'",
                    }
                },
                "required": ["service_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_metric_snapshot",
            "description": "Get the current value of a named metric as a quick spot-check. Use this for a fast reading without needing a full time-range query.",
            "parameters": {
                "type": "object",
                "properties": {
                    "metric_name": {
                        "type": "string",
                        "description": "Friendly name: 'error_rate', 'memory', 'cpu', 'disk', 'latency_p95', 'dep_errors'. Or any raw PromQL expression.",
                    }
                },
                "required": ["metric_name"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Agentic Investigation Loop
# ---------------------------------------------------------------------------
def build_initial_message(alert_name: str, redacted_logs: str, timestamp: str) -> str:
    return f"""ALERT RECEIVED: {alert_name}
Timestamp: {timestamp}

Initial log sample provided by Sentry Agent (PII already redacted):
{redacted_logs}

Begin your investigation. Use the available tools to gather evidence, then write your RCA."""


def _execute_tool(tool_name: str, arguments: dict) -> str:
    """Execute a tool by name with given arguments. Always returns a string."""
    func = TOOL_DISPATCH.get(tool_name)
    if func is None:
        return f"Unknown tool: {tool_name}"
    try:
        return func(**arguments)
    except Exception as exc:
        return f"Tool '{tool_name}' execution failed: {exc}"


def _summarize_result(result: str, max_len: int = 80) -> str:
    """Create a short summary of a tool result for the investigation trace display."""
    # Take the first line or first max_len chars
    first_line = result.split("\n")[0]
    if len(first_line) > max_len:
        return first_line[:max_len] + "..."
    return first_line


def run_agentic_investigation(
    alert_name: str, redacted_logs: str, timestamp: str
) -> tuple[str, list[dict]]:
    """
    Run the agentic tool-use loop. Returns (rca_text, investigation_trace).
    
    The LLM decides which tools to call, we execute them and feed results back,
    and the loop continues until the LLM writes a final text RCA or we hit
    the 6-iteration safety cap.
    """
    client = _get_client()
    investigation_trace = []

    # Step 1: Build initial messages
    messages = [
        {"role": "system", "content": AGENT_SYSTEM_PROMPT},
        {"role": "user", "content": build_initial_message(alert_name, redacted_logs, timestamp)},
    ]

    max_iterations = 6
    iteration = 0
    total_tool_calls = 0
    last_text = None

    logger.info("[AGENT] Starting agentic investigation for alert=%s", alert_name)

    while iteration < max_iterations:
        iteration += 1
        logger.info("[AGENT] Iteration %d/%d", iteration, max_iterations)

        # Step 2: Call Groq with tools
        try:
            response = client.chat.completions.create(
                model=LLM_MODEL,
                messages=messages,
                tools=TOOLS_SCHEMA,
                tool_choice="auto",
                temperature=0.3,
                max_tokens=1200,
            )
        except Exception as exc:
            logger.error("[AGENT] Groq API call failed: %s", exc)
            investigation_trace.append({
                "step": total_tool_calls + 1,
                "type": "error",
                "content": f"Groq API call failed: {exc}",
            })
            break

        choice = response.choices[0]
        message = choice.message

        # Step 3: Check if response contains tool calls
        if message.tool_calls:
            # Append the assistant message (with tool calls) to conversation
            messages.append({
                "role": "assistant",
                "content": message.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in message.tool_calls
                ],
            })

            for tc in message.tool_calls:
                total_tool_calls += 1
                tool_name = tc.function.name

                # Parse arguments
                try:
                    tool_args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    tool_args = {}

                logger.info(
                    "[AGENT] Tool call %d: %s(%s)",
                    total_tool_calls,
                    tool_name,
                    json.dumps(tool_args),
                )

                # Execute the tool
                start_time = time.time()
                result = _execute_tool(tool_name, tool_args)
                duration_ms = int((time.time() - start_time) * 1000)

                logger.info(
                    "[AGENT] Tool result %d: %s (took %dms)",
                    total_tool_calls,
                    _summarize_result(result),
                    duration_ms,
                )

                # Record in investigation trace
                investigation_trace.append({
                    "step": total_tool_calls,
                    "type": "tool_call",
                    "tool": tool_name,
                    "arguments": tool_args,
                    "result": result,
                    "duration_ms": duration_ms,
                })

                # Append tool result to messages for next LLM call
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })

            # Go back to step 2 (continue loop)
            continue

        # Step 4: Response is a text message (no tool calls) — this is the final RCA
        if message.content:
            last_text = message.content.strip()
            logger.info(
                "[AGENT] Final RCA generated after %d tool calls",
                total_tool_calls,
            )
            investigation_trace.append({
                "step": total_tool_calls + 1,
                "type": "final_rca",
                "content": last_text,
                "total_tool_calls": total_tool_calls,
            })
            return last_text, investigation_trace

    # Step 5: Safety cap reached — use whatever we have
    logger.warning(
        "[AGENT] Safety cap reached (%d iterations). Tool calls made: %d",
        max_iterations,
        total_tool_calls,
    )

    if last_text:
        investigation_trace.append({
            "step": total_tool_calls + 1,
            "type": "final_rca",
            "content": last_text,
            "total_tool_calls": total_tool_calls,
        })
        return last_text, investigation_trace

    fallback_msg = (
        f"**Root Cause:** Investigation timed out after {total_tool_calls} tool calls — "
        f"unable to determine root cause definitively.\n"
        f"**Impact:** Alert '{alert_name}' requires manual investigation.\n"
        f"**Evidence:** Agent gathered data from {total_tool_calls} tool calls but could not converge.\n"
        f"**Remediation:** 1. Review the investigation trace below. 2. Manually investigate the alert."
    )
    investigation_trace.append({
        "step": total_tool_calls + 1,
        "type": "final_rca",
        "content": fallback_msg,
        "total_tool_calls": total_tool_calls,
    })
    return fallback_msg, investigation_trace


# ---------------------------------------------------------------------------
# Slack Integration
# ---------------------------------------------------------------------------
def _build_trace_text(investigation_trace: list[dict]) -> str:
    """Build a human-readable investigation trace for the Slack message."""
    lines = []
    for entry in investigation_trace:
        if entry.get("type") == "tool_call":
            step = entry["step"]
            tool = entry["tool"]
            args = entry.get("arguments", {})
            result_summary = _summarize_result(entry.get("result", ""), max_len=60)

            # Format arguments compactly
            arg_str = ", ".join(f"{k}={repr(v)}" for k, v in args.items())
            lines.append(f"Step {step} — {tool}({arg_str}) → {result_summary}")

    return "\n".join(lines) if lines else "No tool calls recorded."


async def post_to_slack(
    alert_name: str,
    rca: str,
    timestamp: str,
    investigation_trace: list[dict] | None = None,
):
    """Post the RCA report to Slack with investigation trace and remediation button."""
    if not SENTINEL_OPS_WEBHOOK:
        logger.warning("SENTINEL_OPS_WEBHOOK not configured — skipping Slack post")
        logger.info("=== SLACK MESSAGE (would be sent) ===")
        logger.info("Alert: %s", alert_name)
        logger.info("RCA: %s", rca)
        logger.info("Timestamp: %s", timestamp)
        if investigation_trace:
            logger.info("Investigation trace: %s", _build_trace_text(investigation_trace))
        return

    # Build trace text
    trace_text = ""
    if investigation_trace:
        trace_text = _build_trace_text(investigation_trace)

    blocks = [
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
    ]

    # Add investigation trace section
    if trace_text:
        blocks.extend([
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🔎 Investigation Trace:*\n```\n{trace_text}\n```",
                },
            },
        ])

    blocks.extend([
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
    ])

    slack_payload = {"blocks": blocks}

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
    Receives tool-call payload from Sentry, runs agentic investigation via Groq,
    posts RCA + investigation trace to Slack.
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

    # --- Agentic Investigation (with fallback) ---
    rca = ""
    investigation_trace = []

    try:
        rca, investigation_trace = run_agentic_investigation(
            alert_name, redacted_logs, timestamp
        )
        logger.info("[AGENT] Investigation complete — %d trace entries", len(investigation_trace))
    except Exception as exc:
        logger.error("[AGENT] Agentic loop failed, falling back to single-call RCA: %s", exc)
        rca = await query_llm(alert_name, redacted_logs)
        investigation_trace = [{
            "step": 1,
            "type": "fallback",
            "content": f"Agentic loop failed ({exc}), used single-call RCA",
        }]

    # --- Post to Slack ---
    await post_to_slack(alert_name, rca, timestamp, investigation_trace)

    # --- Return MCP-style response ---
    response = {
        "jsonrpc": "2.0",
        "id": payload.get("id", "unknown"),
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": rca,
                }
            ],
            "isError": False,
            "investigation_trace": investigation_trace,
        },
    }

    logger.info("=== RCA COMPLETE ===")
    logger.info("Result: %s", rca[:200])
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
