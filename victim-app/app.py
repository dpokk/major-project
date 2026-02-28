"""
Victim Application — Project Sentinel MVP
A Flask microservice that exposes Prometheus metrics and a /trigger-error endpoint.
Logs include synthetic PII (IPs, UUIDs) for testing the Sentry's sanitization pipeline.
"""

import logging
import os
import uuid
import random
from datetime import datetime, timezone

from flask import Flask, Response, jsonify
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

# ---------------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Prometheus metric
ERROR_COUNTER = Counter(
    "http_errors_total",
    "Total number of HTTP 500 errors returned by the victim app",
)

# ---------------------------------------------------------------------------
# Persistent File Logging (shared volume: /app/logs/app.log)
# ---------------------------------------------------------------------------
LOG_DIR = os.environ.get("LOG_DIR", "/app/logs")
LOG_FILE = os.path.join(LOG_DIR, "app.log")
os.makedirs(LOG_DIR, exist_ok=True)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(
    logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(
    logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
)

logger = logging.getLogger("victim-app")
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# ---------------------------------------------------------------------------
# Synthetic PII generators (for testing Sentry sanitization)
# ---------------------------------------------------------------------------

def _random_ip():
    """Generate a random IPv4 address."""
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _random_uuid():
    """Generate a random UUID."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Health-check / landing page."""
    logger.info("Health-check requested from client %s", _random_ip())
    return jsonify({
        "service": "victim-app",
        "status": "running",
        "version": "1.0.0",
    })


@app.route("/metrics")
def metrics():
    """Prometheus scrape endpoint — serves all registered metrics."""
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


@app.route("/trigger-error")
def trigger_error():
    """
    Deliberately induces a 500 error.
    - Increments the http_errors_total counter.
    - Writes a detailed log line containing synthetic PII (IP + UUID).
    """
    ERROR_COUNTER.inc()

    fake_ip = _random_ip()
    fake_uuid = _random_uuid()
    trace_id = _random_uuid()

    logger.error(
        "CRITICAL FAILURE | trace_id=%s | source_ip=%s | user_id=%s | "
        "endpoint=/trigger-error | status=500 | "
        "message=Manually triggered error for incident simulation | "
        "timestamp=%s",
        trace_id,
        fake_ip,
        fake_uuid,
        datetime.now(timezone.utc).isoformat(),
    )

    # Log a few additional context lines (to give the Sentry 20 lines to work with)
    logger.warning(
        "Stack trace context | trace_id=%s | module=victim-app.routes | "
        "function=trigger_error | client_ip=%s",
        trace_id,
        fake_ip,
    )
    logger.info(
        "Recovery attempted | trace_id=%s | action=auto_restart | "
        "node_id=%s | result=pending",
        trace_id,
        fake_uuid,
    )

    return jsonify({
        "error": "Simulated critical failure",
        "trace_id": trace_id,
        "status": 500,
    }), 500


# ---------------------------------------------------------------------------
# Entrypoint (for development; production uses gunicorn)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Victim app starting on port 5001 | node=%s", _random_uuid())
    app.run(host="0.0.0.0", port=5001, debug=False)
