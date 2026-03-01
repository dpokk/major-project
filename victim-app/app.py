"""
Victim Application — Project Sentinel MVP (Phase 2)
A Flask microservice with 6 failure scenarios for autonomous incident response testing.
Exposes Prometheus metrics and writes PII-enriched logs for Sentry sanitization.
"""

import logging
import os
import uuid
import random
import time
import threading
from datetime import datetime, timezone

from flask import Flask, Response, jsonify
from prometheus_client import (
    Counter, Gauge, Histogram,
    generate_latest, CONTENT_TYPE_LATEST,
)

# ---------------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------------
app = Flask(__name__)

# ---------------------------------------------------------------------------
# Prometheus Metrics
# ---------------------------------------------------------------------------
ERROR_COUNTER = Counter(
    "http_errors_total",
    "Total number of HTTP 500 errors returned by the victim app",
)
MEMORY_GAUGE = Gauge(
    "memory_usage_bytes",
    "Simulated heap memory usage in bytes",
)
REQUEST_DURATION = Histogram(
    "request_duration_seconds",
    "Request latency in seconds",
    buckets=[0.5, 1, 2, 3, 5, 8, 10],
)
DEPENDENCY_ERRORS = Counter(
    "dependency_errors_total",
    "Total number of upstream dependency failures",
    ["dependency"],
)
CPU_GAUGE = Gauge(
    "cpu_usage_percent",
    "Simulated CPU usage percentage",
)
DISK_GAUGE = Gauge(
    "disk_usage_percent",
    "Simulated disk usage percentage",
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
# Simulated state for memory leak scenario
# ---------------------------------------------------------------------------
_leaked_memory = []

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
# Routes — Core
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Health-check / landing page."""
    logger.info("Health-check requested from client %s", _random_ip())
    return jsonify({
        "service": "victim-app",
        "status": "running",
        "version": "2.0.0",
        "scenarios": [
            "/trigger-error",
            "/scenario/memory-leak",
            "/scenario/high-latency",
            "/scenario/cascade-failure",
            "/scenario/cpu-spike",
            "/scenario/disk-full",
        ],
    })


@app.route("/metrics")
def metrics():
    """Prometheus scrape endpoint — serves all registered metrics."""
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


# ---------------------------------------------------------------------------
# Scenario 0: Generic 500 (original)
# ---------------------------------------------------------------------------
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
# Scenario 1: Memory Leak
# ---------------------------------------------------------------------------
@app.route("/scenario/memory-leak")
def scenario_memory_leak():
    """
    Simulates a memory leak by accumulating data in a global list.
    Each call adds ~50MB of simulated heap pressure.
    """
    global _leaked_memory

    trace_id = _random_uuid()
    fake_ip = _random_ip()
    fake_uuid = _random_uuid()

    # Simulate memory leak — accumulate data
    chunk_size = 50 * 1024 * 1024  # 50MB
    _leaked_memory.append(b"X" * min(chunk_size, 1024 * 100))  # 100KB actual

    # Update simulated memory gauge (grows with each call)
    simulated_heap = len(_leaked_memory) * 50 * 1024 * 1024  # Pretend 50MB each
    MEMORY_GAUGE.set(simulated_heap)

    heap_mb = simulated_heap / (1024 * 1024)

    logger.error(
        "MEMORY LEAK DETECTED | trace_id=%s | source_ip=%s | user_id=%s | "
        "heap_used=%.0fMB | heap_limit=512MB | gc_cycles=%d | "
        "endpoint=/scenario/memory-leak | status=503 | "
        "message=Heap memory exceeding safe threshold | "
        "timestamp=%s",
        trace_id, fake_ip, fake_uuid,
        heap_mb, random.randint(30, 60),
        datetime.now(timezone.utc).isoformat(),
    )

    logger.warning(
        "GC pressure | trace_id=%s | gc_pause_ms=%d | generation=2 | "
        "objects_collected=%d | client_ip=%s",
        trace_id,
        random.randint(200, 500),
        random.randint(8000, 15000),
        fake_ip,
    )

    logger.info(
        "Auto-scaling requested | trace_id=%s | node_id=%s | "
        "current_replicas=3 | target_replicas=5 | result=pending",
        trace_id, fake_uuid,
    )

    return jsonify({
        "error": "Memory leak detected",
        "scenario": "memory-leak",
        "trace_id": trace_id,
        "heap_used_mb": heap_mb,
        "status": 503,
    }), 503


# ---------------------------------------------------------------------------
# Scenario 2: High Latency
# ---------------------------------------------------------------------------
@app.route("/scenario/high-latency")
def scenario_high_latency():
    """
    Simulates slow response times (3-8 seconds).
    Represents database query timeouts or downstream API delays.
    """

    trace_id = _random_uuid()
    fake_ip = _random_ip()
    fake_uuid = _random_uuid()

    # Simulate slow processing
    delay = random.uniform(3.0, 8.0)

    logger.error(
        "HIGH LATENCY DETECTED | trace_id=%s | source_ip=%s | user_id=%s | "
        "response_time=%.2fs | threshold=2.0s | "
        "endpoint=/scenario/high-latency | status=504 | "
        "message=Request processing exceeded timeout threshold | "
        "timestamp=%s",
        trace_id, fake_ip, fake_uuid, delay,
        datetime.now(timezone.utc).isoformat(),
    )

    logger.warning(
        "Database query slow | trace_id=%s | query=SELECT * FROM orders "
        "WHERE user_id=%s | execution_time=%.2fs | "
        "connection_pool_used=48/50 | client_ip=%s",
        trace_id, fake_uuid, delay - 0.5, fake_ip,
    )

    logger.info(
        "Circuit breaker triggered | trace_id=%s | service=order-service | "
        "state=OPEN | failures=12 | threshold=10 | node_id=%s",
        trace_id, fake_uuid,
    )

    # Actually sleep to make it realistic
    time.sleep(delay)

    # Record in histogram
    REQUEST_DURATION.observe(delay)

    return jsonify({
        "error": "Request timeout",
        "scenario": "high-latency",
        "trace_id": trace_id,
        "response_time_seconds": round(delay, 2),
        "status": 504,
    }), 504


# ---------------------------------------------------------------------------
# Scenario 3: Cascade Failure (Dependency Down)
# ---------------------------------------------------------------------------
@app.route("/scenario/cascade-failure")
def scenario_cascade_failure():
    """
    Simulates upstream dependency failures (payment-service, auth-service).
    Represents microservice dependency chain breaking.
    """

    trace_id = _random_uuid()
    fake_ip = _random_ip()
    fake_uuid = _random_uuid()

    failed_services = random.sample(
        ["payment-service", "auth-service", "inventory-service", "notification-service"],
        k=random.randint(2, 3),
    )

    for svc in failed_services:
        DEPENDENCY_ERRORS.labels(dependency=svc).inc()

    logger.error(
        "CASCADE FAILURE | trace_id=%s | source_ip=%s | user_id=%s | "
        "failed_dependencies=%s | healthy_dependencies=%d/%d | "
        "endpoint=/scenario/cascade-failure | status=502 | "
        "message=Multiple upstream services unreachable | "
        "timestamp=%s",
        trace_id, fake_ip, fake_uuid,
        ",".join(failed_services),
        4 - len(failed_services), 4,
        datetime.now(timezone.utc).isoformat(),
    )

    for svc in failed_services:
        logger.warning(
            "Dependency unreachable | trace_id=%s | service=%s | "
            "last_healthy=%ds ago | retry_count=3 | "
            "error=ConnectionRefused | target_ip=%s",
            trace_id, svc,
            random.randint(15, 120),
            _random_ip(),
        )

    logger.info(
        "Failover initiated | trace_id=%s | node_id=%s | "
        "strategy=circuit_breaker | fallback=cached_response | result=degraded",
        trace_id, fake_uuid,
    )

    return jsonify({
        "error": "Upstream dependency failure",
        "scenario": "cascade-failure",
        "trace_id": trace_id,
        "failed_services": failed_services,
        "status": 502,
    }), 502


# ---------------------------------------------------------------------------
# Scenario 4: CPU Spike
# ---------------------------------------------------------------------------
@app.route("/scenario/cpu-spike")
def scenario_cpu_spike():
    """
    Simulates CPU overload via a tight computation loop (2-3 seconds).
    Represents runaway processes or inefficient algorithms.
    """

    trace_id = _random_uuid()
    fake_ip = _random_ip()
    fake_uuid = _random_uuid()

    cpu_pct = random.uniform(92.0, 99.5)
    CPU_GAUGE.set(cpu_pct)

    logger.error(
        "CPU SPIKE DETECTED | trace_id=%s | source_ip=%s | user_id=%s | "
        "cpu_usage=%.1f%% | threshold=85%% | cores_saturated=7/8 | "
        "endpoint=/scenario/cpu-spike | status=503 | "
        "message=CPU usage exceeding critical threshold | "
        "timestamp=%s",
        trace_id, fake_ip, fake_uuid, cpu_pct,
        datetime.now(timezone.utc).isoformat(),
    )

    logger.warning(
        "Process runaway | trace_id=%s | pid=1847 | "
        "thread_count=142 | cpu_time=347.2s | "
        "top_function=data_aggregation_loop | client_ip=%s",
        trace_id, fake_ip,
    )

    logger.info(
        "Throttling applied | trace_id=%s | node_id=%s | "
        "action=cpu_throttle | limit=80%% | cgroup=sentinel-worker | result=pending",
        trace_id, fake_uuid,
    )

    # Actually burn CPU for 2-3 seconds
    duration = random.uniform(2.0, 3.0)
    end_time = time.time() + duration
    while time.time() < end_time:
        _ = sum(i * i for i in range(1000))

    return jsonify({
        "error": "CPU spike detected",
        "scenario": "cpu-spike",
        "trace_id": trace_id,
        "cpu_percent": round(cpu_pct, 1),
        "status": 503,
    }), 503


# ---------------------------------------------------------------------------
# Scenario 5: Disk Full
# ---------------------------------------------------------------------------
@app.route("/scenario/disk-full")
def scenario_disk_full():
    """
    Simulates disk space exhaustion.
    Represents log bloat or temp file accumulation filling the disk.
    """

    trace_id = _random_uuid()
    fake_ip = _random_ip()
    fake_uuid = _random_uuid()

    disk_pct = random.uniform(94.0, 99.8)
    DISK_GAUGE.set(disk_pct)

    logger.error(
        "DISK SPACE CRITICAL | trace_id=%s | source_ip=%s | user_id=%s | "
        "disk_usage=%.1f%% | partition=/data | available=%.0fMB | "
        "endpoint=/scenario/disk-full | status=507 | "
        "message=Disk space below critical threshold | "
        "timestamp=%s",
        trace_id, fake_ip, fake_uuid,
        disk_pct, (100 - disk_pct) * 10.24,
        datetime.now(timezone.utc).isoformat(),
    )

    logger.warning(
        "Large file detected | trace_id=%s | path=/data/logs/archive.tar.gz | "
        "size=4.7GB | owner=app-worker | age_days=45 | client_ip=%s",
        trace_id, fake_ip,
    )

    logger.warning(
        "Write failure | trace_id=%s | operation=INSERT | "
        "table=audit_logs | error=No space left on device | "
        "errno=ENOSPC | node_id=%s",
        trace_id, fake_uuid,
    )

    logger.info(
        "Cleanup initiated | trace_id=%s | node_id=%s | "
        "action=prune_old_logs | target_free=20%% | result=in_progress",
        trace_id, fake_uuid,
    )

    return jsonify({
        "error": "Disk space critical",
        "scenario": "disk-full",
        "trace_id": trace_id,
        "disk_usage_percent": round(disk_pct, 1),
        "status": 507,
    }), 507


# ---------------------------------------------------------------------------
# Utility: Reset simulated state
# ---------------------------------------------------------------------------
@app.route("/reset")
def reset_state():
    """Reset all simulated failure state (memory, CPU, disk gauges)."""
    global _leaked_memory
    _leaked_memory = []
    MEMORY_GAUGE.set(0)
    CPU_GAUGE.set(0)
    DISK_GAUGE.set(0)
    logger.info("All simulated failure state has been reset")
    return jsonify({"status": "reset", "message": "All failure state cleared"})


# ---------------------------------------------------------------------------
# Entrypoint (for development; production uses gunicorn)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Victim app starting on port 5001 | node=%s", _random_uuid())
    app.run(host="0.0.0.0", port=5001, debug=False)
