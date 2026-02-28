# 🛡️ Project Sentinel

### Autonomous Incident Response System — MVP Prototype

> **From Metric Breach to Root Cause Analysis in under 45 seconds — with zero human intervention.**

Project Sentinel is a distributed, AI-powered incident response pipeline that detects anomalies in a monitored microservice, triages the incident locally with privacy-aware log sanitization, escalates to a cloud LLM for Root Cause Analysis, and delivers actionable intelligence to your team via Slack — all autonomously.

---

## Table of Contents

- [Why Project Sentinel?](#why-project-sentinel)
- [Architecture Overview](#architecture-overview)
- [Data Flow — Step by Step](#data-flow--step-by-step)
- [Component Deep Dive](#component-deep-dive)
  - [1. Victim Application (Flask)](#1-victim-application-flask)
  - [2. Prometheus + Alertmanager](#2-prometheus--alertmanager)
  - [3. Sentry Agent — Tier 1 (FastAPI)](#3-sentry-agent--tier-1-fastapi)
  - [4. Cloud Architect — Tier 2 (FastAPI + Gemini)](#4-cloud-architect--tier-2-fastapi--gemini)
- [Dual-Path Slack Alerting](#dual-path-slack-alerting)
- [Privacy & PII Sanitization](#privacy--pii-sanitization)
- [Model Context Protocol (MCP)](#model-context-protocol-mcp)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Verification & Testing](#verification--testing)
- [Project Structure](#project-structure)
- [Configuration Reference](#configuration-reference)
- [Success Criteria](#success-criteria)
- [Scalability Roadmap](#scalability-roadmap)

---

## Why Project Sentinel?

Modern microservice architectures generate an overwhelming volume of alerts — most of which are noise. Engineering teams suffer from **alert fatigue**, leading to slow response times and missed critical incidents.

Project Sentinel solves this with a **tiered intelligence model**:

| Layer | Role | Analogy |
|-------|------|---------|
| **Tier 1 — Local Sentry** | Fast, cheap, privacy-aware triage | Security guard at the gate |
| **Tier 2 — Cloud Architect** | Deep reasoning, Root Cause Analysis | Senior SRE on call |

The Sentry handles the "noise floor" locally — redacting sensitive data, fetching context, and formatting structured requests. Only redacted, enriched summaries reach the Cloud Architect (Gemini), which performs intelligent Root Cause Analysis and delivers a concise, actionable report to the operations team.

**Key design principles:**
- 🔒 **Privacy-first**: No raw PII ever leaves the local network
- ⚡ **Speed**: End-to-end latency target of < 45 seconds
- 🧠 **Intelligence**: AI-generated 2-sentence RCA, not just regurgitated logs
- 🏗️ **Scalable foundation**: Docker Compose today, Kubernetes tomorrow

---

## Architecture Overview

```
                            PROJECT SENTINEL — DISTRIBUTED CONTROL PLANE
                            
 ┌─────────────────────────────── LOCAL NETWORK ───────────────────────────────┐
 │                                                                             │
 │  ┌──────────────┐    scrape     ┌──────────────┐   fire     ┌────────────┐ │
 │  │  Victim App  │◄────/5s──────│  Prometheus  │──alert──►│ Alertmgr   │ │
 │  │  (Flask)     │               │  :9090       │           │  :9093     │ │
 │  │  :5001       │               └──────────────┘           └─────┬──────┘ │
 │  └──────┬───────┘                                                │        │
 │         │  writes to                              ┌──────────────┤        │
 │         │  /app/logs/app.log                      │              │        │
 │         │                                         │  webhook     │ slack  │
 │  ┌──────▼───────┐                          ┌──────▼───────┐      │ raw    │
 │  │  Shared      │    reads last 20 lines   │  Sentry      │      │ alert  │
 │  │  Volume      │◄────────────────────────│  Agent       │      │        │
 │  │  (victim-    │                          │  (Tier 1)    │      │        │
 │  │   logs)      │                          │  :8001       │      │        │
 │  └──────────────┘                          └──────┬───────┘      │        │
 │                                                   │ MCP JSON     │        │
 └───────────────────────────────────────────────────┼──────────────┼────────┘
                                                     │              │
                          ┌──────────────────────────┼──────────────┼────────┐
                          │       CLOUD / OUTBOUND   │              │        │
                          │                   ┌──────▼───────┐      │        │
                          │                   │  Cloud       │      │        │
                          │                   │  Architect   │      │        │
                          │                   │  (Tier 2)    │      │        │
                          │                   │  :8002       │      │        │
                          │                   └──┬───────┬───┘      │        │
                          │                      │       │          │        │
                          │              ┌───────▼──┐ ┌──▼────────┐ │        │
                          │              │ Gemini   │ │ Slack     │ │        │
                          │              │ 2.0 Flash│ │ #sentinel │ │        │
                          │              │ (API)    │ │ -ops      │ │        │
                          │              └──────────┘ └───────────┘ │        │
                          │                                         │        │
                          │                           ┌─────────────▼──┐     │
                          │                           │ Slack          │     │
                          │                           │ #raw-monitoring│     │
                          │                           └────────────────┘     │
                          └─────────────────────────────────────────────────┘
```

---

## Data Flow — Step by Step

The complete incident lifecycle, from error to Slack notification:

```
 Time   Event                                              Component
 ─────  ─────────────────────────────────────────────────  ──────────────────
  0s    User hits GET /trigger-error                       Victim App
  0s    http_errors_total counter increments               Victim App
  0s    Log written with synthetic PII (IPs, UUIDs)        Victim App → Volume
  5s    Prometheus scrapes /metrics, sees counter rise     Prometheus
 15s    Alert rule fires (rate > 0 for 10s)                Prometheus
 15s    CriticalServiceFailure sent to Alertmanager        Prometheus → Alertmgr
 16s    ┌─ Raw alert posted to #raw-monitoring             Alertmanager → Slack
        └─ Webhook fires to Sentry Agent                   Alertmanager → Sentry
 17s    Sentry reads last 20 log lines from shared volume  Sentry Agent
 17s    Regex PII sanitization: IPs → [REDACTED-IP]        Sentry Agent
 17s    MCP JSON payload built and forwarded               Sentry → Architect
 18s    Gemini 2.0 Flash receives redacted alert + logs    Cloud Architect
 20s    2-sentence RCA generated                           Gemini API
 21s    Block Kit message posted to #sentinel-ops          Cloud Architect → Slack
 ─────
 ~25s   Total end-to-end latency (target: < 45s)
```

---

## Component Deep Dive

### 1. Victim Application (Flask)

> **Role**: The monitored microservice — simulates a production service that experiences failures.

**Location**: `victim-app/`

| Feature | Implementation |
|---------|----------------|
| **Metrics Endpoint** | `GET /metrics` — Prometheus-compatible, serves via `prometheus_client.generate_latest()` |
| **Error Trigger** | `GET /trigger-error` — Increments `http_errors_total` counter, returns HTTP 500 |
| **Persistent Logging** | Writes to `/app/logs/app.log` on a Docker shared volume |
| **Synthetic PII** | Each log line includes randomized IPv4 addresses and UUIDs for sanitization testing |
| **Production Server** | Runs via Gunicorn with 1 worker process |

**Why synthetic PII?** The victim app deliberately embeds fake IP addresses and UUIDs into its log output. This serves as a measurable test for the Sentry Agent's privacy pipeline — if any of these values appear in the Cloud Architect's logs, the sanitization has failed.

**Example log line generated on `/trigger-error`**:
```
2026-02-26 16:50:41 | ERROR | CRITICAL FAILURE | trace_id=5d5a2d6b-882c-4248-b435-f51bbc948d31 |
source_ip=192.168.42.137 | user_id=a1b2c3d4-e5f6-7890-abcd-ef1234567890 |
endpoint=/trigger-error | status=500 | message=Manually triggered error for incident simulation
```

---

### 2. Prometheus + Alertmanager

> **Role**: Metrics collection, threshold evaluation, and alert routing.

**Prometheus** (`prometheus/`)
- **Scrape interval**: Every 5 seconds — aggressive for fast prototype feedback
- **Target**: `victim-app:5001/metrics`
- **Evaluation interval**: Every 5 seconds
- **Alert rule**: `CriticalServiceFailure` fires when `rate(http_errors_total[30s]) > 0` persists for 10 seconds

**Alertmanager** (`alertmanager/`)
- **Dual-path routing** via `continue: true`:
  - **Path 1**: Raw alert → Slack `#raw-monitoring` (simulates noisy production environment)
  - **Path 2**: Structured webhook → Sentry Agent (triggers the AI pipeline)
- **Group wait**: 5 seconds (how long to buffer before sending)
- **Repeat interval**: 1 minute (won't re-fire the same alert for 60s)

---

### 3. Sentry Agent — Tier 1 (FastAPI)

> **Role**: Local privacy guard — triages alerts, collects context, redacts PII, and formats MCP requests.

**Location**: `sentry-agent/`

This is the **first line of defense** and the most critical component for data privacy. It sits between the noisy monitoring layer and the external AI, ensuring that no raw sensitive data ever leaves the local network.

#### Pipeline (executed on each firing alert):

```
Alertmanager Webhook
        │
        ▼
┌─ Step 1: Receive ────────────────────────────────────────┐
│  Parse Alertmanager JSON payload                          │
│  Extract: alert_name, status, severity                    │
│  Skip resolved alerts (MVP optimization)                  │
└───────────────────────────────────────────────────────────┘
        │
        ▼
┌─ Step 2: Fetch Logs ─────────────────────────────────────┐
│  Read last 20 lines from /app/logs/app.log               │
│  (Shared Docker volume — mounted read-only)               │
└───────────────────────────────────────────────────────────┘
        │
        ▼
┌─ Step 3: PII Sanitization ───────────────────────────────┐
│  Regex-based masking:                                     │
│  • IPv4 addresses → [REDACTED-IP]                         │
│  • IPv6 addresses → [REDACTED-IP]                         │
│  • UUIDs          → [REDACTED-UUID]                       │
└───────────────────────────────────────────────────────────┘
        │
        ▼
┌─ Step 4: MCP Forward ───────────────────────────────────┐
│  Build MCP-style JSON payload                             │
│  POST to Cloud Architect at /mcp/tools/call               │
└───────────────────────────────────────────────────────────┘
```

#### Regex Patterns Used:

| Pattern | Match | Replacement |
|---------|-------|-------------|
| `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b` | IPv4 addresses | `[REDACTED-IP]` |
| `\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b` | IPv6 addresses | `[REDACTED-IP]` |
| `\b[0-9a-fA-F]{8}-...-[0-9a-fA-F]{12}\b` | UUIDs | `[REDACTED-UUID]` |

**Before sanitization:**
```
source_ip=192.168.42.137 | user_id=a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**After sanitization:**
```
source_ip=[REDACTED-IP] | user_id=[REDACTED-UUID]
```

---

### 4. Cloud Architect — Tier 2 (FastAPI + Gemini)

> **Role**: The "brain" — receives sanitized incident data, generates AI-powered Root Cause Analysis, posts to Slack.

**Location**: `cloud-architect/`

This component makes **outbound HTTPS calls** to two external services:
1. **Google Gemini API** — for LLM-based RCA generation
2. **Slack Webhook** — for posting the formatted RCA report

#### Gemini Integration:

- **Model**: `gemini-2.0-flash` (fast, cost-effective)
- **System prompt**: Instructs the LLM to act as a Senior SRE producing exactly a 2-sentence RCA
- **Temperature**: 0.3 (low creativity, high precision)
- **Max output tokens**: 200

**Prompt structure sent to Gemini:**
```
ALERT: CriticalServiceFailure

REDACTED APPLICATION LOGS:
2026-02-26 16:50:41 | ERROR | CRITICAL FAILURE | trace_id=[REDACTED-UUID] |
source_ip=[REDACTED-IP] | endpoint=/trigger-error | status=500 |
message=Manually triggered error for incident simulation
... (last 20 lines)

Provide your 2-sentence Root Cause Analysis:
```

**Expected Gemini output:**
> The victim-app experienced a surge of HTTP 500 errors originating from the `/trigger-error` endpoint, causing the `http_errors_total` metric to spike and trigger the CriticalServiceFailure alert. The root cause is a manually invoked error simulation endpoint designed for incident testing, not an organic application failure.

#### Slack Block Kit Message:

The report posted to `#sentinel-ops` includes:
- 🚨 **Header**: Incident Alert with alert name
- **Fields**: Alert name, Severity (Critical), Timestamp, Current status
- 🔍 **RCA Section**: The AI-generated 2-sentence analysis
- **Action Buttons**: "Execute Remediation" (danger button) + "View Dashboard" (links to Prometheus)

---

## Dual-Path Slack Alerting

Project Sentinel demonstrates the difference between **raw noise** and **actionable intelligence**:

| Channel | Source | Content | Purpose |
|---------|--------|---------|---------|
| `#raw-monitoring` | Alertmanager (direct) | Unfiltered Prometheus alert | Simulates the "noisy" status quo |
| `#sentinel-ops` | Cloud Architect (Gemini) | PII-redacted, AI-analyzed RCA report | Demonstrates Sentinel's value-add |

This dual-path design lets stakeholders directly compare:
- **Without Sentinel**: Raw metric alerts with no context
- **With Sentinel**: Intelligent, privacy-safe, actionable incident reports

---

## Privacy & PII Sanitization

Privacy is a **non-negotiable architectural constraint** in Project Sentinel. The system ensures that no raw personally identifiable information (PII) ever reaches the cloud LLM.

```
 Victim App Logs        Sentry Agent           Cloud Architect
 (Raw, with PII)        (Regex Sanitizer)      (Sees only redacted data)
                                 
 source_ip=192.168.42.137  ───►  source_ip=[REDACTED-IP]     ───►  ✅ Safe
 user_id=a1b2c3d4-...      ───►  user_id=[REDACTED-UUID]     ───►  ✅ Safe
 trace_id=5d5a2d6b-...     ───►  trace_id=[REDACTED-UUID]    ───►  ✅ Safe
```

**Privacy verification command:**
```bash
docker logs sentinel-cloud-architect 2>&1 | grep -cP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
# Expected: 0 (zero raw IP addresses in cloud-architect logs)
```

---

## Model Context Protocol (MCP)

Inter-tier communication uses **MCP-style JSON-RPC payloads**, following the emerging industry standard for agent-tool interaction:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "id": "sentry-20260226T165041",
  "params": {
    "name": "analyze_incident",
    "arguments": {
      "alert_name": "CriticalServiceFailure",
      "redacted_logs": "2026-02-26 ... [REDACTED-IP] ...",
      "timestamp": "2026-02-26T16:50:41.567Z",
      "source": "sentry-agent-tier1"
    }
  }
}
```

**Why MCP?** It provides a structured, versioned interface between AI agents. In the scale-out phase, this allows seamless migration from simple HTTP calls to a full MCP SDK implementation with tool discovery, schema validation, and multi-agent orchestration.

---

## Tech Stack

| Layer | Component | Choice | Rationale |
|-------|-----------|--------|-----------|
| **Compute** | Containerization | Docker Compose | Same config works in K8s later |
| **Intelligence** | Cloud LLM | Google Gemini 2.0 Flash | Fast, cost-effective, strong reasoning |
| **Protocol** | Agent Communication | MCP (JSON-RPC) | Industry standard for AI agent tooling |
| **Backend** | API Framework | Python / FastAPI | Async-first, high performance for I/O |
| **Monitoring** | Metrics | Prometheus | De facto standard for cloud-native metrics |
| **Alerting** | Alert Routing | Alertmanager | Native Prometheus integration |
| **Notification** | Messaging | Slack Block Kit | Rich, interactive messages |
| **Privacy** | PII Masking | Regex-based filter | Fast, deterministic, zero false negatives for known patterns |

---

## Prerequisites

Before running Project Sentinel, ensure you have:

### 1. Docker Desktop
- **Download**: [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/)
- Must be **running** before you start the stack
- Verify: `docker compose version` (must be v2+)

### 2. Google Gemini API Key
- Go to **[aistudio.google.com/apikey](https://aistudio.google.com/apikey)**
- Sign in with your Google account
- Click **"Create API Key"**
- Copy the key — you'll need it for the `.env` file
- Free tier is sufficient for prototyping

### 3. Slack Workspace with Incoming Webhooks
- Create two Slack channels: `#raw-monitoring` and `#sentinel-ops`
- Create two Incoming Webhooks (one per channel) at **[api.slack.com/messaging/webhooks](https://api.slack.com/messaging/webhooks)**
- Copy both webhook URLs for the `.env` file

### 4. System Requirements
- ~2 GB RAM available
- Ports `5001`, `8001`, `8002`, `9090`, `9093` must be free
- Internet access (for Gemini API and Slack webhooks)

---

## Quick Start

```bash
# 1. Navigate to the project
cd d:/Major-Project/prototype

# 2. Create your environment file from the template
cp .env.example .env

# 3. Edit .env with your actual values:
#    - GEMINI_API_KEY=your-real-api-key
#    - GEMINI_MODEL=gemini-2.0-flash
#    - Update webhook URLs if different from template

# 4. Build and launch all services
docker compose up -d --build

# 5. Verify all 5 containers are running
docker compose ps

# 6. Wait ~15 seconds for services to initialize, then health-check:
curl http://localhost:5001/          # Victim App
curl http://localhost:8001/health    # Sentry Agent
curl http://localhost:8002/health    # Cloud Architect

# 7. Trigger an incident!
curl http://localhost:5001/trigger-error

# 8. Watch the pipeline execute:
docker logs -f sentinel-sentry-agent       # Tier 1 processing
docker logs -f sentinel-cloud-architect    # Tier 2 RCA + Slack

# 9. Check Slack:
#    #raw-monitoring  → Raw Prometheus alert
#    #sentinel-ops    → AI-generated RCA with remediation button
```

---

## Verification & Testing

### End-to-End Pipeline Test

```bash
# Trigger the error
curl http://localhost:5001/trigger-error

# Wait ~30 seconds, then verify:

# 1. Prometheus received the metric
curl -s "http://localhost:9090/api/v1/query?query=http_errors_total" | python -m json.tool

# 2. Alert fired
# Open: http://localhost:9090/alerts

# 3. Sentry processed the alert
docker logs sentinel-sentry-agent | grep "ALERT RECEIVED"

# 4. Cloud Architect generated RCA
docker logs sentinel-cloud-architect | grep "RCA COMPLETE"

# 5. Slack notifications arrived in both channels
```

### Privacy Verification

```bash
# Must return 0 — no raw IP addresses in cloud-architect logs
docker logs sentinel-cloud-architect 2>&1 | grep -cP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
```

### Individual Service Health Checks

| Service | Command | Expected |
|---------|---------|----------|
| Victim App | `curl localhost:5001/` | `{"service":"victim-app","status":"running"}` |
| Prometheus | `curl localhost:9090/-/healthy` | `Prometheus Server is Healthy` |
| Alertmanager | `curl localhost:9093/-/healthy` | `OK` |
| Sentry Agent | `curl localhost:8001/health` | `{"status":"ok","service":"sentry-agent"}` |
| Cloud Architect | `curl localhost:8002/health` | `{"status":"ok","service":"cloud-architect","llm":"gemini-2.0-flash"}` |

### Teardown

```bash
docker compose down          # Stop containers
docker compose down -v       # Stop + remove volumes (clean slate)
```

---

## Project Structure

```
prototype/
├── docker-compose.yml              # Orchestrates all 5 services
├── .env.example                    # Environment variable template
├── .env                            # Your actual config (git-ignored)
├── README.md                       # This file
│
├── victim-app/                     # FR1: Monitored microservice
│   ├── app.py                      #   Flask app with /metrics + /trigger-error
│   ├── requirements.txt            #   flask, prometheus_client, gunicorn
│   └── Dockerfile                  #   Python 3.11-slim + gunicorn
│
├── prometheus/                     # FR2: Metrics & alerting config
│   ├── prometheus.yml              #   Scrape config (5s interval)
│   └── alert_rules.yml             #   CriticalServiceFailure rule
│
├── alertmanager/                   # FR2: Alert routing config
│   └── alertmanager.yml            #   Dual-path: raw-slack + sentry-webhook
│
├── sentry-agent/                   # FR3: Tier 1 — Privacy Guard
│   ├── main.py                     #   PII sanitizer + log fetcher + MCP forwarder
│   ├── requirements.txt            #   fastapi, uvicorn, httpx
│   └── Dockerfile                  #   Python 3.11-slim + uvicorn
│
└── cloud-architect/                # FR4: Tier 2 — The Brain
    ├── main.py                     #   Gemini RCA + Slack Block Kit
    ├── requirements.txt            #   fastapi, uvicorn, httpx, google-generativeai
    └── Dockerfile                  #   Python 3.11-slim + uvicorn
```

---

## Configuration Reference

### Environment Variables (`.env`)

| Variable | Service | Required | Description |
|----------|---------|----------|-------------|
| `GEMINI_API_KEY` | cloud-architect | ✅ Yes | Google AI Studio API key |
| `GEMINI_MODEL` | cloud-architect | No | Model name (default: `gemini-2.0-flash`) |
| `SENTINEL_OPS_WEBHOOK` | cloud-architect | ✅ Yes | Slack webhook for `#sentinel-ops` |
| `RAW_MONITORING_WEBHOOK` | alertmanager | Hardcoded | Slack webhook for `#raw-monitoring` |

### Service Ports

| Port | Service | Protocol |
|------|---------|----------|
| 5001 | Victim App | HTTP |
| 8001 | Sentry Agent | HTTP |
| 8002 | Cloud Architect | HTTP |
| 9090 | Prometheus | HTTP |
| 9093 | Alertmanager | HTTP |

### Docker Volumes

| Volume | Mounted In | Access | Purpose |
|--------|-----------|--------|---------|
| `victim-logs` | victim-app | Read-Write | Log file output |
| `victim-logs` | sentry-agent | Read-Only | Log file reading |

---

## Success Criteria

| Metric | Target | How to Verify |
|--------|--------|---------------|
| **Latency** | < 45 seconds | Time from `curl /trigger-error` to Slack timestamp |
| **Privacy** | Zero leaked IPs | `docker logs sentinel-cloud-architect \| grep -cP '\d+\.\d+\.\d+\.\d+'` = 0 |
| **Accuracy** | RCA identifies manual trigger | Read the Gemini output in `#sentinel-ops` |
| **Dual-Path** | Both channels receive | Check `#raw-monitoring` AND `#sentinel-ops` |

---

## Scalability Roadmap

| MVP Feature | Scale-out Version |
|-------------|-------------------|
| Local Docker Compose | AWS EKS (Kubernetes) deployment |
| Regex PII redaction | AI-powered PII discovery using Tier 1 SLM |
| Static alert rules | Adaptive thresholds via ML |
| Single Gemini call | Multi-Agent Orchestration with Tier 3 Critic |
| Manual `/trigger-error` | Real application error detection |
| Slack webhook buttons | Automated remediation runbooks |
| `prometheus_client` counter | OpenTelemetry distributed tracing |
| Single victim app | Multi-service mesh monitoring |

---

<p align="center"><i>Built with the Distributed Control Plane architecture — designed to scale from a prototype to production.</i></p>
