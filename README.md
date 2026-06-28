# K3 SIEM Platform

**Enterprise Security Operations Platform — K3 SIEM v2.0**

A full-stack SIEM with agent-based log collection, real-time correlation, and incident response — inspired by SentinelOne and Microsoft Sentinel.

---

## Architecture

```
k3-siem/
├── backend/                    # Node.js + Express API
│   ├── src/
│   │   ├── index.js            # Entry point + WebSocket server
│   │   ├── models/
│   │   │   └── db.js           # Dual-dialect DB (SQLite + PostgreSQL)
│   │   ├── routes/
│   │   │   ├── auth.js         # JWT auth (login, /me)
│   │   │   ├── events.js       # Log ingestion, KQL engine, event CRUD
│   │   │   ├── agents.js       # Agent registration, heartbeat, management
│   │   │   └── api.js          # Alerts, IOCs, Correlation, SOAR, UEBA, KQL
│   │   ├── services/
│   │   │   ├── ingestion.js    # Live log simulation + alert correlation
│   │   │   └── agentMonitor.js # Agent health monitoring
│   │   ├── middleware/
│   │   │   └── auth.js         # JWT middleware + RBAC
│   │   └── utils/
│   │       └── seed.js         # Demo data seeder
│   └── data/                   # SQLite database (auto-created, local dev)
│
├── frontend/                   # React 18 SPA
│   └── src/
│       ├── components/
│       │   ├── Dashboard/      # KPI tiles, charts, live feeds
│       │   ├── Alerts/         # Alert management + detail panel
│       │   ├── Agents/         # Agent management (status, events, detail)
│       │   ├── KQL/            # KQL query editor + results
│       │   ├── Layout/         # Topbar, sidebar, auth
│       │   └── Pages.jsx       # Events, Incidents, Correlation, Intel, UEBA, SOAR
│       ├── hooks/              # WebSocket hook
│       └── services/           # API client (Axios)
│
├── k3-agent/                   # Python endpoint agent
│   ├── agent.py                # Cross-platform log collector
│   ├── config.yaml             # Agent configuration
│   ├── requirements.txt        # Python dependencies
│   └── Dockerfile              # Agent container image
│
├── docker-compose.yml          # PostgreSQL + App + 3 Agent containers
├── Dockerfile                  # Multi-stage Node.js build
├── start.bat / start.sh        # Local development startup
└── package.json                # Workspace root
```

---

## Quick Start

### Local Development (SQLite)

```bash
# Windows
start.bat

# Linux/Mac
chmod +x start.sh && ./start.sh
```

Requires Node.js >= 22. Starts backend on port 3001, frontend on port 3000.

### Docker (PostgreSQL + Agents)

```bash
docker-compose up --build
```

This starts:
- **PostgreSQL 16** — production database
- **K3 SIEM App** — backend + frontend on port 3001
- **3 Simulated Agents** — Windows, Linux, Network endpoints

Open http://localhost:3001 after startup.

### Deploy Real Agents

```bash
cd k3-agent
pip install -r requirements.txt

# Collect real logs from this machine
python agent.py --config config.yaml

# Or simulate an endpoint
python agent.py --simulate --simulate-os windows
```

Configure `config.yaml` or environment variables:
- `K3_SIEM_URL` — SIEM backend URL
- `K3_API_KEY` — Ingest API key
- `K3_HOSTNAME` — Override hostname
- `K3_SIMULATE` — Enable simulation mode
- `K3_SIMULATE_OS` — Simulate: windows, linux, network

---

## Login Credentials

| Username | Password | Role | Full Name |
|----------|----------|------|-----------|
| pbasnet | K3@2026 | Admin | Prem Basnet |
| jmaharjan | K3@2026 | T2 Analyst | Jenan Maharjan |
| bpaudel | K3@2026 | T2 Analyst | Bamdev Paudel |
| analyst1 | K3@2026 | T1 Analyst | SOC Analyst |

---

## Features

### Agent System
- **Cross-platform agents** — Collect Windows Event Logs, Linux syslog/auth, network device logs
- **Agent registration & heartbeat** — Agents self-register and send heartbeats every 30s
- **Agent management UI** — View all agents, status (online/stale/offline), events, detail panel
- **Simulation mode** — Docker containers simulate Windows, Linux, and network endpoints
- **Auto-alerting** — Alerts generated when agents go offline

### Core SIEM
- **Real-time streaming** — WebSocket live feed of events and alerts
- **KQL query engine** — Kusto-style query language transpiled to SQL
- **Alert correlation** — Brute force, PowerShell exec, privilege escalation detection
- **MITRE ATT&CK mapping** — Tactics and techniques on all alerts
- **Incident response** — Create incidents, link alerts, add notes, status workflow

### Modules
- **Threat Intelligence** — IOC management with confidence scoring
- **Correlation Rules** — Custom detection rules with risk scoring
- **SOAR Playbooks** — Automated response with step-by-step execution
- **UEBA** — User risk scoring with anomaly detection
- **Saved Queries** — KQL queries saved as detection rules

### Infrastructure
- **Dual database** — SQLite for local dev, PostgreSQL for production
- **Docker deployment** — Multi-stage build, health checks, persistent volumes
- **JWT + RBAC** — Role-based access (admin, t2_analyst, t1_analyst)
- **Dark theme UI** — Professional security operations interface

---

## API Endpoints

### Agent API
```
POST   /api/agents/register         Agent self-registration (API key auth)
POST   /api/agents/:id/heartbeat    Agent heartbeat (API key auth)
GET    /api/agents                   List all agents (JWT auth)
GET    /api/agents/stats             Agent statistics (JWT auth)
GET    /api/agents/:id               Agent detail + recent events
PATCH  /api/agents/:id               Update agent tags/config (admin/t2)
DELETE /api/agents/:id               Remove agent (admin only)
```

### Log Ingest
```
POST   /api/events/ingest            Bulk log ingestion (API key + X-Agent-Id header)
```

### Auth
```
POST   /api/auth/login               Login → JWT token
GET    /api/auth/me                   Current user info
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 3001 | Backend port |
| NODE_ENV | development | Environment |
| JWT_SECRET | (required) | JWT signing key |
| DB_CLIENT | sqlite | `postgres` for PostgreSQL |
| DATABASE_URL | - | PostgreSQL connection string |
| DB_PATH | ./data/siem.db | SQLite database path |
| LOG_INGEST_INTERVAL | 3000 | Synthetic event generation (ms) |
| INGEST_API_KEY | k3-ingest-key | API key for agent ingest |
| CORS_ORIGIN | * | CORS allowed origins |

---

## Tech Stack

- **Backend**: Node.js 22, Express 4, WebSocket (ws), PostgreSQL/SQLite
- **Frontend**: React 18, React Router 6, Recharts, Axios
- **Agent**: Python 3.12, requests, psutil, PyYAML
- **Database**: PostgreSQL 16 (production), SQLite (development)
- **Deployment**: Docker, Docker Compose
