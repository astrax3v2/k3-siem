<p align="center">
  <img src="https://img.shields.io/badge/K3-SIEM-gold?style=for-the-badge&labelColor=0d1117" alt="K3 SIEM" />
  <img src="https://img.shields.io/badge/version-2.0-blue?style=for-the-badge&labelColor=0d1117" alt="Version" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge&labelColor=0d1117" alt="License" />
</p>

<h1 align="center">🛡️ K3 SIEM Platform</h1>

<p align="center">
  <strong>Enterprise Security Information & Event Management</strong><br/>
  Real-time threat detection · Agent-based log collection · Incident response · SOAR automation
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Node.js-22-339933?logo=nodedotjs&logoColor=white" />
  <img src="https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=white" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white" />
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/WebSocket-Live-brightgreen?logo=socketdotio&logoColor=white" />
</p>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Screenshots](#-screenshots)
- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Dashboard & Modules](#-dashboard--modules)
- [Agent System](#-agent-system)
- [API Reference](#-api-reference)
- [Configuration](#-configuration)
- [Login Credentials](#-login-credentials)
- [Tech Stack](#-tech-stack)

---

## 🔭 Overview

K3 SIEM is a full-stack **Security Information and Event Management** platform inspired by **Microsoft Sentinel** and **SentinelOne**. It provides real-time security monitoring, threat detection, incident response, and automated playbook execution — all from a unified dark-themed security operations interface.

### What Makes K3 SIEM Different

| Feature | Description |
|---------|-------------|
| 🕵️ **Agent-Based Collection** | Deploy Python agents on real endpoints (Windows/Linux/Network) to collect and forward logs |
| ⚡ **Real-Time Streaming** | WebSocket-powered live event and alert feeds — zero polling |
| 🔍 **KQL Query Engine** | Kusto Query Language transpiled to SQL for threat hunting |
| 🤖 **SOAR Automation** | Execute playbooks with step-by-step progress tracking |
| 🧠 **UEBA Analytics** | ML-inspired user behavior analytics with anomaly scoring |
| 🎯 **MITRE ATT&CK Mapping** | Every alert mapped to MITRE tactics and techniques |

---

## 📸 Screenshots

<table>
  <tr>
    <td width="50%"><strong>Security Operations Dashboard</strong><br/><img src="docs/screenshots/dashboard.png" alt="Dashboard" /></td>
    <td width="50%"><strong>Alert Manager</strong><br/><img src="docs/screenshots/alert-manager.png" alt="Alert Manager" /></td>
  </tr>
  <tr>
    <td width="50%"><strong>Incident Response</strong><br/><img src="docs/screenshots/incident-detail.png" alt="Incident Response detail panel" /></td>
    <td width="50%"><strong>🌳 Process Tree — Attack Chain Investigation</strong><br/><img src="docs/screenshots/process-tree.png" alt="Process tree attack chain" /></td>
  </tr>
  <tr>
    <td width="50%"><strong>Process Tree — Stage Detail Panel</strong><br/><img src="docs/screenshots/process-tree-detail.png" alt="Process tree node detail" /></td>
    <td width="50%"><strong>Threat Intelligence</strong><br/><img src="docs/screenshots/threat-intel.png" alt="Threat Intelligence" /></td>
  </tr>
  <tr>
    <td width="50%"><strong>Correlation Engine</strong><br/><img src="docs/screenshots/correlation.png" alt="Correlation Engine" /></td>
    <td width="50%"><strong>SOAR Playbooks</strong><br/><img src="docs/screenshots/soar.png" alt="SOAR" /></td>
  </tr>
  <tr>
    <td width="50%"><strong>Agent Management</strong><br/><img src="docs/screenshots/agents.png" alt="Agent Management" /></td>
    <td width="50%"><strong>KQL Query Engine</strong><br/><img src="docs/screenshots/kql-engine.png" alt="KQL Engine" /></td>
  </tr>
</table>

---

## ✨ Features

### 📊 Security Operations Dashboard
- **4 KPI Tiles** — Alerts (24h) with critical count, Open Incidents, Events Indexed (24h), SOAR Executions
- **14-Day Alert Trend** — Area chart showing alert volume over time
- **Severity Distribution** — Bar chart breakdown (Critical / High / Medium / Low / Info)
- **⚡ Live Alert Feed** — Real-time WebSocket stream of the latest 5 security alerts with MITRE technique tags
- **📡 Live Event Stream** — Top 10 raw events streaming live with green pulse indicator
- **🎯 Top MITRE Tactics** — Ranked breakdown of MITRE ATT&CK tactics across all alerts
- **📊 Alert Status Summary** — New / Assigned / In Progress / Closed counts
- **🔢 Platform Stats** — IOC Hits, High-Risk Users, Active Sources, Indexed Indices

### 🚨 Alert Manager
- **Severity Filters** — Quick filter buttons: All, Critical, High, Medium, Low
- **Status Dropdown** — Filter by New, Assigned, In Progress, Closed
- **Free-Text Search** — Search across alert title, asset, username, IP
- **Alert Table** — ID, Severity badge, Title, Asset, MITRE Tactic, Risk Score (progress bar), Status, Timestamp
- **Pagination** — 25 alerts per page with prev/next navigation
- **Live Alert Integration** — New alerts from WebSocket prepended with deduplication
- **Detail Panel** — Click any row to open side panel with:
  - Full alert metadata display
  - Status update buttons (New → Assigned → In Progress → Closed)
  - "Create Incident" button to escalate
  - Risk score visualization bar

### 🧯 Incident Response
- **Create Incidents** — Form with title, description, severity (Critical/High/Medium/Low), priority (P1-P4)
- **Create from Alert** — One-click incident creation from any alert
- **Incident List** — Filterable by status, severity, search with alert/note counts
- **6-Stage Status Workflow** — Open → In Progress → Contained → Eradicated → Recovered → Closed
- **Detail Panel** includes:
  - Incident metadata (severity, priority, status, owner)
  - Status progression buttons
  - **Linked Alerts Table** — All associated security alerts
  - **Notes Section** — Add timestamped investigation notes with author tracking
- **🌳 Process Tree Link** — Incidents with a reconstructed attack chain show a "View Process
  Tree" button opening the full investigation view (see below)

### 🌳 Process Tree / Attack Chain Investigation
A CrowdStrike Falcon-style process execution tree for tracing a compromise from initial entry
to full compromise, reachable from any incident with a reconstructed attack chain.
- **Incident Overview** — title, description, severity/status, host/user, plus rollup **Impact**,
  **Remediation**, and **Lessons Learned** cards
- **Process Execution Chain** — an indented parent→child tree of every process the attacker
  spawned, color-coded by severity, malicious stages flagged, root labeled "🎯 Initial Entry
  Vector" and the terminal stage labeled "💀 Full Compromise"
- **Per-Stage Detail Panel** — click any process to see PID/PPID, image path, command line,
  host/user, SHA256, MITRE tactic/technique, timestamp, and:
  - **🔍 First Detected By** — the detection engine/rule/analyst that caught this stage
  - **🤖 Auto-Analysis** — a plain-language explanation of why the stage is suspicious
  - **💥 Impact**, **🛠️ Remediation**, and **📘 Lessons Learned** for that specific stage

### 📋 Event Explorer
- **50 events per page** with pagination
- **Filters**: Free-text search (user/computer/IP/action), severity dropdown, index selector
- **5 Log Indices**: `windows-security`, `linux-syslog`, `network-flow`, `endpoint-edr`, `cloud-identity`
- **Live Event Overlay** — Top 10 new events highlighted in green with streaming indicator
- **Columns**: Timestamp, Index badge, Source, Event ID (gold monospace), Computer, User, Action, IP, Severity badge
- **Total Count** display with refresh button

### 🔍 KQL Query Engine
- **Three Tabs**: Editor, Results, Saved Queries
- **Query Editor** — Monospace text area with dark theme
- **Sample Queries** — Quick-load buttons for common threat hunting queries
- **Supported KQL Operators**:
  - `| where event_id == "4625"` — Exact match
  - `| where severity == "Critical"` — Severity filter
  - `| where timestamp > datetime_ago("5m")` — Time window (m/h/d)
  - `| where action has_any ("PowerShell", "bypass")` — OR text search
  - `| where username != "SYSTEM"` — Negation
  - `| where agent_id == "..."` — Filter by agent
  - `| top 10` — Limit results
  - `| project timestamp, computer...` — Column selection (planned)
- **Results Table** — Query output with execution time and row count
- **Saved Queries** — Save queries as reusable detection rules with categories
- **Quick Reference Guide** — Built-in KQL syntax help panel

### 🔗 Correlation Engine
- **Stats**: Active Rules count, Total Hits (all time), Multi-Index Rules count
- **Create Rules** — Name, correlation logic, severity, risk score (0-100), time window (minutes)
- **Rules Table**: Name + logic description, Severity badge, Risk score bar, Window, Index badges, Hit count, Enable/Disable toggle
- **Multi-Index Correlation** — Rules span across `windows-security`, `network-flow`, etc.
- **Built-in Detection Rules**:
  - 🔐 Brute Force Detection (3+ failed logins in 5 min)
  - 🔄 Lateral Movement via RDP
  - 📤 Data Exfiltration (high volume outbound)
  - 🦠 Malware Execution Chain
  - 👤 Account Takeover Pattern
  - 🎫 Kerberoasting Attack
- **RBAC** — Only admin/t2_analyst can create or toggle rules

### 🔴 Threat Intelligence
- **IOC Stats**: Total IOCs, Active Hits, Intel Feeds count, Average Confidence %
- **Type Filters** — All, IP, Domain, Hash, URL, Email
- **Add IOC Form** — Type, value, confidence (0-100%), severity, source, description
- **IOC Table**: Type badge, Indicator (monospace), Confidence bar, Severity, Hits (red if >10), Source, First Seen
- **📡 Feed Status Panel** — Feed name, IOC count, active/inactive indicator
  - MISP, VirusTotal, AbuseIPDB, OTX AlienVault, Recorded Future, NVD NIST
- **🗺️ Threat Origins** — Geographic breakdown: Russia, China, N. Korea, Iran, Anonymous

### 👤 UEBA (User & Entity Behavior Analytics)
- **Stats**: High Risk Users, Total Anomalies, Users Monitored
- **Sort Options**: Risk Score, Anomalies, Name
- **User Risk Table**: Username, Department, Risk Score (color-coded bar), Anomaly count badge, Behavior flags, Location, Last Active
- **🧠 ML Baseline Deviations**:
  - Login Time Anomaly — Off-hours access detection
  - Geo-Velocity — Impossible travel detection
  - Peer Group Deviation — File access pattern outliers
  - Data Volume Spike — Download volume exceeding 30-day baseline

### ⚙️ SOAR (Security Orchestration, Automation & Response)
- **Stats**: Active Playbooks, Total Executions, Avg Response Time, Recent Executions
- **Playbook Grid** (2 columns):
  - Name + status badge (Active/Paused) + execution count
  - Trigger condition display
  - **Live Execution Progress** — Step-by-step progress bar with completion percentage
  - Numbered step circles (completed = green checkmark ✓)
  - Execute / Edit buttons (role-gated)
- **Built-in Playbooks**:
  - 🔐 Brute Force Response — Block IP, reset password, create ticket, notify SOC
  - 🦠 Malware Containment — Isolate endpoint, collect forensics, block hash, alert team
  - 🎣 Phishing Response — Extract IOCs, block sender, scan mailboxes, update filters
  - 🔑 Privilege Escalation — Revoke tokens, audit access, reset credentials, review logs
- **🔗 Integration Connectors** (8):
  - Jira (ticket creation), Slack (SOC notifications), CrowdStrike (endpoint isolation)
  - Palo Alto (firewall block), ServiceNow (ITSM), MS Teams (notifications)
  - MISP (IOC sharing), Email (analyst alerts)
- **📋 Execution History** — Playbook ID, triggered by, status, steps completed, timestamps

### 🖥️ Agent Management
- **Agent Stats**: Total Agents, Online (green), Stale (yellow), Offline (red), Events Collected
- **Agent Table**: Status (pulsing dot), Hostname, OS (with icon 🪟🐧🔥), IP, Version, Events Sent, Last Heartbeat, Registered
- **Status Computation**: Online (<60s), Stale (1-5min), Offline (>5min) — computed from heartbeat
- **Detail Panel**: Agent ID, OS info, collected sources, tags, recent events feed
- **Auto-Alerting**: High severity alert generated when agent goes offline (Defense Evasion tactic)
- **Admin Controls**: Remove agent button (admin only), update tags/config (admin/t2)

---

## 🏗️ Architecture

```
k3-siem/
│
├── 🔧 backend/                         # Node.js + Express API Server
│   ├── src/
│   │   ├── index.js                     # Express + WebSocket + startup
│   │   ├── models/
│   │   │   └── db.js                    # Dual-dialect DB (SQLite + PostgreSQL)
│   │   ├── routes/
│   │   │   ├── auth.js                  # 🔐 JWT authentication (login, /me)
│   │   │   ├── events.js               # 📋 Log ingestion + KQL engine
│   │   │   ├── agents.js               # 🖥️ Agent registration + management
│   │   │   └── api.js                   # 🛡️ Alerts, IOCs, SOAR, UEBA, Incidents
│   │   ├── services/
│   │   │   ├── ingestion.js             # ⚡ Live event generation + correlation
│   │   │   └── agentMonitor.js          # 💓 Agent health monitoring
│   │   ├── middleware/
│   │   │   └── auth.js                  # 🔑 JWT middleware + RBAC
│   │   └── utils/
│   │       └── seed.js                  # 🌱 Demo data seeder
│   └── data/                            # SQLite database (local dev)
│
├── 🎨 frontend/                         # React 18 SPA
│   └── src/
│       ├── components/
│       │   ├── Dashboard/Dashboard.jsx  # 📊 KPI tiles, charts, live feeds
│       │   ├── Alerts/AlertManager.jsx  # 🚨 Alert table + detail panel
│       │   ├── Agents/AgentManager.jsx  # 🖥️ Agent management UI
│       │   ├── Investigation/ProcessTree.jsx # 🌳 Attack chain process tree
│       │   ├── KQL/KQLEngine.jsx        # 🔍 Query editor + results
│       │   ├── Layout/Layout.jsx        # 📐 Topbar + sidebar navigation
│       │   ├── Layout/Auth.jsx          # 🔐 Login + auth context
│       │   └── Pages.jsx                # 📄 Events, Incidents, Correlation,
│       │                                #    Threat Intel, UEBA, SOAR
│       ├── hooks/useWebSocket.js        # 🔌 WebSocket connection hook
│       └── services/api.js              # 📡 Axios API client
│
├── 🐍 k3-agent/                         # Python Endpoint Agent
│   ├── agent.py                         # 🕵️ Cross-platform log collector
│   ├── config.yaml                      # ⚙️ Agent configuration
│   ├── requirements.txt                 # 📦 Python dependencies
│   └── Dockerfile                       # 🐳 Agent container image
│
├── 🐳 docker-compose.yml               # PostgreSQL + App + 3 Agents
├── 🐳 Dockerfile                        # Multi-stage Node.js build
├── 🪟 start.bat                         # Windows dev startup
├── 🐧 start.sh                          # Linux/Mac dev startup
└── 📦 package.json                      # Workspace root
```

### System Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        ENDPOINTS                                 │
│                                                                   │
│  🪟 Windows Agent     🐧 Linux Agent      🔥 Network Agent      │
│  (WS-PC-001)          (SRV-UBUNTU-01)     (FW-PALOALTO-01)      │
│  Event Logs           syslog / auth.log    Firewall logs          │
│  CrowdStrike EDR      OSSEC HIDS           Cisco ASA              │
└──────┬─────────────────────┬──────────────────────┬──────────────┘
       │                     │                      │
       │     HTTP POST /api/events/ingest           │
       │     + X-Api-Key + X-Agent-Id               │
       └──────────────────┬──┬──────────────────────┘
                          │  │
                    ┌─────▼──▼─────┐
                    │  K3 SIEM API  │
                    │  (Express)    │
                    │              │
                    │ ┌──────────┐ │    ┌──────────────┐
                    │ │ Ingest   │─┼───▶│ PostgreSQL   │
                    │ │ Engine   │ │    │ / SQLite     │
                    │ └──────────┘ │    └──────────────┘
                    │ ┌──────────┐ │
                    │ │Correlate │ │◀── Brute Force / PowerShell /
                    │ │ Engine   │ │    Privilege Escalation rules
                    │ └──────────┘ │
                    │ ┌──────────┐ │
                    │ │Agent Mon │ │◀── Offline detection + alerting
                    │ └──────────┘ │
                    └──────┬───────┘
                           │ WebSocket /ws
                    ┌──────▼───────┐
                    │  React SPA   │
                    │  Dashboard   │
                    │  Alerts      │
                    │  Agents      │
                    │  KQL Engine  │
                    │  Incidents   │
                    │  SOAR        │
                    └──────────────┘
```

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/astrax3v2/k3-siem.git
cd k3-siem
docker-compose up --build
```

This starts **5 containers**:
| Container | Description | Port |
|-----------|-------------|------|
| 🐘 `db` | PostgreSQL 16 database | 5432 (internal) |
| 🛡️ `app` | K3 SIEM backend + frontend | **3001** |
| 🪟 `agent-windows` | Simulated Windows endpoint (WS-PC-001) | — |
| 🐧 `agent-linux` | Simulated Linux server (SRV-UBUNTU-01) | — |
| 🔥 `agent-network` | Simulated network device (FW-PALOALTO-01) | — |

Open **http://localhost:3001** → Login with `pbasnet` / `K3@2026`

### Option 2: Local Development (SQLite)

```bash
# Requires Node.js >= 22

# Windows
start.bat

# Linux / Mac
chmod +x start.sh && ./start.sh
```

Backend starts on `:3001`, frontend on `:3000`.

### Option 3: Deploy Real Agents

```bash
cd k3-agent
pip install -r requirements.txt

# Collect real logs from this machine
python agent.py --config config.yaml

# Simulate a Windows endpoint
python agent.py --simulate --simulate-os windows

# Simulate a Linux server
python agent.py --simulate --simulate-os linux

# Simulate a network device
python agent.py --simulate --simulate-os network
```

---

## 📸 Dashboard & Modules

### 📊 Dashboard
| Section | Details |
|---------|---------|
| **KPI Tiles** | Alerts (24h) · Open Incidents · Events Indexed · SOAR Executions |
| **Alert Trend Chart** | 14-day area chart with gradient fill |
| **Severity Chart** | Bar chart: Critical (red), High (orange), Medium (blue), Low (green) |
| **Live Alert Feed** | Real-time WebSocket stream with MITRE technique badges |
| **Live Event Stream** | Raw events with green pulse animation |
| **MITRE Tactics** | Ranked breakdown with horizontal progress bars |
| **Alert Status** | New / Assigned / In Progress / Closed counts |
| **Platform Stats** | IOC Hits · High-Risk Users · Active Sources · Indexed Indices |

### 🚨 Alert Manager
| Feature | Details |
|---------|---------|
| **Filters** | Severity buttons · Status dropdown · Free-text search |
| **Table Columns** | Severity badge · Title · Asset · MITRE Tactic · Risk Score bar · Status · Time |
| **Detail Panel** | Full metadata · Status update buttons · Create Incident · Risk visualization |
| **Live Updates** | New alerts prepended via WebSocket with deduplication |

### 🌳 Process Tree
| Feature | Details |
|---------|---------|
| **Overview** | Incident title/description/severity/status + Impact · Remediation · Lessons Learned cards |
| **Attack Chain Tree** | Indented parent→child process tree, severity-colored, malicious stages flagged |
| **Markers** | Root = "🎯 Initial Entry Vector" · terminal malicious stage = "💀 Full Compromise" |
| **Stage Detail Panel** | PID/PPID · image · command line · SHA256 · MITRE mapping · first detected by · auto-analysis |

### 🖥️ Agent Manager
| Feature | Details |
|---------|---------|
| **Stats Row** | Total · Online (🟢) · Stale (🟡) · Offline (🔴) · Events Collected |
| **Agent Table** | Status dot · Hostname · OS icon · IP · Version · Events · Heartbeat · Registered |
| **Detail Panel** | Agent ID · OS · IP · Sources · Tags · Recent 10 events feed |
| **Health Monitor** | Auto-marks offline after 5 min · Creates High severity alert |

### 🔍 KQL Engine
| Feature | Details |
|---------|---------|
| **Editor** | Dark monospace textarea with sample query buttons |
| **Operators** | `where`, `has_any`, `datetime_ago`, `!=`, `==`, `top`, `project` |
| **Results** | Table output with execution time (ms) and row count |
| **Saved Queries** | Persist as detection rules with categories |

### 🧯 Incident Response
| Feature | Details |
|---------|---------|
| **Create** | Title · Description · Severity · Priority (P1-P4) |
| **Workflow** | Open → In Progress → Contained → Eradicated → Recovered → Closed |
| **Detail** | Metadata · Linked alerts table · Investigation notes with timestamps |

### ⚙️ SOAR Playbooks
| Feature | Details |
|---------|---------|
| **Playbooks** | Brute Force · Malware · Phishing · Privilege Escalation |
| **Execution** | Live progress bar · Step checkmarks · Completion message |
| **Connectors** | Jira · Slack · CrowdStrike · Palo Alto · ServiceNow · Teams · MISP · Email |

### 🔴 Threat Intelligence
| Feature | Details |
|---------|---------|
| **IOC Types** | IP · Domain · Hash · URL · Email with type badges |
| **Feeds** | MISP · VirusTotal · AbuseIPDB · OTX · Recorded Future · NVD NIST |
| **Metrics** | Confidence bars · Hit counts · Threat origin map |

### 👤 UEBA
| Feature | Details |
|---------|---------|
| **Risk Scoring** | 0-100 color-coded bars (green → orange → red) |
| **Anomaly Detection** | Login time · Geo-velocity · Peer group · Data volume |
| **Flags** | Behavior flags per user with anomaly count badges |

---

## 🕵️ Agent System

### How It Works

1. **Agent starts** → Registers with SIEM via `POST /api/agents/register`
2. **Heartbeat loop** → Sends heartbeat every 30s via `POST /api/agents/:id/heartbeat`
3. **Collection loop** → Collects logs every 8-15s based on OS detection
4. **Normalization** → Maps OS-specific log formats to unified SIEM schema
5. **Ingestion** → Batch `POST /api/events/ingest` with `X-Agent-Id` header
6. **Monitoring** → Backend checks heartbeats every 60s, marks offline after 5 min

### Supported Log Sources

| Platform | Sources | Method |
|----------|---------|--------|
| 🪟 **Windows** | Security, System, Application Event Logs | `wevtutil` / PowerShell |
| 🐧 **Linux** | syslog, auth.log, secure | `journalctl` / file tailing |
| 🔥 **Network** | Firewall, IDS, DNS, VPN | Simulated (extensible) |
| ☁️ **Cloud** | Azure AD, AWS CloudTrail | Simulated (extensible) |

### Simulation Profiles

| Profile | Hostname | OS | Sample Actions |
|---------|----------|----|----------------|
| `windows` | WS-PC-001 | Windows 11 Pro | User Logon, Failed Logon, PowerShell Exec, Service Install |
| `linux` | SRV-UBUNTU-01 | Ubuntu 24.04 LTS | SSH Login, Sudo Command, Cron Execution, Package Install |
| `network` | FW-PALOALTO-01 | PAN-OS 11.1 | Traffic Allow/Deny, IDS Alert, Port Scan, DDoS Attempt |

### Agent Configuration

```yaml
# k3-agent/config.yaml
siem_url: http://localhost:3001
api_key: k3-ingest-key
agent_version: "1.0.0"
collection_interval: 10    # seconds between collection cycles
heartbeat_interval: 30     # seconds between heartbeats
batch_size: 50             # max events per batch
sources:
  - windows_security
  - windows_system
  - linux_syslog
  - linux_auth
simulate: false
```

### Environment Variables (Agent)

| Variable | Default | Description |
|----------|---------|-------------|
| `K3_SIEM_URL` | `http://localhost:3001` | SIEM backend URL |
| `K3_API_KEY` | `k3-ingest-key` | Ingest API key |
| `K3_HOSTNAME` | System hostname | Override agent hostname |
| `K3_SIMULATE` | `false` | Enable simulation mode |
| `K3_SIMULATE_OS` | — | Simulation profile: `windows`, `linux`, `network` |
| `K3_COLLECTION_INTERVAL` | `10` | Seconds between log collection |
| `K3_HEARTBEAT_INTERVAL` | `30` | Seconds between heartbeats |

---

## 📡 API Reference

### 🔐 Authentication
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/auth/login` | None | Login → JWT token (12h expiry) |
| `GET` | `/api/auth/me` | JWT | Current user info |

### 🖥️ Agents
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/agents/register` | API Key | Agent self-registration (upsert) |
| `POST` | `/api/agents/:id/heartbeat` | API Key | Agent heartbeat update |
| `GET` | `/api/agents` | JWT | List all agents with computed status |
| `GET` | `/api/agents/stats` | JWT | Agent statistics (online/stale/offline) |
| `GET` | `/api/agents/:id` | JWT | Agent detail + recent events |
| `PATCH` | `/api/agents/:id` | JWT (admin/t2) | Update agent tags/config |
| `DELETE` | `/api/agents/:id` | JWT (admin) | Remove agent |

### 📋 Events
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/events` | JWT | Paginated events (50/page) with filters |
| `GET` | `/api/events/stats` | JWT | Event statistics and counts |
| `POST` | `/api/events/ingest` | API Key | Bulk log ingestion from agents |
| `POST` | `/api/events/kql` | JWT | Execute KQL query |

### 🚨 Alerts
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/alerts` | JWT | Paginated alerts (25/page) |
| `GET` | `/api/alerts/stats` | JWT | Severity, status, tactic breakdown |
| `GET` | `/api/alerts/:id` | JWT | Alert detail |
| `PATCH` | `/api/alerts/:id` | JWT | Update status/analyst/risk |

### 🧯 Incidents
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/incidents` | JWT | Paginated with filters |
| `POST` | `/api/incidents` | JWT | Create new incident |
| `POST` | `/api/incidents/from-alert/:id` | JWT | Create incident from alert |
| `GET` | `/api/incidents/:id` | JWT | Detail + alerts + notes + linked `process_tree` (attack chain) |
| `PATCH` | `/api/incidents/:id` | JWT | Update status/severity/priority |
| `POST` | `/api/incidents/:id/notes` | JWT | Add investigation note |
| `POST` | `/api/incidents/:id/alerts` | JWT | Link alert to incident |

### 🔗 Correlation · 🔴 Intel · ⚙️ SOAR · 👤 UEBA · 🔍 KQL
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/correlation/rules` | JWT | List correlation rules |
| `POST` | `/api/correlation/rules` | JWT (t2+) | Create rule |
| `PATCH` | `/api/correlation/rules/:id` | JWT (t2+) | Toggle enable/disable |
| `GET` | `/api/intel/iocs` | JWT | List IOCs with filters |
| `POST` | `/api/intel/iocs` | JWT (t2+) | Create IOC |
| `GET` | `/api/intel/feeds` | JWT | List intel feeds |
| `GET` | `/api/soar/playbooks` | JWT | List playbooks + executions |
| `POST` | `/api/soar/playbooks/:id/execute` | JWT (t2+) | Execute playbook |
| `GET` | `/api/soar/executions/:id` | JWT | Poll execution progress |
| `GET` | `/api/ueba/scores` | JWT | User risk scores |
| `GET` | `/api/kql/queries` | JWT | Saved queries |
| `POST` | `/api/kql/queries` | JWT | Save query/detection rule |

---

## ⚙️ Configuration

### Backend Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | Backend server port |
| `NODE_ENV` | `development` | `production` for Docker |
| `JWT_SECRET` | *(required)* | JWT signing secret |
| `DB_CLIENT` | `sqlite` | Set to `postgres` for PostgreSQL |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `DB_PATH` | `./data/siem.db` | SQLite database path |
| `LOG_INGEST_INTERVAL` | `3000` | Synthetic event generation (ms) |
| `INGEST_API_KEY` | `k3-ingest-key` | API key for agent authentication |
| `CORS_ORIGIN` | `*` | CORS allowed origins |

### Database Schema (Key Tables)

| Table | Purpose | Key Fields |
|-------|---------|------------|
| `users` | Authentication & RBAC | username, role, password_hash |
| `events` | Raw log storage | timestamp, source, event_id, severity, agent_id |
| `alerts` | Security alerts | title, severity, mitre_tactic, risk_score, status |
| `agents` | Registered agents | hostname, os, ip, status, last_heartbeat |
| `incidents` | Incident cases | title, severity, status (6-stage), priority, impact, remediation, lessons_learned |
| `incident_alerts` | Alert↔Incident links | incident_id, alert_id |
| `incident_notes` | Investigation notes | author, note, timestamp |
| `process_nodes` | Process tree / attack chain stages | incident_id, parent_id, pid, ppid, mitre_tactic, first_detected_by, auto_analysis |
| `correlation_rules` | Detection rules | logic, severity, risk_score, window_minutes |
| `playbooks` | SOAR automation | steps (JSON), trigger_condition, status |
| `playbook_executions` | Execution tracking | status, steps_completed, result |
| `iocs` | Threat indicators | type, value, confidence, hits |
| `ueba_scores` | User risk profiles | risk_score, anomaly_count, flags |
| `kql_saved_queries` | Saved KQL queries | query, category, is_rule |
| `intel_feeds` | Threat feed sources | name, status, ioc_count |

---

## 🔑 Login Credentials (local dev / `npm run seed` only)

These accounts are created by `backend/src/utils/seed.js` for local development and demos
only. **Never run the seeder against a production database, and rotate/remove these
accounts (or their passwords) before exposing a deployment publicly.**

| Username | Password | Role | Full Name | Permissions |
|----------|----------|------|-----------|-------------|
| `pbasnet` | `K3@2026` | 🔴 Admin | Prem Basnet | Full access — manage agents, rules, users |
| `jmaharjan` | `K3@2026` | 🟠 T2 Analyst | Jenan Maharjan | Create rules, IOCs, execute playbooks |
| `bpaudel` | `K3@2026` | 🟠 T2 Analyst | Bamdev Paudel | Create rules, IOCs, execute playbooks |
| `analyst1` | `K3@2026` | 🟢 T1 Analyst | SOC Analyst | View-only, query, create incidents |

---

## 🚢 Production Deployment

K3 SIEM ships with real detection logic and connector integrations, gated behind
configuration so a deployment without external credentials still runs safely with no
fake/simulated behavior pretending to be real.

### Required before going live
- Set real, unique values for `JWT_SECRET` and `INGEST_API_KEY` (the app refuses to start
  without them — see `backend/.env.example` / root `.env.example`). Generate with
  `openssl rand -base64 48` and `openssl rand -hex 32` respectively.
- Set `CORS_ORIGIN` to your real frontend origin(s) — a wildcard is rejected when
  `NODE_ENV=production`.
- Put a TLS-terminating reverse proxy (nginx, Caddy, an ALB, etc.) in front of the app;
  the Node process itself serves plain HTTP.
- Do **not** run `npm run seed` against your production database — it deletes and
  reseeds all tables. Create real user accounts directly instead.

### What's real vs. what needs your credentials
| Capability | Status |
|---|---|
| Correlation rule engine, IOC matching, UEBA risk scoring | Real — runs on ingested event history, no external service required |
| Slack / Teams notifications | Real once `SLACK_WEBHOOK_URL` / `TEAMS_WEBHOOK_URL` is set |
| Jira / ServiceNow ticketing | Real once `JIRA_*` / `SERVICENOW_*` env vars are set |
| Email alerts | Real once `SMTP_*` / `ALERT_EMAIL_*` env vars are set |
| CrowdStrike host isolation, Palo Alto IP blocking, MISP IOC submission | Real once their respective env vars are set (see `.env.example`) — these call your actual tenant, so test in a non-prod environment first |
| VirusTotal / AbuseIPDB / OTX threat-intel feed sync | Real once their API keys are set — runs every 30 minutes |
| Geo-velocity (UEBA) | Uses the free `ip-api.com` lookup by default; set `GEOIP_DISABLED=true` for air-gapped deployments |

Any step/connector without its env vars configured reports "not configured" honestly in
the SOAR execution result rather than silently pretending to succeed.

### Operational
- **Backups**: `scripts/backup.sh` / `scripts/restore.sh` wrap `pg_dump`/`psql` against the
  `db` container — wire `backup.sh` into a host cron job.
- **Retention**: events older than `EVENTS_RETENTION_DAYS` (default 90) and closed alerts
  older than `CLOSED_ALERTS_RETENTION_DAYS` (default 180) are purged nightly.
- **Health checks**: `GET /health` (liveness) and `GET /ready` (DB connectivity) for your
  orchestrator's probes.
- **Audit log**: admin-only `GET /api/audit` records logins, rule/agent/incident/alert
  changes.

---

## 🧰 Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| 🔧 **Backend** | Node.js + Express | 22 / 4.21 |
| 🎨 **Frontend** | React + React Router | 18.3 / 6.30 |
| 📊 **Charts** | Recharts | 2.15 |
| 🔌 **Real-time** | WebSocket (ws) | 8.18 |
| 🐘 **Database** | PostgreSQL (prod) / SQLite (dev) | 16 / built-in |
| 🐍 **Agent** | Python + requests + psutil | 3.12 |
| 🐳 **Deployment** | Docker + Docker Compose | Multi-stage |
| 🔐 **Auth** | JWT + bcrypt | 12h tokens |
| 📡 **HTTP Client** | Axios | 1.9 |
| 📅 **Date Utils** | date-fns | 4.1 |

---

<p align="center">
  <strong>Built with 🛡️ by the K3 Security Team</strong><br/>
  <sub>Enterprise-grade SIEM for modern security operations</sub>
</p>
