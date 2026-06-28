# K3 SIEM Platform

**Enterprise Security Operations Platform — K3 SIEM v2.4.1**

---

## Architecture

```
k3-siem/
├── backend/                    # Node.js + Express API
│   ├── src/
│   │   ├── index.js            # Entry point + WebSocket server
│   │   ├── models/
│   │   │   └── db.js           # SQLite schema + init (better-sqlite3)
│   │   ├── routes/
│   │   │   ├── auth.js         # JWT auth (login, /me)
│   │   │   ├── events.js       # Log ingestion, KQL engine, event CRUD
│   │   │   └── api.js          # Alerts, IOCs, Correlation, SOAR, UEBA, KQL
│   │   ├── services/
│   │   │   └── ingestion.js    # Live log simulation + alert correlation
│   │   ├── middleware/
│   │   │   └── auth.js         # JWT middleware + RBAC
│   │   └── utils/
│   │       └── seed.js         # Demo data seeder
│   └── data/                   # SQLite database (auto-created)
│       └── siem.db
│
└── frontend/                   # React 18 SPA
    └── src/
        ├── App.jsx             # Router + auth guard
        ├── services/api.js     # Axios client + all API calls
        ├── hooks/useWebSocket.js # Live event WebSocket hook
        └── components/
            ├── Layout/         # Topbar, Sidebar, Auth/Login
            ├── Dashboard/      # KPI tiles, trend charts, live feeds
            ├── Alerts/         # Alert manager with real-time updates
            ├── KQL/            # KQL query editor + saved rules
            └── Pages.jsx       # Events, Correlation, Intel, UEBA, SOAR
```

---

## Features

| Module | Capability |
|--------|-----------|
| **Dashboard** | Live KPI tiles, 14-day alert trend (Recharts), severity breakdown, live event stream |
| **Alert Manager** | Paginated alert table, severity/status filtering, real-time WebSocket updates, status management via API |
| **Event Explorer** | 50-per-page raw log view, multi-field search, index filtering, live ingestion overlay |
| **KQL Engine** | Real KQL→SQL transpiler, 5 preloaded detection rules, query saving, execution timing |
| **Correlation** | Multi-index rules, toggle enable/disable, create new rules, hit counters |
| **Threat Intel** | IOC CRUD (add/list/filter), 6 live intel feeds, confidence scoring |
| **UEBA** | User risk scores, anomaly counts, ML deviation flags, sortable table |
| **SOAR** | Playbook execution with real DB updates, step-by-step progress polling, execution history |
| **Log Ingestion** | Live HTTP ingest endpoint + automatic 3s synthetic log generation |
| **WebSocket** | Real-time event and alert streaming to all connected clients |
| **Auth** | JWT login, role-based access (admin/soc_lead/analyst), 12h token expiry |

---

## Quick Start

### Prerequisites
- Node.js >= 18
- npm >= 9

### 1 — Install dependencies

```bash
cd k3-siem

# Backend
cd backend && npm install && cd ..

# Frontend
cd frontend && npm install && cd ..
```

### 2 — Seed demo data

```bash
cd backend && npm run seed
```

This creates:
- **4 users** (pbasnet, jmaharjan, bpaudel, analyst1)
- **500 raw events** across 5 indices
- **60 alerts** with MITRE mappings
- **12 IOCs** with threat intel data
- **6 correlation rules**
- **4 SOAR playbooks**
- **10 UEBA user risk scores**
- **6 KQL saved queries/rules**
- **6 intel feeds**

### 3 — Start backend

```bash
cd backend && npm run dev
```

Backend starts at: `http://localhost:3001`  
WebSocket at: `ws://localhost:3001/ws`

### 4 — Start frontend (new terminal)

```bash
cd frontend && npm start
```

Frontend starts at: `http://localhost:3000`

---

## Login Credentials

| Username | Password | Role |
|----------|----------|------|
| `pbasnet` | `K3@2026` | Admin |
| `jmaharjan` | `K3@2026` | T2 Analyst |
| `bpaudel` | `K3@2026` | T1 Analyst |
| `analyst1` | `K3@2026` | T1 Analyst |

---

## API Reference

### Authentication
```
POST /api/auth/login       { username, password } → { token, user }
GET  /api/auth/me          (Bearer token) → { user }
```

### Events & Log Ingestion
```
GET  /api/events           ?page&limit&severity&source&search&index
GET  /api/events/stats     Summary statistics
POST /api/events/ingest    (x-api-key: k3-ingest-key) Bulk log ingest
POST /api/events/kql       { query } → Execute KQL-style query
```

### Alerts
```
GET   /api/alerts          ?page&limit&severity&status&search
GET   /api/alerts/stats    Severity/status/tactic breakdown
GET   /api/alerts/:id      Single alert detail
PATCH /api/alerts/:id      { status, analyst_id, risk_score }
```

### Threat Intel
```
GET  /api/intel/iocs       ?type&severity&search&page
POST /api/intel/iocs       { type, value, confidence, severity, source }
GET  /api/intel/feeds      Feed status list
```

### Correlation
```
GET   /api/correlation/rules        All rules
POST  /api/correlation/rules        Create new rule
PATCH /api/correlation/rules/:id    { enabled }
```

### SOAR
```
GET  /api/soar/playbooks            All playbooks + recent executions
POST /api/soar/playbooks/:id/execute  { alert_id? } → { execution_id }
GET  /api/soar/executions/:id       Poll execution progress
```

### UEBA
```
GET  /api/ueba/scores      All user risk scores
```

### Log Ingest (External)
```bash
# Send logs programmatically
curl -X POST http://localhost:3001/api/events/ingest \
  -H "Content-Type: application/json" \
  -H "x-api-key: k3-ingest-key" \
  -d '[{
    "source": "Windows Security",
    "event_id": "4625",
    "computer": "WS-001",
    "username": "admin",
    "ip_address": "10.10.1.50",
    "action": "Failed Logon",
    "severity": "High",
    "index": "windows-security"
  }]'
```

---

## WebSocket Events

Connect to `ws://localhost:3001/ws` for live streaming:

```js
const ws = new WebSocket('ws://localhost:3001/ws');
ws.onmessage = (e) => {
  const { type, data } = JSON.parse(e.data);
  // type: 'connected' | 'events' | 'alerts'
  // data: array of event or alert objects
};
```

---

## KQL Query Examples

```kql
// Brute force detection
SecurityEvent
| where event_id == "4625"
| where timestamp > datetime_ago("5m")
| order by timestamp desc

// Suspicious PowerShell
SecurityEvent
| where event_id == "4688"
| where action has_any ("PowerShell","bypass","encoded")
| project timestamp, computer, username, action

// Critical events
SecurityEvent
| where severity == "Critical"
| order by timestamp desc

// Top 10 most recent
SecurityEvent
| top 10
```

---

## Production Deployment

```bash
# Build frontend
cd frontend && npm run build

# Set production env
cd backend
echo "NODE_ENV=production" >> .env
echo "JWT_SECRET=your-very-secure-random-secret" >> .env
echo "CORS_ORIGIN=https://yourdomain.com" >> .env

# Start
npm start
```

The backend serves the React build at `/*` in production mode.

---

## Database Schema

SQLite database at `backend/data/siem.db` with tables:
- `events` — raw log events (indexed by timestamp, severity, source)
- `alerts` — correlated security alerts with MITRE mapping
- `iocs` — threat indicators
- `correlation_rules` — multi-index detection rules
- `playbooks` — SOAR automation playbooks
- `playbook_executions` — execution audit trail
- `ueba_scores` — user risk scores
- `kql_saved_queries` — saved KQL queries and detection rules
- `intel_feeds` — threat intelligence feed registry
- `users` — SIEM user accounts

---

*K3 SIEM v2.4.1 · Built with Node.js + React + SQLite + WebSocket*
