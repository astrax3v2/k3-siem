# Changelog

All notable changes to K3 SIEM are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- **Process Tree / Attack Chain Investigation** — a CrowdStrike Falcon-style process execution
  tree for tracing a compromise from initial entry to full compromise. New `process_nodes`
  table stores parent/child process lineage (pid/ppid), MITRE tactic/technique, severity, and
  per-stage `first_detected_by`, `auto_analysis`, `impact`, `remediation`, and
  `lessons_learned`. Incidents gained `impact`/`remediation`/`lessons_learned` rollup fields
  for an executive summary. `GET /api/incidents/:id` now returns the linked `process_tree`.
  New **Process Tree** page (reachable via "View Process Tree" on the Incident Response detail
  panel) renders the tree with a click-to-expand detail panel per stage. Seeded with a
  realistic 10-stage demo incident (`IR-007`): phishing email → malicious macro → PowerShell →
  recon → C2 download → persistence → discovery → LSASS credential dump → lateral movement to
  the domain controller → ransomware deployment.

## [2.0.1] - 2026-06-30

### Fixed
- CI workflow referenced per-package `package-lock.json` files that don't exist under npm
  workspaces (a single lockfile lives at the repo root), which broke `actions/setup-node`
  cache restoration and skipped every subsequent CI step. `cache-dependency-path` now points
  at the root lockfile.

## [2.0.0] - 2026-06-29

### Added
- **Production hardening**: real detection engines wired up end-to-end.
  - `correlationEngine.js` evaluates `correlation_rules` against ingested events on a 30s
    schedule and creates real alerts when thresholds are crossed.
  - `iocMatcher.js` matches ingested events against the `iocs` table and creates real
    "Threat Intel Match" alerts.
  - `userRiskEngine.js` computes statistical UEBA risk scores (login-time histograms,
    geo-velocity, peer-group/data-volume z-scores) in place of static seeded scores.
  - Real SOAR connectors (Slack, Teams, Jira, ServiceNow, Email, MISP, CrowdStrike, Palo Alto)
    make real HTTP calls when configured and honestly report "not configured" otherwise.
  - `feedSync.js` pulls real IOCs from AbuseIPDB/OTX every 30 minutes when API keys are set.
- Tracked schema migrations (`schema_migrations` table), an admin-only audit log
  (`GET /api/audit`), nightly retention purging, `/health` and `/ready` endpoints, graceful
  shutdown, and `scripts/backup.sh` / `restore.sh`.
- Jest test suite (22 tests) and a GitHub Actions CI workflow.
- **CVE / vulnerability scanning** — agents scan installed software and the host OS against
  the NVD CVE database on a background thread; new `vulnerabilities` table, ingest/query
  endpoints, and a dedicated Vulnerability Scanner page plus a CVE panel in Asset Inventory.
- **Auto OCSF log parser** — schema-light mapper that auto-detects log shape (Windows
  wevtutil JSON, journald JSON, syslog/auth.log text, CEF, generic JSON, raw text) and
  classifies it into the correct OCSF class. Every ingested event is normalized into OCSF
  alongside the raw log; new `/api/ocsf` routes and an OCSF Parser page for ad-hoc log pasting.
- **Agent system** — SentinelOne-style Python cross-platform agent collecting Windows Event
  Logs, Linux syslog/auth, or simulating an endpoint; registration, heartbeat, and health
  monitoring with auto-alerting on offline agents; Agent Manager UI.
- PostgreSQL 16 as the primary database for Docker deployments (SQLite retained for local dev).
- Docker Compose stack with 3 simulated agent containers (Windows, Linux, Network).

### Security
- Removed hardcoded `JWT_SECRET` / `INGEST_API_KEY` fallbacks — the app now fails fast at
  boot if they're unset.
- Reject wildcard CORS in production; require explicit origin(s).
- Redact SSH credentials from deployment logs; warn on password auth.
- Require auth on the agent-download endpoint (previously open).

## [1.0.0] - 2026-06-01

### Added
- Initial release: full-stack SIEM with React 18 frontend, Node.js/Express backend, and
  SQLite database.
- Dashboard, Alert Manager, Incident Response, Event Explorer, KQL Query Engine, Correlation
  Engine, Threat Intelligence, UEBA, and SOAR modules.
- JWT authentication with role-based access control (admin / T2 analyst / T1 analyst).
- WebSocket-powered live event and alert streaming.
- Docker support.
