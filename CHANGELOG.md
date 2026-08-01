# Changelog

All notable changes to K3 SIEM are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- **🕸️ Link Analysis** — a Maltego-style entity-relationship graph for case investigation,
  built purely from data the incident report endpoint already assembles (no new backend route):
  the incident at the center, its linked alerts, and every asset/user/IP/IOC that shows up
  across them, laid out with a self-contained force-directed simulation (no new dependency).
  Pan/zoom, hover to highlight a node's connections, and click any IP/domain/hash/email/URL
  node to open the same OSINT lookup panel used everywhere else. Reachable from Case
  Management's case detail panel and from inside the "Generate Report" slide-over.
- **Inline offline analysis report** — "🔬 Offline Analysis Report" in Event Explorer's Import
  Analysis panel now renders the hits/image-evidence table directly in the app (a new
  `OfflineAnalysisPanel`, fetching the existing JSON endpoint) instead of only offering a
  silent file download; the HTML download is still one click away inside the panel.
- **5 more parsed OSINT sources in the lookup panel**: the freeipapi.com/ipwho.is geolocation
  sources, GreyNoise, urlscan.io, and Google Safe Browsing were already returned by the API
  (added last release) but had no frontend parser, so they fell back to a raw JSON dump — they
  now render as clean labeled fields like every other source. Also wired `url` as a lookup type
  end-to-end (API client, IOC-click handlers, OSINT panel), which was previously unreachable
  from the UI even though the backend route existed.

### Fixed
- **The Go service's threat-intel cache never populated itself on a fresh deployment** — the
  30-day auto-refresh ticker only runs on its own schedule, so a brand-new `cache.db` (first
  run, a fresh container/volume, or after a data reset) silently had zero IOCs until someone
  manually ran a sync, making the offline analyzer and OSINT enrichment produce empty results
  with no obvious cause. `cmd/server` now detects an empty cache at startup and runs the first
  sync immediately instead of waiting a month.

### Docs
- **README corrected to match what's actually reachable in the app**, closing a documentation
  gap left over from the 2.0.x-era removal of the dedicated UEBA and SOAR pages (and, it turns
  out, the standalone Vulnerability Scanner page too — none of the three are routed in
  `App.jsx` any more, and `Pages.jsx`'s `UEBA()`/`SOAR()` exports and `VulnerabilityScanner.jsx`
  are dead code today):
  - UEBA: the risk-scoring engine (`userRiskEngine.js`) and `GET /api/ueba/scores` are real and
    still running — there is just no page to browse them anymore, only a "High-Risk Users"
    count on the Overview dashboard.
  - SOAR: playbook execution is real and still triggered inline from an alert in the Triage
    queue — there is no separate console to browse the playbook catalog or execution history.
  - Vulnerability Scanner: CVE findings are real and still shown per-asset in Asset Inventory's
    detail panel and the "Vulnerability Summary" dashboard widget — there is no separate
    fleet-wide filterable table anymore.
  - Removed a stale screenshot referencing the retired SOAR page; reworded every KPI tile/stat
    description that implied a working drill-through into one of these three.

## [3.0.0] - 2026-08-01

A major version bump: this release adds an entire new Go service alongside the existing
Node.js/React stack, turning K3 SIEM from a live-monitoring SIEM into one that also supports
offline/air-gapped digital-forensic investigation - offline log + image evidence analysis, a
23-feed threat-intel cache, and 9-source OSINT enrichment with cross-corroborating geolocation.

### Added
- **New Go service (`go-service/`) for OSINT enrichment, threat-intel feed caching, and
  offline log analysis** - a standalone module built for concurrent, low-memory-footprint work
  and for analysis that needs to run with no live backend and no live internet access:
  - **Disk-backed cache** (single-file [bbolt](https://github.com/etcd-io/bbolt) store) for IOCs
    and OSINT lookup results, refreshable on demand or automatically every 30 days
    (`FEED_SYNC_INTERVAL_DAYS`) - unlike the in-memory caches it replaces, this survives a
    process restart, and the cache file itself can be copied to another machine for fully
    offline use.
  - **Offline log analyzer** - streams a log file through a CPU-core-sized worker pool (memory
    stays flat regardless of file size), parses it with a Go port of the existing 17-vendor-
    profile OCSF mapper, matches every candidate IP/hash/URL/domain/email against the cached
    IOC set (including CIDR ranges), enriches hits with cached OSINT data, and produces a JSON
    and a self-contained HTML report. Reachable from Event Explorer's Import Analysis panel via
    a new "⬇ Offline Analysis Report" button, or directly via the new
    `POST /api/analyze/offline` route.
  - **`analyzer-cli`** - the same engine as a standalone CLI (`sync feeds`, `sync osint`,
    `analyze --offline`, `cache status`) for air-gapped/compliance use, independent of the web
    app entirely.
  - **`cmd/server`** - a long-running HTTP mode (`GO_SERVICE_ADDR`, default `:8090`) that Node
    now proxies to for OSINT lookups (`backend/src/routes/osint.js` is now a thin proxy, same
    response shape, zero frontend changes) and the new offline-analysis route. The live
    ingestion pipeline, real-time correlation, and IOC-match alerting are untouched - this is
    additive, not a replacement of Node's own threat-intel feed sync.
- **10 more curated threat-intel feeds (23 total) and 5 more OSINT sources**, aimed squarely at
  digital-forensic investigation where evidence is offline logs and images rather than live
  traffic:
  - New feeds: Tor Bulk Exit List, SANS ISC DShield Block List, Team Cymru Fullbogons IPv4,
    GreenSnow Blocklist, Emerging Threats Compromised IPs, DigitalSide OSINT IPs/URLs/Domains,
    botvrij.eu Domain Blocklist, PhishStats Recent - all keyless, all wired into the same bbolt
    cache and sync path as the original 13.
  - **Three independent IP geolocation sources** (ip-api.com, freeipapi.com, ipwho.is) cross-
    checked into a `GeoConsensus` score ("N/M sources agree on country X") instead of trusting a
    single provider - shown in both the OSINT panel and the offline-analysis HTML report.
  - **GreyNoise Community API** (keyless) classifies a hit IP as internet-background scan noise,
    a known-benign service, or neither - separates opportunistic scanning from a targeted attack
    in a forensic report.
  - **urlscan.io** (keyless Search API) surfaces prior scans of a hit IP/domain/URL - contacted
    infrastructure, TLS/hosting details, and a link to the archived screenshot, useful when the
    original site is long gone by the time an investigator looks at the evidence.
  - **Google Safe Browsing** URL reputation - off by default behind `GOOGLE_SAFE_BROWSING_API_KEY`
    (unset in `.env.example`), since Google's no-cost tier restricts it to non-commercial use; a
    new `GET /api/osint/url` route (and `analyzer-cli sync osint --type url`) exposes it.
  - `EnrichLive` (live OSINT enrichment during offline analysis) only ever touches the specific
    IPs/domains/URLs that show up as hits in one evidence run, never the whole IOC cache, so free
    API quotas stay intact regardless of cache size.
- **Image metadata extraction for photographic evidence** - a new `internal/imagemeta` package
  (pure Go, no cgo, via `github.com/bep/imagemeta`) pulls EXIF/IPTC/XMP out of JPEG, PNG, TIFF,
  WebP, HEIC/HEIF, AVIF, and common RAW formats (DNG/CR2/NEF/ARW/PEF): GPS coordinates (with a
  ready-to-click map link), capture timestamp, camera make/model, and software/editing history.
  `analyzer.Analyze()` now accepts a single image, a single log file, or a whole evidence
  directory mixing both - each file is routed by content, log hits and image metadata land in
  one combined JSON/HTML report, and non-text binary files encountered in a directory (PDFs,
  archives, the cache database itself) are skipped rather than scanned as garbage log lines.
- **Automated incident analysis reporting** - a one-click "Generate Report" action on any case
  assembles a narrative summary (entities involved, MITRE tactics observed, threat-intel
  matches), resolves every IOC-matched alert back to its source feed/indicator/confidence via a
  new `GET /api/incidents/:id/report` endpoint, and exports to PDF through the browser's native
  print-to-PDF (no new dependency). Log imports get the same treatment: `POST /api/events/import`
  now awaits IOC matching for the (bounded) batch and returns per-import threat-intel hits and a
  severity breakdown, shown inline in Event Explorer as an "Import Analysis" panel. The live
  agent ingestion path (`POST /api/events/ingest`) is unchanged and stays fire-and-forget on IOC
  matching so device throughput isn't affected.
- **OSINT lookups now render as a parsed, readable feed** instead of a raw JSON dump - geo,
  reverse DNS, RDAP/WHOIS, VirusTotal, AbuseIPDB, and Shodan results are broken into labeled
  fields (with a "View Raw JSON" toggle per source for the original payload).
- **Five more keyless threat-intel feeds**: URLhaus, ThreatFox, and MalwareBazaar (abuse.ch),
  Blocklist.de, and the CINS Army List, alongside the existing catalog - no API key required for
  any of them. AlienVault OTX can now be activated with a free `OTX_API_KEY`.
- **Auto log import into Discover / live dashboards** - Event Explorer now accepts pasted logs,
  uploaded files, or a backend file path and sends them through a new `POST /api/events/import`
  ingestion route. Imported logs reuse the global parser pipeline, auto-detect the log profile,
  write normalized events into Discover, and broadcast matching live event/alert updates to the UI.
- **Expanded open-source threat-intel feed sync** - the built-in feed catalog now includes
  OpenPhish Community, PhishTank Verified Online, Spamhaus DROP IPv4/IPv6, Feodo Tracker
  Recommended, and SSLBL JA3 alongside AbuseIPDB and OTX. The Threat Intel page also gained a
  manual feed sync action via `GET/POST /api/intel/feeds/sync`.
- **Process Tree / Attack Chain Investigation** - a CrowdStrike Falcon-style process execution
  tree for tracing a compromise from initial entry to full compromise. New `process_nodes`
  table stores parent/child process lineage (pid/ppid), MITRE tactic/technique, severity, and
  per-stage `first_detected_by`, `auto_analysis`, `impact`, `remediation`, and
  `lessons_learned`. Incidents gained `impact`/`remediation`/`lessons_learned` rollup fields
  for an executive summary. `GET /api/incidents/:id` now returns the linked `process_tree`.
  New **Process Tree** page (reachable via "View Process Tree" on the Incident Response detail
  panel) renders the tree with a click-to-expand detail panel per stage. Seeded with a
  realistic 10-stage demo incident (`IR-007`): phishing email -> malicious macro -> PowerShell
  -> recon -> C2 download -> persistence -> discovery -> LSASS credential dump -> lateral
  movement to the domain controller -> ransomware deployment.
- **Windows live monitoring pipeline** - added PowerShell Operational log ingestion, better
  Windows event parsing for unnamed XML data fields, richer Windows inventory collection, and
  real-time alert creation for live agent-ingested telemetry.
- **Operational live-data helpers** - added `scripts/purge-demo-operational-data.js` to clear
  seeded operational records before switching to real telemetry, plus
  `scripts/switch-to-live-monitoring.ps1` for local live-monitoring restarts.

### Changed
- **OSINT lookups (`/api/osint/*`) now proxy to the new Go service** instead of running in
  Node directly - same request/response shape, but backed by a disk-persisted cache instead of
  an in-memory 24h `Map`, so results survive a backend restart.
- **Incident Response renamed to Case Management** (`/incidents` now redirects to `/cases`) and
  the UEBA/SOAR/Vulnerabilities nav entries were removed - they had no working pages behind them.
- **Threat-intel sync cadence** is now every 5 minutes instead of every 30 minutes, and the feed
  status panel now reflects real built-in feed rows rather than static placeholders.
- **IOC matching** now supports CIDR/range indicators, so feeds such as Spamhaus DROP can
  generate threat-intel alerts from matching event IPs.
- **Backend startup path handling** now always loads `backend/.env` and resolves the default
  SQLite database relative to `backend/`, preventing mismatched local databases when the server is
  launched from the repo root.
- **SOAR playbooks** now support inline editing from the UI, so the Edit action updates
  playbook metadata and steps instead of being a dead-end button.
- **Asset Inventory** now exposes installed endpoint applications more clearly in inventory
  listings and detail views, including security tooling such as SentinelOne or SIEM agents when
  present on the host.
- **Demo access** now includes a seeded T1 analyst account (`analyst1` / `K3@2026`) alongside
  the existing admin and T2 analyst accounts for role-based testing.

### Dependencies
- **New Go module** (`go-service/`, Go 1.26): `go.etcd.io/bbolt` (disk cache),
  `github.com/spf13/cobra` (CLI), `golang.org/x/sync` (bounded concurrent feed/OSINT fetches).
  Everything else uses the standard library on purpose.
- **Backend**: Express 5, express-rate-limit 8, helmet 8.3, morgan 1.11, node-cron 4, dotenv 17,
  bcryptjs 3, jest 30. Replaced the `uuid` package with Node's built-in `crypto.randomUUID()` -
  `uuid` v14 dropped CommonJS support entirely, which silently broke under Jest (the live server
  itself kept working, since modern Node can `require()` an ESM-only package directly, but Jest's
  module loader can't) and pulled in a dependency that was no longer needed for a single function.
  Fixed the one Express 5 breaking change this app hit: the SPA fallback route
  (`app.get('*', ...)`) needed the new named-wildcard syntax (`app.get('/*splat', ...)`), since
  Express 5's path-to-regexp v8 no longer accepts a bare `*`.
- **Frontend**: React 19, react-dom 19, react-router-dom 7, recharts 3 (now pulls in
  `@reduxjs/toolkit`/`react-redux` internally for its own state management - no app code changes
  needed), axios 1.19. No source changes were required; verified via a clean dependency
  reinstall, dev server, production build, and a full click-through of routing and charts.
- Left two categories of `npm audit` findings unaddressed on purpose: the dev-only vulnerability
  chain through Jest's bundled `glob`/`brace-expansion` (fixing it would force-downgrade Jest to
  a much older major, and it doesn't ship to production), and the vulnerabilities inside
  `react-scripts`' (Create React App, unmaintained since 2023) own build tooling - resolving
  those would mean migrating off CRA entirely, which is a separate, larger effort.

### Fixed
- **Login UX** now shows a backend-unreachable error when `localhost:3001` is down instead of
  incorrectly presenting every network failure as "Invalid credentials".
- **IOC-matched alerts from imported logs were silently dropping** whenever the log didn't carry
  a username/source/IP (common for plain-text log imports) - `iocMatcher.js` was passing
  `undefined` into a SQLite bind, which threw and was swallowed by the caller's fire-and-forget
  error handling. Threat-intel matches now always create their alert.
- **Duplicate rows in the Threat Intel feed list** - two startup code paths both initialized the
  feed catalog without awaiting each other, so a brand-new feed name could occasionally get
  inserted twice. Added a migration to dedupe existing rows and a uniqueness guard to prevent it
  from recurring.
- **AbuseIPDB and PhishTank repeatedly erroring with HTTP 429** - the 5-minute sync was retrying
  immediately after a rate-limit response, which just re-triggered the same limit. Added a
  20-minute cooldown per feed after a 429.
- **OTX AlienVault sync failing/timing out for accounts with a large number of subscribed
  pulses** - a single pulse can embed 10+ MB of indicator data for such accounts; reduced the
  page size and raised the fetch timeout so the sync reliably completes.

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
- **CVE / vulnerability scanning** - agents scan installed software and the host OS against
  the NVD CVE database on a background thread; new `vulnerabilities` table, ingest/query
  endpoints, and a dedicated Vulnerability Scanner page plus a CVE panel in Asset Inventory.
- **Auto OCSF log parser** - schema-light mapper that auto-detects log shape (Windows
  wevtutil JSON, journald JSON, syslog/auth.log text, CEF, generic JSON, raw text) and
  classifies it into the correct OCSF class. Every ingested event is normalized into OCSF
  alongside the raw log; new `/api/ocsf` routes and an OCSF Parser page for ad-hoc log pasting.
- **Agent system** - SentinelOne-style Python cross-platform agent collecting Windows Event
  Logs, Linux syslog/auth, or simulating an endpoint; registration, heartbeat, and health
  monitoring with auto-alerting on offline agents; Agent Manager UI.
- PostgreSQL 16 as the primary database for Docker deployments (SQLite retained for local dev).
- Docker Compose stack with 3 simulated agent containers (Windows, Linux, Network).

### Security
- Removed hardcoded `JWT_SECRET` / `INGEST_API_KEY` fallbacks - the app now fails fast at
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
