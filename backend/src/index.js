'use strict';
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
require('./config'); // validates JWT_SECRET / INGEST_API_KEY are set; exits process if not
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const morgan     = require('morgan');
const compression= require('compression');
const rateLimit  = require('express-rate-limit');
const http       = require('http');
const { WebSocketServer } = require('ws');

const { initDb }            = require('./models/db');
const { initClickHouse, chPing } = require('./models/clickhouse');
const { startIngestion, stopIngestion, registerWsClient } = require('./services/ingestion');
const { startAgentMonitor, stopAgentMonitor } = require('./services/agentMonitor');
const { startCorrelationEngine, stopCorrelationEngine } = require('./services/correlationEngine');
const { startCrossCorrelation, stopCrossCorrelation } = require('./services/crossCorrelation');
const { startUebaEngine, stopUebaEngine } = require('./services/userRiskEngine');
const { startFeedSync, stopFeedSync } = require('./services/connectors/feedSync');
const { startRetention, stopRetention } = require('./services/retention');
const authRouter   = require('./routes/auth');
const eventsRouter = require('./routes/events');
const agentsRouter = require('./routes/agents');
const deployRouter = require('./routes/deploy');
const ocsfRouter   = require('./routes/ocsf');
const osintRouter  = require('./routes/osint');
const dashboardsRouter = require('./routes/dashboardLibrary');
const tenantsRouter = require('./routes/tenants');
const teamsRouter = require('./routes/teams');
const usersRouter = require('./routes/users');
const apiRouter    = require('./routes/api');

const app  = express();
const PORT = process.env.PORT || 3001;
const isProd = process.env.NODE_ENV === 'production';

function isClickHouseConnRefused(error) {
  if (!error) return false;
  if (error.code === 'ECONNREFUSED') return true;
  return Array.isArray(error.errors) && error.errors.some((inner) => inner && inner.code === 'ECONNREFUSED');
}

function resolveCorsOrigins() {
  const raw = process.env.CORS_ORIGIN;
  if (!raw || raw === '*') {
    if (isProd) {
      console.error('[Config] CORS_ORIGIN must be set to an explicit origin (or comma-separated list) in production — refusing to start with a wildcard.');
      process.exit(1);
    }
    return 'http://localhost:3000';
  }
  const list = raw.split(',').map((s) => s.trim()).filter(Boolean);
  return list.length > 1 ? list : list[0];
}

app.set('trust proxy', process.env.TRUST_PROXY ? parseInt(process.env.TRUST_PROXY, 10) : 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: resolveCorsOrigins(), credentials: true }));
app.use(compression());
app.use(morgan('dev'));
app.use(express.json({ limit: '10mb' }));
app.use(rateLimit({ windowMs: 15*60*1000, max: 1000 }));

// Liveness: process is up, no dependency checks. Readiness: can actually serve traffic (DB reachable).
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));
app.get('/ready', async (req, res) => {
  try {
    await (await initDb()).prepare('SELECT 1 as ok').get();
    await chPing();
    res.json({ status: 'ready', time: new Date().toISOString() });
  } catch (e) {
    res.status(503).json({ status: 'not-ready', error: e.message });
  }
});

app.use('/api/auth',   authRouter);
app.use('/api/events', eventsRouter);
app.use('/api/agents', agentsRouter);
app.use('/api/deploy', deployRouter);
app.use('/api/ocsf',   ocsfRouter);
app.use('/api/osint',  osintRouter);
app.use('/api/dashboards', dashboardsRouter);
app.use('/api/tenants', tenantsRouter);
app.use('/api/teams', teamsRouter);
app.use('/api/users', usersRouter);
app.use('/api',        apiRouter);

if (isProd) {
  app.use(express.static(path.join(__dirname,'../../frontend/build')));
  app.get('*', (_,res) => res.sendFile(path.join(__dirname,'../../frontend/build/index.html')));
}

const server = http.createServer(app);
const wss    = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  console.log('[WS] Client connected');
  registerWsClient(ws);
  ws.send(JSON.stringify({ type:'connected', message:'K3 SIEM live stream active', timestamp:new Date().toISOString() }));
});

async function start() {
  await initDb();
  await initClickHouse();

  // Synthetic event/alert generation exists for demos only — it writes fake rows into the
  // same events/alerts tables real ingestion uses, so it must never run unannounced in a
  // real deployment. Defaults on outside of NODE_ENV=production (so `npm run dev` keeps
  // working out of the box); production requires an explicit opt-in.
  const demoMode = process.env.DEMO_MODE != null ? process.env.DEMO_MODE === 'true' : !isProd;
  if (demoMode) {
    console.log('[Ingestion] DEMO_MODE is ON — synthetic events/alerts will be generated. Set DEMO_MODE=false to disable.');
    startIngestion(parseInt(process.env.LOG_INGEST_INTERVAL) || 3000);
  } else {
    console.log('[Ingestion] DEMO_MODE is OFF — only real agent-ingested events will be stored.');
  }

  startAgentMonitor();
  startCorrelationEngine();
  startCrossCorrelation();
  startUebaEngine();
  startFeedSync();
  startRetention();
  server.listen(PORT, () => {
    console.log(`\n🛡️  K3 SIEM Backend v2.0`);
    console.log(`   API  → http://localhost:${PORT}/api`);
    console.log(`   WS   → ws://localhost:${PORT}/ws`);
    console.log(`   Run 'npm run seed' to load demo data\n`);
  });
}

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n[Shutdown] ${signal} received, closing gracefully...`);
  stopIngestion();
  stopAgentMonitor();
  stopCorrelationEngine();
  stopCrossCorrelation();
  stopUebaEngine();
  stopFeedSync();
  stopRetention();
  for (const ws of wss.clients) { try { ws.close(); } catch {} }
  await new Promise((resolve) => server.close(resolve));
  try {
    const { db } = require('./models/db');
    await db().close();
  } catch {}
  console.log('[Shutdown] Complete');
  process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

start().catch((e) => {
  if (isClickHouseConnRefused(e)) {
    console.error('[Startup] ClickHouse is not reachable at %s', process.env.CLICKHOUSE_URL || 'http://localhost:8123');
    console.error('[Startup] Local development requires ClickHouse. Start Docker Desktop or another local ClickHouse service, then run:');
    console.error('[Startup]   docker start k3-clickhouse');
    console.error('[Startup]   docker run -d --name k3-clickhouse -p 8123:8123 -p 9000:9000 clickhouse/clickhouse-server');
  }
  console.error('[Startup] Failed', e);
  process.exit(1);
});

module.exports = { app, server };
