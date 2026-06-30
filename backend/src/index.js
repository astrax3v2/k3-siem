'use strict';
require('dotenv').config();
require('./config'); // validates JWT_SECRET / INGEST_API_KEY are set; exits process if not
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const morgan     = require('morgan');
const compression= require('compression');
const rateLimit  = require('express-rate-limit');
const http       = require('http');
const { WebSocketServer } = require('ws');
const path       = require('path');

const { initDb }            = require('./models/db');
const { startIngestion, stopIngestion, registerWsClient } = require('./services/ingestion');
const { startAgentMonitor, stopAgentMonitor } = require('./services/agentMonitor');
const { startCorrelationEngine, stopCorrelationEngine } = require('./services/correlationEngine');
const { startUebaEngine, stopUebaEngine } = require('./services/userRiskEngine');
const { startFeedSync, stopFeedSync } = require('./services/connectors/feedSync');
const { startRetention, stopRetention } = require('./services/retention');
const authRouter   = require('./routes/auth');
const eventsRouter = require('./routes/events');
const agentsRouter = require('./routes/agents');
const deployRouter = require('./routes/deploy');
const ocsfRouter   = require('./routes/ocsf');
const apiRouter    = require('./routes/api');

const app  = express();
const PORT = process.env.PORT || 3001;
const isProd = process.env.NODE_ENV === 'production';

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
  startIngestion(parseInt(process.env.LOG_INGEST_INTERVAL) || 3000);
  startAgentMonitor();
  startCorrelationEngine();
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
  console.error('[Startup] Failed', e);
  process.exit(1);
});

module.exports = { app, server };
