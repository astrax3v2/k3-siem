'use strict';
require('dotenv').config();
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
const { startIngestion, registerWsClient } = require('./services/ingestion');
const authRouter   = require('./routes/auth');
const eventsRouter = require('./routes/events');
const apiRouter    = require('./routes/api');

const app  = express();
const PORT = process.env.PORT || 3001;

app.set('trust proxy', process.env.TRUST_PROXY ? parseInt(process.env.TRUST_PROXY, 10) : 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CORS_ORIGIN || '*', credentials: true }));
app.use(compression());
app.use(morgan('dev'));
app.use(express.json({ limit: '10mb' }));
app.use(rateLimit({ windowMs: 15*60*1000, max: 1000 }));

app.use('/api/auth',   authRouter);
app.use('/api/events', eventsRouter);
app.use('/api',        apiRouter);

if (process.env.NODE_ENV === 'production') {
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
  server.listen(PORT, () => {
    console.log(`\n🛡️  K3 SIEM Backend`);
    console.log(`   API  → http://localhost:${PORT}/api`);
    console.log(`   WS   → ws://localhost:${PORT}/ws`);
    console.log(`   Run 'npm run seed' to load demo data\n`);
  });
}

start().catch((e) => {
  console.error('[Startup] Failed', e);
  process.exit(1);
});

module.exports = { app, server };
