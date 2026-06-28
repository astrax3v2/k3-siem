'use strict';
const path = require('path');
const fs = require('fs');

const SQLITE_DB_PATH = path.resolve(process.env.DB_PATH || './data/siem.db');
let _dialect = null;
let _sqliteRaw = null;
let _pgPool = null;

function getDialect() {
  if (_dialect) return _dialect;
  const env = (process.env.DB_CLIENT || '').toLowerCase();
  if (env === 'postgres' || env === 'postgresql') { _dialect = 'postgres'; return _dialect; }
  if (process.env.DATABASE_URL || process.env.PGHOST) { _dialect = 'postgres'; return _dialect; }
  _dialect = 'sqlite';
  return _dialect;
}

function sqlNow() {
  return getDialect() === 'postgres' ? 'NOW()' : "datetime('now')";
}

function sqlNowMinus(amount, unit) {
  const d = getDialect();
  if (d === 'postgres') {
    const u = unit.endsWith('s') ? unit : `${unit}s`;
    return `NOW() - interval '${amount} ${u}'`;
  }
  const u = unit.endsWith('s') ? unit : `${unit}s`;
  return `datetime('now','-${amount} ${u}')`;
}

function sqlDate(col) {
  return getDialect() === 'postgres' ? `${col}::date` : `date(${col})`;
}

function getSqliteRaw() {
  if (_sqliteRaw) return _sqliteRaw;
  const { DatabaseSync } = require('node:sqlite');
  const dir = path.dirname(SQLITE_DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  _sqliteRaw = new DatabaseSync(SQLITE_DB_PATH);
  _sqliteRaw.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;");
  return _sqliteRaw;
}

function getPgPool() {
  if (_pgPool) return _pgPool;
  const { Pool } = require('pg');
  const connectionString = process.env.DATABASE_URL;
  const cfg = connectionString ? { connectionString } : {
    host: process.env.PGHOST,
    port: process.env.PGPORT ? parseInt(process.env.PGPORT, 10) : 5432,
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    database: process.env.PGDATABASE,
  };
  _pgPool = new Pool(cfg);
  return _pgPool;
}

function plain(r) {
  if (!r) return undefined;
  return Object.assign({}, r);
}

function toPgPlaceholders(sql) {
  let out = '';
  let i = 0;
  let idx = 0;
  let inSingle = false;
  let inDouble = false;
  while (i < sql.length) {
    const ch = sql[i];
    if (ch === "'" && !inDouble) {
      if (inSingle && sql[i + 1] === "'") {
        out += "''";
        i += 2;
        continue;
      }
      inSingle = !inSingle;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === '?' && !inSingle && !inDouble) {
      idx += 1;
      out += `$${idx}`;
      i += 1;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

function db() {
  const dialect = getDialect();
  if (dialect === 'sqlite') {
    const raw = getSqliteRaw();
    return {
      dialect,
      exec: async (sql) => raw.exec(sql),
      prepare(sql) {
        const stmt = raw.prepare(sql);
        return {
          run: async (...args) => stmt.run(...args),
          get: async (...args) => plain(stmt.get(...args)),
          all: async (...args) => (stmt.all(...args) || []).map(plain),
        };
      },
      transaction(fn) {
        return async (...args) => {
          raw.exec('BEGIN');
          try {
            const out = await fn(...args);
            raw.exec('COMMIT');
            return out;
          } catch (e) {
            raw.exec('ROLLBACK');
            throw e;
          }
        };
      },
      close: async () => {},
    };
  }

  const pool = getPgPool();
  let txClient = null;
  const query = async (sql, args) => {
    const text = toPgPlaceholders(sql);
    const client = txClient || pool;
    return client.query(text, args);
  };
  return {
    dialect,
    exec: async (sql) => { await (txClient || pool).query(sql); },
    prepare(sql) {
      return {
        run: async (...args) => query(sql, args),
        get: async (...args) => (await query(sql, args)).rows[0],
        all: async (...args) => (await query(sql, args)).rows,
      };
    },
    transaction(fn) {
      return async (...args) => {
        const client = await pool.connect();
        const prev = txClient;
        try {
          await client.query('BEGIN');
          txClient = client;
          const out = await fn(...args);
          await client.query('COMMIT');
          return out;
        } catch (e) {
          try { await client.query('ROLLBACK'); } catch {}
          throw e;
        } finally {
          txClient = prev;
          client.release();
        }
      };
    },
    close: async () => { await pool.end(); },
  };
}

function schemaSql() {
  if (getDialect() === 'postgres') {
    return `
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, role TEXT DEFAULT 't1_analyst', full_name TEXT,
        department TEXT, created_at TIMESTAMPTZ DEFAULT NOW(), last_login TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY, timestamp TIMESTAMPTZ DEFAULT NOW(), source TEXT NOT NULL,
        event_id TEXT, computer TEXT, username TEXT, ip_address TEXT, action TEXT,
        severity TEXT DEFAULT 'Info', raw_log TEXT,
        indexed_at TIMESTAMPTZ DEFAULT NOW(), index_name TEXT DEFAULT 'primary'
      );
      CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT, severity TEXT NOT NULL,
        status TEXT DEFAULT 'New', source TEXT, asset TEXT, username TEXT, ip_address TEXT,
        mitre_tactic TEXT, mitre_technique TEXT, rule_id TEXT, risk_score INTEGER DEFAULT 0,
        analyst_id TEXT, created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(), closed_at TIMESTAMPTZ, raw_evidence TEXT
      );
      CREATE TABLE IF NOT EXISTS iocs (
        id TEXT PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL,
        confidence INTEGER DEFAULT 50, severity TEXT DEFAULT 'Medium', source TEXT,
        description TEXT, tags TEXT, hits INTEGER DEFAULT 0, active INTEGER DEFAULT 1,
        first_seen TIMESTAMPTZ DEFAULT NOW(), last_seen TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT,
        severity TEXT NOT NULL, status TEXT DEFAULT 'Open',
        priority INTEGER DEFAULT 3, owner TEXT,
        tags TEXT, created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(), closed_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS incident_alerts (
        incident_id TEXT NOT NULL, alert_id TEXT NOT NULL,
        added_at TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (incident_id, alert_id)
      );
      CREATE TABLE IF NOT EXISTS incident_notes (
        id TEXT PRIMARY KEY, incident_id TEXT NOT NULL,
        author TEXT, note TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS correlation_rules (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT, logic TEXT,
        severity TEXT DEFAULT 'High', risk_score INTEGER DEFAULT 80, enabled INTEGER DEFAULT 1,
        window_minutes INTEGER DEFAULT 5, indices TEXT, threshold INTEGER DEFAULT 1,
        created_at TIMESTAMPTZ DEFAULT NOW(), last_triggered TIMESTAMPTZ, hit_count INTEGER DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS playbooks (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT, trigger_condition TEXT,
        status TEXT DEFAULT 'Active', steps TEXT, execution_count INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW(), last_executed TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS playbook_executions (
        id TEXT PRIMARY KEY, playbook_id TEXT NOT NULL, alert_id TEXT, triggered_by TEXT,
        status TEXT DEFAULT 'running', started_at TIMESTAMPTZ DEFAULT NOW(),
        completed_at TIMESTAMPTZ, steps_completed INTEGER DEFAULT 0, result TEXT
      );
      CREATE TABLE IF NOT EXISTS ueba_scores (
        id TEXT PRIMARY KEY, username TEXT NOT NULL, risk_score INTEGER DEFAULT 0,
        anomaly_count INTEGER DEFAULT 0, baseline_deviation REAL DEFAULT 0,
        flags TEXT, department TEXT, location TEXT, last_activity TEXT,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS kql_saved_queries (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, query TEXT NOT NULL, description TEXT,
        category TEXT, created_by TEXT, is_rule INTEGER DEFAULT 0, schedule TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS intel_feeds (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT, type TEXT,
        status TEXT DEFAULT 'active', last_sync TIMESTAMPTZ, ioc_count INTEGER DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_events_ts  ON events(timestamp);
      CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);
      CREATE INDEX IF NOT EXISTS idx_alerts_ts  ON alerts(created_at);
      CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
      CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(type);
      CREATE INDEX IF NOT EXISTS idx_incidents_ts     ON incidents(created_at);
      CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
      CREATE INDEX IF NOT EXISTS idx_inc_notes_inc    ON incident_notes(incident_id);
    `;
  }
  return `
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role TEXT DEFAULT 't1_analyst', full_name TEXT,
      department TEXT, created_at TEXT DEFAULT (datetime('now')), last_login TEXT
    );
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY, timestamp TEXT DEFAULT (datetime('now')), source TEXT NOT NULL,
      event_id TEXT, computer TEXT, username TEXT, ip_address TEXT, action TEXT,
      severity TEXT DEFAULT 'Info', raw_log TEXT,
      indexed_at TEXT DEFAULT (datetime('now')), index_name TEXT DEFAULT 'primary'
    );
    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT, severity TEXT NOT NULL,
      status TEXT DEFAULT 'New', source TEXT, asset TEXT, username TEXT, ip_address TEXT,
      mitre_tactic TEXT, mitre_technique TEXT, rule_id TEXT, risk_score INTEGER DEFAULT 0,
      analyst_id TEXT, created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')), closed_at TEXT, raw_evidence TEXT
    );
    CREATE TABLE IF NOT EXISTS iocs (
      id TEXT PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL,
      confidence INTEGER DEFAULT 50, severity TEXT DEFAULT 'Medium', source TEXT,
      description TEXT, tags TEXT, hits INTEGER DEFAULT 0, active INTEGER DEFAULT 1,
      first_seen TEXT DEFAULT (datetime('now')), last_seen TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT,
      severity TEXT NOT NULL, status TEXT DEFAULT 'Open',
      priority INTEGER DEFAULT 3, owner TEXT,
      tags TEXT, created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')), closed_at TEXT
    );
    CREATE TABLE IF NOT EXISTS incident_alerts (
      incident_id TEXT NOT NULL, alert_id TEXT NOT NULL,
      added_at TEXT DEFAULT (datetime('now')),
      PRIMARY KEY (incident_id, alert_id)
    );
    CREATE TABLE IF NOT EXISTS incident_notes (
      id TEXT PRIMARY KEY, incident_id TEXT NOT NULL,
      author TEXT, note TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS correlation_rules (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT, logic TEXT,
      severity TEXT DEFAULT 'High', risk_score INTEGER DEFAULT 80, enabled INTEGER DEFAULT 1,
      window_minutes INTEGER DEFAULT 5, indices TEXT, threshold INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now')), last_triggered TEXT, hit_count INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS playbooks (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT, trigger_condition TEXT,
      status TEXT DEFAULT 'Active', steps TEXT, execution_count INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')), last_executed TEXT
    );
    CREATE TABLE IF NOT EXISTS playbook_executions (
      id TEXT PRIMARY KEY, playbook_id TEXT NOT NULL, alert_id TEXT, triggered_by TEXT,
      status TEXT DEFAULT 'running', started_at TEXT DEFAULT (datetime('now')),
      completed_at TEXT, steps_completed INTEGER DEFAULT 0, result TEXT
    );
    CREATE TABLE IF NOT EXISTS ueba_scores (
      id TEXT PRIMARY KEY, username TEXT NOT NULL, risk_score INTEGER DEFAULT 0,
      anomaly_count INTEGER DEFAULT 0, baseline_deviation REAL DEFAULT 0,
      flags TEXT, department TEXT, location TEXT, last_activity TEXT,
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS kql_saved_queries (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, query TEXT NOT NULL, description TEXT,
      category TEXT, created_by TEXT, is_rule INTEGER DEFAULT 0, schedule TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS intel_feeds (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT, type TEXT,
      status TEXT DEFAULT 'active', last_sync TEXT, ioc_count INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts  ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_ts  ON alerts(created_at);
    CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
    CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(type);
    CREATE INDEX IF NOT EXISTS idx_incidents_ts     ON incidents(created_at);
    CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
    CREATE INDEX IF NOT EXISTS idx_inc_notes_inc    ON incident_notes(incident_id);
  `;
}

async function initDb() {
  const d = db();
  await d.exec(schemaSql());
  if (d.dialect === 'sqlite') console.log('[DB] Schema ready:', SQLITE_DB_PATH);
  else console.log('[DB] Schema ready:', 'postgres');
  return d;
}

module.exports = { db, initDb, getDialect, sqlNow, sqlNowMinus, sqlDate };
