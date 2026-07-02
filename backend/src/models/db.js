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
      close: async () => {
        if (_sqliteRaw) { try { _sqliteRaw.close(); } catch {} _sqliteRaw = null; }
      },
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
        indexed_at TIMESTAMPTZ DEFAULT NOW(), index_name TEXT DEFAULT 'primary',
        agent_id TEXT,
        ocsf_log TEXT, ocsf_class_uid INTEGER, ocsf_class_name TEXT, ocsf_category_name TEXT
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
      CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        hostname TEXT NOT NULL,
        os TEXT,
        ip TEXT,
        status TEXT DEFAULT 'online',
        agent_version TEXT,
        tags TEXT,
        config TEXT,
        collected_sources TEXT,
        events_sent INTEGER DEFAULT 0,
        last_heartbeat TIMESTAMPTZ DEFAULT NOW(),
        registered_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS deployments (
        id TEXT PRIMARY KEY,
        target_ip TEXT NOT NULL,
        target_os TEXT NOT NULL,
        target_user TEXT,
        status TEXT DEFAULT 'pending',
        logs TEXT,
        created_by TEXT,
        agent_id TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        completed_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        hostname TEXT,
        os_name TEXT,
        os_version TEXT,
        os_arch TEXT,
        cpu_model TEXT,
        cpu_cores INTEGER,
        ram_total_gb REAL,
        disk_total_gb REAL,
        disk_used_gb REAL,
        network_interfaces TEXT,
        installed_software TEXT,
        running_services TEXT,
        open_ports TEXT,
        local_users TEXT,
        antivirus_status TEXT,
        firewall_enabled INTEGER DEFAULT 0,
        last_patch_date TEXT,
        uptime_hours REAL,
        domain TEXT,
        serial_number TEXT,
        collected_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        software_name TEXT,
        software_version TEXT,
        software_type TEXT DEFAULT 'software',
        description TEXT,
        cvss_score REAL,
        severity TEXT DEFAULT 'UNKNOWN',
        published TEXT,
        last_modified TEXT,
        vuln_status TEXT,
        scanned_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(agent_id, cve_id, software_name)
      );
      CREATE INDEX IF NOT EXISTS idx_events_ts  ON events(timestamp);
      CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);
      CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
      CREATE INDEX IF NOT EXISTS idx_alerts_ts  ON alerts(created_at);
      CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
      CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(type);
      CREATE INDEX IF NOT EXISTS idx_incidents_ts     ON incidents(created_at);
      CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
      CREATE INDEX IF NOT EXISTS idx_inc_notes_inc    ON incident_notes(incident_id);
      CREATE INDEX IF NOT EXISTS idx_agents_status    ON agents(status);
      CREATE INDEX IF NOT EXISTS idx_deployments_status ON deployments(status);
      CREATE INDEX IF NOT EXISTS idx_assets_agent ON assets(agent_id);
      CREATE INDEX IF NOT EXISTS idx_vulns_agent ON vulnerabilities(agent_id);
      CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
      CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);
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
      indexed_at TEXT DEFAULT (datetime('now')), index_name TEXT DEFAULT 'primary',
      agent_id TEXT,
      ocsf_log TEXT, ocsf_class_uid INTEGER, ocsf_class_name TEXT, ocsf_category_name TEXT
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
    CREATE TABLE IF NOT EXISTS agents (
      id TEXT PRIMARY KEY,
      hostname TEXT NOT NULL,
      os TEXT,
      ip TEXT,
      status TEXT DEFAULT 'online',
      agent_version TEXT,
      tags TEXT,
      config TEXT,
      collected_sources TEXT,
      events_sent INTEGER DEFAULT 0,
      last_heartbeat TEXT DEFAULT (datetime('now')),
      registered_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS deployments (
      id TEXT PRIMARY KEY,
      target_ip TEXT NOT NULL,
      target_os TEXT NOT NULL,
      target_user TEXT,
      status TEXT DEFAULT 'pending',
      logs TEXT,
      created_by TEXT,
      agent_id TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      completed_at TEXT
    );
    CREATE TABLE IF NOT EXISTS assets (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      hostname TEXT,
      os_name TEXT,
      os_version TEXT,
      os_arch TEXT,
      cpu_model TEXT,
      cpu_cores INTEGER,
      ram_total_gb REAL,
      disk_total_gb REAL,
      disk_used_gb REAL,
      network_interfaces TEXT,
      installed_software TEXT,
      running_services TEXT,
      open_ports TEXT,
      local_users TEXT,
      antivirus_status TEXT,
      firewall_enabled INTEGER DEFAULT 0,
      last_patch_date TEXT,
      uptime_hours REAL,
      domain TEXT,
      serial_number TEXT,
      collected_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      cve_id TEXT NOT NULL,
      software_name TEXT,
      software_version TEXT,
      software_type TEXT DEFAULT 'software',
      description TEXT,
      cvss_score REAL,
      severity TEXT DEFAULT 'UNKNOWN',
      published TEXT,
      last_modified TEXT,
      vuln_status TEXT,
      scanned_at TEXT DEFAULT (datetime('now')),
      UNIQUE(agent_id, cve_id, software_name)
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts  ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);
    CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
    CREATE INDEX IF NOT EXISTS idx_alerts_ts  ON alerts(created_at);
    CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
    CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(type);
    CREATE INDEX IF NOT EXISTS idx_incidents_ts     ON incidents(created_at);
    CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
    CREATE INDEX IF NOT EXISTS idx_inc_notes_inc    ON incident_notes(incident_id);
    CREATE INDEX IF NOT EXISTS idx_agents_status    ON agents(status);
    CREATE INDEX IF NOT EXISTS idx_deployments_status ON deployments(status);
    CREATE INDEX IF NOT EXISTS idx_assets_agent ON assets(agent_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_agent ON vulnerabilities(agent_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);
  `;
}

async function migrateLegacyColumns(d) {
  const additions = [
    ['events', 'ocsf_log', 'TEXT'],
    ['events', 'ocsf_class_uid', 'INTEGER'],
    ['events', 'ocsf_class_name', 'TEXT'],
    ['events', 'ocsf_category_name', 'TEXT'],
  ];
  for (const [table, col, type] of additions) {
    try { await d.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${type}`); }
    catch (e) { /* column already exists */ }
  }
}

// Ordered, tracked migrations applied on every boot. Each runs at most once (recorded in
// schema_migrations) — this is how schema changes ship after initial release, since
// schemaSql() above only handles brand-new installs via CREATE TABLE IF NOT EXISTS.
const MIGRATIONS = [
  {
    name: '0001_correlation_rule_conditions',
    sql: () => `ALTER TABLE correlation_rules ADD COLUMN conditions TEXT`,
  },
  {
    name: '0002_audit_log',
    sql: (dialect) => dialect === 'postgres'
      ? `CREATE TABLE IF NOT EXISTS audit_log (
           id TEXT PRIMARY KEY, actor TEXT, action TEXT NOT NULL, entity_type TEXT, entity_id TEXT,
           detail TEXT, ip_address TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
         )`
      : `CREATE TABLE IF NOT EXISTS audit_log (
           id TEXT PRIMARY KEY, actor TEXT, action TEXT NOT NULL, entity_type TEXT, entity_id TEXT,
           detail TEXT, ip_address TEXT, created_at TEXT DEFAULT (datetime('now'))
         )`,
  },
  {
    name: '0003_audit_log_index',
    sql: () => `CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(created_at)`,
  },
  {
    name: '0004_process_nodes',
    sql: (dialect) => dialect === 'postgres'
      ? `CREATE TABLE IF NOT EXISTS process_nodes (
           id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, parent_id TEXT, sequence INTEGER,
           pid INTEGER, ppid INTEGER, process_name TEXT, image TEXT, command_line TEXT,
           hostname TEXT, username TEXT, sha256 TEXT, event_type TEXT,
           mitre_tactic TEXT, mitre_technique TEXT, severity TEXT DEFAULT 'Info',
           is_malicious INTEGER DEFAULT 0, first_detected_by TEXT, detection_rule TEXT,
           auto_analysis TEXT, impact TEXT, remediation TEXT, lessons_learned TEXT,
           timestamp TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW()
         )`
      : `CREATE TABLE IF NOT EXISTS process_nodes (
           id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, parent_id TEXT, sequence INTEGER,
           pid INTEGER, ppid INTEGER, process_name TEXT, image TEXT, command_line TEXT,
           hostname TEXT, username TEXT, sha256 TEXT, event_type TEXT,
           mitre_tactic TEXT, mitre_technique TEXT, severity TEXT DEFAULT 'Info',
           is_malicious INTEGER DEFAULT 0, first_detected_by TEXT, detection_rule TEXT,
           auto_analysis TEXT, impact TEXT, remediation TEXT, lessons_learned TEXT,
           timestamp TEXT, created_at TEXT DEFAULT (datetime('now'))
         )`,
  },
  {
    name: '0005_process_nodes_index',
    sql: () => `CREATE INDEX IF NOT EXISTS idx_process_nodes_incident ON process_nodes(incident_id)`,
  },
  {
    name: '0006_incidents_impact',
    sql: () => `ALTER TABLE incidents ADD COLUMN impact TEXT`,
  },
  {
    name: '0007_incidents_remediation',
    sql: () => `ALTER TABLE incidents ADD COLUMN remediation TEXT`,
  },
  {
    name: '0008_incidents_lessons_learned',
    sql: () => `ALTER TABLE incidents ADD COLUMN lessons_learned TEXT`,
  },
];

async function runMigrations(d) {
  await d.exec(d.dialect === 'postgres'
    ? `CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT NOW())`
    : `CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT DEFAULT (datetime('now')))`
  );
  for (const m of MIGRATIONS) {
    const applied = await d.prepare('SELECT name FROM schema_migrations WHERE name = ?').get(m.name);
    if (applied) continue;
    try {
      await d.exec(m.sql(d.dialect));
    } catch (e) {
      if (!/duplicate column|already exists/i.test(e.message)) throw e;
    }
    await d.prepare('INSERT INTO schema_migrations(name) VALUES(?)').run(m.name);
    console.log(`[Migrate] Applied ${m.name}`);
  }
}

async function initDb() {
  const d = db();
  await d.exec(schemaSql());
  await migrateLegacyColumns(d);
  await d.exec('CREATE INDEX IF NOT EXISTS idx_events_ocsf_class ON events(ocsf_class_uid);');
  await runMigrations(d);
  if (d.dialect === 'sqlite') console.log('[DB] Schema ready:', SQLITE_DB_PATH);
  else console.log('[DB] Schema ready:', 'postgres');
  return d;
}

module.exports = { db, initDb, getDialect, sqlNow, sqlNowMinus, sqlDate, runMigrations };
