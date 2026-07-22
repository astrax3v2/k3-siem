'use strict';
// ClickHouse client for the high-volume, append-only log tables (events, audit_log,
// process_nodes). Deliberately separate from db.js's Postgres/SQLite dialect switch:
// ClickHouse has no transactions, no row-level UPDATE/DELETE, and no `?`-positional
// binding, so it doesn't fit that abstraction — it gets its own minimal one instead.
let _client = null;

function chClient() {
  if (_client) return _client;
  const { createClient } = require('@clickhouse/client');
  _client = createClient({
    url: process.env.CLICKHOUSE_URL || 'http://localhost:8123',
    username: process.env.CLICKHOUSE_USER || 'default',
    password: process.env.CLICKHOUSE_PASSWORD || '',
    database: process.env.CLICKHOUSE_DB || 'k3_siem',
  });
  return _client;
}

// SQL-snippet helpers mirroring sqlNow/sqlNowMinus/sqlDate in db.js.
function chNow() {
  return 'now64(3)';
}

function chNowMinus(amount, unit) {
  const u = unit.toUpperCase().endsWith('S') ? unit.toUpperCase() : `${unit.toUpperCase()}S`;
  return `now64(3) - INTERVAL ${amount} ${u}`;
}

function chDate(col) {
  return `toDate(${col})`;
}

async function chQuery(sql, params = {}) {
  const resultSet = await chClient().query({ query: sql, query_params: params, format: 'JSONEachRow' });
  return resultSet.json();
}

async function chInsert(table, rows) {
  if (!rows || !rows.length) return;
  // best_effort lets DateTime64 columns accept ISO 8601 strings (e.g. from Date#toISOString())
  // instead of only ClickHouse's native 'YYYY-MM-DD HH:MM:SS[.ffffff]' format.
  await chClient().insert({
    table, values: rows, format: 'JSONEachRow',
    clickhouse_settings: { date_time_input_format: 'best_effort' },
  });
}

async function chExec(sql) {
  await chClient().command({ query: sql });
}

async function chPing() {
  const ok = await chClient().ping();
  if (!ok || ok.success === false) throw new Error('ClickHouse ping failed');
}

async function initClickHouse() {
  const retentionDays = parseInt(process.env.EVENTS_RETENTION_DAYS || '90', 10);
  const dbName = process.env.CLICKHOUSE_DB || 'k3_siem';

  // The configured database may not exist yet on a fresh server — create it via a
  // bootstrap connection (ClickHouse always has a `default` database to connect to).
  const { createClient } = require('@clickhouse/client');
  const bootstrap = createClient({
    url: process.env.CLICKHOUSE_URL || 'http://localhost:8123',
    username: process.env.CLICKHOUSE_USER || 'default',
    password: process.env.CLICKHOUSE_PASSWORD || '',
  });
  await bootstrap.command({ query: `CREATE DATABASE IF NOT EXISTS ${dbName}` });
  await bootstrap.close();

  await chExec(`
    CREATE TABLE IF NOT EXISTS events (
      id String, timestamp DateTime64(3) DEFAULT now64(3), source String, event_id String,
      computer Nullable(String), username Nullable(String), ip_address Nullable(String),
      action Nullable(String), severity LowCardinality(String) DEFAULT 'Info', raw_log String,
      indexed_at DateTime64(3) DEFAULT now64(3), index_name LowCardinality(String) DEFAULT 'primary',
      agent_id Nullable(String), parser_profile Nullable(String), parser_vendor Nullable(String),
      parser_product Nullable(String), parser_family Nullable(String), parser_device_type Nullable(String),
      parser_format Nullable(String), ocsf_log Nullable(String), ocsf_class_uid Nullable(UInt32),
      ocsf_class_name Nullable(String), ocsf_category_name Nullable(String)
    ) ENGINE = MergeTree
    PARTITION BY toYYYYMM(timestamp)
    ORDER BY (timestamp, severity, agent_id)
    TTL toDateTime(timestamp) + INTERVAL ${retentionDays} DAY
    SETTINGS allow_nullable_key = 1
  `);
  // Applied on every boot so a changed EVENTS_RETENTION_DAYS takes effect without a manual migration.
  await chExec(`ALTER TABLE events MODIFY TTL toDateTime(timestamp) + INTERVAL ${retentionDays} DAY`);
  await chExec(`ALTER TABLE events ADD COLUMN IF NOT EXISTS parser_profile Nullable(String)`);
  await chExec(`ALTER TABLE events ADD COLUMN IF NOT EXISTS parser_vendor Nullable(String)`);
  await chExec(`ALTER TABLE events ADD COLUMN IF NOT EXISTS parser_product Nullable(String)`);
  await chExec(`ALTER TABLE events ADD COLUMN IF NOT EXISTS parser_family Nullable(String)`);
  await chExec(`ALTER TABLE events ADD COLUMN IF NOT EXISTS parser_device_type Nullable(String)`);
  await chExec(`ALTER TABLE events ADD COLUMN IF NOT EXISTS parser_format Nullable(String)`);

  await chExec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id String, actor String, action String, entity_type Nullable(String), entity_id Nullable(String),
      detail Nullable(String), ip_address Nullable(String), created_at DateTime64(3) DEFAULT now64(3)
    ) ENGINE = MergeTree ORDER BY created_at
  `);

  await chExec(`
    CREATE TABLE IF NOT EXISTS process_nodes (
      id String, incident_id String, parent_id Nullable(String), sequence Int32,
      pid Nullable(Int32), ppid Nullable(Int32), process_name Nullable(String), image Nullable(String),
      command_line Nullable(String), hostname Nullable(String), username Nullable(String), sha256 Nullable(String),
      event_type Nullable(String), mitre_tactic Nullable(String), mitre_technique Nullable(String),
      severity LowCardinality(String) DEFAULT 'Info', is_malicious UInt8 DEFAULT 0,
      first_detected_by Nullable(String), detection_rule Nullable(String), auto_analysis Nullable(String),
      impact Nullable(String), remediation Nullable(String), lessons_learned Nullable(String),
      timestamp Nullable(DateTime64(3)), created_at DateTime64(3) DEFAULT now64(3)
    ) ENGINE = MergeTree ORDER BY (incident_id, sequence)
  `);

  console.log('[ClickHouse] Schema ready');
}

module.exports = { chClient, chQuery, chInsert, chExec, chPing, chNow, chNowMinus, chDate, initClickHouse };
