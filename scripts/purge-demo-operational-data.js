'use strict';

const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const dbPath = process.argv[2] || path.resolve(__dirname, '..', 'backend', 'data', 'siem.db');
const db = new DatabaseSync(dbPath);

const tableOrder = [
  'playbook_executions',
  'ueba_scores',
  'intel_feeds',
  'process_nodes',
  'incident_alerts',
  'incident_notes',
  'incidents',
  'iocs',
  'alerts',
  'events',
  'vulnerabilities',
  'assets',
  'agents',
];

function counts() {
  return tableOrder.map((table) => ({
    table,
    count: db.prepare(`SELECT COUNT(*) AS cnt FROM ${table}`).get().cnt,
  }));
}

console.log(JSON.stringify({ dbPath, before: counts() }, null, 2));

db.exec('PRAGMA foreign_keys = OFF;');
for (const table of tableOrder) {
  db.prepare(`DELETE FROM ${table}`).run();
}
db.exec('PRAGMA foreign_keys = ON;');

console.log(JSON.stringify({ dbPath, after: counts() }, null, 2));
