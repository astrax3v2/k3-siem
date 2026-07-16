'use strict';
// Cross-correlation groups alerts from DIFFERENT rules/tactics for the same entity into a
// single auto-created incident — unlike correlationEngine.js, which only ever evaluates one
// rule against raw events. Seeds two alerts with distinct rule_ids for the same username and
// confirms runOnce() creates exactly one incident linking both.
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const TEST_DB = path.resolve(__dirname, '../../data/test-cross-correlation.db');

describe('crossCorrelation.runOnce', () => {
  let db, initDb, runOnce, countRecent;

  beforeAll(async () => {
    process.env.DB_PATH = TEST_DB;
    if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    ({ db, initDb } = require('../../src/models/db'));
    await initDb();
    ({ runOnce, countRecent } = require('../../src/services/crossCorrelation'));
  });

  afterAll(async () => {
    await db().close();
    try { if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB); } catch { /* Windows may hold a brief handle */ }
  });

  async function seedAlert({ rule_id, mitre_tactic = null, username = 'jdoe', severity = 'High' }) {
    const id = uuidv4();
    await db().prepare(
      `INSERT INTO alerts(id,title,description,severity,status,source,username,rule_id,mitre_tactic,risk_score)
       VALUES(?,?,?,?,?,?,?,?,?,?)`
    ).run(id, `Alert from ${rule_id}`, 'test', severity, 'New', 'test', username, rule_id, mitre_tactic, 80);
    return id;
  }

  test('groups alerts from two distinct rules for the same user into one incident', async () => {
    await seedAlert({ rule_id: 'rule-a', username: 'jdoe', severity: 'High' });
    await seedAlert({ rule_id: 'rule-b', username: 'jdoe', severity: 'Critical' });

    await runOnce();

    const incidents = await db().prepare("SELECT * FROM incidents WHERE tags LIKE ?").all('%cross-correlation%');
    expect(incidents.length).toBe(1);
    expect(incidents[0].severity).toBe('Critical'); // max severity among the grouped alerts
    expect(incidents[0].title).toContain('jdoe');

    const links = await db().prepare('SELECT * FROM incident_alerts WHERE incident_id = ?').all(incidents[0].id);
    expect(links.length).toBe(2);
  });

  test('does not create a second incident for alerts already grouped', async () => {
    await runOnce();
    const incidents = await db().prepare("SELECT * FROM incidents WHERE tags LIKE ?").all('%cross-correlation%');
    expect(incidents.length).toBe(1); // still just the one from the previous test
  });

  test('does not group a single alert or alerts sharing the same rule_id', async () => {
    await seedAlert({ rule_id: 'rule-c', username: 'alone' });
    await seedAlert({ rule_id: 'rule-d', username: 'same-rule' });
    await seedAlert({ rule_id: 'rule-d', username: 'same-rule' });

    await runOnce();

    const incidents = await db().prepare("SELECT * FROM incidents WHERE tags LIKE ?").all('%cross-correlation%');
    expect(incidents.length).toBe(1); // no new incidents for 'alone' or 'same-rule'
  });

  test('countRecent reflects auto-created incidents in the last 24h', async () => {
    expect(await countRecent()).toBe(1);
  });
});
