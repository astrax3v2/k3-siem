'use strict';
const express = require('express');
const { chQuery } = require('../models/clickhouse');
const { authenticate } = require('../middleware/auth');
const { parseToOCSF, OCSF_VERSION, OCSF_CLASS_REFERENCE } = require('../services/ocsfParser');
const router = express.Router();

// On-demand parse of any pasted raw log (string or JSON) into OCSF.
router.post('/parse', authenticate, async (req, res) => {
  const { raw } = req.body;
  if (raw === undefined || raw === null || raw === '') {
    return res.status(400).json({ error: 'raw log text or object is required' });
  }
  try {
    const ocsf = parseToOCSF(raw);
    res.json({ ocsf });
  } catch (e) {
    res.status(400).json({ error: `Failed to parse log: ${e.message}` });
  }
});

router.get('/schema', authenticate, async (req, res) => {
  res.json({ version: OCSF_VERSION, classes: OCSF_CLASS_REFERENCE });
});

router.get('/stats', authenticate, async (req, res) => {
  const total = (await chQuery("SELECT COUNT(*) as cnt FROM events WHERE ocsf_class_uid IS NOT NULL"))[0]?.cnt || 0;
  const byClass = await chQuery('SELECT ocsf_class_uid, ocsf_class_name, COUNT(*) as cnt FROM events WHERE ocsf_class_uid IS NOT NULL GROUP BY ocsf_class_uid, ocsf_class_name ORDER BY cnt DESC');
  const byCategory = await chQuery('SELECT ocsf_category_name, COUNT(*) as cnt FROM events WHERE ocsf_category_name IS NOT NULL GROUP BY ocsf_category_name ORDER BY cnt DESC');
  res.json({ total, byClass, byCategory });
});

router.get('/events', authenticate, async (req, res) => {
  const { class_uid, category, search, page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page, 10) - 1) * parseInt(limit, 10);
  let where = ['ocsf_class_uid IS NOT NULL'], params = {};
  if (class_uid) { where.push('ocsf_class_uid = {class_uid:UInt32}'); params.class_uid = parseInt(class_uid, 10); }
  if (category) { where.push('ocsf_category_name = {category:String}'); params.category = category; }
  if (search) { where.push('(action ILIKE {search:String} OR username ILIKE {search:String} OR computer ILIKE {search:String} OR ip_address ILIKE {search:String})'); params.search = `%${search}%`; }
  const wc = 'WHERE ' + where.join(' AND ');
  const total = (await chQuery(`SELECT COUNT(*) as cnt FROM events ${wc}`, params))[0]?.cnt || 0;
  const rows = await chQuery(`SELECT id, timestamp, source, event_id, computer, username, ip_address, action, severity, ocsf_class_uid, ocsf_class_name, ocsf_category_name FROM events ${wc} ORDER BY timestamp DESC LIMIT {limit:UInt32} OFFSET {offset:UInt32}`, { ...params, limit: parseInt(limit, 10), offset });
  res.json({ events: rows, total, page: parseInt(page, 10), limit: parseInt(limit, 10), pages: Math.ceil(total / parseInt(limit, 10)) });
});

router.get('/events/:id', authenticate, async (req, res) => {
  const rows = await chQuery('SELECT * FROM events WHERE id = {id:String}', { id: req.params.id });
  const row = rows[0];
  if (!row) return res.status(404).json({ error: 'Event not found' });
  let ocsf = null;
  if (row.ocsf_log) {
    try { ocsf = JSON.parse(row.ocsf_log); } catch { /* fall through */ }
  }
  if (!ocsf) ocsf = parseToOCSF(row.raw_log || row);
  res.json({ event: row, ocsf });
});

module.exports = router;
