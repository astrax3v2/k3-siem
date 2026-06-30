'use strict';
const { v4: uuidv4 } = require('uuid');
const { db } = require('../models/db');

async function logAction(actor, action, entityType, entityId, detail, ipAddress) {
  try {
    await db().prepare(
      'INSERT INTO audit_log(id,actor,action,entity_type,entity_id,detail,ip_address) VALUES(?,?,?,?,?,?,?)'
    ).run(uuidv4(), actor || 'system', action, entityType || null, entityId || null, detail || null, ipAddress || null);
  } catch (e) {
    console.error('[Audit] Failed to record action:', e.message);
  }
}

module.exports = { logAction };
