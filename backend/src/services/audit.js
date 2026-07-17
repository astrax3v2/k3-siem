'use strict';
const { v4: uuidv4 } = require('uuid');
const { chInsert } = require('../models/clickhouse');

async function logAction(actor, action, entityType, entityId, detail, ipAddress) {
  try {
    await chInsert('audit_log', [{
      id: uuidv4(), actor: actor || 'system', action, entity_type: entityType || null,
      entity_id: entityId || null, detail: detail || null, ip_address: ipAddress || null,
    }]);
  } catch (e) {
    console.error('[Audit] Failed to record action:', e.message);
  }
}

module.exports = { logAction };
