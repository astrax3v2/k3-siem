'use strict';
const { normalizeRole, ROLE_ADMIN } = require('../middleware/auth');

const DEFAULT_TENANT_ID = 'tenant-default';

function isPlatformAdmin(user) {
  return normalizeRole(user?.role) === ROLE_ADMIN;
}

function normalizeTenantId(value) {
  return value || DEFAULT_TENANT_ID;
}

function scopeTenantClause(user, tenantColumnExpr) {
  if (!tenantColumnExpr || isPlatformAdmin(user)) return { clause: null, params: [] };
  return { clause: `${tenantColumnExpr} = ?`, params: [normalizeTenantId(user?.tenant_id)] };
}

class TenantForbiddenError extends Error {
  constructor(message) {
    super(message);
    this.status = 403;
  }
}

function assertTenantAccess(user, itemTenantId) {
  if (isPlatformAdmin(user)) return;
  if (normalizeTenantId(itemTenantId) !== normalizeTenantId(user?.tenant_id)) {
    throw new TenantForbiddenError('This item belongs to another tenant');
  }
}

function guardTenantAccess(res, user, itemTenantId) {
  try {
    assertTenantAccess(user, itemTenantId);
    return true;
  } catch (e) {
    res.status(e.status || 403).json({ error: e.message });
    return false;
  }
}

module.exports = {
  DEFAULT_TENANT_ID,
  isPlatformAdmin,
  normalizeTenantId,
  scopeTenantClause,
  assertTenantAccess,
  guardTenantAccess,
  TenantForbiddenError,
};
