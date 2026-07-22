'use strict';
// Team-scoped RBAC: non-admin analysts only see/act on items belonging to their own
// team, plus "unassigned" items (team_id IS NULL) which are visible to everyone as a
// shared inbox until triaged into a team's queue.
const { normalizeRole, ROLE_ADMIN } = require('../middleware/auth');
const { isPlatformAdmin, scopeTenantClause, assertTenantAccess } = require('./tenantScope');

function isAdmin(user) {
  return normalizeRole(user?.role) === ROLE_ADMIN;
}

// Alerts have no team_id of their own — team is resolved live via the asset hostname
// matching a registered agent's hostname. LEFT JOIN so alerts with no matching agent
// still return (team resolves to NULL = unassigned, not invisible).
function alertTeamJoin() {
  return 'LEFT JOIN agents ag ON ag.hostname = a.asset';
}

/**
 * Returns { clause, params } to AND onto an existing WHERE-builder's where/params
 * arrays. Admins get no restriction (clause is null — caller should skip pushing it).
 */
function scopeClause(user, teamColumnExpr, tenantColumnExpr = null) {
  const parts = [];
  const params = [];

  const tenantScope = scopeTenantClause(user, tenantColumnExpr);
  if (tenantScope.clause) {
    parts.push(tenantScope.clause);
    params.push(...tenantScope.params);
  }

  if (!isAdmin(user)) {
    parts.push(`(${teamColumnExpr} = ? OR ${teamColumnExpr} IS NULL)`);
    params.push(user?.team_id || null);
  }

  return { clause: parts.length ? parts.join(' AND ') : null, params };
}

class ForbiddenError extends Error {
  constructor(message) {
    super(message);
    this.status = 403;
  }
}

// Throws if a non-admin tries to act on an item outside their team. Unassigned items
// (itemTeamId falsy) are always allowed — same shared-inbox rule as scopeClause.
function assertTeamAccess(user, itemTeamId, itemTenantId = null) {
  assertTenantAccess(user, itemTenantId);
  if (isPlatformAdmin(user)) return;
  if (itemTeamId && itemTeamId !== user?.team_id) {
    throw new ForbiddenError('This item belongs to another team');
  }
}

// Express-response-shaped wrapper: returns true if access is allowed, otherwise sends the
// 403 response itself and returns false — callers just do `if (!guardTeamAccess(...)) return;`.
function guardTeamAccess(res, user, itemTeamId, itemTenantId = null) {
  try {
    assertTeamAccess(user, itemTeamId, itemTenantId);
    return true;
  } catch (e) {
    res.status(e.status || 403).json({ error: e.message });
    return false;
  }
}

module.exports = { isAdmin, alertTeamJoin, scopeClause, assertTeamAccess, guardTeamAccess, ForbiddenError };
