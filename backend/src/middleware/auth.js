'use strict';
const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'k3-siem-secret';

const ROLE_ADMIN = 'admin';
const ROLE_T1 = 't1_analyst';
const ROLE_T2 = 't2_analyst';

function normalizeRole(role) {
  const r = String(role || '').trim().toLowerCase();
  if (r === 'soc_lead' || r === 'soclead' || r === 'tier2' || r === 't2') return ROLE_T2;
  if (r === 'analyst' || r === 'tier1' || r === 't1') return ROLE_T1;
  if (r === 'administrator') return ROLE_ADMIN;
  if (r === ROLE_ADMIN || r === ROLE_T1 || r === ROLE_T2) return r;
  return r || ROLE_T1;
}

function getUserRoles(user) {
  if (!user) return new Set();
  const roles = Array.isArray(user.roles) ? user.roles : (user.roles ? [user.roles] : []);
  if (user.role) roles.push(user.role);
  const out = new Set();
  for (const r of roles) {
    if (Array.isArray(r)) {
      for (const rr of r) out.add(normalizeRole(rr));
      continue;
    }
    const s = String(r || '').trim();
    if (!s) continue;
    if (s.startsWith('[')) {
      try {
        const parsed = JSON.parse(s);
        if (Array.isArray(parsed)) for (const rr of parsed) out.add(normalizeRole(rr));
        continue;
      } catch {}
    }
    for (const part of s.split(',').map(x => x.trim()).filter(Boolean)) out.add(normalizeRole(part));
  }
  return out;
}

function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(auth.slice(7), SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

function authorize(...roles) {
  const allowed = roles.flat().map(normalizeRole);
  return (req, res, next) => {
    const userRoles = getUserRoles(req.user);
    if (!allowed.some(r => userRoles.has(r))) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

module.exports = { authenticate, authorize, normalizeRole, ROLE_ADMIN, ROLE_T1, ROLE_T2, SECRET };
