'use strict';
/**
 * OCSF (Open Cybersecurity Schema Framework) auto-parser.
 *
 * Accepts a raw log of (almost) any shape — a Windows wevtutil JSON event,
 * a journald JSON line, a plain syslog/auth.log text line, CEF, or an
 * already-normalized K3 event object — and maps it onto the OCSF schema
 * (https://schema.ocsf.io), auto-detecting the source format and the most
 * fitting OCSF event class.
 *
 * This is intentionally schema-light (not a full code-generated OCSF SDK):
 * it produces a spec-shaped object with the fields analysts actually use
 * (class/category, activity, severity, status, actor, endpoints, observables,
 * raw_data) rather than every optional attribute in the spec.
 */

const OCSF_VERSION = '1.3.0';

const SEVERITY_ID = { Info: 1, Informational: 1, Low: 2, Medium: 3, High: 4, Critical: 5, Fatal: 6 };
const SEVERITY_NAME = { 0: 'Unknown', 1: 'Informational', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Critical', 6: 'Fatal', 99: 'Other' };

const STATUS_ID = { Success: 1, Failure: 2, Other: 99, Unknown: 0 };

const CLASSES = {
  AUTHENTICATION: { class_uid: 3002, class_name: 'Authentication', category_uid: 3, category_name: 'Identity & Access Management' },
  PROCESS: { class_uid: 1007, class_name: 'Process Activity', category_uid: 1, category_name: 'System Activity' },
  FILE: { class_uid: 1001, class_name: 'File System Activity', category_uid: 1, category_name: 'System Activity' },
  SCHEDULED_JOB: { class_uid: 1006, class_name: 'Scheduled Job Activity', category_uid: 1, category_name: 'System Activity' },
  NETWORK: { class_uid: 4001, class_name: 'Network Activity', category_uid: 4, category_name: 'Network Activity' },
  DNS: { class_uid: 4003, class_name: 'DNS Activity', category_uid: 4, category_name: 'Network Activity' },
  FINDING: { class_uid: 2001, class_name: 'Security Finding', category_uid: 2, category_name: 'Findings' },
  BASE: { class_uid: 0, class_name: 'Base Event', category_uid: 0, category_name: 'Uncategorized' },
};

const AUTH_ACTIVITY = { Logon: 1, Logoff: 2, 'Authentication Ticket': 3, Preauth: 6 };
const PROCESS_ACTIVITY = { Launch: 1, Terminate: 2, Open: 3 };

// Windows Security Event ID → OCSF hints
const WIN_AUTH_EVENT_IDS = { '4624': { activity: 'Logon', status: 'Success' }, '4625': { activity: 'Logon', status: 'Failure' }, '4634': { activity: 'Logoff', status: 'Success' }, '4648': { activity: 'Logon', status: 'Success' }, '4672': { activity: 'Logon', status: 'Success' }, '4776': { activity: 'Authentication Ticket', status: 'Success' } };
const WIN_PROCESS_EVENT_IDS = { '4688': 'Launch', '4689': 'Terminate' };
const WIN_NETWORK_EVENT_IDS = new Set(['5156']);
const WIN_SERVICE_EVENT_IDS = new Set(['4697', '7045']);

function severityFromString(sev) {
  return SEVERITY_ID[sev] ?? 0;
}

function tryParseJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

/**
 * Normalize arbitrary input (string or object) into a flat-ish working
 * record plus a guess at which "shape" it came from.
 */
function detectAndFlatten(input) {
  let obj = input;
  if (typeof input === 'string') {
    const trimmed = input.trim();
    const parsed = tryParseJson(trimmed);
    if (parsed) obj = parsed;
    else return flattenPlainText(trimmed);
  }

  if (obj && typeof obj === 'object') {
    // Windows wevtutil JSON: { Event: { System: {...}, EventData: {...} } }
    if (obj.Event && obj.Event.System) {
      return flattenWindowsEvent(obj);
    }
    // journald JSON line
    if (obj.__REALTIME_TIMESTAMP || obj.SYSLOG_IDENTIFIER || obj._HOSTNAME) {
      return flattenJournald(obj);
    }
    // Already-normalized K3 agent event: {timestamp, source, event_id, computer, username, ip_address, action, severity, raw, index}
    if (obj.action !== undefined || obj.source !== undefined) {
      return flattenK3Event(obj);
    }
    // Generic JSON object — best-effort field guessing
    return flattenGenericJson(obj);
  }

  return flattenPlainText(String(input ?? ''));
}

function flattenWindowsEvent(evt) {
  const sys = evt.Event.System || {};
  const data = evt.Event.EventData || {};
  const eid = String(sys.EventID?.['$'] ?? sys.EventID ?? '');
  return {
    shape: 'windows_event_log',
    timestamp: sys.TimeCreated?.['@SystemTime'] || new Date().toISOString(),
    source: 'Windows Security',
    event_id: eid,
    computer: sys.Computer || '',
    username: data.TargetUserName || data.SubjectUserName || '',
    ip_address: data.IpAddress || '',
    action: '',
    severity: 'Info',
    message: '',
    raw: JSON.stringify(evt),
  };
}

function flattenJournald(entry) {
  return {
    shape: 'journald',
    timestamp: entry.__REALTIME_TIMESTAMP
      ? new Date(parseInt(entry.__REALTIME_TIMESTAMP, 10) / 1000).toISOString()
      : new Date().toISOString(),
    source: 'Linux Syslog',
    event_id: entry.SYSLOG_IDENTIFIER || 'syslog',
    computer: entry._HOSTNAME || '',
    username: entry._UID || '',
    ip_address: '',
    action: entry.MESSAGE || '',
    severity: 'Info',
    message: entry.MESSAGE || '',
    raw: JSON.stringify(entry),
  };
}

function flattenK3Event(evt) {
  return {
    shape: 'k3_normalized',
    timestamp: evt.timestamp || new Date().toISOString(),
    source: evt.source || 'Unknown',
    event_id: String(evt.event_id ?? ''),
    computer: evt.computer || '',
    username: evt.username || '',
    ip_address: evt.ip_address || '',
    action: evt.action || '',
    severity: evt.severity || 'Info',
    message: evt.action || '',
    raw: typeof evt.raw === 'string' ? evt.raw : JSON.stringify(evt),
  };
}

function flattenGenericJson(obj) {
  return {
    shape: 'generic_json',
    timestamp: obj.timestamp || obj.time || obj['@timestamp'] || new Date().toISOString(),
    source: obj.source || obj.product || obj.vendor || 'Unknown',
    event_id: String(obj.event_id ?? obj.id ?? ''),
    computer: obj.hostname || obj.host || obj.computer || '',
    username: obj.user || obj.username || '',
    ip_address: obj.ip || obj.ip_address || obj.src_ip || '',
    action: obj.action || obj.message || obj.msg || '',
    severity: obj.severity || 'Info',
    message: obj.message || obj.msg || obj.action || '',
    raw: JSON.stringify(obj),
  };
}

const SYSLOG_LINE_RE = /^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w.\-/]+)(?:\[\d+\])?:\s*(.*)$/;

function flattenPlainText(text) {
  // CEF: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
  if (text.startsWith('CEF:')) {
    const parts = text.split('|');
    return {
      shape: 'cef',
      timestamp: new Date().toISOString(),
      source: parts[2] || 'CEF',
      event_id: parts[4] || '',
      computer: '',
      username: '',
      ip_address: (text.match(/\bsrc=(\S+)/) || [])[1] || '',
      action: parts[5] || text,
      severity: cefSeverityToName(parts[6]),
      message: text,
      raw: text,
    };
  }

  const m = text.match(SYSLOG_LINE_RE);
  if (m) {
    const [, ts, host, proc, msg] = m;
    return {
      shape: 'syslog_text',
      timestamp: new Date().toISOString(),
      source: proc.includes('sshd') || proc.includes('sudo') || proc.includes('login') ? 'Linux Auth' : 'Linux Syslog',
      event_id: proc,
      computer: host,
      username: (msg.match(/for (?:invalid user )?(\S+)/) || [])[1] || '',
      ip_address: (msg.match(/from (\d+\.\d+\.\d+\.\d+)/) || [])[1] || '',
      action: msg,
      severity: msg.match(/fail|invalid|deny|denied/i) ? 'High' : 'Info',
      message: msg,
      raw: text,
    };
  }

  return {
    shape: 'raw_text',
    timestamp: new Date().toISOString(),
    source: 'Unknown',
    event_id: '',
    computer: '',
    username: '',
    ip_address: (text.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/) || [])[1] || '',
    action: text,
    severity: 'Info',
    message: text,
    raw: text,
  };
}

function cefSeverityToName(cefSev) {
  const n = parseInt(cefSev, 10);
  if (Number.isNaN(n)) return 'Info';
  if (n >= 9) return 'Critical';
  if (n >= 7) return 'High';
  if (n >= 4) return 'Medium';
  if (n >= 1) return 'Low';
  return 'Info';
}

/** Pick the best-fitting OCSF class + activity for a flattened record. */
function classifyRecord(rec) {
  const action = (rec.action || '').toLowerCase();
  const eid = rec.event_id || '';

  if (WIN_AUTH_EVENT_IDS[eid]) {
    const h = WIN_AUTH_EVENT_IDS[eid];
    return { ...CLASSES.AUTHENTICATION, activity_name: h.activity, activity_id: AUTH_ACTIVITY[h.activity] || 99, status: h.status };
  }
  if (WIN_PROCESS_EVENT_IDS[eid]) {
    const a = WIN_PROCESS_EVENT_IDS[eid];
    return { ...CLASSES.PROCESS, activity_name: a, activity_id: PROCESS_ACTIVITY[a] || 99, status: 'Success' };
  }
  if (WIN_NETWORK_EVENT_IDS.has(eid)) {
    return { ...CLASSES.NETWORK, activity_name: 'Traffic', activity_id: 6, status: 'Success' };
  }
  if (WIN_SERVICE_EVENT_IDS.has(eid)) {
    return { ...CLASSES.SCHEDULED_JOB, activity_name: 'Create', activity_id: 1, status: 'Success' };
  }

  if (rec.source === 'Linux Auth' || /logon|login|logoff|logout|signed? ?in|password|publickey|authentication failure/.test(action)) {
    const failed = /fail|invalid|denied|deny/.test(action);
    const isLogoff = /logoff|logout/.test(action);
    return { ...CLASSES.AUTHENTICATION, activity_name: isLogoff ? 'Logoff' : 'Logon', activity_id: isLogoff ? 2 : 1, status: failed ? 'Failure' : 'Success' };
  }
  if (/sudo|privilege/.test(action)) {
    return { ...CLASSES.AUTHENTICATION, activity_name: 'Authentication Ticket', activity_id: 3, status: 'Success' };
  }
  if (/process (create|exit|launch|start)/.test(action)) {
    return { ...CLASSES.PROCESS, activity_name: /exit/.test(action) ? 'Terminate' : 'Launch', activity_id: /exit/.test(action) ? 2 : 1, status: 'Success' };
  }
  if (/package install|service (install|restart)|cron|systemd|scheduled/.test(action)) {
    return { ...CLASSES.SCHEDULED_JOB, activity_name: 'Create', activity_id: 1, status: 'Success' };
  }
  if (/dns query/.test(action)) {
    return { ...CLASSES.DNS, activity_name: 'Query', activity_id: 1, status: 'Success' };
  }
  if (/traffic|network connect|port scan|vpn|ddos|threat blocked/.test(action)) {
    const finding = /scan|ddos|threat|ids alert/.test(action);
    if (finding) return { ...CLASSES.FINDING, activity_name: 'Create', activity_id: 1, status: 'Success' };
    return { ...CLASSES.NETWORK, activity_name: /deny|block/.test(action) ? 'Deny' : 'Allow', activity_id: /deny|block/.test(action) ? 2 : 1, status: 'Success' };
  }
  if (/file (access|modif|creat|delet)/.test(action)) {
    return { ...CLASSES.FILE, activity_name: 'Read', activity_id: 1, status: 'Success' };
  }
  if (/audit log clear/.test(action)) {
    return { ...CLASSES.FINDING, activity_name: 'Create', activity_id: 1, status: 'Success' };
  }

  return { ...CLASSES.BASE, activity_name: 'Unknown', activity_id: 0, status: 'Unknown' };
}

function buildObservables(rec) {
  const obs = [];
  if (rec.ip_address) obs.push({ name: 'src_endpoint.ip', type: 'IP Address', value: rec.ip_address });
  if (rec.username) obs.push({ name: 'actor.user.name', type: 'User Name', value: rec.username });
  if (rec.computer) obs.push({ name: 'device.hostname', type: 'Hostname', value: rec.computer });
  return obs;
}

/**
 * Parse any raw log (string or object) into an OCSF-shaped event.
 * @param {string|object} input
 * @returns {object} OCSF event
 */
function parseToOCSF(input) {
  const rec = detectAndFlatten(input);
  const cls = classifyRecord(rec);
  const severityId = severityFromString(rec.severity);
  const statusId = STATUS_ID[cls.status] ?? 0;
  const timeMs = Date.parse(rec.timestamp) || Date.now();
  const typeUid = cls.class_uid * 100 + (cls.activity_id || 0);

  return {
    activity_id: cls.activity_id,
    activity_name: cls.activity_name,
    category_uid: cls.category_uid,
    category_name: cls.category_name,
    class_uid: cls.class_uid,
    class_name: cls.class_name,
    type_uid: typeUid,
    type_name: `${cls.class_name}: ${cls.activity_name}`,
    time: timeMs,
    time_iso: new Date(timeMs).toISOString(),
    severity_id: severityId,
    severity: SEVERITY_NAME[severityId],
    status_id: statusId,
    status: cls.status || 'Unknown',
    message: rec.message || rec.action || '',
    metadata: {
      version: OCSF_VERSION,
      product: { name: 'K3 SIEM Agent', vendor_name: 'K3' },
      log_name: rec.source,
      original_format: rec.shape,
    },
    actor: rec.username ? { user: { name: rec.username } } : undefined,
    src_endpoint: (rec.ip_address || rec.computer) ? { ip: rec.ip_address || undefined, hostname: rec.computer || undefined } : undefined,
    device: rec.computer ? { hostname: rec.computer } : undefined,
    observables: buildObservables(rec),
    raw_data: rec.raw,
    unmapped: { source: rec.source, event_id: rec.event_id },
  };
}

const OCSF_CLASS_REFERENCE = Object.values(CLASSES).map(c => ({
  class_uid: c.class_uid, class_name: c.class_name, category_uid: c.category_uid, category_name: c.category_name,
}));

module.exports = { parseToOCSF, OCSF_VERSION, OCSF_CLASS_REFERENCE };
