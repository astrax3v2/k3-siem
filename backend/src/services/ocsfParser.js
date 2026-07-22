'use strict';

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

const WIN_AUTH_EVENT_IDS = {
  '4624': { activity: 'Logon', status: 'Success' },
  '4625': { activity: 'Logon', status: 'Failure' },
  '4634': { activity: 'Logoff', status: 'Success' },
  '4648': { activity: 'Logon', status: 'Success' },
  '4672': { activity: 'Logon', status: 'Success' },
  '4776': { activity: 'Authentication Ticket', status: 'Success' },
};
const WIN_PROCESS_EVENT_IDS = { '4688': 'Launch', '4689': 'Terminate' };
const WIN_NETWORK_EVENT_IDS = new Set(['5156']);
const WIN_SERVICE_EVENT_IDS = new Set(['4697', '7045']);

const PROFILE_CATALOG = [
  { id: 'windows_evtx_json', title: 'Windows Event Log', family: 'windows', vendor: 'Microsoft', product: 'Windows Security Event Log', device_type: 'endpoint_os', formats: ['wevtutil-json', 'event-json'], description: 'Windows Security events, including logon, privilege, process, and firewall telemetry.' },
  { id: 'linux_journald_json', title: 'Linux Journald', family: 'linux', vendor: 'Linux', product: 'journald', device_type: 'server_os', formats: ['journald-json'], description: 'Structured Linux systemd/journald records.' },
  { id: 'linux_syslog_auth', title: 'Linux Syslog/Auth', family: 'linux', vendor: 'Linux', product: 'Syslog', device_type: 'server_os', formats: ['syslog'], description: 'Linux syslog and auth.log events such as SSH, sudo, login, and service activity.' },
  { id: 'aix_syslog', title: 'IBM AIX Syslog', family: 'aix', vendor: 'IBM', product: 'AIX Syslog', device_type: 'unix_os', formats: ['syslog'], description: 'AIX auth, cron, and operating-system syslog events.' },
  { id: 'cisco_asa_syslog', title: 'Cisco ASA Firewall', family: 'firewall', vendor: 'Cisco', product: 'ASA Firewall', device_type: 'firewall', formats: ['syslog'], description: 'Cisco ASA and related syslog patterns such as connection build, deny, and teardown.' },
  { id: 'cisco_cef', title: 'Cisco CEF', family: 'firewall', vendor: 'Cisco', product: 'CEF Device', device_type: 'network_security', formats: ['cef'], description: 'Cisco device events emitted in CEF format.' },
  { id: 'paloalto_cef', title: 'Palo Alto PAN-OS (CEF)', family: 'firewall', vendor: 'Palo Alto Networks', product: 'PAN-OS', device_type: 'firewall', formats: ['cef'], description: 'Palo Alto firewall and threat events wrapped in CEF.' },
  { id: 'paloalto_syslog_csv', title: 'Palo Alto PAN-OS Syslog', family: 'firewall', vendor: 'Palo Alto Networks', product: 'PAN-OS', device_type: 'firewall', formats: ['csv-syslog'], description: 'Native Palo Alto TRAFFIC, THREAT, SYSTEM, and CONFIG syslog feeds.' },
  { id: 'fortigate_kv', title: 'Fortinet FortiGate', family: 'firewall', vendor: 'Fortinet', product: 'FortiGate', device_type: 'firewall', formats: ['key-value', 'syslog'], description: 'FortiGate traffic, utm, and event logs using key-value pairs.' },
  { id: 'modsecurity_waf', title: 'ModSecurity WAF', family: 'waf', vendor: 'OWASP', product: 'ModSecurity', device_type: 'waf', formats: ['syslog', 'text'], description: 'ModSecurity and CRS WAF findings including blocks, SQLi, XSS, and anomaly scores.' },
  { id: 'aws_waf_json', title: 'AWS WAF', family: 'waf', vendor: 'Amazon Web Services', product: 'AWS WAF', device_type: 'waf', formats: ['json'], description: 'AWS WAF rule, action, and request telemetry.' },
  { id: 'email_postfix', title: 'Postfix Email', family: 'email', vendor: 'Postfix', product: 'Postfix', device_type: 'mail_server', formats: ['syslog'], description: 'Email delivery, rejection, and relay events from Postfix and similar MTAs.' },
  { id: 'exchange_email_json', title: 'Exchange / M365 Email', family: 'email', vendor: 'Microsoft', product: 'Exchange', device_type: 'mail_service', formats: ['json'], description: 'Structured email activity from Microsoft Exchange and M365 mail workloads.' },
  { id: 'email_security_gateway_cef', title: 'Email Security Gateway', family: 'email_security_gateway', vendor: 'Email Security Vendor', product: 'Secure Email Gateway', device_type: 'email_gateway', formats: ['cef', 'syslog'], description: 'Proofpoint, Mimecast, Cisco ESA, and similar secure email gateway telemetry.' },
  { id: 'generic_cef', title: 'Generic CEF', family: 'generic_network', vendor: 'Generic', product: 'CEF Device', device_type: 'security_device', formats: ['cef'], description: 'Fallback for security tools that emit CEF but do not match a more specific profile.' },
  { id: 'generic_json', title: 'Generic JSON', family: 'generic', vendor: 'Generic', product: 'JSON Log', device_type: 'generic', formats: ['json'], description: 'Best-effort mapping for arbitrary JSON logs.' },
  { id: 'raw_text', title: 'Raw Text Fallback', family: 'generic', vendor: 'Generic', product: 'Raw Text Log', device_type: 'generic', formats: ['text'], description: 'Catch-all parser for unstructured raw text lines.' },
];

const PROFILE_MAP = new Map(PROFILE_CATALOG.map((profile) => [profile.id, profile]));

function tryParseJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

function unquote(value) {
  if (typeof value !== 'string') return value;
  return value.replace(/^"(.*)"$/, '$1');
}

function splitEscaped(input, delimiter, limit) {
  const out = [];
  let current = '';
  let escaped = false;
  for (const ch of input) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (ch === delimiter && (!limit || out.length < limit - 1)) {
      out.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  out.push(current);
  return out;
}

function parseCef(text) {
  if (!text.startsWith('CEF:')) return null;
  const parts = splitEscaped(text, '|', 8);
  if (parts.length < 8) return null;
  const [version, vendor, product, deviceVersion, signatureId, name, severity, extension] = parts;
  const kv = {};
  const extText = extension || '';
  const re = /([A-Za-z0-9_.-]+)=((?:"[^"]*")|(?:[^\s]+))/g;
  let match;
  while ((match = re.exec(extText)) !== null) {
    kv[match[1]] = unquote(match[2]);
  }
  return {
    version,
    vendor,
    product,
    deviceVersion,
    signatureId,
    name,
    severity,
    extension: extText,
    kv,
  };
}

function parseKeyValuePairs(text) {
  const kv = {};
  const re = /([A-Za-z0-9_.-]+)=((?:"(?:[^"\\]|\\.)*")|(?:[^\s]+))/g;
  let match;
  while ((match = re.exec(text)) !== null) kv[match[1]] = unquote(match[2]);
  return kv;
}

function parseSyslogEnvelope(text) {
  const match = text.match(/^(?:<\d+>)?([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|[0-9T:+.\-Z/ ]+)\s+(\S+)\s+([^:]+):\s*(.*)$/);
  if (!match) return null;
  const programRaw = match[3].trim();
  const program = programRaw.replace(/\[\d+\]$/, '');
  return {
    timestampToken: match[1].trim(),
    host: match[2].trim(),
    program,
    programRaw,
    message: match[4].trim(),
  };
}

function normalizeTimestamp(value) {
  if (!value) return new Date().toISOString();
  const str = String(value).trim();
  if (!str) return new Date().toISOString();
  let parsed = Date.parse(str);
  if (!Number.isNaN(parsed)) return new Date(parsed).toISOString();

  const syslogParsed = Date.parse(`${str} ${new Date().getUTCFullYear()} UTC`);
  if (!Number.isNaN(syslogParsed)) return new Date(syslogParsed).toISOString();

  const slashParsed = Date.parse(str.replace(/^(\d{4})\/(\d{2})\/(\d{2})/, '$1-$2-$3'));
  if (!Number.isNaN(slashParsed)) return new Date(slashParsed).toISOString();

  return new Date().toISOString();
}

function firstNonEmpty(...values) {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    const text = String(value).trim();
    if (text) return text;
  }
  return '';
}

function pickIp(text) {
  return (String(text || '').match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/) || [])[1] || '';
}

function pickIps(text) {
  return String(text || '').match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
}

function detectOutcome(text, fallback = 'Unknown') {
  const t = String(text || '').toLowerCase();
  if (/fail|failed|deny|denied|drop|dropped|block|blocked|reject|rejected|quarantine|malware|phish|virus|attack/.test(t)) return 'Failure';
  if (/allow|allowed|accept|accepted|success|succeeded|delivered|connected|permitted/.test(t)) return 'Success';
  return fallback;
}

function normalizeSeverity(input, fallback = 'Info') {
  if (input === undefined || input === null || input === '') return fallback;
  if (typeof input === 'number') {
    if (input >= 9) return 'Critical';
    if (input >= 7) return 'High';
    if (input >= 4) return 'Medium';
    if (input >= 1) return 'Low';
    return 'Info';
  }
  const text = String(input).trim();
  const lowered = text.toLowerCase();
  const named = {
    info: 'Info',
    informational: 'Info',
    debug: 'Info',
    notice: 'Low',
    low: 'Low',
    medium: 'Medium',
    med: 'Medium',
    warning: 'Medium',
    warn: 'Medium',
    high: 'High',
    error: 'High',
    critical: 'Critical',
    crit: 'Critical',
    alert: 'Critical',
    emergency: 'Critical',
    emerg: 'Critical',
    fatal: 'Fatal',
  };
  if (named[lowered]) return named[lowered];
  const numeric = parseInt(text, 10);
  if (!Number.isNaN(numeric)) return normalizeSeverity(numeric, fallback);
  return fallback;
}

function ciscoSeverityName(code) {
  const num = parseInt(code, 10);
  if (Number.isNaN(num)) return 'Info';
  if (num <= 2) return 'Critical';
  if (num === 3) return 'High';
  if (num === 4) return 'Medium';
  if (num === 5) return 'Low';
  return 'Info';
}

function inferIndexName(family) {
  switch (family) {
    case 'windows':
      return 'windows-security';
    case 'linux':
    case 'aix':
      return 'linux-syslog';
    case 'firewall':
    case 'waf':
    case 'generic_network':
      return 'network-flow';
    case 'email':
    case 'email_security_gateway':
      return 'email-security';
    default:
      return 'default';
  }
}

function buildContext(input) {
  const original = input;
  const json = input && typeof input === 'object' ? input : tryParseJson(String(input || '').trim());
  const rawText = typeof input === 'string'
    ? input.trim()
    : json ? JSON.stringify(json) : String(input ?? '');
  const embeddedRawText = json && typeof json.raw === 'string' ? json.raw.trim() : '';
  const text = embeddedRawText || rawText;
  return { original, json, rawText, embeddedRawText, text };
}

function finalizeRecord(record, profileId) {
  const profile = PROFILE_MAP.get(profileId) || PROFILE_MAP.get('raw_text');
  const timestamp = normalizeTimestamp(record.timestamp);
  const parser = {
    profile_id: profile.id,
    profile_name: profile.title,
    family: profile.family,
    vendor: profile.vendor,
    product: profile.product,
    device_type: profile.device_type,
    format: Array.isArray(profile.formats) ? profile.formats.join(', ') : String(profile.formats || ''),
  };
  return {
    shape: record.shape || profile.id,
    timestamp,
    source: record.source || `${profile.vendor} ${profile.product}`,
    event_id: record.event_id != null ? String(record.event_id) : '',
    computer: record.computer || '',
    username: record.username || '',
    ip_address: record.ip_address || '',
    dst_ip_address: record.dst_ip_address || '',
    action: record.action || record.message || '',
    severity: normalizeSeverity(record.severity, 'Info'),
    message: record.message || record.action || '',
    outcome: record.outcome || detectOutcome(`${record.action || ''} ${record.message || ''}`),
    raw: record.raw || (typeof record === 'string' ? record : JSON.stringify(record)),
    index_name: record.index_name || inferIndexName(profile.family),
    parser,
    additional: record.additional || {},
  };
}

function normalizeWindowsEvent(obj) {
  const sys = obj.Event.System || {};
  const data = obj.Event.EventData || {};
  const eid = String(sys.EventID?.['$'] ?? sys.EventID ?? '');
  const actionHints = {
    '4624': 'Successful logon',
    '4625': 'Failed logon',
    '4634': 'Logoff',
    '4688': firstNonEmpty(data.NewProcessName, data.ProcessName, 'Process create'),
    '5156': 'Windows Filtering Platform allowed connection',
    '7045': firstNonEmpty(data.ServiceName, 'Service installed'),
  };
  return finalizeRecord({
    shape: 'windows_event_log',
    timestamp: sys.TimeCreated?.['@SystemTime'],
    source: 'Microsoft Windows Security',
    event_id: eid,
    computer: sys.Computer || '',
    username: firstNonEmpty(data.TargetUserName, data.SubjectUserName, data.AccountName),
    ip_address: firstNonEmpty(data.IpAddress, data.SourceAddress),
    dst_ip_address: firstNonEmpty(data.DestinationAddress),
    action: actionHints[eid] || firstNonEmpty(data.ProcessName, data.ServiceName, sys.Provider?.['@Name'], 'Windows event'),
    severity: eid === '4625' ? 'High' : eid === '7045' ? 'High' : 'Info',
    message: firstNonEmpty(data.CommandLine, data.ParentProcessName, actionHints[eid], `Windows event ${eid}`),
    outcome: WIN_AUTH_EVENT_IDS[eid]?.status || 'Success',
    raw: JSON.stringify(obj),
  }, 'windows_evtx_json');
}

function normalizeJournald(obj) {
  const msg = obj.MESSAGE || '';
  return finalizeRecord({
    shape: 'journald_json',
    timestamp: obj.__REALTIME_TIMESTAMP ? new Date(parseInt(obj.__REALTIME_TIMESTAMP, 10) / 1000).toISOString() : obj.timestamp,
    source: 'Linux journald',
    event_id: firstNonEmpty(obj.SYSLOG_IDENTIFIER, obj._SYSTEMD_UNIT, 'journald'),
    computer: obj._HOSTNAME || '',
    username: firstNonEmpty(obj.USER, obj._UID),
    ip_address: pickIp(msg),
    action: msg,
    severity: /fail|error|denied/i.test(msg) ? 'High' : 'Info',
    message: msg,
    raw: JSON.stringify(obj),
  }, 'linux_journald_json');
}

function normalizeCiscoAsa(text) {
  const env = parseSyslogEnvelope(text);
  const message = env ? env.message : text;
  const sevCode = (message.match(/%ASA-(\d)-/) || [])[1];
  const eventId = (message.match(/%ASA-\d-(\d+)/) || [])[1] || 'asa';
  const ips = pickIps(message);
  return finalizeRecord({
    shape: 'cisco_asa_syslog',
    timestamp: env?.timestampToken,
    source: 'Cisco ASA Firewall',
    event_id: eventId,
    computer: env?.host || '',
    username: (message.match(/user\s+("?[\w.\-@\\\/]+"?)/i) || [])[1] || '',
    ip_address: ips[0] || '',
    dst_ip_address: ips[1] || '',
    action: message.replace(/^%ASA-\d-\d+:\s*/, ''),
    severity: ciscoSeverityName(sevCode),
    message,
    outcome: detectOutcome(message),
    raw: text,
  }, 'cisco_asa_syslog');
}

function normalizeFortiGate(text) {
  const kv = parseKeyValuePairs(text);
  const action = [kv.type, kv.subtype, kv.action].filter(Boolean).join(' / ');
  return finalizeRecord({
    shape: 'fortigate_kv',
    timestamp: firstNonEmpty(kv.eventtime, `${kv.date || ''} ${kv.time || ''}`.trim(), kv.timestamp),
    source: firstNonEmpty(kv.devname, 'Fortinet FortiGate'),
    event_id: firstNonEmpty(kv.logid, kv.eventid, kv.subtype),
    computer: firstNonEmpty(kv.devname, kv.devid),
    username: firstNonEmpty(kv.user, kv.srcuser, kv.dstuser),
    ip_address: firstNonEmpty(kv.srcip, kv.src),
    dst_ip_address: firstNonEmpty(kv.dstip, kv.dst),
    action: action || 'FortiGate event',
    severity: normalizeSeverity(firstNonEmpty(kv.level, kv.severity), 'Medium'),
    message: firstNonEmpty(kv.msg, text),
    outcome: detectOutcome(firstNonEmpty(kv.action, kv.status, kv.msg)),
    raw: text,
  }, 'fortigate_kv');
}

function normalizePaloAltoCef(text, cef) {
  const action = firstNonEmpty(cef.kv.act, cef.name, cef.kv.rule, cef.kv.subtype);
  return finalizeRecord({
    shape: 'cef',
    timestamp: firstNonEmpty(cef.kv.rt, cef.kv.receive_time),
    source: 'Palo Alto PAN-OS',
    event_id: firstNonEmpty(cef.signatureId, cef.kv.subtype, 'pan-os'),
    computer: firstNonEmpty(cef.kv.dvchost, cef.kv.dhost),
    username: firstNonEmpty(cef.kv.suser, cef.kv.duser, cef.kv.cn1Label === 'user' ? cef.kv.cn1 : ''),
    ip_address: firstNonEmpty(cef.kv.src, cef.kv.sourceAddress),
    dst_ip_address: firstNonEmpty(cef.kv.dst, cef.kv.destinationAddress),
    action,
    severity: normalizeSeverity(cef.severity, 'Medium'),
    message: cef.name || text,
    outcome: detectOutcome(action || cef.name),
    raw: text,
  }, 'paloalto_cef');
}

function normalizeCiscoCef(text, cef) {
  const action = firstNonEmpty(cef.kv.act, cef.name, cef.kv.cs1, cef.kv.msg);
  return finalizeRecord({
    shape: 'cef',
    timestamp: firstNonEmpty(cef.kv.rt, cef.kv.end),
    source: `Cisco ${firstNonEmpty(cef.product, 'CEF Device')}`,
    event_id: firstNonEmpty(cef.signatureId, cef.kv.rule, 'cisco-cef'),
    computer: firstNonEmpty(cef.kv.dvchost, cef.kv.dhost),
    username: firstNonEmpty(cef.kv.suser, cef.kv.duser),
    ip_address: firstNonEmpty(cef.kv.src, cef.kv.sourceAddress),
    dst_ip_address: firstNonEmpty(cef.kv.dst, cef.kv.destinationAddress),
    action,
    severity: normalizeSeverity(cef.severity, 'Medium'),
    message: cef.name || text,
    outcome: detectOutcome(action || cef.name),
    raw: text,
  }, 'cisco_cef');
}

function normalizeEmailGateway(text, cef) {
  const action = firstNonEmpty(cef?.kv?.act, cef?.name, 'Email security event');
  return finalizeRecord({
    shape: cef ? 'cef' : 'syslog_text',
    timestamp: firstNonEmpty(cef?.kv?.rt, parseSyslogEnvelope(text)?.timestampToken),
    source: firstNonEmpty(`${cef?.vendor || ''} ${cef?.product || ''}`.trim(), 'Secure Email Gateway'),
    event_id: firstNonEmpty(cef?.signatureId, 'email-gateway'),
    computer: firstNonEmpty(cef?.kv?.dvchost, parseSyslogEnvelope(text)?.host),
    username: firstNonEmpty(cef?.kv?.suser, cef?.kv?.duser, (text.match(/recipient[=:]\s*([^\s,]+)/i) || [])[1]),
    ip_address: firstNonEmpty(cef?.kv?.src, pickIp(text)),
    dst_ip_address: firstNonEmpty(cef?.kv?.dst),
    action,
    severity: normalizeSeverity(cef?.severity || (/spam|malware|phish|virus|quarantine/i.test(text) ? 'High' : 'Medium'), 'Medium'),
    message: cef?.name || text,
    outcome: detectOutcome(action || text),
    raw: text,
  }, 'email_security_gateway_cef');
}

function normalizePaloAltoCsv(text) {
  const tokens = text.split(',').map((token) => token.trim());
  const type = tokens.find((token) => /^(TRAFFIC|THREAT|SYSTEM|CONFIG)$/i.test(token)) || 'TRAFFIC';
  const subtypeIdx = tokens.indexOf(type) + 1;
  const subtype = subtypeIdx > 0 ? tokens[subtypeIdx] : '';
  const timestamp = tokens.find((token) => /^\d{4}\/\d{2}\/\d{2} /.test(token));
  const ips = pickIps(text);
  const actionToken = tokens.find((token) => /^(allow|deny|drop|reset-|alert|block)/i.test(token));
  return finalizeRecord({
    shape: 'paloalto_csv',
    timestamp,
    source: 'Palo Alto PAN-OS',
    event_id: firstNonEmpty(subtype, type),
    computer: firstNonEmpty(tokens[2], ''),
    username: firstNonEmpty(tokens.find((token) => /@/.test(token)), ''),
    ip_address: ips[0] || '',
    dst_ip_address: ips[1] || '',
    action: [type, subtype, actionToken].filter(Boolean).join(' / '),
    severity: /THREAT|deny|drop|block/i.test(`${type} ${subtype} ${actionToken || ''}`) ? 'High' : 'Medium',
    message: text,
    outcome: detectOutcome(actionToken || type),
    raw: text,
  }, 'paloalto_syslog_csv');
}

function normalizeLinuxSyslog(text) {
  const env = parseSyslogEnvelope(text);
  const message = env ? env.message : text;
  return finalizeRecord({
    shape: 'syslog_text',
    timestamp: env?.timestampToken,
    source: env?.program && /sshd|sudo|login|su|cron|systemd/i.test(env.program) ? 'Linux Auth' : 'Linux Syslog',
    event_id: env?.program || 'syslog',
    computer: env?.host || '',
    username: (message.match(/for (?:invalid user )?(\S+)/) || message.match(/user(?:name)?[=:]\s*([^\s,]+)/i) || [])[1] || '',
    ip_address: pickIp(message),
    action: message,
    severity: /fail|invalid|deny|error/i.test(message) ? 'High' : 'Info',
    message,
    outcome: detectOutcome(message),
    raw: text,
  }, 'linux_syslog_auth');
}

function normalizeAixSyslog(text, hintedJson = null) {
  const env = parseSyslogEnvelope(text);
  const message = env ? env.message : text;
  return finalizeRecord({
    shape: 'syslog_text',
    timestamp: firstNonEmpty(hintedJson?.timestamp, env?.timestampToken),
    source: 'IBM AIX Syslog',
    event_id: firstNonEmpty(env?.program, hintedJson?.event_id, 'aix'),
    computer: firstNonEmpty(hintedJson?.host, hintedJson?.computer, env?.host),
    username: firstNonEmpty(hintedJson?.user, (message.match(/for user\s+([^\s,]+)/i) || [])[1]),
    ip_address: firstNonEmpty(hintedJson?.ip, hintedJson?.src_ip, pickIp(message)),
    action: firstNonEmpty(hintedJson?.action, message),
    severity: normalizeSeverity(hintedJson?.severity || (/fail|denied|error/i.test(message) ? 'High' : 'Info'), 'Info'),
    message,
    outcome: detectOutcome(message),
    raw: text,
  }, 'aix_syslog');
}

function normalizeModSecurity(text) {
  const env = parseSyslogEnvelope(text);
  const message = env ? env.message : text;
  return finalizeRecord({
    shape: 'waf_text',
    timestamp: env?.timestampToken,
    source: 'OWASP ModSecurity WAF',
    event_id: (message.match(/\[id "?(\d+)"?\]/i) || [])[1] || 'modsecurity',
    computer: env?.host || '',
    username: '',
    ip_address: (message.match(/\[client (\d+\.\d+\.\d+\.\d+)\]/i) || [])[1] || pickIp(message),
    action: /access denied/i.test(message) ? 'Blocked web request' : 'WAF event',
    severity: /sql|xss|rce|scanner|attack|denied/i.test(message) ? 'High' : 'Medium',
    message,
    outcome: 'Failure',
    raw: text,
  }, 'modsecurity_waf');
}

function normalizeAwsWaf(obj) {
  return finalizeRecord({
    shape: 'aws_waf_json',
    timestamp: firstNonEmpty(obj.timestamp, obj['@timestamp']),
    source: 'AWS WAF',
    event_id: firstNonEmpty(obj.terminatingRuleId, obj.ruleGroupId, 'aws-waf'),
    computer: firstNonEmpty(obj.webaclId, obj.httpSourceName),
    username: firstNonEmpty(obj.user, obj.username),
    ip_address: firstNonEmpty(obj.httpRequest?.clientIp, obj.clientIp),
    dst_ip_address: '',
    action: firstNonEmpty(obj.action, obj.httpSourceId, 'WAF request'),
    severity: /block/i.test(obj.action || '') ? 'High' : 'Medium',
    message: firstNonEmpty(obj.terminatingRuleId, obj.action, 'AWS WAF event'),
    outcome: detectOutcome(obj.action),
    raw: JSON.stringify(obj),
  }, 'aws_waf_json');
}

function normalizePostfix(text) {
  const env = parseSyslogEnvelope(text);
  const message = env ? env.message : text;
  return finalizeRecord({
    shape: 'email_syslog',
    timestamp: env?.timestampToken,
    source: 'Postfix Mail Server',
    event_id: (message.match(/^([A-F0-9]+):/) || [])[1] || env?.program || 'postfix',
    computer: env?.host || '',
    username: (message.match(/to=<([^>]+)>/) || message.match(/from=<([^>]+)>/) || [])[1] || '',
    ip_address: pickIp(message),
    action: /reject|deferred|warning|bounced/i.test(message) ? 'Email rejected' : /status=sent/i.test(message) ? 'Email delivered' : 'Email event',
    severity: /reject|bounce|virus|spam/i.test(message) ? 'High' : 'Info',
    message,
    outcome: detectOutcome(message),
    raw: text,
  }, 'email_postfix');
}

function normalizeExchangeJson(obj) {
  const action = firstNonEmpty(obj.action, obj.operation, obj.eventName, 'Email activity');
  return finalizeRecord({
    shape: 'email_json',
    timestamp: firstNonEmpty(obj.timestamp, obj.time, obj.CreationTime, obj['@timestamp']),
    source: firstNonEmpty(obj.source, obj.workload, 'Microsoft Exchange'),
    event_id: firstNonEmpty(obj.event_id, obj.Id, obj.Operation, 'exchange'),
    computer: firstNonEmpty(obj.server, obj.host, obj.ClientIP),
    username: firstNonEmpty(obj.user, obj.UserId, obj.MailboxOwnerUPN, obj.sender, obj.recipient),
    ip_address: firstNonEmpty(obj.ip, obj.ip_address, obj.ClientIP),
    dst_ip_address: '',
    action,
    severity: /malware|phish|spam|blocked|quarantine/i.test(`${action} ${obj.verdict || ''} ${obj.threat || ''}`) ? 'High' : 'Info',
    message: firstNonEmpty(obj.subject, obj.verdict, obj.message, action),
    outcome: detectOutcome(`${action} ${obj.verdict || ''} ${obj.status || ''}`),
    raw: JSON.stringify(obj),
  }, 'exchange_email_json');
}

function normalizeGenericCef(text, cef) {
  return finalizeRecord({
    shape: 'cef',
    timestamp: firstNonEmpty(cef.kv.rt, cef.kv.end),
    source: firstNonEmpty(`${cef.vendor} ${cef.product}`.trim(), 'CEF Device'),
    event_id: firstNonEmpty(cef.signatureId, cef.name),
    computer: firstNonEmpty(cef.kv.dvchost, cef.kv.dhost),
    username: firstNonEmpty(cef.kv.suser, cef.kv.duser),
    ip_address: firstNonEmpty(cef.kv.src, cef.kv.sourceAddress),
    dst_ip_address: firstNonEmpty(cef.kv.dst, cef.kv.destinationAddress),
    action: firstNonEmpty(cef.kv.act, cef.name, text),
    severity: normalizeSeverity(cef.severity, 'Medium'),
    message: cef.name || text,
    outcome: detectOutcome(`${cef.kv.act || ''} ${cef.name || ''}`),
    raw: text,
  }, 'generic_cef');
}

function normalizeGenericJson(obj) {
  const source = firstNonEmpty(obj.source, obj.product, obj.vendor, obj.device_type, 'Generic JSON Log');
  return finalizeRecord({
    shape: 'generic_json',
    timestamp: firstNonEmpty(obj.timestamp, obj.time, obj['@timestamp']),
    source,
    event_id: firstNonEmpty(obj.event_id, obj.id, obj.logid, obj.operation),
    computer: firstNonEmpty(obj.hostname, obj.host, obj.computer, obj.device),
    username: firstNonEmpty(obj.user, obj.username, obj.account, obj.sender, obj.recipient),
    ip_address: firstNonEmpty(obj.ip, obj.ip_address, obj.src_ip, obj.client_ip),
    dst_ip_address: firstNonEmpty(obj.dst_ip, obj.destination_ip),
    action: firstNonEmpty(obj.action, obj.message, obj.msg, obj.operation, source),
    severity: normalizeSeverity(obj.severity, 'Info'),
    message: firstNonEmpty(obj.message, obj.msg, obj.description, obj.action),
    outcome: detectOutcome(`${obj.action || ''} ${obj.status || ''} ${obj.verdict || ''}`),
    raw: JSON.stringify(obj),
    additional: { vendor: obj.vendor, product: obj.product },
  }, 'generic_json');
}

function normalizeK3Event(obj) {
  const source = firstNonEmpty(obj.source, obj.product, obj.vendor, 'K3 Normalized Event');
  return finalizeRecord({
    shape: 'k3_normalized',
    timestamp: obj.timestamp,
    source,
    event_id: obj.event_id,
    computer: obj.computer,
    username: obj.username,
    ip_address: obj.ip_address || obj.src_ip,
    dst_ip_address: obj.dst_ip,
    action: obj.action,
    severity: obj.severity || 'Info',
    message: firstNonEmpty(obj.message, obj.action),
    outcome: detectOutcome(`${obj.action || ''} ${obj.message || ''}`),
    raw: typeof obj.raw === 'string' ? obj.raw : JSON.stringify(obj),
    index_name: obj.index || obj.index_name,
  }, 'generic_json');
}

function normalizeRawText(text) {
  return finalizeRecord({
    shape: 'raw_text',
    timestamp: new Date().toISOString(),
    source: 'Unknown',
    event_id: '',
    computer: '',
    username: '',
    ip_address: pickIp(text),
    dst_ip_address: '',
    action: text,
    severity: /fail|denied|blocked|attack|malware|phish|virus|error/i.test(text) ? 'High' : 'Info',
    message: text,
    outcome: detectOutcome(text),
    raw: text,
  }, 'raw_text');
}

function parseLogRecord(input) {
  const ctx = buildContext(input);
  const json = ctx.json;
  const text = ctx.text;
  const cef = typeof text === 'string' && text.startsWith('CEF:') ? parseCef(text) : null;
  const env = typeof text === 'string' ? parseSyslogEnvelope(text) : null;

  if (json?.Event?.System) return normalizeWindowsEvent(json);
  if (json?.__REALTIME_TIMESTAMP || json?.SYSLOG_IDENTIFIER || json?._HOSTNAME) return normalizeJournald(json);
  if (json?.httpRequest && (json?.terminatingRuleId || json?.action)) return normalizeAwsWaf(json);
  if ((json?.workload && /exchange|office/i.test(String(json.workload))) || (json?.product && /exchange/i.test(String(json.product))) || json?.sender || json?.recipient) {
    return normalizeExchangeJson(json);
  }
  if (json && (String(json.vendor || '').toLowerCase().includes('aix') || String(json.product || '').toLowerCase().includes('aix') || String(json.source || '').toLowerCase().includes('aix'))) {
    return normalizeAixSyslog(ctx.embeddedRawText || ctx.rawText, json);
  }
  if (json && (json.action !== undefined || json.source !== undefined || json.raw !== undefined)) return normalizeK3Event(json);

  if (text && /(?:devname=|devid=|logid=)/.test(text) && (/(?:forti|FortiGate)/i.test(text) || /\bFGT[A-Z0-9-]*\b/.test(text))) return normalizeFortiGate(text);
  if (text && /%ASA-\d-\d+/.test(text)) return normalizeCiscoAsa(text);
  if (cef && /palo\s*alto/i.test(`${cef.vendor} ${cef.product}`)) return normalizePaloAltoCef(text, cef);
  if (cef && /(proofpoint|mimecast|ironport|email security|esa)/i.test(`${cef.vendor} ${cef.product} ${cef.name}`)) return normalizeEmailGateway(text, cef);
  if (cef && /cisco/i.test(`${cef.vendor} ${cef.product}`)) return normalizeCiscoCef(text, cef);
  if (cef) return normalizeGenericCef(text, cef);
  if (text && /^\d+,20\d{2}\/\d{2}\/\d{2} .*?,(TRAFFIC|THREAT|SYSTEM|CONFIG),/i.test(text)) return normalizePaloAltoCsv(text);
  if (text && /ModSecurity:/i.test(text)) return normalizeModSecurity(text);
  if (env && /^postfix\//i.test(env.program)) return normalizePostfix(text);
  if ((env && /\bAIX\b/i.test(`${env.host} ${env.programRaw} ${env.message}`)) || /\bAIX\b/i.test(text)) return normalizeAixSyslog(text);
  if (env && /(?:sshd|sudo|login|su|cron|systemd|kernel)/i.test(env.program)) return normalizeLinuxSyslog(text);
  if (env) return normalizeLinuxSyslog(text);
  if (json && typeof json === 'object') return normalizeGenericJson(json);
  return normalizeRawText(text);
}

function classifyRecord(rec) {
  const action = `${rec.action || ''} ${rec.message || ''}`.toLowerCase();
  const eid = rec.event_id || '';
  const family = rec.parser?.family;

  if (WIN_AUTH_EVENT_IDS[eid]) {
    const hint = WIN_AUTH_EVENT_IDS[eid];
    return { ...CLASSES.AUTHENTICATION, activity_name: hint.activity, activity_id: AUTH_ACTIVITY[hint.activity] || 99, status: hint.status };
  }
  if (WIN_PROCESS_EVENT_IDS[eid]) {
    const activity = WIN_PROCESS_EVENT_IDS[eid];
    return { ...CLASSES.PROCESS, activity_name: activity, activity_id: PROCESS_ACTIVITY[activity] || 99, status: 'Success' };
  }
  if (WIN_NETWORK_EVENT_IDS.has(eid)) {
    return { ...CLASSES.NETWORK, activity_name: 'Traffic', activity_id: 6, status: 'Success' };
  }
  if (WIN_SERVICE_EVENT_IDS.has(eid)) {
    return { ...CLASSES.SCHEDULED_JOB, activity_name: 'Create', activity_id: 1, status: 'Success' };
  }

  if (family === 'firewall' || family === 'waf' || family === 'generic_network') {
    if (/dns/.test(action)) return { ...CLASSES.DNS, activity_name: 'Query', activity_id: 1, status: detectOutcome(action) };
    if (/threat|attack|malware|spyware|virus|exploit|scan|sql|xss|blocked|deny|drop/.test(action)) {
      return { ...CLASSES.FINDING, activity_name: 'Create', activity_id: 1, status: detectOutcome(action) };
    }
    const denied = /deny|denied|block|blocked|drop|rejected|reset/.test(action);
    return { ...CLASSES.NETWORK, activity_name: denied ? 'Deny' : 'Allow', activity_id: denied ? 2 : 1, status: rec.outcome || (denied ? 'Failure' : 'Success') };
  }

  if (family === 'email' || family === 'email_security_gateway') {
    if (/spam|phish|phishing|malware|virus|quarantine|reject|blocked/.test(action)) {
      return { ...CLASSES.FINDING, activity_name: 'Create', activity_id: 1, status: detectOutcome(action) };
    }
    return { ...CLASSES.NETWORK, activity_name: /send|deliver|relay/.test(action) ? 'Allow' : 'Traffic', activity_id: /send|deliver|relay/.test(action) ? 1 : 6, status: rec.outcome || 'Success' };
  }

  if (family === 'linux' || family === 'aix' || family === 'windows') {
    if (/logon|login|logoff|logout|password|publickey|authentication|sudo|su /.test(action)) {
      const isLogoff = /logoff|logout/.test(action);
      const failed = /fail|invalid|denied/.test(action) || rec.outcome === 'Failure';
      return {
        ...CLASSES.AUTHENTICATION,
        activity_name: isLogoff ? 'Logoff' : (/sudo|su /.test(action) ? 'Authentication Ticket' : 'Logon'),
        activity_id: isLogoff ? 2 : (/sudo|su /.test(action) ? 3 : 1),
        status: failed ? 'Failure' : 'Success',
      };
    }
    if (/process|exec|launch|started|spawned|terminated/.test(action)) {
      const terminate = /terminate|terminated|exit/.test(action);
      return { ...CLASSES.PROCESS, activity_name: terminate ? 'Terminate' : 'Launch', activity_id: terminate ? 2 : 1, status: 'Success' };
    }
    if (/cron|systemd|service install|scheduled/.test(action)) {
      return { ...CLASSES.SCHEDULED_JOB, activity_name: 'Create', activity_id: 1, status: 'Success' };
    }
    if (/file |open |read |write |delete /.test(action)) {
      return { ...CLASSES.FILE, activity_name: 'Read', activity_id: 1, status: rec.outcome || 'Success' };
    }
  }

  return { ...CLASSES.BASE, activity_name: 'Unknown', activity_id: 0, status: rec.outcome || 'Unknown' };
}

function buildObservables(rec) {
  const obs = [];
  if (rec.ip_address) obs.push({ name: 'src_endpoint.ip', type: 'IP Address', value: rec.ip_address });
  if (rec.dst_ip_address) obs.push({ name: 'dst_endpoint.ip', type: 'IP Address', value: rec.dst_ip_address });
  if (rec.username) obs.push({ name: 'actor.user.name', type: 'User Name', value: rec.username });
  if (rec.computer) obs.push({ name: 'device.hostname', type: 'Hostname', value: rec.computer });
  return obs;
}

function severityFromString(sev) {
  return SEVERITY_ID[sev] ?? 0;
}

function toOCSF(rec) {
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
      product: { name: rec.parser?.product || 'K3 Parsing Engine', vendor_name: rec.parser?.vendor || 'K3' },
      log_name: rec.source,
      original_format: rec.shape,
      parser: rec.parser,
    },
    actor: rec.username ? { user: { name: rec.username } } : undefined,
    src_endpoint: (rec.ip_address || rec.computer) ? { ip: rec.ip_address || undefined, hostname: rec.computer || undefined } : undefined,
    dst_endpoint: rec.dst_ip_address ? { ip: rec.dst_ip_address } : undefined,
    device: rec.computer ? { hostname: rec.computer, type: rec.parser?.device_type } : undefined,
    observables: buildObservables(rec),
    raw_data: rec.raw,
    unmapped: {
      source: rec.source,
      event_id: rec.event_id,
      index_name: rec.index_name,
      parser_profile: rec.parser?.profile_id,
      additional: rec.additional || {},
    },
  };
}

function parseToOCSF(input) {
  return toOCSF(parseLogRecord(input));
}

const OCSF_CLASS_REFERENCE = Object.values(CLASSES).map((item) => ({
  class_uid: item.class_uid,
  class_name: item.class_name,
  category_uid: item.category_uid,
  category_name: item.category_name,
}));

const SUPPORTED_PARSER_PROFILES = PROFILE_CATALOG.map((profile) => ({ ...profile }));

module.exports = {
  parseLogRecord,
  parseToOCSF,
  toOCSF,
  OCSF_VERSION,
  OCSF_CLASS_REFERENCE,
  SUPPORTED_PARSER_PROFILES,
};
