'use strict';
const { v4: uuidv4 } = require('uuid');
const { db, sqlNowMinus } = require('../models/db');

async function buildRealtimeAlerts(event) {
  const alerts = [];
  const d = db();

  if (event.event_id === '4625') {
    const cnt = (await d.prepare(`SELECT COUNT(*) as cnt FROM events WHERE event_id='4625' AND username=? AND timestamp >= ${sqlNowMinus(5, 'minute')}`).get(event.username))?.cnt || 0;
    if (cnt >= 3) {
      alerts.push({
        id: uuidv4(),
        title: 'Brute Force Attack Detected',
        description: `${cnt} failed logins for ${event.username} from ${event.ip_address} in last 5 minutes`,
        severity: cnt >= 8 ? 'Critical' : 'High',
        status: 'New',
        source: event.source,
        asset: event.computer,
        username: event.username,
        ip_address: event.ip_address,
        mitre_tactic: 'Credential Access',
        mitre_technique: 'T1110.003',
        risk_score: Math.min(95, 50 + cnt * 5),
      });
    }
  }

  const action = String(event.action || '').toLowerCase();
  const source = String(event.source || '');
  const isPowerShellSource = source.includes('PowerShell');
  const suspiciousPowerShell = isPowerShellSource || action.includes('powershell') || action.includes('encodedcommand') || action.includes('downloadstring') || action.includes('invoke-expression') || action.includes('frombase64string');
  const highSignalPowerShell = action.includes('encodedcommand') || action.includes('downloadstring') || action.includes('invoke-expression') || action.includes('frombase64string') || action.includes(' bypass') || action.includes(' -enc ');
  if (suspiciousPowerShell && (event.severity !== 'Info' || highSignalPowerShell)) {
    alerts.push({
      id: uuidv4(),
      title: 'Suspicious PowerShell Execution',
      description: `PowerShell activity on ${event.computer}${event.username ? ` by ${event.username}` : ''}: ${String(event.action || '').slice(0, 220)}`,
      severity: highSignalPowerShell || event.severity === 'Critical' ? 'High' : 'Medium',
      status: 'New',
      source: event.source,
      asset: event.computer,
      username: event.username,
      ip_address: event.ip_address,
      mitre_tactic: 'Execution',
      mitre_technique: 'T1059.001',
      risk_score: action.includes('encodedcommand') || action.includes('downloadstring') ? 88 : 72,
    });
  }

  const privilegeKeywords = [
    'net localgroup administrators',
    'add-localgroupmember',
    'reg add hkcu\\software\\microsoft\\windows\\currentversion\\run',
    'schtasks /create',
    'sc.exe create',
    'wevtutil cl',
    'secedit',
    'runas ',
  ];
  const matchedKeyword = privilegeKeywords.find((keyword) => action.includes(keyword));
  if (matchedKeyword) {
    alerts.push({
      id: uuidv4(),
      title: 'Suspicious Privileged Command Execution',
      description: `Privileged command pattern "${matchedKeyword}" observed on ${event.computer}: ${String(event.action || '').slice(0, 220)}`,
      severity: 'High',
      status: 'New',
      source: event.source,
      asset: event.computer,
      username: event.username,
      ip_address: event.ip_address,
      mitre_tactic: 'Privilege Escalation',
      mitre_technique: 'T1548',
      risk_score: 86,
    });
  }

  if (event.event_id === '4672' && event.username && event.username !== 'SYSTEM') {
    alerts.push({
      id: uuidv4(),
      title: 'Privilege Escalation Alert',
      description: `Special privileges assigned to ${event.username} on ${event.computer}${event.action ? `: ${String(event.action).slice(0, 180)}` : ''}`,
      severity: 'Medium',
      status: 'New',
      source: event.source,
      asset: event.computer,
      username: event.username,
      ip_address: event.ip_address,
      mitre_tactic: 'Privilege Escalation',
      mitre_technique: 'T1078',
      risk_score: 65,
    });
  }

  if (event.event_id === '7045' || event.event_id === '4697') {
    alerts.push({
      id: uuidv4(),
      title: 'Suspicious Service Installation',
      description: `A new service was installed on ${event.computer}${event.action ? `: ${String(event.action).slice(0, 180)}` : ''}`,
      severity: 'High',
      status: 'New',
      source: event.source,
      asset: event.computer,
      username: event.username,
      ip_address: event.ip_address,
      mitre_tactic: 'Persistence',
      mitre_technique: 'T1543.003',
      risk_score: 84,
    });
  }

  if (event.event_id === '1102') {
    alerts.push({
      id: uuidv4(),
      title: 'Security Audit Log Cleared',
      description: `Security audit log cleared on ${event.computer}`,
      severity: 'Critical',
      status: 'New',
      source: event.source,
      asset: event.computer,
      username: event.username,
      ip_address: event.ip_address,
      mitre_tactic: 'Defense Evasion',
      mitre_technique: 'T1070.001',
      risk_score: 95,
    });
  }

  return alerts;
}

async function persistRealtimeAlerts(alerts) {
  if (!alerts.length) return [];
  const d = db();
  const ins = d.prepare(`INSERT INTO alerts(id,title,description,severity,status,source,asset,username,ip_address,mitre_tactic,mitre_technique,risk_score) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`);
  for (const a of alerts) {
    await ins.run(a.id, a.title, a.description, a.severity, a.status, a.source, a.asset, a.username, a.ip_address, a.mitre_tactic, a.mitre_technique, a.risk_score);
  }
  return alerts;
}

module.exports = { buildRealtimeAlerts, persistRealtimeAlerts };
