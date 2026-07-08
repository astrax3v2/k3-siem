'use strict';
const { v4: uuidv4 } = require('uuid');
const { db, sqlNowMinus } = require('../models/db');
const { matchIOCs } = require('./iocMatcher');
const { buildRealtimeAlerts, persistRealtimeAlerts } = require('./realtimeAlerts');

const rand=(a,b)=>Math.floor(Math.random()*(b-a+1))+a;
const pick=arr=>arr[Math.floor(Math.random()*arr.length)];

const SOURCES   =['Windows Security','Linux Syslog','Palo Alto Firewall','CrowdStrike EDR','Cisco DNS','Azure AD','AWS CloudTrail','Network IDS'];
const COMPUTERS =['WS-001','WS-002','WS-023','SRV-001','SRV-002','DC-001','DC-002','GW-EDGE'];
const USERS     =['arun.sharma','sita.rai','ram.poudel','admin','svcAccount','SYSTEM','jmaharjan','bpaudel'];
const ACTIONS   =['User Logon','Failed Logon','Process Create','Service Install','File Access','Network Connect','Privilege Use','PowerShell Exec'];
const SEVS      =['Info','Info','Info','Low','Low','Medium','High','Critical'];
const EIDS      =['4624','4625','4688','7045','4672','5156','4634','4776','1102'];
const INDICES   =['windows-security','linux-syslog','network-flow','endpoint-edr','cloud-identity'];

let interval = null;
const wsClients = new Set();

function registerWsClient(ws) {
  wsClients.add(ws);
  ws.on('close', () => wsClients.delete(ws));
}

function broadcast(type, data) {
  const msg = JSON.stringify({ type, data, timestamp: new Date().toISOString() });
  for (const ws of wsClients) {
    try { ws.send(msg); } catch { wsClients.delete(ws); }
  }
}

function genEvent() {
  const sev=pick(SEVS), comp=pick(COMPUTERS), user=pick(USERS);
  const ip=`${rand(10,192)}.${rand(1,254)}.${rand(1,254)}.${rand(1,254)}`;
  const action=pick(ACTIONS), eid=pick(EIDS), src=pick(SOURCES), idx=pick(INDICES);
  return { id:uuidv4(), timestamp:new Date().toISOString(), source:src, event_id:eid, computer:comp, username:user, ip_address:ip, action, severity:sev, raw_log:JSON.stringify({EventID:eid,Computer:comp,User:user,IP:ip}), index_name:idx };
}

function startIngestion(ms=3000) {
  console.log(`[Ingestion] Live log generation every ${ms}ms`);
  interval = setInterval(() => {
    (async () => {
      const d = db();
      const batch = Array.from({length:rand(1,4)}, genEvent);
      const insE = d.prepare(`INSERT INTO events(id,timestamp,source,event_id,computer,username,ip_address,action,severity,raw_log,index_name,agent_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`);
      const insertEvents = d.transaction(async (rows) => {
        for (const e of rows) await insE.run(e.id,e.timestamp,e.source,e.event_id,e.computer,e.username,e.ip_address,e.action,e.severity,e.raw_log,e.index_name,null);
      });
      await insertEvents(batch);

      const newAlerts = [];
      for (const ev of batch) {
        newAlerts.push(...await buildRealtimeAlerts(ev));
      }
      await persistRealtimeAlerts(newAlerts);
      broadcast('events', batch);
      if (newAlerts.length) broadcast('alerts', newAlerts);

      Promise.all(batch.map((e) => matchIOCs(e).catch(() => []))).catch(() => {});
    })().catch(() => {});
  }, ms);
}

function stopIngestion() { if (interval) { clearInterval(interval); interval=null; } }

module.exports = { startIngestion, stopIngestion, registerWsClient, broadcast };
