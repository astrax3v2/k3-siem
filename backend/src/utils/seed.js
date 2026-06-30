'use strict';
require('dotenv').config();
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const { db, initDb, getDialect } = require('../models/db');

const rand = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const pick = arr => arr[Math.floor(Math.random() * arr.length)];
const ago = ms => new Date(Date.now() - ms).toISOString();

const SOURCES   = ['Windows Security','Linux Syslog','Palo Alto Firewall','CrowdStrike EDR','Cisco DNS','Azure AD','AWS CloudTrail','Network IDS'];
const COMPUTERS = ['WS-001','WS-002','WS-023','SRV-001','SRV-002','DC-001','DC-002','GW-EDGE'];
const USERS     = ['arun.sharma','sita.rai','ram.poudel','gita.thapa','admin','svcAccount','SYSTEM','jmaharjan','bpaudel','pbasnet'];
const ACTIONS   = ['User Logon','Failed Logon','Process Create','Service Install','File Access','Network Connect','Privilege Use','PowerShell Exec','Registry Modify'];
const SEVS      = ['Info','Info','Info','Low','Low','Medium','High','Critical'];
const EIDS      = ['4624','4625','4688','7045','4672','5156','4634','4776','1102'];
const INDICES   = ['windows-security','linux-syslog','network-flow','endpoint-edr','cloud-identity'];
const TACTICS   = ['Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion','Credential Access','Discovery','Lateral Movement','Exfiltration','Command & Control'];
const TECHNIQUES= ['T1078','T1059.001','T1053.005','T1003.001','T1055','T1021.001','T1083','T1041','T1071.004','T1110.003'];
const ATITLES   = ['Brute Force Attack Detected','Lateral Movement via RDP','Suspicious PowerShell Execution',
  'Credential Dumping - LSASS Access','C2 Beacon Traffic Identified','Data Exfiltration via DNS Tunneling',
  'Privilege Escalation Alert','Malware Execution Blocked','Ransomware IOC Match','Mimikatz Usage Detected',
  'Cobalt Strike Beacon','Port Scan Activity','Account Lockout Spike','Pass-the-Hash Attack'];

async function seed() {
  await initDb();
  const d = db();

  await d.exec(`DELETE FROM playbook_executions; DELETE FROM ueba_scores; DELETE FROM kql_saved_queries;
          DELETE FROM intel_feeds; DELETE FROM incident_alerts; DELETE FROM incident_notes; DELETE FROM incidents; DELETE FROM iocs; DELETE FROM alerts; DELETE FROM events;
          DELETE FROM playbooks; DELETE FROM correlation_rules; DELETE FROM users;`);
  console.log('[Seed] Cleared');

  // Users
  const pwHash = bcrypt.hashSync('K3@2026', 10);
  const insU = d.prepare(`INSERT INTO users(id,username,email,password_hash,role,full_name,department) VALUES(?,?,?,?,?,?,?)`);
  for (const r of [
    [uuidv4(),'pbasnet','pbasnet@k3siem.local',pwHash,'admin','Prem Basnet','Security Operations'],
    [uuidv4(),'jmaharjan','jmaharjan@k3siem.local',pwHash,'t2_analyst','Jenan Maharjan','Security Operations'],
    [uuidv4(),'bpaudel','bpaudel@k3siem.local',pwHash,'t2_analyst','Bamdev Paudel','Security Operations'],
    [uuidv4(),'analyst1','analyst1@k3siem.local',pwHash,'t1_analyst','SOC Analyst','Security Operations'],
  ]) await insU.run(...r);
  console.log('[Seed] Users: 4');

  // Events - 500 rows
  const insE = d.prepare(`INSERT INTO events(id,timestamp,source,event_id,computer,username,ip_address,action,severity,raw_log,index_name,agent_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`);
  const insertEvents = d.transaction(async (rows) => { for (const r of rows) await insE.run(...r); });
  const evtRows = Array.from({length:500}, () => {
    const sev=pick(SEVS), src=pick(SOURCES), comp=pick(COMPUTERS), user=pick(USERS);
    const ip=`${rand(10,192)}.${rand(1,254)}.${rand(1,254)}.${rand(1,254)}`;
    const action=pick(ACTIONS), eid=pick(EIDS), ts=ago(rand(0,86400000));
    const idx=pick(INDICES);
    return [uuidv4(),ts,src,eid,comp,user,ip,action,sev,JSON.stringify({EventID:eid,Computer:comp,User:user,IP:ip}),idx,null];
  });
  await insertEvents(evtRows);
  console.log('[Seed] Events: 500');

  // Alerts - 60 rows
  const insA = d.prepare(`INSERT INTO alerts(id,title,description,severity,status,source,asset,username,ip_address,mitre_tactic,mitre_technique,risk_score,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const insertAlerts = d.transaction(async (rows) => { for (const r of rows) await insA.run(...r); });
  await insertAlerts(Array.from({length:60}, () => {
    const sev=pick(['Critical','High','High','Medium','Medium','Low']);
    const title=pick(ATITLES), ts=ago(rand(0,604800000));
    const ip=`${rand(10,192)}.${rand(1,254)}.${rand(1,254)}.${rand(1,254)}`;
    return [uuidv4(),title,`Automated detection: ${title} on ${pick(COMPUTERS)}`,
      sev,pick(['New','Assigned','In Progress','Closed']),pick(SOURCES),pick(COMPUTERS),
      pick(USERS),ip,pick(TACTICS),pick(TECHNIQUES),rand(20,99),ts,ts];
  }));
  console.log('[Seed] Alerts: 60');

  // Incidents - 6 rows (linked to existing alerts)
  const insInc = d.prepare(`INSERT INTO incidents(id,title,description,severity,status,priority,owner,tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`);
  const insLink = d.prepare(getDialect() === 'postgres'
    ? 'INSERT INTO incident_alerts(incident_id,alert_id) VALUES(?,?) ON CONFLICT DO NOTHING'
    : 'INSERT OR IGNORE INTO incident_alerts(incident_id,alert_id) VALUES(?,?)'
  );
  const insNote = d.prepare('INSERT INTO incident_notes(id,incident_id,author,note,created_at) VALUES(?,?,?,?,?)');
  const sampleAlerts = await d.prepare('SELECT id,title,severity,created_at FROM alerts ORDER BY created_at DESC LIMIT 12').all();
  const owners = ['pbasnet', 'jmaharjan', 'bpaudel', 'analyst1'];
  const statuses = ['Open', 'In Progress', 'Contained', 'Eradicated', 'Recovered', 'Closed'];
  const incidentIds = [];
  for (let i = 0; i < 6; i++) {
    const a = sampleAlerts[i];
    const incId = uuidv4();
    const status = statuses[i % statuses.length];
    const createdAt = ago(rand(0, 604800000));
    await insInc.run(
      incId,
      `IR-${String(i + 1).padStart(3, '0')}: ${a?.title || pick(ATITLES)}`,
      `Incident case created for triage and response. Linked alert severity: ${a?.severity || 'Medium'}.`,
      a?.severity || pick(['Critical', 'High', 'Medium', 'Low']),
      status,
      rand(1, 4),
      pick(owners),
      JSON.stringify(['incident-response', 'demo']),
      createdAt,
      createdAt
    );
    incidentIds.push(incId);
    if (a?.id) await insLink.run(incId, a.id);
    await insNote.run(uuidv4(), incId, pick(owners), 'Initial triage started. Evidence collection in progress.', createdAt);
    await insNote.run(uuidv4(), incId, pick(owners), 'Next steps: confirm scope, contain impacted host/user, preserve logs.', ago(rand(0, 604800000)));
  }
  console.log('[Seed] Incidents: 6');

  // IOCs
  const insI = d.prepare(`INSERT INTO iocs(id,type,value,confidence,severity,source,description,tags,hits,first_seen) VALUES(?,?,?,?,?,?,?,?,?,?)`);
  for (const [type,value,conf,sev,src,desc,tags,hits] of [
    ['IP','185.220.101.47',95,'Critical','AbuseIPDB','Known Tor exit node - APT campaigns','["APT29","Tor"]',12],
    ['IP','91.108.4.200',88,'High','OTX AlienVault','C2 server - Cobalt Strike','["CobaltStrike","C2"]',7],
    ['Domain','evil-c2.top',92,'Critical','MISP','Active C2 - LockBit ransomware','["Ransomware","LockBit"]',5],
    ['Domain','malware-payload.xyz',85,'High','VirusTotal','Malware distribution domain','["Malware","Dropper"]',3],
    ['Hash','d41d8cd98f00b204e9800998ecf8427e',90,'Critical','VirusTotal','Mimikatz variant','["Mimikatz","CredDump"]',8],
    ['Hash','4d5a900098765432100fedcba987654',78,'High','Recorded Future','Ransomware payload','["Ransomware"]',2],
    ['URL','http://45.33.32.156/payload.exe',88,'Critical','MISP','Malware download URL','["Dropper"]',4],
    ['URL','https://cryptominer.pw/miner.js',75,'High','AbuseIPDB','Cryptomining script','["Cryptominer"]',9],
    ['Email','attacker@phish-campaign.com',82,'High','Internal','Phishing campaign sender','["Phishing","BEC"]',15],
    ['Domain','cobalt-strike-c2.ru',94,'Critical','Recorded Future','Active Cobalt Strike C2','["CobaltStrike","APT"]',6],
    ['IP','192.168.100.254',60,'Medium','Internal','Internal suspicious host','["Internal","Recon"]',22],
    ['Hash','abc123def456789012345678901234',70,'Medium','VirusTotal','Suspicious obfuscated script','["Script"]',1],
  ]) await insI.run(uuidv4(),type,value,conf,sev,src,desc,tags,hits,ago(rand(0,2592000000)));
  console.log('[Seed] IOCs: 12');

  // Correlation rules
  const insCR = d.prepare(`INSERT INTO correlation_rules(id,name,description,logic,severity,risk_score,window_minutes,indices,threshold,hit_count) VALUES(?,?,?,?,?,?,?,?,?,?)`);
  for (const [name,desc,logic,sev,score,win,idx,thr,hits] of [
    ['Brute Force → Privilege Escalation','Failed logins then privilege use same account','EventID==4625 count>=10 within window → EventID==4672 same account','Critical',95,5,'["windows-security"]',10,7],
    ['Lateral Movement via RDP','RDP success from new internal host','EventID==4624 LogonType==10 new_source → DestPort==3389','High',88,15,'["windows-security","network-flow"]',3,3],
    ['Data Staging and DNS Exfil','Large file write then anomalous DNS','FileWrite size>10MB temp_dir → DNSQuery TXT count>100','Critical',92,30,'["endpoint-edr","network-flow"]',1,1],
    ['Malware Execution Chain','Script exec → injection → C2 beacon','CmdLine has bypass → ProcessInjection → OutboundC2','Critical',97,10,'["endpoint-edr","network-flow"]',1,2],
    ['Account Takeover Pattern','Password spray → MFA enroll → mass access','FailedLogin count>5 external → MFADeviceAdd → MailboxAccess count>50','High',91,60,'["cloud-identity","windows-security"]',5,4],
    ['Kerberoasting Detection','SPN ticket requests for many accounts','EventID==4769 EncryptionType==0x17 count>5 same_user','High',85,5,'["windows-security"]',5,2],
  ]) await insCR.run(uuidv4(),name,desc,logic,sev,score,win,idx,thr,hits);
  console.log('[Seed] Correlation rules: 6');

  // Playbooks
  const insPB = d.prepare(`INSERT INTO playbooks(id,name,description,trigger_condition,status,steps,execution_count) VALUES(?,?,?,?,?,?,?)`);
  for (const [name,desc,trigger,status,steps,count] of [
    ['Brute Force Response','Automated containment for brute force','failed_login_count >= 10 within 5 minutes','Active',
     JSON.stringify(['Detect threshold breach via correlation rule','Block source IP on perimeter firewall (Palo Alto API)','Lock affected user account in Active Directory','Send alert to SOC Slack channel','Create Jira incident ticket with evidence','Generate SIEM incident timeline report','Notify account owner via email']),47],
    ['Malware Containment','Isolation and forensics for malware','EDR malware detection confidence > 85%','Active',
     JSON.stringify(['Isolate endpoint from network via CrowdStrike API','Kill identified malicious process tree','Collect memory dump and disk image','Quarantine malicious file — submit hash to MISP','Notify assigned analyst in Teams','Trigger full AV scan on adjacent systems','Submit IOCs to threat intel feed']),12],
    ['Phishing Email Response','End-to-end phishing remediation','Email gateway phishing alert OR user-reported','Active',
     JSON.stringify(['Extract IOCs from email headers and body','Search IOCs across all SIEM indices (last 30d)','Block sender domain on email gateway','Search all mailboxes for similar messages','Delete matching phishing emails organization-wide','Block IOC URLs on web proxy','Send user awareness notification']),89],
    ['Privilege Escalation Response','Containment of privilege escalation','risk_score > 80 and mitre_tactic == Privilege Escalation','Paused',
     JSON.stringify(['Correlate with parent process and user session','Review account privilege history (last 7d)','Disable compromised account temporarily','Alert SOC manager via Slack and email','Capture forensic process timeline','Reset credentials and revoke tokens','Escalate to IR team if confirmed']),8],
  ]) await insPB.run(uuidv4(),name,desc,trigger,status,steps,count);
  console.log('[Seed] Playbooks: 4');

  // UEBA
  const insUEBA = d.prepare(`INSERT INTO ueba_scores(id,username,risk_score,anomaly_count,baseline_deviation,flags,department,location,last_activity) VALUES(?,?,?,?,?,?,?,?,?)`);
  for (const [user,risk,anom,dev,flags,dept,loc] of [
    ['arun.sharma',78,4,2.3,'["Geo-Velocity","Off-Hours Login"]','Engineering','HQ'],
    ['sita.rai',45,1,0.8,'[]','HR','HQ'],
    ['ram.poudel',91,7,4.1,'["Mass Download","Peer Group Deviation","Off-Hours Login"]','IT','Remote - VPN'],
    ['gita.thapa',22,0,0.2,'[]','Operations','HQ'],
    ['bikash.kc',67,3,1.9,'["Off-Hours Login"]','Security','Branch'],
    ['sunita.malla',33,1,0.5,'[]','Legal','HQ'],
    ['admin',85,5,3.2,'["Privilege Abuse","Suspicious Process"]','IT','SRV-001'],
    ['jmaharjan',18,0,0.1,'[]','Security Operations','HQ'],
    ['bpaudel',29,1,0.4,'[]','Security Operations','HQ'],
    ['pbasnet',12,0,0.0,'[]','Security Operations','HQ'],
  ]) await insUEBA.run(uuidv4(),user,risk,anom,dev,flags,dept,loc,ago(rand(0,3600000)));
  console.log('[Seed] UEBA scores: 10');

  // KQL saved queries
  const insKQL = d.prepare(`INSERT INTO kql_saved_queries(id,name,query,description,category,is_rule) VALUES(?,?,?,?,?,?)`);
  for (const [name,query,desc,cat,isRule] of [
    ['Brute Force Detection','SecurityEvent\n| where event_id == "4625"\n| where timestamp > datetime_ago("5m")\n| order by timestamp desc','Count failed logins per user/IP','Authentication',1],
    ['Suspicious PowerShell','SecurityEvent\n| where event_id == "4688"\n| where action has_any ("PowerShell","bypass","encoded","hidden")\n| project timestamp, computer, username, action\n| order by timestamp desc','PowerShell abuse detection','Execution',1],
    ['Privilege Use Events','SecurityEvent\n| where event_id == "4672"\n| where username != "SYSTEM"\n| order by timestamp desc','Special privilege assignment events','PrivEsc',1],
    ['All Critical Events','SecurityEvent\n| where severity == "Critical"\n| order by timestamp desc','Critical severity events from all sources','Investigation',1],
    ['Failed Logins Last Hour','SecurityEvent\n| where event_id == "4625"\n| order by timestamp desc','All authentication failures','Authentication',0],
    ['Top 10 Recent Events','SecurityEvent\n| top 10','Quick view of latest events','Baseline',0],
  ]) await insKQL.run(uuidv4(),name,query,desc,cat,isRule);
  console.log('[Seed] KQL queries: 6');

  // Intel feeds
  const insFeed = d.prepare(`INSERT INTO intel_feeds(id,name,url,type,status,last_sync,ioc_count) VALUES(?,?,?,?,?,?,?)`);
  for (const [name,url,type,status,sync,count] of [
    ['MISP Instance','https://misp.example.com','STIX/TAXII','active',ago(120000),847],
    ['VirusTotal API','https://www.virustotal.com/api','REST','active',ago(300000),12043],
    ['AbuseIPDB','https://api.abuseipdb.com','REST','active',ago(60000),5821],
    ['OTX AlienVault','https://otx.alienvault.com/api','REST','active',ago(480000),3219],
    ['Recorded Future','https://api.recordedfuture.com','REST','active',ago(720000),9871],
    ['NVD NIST CVE','https://nvd.nist.gov/feeds','XML','active',ago(3600000),2341],
  ]) await insFeed.run(uuidv4(),name,url,type,status,sync,count);
  console.log('[Seed] Intel feeds: 6');

  // Agents + Assets
  const insAgent = d.prepare('INSERT INTO agents(id, hostname, os, ip, status, agent_version, tags, collected_sources, events_sent, last_heartbeat) VALUES(?,?,?,?,?,?,?,?,?,?)');
  const insAsset = d.prepare('INSERT INTO assets(id, agent_id, hostname, os_name, os_version, os_arch, cpu_model, cpu_cores, ram_total_gb, disk_total_gb, disk_used_gb, network_interfaces, installed_software, running_services, open_ports, local_users, antivirus_status, firewall_enabled, last_patch_date, uptime_hours, domain, serial_number) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');

  const agentsData = [
    { hostname: 'WS-PC-001', os: 'Windows 11 Pro', ip: '192.168.1.66', version: '1.0.0', sources: ['Windows Security', 'CrowdStrike EDR'], events: 1247,
      asset: { os_name: 'Windows 11 Pro', os_version: '10.0.22631', os_arch: 'x86_64', cpu_model: 'Intel Core i7-13700K', cpu_cores: 16, ram: 16.0, disk: 512.0, disk_used: 287.3, av: 'CrowdStrike Falcon', fw: 1, patch: '2026-06-15', uptime: 168.5, domain: 'corp.k3sec.io', serial: 'K3-WS-001',
        net: [{"name":"Ethernet","ip":"192.168.1.66","mac":"00:1A:2B:3C:4D:5E"}],
        sw: [{"name":"CrowdStrike Falcon","version":"7.10"},{"name":"Microsoft 365","version":"16.0"},{"name":"Chrome","version":"126.0"},{"name":"VS Code","version":"1.92"},{"name":"Python 3.12","version":"3.12.4"},{"name":"Slack","version":"4.39"},{"name":"Zoom","version":"6.1"},{"name":"7-Zip","version":"24.07"}],
        svc: [{"name":"CrowdStrike","status":"running"},{"name":"Windows Defender","status":"running"},{"name":"DNS Client","status":"running"}],
        ports: [{"port":135,"proto":"tcp"},{"port":445,"proto":"tcp"},{"port":3389,"proto":"tcp"}],
        users: [{"name":"john.doe"},{"name":"Administrator"}] }},
    { hostname: 'SRV-UBUNTU-01', os: 'Ubuntu 24.04 LTS', ip: '10.0.1.50', version: '1.0.0', sources: ['Linux Syslog', 'OSSEC HIDS'], events: 3892,
      asset: { os_name: 'Ubuntu 24.04 LTS', os_version: '6.8.0-45-generic', os_arch: 'x86_64', cpu_model: 'AMD EPYC 7763', cpu_cores: 8, ram: 64.0, disk: 1000.0, disk_used: 423.7, av: 'ClamAV', fw: 1, patch: '2026-06-20', uptime: 744.2, domain: 'srv.k3sec.io', serial: 'K3-SRV-001',
        net: [{"name":"eth0","ip":"10.0.1.50","mac":"02:42:AC:11:00:02"}],
        sw: [{"name":"openssh-server","version":"9.6p1"},{"name":"nginx","version":"1.24.0"},{"name":"postgresql-16","version":"16.3"},{"name":"docker-ce","version":"27.1"},{"name":"python3","version":"3.12.3"},{"name":"clamav","version":"1.3.1"},{"name":"fail2ban","version":"1.0.2"}],
        svc: [{"name":"sshd","status":"running"},{"name":"nginx","status":"running"},{"name":"postgresql","status":"running"},{"name":"docker","status":"running"},{"name":"clamav-daemon","status":"running"}],
        ports: [{"port":22,"proto":"tcp"},{"port":80,"proto":"tcp"},{"port":443,"proto":"tcp"},{"port":5432,"proto":"tcp"}],
        users: [{"name":"root"},{"name":"ubuntu"},{"name":"deploy"},{"name":"postgres"}] }},
    { hostname: 'FW-PALOALTO-01', os: 'PAN-OS 11.1', ip: '203.0.113.1', version: '1.0.0', sources: ['Palo Alto Firewall', 'Network IDS'], events: 8521,
      asset: { os_name: 'PAN-OS 11.1', os_version: '11.1.3', os_arch: 'arm64', cpu_model: 'Cavium Octeon III', cpu_cores: 4, ram: 16.0, disk: 240.0, disk_used: 45.2, av: 'WildFire', fw: 1, patch: '2026-06-10', uptime: 2160.0, domain: 'fw.k3sec.io', serial: 'K3-FW-001',
        net: [{"name":"ethernet1/1","ip":"203.0.113.1","mac":"00:1B:17:00:01:01"},{"name":"ethernet1/2","ip":"10.0.0.1","mac":"00:1B:17:00:01:02"}],
        sw: [{"name":"PAN-OS","version":"11.1.3"},{"name":"Threat Prevention","version":"8832"},{"name":"WildFire","version":"832416"},{"name":"GlobalProtect","version":"6.2.1"}],
        svc: [{"name":"mgmtsrvr","status":"running"},{"name":"configd","status":"running"},{"name":"logrcvr","status":"running"}],
        ports: [{"port":443,"proto":"tcp"},{"port":22,"proto":"tcp"}],
        users: [{"name":"admin"},{"name":"panorama-svc"}] }},
    { hostname: 'WS-LAPTOP-003', os: 'Windows 11 Pro', ip: '192.168.1.102', version: '1.0.0', sources: ['Windows Security'], events: 456,
      asset: { os_name: 'Windows 11 Pro', os_version: '10.0.22631', os_arch: 'x86_64', cpu_model: 'Intel Core i5-1340P', cpu_cores: 12, ram: 8.0, disk: 256.0, disk_used: 198.4, av: 'Windows Defender', fw: 1, patch: '2026-06-01', uptime: 72.3, domain: 'corp.k3sec.io', serial: 'K3-WS-003',
        net: [{"name":"Wi-Fi","ip":"192.168.1.102","mac":"AA:BB:CC:DD:EE:FF"}],
        sw: [{"name":"Windows Defender","version":"4.18"},{"name":"Chrome","version":"126.0"},{"name":"Microsoft 365","version":"16.0"}],
        svc: [{"name":"Windows Defender","status":"running"},{"name":"Windows Update","status":"running"}],
        ports: [{"port":135,"proto":"tcp"},{"port":445,"proto":"tcp"}],
        users: [{"name":"jane.smith"},{"name":"Administrator"}] }},
    { hostname: 'SRV-DB-02', os: 'Ubuntu 22.04 LTS', ip: '10.0.1.55', version: '1.0.0', sources: ['Linux Syslog'], events: 2103,
      asset: { os_name: 'Ubuntu 22.04 LTS', os_version: '5.15.0-119-generic', os_arch: 'x86_64', cpu_model: 'AMD EPYC 7543', cpu_cores: 16, ram: 128.0, disk: 2000.0, disk_used: 1247.0, av: 'None', fw: 0, patch: '2026-04-15', uptime: 1440.0, domain: 'srv.k3sec.io', serial: 'K3-SRV-002',
        net: [{"name":"eth0","ip":"10.0.1.55","mac":"02:42:AC:11:00:05"}],
        sw: [{"name":"postgresql-14","version":"14.12"},{"name":"openssh-server","version":"8.9"},{"name":"python3","version":"3.10.12"}],
        svc: [{"name":"sshd","status":"running"},{"name":"postgresql","status":"running"}],
        ports: [{"port":22,"proto":"tcp"},{"port":5432,"proto":"tcp"}],
        users: [{"name":"root"},{"name":"postgres"},{"name":"dba"}] }},
  ];

  for (const ag of agentsData) {
    const agId = uuidv4();
    await insAgent.run(agId, ag.hostname, ag.os, ag.ip, 'offline', ag.version, JSON.stringify([]), JSON.stringify(ag.sources), ag.events, ago(rand(60000, 600000)));
    const a = ag.asset;
    await insAsset.run(uuidv4(), agId, ag.hostname, a.os_name, a.os_version, a.os_arch, a.cpu_model, a.cpu_cores, a.ram, a.disk, a.disk_used, JSON.stringify(a.net), JSON.stringify(a.sw), JSON.stringify(a.svc), JSON.stringify(a.ports), JSON.stringify(a.users), a.av, a.fw, a.patch, a.uptime, a.domain, a.serial);
  }
  console.log('[Seed] Agents: 5, Assets: 5');

  console.log('\n✅ Seed complete!');
  console.log('   Login: pbasnet / K3@2026');
}

seed().catch(e => { console.error(e); process.exit(1); });
