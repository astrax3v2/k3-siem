import React, { useState, useEffect, useCallback } from 'react';
import { ocsfApi } from '../../services/api';

const SAMPLES = {
  'Windows Event Log': JSON.stringify({
    Event: {
      System: { EventID: { '$': '4625' }, Computer: 'WS-PC-001', TimeCreated: { '@SystemTime': new Date().toISOString() } },
      EventData: { TargetUserName: 'john.doe', IpAddress: '10.0.0.42' },
    },
  }, null, 2),
  'Linux SSH Syslog': 'Jul 22 10:14:22 SRV-UBUNTU-01 sshd[2231]: Failed password for invalid user admin from 203.0.113.7 port 51422 ssh2',
  'AIX Syslog': 'Jul 22 10:30:12 AIX-LPAR-01 sshd[9987]: Failed password for root from 198.51.100.44 port 55222 ssh2',
  'Cisco ASA': 'Jul 22 10:45:33 edge-fw %ASA-4-106023: Deny tcp src outside:198.51.100.20/445 dst inside:10.0.0.15/445 by access-group "outside_access_in"',
  'Palo Alto CEF': 'CEF:0|Palo Alto Networks|PAN-OS|11.1.3|THREAT|Port Scan Detected|8|src=198.51.100.20 dst=10.0.0.1 act=blocked suser=jdoe',
  'FortiGate KV': 'date=2026-07-22 time=10:50:12 devname="FGT-HQ-01" devid="FGT60FTK" type="traffic" subtype="forward" level="warning" action="deny" srcip=203.0.113.9 dstip=10.0.0.25 srcuser="guest" msg="Denied by forward policy check"',
  'AWS WAF JSON': JSON.stringify({
    timestamp: new Date().toISOString(),
    webaclId: 'prod-web-acl',
    terminatingRuleId: 'AWS-AWSManagedRulesSQLiRuleSet',
    action: 'BLOCK',
    httpRequest: { clientIp: '198.51.100.77' },
  }, null, 2),
  'Email Gateway CEF': 'CEF:0|Proofpoint|Email Protection|8.19|MAIL-THREAT|Phishing message quarantined|9|src=192.0.2.25 suser=alice@example.com duser=bob@example.com act=quarantine',
  'Exchange Email JSON': JSON.stringify({
    timestamp: new Date().toISOString(),
    workload: 'Exchange',
    sender: 'finance@external.example',
    recipient: 'ap@contoso.example',
    action: 'Message blocked',
    verdict: 'phish',
    ClientIP: '198.51.100.88',
    subject: 'Invoice Payment Required',
  }, null, 2),
  'ModSecurity WAF': 'Jul 22 11:05:01 waf-01 modsec[1942]: [client 203.0.113.55] ModSecurity: Access denied with code 403 (phase 2). Matched phrase "union select" at ARGS:q. [id "942100"] [msg "SQL Injection Attack Detected"]',
};

const CATEGORY_COLOR = {
  'Identity & Access Management': '#90cdf4',
  'System Activity': '#b794f4',
  'Network Activity': '#68d391',
  Findings: '#fc8181',
  Uncategorized: 'var(--text3)',
};

function CategoryBadge({ name }) {
  const color = CATEGORY_COLOR[name] || 'var(--text3)';
  return <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700, background: `${color}22`, color }}>{name}</span>;
}

function StatCard({ label, value, color }) {
  return (
    <div style={{ background: 'var(--bg2)', borderRadius: 8, padding: '12px 14px', border: '1px solid var(--border)' }}>
      <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700, color }}>{value ?? 0}</div>
    </div>
  );
}

function ProfileCard({ profile }) {
  return (
    <div style={{ background: 'var(--bg3)', borderRadius: 8, border: '1px solid var(--border)', padding: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text)' }}>{profile.title}</div>
        <span className="badge badge-blue" style={{ fontSize: 9 }}>{profile.family}</span>
      </div>
      <div style={{ fontSize: 11, color: 'var(--text2)', marginBottom: 6 }}>{profile.vendor} / {profile.product}</div>
      <div style={{ fontSize: 10, color: 'var(--text3)', lineHeight: 1.4 }}>{profile.description}</div>
    </div>
  );
}

export default function OCSFParser() {
  const [raw, setRaw] = useState(SAMPLES['Windows Event Log']);
  const [result, setResult] = useState(null);
  const [parsed, setParsed] = useState(null);
  const [error, setError] = useState(null);
  const [parsing, setParsing] = useState(false);
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [profiles, setProfiles] = useState([]);

  const loadEvents = useCallback(async () => {
    try {
      const [statsRes, eventsRes, profilesRes] = await Promise.all([
        ocsfApi.stats(),
        ocsfApi.events({ limit: 25 }),
        ocsfApi.profiles(),
      ]);
      setStats(statsRes.data);
      setEvents(eventsRes.data.events || []);
      setProfiles(profilesRes.data.profiles || []);
    } catch {
      // Ignore background refresh errors in the UI.
    }
  }, []);

  useEffect(() => {
    loadEvents();
    const id = setInterval(loadEvents, 20000);
    return () => clearInterval(id);
  }, [loadEvents]);

  const parse = async () => {
    setParsing(true);
    setError(null);
    try {
      const res = await ocsfApi.parse(raw);
      setResult(res.data.ocsf);
      setParsed(res.data.parsed || null);
    } catch (e) {
      setError(e.response?.data?.error || e.message);
      setResult(null);
      setParsed(null);
    } finally {
      setParsing(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, minHeight: 'calc(100vh - 100px)' }}>
      <div>
        <h2 style={{ color: '#fff', margin: 0, fontSize: 18 }}>Global Device Log Parsing Engine</h2>
        <div style={{ color: 'var(--text3)', fontSize: 12, marginTop: 4 }}>
          Normalize Windows, Linux, AIX, firewall, WAF, email, and secure email gateway telemetry into one OCSF-aligned pipeline.
        </div>
      </div>

      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
          <StatCard label="Normalized Events" value={stats.total} color="var(--gold)" />
          <StatCard label="Supported Profiles" value={profiles.length} color="#68d391" />
          <StatCard label="Top OCSF Class" value={stats.byClass?.[0]?.ocsf_class_name || 'None'} color="#90cdf4" />
          <StatCard label="Top Parser" value={stats.byProfile?.[0]?.parser_product || 'None'} color="#b794f4" />
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: 12, minHeight: 360 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0 }}>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: 'var(--text3)' }}>Samples:</span>
            {Object.keys(SAMPLES).map((name) => (
              <button key={name} className="btn btn-secondary btn-sm" style={{ fontSize: 10 }} onClick={() => setRaw(SAMPLES[name])}>{name}</button>
            ))}
          </div>
          <textarea
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            placeholder="Paste raw device telemetry here..."
            style={{ flex: 1, minHeight: 280, fontFamily: 'monospace', fontSize: 12, padding: 10, background: 'var(--bg2)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 8, resize: 'vertical' }}
          />
          <button className="btn btn-primary" onClick={parse} disabled={parsing || !raw.trim()}>{parsing ? 'Parsing...' : 'Parse to OCSF'}</button>
          {error && <div style={{ color: '#fc8181', fontSize: 12 }}>{error}</div>}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>Detected Parser</div>
          <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 12 }}>
            {parsed ? (
              <>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
                  <span className="badge badge-blue">{parsed.parser?.profile_name}</span>
                  <span className="badge badge-gray">{parsed.parser?.vendor}</span>
                  <span className="badge badge-gray">{parsed.parser?.device_type}</span>
                  <span className="badge badge-purple">{parsed.index_name}</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 11 }}>
                  <div><span style={{ color: 'var(--text3)' }}>Source</span><div>{parsed.source || 'Unknown'}</div></div>
                  <div><span style={{ color: 'var(--text3)' }}>Event ID</span><div>{parsed.event_id || 'None'}</div></div>
                  <div><span style={{ color: 'var(--text3)' }}>Computer</span><div>{parsed.computer || 'None'}</div></div>
                  <div><span style={{ color: 'var(--text3)' }}>User</span><div>{parsed.username || 'None'}</div></div>
                  <div><span style={{ color: 'var(--text3)' }}>Source IP</span><div>{parsed.ip_address || 'None'}</div></div>
                  <div><span style={{ color: 'var(--text3)' }}>Destination IP</span><div>{parsed.dst_ip_address || 'None'}</div></div>
                </div>
                <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text2)', whiteSpace: 'pre-wrap' }}>{parsed.action || parsed.message || 'No action detected'}</div>
              </>
            ) : (
              <div style={{ color: 'var(--text3)', fontSize: 12 }}>Run a parse to see the selected parser profile and normalized fields.</div>
            )}
          </div>

          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>OCSF Output</div>
          {result ? (
            <div style={{ flex: 1, overflow: 'auto', background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 12 }}>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
                <CategoryBadge name={result.category_name} />
                <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700, background: 'var(--bg3)', color: 'var(--gold)' }}>{result.class_name}</span>
                <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700, background: 'var(--bg3)', color: 'var(--text2)' }}>{result.activity_name}</span>
                <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700, background: 'var(--bg3)', color: result.status === 'Failure' ? '#fc8181' : '#68d391' }}>{result.status}</span>
                <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700, background: 'var(--bg3)', color: 'var(--text2)' }}>{result.severity}</span>
              </div>
              <pre style={{ margin: 0, fontSize: 11.5, color: 'var(--text2)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{JSON.stringify(result, null, 2)}</pre>
            </div>
          ) : (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text3)', fontSize: 12, background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8 }}>
              Paste a log and run the parser to view normalized OCSF output.
            </div>
          )}
        </div>
      </div>

      <div style={{ background: 'var(--bg2)', borderRadius: 8, border: '1px solid var(--border)', padding: 12 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)', marginBottom: 10 }}>Supported Parser Profiles</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
          {profiles.map((profile) => <ProfileCard key={profile.id} profile={profile} />)}
        </div>
      </div>

      <div style={{ background: 'var(--bg2)', borderRadius: 8, border: '1px solid var(--border)', maxHeight: 240, overflow: 'auto' }}>
        <div style={{ padding: '8px 10px', fontSize: 12, fontWeight: 600, color: 'var(--text)', borderBottom: '1px solid var(--border)', position: 'sticky', top: 0, background: 'var(--bg2)' }}>
          Recently Auto-Normalized Events
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ background: 'var(--bg3)' }}>
              {['Time', 'Profile', 'OCSF Class', 'Source', 'Computer', 'User', 'Action'].map((header) => (
                <th key={header} style={{ padding: '6px 10px', textAlign: 'left', color: 'var(--text3)', fontWeight: 600, fontSize: 10 }}>{header}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: 16, textAlign: 'center', color: 'var(--text3)' }}>No normalized events yet. Ingested logs will appear here once the parser sees them.</td></tr>
            ) : events.map((event) => (
              <tr key={event.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '6px 10px', fontSize: 10, color: 'var(--text3)', whiteSpace: 'nowrap' }}>{new Date(event.timestamp).toLocaleString()}</td>
                <td style={{ padding: '6px 10px' }}><span className="badge badge-gray">{event.parser_profile || 'legacy'}</span></td>
                <td style={{ padding: '6px 10px', color: 'var(--gold)', fontWeight: 600 }}>{event.ocsf_class_name}</td>
                <td style={{ padding: '6px 10px', color: 'var(--text2)' }}>{event.source}</td>
                <td style={{ padding: '6px 10px', fontFamily: 'monospace', fontSize: 11 }}>{event.computer}</td>
                <td style={{ padding: '6px 10px', fontSize: 11 }}>{event.username}</td>
                <td style={{ padding: '6px 10px', fontSize: 11, color: 'var(--text2)' }}>{event.action}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
