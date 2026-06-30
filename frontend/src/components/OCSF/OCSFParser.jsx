import React, { useState, useEffect, useCallback } from 'react';
import { ocsfApi } from '../../services/api';

const SAMPLES = {
  'Windows Logon (EVTX JSON)': JSON.stringify({
    Event: {
      System: { EventID: { '$': '4624' }, Computer: 'WS-PC-001', TimeCreated: { '@SystemTime': new Date().toISOString() } },
      EventData: { TargetUserName: 'john.doe', IpAddress: '10.0.0.42' },
    },
  }, null, 2),
  'Linux SSH Auth (syslog text)': 'Jul  1 09:14:22 SRV-UBUNTU-01 sshd[2231]: Failed password for invalid user admin from 203.0.113.7 port 51422 ssh2',
  'CEF (network device)': 'CEF:0|PaloAlto|PAN-OS|11.1.3|THREAT|Port Scan Detected|8|src=198.51.100.20 dst=10.0.0.1 act=blocked',
  'Generic JSON': JSON.stringify({ timestamp: new Date().toISOString(), host: 'web-01', user: 'svc-deploy', action: 'Process Create', severity: 'Medium', message: 'launched /usr/bin/curl' }, null, 2),
};

const CATEGORY_COLOR = {
  'Identity & Access Management': '#90cdf4',
  'System Activity': '#b794f4',
  'Network Activity': '#68d391',
  'Findings': '#fc8181',
  'Uncategorized': 'var(--text3)',
};

function CategoryBadge({ name }) {
  const color = CATEGORY_COLOR[name] || 'var(--text3)';
  return <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700, background: `${color}22`, color }}>{name}</span>;
}

export default function OCSFParser() {
  const [raw, setRaw] = useState(SAMPLES['Windows Logon (EVTX JSON)']);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [parsing, setParsing] = useState(false);
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);

  const loadEvents = useCallback(async () => {
    try {
      const [sRes, eRes] = await Promise.all([ocsfApi.stats(), ocsfApi.events({ limit: 25 })]);
      setStats(sRes.data);
      setEvents(eRes.data.events || []);
    } catch (e) { /* ignore */ }
  }, []);

  useEffect(() => { loadEvents(); const id = setInterval(loadEvents, 20000); return () => clearInterval(id); }, [loadEvents]);

  const parse = async () => {
    setParsing(true); setError(null);
    try {
      const res = await ocsfApi.parse(raw);
      setResult(res.data.ocsf);
    } catch (e) {
      setError(e.response?.data?.error || e.message);
      setResult(null);
    } finally { setParsing(false); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: 'calc(100vh - 100px)' }}>
      <h2 style={{ color: '#fff', margin: 0, fontSize: 18 }}>
        🧬 OCSF Log Parser
        <span style={{ color: 'var(--text3)', fontSize: 12, fontWeight: 400, marginLeft: 8 }}>Auto-normalize any system log into the Open Cybersecurity Schema Framework</span>
      </h2>

      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
          <StatCard label="Normalized Events" value={stats.total} color="var(--gold)" />
          {stats.byClass.slice(0, 3).map(c => (
            <StatCard key={c.ocsf_class_uid} label={c.ocsf_class_name} value={c.cnt} color="#90cdf4" />
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: 12, flex: 1, minHeight: 0 }}>
        {/* Left: input */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0 }}>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: 'var(--text3)' }}>Samples:</span>
            {Object.keys(SAMPLES).map(name => (
              <button key={name} className="btn btn-secondary btn-sm" style={{ fontSize: 10 }} onClick={() => setRaw(SAMPLES[name])}>{name}</button>
            ))}
          </div>
          <textarea
            value={raw}
            onChange={e => setRaw(e.target.value)}
            placeholder="Paste any raw system log — Windows Event JSON, syslog/auth.log line, CEF, journald JSON, or generic JSON…"
            style={{ flex: 1, fontFamily: 'monospace', fontSize: 12, padding: 10, background: 'var(--bg2)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 8, resize: 'none' }}
          />
          <button className="btn btn-primary" onClick={parse} disabled={parsing || !raw.trim()}>{parsing ? 'Parsing…' : '⚡ Parse to OCSF'}</button>
          {error && <div style={{ color: '#fc8181', fontSize: 12 }}>{error}</div>}
        </div>

        {/* Right: OCSF output */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>OCSF Output</div>
          {result ? (
            <div style={{ flex: 1, overflow: 'auto', background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 12 }}>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
                <CategoryBadge name={result.category_name} />
                <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700, background: 'var(--bg3)', color: 'var(--gold)' }}>{result.class_name} (uid {result.class_uid})</span>
                <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700, background: 'var(--bg3)', color: 'var(--text2)' }}>{result.activity_name}</span>
                <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700, background: 'var(--bg3)', color: result.status === 'Failure' ? '#fc8181' : '#68d391' }}>{result.status}</span>
                <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700, background: 'var(--bg3)', color: 'var(--text2)' }}>{result.severity}</span>
              </div>
              <pre style={{ margin: 0, fontSize: 11.5, color: 'var(--text2)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{JSON.stringify(result, null, 2)}</pre>
            </div>
          ) : (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text3)', fontSize: 12, background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8 }}>
              Paste a log and click "Parse to OCSF" to see the normalized output.
            </div>
          )}
        </div>
      </div>

      {/* Recently auto-normalized events from the live ingestion pipeline */}
      <div style={{ background: 'var(--bg2)', borderRadius: 8, border: '1px solid var(--border)', maxHeight: 220, overflow: 'auto' }}>
        <div style={{ padding: '8px 10px', fontSize: 12, fontWeight: 600, color: 'var(--text)', borderBottom: '1px solid var(--border)', position: 'sticky', top: 0, background: 'var(--bg2)' }}>
          Recently Auto-Normalized Events (live ingestion)
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ background: 'var(--bg3)' }}>
              {['Time', 'OCSF Class', 'Category', 'Source', 'Computer', 'User', 'Action'].map(h => (
                <th key={h} style={{ padding: '6px 10px', textAlign: 'left', color: 'var(--text3)', fontWeight: 600, fontSize: 10 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: 16, textAlign: 'center', color: 'var(--text3)' }}>No normalized events yet. Ingested agent logs are auto-parsed into OCSF.</td></tr>
            ) : events.map(e => (
              <tr key={e.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '6px 10px', fontSize: 10, color: 'var(--text3)', whiteSpace: 'nowrap' }}>{new Date(e.timestamp).toLocaleString()}</td>
                <td style={{ padding: '6px 10px', color: 'var(--gold)', fontWeight: 600 }}>{e.ocsf_class_name}</td>
                <td style={{ padding: '6px 10px' }}><CategoryBadge name={e.ocsf_category_name} /></td>
                <td style={{ padding: '6px 10px', color: 'var(--text2)' }}>{e.source}</td>
                <td style={{ padding: '6px 10px', fontFamily: 'monospace', fontSize: 11 }}>{e.computer}</td>
                <td style={{ padding: '6px 10px', fontSize: 11 }}>{e.username}</td>
                <td style={{ padding: '6px 10px', fontSize: 11, color: 'var(--text2)' }}>{e.action}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div style={{ background: 'var(--bg2)', borderRadius: 8, padding: '12px 14px', border: '1px solid var(--border)' }}>
      <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700, color }}>{value ?? 0}</div>
    </div>
  );
}
