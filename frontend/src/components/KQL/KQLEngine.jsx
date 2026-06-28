import React, { useEffect, useState } from 'react';
import { kqlApi } from '../../services/api';

const SAMPLES = [
  { name: 'Brute Force Detection', category: 'Auth', query: `SecurityEvent\n| where event_id == "4625"\n| where timestamp > datetime_ago("5m")\n| where username != "SYSTEM"\n| order by timestamp desc` },
  { name: 'Suspicious PowerShell', category: 'Execution', query: `SecurityEvent\n| where event_id == "4688"\n| where action has_any ("PowerShell","bypass","encoded","hidden")\n| project timestamp, computer, username, action\n| order by timestamp desc` },
  { name: 'Privilege Escalation', category: 'PrivEsc', query: `SecurityEvent\n| where event_id == "4672"\n| where username != "SYSTEM"\n| order by timestamp desc` },
  { name: 'All Critical Events', category: 'Investigation', query: `SecurityEvent\n| where severity == "Critical"\n| order by timestamp desc` },
  { name: 'Top 10 Events', category: 'Baseline', query: `SecurityEvent\n| top 10` },
];

const SEV = { Critical: 'badge-red', High: 'badge-orange', Medium: 'badge-blue', Low: 'badge-green', Info: 'badge-gray' };

export default function KQLEngine() {
  const [query, setQuery] = useState(SAMPLES[0].query);
  const [results, setResults] = useState([]);
  const [savedQueries, setSavedQueries] = useState([]);
  const [tab, setTab] = useState('editor');
  const [running, setRunning] = useState(false);
  const [execInfo, setExecInfo] = useState(null);
  const [saveForm, setSaveForm] = useState({ show: false, name: '', category: '' });
  const [error, setError] = useState('');

  useEffect(() => {
    kqlApi.queries().then(r => setSavedQueries(r.data.queries));
  }, []);

  const runQuery = async () => {
    setRunning(true); setError(''); setResults([]);
    try {
      const res = await kqlApi.run(query);
      setResults(res.data.results || []);
      setExecInfo({ ms: res.data.execution_ms, total: res.data.total });
      setTab('results');
    } catch (e) {
      setError(e.response?.data?.error || 'Query failed');
    } finally { setRunning(false); }
  };

  const saveQuery = async () => {
    if (!saveForm.name) return;
    try {
      const res = await kqlApi.save({ name: saveForm.name, query, category: saveForm.category, is_rule: 0 });
      setSavedQueries(prev => [res.data, ...prev]);
      setSaveForm({ show: false, name: '', category: '' });
    } catch (e) { setError('Save failed'); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--border)', paddingBottom: 0, marginBottom: 4 }}>
        {['editor', 'results', 'saved'].map(t => (
          <button key={t} onClick={() => setTab(t)} style={{ padding: '7px 16px', background: 'none', border: 'none', cursor: 'pointer', color: tab === t ? 'var(--gold)' : 'var(--text2)', borderBottom: `2px solid ${tab === t ? 'var(--gold)' : 'transparent'}`, fontSize: 12, fontWeight: 500, marginBottom: -1 }}>
            {t.charAt(0).toUpperCase() + t.slice(1)}{t === 'results' && execInfo ? ` (${execInfo.total})` : ''}
          </button>
        ))}
      </div>

      {tab === 'editor' && (
        <>
          <div className="card">
            <div className="card-title">🔍 KQL Query Editor</div>
            <div style={{ display: 'flex', gap: 6, marginBottom: 8, flexWrap: 'wrap' }}>
              {SAMPLES.map(s => (
                <button key={s.name} className="btn btn-secondary btn-sm" onClick={() => setQuery(s.query)}>
                  {s.name}
                </button>
              ))}
            </div>
            <textarea
              value={query}
              onChange={e => setQuery(e.target.value)}
              rows={7}
              spellCheck={false}
              style={{ width: '100%', fontFamily: 'Courier New, monospace', fontSize: 12, background: '#0d1117', border: '1px solid var(--border2)', borderRadius: 6, color: '#e2e8f0', padding: '10px 12px', resize: 'vertical', outline: 'none' }}
            />
            {error && <div style={{ color: '#fc8181', fontSize: 12, marginTop: 6 }}>⚠ {error}</div>}
            <div style={{ display: 'flex', gap: 8, marginTop: 10, alignItems: 'center' }}>
              <button className="btn btn-primary" onClick={runQuery} disabled={running}>
                {running ? '⏳ Running…' : '▶ Run Query'}
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => setSaveForm({ show: true, name: '', category: '' })}>💾 Save</button>
              <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text3)' }}>
                {execInfo ? `Last run: ${execInfo.ms}ms · ${execInfo.total} rows` : 'Time range: Last 24h'}
              </span>
            </div>
            {saveForm.show && (
              <div style={{ marginTop: 10, display: 'flex', gap: 8, alignItems: 'center' }}>
                <input placeholder="Query name" value={saveForm.name} onChange={e => setSaveForm(f => ({ ...f, name: e.target.value }))} style={{ flex: 1, padding: '5px 10px', fontSize: 12 }} />
                <input placeholder="Category" value={saveForm.category} onChange={e => setSaveForm(f => ({ ...f, category: e.target.value }))} style={{ width: 120, padding: '5px 10px', fontSize: 12 }} />
                <button className="btn btn-primary btn-sm" onClick={saveQuery}>Save</button>
                <button className="btn btn-secondary btn-sm" onClick={() => setSaveForm({ show: false, name: '', category: '' })}>Cancel</button>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-title">📚 KQL Quick Reference</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              {[
                ['Pipe Operators', '| where · | summarize · | extend · | project · | order by · | top · | join · | distinct'],
                ['Time Filters', 'timestamp > datetime_ago("1h")\ntimestamp > datetime_ago("5m")\ntimestamp > datetime_ago("7d")'],
                ['String Operators', 'has_any ("a","b") · contains "str"\nstartswith "prefix" · == "exact"\n!= "not equal"'],
                ['Aggregations', 'count() · sum(field) · avg(field)\nmax(field) · min(field)\ndcount(field) — distinct count'],
              ].map(([t, c]) => (
                <div key={t} style={{ background: 'var(--bg4)', borderRadius: 6, padding: '8px 10px' }}>
                  <div style={{ fontSize: 11, color: 'var(--gold)', fontWeight: 600, marginBottom: 4 }}>{t}</div>
                  <pre style={{ fontSize: 11, color: 'var(--text2)', whiteSpace: 'pre-wrap', fontFamily: 'Courier New, monospace', lineHeight: 1.6 }}>{c}</pre>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {tab === 'results' && (
        <div className="card">
          <div className="card-title">
            Query Results
            {execInfo && <span style={{ marginLeft: 8, fontSize: 11, color: 'var(--text3)', fontWeight: 400 }}>{execInfo.total} rows · {execInfo.ms}ms</span>}
          </div>
          {results.length === 0 ? (
            <div style={{ color: 'var(--text3)', padding: 12 }}>No results. Run a query first.</div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    {['timestamp', 'source', 'event_id', 'computer', 'username', 'action', 'ip_address', 'severity'].map(k => (
                      <th key={k}>{k}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {results.map((r, i) => (
                    <tr key={i}>
                      <td style={{ fontSize: 10, color: 'var(--text3)', whiteSpace: 'nowrap' }}>{new Date(r.timestamp).toLocaleString()}</td>
                      <td style={{ fontSize: 11, color: 'var(--text2)' }}>{r.source}</td>
                      <td style={{ fontFamily: 'monospace', color: 'var(--gold)', fontSize: 11 }}>{r.event_id}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{r.computer}</td>
                      <td style={{ fontSize: 12 }}>{r.username}</td>
                      <td style={{ fontSize: 11, color: 'var(--text2)' }}>{r.action}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{r.ip_address}</td>
                      <td><span className={`badge ${SEV[r.severity] || 'badge-gray'}`}>{r.severity}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'saved' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {savedQueries.map((q, i) => (
            <div key={q.id ? `kql:${q.id}:${i}` : `kql:row:${i}`} style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <span style={{ fontSize: 13, fontWeight: 600 }}>{q.name}</span>
                {q.category && <span className="badge badge-blue">{q.category}</span>}
                {q.is_rule ? <span className="badge badge-green">Detection Rule</span> : <span className="badge badge-gray">Query</span>}
                <button className="btn btn-secondary btn-sm" style={{ marginLeft: 'auto' }} onClick={() => { setQuery(q.query); setTab('editor'); }}>Load</button>
                <button className="btn btn-primary btn-sm" onClick={() => { setQuery(q.query); runQuery(); }}>▶ Run</button>
              </div>
              <pre style={{ fontSize: 11, color: 'var(--text2)', fontFamily: 'Courier New, monospace', whiteSpace: 'pre-wrap', lineHeight: 1.6, background: 'var(--bg4)', borderRadius: 4, padding: '8px 10px' }}>{q.query}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
