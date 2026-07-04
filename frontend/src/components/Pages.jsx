import React, { useEffect, useState, useCallback } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { eventsApi, correlationApi, intelApi, uebaApi, soarApi, incidentsApi } from '../services/api';
import { useAuth } from './Layout/Auth';

const SEV = { Critical: 'badge-red', High: 'badge-orange', Medium: 'badge-blue', Low: 'badge-green', Info: 'badge-gray' };

// ── Event Explorer ──────────────────────────────────────────────────────────
export function EventExplorer({ liveEvents }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({
    severity: searchParams.get('severity') || '',
    source: searchParams.get('source') || '',
    search: searchParams.get('search') || '',
    index: searchParams.get('index') || '',
  });

  // Keep the URL in sync so links from dashboard widgets (e.g. "view related events") are shareable.
  useEffect(() => {
    const next = {};
    if (filters.severity) next.severity = filters.severity;
    if (filters.source) next.source = filters.source;
    if (filters.search) next.search = filters.search;
    if (filters.index) next.index = filters.index;
    setSearchParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters]);

  const load = useCallback(() => {
    setLoading(true);
    eventsApi.list({ page, limit: 50, ...filters }).then(res => {
      setEvents(res.data.events);
      setTotal(res.data.total);
      setPages(res.data.pages);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [page, filters]);

  useEffect(() => { load(); }, [load]);

  const liveTop = liveEvents.slice(0, 10);
  const liveIds = new Set(liveTop.map(e => e.id).filter(Boolean));
  const mergedEvents = [...liveTop, ...events.filter(e => !liveIds.has(e.id))];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input placeholder="Search user, computer, IP, action…" value={filters.search} onChange={e => { setFilters(f => ({ ...f, search: e.target.value })); setPage(1); }} style={{ width: 240, padding: '5px 10px', fontSize: 12 }} />
        <select value={filters.severity} onChange={e => { setFilters(f => ({ ...f, severity: e.target.value })); setPage(1); }} style={{ padding: '5px 8px', fontSize: 12 }}>
          <option value="">All Severities</option>
          {['Critical', 'High', 'Medium', 'Low', 'Info'].map(s => <option key={s}>{s}</option>)}
        </select>
        <select value={filters.index} onChange={e => { setFilters(f => ({ ...f, index: e.target.value })); setPage(1); }} style={{ padding: '5px 8px', fontSize: 12 }}>
          <option value="">All Indices</option>
          {['windows-security', 'linux-syslog', 'network-flow', 'endpoint-edr', 'cloud-identity'].map(i => <option key={i}>{i}</option>)}
        </select>
        <button className="btn btn-secondary btn-sm" onClick={load}>🔄 Refresh</button>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text3)' }}>{total.toLocaleString()} events</span>
      </div>

      {liveEvents.length > 0 && (
        <div style={{ background: 'rgba(56,161,105,.1)', border: '1px solid rgba(56,161,105,.3)', borderRadius: 6, padding: '6px 12px', fontSize: 12, color: '#68d391', display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#68d391' }} />
          {liveEvents.length} new events streaming live
        </div>
      )}

      <div className="card" style={{ padding: 0, overflow: 'auto', maxHeight: 'calc(100vh - 220px)' }}>
        {loading ? <div style={{ padding: 20, color: 'var(--text3)' }}>Loading events…</div> : (
          <table>
            <thead style={{ position: 'sticky', top: 0, background: 'var(--bg2)', zIndex: 1 }}>
              <tr><th>Time</th><th>Index</th><th>Source</th><th>Event ID</th><th>Computer</th><th>User</th><th>Action</th><th>IP</th><th>Severity</th></tr>
            </thead>
            <tbody>
              {mergedEvents.map((e, i) => (
                <tr key={e.id ? `event:${e.id}:${i}` : `event:row:${i}`} style={{ background: i < liveTop.length ? 'rgba(56,161,105,.04)' : '' }}>
                  <td style={{ fontSize: 10, color: 'var(--text3)', whiteSpace: 'nowrap' }}>{new Date(e.timestamp).toLocaleString()}</td>
                  <td><span className="badge badge-gray" style={{ fontSize: 9 }}>{e.index_name}</span></td>
                  <td style={{ fontSize: 11, color: 'var(--text2)' }}>{e.source}</td>
                  <td style={{ fontFamily: 'monospace', color: 'var(--gold)', fontSize: 11 }}>{e.event_id}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{e.computer}</td>
                  <td style={{ fontSize: 12 }}>{e.username}</td>
                  <td style={{ fontSize: 11, color: 'var(--text2)' }}>{e.action}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{e.ip_address}</td>
                  <td><span className={`badge ${SEV[e.severity] || 'badge-gray'}`}>{e.severity}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div style={{ display: 'flex', gap: 6, justifyContent: 'center', alignItems: 'center' }}>
        <button className="btn btn-secondary btn-sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
        <span style={{ fontSize: 12, color: 'var(--text3)' }}>Page {page} / {pages}</span>
        <button className="btn btn-secondary btn-sm" disabled={page >= pages} onClick={() => setPage(p => p + 1)}>Next →</button>
      </div>
    </div>
  );
}

// ── Correlation Engine ──────────────────────────────────────────────────────
export function Correlation() {
  const { user } = useAuth();
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({ name: '', logic: '', severity: 'High', risk_score: 80, window_minutes: 5 });
  const canManage = user?.role === 'admin' || user?.role === 't2_analyst';

  useEffect(() => {
    correlationApi.rules().then(r => { setRules(r.data.rules); setLoading(false); });
  }, []);

  const toggle = async (rule) => {
    const res = await correlationApi.toggleRule(rule.id, !rule.enabled);
    setRules(prev => prev.map(r => r.id === rule.id ? res.data : r));
  };

  const createRule = async () => {
    if (!form.name || !form.logic) return;
    const res = await correlationApi.createRule({ ...form, indices: ['windows-security', 'network-flow'] });
    setRules(prev => [res.data, ...prev]);
    setShowNew(false);
    setForm({ name: '', logic: '', severity: 'High', risk_score: 80, window_minutes: 5 });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
        {[{ l: 'Active Rules', v: rules.filter(r => r.enabled).length, c: '#68d391' }, { l: 'Total Hits (All Time)', v: rules.reduce((s, r) => s + r.hit_count, 0), c: '#f6ad55' }, { l: 'Multi-Index Rules', v: rules.filter(r => { try { return JSON.parse(r.indices || '[]').length > 1; } catch { return false; } }).length, c: '#90cdf4' }].map(s => (
          <div key={s.l} className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 26, fontWeight: 700, color: s.c }}>{s.v}</div>
            <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 4 }}>{s.l}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>Multi-Index Correlation Rules</h3>
        {canManage && <button className="btn btn-primary btn-sm" onClick={() => setShowNew(s => !s)}>+ New Rule</button>}
      </div>

      {showNew && (
        <div className="card">
          <div className="card-title">Create Correlation Rule</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
            <input placeholder="Rule name" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} style={{ padding: '6px 10px' }} />
            <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))} style={{ padding: '6px 10px' }}>
              {['Critical', 'High', 'Medium', 'Low'].map(s => <option key={s}>{s}</option>)}
            </select>
          </div>
          <textarea placeholder="Correlation logic…" value={form.logic} onChange={e => setForm(f => ({ ...f, logic: e.target.value }))} rows={3} style={{ width: '100%', marginBottom: 10, padding: '6px 10px', fontFamily: 'Courier New', fontSize: 12 }} />
          <div style={{ display: 'flex', gap: 8 }}>
            <input type="number" placeholder="Risk score" value={form.risk_score} onChange={e => setForm(f => ({ ...f, risk_score: parseInt(e.target.value) }))} style={{ width: 100, padding: '5px 8px' }} />
            <input type="number" placeholder="Window (min)" value={form.window_minutes} onChange={e => setForm(f => ({ ...f, window_minutes: parseInt(e.target.value) }))} style={{ width: 120, padding: '5px 8px' }} />
            <button className="btn btn-primary btn-sm" onClick={createRule} disabled={!canManage}>Create Rule</button>
            <button className="btn btn-secondary btn-sm" onClick={() => setShowNew(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="card" style={{ padding: 0 }}>
        {loading ? <div style={{ padding: 20, color: 'var(--text3)' }}>Loading…</div> : (
          <table>
            <thead><tr><th>Name</th><th>Severity</th><th>Risk</th><th>Window</th><th>Indices</th><th>Hits</th><th>Enabled</th></tr></thead>
            <tbody>
              {rules.map((r, ri) => {
                let indices = [];
                try { indices = JSON.parse(r.indices || '[]'); } catch { }
                return (
                  <tr key={r.id ? `rule:${r.id}:${ri}` : `rule:row:${ri}`}>
                    <td>
                      <div style={{ fontWeight: 600, fontSize: 12 }}>{r.name}</div>
                      <div style={{ fontSize: 11, color: 'var(--text3)', marginTop: 2 }}>{r.logic}</div>
                    </td>
                    <td><span className={`badge ${SEV[r.severity] || 'badge-gray'}`}>{r.severity}</span></td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                        <div style={{ width: 40, height: 4, background: 'var(--bg4)', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ width: `${r.risk_score}%`, height: '100%', background: r.risk_score > 85 ? '#fc8181' : '#f6ad55' }} />
                        </div>
                        <span style={{ fontSize: 11, color: 'var(--text3)' }}>{r.risk_score}</span>
                      </div>
                    </td>
                    <td><span className="badge badge-blue">{r.window_minutes}m</span></td>
                    <td>{indices.map((idx, ii) => <span key={`${idx}:${ii}`} className="badge badge-gray" style={{ marginRight: 3, fontSize: 9 }}>{idx}</span>)}</td>
                    <td style={{ color: r.hit_count > 5 ? '#fc8181' : 'var(--text2)', fontWeight: r.hit_count > 5 ? 600 : 400 }}>{r.hit_count}</td>
                    <td>
                      <div onClick={canManage ? () => toggle(r) : undefined} style={{ width: 36, height: 18, borderRadius: 9, background: r.enabled ? '#38A169' : 'var(--bg4)', position: 'relative', cursor: canManage ? 'pointer' : 'not-allowed', transition: 'background .2s', border: '1px solid var(--border)', opacity: canManage ? 1 : 0.6 }}>
                        <div style={{ position: 'absolute', top: 2, left: r.enabled ? 18 : 2, width: 12, height: 12, borderRadius: '50%', background: '#fff', transition: 'left .2s' }} />
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ── Threat Intel ────────────────────────────────────────────────────────────
export function ThreatIntel() {
  const { user } = useAuth();
  const [iocs, setIocs] = useState([]);
  const [feeds, setFeeds] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ type: 'IP', value: '', confidence: 80, severity: 'High', source: 'Manual', description: '' });
  const canAdd = user?.role === 'admin' || user?.role === 't2_analyst';

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([intelApi.iocs({ type: typeFilter, limit: 50 }), intelApi.feeds()]).then(([i, f]) => {
      setIocs(i.data.iocs); setTotal(i.data.total); setFeeds(f.data.feeds); setLoading(false);
    });
  }, [typeFilter]);

  useEffect(() => { load(); }, [load]);

  const addIoc = async () => {
    if (!form.value) return;
    const res = await intelApi.createIoc(form);
    setIocs(prev => [res.data, ...prev]);
    setShowAdd(false);
  };

  return (
    <div style={{ display: 'flex', gap: 12 }}>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10 }}>
          {[{ l: 'Total IOCs', v: total, c: '#f6ad55' }, { l: 'Active Hits', v: iocs.reduce((s, i) => s + (i.hits || 0), 0), c: '#fc8181' }, { l: 'Intel Feeds', v: feeds.length, c: '#90cdf4' }, { l: 'Avg Confidence', v: iocs.length ? Math.round(iocs.reduce((s, i) => s + i.confidence, 0) / iocs.length) + '%' : '—', c: '#68d391' }].map(s => (
            <div key={s.l} className="card" style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 22, fontWeight: 700, color: s.c }}>{s.v}</div>
              <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 4 }}>{s.l}</div>
            </div>
          ))}
        </div>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {['', 'IP', 'Domain', 'Hash', 'URL', 'Email'].map(t => (
            <button key={t} className={`btn btn-sm ${typeFilter === t ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setTypeFilter(t)}>{t || 'All'}</button>
          ))}
          {canAdd && <button className="btn btn-primary btn-sm" style={{ marginLeft: 'auto' }} onClick={() => setShowAdd(s => !s)}>+ Add IOC</button>}
        </div>

        {showAdd && (
          <div className="card">
            <div className="card-title">Add New IOC</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8, marginBottom: 8 }}>
              <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))} style={{ padding: '6px 8px' }}>
                {['IP', 'Domain', 'Hash', 'URL', 'Email'].map(t => <option key={t}>{t}</option>)}
              </select>
              <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))} style={{ padding: '6px 8px' }}>
                {['Critical', 'High', 'Medium', 'Low'].map(s => <option key={s}>{s}</option>)}
              </select>
              <input type="number" min={0} max={100} placeholder="Confidence %" value={form.confidence} onChange={e => setForm(f => ({ ...f, confidence: parseInt(e.target.value) }))} style={{ padding: '6px 8px' }} />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8 }}>
              <input placeholder="IOC value (IP, domain, hash…)" value={form.value} onChange={e => setForm(f => ({ ...f, value: e.target.value }))} style={{ padding: '6px 10px' }} />
              <input placeholder="Source" value={form.source} onChange={e => setForm(f => ({ ...f, source: e.target.value }))} style={{ padding: '6px 10px' }} />
            </div>
            <input placeholder="Description" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} style={{ width: '100%', padding: '6px 10px', marginBottom: 8 }} />
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-primary btn-sm" onClick={addIoc}>Add IOC</button>
              <button className="btn btn-secondary btn-sm" onClick={() => setShowAdd(false)}>Cancel</button>
            </div>
          </div>
        )}

        <div className="card" style={{ padding: 0, overflow: 'auto' }}>
          {loading ? <div style={{ padding: 20, color: 'var(--text3)' }}>Loading…</div> : (
            <table>
              <thead><tr><th>Type</th><th>Indicator</th><th>Confidence</th><th>Severity</th><th>Hits</th><th>Source</th><th>First Seen</th></tr></thead>
              <tbody>
                {iocs.map((i, ii) => (
                  <tr key={i.id ? `ioc:${i.id}:${ii}` : `ioc:row:${ii}`}>
                    <td><span className="badge badge-blue">{i.type}</span></td>
                    <td style={{ fontFamily: 'monospace', fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{i.value}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                        <div style={{ width: 40, height: 4, background: 'var(--bg4)', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ width: `${i.confidence}%`, height: '100%', background: i.confidence > 80 ? '#68d391' : i.confidence > 60 ? '#f6ad55' : '#fc8181' }} />
                        </div>
                        <span style={{ fontSize: 10, color: 'var(--text3)' }}>{i.confidence}%</span>
                      </div>
                    </td>
                    <td><span className={`badge ${SEV[i.severity] || 'badge-gray'}`}>{i.severity}</span></td>
                    <td style={{ color: i.hits > 10 ? '#fc8181' : 'var(--text2)', fontWeight: i.hits > 10 ? 600 : 400 }}>{i.hits}</td>
                    <td style={{ fontSize: 11, color: 'var(--text2)' }}>{i.source}</td>
                    <td style={{ fontSize: 11, color: 'var(--text3)' }}>{new Date(i.first_seen).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Feed panel */}
      <div style={{ width: 220, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div className="card">
          <div className="card-title">📡 Feed Status</div>
          {feeds.map((f, fi) => (
            <div key={f.id ? `feed:${f.id}:${fi}` : `feed:row:${fi}`} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0', borderBottom: '1px solid rgba(30,58,110,.3)', fontSize: 12 }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: f.status === 'active' ? '#68d391' : '#fc8181', flexShrink: 0 }} />
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 500 }}>{f.name}</div>
                <div style={{ fontSize: 10, color: 'var(--text3)' }}>{f.ioc_count?.toLocaleString()} IOCs</div>
              </div>
            </div>
          ))}
        </div>
        <div className="card">
          <div className="card-title">🗺️ Threat Origins</div>
          {[['Russia', 42], ['China', 31], ['N. Korea', 18], ['Iran', 14], ['Anonymous', 9]].map(([c, p]) => (
            <div key={c} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 7, fontSize: 11 }}>
              <span style={{ width: 70, color: 'var(--text2)' }}>{c}</span>
              <div style={{ flex: 1, height: 5, background: 'var(--bg4)', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ width: `${p}%`, height: '100%', background: '#fc8181' }} />
              </div>
              <span style={{ color: 'var(--text3)', minWidth: 28, textAlign: 'right' }}>{p}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── UEBA ────────────────────────────────────────────────────────────────────
export function UEBA() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [sort, setSort] = useState('risk_score');

  useEffect(() => {
    uebaApi.scores().then(r => { setData(r.data); setLoading(false); });
  }, []);

  const scores = data ? [...data.scores].sort((a, b) => sort === 'name' ? a.username.localeCompare(b.username) : b[sort] - a[sort]) : [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 10 }}>
        {[{ l: 'High Risk Users', v: data?.highRisk ?? '—', c: '#fc8181' }, { l: 'Total Anomalies', v: data?.totalAnomalies ?? '—', c: '#f6ad55' }, { l: 'Users Monitored', v: data?.totalUsers ?? '—', c: '#90cdf4' }].map(s => (
          <div key={s.l} className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 26, fontWeight: 700, color: s.c }}>{s.v}</div>
            <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 4 }}>{s.l}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        <span style={{ fontSize: 12, color: 'var(--text2)' }}>Sort by:</span>
        {[['risk_score', 'Risk Score'], ['anomaly_count', 'Anomalies'], ['name', 'Name']].map(([k, l]) => (
          <button key={k} className={`btn btn-sm ${sort === k ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setSort(k)}>{l}</button>
        ))}
      </div>

      <div className="card" style={{ padding: 0 }}>
        {loading ? <div style={{ padding: 20, color: 'var(--text3)' }}>Loading…</div> : (
          <table>
            <thead><tr><th>User</th><th>Department</th><th>Risk Score</th><th>Anomalies</th><th>Flags</th><th>Location</th><th>Last Active</th></tr></thead>
            <tbody>
              {scores.map((u, ui) => {
                let flags = [];
                try { flags = JSON.parse(u.flags || '[]'); } catch { }
                return (
                  <tr key={u.id ? `ueba:${u.id}:${ui}` : `ueba:row:${ui}`}>
                    <td style={{ fontWeight: 500 }}>{u.username}</td>
                    <td style={{ color: 'var(--text2)', fontSize: 11 }}>{u.department}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{ width: 60, height: 5, background: 'var(--bg4)', borderRadius: 3, overflow: 'hidden' }}>
                          <div style={{ width: `${u.risk_score}%`, height: '100%', background: u.risk_score > 75 ? '#fc8181' : u.risk_score > 50 ? '#f6ad55' : '#68d391' }} />
                        </div>
                        <span style={{ fontSize: 12, fontWeight: 600, color: u.risk_score > 75 ? '#fc8181' : u.risk_score > 50 ? '#f6ad55' : '#68d391' }}>{u.risk_score}</span>
                      </div>
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      <span className={`badge ${u.anomaly_count > 4 ? 'badge-red' : u.anomaly_count > 2 ? 'badge-orange' : 'badge-gray'}`}>{u.anomaly_count}</span>
                    </td>
                    <td>{flags.map((f, fi) => <span key={`${f}:${fi}`} className="badge badge-orange" style={{ marginRight: 3, fontSize: 10 }}>{f}</span>)}</td>
                    <td style={{ fontSize: 11, color: 'var(--text2)' }}>{u.location}</td>
                    <td style={{ fontSize: 11, color: 'var(--text3)' }}>{u.last_activity ? new Date(u.last_activity).toLocaleTimeString() : '—'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <div className="card-title">🧠 ML Baseline Deviations</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          {[['Login Time Anomaly', 'Users logging in outside normal working hours — 3 accounts flagged'], ['Geo-Velocity', 'Geo-velocity anomaly detected: same account from HQ + Singapore within 2h'], ['Peer Group Deviation', 'File access patterns differ significantly from department peers — Engineering team'], ['Data Volume Spike', 'Download volume 4× above 30-day baseline — 1 user (ram.poudel)']].map(([t, d]) => (
            <div key={t} style={{ background: 'var(--bg4)', borderRadius: 6, padding: 10, borderLeft: '3px solid var(--gold)' }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 3 }}>{t}</div>
              <div style={{ fontSize: 11, color: 'var(--text2)' }}>{d}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── SOAR ────────────────────────────────────────────────────────────────────
export function SOAR() {
  const { user } = useAuth();
  const [data, setData] = useState({ playbooks: [], executions: [] });
  const [loading, setLoading] = useState(true);
  const [executing, setExecuting] = useState({});
  const [execStatus, setExecStatus] = useState({});
  const canExecute = user?.role === 'admin' || user?.role === 't2_analyst';

  useEffect(() => {
    soarApi.playbooks().then(r => { setData(r.data); setLoading(false); });
  }, []);

  const executePB = async (pb) => {
    if (pb.status !== 'Active') return;
    setExecuting(e => ({ ...e, [pb.id]: true }));
    try {
      const res = await soarApi.execute(pb.id, null);
      const execId = res.data.execution_id;
      // Poll for completion
      const poll = setInterval(async () => {
        const s = await soarApi.execution(execId);
        setExecStatus(e => ({ ...e, [pb.id]: s.data }));
        if (s.data.status === 'completed') {
          clearInterval(poll);
          setExecuting(e => ({ ...e, [pb.id]: false }));
          setData(d => ({ ...d, playbooks: d.playbooks.map(p => p.id === pb.id ? { ...p, execution_count: p.execution_count + 1 } : p) }));
        }
      }, 900);
    } catch { setExecuting(e => ({ ...e, [pb.id]: false })); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10 }}>
        {[{ l: 'Active Playbooks', v: data.playbooks.filter(p => p.status === 'Active').length, c: '#68d391' }, { l: 'Total Executions', v: data.playbooks.reduce((s, p) => s + p.execution_count, 0), c: 'var(--gold)' }, { l: 'Avg Response Time', v: '4.2s', c: '#90cdf4' }, { l: 'Recent Executions', v: data.executions.length, c: '#b794f4' }].map(s => (
          <div key={s.l} className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 22, fontWeight: 700, color: s.c }}>{s.v}</div>
            <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 4 }}>{s.l}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        {loading ? <div style={{ color: 'var(--text3)' }}>Loading…</div> : data.playbooks.map((pb, pbi) => {
          let steps = [];
          try { steps = JSON.parse(pb.steps || '[]'); } catch { }
          const exec = execStatus[pb.id];
          const isRunning = executing[pb.id];
          const progress = exec ? (exec.steps_completed / steps.length) * 100 : 0;

          return (
            <div key={pb.id ? `pb:${pb.id}:${pbi}` : `pb:row:${pbi}`} style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 8, padding: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <span style={{ fontSize: 13, fontWeight: 600 }}>{pb.name}</span>
                <span className={`badge ${pb.status === 'Active' ? 'badge-green' : 'badge-gray'}`}>{pb.status}</span>
                <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--gold)' }}>{pb.execution_count} runs</span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 8 }}>
                Trigger: <span style={{ color: 'var(--text2)' }}>{pb.trigger_condition}</span>
              </div>
              {isRunning && exec && (
                <div style={{ marginBottom: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text2)', marginBottom: 4 }}>
                    <span>Executing step {exec.steps_completed}/{steps.length}</span>
                    <span>{Math.round(progress)}%</span>
                  </div>
                  <div style={{ height: 4, background: 'var(--bg4)', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ width: `${progress}%`, height: '100%', background: 'var(--gold)', transition: 'width .5s' }} />
                  </div>
                </div>
              )}
              {exec?.status === 'completed' && (
                <div style={{ background: 'rgba(56,161,105,.1)', border: '1px solid rgba(56,161,105,.3)', borderRadius: 4, padding: '4px 8px', fontSize: 11, color: '#68d391', marginBottom: 8 }}>
                  ✓ {exec.result}
                </div>
              )}
              {steps.map((s, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', fontSize: 12, color: 'var(--text2)' }}>
                  <div style={{ width: 18, height: 18, background: exec && exec.steps_completed > i ? '#38A169' : 'var(--navy2)', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: exec && exec.steps_completed > i ? '#fff' : 'var(--gold)', flexShrink: 0 }}>
                    {exec && exec.steps_completed > i ? '✓' : i + 1}
                  </div>
                  <span>{s}</span>
                </div>
              ))}
              <div style={{ marginTop: 10, display: 'flex', gap: 6 }}>
                <button className={`btn btn-sm ${pb.status === 'Active' ? 'btn-primary' : 'btn-secondary'}`} disabled={!canExecute || isRunning || pb.status !== 'Active'} onClick={() => executePB(pb)}>
                  {isRunning ? '⏳ Running…' : '▶ Execute'}
                </button>
                <button className="btn btn-secondary btn-sm">Edit</button>
              </div>
            </div>
          );
        })}
      </div>

      <div className="card">
        <div className="card-title">🔗 Integration Connectors</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 8 }}>
          {[['Jira', 'Ticket creation', 'badge-blue'], ['Slack', 'SOC notifications', 'badge-purple'], ['CrowdStrike', 'Endpoint isolation', 'badge-orange'], ['Palo Alto', 'Firewall block', 'badge-red'], ['ServiceNow', 'ITSM incidents', 'badge-blue'], ['MS Teams', 'Notifications', 'badge-blue'], ['MISP', 'IOC sharing', 'badge-green'], ['Email', 'Analyst alerts', 'badge-gray']].map(([n, d, b]) => (
            <div key={n} style={{ background: 'var(--bg4)', borderRadius: 6, padding: '8px 10px', textAlign: 'center' }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 2 }}>{n}</div>
              <div style={{ fontSize: 10, color: 'var(--text3)', marginBottom: 5 }}>{d}</div>
              <span className={`badge ${b}`} style={{ fontSize: 9 }}>Connected</span>
            </div>
          ))}
        </div>
      </div>

      {data.executions.length > 0 && (
        <div className="card">
          <div className="card-title">📋 Execution History</div>
          <table>
            <thead><tr><th>Playbook</th><th>Triggered By</th><th>Status</th><th>Steps</th><th>Started</th><th>Completed</th></tr></thead>
            <tbody>
              {data.executions.map((e, ei) => (
                <tr key={e.id ? `exec:${e.id}:${ei}` : `exec:row:${ei}`}>
                  <td style={{ fontSize: 11 }}>{e.playbook_id?.slice(0, 8)}</td>
                  <td style={{ fontSize: 11, color: 'var(--text2)' }}>{e.triggered_by}</td>
                  <td><span className={`badge ${e.status === 'completed' ? 'badge-green' : e.status === 'running' ? 'badge-orange' : 'badge-gray'}`}>{e.status}</span></td>
                  <td style={{ fontSize: 11 }}>{e.steps_completed}</td>
                  <td style={{ fontSize: 11, color: 'var(--text3)' }}>{new Date(e.started_at).toLocaleTimeString()}</td>
                  <td style={{ fontSize: 11, color: 'var(--text3)' }}>{e.completed_at ? new Date(e.completed_at).toLocaleTimeString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function IncidentResponse() {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [incidents, setIncidents] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({
    status: searchParams.get('status') || '',
    severity: searchParams.get('severity') || '',
    search: searchParams.get('search') || '',
  });
  const [selectedId, setSelectedId] = useState(searchParams.get('id') || null);
  const [detail, setDetail] = useState(null);
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [createForm, setCreateForm] = useState({ title: '', description: '', severity: 'High', priority: 2 });

  // Keep the URL in sync so filtered/selected views from dashboards are shareable and bookmarkable.
  useEffect(() => {
    const next = {};
    if (filters.status) next.status = filters.status;
    if (filters.severity) next.severity = filters.severity;
    if (filters.search) next.search = filters.search;
    if (selectedId) next.id = selectedId;
    setSearchParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters, selectedId]);

  const activeFilterChips = [
    filters.severity && { key: 'severity', label: `Severity: ${filters.severity}` },
    filters.status && { key: 'status', label: `Status: ${filters.status}` },
    filters.search && { key: 'search', label: `Search: "${filters.search}"` },
  ].filter(Boolean);

  const load = useCallback(() => {
    setLoading(true);
    incidentsApi.list({ page, limit: 25, ...filters }).then(res => {
      setIncidents(res.data.incidents || []);
      setTotal(res.data.total || 0);
      setPages(res.data.pages || 1);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [page, filters]);

  const loadDetail = useCallback((id) => {
    if (!id) { setDetail(null); return; }
    incidentsApi.get(id).then(res => setDetail(res.data)).catch(() => setDetail(null));
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadDetail(selectedId); }, [selectedId, loadDetail]);
  useEffect(() => {
    const incId = location.state?.incidentId;
    if (incId) setSelectedId(incId);
  }, [location.state]);

  const statuses = ['Open', 'In Progress', 'Contained', 'Eradicated', 'Recovered', 'Closed'];

  const updateIncident = async (id, data) => {
    if (!id) return;
    setSaving(true);
    try {
      await incidentsApi.update(id, data);
      await Promise.all([load(), loadDetail(id)]);
    } finally { setSaving(false); }
  };

  const addNote = async () => {
    if (!selectedId || !note.trim()) return;
    setSaving(true);
    try {
      await incidentsApi.addNote(selectedId, note.trim());
      setNote('');
      await loadDetail(selectedId);
      await load();
    } finally { setSaving(false); }
  };

  const createIncident = async () => {
    if (!createForm.title.trim()) return;
    setSaving(true);
    try {
      const res = await incidentsApi.create({ ...createForm });
      setShowCreate(false);
      setCreateForm({ title: '', description: '', severity: 'High', priority: 2 });
      setSelectedId(res.data.id);
      await load();
    } finally { setSaving(false); }
  };

  const inc = detail?.incident;
  const linkedAlerts = detail?.alerts || [];
  const notes = detail?.notes || [];

  return (
    <div style={{ display: 'flex', gap: 12, height: 'calc(100vh - 100px)' }}>
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <select value={filters.status} onChange={e => { setFilters(f => ({ ...f, status: e.target.value })); setPage(1); }} style={{ padding: '4px 8px', fontSize: 12 }}>
            <option value="">All Status</option>
            {statuses.map(s => <option key={s}>{s}</option>)}
          </select>
          <select value={filters.severity} onChange={e => { setFilters(f => ({ ...f, severity: e.target.value })); setPage(1); }} style={{ padding: '4px 8px', fontSize: 12 }}>
            <option value="">All Severity</option>
            {['Critical', 'High', 'Medium', 'Low'].map(s => <option key={s}>{s}</option>)}
          </select>
          <input placeholder="Search incidents…" value={filters.search} onChange={e => { setFilters(f => ({ ...f, search: e.target.value })); setPage(1); }} style={{ width: 220, padding: '4px 10px', fontSize: 12 }} />
          <button className="btn btn-secondary btn-sm" onClick={load}>🔄 Refresh</button>
          <button className="btn btn-primary btn-sm" style={{ marginLeft: 'auto' }} onClick={() => setShowCreate(s => !s)}>+ New Incident</button>
          <span style={{ fontSize: 11, color: 'var(--text3)' }}>{total} incidents</span>
        </div>

        {activeFilterChips.length > 0 && (
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: 'var(--text3)' }}>Filtered from dashboard:</span>
            {activeFilterChips.map(c => (
              <span key={c.key} className="badge badge-blue" style={{ display: 'inline-flex', alignItems: 'center', gap: 5, cursor: 'pointer' }} onClick={() => { setFilters(f => ({ ...f, [c.key]: '' })); setPage(1); }}>
                {c.label} ✕
              </span>
            ))}
            <button className="btn btn-secondary btn-sm" onClick={() => { setFilters({ status: '', severity: '', search: '' }); setPage(1); }}>Clear all</button>
          </div>
        )}

        {showCreate && (
          <div className="card">
            <div className="card-title">Create Incident</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 160px 120px', gap: 8, marginBottom: 8 }}>
              <input placeholder="Incident title" value={createForm.title} onChange={e => setCreateForm(f => ({ ...f, title: e.target.value }))} style={{ padding: '6px 10px' }} />
              <select value={createForm.severity} onChange={e => setCreateForm(f => ({ ...f, severity: e.target.value }))} style={{ padding: '6px 10px' }}>
                {['Critical', 'High', 'Medium', 'Low'].map(s => <option key={s}>{s}</option>)}
              </select>
              <select value={createForm.priority} onChange={e => setCreateForm(f => ({ ...f, priority: parseInt(e.target.value) }))} style={{ padding: '6px 10px' }}>
                {[1, 2, 3, 4].map(p => <option key={p} value={p}>P{p}</option>)}
              </select>
            </div>
            <textarea placeholder="Description / initial triage notes…" value={createForm.description} onChange={e => setCreateForm(f => ({ ...f, description: e.target.value }))} rows={3} style={{ width: '100%', padding: '6px 10px', marginBottom: 8 }} />
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-primary btn-sm" disabled={saving} onClick={createIncident}>Create</button>
              <button className="btn btn-secondary btn-sm" onClick={() => setShowCreate(false)}>Cancel</button>
            </div>
          </div>
        )}

        <div className="card" style={{ flex: 1, overflow: 'auto', padding: 0 }}>
          {loading ? <div style={{ padding: 20, color: 'var(--text3)' }}>Loading…</div> : (
            <table>
              <thead><tr><th>Sev</th><th>Title</th><th>Status</th><th>Owner</th><th>Alerts</th><th>Notes</th><th>Created</th></tr></thead>
              <tbody>
                {incidents.map((i, idx) => (
                  <tr
                    key={i.id ? `inc:${i.id}:${idx}` : `inc:row:${idx}`}
                    onClick={() => setSelectedId(i.id === selectedId ? null : i.id)}
                    style={{ cursor: 'pointer', background: selectedId === i.id ? 'rgba(245,166,35,.06)' : '' }}
                  >
                    <td><span className={`badge ${SEV[i.severity] || 'badge-gray'}`}>{i.severity}</span></td>
                    <td style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{i.title}</td>
                    <td><span className="badge badge-gray">{i.status}</span></td>
                    <td style={{ fontSize: 11, color: 'var(--text2)' }}>{i.owner || '—'}</td>
                    <td style={{ textAlign: 'center', fontSize: 11 }}>{i.alerts_count ?? 0}</td>
                    <td style={{ textAlign: 'center', fontSize: 11 }}>{i.notes_count ?? 0}</td>
                    <td style={{ fontSize: 10, color: 'var(--text3)', whiteSpace: 'nowrap' }}>{new Date(i.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div style={{ display: 'flex', gap: 6, justifyContent: 'center' }}>
          <button className="btn btn-secondary btn-sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
          <span style={{ fontSize: 12, color: 'var(--text3)', padding: '4px 8px' }}>Page {page} / {pages}</span>
          <button className="btn btn-secondary btn-sm" disabled={page >= pages} onClick={() => setPage(p => p + 1)}>Next →</button>
        </div>
      </div>

      {inc && (
        <div style={{ width: 340, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div className="card">
            <div className="card-title">Incident Detail</div>
            <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 8 }}>{inc.title}</div>
            {inc.description && <div style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 10, lineHeight: 1.5 }}>{inc.description}</div>}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 12 }}>
              <div><span style={{ color: 'var(--text3)' }}>Severity</span><div><span className={`badge ${SEV[inc.severity] || 'badge-gray'}`}>{inc.severity}</span></div></div>
              <div><span style={{ color: 'var(--text3)' }}>Priority</span><div style={{ fontWeight: 600 }}>P{inc.priority}</div></div>
              <div><span style={{ color: 'var(--text3)' }}>Status</span><div style={{ fontWeight: 600 }}>{inc.status}</div></div>
              <div><span style={{ color: 'var(--text3)' }}>Owner</span><div style={{ fontWeight: 600 }}>{inc.owner || '—'}</div></div>
            </div>

            {detail?.process_tree?.length > 0 && (
              <button className="btn btn-primary btn-sm" style={{ width: '100%', marginTop: 10 }} onClick={() => navigate(`/investigation/${inc.id}`)}>
                🌳 View Process Tree ({detail.process_tree.length} stages)
              </button>
            )}

            <div style={{ marginTop: 10 }}>
              <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 6 }}>Update Status</div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {statuses.map(s => (
                  <button key={s} className={`btn btn-sm ${inc.status === s ? 'btn-primary' : 'btn-secondary'}`} disabled={saving} onClick={() => updateIncident(inc.id, { status: s })}>
                    {s}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="card" style={{ padding: 0, overflow: 'auto', maxHeight: 220 }}>
            <div style={{ padding: 12, borderBottom: '1px solid var(--border)' }}>
              <div className="card-title" style={{ margin: 0 }}>Linked Alerts</div>
            </div>
            <table>
              <thead><tr><th>Sev</th><th>Title</th></tr></thead>
              <tbody>
                {linkedAlerts.length === 0 ? (
                  <tr><td colSpan={2} style={{ padding: 12, color: 'var(--text3)' }}>No alerts linked</td></tr>
                ) : linkedAlerts.map((a, ai) => (
                  <tr key={a.id ? `incalert:${a.id}:${ai}` : `incalert:row:${ai}`}>
                    <td><span className={`badge ${SEV[a.severity] || 'badge-gray'}`}>{a.severity}</span></td>
                    <td style={{ fontSize: 11, color: 'var(--text2)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div className="card-title">Notes</div>
            <div style={{ display: 'flex', gap: 6 }}>
              <input value={note} onChange={e => setNote(e.target.value)} placeholder="Add a note…" style={{ flex: 1, padding: '6px 10px', fontSize: 12 }} />
              <button className="btn btn-primary btn-sm" disabled={saving} onClick={addNote}>Add</button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 260, overflow: 'auto' }}>
              {notes.length === 0 ? (
                <div style={{ color: 'var(--text3)', fontSize: 12 }}>No notes yet</div>
              ) : notes.map((n, ni) => (
                <div key={n.id ? `note:${n.id}:${ni}` : `note:row:${ni}`} style={{ background: 'var(--bg4)', borderRadius: 6, padding: '8px 10px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
                    <span style={{ fontSize: 11, color: 'var(--gold)', fontWeight: 600 }}>{n.author || 'analyst'}</span>
                    <span style={{ fontSize: 10, color: 'var(--text3)' }}>{new Date(n.created_at).toLocaleString()}</span>
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text2)', whiteSpace: 'pre-wrap' }}>{n.note}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
