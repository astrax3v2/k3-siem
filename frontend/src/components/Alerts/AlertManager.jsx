import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { alertsApi, incidentsApi } from '../../services/api';

const SEV = { Critical: 'badge-red', High: 'badge-orange', Medium: 'badge-blue', Low: 'badge-green' };
const STA = { New: 'badge-red', 'In Progress': 'badge-orange', Assigned: 'badge-blue', Closed: 'badge-gray' };

export default function AlertManager({ liveAlerts }) {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(searchParams.get('id') || null);
  const [filters, setFilters] = useState({
    severity: searchParams.get('severity') || '',
    status: searchParams.get('status') || '',
    search: searchParams.get('search') || '',
    mitre_tactic: searchParams.get('tactic') || '',
  });
  const [updating, setUpdating] = useState(false);
  const [creatingIncident, setCreatingIncident] = useState(false);

  // Keep the URL in sync so filtered/selected views from dashboards are shareable and bookmarkable.
  useEffect(() => {
    const next = {};
    if (filters.severity) next.severity = filters.severity;
    if (filters.status) next.status = filters.status;
    if (filters.search) next.search = filters.search;
    if (filters.mitre_tactic) next.tactic = filters.mitre_tactic;
    if (selected) next.id = selected;
    setSearchParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters, selected]);

  const uniqueById = useCallback((items) => {
    const seen = new Set();
    const out = [];
    for (const it of items || []) {
      const id = it?.id;
      if (!id || seen.has(id)) continue;
      seen.add(id);
      out.push(it);
    }
    return out;
  }, []);

  const load = useCallback(() => {
    setLoading(true);
    alertsApi.list({ page, limit: 25, ...filters }).then(res => {
      setAlerts(uniqueById(res.data.alerts));
      setTotal(res.data.total);
      setPages(res.data.pages);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [page, filters, uniqueById]);

  useEffect(() => { load(); }, [load]);

  // Prepend live alerts that match the active filters — otherwise a filtered view
  // (e.g. severity=Critical from a dashboard link) gets polluted with unrelated live rows.
  useEffect(() => {
    if (liveAlerts.length > 0) {
      const matchesFilters = (a) =>
        (!filters.severity || a.severity === filters.severity) &&
        (!filters.status || a.status === filters.status) &&
        (!filters.mitre_tactic || a.mitre_tactic === filters.mitre_tactic) &&
        (!filters.search || `${a.title || ''} ${a.asset || ''} ${a.username || ''}`.toLowerCase().includes(filters.search.toLowerCase()));
      setAlerts(prev => {
        const ids = new Set(prev.map(a => a.id));
        const newOnes = uniqueById(liveAlerts).filter(a => !ids.has(a.id) && matchesFilters(a));
        return uniqueById([...newOnes, ...prev]);
      });
    }
  }, [liveAlerts, uniqueById, filters]);

  const updateAlert = async (id, data) => {
    setUpdating(true);
    try {
      const res = await alertsApi.update(id, data);
      setAlerts(prev => prev.map(a => a.id === id ? res.data : a));
      if (selected === id) setSelected(id);
    } finally { setUpdating(false); }
  };

  const detail = selected ? alerts.find(a => a.id === selected) : null;

  // Deep links from dashboards/widgets pass ?id=<alert> — fetch it directly if it isn't on the current filtered page.
  useEffect(() => {
    if (!selected || loading || detail) return;
    alertsApi.get(selected).then(res => {
      setAlerts(prev => uniqueById([res.data, ...prev]));
    }).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, loading, detail]);

  const activeFilterChips = [
    filters.severity && { key: 'severity', label: `Severity: ${filters.severity}` },
    filters.status && { key: 'status', label: `Status: ${filters.status}` },
    filters.mitre_tactic && { key: 'mitre_tactic', label: `Tactic: ${filters.mitre_tactic}` },
    filters.search && { key: 'search', label: `Search: "${filters.search}"` },
  ].filter(Boolean);
  const createIncidentFromAlert = async (alertId) => {
    if (!alertId) return;
    setCreatingIncident(true);
    try {
      const res = await incidentsApi.createFromAlert(alertId);
      navigate('/incidents', { state: { incidentId: res.data.id } });
    } finally { setCreatingIncident(false); }
  };

  const tableAlerts = uniqueById(alerts);

  return (
    <div style={{ display: 'flex', gap: 12, height: 'calc(100vh - 100px)' }}>
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
        {/* Filters */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          {['', 'Critical', 'High', 'Medium', 'Low'].map(s => (
            <button key={s} className={`btn btn-sm ${filters.severity === s ? 'btn-primary' : 'btn-secondary'}`} onClick={() => { setFilters(f => ({ ...f, severity: s })); setPage(1); }}>
              {s || 'All Severity'}
            </button>
          ))}
          <select value={filters.status} onChange={e => { setFilters(f => ({ ...f, status: e.target.value })); setPage(1); }} style={{ padding: '4px 8px', fontSize: 12 }}>
            <option value="">All Status</option>
            {['New', 'Assigned', 'In Progress', 'Closed'].map(s => <option key={s}>{s}</option>)}
          </select>
          <input placeholder="Search…" value={filters.search} onChange={e => { setFilters(f => ({ ...f, search: e.target.value })); setPage(1); }} style={{ width: 180, padding: '4px 10px', fontSize: 12 }} />
          <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text3)' }}>{total} alerts</span>
        </div>

        {activeFilterChips.length > 0 && (
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: 'var(--text3)' }}>Filtered from dashboard:</span>
            {activeFilterChips.map(c => (
              <span key={c.key} className="badge badge-blue" style={{ display: 'inline-flex', alignItems: 'center', gap: 5, cursor: 'pointer' }} onClick={() => { setFilters(f => ({ ...f, [c.key]: '' })); setPage(1); }}>
                {c.label} ✕
              </span>
            ))}
            <button className="btn btn-secondary btn-sm" onClick={() => { setFilters({ severity: '', status: '', search: '', mitre_tactic: '' }); setPage(1); }}>Clear all</button>
          </div>
        )}

        {/* Table */}
        <div className="card" style={{ flex: 1, overflow: 'auto', padding: 0 }}>
          {loading ? <div style={{ padding: 20, color: 'var(--text3)' }}>Loading…</div> : (
            <table>
              <thead><tr><th>ID</th><th>Sev</th><th>Title</th><th>Asset</th><th>Tactic</th><th>Score</th><th>Status</th><th>Time</th></tr></thead>
              <tbody>
                {tableAlerts.map((a, i) => (
                  <tr key={a.id ? `alert:${a.id}:${i}` : `alert:row:${i}`} onClick={() => setSelected(a.id === selected ? null : a.id)} style={{ cursor: 'pointer', background: selected === a.id ? 'rgba(245,166,35,.06)' : '' }}>
                    <td style={{ fontFamily: 'monospace', color: 'var(--gold)', fontSize: 11 }}>{a.id?.slice(0, 8)}</td>
                    <td><span className={`badge ${SEV[a.severity] || 'badge-gray'}`}>{a.severity}</span></td>
                    <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{a.asset}</td>
                    <td style={{ fontSize: 11, color: 'var(--text2)' }}>{a.mitre_tactic}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                        <div style={{ width: 36, height: 4, background: 'var(--bg4)', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ width: `${a.risk_score}%`, height: '100%', background: a.risk_score > 75 ? '#fc8181' : a.risk_score > 50 ? '#f6ad55' : '#68d391' }} />
                        </div>
                        <span style={{ fontSize: 10, color: 'var(--text3)' }}>{a.risk_score}</span>
                      </div>
                    </td>
                    <td><span className={`badge ${STA[a.status] || 'badge-gray'}`}>{a.status}</span></td>
                    <td style={{ fontSize: 10, color: 'var(--text3)', whiteSpace: 'nowrap' }}>{new Date(a.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        <div style={{ display: 'flex', gap: 6, justifyContent: 'center' }}>
          <button className="btn btn-secondary btn-sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
          <span style={{ fontSize: 12, color: 'var(--text3)', padding: '4px 8px' }}>Page {page} / {pages}</span>
          <button className="btn btn-secondary btn-sm" disabled={page >= pages} onClick={() => setPage(p => p + 1)}>Next →</button>
        </div>
      </div>

      {/* Detail panel */}
      {detail && (
        <div style={{ width: 300, flexShrink: 0 }}>
          <div className="card">
            <div className="card-title">Alert Detail</div>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>{detail.title}</div>
            {detail.description && <div style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 12, lineHeight: 1.5 }}>{detail.description}</div>}
            {[['ID', detail.id?.slice(0, 8)], ['Severity', detail.severity], ['Asset', detail.asset], ['Source', detail.source], ['MITRE Tactic', detail.mitre_tactic], ['Technique', detail.mitre_technique], ['Risk Score', `${detail.risk_score}/100`], ['Created', detail.created_at ? new Date(detail.created_at).toLocaleString() : '—']].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid rgba(30,58,110,.3)', fontSize: 12 }}>
                <span style={{ color: 'var(--text3)' }}>{k}</span>
                <span style={{ color: 'var(--text)', fontWeight: 500 }}>{v}</span>
              </div>
            ))}
            <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
              <button className="btn btn-primary btn-sm" disabled={creatingIncident} onClick={() => createIncidentFromAlert(detail.id)}>Create Incident</button>
              <button className="btn btn-secondary btn-sm" onClick={() => navigate('/incidents')}>Open Incidents</button>
            </div>
            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 6 }}>Update Status</div>
              <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                {['New', 'Assigned', 'In Progress', 'Closed'].map(s => (
                  <button key={s} className={`btn btn-sm ${detail.status === s ? 'btn-primary' : 'btn-secondary'}`} disabled={updating} onClick={() => updateAlert(detail.id, { status: s })}>
                    {s}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
