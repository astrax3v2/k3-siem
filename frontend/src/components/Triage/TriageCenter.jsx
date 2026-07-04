import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { alertsApi, incidentsApi, eventsApi, soarApi, teamsApi } from '../../services/api';
import { useAuth } from '../Layout/Auth';

const SEV_BADGE = { Critical: 'badge-red', High: 'badge-orange', Medium: 'badge-blue', Low: 'badge-green', Info: 'badge-gray' };
const SEV_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
const ALERT_STATUSES = ['New', 'Assigned', 'In Progress', 'Closed'];
const INCIDENT_STATUSES = ['Open', 'In Progress', 'Contained', 'Eradicated', 'Recovered', 'Closed'];

function uniqueByKey(items) {
  const seen = new Set();
  const out = [];
  for (const it of items) {
    const key = `${it.kind}:${it.id}`;
    if (!it.id || seen.has(key)) continue;
    seen.add(key);
    out.push(it);
  }
  return out;
}

function toQueueItem(kind, row) {
  // Live WebSocket-pushed alerts don't carry created_at (same gap Dashboard.jsx's
  // live feed already works around) — fall back to "now" rather than showing blank age.
  const createdAt = row.created_at || new Date().toISOString();
  if (kind === 'alert') {
    return { kind, id: row.id, severity: row.severity, title: row.title, subtitle: row.asset || '—', status: row.status, score: row.risk_score ?? 0, created_at: createdAt, sla: row.sla, raw: row };
  }
  return { kind, id: row.id, severity: row.severity, title: row.title, subtitle: row.owner ? `Owner: ${row.owner}` : 'Unassigned', status: row.status, score: (5 - (row.priority || 3)) * 20, created_at: createdAt, sla: row.sla, raw: row };
}

function isBreached(sla) {
  return !!sla && (sla.ack_breached || sla.resolve_breached);
}

function formatDuration(minutes) {
  if (minutes == null) return '—';
  if (minutes < 60) return `${Math.round(minutes)}m`;
  const hours = minutes / 60;
  if (hours < 48) return `${hours.toFixed(1)}h`;
  return `${(hours / 24).toFixed(1)}d`;
}

function SlaRow({ label, elapsedMinutes, targetMinutes, done, breached }) {
  const color = breached ? '#fc8181' : done ? '#68d391' : 'var(--text2)';
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0', fontSize: 12 }}>
      <span style={{ color: 'var(--text3)' }}>{label}</span>
      <span style={{ color, fontWeight: 600 }}>
        {formatDuration(elapsedMinutes)} / {formatDuration(targetMinutes)} target
        {breached && ' ⚠ Breached'}
        {!breached && done && ' ✓'}
      </span>
    </div>
  );
}

function sortQueue(items) {
  return [...items].sort((a, b) =>
    (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0) ||
    new Date(b.created_at) - new Date(a.created_at)
  );
}

export default function TriageCenter({ liveAlerts }) {
  const navigate = useNavigate();
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const canRunPlaybooks = isAdmin || user?.role === 't2_analyst';

  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [teams, setTeams] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ severity: '', kind: '', search: '', breachedOnly: false });
  const [selected, setSelected] = useState(null); // { kind, id }
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [relatedEvents, setRelatedEvents] = useState([]);
  const [busy, setBusy] = useState(false);
  const [playbooks, setPlaybooks] = useState([]);
  const [triggered, setTriggered] = useState({});

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      alertsApi.list({ limit: 100 }),
      incidentsApi.list({ limit: 100 }),
    ]).then(([a, i]) => {
      setAlerts(a.data.alerts || []);
      setIncidents(i.data.incidents || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { soarApi.playbooks().then(r => setPlaybooks((r.data.playbooks || []).filter(p => p.status === 'Active'))).catch(() => {}); }, []);
  useEffect(() => { if (isAdmin) teamsApi.list().then(r => setTeams(r.data.teams || [])).catch(() => {}); }, [isAdmin]);

  const queue = useMemo(() => {
    const base = [
      ...alerts.filter(a => a.status !== 'Closed').map(a => toQueueItem('alert', a)),
      ...incidents.filter(i => i.status !== 'Closed').map(i => toQueueItem('incident', i)),
    ];
    const live = uniqueByKey((liveAlerts || []).map(a => toQueueItem('alert', a)));
    const existingKeys = new Set(base.map(it => `${it.kind}:${it.id}`));
    const newLive = live.filter(it => !existingKeys.has(`${it.kind}:${it.id}`));
    let merged = sortQueue([...newLive, ...base]);

    if (filters.kind) merged = merged.filter(it => it.kind === filters.kind);
    if (filters.severity) merged = merged.filter(it => it.severity === filters.severity);
    if (filters.breachedOnly) merged = merged.filter(it => isBreached(it.sla));
    if (filters.search) {
      const s = filters.search.toLowerCase();
      merged = merged.filter(it => (it.title || '').toLowerCase().includes(s) || (it.subtitle || '').toLowerCase().includes(s));
    }
    return merged;
  }, [alerts, incidents, liveAlerts, filters]);

  // Auto-select the top of the queue so the analyst lands ready to work.
  useEffect(() => {
    if (!selected && queue.length > 0) setSelected({ kind: queue[0].kind, id: queue[0].id });
  }, [queue, selected]);

  const selectedAlert = selected?.kind === 'alert' ? alerts.find(a => a.id === selected.id) || queue.find(it => it.kind === 'alert' && it.id === selected.id)?.raw : null;

  useEffect(() => {
    if (!selected) { setIncidentDetail(null); setRelatedEvents([]); return; }
    if (selected.kind === 'incident') {
      incidentsApi.get(selected.id).then(res => {
        setIncidentDetail(res.data);
        const asset = res.data.alerts?.[0]?.asset;
        if (asset) {
          eventsApi.list({ search: asset, limit: 15 }).then(r => setRelatedEvents(r.data.events || [])).catch(() => setRelatedEvents([]));
        } else {
          setRelatedEvents([]);
        }
      }).catch(() => { setIncidentDetail(null); setRelatedEvents([]); });
    } else if (selectedAlert) {
      setIncidentDetail(null);
      const term = selectedAlert.asset || selectedAlert.username || selectedAlert.ip_address;
      if (term) {
        eventsApi.list({ search: term, limit: 15 }).then(r => setRelatedEvents(r.data.events || [])).catch(() => setRelatedEvents([]));
      } else {
        setRelatedEvents([]);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  const counts = useMemo(() => ({
    openAlerts: alerts.filter(a => a.status !== 'Closed').length,
    openIncidents: incidents.filter(i => i.status !== 'Closed').length,
    critical: queue.filter(it => it.severity === 'Critical').length,
    slaBreaches: queue.filter(it => isBreached(it.sla)).length,
  }), [alerts, incidents, queue]);

  async function updateAlertStatus(id, status) {
    setBusy(true);
    try {
      await alertsApi.update(id, { status });
      await load();
    } finally { setBusy(false); }
  }

  async function updateIncidentStatus(id, status) {
    setBusy(true);
    try {
      await incidentsApi.update(id, { status });
      const res = await incidentsApi.get(id);
      setIncidentDetail(res.data);
      await load();
    } finally { setBusy(false); }
  }

  async function updateIncidentTeam(id, teamId) {
    setBusy(true);
    try {
      await incidentsApi.update(id, { team_id: teamId || null });
      const res = await incidentsApi.get(id);
      setIncidentDetail(res.data);
      await load();
    } finally { setBusy(false); }
  }

  async function createIncidentFromAlert(alertId) {
    setBusy(true);
    try {
      const res = await incidentsApi.createFromAlert(alertId);
      await load();
      setSelected({ kind: 'incident', id: res.data.id });
    } finally { setBusy(false); }
  }

  async function runPlaybook(pb, alertId) {
    setTriggered(t => ({ ...t, [pb.id]: 'running' }));
    try {
      await soarApi.execute(pb.id, alertId);
      setTriggered(t => ({ ...t, [pb.id]: 'done' }));
    } catch {
      setTriggered(t => ({ ...t, [pb.id]: 'error' }));
    }
  }

  const detailKind = selected?.kind;
  const detailRaw = detailKind === 'incident' ? incidentDetail?.incident : selectedAlert;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, height: 'calc(100vh - 32px)' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
        <div
          className="card"
          style={{ padding: '10px 14px', cursor: 'pointer', outline: filters.kind === 'alert' && !filters.breachedOnly ? '1px solid var(--gold)' : 'none' }}
          onClick={() => setFilters(f => ({ ...f, kind: f.kind === 'alert' ? '' : 'alert', breachedOnly: false }))}
          title="Click to filter queue to alerts"
        >
          <div style={{ fontSize: 11, color: 'var(--text2)' }}>Open Alerts</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: '#f6ad55' }}>{counts.openAlerts}</div>
        </div>
        <div
          className="card"
          style={{ padding: '10px 14px', cursor: 'pointer', outline: filters.kind === 'incident' && !filters.breachedOnly ? '1px solid var(--gold)' : 'none' }}
          onClick={() => setFilters(f => ({ ...f, kind: f.kind === 'incident' ? '' : 'incident', breachedOnly: false }))}
          title="Click to filter queue to incidents"
        >
          <div style={{ fontSize: 11, color: 'var(--text2)' }}>Open Incidents</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: '#90cdf4' }}>{counts.openIncidents}</div>
        </div>
        <div
          className="card"
          style={{ padding: '10px 14px', cursor: 'pointer', outline: filters.severity === 'Critical' && !filters.breachedOnly ? '1px solid var(--gold)' : 'none' }}
          onClick={() => setFilters(f => ({ ...f, severity: f.severity === 'Critical' ? '' : 'Critical', breachedOnly: false }))}
          title="Click to filter queue to Critical severity"
        >
          <div style={{ fontSize: 11, color: 'var(--text2)' }}>Critical in Queue</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: '#fc8181' }}>{counts.critical}</div>
        </div>
        <div
          className="card"
          style={{ padding: '10px 14px', cursor: 'pointer', outline: filters.breachedOnly ? '1px solid var(--gold)' : 'none' }}
          onClick={() => setFilters(f => ({ ...f, breachedOnly: !f.breachedOnly }))}
          title="Click to filter queue to SLA breaches"
        >
          <div style={{ fontSize: 11, color: 'var(--text2)' }}>SLA Breaches</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: counts.slaBreaches > 0 ? '#fc8181' : '#68d391' }}>{counts.slaBreaches}</div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 12, flex: 1, minHeight: 0 }}>
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            {['', 'alert', 'incident'].map(k => (
              <button key={k || 'all'} className={`btn btn-sm ${filters.kind === k ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setFilters(f => ({ ...f, kind: k }))}>
                {k === '' ? 'All' : k === 'alert' ? '🚨 Alerts' : '🧯 Incidents'}
              </button>
            ))}
            {['', 'Critical', 'High', 'Medium', 'Low'].map(s => (
              <button key={s || 'sev-all'} className={`btn btn-sm ${filters.severity === s ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setFilters(f => ({ ...f, severity: s }))}>
                {s || 'All Severity'}
              </button>
            ))}
            <button className={`btn btn-sm ${filters.breachedOnly ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setFilters(f => ({ ...f, breachedOnly: !f.breachedOnly }))}>
              ⚠ SLA Breaches
            </button>
            <input placeholder="Search…" value={filters.search} onChange={e => setFilters(f => ({ ...f, search: e.target.value }))} style={{ width: 180, padding: '4px 10px', fontSize: 12 }} />
            <button className="btn btn-secondary btn-sm" onClick={load}>🔄 Refresh</button>
            <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text3)' }}>{queue.length} in queue</span>
          </div>

          <div className="card" style={{ flex: 1, overflow: 'auto', padding: 0 }}>
            {loading ? <div style={{ padding: 20, color: 'var(--text3)' }}>Loading triage queue…</div> : queue.length === 0 ? (
              <div style={{ padding: 20, color: 'var(--text3)' }}>Nothing open — queue is clear. 🎉</div>
            ) : (
              <table>
                <thead><tr><th></th><th>Sev</th><th>Title</th><th>Asset / Owner</th><th>Team</th><th>Score</th><th>Status</th><th>SLA</th><th>Age</th></tr></thead>
                <tbody>
                  {queue.map((it, i) => {
                    const isSel = selected?.kind === it.kind && selected?.id === it.id;
                    const breached = isBreached(it.sla);
                    return (
                      <tr key={`${it.kind}:${it.id}:${i}`} onClick={() => setSelected({ kind: it.kind, id: it.id })} style={{ cursor: 'pointer', background: isSel ? 'rgba(245,166,35,.08)' : '' }}>
                        <td style={{ fontSize: 13 }}>{it.kind === 'alert' ? '🚨' : '🧯'}</td>
                        <td><span className={`badge ${SEV_BADGE[it.severity] || 'badge-gray'}`}>{it.severity}</span></td>
                        <td style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{it.title}</td>
                        <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{it.subtitle}</td>
                        <td style={{ fontSize: 11, color: 'var(--text2)' }}>{it.raw.team_name || '—'}</td>
                        <td style={{ fontSize: 11 }}>{it.score}</td>
                        <td><span className="badge badge-orange">{it.status}</span></td>
                        <td>{breached ? <span className="badge badge-red">⚠ Breach</span> : <span style={{ fontSize: 10, color: 'var(--text3)' }}>OK</span>}</td>
                        <td style={{ fontSize: 10, color: 'var(--text3)', whiteSpace: 'nowrap' }}>{it.created_at ? new Date(it.created_at).toLocaleString() : '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {detailRaw && (
          <div style={{ width: 380, flexShrink: 0, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div className="card">
              <div className="card-title">{detailKind === 'alert' ? '🚨 Alert Detail' : '🧯 Incident Detail'}</div>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>{detailRaw.title}</div>
              {detailRaw.description && <div style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 10, lineHeight: 1.5 }}>{detailRaw.description}</div>}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 12 }}>
                <div><span style={{ color: 'var(--text3)' }}>Severity</span><div><span className={`badge ${SEV_BADGE[detailRaw.severity] || 'badge-gray'}`}>{detailRaw.severity}</span></div></div>
                <div><span style={{ color: 'var(--text3)' }}>Status</span><div style={{ fontWeight: 600 }}>{detailRaw.status}</div></div>
                {detailKind === 'alert' ? (
                  <>
                    <div><span style={{ color: 'var(--text3)' }}>Asset</span><div style={{ fontFamily: 'monospace' }}>{detailRaw.asset || '—'}</div></div>
                    <div><span style={{ color: 'var(--text3)' }}>Risk Score</span><div>{detailRaw.risk_score}/100</div></div>
                    <div><span style={{ color: 'var(--text3)' }}>MITRE Tactic</span><div>{detailRaw.mitre_tactic || '—'}</div></div>
                    <div><span style={{ color: 'var(--text3)' }}>Technique</span><div style={{ fontFamily: 'monospace' }}>{detailRaw.mitre_technique || '—'}</div></div>
                  </>
                ) : (
                  <>
                    <div><span style={{ color: 'var(--text3)' }}>Priority</span><div>P{detailRaw.priority}</div></div>
                    <div><span style={{ color: 'var(--text3)' }}>Owner</span><div>{detailRaw.owner || 'Unassigned'}</div></div>
                  </>
                )}
                <div><span style={{ color: 'var(--text3)' }}>Team</span><div>{detailRaw.team_name || 'Unassigned'}</div></div>
                <div style={{ gridColumn: '1 / -1' }}><span style={{ color: 'var(--text3)' }}>Created</span><div>{detailRaw.created_at ? new Date(detailRaw.created_at).toLocaleString() : '—'}</div></div>
              </div>

              {detailKind === 'incident' && isAdmin && (
                <div style={{ marginTop: 10 }}>
                  <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 6 }}>Reassign Team</div>
                  <select value={detailRaw.team_id || ''} disabled={busy} onChange={e => updateIncidentTeam(detailRaw.id, e.target.value)} style={{ width: '100%' }}>
                    <option value="">Unassigned</option>
                    {teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                  </select>
                </div>
              )}

              {detailRaw.sla && (
                <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid rgba(30,58,110,.3)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 2 }}>SLA</div>
                  <SlaRow label="Time to Acknowledge" elapsedMinutes={detailRaw.sla.ack_elapsed_minutes} targetMinutes={detailRaw.sla.ack_target_minutes} done={detailRaw.sla.ack_done} breached={detailRaw.sla.ack_breached} />
                  <SlaRow label={detailKind === 'alert' ? 'Time to Close' : 'Time to Contain'} elapsedMinutes={detailRaw.sla.resolve_elapsed_minutes} targetMinutes={detailRaw.sla.resolve_target_minutes} done={detailRaw.sla.resolve_done} breached={detailRaw.sla.resolve_breached} />
                </div>
              )}

              {detailKind === 'incident' && incidentDetail?.process_tree?.length > 0 && (
                <button className="btn btn-primary btn-sm" style={{ width: '100%', marginTop: 10 }} onClick={() => navigate(`/investigation/${detailRaw.id}`)}>
                  🌳 View Process Tree ({incidentDetail.process_tree.length} stages)
                </button>
              )}

              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 6 }}>Update Status</div>
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                  {(detailKind === 'alert' ? ALERT_STATUSES : INCIDENT_STATUSES).map(s => (
                    <button key={s} className={`btn btn-sm ${detailRaw.status === s ? 'btn-primary' : 'btn-secondary'}`} disabled={busy} onClick={() => detailKind === 'alert' ? updateAlertStatus(detailRaw.id, s) : updateIncidentStatus(detailRaw.id, s)}>
                      {s}
                    </button>
                  ))}
                </div>
              </div>

              {detailKind === 'alert' && (
                <div style={{ marginTop: 10, display: 'flex', gap: 8 }}>
                  <button className="btn btn-secondary btn-sm" disabled={busy} onClick={() => createIncidentFromAlert(detailRaw.id)}>Create Incident</button>
                </div>
              )}

              {detailKind === 'alert' && canRunPlaybooks && playbooks.length > 0 && (
                <div style={{ marginTop: 10 }}>
                  <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 6 }}>Run Playbook</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                    {playbooks.slice(0, 4).map(pb => (
                      <div key={pb.id} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <button className="btn btn-secondary btn-sm" style={{ flex: 1, textAlign: 'left' }} disabled={triggered[pb.id] === 'running'} onClick={() => runPlaybook(pb, detailRaw.id)}>
                          ⚙️ {pb.name}
                        </button>
                        {triggered[pb.id] === 'running' && <span style={{ fontSize: 10, color: 'var(--text3)' }}>running…</span>}
                        {triggered[pb.id] === 'done' && <span style={{ fontSize: 10, color: '#68d391' }}>✓ triggered</span>}
                        {triggered[pb.id] === 'error' && <span style={{ fontSize: 10, color: '#fc8181' }}>failed</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {detailKind === 'incident' && incidentDetail?.alerts?.length > 0 && (
              <div className="card" style={{ padding: 0, maxHeight: 160, overflow: 'auto' }}>
                <div style={{ padding: 12, borderBottom: '1px solid var(--border)' }}>
                  <div className="card-title" style={{ margin: 0 }}>Linked Alerts ({incidentDetail.alerts.length})</div>
                </div>
                <table>
                  <thead><tr><th>Sev</th><th>Title</th></tr></thead>
                  <tbody>
                    {incidentDetail.alerts.map((a, ai) => (
                      <tr key={a.id || `linked:${ai}`}>
                        <td><span className={`badge ${SEV_BADGE[a.severity] || 'badge-gray'}`}>{a.severity}</span></td>
                        <td style={{ fontSize: 11, color: 'var(--text2)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div className="card" style={{ padding: 0, flex: 1, overflow: 'auto', minHeight: 160 }}>
              <div style={{ padding: 12, borderBottom: '1px solid var(--border)' }}>
                <div className="card-title" style={{ margin: 0 }}>📡 Related Raw Events</div>
              </div>
              {relatedEvents.length === 0 ? (
                <div style={{ padding: 12, color: 'var(--text3)', fontSize: 12 }}>No related events found for this asset/user.</div>
              ) : (
                <table>
                  <thead><tr><th>Time</th><th>Source</th><th>Action</th><th>Sev</th></tr></thead>
                  <tbody>
                    {relatedEvents.map((e, i) => (
                      <tr key={e.id || `revt:${i}`}>
                        <td style={{ fontSize: 10, color: 'var(--text3)', whiteSpace: 'nowrap' }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
                        <td style={{ fontSize: 11, color: 'var(--text2)' }}>{e.source}</td>
                        <td style={{ fontSize: 11, color: 'var(--text2)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.action}</td>
                        <td><span className={`badge ${SEV_BADGE[e.severity] || 'badge-gray'}`}>{e.severity}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
