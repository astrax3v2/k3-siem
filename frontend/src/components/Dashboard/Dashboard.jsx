import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { dashboardApi, alertsApi } from '../../services/api';

const SEV_COLORS = { Critical: '#fc8181', High: '#f6ad55', Medium: '#90cdf4', Low: '#68d391', Info: '#94a3b8' };
const STATUS_COLORS = { New: '#fc8181', 'In Progress': '#f6ad55', Assigned: '#90cdf4', Closed: '#94a3b8' };

function StatTile({ label, value, sub, color = 'var(--gold)', onClick }) {
  return (
    <div className="card" style={{ padding: '12px 14px', cursor: onClick ? 'pointer' : 'default' }} onClick={onClick} title={onClick ? 'Click to view details' : undefined}>
      <div style={{ fontSize: 11, color: 'var(--text2)' }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color, lineHeight: 1.2, marginTop: 2 }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--text3)', marginTop: 3 }}>{sub}</div>}
    </div>
  );
}

export default function Dashboard({ liveEvents, liveAlerts }) {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [alertStats, setAlertStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([dashboardApi.stats(), alertsApi.stats()]).then(([d, a]) => {
      setStats(d.data);
      setAlertStats(a.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  if (loading) return <div style={{ color: 'var(--text3)', padding: 20 }}>Loading dashboard…</div>;

  const sevData = alertStats?.bySeverity || [];
  const trend = stats?.trend || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* KPI row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
        <StatTile label="Alerts (24h)" value={stats?.alerts?.total ?? '—'} sub={`${stats?.alerts?.critical ?? 0} Critical`} color="#fc8181" onClick={() => navigate('/alerts')} />
        <StatTile label="Open Incidents" value={stats?.alerts?.open ?? '—'} sub="Requiring attention" color="#f6ad55" onClick={() => navigate('/incidents?status=Open')} />
        <StatTile label="Events Indexed (24h)" value={stats?.eventCount ? (stats.eventCount / 1000).toFixed(1) + 'K' : '—'} sub="Across all indices" color="var(--gold)" onClick={() => navigate('/events')} />
        <StatTile label="SOAR Executions" value={stats?.soarRuns ?? '—'} sub="Automated responses" color="#68d391" onClick={() => navigate('/soar')} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        {/* Alert trend */}
        <div className="card" style={{ cursor: 'pointer' }} onClick={() => navigate('/alerts')} title="Click to view all alerts">
          <div className="card-title">📈 Alert Trend (14 days)</div>
          <ResponsiveContainer width="100%" height={120}>
            <AreaChart data={trend} margin={{ top: 5, right: 5, bottom: 0, left: -30 }}>
              <defs>
                <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#F5A623" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#F5A623" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#64748b' }} tickFormatter={d => d.slice(5)} />
              <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
              <Tooltip contentStyle={{ background: '#1a2235', border: '1px solid #1e3a6e', fontSize: 12 }} />
              <Area type="monotone" dataKey="count" stroke="#F5A623" fill="url(#alertGrad)" strokeWidth={1.5} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity breakdown */}
        <div className="card">
          <div className="card-title">🎯 Severity Distribution</div>
          <ResponsiveContainer width="100%" height={120}>
            <BarChart data={sevData} margin={{ top: 5, right: 5, bottom: 0, left: -30 }}>
              <XAxis dataKey="severity" tick={{ fontSize: 10, fill: '#64748b' }} />
              <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
              <Tooltip contentStyle={{ background: '#1a2235', border: '1px solid #1e3a6e', fontSize: 12 }} />
              <Bar dataKey="cnt" radius={[3, 3, 0, 0]} cursor="pointer" onClick={(d) => d?.severity && navigate(`/alerts?severity=${encodeURIComponent(d.severity)}`)}>
                {sevData.map((e, i) => <Cell key={i} fill={SEV_COLORS[e.severity] || '#94a3b8'} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Live alert feed */}
      <div className="card">
        <div className="card-title">
          ⚡ Live Alert Feed
          {liveAlerts.length > 0 && <span style={{ marginLeft: 8, background: 'var(--red)', color: '#fff', fontSize: 10, padding: '1px 6px', borderRadius: 8, fontWeight: 700 }}>+{liveAlerts.length} live</span>}
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table>
            <thead><tr><th>Severity</th><th>Title</th><th>Asset</th><th>MITRE</th><th>Time</th><th>Status</th></tr></thead>
            <tbody>
              {liveAlerts.slice(0, 5).map((a, i) => (
                <tr key={i} style={{ animation: 'fadeIn .3s', cursor: 'pointer' }} onClick={() => navigate(a.id ? `/alerts?id=${encodeURIComponent(a.id)}` : '/alerts')} title="Click to view this alert">
                  <td><span className={`badge badge-red`}>{a.severity}</span></td>
                  <td style={{ maxWidth: 220, color: 'var(--text)' }}>{a.title}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{a.asset}</td>
                  <td><span className="badge badge-purple">{a.mitre_technique}</span></td>
                  <td style={{ fontSize: 11, color: 'var(--text3)' }}>{new Date(a.created_at || Date.now()).toLocaleTimeString()}</td>
                  <td><span className="badge badge-orange">New</span></td>
                </tr>
              ))}
              {liveAlerts.length === 0 && <tr><td colSpan={6} style={{ color: 'var(--text3)', fontSize: 12 }}>No live alerts yet</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      {/* Live event stream */}
      <div className="card">
        <div className="card-title">
          📡 Live Event Stream
          <div style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text3)', display: 'flex', alignItems: 'center', gap: 5 }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#68d391', animation: 'pulse 1.5s infinite' }} />
            Ingesting
          </div>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table>
            <thead><tr><th>Time</th><th>Source</th><th>Computer</th><th>User</th><th>Action</th><th>IP</th><th>Sev</th></tr></thead>
            <tbody>
              {liveEvents.slice(0, 10).map((e, i) => (
                <tr key={i} style={{ cursor: 'pointer' }} onClick={() => navigate(`/events?search=${encodeURIComponent(e.computer || e.username || e.ip_address || '')}`)} title="Click to view related events">
                  <td style={{ fontSize: 10, color: 'var(--text3)', whiteSpace: 'nowrap' }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td style={{ fontSize: 11, color: 'var(--text2)' }}>{e.source}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{e.computer}</td>
                  <td style={{ fontSize: 12 }}>{e.username}</td>
                  <td style={{ fontSize: 11, color: 'var(--text2)' }}>{e.action}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{e.ip_address}</td>
                  <td><span className={`badge badge-${e.severity === 'Critical' ? 'red' : e.severity === 'High' ? 'orange' : e.severity === 'Medium' ? 'blue' : 'gray'}`}>{e.severity}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Agent & Asset Status */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div className="card" style={{ cursor: 'pointer' }} onClick={() => navigate('/agents')} title="Click to view agents">
          <div className="card-title">🖥️ Agent Status</div>
          <div style={{ display: 'flex', gap: 16 }}>
            {[
              { label: 'Total', value: stats?.agentStats?.total ?? 0, color: 'var(--gold)' },
              { label: 'Online', value: stats?.agentStats?.online ?? 0, color: '#68d391', dot: '#68d391' },
              { label: 'Offline', value: stats?.agentStats?.offline ?? 0, color: '#fc8181', dot: '#fc8181' },
            ].map(a => (
              <div key={a.label} style={{ textAlign: 'center', flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 5 }}>
                  {a.dot && <div style={{ width: 6, height: 6, borderRadius: '50%', background: a.dot }} />}
                  <span style={{ fontSize: 22, fontWeight: 700, color: a.color }}>{a.value}</span>
                </div>
                <div style={{ fontSize: 10, color: 'var(--text3)', marginTop: 2 }}>{a.label}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="card" style={{ cursor: 'pointer' }} onClick={() => navigate('/inventory')} title="Click to view asset inventory">
          <div className="card-title">📦 Asset Overview</div>
          <div style={{ display: 'flex', gap: 16 }}>
            <div style={{ textAlign: 'center', flex: 1 }}>
              <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--gold)' }}>{stats?.assetStats?.total ?? 0}</div>
              <div style={{ fontSize: 10, color: 'var(--text3)', marginTop: 2 }}>Total Assets</div>
            </div>
            <div style={{ textAlign: 'center', flex: 1 }}>
              <div style={{ fontSize: 22, fontWeight: 700, color: stats?.assetStats?.compliancePercent >= 80 ? '#68d391' : '#fc8181' }}>{stats?.assetStats?.compliancePercent ?? 0}%</div>
              <div style={{ fontSize: 10, color: 'var(--text3)', marginTop: 2 }}>Compliant</div>
            </div>
            <div style={{ flex: 2 }}>
              {(stats?.assetStats?.byOs || []).slice(0, 3).map((o, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, padding: '2px 0' }}>
                  <span style={{ color: 'var(--text2)' }}>{o.os_name || 'Unknown'}</span>
                  <span style={{ color: 'var(--gold)', fontWeight: 600 }}>{o.cnt}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* MITRE top tactics */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        <div className="card">
          <div className="card-title">🎯 Top MITRE Tactics</div>
          {(alertStats?.byTactic || []).map((t, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, fontSize: 12, cursor: 'pointer' }} onClick={() => navigate(`/alerts?tactic=${encodeURIComponent(t.mitre_tactic)}`)} title={`Click to view ${t.mitre_tactic} alerts`}>
              <span style={{ flex: 1, color: 'var(--text2)' }}>{t.mitre_tactic}</span>
              <div style={{ width: 60, height: 4, background: 'var(--bg4)', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ width: `${(t.cnt / (alertStats.byTactic[0]?.cnt || 1)) * 100}%`, height: '100%', background: 'var(--navy3)' }} />
              </div>
              <span style={{ color: 'var(--text3)', minWidth: 20, textAlign: 'right' }}>{t.cnt}</span>
            </div>
          ))}
        </div>
        <div className="card">
          <div className="card-title">📊 Alert Status</div>
          {(alertStats?.byStatus || []).map((s, i) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid rgba(30,58,110,.3)', fontSize: 12, cursor: 'pointer' }} onClick={() => navigate(`/alerts?status=${encodeURIComponent(s.status)}`)} title={`Click to view ${s.status} alerts`}>
              <span style={{ color: 'var(--text2)' }}>{s.status}</span>
              <span style={{ color: STATUS_COLORS[s.status] || 'var(--text)', fontWeight: 600 }}>{s.cnt}</span>
            </div>
          ))}
        </div>
        <div className="card">
          <div className="card-title">🔢 Platform Stats</div>
          {[['IOC Hits', stats?.iocHits ?? '—', '/intel'], ['High-Risk Users', stats?.uebaHigh ?? '—', '/ueba'], ['SOAR Runs', stats?.soarRuns ?? '—', '/soar'], ['Events (24h)', stats?.eventCount ? (stats.eventCount > 999 ? (stats.eventCount / 1000).toFixed(1) + 'K' : stats.eventCount) : '—', '/events']].map(([k, v, href]) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid rgba(30,58,110,.3)', fontSize: 12, cursor: 'pointer' }} onClick={() => navigate(href)} title={`Click to view ${k}`}>
              <span style={{ color: 'var(--text2)' }}>{k}</span>
              <span style={{ color: 'var(--gold)', fontWeight: 600 }}>{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
