import React, { useEffect, useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { dashboardApi, alertsApi, eventsApi, agentsApi, assetsApi, vulnApi, intelApi } from '../../../services/api';

const SEV_COLORS = { Critical: '#fc8181', High: '#f6ad55', Medium: '#90cdf4', Low: '#68d391', Info: '#94a3b8' };
const STATUS_COLORS = { New: '#fc8181', 'In Progress': '#f6ad55', Assigned: '#90cdf4', Closed: '#94a3b8' };

export const SIZE_SPAN = { sm: 1, md: 2, lg: 3, full: 4 };

function getPath(obj, path) {
  return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

function formatMetric(value) {
  if (value == null) return '—';
  if (typeof value === 'number' && value > 999) return (value / 1000).toFixed(1) + 'K';
  return value;
}

function CardShell({ title, children }) {
  return (
    <div className="card">
      <div className="card-title">{title}</div>
      {children}
    </div>
  );
}

function KpiTile({ widget }) {
  const [stats, setStats] = useState(null);
  useEffect(() => { dashboardApi.stats().then(r => setStats(r.data)).catch(() => {}); }, []);
  const value = stats ? getPath(stats, widget.config.metric) : null;
  return (
    <div className="card" style={{ padding: '12px 14px' }}>
      <div style={{ fontSize: 11, color: 'var(--text2)' }}>{widget.title}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color: widget.config.color || 'var(--gold)', lineHeight: 1.2, marginTop: 2 }}>
        {formatMetric(value)}{value != null && widget.config.suffix}
      </div>
    </div>
  );
}

function AlertTrend({ widget }) {
  const [trend, setTrend] = useState([]);
  useEffect(() => { dashboardApi.stats().then(r => setTrend(r.data?.trend || [])).catch(() => {}); }, []);
  return (
    <CardShell title={widget.title}>
      <ResponsiveContainer width="100%" height={140}>
        <AreaChart data={trend} margin={{ top: 5, right: 5, bottom: 0, left: -30 }}>
          <defs>
            <linearGradient id={`grad-${widget.id}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#F5A623" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#F5A623" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#64748b' }} tickFormatter={d => d.slice(5)} />
          <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
          <Tooltip contentStyle={{ background: '#1a2235', border: '1px solid #1e3a6e', fontSize: 12 }} />
          <Area type="monotone" dataKey="count" stroke="#F5A623" fill={`url(#grad-${widget.id})`} strokeWidth={1.5} dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </CardShell>
  );
}

function SeverityBar({ widget }) {
  const [data, setData] = useState([]);
  useEffect(() => { alertsApi.stats().then(r => setData(r.data?.bySeverity || [])).catch(() => {}); }, []);
  return (
    <CardShell title={widget.title}>
      <ResponsiveContainer width="100%" height={140}>
        <BarChart data={data} margin={{ top: 5, right: 5, bottom: 0, left: -30 }}>
          <XAxis dataKey="severity" tick={{ fontSize: 10, fill: '#64748b' }} />
          <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
          <Tooltip contentStyle={{ background: '#1a2235', border: '1px solid #1e3a6e', fontSize: 12 }} />
          <Bar dataKey="cnt" radius={[3, 3, 0, 0]}>
            {data.map((e, i) => <Cell key={i} fill={SEV_COLORS[e.severity] || '#94a3b8'} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </CardShell>
  );
}

function MitreTactics({ widget }) {
  const [data, setData] = useState([]);
  useEffect(() => { alertsApi.stats().then(r => setData(r.data?.byTactic || [])).catch(() => {}); }, []);
  const max = data[0]?.cnt || 1;
  return (
    <CardShell title={widget.title}>
      {data.length === 0 && <div style={{ color: 'var(--text3)', fontSize: 12 }}>No data</div>}
      {data.map((t, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, fontSize: 12 }}>
          <span style={{ flex: 1, color: 'var(--text2)' }}>{t.mitre_tactic || 'Unknown'}</span>
          <div style={{ width: 60, height: 4, background: 'var(--bg4)', borderRadius: 2, overflow: 'hidden' }}>
            <div style={{ width: `${(t.cnt / max) * 100}%`, height: '100%', background: 'var(--navy3)' }} />
          </div>
          <span style={{ color: 'var(--text3)', minWidth: 20, textAlign: 'right' }}>{t.cnt}</span>
        </div>
      ))}
    </CardShell>
  );
}

function AlertStatus({ widget }) {
  const [data, setData] = useState([]);
  useEffect(() => { alertsApi.stats().then(r => setData(r.data?.byStatus || [])).catch(() => {}); }, []);
  return (
    <CardShell title={widget.title}>
      {data.map((s, i) => (
        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid rgba(30,58,110,.3)', fontSize: 12 }}>
          <span style={{ color: 'var(--text2)' }}>{s.status}</span>
          <span style={{ color: STATUS_COLORS[s.status] || 'var(--text)', fontWeight: 600 }}>{s.cnt}</span>
        </div>
      ))}
    </CardShell>
  );
}

function AgentStatus({ widget }) {
  const [stats, setStats] = useState(null);
  useEffect(() => { agentsApi.stats().then(r => setStats(r.data)).catch(() => {}); }, []);
  return (
    <CardShell title={widget.title}>
      <div style={{ display: 'flex', gap: 16 }}>
        {[
          { label: 'Total', value: stats?.total ?? 0, color: 'var(--gold)' },
          { label: 'Online', value: stats?.online ?? 0, color: '#68d391', dot: '#68d391' },
          { label: 'Offline', value: stats?.offline ?? 0, color: '#fc8181', dot: '#fc8181' },
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
    </CardShell>
  );
}

function AssetOverview({ widget }) {
  const [stats, setStats] = useState(null);
  useEffect(() => { assetsApi.stats().then(r => setStats(r.data)).catch(() => {}); }, []);
  return (
    <CardShell title={widget.title}>
      <div style={{ display: 'flex', gap: 16 }}>
        <div style={{ textAlign: 'center', flex: 1 }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--gold)' }}>{stats?.total ?? 0}</div>
          <div style={{ fontSize: 10, color: 'var(--text3)', marginTop: 2 }}>Total Assets</div>
        </div>
        <div style={{ textAlign: 'center', flex: 1 }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: (stats?.compliancePercent ?? 0) >= 80 ? '#68d391' : '#fc8181' }}>{stats?.compliancePercent ?? 0}%</div>
          <div style={{ fontSize: 10, color: 'var(--text3)', marginTop: 2 }}>Compliant</div>
        </div>
        <div style={{ flex: 2 }}>
          {(stats?.byOs || []).slice(0, 3).map((o, i) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, padding: '2px 0' }}>
              <span style={{ color: 'var(--text2)' }}>{o.os_name || 'Unknown'}</span>
              <span style={{ color: 'var(--gold)', fontWeight: 600 }}>{o.cnt}</span>
            </div>
          ))}
        </div>
      </div>
    </CardShell>
  );
}

function VulnSummary({ widget }) {
  const [stats, setStats] = useState(null);
  useEffect(() => { vulnApi.stats().then(r => setStats(r.data)).catch(() => {}); }, []);
  const items = [
    ['Total', stats?.total, 'var(--gold)'],
    ['Critical', stats?.critical, '#fc8181'],
    ['High', stats?.high, '#f6ad55'],
    ['Medium', stats?.medium, '#90cdf4'],
    ['Low', stats?.low, '#68d391'],
    ['Affected Assets', stats?.affected_assets, 'var(--text)'],
  ];
  return (
    <CardShell title={widget.title}>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        {items.map(([label, value, color]) => (
          <div key={label} style={{ textAlign: 'center', flex: 1, minWidth: 70 }}>
            <div style={{ fontSize: 20, fontWeight: 700, color }}>{value ?? 0}</div>
            <div style={{ fontSize: 10, color: 'var(--text3)', marginTop: 2 }}>{label}</div>
          </div>
        ))}
      </div>
    </CardShell>
  );
}

function IocFeed({ widget }) {
  const [iocs, setIocs] = useState([]);
  useEffect(() => { intelApi.iocs({ limit: widget.config.limit || 10 }).then(r => setIocs(r.data?.iocs || [])).catch(() => {}); }, [widget.config.limit]);
  return (
    <CardShell title={widget.title}>
      <div style={{ overflowX: 'auto' }}>
        <table>
          <thead><tr><th>Type</th><th>Value</th><th>Severity</th><th>Confidence</th><th>Source</th></tr></thead>
          <tbody>
            {iocs.map((ioc, i) => (
              <tr key={i}>
                <td style={{ fontSize: 11 }}>{ioc.type}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{ioc.value}</td>
                <td><span className="badge badge-orange">{ioc.severity}</span></td>
                <td style={{ fontSize: 11 }}>{ioc.confidence}</td>
                <td style={{ fontSize: 11, color: 'var(--text2)' }}>{ioc.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </CardShell>
  );
}

function AlertsTable({ widget }) {
  const [alerts, setAlerts] = useState([]);
  useEffect(() => {
    const params = { limit: widget.config.limit || 10 };
    if (widget.config.severity) params.severity = widget.config.severity;
    if (widget.config.status) params.status = widget.config.status;
    alertsApi.list(params).then(r => setAlerts(r.data?.alerts || [])).catch(() => {});
  }, [widget.config.limit, widget.config.severity, widget.config.status]);
  return (
    <CardShell title={widget.title}>
      <div style={{ overflowX: 'auto' }}>
        <table>
          <thead><tr><th>Severity</th><th>Title</th><th>Asset</th><th>MITRE</th><th>Status</th></tr></thead>
          <tbody>
            {alerts.map((a, i) => (
              <tr key={i}>
                <td><span className="badge badge-red">{a.severity}</span></td>
                <td style={{ maxWidth: 220, color: 'var(--text)' }}>{a.title}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{a.asset}</td>
                <td><span className="badge badge-purple">{a.mitre_technique}</span></td>
                <td><span className="badge badge-orange">{a.status}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </CardShell>
  );
}

function EventsTable({ widget }) {
  const [events, setEvents] = useState([]);
  useEffect(() => {
    const params = { limit: widget.config.limit || 10 };
    if (widget.config.severity) params.severity = widget.config.severity;
    if (widget.config.source) params.source = widget.config.source;
    if (widget.config.search) params.search = widget.config.search;
    eventsApi.list(params).then(r => setEvents(r.data?.events || [])).catch(() => {});
  }, [widget.config.limit, widget.config.severity, widget.config.source, widget.config.search]);
  return (
    <CardShell title={widget.title}>
      <div style={{ overflowX: 'auto' }}>
        <table>
          <thead><tr><th>Time</th><th>Source</th><th>Computer</th><th>Action</th><th>Sev</th></tr></thead>
          <tbody>
            {events.map((e, i) => (
              <tr key={i}>
                <td style={{ fontSize: 10, color: 'var(--text3)', whiteSpace: 'nowrap' }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
                <td style={{ fontSize: 11, color: 'var(--text2)' }}>{e.source}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{e.computer}</td>
                <td style={{ fontSize: 11, color: 'var(--text2)' }}>{e.action}</td>
                <td><span className={`badge badge-${e.severity === 'Critical' ? 'red' : e.severity === 'High' ? 'orange' : e.severity === 'Medium' ? 'blue' : 'gray'}`}>{e.severity}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </CardShell>
  );
}

function LiveAlertFeed({ widget, liveAlerts }) {
  const items = (liveAlerts || []).slice(0, widget.config.limit || 5);
  return (
    <CardShell title={widget.title}>
      <div style={{ overflowX: 'auto' }}>
        <table>
          <thead><tr><th>Severity</th><th>Title</th><th>Asset</th><th>MITRE</th><th>Time</th></tr></thead>
          <tbody>
            {items.map((a, i) => (
              <tr key={i}>
                <td><span className="badge badge-red">{a.severity}</span></td>
                <td style={{ maxWidth: 220, color: 'var(--text)' }}>{a.title}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{a.asset}</td>
                <td><span className="badge badge-purple">{a.mitre_technique}</span></td>
                <td style={{ fontSize: 11, color: 'var(--text3)' }}>{new Date(a.created_at || Date.now()).toLocaleTimeString()}</td>
              </tr>
            ))}
            {items.length === 0 && <tr><td colSpan={5} style={{ color: 'var(--text3)', fontSize: 12 }}>No live alerts yet</td></tr>}
          </tbody>
        </table>
      </div>
    </CardShell>
  );
}

function LiveEventStream({ widget, liveEvents }) {
  const items = (liveEvents || []).slice(0, widget.config.limit || 10);
  return (
    <CardShell title={widget.title}>
      <div style={{ overflowX: 'auto' }}>
        <table>
          <thead><tr><th>Time</th><th>Source</th><th>Computer</th><th>Action</th><th>Sev</th></tr></thead>
          <tbody>
            {items.map((e, i) => (
              <tr key={i}>
                <td style={{ fontSize: 10, color: 'var(--text3)', whiteSpace: 'nowrap' }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
                <td style={{ fontSize: 11, color: 'var(--text2)' }}>{e.source}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{e.computer}</td>
                <td style={{ fontSize: 11, color: 'var(--text2)' }}>{e.action}</td>
                <td><span className={`badge badge-${e.severity === 'Critical' ? 'red' : e.severity === 'High' ? 'orange' : e.severity === 'Medium' ? 'blue' : 'gray'}`}>{e.severity}</span></td>
              </tr>
            ))}
            {items.length === 0 && <tr><td colSpan={5} style={{ color: 'var(--text3)', fontSize: 12 }}>No live events yet</td></tr>}
          </tbody>
        </table>
      </div>
    </CardShell>
  );
}

const WIDGET_TYPES = {
  kpi_tile: KpiTile,
  alert_trend: AlertTrend,
  severity_bar: SeverityBar,
  mitre_tactics: MitreTactics,
  alert_status: AlertStatus,
  agent_status: AgentStatus,
  asset_overview: AssetOverview,
  vuln_summary: VulnSummary,
  ioc_feed: IocFeed,
  alerts_table: AlertsTable,
  events_table: EventsTable,
  live_alert_feed: LiveAlertFeed,
  live_event_stream: LiveEventStream,
};

export const WIDGET_TYPE_LABELS = {
  kpi_tile: 'KPI Tile',
  alert_trend: 'Alert Trend Chart',
  severity_bar: 'Severity Distribution',
  mitre_tactics: 'Top MITRE Tactics',
  alert_status: 'Alert Status Breakdown',
  agent_status: 'Agent Status',
  asset_overview: 'Asset Overview',
  vuln_summary: 'Vulnerability Summary',
  ioc_feed: 'Recent IOCs',
  alerts_table: 'Alerts Table',
  events_table: 'Events Table',
  live_alert_feed: 'Live Alert Feed',
  live_event_stream: 'Live Event Stream',
};

export default function WidgetRenderer({ widget, liveEvents, liveAlerts }) {
  const Cmp = WIDGET_TYPES[widget.type];
  if (!Cmp) return <div className="card">Unknown widget type: {widget.type}</div>;
  return <Cmp widget={widget} liveEvents={liveEvents} liveAlerts={liveAlerts} />;
}
