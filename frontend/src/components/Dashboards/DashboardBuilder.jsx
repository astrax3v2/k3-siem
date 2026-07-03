import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { dashboardsApi } from '../../services/api';
import { WIDGET_TYPE_LABELS } from './widgets/WidgetRenderer';
import DashboardGrid from './DashboardGrid';

const KPI_METRIC_OPTIONS = [
  { value: 'alerts.total', label: 'Alerts (24h)' },
  { value: 'alerts.critical', label: 'Critical Alerts (24h)' },
  { value: 'alerts.open', label: 'Open Alerts' },
  { value: 'eventCount', label: 'Events Indexed (24h)' },
  { value: 'agentStats.total', label: 'Agents Total' },
  { value: 'agentStats.online', label: 'Agents Online' },
  { value: 'agentStats.offline', label: 'Agents Offline' },
  { value: 'assetStats.total', label: 'Assets Total' },
  { value: 'assetStats.compliancePercent', label: 'Asset Compliance %' },
  { value: 'iocHits', label: 'IOC Hits' },
  { value: 'uebaHigh', label: 'High-Risk Users' },
  { value: 'soarRuns', label: 'SOAR Executions' },
];

const SIZE_OPTIONS = ['sm', 'md', 'lg', 'full'];
const SEVERITIES = ['', 'Critical', 'High', 'Medium', 'Low', 'Info'];

let nextWidgetSeq = 1;
function newWidgetId() { return `w-${Date.now()}-${nextWidgetSeq++}`; }

function defaultConfigFor(type) {
  switch (type) {
    case 'kpi_tile': return { metric: KPI_METRIC_OPTIONS[0].value, color: 'var(--gold)' };
    case 'alerts_table': return { limit: 10, severity: '' };
    case 'events_table': return { limit: 10, severity: '', source: '', search: '' };
    case 'live_alert_feed': return { limit: 5 };
    case 'live_event_stream': return { limit: 10 };
    case 'ioc_feed': return { limit: 10 };
    default: return {};
  }
}

function WidgetConfigForm({ widget, onChange }) {
  const set = (patch) => onChange({ ...widget, config: { ...widget.config, ...patch } });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 }}>
      {widget.type === 'kpi_tile' && (
        <label style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          Metric
          <select value={widget.config.metric} onChange={e => set({ metric: e.target.value })}>
            {KPI_METRIC_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </label>
      )}
      {(widget.type === 'alerts_table') && (
        <label style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          Severity filter
          <select value={widget.config.severity || ''} onChange={e => set({ severity: e.target.value })}>
            {SEVERITIES.map(s => <option key={s} value={s}>{s || 'Any'}</option>)}
          </select>
        </label>
      )}
      {(widget.type === 'events_table') && (
        <>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            Severity filter
            <select value={widget.config.severity || ''} onChange={e => set({ severity: e.target.value })}>
              {SEVERITIES.map(s => <option key={s} value={s}>{s || 'Any'}</option>)}
            </select>
          </label>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            Search
            <input value={widget.config.search || ''} onChange={e => set({ search: e.target.value })} placeholder="username, computer, action…" />
          </label>
        </>
      )}
      {['alerts_table', 'events_table', 'live_alert_feed', 'live_event_stream', 'ioc_feed'].includes(widget.type) && (
        <label style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          Row limit
          <input type="number" min={1} max={50} value={widget.config.limit || 10} onChange={e => set({ limit: parseInt(e.target.value, 10) || 10 })} />
        </label>
      )}
    </div>
  );
}

export default function DashboardBuilder({ liveEvents, liveAlerts }) {
  const { id } = useParams();
  const isEditing = !!id;
  const navigate = useNavigate();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState('Custom');
  const [widgets, setWidgets] = useState([]);
  const [loading, setLoading] = useState(isEditing);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!isEditing) return;
    dashboardsApi.get(id).then(r => {
      setName(r.data.name);
      setDescription(r.data.description || '');
      setCategory(r.data.category || 'Custom');
      setWidgets(r.data.widgets || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [id, isEditing]);

  function addWidget(type) {
    setWidgets(ws => [...ws, { id: newWidgetId(), type, title: WIDGET_TYPE_LABELS[type], size: 'md', config: defaultConfigFor(type) }]);
  }

  function updateWidget(idx, updated) {
    setWidgets(ws => ws.map((w, i) => (i === idx ? updated : w)));
  }

  function removeWidget(idx) {
    setWidgets(ws => ws.filter((_, i) => i !== idx));
  }

  function moveWidget(idx, dir) {
    setWidgets(ws => {
      const next = [...ws];
      const target = idx + dir;
      if (target < 0 || target >= next.length) return ws;
      [next[idx], next[target]] = [next[target], next[idx]];
      return next;
    });
  }

  async function save() {
    if (!name.trim()) { window.alert('Dashboard name is required'); return; }
    setSaving(true);
    try {
      if (isEditing) {
        await dashboardsApi.update(id, { name, description, category, widgets });
        navigate(`/dashboards/${id}`);
      } else {
        const res = await dashboardsApi.create({ name, description, category, widgets });
        navigate(`/dashboards/${res.data.id}`);
      }
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <div style={{ color: 'var(--text3)', padding: 20 }}>Loading…</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <button className="btn btn-secondary btn-sm" onClick={() => navigate('/dashboards')}>← Library</button>
        <h2 style={{ margin: 0, fontSize: 16, color: 'var(--text)' }}>{isEditing ? 'Edit Dashboard' : 'Create Dashboard'}</h2>
        <button className="btn btn-primary btn-sm" style={{ marginLeft: 'auto' }} disabled={saving} onClick={save}>
          {saving ? 'Saving…' : 'Save Dashboard'}
        </button>
      </div>

      <div className="card" style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 3, fontSize: 12, flex: 2, minWidth: 200 }}>
          Name
          <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. My Threat Hunting View" />
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 3, fontSize: 12, flex: 3, minWidth: 240 }}>
          Description
          <input value={description} onChange={e => setDescription(e.target.value)} placeholder="Optional description" />
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 3, fontSize: 12, flex: 1, minWidth: 140 }}>
          Category
          <input value={category} onChange={e => setCategory(e.target.value)} />
        </label>
      </div>

      <div className="card">
        <div className="card-title">Add a widget</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {Object.entries(WIDGET_TYPE_LABELS).map(([type, label]) => (
            <button key={type} className="btn btn-secondary btn-sm" onClick={() => addWidget(type)}>+ {label}</button>
          ))}
        </div>
      </div>

      {widgets.length > 0 && (
        <div className="card">
          <div className="card-title">Widgets ({widgets.length})</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {widgets.map((w, idx) => (
              <div key={w.id} style={{ display: 'flex', gap: 12, alignItems: 'flex-start', padding: '8px 0', borderBottom: '1px solid rgba(30,58,110,.3)' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <button className="btn btn-secondary btn-sm" disabled={idx === 0} onClick={() => moveWidget(idx, -1)}>↑</button>
                  <button className="btn btn-secondary btn-sm" disabled={idx === widgets.length - 1} onClick={() => moveWidget(idx, 1)}>↓</button>
                </div>
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span className="badge badge-purple">{WIDGET_TYPE_LABELS[w.type]}</span>
                    <input
                      value={w.title}
                      onChange={e => updateWidget(idx, { ...w, title: e.target.value })}
                      style={{ flex: 1, fontSize: 12 }}
                    />
                    <select value={w.size} onChange={e => updateWidget(idx, { ...w, size: e.target.value })}>
                      {SIZE_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                    <button className="btn btn-secondary btn-sm" style={{ color: '#fc8181' }} onClick={() => removeWidget(idx)}>Remove</button>
                  </div>
                  <WidgetConfigForm widget={w} onChange={updated => updateWidget(idx, updated)} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <div className="card-title" style={{ marginBottom: 8 }}>Live Preview</div>
        <DashboardGrid widgets={widgets} liveEvents={liveEvents} liveAlerts={liveAlerts} />
      </div>
    </div>
  );
}
