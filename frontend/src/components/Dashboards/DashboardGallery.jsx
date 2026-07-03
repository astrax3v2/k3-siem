import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { dashboardsApi } from '../../services/api';

function Card({ children, onClick }) {
  return (
    <div
      className="card"
      onClick={onClick}
      style={{ cursor: onClick ? 'pointer' : 'default', display: 'flex', flexDirection: 'column', gap: 8 }}
    >
      {children}
    </div>
  );
}

export default function DashboardGallery() {
  const navigate = useNavigate();
  const [templates, setTemplates] = useState([]);
  const [dashboards, setDashboards] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);

  function refresh() {
    return Promise.all([dashboardsApi.templates(), dashboardsApi.list()]).then(([t, d]) => {
      setTemplates(t.data?.templates || []);
      setDashboards(d.data?.dashboards || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }

  useEffect(() => { refresh(); }, []);

  async function cloneTemplate(tpl) {
    setBusyId(tpl.id);
    try {
      const res = await dashboardsApi.create({
        name: tpl.name,
        description: tpl.description,
        category: tpl.category,
        widgets: tpl.widgets,
      });
      navigate(`/dashboards/${res.data.id}`);
    } finally {
      setBusyId(null);
    }
  }

  async function deleteDashboard(id, e) {
    e.stopPropagation();
    if (!window.confirm('Delete this dashboard?')) return;
    await dashboardsApi.remove(id);
    refresh();
  }

  if (loading) return <div style={{ color: 'var(--text3)', padding: 20 }}>Loading dashboard library…</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <h2 style={{ margin: 0, fontSize: 16, color: 'var(--text)' }}>Dashboard Library</h2>
        <button className="btn btn-primary" style={{ marginLeft: 'auto' }} onClick={() => navigate('/dashboards/new')}>
          + Create Custom Dashboard
        </button>
      </div>

      <div>
        <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text2)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.5 }}>
          Templates
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 12 }}>
          {templates.map(tpl => (
            <Card key={tpl.id}>
              <div style={{ fontSize: 10, color: 'var(--gold)', fontWeight: 700, textTransform: 'uppercase' }}>{tpl.category}</div>
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text)' }}>{tpl.name}</div>
              <div style={{ fontSize: 12, color: 'var(--text3)', flex: 1 }}>{tpl.description}</div>
              <div style={{ fontSize: 11, color: 'var(--text3)' }}>{tpl.widgets.length} widgets</div>
              <button className="btn btn-primary btn-sm" disabled={busyId === tpl.id} onClick={() => cloneTemplate(tpl)}>
                {busyId === tpl.id ? 'Cloning…' : 'Use Template'}
              </button>
            </Card>
          ))}
        </div>
      </div>

      <div>
        <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text2)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.5 }}>
          My Dashboards
        </div>
        {dashboards.length === 0 && (
          <div style={{ color: 'var(--text3)', fontSize: 12 }}>No custom dashboards yet — clone a template above or create one from scratch.</div>
        )}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 12 }}>
          {dashboards.map(d => (
            <Card key={d.id} onClick={() => navigate(`/dashboards/${d.id}`)}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ fontSize: 10, color: 'var(--gold)', fontWeight: 700, textTransform: 'uppercase' }}>{d.category}</div>
                {d.is_shared && <span className="badge badge-blue" style={{ fontSize: 9 }}>Shared</span>}
              </div>
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text)' }}>{d.name}</div>
              <div style={{ fontSize: 12, color: 'var(--text3)', flex: 1 }}>{d.description}</div>
              <div style={{ fontSize: 11, color: 'var(--text3)' }}>{d.widgets.length} widgets · updated {new Date(d.updated_at).toLocaleDateString()}</div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-secondary btn-sm" onClick={(e) => { e.stopPropagation(); navigate(`/dashboards/${d.id}/edit`); }}>Edit</button>
                <button className="btn btn-secondary btn-sm" style={{ color: '#fc8181' }} onClick={(e) => deleteDashboard(d.id, e)}>Delete</button>
              </div>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}
