import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { dashboardsApi } from '../../services/api';
import { useAuth } from '../Layout/Auth';
import DashboardGrid from './DashboardGrid';

export default function DashboardViewer({ liveEvents, liveAlerts }) {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    setLoading(true);
    dashboardsApi.get(id)
      .then(r => { setDashboard(r.data); setLoading(false); })
      .catch(e => { setError(e.response?.data?.error || 'Failed to load dashboard'); setLoading(false); });
  }, [id]);

  async function toggleShare() {
    const res = await dashboardsApi.update(id, { is_shared: !dashboard.is_shared });
    setDashboard(res.data);
  }

  async function remove() {
    if (!window.confirm('Delete this dashboard?')) return;
    await dashboardsApi.remove(id);
    navigate('/dashboards');
  }

  if (loading) return <div style={{ color: 'var(--text3)', padding: 20 }}>Loading dashboard…</div>;
  if (error || !dashboard) return <div style={{ color: '#fc8181', padding: 20 }}>{error || 'Dashboard not found'}</div>;

  const isOwner = dashboard.owner === user?.username;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <button className="btn btn-secondary btn-sm" onClick={() => navigate('/dashboards')}>← Library</button>
        <h2 style={{ margin: 0, fontSize: 16, color: 'var(--text)' }}>{dashboard.name}</h2>
        {dashboard.is_shared && <span className="badge badge-blue">Shared</span>}
        {isOwner && (
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            <button className="btn btn-secondary btn-sm" onClick={toggleShare}>{dashboard.is_shared ? 'Unshare' : 'Share'}</button>
            <button className="btn btn-primary btn-sm" onClick={() => navigate(`/dashboards/${id}/edit`)}>Edit</button>
            <button className="btn btn-secondary btn-sm" style={{ color: '#fc8181' }} onClick={remove}>Delete</button>
          </div>
        )}
      </div>
      {dashboard.description && <div style={{ color: 'var(--text3)', fontSize: 12 }}>{dashboard.description}</div>}
      <DashboardGrid widgets={dashboard.widgets} liveEvents={liveEvents} liveAlerts={liveAlerts} />
    </div>
  );
}
