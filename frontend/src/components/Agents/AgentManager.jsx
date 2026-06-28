import React, { useState, useEffect, useCallback } from 'react';
import { agentsApi } from '../../services/api';
import { formatDistanceToNow } from 'date-fns';

const STATUS_COLORS = { online: '#68d391', stale: '#f6ad55', offline: '#fc8181' };
const OS_ICONS = { Windows: '🪟', Ubuntu: '🐧', Linux: '🐧', 'PAN-OS': '🔥', CentOS: '🐧', Debian: '🐧' };

function getOsIcon(os) {
  if (!os) return '🖥️';
  for (const [key, icon] of Object.entries(OS_ICONS)) {
    if (os.includes(key)) return icon;
  }
  return '🖥️';
}

export default function AgentManager() {
  const [agents, setAgents] = useState([]);
  const [stats, setStats] = useState({ total: 0, online: 0, stale: 0, offline: 0, total_events: 0 });
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchAgents = useCallback(async () => {
    try {
      const [agentRes, statsRes] = await Promise.all([agentsApi.list(), agentsApi.stats()]);
      setAgents(agentRes.data.agents || []);
      setStats(statsRes.data);
    } catch (e) {
      console.error('Failed to fetch agents:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgents();
    const id = setInterval(fetchAgents, 15000);
    return () => clearInterval(id);
  }, [fetchAgents]);

  const selectAgent = async (agent) => {
    setSelected(agent.id);
    try {
      const res = await agentsApi.get(agent.id);
      setDetail(res.data);
    } catch { setDetail(null); }
  };

  const deleteAgent = async (id) => {
    try {
      await agentsApi.remove(id);
      setSelected(null);
      setDetail(null);
      fetchAgents();
    } catch (e) {
      console.error('Failed to delete agent:', e);
    }
  };

  if (loading) {
    return <div style={{ color: 'var(--text2)', padding: 40, textAlign: 'center' }}>Loading agents...</div>;
  }

  return (
    <div style={{ display: 'flex', gap: 16, height: 'calc(100vh - 100px)' }}>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Header */}
        <div>
          <h2 style={{ color: '#fff', margin: 0, fontSize: 18 }}>
            Agent Management
            <span style={{ color: 'var(--text3)', fontSize: 12, fontWeight: 400, marginLeft: 8 }}>
              Endpoint Collectors
            </span>
          </h2>
        </div>

        {/* Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10 }}>
          {[
            { label: 'Total Agents', value: stats.total, color: 'var(--gold)' },
            { label: 'Online', value: stats.online, color: '#68d391' },
            { label: 'Stale', value: stats.stale, color: '#f6ad55' },
            { label: 'Offline', value: stats.offline, color: '#fc8181' },
            { label: 'Events Collected', value: stats.total_events?.toLocaleString() || '0', color: 'var(--blue)' },
          ].map(s => (
            <div key={s.label} style={{ background: 'var(--bg2)', borderRadius: 8, padding: '12px 14px', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>{s.label}</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: s.color }}>{s.value}</div>
            </div>
          ))}
        </div>

        {/* Agent Table */}
        <div style={{ flex: 1, overflow: 'auto', background: 'var(--bg2)', borderRadius: 8, border: '1px solid var(--border)' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
            <thead>
              <tr style={{ background: 'var(--bg3)', position: 'sticky', top: 0, zIndex: 1 }}>
                {['Status', 'Hostname', 'OS', 'IP Address', 'Version', 'Events Sent', 'Last Heartbeat', 'Registered'].map(h => (
                  <th key={h} style={{ padding: '8px 12px', textAlign: 'left', color: 'var(--text3)', fontWeight: 600, fontSize: 11, borderBottom: '1px solid var(--border)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {agents.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: 40, textAlign: 'center', color: 'var(--text3)' }}>
                    No agents registered. Deploy k3-agent on endpoints or start with docker-compose.
                  </td>
                </tr>
              ) : agents.map(a => (
                <tr key={a.id} onClick={() => selectAgent(a)}
                  style={{ cursor: 'pointer', background: selected === a.id ? 'var(--navy)' : 'transparent', borderBottom: '1px solid var(--border)' }}
                  onMouseEnter={e => { if (selected !== a.id) e.currentTarget.style.background = 'var(--bg3)'; }}
                  onMouseLeave={e => { if (selected !== a.id) e.currentTarget.style.background = 'transparent'; }}>
                  <td style={{ padding: '8px 12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <div style={{
                        width: 8, height: 8, borderRadius: '50%',
                        background: STATUS_COLORS[a.computed_status] || STATUS_COLORS.offline,
                        boxShadow: a.computed_status === 'online' ? '0 0 6px #68d391' : 'none',
                      }} />
                      <span style={{ color: STATUS_COLORS[a.computed_status], fontSize: 11, fontWeight: 600, textTransform: 'uppercase' }}>
                        {a.computed_status}
                      </span>
                    </div>
                  </td>
                  <td style={{ padding: '8px 12px', color: '#fff', fontWeight: 600 }}>{a.hostname}</td>
                  <td style={{ padding: '8px 12px', color: 'var(--text2)' }}>
                    {getOsIcon(a.os)} {a.os || 'Unknown'}
                  </td>
                  <td style={{ padding: '8px 12px', color: 'var(--text2)', fontFamily: 'monospace' }}>{a.ip || '-'}</td>
                  <td style={{ padding: '8px 12px', color: 'var(--text3)' }}>{a.agent_version || '-'}</td>
                  <td style={{ padding: '8px 12px', color: 'var(--gold)', fontWeight: 600 }}>{(a.events_sent || 0).toLocaleString()}</td>
                  <td style={{ padding: '8px 12px', color: 'var(--text3)', fontSize: 11 }}>
                    {a.last_heartbeat ? formatDistanceToNow(new Date(a.last_heartbeat), { addSuffix: true }) : 'Never'}
                  </td>
                  <td style={{ padding: '8px 12px', color: 'var(--text3)', fontSize: 11 }}>
                    {a.registered_at ? formatDistanceToNow(new Date(a.registered_at), { addSuffix: true }) : '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Panel */}
      {detail && (
        <div style={{ width: 340, background: 'var(--bg2)', borderRadius: 8, border: '1px solid var(--border)', padding: 16, overflow: 'auto', flexShrink: 0 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ color: '#fff', margin: 0, fontSize: 15 }}>Agent Detail</h3>
            <div onClick={() => { setSelected(null); setDetail(null); }} style={{ cursor: 'pointer', color: 'var(--text3)', fontSize: 18 }}>×</div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
            <span style={{ fontSize: 28 }}>{getOsIcon(detail.os)}</span>
            <div>
              <div style={{ color: '#fff', fontWeight: 700, fontSize: 16 }}>{detail.hostname}</div>
              <div style={{ color: 'var(--text3)', fontSize: 11 }}>{detail.os}</div>
            </div>
          </div>

          {[
            { label: 'Agent ID', value: detail.id },
            { label: 'IP Address', value: detail.ip },
            { label: 'Version', value: detail.agent_version },
            { label: 'Status', value: detail.computed_status || detail.status },
            { label: 'Events Sent', value: (detail.events_sent || 0).toLocaleString() },
            { label: 'Event Count (DB)', value: (detail.event_count || 0).toLocaleString() },
          ].map(f => (
            <div key={f.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ color: 'var(--text3)', fontSize: 11 }}>{f.label}</span>
              <span style={{ color: 'var(--text)', fontSize: 11, fontFamily: f.label === 'Agent ID' ? 'monospace' : 'inherit', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.value || '-'}</span>
            </div>
          ))}

          {detail.collected_sources?.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div style={{ color: 'var(--text3)', fontSize: 11, marginBottom: 6 }}>Collected Sources</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {detail.collected_sources.map(s => (
                  <span key={s} style={{ background: 'var(--navy)', color: 'var(--gold)', fontSize: 10, padding: '2px 8px', borderRadius: 4 }}>{s}</span>
                ))}
              </div>
            </div>
          )}

          {detail.tags?.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <div style={{ color: 'var(--text3)', fontSize: 11, marginBottom: 6 }}>Tags</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {detail.tags.map(t => (
                  <span key={t} style={{ background: 'var(--bg3)', color: 'var(--text2)', fontSize: 10, padding: '2px 8px', borderRadius: 4 }}>{t}</span>
                ))}
              </div>
            </div>
          )}

          {/* Recent Events */}
          {detail.recent_events?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ color: 'var(--text3)', fontSize: 11, marginBottom: 8 }}>Recent Events</div>
              {detail.recent_events.slice(0, 10).map(e => (
                <div key={e.id} style={{ padding: '6px 8px', background: 'var(--bg3)', borderRadius: 4, marginBottom: 4, fontSize: 11 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#fff', fontWeight: 600 }}>{e.action || e.event_id}</span>
                    <span style={{
                      color: { Critical: '#fc8181', High: '#f6ad55', Medium: '#f6e05e', Low: '#68d391' }[e.severity] || 'var(--text3)',
                      fontSize: 10, fontWeight: 600,
                    }}>{e.severity}</span>
                  </div>
                  <div style={{ color: 'var(--text3)', fontSize: 10 }}>
                    {e.source} · {e.computer} · {e.username}
                  </div>
                </div>
              ))}
            </div>
          )}

          <button onClick={() => deleteAgent(detail.id)} style={{
            marginTop: 20, width: '100%', padding: '8px 0', background: 'transparent',
            border: '1px solid var(--red)', color: 'var(--red)', borderRadius: 6,
            cursor: 'pointer', fontSize: 12, fontWeight: 600,
          }}>
            Remove Agent
          </button>
        </div>
      )}
    </div>
  );
}
