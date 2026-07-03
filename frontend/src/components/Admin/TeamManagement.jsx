import React, { useEffect, useState, useCallback } from 'react';
import { teamsApi, usersApi, agentsApi } from '../../services/api';

const ROLES = ['t1_analyst', 't2_analyst', 'admin'];

export default function TeamManagement() {
  const [teams, setTeams] = useState([]);
  const [users, setUsers] = useState([]);
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newTeam, setNewTeam] = useState({ name: '', description: '' });
  const [creating, setCreating] = useState(false);
  const [savingId, setSavingId] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([teamsApi.list(), usersApi.list(), agentsApi.list()])
      .then(([t, u, a]) => {
        setTeams(t.data.teams || []);
        setUsers(u.data.users || []);
        setAgents(a.data.agents || []);
        setLoading(false);
      }).catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  async function createTeam() {
    if (!newTeam.name.trim()) return;
    setCreating(true);
    try {
      await teamsApi.create(newTeam);
      setNewTeam({ name: '', description: '' });
      await load();
    } finally { setCreating(false); }
  }

  async function deleteTeam(id) {
    if (!window.confirm('Delete this team? Only allowed if no users, agents, or incidents still reference it.')) return;
    try {
      await teamsApi.remove(id);
      await load();
    } catch (e) {
      window.alert(e.response?.data?.error || 'Failed to delete team');
    }
  }

  async function setUserField(id, field, value) {
    setSavingId(id);
    try {
      await usersApi.update(id, { [field]: value || null });
      await load();
    } finally { setSavingId(null); }
  }

  async function setAgentTeam(id, teamId) {
    setSavingId(id);
    try {
      await agentsApi.update(id, { team_id: teamId || null });
      await load();
    } finally { setSavingId(null); }
  }

  if (loading) return <div style={{ color: 'var(--text3)', padding: 20 }}>Loading…</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <h2 style={{ margin: 0, fontSize: 16, color: 'var(--text)' }}>Teams &amp; Users</h2>
      <div style={{ fontSize: 12, color: 'var(--text3)' }}>
        Non-admin analysts only see alerts, incidents, and agents belonging to their own team,
        plus unassigned items (shared inbox). Admins always see everything.
      </div>

      <div className="card">
        <div className="card-title">Teams</div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
          <input placeholder="Team name" value={newTeam.name} onChange={e => setNewTeam(t => ({ ...t, name: e.target.value }))} style={{ flex: 1, padding: '6px 10px' }} />
          <input placeholder="Description (optional)" value={newTeam.description} onChange={e => setNewTeam(t => ({ ...t, description: e.target.value }))} style={{ flex: 2, padding: '6px 10px' }} />
          <button className="btn btn-primary btn-sm" disabled={creating} onClick={createTeam}>+ Add Team</button>
        </div>
        <table>
          <thead><tr><th>Name</th><th>Description</th><th></th></tr></thead>
          <tbody>
            {teams.map(t => (
              <tr key={t.id}>
                <td style={{ fontWeight: 600 }}>{t.name}</td>
                <td style={{ fontSize: 12, color: 'var(--text2)' }}>{t.description}</td>
                <td><button className="btn btn-secondary btn-sm" style={{ color: '#fc8181' }} onClick={() => deleteTeam(t.id)}>Delete</button></td>
              </tr>
            ))}
            {teams.length === 0 && <tr><td colSpan={3} style={{ color: 'var(--text3)', fontSize: 12 }}>No teams yet.</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="card">
        <div className="card-title">Users</div>
        <table>
          <thead><tr><th>Username</th><th>Full Name</th><th>Role</th><th>Team</th></tr></thead>
          <tbody>
            {users.map(u => (
              <tr key={u.id}>
                <td style={{ fontFamily: 'monospace' }}>{u.username}</td>
                <td>{u.full_name}</td>
                <td>
                  <select value={u.role} disabled={savingId === u.id} onChange={e => setUserField(u.id, 'role', e.target.value)}>
                    {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                  </select>
                </td>
                <td>
                  <select value={u.team_id || ''} disabled={savingId === u.id} onChange={e => setUserField(u.id, 'team_id', e.target.value)}>
                    <option value="">Unassigned</option>
                    {teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <div className="card-title">Agents</div>
        <table>
          <thead><tr><th>Hostname</th><th>OS</th><th>Status</th><th>Team</th></tr></thead>
          <tbody>
            {agents.map(a => (
              <tr key={a.id}>
                <td style={{ fontFamily: 'monospace' }}>{a.hostname}</td>
                <td style={{ fontSize: 12, color: 'var(--text2)' }}>{a.os}</td>
                <td><span className="badge badge-gray">{a.computed_status}</span></td>
                <td>
                  <select value={a.team_id || ''} disabled={savingId === a.id} onChange={e => setAgentTeam(a.id, e.target.value)}>
                    <option value="">Unassigned</option>
                    {teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
