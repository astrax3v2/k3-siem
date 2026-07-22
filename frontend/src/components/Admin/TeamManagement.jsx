import React, { useEffect, useState, useCallback } from 'react';
import { tenantsApi, teamsApi, usersApi, agentsApi } from '../../services/api';

const ROLES = ['t1_analyst', 't2_analyst', 'admin'];

export default function TeamManagement() {
  const [tenants, setTenants] = useState([]);
  const [teams, setTeams] = useState([]);
  const [users, setUsers] = useState([]);
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newTenant, setNewTenant] = useState({ name: '', description: '' });
  const [newTeam, setNewTeam] = useState({ name: '', description: '', tenant_id: '' });
  const [creatingTenant, setCreatingTenant] = useState(false);
  const [creatingTeam, setCreatingTeam] = useState(false);
  const [savingId, setSavingId] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([tenantsApi.list(), teamsApi.list(), usersApi.list(), agentsApi.list()])
      .then(([tn, tm, u, a]) => {
        const tenantRows = tn.data.tenants || [];
        setTenants(tenantRows);
        setTeams(tm.data.teams || []);
        setUsers(u.data.users || []);
        setAgents(a.data.agents || []);
        if (!newTeam.tenant_id && tenantRows[0]?.id) {
          setNewTeam((current) => ({ ...current, tenant_id: tenantRows[0].id }));
        }
        setLoading(false);
      }).catch(() => setLoading(false));
  }, [newTeam.tenant_id]);

  useEffect(() => { load(); }, [load]);

  function teamsForTenant(tenantId) {
    return teams.filter((team) => (team.tenant_id || '') === (tenantId || ''));
  }

  async function createTenant() {
    if (!newTenant.name.trim()) return;
    setCreatingTenant(true);
    try {
      await tenantsApi.create(newTenant);
      setNewTenant({ name: '', description: '' });
      await load();
    } finally { setCreatingTenant(false); }
  }

  async function createTeam() {
    if (!newTeam.name.trim() || !newTeam.tenant_id) return;
    setCreatingTeam(true);
    try {
      await teamsApi.create(newTeam);
      setNewTeam({ name: '', description: '', tenant_id: tenants[0]?.id || '' });
      await load();
    } finally { setCreatingTeam(false); }
  }

  async function deleteTenant(id) {
    if (!window.confirm('Delete this tenant? Only allowed if no users, teams, agents, or dashboards reference it.')) return;
    try {
      await tenantsApi.remove(id);
      await load();
    } catch (e) {
      window.alert(e.response?.data?.error || 'Failed to delete tenant');
    }
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

  async function updateTenant(id, field, value) {
    setSavingId(id);
    try {
      await tenantsApi.update(id, { [field]: value });
      await load();
    } finally { setSavingId(null); }
  }

  async function updateTeam(id, field, value) {
    const team = teams.find((row) => row.id === id);
    if (!team) return;
    const payload = field === 'tenant_id'
      ? { tenant_id: value || null }
      : { [field]: value };
    setSavingId(id);
    try {
      await teamsApi.update(id, payload);
      await load();
    } catch (e) {
      window.alert(e.response?.data?.error || 'Failed to update team');
    } finally { setSavingId(null); }
  }

  async function updateUser(id, patch) {
    setSavingId(id);
    try {
      await usersApi.update(id, patch);
      await load();
    } catch (e) {
      window.alert(e.response?.data?.error || 'Failed to update user');
    } finally { setSavingId(null); }
  }

  async function updateAgent(id, patch) {
    setSavingId(id);
    try {
      await agentsApi.update(id, patch);
      await load();
    } catch (e) {
      window.alert(e.response?.data?.error || 'Failed to update agent');
    } finally { setSavingId(null); }
  }

  if (loading) return <div style={{ color: 'var(--text3)', padding: 20 }}>Loading…</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <h2 style={{ margin: 0, fontSize: 16, color: 'var(--text)' }}>Tenants, Teams &amp; Users</h2>
      <div style={{ fontSize: 12, color: 'var(--text3)' }}>
        This is the first multi-tenant foundation slice: tenant records, tenant-aware team and agent ownership, and tenant context attached to authenticated users.
      </div>

      <div className="card">
        <div className="card-title">Tenants</div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
          <input placeholder="Tenant name" value={newTenant.name} onChange={e => setNewTenant((t) => ({ ...t, name: e.target.value }))} style={{ flex: 1, padding: '6px 10px' }} />
          <input placeholder="Description (optional)" value={newTenant.description} onChange={e => setNewTenant((t) => ({ ...t, description: e.target.value }))} style={{ flex: 2, padding: '6px 10px' }} />
          <button className="btn btn-primary btn-sm" disabled={creatingTenant} onClick={createTenant}>+ Add Tenant</button>
        </div>
        <table>
          <thead><tr><th>Name</th><th>Description</th><th>Status</th><th>Counts</th><th></th></tr></thead>
          <tbody>
            {tenants.map((tenant) => (
              <tr key={tenant.id}>
                <td style={{ fontWeight: 600 }}>{tenant.name}</td>
                <td style={{ fontSize: 12, color: 'var(--text2)' }}>{tenant.description}</td>
                <td>
                  <select value={tenant.is_active ? 'active' : 'inactive'} disabled={savingId === tenant.id} onChange={(e) => updateTenant(tenant.id, 'is_active', e.target.value === 'active')}>
                    <option value="active">active</option>
                    <option value="inactive">inactive</option>
                  </select>
                </td>
                <td style={{ fontSize: 12, color: 'var(--text2)' }}>
                  {tenant.user_count || 0} users · {tenant.team_count || 0} teams · {tenant.agent_count || 0} agents
                </td>
                <td><button className="btn btn-secondary btn-sm" style={{ color: '#fc8181' }} onClick={() => deleteTenant(tenant.id)}>Delete</button></td>
              </tr>
            ))}
            {tenants.length === 0 && <tr><td colSpan={5} style={{ color: 'var(--text3)', fontSize: 12 }}>No tenants yet.</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="card">
        <div className="card-title">Teams</div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
          <select value={newTeam.tenant_id} onChange={(e) => setNewTeam((t) => ({ ...t, tenant_id: e.target.value }))} style={{ minWidth: 180 }}>
            <option value="">Select tenant</option>
            {tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
          </select>
          <input placeholder="Team name" value={newTeam.name} onChange={e => setNewTeam((t) => ({ ...t, name: e.target.value }))} style={{ flex: 1, padding: '6px 10px' }} />
          <input placeholder="Description (optional)" value={newTeam.description} onChange={e => setNewTeam((t) => ({ ...t, description: e.target.value }))} style={{ flex: 2, padding: '6px 10px' }} />
          <button className="btn btn-primary btn-sm" disabled={creatingTeam} onClick={createTeam}>+ Add Team</button>
        </div>
        <table>
          <thead><tr><th>Name</th><th>Tenant</th><th>Description</th><th></th></tr></thead>
          <tbody>
            {teams.map((team) => (
              <tr key={team.id}>
                <td style={{ fontWeight: 600 }}>{team.name}</td>
                <td>
                  <select value={team.tenant_id || ''} disabled={savingId === team.id} onChange={(e) => updateTeam(team.id, 'tenant_id', e.target.value)}>
                    <option value="">Unassigned</option>
                    {tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
                  </select>
                </td>
                <td style={{ fontSize: 12, color: 'var(--text2)' }}>{team.description}</td>
                <td><button className="btn btn-secondary btn-sm" style={{ color: '#fc8181' }} onClick={() => deleteTeam(team.id)}>Delete</button></td>
              </tr>
            ))}
            {teams.length === 0 && <tr><td colSpan={4} style={{ color: 'var(--text3)', fontSize: 12 }}>No teams yet.</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="card">
        <div className="card-title">Users</div>
        <table>
          <thead><tr><th>Username</th><th>Full Name</th><th>Role</th><th>Tenant</th><th>Team</th></tr></thead>
          <tbody>
            {users.map((user) => {
              const availableTeams = teamsForTenant(user.tenant_id);
              return (
                <tr key={user.id}>
                  <td style={{ fontFamily: 'monospace' }}>{user.username}</td>
                  <td>{user.full_name}</td>
                  <td>
                    <select value={user.role} disabled={savingId === user.id} onChange={(e) => updateUser(user.id, { role: e.target.value })}>
                      {ROLES.map((role) => <option key={role} value={role}>{role}</option>)}
                    </select>
                  </td>
                  <td>
                    <select
                      value={user.tenant_id || ''}
                      disabled={savingId === user.id}
                      onChange={(e) => updateUser(user.id, { tenant_id: e.target.value || null, team_id: null })}
                    >
                      {tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
                    </select>
                  </td>
                  <td>
                    <select value={user.team_id || ''} disabled={savingId === user.id} onChange={(e) => updateUser(user.id, { team_id: e.target.value || null })}>
                      <option value="">Unassigned</option>
                      {availableTeams.map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}
                    </select>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="card">
        <div className="card-title">Agents</div>
        <table>
          <thead><tr><th>Hostname</th><th>OS</th><th>Status</th><th>Tenant</th><th>Team</th></tr></thead>
          <tbody>
            {agents.map((agent) => {
              const availableTeams = teamsForTenant(agent.tenant_id);
              return (
                <tr key={agent.id}>
                  <td style={{ fontFamily: 'monospace' }}>{agent.hostname}</td>
                  <td style={{ fontSize: 12, color: 'var(--text2)' }}>{agent.os}</td>
                  <td><span className="badge badge-gray">{agent.computed_status}</span></td>
                  <td>
                    <select
                      value={agent.tenant_id || ''}
                      disabled={savingId === agent.id}
                      onChange={(e) => updateAgent(agent.id, { tenant_id: e.target.value || null, team_id: null })}
                    >
                      {tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
                    </select>
                  </td>
                  <td>
                    <select value={agent.team_id || ''} disabled={savingId === agent.id} onChange={(e) => updateAgent(agent.id, { team_id: e.target.value || null })}>
                      <option value="">Unassigned</option>
                      {availableTeams.map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}
                    </select>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
