import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { correlationApi } from '../../services/api';
import { useAuth } from '../Layout/Auth';

const SEV = {
  Critical: 'badge-red',
  High: 'badge-orange',
  Medium: 'badge-blue',
  Low: 'badge-green',
  Info: 'badge-gray',
};

const EMPTY_FORM = {
  name: '',
  description: '',
  logic: '',
  severity: 'High',
  risk_score: 80,
  window_minutes: 5,
  threshold: 1,
  indicesText: 'windows-security, network-flow',
};

function parseIndices(raw) {
  if (Array.isArray(raw)) return raw.map((item) => String(item).trim()).filter(Boolean);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.map((item) => String(item).trim()).filter(Boolean);
  } catch {}
  return String(raw).split(',').map((item) => item.trim()).filter(Boolean);
}

function toEditableForm(rule) {
  return {
    name: rule.name || '',
    description: rule.description || '',
    logic: rule.logic || '',
    severity: rule.severity || 'High',
    risk_score: rule.risk_score ?? 80,
    window_minutes: rule.window_minutes ?? 5,
    threshold: rule.threshold ?? 1,
    indicesText: parseIndices(rule.indices).join(', '),
    enabled: !!rule.enabled,
  };
}

export default function CorrelationManager() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [rules, setRules] = useState([]);
  const [crossHits, setCrossHits] = useState(0);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [savingEdit, setSavingEdit] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [editForm, setEditForm] = useState({ ...EMPTY_FORM, enabled: true });
  const canManage = user?.role === 'admin' || user?.role === 't2_analyst';

  useEffect(() => {
    correlationApi.rules().then((r) => {
      setRules(r.data.rules || []);
      setLoading(false);
    }).catch(() => setLoading(false));
    correlationApi.crossHits().then((r) => setCrossHits(r.data.count || 0)).catch(() => {});
  }, []);

  const toggle = async (rule) => {
    const res = await correlationApi.toggleRule(rule.id, !rule.enabled);
    setRules((prev) => prev.map((item) => (item.id === rule.id ? res.data : item)));
  };

  const createRule = async () => {
    if (!form.name.trim() || !form.logic.trim()) return;
    const res = await correlationApi.createRule({
      name: form.name.trim(),
      description: form.description.trim(),
      logic: form.logic.trim(),
      severity: form.severity,
      risk_score: parseInt(form.risk_score, 10) || 0,
      window_minutes: parseInt(form.window_minutes, 10) || 1,
      threshold: parseInt(form.threshold, 10) || 1,
      indices: parseIndices(form.indicesText),
    });
    setRules((prev) => [res.data, ...prev]);
    setShowNew(false);
    setForm(EMPTY_FORM);
  };

  const startEdit = (rule) => {
    setEditingId(rule.id);
    setEditForm(toEditableForm(rule));
  };

  const cancelEdit = () => {
    setEditingId(null);
    setSavingEdit(false);
  };

  const saveEdit = async (id) => {
    if (!editForm.name.trim() || !editForm.logic.trim()) return;
    setSavingEdit(true);
    try {
      const res = await correlationApi.updateRule(id, {
        name: editForm.name.trim(),
        description: editForm.description.trim(),
        logic: editForm.logic.trim(),
        severity: editForm.severity,
        risk_score: parseInt(editForm.risk_score, 10) || 0,
        window_minutes: parseInt(editForm.window_minutes, 10) || 1,
        threshold: parseInt(editForm.threshold, 10) || 1,
        indices: parseIndices(editForm.indicesText),
        enabled: !!editForm.enabled,
      });
      setRules((prev) => prev.map((item) => (item.id === id ? res.data : item)));
      setEditingId(null);
    } finally {
      setSavingEdit(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
        {[
          { l: 'Active Rules', v: rules.filter((r) => r.enabled).length, c: '#68d391' },
          { l: 'Total Hits (All Time)', v: rules.reduce((sum, r) => sum + (r.hit_count || 0), 0), c: '#f6ad55' },
          { l: 'Multi-Index Rules', v: rules.filter((r) => parseIndices(r.indices).length > 1).length, c: '#90cdf4' },
        ].map((s) => (
          <div key={s.l} className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 26, fontWeight: 700, color: s.c }}>{s.v}</div>
            <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 4 }}>{s.l}</div>
          </div>
        ))}
        <div className="card" style={{ textAlign: 'center', cursor: 'pointer' }} onClick={() => navigate('/incidents')} title="Incidents auto-created by correlating multiple alerts across rules for the same user, IP, or asset">
          <div style={{ fontSize: 26, fontWeight: 700, color: '#b794f4' }}>{crossHits}</div>
          <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 4 }}>Cross-Correlated Incidents (24h)</div>
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>Multi-Index Correlation Rules</h3>
        {canManage && <button className="btn btn-primary btn-sm" onClick={() => setShowNew((open) => !open)}>+ New Rule</button>}
      </div>

      {showNew && (
        <div className="card">
          <div className="card-title">Create Correlation Rule</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
            <input placeholder="Rule name" value={form.name} onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))} style={{ padding: '6px 10px' }} />
            <select value={form.severity} onChange={(e) => setForm((prev) => ({ ...prev, severity: e.target.value }))} style={{ padding: '6px 10px' }}>
              {['Critical', 'High', 'Medium', 'Low'].map((s) => <option key={s}>{s}</option>)}
            </select>
          </div>
          <input placeholder="Description" value={form.description} onChange={(e) => setForm((prev) => ({ ...prev, description: e.target.value }))} style={{ width: '100%', marginBottom: 10, padding: '6px 10px' }} />
          <textarea placeholder="Correlation logic..." value={form.logic} onChange={(e) => setForm((prev) => ({ ...prev, logic: e.target.value }))} rows={3} style={{ width: '100%', marginBottom: 10, padding: '6px 10px', fontFamily: 'Courier New', fontSize: 12 }} />
          <input placeholder="Indices (comma separated)" value={form.indicesText} onChange={(e) => setForm((prev) => ({ ...prev, indicesText: e.target.value }))} style={{ width: '100%', marginBottom: 10, padding: '6px 10px' }} />
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <input type="number" placeholder="Risk score" value={form.risk_score} onChange={(e) => setForm((prev) => ({ ...prev, risk_score: parseInt(e.target.value, 10) }))} style={{ width: 100, padding: '5px 8px' }} />
            <input type="number" placeholder="Window (min)" value={form.window_minutes} onChange={(e) => setForm((prev) => ({ ...prev, window_minutes: parseInt(e.target.value, 10) }))} style={{ width: 120, padding: '5px 8px' }} />
            <input type="number" placeholder="Threshold" value={form.threshold} onChange={(e) => setForm((prev) => ({ ...prev, threshold: parseInt(e.target.value, 10) }))} style={{ width: 110, padding: '5px 8px' }} />
            <button className="btn btn-primary btn-sm" onClick={createRule} disabled={!canManage}>Create Rule</button>
            <button className="btn btn-secondary btn-sm" onClick={() => setShowNew(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="card" style={{ padding: 0 }}>
        {loading ? <div style={{ padding: 20, color: 'var(--text3)' }}>Loading...</div> : (
          <table>
            <thead><tr><th>Name</th><th>Severity</th><th>Risk</th><th>Window</th><th>Indices</th><th>Hits</th><th>Enabled</th><th>Actions</th></tr></thead>
            <tbody>
              {rules.map((rule, index) => {
                const indices = parseIndices(rule.indices);
                return (
                  <React.Fragment key={rule.id ? `rule:${rule.id}:${index}` : `rule:row:${index}`}>
                    <tr>
                      <td>
                        <div style={{ fontWeight: 600, fontSize: 12 }}>{rule.name}</div>
                        {rule.description && <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 2 }}>{rule.description}</div>}
                        <div style={{ fontSize: 11, color: 'var(--text3)', marginTop: 2 }}>{rule.logic}</div>
                      </td>
                      <td><span className={`badge ${SEV[rule.severity] || 'badge-gray'}`}>{rule.severity}</span></td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                          <div style={{ width: 40, height: 4, background: 'var(--bg4)', borderRadius: 2, overflow: 'hidden' }}>
                            <div style={{ width: `${rule.risk_score}%`, height: '100%', background: rule.risk_score > 85 ? '#fc8181' : '#f6ad55' }} />
                          </div>
                          <span style={{ fontSize: 11, color: 'var(--text3)' }}>{rule.risk_score}</span>
                        </div>
                      </td>
                      <td><span className="badge badge-blue">{rule.window_minutes}m</span></td>
                      <td>{indices.map((idx, ii) => <span key={`${idx}:${ii}`} className="badge badge-gray" style={{ marginRight: 3, fontSize: 9 }}>{idx}</span>)}</td>
                      <td style={{ color: rule.hit_count > 5 ? '#fc8181' : 'var(--text2)', fontWeight: rule.hit_count > 5 ? 600 : 400 }}>{rule.hit_count}</td>
                      <td>
                        <div onClick={canManage ? () => toggle(rule) : undefined} style={{ width: 36, height: 18, borderRadius: 9, background: rule.enabled ? '#38A169' : 'var(--bg4)', position: 'relative', cursor: canManage ? 'pointer' : 'not-allowed', transition: 'background .2s', border: '1px solid var(--border)', opacity: canManage ? 1 : 0.6 }}>
                          <div style={{ position: 'absolute', top: 2, left: rule.enabled ? 18 : 2, width: 12, height: 12, borderRadius: '50%', background: '#fff', transition: 'left .2s' }} />
                        </div>
                      </td>
                      <td>
                        {canManage && (
                          <button className="btn btn-secondary btn-sm" onClick={() => (editingId === rule.id ? cancelEdit() : startEdit(rule))}>
                            {editingId === rule.id ? 'Close' : 'Edit'}
                          </button>
                        )}
                      </td>
                    </tr>
                    {editingId === rule.id && (
                      <tr>
                        <td colSpan={8} style={{ background: 'rgba(255,255,255,.02)' }}>
                          <div style={{ display: 'grid', gap: 8 }}>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 180px 110px', gap: 8 }}>
                              <input value={editForm.name} onChange={(e) => setEditForm((prev) => ({ ...prev, name: e.target.value }))} placeholder="Rule name" style={{ padding: '7px 10px' }} />
                              <select value={editForm.severity} onChange={(e) => setEditForm((prev) => ({ ...prev, severity: e.target.value }))} style={{ padding: '7px 10px' }}>
                                {['Critical', 'High', 'Medium', 'Low'].map((s) => <option key={s}>{s}</option>)}
                              </select>
                              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text2)' }}>
                                <input type="checkbox" checked={editForm.enabled} onChange={(e) => setEditForm((prev) => ({ ...prev, enabled: e.target.checked }))} style={{ width: 14, height: 14 }} />
                                Enabled
                              </label>
                            </div>
                            <input value={editForm.description} onChange={(e) => setEditForm((prev) => ({ ...prev, description: e.target.value }))} placeholder="Description" style={{ padding: '7px 10px' }} />
                            <textarea value={editForm.logic} onChange={(e) => setEditForm((prev) => ({ ...prev, logic: e.target.value }))} placeholder="Correlation logic" rows={3} style={{ padding: '7px 10px', fontFamily: 'Courier New', fontSize: 12, resize: 'vertical' }} />
                            <input value={editForm.indicesText} onChange={(e) => setEditForm((prev) => ({ ...prev, indicesText: e.target.value }))} placeholder="Indices (comma separated)" style={{ padding: '7px 10px' }} />
                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                              <input type="number" value={editForm.risk_score} onChange={(e) => setEditForm((prev) => ({ ...prev, risk_score: parseInt(e.target.value, 10) }))} placeholder="Risk score" style={{ width: 110, padding: '7px 10px' }} />
                              <input type="number" value={editForm.window_minutes} onChange={(e) => setEditForm((prev) => ({ ...prev, window_minutes: parseInt(e.target.value, 10) }))} placeholder="Window (min)" style={{ width: 120, padding: '7px 10px' }} />
                              <input type="number" value={editForm.threshold} onChange={(e) => setEditForm((prev) => ({ ...prev, threshold: parseInt(e.target.value, 10) }))} placeholder="Threshold" style={{ width: 100, padding: '7px 10px' }} />
                            </div>
                            <div style={{ display: 'flex', gap: 8 }}>
                              <button className="btn btn-primary btn-sm" disabled={savingEdit} onClick={() => saveEdit(rule.id)}>
                                {savingEdit ? 'Saving...' : 'Save'}
                              </button>
                              <button className="btn btn-secondary btn-sm" disabled={savingEdit} onClick={cancelEdit}>Cancel</button>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
