import React, { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { incidentsApi } from '../../services/api';

const SEV = { Critical: 'badge-red', High: 'badge-orange', Medium: 'badge-blue', Low: 'badge-green', Info: 'badge-gray' };
const SEV_COLOR = { Critical: '#fc8181', High: '#f6ad55', Medium: '#90cdf4', Low: '#68d391', Info: '#94a3b8' };
const EVENT_ICON = {
  'Process Create': '⚙️', 'Network Connect': '🌐', 'Registry Modify': '🗝️',
  'File Access': '📄', 'Terminate': '🛑',
};

function buildTree(nodes) {
  const byId = new Map(nodes.map(n => [n.id, { ...n, children: [] }]));
  const roots = [];
  for (const n of byId.values()) {
    if (n.parent_id && byId.has(n.parent_id)) byId.get(n.parent_id).children.push(n);
    else roots.push(n);
  }
  return roots;
}

function TreeNode({ node, depth, selectedId, onSelect, isLast }) {
  const active = selectedId === node.id;
  const isRoot = depth === 0;
  const isCompromiseLeaf = node.children.length === 0 && node.is_malicious && node.severity === 'Critical';

  return (
    <div>
      <div
        onClick={() => onSelect(node.id)}
        style={{
          display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer',
          marginLeft: depth * 24, padding: '6px 10px', borderRadius: 6,
          borderLeft: `3px solid ${SEV_COLOR[node.severity] || '#94a3b8'}`,
          background: active ? 'rgba(245,166,35,.1)' : 'var(--bg2)',
          marginBottom: 4, marginTop: 4,
        }}
      >
        <span style={{ fontSize: 14 }}>{EVENT_ICON[node.event_type] || '🖥️'}</span>
        <span style={{ fontFamily: 'monospace', fontSize: 12.5, fontWeight: 600 }}>{node.process_name}</span>
        <span style={{ fontSize: 10, color: 'var(--text3)' }}>PID {node.pid}</span>
        <span className={`badge ${SEV[node.severity] || 'badge-gray'}`} style={{ fontSize: 9 }}>{node.severity}</span>
        {node.is_malicious ? <span className="badge badge-red" style={{ fontSize: 9 }}>MALICIOUS</span> : null}
        <span style={{ fontSize: 10, color: 'var(--text3)', marginLeft: 4 }}>{node.first_detected_by}</span>
        {isRoot && <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--gold)', fontWeight: 700 }}>🎯 INITIAL ENTRY VECTOR</span>}
        {isCompromiseLeaf && <span style={{ marginLeft: 'auto', fontSize: 10, color: '#fc8181', fontWeight: 700 }}>💀 FULL COMPROMISE</span>}
      </div>
      {node.children.map((c, i) => (
        <TreeNode key={c.id} node={c} depth={depth + 1} selectedId={selectedId} onSelect={onSelect} isLast={i === node.children.length - 1} />
      ))}
    </div>
  );
}

export default function ProcessTree() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    incidentsApi.get(id).then(res => { setData(res.data); setLoading(false); }).catch(() => setLoading(false));
  }, [id]);

  useEffect(() => { load(); }, [load]);

  if (loading) return <div style={{ padding: 20, color: 'var(--text3)' }}>Loading process tree…</div>;
  if (!data || !data.incident) return <div style={{ padding: 20, color: 'var(--text3)' }}>Incident not found.</div>;

  const { incident, process_tree = [] } = data;
  const tree = buildTree(process_tree);
  const selected = process_tree.find(n => n.id === selectedId);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <button className="btn btn-secondary btn-sm" onClick={() => navigate('/incidents')}>← Back to Incidents</button>
        <span style={{ fontSize: 13, fontWeight: 600 }}>🌳 Process Tree — Attack Chain Investigation</span>
      </div>

      <div className="card">
        <div className="card-title">Incident Overview</div>
        <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 6 }}>{incident.title}</div>
        <div style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 10, lineHeight: 1.5 }}>{incident.description}</div>
        <div style={{ display: 'flex', gap: 10 }}>
          <span className={`badge ${SEV[incident.severity] || 'badge-gray'}`}>{incident.severity}</span>
          <span className="badge badge-gray">{incident.status}</span>
          <span style={{ fontSize: 11, color: 'var(--text3)' }}>Owner: {incident.owner}</span>
          {process_tree[0] && <span style={{ fontSize: 11, color: 'var(--text3)' }}>Host: {process_tree[0].hostname} · User: {process_tree[0].username}</span>}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
        <div className="card">
          <div className="card-title">Impact</div>
          <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.5 }}>{incident.impact || '—'}</div>
        </div>
        <div className="card">
          <div className="card-title">Remediation</div>
          <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.5 }}>{incident.remediation || '—'}</div>
        </div>
        <div className="card">
          <div className="card-title">Lessons Learned</div>
          <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.5 }}>{incident.lessons_learned || '—'}</div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 12 }}>
        <div className="card" style={{ flex: 1, minWidth: 0, overflow: 'auto', maxHeight: 'calc(100vh - 420px)' }}>
          <div className="card-title">Process Execution Chain ({process_tree.length} stages)</div>
          {tree.length === 0 ? (
            <div style={{ color: 'var(--text3)', fontSize: 12 }}>No process tree data for this incident.</div>
          ) : tree.map(n => (
            <TreeNode key={n.id} node={n} depth={0} selectedId={selectedId} onSelect={setSelectedId} isLast />
          ))}
        </div>

        {selected && (
          <div className="card" style={{ width: 360, flexShrink: 0, overflow: 'auto', maxHeight: 'calc(100vh - 420px)' }}>
            <div className="card-title">{selected.process_name}</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 12, marginBottom: 10 }}>
              <div><span style={{ color: 'var(--text3)' }}>PID / PPID</span><div style={{ fontFamily: 'monospace' }}>{selected.pid} / {selected.ppid}</div></div>
              <div><span style={{ color: 'var(--text3)' }}>Severity</span><div><span className={`badge ${SEV[selected.severity] || 'badge-gray'}`}>{selected.severity}</span></div></div>
              <div><span style={{ color: 'var(--text3)' }}>Host</span><div style={{ fontFamily: 'monospace' }}>{selected.hostname}</div></div>
              <div><span style={{ color: 'var(--text3)' }}>User</span><div>{selected.username}</div></div>
              <div style={{ gridColumn: '1 / -1' }}><span style={{ color: 'var(--text3)' }}>Image</span><div style={{ fontFamily: 'monospace', fontSize: 11, wordBreak: 'break-all' }}>{selected.image}</div></div>
              <div style={{ gridColumn: '1 / -1' }}><span style={{ color: 'var(--text3)' }}>Command Line</span><div style={{ fontFamily: 'monospace', fontSize: 11, wordBreak: 'break-all', background: 'var(--bg4)', padding: 6, borderRadius: 4 }}>{selected.command_line}</div></div>
              {selected.sha256 && <div style={{ gridColumn: '1 / -1' }}><span style={{ color: 'var(--text3)' }}>SHA256</span><div style={{ fontFamily: 'monospace', fontSize: 10, wordBreak: 'break-all' }}>{selected.sha256}</div></div>}
              <div><span style={{ color: 'var(--text3)' }}>MITRE Tactic</span><div>{selected.mitre_tactic || '—'}</div></div>
              <div><span style={{ color: 'var(--text3)' }}>MITRE Technique</span><div style={{ fontFamily: 'monospace' }}>{selected.mitre_technique || '—'}</div></div>
              <div style={{ gridColumn: '1 / -1' }}><span style={{ color: 'var(--text3)' }}>Timestamp</span><div>{new Date(selected.timestamp).toLocaleString()}</div></div>
            </div>

            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: 'var(--gold)', fontWeight: 700, marginBottom: 3 }}>🔍 First Detected By</div>
              <div style={{ fontSize: 12, color: 'var(--text2)' }}>{selected.first_detected_by}</div>
              {selected.detection_rule && <div style={{ fontSize: 10, color: 'var(--text3)', marginTop: 2 }}>Rule: {selected.detection_rule}</div>}
            </div>

            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: 'var(--gold)', fontWeight: 700, marginBottom: 3 }}>🤖 Auto-Analysis</div>
              <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.5 }}>{selected.auto_analysis}</div>
            </div>

            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: 'var(--gold)', fontWeight: 700, marginBottom: 3 }}>💥 Impact</div>
              <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.5 }}>{selected.impact}</div>
            </div>

            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: 'var(--gold)', fontWeight: 700, marginBottom: 3 }}>🛠️ Remediation</div>
              <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.5 }}>{selected.remediation}</div>
            </div>

            {selected.lessons_learned && (
              <div>
                <div style={{ fontSize: 11, color: 'var(--gold)', fontWeight: 700, marginBottom: 3 }}>📘 Lessons Learned</div>
                <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.5 }}>{selected.lessons_learned}</div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
