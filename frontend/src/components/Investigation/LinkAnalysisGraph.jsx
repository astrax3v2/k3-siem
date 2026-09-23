import React, { useMemo, useRef, useState } from 'react';
import OsintPanel from '../OSINT/OsintPanel';

const IOC_TYPE_TO_OSINT = { IP: 'ip', Domain: 'domain', Hash: 'hash', Email: 'email', URL: 'url' };
const SEV_COLOR = { Critical: '#fc8181', High: '#f6ad55', Medium: '#63b3ed', Low: '#68d391', Info: '#a0aec0' };

const NODE_STYLE = {
  incident: { color: '#f5a623', radius: 18, icon: '🛡️' },
  alert: { color: '#4a5568', radius: 9, icon: '🚨' },
  asset: { color: '#805ad5', radius: 10, icon: '💻' },
  user: { color: '#38b2ac', radius: 10, icon: '👤' },
  ip: { color: '#ed8936', radius: 10, icon: '🌐' },
  ioc: { color: '#e53e3e', radius: 10, icon: '⚠' },
};

// Builds a Maltego-style entity graph purely from data the incident report already assembled
// (entities, ioc_summary, alerts) — no separate backend endpoint needed. Nodes: the incident at
// the center, each linked alert, and every asset/user/IP/IOC that shows up across those alerts.
// Edges represent "appeared together in this alert", which is what an analyst actually wants to
// pivot on during triage: click any IP/domain/hash/email/URL node to open the same OSINT panel
// used everywhere else in the app.
function buildGraph(report) {
  const { incident, alerts = [], ioc_summary: iocSummary = [] } = report;
  const nodes = new Map();
  const edges = [];
  const addNode = (id, node) => { if (!nodes.has(id)) nodes.set(id, { id, ...node }); };
  const addEdge = (source, target) => edges.push({ source, target });

  addNode('incident', { type: 'incident', label: incident?.title || 'Incident' });

  const iocValueToType = new Map();
  iocSummary.forEach(s => s.values.forEach(v => iocValueToType.set(v, s.type)));

  alerts.slice(0, 60).forEach((a, i) => {
    const alertId = `alert:${a.id || i}`;
    addNode(alertId, { type: 'alert', label: a.title, severity: a.severity });
    addEdge('incident', alertId);

    if (a.asset) {
      const id = `asset:${a.asset}`;
      addNode(id, { type: 'asset', label: a.asset });
      addEdge(alertId, id);
    }
    if (a.username) {
      const id = `user:${a.username}`;
      addNode(id, { type: 'user', label: a.username });
      addEdge(alertId, id);
    }
    if (a.ip_address) {
      const id = `ip:${a.ip_address}`;
      addNode(id, { type: 'ip', label: a.ip_address, osint: 'ip' });
      addEdge(alertId, id);
    }
    if (a.ioc) {
      const id = `ioc:${a.ioc.type}:${a.ioc.value}`;
      addNode(id, { type: 'ioc', label: a.ioc.value, iocType: a.ioc.type, osint: IOC_TYPE_TO_OSINT[a.ioc.type] });
      addEdge(alertId, id);
    }
  });

  // Any IOC values summarized but not directly wired to a single alert's `ioc` field still get
  // a node hanging off the incident, so nothing gets silently dropped from the report's own count.
  iocSummary.forEach(s => s.values.forEach(v => {
    const id = `ioc:${s.type}:${v}`;
    if (!nodes.has(id)) {
      addNode(id, { type: 'ioc', label: v, iocType: s.type, osint: IOC_TYPE_TO_OSINT[s.type] });
      addEdge('incident', id);
    }
  }));

  return { nodes: [...nodes.values()], edges };
}

// Classic Fruchterman-Reingold-style force layout, computed synchronously once per graph. Small
// enough graphs (single-incident scope, capped at ~60 alerts) that O(n²) repulsion for a couple
// hundred iterations is instant — no need for a streaming/animated simulation or an external
// graph library.
function layout(nodes, edges, width, height) {
  const n = nodes.length;
  if (n === 0) return [];
  const idx = new Map(nodes.map((node, i) => [node.id, i]));
  const pos = nodes.map((node, i) => ({
    ...node,
    x: width / 2 + Math.cos((2 * Math.PI * i) / n) * Math.min(width, height) * 0.38,
    y: height / 2 + Math.sin((2 * Math.PI * i) / n) * Math.min(width, height) * 0.38,
    vx: 0, vy: 0,
  }));
  const edgeIdx = edges.map(e => [idx.get(e.source), idx.get(e.target)]).filter(([a, b]) => a != null && b != null);

  const REPULSION = 14000;
  const SPRING_LEN = 95;
  const SPRING_K = 0.02;
  const CENTER_K = 0.015;
  const DAMPING = 0.82;
  const ITERATIONS = n > 120 ? 120 : 260;

  for (let iter = 0; iter < ITERATIONS; iter++) {
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const dx = pos[i].x - pos[j].x;
        const dy = pos[i].y - pos[j].y;
        const distSq = dx * dx + dy * dy || 0.01;
        const force = REPULSION / distSq;
        const dist = Math.sqrt(distSq);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        pos[i].vx += fx; pos[i].vy += fy;
        pos[j].vx -= fx; pos[j].vy -= fy;
      }
    }
    for (const [a, b] of edgeIdx) {
      const dx = pos[b].x - pos[a].x;
      const dy = pos[b].y - pos[a].y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const force = (dist - SPRING_LEN) * SPRING_K;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      pos[a].vx += fx; pos[a].vy += fy;
      pos[b].vx -= fx; pos[b].vy -= fy;
    }
    for (let i = 0; i < n; i++) {
      pos[i].vx += (width / 2 - pos[i].x) * CENTER_K;
      pos[i].vy += (height / 2 - pos[i].y) * CENTER_K;
      pos[i].vx *= DAMPING;
      pos[i].vy *= DAMPING;
      pos[i].x += pos[i].vx * 0.02;
      pos[i].y += pos[i].vy * 0.02;
    }
  }
  return pos;
}

const CANVAS_W = 1400;
const CANVAS_H = 900;

export default function LinkAnalysisGraph({ report, onClose }) {
  const [osintTarget, setOsintTarget] = useState(null);
  const [hoverId, setHoverId] = useState(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 0.55 });
  const dragRef = useRef(null);

  const { nodes, edges } = useMemo(() => buildGraph(report), [report]);
  const positioned = useMemo(() => layout(nodes, edges, CANVAS_W, CANVAS_H), [nodes, edges]);
  const byId = useMemo(() => new Map(positioned.map(n => [n.id, n])), [positioned]);

  const onWheel = (e) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setView(v => ({ ...v, k: Math.min(2.5, Math.max(0.15, v.k * delta)) }));
  };

  const onPointerDown = (e) => {
    dragRef.current = { startX: e.clientX, startY: e.clientY, origX: view.x, origY: view.y };
  };
  const onPointerMove = (e) => {
    if (!dragRef.current) return;
    const dx = e.clientX - dragRef.current.startX;
    const dy = e.clientY - dragRef.current.startY;
    setView(v => ({ ...v, x: dragRef.current.origX + dx, y: dragRef.current.origY + dy }));
  };
  const onPointerUp = () => { dragRef.current = null; };

  const nodeClick = (node) => {
    if (node.osint) setOsintTarget({ type: node.osint, value: node.label });
  };

  const connected = (id) => {
    const set = new Set([id]);
    edges.forEach(e => {
      if (e.source === id) set.add(e.target);
      if (e.target === id) set.add(e.source);
    });
    return set;
  };
  const highlight = hoverId ? connected(hoverId) : null;

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'var(--bg)', zIndex: 1100, display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 16px', borderBottom: '1px solid var(--border)' }}>
        <div>
          <div style={{ fontSize: 15, fontWeight: 600 }}>🕸️ Link Analysis</div>
          <div style={{ fontSize: 11, color: 'var(--text3)' }}>
            {report.incident?.title} · {nodes.length} entities · {edges.length} links · scroll to zoom, drag to pan, click a node to pivot
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button className="btn btn-secondary btn-sm" onClick={() => setView({ x: 0, y: 0, k: 0.55 })}>Reset View</button>
          <button className="btn btn-secondary btn-sm" onClick={onClose}>Close</button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 14, padding: '8px 16px', fontSize: 11, color: 'var(--text3)', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
        {Object.entries(NODE_STYLE).map(([type, s]) => (
          <span key={type} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: s.color, display: 'inline-block' }} />
            {type === 'ioc' ? 'IOC (domain/hash/email/URL)' : type}
          </span>
        ))}
      </div>

      <div
        style={{ flex: 1, overflow: 'hidden', cursor: dragRef.current ? 'grabbing' : 'grab', background: 'radial-gradient(circle at center, var(--bg2), var(--bg))' }}
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerLeave={onPointerUp}
      >
        <svg width="100%" height="100%">
          <g transform={`translate(${view.x + window.innerWidth / 2 - (CANVAS_W / 2) * view.k}, ${view.y + (window.innerHeight - 90) / 2 - (CANVAS_H / 2) * view.k}) scale(${view.k})`}>
            {edges.map((e, i) => {
              const a = byId.get(e.source);
              const b = byId.get(e.target);
              if (!a || !b) return null;
              const dim = highlight && !(highlight.has(e.source) && highlight.has(e.target));
              return (
                <line
                  key={i}
                  x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                  stroke={dim ? 'var(--border)' : 'var(--text3)'}
                  strokeWidth={dim ? 1 : 1.4}
                  opacity={dim ? 0.25 : 0.7}
                />
              );
            })}
            {positioned.map(node => {
              const style = NODE_STYLE[node.type] || NODE_STYLE.ioc;
              const color = node.type === 'alert' ? (SEV_COLOR[node.severity] || style.color) : style.color;
              const dim = highlight && !highlight.has(node.id);
              const clickable = !!node.osint;
              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  onMouseEnter={() => setHoverId(node.id)}
                  onMouseLeave={() => setHoverId(null)}
                  onClick={() => nodeClick(node)}
                  style={{ cursor: clickable ? 'pointer' : 'default', opacity: dim ? 0.3 : 1 }}
                >
                  <circle r={style.radius} fill={color} stroke={clickable ? '#fff' : 'none'} strokeWidth={clickable ? 1.5 : 0} />
                  <title>{node.label}{node.iocType ? ` (${node.iocType})` : ''}</title>
                  <text
                    y={style.radius + 12}
                    textAnchor="middle"
                    fontSize={11}
                    fill={clickable ? 'var(--gold)' : 'var(--text2)'}
                    style={{ pointerEvents: 'none', fontFamily: clickable ? 'Consolas, monospace' : 'inherit' }}
                  >
                    {node.label.length > 24 ? node.label.slice(0, 24) + '…' : node.label}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {osintTarget && (
        <OsintPanel type={osintTarget.type} value={osintTarget.value} onClose={() => setOsintTarget(null)} />
      )}
    </div>
  );
}
