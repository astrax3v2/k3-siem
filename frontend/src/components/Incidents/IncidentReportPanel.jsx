import React, { useState } from 'react';
import OsintPanel from '../OSINT/OsintPanel';
import LinkAnalysisGraph from '../Investigation/LinkAnalysisGraph';

const SEV = { Critical: 'badge-red', High: 'badge-orange', Medium: 'badge-blue', Low: 'badge-green', Info: 'badge-gray' };
const IOC_TYPE_TO_OSINT = { IP: 'ip', Domain: 'domain', Hash: 'hash', Email: 'email', URL: 'url' };

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontSize: 11, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: .5, marginBottom: 6 }}>{title}</div>
      {children}
    </div>
  );
}

function Chip({ children }) {
  return <span className="badge badge-gray" style={{ marginRight: 5, marginBottom: 5, display: 'inline-block' }}>{children}</span>;
}

// Slide-over rendering the assembled result of a "generate report" request — the narrative and
// grouping are computed server-side from data the pipeline already produced (alerts, IOC
// matches, MITRE coverage); this just lays it out and wires indicator clicks to OsintPanel.
export default function IncidentReportPanel({ report, onClose }) {
  const [osintTarget, setOsintTarget] = useState(null);
  const [showGraph, setShowGraph] = useState(false);
  if (!report) return null;
  const { incident, alerts = [], notes = [], entities = {}, mitre = [], ioc_summary: iocSummary = [], narrative, generated_at: generatedAt } = report;

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 1000, display: 'flex', justifyContent: 'flex-end' }}
      onClick={onClose}
    >
      <div
        className="print-area"
        style={{ width: 480, maxWidth: '100%', height: '100%', background: 'var(--bg)', borderLeft: '1px solid var(--border)', padding: 16, overflowY: 'auto' }}
        onClick={e => e.stopPropagation()}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600 }}>Incident Report</div>
            <div style={{ fontSize: 12, color: 'var(--text3)' }}>{incident?.title}</div>
            {generatedAt && <div style={{ fontSize: 10, color: 'var(--text3)' }}>Generated {new Date(generatedAt).toLocaleString()}</div>}
          </div>
          <div className="no-print" style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
            <button className="btn btn-secondary btn-sm" onClick={() => setShowGraph(true)}>🕸️ Link Analysis</button>
            <button className="btn btn-secondary btn-sm" onClick={() => window.print()}>🖨️ Export PDF</button>
            <button className="btn btn-secondary btn-sm" onClick={onClose}>Close</button>
          </div>
        </div>

        <Section title="Summary">
          <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6 }}>{narrative}</div>
        </Section>

        {mitre.length > 0 && (
          <Section title="MITRE Tactics">
            {mitre.map(t => <Chip key={t}>{t}</Chip>)}
          </Section>
        )}

        <Section title="Entities Involved">
          <div style={{ display: 'flex', flexWrap: 'wrap' }}>
            {entities.assets?.map(a => <Chip key={`asset:${a}`}>💻 {a}</Chip>)}
            {entities.users?.map(u => <Chip key={`user:${u}`}>👤 {u}</Chip>)}
            {entities.ips?.map(ip => (
              <span
                key={`ip:${ip}`}
                className="badge badge-gray"
                style={{ marginRight: 5, marginBottom: 5, display: 'inline-block', cursor: 'pointer', color: 'var(--gold)' }}
                onClick={() => setOsintTarget({ type: 'ip', value: ip })}
              >
                🌐 {ip}
              </span>
            ))}
            {!entities.assets?.length && !entities.users?.length && !entities.ips?.length && (
              <span style={{ fontSize: 12, color: 'var(--text3)' }}>None recorded</span>
            )}
          </div>
        </Section>

        {iocSummary.length > 0 && (
          <Section title="Threat Intel Context">
            <table>
              <thead><tr><th>Type</th><th>Indicators</th><th>Alerts</th></tr></thead>
              <tbody>
                {iocSummary.map(s => (
                  <tr key={s.type}>
                    <td><span className="badge badge-gray">{s.type}</span></td>
                    <td style={{ fontSize: 11 }}>
                      {s.values.map((v, vi) => (
                        <span key={v}>
                          {IOC_TYPE_TO_OSINT[s.type] ? (
                            <span style={{ cursor: 'pointer', color: 'var(--gold)', fontFamily: 'monospace' }} onClick={() => setOsintTarget({ type: IOC_TYPE_TO_OSINT[s.type], value: v })}>{v}</span>
                          ) : <span style={{ fontFamily: 'monospace' }}>{v}</span>}
                          {vi < s.values.length - 1 ? ', ' : ''}
                        </span>
                      ))}
                    </td>
                    <td style={{ fontSize: 11, textAlign: 'center' }}>{s.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
        )}

        <Section title={`Alerts (${alerts.length})`}>
          <table>
            <thead><tr><th>Sev</th><th>Title</th><th>Source</th></tr></thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr><td colSpan={3} style={{ padding: 10, color: 'var(--text3)', fontSize: 12 }}>No alerts linked</td></tr>
              ) : alerts.map((a, ai) => (
                <tr key={a.id ? `report-alert:${a.id}:${ai}` : `report-alert:row:${ai}`}>
                  <td><span className={`badge ${SEV[a.severity] || 'badge-gray'}`}>{a.severity}</span></td>
                  <td style={{ fontSize: 11, color: 'var(--text2)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.title}
                    {a.ioc && <span className="badge badge-blue" style={{ marginLeft: 5, fontSize: 9 }}>IOC</span>}
                  </td>
                  <td style={{ fontSize: 10, color: 'var(--text3)' }}>{a.source || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>

        <Section title={`Notes (${notes.length})`}>
          {notes.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--text3)' }}>No notes yet</div>
          ) : notes.map((n, ni) => (
            <div key={n.id ? `report-note:${n.id}:${ni}` : `report-note:row:${ni}`} style={{ background: 'var(--bg4)', borderRadius: 6, padding: '8px 10px', marginBottom: 6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
                <span style={{ fontSize: 11, color: 'var(--gold)', fontWeight: 600 }}>{n.author || 'analyst'}</span>
                <span style={{ fontSize: 10, color: 'var(--text3)' }}>{new Date(n.created_at).toLocaleString()}</span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text2)', whiteSpace: 'pre-wrap' }}>{n.note}</div>
            </div>
          ))}
        </Section>
      </div>

      {osintTarget && (
        <OsintPanel type={osintTarget.type} value={osintTarget.value} onClose={() => setOsintTarget(null)} />
      )}
      {showGraph && (
        <LinkAnalysisGraph report={report} onClose={() => setShowGraph(false)} />
      )}
    </div>
  );
}
