import React, { useEffect, useState } from 'react';
import { analyzeApi } from '../../services/api';
import OsintPanel from '../OSINT/OsintPanel';

const SEV = { Critical: 'badge-red', High: 'badge-orange', Medium: 'badge-blue', Low: 'badge-green', Info: 'badge-gray' };
const IOC_TYPE_TO_OSINT = { IP: 'ip', Domain: 'domain', Hash: 'hash', Email: 'email', URL: 'url' };

function osintSummary(hit) {
  const osint = hit.osint;
  if (!osint?.sources) return null;
  const parts = [];
  const geoSources = ['geo', 'geo_freeipapi', 'geo_ipwhois'].map(n => osint.sources[n]).filter(s => s?.data);
  if (geoSources.length) {
    const countries = geoSources.map(s => s.data.country).filter(Boolean);
    const counts = {};
    countries.forEach(c => { counts[c] = (counts[c] || 0) + 1; });
    const best = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
    if (best) parts.push(`Geo: ${best[0]} (${best[1]}/${countries.length} agree)`);
  }
  const gn = osint.sources.greynoise?.data;
  if (gn?.noise) parts.push(`GreyNoise: ${gn.classification || 'noise'}`);
  else if (gn?.riot) parts.push('GreyNoise: benign service');
  ['abuseipdb', 'virustotal', 'shodan', 'urlscan', 'safe_browsing'].forEach(name => {
    const src = osint.sources[name];
    if (src?.configured && src.data != null) parts.push(`${name}: cached`);
  });
  return parts.length ? parts.join(' · ') : 'cached (no configured sources)';
}

// Inline rendering of an offline analyzer run — fetches the JSON report from the Go service
// and shows it directly in the app instead of only offering a file download, so an analyst can
// see the actual hits/image evidence without leaving the page or hunting through Downloads.
export default function OfflineAnalysisPanel({ content, onClose }) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [downloading, setDownloading] = useState(false);
  const [osintTarget, setOsintTarget] = useState(null);

  useEffect(() => {
    if (!content) return;
    setLoading(true);
    setError('');
    analyzeApi.offline({ content })
      .then(res => setResult(res.data))
      .catch(e => setError(e.response?.data?.error || e.message || 'Analysis failed'))
      .finally(() => setLoading(false));
  }, [content]);

  const downloadHtml = async () => {
    setDownloading(true);
    try {
      const res = await analyzeApi.offlineHtml({ content });
      const blob = new Blob([res.data], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `k3-offline-analysis-${new Date().toISOString().replace(/[:.]/g, '-')}.html`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 1000, display: 'flex', justifyContent: 'flex-end' }} onClick={onClose}>
      <div style={{ width: 720, maxWidth: '100%', height: '100%', background: 'var(--bg)', borderLeft: '1px solid var(--border)', padding: 16, overflowY: 'auto' }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600 }}>🔬 Offline Analysis Report</div>
            <div style={{ fontSize: 11, color: 'var(--text3)' }}>OSINT-enriched IOC matching against the cached threat-intel feeds, via the Go analyzer</div>
          </div>
          <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
            <button className="btn btn-secondary btn-sm" disabled={downloading || loading || !!error} onClick={downloadHtml}>
              {downloading ? 'Preparing…' : '⬇ Download HTML'}
            </button>
            <button className="btn btn-secondary btn-sm" onClick={onClose}>Close</button>
          </div>
        </div>

        {loading && <div style={{ color: 'var(--text3)', fontSize: 12 }}>Analyzing…</div>}
        {error && <div style={{ color: '#fc8181', fontSize: 12 }}>{error}</div>}

        {result && (
          <>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14 }}>
              {result.files_scanned > 0 && <span className="badge badge-gray">{result.files_scanned} files scanned</span>}
              <span className="badge badge-gray">{result.lines_scanned} lines scanned</span>
              <span className="badge badge-gray">{(result.hits || []).length} hits</span>
              {result.images?.length > 0 && <span className="badge badge-gray">{result.images.length} image(s) with metadata</span>}
              {Object.entries(result.hits_by_severity || {}).map(([sev, count]) => (
                <span key={sev} className={`badge ${SEV[sev] || 'badge-gray'}`}>{count} {sev}</span>
              ))}
              {(result.hits || []).length === 0 && !(result.images || []).length && (
                <span className="badge badge-gray">No indicator matches or image evidence found</span>
              )}
            </div>

            {(result.hits || []).length > 0 && (
              <div style={{ marginBottom: 18 }}>
                <div style={{ fontSize: 11, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: .5, marginBottom: 6 }}>
                  Indicator Hits ({result.hits.length})
                </div>
                <table>
                  <thead>
                    <tr>
                      {result.files_scanned > 0 && <th>File</th>}
                      <th>Line</th><th>Type</th><th>Value</th><th>Severity</th><th>Conf.</th><th>Source</th><th>OSINT</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.hits.map((h, hi) => (
                      <tr key={hi}>
                        {result.files_scanned > 0 && (
                          <td style={{ fontSize: 10, color: 'var(--text3)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.source_file}</td>
                        )}
                        <td style={{ fontSize: 11 }}>{h.line_number}</td>
                        <td><span className="badge badge-gray">{h.indicator?.type}</span></td>
                        <td style={{ fontFamily: 'monospace', fontSize: 11 }}>
                          {IOC_TYPE_TO_OSINT[h.indicator?.type] ? (
                            <span style={{ cursor: 'pointer', color: 'var(--gold)' }} onClick={() => setOsintTarget({ type: IOC_TYPE_TO_OSINT[h.indicator.type], value: h.indicator.value })}>{h.indicator?.value}</span>
                          ) : h.indicator?.value}
                        </td>
                        <td><span className={`badge ${SEV[h.indicator?.severity] || 'badge-gray'}`}>{h.indicator?.severity}</span></td>
                        <td style={{ fontSize: 11 }}>{h.indicator?.confidence}%</td>
                        <td style={{ fontSize: 11, color: 'var(--text2)' }}>{h.indicator?.source || '—'}</td>
                        <td style={{ fontSize: 10, color: 'var(--text2)', maxWidth: 180 }}>{osintSummary(h) || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {(result.images || []).length > 0 && (
              <div>
                <div style={{ fontSize: 11, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: .5, marginBottom: 6 }}>
                  📷 Image Evidence ({result.images.length})
                </div>
                <table>
                  <thead><tr><th>File</th><th>Format</th><th>GPS</th><th>Captured</th><th>Make / Model</th><th>Software</th><th>Note</th></tr></thead>
                  <tbody>
                    {result.images.map((img, ii) => (
                      <tr key={ii}>
                        <td style={{ fontSize: 10, color: 'var(--text2)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{img.path}</td>
                        <td style={{ fontSize: 11 }}>{img.format}</td>
                        <td style={{ fontSize: 11 }}>
                          {img.has_gps ? (
                            <a href={img.map_url} target="_blank" rel="noreferrer" style={{ color: 'var(--gold)' }}>{img.latitude?.toFixed(5)}, {img.longitude?.toFixed(5)}</a>
                          ) : '—'}
                        </td>
                        <td style={{ fontSize: 11 }}>{img.captured_at ? new Date(img.captured_at).toLocaleString() : '—'}</td>
                        <td style={{ fontSize: 11 }}>{[img.make, img.model].filter(Boolean).join(' ') || '—'}</td>
                        <td style={{ fontSize: 11 }}>{img.software || '—'}</td>
                        <td style={{ fontSize: 10, color: '#f6ad55' }}>{img.warning || ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>

      {osintTarget && (
        <OsintPanel type={osintTarget.type} value={osintTarget.value} onClose={() => setOsintTarget(null)} />
      )}
    </div>
  );
}
