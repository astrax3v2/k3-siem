import React, { useState, useEffect, useCallback } from 'react';
import { assetsApi, vulnApi } from '../../services/api';
import { formatDistanceToNow } from 'date-fns';
function softwareName(item) { return typeof item === 'object' ? item.name : item; }

const OS_ICONS = { Windows: '🪟', Ubuntu: '🐧', Linux: '🐧', 'PAN-OS': '🔥', macOS: '🍎', CentOS: '🐧', Debian: '🐧' };
function osIcon(name) { if (!name) return '🖥️'; for (const [k, v] of Object.entries(OS_ICONS)) { if (name.includes(k)) return v; } return '🖥️'; }

const SEVERITY_COLOR = { CRITICAL: '#fc8181', HIGH: '#f6ad55', MEDIUM: '#f6e05e', LOW: '#68d391', NONE: 'var(--text3)', UNKNOWN: 'var(--text3)' };

export default function AssetInventory() {
  const [assets, setAssets] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [filters, setFilters] = useState({ os: '', search: '', compliance: '' });
  const [vulns, setVulns] = useState([]);

  const load = useCallback(async () => {
    try {
      const [aRes, sRes] = await Promise.all([assetsApi.list(filters), assetsApi.stats()]);
      setAssets(aRes.data.assets || []);
      setStats(sRes.data);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [filters]);

  useEffect(() => { load(); const id = setInterval(load, 30000); return () => clearInterval(id); }, [load]);

  useEffect(() => {
    if (!selected) { setVulns([]); return; }
    vulnApi.forAsset(selected).then(r => setVulns(r.data.vulnerabilities || [])).catch(() => setVulns([]));
  }, [selected]);

  const detail = selected ? assets.find(a => a.agent_id === selected) : null;

  return (
    <div style={{ display: 'flex', gap: 16, height: 'calc(100vh - 100px)' }}>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <h2 style={{ color: '#fff', margin: 0, fontSize: 18 }}>
          📦 Asset Inventory
          <span style={{ color: 'var(--text3)', fontSize: 12, fontWeight: 400, marginLeft: 8 }}>Endpoint Hardware & Software</span>
        </h2>

        {/* Stats */}
        {stats && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10 }}>
            <StatCard label="Total Assets" value={stats.total} color="var(--gold)" />
            <StatCard label="Compliant" value={`${stats.compliancePercent}%`} color={stats.compliancePercent >= 80 ? '#68d391' : '#fc8181'} />
            <StatCard label="Avg Uptime" value={`${stats.avgUptime}h`} color="#90cdf4" />
            <StatCard label="Total RAM" value={`${stats.totalRam} GB`} color="#b794f4" />
            <StatCard label="Total Disk" value={`${stats.totalDisk} GB`} color="#f6ad55" />
          </div>
        )}

        {/* Filters */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <input placeholder="Search hostname, OS, CPU, app…" value={filters.search} onChange={e => setFilters(f => ({ ...f, search: e.target.value }))} style={{ width: 220, padding: '5px 10px', fontSize: 12 }} />
          <select value={filters.os} onChange={e => setFilters(f => ({ ...f, os: e.target.value }))} style={{ padding: '5px 8px', fontSize: 12 }}>
            <option value="">All OS</option>
            <option value="Windows">Windows</option>
            <option value="Ubuntu">Ubuntu / Linux</option>
            <option value="PAN-OS">Network Devices</option>
            <option value="macOS">macOS</option>
          </select>
          <select value={filters.compliance} onChange={e => setFilters(f => ({ ...f, compliance: e.target.value }))} style={{ padding: '5px 8px', fontSize: 12 }}>
            <option value="">All Compliance</option>
            <option value="compliant">Compliant</option>
            <option value="non-compliant">Non-Compliant</option>
          </select>
          <button className="btn btn-secondary btn-sm" onClick={load}>🔄 Refresh</button>
          <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text3)' }}>{assets.length} assets</span>
        </div>

        {/* Table */}
        <div style={{ flex: 1, overflow: 'auto', background: 'var(--bg2)', borderRadius: 8, border: '1px solid var(--border)' }}>
          {loading ? <div style={{ padding: 20, color: 'var(--text3)' }}>Loading…</div> : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
              <thead>
                <tr style={{ background: 'var(--bg3)', position: 'sticky', top: 0, zIndex: 1 }}>
                  {['OS', 'Hostname', 'IP', 'Applications', 'CPU', 'RAM', 'Disk', 'AV Status', 'Firewall', 'Uptime', 'Last Updated'].map(h => (
                    <th key={h} style={{ padding: '8px 10px', textAlign: 'left', color: 'var(--text3)', fontWeight: 600, fontSize: 11, borderBottom: '1px solid var(--border)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {assets.length === 0 ? (
                  <tr><td colSpan={11} style={{ padding: 40, textAlign: 'center', color: 'var(--text3)' }}>No assets collected yet. Deploy agents to start collecting inventory.</td></tr>
                ) : assets.map(a => {
                  const diskPct = a.disk_total_gb > 0 ? Math.round((a.disk_used_gb / a.disk_total_gb) * 100) : 0;
                  const installedApps = (a.installed_software || []).map(softwareName).filter(Boolean);
                  return (
                    <tr key={a.agent_id} onClick={() => setSelected(selected === a.agent_id ? null : a.agent_id)}
                      style={{ cursor: 'pointer', background: selected === a.agent_id ? 'var(--navy)' : 'transparent', borderBottom: '1px solid var(--border)' }}
                      onMouseEnter={e => { if (selected !== a.agent_id) e.currentTarget.style.background = 'var(--bg3)'; }}
                      onMouseLeave={e => { if (selected !== a.agent_id) e.currentTarget.style.background = 'transparent'; }}>
                      <td style={{ padding: '8px 10px' }}>{osIcon(a.os_name)} <span style={{ fontSize: 11 }}>{a.os_name || 'Unknown'}</span></td>
                      <td style={{ padding: '8px 10px', color: '#fff', fontWeight: 600 }}>{a.hostname}</td>
                      <td style={{ padding: '8px 10px', fontFamily: 'monospace', fontSize: 11, color: 'var(--text2)' }}>{a.agent_ip || '-'}</td>
                      <td style={{ padding: '8px 10px', minWidth: 220 }}>
                        {installedApps.length > 0 ? (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                            {installedApps.slice(0, 3).map((app, i) => (
                              <span key={`${a.agent_id}:app:${i}`} style={{ background: 'var(--bg3)', color: 'var(--text2)', fontSize: 10, padding: '2px 6px', borderRadius: 999 }}>
                                {app}
                              </span>
                            ))}
                            {installedApps.length > 3 && <span style={{ fontSize: 10, color: 'var(--text3)' }}>+{installedApps.length - 3} more</span>}
                          </div>
                        ) : <span style={{ fontSize: 11, color: 'var(--text3)' }}>No app data</span>}
                      </td>
                      <td style={{ padding: '8px 10px', fontSize: 11, color: 'var(--text2)' }}>{a.cpu_model ? `${a.cpu_model} (${a.cpu_cores}c)` : '-'}</td>
                      <td style={{ padding: '8px 10px', color: 'var(--gold)', fontWeight: 600, fontSize: 11 }}>{a.ram_total_gb ? `${a.ram_total_gb} GB` : '-'}</td>
                      <td style={{ padding: '8px 10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                          <div style={{ width: 40, height: 4, background: 'var(--bg4)', borderRadius: 2, overflow: 'hidden' }}>
                            <div style={{ width: `${diskPct}%`, height: '100%', background: diskPct > 85 ? '#fc8181' : diskPct > 60 ? '#f6ad55' : '#68d391' }} />
                          </div>
                          <span style={{ fontSize: 10, color: 'var(--text3)' }}>{diskPct}%</span>
                        </div>
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, fontWeight: 600, background: a.antivirus_status && a.antivirus_status !== 'None' && a.antivirus_status !== 'Unknown' ? 'rgba(56,161,105,.15)' : 'rgba(252,129,129,.15)', color: a.antivirus_status && a.antivirus_status !== 'None' && a.antivirus_status !== 'Unknown' ? '#68d391' : '#fc8181' }}>
                          {a.antivirus_status || 'Unknown'}
                        </span>
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        {a.firewall_enabled ? <span style={{ color: '#68d391', fontSize: 11 }}>✓ On</span> : <span style={{ color: '#fc8181', fontSize: 11 }}>✗ Off</span>}
                      </td>
                      <td style={{ padding: '8px 10px', fontSize: 11, color: 'var(--text3)' }}>{a.uptime_hours ? `${Math.round(a.uptime_hours)}h` : '-'}</td>
                      <td style={{ padding: '8px 10px', fontSize: 11, color: 'var(--text3)' }}>{a.updated_at ? formatDistanceToNow(new Date(a.updated_at), { addSuffix: true }) : '-'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Detail Panel */}
      {detail && (
        <div style={{ width: 360, background: 'var(--bg2)', borderRadius: 8, border: '1px solid var(--border)', padding: 16, overflow: 'auto', flexShrink: 0 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <h3 style={{ color: '#fff', margin: 0, fontSize: 15 }}>Asset Detail</h3>
            <div onClick={() => setSelected(null)} style={{ cursor: 'pointer', color: 'var(--text3)', fontSize: 18 }}>×</div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <span style={{ fontSize: 28 }}>{osIcon(detail.os_name)}</span>
            <div>
              <div style={{ color: '#fff', fontWeight: 700, fontSize: 16 }}>{detail.hostname}</div>
              <div style={{ color: 'var(--text3)', fontSize: 11 }}>{detail.os_name} {detail.os_version}</div>
            </div>
          </div>

          <Section title="🖥️ Hardware">
            <Field label="CPU" value={`${detail.cpu_model || '-'} (${detail.cpu_cores || 0} cores)`} />
            <Field label="Architecture" value={detail.os_arch} />
            <Field label="RAM" value={`${detail.ram_total_gb || 0} GB`} />
            <Field label="Disk Total" value={`${detail.disk_total_gb || 0} GB`} />
            <Field label="Disk Used" value={`${detail.disk_used_gb || 0} GB (${detail.disk_total_gb > 0 ? Math.round((detail.disk_used_gb / detail.disk_total_gb) * 100) : 0}%)`} />
            <Field label="Serial" value={detail.serial_number} />
            <Field label="Domain" value={detail.domain} />
            <Field label="Uptime" value={`${Math.round(detail.uptime_hours || 0)} hours`} />
          </Section>

          <Section title="🔒 Compliance">
            <Field label="Antivirus" value={detail.antivirus_status} highlight={detail.antivirus_status && detail.antivirus_status !== 'None' && detail.antivirus_status !== 'Unknown'} />
            <Field label="Firewall" value={detail.firewall_enabled ? 'Enabled' : 'Disabled'} highlight={!!detail.firewall_enabled} />
            <Field label="Last Patch" value={detail.last_patch_date || 'Unknown'} />
          </Section>

          {vulns.length > 0 && (
            <Section title="🛡️ Vulnerabilities" count={vulns.length}>
              <div style={{ maxHeight: 180, overflow: 'auto' }}>
                {vulns.map((v, i) => {
                  const sev = (v.severity || 'UNKNOWN').toUpperCase();
                  const color = SEVERITY_COLOR[sev] || 'var(--text3)';
                  return (
                    <div key={`${v.id || v.cve_id}-${i}`} style={{ background: 'var(--bg3)', borderRadius: 4, padding: '6px 8px', marginBottom: 4 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--gold)', fontWeight: 600 }}>{v.cve_id}</span>
                        <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 4, fontWeight: 700, background: `${color}22`, color }}>{sev}{v.cvss_score != null ? ` ${v.cvss_score.toFixed(1)}` : ''}</span>
                      </div>
                      <div style={{ color: 'var(--text3)', fontSize: 10, marginTop: 2 }}>{v.software_name} {v.software_version || ''}</div>
                    </div>
                  );
                })}
              </div>
            </Section>
          )}

          {detail.network_interfaces?.length > 0 && (
            <Section title="🌐 Network">
              {detail.network_interfaces.map((n, i) => (
                <div key={i} style={{ background: 'var(--bg3)', borderRadius: 4, padding: '6px 8px', marginBottom: 4, fontSize: 11 }}>
                  <div style={{ color: '#fff', fontWeight: 600 }}>{n.name || `Interface ${i}`}</div>
                  <div style={{ color: 'var(--text3)' }}>IP: {n.ip || '-'} | MAC: {n.mac || '-'}</div>
                </div>
              ))}
            </Section>
          )}

          {detail.open_ports?.length > 0 && (
            <Section title="🔌 Open Ports">
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {detail.open_ports.slice(0, 20).map((p, i) => (
                  <span key={i} style={{ background: 'var(--navy)', color: 'var(--gold)', fontSize: 10, padding: '2px 6px', borderRadius: 4 }}>{typeof p === 'object' ? `${p.port}/${p.proto}` : p}</span>
                ))}
              </div>
            </Section>
          )}

          {detail.installed_software?.length > 0 && (
            <Section title="📦 Software" count={detail.installed_software.length}>
              <div style={{ maxHeight: 150, overflow: 'auto' }}>
                {detail.installed_software.slice(0, 30).map((s, i) => (
                  <div key={i} style={{ fontSize: 11, color: 'var(--text2)', padding: '3px 0', borderBottom: '1px solid var(--border)' }}>
                    {typeof s === 'object' ? `${s.name} ${s.version || ''}` : s}
                  </div>
                ))}
              </div>
            </Section>
          )}

          {detail.running_services?.length > 0 && (
            <Section title="⚙️ Services" count={detail.running_services.length}>
              <div style={{ maxHeight: 120, overflow: 'auto' }}>
                {detail.running_services.slice(0, 20).map((s, i) => (
                  <div key={i} style={{ fontSize: 11, color: 'var(--text2)', padding: '3px 0', borderBottom: '1px solid var(--border)' }}>
                    {typeof s === 'object' ? `${s.name} (${s.status || 'running'})` : s}
                  </div>
                ))}
              </div>
            </Section>
          )}

          {detail.local_users?.length > 0 && (
            <Section title="👤 Local Users">
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {detail.local_users.map((u, i) => (
                  <span key={i} style={{ background: 'var(--bg3)', color: 'var(--text2)', fontSize: 10, padding: '2px 8px', borderRadius: 4 }}>{typeof u === 'object' ? u.name : u}</span>
                ))}
              </div>
            </Section>
          )}
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div style={{ background: 'var(--bg2)', borderRadius: 8, padding: '12px 14px', border: '1px solid var(--border)' }}>
      <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700, color }}>{value}</div>
    </div>
  );
}

function Section({ title, count, children }) {
  return (
    <div style={{ marginTop: 14 }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)', marginBottom: 6 }}>
        {title} {count !== undefined && <span style={{ color: 'var(--text3)', fontWeight: 400 }}>({count})</span>}
      </div>
      {children}
    </div>
  );
}

function Field({ label, value, highlight }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border)' }}>
      <span style={{ color: 'var(--text3)', fontSize: 11 }}>{label}</span>
      <span style={{ color: highlight !== undefined ? (highlight ? '#68d391' : '#fc8181') : 'var(--text)', fontSize: 11 }}>{value || '-'}</span>
    </div>
  );
}
