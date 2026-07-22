import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from './Auth';

const NAV = [
  { path: '/', icon: 'triage', label: 'Triage' },
  { path: '/overview', icon: 'overview', label: 'Overview' },
  { path: '/dashboards', icon: 'dashboard', label: 'Dashboard Library' },
  { path: '/alerts', icon: 'alerts', label: 'Alert Manager' },
  { path: '/incidents', icon: 'incidents', label: 'Incident Response' },
  { path: '/events', icon: 'events', label: 'Event Explorer' },
  { path: '/kql', icon: 'kql', label: 'KQL Engine' },
  { path: '/correlation', icon: 'correlation', label: 'Correlation' },
  { path: '/intel', icon: 'intel', label: 'Threat Intel' },
  { path: '/ueba', icon: 'ueba', label: 'UEBA' },
  { path: '/soar', icon: 'soar', label: 'SOAR' },
  { path: '/agents', icon: 'agents', label: 'Agents' },
  { path: '/inventory', icon: 'inventory', label: 'Inventory' },
  { path: '/vulnerabilities', icon: 'vulnerabilities', label: 'Vulnerabilities' },
  { path: '/ocsf', icon: 'ocsf', label: 'OCSF Parser' },
  { path: '/admin/teams', icon: 'admin', label: 'Tenants & Users', adminOnly: true },
];

function NavIcon({ name }) {
  const props = {
    width: 16,
    height: 16,
    viewBox: '0 0 20 20',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.7,
    strokeLinecap: 'round',
    strokeLinejoin: 'round',
    'aria-hidden': true,
  };

  switch (name) {
    case 'triage':
      return <svg {...props}><circle cx="10" cy="10" r="5.5" /><path d="M10 2.5v3M10 14.5v3M2.5 10h3M14.5 10h3" /></svg>;
    case 'overview':
      return <svg {...props}><path d="M3 16.5h14" /><path d="M5.5 13V8.5" /><path d="M10 13V5.5" /><path d="M14.5 13v-3" /></svg>;
    case 'dashboard':
      return <svg {...props}><rect x="3" y="3" width="6" height="6" rx="1.2" /><rect x="11" y="3" width="6" height="4" rx="1.2" /><rect x="11" y="9" width="6" height="8" rx="1.2" /><rect x="3" y="11" width="6" height="6" rx="1.2" /></svg>;
    case 'alerts':
      return <svg {...props}><path d="M10 3.5a4 4 0 0 0-4 4v2.2L4.5 12v1h11v-1L14 9.7V7.5a4 4 0 0 0-4-4Z" /><path d="M8 15a2 2 0 0 0 4 0" /></svg>;
    case 'incidents':
      return <svg {...props}><path d="M10 2.5 15.5 4.5v4.8c0 3.4-2.3 6.5-5.5 8.2-3.2-1.7-5.5-4.8-5.5-8.2V4.5L10 2.5Z" /><path d="M10 6.5v4.2" /><path d="M10 13.8h.01" /></svg>;
    case 'events':
      return <svg {...props}><path d="M5 5.5h10" /><path d="M5 10h10" /><path d="M5 14.5h10" /><circle cx="3.5" cy="5.5" r=".75" fill="currentColor" stroke="none" /><circle cx="3.5" cy="10" r=".75" fill="currentColor" stroke="none" /><circle cx="3.5" cy="14.5" r=".75" fill="currentColor" stroke="none" /></svg>;
    case 'kql':
      return <svg {...props}><rect x="3" y="4" width="14" height="12" rx="1.5" /><path d="m6 8 2 2-2 2" /><path d="M10.5 12h3.5" /></svg>;
    case 'correlation':
      return <svg {...props}><circle cx="5" cy="5" r="2" /><circle cx="15" cy="6" r="2" /><circle cx="10" cy="15" r="2" /><path d="M6.7 6.1 13.3 4.9" /><path d="M6.3 6.6 8.7 13.2" /><path d="M13.8 7.7 11.2 13.1" /></svg>;
    case 'intel':
      return <svg {...props}><circle cx="10" cy="10" r="6" /><circle cx="10" cy="10" r="2" /><path d="M10 4v2" /><path d="M16 10h-2" /><path d="M10 16v-2" /><path d="M4 10h2" /></svg>;
    case 'ueba':
      return <svg {...props}><circle cx="10" cy="7" r="3" /><path d="M4.5 16c1.2-2.5 3.1-3.8 5.5-3.8s4.3 1.3 5.5 3.8" /></svg>;
    case 'soar':
      return <svg {...props}><path d="M11.5 2.5 5.8 10h3l-.3 7.5 5.7-7.5h-3.1l.4-7.5Z" /></svg>;
    case 'agents':
      return <svg {...props}><rect x="4" y="3.5" width="12" height="5" rx="1.2" /><rect x="4" y="11.5" width="12" height="5" rx="1.2" /><path d="M6.5 6h.01" /><path d="M6.5 14h.01" /><path d="M9 6h5" /><path d="M9 14h5" /></svg>;
    case 'inventory':
      return <svg {...props}><path d="M4 6.5h12v9a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 4 15.5v-9Z" /><path d="M7 6.5V4.8A1.8 1.8 0 0 1 8.8 3h2.4A1.8 1.8 0 0 1 13 4.8v1.7" /></svg>;
    case 'vulnerabilities':
      return <svg {...props}><path d="M10 2.5 15.5 4.5v4.8c0 3.4-2.3 6.5-5.5 8.2-3.2-1.7-5.5-4.8-5.5-8.2V4.5L10 2.5Z" /><path d="M10 6.4v4.1" /><path d="M10 13.6h.01" /></svg>;
    case 'ocsf':
      return <svg {...props}><path d="M7 5 4 10l3 5" /><path d="M13 5l3 5-3 5" /><path d="M10 4v12" /></svg>;
    case 'admin':
      return <svg {...props}><circle cx="7" cy="7" r="2.2" /><circle cx="13.5" cy="8" r="1.7" /><path d="M3.8 15c.9-2 2.4-3 4.2-3s3.2 1 4.2 3" /><path d="M11.5 14.4c.5-1.4 1.5-2.2 2.9-2.2 1 0 1.9.4 2.6 1.3" /></svg>;
    default:
      return <svg {...props}><circle cx="10" cy="10" r="5.5" /></svg>;
  }
}

export default function Layout({ children, connected, liveAlertCount = 0 }) {
  const location = useLocation();
  const { user, logout } = useAuth();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
      <div style={{ background: 'var(--navy)', padding: '0 16px', height: 48, display: 'flex', alignItems: 'center', gap: 12, borderBottom: '1px solid var(--border2)', flexShrink: 0, zIndex: 100 }}>
        <div style={{ fontSize: 16, fontWeight: 700, color: '#fff', display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ width: 8, height: 8, background: 'var(--gold)', borderRadius: '50%' }} />
          K3 <span style={{ color: 'var(--gold)', marginLeft: 4 }}>SIEM</span>
        </div>
        <span style={{ fontSize: 11, color: 'rgba(255,255,255,.4)' }}>Enterprise Security Operations</span>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11 }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: connected ? '#68d391' : '#fc8181' }} />
            <span style={{ color: 'rgba(255,255,255,.5)' }}>{connected ? 'Live' : 'Reconnecting...'}</span>
          </div>
          {liveAlertCount > 0 && (
            <div style={{ background: 'var(--red)', color: '#fff', fontSize: 10, padding: '2px 7px', borderRadius: 10, fontWeight: 700 }}>
              {liveAlertCount} new
            </div>
          )}
          {user?.tenant_name && (
            <div style={{ background: 'var(--navy3)', color: 'var(--gold)', fontSize: 10, padding: '2px 8px', borderRadius: 999, border: '1px solid var(--border2)', fontWeight: 700 }}>
              {user.tenant_name}
            </div>
          )}
          <div style={{ fontSize: 11, color: 'rgba(255,255,255,.5)' }}>{user?.full_name}</div>
          <div onClick={logout} style={{ width: 28, height: 28, borderRadius: '50%', background: 'var(--navy3)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, fontWeight: 700, color: 'var(--gold)', border: '1px solid var(--border2)', cursor: 'pointer' }}>
            {user?.full_name?.[0] || 'U'}
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <div style={{ width: 196, background: 'var(--bg2)', borderRight: '1px solid var(--border)', flexShrink: 0, display: 'flex', flexDirection: 'column', padding: '8px 0' }}>
          {NAV.filter((n) => !n.adminOnly || user?.role === 'admin').map((n) => {
            const active = location.pathname === n.path;
            return (
              <Link key={n.path} to={n.path} style={{ textDecoration: 'none' }}>
                <div
                  style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 14px', borderRadius: 6, margin: '1px 6px', cursor: 'pointer', background: active ? 'var(--navy)' : 'transparent', color: active ? '#fff' : 'var(--text2)', fontSize: 12.5, fontWeight: 500, transition: 'all .15s' }}
                  onMouseEnter={(e) => { if (!active) e.currentTarget.style.background = 'var(--bg3)'; e.currentTarget.style.color = 'var(--text)'; }}
                  onMouseLeave={(e) => { if (!active) { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text2)'; } }}
                >
                  <span style={{ width: 16, height: 16, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <NavIcon name={n.icon} />
                  </span>
                  <span>{n.label}</span>
                  {n.path === '/alerts' && liveAlertCount > 0 && (
                    <span style={{ marginLeft: 'auto', background: 'var(--red)', color: '#fff', fontSize: 10, padding: '1px 5px', borderRadius: 8, fontWeight: 700 }}>{liveAlertCount}</span>
                  )}
                </div>
              </Link>
            );
          })}
          <div style={{ marginTop: 'auto', padding: '8px 14px', borderTop: '1px solid var(--border)', fontSize: 11, color: 'var(--text3)' }}>
            <div>K3 SIEM v2.0.0</div>
          </div>
        </div>

        <div style={{ flex: 1, overflow: 'auto', background: 'var(--bg)' }}>
          <div style={{ padding: 16, minHeight: '100%' }}>
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}
