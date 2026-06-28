import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from './Auth';

const NAV = [
  { path: '/', icon: '🏠', label: 'Dashboard' },
  { path: '/alerts', icon: '🚨', label: 'Alert Manager' },
  { path: '/incidents', icon: '🧯', label: 'Incident Response' },
  { path: '/events', icon: '📋', label: 'Event Explorer' },
  { path: '/kql', icon: '🔍', label: 'KQL Engine' },
  { path: '/correlation', icon: '🔗', label: 'Correlation' },
  { path: '/intel', icon: '🔴', label: 'Threat Intel' },
  { path: '/ueba', icon: '👤', label: 'UEBA' },
  { path: '/soar', icon: '⚙️', label: 'SOAR' },
  { path: '/agents', icon: '🖥️', label: 'Agents' },
];

export default function Layout({ children, connected, liveAlertCount = 0 }) {
  const location = useLocation();
  const { user, logout } = useAuth();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
      {/* Topbar */}
      <div style={{ background: 'var(--navy)', padding: '0 16px', height: 48, display: 'flex', alignItems: 'center', gap: 12, borderBottom: '1px solid var(--border2)', flexShrink: 0, zIndex: 100 }}>
        <div style={{ fontSize: 16, fontWeight: 700, color: '#fff', display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ width: 8, height: 8, background: 'var(--gold)', borderRadius: '50%' }} />
          K3 <span style={{ color: 'var(--gold)', marginLeft: 4 }}>SIEM</span>
        </div>
        <span style={{ fontSize: 11, color: 'rgba(255,255,255,.4)' }}>Enterprise Security Operations</span>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11 }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: connected ? '#68d391' : '#fc8181' }} />
            <span style={{ color: 'rgba(255,255,255,.5)' }}>{connected ? 'Live' : 'Reconnecting…'}</span>
          </div>
          {liveAlertCount > 0 && (
            <div style={{ background: 'var(--red)', color: '#fff', fontSize: 10, padding: '2px 7px', borderRadius: 10, fontWeight: 700 }}>
              {liveAlertCount} new
            </div>
          )}
          <div style={{ fontSize: 11, color: 'rgba(255,255,255,.5)' }}>{user?.full_name}</div>
          <div onClick={logout} style={{ width: 28, height: 28, borderRadius: '50%', background: 'var(--navy3)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, fontWeight: 700, color: 'var(--gold)', border: '1px solid var(--border2)', cursor: 'pointer' }}>
            {user?.full_name?.[0] || 'U'}
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* Sidebar */}
        <div style={{ width: 196, background: 'var(--bg2)', borderRight: '1px solid var(--border)', flexShrink: 0, display: 'flex', flexDirection: 'column', padding: '8px 0' }}>
          {NAV.map(n => {
            const active = location.pathname === n.path;
            return (
              <Link key={n.path} to={n.path} style={{ textDecoration: 'none' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 14px', borderRadius: 6, margin: '1px 6px', cursor: 'pointer', background: active ? 'var(--navy)' : 'transparent', color: active ? '#fff' : 'var(--text2)', fontSize: 12.5, fontWeight: 500, transition: 'all .15s' }}
                  onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--bg3)'; e.currentTarget.style.color = 'var(--text)'; }}
                  onMouseLeave={e => { if (!active) { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text2)'; } }}>
                  <span style={{ width: 16, textAlign: 'center', fontSize: 14 }}>{n.icon}</span>
                  <span>{n.label}</span>
                  {n.path === '/alerts' && liveAlertCount > 0 && (
                    <span style={{ marginLeft: 'auto', background: 'var(--red)', color: '#fff', fontSize: 10, padding: '1px 5px', borderRadius: 8, fontWeight: 700 }}>{liveAlertCount}</span>
                  )}
                </div>
              </Link>
            );
          })}
          <div style={{ marginTop: 'auto', padding: '8px 14px', borderTop: '1px solid var(--border)', fontSize: 11, color: 'var(--text3)' }}>
            <div>K3 SIEM · v2.0.0</div>
          </div>
        </div>

        {/* Main content */}
        <div style={{ flex: 1, overflow: 'auto', background: 'var(--bg)' }}>
          <div style={{ padding: 16, minHeight: '100%' }}>
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}
