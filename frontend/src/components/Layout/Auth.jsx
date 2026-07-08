import React, { createContext, useContext, useState, useEffect } from 'react';
import { authApi } from '../../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('siem_token');
    if (token) {
      authApi.me().then(res => { setUser(res.data.user); }).catch(() => {
        localStorage.removeItem('siem_token');
      }).finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const login = async (username, password) => {
    const res = await authApi.login(username, password);
    localStorage.setItem('siem_token', res.data.token);
    setUser(res.data.user);
    return res.data;
  };

  const logout = () => {
    localStorage.removeItem('siem_token');
    setUser(null);
  };

  return <AuthContext.Provider value={{ user, login, logout, loading }}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);

export function LoginPage() {
  const { login } = useAuth();
  const [creds, setCreds] = useState({ username: 'pbasnet', password: 'K3@2026' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const demoAccounts = [
    { username: 'pbasnet', role: 'Admin' },
    { username: 'jmaharjan', role: 'T2 Analyst' },
    { username: 'bpaudel', role: 'T2 Analyst' },
    { username: 'analyst1', role: 'T1 Analyst' },
  ];

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true); setError('');
    try { await login(creds.username, creds.password); }
    catch { setError('Invalid credentials. Try one of the demo accounts below with password K3@2026.'); }
    finally { setLoading(false); }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)' }}>
      <div style={{ width: 360 }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#fff' }}>
            K3 <span style={{ color: 'var(--gold)' }}>SIEM</span>
          </div>
          <div style={{ fontSize: 12, color: 'var(--text3)', marginTop: 4 }}>Enterprise Security Operations Platform</div>
        </div>
        <div className="card">
          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: 14 }}>
              <label style={{ fontSize: 11, color: 'var(--text2)', display: 'block', marginBottom: 5 }}>Username</label>
              <input value={creds.username} onChange={e => setCreds(p => ({ ...p, username: e.target.value }))} style={{ width: '100%', padding: '8px 12px' }} placeholder="Username" autoFocus />
            </div>
            <div style={{ marginBottom: 20 }}>
              <label style={{ fontSize: 11, color: 'var(--text2)', display: 'block', marginBottom: 5 }}>Password</label>
              <input type="password" value={creds.password} onChange={e => setCreds(p => ({ ...p, password: e.target.value }))} style={{ width: '100%', padding: '8px 12px' }} placeholder="Password" />
            </div>
            {error && <div style={{ color: '#fc8181', fontSize: 12, marginBottom: 12 }}>{error}</div>}
            <button type="submit" className="btn btn-primary" style={{ width: '100%', padding: '9px' }} disabled={loading}>
              {loading ? 'Authenticating…' : 'Sign In to SIEM'}
            </button>
          </form>
          <div style={{ marginTop: 16, borderTop: '1px solid var(--border)', paddingTop: 12 }}>
            <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 8 }}>Demo accounts for testing</div>
            <div style={{ display: 'grid', gap: 6 }}>
              {demoAccounts.map((account) => (
                <button
                  key={account.username}
                  type="button"
                  className="btn btn-secondary btn-sm"
                  style={{ width: '100%', display: 'flex', justifyContent: 'space-between' }}
                  onClick={() => setCreds({ username: account.username, password: 'K3@2026' })}
                >
                  <span>{account.username}</span>
                  <span style={{ color: 'var(--text3)', fontSize: 11 }}>{account.role}</span>
                </button>
              ))}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text3)', marginTop: 8 }}>
              Shared demo password: <span style={{ color: 'var(--gold)' }}>K3@2026</span>
            </div>
          </div>
        </div>
        <div style={{ textAlign: 'center', marginTop: 16, fontSize: 11, color: 'var(--text3)' }}>
          K3 SIEM · v2.4.1
        </div>
      </div>
    </div>
  );
}
