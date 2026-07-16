import React, { useEffect, useState } from 'react';
import { osintApi } from '../../services/api';

const LOOKUP = {
  ip: osintApi.lookupIp,
  domain: osintApi.lookupDomain,
  hash: osintApi.lookupHash,
  email: osintApi.lookupEmail,
};

const SOURCE_LABEL = {
  geo: 'Geolocation', reverse_dns: 'Reverse DNS', rdap: 'RDAP (WHOIS)',
  virustotal: 'VirusTotal', abuseipdb: 'AbuseIPDB', shodan: 'Shodan',
  crtsh: 'crt.sh (Certificate Transparency)', domain_rdap: 'RDAP (WHOIS)', domain_mx: 'MX Records',
};

function SourceCard({ name, source }) {
  const label = SOURCE_LABEL[name] || name;
  return (
    <div className="card" style={{ marginBottom: 10 }}>
      <div className="card-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>{label}</span>
        {!source.configured && <span className="badge badge-gray">Not configured</span>}
      </div>
      {!source.configured ? (
        <div style={{ fontSize: 12, color: 'var(--text3)' }}>Set the API key in the server .env to enable this source.</div>
      ) : source.data == null ? (
        <div style={{ fontSize: 12, color: 'var(--text3)' }}>No data returned.</div>
      ) : (
        <pre style={{ fontSize: 11, color: 'var(--text2)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, maxHeight: 220, overflow: 'auto' }}>
          {JSON.stringify(source.data, null, 2)}
        </pre>
      )}
    </div>
  );
}

// Slide-over OSINT lookup panel — attaches to any view where an analyst needs to pivot from an
// IP/domain/hash/email seen in an alert or process node out to external reputation/WHOIS data.
export default function OsintPanel({ type, value, onClose }) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!type || !value) return;
    const lookup = LOOKUP[type];
    if (!lookup) return;
    setLoading(true);
    setError(null);
    setResult(null);
    lookup(value)
      .then(res => setResult(res.data))
      .catch(err => setError(err.response?.data?.error || 'Lookup failed'))
      .finally(() => setLoading(false));
  }, [type, value]);

  if (!type || !value) return null;

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 1000, display: 'flex', justifyContent: 'flex-end' }}
      onClick={onClose}
    >
      <div
        style={{ width: 420, maxWidth: '100%', height: '100%', background: 'var(--bg)', borderLeft: '1px solid var(--border)', padding: 16, overflowY: 'auto' }}
        onClick={e => e.stopPropagation()}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600 }}>OSINT Lookup</div>
            <div style={{ fontSize: 12, color: 'var(--text3)', fontFamily: 'monospace', wordBreak: 'break-all' }}>{type}: {value}</div>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={onClose}>Close</button>
        </div>

        {loading && <div style={{ color: 'var(--text3)', fontSize: 12 }}>Looking up…</div>}
        {error && <div style={{ color: '#fc8181', fontSize: 12 }}>{error}</div>}
        {result && Object.entries(result.sources).map(([name, source]) => (
          <SourceCard key={name} name={name} source={source} />
        ))}
      </div>
    </div>
  );
}
