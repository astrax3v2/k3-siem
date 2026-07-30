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

function vcardField(vcardArray, field) {
  const props = vcardArray?.[1];
  if (!Array.isArray(props)) return null;
  const hit = props.find(p => p[0] === field);
  return hit ? hit[3] : null;
}

function rdapEntity(data, role) {
  return data.entities?.find(e => e.roles?.includes(role)) || null;
}

function rdapEventDate(data, action) {
  return data.events?.find(e => e.eventAction === action)?.eventDate || null;
}

function fmtDate(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

// Each parser turns a source's raw payload into an ordered list of {label, value, badge?} rows —
// the analyst-facing "clean feed". Sources with no parser fall back to raw JSON.
const PARSERS = {
  geo(data) {
    return [
      { label: 'Country', value: data.country || '—' },
      data.lat != null && data.lon != null && {
        label: 'Coordinates',
        value: `${data.lat}, ${data.lon}`,
        href: `https://www.google.com/maps?q=${data.lat},${data.lon}`,
      },
    ].filter(Boolean);
  },

  reverse_dns(data) {
    const names = Array.isArray(data) ? data : [data];
    return [{ label: 'Hostname' + (names.length > 1 ? 's' : ''), value: names.join(', ') }];
  },

  rdap(data) {
    const org = rdapEntity(data, 'registrant') || rdapEntity(data, 'technical');
    const abuse = rdapEntity(data, 'abuse');
    const cidrs = data.cidr0_cidrs?.map(c => `${c.v4prefix || c.v6prefix}/${c.length}`).join(', ');
    const range = data.startAddress && data.endAddress ? `${data.startAddress} – ${data.endAddress}` : null;
    return [
      { label: 'Network Name', value: data.name || '—' },
      org && { label: 'Organization', value: vcardField(org.vcardArray, 'fn') || '—' },
      { label: 'Country', value: data.country || '—' },
      { label: 'Status', value: (data.status || []).join(', ') || '—', badge: data.status?.includes('active') ? 'green' : 'gray' },
      (cidrs || range) && { label: 'IP Range', value: cidrs || range },
      { label: 'Registered', value: fmtDate(rdapEventDate(data, 'registration')) || '—' },
      { label: 'Last Changed', value: fmtDate(rdapEventDate(data, 'last changed')) || '—' },
      abuse && { label: 'Abuse Contact', value: vcardField(abuse.vcardArray, 'email') || '—' },
    ].filter(Boolean);
  },

  domain_rdap(data) { return PARSERS.rdap(data); },

  domain_mx(data) {
    if (!Array.isArray(data) || !data.length) return [{ label: 'MX Records', value: 'None' }];
    return [{ label: 'MX Records', value: data.sort((a, b) => a.priority - b.priority).map(r => `${r.exchange} (priority ${r.priority})`).join(', ') }];
  },

  crtsh(data) {
    if (!Array.isArray(data) || !data.length) return [{ label: 'Certificates', value: 'None found' }];
    const names = new Set();
    data.forEach(c => (c.name_value || '').split('\n').forEach(n => names.add(n.trim())));
    const mostRecent = data.reduce((a, b) => (new Date(b.not_before) > new Date(a.not_before) ? b : a));
    return [
      { label: 'Certificates Issued', value: String(data.length) },
      { label: 'Distinct Names', value: String(names.size) },
      { label: 'Sample Names', value: [...names].slice(0, 8).join(', ') },
      { label: 'Most Recent', value: fmtDate(mostRecent.not_before) },
    ];
  },

  virustotal(data, target) {
    if (data.last_analysis_stats) {
      const s = data.last_analysis_stats;
      const total = (s.malicious || 0) + (s.suspicious || 0) + (s.harmless || 0) + (s.undetected || 0) + (s.timeout || 0);
      const rows = [
        {
          label: 'Detections', value: `${s.malicious || 0} malicious / ${total} vendors`,
          badge: s.malicious > 0 ? 'red' : s.suspicious > 0 ? 'orange' : 'green',
        },
        { label: 'Suspicious', value: String(s.suspicious || 0) },
        { label: 'Harmless', value: String(s.harmless || 0) },
        { label: 'Undetected', value: String(s.undetected || 0) },
      ];
      if (data.reputation != null) rows.push({ label: 'Reputation Score', value: String(data.reputation) });
      if (data.as_owner) rows.push({ label: 'AS Owner', value: data.as_owner });
      if (data.country) rows.push({ label: 'Country', value: data.country });
      if (data.tags?.length) rows.push({ label: 'Tags', value: data.tags.join(', ') });
      if (data.meaningful_name) rows.push({ label: 'File Name', value: data.meaningful_name });
      if (data.type_description) rows.push({ label: 'File Type', value: data.type_description });
      if (data.size != null) rows.push({ label: 'Size', value: `${data.size} bytes` });
      return rows;
    }
    return null; // unrecognized shape — fall back to raw JSON
  },

  abuseipdb(data) {
    return [
      {
        label: 'Abuse Confidence', value: `${data.abuseConfidenceScore ?? 0}%`,
        badge: data.abuseConfidenceScore >= 75 ? 'red' : data.abuseConfidenceScore >= 25 ? 'orange' : 'green',
      },
      { label: 'Total Reports', value: String(data.totalReports ?? 0) },
      { label: 'Distinct Reporters', value: String(data.numDistinctUsers ?? 0) },
      { label: 'ISP', value: data.isp || '—' },
      { label: 'Usage Type', value: data.usageType || '—' },
      { label: 'Domain', value: data.domain || '—' },
      { label: 'Country', value: data.countryCode || '—' },
      data.lastReportedAt && { label: 'Last Reported', value: fmtDate(data.lastReportedAt) },
      { label: 'Whitelisted', value: data.isWhitelisted ? 'Yes' : 'No', badge: data.isWhitelisted ? 'green' : 'gray' },
    ].filter(Boolean);
  },

  shodan(data) {
    const vulnCount = data.vulns ? Object.keys(data.vulns).length : 0;
    return [
      { label: 'Organization', value: data.org || '—' },
      { label: 'ISP', value: data.isp || '—' },
      { label: 'Operating System', value: data.os || 'Unknown' },
      { label: 'Location', value: [data.city, data.country_name].filter(Boolean).join(', ') || '—' },
      { label: 'Open Ports', value: data.ports?.length ? data.ports.join(', ') : 'None' },
      { label: 'Hostnames', value: data.hostnames?.length ? data.hostnames.join(', ') : '—' },
      vulnCount > 0 && { label: 'Known Vulnerabilities', value: `${vulnCount} (${Object.keys(data.vulns).slice(0, 5).join(', ')}${vulnCount > 5 ? '…' : ''})`, badge: 'red' },
    ].filter(Boolean);
  },
};

function parseSource(name, data) {
  const parser = PARSERS[name];
  if (!parser) return null;
  try {
    return parser(data, name);
  } catch {
    return null;
  }
}

const BADGE_CLASS = { red: 'badge-red', orange: 'badge-orange', green: 'badge-green', blue: 'badge-blue', gray: 'badge-gray' };

function FieldRow({ label, value, href, badge }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '4px 0', fontSize: 12, borderBottom: '1px solid var(--border)' }}>
      <span style={{ color: 'var(--text3)', flexShrink: 0 }}>{label}</span>
      <span style={{ color: 'var(--text1)', textAlign: 'right', wordBreak: 'break-word' }}>
        {badge ? <span className={`badge ${BADGE_CLASS[badge] || 'badge-gray'}`}>{value}</span> : null}
        {!badge && href ? <a href={href} target="_blank" rel="noreferrer">{value}</a> : null}
        {!badge && !href ? value : null}
      </span>
    </div>
  );
}

function SourceCard({ name, source }) {
  const label = SOURCE_LABEL[name] || name;
  const [showRaw, setShowRaw] = useState(false);
  const parsed = source.data != null ? parseSource(name, source.data) : null;

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
      ) : parsed && !showRaw ? (
        <div>
          {parsed.map((row, i) => <FieldRow key={i} {...row} />)}
          <button
            className="btn btn-secondary btn-sm"
            style={{ marginTop: 8, fontSize: 11 }}
            onClick={() => setShowRaw(true)}
          >
            View Raw JSON
          </button>
        </div>
      ) : (
        <div>
          <pre style={{ fontSize: 11, color: 'var(--text2)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, maxHeight: 220, overflow: 'auto' }}>
            {JSON.stringify(source.data, null, 2)}
          </pre>
          {parsed && (
            <button
              className="btn btn-secondary btn-sm"
              style={{ marginTop: 8, fontSize: 11 }}
              onClick={() => setShowRaw(false)}
            >
              View Parsed
            </button>
          )}
        </div>
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
