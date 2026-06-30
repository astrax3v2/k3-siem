'use strict';
function isConfigured() {
  return !!(process.env.CROWDSTRIKE_CLIENT_ID && process.env.CROWDSTRIKE_CLIENT_SECRET && process.env.CROWDSTRIKE_BASE_URL);
}

async function getToken() {
  const base = process.env.CROWDSTRIKE_BASE_URL.replace(/\/$/, '');
  const res = await fetch(`${base}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: process.env.CROWDSTRIKE_CLIENT_ID, client_secret: process.env.CROWDSTRIKE_CLIENT_SECRET }),
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`token request failed (HTTP ${res.status})`);
  const data = await res.json();
  return data.access_token;
}

async function isolateHost(hostname) {
  if (!isConfigured()) return { ok: false, detail: 'CrowdStrike not configured (CROWDSTRIKE_CLIENT_ID/SECRET/BASE_URL unset)' };
  const base = process.env.CROWDSTRIKE_BASE_URL.replace(/\/$/, '');
  try {
    const token = await getToken();
    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

    const lookup = await fetch(`${base}/devices/queries/devices/v1?filter=${encodeURIComponent(`hostname:'${hostname}'`)}`, { headers, signal: AbortSignal.timeout(8000) });
    const lookupData = await lookup.json().catch(() => ({}));
    const deviceId = lookupData?.resources?.[0];
    if (!lookup.ok || !deviceId) return { ok: false, detail: `CrowdStrike: host "${hostname}" not found in Falcon` };

    const action = await fetch(`${base}/devices/entities/devices-actions/v2?action_name=contain`, {
      method: 'POST', headers,
      body: JSON.stringify({ ids: [deviceId] }),
      signal: AbortSignal.timeout(8000),
    });
    if (!action.ok) return { ok: false, detail: `CrowdStrike containment request failed (HTTP ${action.status})` };
    return { ok: true, detail: `Host ${hostname} (${deviceId}) network-contained via Falcon` };
  } catch (e) { return { ok: false, detail: `CrowdStrike error: ${e.message}` }; }
}

module.exports = { isConfigured, isolateHost };
