'use strict';
function isConfigured() { return !!(process.env.MISP_BASE_URL && process.env.MISP_API_KEY); }

async function submitIOC(value, type, comment) {
  if (!isConfigured()) return { ok: false, detail: 'MISP not configured (MISP_BASE_URL/MISP_API_KEY unset)' };
  try {
    const headers = { 'Content-Type': 'application/json', Authorization: process.env.MISP_API_KEY, Accept: 'application/json' };
    const eventRes = await fetch(`${process.env.MISP_BASE_URL.replace(/\/$/, '')}/events/add`, {
      method: 'POST', headers,
      body: JSON.stringify({ Event: { info: comment || `K3 SIEM IOC submission: ${value}`, distribution: 0, threat_level_id: 2, analysis: 0 } }),
      signal: AbortSignal.timeout(8000),
    });
    const eventData = await eventRes.json().catch(() => ({}));
    const eventId = eventData?.Event?.id;
    if (!eventRes.ok || !eventId) return { ok: false, detail: `MISP event creation failed (HTTP ${eventRes.status})` };

    const attrRes = await fetch(`${process.env.MISP_BASE_URL.replace(/\/$/, '')}/attributes/add/${eventId}`, {
      method: 'POST', headers,
      body: JSON.stringify({ Attribute: { type, category: 'Network activity', value, to_ids: true } }),
      signal: AbortSignal.timeout(8000),
    });
    if (!attrRes.ok) return { ok: false, detail: `MISP attribute submission failed (HTTP ${attrRes.status})` };
    return { ok: true, detail: `MISP IOC submitted to event ${eventId}` };
  } catch (e) { return { ok: false, detail: `MISP error: ${e.message}` }; }
}

module.exports = { isConfigured, submitIOC };
