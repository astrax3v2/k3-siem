'use strict';
function isConfigured() {
  return !!(process.env.SERVICENOW_INSTANCE && process.env.SERVICENOW_USER && process.env.SERVICENOW_PASS);
}

async function createIncident(shortDescription, description) {
  if (!isConfigured()) return { ok: false, detail: 'ServiceNow not configured (SERVICENOW_INSTANCE/SERVICENOW_USER/SERVICENOW_PASS unset)' };
  try {
    const auth = Buffer.from(`${process.env.SERVICENOW_USER}:${process.env.SERVICENOW_PASS}`).toString('base64');
    const res = await fetch(`https://${process.env.SERVICENOW_INSTANCE}.service-now.com/api/now/table/incident`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Basic ${auth}` },
      body: JSON.stringify({ short_description: shortDescription, description, urgency: '2', impact: '2' }),
      signal: AbortSignal.timeout(8000),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, detail: `ServiceNow API error ${res.status}` };
    return { ok: true, detail: `ServiceNow incident created: ${data?.result?.number || 'unknown'}` };
  } catch (e) { return { ok: false, detail: `ServiceNow error: ${e.message}` }; }
}

module.exports = { isConfigured, createIncident };
