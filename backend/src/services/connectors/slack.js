'use strict';
function isConfigured() { return !!process.env.SLACK_WEBHOOK_URL; }

async function notify(text) {
  if (!isConfigured()) return { ok: false, detail: 'Slack not configured (SLACK_WEBHOOK_URL unset)' };
  try {
    const res = await fetch(process.env.SLACK_WEBHOOK_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }), signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return { ok: false, detail: `Slack webhook returned HTTP ${res.status}` };
    return { ok: true, detail: 'Slack notification sent' };
  } catch (e) { return { ok: false, detail: `Slack error: ${e.message}` }; }
}

module.exports = { isConfigured, notify };
