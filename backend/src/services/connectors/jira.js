'use strict';
function isConfigured() {
  return !!(process.env.JIRA_BASE_URL && process.env.JIRA_EMAIL && process.env.JIRA_API_TOKEN && process.env.JIRA_PROJECT_KEY);
}

async function createIssue(summary, description) {
  if (!isConfigured()) return { ok: false, detail: 'Jira not configured (JIRA_BASE_URL/JIRA_EMAIL/JIRA_API_TOKEN/JIRA_PROJECT_KEY unset)' };
  try {
    const auth = Buffer.from(`${process.env.JIRA_EMAIL}:${process.env.JIRA_API_TOKEN}`).toString('base64');
    const res = await fetch(`${process.env.JIRA_BASE_URL.replace(/\/$/, '')}/rest/api/2/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Basic ${auth}` },
      body: JSON.stringify({
        fields: {
          project: { key: process.env.JIRA_PROJECT_KEY },
          summary, description,
          issuetype: { name: 'Task' },
        },
      }),
      signal: AbortSignal.timeout(8000),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, detail: `Jira API error ${res.status}: ${JSON.stringify(data.errors || data)}` };
    return { ok: true, detail: `Jira ticket created: ${data.key}` };
  } catch (e) { return { ok: false, detail: `Jira error: ${e.message}` }; }
}

module.exports = { isConfigured, createIssue };
