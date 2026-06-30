'use strict';
// Routes a playbook step's human-readable text to the connector it describes. Replaces the
// previous SOAR execution behavior, which just incremented a step counter on a timer with
// no actual external call — every "Block IP", "Notify SOC Slack", "Create Jira ticket" step
// was pure fiction. Steps that don't name an external system (e.g. "Generate SIEM incident
// timeline report") are the platform's own work and are reported as done directly.
const slack = require('./slack');
const teams = require('./teams');
const email = require('./email');
const jira = require('./jira');
const servicenow = require('./servicenow');
const misp = require('./misp');
const paloalto = require('./paloalto');
const crowdstrike = require('./crowdstrike');

const CONNECTORS = { slack, teams, email, jira, servicenow, misp, paloalto, crowdstrike };

async function runStep(stepText, context = {}) {
  const text = stepText || '';
  const summary = context.summary || stepText;

  if (/slack/i.test(text)) {
    const r = await slack.notify(`*K3 SIEM*: ${summary}`);
    return { ...r, connector: 'slack' };
  }
  if (/teams/i.test(text)) {
    const r = await teams.notify(`K3 SIEM: ${summary}`);
    return { ...r, connector: 'teams' };
  }
  if (/jira/i.test(text)) {
    const r = await jira.createIssue(stepText, summary);
    return { ...r, connector: 'jira' };
  }
  if (/servicenow/i.test(text)) {
    const r = await servicenow.createIncident(stepText, summary);
    return { ...r, connector: 'servicenow' };
  }
  if (/misp/i.test(text)) {
    const value = context.ip || context.hash || context.domain || null;
    if (!value) return { ok: false, detail: 'No IOC value available on this alert to submit to MISP', connector: 'misp' };
    const type = context.ip ? 'ip-dst' : context.hash ? 'sha256' : 'domain';
    const r = await misp.submitIOC(value, type, summary);
    return { ...r, connector: 'misp' };
  }
  if (/crowdstrike|isolate endpoint/i.test(text)) {
    if (!context.asset) return { ok: false, detail: 'No asset/hostname on this alert to isolate', connector: 'crowdstrike' };
    const r = await crowdstrike.isolateHost(context.asset);
    return { ...r, connector: 'crowdstrike' };
  }
  if (/palo alto|perimeter firewall|block.*ip/i.test(text)) {
    if (!context.ip) return { ok: false, detail: 'No source IP on this alert to block', connector: 'paloalto' };
    const r = await paloalto.blockIp(context.ip);
    return { ...r, connector: 'paloalto' };
  }
  if (/email|notify.*owner|notify analyst/i.test(text)) {
    const r = await email.send(`K3 SIEM Alert: ${summary}`, `Playbook step: ${stepText}\n\n${summary}`);
    return { ...r, connector: 'email' };
  }

  return { ok: true, detail: 'Internal SIEM action — no external connector required', connector: 'internal' };
}

module.exports = { runStep, CONNECTORS };
