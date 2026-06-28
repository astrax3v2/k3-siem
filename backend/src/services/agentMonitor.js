'use strict';
const { v4: uuidv4 } = require('uuid');
const { db } = require('../models/db');

let monitorInterval = null;

function startAgentMonitor() {
  console.log('[AgentMonitor] Checking agent health every 60s');
  monitorInterval = setInterval(async () => {
    try {
      const d = db();
      const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();

      const staleAgents = await d.prepare(
        "SELECT id, hostname, status FROM agents WHERE last_heartbeat < ? AND status != 'offline'"
      ).all(fiveMinAgo);

      for (const agent of staleAgents) {
        await d.prepare("UPDATE agents SET status = 'offline' WHERE id = ?").run(agent.id);

        if (agent.status === 'online') {
          const alertId = uuidv4();
          await d.prepare(
            'INSERT INTO alerts(id, title, description, severity, status, source, asset, mitre_tactic, risk_score) VALUES(?,?,?,?,?,?,?,?,?)'
          ).run(
            alertId,
            `Agent Offline: ${agent.hostname}`,
            `Agent ${agent.hostname} (${agent.id}) has not sent a heartbeat in over 5 minutes`,
            'High',
            'New',
            'K3 Agent Monitor',
            agent.hostname,
            'Defense Evasion',
            70
          );
          console.log(`[AgentMonitor] Agent ${agent.hostname} marked offline, alert created`);
        }
      }
    } catch (err) {
      console.error('[AgentMonitor] Error:', err.message);
    }
  }, 60000);
}

function stopAgentMonitor() {
  if (monitorInterval) { clearInterval(monitorInterval); monitorInterval = null; }
}

module.exports = { startAgentMonitor, stopAgentMonitor };
