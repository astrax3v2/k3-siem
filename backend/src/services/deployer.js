'use strict';
const path = require('path');
const fs = require('fs');
const { db } = require('../models/db');

const AGENT_DIR = path.resolve(__dirname, '../../../k3-agent');

function getAgentFiles() {
  const files = {};
  for (const f of ['agent.py', 'config.yaml', 'requirements.txt']) {
    const p = path.join(AGENT_DIR, f);
    if (fs.existsSync(p)) files[f] = fs.readFileSync(p, 'utf8');
  }
  return files;
}

function appendLog(deployId, line) {
  const d = db();
  const current = d.prepare ? null : null;
  try {
    const row = db().prepare('SELECT logs FROM deployments WHERE id = ?').get(deployId);
    const existing = row?.logs || '';
    const ts = new Date().toISOString().slice(11, 19);
    db().prepare('UPDATE deployments SET logs = ? WHERE id = ?')
      .run(existing + `[${ts}] ${line}\n`, deployId);
  } catch {}
}

async function deployViaSSH(deployId, config) {
  const { target_ip, target_os, username, password, ssh_key } = config;
  const d = db();

  await d.prepare("UPDATE deployments SET status = 'deploying' WHERE id = ?").run(deployId);
  appendLog(deployId, `Starting deployment to ${target_ip} (${target_os})`);

  let Client;
  try {
    Client = require('ssh2').Client;
  } catch {
    appendLog(deployId, 'ERROR: ssh2 module not installed. Run: npm install ssh2');
    await d.prepare("UPDATE deployments SET status = 'failed', completed_at = ? WHERE id = ?")
      .run(new Date().toISOString(), deployId);
    return;
  }

  const conn = new Client();
  const sshConfig = {
    host: target_ip,
    port: 22,
    username,
    readyTimeout: 30000,
  };
  if (ssh_key) sshConfig.privateKey = ssh_key;
  else if (password) sshConfig.password = password;

  const agentFiles = getAgentFiles();
  if (!agentFiles['agent.py']) {
    appendLog(deployId, 'ERROR: agent.py not found in k3-agent directory');
    await d.prepare("UPDATE deployments SET status = 'failed', completed_at = ? WHERE id = ?")
      .run(new Date().toISOString(), deployId);
    return;
  }

  const siemUrl = process.env.SIEM_PUBLIC_URL || `http://${target_ip === '127.0.0.1' ? 'localhost' : require('os').hostname()}:${process.env.PORT || 3001}`;
  const apiKey = process.env.INGEST_API_KEY || 'k3-ingest-key';

  return new Promise((resolve) => {
    conn.on('ready', () => {
      appendLog(deployId, 'SSH connection established');

      const commands = [
        'mkdir -p /opt/k3-agent',
        `cat > /opt/k3-agent/agent.py << \'AGENTEOF\'\n${agentFiles['agent.py']}\nAGENTEOF`,
        `cat > /opt/k3-agent/requirements.txt << \'REQEOF\'\n${agentFiles['requirements.txt'] || 'requests>=2.32.0\npsutil>=6.1.0\npyyaml>=6.0.2'}\nREQEOF`,
        `cat > /opt/k3-agent/config.yaml << 'CFGEOF'\nsiem_url: "${siemUrl}"\napi_key: "${apiKey}"\nagent_version: "1.0.0"\ncollection_interval: 10\nheartbeat_interval: 30\nbatch_size: 50\nsimulate: false\nCFGEOF`,
        'which python3 || which python || (apt-get update -qq && apt-get install -y -qq python3 python3-pip)',
        'cd /opt/k3-agent && (python3 -m pip install -r requirements.txt 2>/dev/null || pip install -r requirements.txt 2>/dev/null || pip3 install -r requirements.txt)',
        'cd /opt/k3-agent && nohup python3 agent.py > /var/log/k3-agent.log 2>&1 &',
        'echo "K3_DEPLOY_SUCCESS"',
      ];

      const fullCmd = commands.join(' && ');
      appendLog(deployId, 'Uploading agent files...');

      conn.exec(fullCmd, async (err, stream) => {
        if (err) {
          appendLog(deployId, `SSH exec error: ${err.message}`);
          await d.prepare("UPDATE deployments SET status = 'failed', completed_at = ? WHERE id = ?")
            .run(new Date().toISOString(), deployId);
          conn.end();
          resolve();
          return;
        }

        let output = '';
        stream.on('data', (data) => {
          const line = data.toString().trim();
          if (line) {
            output += line + '\n';
            appendLog(deployId, line);
          }
        });
        stream.stderr.on('data', (data) => {
          const line = data.toString().trim();
          if (line && !line.includes('WARNING') && !line.includes('DEPRECATION')) {
            appendLog(deployId, `STDERR: ${line}`);
          }
        });
        stream.on('close', async () => {
          if (output.includes('K3_DEPLOY_SUCCESS')) {
            appendLog(deployId, 'Agent deployed and started successfully');
            appendLog(deployId, 'Waiting for agent registration...');
            await d.prepare("UPDATE deployments SET status = 'success', completed_at = ? WHERE id = ?")
              .run(new Date().toISOString(), deployId);

            setTimeout(async () => {
              const agent = await d.prepare('SELECT id FROM agents WHERE ip = ? ORDER BY registered_at DESC LIMIT 1').get(target_ip);
              if (agent) {
                await d.prepare('UPDATE deployments SET agent_id = ? WHERE id = ?').run(agent.id, deployId);
                appendLog(deployId, `Agent registered: ${agent.id}`);
              }
            }, 15000);
          } else {
            appendLog(deployId, 'Deployment may have failed — success marker not found');
            await d.prepare("UPDATE deployments SET status = 'failed', completed_at = ? WHERE id = ?")
              .run(new Date().toISOString(), deployId);
          }
          conn.end();
          resolve();
        });
      });
    });

    conn.on('error', async (err) => {
      appendLog(deployId, `SSH connection failed: ${err.message}`);
      await d.prepare("UPDATE deployments SET status = 'failed', completed_at = ? WHERE id = ?")
        .run(new Date().toISOString(), deployId);
      resolve();
    });

    conn.connect(sshConfig);
  });
}

function generateInstallScript(os, siemUrl, apiKey) {
  const url = siemUrl || `http://localhost:${process.env.PORT || 3001}`;
  const key = apiKey || process.env.INGEST_API_KEY || 'k3-ingest-key';

  if (os === 'linux' || os === 'macos') {
    return `#!/bin/bash
set -e
echo "[K3 Agent] Installing on $(hostname)..."
mkdir -p /opt/k3-agent
cd /opt/k3-agent

# Download agent
curl -sSL ${url}/api/deploy/download/agent.py -o agent.py
curl -sSL ${url}/api/deploy/download/requirements.txt -o requirements.txt

# Configure
cat > config.yaml << EOF
siem_url: "${url}"
api_key: "${key}"
agent_version: "1.0.0"
collection_interval: 10
heartbeat_interval: 30
batch_size: 50
simulate: false
EOF

# Install dependencies
python3 -m pip install -r requirements.txt 2>/dev/null || pip3 install -r requirements.txt

# Start agent
nohup python3 agent.py > /var/log/k3-agent.log 2>&1 &
echo "[K3 Agent] Started (PID: $!)"
echo "[K3 Agent] Logs: /var/log/k3-agent.log"
`;
  }

  return `# K3 SIEM Agent Installer (PowerShell)
Write-Host "[K3 Agent] Installing on $env:COMPUTERNAME..."
$agentDir = "C:\\K3Agent"
New-Item -ItemType Directory -Force -Path $agentDir | Out-Null
Set-Location $agentDir

# Download agent
Invoke-WebRequest -Uri "${url}/api/deploy/download/agent.py" -OutFile agent.py
Invoke-WebRequest -Uri "${url}/api/deploy/download/requirements.txt" -OutFile requirements.txt

# Configure
@"
siem_url: "${url}"
api_key: "${key}"
agent_version: "1.0.0"
collection_interval: 10
heartbeat_interval: 30
batch_size: 50
simulate: false
"@ | Set-Content config.yaml

# Install dependencies
python -m pip install -r requirements.txt

# Start agent
Start-Process -NoNewWindow -FilePath "python" -ArgumentList "agent.py" -RedirectStandardOutput "k3-agent.log"
Write-Host "[K3 Agent] Started successfully"
`;
}

module.exports = { deployViaSSH, generateInstallScript, getAgentFiles };
