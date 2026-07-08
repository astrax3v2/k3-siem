param(
  [string]$Root = "C:\Users\ASUS\Documents\Github\k3-siem"
)

$ErrorActionPreference = "Stop"

$backend = Join-Path $Root "backend"
$frontend = Join-Path $Root "frontend"
$agent = Join-Path $Root "k3-agent"
$node = "C:\Program Files\nodejs\node.exe"
$npm = "C:\Program Files\nodejs\npm.cmd"
$python = "C:\Users\ASUS\AppData\Local\Programs\Python\Python312\python.exe"
$powershellExe = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

function Stop-PortListener {
  param([int]$Port)
  $lines = cmd /c "netstat -ano | findstr :$Port | findstr LISTENING"
  foreach ($line in $lines) {
    $parts = ($line -split "\s+") | Where-Object { $_ }
    if ($parts.Length -ge 5) {
      $procId = [int]$parts[-1]
      try {
        Stop-Process -Id $procId -Force -ErrorAction Stop
        Write-Output "Stopped listener on port $Port (PID $procId)"
      } catch {
      }
    }
  }
}

function Remove-IfExists {
  param([string]$Path)
  if (Test-Path $Path) {
    Remove-Item $Path -Force
  }
}

Stop-PortListener -Port 3000
Stop-PortListener -Port 3001

Get-CimInstance Win32_Process |
  Where-Object { $_.CommandLine -like "*k3-agent*agent.py*" } |
  ForEach-Object {
    try {
      Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
      Write-Output "Stopped agent PID $($_.ProcessId)"
    } catch {
    }
  }

foreach ($file in @("backend-real.log", "backend-real.err.log", "frontend-real.log", "frontend-real.err.log")) {
  Remove-IfExists (Join-Path $Root $file)
}
foreach ($file in @("agent_state.json", "k3-agent-live.log", "k3-agent-live.err.log")) {
  Remove-IfExists (Join-Path $agent $file)
}

Push-Location $backend
& $node -e "const {initDb,db}=require('./src/models/db'); (async()=>{await initDb(); const d=db(); await d.exec(\`DELETE FROM playbook_executions; DELETE FROM ueba_scores; DELETE FROM intel_feeds; DELETE FROM process_nodes; DELETE FROM incident_alerts; DELETE FROM incident_notes; DELETE FROM incidents; DELETE FROM iocs; DELETE FROM alerts; DELETE FROM events; DELETE FROM vulnerabilities; DELETE FROM assets; DELETE FROM agents;\`); console.log('CLEARED_DEMO_ROWS'); process.exit(0);})().catch(e=>{console.error(e);process.exit(1)})"
Pop-Location

Start-Process -FilePath $powershellExe -ArgumentList "-NoProfile", "-WindowStyle", "Hidden", "-Command", "Set-Location '$backend'; & '$node' 'src/index.js' 1>> '$Root\backend-real.log' 2>> '$Root\backend-real.err.log'" -WindowStyle Hidden
Start-Sleep -Seconds 5

Start-Process -FilePath $powershellExe -ArgumentList "-NoProfile", "-WindowStyle", "Hidden", "-Command", "Set-Location '$frontend'; `$env:BROWSER='none'; & '$npm' 'start' 1>> '$Root\frontend-real.log' 2>> '$Root\frontend-real.err.log'" -WindowStyle Hidden
Start-Sleep -Seconds 8

Start-Process -FilePath $python -ArgumentList "agent.py", "--config", "config.yaml" -WorkingDirectory $agent -RedirectStandardOutput (Join-Path $agent "k3-agent-live.log") -RedirectStandardError (Join-Path $agent "k3-agent-live.err.log") -WindowStyle Hidden
Start-Sleep -Seconds 18

$health = (Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:3001/health" -TimeoutSec 8).Content
$loginBody = @{ username = "pbasnet"; password = "K3@2026" } | ConvertTo-Json
$login = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:3001/api/auth/login" -ContentType "application/json" -Body $loginBody
$headers = @{ Authorization = "Bearer $($login.token)" }
$agentsResp = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:3001/api/agents" -Headers $headers
$agents = @($agentsResp.agents)
$latestAgent = $agents | Sort-Object registered_at -Descending | Select-Object -First 1
$eventsResp = $null
if ($latestAgent) {
  $eventsResp = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:3001/api/events?agent_id=" + $latestAgent.id + "&limit=5") -Headers $headers
}

Write-Output "HEALTH=$health"
if ($latestAgent) {
  Write-Output ("AGENT=" + $latestAgent.hostname + "|" + $latestAgent.id + "|" + $latestAgent.status + "|events_sent=" + $latestAgent.events_sent)
}
if ($eventsResp) {
  Write-Output ("EVENT_COUNT=" + $eventsResp.total)
}
Write-Output "--- BACKEND LOG ---"
Get-Content (Join-Path $Root "backend-real.log") -Tail 20
Write-Output "--- AGENT LOG ---"
Get-Content (Join-Path $agent "k3-agent-live.log") -Tail 40
