#!/usr/bin/env bash
# Run by the makeself .bin on extraction (or directly from the extracted payload dir).
# Installs the agent as a systemd service — service registration + autostart only, per plan;
# it does not touch auditd/syslog policy.
#
#   sudo ./install.sh --siem-url https://siem.example.com --api-key XXXX
set -euo pipefail

SIEM_URL="http://localhost:3001"
API_KEY=""
INSTALL_DIR="/opt/k3-agent"

while [ $# -gt 0 ]; do
  case "$1" in
    --siem-url) SIEM_URL="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo) — installing a systemd service requires it." >&2
  exit 1
fi
if [ -z "$API_KEY" ]; then
  echo "Warning: no --api-key given. The service will install but refuse to start until config.yaml has one." >&2
fi

mkdir -p "$INSTALL_DIR"
cp "$(dirname "$0")/k3-agent" "$INSTALL_DIR/k3-agent"
chmod 755 "$INSTALL_DIR/k3-agent"

cat > "$INSTALL_DIR/config.yaml" <<EOF
siem_url: $SIEM_URL
api_key: $API_KEY
agent_version: "1.0.0-cpp"
collection_interval: 10
heartbeat_interval: 30
batch_size: 50
vuln_scan_enabled: true
EOF
chmod 600 "$INSTALL_DIR/config.yaml"

cp "$(dirname "$0")/k3-agent.service" /etc/systemd/system/k3-agent.service
systemctl daemon-reload
systemctl enable --now k3-agent

# Outbound firewall rule, best-effort: Linux firewalls don't have Windows-style per-application
# rules, and the vast majority of distro defaults already allow all outbound traffic — this
# only takes action when ufw is both installed AND already in its (non-default) deny-outgoing
# mode, so the agent isn't silently blocked by a policy an admin deliberately turned on.
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  if ufw status verbose | grep -q "Default: deny (outgoing)"; then
    ufw allow out to any port 443 proto tcp comment "k3-agent"
    ufw allow out to any port 80 proto tcp comment "k3-agent"
  fi
fi

echo "K3 SIEM Agent installed and started (systemctl status k3-agent)."
