#!/usr/bin/env python3
"""
K3 SIEM Agent - Endpoint log collector and forwarder.
Collects logs from Windows Event Logs, Linux syslog, or simulates endpoints.
Sends normalized events to K3 SIEM via the /api/events/ingest endpoint.
"""

import argparse
import json
import os
import platform
import random
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

import requests
import yaml

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "siem_url": "http://localhost:3001",
    "api_key": "k3-ingest-key",
    "agent_version": "1.0.0",
    "collection_interval": 10,
    "heartbeat_interval": 30,
    "batch_size": 50,
    "sources": [],
    "simulate": False,
}


def load_config(config_path="config.yaml"):
    cfg = dict(DEFAULT_CONFIG)

    if os.path.exists(config_path):
        with open(config_path) as f:
            file_cfg = yaml.safe_load(f) or {}
        cfg.update(file_cfg)

    cfg["siem_url"] = os.environ.get("K3_SIEM_URL", cfg["siem_url"]).rstrip("/")
    cfg["api_key"] = os.environ.get("K3_API_KEY", cfg["api_key"])
    cfg["simulate"] = os.environ.get("K3_SIMULATE", str(cfg["simulate"])).lower() in ("true", "1", "yes")
    cfg["collection_interval"] = int(os.environ.get("K3_COLLECTION_INTERVAL", cfg["collection_interval"]))
    cfg["heartbeat_interval"] = int(os.environ.get("K3_HEARTBEAT_INTERVAL", cfg["heartbeat_interval"]))

    return cfg


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

running = True


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ---------------------------------------------------------------------------
# Real log collectors
# ---------------------------------------------------------------------------

def collect_windows_security(batch_size=50):
    """Collect Windows Security event logs via wevtutil."""
    events = []
    try:
        result = subprocess.run(
            ["wevtutil", "qe", "Security", f"/c:{batch_size}", "/f:json", "/rd:true"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                line = line.strip().rstrip(",")
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                    sys_data = evt.get("Event", {}).get("System", {})
                    event_data = evt.get("Event", {}).get("EventData", {})
                    eid = str(sys_data.get("EventID", {}).get("$", sys_data.get("EventID", "")))
                    events.append({
                        "timestamp": sys_data.get("TimeCreated", {}).get("@SystemTime", now_iso()),
                        "source": "Windows Security",
                        "event_id": eid,
                        "computer": sys_data.get("Computer", socket.gethostname()),
                        "username": event_data.get("TargetUserName", event_data.get("SubjectUserName", "")),
                        "ip_address": event_data.get("IpAddress", get_local_ip()),
                        "action": map_windows_event_action(eid),
                        "severity": map_windows_severity(eid),
                        "raw": json.dumps(evt),
                        "index": "windows-security",
                    })
                except (json.JSONDecodeError, KeyError):
                    continue
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        print(f"[Collector] Windows Security collection failed: {e}")
    return events


def collect_windows_system(batch_size=50):
    """Collect Windows System event logs."""
    events = []
    try:
        result = subprocess.run(
            ["wevtutil", "qe", "System", f"/c:{batch_size}", "/f:json", "/rd:true"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                line = line.strip().rstrip(",")
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                    sys_data = evt.get("Event", {}).get("System", {})
                    eid = str(sys_data.get("EventID", {}).get("$", sys_data.get("EventID", "")))
                    events.append({
                        "timestamp": sys_data.get("TimeCreated", {}).get("@SystemTime", now_iso()),
                        "source": "Windows System",
                        "event_id": eid,
                        "computer": sys_data.get("Computer", socket.gethostname()),
                        "username": "",
                        "ip_address": get_local_ip(),
                        "action": "System Event",
                        "severity": "Info",
                        "raw": json.dumps(evt),
                        "index": "windows-system",
                    })
                except (json.JSONDecodeError, KeyError):
                    continue
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        print(f"[Collector] Windows System collection failed: {e}")
    return events


def collect_linux_syslog(batch_size=50):
    """Collect from Linux syslog or journalctl."""
    events = []
    try:
        result = subprocess.run(
            ["journalctl", "--since", "30 seconds ago", "-o", "json", f"--lines={batch_size}"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    events.append({
                        "timestamp": datetime.fromtimestamp(
                            int(entry.get("__REALTIME_TIMESTAMP", "0")) / 1_000_000,
                            tz=timezone.utc
                        ).isoformat(),
                        "source": "Linux Syslog",
                        "event_id": entry.get("SYSLOG_IDENTIFIER", "syslog"),
                        "computer": entry.get("_HOSTNAME", socket.gethostname()),
                        "username": entry.get("_UID", ""),
                        "ip_address": get_local_ip(),
                        "action": entry.get("MESSAGE", "")[:200],
                        "severity": map_syslog_priority(int(entry.get("PRIORITY", "6"))),
                        "raw": json.dumps(entry),
                        "index": "linux-syslog",
                    })
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        log_path = "/var/log/syslog"
        if not os.path.exists(log_path):
            log_path = "/var/log/messages"
        if os.path.exists(log_path):
            try:
                result = subprocess.run(
                    ["tail", f"-n{batch_size}", log_path],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.strip().split("\n"):
                    if line:
                        events.append({
                            "timestamp": now_iso(),
                            "source": "Linux Syslog",
                            "event_id": "syslog",
                            "computer": socket.gethostname(),
                            "username": "",
                            "ip_address": get_local_ip(),
                            "action": line[:200],
                            "severity": "Info",
                            "raw": line,
                            "index": "linux-syslog",
                        })
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
    return events


def collect_linux_auth(batch_size=50):
    """Collect from Linux auth.log."""
    events = []
    auth_path = "/var/log/auth.log"
    if not os.path.exists(auth_path):
        auth_path = "/var/log/secure"
    if not os.path.exists(auth_path):
        return events
    try:
        result = subprocess.run(
            ["tail", f"-n{batch_size}", auth_path],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            severity = "Info"
            action = line[:200]
            if "Failed password" in line or "authentication failure" in line:
                severity = "High"
                action = "Failed Login"
            elif "Accepted password" in line or "Accepted publickey" in line:
                severity = "Low"
                action = "Successful Login"
            elif "sudo" in line:
                severity = "Medium"
                action = "Privilege Escalation"

            events.append({
                "timestamp": now_iso(),
                "source": "Linux Auth",
                "event_id": "auth",
                "computer": socket.gethostname(),
                "username": extract_username_from_auth(line),
                "ip_address": extract_ip_from_auth(line),
                "action": action,
                "severity": severity,
                "raw": line,
                "index": "linux-syslog",
            })
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return events


def extract_username_from_auth(line):
    import re
    m = re.search(r"for (?:invalid user )?(\S+)", line)
    return m.group(1) if m else ""


def extract_ip_from_auth(line):
    import re
    m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    return m.group(1) if m else get_local_ip()


def map_windows_event_action(eid):
    return {
        "4624": "User Logon", "4625": "Failed Logon", "4634": "User Logoff",
        "4648": "Explicit Credential Logon", "4672": "Privilege Use",
        "4688": "Process Create", "4689": "Process Exit",
        "4697": "Service Install", "7045": "Service Install",
        "1102": "Audit Log Cleared", "5156": "Network Connect",
        "4776": "Credential Validation",
    }.get(eid, "Security Event")


def map_windows_severity(eid):
    return {
        "4625": "Medium", "4672": "Medium", "4697": "High",
        "7045": "High", "1102": "Critical", "4688": "Low",
    }.get(eid, "Info")


def map_syslog_priority(priority):
    if priority <= 2:
        return "Critical"
    if priority == 3:
        return "High"
    if priority == 4:
        return "Medium"
    if priority == 5:
        return "Low"
    return "Info"


# ---------------------------------------------------------------------------
# Simulation engine
# ---------------------------------------------------------------------------

SIMULATE_PROFILES = {
    "windows": {
        "hostname_default": "WS-PC-001",
        "os": "Windows 11 Pro",
        "sources": ["Windows Security", "Windows System", "CrowdStrike EDR"],
        "index": "windows-security",
        "users": ["admin", "john.doe", "jane.smith", "svcAccount", "SYSTEM"],
        "computers": ["WS-PC-001", "WS-PC-002", "WS-LAPTOP-003"],
        "actions": ["User Logon", "Failed Logon", "Process Create", "Service Install",
                     "File Access", "PowerShell Exec", "Privilege Use", "Network Connect"],
        "event_ids": ["4624", "4625", "4688", "7045", "4672", "5156", "4634", "1102"],
    },
    "linux": {
        "hostname_default": "SRV-UBUNTU-01",
        "os": "Ubuntu 24.04 LTS",
        "sources": ["Linux Syslog", "Linux Auth", "OSSEC HIDS"],
        "index": "linux-syslog",
        "users": ["root", "www-data", "ubuntu", "deploy", "postgres", "nobody"],
        "computers": ["SRV-UBUNTU-01", "SRV-DEBIAN-02", "SRV-CENTOS-03"],
        "actions": ["SSH Login", "Failed SSH", "Sudo Command", "Cron Execution",
                     "File Modified", "Package Install", "Service Restart", "Process Killed"],
        "event_ids": ["sshd", "sudo", "cron", "systemd", "kernel", "auditd", "pam"],
    },
    "network": {
        "hostname_default": "FW-PALOALTO-01",
        "os": "PAN-OS 11.1",
        "sources": ["Palo Alto Firewall", "Cisco ASA", "Network IDS", "Cisco DNS"],
        "index": "network-flow",
        "users": ["N/A"],
        "computers": ["FW-PALOALTO-01", "FW-CISCO-01", "IDS-SNORT-01", "SW-CORE-01"],
        "actions": ["Traffic Allow", "Traffic Deny", "IDS Alert", "DNS Query",
                     "VPN Connect", "Port Scan Detected", "DDoS Attempt", "Threat Blocked"],
        "event_ids": ["TRAFFIC", "THREAT", "SYSTEM", "CONFIG", "GLOBALPROTECT"],
    },
}

SEVERITIES = ["Info", "Info", "Info", "Low", "Low", "Medium", "High", "Critical"]

MITRE_TACTICS = {
    "Failed Logon": ("Credential Access", "T1110.003"),
    "Failed SSH": ("Credential Access", "T1110.001"),
    "PowerShell Exec": ("Execution", "T1059.001"),
    "Privilege Use": ("Privilege Escalation", "T1078"),
    "Sudo Command": ("Privilege Escalation", "T1548.003"),
    "Service Install": ("Persistence", "T1543.003"),
    "File Access": ("Collection", "T1005"),
    "File Modified": ("Defense Evasion", "T1070"),
    "Port Scan Detected": ("Discovery", "T1046"),
    "DDoS Attempt": ("Impact", "T1498"),
    "IDS Alert": ("Initial Access", "T1190"),
    "Traffic Deny": ("Command and Control", "T1071"),
}


def generate_simulated_events(profile_name, hostname, batch_size=5):
    profile = SIMULATE_PROFILES.get(profile_name, SIMULATE_PROFILES["windows"])
    events = []

    for _ in range(random.randint(1, batch_size)):
        action = random.choice(profile["actions"])
        sev = random.choice(SEVERITIES)
        user = random.choice(profile["users"])
        comp = random.choice(profile["computers"])
        eid = random.choice(profile["event_ids"])
        src = random.choice(profile["sources"])
        src_ip = f"{random.randint(10, 192)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        dst_ip = f"{random.randint(10, 192)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

        raw = {
            "EventID": eid, "Computer": comp, "User": user,
            "SourceIP": src_ip, "DestIP": dst_ip,
            "Action": action, "Agent": hostname,
        }

        if action in MITRE_TACTICS:
            tactic, technique = MITRE_TACTICS[action]
            raw["MITRE_Tactic"] = tactic
            raw["MITRE_Technique"] = technique

        if action in ("Failed Logon", "Failed SSH") and random.random() > 0.5:
            sev = random.choice(["Medium", "High", "Critical"])

        events.append({
            "timestamp": now_iso(),
            "source": src,
            "event_id": eid,
            "computer": comp,
            "username": user,
            "ip_address": src_ip,
            "action": action,
            "severity": sev,
            "raw": json.dumps(raw),
            "index": profile["index"],
        })

    return events


# ---------------------------------------------------------------------------
# SIEM communication
# ---------------------------------------------------------------------------

class SIEMClient:
    def __init__(self, cfg):
        self.base_url = cfg["siem_url"]
        self.api_key = cfg["api_key"]
        self.agent_id = None
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "X-Api-Key": self.api_key,
        })

    def register(self, hostname, os_name, ip, version, sources):
        for attempt in range(10):
            try:
                resp = self.session.post(f"{self.base_url}/api/agents/register", json={
                    "hostname": hostname,
                    "os": os_name,
                    "ip": ip,
                    "agent_version": version,
                    "collected_sources": sources,
                })
                resp.raise_for_status()
                data = resp.json()
                self.agent_id = data["agent_id"]
                self.session.headers["X-Agent-Id"] = self.agent_id
                print(f"[Agent] Registered as {self.agent_id} ({data['status']})")
                return True
            except requests.RequestException as e:
                wait = min(2 ** attempt, 60)
                print(f"[Agent] Registration failed (attempt {attempt + 1}): {e} — retrying in {wait}s")
                time.sleep(wait)
        return False

    def send_heartbeat(self):
        try:
            self.session.post(
                f"{self.base_url}/api/agents/{self.agent_id}/heartbeat",
                json={"metrics": {}},
                timeout=10,
            )
        except requests.RequestException:
            pass

    def send_events(self, events):
        if not events:
            return 0
        for evt in events:
            evt["agent_id"] = self.agent_id

        for attempt in range(3):
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/events/ingest",
                    json=events,
                    timeout=30,
                )
                resp.raise_for_status()
                return resp.json().get("ingested", len(events))
            except requests.RequestException as e:
                if attempt < 2:
                    time.sleep(2 ** attempt)
                else:
                    print(f"[Agent] Failed to send {len(events)} events: {e}")
        return 0


# ---------------------------------------------------------------------------
# Collector dispatcher
# ---------------------------------------------------------------------------

COLLECTORS = {
    "windows_security": collect_windows_security,
    "windows_system": collect_windows_system,
    "windows_application": lambda bs: [],
    "linux_syslog": collect_linux_syslog,
    "linux_auth": collect_linux_auth,
}


def collect_real_logs(sources, batch_size):
    all_events = []
    for src in sources:
        collector = COLLECTORS.get(src)
        if collector:
            try:
                all_events.extend(collector(batch_size))
            except Exception as e:
                print(f"[Collector] Error in {src}: {e}")
    return all_events


# ---------------------------------------------------------------------------
# Main agent loop
# ---------------------------------------------------------------------------

def heartbeat_loop(client, interval):
    while running:
        client.send_heartbeat()
        for _ in range(interval):
            if not running:
                break
            time.sleep(1)


def main():
    global running

    parser = argparse.ArgumentParser(description="K3 SIEM Agent")
    parser.add_argument("--config", default="config.yaml", help="Config file path")
    parser.add_argument("--simulate", action="store_true", help="Run in simulation mode")
    parser.add_argument("--simulate-os", default=None, help="OS to simulate: windows, linux, network")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.simulate:
        cfg["simulate"] = True

    simulate_os = args.simulate_os or os.environ.get("K3_SIMULATE_OS", "").lower()
    hostname = os.environ.get("K3_HOSTNAME", socket.gethostname())

    if cfg["simulate"] and simulate_os:
        profile = SIMULATE_PROFILES.get(simulate_os, SIMULATE_PROFILES["windows"])
        os_name = profile["os"]
        hostname = os.environ.get("K3_HOSTNAME", profile["hostname_default"])
        sources = profile["sources"]
    else:
        os_name = f"{platform.system()} {platform.release()}"
        sources = cfg.get("sources", [])

    ip = get_local_ip()
    version = cfg.get("agent_version", "1.0.0")

    print(f"[Agent] K3 SIEM Agent v{version}")
    print(f"[Agent] Hostname: {hostname} | OS: {os_name} | IP: {ip}")
    print(f"[Agent] SIEM: {cfg['siem_url']}")
    print(f"[Agent] Mode: {'Simulation (' + simulate_os + ')' if cfg['simulate'] else 'Live Collection'}")

    def shutdown(sig, frame):
        global running
        print("\n[Agent] Shutting down...")
        running = False

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    client = SIEMClient(cfg)
    if not client.register(hostname, os_name, ip, version, sources):
        print("[Agent] Failed to register after 10 attempts. Exiting.")
        sys.exit(1)

    hb_thread = threading.Thread(target=heartbeat_loop, args=(client, cfg["heartbeat_interval"]), daemon=True)
    hb_thread.start()

    total_sent = 0
    print(f"[Agent] Collecting every {cfg['collection_interval']}s (batch_size={cfg['batch_size']})")

    while running:
        try:
            if cfg["simulate"]:
                events = generate_simulated_events(simulate_os or "windows", hostname, cfg["batch_size"])
            else:
                events = collect_real_logs(cfg.get("sources", []), cfg["batch_size"])

            if events:
                sent = client.send_events(events)
                total_sent += sent
                print(f"[Agent] Sent {sent} events (total: {total_sent})")

        except Exception as e:
            print(f"[Agent] Collection error: {e}")

        for _ in range(cfg["collection_interval"]):
            if not running:
                break
            time.sleep(1)

    print(f"[Agent] Stopped. Total events sent: {total_sent}")


if __name__ == "__main__":
    main()
