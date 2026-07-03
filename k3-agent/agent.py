#!/usr/bin/env python3
"""
K3 SIEM Agent - Endpoint log collector and forwarder.
Collects logs from Windows Event Logs, Linux syslog, or simulates endpoints.
Sends normalized events to K3 SIEM via the /api/events/ingest endpoint.
"""

import argparse
import glob
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
    "vuln_scan_enabled": True,
    "nvd_api_key": None,
    "auto_discover_app_logs": True,
    "app_log_paths": [],
    "app_log_max_files": 40,
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
    cfg["vuln_scan_enabled"] = os.environ.get("K3_VULN_SCAN", str(cfg["vuln_scan_enabled"])).lower() in ("true", "1", "yes")
    cfg["nvd_api_key"] = os.environ.get("K3_NVD_API_KEY", cfg.get("nvd_api_key"))

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

def _xml_local(tag):
    return tag.rsplit('}', 1)[-1] if '}' in tag else tag


def parse_wevtutil_xml(raw_output):
    """Parse `wevtutil qe ... /f:XML` output.

    wevtutil prints one full <Event>...</Event> document per record with no
    separators (not newline-delimited, not comma-delimited, not JSON despite
    what /f:json — an invalid value — might suggest). Wrapping the whole
    stream in a synthetic root lets ElementTree parse it as one document.
    Returns a list of {"Event": {"System": {...}, "EventData": {...}}} dicts
    shaped the same way ocsfParser.js's flattenWindowsEvent expects.
    """
    import xml.etree.ElementTree as ET

    events = []
    if not raw_output or not raw_output.strip():
        return events
    try:
        root = ET.fromstring(f"<Events>{raw_output}</Events>")
    except ET.ParseError:
        return events

    for ev in root:
        if _xml_local(ev.tag) != "Event":
            continue
        system, event_data = {}, {}
        for child in ev:
            tag = _xml_local(child.tag)
            if tag == "System":
                for f in child:
                    ftag = _xml_local(f.tag)
                    if ftag == "EventID":
                        system["EventID"] = (f.text or "").strip()
                    elif ftag == "TimeCreated":
                        system["TimeCreated"] = {"@SystemTime": f.get("SystemTime", "")}
                    elif ftag == "Computer":
                        system["Computer"] = (f.text or "").strip()
                    elif ftag == "Provider":
                        system["Provider"] = {"@Name": f.get("Name", "")}
                    elif ftag == "Level":
                        system["Level"] = (f.text or "").strip()
            elif tag == "EventData":
                for d in child:
                    name = d.get("Name")
                    if name:
                        event_data[name] = d.text or ""
        events.append({"Event": {"System": system, "EventData": event_data}})
    return events


def collect_windows_security(batch_size=50):
    """Collect Windows Security event logs via wevtutil."""
    events = []
    try:
        result = subprocess.run(
            ["wevtutil", "qe", "Security", f"/c:{batch_size}", "/f:XML", "/rd:true"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            for evt in parse_wevtutil_xml(result.stdout):
                sys_data = evt["Event"]["System"]
                event_data = evt["Event"]["EventData"]
                eid = str(sys_data.get("EventID", ""))
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
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        print(f"[Collector] Windows Security collection failed: {e}")
    return events


def collect_windows_system(batch_size=50):
    """Collect Windows System event logs."""
    events = []
    try:
        result = subprocess.run(
            ["wevtutil", "qe", "System", f"/c:{batch_size}", "/f:XML", "/rd:true"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            for evt in parse_wevtutil_xml(result.stdout):
                sys_data = evt["Event"]["System"]
                eid = str(sys_data.get("EventID", ""))
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
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        print(f"[Collector] Windows System collection failed: {e}")
    return events


def collect_windows_application(batch_size=50):
    """Collect Windows Application event logs (installed apps/services logging via ETW)."""
    events = []
    try:
        result = subprocess.run(
            ["wevtutil", "qe", "Application", f"/c:{batch_size}", "/f:XML", "/rd:true"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            for evt in parse_wevtutil_xml(result.stdout):
                sys_data = evt["Event"]["System"]
                eid = str(sys_data.get("EventID", ""))
                app_name = sys_data.get("Provider", {}).get("@Name", "Application")
                level_val = sys_data.get("Level", "")
                events.append({
                    "timestamp": sys_data.get("TimeCreated", {}).get("@SystemTime", now_iso()),
                    "source": f"AppLog:{app_name}",
                    "event_id": eid,
                    "computer": sys_data.get("Computer", socket.gethostname()),
                    "username": "",
                    "ip_address": get_local_ip(),
                    "action": f"{app_name} Event {eid}",
                    "severity": map_windows_app_level(level_val),
                    "raw": json.dumps(evt),
                    "index": "windows-application",
                })
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        print(f"[Collector] Windows Application collection failed: {e}")
    return events


def map_windows_app_level(level):
    return {"1": "Critical", "2": "High", "3": "Medium", "4": "Info", "0": "Info"}.get(str(level), "Info")


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

    def send_inventory(self, inventory):
        try:
            resp = self.session.post(
                f"{self.base_url}/api/agents/{self.agent_id}/inventory",
                json=inventory,
                timeout=30,
            )
            resp.raise_for_status()
            print(f"[Agent] Inventory reported ({inventory.get('os_name', 'unknown')})")
            return True
        except requests.RequestException as e:
            print(f"[Agent] Failed to send inventory: {e}")
            return False

    def send_vulnerabilities(self, vulnerabilities):
        try:
            resp = self.session.post(
                f"{self.base_url}/api/agents/{self.agent_id}/vulnerabilities",
                json={"vulnerabilities": vulnerabilities},
                timeout=60,
            )
            resp.raise_for_status()
            print(f"[Agent] Vulnerability scan reported ({len(vulnerabilities)} findings)")
            return True
        except requests.RequestException as e:
            print(f"[Agent] Failed to send vulnerabilities: {e}")
            return False

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
    "windows_application": collect_windows_application,
    "linux_syslog": collect_linux_syslog,
    "linux_auth": collect_linux_auth,
}


def collect_real_logs(sources, batch_size, cfg=None, state=None):
    all_events = []
    for src in sources:
        if src == "app_logs":
            try:
                all_events.extend(collect_app_logs(cfg or {}, state if state is not None else {}))
            except Exception as e:
                print(f"[Collector] Error in app_logs: {e}")
            continue
        collector = COLLECTORS.get(src)
        if collector:
            try:
                all_events.extend(collector(batch_size))
            except Exception as e:
                print(f"[Collector] Error in {src}: {e}")
    return all_events


# ---------------------------------------------------------------------------
# Installed-application log discovery & tailing
# ---------------------------------------------------------------------------

WINDOWS_APP_LOG_GLOBS = [
    r"C:\inetpub\logs\LogFiles\**\*.log",
    r"C:\ProgramData\*\Logs\*.log",
    r"C:\ProgramData\*\logs\*.log",
    r"C:\Program Files\*\logs\*.log",
    r"C:\Program Files\*\Logs\*.log",
    r"C:\Program Files (x86)\*\logs\*.log",
]

LINUX_APP_LOG_GLOBS = [
    "/var/log/*.log",
    "/var/log/nginx/*.log",
    "/var/log/apache2/*.log",
    "/var/log/httpd/*.log",
    "/var/log/mysql/*.log",
    "/var/log/postgresql/*.log",
    "/var/log/docker.log",
]

_STATE_LOCK = threading.Lock()


def load_state(state_path):
    if os.path.exists(state_path):
        try:
            with open(state_path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {"files": {}}


def save_state(state_path, state):
    tmp_path = f"{state_path}.tmp"
    try:
        with _STATE_LOCK:
            with open(tmp_path, "w") as f:
                json.dump(state, f)
            os.replace(tmp_path, state_path)
    except OSError as e:
        print(f"[Agent] Failed to save state: {e}")


def discover_app_log_paths(cfg):
    """Find candidate installed-application log files, capped by app_log_max_files.

    Dedupes via os.path.normcase so the same physical file matched by two glob
    patterns under different casing (e.g. "...\\Logs\\..." and "...\\logs\\...",
    which are identical on Windows' case-insensitive filesystem) is only tailed once.
    """
    max_files = int(cfg.get("app_log_max_files", 40))
    found = []
    seen = set()

    def add(p):
        key = os.path.normcase(os.path.abspath(p))
        if key in seen:
            return False
        seen.add(key)
        found.append(p)
        return True

    for p in cfg.get("app_log_paths", []) or []:
        if os.path.isfile(p):
            add(p)

    if cfg.get("auto_discover_app_logs", True):
        patterns = WINDOWS_APP_LOG_GLOBS if platform.system() == "Windows" else LINUX_APP_LOG_GLOBS
        for pattern in patterns:
            try:
                for p in glob.glob(pattern, recursive=True):
                    if os.path.isfile(p):
                        add(p)
                    if len(found) >= max_files:
                        break
            except OSError:
                continue
            if len(found) >= max_files:
                break

    return found[:max_files]


def read_new_lines(path, state, max_lines=200):
    """Tail a log file since the last recorded byte offset, tracked in `state`."""
    files_state = state.setdefault("files", {})
    entry = files_state.get(path, {"offset": 0})

    try:
        size = os.path.getsize(path)
    except OSError:
        return []

    offset = entry.get("offset", 0)
    if size < offset:
        # File was truncated or rotated — start over.
        offset = 0

    # Read in binary mode and split on exact byte boundaries — text-mode iteration
    # (`for line in f`) disables `f.tell()` once read-ahead buffering kicks in, so
    # offsets can't be tracked accurately that way.
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            chunk = f.read()
    except OSError as e:
        print(f"[Collector] Failed to read {path}: {e}")
        return []

    raw_lines = chunk.split(b"\n")
    # Drop the last element: if the chunk ends with '\n' it's an empty string;
    # otherwise it's a partial line still being written, so leave it unread.
    complete_lines = raw_lines[:-1][:max_lines]
    consumed_bytes = sum(len(l) + 1 for l in complete_lines)
    entry["offset"] = offset + consumed_bytes
    files_state[path] = entry

    lines = [l.decode("utf-8", errors="ignore").rstrip("\r") for l in complete_lines]
    lines = [l for l in lines if l]
    return lines


def guess_log_severity(line):
    low = line.lower()
    if "fatal" in low or "critical" in low or "panic" in low:
        return "Critical"
    if "error" in low or "exception" in low or "fail" in low:
        return "High"
    if "warn" in low:
        return "Medium"
    return "Info"


def collect_app_logs(cfg, state):
    """Discover installed-application log files and ship any new lines since last read."""
    now = time.time()
    cache = state.setdefault("_discovery_cache", {"paths": [], "at": 0})
    if now - cache.get("at", 0) > 300 or not cache.get("paths"):
        cache["paths"] = discover_app_log_paths(cfg)
        cache["at"] = now

    events = []
    hostname = socket.gethostname()
    ip = get_local_ip()
    for path in cache["paths"]:
        for line in read_new_lines(path, state):
            app_name = os.path.splitext(os.path.basename(path))[0]
            events.append({
                "timestamp": now_iso(),
                "source": f"AppLog:{app_name}",
                "event_id": "app_log",
                "computer": hostname,
                "username": "",
                "ip_address": ip,
                "action": line[:300],
                "severity": guess_log_severity(line),
                "raw": line,
                "index": "application-logs",
            })

    return events


# ---------------------------------------------------------------------------
# Inventory collection
# ---------------------------------------------------------------------------

def collect_real_inventory():
    import psutil
    inv = {
        "hostname": socket.gethostname(),
        "os_name": f"{platform.system()} {platform.release()}",
        "os_version": platform.version(),
        "os_arch": platform.machine(),
        "cpu_model": platform.processor() or "Unknown",
        "cpu_cores": psutil.cpu_count(logical=True),
        "ram_total_gb": round(psutil.virtual_memory().total / (1024 ** 3), 1),
        "disk_total_gb": 0,
        "disk_used_gb": 0,
        "network_interfaces": [],
        "installed_software": [],
        "running_services": [],
        "open_ports": [],
        "local_users": [],
        "antivirus_status": "Unknown",
        "firewall_enabled": False,
        "last_patch_date": None,
        "uptime_hours": round((time.time() - psutil.boot_time()) / 3600, 1),
        "domain": socket.getfqdn(),
        "serial_number": None,
    }

    try:
        for part in psutil.disk_partitions():
            usage = psutil.disk_usage(part.mountpoint)
            inv["disk_total_gb"] += round(usage.total / (1024 ** 3), 1)
            inv["disk_used_gb"] += round(usage.used / (1024 ** 3), 1)
    except Exception:
        pass

    try:
        for name, addrs in psutil.net_if_addrs().items():
            iface = {"name": name, "ip": None, "mac": None}
            for a in addrs:
                if a.family.name == "AF_INET":
                    iface["ip"] = a.address
                elif a.family.name == "AF_LINK" or str(a.family) == "17":
                    iface["mac"] = a.address
            if iface["ip"]:
                inv["network_interfaces"].append(iface)
    except Exception:
        pass

    try:
        conns = psutil.net_connections(kind="inet")
        seen = set()
        for c in conns:
            if c.status == "LISTEN" and c.laddr and c.laddr.port not in seen:
                seen.add(c.laddr.port)
                inv["open_ports"].append({"port": c.laddr.port, "proto": "tcp"})
    except Exception:
        pass

    try:
        for u in psutil.users():
            inv["local_users"].append({"name": u.name, "terminal": u.terminal or ""})
    except Exception:
        pass

    if platform.system() == "Linux":
        try:
            result = subprocess.run(["dpkg", "-l"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split("\n")[5:55]:
                parts = line.split()
                if len(parts) >= 3:
                    inv["installed_software"].append({"name": parts[1], "version": parts[2]})
        except Exception:
            pass
        try:
            result = subprocess.run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.strip().split("\n")[:30]:
                parts = line.split()
                if parts:
                    inv["running_services"].append({"name": parts[0].replace(".service", ""), "status": "running"})
        except Exception:
            pass
        try:
            result = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
            inv["firewall_enabled"] = "active" in result.stdout.lower()
        except Exception:
            pass

    elif platform.system() == "Windows":
        try:
            result = subprocess.run(["wmic", "product", "get", "name,version", "/format:csv"], capture_output=True, text=True, timeout=30)
            for line in result.stdout.strip().split("\n")[1:51]:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 3 and parts[1]:
                    inv["installed_software"].append({"name": parts[1], "version": parts[2]})
        except Exception:
            pass
        try:
            result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"], capture_output=True, text=True, timeout=5)
            inv["firewall_enabled"] = "ON" in result.stdout.upper()
        except Exception:
            pass

    return inv


INVENTORY_PROFILES = {
    "windows": {
        "os_name": "Windows 11 Pro",
        "os_version": "10.0.22631",
        "os_arch": "x86_64",
        "cpu_model": "Intel Core i7-13700K",
        "cpu_cores": 16,
        "ram_total_gb": 16.0,
        "disk_total_gb": 512.0,
        "disk_used_gb": 287.3,
        "antivirus_status": "CrowdStrike Falcon",
        "firewall_enabled": True,
        "last_patch_date": "2026-06-15",
        "domain": "corp.k3sec.io",
        "serial_number": "K3-WS-2024-001",
        "network_interfaces": [
            {"name": "Ethernet", "ip": "192.168.1.66", "mac": "00:1A:2B:3C:4D:5E"},
            {"name": "Wi-Fi", "ip": "192.168.1.67", "mac": "00:1A:2B:3C:4D:5F"},
        ],
        "installed_software": [
            {"name": "CrowdStrike Falcon Sensor", "version": "7.10.18012"},
            {"name": "Microsoft 365 Apps", "version": "16.0.17928"},
            {"name": "Google Chrome", "version": "126.0.6478"},
            {"name": "Visual Studio Code", "version": "1.92.2"},
            {"name": "7-Zip", "version": "24.07"},
            {"name": "Python 3.12", "version": "3.12.4"},
            {"name": "Git for Windows", "version": "2.46.0"},
            {"name": "Slack", "version": "4.39.95"},
            {"name": "Zoom", "version": "6.1.6"},
            {"name": "Adobe Acrobat Reader", "version": "24.002"},
        ],
        "running_services": [
            {"name": "CrowdStrike Falcon", "status": "running"},
            {"name": "Windows Defender", "status": "running"},
            {"name": "Windows Update", "status": "running"},
            {"name": "DNS Client", "status": "running"},
            {"name": "DHCP Client", "status": "running"},
            {"name": "Print Spooler", "status": "running"},
        ],
        "open_ports": [
            {"port": 135, "proto": "tcp"}, {"port": 445, "proto": "tcp"},
            {"port": 3389, "proto": "tcp"}, {"port": 5985, "proto": "tcp"},
        ],
        "local_users": [
            {"name": "john.doe"}, {"name": "Administrator"}, {"name": "svcCrowdStrike"},
        ],
    },
    "linux": {
        "os_name": "Ubuntu 24.04 LTS",
        "os_version": "6.8.0-45-generic",
        "os_arch": "x86_64",
        "cpu_model": "AMD EPYC 7763",
        "cpu_cores": 8,
        "ram_total_gb": 64.0,
        "disk_total_gb": 1000.0,
        "disk_used_gb": 423.7,
        "antivirus_status": "ClamAV",
        "firewall_enabled": True,
        "last_patch_date": "2026-06-20",
        "domain": "srv.k3sec.io",
        "serial_number": "K3-SRV-2024-001",
        "network_interfaces": [
            {"name": "eth0", "ip": "10.0.1.50", "mac": "02:42:AC:11:00:02"},
            {"name": "docker0", "ip": "172.17.0.1", "mac": "02:42:D4:6E:8A:01"},
        ],
        "installed_software": [
            {"name": "openssh-server", "version": "9.6p1"},
            {"name": "nginx", "version": "1.24.0"},
            {"name": "postgresql-16", "version": "16.3"},
            {"name": "docker-ce", "version": "27.1.1"},
            {"name": "python3", "version": "3.12.3"},
            {"name": "clamav", "version": "1.3.1"},
            {"name": "fail2ban", "version": "1.0.2"},
            {"name": "ufw", "version": "0.36.2"},
            {"name": "curl", "version": "8.5.0"},
            {"name": "git", "version": "2.43.0"},
        ],
        "running_services": [
            {"name": "sshd", "status": "running"},
            {"name": "nginx", "status": "running"},
            {"name": "postgresql", "status": "running"},
            {"name": "docker", "status": "running"},
            {"name": "clamav-daemon", "status": "running"},
            {"name": "fail2ban", "status": "running"},
            {"name": "ufw", "status": "running"},
        ],
        "open_ports": [
            {"port": 22, "proto": "tcp"}, {"port": 80, "proto": "tcp"},
            {"port": 443, "proto": "tcp"}, {"port": 5432, "proto": "tcp"},
        ],
        "local_users": [
            {"name": "root"}, {"name": "ubuntu"}, {"name": "deploy"}, {"name": "postgres"}, {"name": "www-data"},
        ],
    },
    "network": {
        "os_name": "PAN-OS 11.1",
        "os_version": "11.1.3",
        "os_arch": "arm64",
        "cpu_model": "Cavium Octeon III",
        "cpu_cores": 4,
        "ram_total_gb": 16.0,
        "disk_total_gb": 240.0,
        "disk_used_gb": 45.2,
        "antivirus_status": "WildFire",
        "firewall_enabled": True,
        "last_patch_date": "2026-06-10",
        "domain": "fw.k3sec.io",
        "serial_number": "K3-FW-2024-001",
        "network_interfaces": [
            {"name": "ethernet1/1", "ip": "203.0.113.1", "mac": "00:1B:17:00:01:01"},
            {"name": "ethernet1/2", "ip": "10.0.0.1", "mac": "00:1B:17:00:01:02"},
            {"name": "loopback", "ip": "192.168.255.1", "mac": "N/A"},
        ],
        "installed_software": [
            {"name": "PAN-OS", "version": "11.1.3"},
            {"name": "Threat Prevention", "version": "8832-8640"},
            {"name": "WildFire", "version": "832416"},
            {"name": "URL Filtering", "version": "20260625"},
            {"name": "GlobalProtect", "version": "6.2.1"},
        ],
        "running_services": [
            {"name": "mgmtsrvr", "status": "running"},
            {"name": "pan_task", "status": "running"},
            {"name": "configd", "status": "running"},
            {"name": "logrcvr", "status": "running"},
        ],
        "open_ports": [
            {"port": 443, "proto": "tcp"}, {"port": 22, "proto": "tcp"},
            {"port": 4443, "proto": "tcp"},
        ],
        "local_users": [
            {"name": "admin"}, {"name": "panorama-svc"},
        ],
    },
}


def generate_simulated_inventory(profile_name, hostname):
    profile = INVENTORY_PROFILES.get(profile_name, INVENTORY_PROFILES["windows"])
    inv = dict(profile)
    inv["hostname"] = hostname
    inv["uptime_hours"] = round(random.uniform(24, 2160), 1)
    inv["disk_used_gb"] = round(inv["disk_used_gb"] + random.uniform(-20, 20), 1)
    return inv


# ---------------------------------------------------------------------------
# Vulnerability / CVE scanning
# ---------------------------------------------------------------------------

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SIMULATED_CVES = {
    "windows": [
        {"cve_id": "CVE-2024-30051", "software_name": "Windows 11 Pro", "software_version": "10.0.22631", "software_type": "os", "description": "Windows DWM Core Library Elevation of Privilege Vulnerability allows a local attacker to gain SYSTEM privileges.", "cvss_score": 7.8, "severity": "HIGH", "published": "2024-05-14", "last_modified": "2024-05-20", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2024-20674", "software_name": "Windows 11 Pro", "software_version": "10.0.22631", "software_type": "os", "description": "Windows Kerberos Security Feature Bypass Vulnerability allows an attacker to bypass authentication.", "cvss_score": 9.0, "severity": "CRITICAL", "published": "2024-01-09", "last_modified": "2024-01-18", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2023-36025", "software_name": "Windows 11 Pro", "software_version": "10.0.22631", "software_type": "os", "description": "Windows SmartScreen Security Feature Bypass Vulnerability.", "cvss_score": 8.8, "severity": "HIGH", "published": "2023-11-14", "last_modified": "2023-11-21", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2024-21413", "software_name": "Microsoft 365 Apps", "software_version": "16.0.17928", "software_type": "software", "description": "Microsoft Outlook Remote Code Execution Vulnerability via crafted email (Moniker Link).", "cvss_score": 9.8, "severity": "CRITICAL", "published": "2024-02-13", "last_modified": "2024-02-15", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2024-0519", "software_name": "Google Chrome", "software_version": "126.0.6478", "software_type": "software", "description": "Out of bounds memory access in V8 in Google Chrome allows a remote attacker to exploit heap corruption.", "cvss_score": 8.8, "severity": "HIGH", "published": "2024-01-17", "last_modified": "2024-01-19", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2024-21338", "software_name": "Windows 11 Pro", "software_version": "10.0.22631", "software_type": "os", "description": "Windows Kernel Elevation of Privilege Vulnerability exploited via AppLocker driver.", "cvss_score": 7.8, "severity": "HIGH", "published": "2024-02-13", "last_modified": "2024-02-21", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2024-23897", "software_name": "Git for Windows", "software_version": "2.46.0", "software_type": "software", "description": "Jenkins CLI arbitrary file read vulnerability affecting bundled Git client args parsing.", "cvss_score": 7.5, "severity": "HIGH", "published": "2024-01-24", "last_modified": "2024-01-29", "vuln_status": "Analyzed"},
    ],
    "linux": [
        {"cve_id": "CVE-2024-6387", "software_name": "openssh-server", "software_version": "9.6p1", "software_type": "software", "description": "RegreSSHion: signal handler race condition in OpenSSH server allows unauthenticated remote code execution.", "cvss_score": 8.1, "severity": "HIGH", "published": "2024-07-01", "last_modified": "2024-07-08", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2023-44487", "software_name": "nginx", "software_version": "1.24.0", "software_type": "software", "description": "HTTP/2 Rapid Reset Attack allows remote denial of service via stream cancellation.", "cvss_score": 7.5, "severity": "HIGH", "published": "2023-10-10", "last_modified": "2023-10-19", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2024-2961", "software_name": "python3", "software_version": "3.12.3", "software_type": "software", "description": "glibc iconv() out-of-bounds write when converting strings to ISO-2022-CN-EXT.", "cvss_score": 8.8, "severity": "HIGH", "published": "2024-04-09", "last_modified": "2024-04-15", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2024-1086", "software_name": "Ubuntu 24.04 LTS", "software_version": "6.8.0-45-generic", "software_type": "os", "description": "Linux kernel netfilter nf_tables use-after-free allows local privilege escalation to root.", "cvss_score": 7.8, "severity": "HIGH", "published": "2024-01-31", "last_modified": "2024-03-26", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2024-21626", "software_name": "docker-ce", "software_version": "27.1.1", "software_type": "software", "description": "runc container breakout via leaked file descriptor allows host filesystem access.", "cvss_score": 8.6, "severity": "HIGH", "published": "2024-01-31", "last_modified": "2024-02-07", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2024-10963", "software_name": "postgresql-16", "software_version": "16.3", "software_type": "software", "description": "PostgreSQL pg_database access control bypass via RLS policy on row-level security.", "cvss_score": 6.5, "severity": "MEDIUM", "published": "2024-11-14", "last_modified": "2024-11-18", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2024-28182", "software_name": "nginx", "software_version": "1.24.0", "software_type": "software", "description": "nghttp2 HTTP/2 CONTINUATION frame flood causes excessive resource consumption.", "cvss_score": 5.3, "severity": "MEDIUM", "published": "2024-04-03", "last_modified": "2024-04-05", "vuln_status": "Analyzed"},
    ],
    "network": [
        {"cve_id": "CVE-2024-3400", "software_name": "PAN-OS", "software_version": "11.1.3", "software_type": "os", "description": "Arbitrary file creation vulnerability in PAN-OS GlobalProtect feature leads to unauthenticated remote code execution.", "cvss_score": 10.0, "severity": "CRITICAL", "published": "2024-04-12", "last_modified": "2024-04-18", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2024-0012", "software_name": "PAN-OS", "software_version": "11.1.3", "software_type": "os", "description": "Authentication bypass in PAN-OS management web interface allows admin privilege actions.", "cvss_score": 9.3, "severity": "CRITICAL", "published": "2024-11-18", "last_modified": "2024-11-20", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2024-5910", "software_name": "GlobalProtect", "software_version": "6.2.1", "software_type": "software", "description": "Missing authentication for critical function in PAN-OS Expedition allows admin account takeover.", "cvss_score": 9.3, "severity": "CRITICAL", "published": "2024-07-10", "last_modified": "2024-07-12", "vuln_status": "Analyzed"},
        {"cve_id": "CVE-2024-9474", "software_name": "PAN-OS", "software_version": "11.1.3", "software_type": "os", "description": "OS command injection in PAN-OS management web interface allows root command execution as admin.", "cvss_score": 7.2, "severity": "HIGH", "published": "2024-11-18", "last_modified": "2024-11-20", "vuln_status": "Analyzed"},
    ],
}


def severity_from_score(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def scan_vulnerabilities_nvd(installed_software, os_name=None, max_items=12, api_key=None):
    """Query the NVD CVE API for known vulnerabilities matching installed software/OS."""
    findings = []
    items = []
    if os_name:
        items.append({"name": os_name, "version": None, "type": "os"})
    for sw in installed_software[:max_items]:
        name = sw.get("name") if isinstance(sw, dict) else sw
        version = sw.get("version") if isinstance(sw, dict) else None
        if name:
            items.append({"name": name, "version": version, "type": "software"})

    headers = {"apiKey": api_key} if api_key else {}
    delay = 2.5 if api_key else 6.5  # NVD rate limit: 50/30s with key, 5/30s without

    for item in items:
        try:
            params = {"keywordSearch": item["name"], "resultsPerPage": 3}
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for v in data.get("vulnerabilities", []):
                    cve = v.get("cve", {})
                    cve_id = cve.get("id", "")
                    if not cve_id:
                        continue
                    desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")

                    score, severity = None, "UNKNOWN"
                    metrics = cve.get("metrics", {})
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if metrics.get(key):
                            cvss = metrics[key][0].get("cvssData", {})
                            score = cvss.get("baseScore")
                            severity = (cvss.get("baseSeverity") or metrics[key][0].get("baseSeverity") or severity_from_score(score)).upper()
                            break

                    findings.append({
                        "cve_id": cve_id,
                        "software_name": item["name"],
                        "software_version": item["version"],
                        "software_type": item["type"],
                        "description": desc[:500],
                        "cvss_score": score,
                        "severity": severity,
                        "published": cve.get("published"),
                        "last_modified": cve.get("lastModified"),
                        "vuln_status": cve.get("vulnStatus", ""),
                    })
            elif resp.status_code == 403:
                print("[CVE] NVD rate limited (403) — backing off")
                time.sleep(10)
        except requests.RequestException as e:
            print(f"[CVE] Lookup failed for {item['name']}: {e}")
        time.sleep(delay)

    return findings


def generate_simulated_vulnerabilities(profile_name):
    return list(SIMULATED_CVES.get(profile_name, SIMULATED_CVES["windows"]))


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
    state_path = os.environ.get("K3_STATE_PATH", "agent_state.json")
    state = load_state(state_path)
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

    if cfg["simulate"]:
        inv = generate_simulated_inventory(simulate_os or "windows", hostname)
    else:
        inv = collect_real_inventory()
    client.send_inventory(inv)

    def run_vuln_scan(inventory):
        try:
            if cfg["simulate"]:
                vulns = generate_simulated_vulnerabilities(simulate_os or "windows")
            else:
                vulns = scan_vulnerabilities_nvd(
                    inventory.get("installed_software", []),
                    os_name=inventory.get("os_name"),
                    api_key=cfg.get("nvd_api_key"),
                )
            if vulns:
                client.send_vulnerabilities(vulns)
        except Exception as e:
            print(f"[Agent] Vulnerability scan error: {e}")

    if cfg["vuln_scan_enabled"]:
        threading.Thread(target=run_vuln_scan, args=(inv,), daemon=True).start()

    total_sent = 0
    inv_counter = 0
    inv_interval = 30
    vuln_counter = 0
    vuln_interval = 180  # rescan roughly every 30 min at 10s collection_interval
    print(f"[Agent] Collecting every {cfg['collection_interval']}s (batch_size={cfg['batch_size']})")

    while running:
        try:
            if cfg["simulate"]:
                events = generate_simulated_events(simulate_os or "windows", hostname, cfg["batch_size"])
            else:
                events = collect_real_logs(cfg.get("sources", []), cfg["batch_size"], cfg=cfg, state=state)
                save_state(state_path, state)

            if events:
                sent = client.send_events(events)
                total_sent += sent
                print(f"[Agent] Sent {sent} events (total: {total_sent})")

        except Exception as e:
            print(f"[Agent] Collection error: {e}")

        inv_counter += 1
        if inv_counter >= inv_interval:
            inv_counter = 0
            try:
                if cfg["simulate"]:
                    inv = generate_simulated_inventory(simulate_os or "windows", hostname)
                else:
                    inv = collect_real_inventory()
                client.send_inventory(inv)
            except Exception:
                pass

        if cfg["vuln_scan_enabled"]:
            vuln_counter += 1
            if vuln_counter >= vuln_interval:
                vuln_counter = 0
                threading.Thread(target=run_vuln_scan, args=(inv,), daemon=True).start()

        for _ in range(cfg["collection_interval"]):
            if not running:
                break
            time.sleep(1)

    save_state(state_path, state)
    print(f"[Agent] Stopped. Total events sent: {total_sent}")


if __name__ == "__main__":
    main()
