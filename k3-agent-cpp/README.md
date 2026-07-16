# k3-agent-cpp

Native (C++) K3 SIEM agent. Ships **alongside** the existing Python agent
(`k3-agent/`), not as a replacement — pick whichever fits a given target
machine. Both speak the exact same HTTP protocol against the backend
(`backend/src/routes/agents.js`, `backend/src/routes/events.js`), so either
one can register, heartbeat, and ship events/inventory/vulnerabilities
interchangeably.

## What it collects

- **Events**: native OS log sources — Windows Event Log (Security/System/
  Application/PowerShell-Operational via `EvtQuery`), Linux journald/syslog,
  macOS unified log.
- **Inventory**: installed software, OS/hardware info, firewall/AV status —
  posted to the same `assets` table the Python agent's inventory populates.
- **Missing patches**: Windows via the Windows Update Agent COM API (real
  missing-update detection, not a stub date), Linux via
  `apt list --upgradable` / `dnf check-update`, macOS via `softwareupdate -l`.

## Building

Requires a C++17 compiler, CMake >= 3.16, and libcurl (dev headers). On
Linux, also install `libsystemd-dev` for native journald support (falls back
to tailing `/var/log/auth.log` / `/var/log/syslog` without it).

```sh
cmake -S . -B build
cmake --build build
```

Copy `config.yaml.example` to `config.yaml`, set `siem_url` / `api_key`, then:

```sh
./build/k3-agent config.yaml
```

## Installers

Each platform's installer registers the agent as an auto-starting background
service (Windows Service / systemd unit / launchd daemon) and opens the
outbound access it needs — nothing beyond that (no OS audit-policy changes).
See `installers/<platform>/` for the build scripts; each requires that
platform's own packaging tool (`makensis`, `makeself`, `pkgbuild` +
`productbuild` respectively) and must be built on that OS. The
`.github/workflows/build-agent.yml` CI matrix builds and packages all three
on their native runners.
