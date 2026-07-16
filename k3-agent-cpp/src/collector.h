#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

using json = nlohmann::json;

// Platform-agnostic collection surface. Each OS collector (collectors/windows.cpp,
// collectors/linux.cpp, collectors/macos.cpp) implements this against native APIs and produces
// JSON shaped to match the server's expected wire format exactly (see siem_client.h) — the rest
// of the agent (main.cpp, siem_client.cpp) never branches on platform.
struct Collector {
  virtual ~Collector() = default;

  // Each element uses the client-side event field names the server expects on
  // POST /api/events/ingest: timestamp, source, event_id, computer, username, ip_address,
  // action, severity, raw, index.
  virtual std::vector<json> collectEvents(const std::vector<std::string>& sources, int maxPerSource) = 0;

  // Single object with the 20 fields the server maps onto the `assets` table via
  // POST /api/agents/:id/inventory (see backend/src/routes/agents.js).
  virtual json collectInventory() = 0;

  // Missing OS/software patches, already shaped as vulnerability entries for
  // POST /api/agents/:id/vulnerabilities: cve_id, software_name, software_version,
  // software_type, description, cvss_score, severity, published, last_modified, vuln_status.
  virtual std::vector<json> collectMissingPatches() = 0;

  virtual std::string osName() const = 0;
};

Collector* createPlatformCollector();
