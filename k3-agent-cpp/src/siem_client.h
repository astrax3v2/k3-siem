#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

using json = nlohmann::json;

// Speaks the exact HTTP protocol the existing Python agent (k3-agent/agent.py) already uses,
// so this agent is a drop-in alternative against the same backend without any server-side
// changes. Every call degrades to a logged failure rather than throwing — a transient network
// blip must not crash the agent's collection loop.
class SiemClient {
public:
  SiemClient(std::string siemUrl, std::string apiKey);

  // POST /api/agents/register — captures agent_id from the response on success.
  bool registerAgent(const std::string& hostname, const std::string& os,
                      const std::string& ip, const std::string& agentVersion,
                      const std::vector<std::string>& collectedSources);

  // POST /api/agents/{id}/heartbeat
  bool sendHeartbeat();

  // POST /api/events/ingest — body is a raw JSON array; each event gets agent_id stamped in.
  bool sendEvents(std::vector<json> events);

  // POST /api/agents/{id}/inventory — body is the raw inventory object.
  bool sendInventory(json inventory);

  // POST /api/agents/{id}/vulnerabilities — body is {"vulnerabilities": [...]}.
  bool sendVulnerabilities(std::vector<json> vulnerabilities);

  bool isRegistered() const { return !agentId_.empty(); }
  const std::string& agentId() const { return agentId_; }

private:
  std::string siemUrl_;
  std::string apiKey_;
  std::string agentId_;

  // Returns true + fills `outBody` on 2xx, logs and returns false otherwise. Retries with
  // exponential backoff, mirroring agent.py's SIEMClient retry behavior.
  bool postJson(const std::string& path, const json& body, json& outBody, int maxRetries, int timeoutSeconds);
};
