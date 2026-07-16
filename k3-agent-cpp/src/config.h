#pragma once
#include <string>
#include <vector>
#include <map>

// config.yaml is flat key:value plus one block-list key ("sources") — no nested maps, no
// multi-line scalars — so a minimal line parser is enough and avoids pulling in a full YAML
// library for a config format this simple. K3_* env vars override any file value, matching
// the existing Python agent's config precedence (k3-agent/agent.py load_config()).
struct Config {
  std::string siem_url = "http://localhost:3001";
  std::string api_key;
  std::string agent_version = "1.0.0-cpp";
  int collection_interval = 10;
  int heartbeat_interval = 30;
  int batch_size = 50;
  std::vector<std::string> sources;
  bool simulate = false;
  bool vuln_scan_enabled = false;
  std::string nvd_api_key;
  std::string state_path = "agent_state.json";
  std::string hostname_override;

  static Config load(const std::string& path);
};
