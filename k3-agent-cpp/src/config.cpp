#include "config.h"
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <algorithm>

namespace {

std::string trim(const std::string& s) {
  size_t a = s.find_first_not_of(" \t\r\n");
  if (a == std::string::npos) return "";
  size_t b = s.find_last_not_of(" \t\r\n");
  return s.substr(a, b - a + 1);
}

std::string stripQuotes(std::string s) {
  s = trim(s);
  if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\'')))
    return s.substr(1, s.size() - 2);
  return s;
}

bool toBool(const std::string& s, bool def) {
  std::string v = s;
  std::transform(v.begin(), v.end(), v.begin(), ::tolower);
  if (v == "true" || v == "yes" || v == "1") return true;
  if (v == "false" || v == "no" || v == "0") return false;
  return def;
}

const char* envOr(const char* name, const char* def) {
  const char* v = std::getenv(name);
  return (v && *v) ? v : def;
}

} // namespace

Config Config::load(const std::string& path) {
  Config cfg;
  std::ifstream f(path);
  std::string line;
  bool inSourcesList = false;

  while (std::getline(f, line)) {
    // Strip trailing comment (a bare '#' — config.yaml never quotes a literal '#').
    auto hash = line.find('#');
    if (hash != std::string::npos) line = line.substr(0, hash);
    if (trim(line).empty()) continue;

    // Block-list continuation: "  - item"
    if (inSourcesList) {
      size_t dash = line.find('-');
      // A non-indented or non-dash line ends the list.
      if (line.front() == ' ' && dash != std::string::npos && trim(line.substr(0, dash)).empty()) {
        cfg.sources.push_back(stripQuotes(trim(line.substr(dash + 1))));
        continue;
      }
      inSourcesList = false;
    }

    size_t colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string key = trim(line.substr(0, colon));
    std::string value = trim(line.substr(colon + 1));

    if (key == "sources" && value.empty()) { inSourcesList = true; continue; }
    if (value.empty()) continue;
    value = stripQuotes(value);

    if (key == "siem_url") cfg.siem_url = value;
    else if (key == "api_key") cfg.api_key = value;
    else if (key == "agent_version") cfg.agent_version = value;
    else if (key == "collection_interval") cfg.collection_interval = std::stoi(value);
    else if (key == "heartbeat_interval") cfg.heartbeat_interval = std::stoi(value);
    else if (key == "batch_size") cfg.batch_size = std::stoi(value);
    else if (key == "simulate") cfg.simulate = toBool(value, cfg.simulate);
    else if (key == "vuln_scan_enabled") cfg.vuln_scan_enabled = toBool(value, cfg.vuln_scan_enabled);
    else if (key == "nvd_api_key") cfg.nvd_api_key = value;
  }

  // Env var overrides — same K3_* names the Python agent recognizes, so either agent can be
  // driven by the same deployment tooling/environment.
  cfg.siem_url = envOr("K3_SIEM_URL", cfg.siem_url.c_str());
  cfg.api_key = envOr("K3_API_KEY", cfg.api_key.c_str());
  cfg.simulate = toBool(envOr("K3_SIMULATE", cfg.simulate ? "true" : "false"), cfg.simulate);
  cfg.collection_interval = std::stoi(envOr("K3_COLLECTION_INTERVAL", std::to_string(cfg.collection_interval).c_str()));
  cfg.heartbeat_interval = std::stoi(envOr("K3_HEARTBEAT_INTERVAL", std::to_string(cfg.heartbeat_interval).c_str()));
  cfg.vuln_scan_enabled = toBool(envOr("K3_VULN_SCAN", cfg.vuln_scan_enabled ? "true" : "false"), cfg.vuln_scan_enabled);
  cfg.nvd_api_key = envOr("K3_NVD_API_KEY", cfg.nvd_api_key.c_str());
  cfg.state_path = envOr("K3_STATE_PATH", cfg.state_path.c_str());
  cfg.hostname_override = envOr("K3_HOSTNAME", "");

  return cfg;
}
