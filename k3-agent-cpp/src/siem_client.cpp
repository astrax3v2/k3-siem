#include "siem_client.h"
#include <curl/curl.h>
#include <iostream>
#include <thread>
#include <chrono>

namespace {
size_t writeCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
  auto* out = static_cast<std::string*>(userdata);
  out->append(ptr, size * nmemb);
  return size * nmemb;
}
} // namespace

SiemClient::SiemClient(std::string siemUrl, std::string apiKey)
    : siemUrl_(std::move(siemUrl)), apiKey_(std::move(apiKey)) {}

bool SiemClient::postJson(const std::string& path, const json& body, json& outBody, int maxRetries, int timeoutSeconds) {
  const std::string url = siemUrl_ + path;
  const std::string payload = body.dump();

  for (int attempt = 0; attempt < maxRetries; ++attempt) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::string response;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, ("X-Api-Key: " + apiKey_).c_str());
    if (!agentId_.empty()) headers = curl_slist_append(headers, ("X-Agent-Id: " + agentId_).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(payload.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(timeoutSeconds));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res == CURLE_OK && httpCode >= 200 && httpCode < 300) {
      try { outBody = response.empty() ? json::object() : json::parse(response); }
      catch (...) { outBody = json::object(); }
      return true;
    }

    std::cerr << "[SiemClient] " << path << " failed (attempt " << (attempt + 1) << "/" << maxRetries
               << "): curl=" << curl_easy_strerror(res) << " http=" << httpCode << std::endl;
    if (attempt + 1 < maxRetries) {
      std::this_thread::sleep_for(std::chrono::seconds(std::min(1 << attempt, 60)));
    }
  }
  return false;
}

bool SiemClient::registerAgent(const std::string& hostname, const std::string& os,
                                const std::string& ip, const std::string& agentVersion,
                                const std::vector<std::string>& collectedSources) {
  json body = {
    {"hostname", hostname}, {"os", os}, {"ip", ip},
    {"agent_version", agentVersion}, {"collected_sources", collectedSources},
  };
  json resp;
  if (!postJson("/api/agents/register", body, resp, 10, 15)) return false;
  if (!resp.contains("agent_id")) return false;
  agentId_ = resp["agent_id"].get<std::string>();
  return true;
}

bool SiemClient::sendHeartbeat() {
  if (!isRegistered()) return false;
  json resp;
  return postJson("/api/agents/" + agentId_ + "/heartbeat", json{{"metrics", json::object()}}, resp, 1, 10);
}

bool SiemClient::sendEvents(std::vector<json> events) {
  if (events.empty()) return true;
  for (auto& e : events) e["agent_id"] = agentId_;
  json resp;
  return postJson("/api/events/ingest", json(events), resp, 3, 30);
}

bool SiemClient::sendInventory(json inventory) {
  if (!isRegistered()) return false;
  json resp;
  return postJson("/api/agents/" + agentId_ + "/inventory", inventory, resp, 3, 30);
}

bool SiemClient::sendVulnerabilities(std::vector<json> vulnerabilities) {
  if (!isRegistered()) return false;
  json resp;
  return postJson("/api/agents/" + agentId_ + "/vulnerabilities", json{{"vulnerabilities", vulnerabilities}}, resp, 3, 60);
}
