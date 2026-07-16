// k3-agent-cpp — native agent, ships alongside the Python agent (k3-agent/agent.py) rather
// than replacing it. Mirrors agent.py's control flow (register -> heartbeat thread ->
// inventory -> event loop) and speaks the identical HTTP protocol, so it's interchangeable
// with the Python agent from the backend's point of view.
//
// On Windows this doubles as a Windows Service: the installer registers it via `sc.exe create
// ... binPath= "k3-agent.exe --service"`. A service process MUST call
// StartServiceCtrlDispatcher within a few seconds of starting or the SCM kills it as
// unresponsive, so `--service` routes into ServiceMain instead of running the loop directly
// on the main thread. Linux/macOS installers run the binary directly under systemd/launchd,
// which don't need this dispatcher dance — the plain `runAgent()` loop is already exactly what
// a long-running foreground service process should do.
#include "config.h"
#include "siem_client.h"
#include "collector.h"
#include <curl/curl.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <csignal>
#include <vector>
#include <string>
#include <memory>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
#else
  #include <unistd.h>
  #include <netdb.h>
  #include <arpa/inet.h>
#endif

namespace {

std::atomic<bool> g_running{true};

void onSignal(int) { g_running = false; }

std::string getLocalHostname() {
  char buf[256] = {0};
#ifdef _WIN32
  DWORD size = sizeof(buf);
  GetComputerNameA(buf, &size);
#else
  gethostname(buf, sizeof(buf));
#endif
  return std::string(buf);
}

// Best-effort primary outbound-interface IP; falls back to empty string (server treats a
// missing IP as informational-only, same as the Python agent when psutil can't resolve one).
std::string getLocalIp() {
  std::string ip;
  char hostname[256] = {0};
#ifdef _WIN32
  DWORD size = sizeof(hostname);
  GetComputerNameA(hostname, &size);
#else
  gethostname(hostname, sizeof(hostname));
#endif
  addrinfo hints{}, *res = nullptr;
  hints.ai_family = AF_INET;
  if (getaddrinfo(hostname, nullptr, &hints, &res) == 0) {
    for (auto* p = res; p; p = p->ai_next) {
      char addrStr[INET6_ADDRSTRLEN] = {0};
      auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
      inet_ntop(AF_INET, &sa->sin_addr, addrStr, sizeof(addrStr));
      ip = addrStr;
      break;
    }
    freeaddrinfo(res);
  }
  return ip;
}

std::vector<std::string> defaultSources(const std::string& osName) {
  if (osName == "windows")
    return {"windows_security", "windows_system", "windows_application", "windows_powershell"};
  if (osName == "macos")
    return {"macos_unified_log"};
  return {"linux_syslog", "linux_auth"};
}

// The actual agent: register once, then heartbeat/collect/send on a loop until `running`
// flips false. Shared by interactive mode and the Windows service worker thread.
int runAgent(const std::string& configPath, std::atomic<bool>& running) {
  Config cfg = Config::load(configPath);
  if (cfg.api_key.empty()) {
    std::cerr << "[k3-agent] api_key is not set (config.yaml or K3_API_KEY) — refusing to start." << std::endl;
    return 1;
  }

  std::unique_ptr<Collector> collector(createPlatformCollector());
  const std::string hostname = cfg.hostname_override.empty() ? getLocalHostname() : cfg.hostname_override;
  const std::string ip = getLocalIp();
  const std::vector<std::string> sources = cfg.sources.empty() ? defaultSources(collector->osName()) : cfg.sources;

  SiemClient client(cfg.siem_url, cfg.api_key);

  std::cout << "[k3-agent] Registering " << hostname << " (" << collector->osName() << ") with " << cfg.siem_url << std::endl;
  int attempts = 0;
  while (running && !client.registerAgent(hostname, collector->osName(), ip, cfg.agent_version, sources)) {
    if (++attempts >= 10) {
      std::cerr << "[k3-agent] Failed to register after 10 attempts, giving up." << std::endl;
      return 1;
    }
    std::this_thread::sleep_for(std::chrono::seconds(std::min(1 << attempts, 60)));
  }
  if (!running) return 0;
  std::cout << "[k3-agent] Registered as agent_id=" << client.agentId() << std::endl;

  std::thread heartbeatThread([&]() {
    while (running) {
      client.sendHeartbeat();
      for (int i = 0; i < cfg.heartbeat_interval && running; ++i)
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  });

  auto sendInventoryAndPatches = [&]() {
    client.sendInventory(collector->collectInventory());
    if (cfg.vuln_scan_enabled) {
      auto patches = collector->collectMissingPatches();
      if (!patches.empty()) client.sendVulnerabilities(patches);
    }
  };
  sendInventoryAndPatches();

  int loopCount = 0;
  while (running) {
    auto events = collector->collectEvents(sources, cfg.batch_size);
    if (!events.empty()) client.sendEvents(events);

    if (++loopCount % 30 == 0) sendInventoryAndPatches(); // refresh inventory periodically, same cadence as agent.py

    for (int i = 0; i < cfg.collection_interval && running; ++i)
      std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  std::cout << "[k3-agent] Shutting down..." << std::endl;
  heartbeatThread.join();
  return 0;
}

#ifdef _WIN32
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_serviceStatus = {};
std::string g_configPath = "config.yaml";

void setServiceStatus(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHint = 0) {
  if (!g_statusHandle) return;
  g_serviceStatus.dwCurrentState = state;
  g_serviceStatus.dwWin32ExitCode = exitCode;
  g_serviceStatus.dwWaitHint = waitHint;
  g_serviceStatus.dwControlsAccepted = (state == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  SetServiceStatus(g_statusHandle, &g_serviceStatus);
}

void WINAPI serviceCtrlHandler(DWORD ctrl) {
  if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
    setServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    g_running = false;
  }
}

void WINAPI serviceMain(DWORD, LPTSTR*) {
  g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_serviceStatus.dwServiceSpecificExitCode = 0;

  g_statusHandle = RegisterServiceCtrlHandlerA("K3Agent", serviceCtrlHandler);
  if (!g_statusHandle) return;

  setServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
  setServiceStatus(SERVICE_RUNNING);

  runAgent(g_configPath, g_running);

  setServiceStatus(SERVICE_STOPPED);
}
#endif

} // namespace

int main(int argc, char** argv) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
  std::signal(SIGINT, onSignal);
  std::signal(SIGTERM, onSignal);

#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);

  bool asService = false;
  std::string configPath = "config.yaml";
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--service") asService = true;
    else configPath = arg;
  }

  if (asService) {
    g_configPath = configPath;
    SERVICE_TABLE_ENTRYA table[] = {
      {const_cast<LPSTR>("K3Agent"), (LPSERVICE_MAIN_FUNCTIONA)serviceMain},
      {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherA(table)) {
      std::cerr << "[k3-agent] StartServiceCtrlDispatcher failed (run without --service for interactive mode)." << std::endl;
      return 1;
    }
    curl_global_cleanup();
    return 0;
  }

  int rc = runAgent(configPath, g_running);
  curl_global_cleanup();
  return rc;
#else
  std::string configPath = argc > 1 ? argv[1] : "config.yaml";
  int rc = runAgent(configPath, g_running);
  curl_global_cleanup();
  return rc;
#endif
}
