// macOS collector: unified log via `log show --style ndjson` (one JSON object per line,
// windowed by a persisted last-seen timestamp), installed applications via
// `system_profiler SPApplicationsDataType -json`, and missing patches via `softwareupdate -l`.
// There is no public native C API for the unified log or Software Update equivalent to the
// Windows Event Log / WUA COM APIs used on Windows, so these go through Apple's own
// command-line tools — the same approach Apple's own documentation recommends for this data.
#include "../collector.h"
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <pwd.h>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <cstring>
#include <array>
#include <memory>
#include <ctime>
#include <cmath>

namespace {

std::string trim(const std::string& s) {
  size_t a = s.find_first_not_of(" \t\r\n");
  if (a == std::string::npos) return "";
  size_t b = s.find_last_not_of(" \t\r\n");
  return s.substr(a, b - a + 1);
}

std::string runCommand(const std::string& cmd) {
  std::string out;
  std::array<char, 4096> buf{};
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen((cmd + " 2>/dev/null").c_str(), "r"), pclose);
  if (!pipe) return out;
  while (fgets(buf.data(), (int)buf.size(), pipe.get())) out += buf.data();
  return out;
}

std::string sysctlString(const char* name) {
  char buf[256] = {0};
  size_t size = sizeof(buf);
  if (sysctlbyname(name, buf, &size, nullptr, 0) == 0) return std::string(buf, size > 0 ? size - 1 : 0);
  return "";
}

std::string nowIsoLocal() {
  // `log show --start` wants "YYYY-MM-DD HH:MM:SS" in local time, not ISO8601/UTC.
  time_t t = time(nullptr);
  tm local{};
  localtime_r(&t, &local);
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &local);
  return buf;
}

std::string nowIso() {
  time_t t = time(nullptr);
  tm utc{};
  gmtime_r(&t, &utc);
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
  return buf;
}

std::string severityFromMessageType(const std::string& type) {
  if (type == "Fault") return "Critical";
  if (type == "Error") return "High";
  if (type == "Default") return "Medium";
  return "Info"; // Debug / Info
}

class State {
public:
  State() : path_("k3-agent-cpp-state.json") { load(); }
  std::string lastLogTime() { return state_.value("last_log_time", ""); }
  void setLastLogTime(const std::string& t) { state_["last_log_time"] = t; save(); }

private:
  std::string path_;
  json state_ = json::object();
  void load() { std::ifstream f(path_); if (f) { try { f >> state_; } catch (...) { state_ = json::object(); } } }
  void save() { std::ofstream f(path_); if (f) f << state_.dump(); }
};

} // namespace

class MacosCollector : public Collector {
public:
  std::string osName() const override { return "macos"; }

  std::vector<json> collectEvents(const std::vector<std::string>& /*sources*/, int maxCount) override {
    std::vector<json> out;
    std::string start = state_.lastLogTime();
    if (start.empty()) start = nowIsoLocal(); // first run: only pick up new events from here on

    std::string cmd = "log show --style ndjson --start \"" + start + "\" --predicate "
                       "'eventType == \"logEvent\" AND (messageType == \"Error\" OR messageType == \"Fault\" OR messageType == \"Default\")'";
    std::string result = runCommand(cmd);

    std::istringstream iss(result);
    std::string line;
    std::string newestTime = start;
    int count = 0;
    while (count < maxCount && std::getline(iss, line)) {
      if (line.empty() || line.front() != '{') continue; // skip the header line log show prints
      try {
        json entry = json::parse(line);
        std::string timestamp = entry.value("timestamp", nowIso());
        std::string messageType = entry.value("messageType", "Info");
        std::string eventMessage = entry.value("eventMessage", "");
        std::string process = entry.value("processImagePath", "");

        out.push_back({
          {"timestamp", timestamp}, {"source", "macOS Unified Log"}, {"event_id", nullptr},
          {"computer", nullptr}, {"username", nullptr}, {"ip_address", nullptr},
          {"action", process.empty() ? "Log Entry" : process}, {"severity", severityFromMessageType(messageType)},
          {"raw", eventMessage}, {"index", "macos_unified_log"},
        });
        if (timestamp > newestTime) newestTime = timestamp;
        ++count;
      } catch (...) { /* non-JSON line (progress/header output) — skip */ }
    }
    if (newestTime > start) state_.setLastLogTime(newestTime);
    return out;
  }

  json collectInventory() override {
    json inv;
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    inv["hostname"] = hostname;
    inv["os_name"] = "macOS";
    inv["os_version"] = trim(runCommand("sw_vers -productVersion"));
    inv["os_arch"] = trim(runCommand("uname -m"));

    int cores = 0;
    size_t coresSize = sizeof(cores);
    sysctlbyname("hw.ncpu", &cores, &coresSize, nullptr, 0);
    inv["cpu_cores"] = cores;
    inv["cpu_model"] = sysctlString("machdep.cpu.brand_string");

    uint64_t memBytes = 0;
    size_t memSize = sizeof(memBytes);
    sysctlbyname("hw.memsize", &memBytes, &memSize, nullptr, 0);
    inv["ram_total_gb"] = std::round((double)memBytes / (1024.0 * 1024 * 1024) * 10) / 10;

    struct statvfs vfs{};
    if (statvfs("/", &vfs) == 0) {
      double totalGb = (double)vfs.f_blocks * vfs.f_frsize / (1024.0 * 1024 * 1024);
      double freeGb = (double)vfs.f_bfree * vfs.f_frsize / (1024.0 * 1024 * 1024);
      inv["disk_total_gb"] = std::round(totalGb * 10) / 10;
      inv["disk_used_gb"] = std::round((totalGb - freeGb) * 10) / 10;
    }

    inv["installed_software"] = collectInstalledApps();
    inv["network_interfaces"] = json::array();
    inv["running_services"] = json::array();
    inv["open_ports"] = json::array();
    inv["local_users"] = collectLocalUsers();
    inv["antivirus_status"] = "XProtect (built-in)";

    std::string fwState = trim(runCommand("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"));
    inv["firewall_enabled"] = fwState.find("enabled") != std::string::npos;

    inv["last_patch_date"] = nullptr;
    inv["uptime_hours"] = readUptimeHours();
    inv["domain"] = "";
    inv["serial_number"] = trim(runCommand("ioreg -l | awk -F'\"' '/IOPlatformSerialNumber/{print $4}'"));

    return inv;
  }

  std::vector<json> collectMissingPatches() override {
    std::vector<json> out;
    std::string result = runCommand("softwareupdate -l");
    std::istringstream iss(result);
    std::string line;
    std::string currentLabel;
    while (std::getline(iss, line)) {
      auto pos = line.find("* Label: ");
      if (pos != std::string::npos) {
        currentLabel = trim(line.substr(pos + strlen("* Label: ")));
        out.push_back({
          {"cve_id", "SU-" + currentLabel}, {"software_name", currentLabel}, {"software_version", nullptr},
          {"software_type", "os"}, {"description", "Available macOS software update: " + currentLabel},
          {"cvss_score", nullptr}, {"severity", "UNKNOWN"}, {"published", nullptr},
          {"last_modified", nullptr}, {"vuln_status", "MissingUpdate"},
        });
      }
    }
    return out;
  }

private:
  State state_;

  static std::vector<json> collectInstalledApps() {
    std::vector<json> out;
    std::string result = runCommand("system_profiler SPApplicationsDataType -json");
    try {
      json parsed = json::parse(result);
      for (const auto& app : parsed.value("SPApplicationsDataType", json::array())) {
        out.push_back({
          {"name", app.value("_name", "")},
          {"version", app.value("version", "")},
        });
      }
    } catch (...) { /* system_profiler produced unparseable output — leave list empty */ }
    return out;
  }

  static std::vector<json> collectLocalUsers() {
    std::vector<json> out;
    setpwent();
    while (passwd* pw = getpwent()) {
      if (pw->pw_uid >= 500) out.push_back({{"name", pw->pw_name}});
    }
    endpwent();
    return out;
  }

  static double readUptimeHours() {
    struct timeval boottime{};
    size_t size = sizeof(boottime);
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    if (sysctl(mib, 2, &boottime, &size, nullptr, 0) == 0) {
      double seconds = difftime(time(nullptr), boottime.tv_sec);
      return std::round(seconds / 3600.0 * 10) / 10;
    }
    return 0;
  }
};

Collector* createPlatformCollector() { return new MacosCollector(); }
