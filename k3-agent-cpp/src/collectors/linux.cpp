// Linux collector: journald via libsystemd's sd_journal API when available (persisted cursor,
// so restarts resume rather than resend), falling back to tailing /var/log/auth.log and
// /var/log/syslog by byte offset (same technique as agent.py's read_new_lines) on systems
// without libsystemd-dev at build time. Installed packages via dpkg/rpm, missing patches via
// `apt list --upgradable` / `dnf check-update`, matching what agent.py already does — just
// re-implemented natively instead of via psutil/subprocess-from-Python.
#include "../collector.h"
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <cstring>
#include <array>
#include <memory>
#include <ctime>
#include <algorithm>
#include <cmath>
#include <cstdlib>

#ifdef K3_HAVE_LIBSYSTEMD
  #include <systemd/sd-journal.h>
#endif

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

bool exists(const std::string& path) { return access(path.c_str(), F_OK) == 0; }

std::string nowIso() {
  time_t t = time(nullptr);
  tm utc{};
  gmtime_r(&t, &utc);
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
  return buf;
}

std::string isoFromUsec(uint64_t usec) {
  time_t t = (time_t)(usec / 1000000ULL);
  tm utc{};
  gmtime_r(&t, &utc);
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
  return buf;
}

bool isAuthIdentifier(const std::string& id) {
  static const std::vector<std::string> authTools = {"sshd", "sudo", "su", "login", "polkit", "systemd-logind", "useradd", "passwd"};
  for (const auto& t : authTools) if (id.find(t) != std::string::npos) return true;
  return false;
}

// Small persisted-state helper: journal cursor + per-file byte offsets, so the fallback
// file-tail path and the journald path each resume where they left off after a restart.
class State {
public:
  State() : path_("k3-agent-cpp-state.json") { load(); }
  std::string journalCursor() { return state_.value("journal_cursor", ""); }
  void setJournalCursor(const std::string& c) { state_["journal_cursor"] = c; save(); }
  long fileOffset(const std::string& path) { return state_.value("offsets", json::object()).value(path, 0L); }
  void setFileOffset(const std::string& path, long offset) { state_["offsets"][path] = offset; save(); }

private:
  std::string path_;
  json state_ = json::object();
  void load() { std::ifstream f(path_); if (f) { try { f >> state_; } catch (...) { state_ = json::object(); } } }
  void save() { std::ofstream f(path_); if (f) f << state_.dump(); }
};

} // namespace

class LinuxCollector : public Collector {
public:
  std::string osName() const override { return "linux"; }

  std::vector<json> collectEvents(const std::vector<std::string>& sources, int maxPerSource) override {
    std::vector<json> out;
    bool wantSyslog = sources.empty(), wantAuth = sources.empty();
    for (const auto& s : sources) { if (s == "linux_syslog") wantSyslog = true; if (s == "linux_auth") wantAuth = true; }

#ifdef K3_HAVE_LIBSYSTEMD
    collectFromJournal(wantSyslog, wantAuth, maxPerSource, out);
#else
    if (wantAuth) collectFromFile("/var/log/auth.log", "Linux Auth", "linux_auth", maxPerSource, out);
    if (exists("/var/log/secure")) collectFromFile("/var/log/secure", "Linux Auth", "linux_auth", maxPerSource, out);
    if (wantSyslog) {
      if (exists("/var/log/syslog")) collectFromFile("/var/log/syslog", "Linux Syslog", "linux_syslog", maxPerSource, out);
      else if (exists("/var/log/messages")) collectFromFile("/var/log/messages", "Linux Syslog", "linux_syslog", maxPerSource, out);
    }
#endif
    return out;
  }

  json collectInventory() override {
    json inv;
    utsname uts{};
    uname(&uts);
    inv["hostname"] = uts.nodename;
    inv["os_name"] = readOsRelease("PRETTY_NAME");
    inv["os_version"] = uts.release;
    inv["os_arch"] = uts.machine;

    inv["cpu_cores"] = (int)sysconf(_SC_NPROCESSORS_ONLN);
    inv["cpu_model"] = readCpuModel();

    struct sysinfo si{};
    if (sysinfo(&si) == 0) {
      inv["ram_total_gb"] = std::round((double)si.totalram * si.mem_unit / (1024.0 * 1024 * 1024) * 10) / 10;
      inv["uptime_hours"] = std::round((double)si.uptime / 3600.0 * 10) / 10;
    }

    struct statvfs vfs{};
    if (statvfs("/", &vfs) == 0) {
      double totalGb = (double)vfs.f_blocks * vfs.f_frsize / (1024.0 * 1024 * 1024);
      double freeGb = (double)vfs.f_bfree * vfs.f_frsize / (1024.0 * 1024 * 1024);
      inv["disk_total_gb"] = std::round(totalGb * 10) / 10;
      inv["disk_used_gb"] = std::round((totalGb - freeGb) * 10) / 10;
    }

    inv["installed_software"] = collectInstalledPackages();
    inv["network_interfaces"] = json::array();
    inv["running_services"] = collectRunningServices();
    inv["open_ports"] = json::array();
    inv["local_users"] = collectLocalUsers();
    inv["antivirus_status"] = "N/A";

    std::string ufw = runCommand("ufw status");
    std::string firewalld = runCommand("firewall-cmd --state");
    inv["firewall_enabled"] = ufw.find("Status: active") != std::string::npos || firewalld.find("running") != std::string::npos;

    inv["last_patch_date"] = nullptr;
    inv["domain"] = "";
    inv["serial_number"] = trim(runCommand("cat /sys/class/dmi/id/product_serial"));

    return inv;
  }

  std::vector<json> collectMissingPatches() override {
    std::vector<json> out;
    if (exists("/usr/bin/apt-get") || exists("/usr/bin/apt")) collectAptUpgradable(out);
    else if (exists("/usr/bin/dnf")) collectDnfUpdates(out);
    else if (exists("/usr/bin/yum")) collectYumUpdates(out);
    return out;
  }

private:
  State state_;

  static std::string readOsRelease(const std::string& key) {
    std::ifstream f("/etc/os-release");
    std::string line;
    while (std::getline(f, line)) {
      if (line.rfind(key + "=", 0) == 0) {
        std::string v = line.substr(key.size() + 1);
        if (!v.empty() && v.front() == '"') v = v.substr(1, v.size() - 2);
        return v;
      }
    }
    return "Linux";
  }

  static std::string readCpuModel() {
    std::ifstream f("/proc/cpuinfo");
    std::string line;
    while (std::getline(f, line)) {
      if (line.rfind("model name", 0) == 0) {
        auto colon = line.find(':');
        if (colon != std::string::npos) return trim(line.substr(colon + 1));
      }
    }
    return "";
  }

  static std::vector<json> collectInstalledPackages() {
    std::vector<json> out;
    if (exists("/usr/bin/dpkg-query")) {
      std::string result = runCommand("dpkg-query -W -f='${Package}\\t${Version}\\n'");
      std::istringstream iss(result);
      std::string line;
      while (std::getline(iss, line)) {
        auto tab = line.find('\t');
        if (tab != std::string::npos) out.push_back({{"name", line.substr(0, tab)}, {"version", trim(line.substr(tab + 1))}});
      }
    } else if (exists("/usr/bin/rpm")) {
      std::string result = runCommand("rpm -qa --queryformat '%{NAME}\\t%{VERSION}\\n'");
      std::istringstream iss(result);
      std::string line;
      while (std::getline(iss, line)) {
        auto tab = line.find('\t');
        if (tab != std::string::npos) out.push_back({{"name", line.substr(0, tab)}, {"version", trim(line.substr(tab + 1))}});
      }
    }
    return out;
  }

  static std::vector<json> collectRunningServices() {
    std::vector<json> out;
    std::string result = runCommand("systemctl list-units --type=service --state=running --no-legend --no-pager");
    std::istringstream iss(result);
    std::string line;
    while (std::getline(iss, line)) {
      std::istringstream ls(line);
      std::string name;
      ls >> name;
      if (!name.empty()) out.push_back({{"name", name}, {"status", "running"}});
    }
    return out;
  }

  static std::vector<json> collectLocalUsers() {
    std::vector<json> out;
    setpwent();
    while (passwd* pw = getpwent()) {
      if (pw->pw_uid >= 1000 || pw->pw_uid == 0) out.push_back({{"name", pw->pw_name}});
    }
    endpwent();
    return out;
  }

  static void collectAptUpgradable(std::vector<json>& out) {
    std::string result = runCommand("apt list --upgradable");
    std::istringstream iss(result);
    std::string line;
    while (std::getline(iss, line)) {
      if (line.rfind("Listing...", 0) == 0) continue;
      auto slash = line.find('/');
      auto space = line.find(' ');
      if (slash == std::string::npos || space == std::string::npos) continue;
      std::string name = line.substr(0, slash);
      auto verStart = line.find(' ', space) == std::string::npos ? space + 1 : space + 1;
      std::istringstream ls(line.substr(space));
      std::string repo, version;
      ls >> repo >> version;
      out.push_back({
        {"cve_id", "APT-" + name}, {"software_name", name}, {"software_version", version},
        {"software_type", "software"}, {"description", "Upgradable package: " + line},
        {"cvss_score", nullptr}, {"severity", "UNKNOWN"}, {"published", nullptr},
        {"last_modified", nullptr}, {"vuln_status", "MissingUpdate"},
      });
    }
  }

  static void collectDnfUpdates(std::vector<json>& out) { collectYumStyle("dnf check-update", out); }
  static void collectYumUpdates(std::vector<json>& out) { collectYumStyle("yum check-update", out); }

  static void collectYumStyle(const std::string& cmd, std::vector<json>& out) {
    std::string result = runCommand(cmd);
    std::istringstream iss(result);
    std::string line;
    while (std::getline(iss, line)) {
      std::istringstream ls(line);
      std::string nameArch, version, repo;
      ls >> nameArch >> version >> repo;
      if (nameArch.empty() || version.empty() || nameArch.find('.') == std::string::npos) continue;
      std::string name = nameArch.substr(0, nameArch.rfind('.'));
      out.push_back({
        {"cve_id", "YUM-" + name}, {"software_name", name}, {"software_version", version},
        {"software_type", "software"}, {"description", "Upgradable package via " + repo},
        {"cvss_score", nullptr}, {"severity", "UNKNOWN"}, {"published", nullptr},
        {"last_modified", nullptr}, {"vuln_status", "MissingUpdate"},
      });
    }
  }

  void collectFromFile(const std::string& path, const std::string& sourceLabel, const std::string& index, int maxLines, std::vector<json>& out) {
    std::ifstream f(path);
    if (!f) return;
    long offset = state_.fileOffset(path);
    f.seekg(0, std::ios::end);
    long size = f.tellg();
    if (offset > size) offset = 0; // log rotated
    f.seekg(offset);

    std::string line;
    int count = 0;
    while (count < maxLines && std::getline(f, line)) {
      if (!line.empty()) {
        out.push_back({
          {"timestamp", nowIso()}, {"source", sourceLabel}, {"event_id", nullptr},
          {"computer", nullptr}, {"username", nullptr}, {"ip_address", nullptr},
          {"action", "Log Entry"}, {"severity", "Info"}, {"raw", line}, {"index", index},
        });
        ++count;
      }
    }
    state_.setFileOffset(path, (long)f.tellg() >= 0 ? (long)f.tellg() : size);
  }

#ifdef K3_HAVE_LIBSYSTEMD
  void collectFromJournal(bool wantSyslog, bool wantAuth, int maxCount, std::vector<json>& out) {
    sd_journal* j = nullptr;
    if (sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY) < 0) return;

    std::string cursor = state_.journalCursor();
    if (!cursor.empty() && sd_journal_seek_cursor(j, cursor.c_str()) >= 0) {
      sd_journal_next(j); // move past the last-read entry
    } else {
      sd_journal_seek_tail(j);
    }

    int count = 0;
    while (count < maxCount && sd_journal_next(j) > 0) {
      const void* data;
      size_t length;
      std::string message, identifier;
      uint64_t usec = 0;

      if (sd_journal_get_data(j, "MESSAGE", &data, &length) >= 0)
        message.assign((const char*)data, length).erase(0, strlen("MESSAGE="));
      if (sd_journal_get_data(j, "SYSLOG_IDENTIFIER", &data, &length) >= 0)
        identifier.assign((const char*)data, length).erase(0, strlen("SYSLOG_IDENTIFIER="));
      sd_journal_get_realtime_usec(j, &usec);

      bool isAuth = isAuthIdentifier(identifier);
      if ((isAuth && !wantAuth) || (!isAuth && !wantSyslog)) continue;

      out.push_back({
        {"timestamp", isoFromUsec(usec)}, {"source", isAuth ? "Linux Auth" : "Linux Journal"},
        {"event_id", nullptr}, {"computer", nullptr}, {"username", nullptr}, {"ip_address", nullptr},
        {"action", identifier.empty() ? "Journal Entry" : identifier}, {"severity", "Info"},
        {"raw", message}, {"index", isAuth ? "linux_auth" : "linux_syslog"},
      });
      ++count;
    }

    char* newCursor = nullptr;
    if (sd_journal_get_cursor(j, &newCursor) >= 0 && newCursor) {
      state_.setJournalCursor(newCursor);
      free(newCursor);
    }
    sd_journal_close(j);
  }
#endif
};

Collector* createPlatformCollector() { return new LinuxCollector(); }
