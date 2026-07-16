// Windows collector: Event Log via the native EvtQuery/EvtNext API (Security/System/
// Application/PowerShell-Operational channels), installed software via registry Uninstall key
// enumeration, and missing patches via the Windows Update Agent COM API. A few fields
// (antivirus status, firewall state, BIOS serial number) are read by shelling out to the same
// built-in Windows tools agent.py already relies on for those — matching its hybrid
// native-API-plus-tool-output approach rather than reimplementing WMI/SecurityCenter2 COM
// plumbing for fields that change rarely and aren't security-critical to get from a native API.
#include "../collector.h"
#include <windows.h>
#include <winevt.h>
#include <comdef.h>
#include <string>
#include <vector>
#include <map>
#include <array>
#include <memory>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cmath>
#include <ctime>

#pragma comment(lib, "wevtapi.lib")

#import <wuapi.dll> rename_namespace("WUApiLib") named_guids
using namespace WUApiLib;

namespace {

std::string wideToUtf8(const std::wstring& w) {
  if (w.empty()) return "";
  int size = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
  std::string out(size, 0);
  WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), out.data(), size, nullptr, nullptr);
  return out;
}

std::wstring utf8ToWide(const std::string& s) {
  if (s.empty()) return L"";
  int size = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
  std::wstring out(size, 0);
  MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), size);
  return out;
}

std::string extractTag(const std::string& xml, const std::string& tag) {
  std::string open = "<" + tag + ">", close = "</" + tag + ">";
  auto a = xml.find(open);
  if (a == std::string::npos) return "";
  a += open.size();
  auto b = xml.find(close, a);
  if (b == std::string::npos) return "";
  return xml.substr(a, b - a);
}

std::string extractAttr(const std::string& xml, const std::string& tag, const std::string& attr) {
  auto tagPos = xml.find("<" + tag + " ");
  if (tagPos == std::string::npos) return "";
  auto attrPos = xml.find(attr + "='", tagPos);
  if (attrPos == std::string::npos) attrPos = xml.find(attr + "=\"", tagPos);
  if (attrPos == std::string::npos) return "";
  auto valStart = xml.find_first_of("'\"", attrPos) + 1;
  auto valEnd = xml.find_first_of("'\"", valStart);
  if (valEnd == std::string::npos) return "";
  return xml.substr(valStart, valEnd - valStart);
}

std::string mapSeverity(int level) {
  // Windows Event Log Level values: 1=Critical, 2=Error, 3=Warning, 4=Info, 0/5=Verbose/LogAlways.
  switch (level) {
    case 1: return "Critical";
    case 2: return "High";
    case 3: return "Medium";
    default: return "Info";
  }
}

std::string runCommand(const std::string& cmd) {
  std::string out;
  std::array<char, 4096> buf{};
  std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen((cmd + " 2>NUL").c_str(), "r"), _pclose);
  if (!pipe) return out;
  while (fgets(buf.data(), (int)buf.size(), pipe.get())) out += buf.data();
  return out;
}

// Minimal persisted "last collected" timestamp per channel so a restart doesn't resend the
// entire log — same purpose as agent.py's agent_state.json, kept self-contained here rather
// than threaded through the Collector interface.
class ChannelState {
public:
  ChannelState() : path_("k3-agent-cpp-state.json") { load(); }

  std::string lastTime(const std::string& channel) {
    if (state_.contains(channel)) return state_[channel].get<std::string>();
    // First run: only pick up the last collection_interval's worth of history.
    return isoNowMinusSeconds(60);
  }

  void setLastTime(const std::string& channel, const std::string& iso) {
    state_[channel] = iso;
    save();
  }

private:
  std::string path_;
  json state_ = json::object();

  static std::string isoNowMinusSeconds(int seconds) {
    time_t t = time(nullptr) - seconds;
    tm utc{};
    gmtime_s(&utc, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return buf;
  }

  void load() {
    std::ifstream f(path_);
    if (f) { try { f >> state_; } catch (...) { state_ = json::object(); } }
  }

  void save() {
    std::ofstream f(path_);
    if (f) f << state_.dump();
  }
};

std::string nowIso() {
  time_t t = time(nullptr);
  tm utc{};
  gmtime_s(&utc, &t);
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
  return buf;
}

struct ChannelSpec { std::string name; std::string channel; std::string sourceLabel; };
const std::vector<ChannelSpec> kChannels = {
  {"windows_security", "Security", "Windows Security"},
  {"windows_system", "System", "Windows System"},
  {"windows_application", "Application", "Windows Application"},
  {"windows_powershell", "Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"},
};

class WindowsCollector : public Collector {
public:
  std::string osName() const override { return "windows"; }

  std::vector<json> collectEvents(const std::vector<std::string>& sources, int maxPerSource) override {
    std::vector<json> out;
    for (const auto& spec : kChannels) {
      bool wanted = sources.empty();
      for (const auto& s : sources) if (s == spec.name) wanted = true;
      if (!wanted) continue;
      collectChannel(spec, maxPerSource, out);
    }
    return out;
  }

  json collectInventory() override {
    json inv;
    char hostname[256] = {0};
    DWORD hlen = sizeof(hostname);
    GetComputerNameA(hostname, &hlen);
    inv["hostname"] = hostname;

    inv["os_name"] = readRegString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName");
    std::string build = readRegString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuildNumber");
    std::string displayVer = readRegString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "DisplayVersion");
    inv["os_version"] = displayVer.empty() ? build : (displayVer + " (Build " + build + ")");

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    inv["os_arch"] = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86";
    inv["cpu_cores"] = (int)si.dwNumberOfProcessors;
    inv["cpu_model"] = readRegString(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString");

    MEMORYSTATUSEX mem{};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    inv["ram_total_gb"] = std::round((double)mem.ullTotalPhys / (1024.0 * 1024 * 1024) * 10) / 10;

    ULARGE_INTEGER freeBytes{}, totalBytes{};
    if (GetDiskFreeSpaceExA("C:\\", nullptr, &totalBytes, &freeBytes)) {
      double totalGb = (double)totalBytes.QuadPart / (1024.0 * 1024 * 1024);
      double freeGb = (double)freeBytes.QuadPart / (1024.0 * 1024 * 1024);
      inv["disk_total_gb"] = std::round(totalGb * 10) / 10;
      inv["disk_used_gb"] = std::round((totalGb - freeGb) * 10) / 10;
    }

    inv["installed_software"] = collectInstalledSoftware();
    inv["network_interfaces"] = json::array();
    inv["running_services"] = json::array();
    inv["open_ports"] = json::array();
    inv["local_users"] = json::array();

    std::string av = runCommand("wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName /format:list");
    inv["antivirus_status"] = av.find("displayName=") != std::string::npos ? "Active" : "Unknown";

    std::string fw = runCommand("netsh advfirewall show allprofiles state");
    inv["firewall_enabled"] = fw.find("State                                 ON") != std::string::npos || fw.find("ON") != std::string::npos;

    inv["last_patch_date"] = nullptr; // superseded by the real missing-patch list from collectMissingPatches()
    inv["uptime_hours"] = std::round((double)GetTickCount64() / 1000.0 / 3600.0 * 10) / 10;

    char domain[256] = {0};
    DWORD dlen = sizeof(domain);
    GetComputerNameExA(ComputerNameDnsDomain, domain, &dlen);
    inv["domain"] = domain;

    std::string serial = runCommand("wmic bios get serialnumber");
    auto pos = serial.find('\n');
    inv["serial_number"] = pos != std::string::npos ? trimStr(serial.substr(pos)) : trimStr(serial);

    return inv;
  }

  std::vector<json> collectMissingPatches() override {
    std::vector<json> out;
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool needUninit = SUCCEEDED(hr);
    try {
      IUpdateSessionPtr session;
      HRESULT chr = session.CreateInstance(__uuidof(UpdateSession));
      if (FAILED(chr)) { if (needUninit) CoUninitialize(); return out; }
      IUpdateSearcherPtr searcher = session->CreateUpdateSearcher();
      ISearchResultPtr result = searcher->Search(_bstr_t(L"IsInstalled=0 and Type='Software'"));
      IUpdateCollectionPtr updates = result->Updates;
      long count = updates->Count;
      for (long i = 0; i < count && i < 50; ++i) {
        IUpdatePtr update = updates->Item[i];
        std::string title = update->Title ? wideToUtf8(update->Title) : "";
        std::string description = update->Description ? wideToUtf8(update->Description) : "";
        std::string msrcSeverity = update->MsrcSeverity ? wideToUtf8(update->MsrcSeverity) : "";

        // WUA doesn't expose CVE IDs directly on IUpdate — the KB article ID is the reliable
        // identifier it does expose, so that's used as the vulnerability identifier here
        // instead of fabricating a CVE that isn't actually available from this API.
        std::string kb = "unknown";
        IStringCollectionPtr kbs = update->KBArticleIDs;
        if (kbs && kbs->Count > 0) kb = "KB" + wideToUtf8((_bstr_t)kbs->Item[0]);

        std::string severity = msrcSeverity == "Critical" ? "CRITICAL"
                              : msrcSeverity == "Important" ? "HIGH"
                              : msrcSeverity == "Moderate" ? "MEDIUM"
                              : msrcSeverity == "Low" ? "LOW" : "UNKNOWN";

        out.push_back({
          {"cve_id", kb},
          {"software_name", title},
          {"software_version", nullptr},
          {"software_type", "os"},
          {"description", description.substr(0, 500)},
          {"cvss_score", nullptr},
          {"severity", severity},
          {"published", nullptr},
          {"last_modified", nullptr},
          {"vuln_status", "MissingUpdate"},
        });
      }
    } catch (const _com_error& e) {
      std::cerr << "[windows] WUA patch scan failed: " << wideToUtf8(e.ErrorMessage()) << std::endl;
    }
    if (needUninit) CoUninitialize();
    return out;
  }

private:
  ChannelState state_;

  static std::string trimStr(std::string s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
  }

  static std::string readRegString(HKEY root, const std::string& subkey, const std::string& value) {
    HKEY hKey;
    if (RegOpenKeyExA(root, subkey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return "";
    char buf[512] = {0};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    std::string result;
    if (RegQueryValueExA(hKey, value.c_str(), nullptr, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS && type == REG_SZ)
      result = buf;
    RegCloseKey(hKey);
    return result;
  }

  static void collectSoftwareFromKey(HKEY root, const std::string& subkey, std::vector<json>& out) {
    HKEY hKey;
    if (RegOpenKeyExA(root, subkey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
    char nameBuf[256];
    for (DWORD i = 0; ; ++i) {
      DWORD nameLen = sizeof(nameBuf);
      if (RegEnumKeyExA(hKey, i, nameBuf, &nameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
      HKEY subKey;
      if (RegOpenKeyExA(hKey, nameBuf, 0, KEY_READ, &subKey) == ERROR_SUCCESS) {
        char displayName[512] = {0}, displayVersion[128] = {0};
        DWORD nsz = sizeof(displayName), vsz = sizeof(displayVersion), type = 0;
        LONG r1 = RegQueryValueExA(subKey, "DisplayName", nullptr, &type, (LPBYTE)displayName, &nsz);
        RegQueryValueExA(subKey, "DisplayVersion", nullptr, &type, (LPBYTE)displayVersion, &vsz);
        if (r1 == ERROR_SUCCESS && displayName[0]) {
          out.push_back({{"name", displayName}, {"version", std::string(displayVersion)}});
        }
        RegCloseKey(subKey);
      }
    }
    RegCloseKey(hKey);
  }

  static std::vector<json> collectInstalledSoftware() {
    std::vector<json> out;
    collectSoftwareFromKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", out);
    collectSoftwareFromKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", out);
    return out;
  }

  void collectChannel(const ChannelSpec& spec, int maxCount, std::vector<json>& out) {
    std::wstring channelW = utf8ToWide(spec.channel);
    std::string since = state_.lastTime(spec.name);
    std::wstring query = L"*[System[TimeCreated[@SystemTime>'" + utf8ToWide(since) + L"']]]";

    EVT_HANDLE hResults = EvtQuery(nullptr, channelW.c_str(), query.c_str(), EvtQueryChannelPath | EvtQueryForwardDirection);
    if (!hResults) return; // channel may not exist / not accessible without elevation — skip, not fatal

    std::string newestSeen = since;
    std::vector<EVT_HANDLE> events(maxCount > 0 ? maxCount : 50);
    DWORD returned = 0;
    if (EvtNext(hResults, (DWORD)events.size(), events.data(), 5000, 0, &returned)) {
      for (DWORD i = 0; i < returned; ++i) {
        DWORD bufUsed = 0, propCount = 0;
        EvtRender(nullptr, events[i], EvtRenderEventXml, 0, nullptr, &bufUsed, &propCount);
        std::wstring xmlBuf(bufUsed / sizeof(wchar_t) + 1, L'\0');
        if (EvtRender(nullptr, events[i], EvtRenderEventXml, bufUsed, xmlBuf.data(), &bufUsed, &propCount)) {
          std::string xml = wideToUtf8(xmlBuf);
          std::string eventId = extractTag(xml, "EventID");
          std::string computer = extractTag(xml, "Computer");
          std::string timeCreated = extractAttr(xml, "TimeCreated", "SystemTime");
          std::string levelStr = extractTag(xml, "Level");
          int level = levelStr.empty() ? 4 : std::stoi(levelStr);

          out.push_back({
            {"timestamp", timeCreated.empty() ? nowIso() : timeCreated},
            {"source", spec.sourceLabel},
            {"event_id", eventId},
            {"computer", computer},
            {"username", nullptr},
            {"ip_address", nullptr},
            {"action", spec.sourceLabel + " Event " + eventId},
            {"severity", mapSeverity(level)},
            {"raw", xml},
            {"index", spec.name},
          });
          if (!timeCreated.empty() && timeCreated > newestSeen) newestSeen = timeCreated;
        }
        EvtClose(events[i]);
      }
    }
    EvtClose(hResults);
    if (newestSeen > since) state_.setLastTime(spec.name, newestSeen);
  }
};

} // namespace

Collector* createPlatformCollector() { return new WindowsCollector(); }
