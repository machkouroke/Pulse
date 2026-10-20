// PulseMCP (native): MCP stdio server built on PulseService's own collectors.
// Reads Windows directly (Event Log, PDH, SetupAPI, SMBIOS...) with the code
// Pulse uses, without the service or its pipe. stdout carries MCP JSON-RPC
// only; the Pulse logger writes to stderr.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "collectors/event_log_channels.hpp"
#include "collectors/event_log_collector.hpp"
#include "collectors/evtx_file_reader.hpp"
#include "collectors/health_metrics_collector.hpp"
#include "inventory/inventory_engine.hpp"
#include "ipc/event_mapper.hpp"
#include "logging/logger.hpp"
#include "windows/wevt_helpers.hpp"
#include "wire_json.hpp"

#include <fcntl.h>
#include <io.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

using nlohmann::json;
namespace ipc = pulse::ipc;
using namespace std::chrono_literals;

namespace {

constexpr const char* kVersion = "0.1.0";
// Bounds one query when a keyword filter rarely matches.
constexpr std::size_t kMaxScan = 20000;

std::wstring Widen(const std::string& s) {
  if (s.empty()) return {};
  const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
  return w;
}

std::string Lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

bool Contains(const std::string& haystack, const std::string& lower_needle) {
  return lower_needle.empty() || Lower(haystack).find(lower_needle) != std::string::npos;
}

// ---------- argument helpers (throw = tool error shown to the model) ----------

std::string Str(const json& a, const char* k, std::string def = "") {
  if (!a.contains(k) || a[k].is_null()) return def;
  if (!a[k].is_string()) throw std::invalid_argument(std::string(k) + " must be a string");
  return a[k].get<std::string>();
}

long long Int(const json& a, const char* k, long long def, long long lo, long long hi) {
  if (!a.contains(k) || a[k].is_null()) return def;
  if (!a[k].is_number_integer()) throw std::invalid_argument(std::string(k) + " must be an integer");
  return std::clamp(a[k].get<long long>(), lo, hi);
}

double Num(const json& a, const char* k, double def) {
  if (!a.contains(k) || a[k].is_null()) return def;
  if (!a[k].is_number()) throw std::invalid_argument(std::string(k) + " must be a number");
  return a[k].get<double>();
}

bool Bool(const json& a, const char* k, bool def) {
  if (!a.contains(k) || a[k].is_null()) return def;
  if (!a[k].is_boolean()) throw std::invalid_argument(std::string(k) + " must be a boolean");
  return a[k].get<bool>();
}

std::vector<std::string> StrList(const json& a, const char* k) {
  if (!a.contains(k) || a[k].is_null()) return {};
  if (!a[k].is_array()) throw std::invalid_argument(std::string(k) + " must be an array");
  std::vector<std::string> out;
  for (const auto& v : a[k]) {
    if (!v.is_string()) throw std::invalid_argument(std::string(k) + " must hold strings");
    out.push_back(v.get<std::string>());
  }
  return out;
}

// ---------- time ----------

std::string IsoHoursAgo(double hours) {
  FILETIME ft{};
  GetSystemTimeAsFileTime(&ft);
  ULARGE_INTEGER t{};
  t.LowPart = ft.dwLowDateTime;
  t.HighPart = ft.dwHighDateTime;
  t.QuadPart -= static_cast<ULONGLONG>(std::max(hours, 0.0) * 3600.0 * 1e7);
  ft.dwLowDateTime = t.LowPart;
  ft.dwHighDateTime = t.HighPart;
  return pulse::wevt::FileTimeToIso8601Utc(ft);
}

long long UtcOffsetMinutes() {
  FILETIME utc{}, local{};
  GetSystemTimeAsFileTime(&utc);
  FileTimeToLocalFileTime(&utc, &local);
  ULARGE_INTEGER u{}, l{};
  u.LowPart = utc.dwLowDateTime;
  u.HighPart = utc.dwHighDateTime;
  l.LowPart = local.dwLowDateTime;
  l.HighPart = local.dwHighDateTime;
  return (static_cast<long long>(l.QuadPart) - static_cast<long long>(u.QuadPart)) / 600000000LL;
}

// Goes into an XPath literal, so only ISO-8601 characters are allowed.
const std::string& CheckIso(const std::string& s, const char* k) {
  static const std::regex re(R"(^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,7})?)?)?Z?$)");
  if (!std::regex_match(s, re)) {
    throw std::invalid_argument(std::string(k) + " must be UTC ISO-8601, e.g. 2026-10-20T08:00:00Z");
  }
  return s;
}

// ---------- events ----------

struct EventFilter {
  std::set<ipc::Severity> severities;  // empty = any
  std::string keyword;                 // lowercase; empty = any

  bool Matches(const ipc::TimelineEvent& e) const {
    if (!severities.empty() && !severities.count(e.severity)) return false;
    return Contains(e.title + '\n' + e.summary + '\n' + e.message + '\n' + e.provider_name, keyword);
  }
};

struct SeverityLevel {
  const char* xpath;
  ipc::Severity severity;
};
const std::map<std::string, SeverityLevel> kSeverities = {
    {"critical", {"Level=1", ipc::Severity::Critical}},
    {"error", {"Level=2", ipc::Severity::Error}},
    {"warning", {"Level=3", ipc::Severity::Warning}},
    {"info", {"Level=0 or Level=4", ipc::Severity::Info}},
    {"verbose", {"Level=5", ipc::Severity::Verbose}},
};

EventFilter ParseFilter(const json& a, std::string* xpath_levels) {
  EventFilter f;
  f.keyword = Lower(Str(a, "keyword"));
  for (const auto& s : StrList(a, "severity")) {
    const auto it = kSeverities.find(s);
    if (it == kSeverities.end()) throw std::invalid_argument("unknown severity: " + s);
    f.severities.insert(it->second.severity);
    if (xpath_levels) *xpath_levels += (xpath_levels->empty() ? "" : " or ") + std::string(it->second.xpath);
  }
  return f;
}

// Drops fields that only cost tokens (composite id, duplicate time and level);
// compact also drops the low-level Wevtapi fields that timeline_event keeps.
json EventJson(const ipc::TimelineEvent& e, bool include_xml, bool compact) {
  json j = e;
  for (const char* k : {"event_id", "timestamp_unix_ms", "level_name", "technical_summary"}) j.erase(k);
  if (compact) {
    for (const char* k : {"keywords", "opcode", "task", "thread_id", "activity_id", "related_activity_id"}) j.erase(k);
    if (e.summary == e.message) j.erase("summary");
  }
  if (!include_xml) j.erase("raw_xml");
  return j;
}

// One row per (provider, Event ID, severity), most frequent first. `events` is newest first.
json GroupEvents(const std::vector<ipc::TimelineEvent>& events, std::size_t limit, std::size_t* group_count) {
  struct Group {
    const ipc::TimelineEvent* latest = nullptr;
    const ipc::TimelineEvent* oldest = nullptr;
    std::size_t count = 0;
  };
  std::map<std::tuple<std::string, std::uint32_t, int>, Group> groups;
  for (const auto& e : events) {
    Group& g = groups[{e.provider_name, e.win_event_id, static_cast<int>(e.severity)}];
    if (g.count++ == 0) g.latest = &e;
    g.oldest = &e;
  }
  std::vector<const Group*> order;
  for (const auto& [key, g] : groups) order.push_back(&g);
  std::stable_sort(order.begin(), order.end(), [](const Group* x, const Group* y) { return x->count > y->count; });
  *group_count = order.size();

  json list = json::array();
  for (std::size_t i = 0; i < order.size() && i < limit; ++i) {
    const Group& g = *order[i];
    json latest = {{"channel", g.latest->channel}, {"record_id", g.latest->record_id}, {"summary", g.latest->summary}};
    if (!g.latest->recommendation.empty()) latest["recommendation"] = g.latest->recommendation;
    list.push_back({{"provider_name", g.latest->provider_name}, {"win_event_id", g.latest->win_event_id},
                    {"severity", g.latest->severity}, {"title", g.latest->title}, {"count", g.count},
                    {"first_seen", g.oldest->timestamp_iso}, {"last_seen", g.latest->timestamp_iso},
                    {"latest", std::move(latest)}});
  }
  return list;
}

bool QueryChannel(const std::wstring& channel, const std::wstring& xpath, const EventFilter& f,
                  std::size_t limit, std::vector<ipc::TimelineEvent>* out, std::string* err,
                  bool* capped) {
  pulse::wevt::EvtHandle query(EvtQuery(nullptr, channel.c_str(), xpath.c_str(),
                                        EvtQueryChannelPath | EvtQueryReverseDirection |
                                            EvtQueryTolerateQueryErrors));
  if (!query) {
    *err = pulse::wevt::FormatWin32Error(GetLastError());
    return false;
  }
  DWORD error = ERROR_SUCCESS;
  pulse::wevt::EvtHandle context = pulse::wevt::CreateSystemRenderContext(&error);
  if (!context) {
    *err = pulse::wevt::FormatWin32Error(error);
    return false;
  }
  std::size_t matched = 0, scanned = 0;
  while (matched < limit && scanned < kMaxScan) {
    auto batch = pulse::wevt::NextEvents(query.get(), 64, &error);
    if (batch.empty()) break;
    for (auto& handle : batch) {
      ++scanned;
      auto record = pulse::EventLogCollector::ParseEvtHandle(handle.get(), context.get());
      if (!record) continue;
      ipc::TimelineEvent event = pulse::ToTimelineEvent(*record);
      if (!f.Matches(event)) continue;
      out->push_back(std::move(event));
      if (++matched >= limit) break;
    }
  }
  if (scanned >= kMaxScan) *capped = true;
  return true;
}

json TimelineSearch(const json& a) {
  std::string levels;
  const EventFilter f = ParseFilter(a, &levels);
  const std::string from = a.contains("from") ? CheckIso(Str(a, "from"), "from") : IsoHoursAgo(Num(a, "hours", 24));
  const std::string to = Str(a, "to");
  const std::string provider = Str(a, "provider");
  const long long event_id = Int(a, "event_id", -1, -1, 65535);
  const auto limit = static_cast<std::size_t>(Int(a, "limit", 50, 1, 500));
  const bool include_xml = Bool(a, "include_xml", false);
  const bool group = Bool(a, "group", false);

  std::string cond = "TimeCreated[@SystemTime>='" + from + "']";
  if (!to.empty()) cond += " and TimeCreated[@SystemTime<='" + CheckIso(to, "to") + "']";
  if (!levels.empty()) cond += " and (" + levels + ")";
  if (!provider.empty()) {
    if (provider.find_first_of("'\"[]") != std::string::npos) throw std::invalid_argument("invalid provider name");
    cond += " and Provider[@Name='" + provider + "']";
  }
  if (event_id >= 0) cond += " and (EventID=" + std::to_string(event_id) + ")";
  const std::string xpath = "*[System[" + cond + "]]";

  std::vector<std::wstring> channels;
  for (const auto& c : StrList(a, "channels")) channels.push_back(Widen(c));
  if (channels.empty()) channels = pulse::AccessibleDiagnosticsChannels();

  std::vector<ipc::TimelineEvent> events;
  json read = json::array(), failed = json::object();
  bool capped = false;
  for (const auto& channel : channels) {
    std::string err;
    if (QueryChannel(channel, Widen(xpath), f, group ? kMaxScan : limit, &events, &err, &capped)) {
      read.push_back(pulse::wevt::WideToUtf8(channel));
    } else {
      failed[pulse::wevt::WideToUtf8(channel)] = err;
    }
  }
  std::sort(events.begin(), events.end(), [](const auto& x, const auto& y) {
    return x.timestamp_unix_ms > y.timestamp_unix_ms;
  });

  json out = {{"from", from}, {"utc_offset_minutes", UtcOffsetMinutes()}, {"channels_read", read}};
  if (!to.empty()) out["to"] = to;
  if (!failed.empty()) out["channels_failed"] = failed;
  if (group) {
    std::size_t group_count = 0;
    out["groups"] = GroupEvents(events, limit, &group_count);
    out["events_matched"] = events.size();
    out["group_count"] = group_count;
    if (capped) out["scan_capped"] = true;  // narrow the time range for exact counts
    return out;
  }
  // limit reached: more events may exist (each channel stops at `limit`).
  out["truncated"] = events.size() >= limit;
  if (events.size() > limit) events.resize(limit);
  json list = json::array();
  for (const auto& e : events) list.push_back(EventJson(e, include_xml, /*compact=*/true));
  out["count"] = list.size();
  out["events"] = std::move(list);
  return out;
}

json TimelineEvent(const json& a) {
  const std::string channel = Str(a, "channel");
  if (channel.empty()) throw std::invalid_argument("channel is required");
  if (!a.contains("record_id") || !a["record_id"].is_number_unsigned()) {
    throw std::invalid_argument("record_id (non-negative integer) is required");
  }
  const auto record_id = a["record_id"].get<std::uint64_t>();
  pulse::EventLogCollector collector;
  auto result = collector.CollectByRecordId(Widen(channel), record_id, /*include_raw_xml=*/true);
  if (!result) throw std::runtime_error(result.error());
  if (!result.value()) throw std::runtime_error("no event " + std::to_string(record_id) + " in " + channel);
  return EventJson(pulse::ToTimelineEvent(*result.value()), /*include_xml=*/true, /*compact=*/false);
}

json ReadEvtx(const json& a) {
  const std::string path = Str(a, "path");
  if (path.empty()) throw std::invalid_argument("path is required");
  const EventFilter f = ParseFilter(a, nullptr);
  const auto limit = static_cast<std::size_t>(Int(a, "limit", 100, 1, 2000));
  const bool include_xml = Bool(a, "include_xml", false);

  auto result = pulse::ReadEvtxFile(Widen(path), kMaxScan);
  if (!result) throw std::runtime_error(result.error());
  json list = json::array();
  std::size_t matched = 0;
  for (const auto& record : result.value().events) {
    const ipc::TimelineEvent event = pulse::ToTimelineEvent(record);
    if (!f.Matches(event)) continue;
    if (++matched <= limit) list.push_back(EventJson(event, include_xml, /*compact=*/true));
  }
  return {{"path", path},
          {"events_read", result.value().events.size()},
          {"file_truncated", result.value().truncated},
          {"matched", matched},
          {"events", list}};
}

// ---------- health / processes ----------

struct Health {
  pulse::HealthMetricsCollector collector;
  bool ready = false;
  std::optional<ipc::HealthStaticInfo> info;
  std::map<std::uint32_t, ipc::HealthProcessEntry> processes;
  std::chrono::steady_clock::time_point last{};

  void EnsureInit() {
    if (ready) return;
    if (!collector.Initialize()) throw std::runtime_error("health collector failed to initialize");
    ready = true;
    Update();  // the first sample has no rates (CPU %, disk, network)
  }

  ipc::HealthSample Update() {
    ipc::HealthUpdate u = collector.CollectHealthUpdate();
    last = std::chrono::steady_clock::now();
    auto& inv = u.process_inventory;
    if (inv.full_resync) processes.clear();
    for (auto& p : inv.upserts) processes[p.pid] = std::move(p);
    for (const auto pid : inv.removed_pids) processes.erase(pid);
    return std::move(u.sample);
  }

  // Rates need ~1 s between samples, like Task Manager.
  ipc::HealthSample Sample() {
    EnsureInit();
    const auto since = std::chrono::steady_clock::now() - last;
    if (since < 1s) std::this_thread::sleep_for(1s - since);
    return Update();
  }

  const ipc::HealthStaticInfo& Static() {
    EnsureInit();
    if (!info) info = collector.CollectStatic();
    return *info;
  }
};
std::unique_ptr<Health> g_health;
Health& H() {
  if (!g_health) g_health = std::make_unique<Health>();
  return *g_health;
}

json SystemHealth(const json&) {
  Health& h = H();
  json sample = h.Sample();
  return {{"static", h.Static()}, {"sample", std::move(sample)}};
}

json ProcessList(const json& a) {
  Health& h = H();
  h.Sample();
  const std::string sort_by = Str(a, "sort_by", "memory");
  const std::string needle = Lower(Str(a, "name_contains"));
  const auto limit = static_cast<std::size_t>(Int(a, "limit", 30, 1, 1000));

  std::vector<const ipc::HealthProcessEntry*> rows;
  for (const auto& [pid, p] : h.processes) {
    if (Contains(p.name + ' ' + p.path, needle)) rows.push_back(&p);
  }
  using P = const ipc::HealthProcessEntry*;
  std::function<bool(P, P)> less;
  if (sort_by == "cpu") {
    less = [](P x, P y) { return (x->has_cpu_percent ? x->cpu_percent : -1) > (y->has_cpu_percent ? y->cpu_percent : -1); };
  } else if (sort_by == "memory") {
    less = [](P x, P y) { return (x->has_memory_bytes ? x->memory_bytes : 0) > (y->has_memory_bytes ? y->memory_bytes : 0); };
  } else if (sort_by == "name") {
    less = [](P x, P y) { return Lower(x->name) < Lower(y->name); };
  } else if (sort_by == "pid") {
    less = [](P x, P y) { return x->pid < y->pid; };
  } else {
    throw std::invalid_argument("sort_by must be cpu, memory, name or pid");
  }
  std::stable_sort(rows.begin(), rows.end(), less);

  json list = json::array();
  for (std::size_t i = 0; i < rows.size() && i < limit; ++i) list.push_back(*rows[i]);
  return {{"total", h.processes.size()}, {"matched", rows.size()}, {"processes", list}};
}

// Command lines can carry credentials; the model does not need them.
std::string RedactSecrets(const std::string& s) {
  static const std::regex re(
      R"(((?:token|password|passwd|pwd|secret|api[-_]?key|auth[a-z]*)(?:\s*[=:]\s*|\s+))("[^"]*"|\S+))",
      std::regex::icase);
  return std::regex_replace(s, re, "$1***");
}

json ProcessDetails(const json& a) {
  const auto pid = Int(a, "pid", -1, -1, 0xFFFFFFFFLL);
  if (pid < 0) throw std::invalid_argument("pid is required");
  Health& h = H();
  h.EnsureInit();
  json j = h.collector.QueryProcessDetails(static_cast<std::uint32_t>(pid));
  if (j.contains("command_line")) j["command_line"] = RedactSecrets(j["command_line"].get<std::string>());
  return j;
}

// ---------- inventory ----------

pulse::inventory::InventoryEngine g_inventory;

json Inventory(const json& a) {
  const std::string domain = Str(a, "domain");
  const auto id = json(domain).get<ipc::InventoryDomainId>();
  if (id == ipc::InventoryDomainId::Unspecified) throw std::invalid_argument("unknown domain: " + domain);
  pulse::inventory::CollectRequest request;
  request.domain = id;
  request.force_refresh = Bool(a, "refresh", false);
  json j = g_inventory.GetDomain(request);

  const std::string needle = Lower(Str(a, "contains"));
  const auto limit = static_cast<std::size_t>(Int(a, "limit", 100, 1, 2000));
  std::size_t matched = 0;
  bool cut = false;
  for (auto& [key, value] : j.items()) {
    if (!value.is_array()) continue;
    json kept = json::array();
    for (auto& item : value) {
      if (!Contains(item.dump(-1, ' ', false, json::error_handler_t::replace), needle)) continue;
      ++matched;
      if (kept.size() < limit) kept.push_back(std::move(item)); else cut = true;
    }
    value = std::move(kept);
  }
  j["matched"] = matched;
  if (cut) j["limit_reached"] = true;
  return j;
}

// ---------- status ----------

bool IsElevated() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  const bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
  CloseHandle(token);
  return ok && elevation.TokenIsElevated != 0;
}

json Status(const json&) {
  json channels = json::array();
  for (const auto& spec : pulse::DiagnosticsChannelCatalog()) {
    std::string detail;
    const bool ok = pulse::IsEventLogChannelAccessible(spec.path, spec.kind, &detail);
    json c = {{"channel", pulse::wevt::WideToUtf8(spec.path)}, {"readable", ok}};
    if (!ok) c["detail"] = detail;
    channels.push_back(std::move(c));
  }
  json j = {{"server", "pulse-mcp-native"}, {"version", kVersion},
            {"elevated", IsElevated()}, {"utc_offset_minutes", UtcOffsetMinutes()},
            {"channels", channels}};
  if (g_health && g_health->ready) {
    // The ETW session can run on the TCPIP fallback yet attribute no bytes to
    // processes (Kernel-Network access denied), so report the data itself.
    const bool per_app = std::any_of(g_health->processes.begin(), g_health->processes.end(),
                                     [](const auto& kv) { return kv.second.has_net_bps; });
    j["per_app_network"] = per_app;
    if (!per_app) {
      j["per_app_network_hint"] =
          "No per-app network data: Kernel-Network ETW needs more rights (admin, or the Performance Log Users group).";
    }
    const std::string etw_error = g_health->collector.network_etw_last_error();
    if (!etw_error.empty()) j["network_etw_error"] = etw_error;
  } else {
    j["per_app_network"] = "unknown until system_health or process_list runs";
  }
  return j;
}

// ---------- tool table ----------

struct Tool {
  const char* name;
  const char* description;
  const char* schema;
  std::function<json(const json&)> run;
};

const std::vector<Tool>& Tools() {
  static const std::vector<Tool> tools = {
      {"timeline_search",
       "Windows Event Log search, as in Pulse's Timeline. Events come with Pulse's plain-language "
       "title, summary and recommendation; crashes (BugCheck 1001, Kernel-Power 41) and wakes are "
       "explained. Timestamps are UTC; add utc_offset_minutes for local time. Newest first.",
       R"({"type":"object","properties":{
         "hours":{"type":"number","description":"Look back this many hours (default 24). Ignored when 'from' is set."},
         "from":{"type":"string","description":"Start, UTC ISO-8601, e.g. 2026-10-20T08:00:00Z."},
         "to":{"type":"string","description":"End, UTC ISO-8601."},
         "severity":{"type":"array","items":{"type":"string","enum":["critical","error","warning","info","verbose"]}},
         "provider":{"type":"string","description":"Exact provider name, e.g. Microsoft-Windows-Kernel-Power."},
         "event_id":{"type":"integer"},
         "keyword":{"type":"string","description":"Case-insensitive text in title, summary, message or provider."},
         "channels":{"type":"array","items":{"type":"string"},"description":"Event Log channels. Default: Pulse's diagnostics set (System, Application, ...)."},
         "limit":{"type":"integer","minimum":1,"maximum":500,"description":"Max events, or max groups with group=true. Default 50."},
         "group":{"type":"boolean","description":"Count events per provider + Event ID instead of listing them. Best first call for 'what is wrong': repeated events no longer hide the rest."},
         "include_xml":{"type":"boolean","description":"Include raw event XML (EventData). Default false."}}})",
       TimelineSearch},
      {"timeline_event",
       "One Event Log record with its raw XML (EventData), from channel + record_id returned by timeline_search.",
       R"({"type":"object","required":["channel","record_id"],"properties":{
         "channel":{"type":"string"},"record_id":{"type":"integer","minimum":0}}})",
       TimelineEvent},
      {"read_evtx",
       "Read an exported .evtx file (e.g. from another PC), newest first, with Pulse's explanations.",
       R"({"type":"object","required":["path"],"properties":{
         "path":{"type":"string","description":"Absolute path to the .evtx file."},
         "severity":{"type":"array","items":{"type":"string","enum":["critical","error","warning","info","verbose"]}},
         "keyword":{"type":"string"},
         "limit":{"type":"integer","minimum":1,"maximum":2000,"description":"Default 100."},
         "include_xml":{"type":"boolean"}}})",
       ReadEvtx},
      {"system_health",
       "Live system health as in Pulse's Health page: CPU, memory, GPUs, disks (incl. SMART/NVMe health), "
       "volumes, network, uptime, top processes, plus static hardware/OS info. Fields a sensor does not report are omitted.",
       R"({"type":"object","properties":{}})", SystemHealth},
      {"process_list",
       "Running processes with CPU %, memory, GPU, disk and network use (Task Manager style).",
       R"({"type":"object","properties":{
         "sort_by":{"type":"string","enum":["cpu","memory","name","pid"],"description":"Default memory."},
         "name_contains":{"type":"string","description":"Filter on process name or path."},
         "limit":{"type":"integer","minimum":1,"maximum":1000,"description":"Default 30."}}})",
       ProcessList},
      {"process_details",
       "Details of one process: path, publisher, command line (secrets redacted), parent, user, integrity, architecture.",
       R"({"type":"object","required":["pid"],"properties":{"pid":{"type":"integer","minimum":0}}})",
       ProcessDetails},
      {"inventory",
       "Hardware and software inventory as in Pulse's Inventory page. Entries come with status "
       "(available / unsupported / access_denied / partial / error).",
       R"({"type":"object","required":["domain"],"properties":{
         "domain":{"type":"string","enum":["services","drivers","software","usb","pci","displays","audio","bluetooth","printers","battery","motherboard","bios","cpu","memory_modules","storage","network_adapters"]},
         "contains":{"type":"string","description":"Case-insensitive text filter on each entry."},
         "limit":{"type":"integer","minimum":1,"maximum":2000,"description":"Default 100."},
         "refresh":{"type":"boolean","description":"Bypass the cache. Default false."}}})",
       Inventory},
      {"status",
       "What this server can read: Event Log channels readable with the current account, elevation, "
       "network ETW state, UTC offset. Use it when data looks missing.",
       R"({"type":"object","properties":{}})", Status},
  };
  return tools;
}

// ---------- JSON-RPC over stdio ----------

json Result(const json& id, json result) {
  return {{"jsonrpc", "2.0"}, {"id", id}, {"result", std::move(result)}};
}

json Error(const json& id, int code, const std::string& message) {
  return {{"jsonrpc", "2.0"}, {"id", id}, {"error", {{"code", code}, {"message", message}}}};
}

json CallTool(const json& id, const json& params) {
  const std::string name = params.value("name", "");
  const auto& tools = Tools();
  const auto tool = std::find_if(tools.begin(), tools.end(), [&](const Tool& t) { return name == t.name; });
  if (tool == tools.end()) return Error(id, -32602, "unknown tool: " + name);
  const json args = params.contains("arguments") && params["arguments"].is_object() ? params["arguments"] : json::object();
  std::string text;
  bool is_error = false;
  try {
    text = tool->run(args).dump(-1, ' ', false, json::error_handler_t::replace);
  } catch (const std::exception& e) {
    text = e.what();
    is_error = true;
  } catch (...) {
    text = "internal error";
    is_error = true;
  }
  json content = json::array();
  content.push_back({{"type", "text"}, {"text", text}});
  return Result(id, {{"content", std::move(content)}, {"isError", is_error}});
}

json Handle(const json& msg) {
  const json& id = msg["id"];
  const std::string method = msg.value("method", "");
  const json params = msg.contains("params") ? msg["params"] : json::object();
  if (method == "initialize") {
    return Result(id, {{"protocolVersion", params.value("protocolVersion", "2025-06-18")},
                       {"capabilities", {{"tools", json::object()}}},
                       {"serverInfo", {{"name", "pulse-mcp-native"}, {"version", kVersion}}},
                       {"instructions",
                        "Read-only Windows diagnostics, collected with Pulse's own code. Start with "
                        "timeline_search for problems, system_health for live state, inventory for "
                        "hardware/software. Times are UTC."}});
  }
  if (method == "ping") return Result(id, json::object());
  if (method == "tools/list") {
    json list = json::array();
    for (const auto& t : Tools()) {
      list.push_back({{"name", t.name},
                      {"description", t.description},
                      {"inputSchema", json::parse(t.schema)},
                      {"annotations", {{"readOnlyHint", true}, {"openWorldHint", false}}}});
    }
    return Result(id, {{"tools", list}});
  }
  if (method == "tools/call") return CallTool(id, params);
  return Error(id, -32601, "method not found: " + method);
}

// PulseMCP.exe --self-test: the input-safety helpers, no Windows data needed.
int SelfTest() {
  int failures = 0;
  auto check = [&](bool ok, const char* what) {
    if (!ok) {
      std::fprintf(stderr, "FAIL: %s\n", what);
      ++failures;
    }
  };
  check(RedactSecrets("app.exe --token=abc123 -v") == "app.exe --token=*** -v", "redact --token=");
  check(RedactSecrets("x --password \"p w\"") == "x --password ***", "redact quoted password");
  check(RedactSecrets("svchost.exe -k netsvcs") == "svchost.exe -k netsvcs", "leave plain cmdline");
  auto rejects = [](const std::string& s) {
    try { CheckIso(s, "t"); return false; } catch (const std::invalid_argument&) { return true; }
  };
  check(!rejects("2026-10-20T08:00:00Z") && !rejects("2026-10-20T08:00:00.123Z"), "accept ISO");
  check(rejects("2026-10-20' or '1'='1") && rejects("yesterday"), "reject XPath injection");
  std::string levels;
  ParseFilter(json{{"severity", {"error", "critical"}}}, &levels);
  check(levels == "Level=2 or Level=1", "severity to XPath");
  std::fprintf(stderr, failures ? "self-test: %d failure(s)\n" : "self-test: ok\n", failures);
  return failures ? 1 : 0;
}

void Send(const json& j) {
  const std::string line = j.dump(-1, ' ', false, json::error_handler_t::replace) + '\n';
  std::fwrite(line.data(), 1, line.size(), stdout);
  std::fflush(stdout);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc > 1 && std::string(argv[1]) == "--self-test") return SelfTest();
  _setmode(_fileno(stdin), _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
  pulse::Logger::Instance().SetLevel(pulse::LogLevel::Warn);

  std::string line;
  while (std::getline(std::cin, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    const json msg = json::parse(line, nullptr, /*allow_exceptions=*/false);
    if (msg.is_discarded() || !msg.is_object()) {
      Send(Error(nullptr, -32700, "parse error"));
      continue;
    }
    // Notifications and client responses need no reply.
    if (!msg.contains("id") || !msg.contains("method")) continue;
    Send(Handle(msg));
  }
  if (g_health && g_health->ready) g_health->collector.Shutdown();  // stops the ETW session
  return 0;
}
