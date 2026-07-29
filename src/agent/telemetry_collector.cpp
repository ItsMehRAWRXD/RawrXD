/**
 * @file telemetry_collector.cpp
 * @brief TelemetryCollector implementation – Qt-free (C++20 / Win32)
 *
 * Privacy-respecting, opt-in telemetry. Uses WinHTTP for data submission,
 * std::filesystem for consent persistence, and json_types.hpp for payloads.
 */

#include "telemetry_collector.hpp"
<<<<<<< HEAD
#include "process_utils.hpp"
#include <cstdio>
#include <chrono>
#include <filesystem>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#pragma comment(lib, "ole32.lib")
#endif

namespace fs = std::filesystem;

// ── Helpers ──────────────────────────────────────────────────────────────

static int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();
}

static std::string generateSessionId() {
#ifdef _WIN32
    GUID guid{};
    CoCreateGuid(&guid);
    char buf[64];
    snprintf(buf, sizeof(buf),
             "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             guid.Data1, guid.Data2, guid.Data3,
             guid.Data4[0], guid.Data4[1],
             guid.Data4[2], guid.Data4[3],
             guid.Data4[4], guid.Data4[5],
             guid.Data4[6], guid.Data4[7]);
    return buf;
#else
    char buf[64];
    snprintf(buf, sizeof(buf), "sess-%016llx%08x",
             (unsigned long long)nowMs(), (unsigned)rand());
    return buf;
#endif
}

static std::string isoTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto tt  = std::chrono::system_clock::to_time_t(now);
    struct tm t{};
#ifdef _WIN32
    gmtime_s(&t, &tt);
#else
    gmtime_r(&tt, &t);
#endif
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &t);
    return buf;
}

static std::string consentFilePath() {
    std::string appData = getEnvVar("APPDATA", ".");
    return appData + "\\RawrXD\\telemetry_consent.txt";
}

// ── Singleton ────────────────────────────────────────────────────────────
=======
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <chrono>
#include <vector>
#include <map>
#include <regex>
#include <windows.h>
#include <winhttp.h>
#include <objbase.h>
#include <nlohmann/json.hpp>

// Link against these libraries in CMake:
// target_link_libraries(target PRIVATE winhttp ole32)

using json = nlohmann::json;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

TelemetryCollector* TelemetryCollector::s_instance = nullptr;

TelemetryCollector* TelemetryCollector::instance() {
    if (!s_instance) s_instance = new TelemetryCollector();
    return s_instance;
}

<<<<<<< HEAD
TelemetryCollector::TelemetryCollector()  = default;
TelemetryCollector::~TelemetryCollector() = default;

// ── initialize ───────────────────────────────────────────────────────────

bool TelemetryCollector::initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_sessionId        = generateSessionId();
    m_sessionStartTime = nowMs();
    m_enabled          = loadUserConsent();

    fprintf(stderr, "[Telemetry] Initialized (enabled=%d, session=%s)\n",
            m_enabled, m_sessionId.c_str());
    return true;
=======
// UUID Helper
static std::string generateUUID() {
    GUID guid;
    HRESULT h = CoCreateGuid(&guid);
    if (FAILED(h)) return "00000000-0000-0000-0000-000000000000";

    char buf[64];
    sprintf_s(buf, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return std::string(buf);
}

// Time Helper
static std::string currentIsoTime() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    gmtime_s(&tm, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

TelemetryCollector::TelemetryCollector(void* parent)
    : m_enabled(false)
{
    // Parent unused
    m_sessionId = generateUUID();
    m_sessionStartTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

TelemetryCollector::~TelemetryCollector() {
    if (m_enabled && !m_events.empty()) {
        flushData();
    }
}

bool TelemetryCollector::initialize() {
    m_enabled = loadUserConsent();

    // Check Env
    char* envVal;
    size_t len;
    if (_dupenv_s(&envVal, &len, "TELEMETRY_ENABLED") == 0 && envVal) {
        std::string s(envVal);
        if (s == "1" || s == "true" || s == "TRUE") m_enabled = true;
        free(envVal);
    }

    if (m_enabled) {
        
    } else {
        
    }
    return m_enabled;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ── enable / disable ─────────────────────────────────────────────────────

void TelemetryCollector::enableTelemetry() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_enabled = true;
    saveUserConsent(true);
<<<<<<< HEAD
    fprintf(stderr, "[Telemetry] Enabled\n");
    if (m_enabledCb) m_enabledCb(m_enabledCtx);
=======
    
    trackFeatureUsage("telemetry.enabled", {});
    // Signal equivalent? m_callbacks... (omitted for now)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void TelemetryCollector::disableTelemetry() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_enabled = false;
    saveUserConsent(false);
<<<<<<< HEAD
    fprintf(stderr, "[Telemetry] Disabled\n");
    if (m_disabledCb) m_disabledCb(m_disabledCtx);
}

// ── trackFeatureUsage ────────────────────────────────────────────────────

void TelemetryCollector::trackFeatureUsage(const std::string& featureName,
                                           const JsonObject& metadata) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_enabled) return;

    std::string safe = sanitize(featureName);
    m_featureUsage[safe]++;

    JsonObject ev;
    ev["type"]      = JsonValue("feature_usage");
    ev["feature"]   = JsonValue(safe);
    ev["count"]     = JsonValue(m_featureUsage[safe]);
    ev["timestamp"] = JsonValue(isoTimestamp());
    ev["session"]   = JsonValue(m_sessionId);

    if (!metadata.empty()) {
        ev["metadata"] = JsonValue(metadata);
    }

    m_events.push_back(std::move(ev));
}

// ── trackCrash ───────────────────────────────────────────────────────────

void TelemetryCollector::trackCrash(const std::string& crashReason) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_enabled) return;

    JsonObject ev;
    ev["type"]      = JsonValue("crash");
    ev["reason"]    = JsonValue(sanitize(crashReason));
    ev["timestamp"] = JsonValue(isoTimestamp());
    ev["session"]   = JsonValue(m_sessionId);
    ev["platform"]  = JsonValue(sysinfo::productType());
    ev["arch"]      = JsonValue(sysinfo::cpuArchitecture());

    m_events.push_back(std::move(ev));
}

// ── trackPerformance ─────────────────────────────────────────────────────

void TelemetryCollector::trackPerformance(const std::string& metricName,
                                          double value,
                                          const std::string& unit) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_enabled) return;

    JsonObject ev;
    ev["type"]      = JsonValue("performance");
    ev["metric"]    = JsonValue(sanitize(metricName));
    ev["value"]     = JsonValue(value);
    ev["timestamp"] = JsonValue(isoTimestamp());
    ev["session"]   = JsonValue(m_sessionId);

    if (!unit.empty()) {
        ev["unit"] = JsonValue(unit);
    }

    m_events.push_back(std::move(ev));
}

// ── getAllTelemetryData ──────────────────────────────────────────────────

JsonObject TelemetryCollector::getAllTelemetryData() const {
    std::lock_guard<std::mutex> lock(m_mutex);

    JsonObject result;
    result["session_id"]    = JsonValue(m_sessionId);
    result["enabled"]       = JsonValue(m_enabled);
    result["event_count"]   = JsonValue(static_cast<int64_t>(m_events.size()));

    // Feature usage summary
    JsonObject usage;
    for (auto& [k, v] : m_featureUsage) {
        usage[k] = JsonValue(v);
    }
    result["feature_usage"] = JsonValue(std::move(usage));

    // Session duration
    int64_t durationMs = nowMs() - m_sessionStartTime;
    result["session_duration_ms"] = JsonValue(durationMs);

    return result;
=======
    clearAllData();
    
}

void TelemetryCollector::trackFeatureUsage(const std::string& featureName, const std::map<std::string, std::string>& metadata) {
    if (!m_enabled) return;

    std::string sanitizedFeature = sanitize(featureName);
    m_featureUsage[sanitizedFeature]++;

    json event;
    event["type"] = "feature_usage";
    event["feature"] = sanitizedFeature;
    event["timestamp"] = currentIsoTime();
    event["session_id"] = m_sessionId;

    if (!metadata.empty()) {
        json metaJson;
        for (const auto& kv : metadata) {
             std::string key = kv.first;
             // Simple lower casing check
             std::string keyLower = key;
             std::transform(keyLower.begin(), keyLower.end(), keyLower.begin(), ::tolower);
             
             if (keyLower.find("user") == std::string::npos && 
                 keyLower.find("email") == std::string::npos &&
                 keyLower.find("ip") == std::string::npos) {
                 metaJson[key] = kv.second;
             }
        }
        event["metadata"] = metaJson;
    }

    m_events.push_back(event);


    if (m_events.size() >= 50) flushData();
}

void TelemetryCollector::trackCrash(const std::string& crashReason) {
    if (!m_enabled) return;

    std::string sanitizedReason = sanitize(crashReason);
    json event;
    event["type"] = "crash";
    event["reason"] = sanitizedReason;
    event["timestamp"] = currentIsoTime();
    event["session_id"] = m_sessionId;
    
    m_events.push_back(event);


    flushData();
}

void TelemetryCollector::trackPerformance(const std::string& metricName, double value, const std::string& unit) {
    if (!m_enabled) return;

    std::string sanitizedMetric = sanitize(metricName);
    json event;
    event["type"] = "performance";
    event["metric"] = sanitizedMetric;
    event["value"] = value;
    event["unit"] = unit.empty() ? "ms" : unit;
    event["timestamp"] = currentIsoTime();
    event["session_id"] = m_sessionId;

    m_events.push_back(event);
}

// Return json string representation
std::string TelemetryCollector::getAllTelemetryData() const {
    json data;
    data["session_id"] = m_sessionId;
    auto nowSync = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    data["session_duration_ms"] = nowSync - m_sessionStartTime;
    data["enabled"] = m_enabled;
    data["feature_usage"] = m_featureUsage;
    data["buffered_events"] = m_events;
    
    return data.dump(4);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ── clearAllData ─────────────────────────────────────────────────────────

void TelemetryCollector::clearAllData() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_events.clear();
    m_featureUsage.clear();
<<<<<<< HEAD
    fprintf(stderr, "[Telemetry] All data cleared\n");
=======
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ── flushData ────────────────────────────────────────────────────────────

void TelemetryCollector::flushData() {
<<<<<<< HEAD
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_enabled || m_events.empty()) return;

    int count = static_cast<int>(m_events.size());

    // Build batch payload
    JsonObject payload;
    payload["session_id"] = JsonValue(m_sessionId);
    payload["platform"]   = JsonValue(sysinfo::productType());
    payload["arch"]       = JsonValue(sysinfo::cpuArchitecture());
    payload["timestamp"]  = JsonValue(isoTimestamp());

    JsonArray eventArr;
    for (auto& ev : m_events) {
        eventArr.push_back(JsonValue(ev));
    }
    payload["events"] = JsonValue(std::move(eventArr));

    sendTelemetry(payload);
    m_events.clear();

    if (m_flushedCb) m_flushedCb(m_flushedCtx, count);

    fprintf(stderr, "[Telemetry] Flushed %d events\n", count);
}

// ── sanitize (private) ──────────────────────────────────────────────────

std::string TelemetryCollector::sanitize(const std::string& input) const {
    std::string out;
    out.reserve(input.size());
    for (char c : input) {
        // Keep alphanumeric, underscores, hyphens, dots, spaces
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' ||
            c == '.' || c == ' ') {
            out += c;
        }
    }
    return out;
}

// ── sendTelemetry (private) ──────────────────────────────────────────────

void TelemetryCollector::sendTelemetry(const JsonObject& payload) {
    std::string endpoint = getEnvVar("RAWRXD_TELEMETRY_URL");
    if (endpoint.empty()) {
        // No endpoint configured – just log locally
        fprintf(stderr, "[Telemetry] (no endpoint) payload: %s\n",
                JsonDoc::toJson(payload).c_str());
        return;
    }

    std::string body = JsonDoc::toJson(payload);

    http::Response resp = http::post(endpoint, body, {
        {"Content-Type", "application/json"},
        {"X-Session-Id", m_sessionId}
    });

    if (!resp.ok()) {
        fprintf(stderr, "[Telemetry] HTTP %d: %s\n",
                resp.statusCode, resp.error.c_str());
    }
=======
    if (!m_enabled || m_events.empty()) return;

    json payload;
    payload["session_id"] = m_sessionId;
    
    auto nowSync = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    payload["session_duration_ms"] = nowSync - m_sessionStartTime;
    payload["events"] = m_events;

    int eventCount = (int)m_events.size();
    m_events.clear(); // Clear immediately

    std::string jsonStr = payload.dump();


    sendTelemetry(jsonStr);
}

std::string TelemetryCollector::sanitize(const std::string& input) const {
    std::string s = input;
    // std::regex replacement
    s = std::regex_replace(s, std::regex(R"(C:\\Users\\[^\\]+)"), "C:\\Users\\[USER]");
    s = std::regex_replace(s, std::regex(R"(/home/[^/]+)"), "/home/[USER]");
    s = std::regex_replace(s, std::regex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"), "[EMAIL]");
    s = std::regex_replace(s, std::regex(R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)"), "[IP]"); // IPv4

    if (s.length() > 200) {
        s = s.substr(0, 197) + "...";
    }
    return s;
}

void TelemetryCollector::sendTelemetry(const std::string& jsonPayload) {
    // WinHTTP implementation
    char* envVal;
    size_t len;
    std::string url = "https://telemetry.rawrxd.io/api/v1/events";
    if (_dupenv_s(&envVal, &len, "TELEMETRY_ENDPOINT") == 0 && envVal) {
        url = envVal;
        free(envVal);
    }

    // Parsing hostname and path from URL for WinHTTP is tedious. 
    // Assuming simplified usage or direct WinHTTP logic.
    // For this context, I'll use a simplified helper or just log it if we don't have a real endpoint.
    // But I should try to implement a basic POST.
    
    // Parse URL (very basic)
    std::string hostname;
    std::string path;
    int port = 443; // https default
    
    size_t schemeEnd = url.find("://");
    std::string bareUrl = (schemeEnd != std::string::npos) ? url.substr(schemeEnd + 3) : url;
    
    size_t pathStart = bareUrl.find("/");
    if (pathStart != std::string::npos) {
        hostname = bareUrl.substr(0, pathStart);
        path = bareUrl.substr(pathStart);
    } else {
        hostname = bareUrl;
        path = "/";
    }

    HINTERNET hSession = WinHttpOpen(L"RawrXD-Agent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    std::wstring wHost(hostname.begin(), hostname.end()); // Simple ASCII to WString conversion
    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return; }

    std::wstring wPath(path.begin(), path.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

    std::wstring headers = L"Content-Type: application/json";
    bool result = WinHttpSendRequest(hRequest, headers.c_str(), -1L, (LPVOID)jsonPayload.c_str(), (DWORD)jsonPayload.length(), (DWORD)jsonPayload.length(), 0);
    
    if (result) {
        WinHttpReceiveResponse(hRequest, NULL);
        // We could check status here
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ── loadUserConsent (private) ────────────────────────────────────────────

bool TelemetryCollector::loadUserConsent() const {
<<<<<<< HEAD
    std::string path = consentFilePath();
    if (!fs::exists(path)) return false; // opt-in: default off

    std::string content = fileutil::readAll(path);
    // Trim whitespace
    while (!content.empty() && (content.back() == '\n' || content.back() == '\r' || content.back() == ' '))
        content.pop_back();

    return content == "1" || content == "true" || content == "yes";
=======
    // Simple file based config
    std::ifstream f("telemetry.cfg");
    if (!f) return false;
    std::string s;
    f >> s;
    return (s == "1");
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ── saveUserConsent (private) ────────────────────────────────────────────

void TelemetryCollector::saveUserConsent(bool enabled) {
<<<<<<< HEAD
    std::string path = consentFilePath();

    // Ensure directory exists
    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);

    fileutil::writeAll(path, enabled ? "1" : "0");
=======
    std::ofstream f("telemetry.cfg");
    if (f) f << (enabled ? "1" : "0");
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}
