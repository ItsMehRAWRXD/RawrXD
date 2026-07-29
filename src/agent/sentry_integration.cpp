/**
 * @file sentry_integration.cpp
 * @brief SentryIntegration implementation – Qt-free (C++20 / Win32)
 *
 * Sends crash reports, performance transactions, and breadcrumbs
 * to Sentry via WinHTTP (through process_utils.hpp http:: namespace).
 */

#include "sentry_integration.hpp"
<<<<<<< HEAD
#include "process_utils.hpp"
#include "../json_types.hpp"
#include <cstdio>
#include <chrono>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>     // CoCreateGuid
#pragma comment(lib, "ole32.lib")
#endif

// ── Helpers ──────────────────────────────────────────────────────────────

static int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();
}

static std::string generateEventId() {
#ifdef _WIN32
    GUID guid{};
    CoCreateGuid(&guid);
    char buf[64];
    snprintf(buf, sizeof(buf),
             "%08lx%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x",
             guid.Data1, guid.Data2, guid.Data3,
             guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
             guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return buf;
#else
    // Simple fallback: timestamp + random
    char buf[64];
    snprintf(buf, sizeof(buf), "%016llx%08x",
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

// ── Singleton ────────────────────────────────────────────────────────────
=======
#include <iostream>
#include <chrono>
#include <windows.h>
#include <winhttp.h>
#include <objbase.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ole32.lib")

using json = nlohmann::json;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

SentryIntegration* SentryIntegration::s_instance = nullptr;

SentryIntegration* SentryIntegration::instance() {
    if (!s_instance) s_instance = new SentryIntegration();
    return s_instance;
}

<<<<<<< HEAD
SentryIntegration::SentryIntegration()  = default;
SentryIntegration::~SentryIntegration() = default;

// ── initialize ───────────────────────────────────────────────────────────
=======
static std::string genUuid() {
    GUID guid;
    CoCreateGuid(&guid);
    char buf[64];
    sprintf_s(buf, "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x", 
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return std::string(buf);
}

static std::string nowIso() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    gmtime_s(&tm, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

static std::string getEnvVar(const std::string& name) {
    char* val = nullptr;
    size_t len = 0;
    if (_dupenv_s(&val, &len, name.c_str()) == 0 && val) {
        std::string s(val);
        free(val);
        return s;
    }
    return "";
}

SentryIntegration::SentryIntegration() {}

SentryIntegration::~SentryIntegration() {}

bool SentryIntegration::initialize() {
<<<<<<< HEAD
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_initialized) return true;

    m_dsn = getEnvVar("SENTRY_DSN");
    if (m_dsn.empty()) {
        fprintf(stderr, "[Sentry] SENTRY_DSN not set – crash reporting disabled\n");
        // Not fatal: run without sentry
    }

    m_initialized = true;
    fprintf(stderr, "[Sentry] Initialized (dsn=%s)\n",
            m_dsn.empty() ? "<none>" : "***");
    return true;
}

// ── captureException ─────────────────────────────────────────────────────

void SentryIntegration::captureException(const std::string& exception,
                                         const JsonObject& context) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string eventId = generateEventId();

    JsonObject event;
    event["event_id"]  = JsonValue(eventId);
    event["timestamp"] = JsonValue(isoTimestamp());
    event["level"]     = JsonValue("error");
    event["platform"]  = JsonValue("native");

    // Exception payload
    JsonObject exVal;
    exVal["type"]  = JsonValue("RuntimeError");
    exVal["value"] = JsonValue(exception);

    JsonArray exValues;
    exValues.push_back(JsonValue(std::move(exVal)));

    JsonObject exBlock;
    exBlock["values"] = JsonValue(std::move(exValues));
    event["exception"] = JsonValue(std::move(exBlock));

    // Merge user context
    if (!context.empty()) {
        event["extra"] = JsonValue(context);
    }

    // Attach breadcrumbs
    if (!m_breadcrumbs.empty()) {
        JsonArray crumbs;
        for (auto& bc : m_breadcrumbs)
            crumbs.push_back(JsonValue(bc));
        event["breadcrumbs"] = JsonValue(std::move(crumbs));
    }

    sendEvent(event);

    if (m_errCb) m_errCb(m_errCtx, eventId.c_str());

    fprintf(stderr, "[Sentry] Exception captured: %s (id=%s)\n",
            exception.c_str(), eventId.c_str());
}

// ── captureMessage ───────────────────────────────────────────────────────

void SentryIntegration::captureMessage(const std::string& message,
                                       const std::string& level) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string eventId = generateEventId();

    JsonObject event;
    event["event_id"]  = JsonValue(eventId);
    event["timestamp"] = JsonValue(isoTimestamp());
    event["level"]     = JsonValue(level);
    event["message"]   = JsonValue(message);
    event["platform"]  = JsonValue("native");

    sendEvent(event);
    fprintf(stderr, "[Sentry] Message: [%s] %s\n", level.c_str(), message.c_str());
}

// ── addBreadcrumb ────────────────────────────────────────────────────────

void SentryIntegration::addBreadcrumb(const std::string& message,
                                      const std::string& category) {
    std::lock_guard<std::mutex> lock(m_mutex);

    JsonObject crumb;
    crumb["timestamp"] = JsonValue(isoTimestamp());
    crumb["message"]   = JsonValue(message);
    crumb["category"]  = JsonValue(category);

    m_breadcrumbs.push_back(std::move(crumb));

    // Cap at 100 breadcrumbs
    while (m_breadcrumbs.size() > 100) {
        m_breadcrumbs.erase(m_breadcrumbs.begin());
    }
}

// ── startTransaction ─────────────────────────────────────────────────────

std::string SentryIntegration::startTransaction(const std::string& operation) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string txId = generateEventId();
    m_activeTransactions[txId] = nowMs();

    fprintf(stderr, "[Sentry] Transaction started: %s (op=%s)\n",
            txId.c_str(), operation.c_str());
    return txId;
}

// ── finishTransaction ────────────────────────────────────────────────────

void SentryIntegration::finishTransaction(const std::string& transactionId) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_activeTransactions.find(transactionId);
    if (it == m_activeTransactions.end()) {
        fprintf(stderr, "[Sentry] finishTransaction: unknown id %s\n",
                transactionId.c_str());
        return;
    }

    int64_t startMs   = it->second;
    int64_t durationMs = nowMs() - startMs;
    m_activeTransactions.erase(it);

    // Send transaction event
    JsonObject event;
    event["event_id"]  = JsonValue(transactionId);
    event["type"]      = JsonValue("transaction");
    event["timestamp"] = JsonValue(isoTimestamp());
    event["platform"]  = JsonValue("native");

    JsonObject spans;
    spans["duration_ms"] = JsonValue(durationMs);
    event["spans"] = JsonValue(std::move(spans));

    sendEvent(event);

    if (m_txCb) m_txCb(m_txCtx, transactionId.c_str(), durationMs);

    fprintf(stderr, "[Sentry] Transaction finished: %s (%lld ms)\n",
            transactionId.c_str(), (long long)durationMs);
}

// ── setUser ──────────────────────────────────────────────────────────────

void SentryIntegration::setUser(const std::string& userId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    // Store for inclusion in future events (breadcrumb approach)
    addBreadcrumb("User set: " + userId, "auth");
}

// ── sendEvent (private) ──────────────────────────────────────────────────

void SentryIntegration::sendEvent(const JsonObject& event) {
    if (m_dsn.empty()) {
        // No DSN configured – log only
        fprintf(stderr, "[Sentry] (no DSN) event: %s\n",
                JsonDoc::toJson(event).c_str());
        return;
    }

    // Parse DSN: https://<key>@<host>/<project_id>
    // Format: https://KEY@HOST/PROJECT_ID
    std::string dsn = m_dsn;
    std::string key, host, projectId;

    // Strip scheme
    size_t schemeEnd = dsn.find("://");
    if (schemeEnd != std::string::npos) dsn = dsn.substr(schemeEnd + 3);

    // key@host/project
    size_t atPos = dsn.find('@');
    if (atPos != std::string::npos) {
        key = dsn.substr(0, atPos);
        std::string rest = dsn.substr(atPos + 1);
        size_t slashPos = rest.find('/');
        if (slashPos != std::string::npos) {
            host      = rest.substr(0, slashPos);
            projectId = rest.substr(slashPos + 1);
        }
    }

    if (key.empty() || host.empty() || projectId.empty()) {
        fprintf(stderr, "[Sentry] Invalid DSN format\n");
        return;
    }

    std::string url = "https://" + host + "/api/" + projectId + "/store/";
    std::string payload = JsonDoc::toJson(event);

    http::Response resp = http::post(url, payload, {
        {"Content-Type",          "application/json"},
        {"X-Sentry-Auth",
         "Sentry sentry_version=7, sentry_client=rawrxd/1.0, sentry_key=" + key}
    });

    if (!resp.ok()) {
        fprintf(stderr, "[Sentry] HTTP %d: %s\n",
                resp.statusCode, resp.error.c_str());
    }
=======
    m_dsn = getEnvVar("SENTRY_DSN");
    if (m_dsn.empty()) return false;

    // Parse DSN: https://public@sentry.example.com/1
    // Simplified parsing
    size_t atPos = m_dsn.find('@');
    size_t slashPos = m_dsn.rfind('/');
    if (atPos == std::string::npos || slashPos == std::string::npos) return false;

    std::string proto = m_dsn.substr(0, m_dsn.find("://") + 3);
    m_publicKey = m_dsn.substr(proto.length(), atPos - proto.length());
    std::string host = m_dsn.substr(atPos + 1, slashPos - (atPos + 1));
    m_projectId = m_dsn.substr(slashPos + 1);
    
    // Construct endpoint
    // https://sentry.io/api/PROJECT_ID/store/
    m_sentryEndpoint = "https://" + host + "/api/" + m_projectId + "/store/";

    m_initialized = true;
    addBreadcrumb("Sentry initialized", "sentry");
    return true;
}

void SentryIntegration::captureException(const std::string& exception, const json& context) {
    if (!m_initialized) return;

    json event;
    event["event_id"] = genUuid();
    event["timestamp"] = nowIso();
    event["level"] = "error";
    event["platform"] = "native";
    event["sdk"] = { {"name", "rawrxd-sentry"}, {"version", "1.0"} };
    
    json excData;
    excData["type"] = "Exception";
    excData["value"] = exception;
    if (!context.empty()) excData["context"] = context;

    event["exception"] = { {"values", {excData}} };

    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_breadcrumbs.empty()) {
         event["breadcrumbs"] = { {"values", m_breadcrumbs} };
    }

    event["environment"] = getEnvVar("RAWRXD_ENV").empty() ? "production" : getEnvVar("RAWRXD_ENV");

    sendEvent(event);
}

void SentryIntegration::captureMessage(const std::string& message, const std::string& level) {
    if (!m_initialized) return;
    
    json event;
    event["event_id"] = genUuid();
    event["timestamp"] = nowIso();
    event["level"] = level;
    event["platform"] = "native";
    event["message"] = message;
    
    sendEvent(event);
}

void SentryIntegration::addBreadcrumb(const std::string& message, const std::string& category, const std::string& level) {
    std::lock_guard<std::mutex> lock(m_mutex);
    json bc;
    bc["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() / 1000.0;
    bc["message"] = message;
    bc["category"] = category;
    bc["level"] = level;
    
    m_breadcrumbs.push_back(bc);
    if (m_breadcrumbs.size() > 50) m_breadcrumbs.erase(m_breadcrumbs.begin());
}

void SentryIntegration::sendEvent(const json& event) {
    // WinHTTP Post
    // Parsing m_sentryEndpoint again to get host/path
    std::string url = m_sentryEndpoint;
    std::string hostname;
    std::string path;
    int port = 443;

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

    HINTERNET hSession = WinHttpOpen(L"RawrXD-Sentry/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    std::wstring wHost(hostname.begin(), hostname.end());
    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return; }

    std::wstring wPath(path.begin(), path.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

    // X-Sentry-Auth
    std::string authHeader = "X-Sentry-Auth: Sentry sentry_version=7, sentry_key=" + m_publicKey + ", sentry_client=rawrxd-sentry/1.0";
    std::wstring wAuth(authHeader.begin(), authHeader.end());
    WinHttpAddRequestHeaders(hRequest, wAuth.c_str(), -1L, WINHTTP_ADDREQ_FLAG_ADD);

    std::string body = event.dump();
    WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)body.c_str(), (DWORD)body.length(), (DWORD)body.length(), 0);
    WinHttpReceiveResponse(hRequest, NULL);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}
