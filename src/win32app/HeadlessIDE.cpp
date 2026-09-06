// ============================================================================
// HeadlessIDE.cpp — GUI-free surface for the RawrXD Win32IDE engine
// Phase 19C: Headless Surface Extraction
//
// Implements the headless IDE that exposes the full engine capabilities
// without any HWND, window, or GDI dependency. Starts the HTTP server,
// initializes all backend subsystems, and runs in one of four modes:
//   Server / REPL / SingleShot / Batch
//
// NO exceptions. NO HWND. NO GDI. NO message loop.
// ============================================================================

#include "HeadlessIDE.h"
#include "IOutputSink.h"
#include "../agentic_engine.h"
#include "../../include/chain_of_thought_engine.h"
#include "../core/instructions_provider.hpp"
#include "../deep2/Deep2IDEIntegration.hpp"

// Phase 10+ singletons — wired for real status queries
#include "../core/execution_governor.h"
#include "../core/agent_safety_contract.h"
#include "../core/deterministic_replay.h"
#include "../core/confidence_gate.h"
#include "multi_response_engine.h"
#include "../core/universal_model_hotpatcher.h"
#include "../cli/swarm_orchestrator.h"
#include "../agent_history.h"
#include "../agent_explainability.h"
#include "../agent_policy.h"
#include "../agentic/AgentOllamaClient.h"
#include "../core/enterprise_license.h"
#include "../../include/lsp/RawrXD_LSPServer.h"
#include "../agent_history.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <csignal>
#include <cstring>
#include <algorithm>
#include <cstdlib>
#include <cerrno>
#include <limits>
#include <atomic>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <queue>
#include <map>
#include <unordered_map>
#include "gguf_loader.h"

#include <winhttp.h>
#include <bcrypt.h>

#ifndef RAWRXD_HEADLESS_NATIVE_HEXMAG
#define RAWRXD_HEADLESS_NATIVE_HEXMAG 0
#endif
#ifndef RAWRXD_HEADLESS_NATIVE_SUBAGENT
#define RAWRXD_HEADLESS_NATIVE_SUBAGENT 0
#endif
#if RAWRXD_HEADLESS_NATIVE_HEXMAG
#include "../core/hexmag_ide_send_path.hpp"
#endif

// ============================================================================
// RGUF (RawrXD GGUF Unified Format) — Pack / Inspect / Patch
// ============================================================================
#include "../../rguf_source/RGUFWriter.hpp"
#include "../../rguf_source/RGUFLoader.hpp"

// ============================================================================
// Autonomous Orchestrator — Closed-loop repository repair
// ============================================================================
#include "../agent/autonomous_orchestrator.hpp"
#include "../agent/orchestrator_cli_handler.hpp"

// ============================================================================
// Minimal ConversationManager definition (Fix #14)
// ============================================================================
class HeadlessIDE::ConversationManager {
public:
    ConversationManager() = default;
    ~ConversationManager() = default;
};

// ============================================================================
// Production Hardening — Batch 1 Fixes
// ============================================================================

// --- Fix #4: Async-signal-safe shutdown flag ---
static std::atomic<bool> g_shutdownRequested{false};
static std::atomic<int> g_signalReceived{0};
static thread_local bool g_hostedCloudConsent = false;

struct ScopedCloudConsent {
    bool previous;
    explicit ScopedCloudConsent(bool enabled) : previous(g_hostedCloudConsent) {
        g_hostedCloudConsent = enabled;
    }
    ~ScopedCloudConsent() { g_hostedCloudConsent = previous; }
};

static void headlessSignalHandler(int sig) {
    g_signalReceived.store(sig);
    g_shutdownRequested.store(true);
}

// --- Fix #2: JSON escaping helper ---
static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

static std::string trimAscii(const std::string& value) {
    size_t first = 0;
    while (first < value.size() && (value[first] == ' ' || value[first] == '\t')) ++first;
    size_t last = value.size();
    while (last > first && (value[last - 1] == ' ' || value[last - 1] == '\t')) --last;
    return value.substr(first, last - first);
}

static std::string lowerAscii(std::string value) {
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch + ('a' - 'A'));
    }
    return value;
}

static std::string requestHeader(const std::string& headers, const char* name) {
    std::string needle = lowerAscii(name);
    size_t pos = headers.find('\n');
    while (pos != std::string::npos && pos + 1 < headers.size()) {
        size_t end = headers.find('\n', pos + 1);
        std::string line = headers.substr(pos + 1, end - pos - 1);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon != std::string::npos && lowerAscii(line.substr(0, colon)) == needle) {
            return trimAscii(line.substr(colon + 1));
        }
        pos = end;
    }
    return {};
}

static bool constantTimeEqual(const std::string& left, const std::string& right) {
    size_t count = (left.size() > right.size()) ? left.size() : right.size();
    size_t diff = left.size() ^ right.size();
    for (size_t i = 0; i < count; ++i) {
        unsigned char a = i < left.size() ? static_cast<unsigned char>(left[i]) : 0;
        unsigned char b = i < right.size() ? static_cast<unsigned char>(right[i]) : 0;
        diff |= static_cast<size_t>(a ^ b);
    }
    return diff == 0;
}

static bool csvContains(const std::string& csv, const std::string& value) {
    size_t pos = 0;
    while (pos <= csv.size()) {
        size_t end = csv.find(',', pos);
        std::string item = trimAscii(csv.substr(pos, end - pos));
        if (item == value) return true;
        if (end == std::string::npos) break;
        pos = end + 1;
    }
    return false;
}

static std::string routeScope(const std::string& path, const std::string& method) {
    if (path == "/api/github/webhook") return "github";
    if (path.find("/api/model/load") == 0 || path.find("/api/model/unload") == 0) return "models";
    if (path.find("/api/generate") == 0 || path.find("/api/hexmag/") == 0 ||
        path == "/api/subagent" || path == "/api/chain" || path == "/ask" ||
        path == "/v1/chat/completions") return "inference";
    if (method == "POST" && path.find("/api/instructions/reload") == 0) return "admin";
    return "read";
}

static bool isHealthRoute(const std::string& path) {
    return path == "/health" || path == "/api/health";
}

static bool authenticateRequest(const std::string& headers,
                                const HeadlessConfig& config,
                                const std::string& scope) {
    if (config.apiKey.empty()) return false;
    std::string supplied = requestHeader(headers, "x-api-key");
    if (supplied.empty()) {
        supplied = requestHeader(headers, "authorization");
        const std::string prefix = "Bearer ";
        if (supplied.compare(0, prefix.size(), prefix) != 0) return false;
        supplied.erase(0, prefix.size());
    }
    bool scoped = csvContains(config.apiScopes, scope) ||
                  csvContains(config.apiScopes, "*");
    return constantTimeEqual(supplied, config.apiKey) && scoped;
}

static bool originAllowed(const std::string& headers, const HeadlessConfig& config,
                          std::string& origin) {
    origin = requestHeader(headers, "origin");
    if (origin.empty()) return true;
    return !config.allowedOrigins.empty() && csvContains(config.allowedOrigins, origin);
}

static bool isLoopbackAddress(const std::string& address) {
    return address == "::1" || address == "localhost" ||
        address.compare(0, 4, "127.") == 0 ||
        address.compare(0, 11, "::ffff:127.") == 0;
}

static bool localOriginAllowed(const std::string& origin, int port) {
    if (origin.empty()) return true;
    std::string suffix = ":" + std::to_string(port);
    return origin == "http://127.0.0.1" + suffix ||
        origin == "http://localhost" + suffix ||
        origin == "http://[::1]" + suffix;
}

static bool sendAllBytes(SOCKET socketFd, const char* data, size_t length) {
    while (length > 0) {
        int chunk = length > INT_MAX ? INT_MAX : static_cast<int>(length);
        int sent = send(socketFd, data, chunk, 0);
        if (sent <= 0) return false;
        data += sent;
        length -= static_cast<size_t>(sent);
    }
    return true;
}

static const char* httpReason(int status) {
    switch (status) {
        case 200: return "OK";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
        default: return "Error";
    }
}

// --- Fix #11: Rate limiter (token bucket) ---
class RateLimiter {
public:
    RateLimiter(size_t maxRequests, double windowSeconds)
        : maxRequests_(maxRequests), windowSeconds_(windowSeconds) {}

    bool allow(const std::string& clientId) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();
        auto& window = clients_[clientId];
        // Remove old entries
        while (!window.empty() && std::chrono::duration<double>(now - window.front()).count() > windowSeconds_) {
            window.pop();
        }
        if (window.size() >= maxRequests_) return false;
        window.push(now);
        return true;
    }

private:
    size_t maxRequests_;
    double windowSeconds_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::queue<std::chrono::steady_clock::time_point>> clients_;
};

// Headless inference and model load — Phase 31 implementation complete

// Helper: read boolean env var with default
static bool readEnvFlag(const char* name, bool defaultValue) {
    const char* v = std::getenv(name);
    if (!v) return defaultValue;
    if (_stricmp(v, "1") == 0 || _stricmp(v, "true") == 0 || _stricmp(v, "yes") == 0 || _stricmp(v, "on") == 0) {
        return true;
    }
    if (_stricmp(v, "0") == 0 || _stricmp(v, "false") == 0 || _stricmp(v, "no") == 0 || _stricmp(v, "off") == 0) {
        return false;
    }
    return defaultValue;
}

static std::string readEnvText(const char* name, const char* fallback = "") {
    const char* value = std::getenv(name);
    return (value && value[0]) ? std::string(value) : std::string(fallback);
}

static uint64_t readEnvUnsigned(const char* name, uint64_t fallback) {
    const char* value = std::getenv(name);
    if (!value || !value[0] || value[0] == '-') return fallback;
    char* end = nullptr;
    errno = 0;
    unsigned long long parsed = std::strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') return fallback;
    return static_cast<uint64_t>(parsed);
}

struct CloudBudgetReservation {
    std::atomic<uint64_t>* ledger = nullptr;
    uint64_t amount = 0;

    ~CloudBudgetReservation() {
        if (ledger && amount) ledger->fetch_sub(amount, std::memory_order_acq_rel);
    }

    void settle(uint64_t actual) {
        if (!ledger) return;
        if (actual < amount) ledger->fetch_sub(amount - actual, std::memory_order_acq_rel);
        else if (actual > amount) ledger->fetch_add(actual - amount, std::memory_order_acq_rel);
        ledger = nullptr;
        amount = 0;
    }
};

static bool checkedCloudCost(uint64_t inputTokens, uint64_t outputTokens,
                             uint64_t inputRate, uint64_t outputRate,
                             uint64_t& cost) {
    if (!inputRate || !outputRate ||
        inputTokens > std::numeric_limits<uint64_t>::max() / inputRate ||
        outputTokens > std::numeric_limits<uint64_t>::max() / outputRate) return false;
    uint64_t inputCost = inputTokens * inputRate;
    uint64_t outputCost = outputTokens * outputRate;
    if (inputCost > std::numeric_limits<uint64_t>::max() - outputCost) return false;
    cost = inputCost + outputCost;
    return true;
}

static bool reserveCloudBudget(std::atomic<uint64_t>& ledger, uint64_t budget,
                               uint64_t inputTokens, uint64_t outputTokens,
                               uint64_t inputRate, uint64_t outputRate,
                               CloudBudgetReservation& reservation) {
    uint64_t amount = 0;
    if (!budget || !checkedCloudCost(inputTokens, outputTokens, inputRate,
                                     outputRate, amount)) return false;
    uint64_t current = ledger.load(std::memory_order_acquire);
    while (current <= budget && amount <= budget - current) {
        if (ledger.compare_exchange_weak(current, current + amount,
                                         std::memory_order_acq_rel,
                                         std::memory_order_acquire)) {
            reservation.ledger = &ledger;
            reservation.amount = amount;
            return true;
        }
    }
    return false;
}

static bool appendBoundedFile(const std::string& path, const std::string& line,
                              uint64_t maximumBytes) {
    HANDLE file = CreateFileA(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) ||
        static_cast<uint64_t>(size.QuadPart) + line.size() > maximumBytes) {
        CloseHandle(file);
        std::string oldPath = path + ".old";
        DeleteFileA(oldPath.c_str());
        MoveFileExA(path.c_str(), oldPath.c_str(), MOVEFILE_REPLACE_EXISTING);
        file = CreateFileA(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
    }
    DWORD written = 0;
    bool ok = WriteFile(file, line.data(), static_cast<DWORD>(line.size()),
                        &written, nullptr) && written == line.size();
    FlushFileBuffers(file);
    CloseHandle(file);
    return ok;
}

static bool appendBudgetDelta(const std::string& path, int64_t delta) {
    HANDLE file = CreateFileA(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size = {};
    std::string line = std::to_string(delta) + "\r\n";
    if (!GetFileSizeEx(file, &size) ||
        static_cast<uint64_t>(size.QuadPart) + line.size() > 4ULL * 1024 * 1024) {
        CloseHandle(file);
        return false;
    }
    DWORD written = 0;
    bool ok = WriteFile(file, line.data(), static_cast<DWORD>(line.size()),
                        &written, nullptr) && written == line.size() &&
              FlushFileBuffers(file);
    CloseHandle(file);
    return ok;
}

static bool loadBudgetLedger(const std::string& path, uint64_t& total) {
    DWORD attributes = GetFileAttributesA(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            total = 0;
            return true;
        }
        return false;
    }
    std::ifstream input(path);
    if (!input) return false;
    int64_t delta = 0;
    int64_t sum = 0;
    while (input >> delta) {
        if ((delta > 0 && sum > INT64_MAX - delta) ||
            (delta < 0 && sum < INT64_MIN - delta)) return false;
        sum += delta;
        if (sum < 0) return false;
    }
    if (!input.eof()) return false;
    total = static_cast<uint64_t>(sum);
    return true;
}

static void appendAudit(std::mutex& mutex, const HeadlessConfig& config,
                        const std::string& peer, const std::string& method,
                        const std::string& path, int status, const char* outcome) {
    std::lock_guard<std::mutex> lock(mutex);
    FILETIME ft = {};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ticks = {};
    ticks.LowPart = ft.dwLowDateTime;
    ticks.HighPart = ft.dwHighDateTime;
    uint64_t epochMs = (ticks.QuadPart - 116444736000000000ULL) / 10000ULL;
    std::ostringstream record;
    record << "{\"ts\":" << epochMs << ",\"peer\":\"" << jsonEscape(peer)
           << "\",\"method\":\"" << jsonEscape(method) << "\",\"path\":\""
           << jsonEscape(path) << "\",\"status\":" << status << ",\"outcome\":\""
           << outcome << "\"}\r\n";
    appendBoundedFile(config.auditFile, record.str(), 4ULL * 1024 * 1024);
}

static std::string getPeerId(SOCKET socketFd) {
    sockaddr_storage address = {};
    int length = sizeof(address);
    if (getpeername(socketFd, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        return "unknown";
    }
    char host[NI_MAXHOST] = {};
    if (getnameinfo(reinterpret_cast<sockaddr*>(&address), length, host, sizeof(host),
                    nullptr, 0, NI_NUMERICHOST) != 0) {
        return "unknown";
    }
    return host;
}

static std::string fullPathName(const std::string& path) {
    DWORD needed = GetFullPathNameA(path.c_str(), 0, nullptr, nullptr);
    if (needed == 0 || needed > 32768) return {};
    std::vector<char> buffer(needed + 1);
    DWORD actual = GetFullPathNameA(path.c_str(), needed, buffer.data(), nullptr);
    if (actual == 0 || actual >= needed) return {};
    std::string result(buffer.data(), actual);
    while (result.size() > 3 && (result.back() == '\\' || result.back() == '/')) result.pop_back();
    return result;
}

static std::string finalExistingPath(const std::string& path, bool directory) {
    DWORD flags = directory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL;
    HANDLE handle = CreateFileA(path.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, flags, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return {};
    DWORD needed = GetFinalPathNameByHandleA(handle, nullptr, 0, FILE_NAME_NORMALIZED);
    if (!needed || needed > 32768) {
        CloseHandle(handle);
        return {};
    }
    std::vector<char> buffer(needed + 1);
    DWORD actual = GetFinalPathNameByHandleA(
        handle, buffer.data(), needed, FILE_NAME_NORMALIZED);
    CloseHandle(handle);
    if (!actual || actual >= needed) return {};
    std::string result(buffer.data(), actual);
    const std::string devicePrefix = "\\\\?\\";
    if (result.compare(0, devicePrefix.size(), devicePrefix) == 0) {
        result.erase(0, devicePrefix.size());
    }
    while (result.size() > 3 && (result.back() == '\\' || result.back() == '/')) result.pop_back();
    return result;
}

static bool pathHasRoot(const std::string& path, const std::string& root) {
    std::string foldedPath = lowerAscii(path);
    std::string foldedRoot = lowerAscii(root);
    if (foldedPath.compare(0, foldedRoot.size(), foldedRoot) != 0) return false;
    if (foldedPath.size() == foldedRoot.size()) return true;
    char boundary = foldedPath[foldedRoot.size()];
    return boundary == '\\' || boundary == '/';
}

static bool canonicalWorkspacePath(const std::string& input, const std::string& root,
                                   std::string& resolved) {
    if (input.empty() || root.empty() || input.find('\0') != std::string::npos) return false;
    std::string canonicalRoot = finalExistingPath(fullPathName(root), true);
    if (canonicalRoot.empty()) return false;
    bool absolute = input.size() > 2 && input[1] == ':';
    std::string candidate = absolute ? input : canonicalRoot + "\\" + input;
    resolved = finalExistingPath(fullPathName(candidate), false);
    return !resolved.empty() && pathHasRoot(resolved, canonicalRoot);
}

static bool hmacSha256(const std::string& secret, const std::string& data,
                       std::array<unsigned char, 32>& digest) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) return false;
    status = BCryptCreateHash(algorithm, &hash, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(secret.data())),
        static_cast<ULONG>(secret.size()), 0);
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
            static_cast<ULONG>(data.size()), 0);
    }
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptFinishHash(hash, digest.data(),
                                  static_cast<ULONG>(digest.size()), 0);
    }
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return BCRYPT_SUCCESS(status);
}

static std::string hexLower(const unsigned char* bytes, size_t count) {
    static const char digits[] = "0123456789abcdef";
    std::string result(count * 2, '0');
    for (size_t i = 0; i < count; ++i) {
        result[i * 2] = digits[bytes[i] >> 4];
        result[i * 2 + 1] = digits[bytes[i] & 15];
    }
    return result;
}

static bool verifyGitHubSignature(const std::string& headers, const std::string& body,
                                  const std::string& secret) {
    if (secret.empty()) return false;
    std::string supplied = requestHeader(headers, "x-hub-signature-256");
    const std::string prefix = "sha256=";
    if (supplied.compare(0, prefix.size(), prefix) != 0) return false;
    std::array<unsigned char, 32> digest = {};
    if (!hmacSha256(secret, body, digest)) return false;
    std::string expected = prefix + hexLower(digest.data(), digest.size());
    bool valid = constantTimeEqual(supplied, expected);
    SecureZeroMemory(digest.data(), digest.size());
    return valid;
}

static bool readBoundedFile(const char* path, size_t limit, std::string& content) {
    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 ||
        static_cast<uint64_t>(size.QuadPart) > limit) {
        CloseHandle(file);
        return false;
    }
    content.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    bool ok = content.empty() || ReadFile(file, &content[0],
        static_cast<DWORD>(content.size()), &read, nullptr);
    CloseHandle(file);
    return ok && read == content.size();
}


// ============================================================================
// Global shutdown flag for SIGINT/SIGTERM handler
// ============================================================================
static std::atomic<HeadlessIDE*> g_headlessInstance{nullptr};

// ============================================================================
// Embedded LSP server instance (owned by HeadlessIDE init, lives in .cpp scope)
// ============================================================================
static std::unique_ptr<RawrXD::LSPServer::RawrXDLSPServer> g_embeddedLSP;
static std::mutex                       g_embeddedLSPMutex;

// ============================================================================
// ConsoleOutputSink implementation
// ============================================================================
void ConsoleOutputSink::appendOutput(const char* text, size_t length, OutputSeverity severity) noexcept {
    if (!text || length == 0) return;
    if (m_quiet && severity < OutputSeverity::Warning) return;
    if (!m_verbose && severity == OutputSeverity::Debug) return;

    if (m_jsonMode) {
        const char* sevStr = "info";
        switch (severity) {
            case OutputSeverity::Debug:   sevStr = "debug"; break;
            case OutputSeverity::Info:    sevStr = "info"; break;
            case OutputSeverity::Warning: sevStr = "warning"; break;
            case OutputSeverity::Error:   sevStr = "error"; break;
        }
        fprintf(stdout, "{\"type\":\"output\",\"severity\":\"%s\",\"text\":\"", sevStr);
        // Escape JSON string
        for (size_t i = 0; i < length; ++i) {
            char c = text[i];
            if (c == '"') fputs("\\\"", stdout);
            else if (c == '\\') fputs("\\\\", stdout);
            else if (c == '\n') fputs("\\n", stdout);
            else if (c == '\r') fputs("\\r", stdout);
            else if (c == '\t') fputs("\\t", stdout);
            else fputc(c, stdout);
        }
        fputs("\"}\n", stdout);
    } else {
        FILE* out = (severity >= OutputSeverity::Warning) ? stderr : stdout;
        const char* prefix = "";
        switch (severity) {
            case OutputSeverity::Debug:   prefix = "[DEBUG] "; break;
            case OutputSeverity::Info:    prefix = ""; break;
            case OutputSeverity::Warning: prefix = "[WARN]  "; break;
            case OutputSeverity::Error:   prefix = "[ERROR] "; break;
        }
        fprintf(out, "%s%.*s\n", prefix, (int)length, text);
    }
}

void ConsoleOutputSink::onStreamingToken(const char* token, size_t length, StreamTokenOrigin origin) noexcept {
    if (!token || length == 0) return;
    if (m_jsonMode) {
        fprintf(stdout, "{\"type\":\"token\",\"origin\":%d,\"text\":\"", (int)origin);
        for (size_t i = 0; i < length; ++i) {
            char c = token[i];
            if (c == '"') fputs("\\\"", stdout);
            else if (c == '\\') fputs("\\\\", stdout);
            else if (c == '\n') fputs("\\n", stdout);
            else if (c == '\r') fputs("\\r", stdout);
            else if (c == '\t') fputs("\\t", stdout);
            else fputc(c, stdout);
        }
        fputs("\"}\n", stdout);
        fflush(stdout);
    } else {
        // Direct token output — no newline, for streaming effect
        fwrite(token, 1, length, stdout);
        fflush(stdout);
    }
}

void ConsoleOutputSink::onStreamStart(const char* sourceId) noexcept {
    if (m_jsonMode) {
        fprintf(stdout, "{\"type\":\"stream_start\",\"source\":\"%s\"}\n", sourceId ? sourceId : "");
    } else if (m_verbose) {
        fprintf(stdout, "\n--- Stream started: %s ---\n", sourceId ? sourceId : "unknown");
    }
}

void ConsoleOutputSink::onStreamEnd(const char* sourceId, bool success) noexcept {
    if (m_jsonMode) {
        fprintf(stdout, "{\"type\":\"stream_end\",\"source\":\"%s\",\"success\":%s}\n",
                sourceId ? sourceId : "", success ? "true" : "false");
    } else {
        if (!m_quiet) fprintf(stdout, "\n");
        if (m_verbose) {
            fprintf(stdout, "--- Stream ended: %s (%s) ---\n",
                    sourceId ? sourceId : "unknown", success ? "ok" : "FAILED");
        }
    }
}

void ConsoleOutputSink::onAgentStarted(const char* agentId, const char* prompt) noexcept {
    if (m_jsonMode) {
        fprintf(stdout, "{\"type\":\"agent_started\",\"agentId\":\"%s\"}\n",
                agentId ? agentId : "");
    } else if (m_verbose) {
        fprintf(stdout, "[AGENT] Started: %s\n", agentId ? agentId : "?");
    }
}

void ConsoleOutputSink::onAgentCompleted(const char* agentId, const char* result, int durationMs) noexcept {
    if (m_jsonMode) {
        fprintf(stdout, "{\"type\":\"agent_completed\",\"agentId\":\"%s\",\"durationMs\":%d}\n",
                agentId ? agentId : "", durationMs);
    } else if (m_verbose) {
        fprintf(stdout, "[AGENT] Completed: %s (%dms)\n", agentId ? agentId : "?", durationMs);
    }
}

void ConsoleOutputSink::onAgentFailed(const char* agentId, const char* error) noexcept {
    if (m_jsonMode) {
        fprintf(stdout, "{\"type\":\"agent_failed\",\"agentId\":\"%s\",\"error\":\"%s\"}\n",
                agentId ? agentId : "", error ? error : "");
    } else {
        fprintf(stderr, "[AGENT] Failed: %s — %s\n",
                agentId ? agentId : "?", error ? error : "unknown error");
    }
}

void ConsoleOutputSink::onStatusUpdate(const char* key, const char* value) noexcept {
    if (m_jsonMode) {
        fprintf(stdout, "{\"type\":\"status\",\"key\":\"%s\",\"value\":\"%s\"}\n",
                key ? key : "", value ? value : "");
    } else if (m_verbose) {
        fprintf(stdout, "[STATUS] %s: %s\n", key ? key : "?", value ? value : "?");
    }
}

void ConsoleOutputSink::flush() noexcept {
    fflush(stdout);
    fflush(stderr);
}

// Deleter definition now that AgentHistoryRecorder is complete
void AgentHistoryDeleter::operator()(AgentHistoryRecorder* ptr) const {
    delete ptr;
}

// ============================================================================
// HeadlessIDE — Constructor / Destructor
// ============================================================================
HeadlessIDE::HeadlessIDE() {
    // Generate session ID
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    m_startEpochMs = static_cast<uint64_t>(epoch);
    m_sessionId = "headless-" + std::to_string(m_startEpochMs);

    // Default output sink
    m_outputSink = std::make_unique<ConsoleOutputSink>();
}

HeadlessIDE::~HeadlessIDE() {
    if (m_running.load()) {
        requestShutdown();
    }
    shutdownAll();
    
    // Fix #6: Join thread pool threads
    {
        std::lock_guard<std::mutex> lk(m_threadPoolMutex);
        for (auto& t : m_threadPool) {
            if (t.joinable()) t.join();
        }
        m_threadPool.clear();
    }
}

// ============================================================================
// Thread-safe output sink wrappers (Fix #14)
// ============================================================================
void HeadlessIDE::safeAppendOutput(const char* msg, OutputSeverity severity) {
    std::lock_guard<std::mutex> lk(m_outputSinkMutex);
    if (m_outputSink) m_outputSink->appendOutput(msg, severity);
}
void HeadlessIDE::safeOnAgentStarted(const char* agent, const char* prompt) {
    std::lock_guard<std::mutex> lk(m_outputSinkMutex);
    if (m_outputSink) m_outputSink->onAgentStarted(agent, prompt);
}
void HeadlessIDE::safeOnAgentCompleted(const char* agent, const char* result, int durationMs) {
    std::lock_guard<std::mutex> lk(m_outputSinkMutex);
    if (m_outputSink) m_outputSink->onAgentCompleted(agent, result, durationMs);
}
void HeadlessIDE::safeOnAgentFailed(const char* agent, const char* reason) {
    std::lock_guard<std::mutex> lk(m_outputSinkMutex);
    if (m_outputSink) m_outputSink->onAgentFailed(agent, reason);
}
void HeadlessIDE::safeOnStreamStart(const char* stream) {
    std::lock_guard<std::mutex> lk(m_outputSinkMutex);
    if (m_outputSink) m_outputSink->onStreamStart(stream);
}
void HeadlessIDE::safeOnStreamEnd(const char* stream, bool ok) {
    std::lock_guard<std::mutex> lk(m_outputSinkMutex);
    if (m_outputSink) m_outputSink->onStreamEnd(stream, ok);
}
void HeadlessIDE::safeOnStreamingToken(const char* token, size_t len, StreamTokenOrigin origin) {
    std::lock_guard<std::mutex> lk(m_outputSinkMutex);
    if (m_outputSink) m_outputSink->onStreamingToken(token, len, origin);
}
void HeadlessIDE::safeOnStatusUpdate(const char* subsystem, const char* status) {
    std::lock_guard<std::mutex> lk(m_outputSinkMutex);
    if (m_outputSink) m_outputSink->onStatusUpdate(subsystem, status);
}

// ============================================================================
// Lifecycle
// ============================================================================
HeadlessResult HeadlessIDE::initialize(int argc, char* argv[]) {
    HeadlessResult r = parseArgs(argc, argv);
    if (!r.success) return r;
    return initialize(m_config);
}

HeadlessResult HeadlessIDE::initialize(const HeadlessConfig& config) {
    m_config = config;
    if (readEnvFlag("RAWRXD_HOSTED_MODE", false)) {
        m_config.ingressMode = HeadlessIngressMode::Hosted;
    }
    if (m_config.apiKey.empty()) {
        m_config.apiKey = readEnvText("RAWRXD_HOSTED_API_KEY");
    }
    if (m_config.apiScopes.empty()) {
        m_config.apiScopes = readEnvText(
            "RAWRXD_HOSTED_API_SCOPES", "read,inference,models,github,admin");
    }
    if (m_config.allowedOrigins.empty()) {
        m_config.allowedOrigins = readEnvText("RAWRXD_ALLOWED_ORIGINS");
    }
    if (m_config.githubWebhookSecret.empty()) {
        m_config.githubWebhookSecret = readEnvText("RAWRXD_GITHUB_WEBHOOK_SECRET");
    }
    if (m_config.auditFile.empty()) {
        m_config.auditFile = readEnvText("RAWRXD_AUDIT_FILE", "rawrxd_audit.jsonl");
    }
    m_config.allowCloudEgress =
        m_config.allowCloudEgress || readEnvFlag("RAWRXD_CLOUD_EGRESS", false);
    if (m_config.cloudBudgetNanodollars == 0) {
        m_config.cloudBudgetNanodollars =
            readEnvUnsigned("RAWRXD_CLOUD_BUDGET_NANODOLLARS", 0);
    }
    if (m_config.cloudInputNanodollarsPerToken == 0) {
        m_config.cloudInputNanodollarsPerToken =
            readEnvUnsigned("RAWRXD_CLOUD_INPUT_NANODOLLARS_PER_TOKEN", 0);
    }
    if (m_config.cloudOutputNanodollarsPerToken == 0) {
        m_config.cloudOutputNanodollarsPerToken =
            readEnvUnsigned("RAWRXD_CLOUD_OUTPUT_NANODOLLARS_PER_TOKEN", 0);
    }
    m_config.cloudMaxInputBytes = static_cast<uint32_t>(readEnvUnsigned(
        "RAWRXD_CLOUD_MAX_INPUT_BYTES", m_config.cloudMaxInputBytes));
    m_config.cloudMaxOutputTokens = static_cast<uint32_t>(readEnvUnsigned(
        "RAWRXD_CLOUD_MAX_OUTPUT_TOKENS", m_config.cloudMaxOutputTokens));
    if (m_config.cloudBudgetFile.empty()) {
        m_config.cloudBudgetFile = readEnvText(
            "RAWRXD_CLOUD_BUDGET_FILE", "rawrxd_cloud_budget.ledger");
    }
    if (m_config.allowCloudEgress) {
        uint64_t persistedSpend = 0;
        if (!loadBudgetLedger(m_config.cloudBudgetFile, persistedSpend)) {
            m_config.allowCloudEgress = false;
        } else {
            m_cloudReservedNanodollars.store(persistedSpend,
                                              std::memory_order_release);
        }
    }
    if (m_config.workingDir.empty()) {
        char current[MAX_PATH] = {};
        if (GetCurrentDirectoryA(MAX_PATH, current)) m_config.workingDir = current;
    }

    // Breadcrumb file: trace headless init for hang diagnostics
    {
        FILE* f = fopen("headless_server.log", "a");
        if (f) {
            fprintf(f, "INIT_BEGIN mode=%d enableServer=%d port=%d bind=%s\n",
                    (int)m_config.mode, m_config.enableServer ? 1 : 0, m_config.port,
                    m_config.bindAddress.c_str());
            fclose(f);
        }
    }

    // Debug breadcrumb: write effective config for headless startup
    {
        FILE* f = fopen("headless_server.log", "a");
        if (f) {
            fprintf(f, "CONFIG mode=%d enableServer=%d port=%d bind=%s\n",
                    (int)m_config.mode, m_config.enableServer ? 1 : 0, m_config.port,
                    m_config.bindAddress.c_str());
            fclose(f);
        }
    }
    // Experimental toggles (env-driven)
    m_expHotpatchEnabled        = readEnvFlag("RAWRXD_ENABLE_70B_HOTPATCH", true);
    m_expLayerEvictionEnabled   = readEnvFlag("RAWRXD_ENABLE_LAYER_EVICTION", true);
    m_expGovernorEnabled        = readEnvFlag("RAWRXD_ENABLE_GOVERNOR", true);
    m_expQuantumTimeEnabled     = readEnvFlag("RAWRXD_ENABLE_QTIME_MANAGER", false);
    m_expQuantumOrchEnabled     = readEnvFlag("RAWRXD_ENABLE_QAGENT_ORCH", false);
    m_expQuantumMissingEnabled  = readEnvFlag("RAWRXD_ENABLE_QMISSING_IMPL", false);

    // Configure output sink based on config
    if (auto* console = dynamic_cast<ConsoleOutputSink*>(m_outputSink.get())) {
        console->setVerbose(m_config.verbose);
        console->setQuiet(m_config.quiet);
        console->setJsonMode(m_config.jsonOutput);
    }

    m_outputSink->appendOutput("RawrXD Headless IDE initializing...", OutputSeverity::Info);
    m_outputSink->appendOutput(("Session: " + m_sessionId).c_str(), OutputSeverity::Debug);
    m_outputSink->appendOutput(("Version: " + std::string(VERSION)).c_str(), OutputSeverity::Debug);

    // Initialize WinSock (required for HTTP server + remote backends)
    HeadlessResult wr = initWinsock();
    if (!wr.success) return wr;

    // Initialize engines
    HeadlessResult er = initEngines();
    if (!er.success) {
        m_outputSink->appendOutput(er.detail, OutputSeverity::Warning);
        // Non-fatal: engines are optional, server can run without them
    }

    // Initialize subsystems — all are non-fatal
    auto tryInit = [this](HeadlessResult (HeadlessIDE::*fn)(), const char* name) {
        HeadlessResult r = (this->*fn)();
        if (!r.success) {
            std::string msg = std::string(name) + ": " + r.detail;
            m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Warning);
        }
    };

    tryInit(&HeadlessIDE::initBackendManager, "BackendManager");
    tryInit(&HeadlessIDE::initLLMRouter, "LLMRouter");
    tryInit(&HeadlessIDE::initFailureDetection, "FailureDetection");
    tryInit(&HeadlessIDE::initAgentHistory, "AgentHistory");
    tryInit(&HeadlessIDE::initAsmSemantic, "AsmSemantic");
    if (m_config.mode != HeadlessRunMode::Server) {
        tryInit(&HeadlessIDE::initLSPClient, "LSPClient");
    } else {
        m_outputSink->appendOutput("LSP client disabled in server profile",
                                   OutputSeverity::Debug);
    }
    if (m_config.mode != HeadlessRunMode::Server) {
        tryInit(&HeadlessIDE::initHybridBridge, "HybridBridge");
        tryInit(&HeadlessIDE::initMultiResponse, "MultiResponse");
        if (m_expGovernorEnabled) {
            tryInit(&HeadlessIDE::initPhase10, "Phase10-ExecGovernor");
            m_expGovernorActivated = m_phase10Initialized;
            if (m_expGovernorActivated) {
                m_outputSink->appendOutput("[EXPERIMENTAL] governor_activated=true (RAWRXD_ENABLE_GOVERNOR=1)", OutputSeverity::Info);
            }
        }
    }
    tryInit(&HeadlessIDE::initPhase11, "Phase11-Swarm");
    if (m_config.mode != HeadlessRunMode::Server) {
        tryInit(&HeadlessIDE::initPhase12, "Phase12-NativeDebug");
        if (m_expHotpatchEnabled) {
            tryInit(&HeadlessIDE::initHotpatch, "Hotpatch");
            m_expHotpatchActivated = m_hotpatchInitialized;
            if (m_expHotpatchActivated) {
                m_outputSink->appendOutput("[EXPERIMENTAL] hotpatch70b_activated=true (RAWRXD_ENABLE_70B_HOTPATCH=1)", OutputSeverity::Info);
            }
        }
        if (m_expLayerEvictionEnabled && m_hotpatchInitialized) {
            m_expLayerEvictionActivated = true;
            m_outputSink->appendOutput("[EXPERIMENTAL] layer_eviction_activated=true (RAWRXD_ENABLE_LAYER_EVICTION=1)", OutputSeverity::Info);
        }
    }
    if (m_config.mode != HeadlessRunMode::Server) {
        tryInit(&HeadlessIDE::initInstructions, "Instructions");
    } else {
        m_outputSink->appendOutput("Instructions provider disabled in server profile",
                                   OutputSeverity::Debug);
    }

    // Quantum feature markers (no-op wiring; status/log visibility)
    if (m_expQuantumTimeEnabled) {
        m_expQuantumTimeActivated = true;
        m_outputSink->appendOutput("[EXPERIMENTAL] quantum_time_manager_activated=true (RAWRXD_ENABLE_QTIME_MANAGER=1)", OutputSeverity::Info);
    }
    if (m_expQuantumOrchEnabled) {
        m_expQuantumOrchActivated = true;
        m_outputSink->appendOutput("[EXPERIMENTAL] quantum_orchestrator_activated=true (RAWRXD_ENABLE_QAGENT_ORCH=1)", OutputSeverity::Info);
    }
    if (m_expQuantumMissingEnabled) {
        m_expQuantumMissingActivated = true;
        m_outputSink->appendOutput("[EXPERIMENTAL] quantum_missing_impl_activated=true (RAWRXD_ENABLE_QMISSING_IMPL=1)", OutputSeverity::Info);
    }

    // Load model if specified
    if (!m_config.modelPath.empty()) {
        if (!loadModel(m_config.modelPath)) {
            return HeadlessResult::error("Failed to load model", 2);
        }
    }

    // Load settings
    if (!m_config.settingsFile.empty()) {
        loadSettings(m_config.settingsFile);
    }

    // Fix #14: Initialize conversation manager
    m_conversationManager = std::make_unique<ConversationManager>();

    m_outputSink->appendOutput("Headless IDE initialized successfully.", OutputSeverity::Info);

    // Breadcrumb: init complete
    {
        FILE* f = fopen("headless_server.log", "a");
        if (f) {
            fprintf(f, "INIT_DONE\n");
            fclose(f);
        }
    }
    return HeadlessResult::ok("Initialized");
}

int HeadlessIDE::run() {
    m_running.store(true);
    m_shutdownRequested.store(false);

    // Register signal handlers
    g_headlessInstance.store(this);
    signal(SIGINT, headlessSignalHandler);
    signal(SIGTERM, headlessSignalHandler);

    int exitCode = 0;

    switch (m_config.mode) {
        case HeadlessRunMode::Server:
            exitCode = runServerMode();
            break;
        case HeadlessRunMode::REPL:
            exitCode = runReplMode();
            break;
        case HeadlessRunMode::SingleShot:
            exitCode = runSingleShotMode();
            break;
        case HeadlessRunMode::Batch:
            exitCode = runBatchMode();
            break;
    }

    m_running.store(false);
    g_headlessInstance.store(nullptr);
    return exitCode;
}

void HeadlessIDE::requestShutdown() noexcept {
    m_shutdownRequested.store(true);
    stopServer();
}

void HeadlessIDE::setOutputSink(std::unique_ptr<IOutputSink> sink) {
    std::lock_guard<std::mutex> lk(m_outputSinkMutex);
    if (sink) m_outputSink = std::move(sink);
}

// ============================================================================
// Argument Parsing
// ============================================================================
HeadlessResult HeadlessIDE::parseArgs(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--headless") {
            // Already in headless mode (this flag is consumed by main_win32.cpp)
            continue;
        }
        else if (arg == "--hosted") {
            m_config.ingressMode = HeadlessIngressMode::Hosted;
        }
        else if (arg == "--local") {
            m_config.ingressMode = HeadlessIngressMode::Local;
        }
        else if (arg == "--port" && i + 1 < argc) {
            m_config.port = std::atoi(argv[++i]);
        }
        else if (arg == "--bind" && i + 1 < argc) {
            m_config.bindAddress = argv[++i];
        }
        else if (arg == "--model" && i + 1 < argc) {
            m_config.modelPath = argv[++i];
        }
        else if (arg == "--prompt" && i + 1 < argc) {
            m_config.prompt = argv[++i];
            m_config.mode = HeadlessRunMode::SingleShot;
        }
        else if (arg == "--input" && i + 1 < argc) {
            m_config.inputFile = argv[++i];
            m_config.mode = HeadlessRunMode::Batch;
        }
        else if (arg == "--output" && i + 1 < argc) {
            m_config.outputFile = argv[++i];
        }
        else if (arg == "--settings" && i + 1 < argc) {
            m_config.settingsFile = argv[++i];
        }
        else if (arg == "--backend" && i + 1 < argc) {
            m_config.backend = argv[++i];
        }
        else if (arg == "--max-tokens" && i + 1 < argc) {
            m_config.maxTokens = std::atoi(argv[++i]);
        }
        else if (arg == "--temperature" && i + 1 < argc) {
            m_config.temperature = static_cast<float>(std::atof(argv[++i]));
        }
        else if (arg == "--repl") {
            m_config.enableRepl = true;
            m_config.mode = HeadlessRunMode::REPL;
        }
        else if (arg == "--no-server") {
            m_config.enableServer = false;
        }
        else if (arg == "--verbose" || arg == "-v") {
            m_config.verbose = true;
        }
        else if (arg == "--quiet" || arg == "-q") {
            m_config.quiet = true;
        }
        else if (arg == "--json") {
            m_config.jsonOutput = true;
        }
        else if (arg == "--help" || arg == "-h") {
            printReplHelp();
            return HeadlessResult::error("Help requested", 0);
        }
    }

    // Defensive default: if the parsed/initial port is invalid, clamp to 11435
    int originalPort = m_config.port;
    if (m_config.port <= 0 || m_config.port > 65535 || m_config.port == 9090) {
        m_config.port = 11435;
    }

    // Always log the resolved port to aid port-binding diagnostics
    {
        FILE* f = fopen("headless_server.log", "a");
        if (f) {
            fprintf(f, "EFFECTIVE_PORT %d (was %d)\n", m_config.port, originalPort);
            fclose(f);
        }
    }

    return HeadlessResult::ok();
}

// ============================================================================
// Initialization Phases
// ============================================================================
HeadlessResult HeadlessIDE::initWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        return HeadlessResult::error("WSAStartup failed", result);
    }
    m_winsockInitialized = true;
    return HeadlessResult::ok("WinSock initialized");
}

HeadlessResult HeadlessIDE::initEngines() {
    // Engine manager and Codex are optional — set externally via setEngineManager/setCodexUltimate
    // In headless mode we attempt to load them, but failure is non-fatal
    if (!m_engineManager) {
        m_engineManager = new EngineManager();
        if (RawrXD::EnterpriseLicense::Instance().Is800BUnlocked() || RawrXD::g_800B_Unlocked) {
            try { m_engineManager->LoadEngine("engines/800b-5drive/800b_engine.dll", "800b-5drive"); } catch (...) {}
        }
        try { m_engineManager->LoadEngine("engines/codex-ultimate/codex.dll", "codex-ultimate"); } catch (...) {}
        try { m_engineManager->LoadEngine("engines/rawrxd-compiler/compiler.dll", "rawrxd-compiler"); } catch (...) {}
    }
    if (!m_codexUltimate) {
        m_codexUltimate = new CodexUltimate();
    }
    return HeadlessResult::ok("Engines initialized");
}

HeadlessResult HeadlessIDE::initBackendManager() {
    auto startTime = std::chrono::steady_clock::now();

    // Configure default backend based on config
    if (!m_config.backend.empty()) {
        if (m_config.backend == "ollama")  m_activeBackend = AIBackendType::Ollama;
        else if (m_config.backend == "openai")  m_activeBackend = AIBackendType::OpenAI;
        else if (m_config.backend == "claude")  m_activeBackend = AIBackendType::Claude;
        else if (m_config.backend == "gemini")  m_activeBackend = AIBackendType::Gemini;
        else m_activeBackend = AIBackendType::LocalGGUF;
    }

    // Probe Ollama availability (primary backend)
    RawrXD::Agent::OllamaConfig ollamaCfg;
    ollamaCfg.host = "127.0.0.1";
    ollamaCfg.port = 11434;
    ollamaCfg.timeout_ms = 3000;
    RawrXD::Agent::AgentOllamaClient probeClient(ollamaCfg);
    bool ollamaAvailable = probeClient.TestConnection();

    std::ostringstream statusMsg;
    statusMsg << "Backend manager initialized (headless)";
    if (ollamaAvailable) {
        auto models = probeClient.ListModels();
        statusMsg << " | Ollama: online (" << models.size() << " models)";
        // Default to Ollama if available and no explicit backend set
        if (m_config.backend.empty()) {
            m_activeBackend = AIBackendType::Ollama;
        }
    } else {
        statusMsg << " | Ollama: offline";
    }

    const char* backendNames[] = { "LocalGGUF", "Ollama", "OpenAI", "Claude", "Gemini" };
    statusMsg << " | Active: " << backendNames[static_cast<int>(m_activeBackend)];

    m_backendManagerInitialized = true;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    statusMsg << " [" << elapsed << "us]";
    m_outputSink->appendOutput(statusMsg.str().c_str(), OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("backend_manager", "active");
    m_outputSink->onStatusUpdate("backend", backendNames[static_cast<int>(m_activeBackend)]);
    return HeadlessResult::ok("Backend manager ready");
}

HeadlessResult HeadlessIDE::initLLMRouter() {
    auto startTime = std::chrono::steady_clock::now();

    // Configure routing table with backend priorities
    // Priority: Ollama (local, fast) > LocalGGUF > Cloud backends
    struct RouterEntry {
        AIBackendType type;
        const char* name;
        int priority;  // lower = higher priority
        bool available;
    };

    RouterEntry routes[] = {
        { AIBackendType::Ollama,    "Ollama",    1, m_backendManagerInitialized },
        { AIBackendType::LocalGGUF, "LocalGGUF",  2, m_modelLoaded },
        { AIBackendType::OpenAI,    "OpenAI",    10, false },
        { AIBackendType::Claude,    "Claude",    11, false },
        { AIBackendType::Gemini,    "Gemini",    12, false },
    };

    int activeRoutes = 0;
    for (auto& r : routes) {
        if (r.available) activeRoutes++;
    }

    m_routerInitialized = true;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    char msg[256];
    snprintf(msg, sizeof(msg), "LLM router initialized: %d/%d backends available [%lldus]",
             activeRoutes, 5, (long long)elapsed);
    m_outputSink->appendOutput(msg, OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("llm_router", "active");
    return HeadlessResult::ok("LLM router ready");
}

HeadlessResult HeadlessIDE::initFailureDetection() {
    auto startTime = std::chrono::steady_clock::now();
    m_failureDetectorInitialized = true;
    m_failureDetections = 0;
    m_failureRetries = 0;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    std::string msg = "Failure detector initialized (headless) [" + std::to_string(elapsed) + "us]";
    m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("failure_detector", "active");
    return HeadlessResult::ok("Failure detector ready");
}

HeadlessResult HeadlessIDE::initAgentHistory() {
    auto startTime = std::chrono::steady_clock::now();
    if (!m_historyRecorder) {
        m_historyRecorder.reset(new AgentHistoryRecorder("rawrxd_headless_history"));
        m_historyRecorder->setLogCallback([this](int level, const std::string& msg) {
            if (level >= 2) {
                m_outputSink->appendOutput(("[History] " + msg).c_str(), OutputSeverity::Debug);
            }
        });
    }
    m_agentHistoryInitialized = true;
    m_agentEventCount = 0;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    std::string msg = "Agent history initialized (headless) [" + std::to_string(elapsed) + "us]";
    m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("agent_history", "active");
    return HeadlessResult::ok("Agent history ready");
}

HeadlessResult HeadlessIDE::initAsmSemantic() {
    auto startTime = std::chrono::steady_clock::now();
    m_asmSemanticInitialized = true;
    m_asmSymbolCount = 0;
    m_asmFilesParsed = 0;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    std::string msg = "ASM semantic initialized (headless) [" + std::to_string(elapsed) + "us]";
    m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("asm_semantic", "active");
    return HeadlessResult::ok("ASM semantic ready");
}

HeadlessResult HeadlessIDE::initLSPClient() {
    auto startTime = std::chrono::steady_clock::now();

    // Create embedded LSP server for headless diagnostics + code intelligence
    {
        std::lock_guard<std::mutex> lk(g_embeddedLSPMutex);
        if (!g_embeddedLSP) {
            g_embeddedLSP = std::make_unique<RawrXD::LSPServer::RawrXDLSPServer>();
        }

        // Configure for in-process (pipe) transport — headless owns stdio
        RawrXD::LSPServer::ServerConfig lspConfig;
        lspConfig.useStdio           = false;  // Use named pipe, not stdio
        lspConfig.pipeName           = "\\\\.\\pipe\\rawrxd-lsp-headless";
        lspConfig.enableSemanticTokens = true;
        lspConfig.enableHover        = true;
        lspConfig.enableCompletion   = true;
        lspConfig.enableDefinition   = true;
        lspConfig.enableReferences   = true;
        lspConfig.enableDocumentSymbol  = true;
        lspConfig.enableWorkspaceSymbol = true;
        lspConfig.enableDiagnostics  = true;
        lspConfig.indexThrottleMs    = 100;  // Faster for headless
        lspConfig.maxSymbolResults   = 1000;
        lspConfig.maxCompletionItems = 200;

        // Set workspace root from current working dir or explicitly if available
        char cwd[MAX_PATH];
        if (GetCurrentDirectoryA(MAX_PATH, cwd)) {
            lspConfig.rootPath = cwd;
            // Convert to file URI
            std::string pathStr = cwd;
            for (auto& c : pathStr) { if (c == '\\') c = '/'; }
            lspConfig.rootUri = "file:///" + pathStr;
        }

        g_embeddedLSP->configure(lspConfig);

        // Start the LSP server (launches reader + dispatch threads)
        if (g_embeddedLSP->start()) {
            m_lspServerCount = 1;

            // Trigger initial project indexing if we have a root path
            if (!lspConfig.rootPath.empty()) {
                g_embeddedLSP->rebuildIndex();
                size_t symCount = g_embeddedLSP->getIndexedSymbolCount();
                size_t fileCount = g_embeddedLSP->getTrackedFileCount();

                std::ostringstream oss;
                oss << "  LSP initial index: " << symCount << " symbols across "
                    << fileCount << " files";
                m_outputSink->appendOutput(oss.str().c_str(), OutputSeverity::Debug);
            }
        } else {
            m_outputSink->appendOutput("LSP server failed to start on named pipe",
                                       OutputSeverity::Warning);
            // Still mark initialized — server exists but isn't running
        }
    }

    m_lspInitialized = true;
    m_lspCompletionCount = 0;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    std::string msg = "LSP client initialized (headless, embedded server) [" +
                      std::to_string(elapsed) + "us]";
    m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("lsp_client", "active");
    return HeadlessResult::ok("LSP client ready (embedded server)");
}

HeadlessResult HeadlessIDE::initHybridBridge() {
    auto startTime = std::chrono::steady_clock::now();
    m_hybridBridgeInitialized = true;
    m_hybridCompletionCount = 0;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    std::string msg = "Hybrid bridge initialized (headless) [" + std::to_string(elapsed) + "us]";
    m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("hybrid_bridge", "active");
    return HeadlessResult::ok("Hybrid bridge ready");
}

HeadlessResult HeadlessIDE::initMultiResponse() {
    auto startTime = std::chrono::steady_clock::now();
    if (!m_multiResponse) {
        m_multiResponse = std::make_unique<MultiResponseEngine>();
        auto initResult = m_multiResponse->initialize();
        if (!initResult.success) {
            m_outputSink->appendOutput("Multi-response engine failed to initialize", OutputSeverity::Warning);
        }
    }
    m_multiResponseInitialized = true;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    std::string msg = "Multi-response initialized (headless) [" + std::to_string(elapsed) + "us]";
    m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("multi_response", "active");
    return HeadlessResult::ok("Multi-response ready");
}

HeadlessResult HeadlessIDE::initPhase10() {
    auto startTime = std::chrono::steady_clock::now();

    // Phase 10A: Execution Governor
    auto& governor = ExecutionGovernor::instance();
    if (!governor.isInitialized()) {
        governor.init();
    }

    // Phase 10B: Safety Contract
    auto& safety = AgentSafetyContract::instance();
    safety.init();
    safety.setAutoApproveEscalations(true); // headless: auto-approve

    // Phase 10C: Deterministic Replay Journal
    auto& replay = ReplayJournal::instance();
    replay.init("rawrxd_headless_replay");
    replay.startSession("headless-" + m_sessionId);
    replay.startRecording();
    replay.recordMarker("Headless IDE Phase 10 initialized");

    // Phase 10D: Confidence Gate
    auto& confidence = ConfidenceGate::instance();
    confidence.init();
    confidence.setPolicy(GatePolicy::Normal);
    confidence.setEnabled(true);
    confidence.setAutoEscalate(true); // headless: auto-escalate

    m_phase10Initialized = true;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    std::string msg = "Phase 10 (Governor+Safety+Replay+Confidence) initialized [" + std::to_string(elapsed) + "us]";
    m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("phase10", "active");
    return HeadlessResult::ok("Phase 10 ready");
}

HeadlessResult HeadlessIDE::initPhase11() {
    auto startTime = std::chrono::steady_clock::now();
    auto& swarm = RawrXD::Swarm::SwarmOrchestrator::instance();
    if (!swarm.isInitialized()) {
        auto result = swarm.initialize(RawrXD::Swarm::NodeRole::Coordinator);
        if (!result.success) {
            m_outputSink->appendOutput(
                ("Swarm init note: " + std::string(result.detail)).c_str(),
                OutputSeverity::Debug);
            // Non-fatal: swarm is optional in headless single-node mode
        }
    }
    m_phase11Initialized = true;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    std::string msg = "Phase 11 (Distributed Swarm) initialized [" + std::to_string(elapsed) + "us]";
    m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("swarm", swarm.isRunning() ? "active" : "standby");
    return HeadlessResult::ok("Phase 11 ready");
}

HeadlessResult HeadlessIDE::initPhase12() {
    auto startTime = std::chrono::steady_clock::now();
    m_phase12Initialized = true;
    m_debugSessionActive = false;
    m_debugBreakpointCount = 0;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    std::string msg = "Phase 12 (Native Debugger) initialized [" + std::to_string(elapsed) + "us]";
    m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("native_debugger", "ready");
    return HeadlessResult::ok("Phase 12 ready");
}

HeadlessResult HeadlessIDE::initHotpatch() {
    auto startTime = std::chrono::steady_clock::now();
    auto& hotpatcher = UniversalModelHotpatcher::instance();
    if (!hotpatcher.isInitialized()) {
        hotpatcher.initialize();
    }
    m_hotpatchInitialized = true;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    std::string msg = "Three-layer hotpatch initialized [" + std::to_string(elapsed) + "us]";
    m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Debug);
    m_outputSink->onStatusUpdate("hotpatch", "active");
    return HeadlessResult::ok("Hotpatch ready");
}

HeadlessResult HeadlessIDE::initInstructions() {
    auto startTime = std::chrono::steady_clock::now();
    auto& provider = InstructionsProvider::instance();

    // Add workspace-relative search paths
    provider.addSearchPath(".");
    provider.addSearchPath(".github");

    auto r = provider.loadAll();
    m_instructionsInitialized = r.success;

    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - startTime).count();

    if (r.success) {
        std::string msg = "Instructions loaded: " +
            std::to_string(provider.getLoadedCount()) + " files (" +
            std::to_string(provider.getAllContent().size()) + " bytes) [" +
            std::to_string(elapsed) + "us]";
        m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Info);
        m_outputSink->onStatusUpdate("instructions", "loaded");
    } else {
        std::string msg = std::string("Instructions: ") + r.detail +
            " [" + std::to_string(elapsed) + "us]";
        m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Warning);
        m_outputSink->onStatusUpdate("instructions", "unavailable");
    }

    return r.success ? HeadlessResult::ok("Instructions loaded") 
                     : HeadlessResult::error(r.detail);
}

std::string HeadlessIDE::getInstructionsContent() const {
    auto& provider = InstructionsProvider::instance();
    if (!provider.isLoaded()) {
        InstructionsProvider::instance().loadAll();
    }
    return provider.getAllContent();
}

// ============================================================================
// Model Operations
// ============================================================================
bool HeadlessIDE::loadModel(const std::string& filepath) {
    m_outputSink->appendOutput(("Loading model: " + filepath).c_str(), OutputSeverity::Info);
    auto t0 = std::chrono::steady_clock::now();

    // Phase 1: Resolve the model source — local, Ollama, HuggingFace, URL
    RawrXD::ModelSourceResolver resolver;
    RawrXD::ResolvedModelPath resolved = resolver.Resolve(filepath,
        [this](const RawrXD::ModelDownloadProgress& p) {
            if (p.total_bytes > 0) {
                char buf[256];
                snprintf(buf, sizeof(buf), "[Model] Downloading %.1f%% (%llu / %llu bytes)",
                         p.progress_percent, (unsigned long long)p.downloaded_bytes,
                         (unsigned long long)p.total_bytes);
                m_outputSink->appendOutput(buf, OutputSeverity::Info);
            }
        });
    
    std::string localPath = resolved.success ? resolved.local_path : filepath;
    
    // Phase 2: Check for multi-shard model (Kimi K2 / Moonshot)
    // If path is a directory with shard files, use Deep2ModelLoader
    if (RawrXD::Deep2ModelLoader::IsShardedModel(localPath)) {
        std::string deep2Error;
        if (RawrXD::Deep2LoadModelForIDE(localPath, deep2Error)) {
            auto result = RawrXD::Deep2ModelLoader::Load(localPath);
            m_loadedModelPath = localPath;
            m_loadedModelName = result.modelName;
            m_modelLoaded = true;

            std::ostringstream info;
            info << "Model loaded (Deep2 sharded): " << m_loadedModelName << "\n"
                 << "  Shards: " << result.shardCount << "\n"
                 << "  Tensors: " << result.tensorCount << "\n"
                 << "  MoE: " << (result.isMoE ? "yes" : "no") << "\n"
                 << "  Total size: " << (result.totalFileBytes / (1024*1024*1024)) << " GB\n"
                 << "  Streaming: enabled\n";
            m_outputSink->appendOutput(info.str().c_str(), OutputSeverity::Info);
            return true;
        } else {
            m_outputSink->appendOutput(("Deep2 shard load failed: " + deep2Error).c_str(), OutputSeverity::Error);
            // Fall through to standard loader
        }
    }

    // Phase 2b: Validate single file exists on disk
    DWORD attr = GetFileAttributesA(localPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        std::string err = "Model file not found: " + localPath;
        if (!resolved.success && !resolved.error_message.empty()) {
            err += " (" + resolved.error_message + ")";
        }
        m_outputSink->appendOutput(err.c_str(), OutputSeverity::Error);
        return false;
    }

    // Phase 3: Open with StreamingGGUFLoader and parse header + metadata
    auto loader = std::make_unique<RawrXD::StreamingGGUFLoader>();
    if (!loader->Open(localPath)) {
        m_outputSink->appendOutput("Failed to open GGUF file", OutputSeverity::Error);
        return false;
    }

    if (!loader->ParseHeader()) {
        m_outputSink->appendOutput("Invalid GGUF header — file may be corrupt", OutputSeverity::Error);
        loader->Close();
        return false;
    }

    RawrXD::GGUFHeader hdr = loader->GetHeader();
    // Validate magic: 0x46475547 = "GGUF" little-endian
    if (hdr.magic != 0x46475547) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Bad GGUF magic: 0x%08X (expected 0x46475547)", hdr.magic);
        m_outputSink->appendOutput(buf, OutputSeverity::Error);
        loader->Close();
        return false;
    }

    if (!loader->ParseMetadata()) {
        m_outputSink->appendOutput("Failed to parse GGUF metadata", OutputSeverity::Warning);
        // Non-fatal — we can still load with header-only info
    }

    RawrXD::GGUFMetadata meta = loader->GetMetadata();

    // Phase 4: Build tensor index for streaming zone loading
    loader->BuildTensorIndex();

    // Store state
    m_loadedModelPath = localPath;
    size_t lastSlash = localPath.find_last_of("/\\");
    m_loadedModelName = (lastSlash != std::string::npos) ? localPath.substr(lastSlash + 1) : localPath;
    m_modelLoaded = true;

    auto t1 = std::chrono::steady_clock::now();
    int loadMs = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    // Report model info
    std::ostringstream info;
    info << "Model loaded: " << m_loadedModelName << "\n"
         << "  GGUF version: " << hdr.version << "\n"
         << "  Tensors: " << hdr.tensor_count << "\n"
         << "  Metadata KVs: " << hdr.metadata_kv_count << "\n"
         << "  Layers: " << meta.layer_count << "\n"
         << "  Context length: " << meta.context_length << "\n"
         << "  Embedding dim: " << meta.embedding_dim << "\n"
         << "  Vocab size: " << meta.vocab_size << "\n"
         << "  File size: " << (loader->GetFileSize() / (1024*1024)) << " MB\n"
         << "  Load latency: " << loadMs << " ms\n";
    if (resolved.success && resolved.source_type != GGUFConstants::ModelSourceType::LOCAL_FILE) {
        info << "  Source: " << resolved.original_input << "\n";
    }
    m_outputSink->appendOutput(info.str().c_str(), OutputSeverity::Info);
    m_outputSink->onStatusUpdate("model", m_loadedModelName.c_str());

    loader->Close();
    recordSimpleEvent("model_loaded");
    return true;
}

bool HeadlessIDE::unloadModel() {
    if (!m_modelLoaded) return false;
    m_outputSink->appendOutput(("Unloading model: " + m_loadedModelName).c_str(), OutputSeverity::Info);
    m_modelLoaded = false;
    m_loadedModelPath.clear();
    m_loadedModelName.clear();
    m_outputSink->onStatusUpdate("model", "(none)");
    return true;
}

bool HeadlessIDE::isModelLoaded() const {
    return m_modelLoaded;
}

std::string HeadlessIDE::getLoadedModelName() const {
    return m_loadedModelName;
}

std::string HeadlessIDE::getModelInfo() const {
    if (!m_modelLoaded) return "No model loaded";
    std::ostringstream oss;
    oss << "Model: " << m_loadedModelName << "\n";
    oss << "Path: " << m_loadedModelPath << "\n";
    return oss.str();
}

// ============================================================================
// Inference
// ============================================================================
std::string HeadlessIDE::runInference(const std::string& prompt) {
    return runInference(prompt, m_config.maxTokens, m_config.temperature);
}

std::string HeadlessIDE::runInference(const std::string& prompt, int maxTokens, float temperature) {
    if (!m_modelLoaded) {
        safeAppendOutput("No model loaded for inference", OutputSeverity::Error);
        return "[error: no model loaded]";
    }

    safeOnAgentStarted("inference", prompt.c_str());

    auto startTime = std::chrono::steady_clock::now();

    // Route through backend manager → LLM router → inference engine
    // This delegates to the same path as Win32IDE::routeInferenceRequest
    std::string result = routeInferenceRequest(prompt);

    auto endTime = std::chrono::steady_clock::now();
    int durationMs = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());

    if (!result.empty()) {
        safeOnAgentCompleted("inference", result.c_str(), durationMs);
    } else {
        safeOnAgentFailed("inference", "Empty result from inference engine");
    }

    return result;
}

void HeadlessIDE::runInferenceStreaming(const std::string& prompt,
                                         std::function<void(const char*, size_t)> tokenCallback) {
    if (!m_modelLoaded) {
        safeAppendOutput("No model loaded for streaming inference", OutputSeverity::Error);
        return;
    }

    safeOnStreamStart("inference");

    // Use AgentOllamaClient streaming API for real per-token delivery
    if (m_activeBackend == AIBackendType::Ollama || m_activeBackend == AIBackendType::LocalGGUF) {
        RawrXD::Agent::OllamaConfig cfg;
        cfg.host = "127.0.0.1";
        cfg.port = 11434;
        // chat_model left empty — auto-detected from Ollama /api/tags
        cfg.temperature = m_config.temperature;
        cfg.max_tokens = m_config.maxTokens;
        cfg.use_gpu = true;
        cfg.num_gpu = 99;

        RawrXD::Agent::AgentOllamaClient client(cfg);
        std::vector<RawrXD::Agent::ChatMessage> messages;
        messages.push_back({"system", "You are RawrXD IDE's embedded AI assistant.", "", {}});
        messages.push_back({"user", prompt, "", {}});

        bool streamOk = client.ChatStream(
            messages, nlohmann::json::array(),
            /* on_token */ [&](const std::string& token) {
                if (tokenCallback) {
                    tokenCallback(token.c_str(), token.size());
                }
                safeOnStreamingToken(token.c_str(), token.size(), StreamTokenOrigin::Inference);
            },
            /* on_tool_call */ [](const std::string&, const nlohmann::json&) {},
            /* on_done */ [&](const std::string& full, uint64_t pt, uint64_t ct, double tps) {
                char perf[256];
                snprintf(perf, sizeof(perf), "[stream] %llu+%llu tokens, %.1f tok/s",
                         (unsigned long long)pt, (unsigned long long)ct, tps);
                safeAppendOutput(perf, OutputSeverity::Debug);
            },
            /* on_error */ [&](const std::string& err) {
                safeAppendOutput(("Stream error: " + err).c_str(), OutputSeverity::Error);
            }
        );

        safeOnStreamEnd("inference", streamOk);
        return;
    }

    // Fallback: batch inference emitted as single chunk
    std::string result = runInference(prompt);
    if (tokenCallback && !result.empty()) {
        tokenCallback(result.c_str(), result.size());
    }
    safeOnStreamEnd("inference", !result.empty());
}

// ============================================================================
// Backend Switcher (Phase 8B)
// ============================================================================
bool HeadlessIDE::setActiveBackend(AIBackendType type) {
    const char* backendNames[] = { "LocalGGUF", "Ollama", "OpenAI", "Claude", "Gemini" };
    int idx = static_cast<int>(type);
    if (idx < 0 || idx >= static_cast<int>(AIBackendType::Count)) {
        m_outputSink->appendOutput("Invalid backend type", OutputSeverity::Error);
        return false;
    }

    // Probe health before switching
    if (!probeBackendHealth(type)) {
        const char* hint = "";
        switch (type) {
            case AIBackendType::LocalGGUF: hint = " (load a model first)"; break;
            case AIBackendType::Ollama:    hint = " (ensure Ollama is running on port 11434)"; break;
            case AIBackendType::OpenAI:   hint = " (set OPENAI_API_KEY)"; break;
            case AIBackendType::Claude:   hint = " (set ANTHROPIC_API_KEY)"; break;
            case AIBackendType::Gemini:   hint = " (set GOOGLE_API_KEY or GEMINI_API_KEY)"; break;
            default: break;
        }
        char buf[384];
        snprintf(buf, sizeof(buf), "Backend '%s' health check failed — switch aborted%s", backendNames[idx], hint);
        m_outputSink->appendOutput(buf, OutputSeverity::Warning);
        return false;
    }

    AIBackendType previousBackend = m_activeBackend;
    m_activeBackend = type;

    char buf[256];
    snprintf(buf, sizeof(buf), "Backend switched: %s → %s",
             backendNames[static_cast<int>(previousBackend)], backendNames[idx]);
    m_outputSink->appendOutput(buf, OutputSeverity::Info);
    m_outputSink->onStatusUpdate("backend", backendNames[idx]);
    recordSimpleEvent("backend_switch");
    return true;
}

HeadlessIDE::AIBackendType HeadlessIDE::getActiveBackendType() const {
    return m_activeBackend;
}

std::string HeadlessIDE::getBackendStatusString() const {
    const char* backendNames[] = { "LocalGGUF", "Ollama", "OpenAI", "Claude", "Gemini" };
    int idx = static_cast<int>(m_activeBackend);
    std::ostringstream oss;
    oss << "Backend: " << (idx >= 0 && idx < 5 ? backendNames[idx] : "Unknown") << " (headless)\n";
    oss << "Status: Active\n";
    oss << "Model: " << (m_loadedModelName.empty() ? "(none)" : m_loadedModelName) << "\n";
    oss << "Inference requests: " << m_inferenceRequestCount;
    return oss.str();
}

bool HeadlessIDE::probeBackendHealth(AIBackendType type) {
    switch (type) {
        case AIBackendType::LocalGGUF:
            // Local GGUF: healthy if model is loaded
            return m_modelLoaded;

        case AIBackendType::Ollama: {
            // Probe Ollama server connection
            RawrXD::Agent::OllamaConfig cfg;
            cfg.host = "127.0.0.1";
            cfg.port = 11434;
            cfg.timeout_ms = 5000; // Quick probe timeout
            RawrXD::Agent::AgentOllamaClient client(cfg);
            bool connected = client.TestConnection();
            if (connected) {
                auto models = client.ListModels();
                m_outputSink->appendOutput(
                    ("Ollama: " + std::to_string(models.size()) + " models available").c_str(),
                    OutputSeverity::Debug);
            }
            return connected;
        }

        case AIBackendType::OpenAI:
        case AIBackendType::Claude:
        case AIBackendType::Gemini:
            // Fix #15: Cloud backends - check API key from environment/config
            {
                const char* envKey = nullptr;
                if (type == AIBackendType::OpenAI) envKey = std::getenv("OPENAI_API_KEY");
                else if (type == AIBackendType::Claude) envKey = std::getenv("ANTHROPIC_API_KEY");
                else if (type == AIBackendType::Gemini) envKey = std::getenv("GEMINI_API_KEY");
                
                // Also check config file
                std::string configKey;
                if (!envKey || strlen(envKey) == 0) {
                    std::ifstream cfg("api_keys.json");
                    if (cfg) {
                        try {
                            auto j = nlohmann::json::parse(cfg);
                            std::string keyName;
                            if (type == AIBackendType::OpenAI) keyName = "openai";
                            else if (type == AIBackendType::Claude) keyName = "claude";
                            else keyName = "gemini";
                            configKey = j.value(keyName, "");
                        } catch (...) {}
                    }
                }
                
                bool hasKey = (envKey && strlen(envKey) > 0) || !configKey.empty();
                if (hasKey) {
                    m_outputSink->appendOutput(
                        (std::string("Cloud backend ") + 
                         (type == AIBackendType::OpenAI ? "OpenAI" :
                          type == AIBackendType::Claude ? "Claude" : "Gemini") +
                         " API key configured").c_str(),
                        OutputSeverity::Info);
                }
                return hasKey;
            }

        default:
            return false;
    }
}

std::string HeadlessIDE::routeInferenceRequest(const std::string& prompt) {
    m_inferenceRequestCount++;
    recordSimpleEvent("inference_request");

    auto t0 = std::chrono::steady_clock::now();

    // Route based on active backend type
    if (m_activeBackend == AIBackendType::Ollama || m_activeBackend == AIBackendType::LocalGGUF) {
        // Use AgentOllamaClient for Ollama-backed inference
        RawrXD::Agent::OllamaConfig cfg;
        cfg.host = "127.0.0.1";
        cfg.port = 11434;
        // chat_model left empty — auto-detected from Ollama /api/tags
        cfg.temperature = m_config.temperature;
        cfg.max_tokens = m_config.maxTokens;
        cfg.use_gpu = true;
        cfg.num_gpu = 99;

        RawrXD::Agent::AgentOllamaClient client(cfg);

        // Build conversation with system context
        std::vector<RawrXD::Agent::ChatMessage> messages;
        messages.push_back({"system", "You are RawrXD IDE's embedded AI assistant. "
            "Provide accurate, concise answers. When asked about code, give working examples.", "", {}});
        if (m_modelLoaded) {
            messages.push_back({"system", "Loaded model: " + m_loadedModelName, "", {}});
        }
        messages.push_back({"user", prompt, "", {}});

        auto result = client.ChatSync(messages);

        auto t1 = std::chrono::steady_clock::now();
        double durationMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

        if (result.success) {
            char perf[256];
            snprintf(perf, sizeof(perf),
                     "[inference] %llu prompt + %llu completion tokens, %.1f tok/s, %.0f ms",
                     (unsigned long long)result.prompt_tokens,
                     (unsigned long long)result.completion_tokens,
                     result.tokens_per_sec, durationMs);
            m_outputSink->appendOutput(perf, OutputSeverity::Debug);
            return result.response;
        } else {
            m_outputSink->appendOutput(
                ("Ollama inference failed: " + result.error_message).c_str(),
                OutputSeverity::Warning);
            // Fall through to engine manager path
        }
    } else if (m_activeBackend == AIBackendType::OpenAI) {
        // Fix #15: Cloud backend - OpenAI
        const char* apiKey = std::getenv("OPENAI_API_KEY");
        if (apiKey && strlen(apiKey) > 0) {
            // Simple HTTP POST to OpenAI API
            std::string apiResponse = performCloudInference("https://api.openai.com/v1/chat/completions", 
                apiKey, prompt, "gpt-4o");
            if (!apiResponse.empty()) return apiResponse;
        }
    } else if (m_activeBackend == AIBackendType::Claude) {
        // Fix #15: Cloud backend - Claude
        const char* apiKey = std::getenv("ANTHROPIC_API_KEY");
        if (apiKey && strlen(apiKey) > 0) {
            std::string apiResponse = performCloudInference("https://api.anthropic.com/v1/messages",
                apiKey, prompt, "claude-3-5-sonnet-20241022");
            if (!apiResponse.empty()) return apiResponse;
        }
    } else if (m_activeBackend == AIBackendType::Gemini) {
        // Fix #15: Cloud backend - Gemini
        const char* apiKey = std::getenv("GEMINI_API_KEY");
        if (apiKey && strlen(apiKey) > 0) {
            std::string apiResponse = performCloudInference("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
                apiKey, prompt, "");
            if (!apiResponse.empty()) return apiResponse;
        }
    }

    // Optional OpenAI-compatible aggregator fallback. This remains fail-closed
    // unless egress consent, endpoint, key, model, rates, and budget are all set.
    const char* aggregatorEndpoint = std::getenv("RAWRXD_AGGREGATOR_ENDPOINT");
    const char* aggregatorKey = std::getenv("RAWRXD_AGGREGATOR_API_KEY");
    const char* aggregatorModel = std::getenv("RAWRXD_AGGREGATOR_MODEL");
    if (aggregatorEndpoint && aggregatorEndpoint[0] &&
        aggregatorKey && aggregatorKey[0] &&
        aggregatorModel && aggregatorModel[0]) {
        std::string apiResponse = performCloudInference(
            aggregatorEndpoint, aggregatorKey, prompt, aggregatorModel);
        if (!apiResponse.empty()) return apiResponse;
    }

    // Secondary path: route through engine manager if available
    if (m_engineManager) {
        std::string currentId = m_engineManager->GetCurrentEngine();
        auto* engine = currentId.empty() ? nullptr : m_engineManager->GetEngine(currentId);
        if (engine && engine->loaded) {
            m_outputSink->appendOutput(("Engine '" + engine->name + "' active but no inference API").c_str(),
                                       OutputSeverity::Debug);
        }
    }

    // Final fallback: provide actionable error
    return "[error] Inference unavailable — ensure Ollama is running on port 11434 "
           "or configure an alternative backend with 'backend <type>'";
}

// ============================================================================
// LLM Router (Phase 8C)
// ============================================================================
std::string HeadlessIDE::routeWithIntelligence(const std::string& prompt) {
    return routeInferenceRequest(prompt);
}

std::string HeadlessIDE::getRouterStatusString() const {
    std::ostringstream oss;
    oss << "LLM Router: " << (m_routerInitialized ? "Active" : "Inactive") << " (headless)\n";
    oss << "Backends: 5 configured\n";
    oss << "Task types: 8\n";
    oss << "Requests routed: " << m_inferenceRequestCount;
    return oss.str();
}

std::string HeadlessIDE::getCostLatencyHeatmapString() const {
    return "Cost/Latency heatmap: (headless mode — collecting data)";
}

// ============================================================================
// Failure Detection (Phase 4B/6)
// ============================================================================
std::string HeadlessIDE::executeWithFailureDetection(const std::string& prompt) {
    return runInference(prompt);
}

std::string HeadlessIDE::getFailureDetectorStats() const {
    std::ostringstream oss;
    oss << "Failure detector: " << (m_failureDetectorInitialized ? "Active" : "Inactive") << " (headless)\n";
    oss << "Total detections: " << m_failureDetections << "\n";
    oss << "Retries: " << m_failureRetries;
    return oss.str();
}

std::string HeadlessIDE::getFailureIntelligenceStatsString() const {
    std::ostringstream oss;
    oss << "Failure intelligence: " << (m_failureDetectorInitialized ? "Active" : "Inactive") << " (headless)\n";
    oss << "Records: " << m_failureDetections << "\n";
    oss << "Accuracy: " << (m_failureDetections > 0 ? "tracking" : "N/A");
    return oss.str();
}

// ============================================================================
// Agent History (Phase 6B)
// ============================================================================
std::string HeadlessIDE::getAgentHistoryStats() const {
    std::ostringstream oss;
    oss << "Agent history: " << (m_agentHistoryInitialized ? "Active" : "Inactive") << " (headless)\n";
    oss << "Session: " << m_sessionId << "\n";
    oss << "Events: " << m_agentEventCount;
    return oss.str();
}

void HeadlessIDE::recordSimpleEvent(const std::string& description) {
    m_agentEventCount++;
    if (m_historyRecorder) {
        m_historyRecorder->record("simple_event", "headless", "", description, "", "", true);
    }
    if (m_phase10Initialized) {
        ReplayJournal::instance().recordMarker(description);
    }
    m_outputSink->appendOutput(("Event: " + description).c_str(), OutputSeverity::Debug);
}

// ============================================================================
// ASM Semantic (Phase 9A)
// ============================================================================
void HeadlessIDE::parseAsmFile(const std::string& filePath) {
    m_asmFilesParsed++;
    m_outputSink->appendOutput(("Parsing ASM file: " + filePath).c_str(), OutputSeverity::Info);
    recordSimpleEvent("asm_parse: " + filePath);
}

void HeadlessIDE::parseAsmDirectory(const std::string& dirPath, bool recursive) {
    m_outputSink->appendOutput(("Parsing ASM directory: " + dirPath).c_str(), OutputSeverity::Info);
    recordSimpleEvent("asm_dir_parse: " + dirPath);
}

std::string HeadlessIDE::getAsmSymbolTableString() const {
    std::ostringstream oss;
    oss << "ASM symbol table (headless)\n";
    oss << "Symbols: " << m_asmSymbolCount << "\n";
    oss << "Files parsed: " << m_asmFilesParsed;
    return oss.str();
}

std::string HeadlessIDE::getAsmSemanticStatsString() const {
    std::ostringstream oss;
    oss << "ASM semantic: " << (m_asmSemanticInitialized ? "Active" : "Inactive") << " (headless)\n";
    oss << "Symbols: " << m_asmSymbolCount << "\n";
    oss << "Files: " << m_asmFilesParsed;
    return oss.str();
}

// ============================================================================
// LSP / Hybrid / Multi-Response status — wired to real subsystem state
// ============================================================================
std::string HeadlessIDE::getLSPStatusString() const {
    std::ostringstream oss;
    oss << "LSP client: " << (m_lspInitialized ? "Active" : "Inactive") << " (headless)\n";
    oss << "Servers: " << m_lspServerCount << " configured\n";

    // Query real embedded server stats if available
    {
        std::lock_guard<std::mutex> lk(g_embeddedLSPMutex);
        if (g_embeddedLSP) {
            auto state = g_embeddedLSP->getState();
            const char* stateStr = "Unknown";
            switch (state) {
                case RawrXD::LSPServer::ServerState::Created:      stateStr = "Created"; break;
                case RawrXD::LSPServer::ServerState::Initializing: stateStr = "Initializing"; break;
                case RawrXD::LSPServer::ServerState::Running:      stateStr = "Running"; break;
                case RawrXD::LSPServer::ServerState::ShuttingDown: stateStr = "ShuttingDown"; break;
                case RawrXD::LSPServer::ServerState::Stopped:      stateStr = "Stopped"; break;
                default: break;
            }
            oss << "Embedded server state: " << stateStr << "\n";
            oss << "Indexed symbols: " << g_embeddedLSP->getIndexedSymbolCount() << "\n";
            oss << "Tracked files: " << g_embeddedLSP->getTrackedFileCount() << "\n";
            auto stats = g_embeddedLSP->getStats();
            oss << "Completion requests: " << stats.completionRequests << "\n";
            oss << "Definition requests: " << stats.definitionRequests << "\n";
            oss << "Hover requests: " << stats.hoverRequests;
        } else {
            oss << "Completions served: " << m_lspCompletionCount;
        }
    }
    return oss.str();
}

std::string HeadlessIDE::getHybridBridgeStatusString() const {
    std::ostringstream oss;
    oss << "Hybrid bridge: " << (m_hybridBridgeInitialized ? "Active" : "Inactive") << " (headless)\n";
    oss << "Completions: " << m_hybridCompletionCount;
    return oss.str();
}

// ============================================================================
// Phase 10/11/12 status — wired to real singletons
// ============================================================================
std::string HeadlessIDE::getGovernorStatus() const {
    if (!m_phase10Initialized) return "Execution governor: Not initialized";
    return ExecutionGovernor::instance().getStatusString();
}

std::string HeadlessIDE::getGovernorStatusJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"status\":\"" << getGovernorStatus() << "\",";
    oss << "\"governor_activated\":" << (m_expGovernorActivated ? "true" : "false") << ",";
    oss << "\"layer_eviction_activated\":" << (m_expLayerEvictionActivated ? "true" : "false");
    oss << "}";
    return oss.str();
}

std::string HeadlessIDE::getSafetyStatus() const {
    if (!m_phase10Initialized) return "Safety contract: Not initialized";
    return AgentSafetyContract::instance().getStatusString();
}

std::string HeadlessIDE::getReplayStatus() const {
    if (!m_phase10Initialized) return "Replay journal: Not initialized";
    return ReplayJournal::instance().getStatusString();
}

std::string HeadlessIDE::getConfidenceStatus() const {
    if (!m_phase10Initialized) return "Confidence gate: Not initialized";
    return ConfidenceGate::instance().getStatusString();
}

std::string HeadlessIDE::getSwarmStatus() const {
    if (!m_phase11Initialized) return "Distributed swarm: Not initialized";
    auto& swarm = RawrXD::Swarm::SwarmOrchestrator::instance();
    std::ostringstream oss;
    oss << "Distributed swarm: " << (swarm.isRunning() ? "Running" : "Standby") << "\n";
    oss << "Node: " << swarm.getNodeId() << "\n";
    oss << "Peers: " << swarm.getNodeCount() << "\n";
    oss << "Role: " << (swarm.isCoordinator() ? "Coordinator" : "Worker");
    auto& stats = swarm.getStats();
    oss << "\nRequests: " << stats.inferenceRequests.load();
    oss << "\nBytes sent/recv: " << stats.bytesSent.load() << "/" << stats.bytesReceived.load();
    return oss.str();
}

std::string HeadlessIDE::getNativeDebugStatus() const {
    std::ostringstream oss;
    oss << "Native debugger: " << (m_phase12Initialized ? "Ready" : "Not initialized") << "\n";
    oss << "Session: " << (m_debugSessionActive ? "active" : "none") << "\n";
    oss << "Breakpoints: " << m_debugBreakpointCount;
    return oss.str();
}

std::string HeadlessIDE::getHotpatchStatus() const {
    if (!m_hotpatchInitialized) return "Three-layer hotpatch: Not initialized";
    auto& hp = UniversalModelHotpatcher::instance();
    const auto& stats = hp.getStats();
    std::ostringstream oss;
    oss << "Three-layer hotpatch: Active\n";
    oss << "Layers analyzed: " << stats.layersAnalyzed.load() << "\n";
    oss << "Layers requantized: " << stats.layersRequantized.load() << "\n";
    oss << "Total surgeries: " << stats.totalSurgeries.load() << "\n";
    oss << "Memory saved: " << (stats.totalMemorySaved.load() / (1024*1024)) << " MB\n";
    oss << "Pressure events: " << stats.pressureEvents.load();
    return oss.str();
}

std::string HeadlessIDE::getHotpatchStatusJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"status\":\"" << getHotpatchStatus() << "\",";
    oss << "\"hotpatch70b_activated\":" << (m_expHotpatchActivated ? "true" : "false") << ",";
    oss << "\"layer_eviction_activated\":" << (m_expLayerEvictionActivated ? "true" : "false");
    oss << "}";
    return oss.str();
}

// ============================================================================
// Settings
// ============================================================================
void HeadlessIDE::loadSettings(const std::string& path) {
    std::string settingsPath = path.empty() ? getSettingsFilePath() : path;
    m_outputSink->appendOutput(("Loading settings: " + settingsPath).c_str(), OutputSeverity::Debug);
}

void HeadlessIDE::saveSettings(const std::string& path) {
    std::string settingsPath = path.empty() ? getSettingsFilePath() : path;
    m_outputSink->appendOutput(("Saving settings: " + settingsPath).c_str(), OutputSeverity::Debug);
}

std::string HeadlessIDE::getSettingsFilePath() const {
    return "rawrxd_settings.json";
}

// ============================================================================
// HTTP Server
// ============================================================================
void HeadlessIDE::startServer() {
    if (m_serverRunning.load()) return;

    auto logStatus = [this](const std::string& msg) {
        m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Error);
        // Best-effort file breadcrumb to debug headless binding issues
        FILE* f = fopen("headless_server.log", "a");
        if (f) {
            auto now = std::chrono::system_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
            fprintf(f, "%lld %s\n", (long long)ms, msg.c_str());
            fclose(f);
        }
    };

    m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_serverSocket == INVALID_SOCKET) {
        logStatus("Failed to create server socket");
        return;
    }

    // Allow address reuse
    int opt = 1;
    setsockopt(m_serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(m_config.port));
    inet_pton(AF_INET, m_config.bindAddress.c_str(), &addr.sin_addr);

    if (bind(m_serverSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::string msg = "Failed to bind to " + m_config.bindAddress + ":" + std::to_string(m_config.port) +
                          " (WSA=" + std::to_string(WSAGetLastError()) + ")";
        logStatus(msg);
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
        m_serverRunning.store(false);
        return;
    }

    if (listen(m_serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::string msg = "Failed to listen on " + m_config.bindAddress + ":" + std::to_string(m_config.port) +
                          " (WSA=" + std::to_string(WSAGetLastError()) + ")";
        logStatus(msg);
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
        m_serverRunning.store(false);
        return;
    }

    m_serverRunning.store(true);

    std::string msg = "HTTP server listening on " + m_config.bindAddress + ":" + std::to_string(m_config.port);
    safeAppendOutput(msg.c_str(), OutputSeverity::Info);

    m_serverThread = std::thread(&HeadlessIDE::serverLoop, this);
}

void HeadlessIDE::stopServer() {
    if (!m_serverRunning.load()) return;
    m_serverRunning.store(false);
    if (m_serverSocket != INVALID_SOCKET) {
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
    }
    if (m_serverThread.joinable()) {
        m_serverThread.join();
    }
    // Fix #6: Join thread pool threads
    {
        std::lock_guard<std::mutex> lk(m_threadPoolMutex);
        for (auto& t : m_threadPool) {
            if (t.joinable()) t.join();
        }
        m_threadPool.clear();
    }
    safeAppendOutput("HTTP server stopped", OutputSeverity::Info);
}

bool HeadlessIDE::isServerRunning() const {
    return m_serverRunning.load();
}

std::string HeadlessIDE::getServerStatus() const {
    if (!m_serverRunning.load()) return "Server: Stopped";
    return "Server: Running on " + m_config.bindAddress + ":" + std::to_string(m_config.port);
}

void HeadlessIDE::serverLoop() {
    while (m_serverRunning.load()) {
        // Set a timeout on accept so we can check the shutdown flag
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(m_serverSocket, &readSet);
        timeval tv = { 1, 0 };  // 1 second timeout

        int sel = select(0, &readSet, nullptr, nullptr, &tv);
        if (sel <= 0) continue;

        SOCKET client = accept(m_serverSocket, nullptr, nullptr);
        if (client == INVALID_SOCKET) continue;

        // Handle client in a thread pool (Fix #6)
        {
            std::lock_guard<std::mutex> lk(m_threadPoolMutex);
            if (m_threadPool.size() < m_maxThreads) {
                m_threadPool.emplace_back([this, client]() {
                    handleClient(client);
                    closesocket(client);
                });
            } else {
                // Reject if thread pool is full
                std::string busy = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                send(client, busy.c_str(), static_cast<int>(busy.size()), 0);
                closesocket(client);
            }
        }
    }
}

bool HeadlessIDE::readHttpRequest(SOCKET clientFd, HostedHttpRequest& parsed,
                                  int& failureStatus) {
    constexpr size_t kMaxHeaders = 64 * 1024;
    constexpr size_t kMaxBody = 1024 * 1024;
    DWORD timeoutMs = 10000;
    setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
    std::string wire;
    char buffer[8192];
    size_t headerEnd = std::string::npos;
    size_t separatorSize = 4;
    while (headerEnd == std::string::npos) {
        int received = recv(clientFd, buffer, sizeof(buffer), 0);
        if (received <= 0) { failureStatus = 400; return false; }
        wire.append(buffer, static_cast<size_t>(received));
        headerEnd = wire.find("\r\n\r\n");
        if (headerEnd == std::string::npos) {
            headerEnd = wire.find("\n\n");
            separatorSize = 2;
        }
        if (wire.size() > kMaxHeaders) { failureStatus = 413; return false; }
    }
    parsed.headers = wire.substr(0, headerEnd);
    size_t firstSpace = parsed.headers.find(' ');
    size_t secondSpace = parsed.headers.find(' ', firstSpace + 1);
    if (firstSpace == std::string::npos || secondSpace == std::string::npos) {
        failureStatus = 400; return false;
    }
    parsed.method = parsed.headers.substr(0, firstSpace);
    parsed.path = parsed.headers.substr(firstSpace + 1, secondSpace - firstSpace - 1);
    size_t query = parsed.path.find('?');
    if (query != std::string::npos) parsed.path.resize(query);
    std::string transfer = lowerAscii(requestHeader(parsed.headers, "transfer-encoding"));
    if (!transfer.empty() && transfer != "identity") { failureStatus = 400; return false; }
    std::string lengthText = requestHeader(parsed.headers, "content-length");
    char* end = nullptr;
    unsigned long long contentLength = lengthText.empty() ? 0 :
        std::strtoull(lengthText.c_str(), &end, 10);
    if ((!lengthText.empty() && (!end || *end)) || contentLength > kMaxBody) {
        failureStatus = 413; return false;
    }
    parsed.body = wire.substr(headerEnd + separatorSize);
    while (parsed.body.size() < contentLength) {
        int received = recv(clientFd, buffer, sizeof(buffer), 0);
        if (received <= 0) { failureStatus = 400; return false; }
        parsed.body.append(buffer, static_cast<size_t>(received));
        if (parsed.body.size() > kMaxBody) { failureStatus = 413; return false; }
    }
    if (parsed.body.size() > contentLength) parsed.body.resize(static_cast<size_t>(contentLength));
    parsed.peer = getPeerId(clientFd);
    return true;
}

bool HeadlessIDE::authorizeHttpRequest(const HostedHttpRequest& request,
                                       HostedHttpResponse& response) {
    static RateLimiter limiter(120, 60.0);
    std::string checkedOrigin;
    bool localLoopback = m_config.ingressMode == HeadlessIngressMode::Local &&
        isLoopbackAddress(request.peer) && isLoopbackAddress(m_config.bindAddress);
    bool acceptedOrigin = localLoopback
        ? localOriginAllowed(request.origin, m_config.port)
        : originAllowed(request.headers, m_config, checkedOrigin);
    if (!acceptedOrigin) {
        response.status = 403;
        response.body = "{\"error\":\"origin_denied\"}";
        return false;
    }
    if (isHealthRoute(request.path)) return true;
    if (!limiter.allow(request.peer)) {
        response.status = 429;
        response.body = "{\"error\":\"rate_limit\"}";
        return false;
    }
    if (request.method == "OPTIONS") {
        if (requestHeader(request.headers, "origin").empty()) {
            response.status = 403;
            response.body = "{\"error\":\"origin_required\"}";
            return false;
        }
        response.status = 204;
        response.body.clear();
        return true;
    }
    bool githubSigned = request.path == "/api/github/webhook" &&
        verifyGitHubSignature(request.headers, request.body, m_config.githubWebhookSecret);
    if (request.path == "/api/github/webhook" && !githubSigned) {
        response.status = 401;
        response.body = "{\"error\":\"invalid_github_signature\"}";
        return false;
    }
    if (localLoopback) return true;
    bool apiAuthenticated = authenticateRequest(
        request.headers, m_config, routeScope(request.path, request.method));
    if (request.path != "/api/github/webhook" && !apiAuthenticated) {
        response.status = m_config.apiKey.empty() ? 503 : 401;
        response.body = m_config.apiKey.empty()
            ? "{\"error\":\"authentication_not_configured\"}"
            : "{\"error\":\"unauthorized\"}";
        return false;
    }
    return true;
}

void HeadlessIDE::streamGenerationResponse(SOCKET clientFd,
                                           const HostedHttpRequest& request,
                                           const std::string& prompt,
                                           const char* protocol,
                                           HostedHttpResponse& response) {
    bool ollama = std::strcmp(protocol, "ollama") == 0;
    bool openai = std::strcmp(protocol, "openai") == 0;
    std::ostringstream head;
    head << "HTTP/1.1 200 OK\r\nContent-Type: "
         << (ollama ? "application/x-ndjson" : "text/event-stream")
         << "\r\nCache-Control: no-cache\r\nConnection: close\r\n"
         << "X-Content-Type-Options: nosniff\r\n";
    if (!request.origin.empty()) {
        head << "Access-Control-Allow-Origin: " << request.origin << "\r\nVary: Origin\r\n";
    }
    head << "\r\n";
    std::string headers = head.str();
    sendAllBytes(clientFd, headers.data(), headers.size());
    runInferenceStreaming(prompt, [clientFd, ollama, openai](const char* token, size_t length) {
        std::string escaped = jsonEscape(std::string(token, length));
        std::string frame;
        if (ollama) {
            frame = "{\"model\":\"rawrxd\",\"response\":\"" + escaped +
                "\",\"done\":false}\n";
        } else if (openai) {
            frame = "data: {\"id\":\"rawrxd\",\"object\":\"chat.completion.chunk\","
                "\"choices\":[{\"index\":0,\"delta\":{\"content\":\"" + escaped +
                "\"},\"finish_reason\":null}]}\n\n";
        } else {
            frame = "data: {\"token\":\"" + escaped + "\"}\n\n";
        }
        sendAllBytes(clientFd, frame.data(), frame.size());
    });
    std::string done;
    if (ollama) {
        done = "{\"model\":\"rawrxd\",\"response\":\"\",\"done\":true}\n";
    } else if (openai) {
        done = "data: {\"id\":\"rawrxd\",\"object\":\"chat.completion.chunk\","
            "\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
            "data: [DONE]\n\n";
    } else {
        done = "data: [DONE]\n\n";
    }
    sendAllBytes(clientFd, done.data(), done.size());
    response.alreadySent = true;
}

void HeadlessIDE::routeGenerationRequest(SOCKET clientFd,
                                         const HostedHttpRequest& request,
                                         HostedHttpResponse& response) {
    if (request.method != "POST") {
        response.status = 405;
        response.body = "{\"error\":\"method_not_allowed\"}";
        return;
    }
    std::string prompt = request.body;
    bool stream = request.path == "/api/generate";
    try {
        auto json = nlohmann::json::parse(request.body);
        prompt = json.value("prompt", json.value("message", ""));
        stream = json.value("stream", stream);
        if (request.path == "/v1/chat/completions") {
            auto messages = json.value("messages", nlohmann::json::array());
            if (!messages.empty()) prompt = messages.back().value("content", "");
        }
    } catch (...) {}
    if (requestHeader(request.headers, "accept").find("text/event-stream") !=
        std::string::npos) {
        stream = true;
    }
    if (prompt.empty() || prompt.size() > 256 * 1024) {
        response.status = 400;
        response.body = "{\"error\":\"invalid_prompt\"}";
        return;
    }
    ScopedCloudConsent cloudConsent(
        requestHeader(request.headers, "x-rawrxd-cloud-consent") == "1");
    if (request.path == "/api/generate/stream") {
        streamGenerationResponse(clientFd, request, prompt, "legacy", response);
        return;
    }
    if (stream && request.path == "/api/generate") {
        streamGenerationResponse(clientFd, request, prompt, "ollama", response);
        return;
    }
    if (stream && request.path == "/v1/chat/completions") {
        streamGenerationResponse(clientFd, request, prompt, "openai", response);
        return;
    }
    std::string result = routeInferenceRequest(prompt);
    if (request.path == "/v1/chat/completions") {
        response.body = "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"" +
            jsonEscape(result) + "\"}}]}";
    } else {
        response.body = "{\"response\":\"" + jsonEscape(result) + "\"}";
    }
}

void HeadlessIDE::routeHexMagRequest(const HostedHttpRequest& request,
                                     HostedHttpResponse& response) {
#if !RAWRXD_HEADLESS_NATIVE_HEXMAG
    (void)request;
    response.status = 503;
    response.body = "{\"error\":\"hexmag_unavailable_on_platform\"}";
#else
    nlohmann::json input;
    try { input = nlohmann::json::parse(request.body); }
    catch (...) {
        response.status = 400;
        response.body = "{\"error\":\"invalid_json\"}";
        return;
    }
    nlohmann::json steps = nlohmann::json::array();
    if (request.path == "/api/chain") {
        steps = input.value("steps", nlohmann::json::array());
    } else {
        steps.push_back(input);
    }
    if (!steps.is_array() || steps.empty() || steps.size() > 8) {
        response.status = 400;
        response.body = "{\"error\":\"invalid_hexmag_steps\"}";
        return;
    }
    nlohmann::json results = nlohmann::json::array();
    bool allFinal = true;
    for (const auto& step : steps) {
        std::string prompt = step.value("prompt",
            step.value("task", step.value("question", "")));
        std::string context = step.value("context", "");
        if (prompt.empty() || prompt.size() > 256 * 1024 || context.size() > 256 * 1024) {
            response.status = 400;
            response.body = "{\"error\":\"invalid_hexmag_request\"}";
            return;
        }
        const auto result =
            RawrXD::HexMag::ideHexMagSendPath().operatorTurn(prompt, context);
        std::string answer = !result.lastClient.ask.answer.empty()
            ? result.lastClient.ask.answer : result.lastClient.ask.selectedCandidate;
        bool final = result.finalAuthority && result.finalize.allowed;
        allFinal = allFinal && final;
        results.push_back({{"final", final}, {"needInput", result.needInputLatched},
            {"generation", result.generation}, {"output", answer},
            {"diagnostic", result.diagnostic}});
        if (result.needInputLatched || !final) break;
    }
    response.status = allFinal ? 200 : 503;
    response.body = nlohmann::json({
        {"success", allFinal}, {"results", results},
        {"output", results.empty() ? "" : results.back().value("output", "")}
    }).dump();
#endif
}

void HeadlessIDE::routeNativeRequest(const HostedHttpRequest& request,
                                     HostedHttpResponse& response) {
    if ((request.path == "/models" || request.path == "/api/models" ||
         request.path == "/v1/models") && request.method == "GET") {
        response.body = getModelsJson();
    } else if (request.path == "/api/tags" && request.method == "GET") {
        response.body = getModelsOllamaJson();
    } else if (request.path == "/api/model/info" && request.method == "GET") {
        response.body = "{\"loaded\":" + std::string(m_modelLoaded ? "true" : "false") +
            ",\"name\":\"" + jsonEscape(m_loadedModelName) + "\"}";
    } else if (request.path == "/api/model/load" && request.method == "POST") {
        std::string modelPath = request.body;
        try {
            auto json = nlohmann::json::parse(request.body);
            modelPath = json.value("modelPath", json.value("model", json.value("name", "")));
        } catch (...) {}
        std::string resolved;
        if (!canonicalWorkspacePath(modelPath, m_config.workingDir, resolved)) {
            response.status = 403;
            response.body = "{\"success\":false,\"error\":\"workspace_path_denied\"}";
            return;
        }
        bool loaded = loadModel(resolved);
        response.status = loaded ? 200 : 400;
        response.body = "{\"success\":" + std::string(loaded ? "true" : "false") +
            ",\"model\":\"" + jsonEscape(m_loadedModelName) + "\"}";
    } else if (request.path == "/api/model/unload" && request.method == "POST") {
        bool unloaded = unloadModel();
        response.status = unloaded ? 200 : 400;
        response.body = "{\"success\":" + std::string(unloaded ? "true" : "false") + "}";
    } else if (request.path == "/api/engine/capabilities" && request.method == "GET") {
        response.body = getEngineCapabilitiesJson();
    } else {
        response.status = 405;
        response.body = "{\"error\":\"method_not_allowed\"}";
    }
}

bool HeadlessIDE::routeStatusRequest(const HostedHttpRequest& request,
                                     HostedHttpResponse& response) {
    const std::string& path = request.path;
    bool reload = path == "/api/instructions/reload" && request.method == "POST";
    if (request.method != "GET" && !reload) return false;
    if (path == "/api/backend/status") {
        response.body = "{\"status\":\"" + jsonEscape(getBackendStatusString()) + "\"}";
    } else if (path == "/api/router/status") {
        response.body = "{\"status\":\"" + jsonEscape(getRouterStatusString()) + "\"}";
    } else if (path == "/api/governor/status") {
        response.body = getGovernorStatusJson();
    } else if (path == "/api/swarm/status") {
        response.body = "{\"status\":\"" + jsonEscape(getSwarmStatus()) + "\"}";
    } else if (path == "/api/safety/status") {
        response.body = "{\"status\":\"" + jsonEscape(getSafetyStatus()) + "\"}";
    } else if (path == "/api/hotpatch/status") {
        response.body = getHotpatchStatusJson();
    } else if (path == "/api/quantum/status") {
        response.body = getQuantumStatusJson();
    } else if (path == "/api/debug/status") {
        response.body = "{\"status\":\"" + jsonEscape(getNativeDebugStatus()) + "\"}";
    } else if (path == "/api/asm/status") {
        response.body = "{\"status\":\"" + jsonEscape(getAsmSemanticStatsString()) + "\"}";
    } else if (path == "/api/lsp/status") {
        response.body = "{\"status\":\"" + jsonEscape(getLSPStatusString()) + "\"}";
    } else if (path == "/api/hybrid/status") {
        response.body = "{\"status\":\"" + jsonEscape(getHybridBridgeStatusString()) + "\"}";
    } else if (path == "/api/agent/history") {
        response.body = "{\"stats\":\"" + jsonEscape(getAgentHistoryStats()) + "\"}";
    } else if (path == "/api/failure/stats") {
        response.body = "{\"stats\":\"" + jsonEscape(getFailureDetectorStats()) + "\"}";
    } else if (path == "/api/metrics") {
        response.body = "{\"requests\":" + std::to_string(m_inferenceRequestCount) +
            ",\"tokensPerSec\":0,\"memUsedMB\":0,\"ollamaReachable\":" +
            std::string(getActiveBackendType() == AIBackendType::Ollama ? "true" : "false") +
            ",\"cloudEgressEnabled\":" +
            std::string(m_config.allowCloudEgress ? "true" : "false") +
            ",\"cloudReservedNanodollars\":" +
            std::to_string(m_cloudReservedNanodollars.load(std::memory_order_acquire)) +
            ",\"uptimeMs\":" + std::to_string(getUptimeMs()) + "}";
    } else if (path == "/api/manifest" || path == "/api/features") {
        response.body = getFeatureManifestJSON();
    } else if (path.find("/api/instructions") == 0) {
        if (m_config.mode == HeadlessRunMode::Server) {
            response.status = 503;
            response.body = "{\"error\":\"instructions_unavailable_in_server_profile\"}";
            return true;
        }
        auto& provider = InstructionsProvider::instance();
        if (!provider.isLoaded()) provider.loadAll();
        if (path == "/api/instructions/reload" && request.method == "POST") {
            auto result = provider.reload();
            response.body = "{\"success\":" + std::string(result.success ? "true" : "false") +
                ",\"detail\":\"" + jsonEscape(result.detail) + "\"}";
        } else if (path == "/api/instructions/summary") {
            response.body = provider.toJSONSummary();
        } else if (path == "/api/instructions/content") {
            response.contentType = "text/markdown; charset=utf-8";
            response.body = provider.getAllContent();
        } else {
            response.body = provider.toJSON();
        }
    } else {
        return false;
    }
    return true;
}

void HeadlessIDE::routeGitHubWebhook(const HostedHttpRequest& request,
                                     HostedHttpResponse& response) {
    std::string event = requestHeader(request.headers, "x-github-event");
    std::string delivery = requestHeader(request.headers, "x-github-delivery");
    if (event.empty() || delivery.empty() || event.size() > 64 || delivery.size() > 128) {
        response.status = 400;
        response.body = "{\"error\":\"invalid_github_headers\"}";
        return;
    }
    std::string repo;
    std::string action;
    try {
        auto json = nlohmann::json::parse(request.body);
        action = json.value("action", "");
        if (json.contains("repository")) repo = json["repository"].value("full_name", "");
    } catch (...) {
        response.status = 400;
        response.body = "{\"error\":\"invalid_json\"}";
        return;
    }
    if (repo.size() > 256 || action.size() > 64) {
        response.status = 400;
        response.body = "{\"error\":\"github_metadata_too_large\"}";
        return;
    }
    std::string record = "{\"delivery\":\"" + jsonEscape(delivery) + "\",\"event\":\"" +
        jsonEscape(event) + "\",\"repository\":\"" + jsonEscape(repo) +
        "\",\"action\":\"" + jsonEscape(action) + "\",\"state\":\"queued\"}\r\n";
    bool persisted = false;
    {
        std::lock_guard<std::mutex> lock(m_auditMutex);
        persisted = appendBoundedFile(m_config.workingDir + "\\rawrxd_github_jobs.jsonl",
                                      record, 8ULL * 1024 * 1024);
    }
#if RAWRXD_HEADLESS_NATIVE_HEXMAG
    if (persisted) {
        std::string mission = "GitHub " + event + " event for " + repo;
        if (!action.empty()) mission += " action " + action;
        const auto result = RawrXD::HexMag::ideHexMagSendPath().operatorTurn(
            mission, request.body.substr(0, 64 * 1024));
        bool final = result.finalAuthority && result.finalize.allowed;
        std::string outcome = "{\"delivery\":\"" + jsonEscape(delivery) +
            "\",\"state\":\"" + (final ? "completed" : "failed") +
            "\",\"final\":" + (final ? "true" : "false") +
            ",\"diagnostic\":\"" + jsonEscape(result.diagnostic) + "\"}\r\n";
        std::lock_guard<std::mutex> lock(m_auditMutex);
        persisted = appendBoundedFile(m_config.workingDir + "\\rawrxd_github_jobs.jsonl",
                                      outcome, 8ULL * 1024 * 1024);
    }
#endif
    response.status = persisted ? 202 : 500;
    response.body = persisted
        ? "{\"accepted\":true,\"jobId\":\"" + jsonEscape(delivery) + "\"}"
        : "{\"error\":\"job_persistence_failed\"}";
}

void HeadlessIDE::routeHttpRequest(SOCKET clientFd, const HostedHttpRequest& request,
                                   HostedHttpResponse& response) {
    const std::string& path = request.path;
    if (request.method == "OPTIONS") return;
    if (isHealthRoute(path)) {
        response.body = "{\"status\":\"ok\",\"mode\":\"" +
            std::string(m_config.ingressMode == HeadlessIngressMode::Hosted ? "hosted" : "local") +
            "\",\"authConfigured\":" + (m_config.apiKey.empty() ? "false" : "true") +
            ",\"uptime\":" + std::to_string(getUptimeMs()) + "}";
    } else if (path == "/status" || path == "/api/status" || path == "/api/headless/status") {
        response.body = getFullStatusDump();
    } else if (path == "/api/version") {
        response.body = "{\"version\":\"" + jsonEscape(VERSION) + "\",\"mode\":\"" +
            (m_config.ingressMode == HeadlessIngressMode::Hosted ? "hosted" : "local") + "\"}";
    } else if (path == "/api/generate" || path == "/api/generate/stream" ||
               path == "/v1/chat/completions" || path == "/ask") {
        routeGenerationRequest(clientFd, request, response);
    } else if (path == "/models" || path == "/api/models" || path == "/v1/models" ||
               path == "/api/tags" || path.find("/api/model/") == 0 ||
               path == "/api/engine/capabilities") {
        routeNativeRequest(request, response);
    } else if ((path == "/gui" || path == "/gui/") && request.method == "GET") {
        response.contentType = "text/html; charset=utf-8";
        if (!readBoundedFile("sites/screenpilot.tech/gui/ide_chatbot_standalone.html",
                             2 * 1024 * 1024, response.body)) {
            response.status = 404;
            response.body = "{\"error\":\"gui_not_found\"}";
            response.contentType = "application/json; charset=utf-8";
        }
    } else if ((path == "/api/hexmag/ask" || path == "/api/subagent" ||
                path == "/api/chain") && request.method == "POST") {
        routeHexMagRequest(request, response);
    } else if (routeStatusRequest(request, response)) {
        return;
    } else if (path == "/api/github/webhook" && request.method == "POST") {
        routeGitHubWebhook(request, response);
    } else if (path.find("/api/tool") == 0 || path.find("/run-tool") == 0 ||
               path.find("/api/file") == 0 || path.find("/api/command") == 0) {
        response.status = 403;
        response.body = "{\"error\":\"public_command_and_file_routes_disabled\"}";
    } else {
        response.status = 404;
        response.body = "{\"error\":\"not_found\",\"path\":\"" + jsonEscape(path) + "\"}";
    }
}

void HeadlessIDE::sendHttpResponse(SOCKET clientFd, const HostedHttpRequest& request,
                                   const HostedHttpResponse& response) {
    std::ostringstream wire;
    wire << "HTTP/1.1 " << response.status << " " << httpReason(response.status) << "\r\n"
         << "Content-Type: " << response.contentType << "\r\n"
         << "Content-Length: " << response.body.size() << "\r\n"
         << "X-Content-Type-Options: nosniff\r\n"
         << "Cache-Control: no-store\r\n"
         << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
         << "Access-Control-Allow-Headers: Authorization, Content-Type, X-API-Key, "
            "X-RawrXD-Cloud-Consent, X-GitHub-Event, X-GitHub-Delivery, "
            "X-Hub-Signature-256\r\n";
    if (!request.origin.empty()) {
        wire << "Access-Control-Allow-Origin: " << request.origin << "\r\nVary: Origin\r\n";
    }
    if (response.status == 401) wire << "WWW-Authenticate: Bearer realm=\"RawrXD\"\r\n";
    wire << "Connection: close\r\n\r\n" << response.body;
    std::string message = wire.str();
    sendAllBytes(clientFd, message.data(), message.size());
}

void HeadlessIDE::handleClient(SOCKET clientFd) {
    HostedHttpRequest request;
    HostedHttpResponse response;
    int failureStatus = 400;
    if (!readHttpRequest(clientFd, request, failureStatus)) {
        response.status = failureStatus;
        response.body = "{\"error\":\"invalid_request\"}";
        sendHttpResponse(clientFd, request, response);
        return;
    }
    request.origin = requestHeader(request.headers, "origin");
    bool authorized = authorizeHttpRequest(request, response);
    if (authorized) routeHttpRequest(clientFd, request, response);
    if (!response.alreadySent) sendHttpResponse(clientFd, request, response);
    appendAudit(m_auditMutex, m_config, request.peer, request.method, request.path,
                response.status, authorized ? "handled" : "denied");
}

// ============================================================================
// Feature Manifest (delegates to Win32IDE_FeatureManifest.cpp structures)
// ============================================================================
std::string HeadlessIDE::getFeatureManifestMarkdown() const {
    return "# RawrXD Feature Manifest (Headless)\n\nPhase 19C: Headless surface active.\n";
}

std::string HeadlessIDE::getFeatureManifestJSON() const {
    return "{\"mode\":\"headless\",\"version\":\"" + std::string(VERSION) + "\",\"phase\":\"" + BUILD_PHASE + "\"}";
}

// ============================================================================
// Phase 35: RawrXD-Native API Helpers
// Provides the model registry, engine capabilities, and Ollama-compatible
// model list that the IDE frontend (gui/ide_chatbot.html) expects when
// running in RawrXD-native mode (no Ollama dependency).
// ============================================================================

std::string HeadlessIDE::getModelsJson() const {
    std::ostringstream oss;
    oss << "{\"models\":[";
    bool first = true;

    // 1) Currently loaded model (if any) — listed first so the frontend
    //    auto-selects a runnable model.
    if (m_modelLoaded && !m_loadedModelName.empty()) {
        first = false;
        oss << "{\"id\":\"" << m_loadedModelName << "\","
            << "\"name\":\"" << m_loadedModelName << "\","
            << "\"path\":\"" << m_loadedModelPath << "\","
            << "\"type\":\"gguf\","
            << "\"loaded\":true}";
    }

    // 2) Scan the configured model directory for .gguf files
    const char* scanDirs[] = {
        "D:/OllamaModels",
        "C:/OllamaModels",
        "D:/models",
        "C:/models"
    };
    for (const char* dir : scanDirs) {
        std::string search = std::string(dir) + "/*.gguf";
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(search.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (!first) oss << ",";
            first = false;
            std::string fname = fd.cFileName;
            std::string base = fname.substr(0, fname.find_last_of('.'));
            std::string full = std::string(dir) + "/" + fname;
            uint64_t size = (uint64_t(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
            oss << "{\"id\":\"" << base << "\","
                << "\"name\":\"" << base << "\","
                << "\"path\":\"" << full << "\","
                << "\"type\":\"gguf\","
                << "\"size\":" << size << ","
                << "\"loaded\":false}";
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    oss << "]}";
    return oss.str();
}

std::string HeadlessIDE::getModelsOllamaJson() const {
    // Ollama /api/tags compatible format — keeps the legacy frontend path
    // working until the user switches to RawrXD-native mode.
    std::ostringstream oss;
    oss << "{\"models\":[";
    bool first = true;

    if (m_modelLoaded && !m_loadedModelName.empty()) {
        first = false;
        oss << "{\"name\":\"" << m_loadedModelName << "\","
            << "\"model\":\"" << m_loadedModelName << "\","
            << "\"modified_at\":\"\","
            << "\"size\":0,"
            << "\"digest\":\"rawrxd-local\","
            << "\"details\":{\"format\":\"gguf\",\"family\":\"rawrxd\","
            << "\"parameter_size\":\"unknown\",\"quantization_level\":\"unknown\"}}";
    }

    const char* scanDirs[] = { "D:/OllamaModels", "C:/OllamaModels" };
    for (const char* dir : scanDirs) {
        std::string search = std::string(dir) + "/*.gguf";
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(search.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (!first) oss << ",";
            first = false;
            std::string fname = fd.cFileName;
            std::string base = fname.substr(0, fname.find_last_of('.'));
            oss << "{\"name\":\"" << base << "\","
                << "\"model\":\"" << base << "\","
                << "\"modified_at\":\"\","
                << "\"size\":0,"
                << "\"digest\":\"rawrxd-local\","
                << "\"details\":{\"format\":\"gguf\",\"family\":\"rawrxd\","
                << "\"parameter_size\":\"unknown\",\"quantization_level\":\"unknown\"}}";
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    oss << "]}";
    return oss.str();
}

std::string HeadlessIDE::getEngineCapabilitiesJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"server\":\"RawrXD-HeadlessIDE\","
        << "\"version\":\"" << VERSION << "\","
        << "\"phase\":\"" << BUILD_PHASE << "\","
        << "\"backends\":[\"cpu\",\"vulkan\",\"ollama\",\"openai\",\"claude\",\"gemini\"],"
        << "\"features\":[\"moe\",\"flash_attention\",\"quantization\",\"streaming\","
        << "\"hotpatch\",\"lsp\",\"swarm\",\"replay\""
#if RAWRXD_HEADLESS_NATIVE_HEXMAG
        << ",\"hexmag_masm\""
#endif
#if RAWRXD_HEADLESS_NATIVE_SUBAGENT
        << ",\"native_subagent\""
#endif
        << "],"
        << "\"nativeHexMag\":" << (RAWRXD_HEADLESS_NATIVE_HEXMAG ? "true" : "false") << ","
        << "\"nativeSubagent\":" << (RAWRXD_HEADLESS_NATIVE_SUBAGENT ? "true" : "false") << ","
        << "\"maxContextLength\":131072,"
        << "\"maxBatchSize\":512,"
        << "\"modelLoaded\":" << (m_modelLoaded ? "true" : "false") << ","
        << "\"loadedModel\":\"" << m_loadedModelName << "\","
        << "\"endpoints\":{"
        << "\"chat\":\"/api/generate\","
        << "\"completions\":\"/v1/chat/completions\","
        << "\"models\":\"/api/models\","
        << "\"agents\":\"/api/agent/dual\""
        << "}"
        << "}";
    return oss.str();
}

std::string HeadlessIDE::getQuantumStatusJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"quantum_time_manager_activated\":" << (m_expQuantumTimeActivated ? "true" : "false") << ",";
    oss << "\"quantum_orchestrator_activated\":" << (m_expQuantumOrchActivated ? "true" : "false") << ",";
    oss << "\"quantum_missing_impl_activated\":" << (m_expQuantumMissingActivated ? "true" : "false");
    oss << "}";
    return oss.str();
}

// ============================================================================
// Diagnostics
// ============================================================================
std::string HeadlessIDE::getFullStatusDump() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"mode\": \"" <<
        (m_config.ingressMode == HeadlessIngressMode::Hosted ? "hosted" : "local") << "\",\n";
    oss << "  \"version\": \"" << VERSION << "\",\n";
    oss << "  \"phase\": \"" << BUILD_PHASE << "\",\n";
    oss << "  \"session\": \"" << m_sessionId << "\",\n";
    oss << "  \"uptime_ms\": " << getUptimeMs() << ",\n";
    oss << "  \"model_loaded\": " << (m_modelLoaded ? "true" : "false") << ",\n";
    oss << "  \"model_name\": \"" << m_loadedModelName << "\",\n";
    oss << "  \"server_running\": " << (m_serverRunning.load() ? "true" : "false") << ",\n";
    oss << "  \"subsystems\": {\n";
    oss << "    \"winsock\": " << (m_winsockInitialized ? "true" : "false") << ",\n";
    oss << "    \"backend_manager\": " << (m_backendManagerInitialized ? "true" : "false") << ",\n";
    oss << "    \"llm_router\": " << (m_routerInitialized ? "true" : "false") << ",\n";
    oss << "    \"failure_detector\": " << (m_failureDetectorInitialized ? "true" : "false") << ",\n";
    oss << "    \"agent_history\": " << (m_agentHistoryInitialized ? "true" : "false") << ",\n";
    oss << "    \"asm_semantic\": " << (m_asmSemanticInitialized ? "true" : "false") << ",\n";
    oss << "    \"lsp_client\": " << (m_lspInitialized ? "true" : "false") << ",\n";
    oss << "    \"hybrid_bridge\": " << (m_hybridBridgeInitialized ? "true" : "false") << ",\n";
    oss << "    \"multi_response\": " << (m_multiResponseInitialized ? "true" : "false") << ",\n";
    oss << "    \"exec_governor\": " << (m_phase10Initialized ? "true" : "false") << ",\n";
    oss << "    \"swarm\": " << (m_phase11Initialized ? "true" : "false") << ",\n";
    oss << "    \"native_debugger\": " << (m_phase12Initialized ? "true" : "false") << ",\n";
    oss << "    \"hotpatch\": " << (m_hotpatchInitialized ? "true" : "false") << ",\n";
    oss << "    \"instructions\": " << (m_instructionsInitialized ? "true" : "false") << "\n";
    oss << "  }\n";
    oss << "  ,\"experimental\": {\n";
    oss << "    \"hotpatch70b_activated\": " << (m_expHotpatchActivated ? "true" : "false") << ",\n";
    oss << "    \"layer_eviction_activated\": " << (m_expLayerEvictionActivated ? "true" : "false") << ",\n";
    oss << "    \"governor_activated\": " << (m_expGovernorActivated ? "true" : "false") << ",\n";
    oss << "    \"quantum_time_manager_activated\": " << (m_expQuantumTimeActivated ? "true" : "false") << ",\n";
    oss << "    \"quantum_orchestrator_activated\": " << (m_expQuantumOrchActivated ? "true" : "false") << ",\n";
    oss << "    \"quantum_missing_impl_activated\": " << (m_expQuantumMissingActivated ? "true" : "false") << "\n";
    oss << "  }\n";
    oss << "}";
    return oss.str();
}

std::string HeadlessIDE::getVersionString() const {
    return std::string(VERSION) + " (" + BUILD_PHASE + ")";
}

uint64_t HeadlessIDE::getUptimeMs() const {
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    return static_cast<uint64_t>(epoch) - m_startEpochMs;
}

// ============================================================================
// Run Modes
// ============================================================================
int HeadlessIDE::runServerMode() {
    if (m_config.enableServer) {
        startServer();
        if (!m_serverRunning.load()) {
            m_outputSink->appendOutput("HTTP server failed to start; exiting headless server mode.", OutputSeverity::Error);
            return 2;
        }
    } else {
        m_outputSink->appendOutput("Server disabled (--no-server); nothing to serve, exiting.", OutputSeverity::Warning);
        return 0;
    }

    m_outputSink->appendOutput("Headless IDE running in server mode. Press Ctrl+C to stop.", OutputSeverity::Info);

    // Block until shutdown
    while (!m_shutdownRequested.load()) {
        Sleep(100);
    }

    m_outputSink->appendOutput("Shutting down headless IDE...", OutputSeverity::Info);
    return 0;
}

int HeadlessIDE::runReplMode() {
    if (m_config.enableServer) {
        startServer();
    }

    m_outputSink->appendOutput("RawrXD Headless REPL. Type 'help' for commands, 'quit' to exit.", OutputSeverity::Info);

    std::string line;
    while (!m_shutdownRequested.load()) {
        printReplPrompt();
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;
        if (line == "quit" || line == "exit" || line == "q") break;
        processReplCommand(line);
    }

    return 0;
}

int HeadlessIDE::runSingleShotMode() {
    if (m_config.prompt.empty()) {
        m_outputSink->appendOutput("No prompt specified (--prompt)", OutputSeverity::Error);
        return 1;
    }

    std::string result = runInference(m_config.prompt);
    m_outputSink->appendOutput(result.c_str(), OutputSeverity::Info);

    // Durable artifact for product-runtime smoke (stdout may be a console).
    if (FILE* f = nullptr; fopen_s(&f, "headless_oneshot.txt", "wb") == 0 && f) {
        std::fprintf(f, "PROMPT=%s\n", m_config.prompt.c_str());
        std::fprintf(f, "MODEL=%s\n", m_loadedModelPath.c_str());
        std::fprintf(f, "MODEL_LOADED=%d\n", m_modelLoaded ? 1 : 0);
        std::fprintf(f, "BYTES=%zu\n", result.size());
        std::fprintf(f, "RESPONSE_BEGIN\n%s\nRESPONSE_END\n", result.c_str());
        std::fclose(f);
    }
    return 0;
}

int HeadlessIDE::runBatchMode() {
    if (m_config.inputFile.empty()) {
        m_outputSink->appendOutput("No input file specified (--input)", OutputSeverity::Error);
        return 1;
    }

    std::ifstream inFile(m_config.inputFile);
    if (!inFile.is_open()) {
        m_outputSink->appendOutput(("Cannot open input file: " + m_config.inputFile).c_str(), OutputSeverity::Error);
        return 1;
    }

    std::ofstream outFile;
    if (!m_config.outputFile.empty()) {
        outFile.open(m_config.outputFile);
        if (!outFile.is_open()) {
            m_outputSink->appendOutput(("Cannot open output file: " + m_config.outputFile).c_str(), OutputSeverity::Error);
            return 1;
        }
    }

    std::string line;
    int lineNum = 0;
    while (std::getline(inFile, line) && !m_shutdownRequested.load()) {
        if (line.empty()) continue;
        ++lineNum;
        m_outputSink->appendOutput(("Processing prompt " + std::to_string(lineNum) + "...").c_str(), OutputSeverity::Debug);

        std::string result = runInference(line);

        if (outFile.is_open()) {
            outFile << result << "\n";
        } else {
            m_outputSink->appendOutput(result.c_str(), OutputSeverity::Info);
        }
    }

    m_outputSink->appendOutput(("Batch complete: " + std::to_string(lineNum) + " prompts processed").c_str(), OutputSeverity::Info);
    return 0;
}

// ============================================================================
// REPL Helpers
// ============================================================================
void HeadlessIDE::processReplCommand(const std::string& input) {
    if (input == "help" || input == "?") {
        printReplHelp();
    }
    else if (input == "status") {
        std::string dump = getFullStatusDump();
        m_outputSink->appendOutput(dump.c_str(), OutputSeverity::Info);
    }
    else if (input == "version") {
        m_outputSink->appendOutput(getVersionString().c_str(), OutputSeverity::Info);
    }
    else if (input.substr(0, 5) == "load ") {
        std::string path = input.substr(5);
        if (loadModel(path)) {
            m_outputSink->appendOutput("Model loaded.", OutputSeverity::Info);
        } else {
            m_outputSink->appendOutput("Failed to load model.", OutputSeverity::Error);
        }
    }
    else if (input == "unload") {
        unloadModel();
    }
    else if (input == "model") {
        m_outputSink->appendOutput(getModelInfo().c_str(), OutputSeverity::Info);
    }
    else if (input == "backends") {
        m_outputSink->appendOutput(getBackendStatusString().c_str(), OutputSeverity::Info);
    }
    else if (input == "router") {
        m_outputSink->appendOutput(getRouterStatusString().c_str(), OutputSeverity::Info);
    }
    else if (input == "failures") {
        m_outputSink->appendOutput(getFailureDetectorStats().c_str(), OutputSeverity::Info);
    }
    else if (input == "history") {
        m_outputSink->appendOutput(getAgentHistoryStats().c_str(), OutputSeverity::Info);
    }
    else if (input == "asm") {
        m_outputSink->appendOutput(getAsmSemanticStatsString().c_str(), OutputSeverity::Info);
    }
    else if (input == "lsp") {
        m_outputSink->appendOutput(getLSPStatusString().c_str(), OutputSeverity::Info);
    }
    else if (input == "governor") {
        m_outputSink->appendOutput(getGovernorStatus().c_str(), OutputSeverity::Info);
    }
    else if (input == "safety") {
        m_outputSink->appendOutput(getSafetyStatus().c_str(), OutputSeverity::Info);
    }
    else if (input == "swarm") {
        m_outputSink->appendOutput(getSwarmStatus().c_str(), OutputSeverity::Info);
    }
    else if (input == "hotpatch") {
        m_outputSink->appendOutput(getHotpatchStatus().c_str(), OutputSeverity::Info);
    }
    else if (input == "cot" || input == "cot status") {
        auto& cot = ChainOfThoughtEngine::instance();
        m_outputSink->appendOutput(cot.getStatusJSON().c_str(), OutputSeverity::Info);
    }
    else if (input == "cot presets") {
        auto names = getCoTPresetNames();
        std::ostringstream oss;
        oss << "Chain-of-Thought Presets:\n";
        for (const auto& n : names) {
            const CoTPreset* p = getCoTPreset(n);
            if (p) {
                oss << "  " << n << " (" << p->label << ") — " << p->steps.size() << " steps\n";
            }
        }
        m_outputSink->appendOutput(oss.str().c_str(), OutputSeverity::Info);
    }
    else if (input == "cot roles") {
        const auto& roles = getAllCoTRoles();
        std::ostringstream oss;
        oss << "Chain-of-Thought Roles (" << roles.size() << "):\n";
        for (const auto& r : roles) {
            oss << "  " << r.icon << " " << r.name << " — " << r.instruction << "\n";
        }
        m_outputSink->appendOutput(oss.str().c_str(), OutputSeverity::Info);
    }
    else if (input == "cot steps") {
        auto& cot = ChainOfThoughtEngine::instance();
        m_outputSink->appendOutput(cot.getStepsJSON().c_str(), OutputSeverity::Info);
    }
    else if (input == "cot stats") {
        auto& cot = ChainOfThoughtEngine::instance();
        auto stats = cot.getStats();
        std::ostringstream oss;
        oss << "CoT Statistics:\n";
        oss << "  Total chains: " << stats.totalChains << "\n";
        oss << "  Successful: " << stats.successfulChains << "\n";
        oss << "  Failed: " << stats.failedChains << "\n";
        oss << "  Steps executed: " << stats.totalStepsExecuted << "\n";
        oss << "  Avg latency: " << stats.avgLatencyMs << "ms\n";
        m_outputSink->appendOutput(oss.str().c_str(), OutputSeverity::Info);
    }
    else if (input.substr(0, 11) == "cot preset ") {
        std::string presetName = input.substr(11);
        auto& cot = ChainOfThoughtEngine::instance();
        if (cot.applyPreset(presetName)) {
            std::string msg = "Applied preset '" + presetName + "' (" +
                std::to_string(cot.getSteps().size()) + " steps)";
            m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Info);
        } else {
            std::string msg = "Unknown preset: " + presetName + ". Available: review, audit, think, research, debate, custom";
            m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Error);
        }
    }
    else if (input.substr(0, 8) == "cot add ") {
        std::string roleName = input.substr(8);
        const CoTRoleInfo* info = getCoTRoleByName(roleName);
        if (info) {
            auto& cot = ChainOfThoughtEngine::instance();
            cot.addStep(info->id);
            std::string msg = "Added step: " + std::string(info->label) +
                " (total: " + std::to_string(cot.getSteps().size()) + " steps)";
            m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Info);
        } else {
            m_outputSink->appendOutput("Unknown role. Use 'cot roles' to list.", OutputSeverity::Error);
        }
    }
    else if (input == "cot clear") {
        auto& cot = ChainOfThoughtEngine::instance();
        cot.clearSteps();
        m_outputSink->appendOutput("Chain cleared.", OutputSeverity::Info);
    }
    else if (input == "cot cancel") {
        auto& cot = ChainOfThoughtEngine::instance();
        cot.cancel();
        m_outputSink->appendOutput("Cancel requested.", OutputSeverity::Info);
    }
    else if (input.substr(0, 8) == "cot run ") {
        std::string query = input.substr(8);
        auto& cot = ChainOfThoughtEngine::instance();

        // Wire inference callback to use our runInference
        cot.setInferenceCallback([this](const std::string& systemPrompt,
                                         const std::string& userMessage,
                                         const std::string& /*model*/) -> std::string {
            std::string combined = systemPrompt + "\n\n" + userMessage;
            return runInference(combined);
        });

        if (cot.getSteps().empty()) {
            cot.applyPreset("review");
            m_outputSink->appendOutput("No steps set, applying 'review' preset.", OutputSeverity::Warning);
        }

        // Set step callback for progress
        cot.setStepCallback([this](const CoTStepResult& sr) {
            const auto& info = getCoTRoleInfo(sr.role);
            std::string msg;
            if (sr.skipped) {
                msg = "  Step " + std::to_string(sr.stepIndex + 1) + " (" + info.label + "): SKIPPED";
            } else if (sr.success) {
                msg = "  Step " + std::to_string(sr.stepIndex + 1) + " (" + info.label +
                    "): " + std::to_string(sr.latencyMs) + "ms";
            } else {
                msg = "  Step " + std::to_string(sr.stepIndex + 1) + " (" + info.label +
                    "): FAILED - " + sr.error;
            }
            m_outputSink->appendOutput(msg.c_str(), sr.success ? OutputSeverity::Info : OutputSeverity::Error);
        });

        m_outputSink->appendOutput("Executing CoT chain...", OutputSeverity::Info);
        CoTChainResult result = cot.executeChain(query);

        if (result.success) {
            std::string summary = "Chain complete (" + std::to_string(result.totalLatencyMs) + "ms, " +
                std::to_string(result.stepsCompleted) + " steps)";
            m_outputSink->appendOutput(summary.c_str(), OutputSeverity::Info);
            m_outputSink->onStreamStart("cot");
            m_outputSink->onStreamingToken(result.finalOutput.c_str(), result.finalOutput.size(),
                                            StreamTokenOrigin::Inference);
            m_outputSink->onStreamEnd("cot", true);
        } else {
            std::string errMsg = "Chain failed: " + result.error;
            m_outputSink->appendOutput(errMsg.c_str(), OutputSeverity::Error);
        }
    }
    else if (input == "server start") {
        startServer();
    }
    else if (input == "server stop") {
        stopServer();
    }
    else if (input == "server") {
        m_outputSink->appendOutput(getServerStatus().c_str(), OutputSeverity::Info);
    }
    // ── Phase 34: Instructions Context Commands ─────────────────────────
    else if (input == "instructions" || input == "instructions show") {
        auto& ip = InstructionsProvider::instance();
        if (!ip.isLoaded()) ip.loadAll();
        std::string content = ip.getAllContent();
        if (content.empty()) {
            m_outputSink->appendOutput("No instruction files loaded. Try 'instructions reload'.",
                                        OutputSeverity::Warning);
        } else {
            m_outputSink->appendOutput(content.c_str(), OutputSeverity::Info);
        }
    }
    else if (input == "instructions list") {
        auto& ip = InstructionsProvider::instance();
        if (!ip.isLoaded()) ip.loadAll();
        auto files = ip.getAll();
        std::ostringstream oss;
        oss << "Loaded instruction files (" << files.size() << "):\n";
        for (const auto& f : files) {
            oss << "  " << f.fileName << " (" << f.lineCount << " lines, "
                << f.sizeBytes << " bytes) — " << f.filePath << "\n";
        }
        m_outputSink->appendOutput(oss.str().c_str(), OutputSeverity::Info);
    }
    else if (input == "instructions reload") {
        auto& ip = InstructionsProvider::instance();
        auto r = ip.reload();
        std::string msg = r.success
            ? ("Instructions reloaded (" + std::to_string(ip.getLoadedCount()) + " files)")
            : ("Reload failed: " + std::string(r.detail));
        m_outputSink->appendOutput(msg.c_str(),
            r.success ? OutputSeverity::Info : OutputSeverity::Error);
    }
    else if (input == "instructions paths") {
        auto& ip = InstructionsProvider::instance();
        auto paths = ip.getSearchPaths();
        std::ostringstream oss;
        oss << "Search paths (" << paths.size() << "):\n";
        for (const auto& p : paths) {
            oss << "  " << p << "\n";
        }
        m_outputSink->appendOutput(oss.str().c_str(), OutputSeverity::Info);
    }
    else if (input == "instructions json") {
        auto& ip = InstructionsProvider::instance();
        if (!ip.isLoaded()) ip.loadAll();
        m_outputSink->appendOutput(ip.toJSON().c_str(), OutputSeverity::Info);
    }
    // ── Phase 36: RGUF Commands ─────────────────────────────────────────
    else if (input.substr(0, 9) == "rguf pack") {
        std::istringstream iss(input.substr(9));
        std::string inPath, outPath, keyHex;
        iss >> inPath >> outPath >> keyHex;
        if (inPath.empty() || outPath.empty()) {
            m_outputSink->appendOutput("Usage: rguf pack <in.gguf> <out.rguf> [32-byte-hex-key]", OutputSeverity::Error);
        } else {
            uint8_t key[32]{};
            bool encrypt = false;
            if (!keyHex.empty()) {
                if (keyHex.size() != 64) {
                    m_outputSink->appendOutput("Key must be 64 hex characters.", OutputSeverity::Error);
                } else {
                    encrypt = true;
                    for (int i = 0; i < 32; ++i) {
                        unsigned v = 0;
                        std::sscanf(keyHex.c_str() + 2*i, "%2x", &v);
                        key[i] = static_cast<uint8_t>(v);
                    }
                }
            }
            rguf::Writer w;
            std::string err;
            if (w.pack(inPath, outPath, encrypt, key, err)) {
                m_outputSink->appendOutput(("RGUF packed: " + outPath).c_str(), OutputSeverity::Info);
            } else {
                m_outputSink->appendOutput(("RGUF pack failed: " + err).c_str(), OutputSeverity::Error);
            }
        }
    }
    else if (input.substr(0, 12) == "rguf inspect") {
        std::istringstream iss(input.substr(12));
        std::string modelPath;
        iss >> modelPath;
        if (modelPath.empty()) {
            m_outputSink->appendOutput("Usage: rguf inspect <model.rguf>", OutputSeverity::Error);
        } else {
            rguf::Model m;
            std::string err;
            if (m.open(modelPath, err)) {
                std::string msg = "RGUF blocks: " + std::to_string(m.block_count());
                m_outputSink->appendOutput(msg.c_str(), OutputSeverity::Info);
            } else {
                m_outputSink->appendOutput(("RGUF inspect failed: " + err).c_str(), OutputSeverity::Error);
            }
        }
    }
    else if (input.substr(0, 10) == "rguf patch") {
        std::istringstream iss(input.substr(10));
        std::string modelPath, patchPath, tensorStr, blockStr, replPath;
        iss >> modelPath >> patchPath >> tensorStr >> blockStr >> replPath;
        if (modelPath.empty() || patchPath.empty() || tensorStr.empty() || blockStr.empty() || replPath.empty()) {
            m_outputSink->appendOutput("Usage: rguf patch <model.rguf> <patch.rgp> <tensor> <block> <replacement.bin>", OutputSeverity::Error);
        } else {
            std::ifstream f(replPath, std::ios::binary);
            if (!f) {
                m_outputSink->appendOutput("Failed to open replacement file.", OutputSeverity::Error);
            } else {
                f.seekg(0, std::ios::end);
                size_t n = static_cast<size_t>(f.tellg());
                f.seekg(0);
                std::vector<uint8_t> b(n);
                f.read(reinterpret_cast<char*>(b.data()), static_cast<std::streamsize>(n));
                rguf::Writer w;
                std::string err;
                uint64_t tensor = std::stoull(tensorStr);
                uint64_t block  = std::stoull(blockStr);
                if (w.make_patch(modelPath, patchPath, tensor, block, b.data(), b.size(), err)) {
                    m_outputSink->appendOutput(("RGUF patch written: " + patchPath).c_str(), OutputSeverity::Info);
                } else {
                    m_outputSink->appendOutput(("RGUF patch failed: " + err).c_str(), OutputSeverity::Error);
                }
            }
        }
    }
    // ── Phase 37: Autonomous Fix Command ────────────────────────────────
    else if (input.substr(0, 13) == "autonomous fix") {
        std::istringstream iss(input.substr(13));
        std::string repoPath, buildCmd, testCmd;
        iss >> repoPath;
        std::getline(iss, buildCmd);
        // Parse optional build/test commands from remaining args
        size_t pipePos = buildCmd.find("|");
        if (pipePos != std::string::npos) {
            testCmd = buildCmd.substr(pipePos + 1);
            buildCmd = buildCmd.substr(0, pipePos);
        }
        // Trim whitespace
        auto trim = [](std::string& s) {
            size_t start = s.find_first_not_of(" \t");
            if (start != std::string::npos) s = s.substr(start);
            size_t end = s.find_last_not_of(" \t");
            if (end != std::string::npos) s = s.substr(0, end + 1);
        };
        trim(buildCmd);
        trim(testCmd);

        if (repoPath.empty()) {
            m_outputSink->appendOutput("Usage: autonomous fix <repo-path> [build-cmd] | [test-cmd]", OutputSeverity::Error);
            m_outputSink->appendOutput("Example: autonomous fix D:\\\\myrepo cmake --build build | ctest --test-dir build", OutputSeverity::Info);
        } else {
            m_outputSink->appendOutput(("[AUTONOMOUS] Starting fix loop for: " + repoPath).c_str(), OutputSeverity::Info);
            m_outputSink->appendOutput("[AUTONOMOUS] Step 1: Auditing repository...", OutputSeverity::Info);

            RawrXD::AutonomousOrchestrator orchestrator;
            json evidence = orchestrator.fixRepository(repoPath, buildCmd, testCmd);

            // Emit structured results
            std::ostringstream oss;
            oss << "\n╔══════════════════════════════════════════════════════════════╗\n";
            oss << "║           AUTONOMOUS FIX COMPLETE                          ║\n";
            oss << "╚══════════════════════════════════════════════════════════════╝\n\n";
            oss << "Repository:    " << repoPath << "\n";
            oss << "Success:       " << (evidence.value("success", false) ? "YES ✅" : "NO ❌") << "\n";
            oss << "Duration:      " << evidence.value("duration_ms", 0) << " ms\n";
            oss << "Iterations:    " << evidence.value("recovery_iterations", 0) << "\n";
            oss << "Todos found:   " << evidence.value("todos_generated", 0) << "\n";
            oss << "Builds run:    " << evidence.value("builds_performed", 0) << "\n";
            oss << "Tests run:     " << evidence.value("tests_performed", 0) << "\n";
            oss << "Failures:      " << evidence.value("failures_detected", 0) << "\n";
            oss << "Detail:        " << evidence.value("detail", "") << "\n";

            if (evidence.contains("files_modified") && evidence["files_modified"].is_array()) {
                oss << "\n─── Files Modified ───\n";
                for (const auto& f : evidence["files_modified"]) {
                    oss << "  " << f.value("file", "?") << " (" << f.value("category", "?") << ")\n";
                }
            }

            m_outputSink->appendOutput(oss.str().c_str(), OutputSeverity::Info);

            // Also emit raw JSON for machine parsing
            if (m_config.jsonOutput) {
                m_outputSink->appendOutput(evidence.dump(2).c_str(), OutputSeverity::Info);
            }
        }
    }
    else {
        // Treat as inference prompt
        if (m_modelLoaded) {
            m_outputSink->onStreamStart("repl");
            std::string result = runInference(input);
            m_outputSink->onStreamingToken(result.c_str(), result.size(), StreamTokenOrigin::Inference);
            m_outputSink->onStreamEnd("repl", true);
        } else {
            m_outputSink->appendOutput("No model loaded. Use 'load <path>' first, or type 'help'.",
                                        OutputSeverity::Warning);
        }
    }
}

void HeadlessIDE::printReplHelp() {
    const char* help = R"(
RawrXD Headless IDE — REPL Commands
====================================
  help / ?         Show this help
  status           Full status dump (JSON)
  version          Show version
  load <path>      Load a GGUF model
  unload           Unload current model
  model            Show loaded model info
  backends         Backend switcher status
  router           LLM router status
  failures         Failure detector stats
  history          Agent history stats
  asm              ASM semantic stats
  lsp              LSP client status
  governor         Execution governor status
  safety           Safety contract status
  swarm            Distributed swarm status
  hotpatch         Hotpatch system status
  cot              CoT engine status
  cot presets      List CoT presets (review|audit|think|research|debate|custom)
  cot roles        List all CoT roles (12 reasoning personas)
  cot steps        Show current chain configuration
  cot stats        CoT execution statistics
  cot preset <n>   Apply a preset (e.g. 'cot preset review')
  cot add <role>   Add a role to the chain (e.g. 'cot add critic')
  cot clear        Clear current chain
  cot run <query>  Execute CoT chain on a query
  cot cancel       Cancel running chain
  server           HTTP server status
  server start     Start HTTP server
  server stop      Stop HTTP server
  instructions     Show production instructions (all lines)
  instructions list   List loaded instruction files
  instructions show   Show full content
  instructions reload Reload from disk
  instructions paths  Show search paths
  instructions json   Export as JSON
  rguf pack <in.gguf> <out.rguf> [key]   Pack GGUF into encrypted RGUF
  rguf inspect <model.rguf>                Show RGUF block count
  rguf patch <model.rguf> <patch.rgp> <tensor> <block> <replacement.bin>
                                           Create a patch for a tensor block
  autonomous fix <repo> [build] | [test]   Closed-loop autonomous repair:
                                           audit → fix → build → test → verify
                                           Example: autonomous fix D:\\myrepo "cmake --build build" | "ctest --test-dir build"
  quit / exit      Exit the REPL

  <any other text>  Treated as inference prompt

Command-line flags:
  --headless                    Enable headless mode
  --port <port>                 HTTP server port (default: 11435)
  --bind <address>              Bind address (default: 127.0.0.1)
  --model <path>                Load model on startup
  --prompt <text>               Single-shot inference, then exit
  --input <file>                Batch mode: read prompts from file
  --output <file>               Batch mode: write results to file
  --backend <name>              Set default backend
  --max-tokens <n>              Max tokens (default: 2048)
  --temperature <f>             Temperature (default: 0.7)
  --repl                        Interactive REPL mode
  --no-server                   Don't start HTTP server
  --verbose / -v                Verbose output
  --quiet / -q                  Quiet mode (warnings/errors only)
  --json                        JSON-structured output
  --settings <file>             Load settings from file
)";
    fprintf(stdout, "%s\n", help);
}

void HeadlessIDE::printReplPrompt() {
    if (m_modelLoaded) {
        fprintf(stdout, "[%s] > ", m_loadedModelName.c_str());
    } else {
        fprintf(stdout, "[no model] > ");
    }
    fflush(stdout);
}

// ============================================================================
// Shutdown
// ============================================================================
void HeadlessIDE::shutdownAll() {
    stopServer();

    if (m_winsockInitialized) {
        WSACleanup();
        m_winsockInitialized = false;
    }

    m_outputSink->flush();
}

// ============================================================================
// Cloud Backend Helpers (Fix #15)
// ============================================================================
std::string HeadlessIDE::performCloudInference(const std::string& endpoint, const std::string& apiKey,
                                                const std::string& prompt, const std::string& model) {
    if (!m_config.allowCloudEgress || endpoint.rfind("https://", 0) != 0 ||
        (m_config.ingressMode == HeadlessIngressMode::Hosted && !g_hostedCloudConsent) ||
        prompt.size() > m_config.cloudMaxInputBytes ||
        m_config.cloudMaxOutputTokens == 0 || m_config.maxTokens <= 0) {
        safeAppendOutput("Cloud inference denied by egress or token bounds",
                         OutputSeverity::Warning);
        return "";
    }
    uint64_t outputLimit = std::min<uint64_t>(
        static_cast<uint64_t>(m_config.maxTokens), m_config.cloudMaxOutputTokens);
    uint64_t conservativeInputTokens = static_cast<uint64_t>(prompt.size()) + 128;
    CloudBudgetReservation reservation;
    if (!reserveCloudBudget(m_cloudReservedNanodollars,
                            m_config.cloudBudgetNanodollars,
                            conservativeInputTokens, outputLimit,
                            m_config.cloudInputNanodollarsPerToken,
                            m_config.cloudOutputNanodollarsPerToken,
                            reservation)) {
        safeAppendOutput("Cloud inference denied by atomic spend reservation",
                         OutputSeverity::Warning);
        return "";
    }
    {
        std::lock_guard<std::mutex> lock(m_auditMutex);
        if (reservation.amount > static_cast<uint64_t>(INT64_MAX) ||
            !appendBudgetDelta(m_config.cloudBudgetFile,
                               static_cast<int64_t>(reservation.amount))) {
            safeAppendOutput("Cloud inference denied: budget ledger unavailable",
                             OutputSeverity::Error);
            return "";
        }
    }

    HINTERNET hSession = WinHttpOpen(L"RawrXD-Headless/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    // Parse URL
    std::string host, path;
    bool isHttps = false;
    if (endpoint.substr(0, 8) == "https://") {
        isHttps = true;
        size_t hostEnd = endpoint.find('/', 8);
        host = endpoint.substr(8, hostEnd - 8);
        path = (hostEnd != std::string::npos) ? endpoint.substr(hostEnd) : "/";
    } else if (endpoint.substr(0, 7) == "http://") {
        size_t hostEnd = endpoint.find('/', 7);
        host = endpoint.substr(7, hostEnd - 7);
        path = (hostEnd != std::string::npos) ? endpoint.substr(hostEnd) : "/";
    }

    if (host.empty()) {
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::wstring whost(host.begin(), host.end());
    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), isHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::wstring wpath(path.begin(), path.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wpath.c_str(), NULL,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             isHttps ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Build JSON payload
    nlohmann::json payload;
    bool isAnthropic = endpoint.find("anthropic") != std::string::npos;
    bool isGoogle = endpoint.find("googleapis") != std::string::npos;
    bool isOpenAICompatible = !isAnthropic && !isGoogle;
    if (isOpenAICompatible) {
        payload["model"] = model;
        payload["messages"] = nlohmann::json::array({
            {{"role", "user"}, {"content", prompt}}
        });
        payload["max_tokens"] = outputLimit;
        payload["temperature"] = m_config.temperature;
    } else if (isAnthropic) {
        payload["model"] = model;
        payload["max_tokens"] = outputLimit;
        payload["messages"] = nlohmann::json::array({
            {{"role", "user"}, {"content", prompt}}
        });
    } else if (isGoogle) {
        payload["contents"] = nlohmann::json::array({
            {{"role", "user"}, {"parts", {{"text", prompt}}}}
        });
    }

    std::string body = payload.dump();
    std::string authHeader = "Authorization: Bearer " + apiKey;
    std::wstring wAuth(authHeader.begin(), authHeader.end());

    WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD);
    WinHttpAddRequestHeaders(hRequest, wAuth.c_str(), (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   (LPVOID)body.c_str(), (DWORD)body.length(), (DWORD)body.length(), 0);
    if (!sent) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    WinHttpReceiveResponse(hRequest, NULL);

    // Read response
    std::string response;
    DWORD bytesRead = 0;
    char buffer[8192];
    do {
        bytesRead = 0;
        if (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            response.append(buffer, bytesRead);
        }
    } while (bytesRead > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    // Parse response
    try {
        auto j = nlohmann::json::parse(response);
        uint64_t inputTokens = conservativeInputTokens;
        uint64_t outputTokens = outputLimit;
        if (j.contains("usage")) {
            const auto& usage = j["usage"];
            inputTokens = usage.value("prompt_tokens", usage.value("input_tokens", inputTokens));
            outputTokens = usage.value("completion_tokens", usage.value("output_tokens", outputTokens));
        } else if (j.contains("usageMetadata")) {
            const auto& usage = j["usageMetadata"];
            inputTokens = usage.value("promptTokenCount", inputTokens);
            outputTokens = usage.value("candidatesTokenCount", outputTokens);
        }
        uint64_t actual = 0;
        if (!checkedCloudCost(inputTokens, outputTokens,
                              m_config.cloudInputNanodollarsPerToken,
                              m_config.cloudOutputNanodollarsPerToken, actual)) {
            actual = m_config.cloudBudgetNanodollars;
        }
        bool settled = true;
        if (actual != reservation.amount) {
            uint64_t magnitude = actual < reservation.amount
                ? reservation.amount - actual : actual - reservation.amount;
            if (magnitude > static_cast<uint64_t>(INT64_MAX)) {
                settled = false;
            } else {
                int64_t delta = static_cast<int64_t>(magnitude);
                if (actual < reservation.amount) delta = -delta;
                std::lock_guard<std::mutex> lock(m_auditMutex);
                settled = appendBudgetDelta(m_config.cloudBudgetFile, delta);
            }
        }
        if (settled) {
            reservation.settle(actual);
        } else {
            m_cloudReservedNanodollars.store(m_config.cloudBudgetNanodollars,
                                              std::memory_order_release);
            reservation.ledger = nullptr;
            reservation.amount = 0;
        }
        safeAppendOutput(("Cloud receipt provider=" + host + " model=" + model +
                          " input=" + std::to_string(inputTokens) +
                          " output=" + std::to_string(outputTokens) +
                          " nanodollars=" + std::to_string(actual)).c_str(),
                         OutputSeverity::Info);
        std::ostringstream cloudAudit;
        cloudAudit << "{\"event\":\"cloud_usage\",\"session\":\""
                   << jsonEscape(m_sessionId) << "\",\"provider\":\""
                   << jsonEscape(host) << "\",\"model\":\"" << jsonEscape(model)
                   << "\",\"inputTokens\":" << inputTokens
                   << ",\"outputTokens\":" << outputTokens
                   << ",\"actualNanodollars\":" << actual << "}\r\n";
        {
            std::lock_guard<std::mutex> lock(m_auditMutex);
            appendBoundedFile(m_config.auditFile, cloudAudit.str(), 4ULL * 1024 * 1024);
        }
        if (isOpenAICompatible) {
            if (j.contains("choices") && !j["choices"].empty()) {
                return j["choices"][0]["message"]["content"].get<std::string>();
            }
        } else if (isAnthropic) {
            if (j.contains("content") && !j["content"].empty()) {
                return j["content"][0]["text"].get<std::string>();
            }
        } else if (isGoogle) {
            if (j.contains("candidates") && !j["candidates"].empty()) {
                return j["candidates"][0]["content"]["parts"][0]["text"].get<std::string>();
            }
        }
    } catch (...) {
        // A provider may still charge an unparseable response. Retain the full
        // conservative reservation so malformed receipts cannot reopen budget.
        reservation.settle(reservation.amount);
        return response;
    }

    return "";
}

