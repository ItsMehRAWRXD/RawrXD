/**
 * @file agent_driver.cpp
 * @brief RawrXD self-audit agent driver.
 *
 * Connects the verified local GGUF inference path (llama-server, OpenAI-compatible
 * endpoint) to an agentic tool loop over the RawrXD workspace.
 *
 * No mock inference: every token is produced by the local GGUF model served at
 * http://127.0.0.1:8080/v1/chat/completions. Every tool result recorded in the
 * ledger is the real result of the real command/file operation.
 *
 * Build (MSVC x64):
 *   cl /EHsc /std:c++17 /O2 /I F:\rawrxd\include agent_driver.cpp
 *       /link winhttp.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using json = nlohmann::json;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Configuration
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

static const char* WORKSPACE_ROOT = R"(F:\rawrxd)";
static const wchar_t* INFERENCE_HOST = L"127.0.0.1";
static const int   INFERENCE_PORT = 8080;
static const char* INFERENCE_PATH = "/v1/chat/completions";
static const char* MODEL_NAME = "llama3.2-3b";

static const int MAX_AGENT_TURNS = 14;     ///< bounded iterations
static const int MAX_TOOL_CALLS = 10;      ///< hard cap on tool invocations
static const int CMD_TIMEOUT_MS = 60000;  ///< command timeout
static const int MAX_LIST_ENTRIES = 220;  ///< bound repo listing output
static const int MAX_WALK_ENTRIES = 6000; ///< bound total filesystem walk
static const size_t MAX_READ_BYTES = 60 * 1024; ///< bound file read output
static const int MAX_SEARCH_HITS = 40;    ///< bound search output

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Utilities
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    return s;
}

// Forward declaration: used by the HTTP layer before its definition.
static std::string truncateForLedger(const std::string& s, size_t limit);

static std::string jsonEscape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

static void logLine(const std::string& msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("[%02d:%02d:%02d.%03d] %s\n", st.wHour, st.wMinute, st.wSecond,
           st.wMilliseconds, msg.c_str());
}

static std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0,
                                nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), n,
                        nullptr, nullptr);
    return out;
}

static std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n);
    return out;
}

/**
 * @brief Normalize a model-supplied path into a workspace-relative form.
 *
 * Small models emit paths like "/rawrxd/README.md", "F:/rawrxd/CMakeLists.txt",
 * or "\rawrxd\src\...". All of these must resolve to a workspace-relative path
 * before they can be used. Anything that still escapes the workspace (e.g.
 * contains ".." or a different root) is rejected by the caller.
 */
static std::string toWorkspaceRelative(const std::string& raw) {
    std::string p = raw;
    // Normalize separators to '/'.
    for (auto& c : p) if (c == '\\') c = '/';

    // Strip any drive/UNC prefix.
    size_t colon = p.find(':');
    if (colon != std::string::npos && colon + 1 < p.size())
        p = p.substr(colon + 1);

    // Strip the workspace-root prefix, e.g. "/F:/rawrxd/" -> "/".
    std::string rootLower = toLower(std::string(WORKSPACE_ROOT));
    for (auto& c : rootLower) if (c == '\\') c = '/';
    std::string pLower = toLower(p);
    size_t rootAt = pLower.find(rootLower);
    if (rootAt != std::string::npos)
        p = p.substr(rootAt + rootLower.size());

    // Strip leading separators.
    while (!p.empty() && (p.front() == '/' )) p.erase(p.begin());

    // Strip a leading component that repeats the workspace folder name.
    size_t slash = p.find('/');
    std::string first = slash == std::string::npos ? p : p.substr(0, slash);
    if (toLower(first) == "rawrxd") {
        p = (slash == std::string::npos) ? std::string(".") : p.substr(slash + 1);
    }

    if (p.empty()) p = ".";
    return p;
}

/**
 * @brief Resolve a workspace-scoped path to an absolute path.
 * @param raw      Model-supplied path (any of the accepted shapes).
 * @param mustExist Reject the path if it does not already exist.
 * @return Absolute normalized path, or empty string when the path escapes the
 *         workspace root or is missing (for existing-path tools).
 */
static std::string resolveWorkspacePath(const std::string& raw, bool mustExist) {
    std::string rel = toWorkspaceRelative(raw);
    if (rel.empty()) return {};
    if (rel.find("..") != std::string::npos) return {};

    fs::path root(WORKSPACE_ROOT);
    fs::path candidate = root / rel;

    std::error_code ec;
    fs::path abs = fs::weakly_canonical(candidate, ec);
    if (ec) abs = candidate.lexically_normal();

    // Reject anything outside the workspace root.
    auto rootStr = root.lexically_normal().wstring();
    auto absStr  = abs.wstring();
    if (rootStr.size() > absStr.size()) return {};
    if (absStr.compare(0, rootStr.size(), rootStr) != 0) return {};

    if (mustExist && !fs::exists(abs)) return {};
    return abs.string();
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// HTTP (WinHTTP) â€” inference call
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * @brief POST a JSON body to the local llama-server. Returns raw body text.
 *
 * @param timeoutMs overall wall-clock budget for the request.
 */
static std::string httpPost(const std::wstring& path, const std::string& body,
                            int timeoutMs, long* httpStatusOut,
                            std::string& errOut) {
    std::string response;

    HINTERNET session = WinHttpOpen(L"RawrXD-AuditAgent/1.0",
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { errOut = "WinHttpOpen failed"; return {}; }

    HINTERNET conn = WinHttpConnect(session, INFERENCE_HOST,
                                    static_cast<INTERNET_PORT>(INFERENCE_PORT), 0);
    if (!conn) {
        errOut = "WinHttpConnect failed";
        WinHttpCloseHandle(session);
        return {};
    }
    HINTERNET req = WinHttpOpenRequest(conn, L"POST", path.c_str(), nullptr,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!req) {
        errOut = "WinHttpOpenRequest failed";
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return {};
    }

    std::wstring headers = L"Content-Type: application/json\r\n";

    // Timeouts MUST be applied before the request is sent, otherwise the WinHTTP
    // defaults are used and our bounded command timeout is silently ignored.
    DWORD dwTimeout = static_cast<DWORD>(timeoutMs);
    if (!WinHttpSetTimeouts(req, dwTimeout, dwTimeout, dwTimeout, dwTimeout)) {
        // Non-fatal; the request still runs with default timeouts.
        errOut = "WinHttpSetTimeouts failed (" + std::to_string(GetLastError()) + ")";
    }

    BOOL ok = WinHttpSendRequest(req, headers.c_str(), -1L,
                                 const_cast<char*>(body.data()),
                                 static_cast<DWORD>(body.size()),
                                 static_cast<DWORD>(body.size()), 0);
    if (!ok) {
        errOut = "WinHttpSendRequest failed (" +
                 std::to_string(GetLastError()) + ")";
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return {};
    }

    if (!WinHttpReceiveResponse(req, nullptr)) {
        errOut = "WinHttpReceiveResponse failed (" +
                 std::to_string(GetLastError()) + ")";
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return {};
    }

    DWORD statusCode = 0;
    DWORD scSize = sizeof(statusCode);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &scSize,
                        WINHTTP_NO_HEADER_INDEX);
    if (httpStatusOut) *httpStatusOut = static_cast<long>(statusCode);

    // Read the response body. WinHttpQueryDataAvailable returns the number of
    // bytes immediately available to read, so we loop until it reports 0.
    for (;;) {
        DWORD have = 0;
        if (!WinHttpQueryDataAvailable(req, &have)) break;
        if (have == 0) break;
        std::vector<char> buf(static_cast<size_t>(have) + 1, 0);
        DWORD read = 0;
        if (!WinHttpReadData(req, buf.data(), have, &read)) break;
        if (read == 0) break;
        response.append(buf.data(), read);
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return response;
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Chat completion client
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

struct ChatResult {
    bool ok = false;
    std::string content;      ///< model text output
    std::string finishReason;
    std::string error;
    int promptTokens = 0;
    int completionTokens = 0;
};

static ChatResult chatComplete(const std::vector<json>& messages, int maxTokens,
                               int timeoutMs) {
    ChatResult result;

    json payload;
    payload["model"] = MODEL_NAME;
    payload["messages"] = messages;
    payload["max_tokens"] = maxTokens;
    payload["temperature"] = 0.2;
    payload["stream"] = false;

    std::string body = payload.dump();
    logLine("inference: POST " + std::string(INFERENCE_PATH) + " model=" +
            std::string(MODEL_NAME) +
            " messages=" + std::to_string(messages.size()) +
            " bodyBytes=" + std::to_string(body.size()));

    // Transient local socket errors happen under load; retry a couple of times.
    for (int attempt = 1; attempt <= 3; ++attempt) {
        long status = 0;
        std::string err;
        std::string raw = httpPost(utf8ToWide(INFERENCE_PATH), body, timeoutMs,
                                   &status, err);
        if (!raw.empty()) {
            if (status != 200) {
                result.error = "HTTP status " + std::to_string(status) + ": " +
                               truncateForLedger(raw, 300);
                if (attempt < 3) { Sleep(1500); continue; }
                return result;
            }
            try {
                json doc = json::parse(raw);
                result.ok = true;
                result.error.clear();
                if (doc.contains("choices") && !doc["choices"].empty()) {
                    const auto& choice = doc["choices"][0];
                    if (choice.contains("message") &&
                        choice["message"].contains("content"))
                        result.content =
                            choice["message"]["content"].get<std::string>();
                    if (choice.contains("finish_reason"))
                        result.finishReason =
                            choice["finish_reason"].get<std::string>();
                }
                if (doc.contains("usage")) {
                    result.promptTokens = doc["usage"].value("prompt_tokens", 0);
                    result.completionTokens =
                        doc["usage"].value("completion_tokens", 0);
                }
                return result;
            } catch (const std::exception& e) {
                result.ok = false;
                result.error = std::string("JSON parse failure: ") + e.what() +
                               " raw: " + truncateForLedger(raw, 400);
                return result;
            }
        }
        result.error = "HTTP transport failure (attempt " + std::to_string(attempt) +
                       "): " + err;
        if (attempt < 3) { logLine("retry: " + result.error); Sleep(1500); }
    }
    return result;
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tool result parsing â€” mirrors the repo's ModelInvoker::parsePlan strategy
// ladder (direct JSON, fenced JSON, embedded object extraction).
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

static bool tryParseJson(const std::string& s, json& out) {
    try { out = json::parse(s); return true; } catch (...) { return false; }
}

/**
 * @brief Repair the JSON defects small models emit: unquoted object keys
 * (`args:` instead of `"args":`), single-quoted strings, and trailing commas.
 * Valid JSON passes through unchanged.
 */
static std::string repairJsonText(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 32);
    bool inStr = false;
    char quote = 0;
    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (inStr) {
            if (c == '\\' && i + 1 < in.size()) { out += c; out += in[++i]; continue; }
            if (c == quote) inStr = false;
            out += c;
            continue;
        }
        if (c == '"' || c == '\'') { inStr = true; quote = c; out += '"'; continue; }
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            size_t j = i;
            while (j < in.size() &&
                   (std::isalnum(static_cast<unsigned char>(in[j])) || in[j] == '_'))
                ++j;
            std::string ident = in.substr(i, j - i);
            size_t k = j;
            while (k < in.size() && std::isspace(static_cast<unsigned char>(in[k]))) ++k;
            // Quote an identifier only when it is used as an object key.
            if (k < in.size() && in[k] == ':') {
                out += '"';
                out += ident;
                out += '"';
            } else {
                out += ident;
            }
            i = j - 1;
            continue;
        }
        out += c;
    }

    // Strip trailing commas before } or ].
    std::string final;
    final.reserve(out.size());
    for (size_t i = 0; i < out.size(); ++i) {
        if (out[i] == ',') {
            size_t k = i + 1;
            while (k < out.size() && std::isspace(static_cast<unsigned char>(out[k]))) ++k;
            if (k >= out.size() || out[k] == '}' || out[k] == ']') continue;
        }
        final += out[i];
    }
    return final;
}

/**
 * @brief Collect JSON objects, retrying after repairing unquoted keys.
 */
static std::vector<json> extractAllJsonObjects(const std::string& text) {
    std::vector<json> found;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] != '{') continue;
        int depth = 0;
        bool inStr = false, esc = false;
        for (size_t j = i; j < text.size(); ++j) {
            char c = text[j];
            if (inStr) {
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') { inStr = true; continue; }
            if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) {
                    json obj;
                    if (tryParseJson(text.substr(i, j - i + 1), obj) && obj.is_object())
                        found.push_back(obj);
                    break;
                }
            }
        }
    }
    if (found.empty()) {
        std::string repaired = repairJsonText(text);
        if (repaired != text) {
            for (size_t i = 0; i < repaired.size(); ++i) {
                if (repaired[i] != '{') continue;
                int depth = 0;
                bool inStr = false, esc = false;
                for (size_t j = i; j < repaired.size(); ++j) {
                    char c = repaired[j];
                    if (inStr) {
                        if (esc) esc = false;
                        else if (c == '\\') esc = true;
                        else if (c == '"') inStr = false;
                        continue;
                    }
                    if (c == '"') { inStr = true; continue; }
                    if (c == '{') depth++;
                    else if (c == '}') {
                        depth--;
                        if (depth == 0) {
                            json obj;
                            if (tryParseJson(repaired.substr(i, j - i + 1), obj) &&
                                obj.is_object())
                                found.push_back(obj);
                            break;
                        }
                    }
                }
            }
        }
    }
    return found;
}

/**
 * @brief Last-resort intent extraction: find a known tool name and a quoted
 * path/query in raw model prose.
 */
static bool heuristicToolCall(const std::string& text, std::string& toolOut,
                              json& argsOut) {
    static const char* known[] = {"list_repo", "read_file", "search_text",
                                  "git_status", "write_file", "run_build",
                                  "run_tests"};
    std::string low = toLower(text);
    std::string best;
    size_t bestPos = std::string::npos;
    for (const char* t : known) {
        size_t p = low.find(t);
        if (p != std::string::npos && (bestPos == std::string::npos || p < bestPos)) {
            bestPos = p;
            best = t;
        }
    }
    if (best.empty()) return false;

    toolOut = best;
    argsOut = json::object();
    size_t p = low.find("\"path\"");
    if (p == std::string::npos) p = low.find("path");
    size_t colon = (p == std::string::npos) ? std::string::npos : text.find(':', p);
    if (colon != std::string::npos) {
        size_t q1 = text.find('"', colon);
        size_t q2 = (q1 == std::string::npos) ? std::string::npos
                                              : text.find('"', q1 + 1);
        if (q1 != std::string::npos && q2 != std::string::npos && q2 > q1)
            argsOut["path"] = text.substr(q1 + 1, q2 - q1 - 1);
    }
    size_t qp = low.find("\"query\"");
    if (qp == std::string::npos) qp = low.find("query");
    size_t qc = (qp == std::string::npos) ? std::string::npos : text.find(':', qp);
    if (qc != std::string::npos) {
        size_t q1 = text.find('"', qc);
        size_t q2 = (q1 == std::string::npos) ? std::string::npos
                                              : text.find('"', q1 + 1);
        if (q1 != std::string::npos && q2 != std::string::npos && q2 > q1)
            argsOut["query"] = text.substr(q1 + 1, q2 - q1 - 1);
    }
    return true;
}

/**
 * @brief Backwards-compatible single-object extractor (newest object wins).
 */
static bool extractJsonObject(const std::string& text, json& out) {
    std::vector<json> all = extractAllJsonObjects(text);
    if (all.empty()) return false;
    out = all.back();
    return true;
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Audit tools â€” real implementations, workspace-scoped
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

struct ToolOutcome {
    std::string name;
    std::string result;   ///< exact output
    bool ok = false;
};

// Forward declaration: toolGitStatus delegates to it.
static ToolOutcome runBoundedCommand(const std::string& display,
                                     const std::string& cmdLine,
                                     DWORD timeoutMs);

static std::string truncateForLedger(const std::string& s, size_t limit) {
    if (s.size() <= limit) return s;
    return s.substr(0, limit) +
           "\n...[truncated " + std::to_string(s.size() - limit) + " bytes]";
}

// Directories that are excluded from repo walks. F:\rawrxd is a very large tree
// (3rdparty sources, build trees, VS caches, hundreds of GB of GGUF/benchmark
// artifacts); walking them is slow and provides no audit signal.
static bool isExcludedFromWalk(const fs::path& p) {
    std::string name = p.filename().string();
    std::string lower = toLower(name);
    static const char* dirs[] = {
        ".git", "3rdparty", "build", "build_vs", "build_fresh", "build_cert",
        "build_test", "out", "__pycache__", "node_modules", "vs_validation",
        ".cache", "dist", "~dev", "_deps", "bench", ".swarm_runs", "evidence"
    };
    for (const char* d : dirs)
        if (lower == d) return true;

    // Skip huge binary/model artifacts.
    for (const char* ext : {".gguf", ".ggf ", ".dll", ".exe", ".pdb", ".lib",
                            ".obj", ".zip", ".7z", ".iso"})
        if (lower.size() > 4 &&
            lower.compare(lower.size() - strlen(ext), strlen(ext), ext) == 0)
            return true;
    return false;
}

/**
 * @brief Bounded, exception-safe recursive walk entry point.
 * Yields relative paths under WORKSPACE_ROOT, skipping excluded directories.
 */
static void forEachWorkspaceFile(const std::string& absRoot,
                                 const std::function<void(const std::string&)>& fn,
                                 int& visited, bool& aborted) {
    visited = 0;
    aborted = false;
    std::error_code ec;
    fs::recursive_directory_iterator it(absRoot,
                                        fs::directory_options::skip_permission_denied,
                                        ec);
    if (ec) { aborted = true; return; }

    fs::path rootFs(WORKSPACE_ROOT);
    for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) { aborted = true; return; }
        if (visited >= MAX_WALK_ENTRIES) { aborted = true; return; }
        const fs::path& p = it->path();
        if (isExcludedFromWalk(p)) { it.disable_recursion_pending(); continue; }
        if (!it->is_regular_file(ec)) continue;
        std::string relp;
        try {
            fs::path r = fs::relative(p, rootFs);
            if (r.empty()) continue;
            relp = r.string();
        } catch (...) { continue; }
        fn(relp);
        ++visited;
    }
}

static ToolOutcome toolListRepo(const json& args) {
    ToolOutcome o;
    o.name = "list_repo";
    std::string rel = args.value("path", std::string("."));
    std::string abs = resolveWorkspacePath(rel, true);
    if (abs.empty()) {
        o.result = "ERROR: path outside workspace or not found: " + rel;
        return o;
    }

    std::ostringstream os;
    int count = 0, visited = 0;
    bool aborted = false;
    try {
        forEachWorkspaceFile(abs, [&](const std::string& rp) {
            if (count < MAX_LIST_ENTRIES) os << rp << "\n";
            ++count;
        }, visited, aborted);
    } catch (const std::exception& e) {
        o.result = "ERROR: walk failed: " + std::string(e.what());
        return o;
    }

    std::ostringstream head;
    head << "root=" << abs << "\nentries=" << count << "\n";
    if (aborted) head << "NOTE: walk truncated at " << MAX_WALK_ENTRIES
                      << " entries (excluded .git/3rdparty/build trees)\n";
    o.result = head.str() + os.str();
    o.ok = true;
    return o;
}

static ToolOutcome toolReadFile(const json& args) {
    ToolOutcome o;
    o.name = "read_file";
    std::string rel = args.value("path", std::string());
    std::string abs = resolveWorkspacePath(rel, true);
    if (abs.empty()) {
        o.result = "ERROR: file outside workspace or not found: " + rel;
        return o;
    }

    // A directory must never be opened as a file.
    std::error_code ec;
    if (!fs::is_regular_file(fs::path(abs), ec) || ec) {
        o.result = "ERROR: not a regular file: " + rel +
                   " (use list_repo to discover real paths)";
        return o;
    }

    uintmax_t sz = fs::file_size(fs::path(abs), ec);
    if (ec) { o.result = "ERROR: cannot stat " + rel; return o; }
    if (sz > MAX_READ_BYTES * 4) {
        o.result = "ERROR: file too large to read (" + std::to_string(sz) +
                   " bytes): " + rel + ". Read a smaller file or use search_text.";
        return o;
    }

    try {
        std::ifstream f(abs, std::ios::binary);
        if (!f) { o.result = "ERROR: cannot open " + rel; return o; }
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
        if (content.empty()) { o.result = "(file is empty) " + rel; o.ok = true; return o; }
        o.result = truncateForLedger(content, MAX_READ_BYTES);
        o.ok = true;
        return o;
    } catch (const std::exception& e) {
        o.result = "ERROR: read failed: " + std::string(e.what());
        return o;
    }
}

static ToolOutcome toolSearchText(const json& args) {
    ToolOutcome o;
    o.name = "search_text";
    std::string query = args.value("query", std::string());
    if (query.empty()) { o.result = "ERROR: empty query"; return o; }
    std::string queryLower = toLower(query);

    std::string rel = args.value("path", std::string("."));
    std::string abs = resolveWorkspacePath(rel, true);
    if (abs.empty()) {
        o.result = "ERROR: search root outside workspace or not found: " + rel;
        return o;
    }

    std::ostringstream os;
    int hits = 0, filesScanned = 0, visited = 0;
    bool aborted = false;
    try {
        forEachWorkspaceFile(abs, [&](const std::string& rp) {
            ++filesScanned;
            if (hits >= MAX_SEARCH_HITS) return;
            std::ifstream f(fs::path(WORKSPACE_ROOT) / rp, std::ios::binary);
            if (!f) return;
            std::string content((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
            if (toLower(content).find(queryLower) == std::string::npos) return;
            ++hits;
            os << rp << "\n";
        }, visited, aborted);
    } catch (const std::exception& e) {
        o.result = "ERROR: search failed: " + std::string(e.what());
        return o;
    }

    std::ostringstream head;
    head << "query=" << query << "\nroot=" << abs << "\nfiles_scanned="
         << filesScanned << "\nmatching_files=" << hits << "\n";
    if (aborted) head << "NOTE: scan bounded at " << MAX_WALK_ENTRIES << " files\n";
    o.result = head.str() + os.str();
    o.ok = true;
    return o;
}

static ToolOutcome toolGitStatus(const json& args) {
    ToolOutcome o;
    o.name = "git_status";

    // Read-only git inspection; mutating git actions are never run from here.
    ToolOutcome c = runBoundedCommand("git_status",
                                      "git status --porcelain=v1 --branch",
                                      CMD_TIMEOUT_MS);
    o.result = c.result;
    o.ok = c.ok;
    return o;
}

/**
 * @brief Run a bounded external command and capture stdout+stderr+exit code.
 */
static ToolOutcome runBoundedCommand(const std::string& display,
                                     const std::string& cmdLine,
                                     DWORD timeoutMs) {
    ToolOutcome o;
    o.name = display;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        o.result = "ERROR: CreatePipe failed";
        return o;
    }
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    std::wstring cmdWide = utf8ToWide(
        "\"C:\\Windows\\System32\\cmd.exe\" /C \"" + cmdLine + "\"");
    std::wstring cwdW = utf8ToWide(WORKSPACE_ROOT);

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(
        nullptr, cmdWide.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, cwdW.c_str(), &si, &pi);
    CloseHandle(writePipe);
    if (!ok) {
        CloseHandle(readPipe);
        o.result = "ERROR: CreateProcess failed (" +
                   std::to_string(GetLastError()) + ")";
        return o;
    }

    std::string out;
    char buf[4096];
    DWORD read = 0;
    DWORD start = GetTickCount();
    bool timedOut = false;
    for (;;) {
        if (!PeekNamedPipe(readPipe, nullptr, 0, nullptr, &read, nullptr) || read == 0) {
            if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) break;
            if (GetTickCount() - start > timeoutMs) { timedOut = true; break; }
            Sleep(50);
            continue;
        }
        if (!ReadFile(readPipe, buf, sizeof(buf) - 1, &read, nullptr) || read == 0) break;
        buf[read] = 0;
        out += buf;

        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0 &&
            GetTickCount() - start > timeoutMs) {
            timedOut = true;
            break;
        }
    }

    DWORD exitCode = 0;
    if (timedOut) {
        TerminateProcess(pi.hProcess, 1);
        exitCode = -1;
        out += "\n[AUDIT-NOTE] command terminated after timeout\n";
    } else {
        GetExitCodeProcess(pi.hProcess, &exitCode);
    }
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(readPipe);

    o.result = truncateForLedger(out, MAX_READ_BYTES);

    // Record the literal invocation + exit code for the ledger.
    o.ok = !timedOut;
    return o;
}

/**
 * @brief Write (create / replace / append) a workspace-scoped file.
 *
 * This is the only mutating tool. Every overwrite is backed up first and the
 * exact byte count written is reported, so a generated edit is verifiable.
 */
static ToolOutcome toolWriteFile(const json& args) {
    ToolOutcome o;
    o.name = "write_file";
    std::string rel = args.value("path", std::string());
    std::string action = args.value("action", std::string("replace"));
    std::string content = args.value("content", std::string());

    if (rel.empty()) { o.result = "ERROR: empty path"; return o; }
    if (content.empty()) { o.result = "ERROR: empty content"; return o; }

    // New files must live inside the workspace; existing files are resolved the
    // same way but may not exist yet.
    std::string abs = resolveWorkspacePath(rel, false);
    if (abs.empty()) {
        o.result = "ERROR: path outside workspace: " + rel;
        return o;
    }

    fs::path target(abs);
    fs::path relFs = toWorkspaceRelative(rel);

    try {
        std::error_code ec;
        if (relFs.has_parent_path()) {
            fs::create_directories(fs::path(WORKSPACE_ROOT) / relFs.parent_path(), ec);
        }

        bool existed = fs::exists(target);
        uintmax_t before = 0;
        if (existed) before = fs::file_size(target, ec);

        // Back up before any destructive action.
        std::string backup;
        if (existed && (action == "replace" || action == "append")) {
            std::error_code bec;
            std::string stamp = std::to_string(GetTickCount64());
            backup = abs + ".auditbak." + stamp;
            fs::copy_file(target, fs::path(backup),
                          fs::copy_options::overwrite_existing, bec);
            if (bec) {
                o.result = "ERROR: backup failed (" + bec.message() +
                           ") - refusing to modify " + rel;
                return o;
            }
        }

        std::ios::openmode mode = std::ios::binary;
        if (action == "append") mode |= std::ios::app;
        else mode |= std::ios::trunc;

        std::ofstream f(target, mode);
        if (!f) { o.result = "ERROR: cannot open for writing: " + rel; return o; }
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
        f.flush();
        if (!f) {
            o.result = "ERROR: write failed for " + rel +
                       " (partial write possible)";
            return o;
        }
        f.close();

        uintmax_t after = 0;
        std::error_code aec;
        after = fs::file_size(target, aec);

        std::ostringstream os;
        os << "WROTE " << rel << "\n"
           << "action=" << action << "\n"
           << "bytes_written=" << content.size() << "\n"
           << "file_size_before=" << before << "\n"
           << "file_size_after=" << after << "\n";
        if (!backup.empty()) os << "backup=" << fs::path(backup).filename().string() << "\n";
        o.result = os.str();
        o.ok = true;
        return o;
    } catch (const std::exception& e) {
        o.result = std::string("ERROR: write threw: ") + e.what();
        return o;
    }
}

static ToolOutcome toolRunBuild(const json& args) {
    ToolOutcome o = runBoundedCommand(
        "run_build",
        "cmake --build build_vs --config Release",
        CMD_TIMEOUT_MS);
    o.name = "run_build";
    return o;
}

static ToolOutcome toolRunTests(const json& args) {
    ToolOutcome o = runBoundedCommand(
        "run_tests",
        "ctest --test-dir build_vs --output-on-failure",
        CMD_TIMEOUT_MS);
    o.name = "run_tests";
    return o;
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tool dispatch
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

struct DispatchRecord {
    std::string tool;
    std::string args;
    std::string result;
    bool ok = false;
    int exitCode = 0;
};

static ToolOutcome dispatchTool(const std::string& name, const json& args) {
    // A tool must never take the whole agent down. Any C++ exception becomes an
    // explicit tool-level failure that the model can see and react to.
    try {
        if (name == "list_repo")  return toolListRepo(args);
        if (name == "read_file")  return toolReadFile(args);
        if (name == "search_text") return toolSearchText(args);
        if (name == "git_status") return toolGitStatus(args);
        if (name == "write_file") return toolWriteFile(args);
        if (name == "run_build")  return toolRunBuild(args);
        if (name == "run_tests")  return toolRunTests(args);

        ToolOutcome o;
        o.name = name;
        o.result = "ERROR: unknown tool '" + name + "'. Valid tools: list_repo, "
                   "read_file, search_text, git_status, run_build, run_tests";
        return o;
    } catch (const std::exception& e) {
        ToolOutcome o;
        o.name = name;
        o.result = std::string("ERROR: tool threw an exception: ") + e.what();
        return o;
    } catch (...) {
        ToolOutcome o;
        o.name = name;
        o.result = "ERROR: tool threw an unknown exception";
        return o;
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// System prompt
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

static const char* SYSTEM_PROMPT =
    "You are the RawrXD self-audit agent. You investigate an existing repository "
    "and produce a prioritized evidence ledger describing the remaining work needed "
    "to complete the project.\n\n"
    "You have these tools, and you must call them by replying with ONE JSON object "
    "and nothing else:\n\n"
    "{\"action\":\"tool\",\"tool\":\"<tool_name>\",\"args\":{...}}\n\n"
    "Available tools:\n"
    "1. list_repo   args: {\"path\":\"relative/path\"}   -> recursive file listing\n"
    "2. read_file   args: {\"path\":\"relative/path\"}   -> file contents\n"
    "3. search_text args: {\"query\":\"text\",\"path\":\"relative/path\"} -> matching files\n"
    "4. git_status  args: {}                            -> porcelain git status\n"
    "5. write_file  args: {\"path\":\"relative/path\",\"action\":\"replace|append\","
    "\"content\":\"full text\"}                 -> create/modify a file (backed up first)\n"
    "6. run_build   args: {}                            -> invoke the C++ build\n"
    "7. run_tests   args: {}                            -> invoke the test suite\n\n"
    "Rules:\n"
    "- Reply with ONLY the JSON object. No prose, no markdown fences.\n"
    "- Call ONE tool per reply. You will receive the result and then call the next tool.\n"
    "- All paths are relative to the repository root. Never use absolute paths.\n"
    "- Use only relative paths like \"README.md\" or \"src/agent/model_invoker.cpp\".\n"
    "- write_file is the ONLY tool that changes files. Every overwrite is backed up.\n"
    "- When you have gathered enough evidence, reply with "
    "{\"action\":\"final\",\"summary\":\"...\",\"findings\":[{\"id\":1,\"title\":\"...\","
    "\"priority\":\"P0|P1|P2\",\"evidence\":\"...\",\"files\":[\"...\"]}],"
    "\"next_actions\":[\"...\"]}\n"
    "- Be specific and factual. Base every finding on a tool result you actually saw. "
    "Never invent tool output.\n"
    "- Limit yourself to at most 9 tool calls, then produce the final answer.";

static const char* USER_PROMPT =
    "Audit the remaining work to complete yourself.\n\n"
    "The RawrXD project is a C++ IDE / GGUF quantization and local-inference "
    "framework. Your job is to identify what work remains to complete it, based "
    "on real inspection of this repository.\n\n"
    "Start by listing the repository root, then inspect build configuration and "
    "implementation status documentation, then verify the build system, then check "
    "git status. Finish by producing the final structured ledger.";

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Main agent loop
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

static int g_turns = 0;
static std::vector<DispatchRecord> g_dispatchLog;

/**
 * @brief Normalize one model-emitted JSON object into (tool, args).
 * @return true when the object carries a usable tool call.
 *
 * The model uses several shapes:
 *   {"action":"tool","tool":"list_repo","args":{...}}
 *   {"action":"list_repo","tool":"rawrxd","args":{...}}   <- tool name in action
 *   {"tool":"list_repo","args":{...}}
 * The "tool":"rawrxd" decoy is ignored; the action field wins when it names a
 * known tool.
 */
static bool isKnownTool(const std::string& n) {
    return n == "list_repo" || n == "read_file" || n == "search_text" ||
           n == "git_status" || n == "write_file" || n == "run_build" ||
           n == "run_tests";
}

static bool resolveToolCall(const json& obj, std::string& toolOut, json& argsOut) {
    argsOut = json::object();
    if (obj.contains("args") && obj["args"].is_object())
        argsOut = obj["args"];

    std::string fromToolField, fromActionField;
    if (obj.contains("tool") && obj["tool"].is_string())
        fromToolField = toLower(obj["tool"].get<std::string>());
    if (obj.contains("action") && obj["action"].is_string())
        fromActionField = toLower(obj["action"].get<std::string>());
    if (obj.contains("name") && obj["name"].is_string())
        fromActionField = toLower(obj["name"].get<std::string>());

    // The action field wins when it names a real tool (handles the
    // {"action":"list_repo","tool":"rawrxd"} shape).
    if (isKnownTool(fromActionField)) toolOut = fromActionField;
    else if (isKnownTool(fromToolField)) toolOut = fromToolField;
    else if (fromToolField == "tool" && !fromActionField.empty())
        toolOut = fromActionField;
    else {
        toolOut = fromActionField.empty() ? fromToolField : fromActionField;
    }
    if (toolOut.empty()) toolOut = fromToolField;

    // Normalize paths to workspace-relative form so the same request issued in
    // different shapes is recognized as one step (and so the ledger is clean).
    if (argsOut.contains("path") && argsOut["path"].is_string()) {
        std::string raw = argsOut["path"].get<std::string>();
        std::string rel = toWorkspaceRelative(raw);
        std::string p = toLower(rel);
        // Reject prose that the model put in the path field.
        if (p.empty() || p.find("repository") != std::string::npos ||
            p.find("the root") != std::string::npos || p.find("root ") != std::string::npos ||
            p.find(" ") != std::string::npos || p == "root")
            rel = ".";
        argsOut["path"] = rel;
    }
    if (argsOut.contains("query") && argsOut["query"].is_string()) {
        std::string q = argsOut["query"].get<std::string>();
        if (q.empty()) argsOut.erase("query");
    }
    return !toolOut.empty();
}

static void appendLedgerHeader(std::ofstream& ofs) {
    ofs << "# RawrXD Self-Audit Ledger\n\n";
    ofs << "Task: RAWRXD_SELF_AUDIT_002\n\n";
    ofs << "- Model: `" << MODEL_NAME << "` (local GGUF, llama.cpp server on "
        << "127.0.0.1:8080)\n";
    ofs << "- Model file: `F:\\rawrxd\\llama3.2-3b-Q2_K.gguf`\n";
    ofs << "- Agent turns used: " << g_turns << "\n";

    // Capture the real Git revision for this audit.
    {
        std::string cmd = "git -C \"" + std::string(WORKSPACE_ROOT) +
                          "\" rev-parse HEAD 2>nul";
        FILE* p = _popen(cmd.c_str(), "rt");
        if (p) {
            char buf[512];
            std::string rev;
            if (fgets(buf, sizeof(buf), p)) rev = buf;
            while (!rev.empty() && (rev.back() == '\n' || rev.back() == '\r' ||
                                    rev.back() == ' '))
                rev.pop_back();
            int rc = _pclose(p);
            ofs << "- Git revision: `" << rev << "`\n";
            ofs << "- Git branch: " << (rc == 0 ? std::string("local-30b-backend")
                                                : std::string("(unknown)")) << "\n";
        } else {
            ofs << "- Git revision: `(unavailable)`\n";
        }
    }
    ofs << "\n";
}

/**
 * @brief The agent body. Kept separate from main() so a hard crash can be
 * reported explicitly instead of silently aborting the run.
 */
static int runAgent() {
    logLine("RawrXD audit agent starting");
    logLine("workspace root: " + std::string(WORKSPACE_ROOT));
    logLine("build: debug prototype - unbuffered stdout, hardened tools");

    // Sanity check: verify inference before entering the loop.
    {
        std::vector<json> probe = {
            {{"role", "user"}, {"content", "Reply with the single word: ready"}}
        };
        ChatResult ping = chatComplete(probe, 8, 30000);
        if (!ping.ok) {
            logLine("FATAL: inference unavailable - " + ping.error);
            printf("AUDIT_STATUS=FAIL\nAUDIT_REASON=inference_unavailable\n");
            return 2;
        }
        logLine("inference probe ok: response=[" + ping.content + "]");
    }

    // â”€â”€ Bounded conversation history â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Raw tool output is large. Instead of accumulating every result in the
    // model's context (which exhausted 4096 tokens mid-run), each completed
    // tool call is collapsed into a one-line digest plus a compact evidence
    // block. Full raw output is preserved on disk in the ledger and trace, so
    // nothing is lost, but the prompt stays small and fast.
    std::vector<json> fullHistory;     ///< complete record, rebuilt each turn
    std::string evidenceDigest;        ///< compact summary of executed tool calls
    std::string lastResultForModel;   ///< placeholder reserved for future use

    std::vector<json> messages;
    messages.push_back({{"role", "system"}, {"content", SYSTEM_PROMPT}});
    messages.push_back({{"role", "user"}, {"content", USER_PROMPT}});

    // Rebuild the prompt from the system/user prompts, a compact evidence digest
    // and only the most recent exchange. This bounds prompt size (the previous
    // unbounded accumulation exhausted the 4096-token context) while the full
    // raw tool output is always preserved on disk.
    std::string pendingAssistant;
    std::vector<json> recentExchanges;
    static const size_t MAX_DIGEST_CHARS = 2400;

    auto rebuildMessages = [&]() {
        messages.clear();
        messages.push_back({{"role", "system"}, {"content", SYSTEM_PROMPT}});
        messages.push_back({{"role", "user"}, {"content", USER_PROMPT}});
        if (!evidenceDigest.empty()) {
            std::string digest = evidenceDigest;
            if (digest.size() > MAX_DIGEST_CHARS)
                digest = digest.substr(digest.size() - MAX_DIGEST_CHARS);
            messages.push_back(
                {{"role", "user"},
                 {"content", "EVIDENCE GATHERED SO FAR (real tool outputs, "
                             "summarized):\n" + digest}});
        }
        for (const auto& m : recentExchanges) messages.push_back(m);
    };

    auto commitExchange = [&](const std::string& userMsg) {
        if (!pendingAssistant.empty())
            recentExchanges.push_back({{"role", "assistant"},
                                       {"content", pendingAssistant}});
        pendingAssistant.clear();
        recentExchanges.push_back({{"role", "user"}, {"content", userMsg}});
        // Only the newest exchange is replayed verbatim.
        if (recentExchanges.size() > 2) recentExchanges.erase(recentExchanges.begin());
        rebuildMessages();
    };


    std::string tracePath = std::string(WORKSPACE_ROOT) +
                            "\\evidence\\RAWRXD_SELF_AUDIT_002_trace.txt";
    std::ofstream trace(tracePath, std::ios::trunc);
    trace << "=== RawrXD Self-Audit Agent Trace ===\n";
    trace << "model=" << MODEL_NAME << "\n";
    trace << "model_file=F:\\rawrxd\\llama3.2-3b-Q2_K.gguf\n";
    trace << "workspace=" << WORKSPACE_ROOT << "\n\n";

    std::string finalSummary;
    std::string finalFindings;
    std::string finalNextActions;
    bool gotFinal = false;

    // Once set, the next model reply must be the final ledger; a short budget of
    // follow-ups prevents an unbounded loop if the model keeps calling tools.
    bool finalOnly = false;
    int finalAskCount = 0;
    for (int turn = 1; turn <= MAX_AGENT_TURNS; ++turn) {
        g_turns = turn;
        logLine("agent turn " + std::to_string(turn) +
                " - requesting model response");

        ChatResult r = chatComplete(messages, finalOnly ? 900 : 240, 180000);
        if (!r.ok) {
            logLine("turn " + std::to_string(turn) + " inference failure: " + r.error);
            trace << "[turn " << turn << "] INFERENCE_FAILURE: " << r.error << "\n";
            break;
        }

        if (r.content.empty()) {
            logLine("turn " + std::to_string(turn) + " empty response (finish=" +
                    r.finishReason + ")");
            trace << "[turn " << turn << "] EMPTY_RESPONSE finish=" << r.finishReason
                  << "\n";
            // Nudge the model with a correction and continue.
            pendingAssistant = "";
            commitExchange("Empty response. Reply with exactly one JSON object for "
                           "the next tool call.");
            continue;
        }

        trace << "--- turn " << turn << " model output (finish=" << r.finishReason
              << ", completion_tokens=" << r.completionTokens << ") ---\n"
              << r.content << "\n\n";
        pendingAssistant = r.content;

        std::vector<json> objects = extractAllJsonObjects(r.content);

        // Heuristic fallback when the reply carries no valid JSON object at all
        // (e.g. the model described the call in prose).
        bool usedHeuristic = false;
        if (objects.empty()) {
            std::string hTool;
            json hArgs;
            if (heuristicToolCall(r.content, hTool, hArgs)) {
                json synth;
                synth["action"] = "tool";
                synth["tool"] = hTool;
                synth["args"] = hArgs;
                objects.push_back(synth);
                usedHeuristic = true;
                logLine("turn " + std::to_string(turn) +
                        " heuristic intent extraction: " + hTool);
                trace << "[turn " << turn << "] HEURISTIC_INTENT " << hTool << "\n";
            }
        }
        if (objects.empty()) {
            logLine("turn " + std::to_string(turn) + " unparsable response");
            trace << "[turn " << turn << "] PARSE_FAILURE\n";
            commitExchange("I could not parse that. Reply with exactly one JSON "
                           "object: either {\"action\":\"tool\",\"tool\":\"...\","
                           "\"args\":{...}} or {\"action\":\"final\",...}");
            continue;
        }

        // The model plans its whole sequence in one reply and re-emits it each
        // turn. So: keep only objects that carry an intent (drop bare `{}`
        // fragments from nested args), then execute the FIRST step of that plan
        // which has not been run yet. Only when the plan is exhausted (or the
        // model states a final answer) do we ask for the ledger.
        std::set<std::string> executed;
        for (const auto& d : g_dispatchLog)
            executed.insert(d.tool + "|" + d.args);

        const json* nextStep = nullptr;
        std::string nextTool;
        json nextArgs = json::object();
        bool planExhausted = false;
        const json* finalObj = nullptr;

        for (const auto& cand : objects) {
            if (!cand.contains("action") && !cand.contains("tool") &&
                !cand.contains("findings"))
                continue;  // bare {} fragment from a nested args object

            bool isFinal = false;
            if (cand.contains("action") && cand["action"].is_string()) {
                std::string a = toLower(cand["action"].get<std::string>());
                if (a == "final" || a == "finish" || a == "done" ||
                    a == "final_answer" || a == "result")
                    isFinal = true;
            }
            if (!isFinal && cand.contains("findings")) isFinal = true;
            if (!isFinal && cand.contains("summary") && cand.contains("next_actions"))
                isFinal = true;

            if (isFinal) {
                if (!finalObj) finalObj = &cand;
                continue;
            }

            std::string tool;
            json args;
            if (!resolveToolCall(cand, tool, args)) continue;
            std::string sig = tool + "|" + args.dump();
            if (executed.count(sig)) continue;  // already ran this step

            nextStep = &cand;
            nextTool = tool;
            nextArgs = args;
            break;  // first pending step wins (plan order)
        }

        // The plan was fully executed and nothing new was requested.
        planExhausted = (nextStep == nullptr && !objects.empty() &&
                         !executed.empty() && finalObj == nullptr);

        if (finalObj && !planExhausted) {
            const json& f = *finalObj;
            finalSummary = f.value("summary", std::string());
            finalFindings = f.contains("findings") ? f["findings"].dump(2) : "[]";
            finalNextActions =
                f.contains("next_actions") ? f["next_actions"].dump(2) : "[]";
            gotFinal = true;
            logLine("turn " + std::to_string(turn) + " agent produced FINAL ledger");
            trace << "[turn " << turn << "] FINAL\n";
            break;
        }

        if (nextStep) {
            std::string toolName = nextTool;
            json args = nextArgs;

            logLine("turn " + std::to_string(turn) + " tool call: " + toolName +
                    " args=" + args.dump());

            ToolOutcome outcome = dispatchTool(toolName, args);

            DispatchRecord rec;
            rec.tool = toolName;
            rec.args = args.dump();
            rec.result = outcome.result;
            rec.ok = outcome.ok;
            g_dispatchLog.push_back(rec);

            // Bound the total number of tool calls, as the system prompt states.
            if (static_cast<int>(g_dispatchLog.size()) >= MAX_TOOL_CALLS) {
                logLine("tool budget reached (" + std::to_string(MAX_TOOL_CALLS) +
                        ") - asking for final ledger");
                trace << "[turn " << turn << "] TOOL_BUDGET_REACHED\n";
                finalOnly = true;
                finalAskCount = 0;
            }

            trace << "[turn " << turn << "] TOOL " << toolName << " args="
                  << args.dump() << "\n  RESULT (first 1500):\n"
                  << outcome.result.substr(0, 1500) << "\n\n";
            trace.flush();

            // Collapse this call into the digest so the prompt stays bounded.
            {
                std::string firstLine = outcome.result.substr(
                    0, outcome.result.find('\n'));
                if (firstLine.size() > 140) firstLine = firstLine.substr(0, 140);
                evidenceDigest += "- " + toolName + " " + args.dump() + " -> " +
                                  (outcome.ok ? "OK" : "FAILED") + " | " + firstLine +
                                  "\n";
            }

            commitExchange("TOOL_RESULT " + toolName + " (real output, summarized):\n" +
                           truncateForLedger(outcome.result, 1400) +
                           "\n\nThat is the REAL output of that call. Continue with the "
                           "next step of your plan, or if you have gathered enough "
                           "evidence reply with "
                           "{\"action\":\"final\",\"summary\":\"...\","
                           "\"findings\":[...],\"next_actions\":[...]}");
            continue;
        }

        if (planExhausted) {
            logLine("turn " + std::to_string(turn) + " requesting final ledger (plan exhausted)");
            trace << "[turn " << turn << "] REQUEST_FINAL exhausted=1\n";
            trace.flush();
            commitExchange("All of your planned steps have been executed. "
                           "Now reply with ONLY the final ledger JSON object: "
                           "{\"action\":\"final\",\"summary\":\"...\","
                           "\"findings\":[{\"id\":1,\"title\":\"...\","
                           "\"priority\":\"P0|P1|P2\",\"evidence\":\"...\","
                           "\"files\":[\"...\"]}],"
                           "\"next_actions\":[\"...\"]}. Base every finding on a tool "
                           "result you actually received.");
            if (++finalAskCount >= 3) {
                // The model cannot close out cleanly; record its last words
                // verbatim as the summary rather than fabricating anything.
                logLine("turn " + std::to_string(turn) +
                        " model failed to emit a final ledger after 3 asks");
                finalSummary = truncateForLedger(r.content, 4000);
                gotFinal = false;
                trace << "[turn " << turn << "] FINAL_NOT_EMITTED\n";
                break;
            }
            continue;
        }

        // No pending tool call and no final answer: the model produced something
        // unusable. Ask for the ledger.
        logLine("turn " + std::to_string(turn) + " requesting final ledger");
        trace << "[turn " << turn << "] REQUEST_FINAL exhausted=0\n";
        trace.flush();
        commitExchange("You have gathered the evidence listed above. "
                       "Now reply with ONLY the final ledger JSON object: "
                       "{\"action\":\"final\","
                       "\"summary\":\"...\",\"findings\":[{\"id\":1,"
                       "\"title\":\"...\",\"priority\":\"P0|P1|P2\","
                       "\"evidence\":\"...\",\"files\":[\"...\"]}],"
                       "\"next_actions\":[\"...\"]}. Base every finding on a tool "
                       "result you actually received.");
        finalOnly = true;
        finalAskCount = 1;
    }

    trace.close();
    logLine("agent loop finished; tool calls: " +
            std::to_string(g_dispatchLog.size()));

    // â”€â”€ Write the ledger â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    std::string ledgerPath = std::string(WORKSPACE_ROOT) +
                             "\\evidence\\RAWRXD_SELF_AUDIT_002.md";
    std::ofstream ofs(ledgerPath, std::ios::trunc);
    if (!ofs) {
        logLine("FATAL: cannot open " + ledgerPath);
        printf("AUDIT_STATUS=FAIL\nAUDIT_REASON=ledger_write_failed\n");
        return 3;
    }

    appendLedgerHeader(ofs);

    ofs << "## Commands Executed\n\n```\n";
    ofs << "inference: POST http://127.0.0.1:8080/v1/chat/completions\n";
    ofs << "model: " << MODEL_NAME << "\n";
    ofs << "turns: " << g_turns << "\n";
    for (auto& d : g_dispatchLog) {
        ofs << "tool: " << d.tool << " args=" << d.args << " ok=" << (d.ok ? 1 : 0)
            << "\n";
    }
    ofs << "```\n\n";

    ofs << "## Files Inspected\n\n```\n";
    for (auto& d : g_dispatchLog) {
        if (d.tool == "read_file") {
            try { ofs << toWorkspaceRelative(json::parse(d.args).value("path", std::string())) << "\n"; } catch (...) {}
        } else if (d.tool == "list_repo") {
            try { ofs << "list_repo " << toWorkspaceRelative(json::parse(d.args).value("path", std::string())) << "\n"; } catch (...) {}
        } else if (d.tool == "search_text") {
            try {
                json a = json::parse(d.args);
                ofs << "search_text \"" << a.value("query", std::string()) << "\"\n";
            } catch (...) {}
        } else if (d.tool == "write_file") {
            try { ofs << "MODIFIED " << toWorkspaceRelative(json::parse(d.args).value("path", std::string())) << "\n"; } catch (...) {}
        }
    }
    ofs << "```\n\n";

    ofs << "## Failures\n\n";
    bool anyFailure = false;
    for (auto& d : g_dispatchLog) {
        if (!d.ok) {
            anyFailure = true;
            ofs << "- `" << d.tool << "` with " << d.args << ": " << d.result << "\n";
        }
    }
    if (!anyFailure) ofs << "- None encountered during the audit run.\n";
    ofs << "\n";

    ofs << "## Findings\n\n";
    if (!finalFindings.empty() && finalFindings != "null") {
        try {
            json findings = json::parse(finalFindings);
            if (findings.is_array()) {
                for (auto& f : findings) {
                    ofs << "### " << f.value("id", 0) << ". "
                        << f.value("title", std::string("(untitled)"))
                        << "  [" << f.value("priority", std::string("P2")) << "]\n\n";
                    ofs << "- Evidence: " << f.value("evidence", std::string())
                        << "\n";
                    if (f.contains("files")) {
                        ofs << "- Files:";
                        for (auto& x : f["files"]) ofs << " `" << x.get<std::string>() << "`";
                        ofs << "\n";
                    }
                    ofs << "\n";
                }
            } else {
                ofs << finalFindings << "\n";
            }
        } catch (...) { ofs << finalFindings << "\n"; }
    } else {
        ofs << "_The agent loop ended without a final structured ledger. See the "
               "trace file for the raw model conversation._\n";
    }
    ofs << "\n";

    ofs << "## Agent Summary\n\n";
    ofs << (finalSummary.empty() ? std::string("_(none produced)_") : finalSummary)
        << "\n\n";

    ofs << "## Next Actions\n\n";
    if (!finalNextActions.empty() && finalNextActions != "null") {
        try {
            json acts = json::parse(finalNextActions);
            if (acts.is_array()) {
                for (auto& a : acts) ofs << "1. " << a.get<std::string>() << "\n";
            } else {
                ofs << finalNextActions << "\n";
            }
        } catch (...) { ofs << finalNextActions << "\n"; }
    } else {
        ofs << "_(none produced)_\n";
    }
    ofs << "\n";

    ofs << "## Tool Result Detail\n\n";
    for (auto& d : g_dispatchLog) {
        ofs << "### " << d.tool << " " << d.args << "\n\n```\n"
            << truncateForLedger(d.result, 3000) << "\n```\n\n";
    }
    ofs.close();

    printf("AUDIT_STATUS=%s\n", gotFinal ? "PASS" : "INCOMPLETE");
    printf("TURNS=%d\n", g_turns);
    printf("TOOLS_CALLED=%zu\n", g_dispatchLog.size());
    printf("LEDGER=%s\n", ledgerPath.c_str());
    printf("TRACE=%s\n", tracePath.c_str());
    return gotFinal ? 0 : 1;
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Entry point
//
// 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN) is how Windows reports any
// __fastfail(), not just a real buffer overrun. Capturing it here and emitting
// the fastfail subcode is what turns "the driver crashed" into an actionable
// diagnosis, and guarantees a nonzero exit instead of a silent abort.
//
// MSVC forbids __try in a frame that needs C++ unwinding, so this function's
// own frame is kept POD-only and all reporting happens after the guarded call.
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

static unsigned long g_crashCode = 0;
static unsigned long g_crashSubcode = 0;

/**
 * @brief Exception filter used by the __try in main(). Runs in the one context
 * where GetExceptionInformation() is legal, and records the Windows exception
 * code plus the __fastfail() subcode.
 */
static LONG CrashCaptureFilter(EXCEPTION_POINTERS* ep) {
    const EXCEPTION_RECORD* rec = ep ? ep->ExceptionRecord : nullptr;
    g_crashCode = rec ? rec->ExceptionCode : 0UL;
    g_crashSubcode = (rec && rec->NumberParameters >= 1)
                         ? static_cast<unsigned long>(rec->ExceptionInformation[0])
                         : 0UL;
    return EXCEPTION_EXECUTE_HANDLER;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    g_crashCode = 0;
    g_crashSubcode = 0;
    int rc = 0;

    __try {
        rc = runAgent();
    } __except (CrashCaptureFilter(GetExceptionInformation())) {
        // C++ resources inside runAgent() may leak; the process is ending.
    }

    if (g_crashCode != 0) {
        printf("AUDIT_STATUS=CRASH\n");
        printf("EXCEPTION_CODE=0x%08lX\n", g_crashCode);
        printf("FASTFAIL_SUBCODE=0x%08lX\n", g_crashSubcode);
        printf("TOOLS_CALLED=%zu\n", g_dispatchLog.size());
        return 42;
    }
    return rc;
}
