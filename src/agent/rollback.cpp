/**
 * @file rollback.cpp
 * @brief Rollback implementation — Qt-free, nlohmann-free (C++20 / Win32)
 *
 * Detects performance regressions, reverts commits, opens GitHub issues.
 * Uses json_types.hpp for serialization, manual parse for perf_db.json.
 */

#include "rollback.hpp"
<<<<<<< HEAD
#include "json_types.hpp"
#include "process_utils.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

// ═══════════════════════════════════════════════════════════════════════════
// Minimal perf_db.json parser — extracts tps/ppl from last two entries
// The file is a JSON array of objects: [{ "tps": 42.0, "ppl": 3.2, ... }, ...]
// We only need the numeric tps/ppl fields from the last two entries.
// ═══════════════════════════════════════════════════════════════════════════

struct PerfEntry {
    double tps = 0.0;
    double ppl = 0.0;
};

/// Extract a numeric value after "key": in a JSON string fragment
static double extractDouble(const std::string& obj, const char* key) {
    std::string pat = std::string("\"") + key + "\"";
    size_t pos = obj.find(pat);
    if (pos == std::string::npos) return 0.0;
    pos = obj.find(':', pos + pat.size());
    if (pos == std::string::npos) return 0.0;
    ++pos;
    // skip whitespace
    while (pos < obj.size() && (obj[pos] == ' ' || obj[pos] == '\t')) ++pos;
    if (pos >= obj.size()) return 0.0;
    return std::strtod(obj.c_str() + pos, nullptr);
}

/// Parse perf_db.json: find last two top-level objects in the array
static bool loadPerfEntries(std::vector<PerfEntry>& out) {
    // Resolve path — check CWD/perf_db.json, then CWD/data/perf_db.json
    std::string path;
    if (fs::exists("perf_db.json"))
        path = "perf_db.json";
    else if (fs::exists("data/perf_db.json"))
        path = "data/perf_db.json";
    else {
        // Try environment override
        std::string envPath = getEnvVar("RAWRXD_PERF_DB");
        if (!envPath.empty() && fs::exists(envPath))
            path = envPath;
        else
            return false;
    }

    std::string raw = fileutil::readAll(path);
    if (raw.empty()) return false;

    // Find all top-level { ... } blocks inside the outer [ ... ]
    int depth = 0;
    size_t objStart = std::string::npos;
    std::vector<std::string> objects;

    for (size_t i = 0; i < raw.size(); ++i) {
        char c = raw[i];
        if (c == '{') {
            if (depth == 1 || (depth == 0 && objStart == std::string::npos)) {
                if (depth == 0) {
                    // hadn't seen '[' yet; this might be the first object
                }
                objStart = i;
            }
            ++depth;
        } else if (c == '}') {
            --depth;
            if ((depth == 0 || depth == 1) && objStart != std::string::npos) {
                // We only keep the last N objects to save memory
                objects.push_back(raw.substr(objStart, i - objStart + 1));
                // Keep only last 2 to conserve memory on large DBs
                if (objects.size() > 2)
                    objects.erase(objects.begin());
                objStart = std::string::npos;
            }
        } else if (c == '[' && depth == 0) {
            ++depth; // enter array
        } else if (c == ']' && depth == 1) {
            break;
        }
    }

    for (const auto& obj : objects) {
        PerfEntry e;
        e.tps = extractDouble(obj, "tps");
        e.ppl = extractDouble(obj, "ppl");
        out.push_back(e);
    }
    return !out.empty();
=======
#include "meta_learn.hpp"
#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <string>
#include <nlohmann/json.hpp>

#pragma comment(lib, "winhttp.lib")

// Helper: WinHTTP POST
static bool SendGitHubIssue(const std::string& token, const std::string& title, const std::string& body) {
    HINTERNET hSession = WinHttpOpen(L"RawrXD-Rollback/1.0", 
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                                     WINHTTP_NO_PROXY_NAME, 
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.github.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/repos/ItsMehRAWRXD/RawrXD-ModelLoader/issues",
                                            NULL, WINHTTP_NO_REFERER, 
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    // Headers
    std::string authHeader = "Authorization: Bearer " + token + "\r\ncontent-type: application/json";
    std::wstring wHeader(authHeader.begin(), authHeader.end());

    // Body
    nlohmann::json jsonBody;
    jsonBody["title"] = title;
    jsonBody["body"] = body;
    jsonBody["labels"] = {"regression", "auto"};
    std::string sBody = jsonBody.dump();

    bool bResults = WinHttpSendRequest(hRequest,
                                       wHeader.c_str(), (DWORD)wHeader.length(),
                                       (LPVOID)sBody.c_str(), (DWORD)sBody.length(),
                                       (DWORD)sBody.length(), 0);

    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }
    
    // We could check status code here, but for now we assume success if response received
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return bResults;
}

// Reusing helper function pattern
static bool runProcess(const std::string& cmd, const std::vector<std::string>& args, int timeoutMs = 60000) {
    std::string commandLine = cmd;
    for (const auto& arg : args) {
        commandLine += " \"" + arg + "\"";
    }
    
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    
    char* cmdLine = _strdup(commandLine.c_str());
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        free(cmdLine);
        return false;
    }
    free(cmdLine);
    
    DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
    bool success = false;
    
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
    } else {
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        success = (exitCode == 0);
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return success;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ---------- 1. detect regression ----------
bool Rollback::detectRegression() {
<<<<<<< HEAD
    std::vector<PerfEntry> entries;
    if (!loadPerfEntries(entries)) {
        fprintf(stderr, "[WARN] Rollback: unable to read perf_db.json\n");
        return false;
    }
    if (entries.size() < 2)
        return false;

    const PerfEntry& last = entries[entries.size() - 1];
    const PerfEntry& prev = entries[entries.size() - 2];

    bool tpsReg = (prev.tps > 0.0) && (last.tps < prev.tps * 0.95);
    bool pplReg = (prev.ppl > 0.0) && (last.ppl > prev.ppl * 1.02);

    fprintf(stderr, "[INFO] Rollback::detectRegression tpsReg=%d pplReg=%d lastTPS=%.2f prevTPS=%.2f lastPPL=%.2f prevPPL=%.2f\n",
            tpsReg, pplReg, last.tps, prev.tps, last.ppl, prev.ppl);
=======
    // load before/after from perf_db.json via MetaLearn
    bool ok = false;
    MetaLearn ml;
    auto db = ml.getHistory(""); // Load all
    
    if (db.size() < 2)
        return false; // need at least 2 records

    // last commit = most recent (assuming order or check timestamp)
    // The previous implementation assumed order in list.
    // m_records is appended, so last is most recent.
    
    const auto& last = db.back();
    const auto& prev = db[db.size() - 2];

    double lastTPS = last.tps;
    double prevTPS = prev.tps;
    double lastPPL = last.ppl;
    double prevPPL = prev.ppl;

    // regression: TPS drop > 5 % OR PPL increase > 2 %
    bool tpsReg = lastTPS < prevTPS * 0.95;
    bool pplReg = lastPPL > prevPPL * 1.02;

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    return tpsReg || pplReg;
}

// ---------- 2. git revert ----------
bool Rollback::revertLastCommit() {
<<<<<<< HEAD
    ProcResult pr = proc::run("git", {"revert", "--no-edit", "HEAD"}, 60000);
    if (pr.timedOut) {
        fprintf(stderr, "[WARN] Rollback: git revert timed out\n");
        return false;
    }
    if (pr.exitCode != 0) {
        fprintf(stderr, "[WARN] Rollback: git revert failed: %s\n", pr.stderrStr.c_str());
        return false;
    }
    fprintf(stderr, "[INFO] Rollback: git revert SUCCESS\n");
=======
    if (!runProcess("git", {"revert", "--no-edit", "HEAD"}, 60000)) {
        
        return false;
    }
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

// ---------- 3. open GitHub issue ----------
bool Rollback::openIssue(const std::string& title, const std::string& body) {
<<<<<<< HEAD
    std::string token = getEnvVar("GITHUB_TOKEN");
    if (token.empty()) {
        fprintf(stderr, "[WARN] Rollback: GITHUB_TOKEN not set, skipping issue\n");
=======
    char* token = nullptr;
    size_t len = 0;
    _dupenv_s(&token, &len, "GITHUB_TOKEN");
    
    if (!token || len == 0) {
        
        if (token) free(token);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        return true; // allow in dev
    }
    std::string tokenStr(token);
    free(token);

<<<<<<< HEAD
    JsonObject issue;
    issue["title"] = JsonValue(title);
    issue["body"] = JsonValue(body);

    JsonArray labels;
    labels.push_back(JsonValue("regression"));
    labels.push_back(JsonValue("auto"));
    issue["labels"] = JsonValue(std::move(labels));

    JsonDoc doc(issue);
    std::string payload = doc.toJson();

    http::Response resp = http::post(
        "https://api.github.com/repos/ItsMehRAWRXD/RawrXD-ModelLoader/issues",
        payload,
        {
            {"Authorization", "Bearer " + token},
            {"Content-Type", "application/json"},
            {"Accept", "application/vnd.github+json"}
        }
    );

    if (!resp.ok()) {
        fprintf(stderr, "[WARN] Rollback: GitHub issue failed (HTTP %d): %s\n",
                resp.statusCode, resp.error.c_str());
        return false;
    }

    fprintf(stderr, "[INFO] Rollback: GitHub issue opened\n");
    return true;
=======
    // Native implementation replacing fallback/mock
    return SendGitHubIssue(tokenStr, title, body);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}
