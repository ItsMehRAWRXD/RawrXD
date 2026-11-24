// =============================================================================
// tool_security.hpp — Unified agent tool security (IDE + standalone)
// =============================================================================
// Single source of truth for the P0 agent-security contract shared by:
//   * the IDE path  (src/win32app ToolCallBridge + rawrxd::tools::Registry)
//   * the standalone path (tools/deep2_agentic_loop.cpp)
//
// Provides:
//   1. AuthorizeExecute()      — privileged (Execute-risk) execution requires
//                                explicit HOST authorization. There is no
//                                implicit "the model asked" path in either
//                                frontend; both emit the same reason strings.
//   2. ToolReceiptLog          — durable, append-only JSONL receipt for every
//                                tool decision (allow AND deny), so a run can
//                                be audited after the fact.
//   3. JobIsolation            — Win32 Job Object subprocess containment:
//                                children run inside a per-execution job with
//                                KILL_ON_JOB_CLOSE; timeout/cancel kills the
//                                whole process tree, never orphans it.
//   4. CommandEscapesWorkspace — cheap lexical guard rejecting the obvious
//                                `cd ..` / `cd /` / `cd \` workspace escapes in
//                                model-issued shell commands. The runner also
//                                pins cwd to the workspace root; this guard is
//                                defense-in-depth, not a sandbox.
//
// Header-only: std + Win32 only. No nlohmann dependency (receipts escape JSON
// manually so this can be included from the leanest TU).
// =============================================================================
#pragma once

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace rawrxd::agentic::security {

// ---------------------------------------------------------------------------
// JSON string escaping (receipts are hand-rolled JSONL; keep zero deps)
// ---------------------------------------------------------------------------
inline std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)c);
                    out += buf;
                } else {
                    out += (char)c;
                }
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// 1. Privileged-execution authorization (unified IDE + standalone policy)
// ---------------------------------------------------------------------------
struct ExecuteAuthorization {
    bool allowed = false;
    std::string reason;   // stable machine-readable prefix + human detail
};

// The ONLY way Execute-risk tools (bash/build/test/run, runInTerminal) run:
// the HOST must explicitly authorize them for this process. The model asking
// is never authorization. Both frontends pass their own host-side flag:
//   IDE        -> user approval callback / menu action (interactive host)
//   standalone -> --authorize-execute CLI flag (CI/launcher host decision)
inline ExecuteAuthorization AuthorizeExecute(bool hostAuthorized,
                                             const std::string& hostSource) {
    ExecuteAuthorization a;
    a.allowed = hostAuthorized;
    if (hostAuthorized) {
        a.reason = "AUTHORIZED_BY_HOST source=" + hostSource;
    } else {
        a.reason = "AUTHORIZATION_REQUIRED: privileged execution requires explicit "
                   "host authorization (standalone: --authorize-execute; IDE: user "
                   "approval). hostSource=" + hostSource;
    }
    return a;
}

// ---------------------------------------------------------------------------
// 2. Durable execution receipts (append-only JSONL)
// ---------------------------------------------------------------------------
struct Receipt {
    std::string ts;          // ISO-8601 UTC
    std::string session;     // authorization session id ("" when none)
    std::string tool;
    std::string target;
    std::string risk;        // ReadOnly|Write|Execute|Network|External
    std::string decision;    // ALLOW|DENY
    std::string authorizer;  // e.g. motd+approval, motd+execute-flag, motd-only
    std::string detail;      // deny reason / error / first failure
    long long   exit_code = -999;
    long long   bytes = 0;
    bool        accepted = false;
};

inline std::string NowIso8601Utc() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

// Default durable location: <workspace>/.rawrxd/audit/tool-receipts.jsonl
inline std::string DefaultReceiptPath(const std::string& workspaceRoot) {
    return workspaceRoot + "/.rawrxd/audit/tool-receipts.jsonl";
}

class ToolReceiptLog {
public:
    explicit ToolReceiptLog(std::string path) : path_(std::move(path)) {}

    bool enabled() const { return !path_.empty(); }

    // Append one receipt. Never throws; a failed write sets last_error() and
    // the run continues (receipts are evidence, not a control-flow gate).
    void Write(const Receipt& r) {
        std::lock_guard<std::mutex> lock(mu_);
        if (path_.empty()) return;
        std::error_code ec;
        // Create parent dirs once per write (cheap; keeps the log self-healing
        // when the workspace is created after the loop starts).
        std::filesystem::create_directories(
            std::filesystem::path(path_).parent_path(), ec);
        std::ofstream out(path_, std::ios::app | std::ios::binary);
        if (!out) {
            last_error_ = "cannot open receipt log: " + path_;
            return;
        }
        out << "{\"ts\":\"" << JsonEscape(r.ts) << "\""
            << ",\"session\":\"" << JsonEscape(r.session) << "\""
            << ",\"tool\":\"" << JsonEscape(r.tool) << "\""
            << ",\"target\":\"" << JsonEscape(r.target) << "\""
            << ",\"risk\":\"" << JsonEscape(r.risk) << "\""
            << ",\"decision\":\"" << JsonEscape(r.decision) << "\""
            << ",\"authorizer\":\"" << JsonEscape(r.authorizer) << "\""
            << ",\"detail\":\"" << JsonEscape(r.detail) << "\""
            << ",\"exit_code\":" << r.exit_code
            << ",\"bytes\":" << r.bytes
            << ",\"accepted\":" << (r.accepted ? "true" : "false")
            << "}\n";
        out.flush();
        if (!out) last_error_ = "receipt write failed: " + path_;
    }

    const std::string& last_error() const { return last_error_; }

private:
    std::string path_;
    mutable std::mutex mu_;
    std::string last_error_;
};

// ---------------------------------------------------------------------------
// 3. Win32 Job Object subprocess isolation
// ---------------------------------------------------------------------------
#ifdef _WIN32
class JobIsolation {
public:
    // Per-execution job: KILL_ON_JOB_CLOSE so the whole tree dies with the
    // handle; no breakaway (children cannot escape the job).
    static HANDLE CreateKillJob() {
        HANDLE job = CreateJobObjectA(nullptr, nullptr);
        if (!job) return nullptr;
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                      &info, sizeof(info))) {
            CloseHandle(job);
            return nullptr;
        }
        return job;
    }

    static bool Assign(HANDLE job, HANDLE hProcess) {
        return job && AssignProcessToJobObject(job, hProcess);
    }

    // Terminate every job registered by RunIsolated (cancel path).
    static void KillAll() {
        std::lock_guard<std::mutex> lock(registry_mu());
        for (HANDLE job : registry()) {
            if (job) TerminateJobObject(job, 1);
        }
    }

    // Run `cmdLine` (already a full command line) with cwd=workdir inside a
    // fresh job. timeoutMs==0 means no deadline. On timeout the ENTIRE job is
    // terminated (cancellation/cleanup guarantee). Returns false only when the
    // process could not be launched at all.
    static bool RunIsolated(const std::string& cmdLine,
                            const std::string& workdir,
                            unsigned long long timeoutMs,
                            std::string& out, std::string& err,
                            int& exitCode, bool& timedOut) {
        out.clear(); err.clear(); exitCode = -1; timedOut = false;

        SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
        HANDLE hOutR = nullptr, hOutW = nullptr, hErrR = nullptr, hErrW = nullptr;
        if (!CreatePipe(&hOutR, &hOutW, &sa, 0) ||
            !CreatePipe(&hErrR, &hErrW, &sa, 0)) {
            if (hOutR) CloseHandle(hOutR);
            if (hOutW) CloseHandle(hOutW);
            if (hErrR) CloseHandle(hErrR);
            if (hErrW) CloseHandle(hErrW);
            return false;
        }

        STARTUPINFOA si = {sizeof(si)};
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hOutW;
        si.hStdError = hErrW;
        PROCESS_INFORMATION pi = {};
        std::string mutableCmd = cmdLine;
        if (!CreateProcessA(nullptr, mutableCmd.data(), nullptr, nullptr, TRUE,
                            CREATE_NO_WINDOW, nullptr,
                            workdir.empty() ? nullptr : workdir.c_str(),
                            &si, &pi)) {
            CloseHandle(hOutR); CloseHandle(hOutW);
            CloseHandle(hErrR); CloseHandle(hErrW);
            return false;
        }
        CloseHandle(hOutW); CloseHandle(hErrW);

        HANDLE job = CreateKillJob();
        const bool inJob = Assign(job, pi.hProcess);
        if (job) {
            std::lock_guard<std::mutex> lock(registry_mu());
            registry().insert(job);
        }
        CloseHandle(pi.hThread);

        const auto start = std::chrono::steady_clock::now();
        const size_t cap = 2 * 1024 * 1024;
        auto drain = [&](HANDLE h, std::string& dst) {
            char buf[4096];
            DWORD avail = 0;
            while (PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr) &&
                   avail > 0) {
                DWORD n = 0;
                const DWORD toRead =
                    (std::min<DWORD>)(avail, (DWORD)(sizeof(buf) - 1));
                if (!ReadFile(h, buf, toRead, &n, nullptr) || n == 0) break;
                dst.append(buf, n);
                if (dst.size() > cap) {
                    dst.resize(cap);
                    dst += "\n...[truncated]\n";
                    break;
                }
            }
        };
        for (;;) {
            drain(hOutR, out);
            drain(hErrR, err);
            if (WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) break;
            if (timeoutMs > 0) {
                const auto elapsed =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - start).count();
                if ((unsigned long long)elapsed >= timeoutMs) {
                    timedOut = true;
                    // Kill the whole tree: job first (grandchildren included),
                    // then the direct child as a fallback when no job exists.
                    if (inJob) TerminateJobObject(job, 1);
                    TerminateProcess(pi.hProcess, 1);
                    WaitForSingleObject(pi.hProcess, 5000);
                    break;
                }
            }
        }
        drain(hOutR, out);
        drain(hErrR, err);

        DWORD ec = 0;
        GetExitCodeProcess(pi.hProcess, &ec);
        exitCode = (int)ec;
        CloseHandle(pi.hProcess);
        CloseHandle(hOutR);
        CloseHandle(hErrR);
        if (job) {
            {
                std::lock_guard<std::mutex> lock(registry_mu());
                registry().erase(job);
            }
            CloseHandle(job);  // KILL_ON_JOB_CLOSE: tree is dead by now
        }
        return true;
    }

private:
    static std::set<HANDLE>& registry() {
        static std::set<HANDLE> r;
        return r;
    }
    static std::mutex& registry_mu() {
        static std::mutex m;
        return m;
    }
};
#endif  // _WIN32

// ---------------------------------------------------------------------------
// 4. Workspace-boundary helper for model-issued shell commands
// ---------------------------------------------------------------------------
// Lexical defense-in-depth: the isolated runner pins cwd to the workspace, but
// a command can still `cd` out. Reject the canonical escape forms; the file
// tools (read/write/edit) already enforce the boundary via scoped()/SafeWorkPath.
inline bool CommandEscapesWorkspace(const std::string& cmd) {
    std::string lower;
    lower.reserve(cmd.size());
    for (char c : cmd) lower += (char)std::tolower((unsigned char)c);
    // Tokenize on whitespace and shell separators; look for cd/pushd targets.
    size_t i = 0;
    while (i < lower.size()) {
        size_t j = i;
        while (j < lower.size() && !std::isspace((unsigned char)lower[j]) &&
               lower[j] != ';' && lower[j] != '&' && lower[j] != '|' &&
               lower[j] != '(' && lower[j] != ')')
            ++j;
        const std::string tok = lower.substr(i, j - i);
        if (tok == "cd" || tok == "pushd") {
            // Next token is the target.
            size_t k = j;
            while (k < lower.size() &&
                   std::isspace((unsigned char)lower[k]))
                ++k;
            size_t e = k;
            while (e < lower.size() && !std::isspace((unsigned char)lower[e]) &&
                   lower[e] != ';' && lower[e] != '&' && lower[e] != '|')
                ++e;
            const std::string target = lower.substr(k, e - k);
            if (target == ".." || target == "../" || target == "..\\" ||
                target == "/" || target == "\\" || target == "-") {
                return true;
            }
            // Absolute drive target (cd C:\ or cd C:/...) leaves the workspace.
            if (target.size() >= 2 && target[1] == ':' &&
                (target.size() == 2 || target[2] == '\\' || target[2] == '/')) {
                return true;
            }
            i = e;
            continue;
        }
        i = (j > i) ? j : i + 1;
    }
    return false;
}

}  // namespace rawrxd::agentic::security