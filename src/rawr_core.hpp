/**
 * @file rawr_core.hpp
 * @brief RawrXD shared native core: verified local inference + tool registry.
 *
 * This is the single native contract shared by the IDE, the CLI (`rawr`) and the
 * autonomous agent driver. Everything here is dependency-free Win32/C++17 so the
 * same code links into every front end with no Qt or third-party requirement.
 *
 * Design rules enforced here, not by instructions to the model:
 *  - Every path is resolved inside the workspace root; escapes are rejected.
 *  - Every tool declares a required capability; a mode that lacks it is denied
 *    in the dispatcher, so a read-only mode can never write.
 *  - Every tool returns the *real* result, or an explicit error. There is no
 *    fallback that fabricates success.
 *  - Every external command is bounded by a timeout and killed on expiry.
 */
#ifndef RAWRXD_CORE_HPP
#define RAWRXD_CORE_HPP

// NOMINMAX must precede <windows.h>, otherwise its min/max macros break every
// std::min / std::max call downstream (they rewrite std::min(a,b) into
// std::(a,b), which is a syntax error, not a warning).
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

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

namespace rawr {

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

inline std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    return s;
}

inline std::string truncateForLedger(const std::string& s, size_t limit) {
    if (s.size() <= limit) return s;
    return s.substr(0, limit) +
           "\n...[truncated " + std::to_string(s.size() - limit) + " bytes]";
}

inline void logLine(const std::string& msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("[%02d:%02d:%02d.%03d] %s\n", st.wHour, st.wMinute, st.wSecond,
           st.wMilliseconds, msg.c_str());
}

inline std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Capabilities and modes
// ─────────────────────────────────────────────────────────────────────────────

enum ToolCap : unsigned {
    CAP_NONE   = 0,
    CAP_READ   = 1u << 0,  ///< list directories, read file contents
    CAP_SEARCH = 1u << 1,  ///< text search across the workspace
    CAP_EXEC   = 1u << 2,  ///< run builds, tests, git inspection
    CAP_WRITE  = 1u << 3,  ///< create/modify workspace files
};

struct ModeProfile {
    const char* name;
    const char* description;
    unsigned caps;
    bool sourceEditsAllowed;   ///< project source edits
    bool planFilesOnly;        ///< writes restricted to plan artifacts
    bool executeByDefault;     ///< builds/tests allowed without approval
    bool commitAllowed;        ///< commits require approval at the CLI layer
};

inline const std::vector<ModeProfile>& modeProfiles() {
    static const std::vector<ModeProfile> kModes = {
        {"code",       "Default agent: inspect, modify, build and test",        CAP_READ | CAP_SEARCH | CAP_EXEC | CAP_WRITE, true,  false, true,  false},
        {"ask",        "Answer and explain without changing anything",          CAP_READ | CAP_SEARCH,                        false, false, false, false},
        {"debug",      "Diagnose crashes, apply and verify fixes",              CAP_READ | CAP_SEARCH | CAP_EXEC | CAP_WRITE, true,  false, true,  false},
        {"plan",       "Research and produce implementation plans",             CAP_READ | CAP_SEARCH | CAP_WRITE,            false, true,  false, false},
        {"architect",  "Design components, interfaces and dependency graphs",   CAP_READ | CAP_SEARCH | CAP_WRITE,            false, true,  false, false},
        {"review",     "Review code, diffs and security (read-only)",           CAP_READ | CAP_SEARCH,                        false, false, false, false},
        {"research",   "Investigate local sources and approved docs",           CAP_READ | CAP_SEARCH,                        false, false, false, false},
        {"audit",      "Check completeness and produce evidence",               CAP_READ | CAP_SEARCH | CAP_EXEC,             true,  false, true,  false},
        {"test",       "Discover, generate and execute tests",                  CAP_READ | CAP_SEARCH | CAP_EXEC | CAP_WRITE, false, false, true,  false},
        {"repair",     "Fix build failures and failing tests",                  CAP_READ | CAP_SEARCH | CAP_EXEC | CAP_WRITE, false, false, true,  false},
        {"refactor",   "Restructure while preserving behavior",                 CAP_READ | CAP_SEARCH | CAP_EXEC | CAP_WRITE, false, false, true,  false},
        {"benchmark",  "Measure real inference and system performance",         CAP_READ | CAP_EXEC,                          false, false, true,  false},
        {"swarm",      "Coordinate specialized subagents (alias: orchestrator)", CAP_READ | CAP_SEARCH | CAP_EXEC,             false, false, true,  false},
        {"autonomous", "Execute a persistent backlog across sessions",          CAP_READ | CAP_SEARCH | CAP_EXEC | CAP_WRITE, false, false, true,  false},
    };
    return kModes;
}

inline const ModeProfile* findMode(const std::string& name) {
    std::string n = toLower(name);
    if (n == "orchestrator") n = "swarm";  // deprecated alias
    for (const auto& m : modeProfiles())
        if (n == m.name) return &m;
    return nullptr;
}

inline const char* capName(unsigned bit) {
    switch (bit) {
        case CAP_READ:   return "read";
        case CAP_SEARCH: return "search";
        case CAP_EXEC:   return "execute";
        case CAP_WRITE:  return "write";
        default:         return "unknown";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Workspace
// ─────────────────────────────────────────────────────────────────────────────

class Workspace {
public:
    void setRoot(const std::string& root) { root_ = root; }
    const std::string& root() const { return root_; }

    /// @brief Convert a model-supplied path into a workspace-relative path.
    std::string toRelative(const std::string& raw) const {
        std::string p = raw;
        for (auto& c : p) if (c == '\\') c = '/';
        size_t colon = p.find(':');
        if (colon != std::string::npos && colon + 1 < p.size()) p = p.substr(colon + 1);

        std::string rl = toLower(root_);
        for (auto& c : rl) if (c == '\\') c = '/';
        std::string pl = toLower(p);
        size_t at = pl.find(rl);
        if (at != std::string::npos) p = p.substr(at + rl.size());
        while (!p.empty() && p.front() == '/') p.erase(p.begin());

        size_t slash = p.find('/');
        std::string first = slash == std::string::npos ? p : p.substr(0, slash);
        if (toLower(first) == "rawrxd")
            p = (slash == std::string::npos) ? std::string(".") : p.substr(slash + 1);
        if (p.empty()) p = ".";
        return p;
    }

    /**
     * @brief Resolve a workspace-scoped path.
     * @return Absolute path, or empty string when it escapes the workspace.
     */
    std::string resolve(const std::string& raw, bool mustExist) const {
        std::string rel = toRelative(raw);
        if (rel.empty() || rel.find("..") != std::string::npos) return {};

        fs::path root(root_);
        fs::path candidate = root / rel;
        std::error_code ec;
        fs::path abs = fs::weakly_canonical(candidate, ec);
        if (ec) abs = candidate.lexically_normal();

        auto rootStr = root.lexically_normal().wstring();
        auto absStr = abs.wstring();
        if (rootStr.size() > absStr.size()) return {};
        if (absStr.compare(0, rootStr.size(), rootStr) != 0) return {};
        if (mustExist && !fs::exists(abs)) return {};
        return abs.string();
    }

    std::string relOf(const fs::path& p) const {
        // A path with characters outside the current code page cannot be
        // converted; report the raw form rather than throwing and aborting a
        // whole directory walk.
        try {
            std::error_code ec;
            fs::path r = fs::relative(p, fs::path(root_), ec);
            if (ec || r.empty()) return p.string();
            return r.string();
        } catch (const std::exception&) {
            try { return p.string(); } catch (...) { return "<unrepresentable path>"; }
        }
    }

private:
    std::string root_;
};

// ─────────────────────────────────────────────────────────────────────────────
// Bounded command execution
// ─────────────────────────────────────────────────────────────────────────────

struct CommandResult {
    bool launched = false;
    bool completed = false;   ///< false when killed by timeout
    DWORD exitCode = 0;
    std::string output;
    std::string error;
};

inline CommandResult runBoundedCommand(const std::string& cmdLine,
                                       const std::string& cwd,
                                       DWORD timeoutMs) {
    CommandResult res;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        res.error = "CreatePipe failed";
        return res;
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
    std::wstring cwdW = utf8ToWide(cwd.empty() ? std::string(".") : cwd);

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(nullptr, cmdWide.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, cwdW.c_str(), &si, &pi);
    CloseHandle(writePipe);
    if (!ok) {
        CloseHandle(readPipe);
        res.error = "CreateProcess failed (" + std::to_string(GetLastError()) + ")";
        return res;
    }
    res.launched = true;

    char buf[4096];
    DWORD have = 0;
    DWORD start = GetTickCount();
    bool timedOut = false;
    for (;;) {
        // Collect any pending output.
        while (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &have, nullptr) && have > 0) {
            DWORD rd = 0;
            if (!ReadFile(readPipe, buf, sizeof(buf) - 1, &rd, nullptr) || rd == 0) break;
            buf[rd] = 0;
            res.output += buf;
            if (res.output.size() > 512 * 1024) { res.output += "\n[output cap]\n"; break; }
        }
        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
            // Drain anything written just before exit.
            while (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &have, nullptr) && have > 0) {
                DWORD rd = 0;
                if (!ReadFile(readPipe, buf, sizeof(buf) - 1, &rd, nullptr) || rd == 0) break;
                buf[rd] = 0;
                res.output += buf;
            }
            break;
        }
        if (GetTickCount() - start > timeoutMs) {
            TerminateProcess(pi.hProcess, 1);
            timedOut = true;
            res.exitCode = static_cast<DWORD>(-1);
            res.output += "\n[RAWRXD-NOTE] command killed after timeout (";
            res.output += std::to_string(timeoutMs) + " ms)";
            break;
        }
        Sleep(50);
    }

    if (!timedOut) {
        GetExitCodeProcess(pi.hProcess, &res.exitCode);
        res.completed = true;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(readPipe);
    return res;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool registry
// ─────────────────────────────────────────────────────────────────────────────

struct ToolResult {
    std::string tool;
    std::string argsJson;
    std::string output;
    bool ok = false;
    bool denied = false;   ///< blocked by the permission policy
    DWORD exitCode = 0;
};

struct ToolContext {
    const ModeProfile* mode = nullptr;
    const Workspace* ws = nullptr;
};

class ToolRegistry {
public:
    using Handler = std::function<ToolResult(const json&, const ToolContext&)>;

    void registerTool(const std::string& name, const std::string& description,
                      const std::string& argsSchema, unsigned requiredCaps,
                      Handler handler);

    size_t size() const { return tools_.size(); }
    bool exists(const std::string& name) const { return tools_.count(name) > 0; }
    std::vector<std::string> names() const;
    const json& describe(const std::string& name) const;

    /// @brief Dispatch a tool. Permission checks happen HERE, not in the model.
    ToolResult dispatch(const std::string& name, const json& args,
                        const ToolContext& ctx) const;

private:
    struct Entry {
        std::string name;
        std::string description;
        std::string argsSchema;
        unsigned caps = CAP_NONE;
        Handler handler;
    };
    std::map<std::string, Entry> tools_;
};

void registerDefaultTools(ToolRegistry& reg, const Workspace& ws);

// ─────────────────────────────────────────────────────────────────────────────
// Inference client (local llama.cpp / OpenAI-compatible server)
// ─────────────────────────────────────────────────────────────────────────────

struct InferenceResult {
    bool ok = false;
    std::string content;
    std::string finishReason;
    std::string error;
    int promptTokens = 0;
    int completionTokens = 0;
};

class InferenceClient {
public:
    void setModel(const std::string& m) { model_ = m; }
    void setEndpoint(int port, const std::string& host = "127.0.0.1",
                     const std::string& path = "/v1/chat/completions");
    void setTimeout(int ms) { timeoutMs_ = ms; }

    /// @brief Blocking chat completion against the local backend.
    InferenceResult complete(const std::vector<json>& messages, int maxTokens,
                             double temperature = 0.2);

    /// @brief Cheap liveness probe used by `rawr doctor` and session startup.
    bool ping(int timeoutMs = 30000);

private:
    std::string httpPost(const std::string& path, const std::string& body,
                         long* status, std::string& err);

    std::string model_ = "llama3.2-3b";
    std::wstring host_ = L"127.0.0.1";
    int port_ = 8080;
    std::string path_ = "/v1/chat/completions";
    int timeoutMs_ = 180000;
};

}  // namespace rawr

#endif  // RAWRXD_CORE_HPP
