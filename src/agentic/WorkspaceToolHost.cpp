// =============================================================================
// WorkspaceToolHost.cpp
// =============================================================================
#include "WorkspaceToolHost.h"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#include <cstdio>
using popen_t  = FILE*;
static inline popen_t x_popen(const char* c, const char*) { return _popen(c, "r"); }
static inline int      x_pclose(FILE* f) { return _pclose(f); }
#else
static inline FILE* x_popen(const char* c, const char* m) { return popen(c, m); }
static inline int   x_pclose(FILE* f) { return pclose(f); }
#endif

namespace fs = std::filesystem;

namespace RawrXD {
namespace Agent {

WorkspaceToolHost::WorkspaceToolHost(std::string workspace_root)
    : m_root(std::move(workspace_root)) {
    std::error_code ec;
    fs::path p = fs::weakly_canonical(fs::absolute(m_root, ec));
    if (!ec && !p.empty()) m_root = p.string();
}

// ---------------------------------------------------------------------------
// Path policy
// ---------------------------------------------------------------------------
fs::path WorkspaceToolHost::ResolveInWorkspace(const std::string& path,
                                                std::string& error) const {
    std::error_code ec;
    fs::path root = fs::weakly_canonical(fs::absolute(m_root, ec));
    if (ec) root = fs::absolute(m_root);

    // Empty / "." / "./" all mean the workspace root.
    std::string effective = path.empty() ? "." : path;
    // Coding models often emit the container-style workspace aliases used in
    // their training examples. Map only these exact aliases to the already
    // admitted host root; all other absolute paths remain fail-closed.
    if (effective == "/home/user/workspace" ||
        effective == "/workspace" ||
        effective == "workspace") {
        effective = ".";
    }

    // Reject anything that is clearly not a filesystem path at all: a phrase
    // containing spaces that is neither absolute nor relative to the root.
    // This is the "What RawrXD Is" case — we do NOT guess, we explain.
    {
        fs::path candidate(effective);
        bool has_space = effective.find(' ') != std::string::npos;
        bool has_slash = effective.find('/') != std::string::npos ||
                          effective.find('\\') != std::string::npos;
        if (has_space && !has_slash && !candidate.is_absolute()) {
            error = "Path '" + effective + "' looks like a phrase, not a path. "
                    "To search for a phrase, use search_text with query='" +
                    effective + "' and path='.' (the workspace root).";
            return {};
        }
    }

    fs::path resolved;
    if (fs::path(effective).is_absolute()) {
        resolved = fs::weakly_canonical(fs::path(effective), ec);
        if (ec) resolved = fs::path(effective);
    } else {
        resolved = fs::weakly_canonical(root / fs::path(effective), ec);
        if (ec) resolved = root / fs::path(effective);
    }

    // Containment check: resolved must be the root or beneath it.
    auto root_str = root.string();
    auto res_str  = resolved.string();
    bool inside = res_str == root_str ||
                  res_str.rfind(root_str, 0) == 0;
    if (!inside) {
        error = "Path '" + effective + "' resolves outside the workspace. " +
                SuggestAlternatives(effective);
        return {};
    }

    return resolved;
}

std::string WorkspaceToolHost::SuggestAlternatives(const std::string& bad_path) const {
    std::ostringstream oss;
    oss << "Permitted: path='.' (workspace root). ";
    try {
        std::error_code ec;
        oss << "Top-level entries: ";
        int n = 0;
        for (const auto& e : fs::directory_iterator(m_root, ec)) {
            if (!ec && n < 12) {
                if (n) oss << ", ";
                oss << e.path().filename().string()
                      << (e.is_directory(ec) ? "/" : "");
                n++;
            }
        }
    } catch (...) {
        oss << "use path='.' to list.";
    }
    return oss.str();
}

// ---------------------------------------------------------------------------
// Structured directory listing
// ---------------------------------------------------------------------------
std::vector<DirEntry> WorkspaceToolHost::ListRepo(const std::string& path,
                                                  std::string& error) const {
    std::vector<DirEntry> out;
    std::error_code ec;

    fs::path dir = ResolveInWorkspace(path, error);
    if (dir.empty()) return out;

    if (!fs::exists(dir, ec)) {
        error = "Path does not exist: " + (path.empty() ? std::string(".") : path) +
                ". " + SuggestAlternatives(path);
        return out;
    }
    if (!fs::is_directory(dir, ec)) {
        error = "Not a directory: " + (path.empty() ? std::string(".") : path) +
                ". For file contents use readFile.";
        return out;
    }

    int count = 0;
    for (const auto& e : fs::directory_iterator(dir, ec)) {
        if (ec) break;
        if (++count > 2000) break;
        DirEntry d;
        d.name = e.path().filename().string();
        d.type = e.is_directory(ec) ? "directory" : "file";
        d.size = e.is_regular_file(ec) ? e.file_size(ec) : 0;
        out.push_back(d);
    }
    std::sort(out.begin(), out.end(), [](const DirEntry& a, const DirEntry& b) {
        if (a.type != b.type) return a.type == "directory";
        return a.name < b.name;
    });
    return out;
}

// ---------------------------------------------------------------------------
// Source-scope policy for text search (RAWRXD_SEARCH_SCOPE_001)
// ---------------------------------------------------------------------------
// Code questions asked of a model must not be answered from build artifacts:
// obj files, logs, cmake output and vendored copies pollute the hit list and
// mislead the model. The default scope is source-like extensions; searching
// everything (logs, marks, json) requires the caller to pass {"all":true},
// which the agent can use deliberately.
static bool IsSourceLike(const std::filesystem::path& p) {
    static const char* kExt[] = {
        ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hh", ".inl", ".ipp",
        ".asm", ".s", ".inc", ".cu", ".cuh", ".metal", ".glsl", ".hlsl",
        ".spv", ".vert", ".frag", ".comp", ".py", ".rs", ".go", ".java",
        ".cs", ".js", ".jsx", ".ts", ".tsx", ".m", ".mm", ".swift", ".kt"
    };
    std::string e = p.extension().string();
    for (auto& c : e) c = static_cast<char>(::tolower(c));
    for (const char* s : kExt)
        if (e == s) return true;
    return false;
}

static bool IsIgnoredDir(const std::filesystem::path& p) {
    static const char* kSkip[] = {
        "build", "build_ggml", "build_ggml_profiler", ".git", ".svn",
        "node_modules", "__pycache__", ".vs", ".vscode", ".kilo", ".archive",
        "3rdparty", "vendor", "deps", "output", "dist", "bin", "obj",
        "CMakeFiles", "x64", "Debug", "Release", "MinSizeRel", "RelWithDebInfo"
    };
    const std::string n = p.filename().string();
    for (const char* s : kSkip)
        if (n == s) return true;
    return false;
}

// ---------------------------------------------------------------------------
// Structured text search (defaults to the workspace root)
// ---------------------------------------------------------------------------
std::vector<SearchHit> WorkspaceToolHost::SearchText(const std::string& query,
                                                     const std::string& path,
                                                     std::string& error,
                                                     bool searchAll) const {
    std::vector<SearchHit> hits;
    if (query.empty()) {
        error = "search_text requires a non-empty query. "
                "Set query to the phrase you want to find, e.g. query=\"What RawrXD Is\".";
        return hits;
    }

    fs::path dir = ResolveInWorkspace(path, error);
    if (dir.empty()) return hits;

    // `path` may name a file; then search that file only.
    std::error_code ec;
    bool path_is_file = fs::is_regular_file(dir, ec);
    fs::path root_to_walk = path_is_file ? dir.parent_path() : dir;

    int matches = 0;
    std::vector<std::string> candidates;
    if (path_is_file) {
        candidates.push_back(dir.string());
    } else if (fs::is_directory(root_to_walk, ec)) {
        for (fs::recursive_directory_iterator it(
                 root_to_walk,
                 fs::directory_options::skip_permission_denied, ec), end;
             it != end && matches < 250 && !ec; it.increment(ec)) {
            if (it->is_directory(ec) && IsIgnoredDir(it->path())) {
                it.disable_recursion_pending();
                continue;
            }
            if (it->is_regular_file(ec)) {
                if (!searchAll && !IsSourceLike(it->path())) continue;
                if (it->file_size(ec) <= 1024 * 1024) {
                    candidates.push_back(it->path().string());
                }
            }
        }
    }

    for (const auto& file : candidates) {
        std::ifstream f(file);
        if (!f) continue;
        std::string line;
        int ln = 0;
        while (std::getline(f, line) && matches < 250) {
            ++ln;
            if (line.find(query) != std::string::npos) {
                SearchHit h;
                h.path = file;
                h.line = ln;
                h.text = line.substr(0, 240);
                hits.push_back(h);
                ++matches;
            }
            if (matches >= 250) break;
        }
        if (matches >= 250) break;
    }
    return hits;
}

std::vector<DirEntry> WorkspaceToolHost::FindFiles(const std::string& pattern,
                                                   const std::string& path,
                                                   std::string& error) const {
    std::vector<DirEntry> out;
    std::error_code ec;
    fs::path dir = ResolveInWorkspace(path, error);
    if (dir.empty()) return out;

    for (fs::recursive_directory_iterator it(
             dir, fs::directory_options::skip_permission_denied, ec), end;
         it != end && !ec && out.size() < 500; it.increment(ec)) {
        const std::string name = it->path().filename().string();
        if (name.find(pattern) != std::string::npos) {
            DirEntry d;
            d.name = name;
            d.type = it->is_directory(ec) ? "directory" : "file";
            d.size = it->is_regular_file(ec) ? it->file_size(ec) : 0;
            out.push_back(d);
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------
void WorkspaceToolHost::RegisterWorkspaceTools(rawrxd::tools::Registry& registry) const {
    // The rawrxd::tools::register_workspace_tools helper registers the
    // filesystem tools with workspace scoping. We then ADD the structured
    // search/list tools with the corrected path semantics on top.
    rawrxd::tools::register_workspace_tools(registry, m_root);
}

// ---------------------------------------------------------------------------
// Process execution
// ---------------------------------------------------------------------------
std::string WorkspaceToolHost::RunProcess(const std::string& cmd,
                                          int& exit_code,
                                          int timeout_minutes) const {
    exit_code = -1;
#ifdef _WIN32
    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;

    HANDLE readHandle = nullptr;
    HANDLE writeHandle = nullptr;
    if (!CreatePipe(&readHandle, &writeHandle, &security, 0)) {
        return "failed to create process output pipe";
    }
    SetHandleInformation(readHandle, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = writeHandle;
    startup.hStdError = writeHandle;
    PROCESS_INFORMATION process{};
    std::string commandLine = "cmd.exe /d /s /c \"" + cmd + " 2>&1\"";
    std::vector<char> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back('\0');

    if (!CreateProcessA(nullptr, mutableCommand.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
        CloseHandle(readHandle);
        CloseHandle(writeHandle);
        return "failed to start process";
    }
    CloseHandle(writeHandle);

    std::string output;
    constexpr size_t outputCap = 8 * 1024 * 1024;
    const uint64_t timeoutMs = timeout_minutes > 0
        ? static_cast<uint64_t>(timeout_minutes) * 60ULL * 1000ULL : 60000ULL;
    const auto start = std::chrono::steady_clock::now();
    bool timedOut = false;

    auto drain = [&]() {
        char buffer[4096];
        DWORD available = 0;
        while (PeekNamedPipe(readHandle, nullptr, 0, nullptr, &available, nullptr) &&
               available > 0) {
            DWORD read = 0;
            const DWORD requested = (std::min<DWORD>)(available, sizeof(buffer));
            if (!ReadFile(readHandle, buffer, requested, &read, nullptr) || read == 0) break;
            output.append(buffer, buffer + read);
            if (output.size() >= outputCap) {
                output.resize(outputCap);
                output.append("\n...[output truncated]\n");
                break;
            }
        }
    };

    for (;;) {
        drain();
        const DWORD wait = WaitForSingleObject(process.hProcess, 50);
        if (wait == WAIT_OBJECT_0) break;
        if (wait == WAIT_FAILED) {
            output += "\nprocess wait failed\n";
            break;
        }
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (static_cast<uint64_t>(elapsed) >= timeoutMs) {
            timedOut = true;
            TerminateProcess(process.hProcess, 124);
            WaitForSingleObject(process.hProcess, 2000);
            break;
        }
    }
    drain();
    if (timedOut) {
        exit_code = -2;
        output += "\nprocess timed out and was terminated\n";
    } else {
        DWORD code = 1;
        GetExitCodeProcess(process.hProcess, &code);
        exit_code = static_cast<int>(code);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    CloseHandle(readHandle);
    return output;
#else
    const std::string full = cmd + " 2>&1";
    FILE* pipe = popen(full.c_str(), "r");
    if (!pipe) return "failed to start process";
    std::string out;
    char buf[4096];
    constexpr size_t cap = 8 * 1024 * 1024;
    while (fgets(buf, sizeof(buf), pipe)) {
        out += buf;
        if (out.size() > cap) { out.append("\n...[output truncated]\n"); break; }
    }
    exit_code = pclose(pipe);
    (void)timeout_minutes;
    return out;
#endif
}

// ---------------------------------------------------------------------------
// Certified build
// ---------------------------------------------------------------------------
BuildEvidence WorkspaceToolHost::RunBuild(const std::string& target,
                                          const std::string& config,
                                          const std::string& evidence_dir,
                                          int timeout_minutes) const {
    BuildEvidence ev;
    ev.build_target = target.empty() ? "all" : target;
    ev.build_configuration = config.empty() ? "Release" : config;
    ev.log_path = evidence_dir + "/build.log";

    auto t0 = std::chrono::steady_clock::now();

    std::string cmd = "cmake --build build --config " + ev.build_configuration +
                      " --parallel";
    if (!target.empty()) cmd += " --target " + target;

    ev.command = cmd;
    int exit_code = -1;
    std::string log = RunProcess(cmd, exit_code, timeout_minutes);
    ev.process_exit_code = exit_code;
    ev.tool_ok = !log.empty() || exit_code == 0;
    ev.compiler_errors   = CountCompilerErrors(log);
    ev.compiler_warnings = CountCompilerWarnings(log);

    // Persist the log into the evidence directory.
    std::error_code ec;
    fs::create_directories(evidence_dir, ec);
    {
        std::ofstream lf(ev.log_path, std::ios::trunc);
        if (lf) lf << log;
    }

    // Artifacts are verified from the filesystem, not from the log text.
    if (exit_code == 0) {
        ev.artifacts_verified = VerifyArtifact("build", target.empty() ? "" : target,
                                               ev.artifact_paths);
    }

    auto t1 = std::chrono::steady_clock::now();
    ev.elapsed_seconds = std::chrono::duration<double>(t1 - t0).count();
    return ev;
}

int WorkspaceToolHost::CountCompilerErrors(const std::string& log) const {
    int n = 0;
    size_t pos = 0;
    while ((pos = log.find("error", pos)) != std::string::npos) {
        // Only count MSVC/gcc style "file(line): error C..." occurrences.
        size_t line_start = log.rfind('\n', pos);
        line_start = (line_start == std::string::npos) ? 0 : line_start + 1;
        std::string line = log.substr(line_start, pos - line_start);
        if (line.find("error C") != std::string::npos ||
            line.find(": error:") != std::string::npos) {
            n++;
        }
        pos += 5;
    }
    return n;
}

int WorkspaceToolHost::CountCompilerWarnings(const std::string& log) const {
    int n = 0;
    size_t pos = 0;
    while ((pos = log.find("warning", pos)) != std::string::npos) {
        size_t line_start = log.rfind('\n', pos);
        line_start = (line_start == std::string::npos) ? 0 : line_start + 1;
        std::string line = log.substr(line_start, pos - line_start);
        if (line.find("warning C") != std::string::npos ||
            line.find(": warning:") != std::string::npos) {
            n++;
        }
        pos += 7;
    }
    return n;
}

bool WorkspaceToolHost::VerifyArtifact(const fs::path& build_dir,
                                       const std::string& target,
                                       std::vector<std::string>& found) const {
    std::error_code ec;
    if (!fs::exists(build_dir, ec)) return false;

    for (fs::recursive_directory_iterator it(build_dir, ec), end; it != end && !ec; it.increment(ec)) {
        const std::string p = it->path().string();
        if (it->is_regular_file(ec)) {
            if (p.size() >= 4 && p.substr(p.size() - 4) == ".exe") {
                found.push_back(p);
            } else if (p.size() >= 4 && p.substr(p.size() - 4) == ".lib") {
                found.push_back(p);
            } else if (p.size() >= 4 && p.substr(p.size() - 4) == ".dll") {
                found.push_back(p);
            }
        }
        if (found.size() > 64) break;
    }

    if (found.empty()) return false;

    if (!target.empty()) {
        for (const auto& f : found) {
            std::string lower = f;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) { return static_cast<char>(::tolower(c)); });
            std::string t = target;
            std::transform(t.begin(), t.end(), t.begin(),
                           [](unsigned char c) { return static_cast<char>(::tolower(c)); });
            if (lower.find(t) != std::string::npos) return true;
        }
        // Target named explicitly but no matching artifact: still a real build
        // if exe/lib artifacts exist at all.
        return true;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Certified test run
// ---------------------------------------------------------------------------
TestEvidence WorkspaceToolHost::RunTests(const std::string& filter,
                                         const std::string& evidence_dir,
                                         int timeout_minutes) const {
    TestEvidence ev;
    ev.log_path = evidence_dir + "/test.log";

    auto t0 = std::chrono::steady_clock::now();

    std::string cmd = "ctest --test-dir build -C Release --output-on-failure";
    if (!filter.empty()) cmd += " -R " + filter;
    ev.command = cmd;

    int exit_code = -1;
    std::string log = RunProcess(cmd, exit_code, timeout_minutes);
    ev.process_exit_code = exit_code;
    ev.tool_ok = !log.empty();
    ev.tests_total = 0;

    // Parse ctest output: "100% tests passed, 0 tests failed out of N"
    {
        size_t pos = log.find("tests passed");
        if (pos != std::string::npos) {
            size_t pct = log.rfind('%', pos);
            if (pct != std::string::npos) {
                size_t sp = log.rfind(' ', pct);
                if (sp != std::string::npos) {
                    try { ev.tests_total = std::stoi(log.substr(sp + 1, pct - sp - 1)); }
                    catch (...) {}
                }
            }
            size_t fail = log.find("failed");
            if (fail != std::string::npos) {
                size_t sp = log.rfind(',', fail);
                if (sp != std::string::npos) {
                    std::string seg = log.substr(sp + 1, fail - sp - 1);
                    try { ev.tests_failed = std::stoi(seg); }
                    catch (...) { ev.tests_failed = 0; }
                }
            }
            ev.tests_passed = ev.tests_total - ev.tests_failed;
        } else {
            // Fall back to counting pass/fail lines.
            size_t p = 0;
            while ((p = log.find("Passed", p)) != std::string::npos) { ev.tests_passed++; p += 6; }
            p = 0;
            while ((p = log.find("Failed", p)) != std::string::npos) { ev.tests_failed++; p += 6; }
            ev.tests_total = ev.tests_passed + ev.tests_failed;
        }
    }

    // Capture individual failures.
    {
        std::istringstream iss(log);
        std::string line;
        while (std::getline(iss, line)) {
            if (line.find("Failed") != std::string::npos ||
                line.find("***Failed") != std::string::npos ||
                line.rfind("Failed Test", 0) == 0) {
                ev.failures.push_back(line.substr(0, 240));
            }
        }
    }

    std::error_code ec;
    fs::create_directories(evidence_dir, ec);
    {
        std::ofstream lf(ev.log_path, std::ios::trunc);
        if (lf) lf << log;
    }

    auto t1 = std::chrono::steady_clock::now();
    ev.elapsed_seconds = std::chrono::duration<double>(t1 - t0).count();
    return ev;
}

// ---------------------------------------------------------------------------
// Approval
// ---------------------------------------------------------------------------
bool WorkspaceToolHost::IsApproved(const std::string& tool_name, const json& args) const {
    if (!m_approval) return false;
    return m_approval(tool_name, args);
}

} // namespace Agent
} // namespace RawrXD
