// ============================================================================
// RawrXDAgenticE2E.cpp — RAWRXD_WIN32IDE_AGENTIC_001
//
// Real-model certification path. There is deliberately no success shortcut:
// PASS requires a model-emitted tool call for each real operation and a real
// child executable returning 0 with AGENTIC_E2E_OK in its captured output.
// ============================================================================

#include "RawrXDAgenticE2E.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/wait.h>
#endif

#include "deep2/AgentToolAuthority.hpp"
#include "deep2/AgentToolRegistry.hpp"
#include "deep2/Deep2Engine.h"

namespace rawrxd::agentic_e2e {
namespace {

using RawrXD::Agentic::AgentToolRegistry;
using RawrXD::Agentic::AgentToolSurface;
using RawrXD::Agentic::BindAgentToolAuthority;
using RawrXD::Agentic::IsAgentToolAuthorityBound;
using RawrXD::Agentic::ToolContext;
using RawrXD::Agentic::ToolDescriptor;
using RawrXD::Agentic::ToolRequest;
using RawrXD::Agentic::ToolResult;

struct ProcessResult {
    bool launched = false;
    bool timedOut = false;
    int exitCode = -1;
    std::string output;
};

std::string trim(std::string s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

std::string jsonString(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    size_t p = json.find(needle);
    if (p == std::string::npos) return {};
    p = json.find(':', p + needle.size());
    if (p == std::string::npos) return {};
    ++p;
    while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
    if (p >= json.size()) return {};

    if (json[p] != '"') {
        const size_t b = p;
        while (p < json.size() && json[p] != ',' && json[p] != '}' &&
               !std::isspace(static_cast<unsigned char>(json[p]))) {
            ++p;
        }
        return json.substr(b, p - b);
    }

    ++p;
    std::string out;
    while (p < json.size()) {
        const char c = json[p++];
        if (c == '"') return out;
        if (c != '\\') {
            out.push_back(c);
            continue;
        }
        if (p >= json.size()) break;
        const char e = json[p++];
        switch (e) {
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case '\\': out.push_back('\\'); break;
            case '"': out.push_back('"'); break;
            default: out.push_back(e); break;
        }
    }
    return {};
}

uint32_t jsonU32(const std::string& json, const std::string& key, uint32_t fallback) {
    const std::string s = jsonString(json, key);
    if (s.empty()) return fallback;
    try {
        const unsigned long v = std::stoul(s);
        return static_cast<uint32_t>(std::min<unsigned long>(v, 0xffffffffUL));
    } catch (...) {
        return fallback;
    }
}

bool pathIsInside(const std::filesystem::path& root,
                  const std::filesystem::path& candidate) {
    auto r = root.lexically_normal();
    auto c = candidate.lexically_normal();
    auto ri = r.begin();
    auto ci = c.begin();
    for (; ri != r.end(); ++ri, ++ci) {
        if (ci == c.end() || *ri != *ci) return false;
    }
    return true;
}

bool resolveWorkspacePath(const std::filesystem::path& rootInput,
                          const std::string& relText,
                          std::filesystem::path& out,
                          std::string& error) {
    if (relText.empty()) {
        error = "empty path";
        return false;
    }
    std::filesystem::path rel(relText);
    if (rel.is_absolute() || rel.has_root_name() || rel.has_root_directory()) {
        error = "absolute path rejected";
        return false;
    }
    for (const auto& part : rel) {
        if (part == "..") {
            error = "path escape rejected";
            return false;
        }
    }

    std::error_code ec;
    auto root = std::filesystem::weakly_canonical(rootInput, ec);
    if (ec || root.empty()) {
        error = "workspace root is not canonical/readable";
        return false;
    }

    auto candidate = std::filesystem::weakly_canonical(root / rel, ec);
    if (ec) {
        // weakly_canonical may fail if several tail components do not exist.
        // Canonicalize the parent that exists, then append the filename.
        ec.clear();
        auto parent = std::filesystem::weakly_canonical((root / rel).parent_path(), ec);
        if (ec || parent.empty()) {
            error = "cannot resolve path parent";
            return false;
        }
        candidate = parent / (root / rel).filename();
    }
    candidate = candidate.lexically_normal();
    if (!pathIsInside(root, candidate)) {
        error = "resolved path escaped workspace";
        return false;
    }
    out = candidate;
    return true;
}

std::string quoteArg(const std::filesystem::path& p) {
    std::string s = p.string();
    std::string q = "\"";
    size_t slashes = 0;
    for (char c : s) {
        if (c == '\\') {
            ++slashes;
            continue;
        }
        if (c == '"') {
            q.append(slashes * 2 + 1, '\\');
            q.push_back('"');
            slashes = 0;
            continue;
        }
        q.append(slashes, '\\');
        slashes = 0;
        q.push_back(c);
    }
    q.append(slashes * 2, '\\');
    q.push_back('"');
    return q;
}

#ifdef _WIN32
ProcessResult runProcess(const std::filesystem::path& cwd,
                         const std::string& commandLineUtf8,
                         uint32_t timeoutMs) {
    ProcessResult result;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) return result;
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::vector<char> cmd(commandLineUtf8.begin(), commandLineUtf8.end());
    cmd.push_back('\0');
    const std::string cwdText = cwd.string();

    const BOOL ok = CreateProcessA(
        nullptr, cmd.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr,
        cwdText.empty() ? nullptr : cwdText.c_str(), &si, &pi);

    CloseHandle(writePipe);
    writePipe = nullptr;
    if (!ok) {
        CloseHandle(readPipe);
        return result;
    }

    result.launched = true;
    const auto start = std::chrono::steady_clock::now();
    std::array<char, 4096> buffer{};

    for (;;) {
        DWORD available = 0;
        if (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) && available) {
            DWORD got = 0;
            const DWORD want = static_cast<DWORD>(std::min<size_t>(buffer.size(), available));
            if (ReadFile(readPipe, buffer.data(), want, &got, nullptr) && got) {
                result.output.append(buffer.data(), got);
                if (result.output.size() > 1024 * 1024) {
                    result.output.resize(1024 * 1024);
                    result.output += "\n[output truncated]\n";
                }
            }
        }

        const DWORD state = WaitForSingleObject(pi.hProcess, 10);
        if (state == WAIT_OBJECT_0) break;

        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeoutMs) {
            result.timedOut = true;
            TerminateProcess(pi.hProcess, 124);
            WaitForSingleObject(pi.hProcess, 5000);
            break;
        }
    }

    // Drain remaining output.
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(readPipe, buffer.data(), static_cast<DWORD>(buffer.size()), &got, nullptr) || got == 0)
            break;
        result.output.append(buffer.data(), got);
        if (result.output.size() > 1024 * 1024) break;
    }

    DWORD ec = 1;
    GetExitCodeProcess(pi.hProcess, &ec);
    result.exitCode = static_cast<int>(ec);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(readPipe);
    return result;
}
#else
ProcessResult runProcess(const std::filesystem::path& cwd,
                         const std::string& commandLineUtf8,
                         uint32_t) {
    ProcessResult r;
    const std::string cmd = "cd \"" + cwd.string() + "\" && " + commandLineUtf8 + " 2>&1";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return r;
    r.launched = true;
    char buf[4096];
    while (fgets(buf, sizeof(buf), p)) r.output += buf;
    const int st = pclose(p);
    r.exitCode = WIFEXITED(st) ? WEXITSTATUS(st) : 1;
    return r;
}
#endif


bool commitTempFile(const std::filesystem::path& temp,
                    const std::filesystem::path& dest,
                    std::string& error) {
#ifdef _WIN32
    if (!MoveFileExW(temp.wstring().c_str(), dest.wstring().c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        error = "MoveFileEx failed: " + std::to_string(GetLastError());
        return false;
    }
    return true;
#else
    std::error_code ec;
    std::filesystem::rename(temp, dest, ec);
    if (ec) {
        error = "rename failed: " + ec.message();
        return false;
    }
    return true;
#endif
}

ToolResult readTool(const ToolRequest& req, ToolContext&) {
    ToolResult r;
    const std::string rel = jsonString(req.stdin_text, "path");
    std::filesystem::path full;
    std::string err;
    if (!resolveWorkspacePath(req.working_directory, rel, full, err)) {
        r.exit_code = 77;
        r.stderr_text = err;
        return r;
    }
    std::ifstream f(full, std::ios::binary);
    if (!f) {
        r.exit_code = 66;
        r.stderr_text = "cannot open: " + rel;
        return r;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    r.stdout_text = ss.str();
    if (r.stdout_text.size() > 65536) r.stdout_text.resize(65536);
    return r;
}

ToolResult writeTool(const ToolRequest& req, ToolContext&) {
    ToolResult r;
    const std::string rel = jsonString(req.stdin_text, "path");
    const std::string content = jsonString(req.stdin_text, "content");
    if (rel.empty()) {
        r.exit_code = 64;
        r.stderr_text = "missing path";
        return r;
    }

    std::filesystem::path full;
    std::string err;
    if (!resolveWorkspacePath(req.working_directory, rel, full, err)) {
        r.exit_code = 77;
        r.stderr_text = err;
        return r;
    }

    std::error_code ec;
    std::filesystem::create_directories(full.parent_path(), ec);
    if (ec) {
        r.exit_code = 73;
        r.stderr_text = "cannot create parent directory: " + ec.message();
        return r;
    }

    const auto temp = full.string() + ".rawrxd_tmp";
    {
        std::ofstream f(temp, std::ios::binary | std::ios::trunc);
        if (!f) {
            r.exit_code = 73;
            r.stderr_text = "cannot create temp file";
            return r;
        }
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
        f.flush();
        if (!f) {
            r.exit_code = 74;
            r.stderr_text = "write failed";
            return r;
        }
    }

    std::string commitError;
    if (!commitTempFile(temp, full, commitError)) {
        std::filesystem::remove(temp, ec);
        r.exit_code = 74;
        r.stderr_text = commitError;
        return r;
    }

    r.stdout_text = "WROTE_BYTES=" + std::to_string(content.size()) + "\nPATH=" + rel;
    return r;
}

ToolResult replaceTool(const ToolRequest& req, ToolContext&) {
    ToolResult r;
    const std::string rel = jsonString(req.stdin_text, "path");
    const std::string find = jsonString(req.stdin_text, "find");
    const std::string repl = jsonString(req.stdin_text, "replace");
    const uint32_t expected = jsonU32(req.stdin_text, "expected", 1);
    if (rel.empty() || find.empty()) {
        r.exit_code = 64;
        r.stderr_text = "missing path/find";
        return r;
    }

    std::filesystem::path full;
    std::string err;
    if (!resolveWorkspacePath(req.working_directory, rel, full, err)) {
        r.exit_code = 77;
        r.stderr_text = err;
        return r;
    }

    std::ifstream in(full, std::ios::binary);
    if (!in) {
        r.exit_code = 66;
        r.stderr_text = "cannot open: " + rel;
        return r;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    std::string content = ss.str();

    uint32_t matches = 0;
    size_t p = 0;
    while ((p = content.find(find, p)) != std::string::npos) {
        ++matches;
        p += find.size();
    }
    if (matches != expected) {
        r.exit_code = 65;
        r.stderr_text = "replace cardinality mismatch: expected=" +
                        std::to_string(expected) + " actual=" + std::to_string(matches);
        return r;
    }

    p = 0;
    while ((p = content.find(find, p)) != std::string::npos) {
        content.replace(p, find.size(), repl);
        p += repl.size();
    }

    const auto temp = full.string() + ".rawrxd_tmp";
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        if (!out) {
            r.exit_code = 73;
            r.stderr_text = "cannot create temp file";
            return r;
        }
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        out.flush();
        if (!out) {
            r.exit_code = 74;
            r.stderr_text = "write failed";
            return r;
        }
    }
    std::error_code ec;
    std::string commitError;
    if (!commitTempFile(temp, full, commitError)) {
        std::filesystem::remove(temp, ec);
        r.exit_code = 74;
        r.stderr_text = commitError;
        return r;
    }

    r.stdout_text = "REPLACED=" + std::to_string(matches) + "\nPATH=" + rel;
    return r;
}

ToolResult processTool(const ToolRequest& req, ToolContext&) {
    ToolResult r;
    const std::string exeText = jsonString(req.stdin_text, "exe");
    const std::string args = jsonString(req.stdin_text, "args");
    std::string cwdText = jsonString(req.stdin_text, "cwd");
    const uint32_t timeoutMs = jsonU32(req.stdin_text, "timeout_ms", 120000);
    if (exeText.empty()) {
        r.exit_code = 64;
        r.stderr_text = "missing exe";
        return r;
    }
    if (cwdText.empty()) cwdText = ".";

    std::filesystem::path cwd;
    std::string err;
    if (!resolveWorkspacePath(req.working_directory, cwdText, cwd, err)) {
        r.exit_code = 77;
        r.stderr_text = "cwd: " + err;
        return r;
    }

    std::string command;
    if (exeText.find('/') != std::string::npos || exeText.find('\\') != std::string::npos ||
        exeText.find(':') != std::string::npos) {
        std::filesystem::path exePath;
        if (!resolveWorkspacePath(req.working_directory, exeText, exePath, err)) {
            r.exit_code = 77;
            r.stderr_text = "exe: " + err;
            return r;
        }
        std::error_code ec;
        if (!std::filesystem::is_regular_file(exePath, ec)) {
            r.exit_code = 66;
            r.stderr_text = "workspace executable not found";
            return r;
        }
        command = quoteArg(exePath);
    } else {
        // Bare executable names are resolved by CreateProcess/PATH. There is no
        // cmd.exe / shell layer, so metacharacters are not interpreted here.
        for (char c : exeText) {
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-')) {
                r.exit_code = 64;
                r.stderr_text = "invalid bare executable name";
                return r;
            }
        }
        command = "\"" + exeText + "\"";
    }
    if (!args.empty()) command += " " + args;

    ProcessResult p = runProcess(cwd, command, timeoutMs);
    if (!p.launched) {
        r.exit_code = 127;
        r.stderr_text = "process launch failed";
        return r;
    }
    r.exit_code = p.timedOut ? 124 : p.exitCode;
    r.stdout_text = p.output;
    if (r.exit_code != 0) r.stderr_text = p.output;
    return r;
}

ToolResult buildTool(const ToolRequest& req, ToolContext&) {
    ToolResult r;
    const std::string rel = jsonString(req.stdin_text, "dir");
    const uint32_t timeoutMs = jsonU32(req.stdin_text, "timeout_ms", 120000);
    std::filesystem::path gateDir;
    std::string err;
    if (!resolveWorkspacePath(req.working_directory, rel, gateDir, err)) {
        r.exit_code = 77;
        r.stderr_text = err;
        return r;
    }

    const auto buildDir = gateDir / "build";
    std::error_code ec;
    std::filesystem::create_directories(buildDir, ec);
    if (ec) {
        r.exit_code = 73;
        r.stderr_text = ec.message();
        return r;
    }

#ifdef _WIN32
    const std::string cmakeExe = "cmake.exe";
#else
    const std::string cmakeExe = "cmake";
#endif
    const std::string configure = cmakeExe + " -S " + quoteArg(gateDir) +
                                  " -B " + quoteArg(buildDir);
    ProcessResult c = runProcess(req.working_directory, configure, timeoutMs);
    if (!c.launched) {
        r.exit_code = 127;
        r.stderr_text = "cmake configure launch failed";
        return r;
    }
    if (c.timedOut || c.exitCode != 0) {
        r.exit_code = c.timedOut ? 124 : c.exitCode;
        r.stderr_text = "CONFIGURE_FAIL\n" + c.output;
        return r;
    }

    const std::string build = cmakeExe + " --build " + quoteArg(buildDir) +
                              " --config Release --target agentic_probe";
    ProcessResult b = runProcess(req.working_directory, build, timeoutMs);
    if (!b.launched) {
        r.exit_code = 127;
        r.stderr_text = "cmake build launch failed";
        return r;
    }
    r.exit_code = b.timedOut ? 124 : b.exitCode;
    r.stdout_text = c.output + "\n" + b.output;
    if (r.exit_code != 0) r.stderr_text = "BUILD_FAIL\n" + b.output;
    else r.stdout_text += "\nBUILD_PASS";
    return r;
}

ToolResult testTool(const ToolRequest& req, ToolContext&) {
    ToolResult r;
    const std::string rel = jsonString(req.stdin_text, "dir");
    const uint32_t timeoutMs = jsonU32(req.stdin_text, "timeout_ms", 30000);
    std::filesystem::path gateDir;
    std::string err;
    if (!resolveWorkspacePath(req.working_directory, rel, gateDir, err)) {
        r.exit_code = 77;
        r.stderr_text = err;
        return r;
    }

    std::vector<std::filesystem::path> candidates;
#ifdef _WIN32
    candidates.push_back(gateDir / "build" / "Release" / "agentic_probe.exe");
    candidates.push_back(gateDir / "build" / "agentic_probe.exe");
#else
    candidates.push_back(gateDir / "build" / "agentic_probe");
    candidates.push_back(gateDir / "build" / "Release" / "agentic_probe");
#endif

    std::filesystem::path exe;
    std::error_code ec;
    for (const auto& p : candidates) {
        if (std::filesystem::is_regular_file(p, ec)) {
            exe = p;
            break;
        }
        ec.clear();
    }
    if (exe.empty()) {
        r.exit_code = 66;
        r.stderr_text = "built executable not found";
        return r;
    }

    ProcessResult p = runProcess(gateDir, quoteArg(exe), timeoutMs);
    if (!p.launched) {
        r.exit_code = 127;
        r.stderr_text = "test executable launch failed";
        return r;
    }
    r.exit_code = p.timedOut ? 124 : p.exitCode;
    r.stdout_text = p.output;
    if (r.exit_code == 0 && p.output.find("AGENTIC_E2E_OK") != std::string::npos) {
        r.stdout_text += "\nTEST_PASS";
    } else {
        if (r.exit_code == 0) r.exit_code = 3;
        r.stderr_text = "TEST_FAIL exit=" + std::to_string(p.exitCode) + "\n" + p.output;
    }
    return r;
}

void registerGateTools(AgentToolRegistry& registry) {
    if (!registry.contains("agent.file.read"))
        registry.registerTool(
            {"agent.file.read", {}, "Read a workspace-relative file."}, readTool);
    if (!registry.contains("agent.file.write"))
        registry.registerTool(
            {"agent.file.write", {}, "Atomically write a workspace-relative file."}, writeTool);
    if (!registry.contains("agent.file.replace"))
        registry.registerTool(
            {"agent.file.replace", {}, "Exact-cardinality atomic source replacement."}, replaceTool);
    if (!registry.contains("agent.build"))
        registry.registerTool(
            {"agent.build", {}, "Configure and build the real agentic probe target."}, buildTool);
    if (!registry.contains("agent.test"))
        registry.registerTool(
            {"agent.test", {}, "Execute the real built agentic probe and capture its exit/output."}, testTool);
}

AgentToolRegistry& gateAuthority() {
    // Gate ownership is process-lifetime so the certification path can never
    // leave AgentToolAuthority pointing at a destroyed stack registry. If no
    // authority is bound yet, this registry also becomes the process authority.
    // If the IDE already owns a different authority, that authority is left
    // untouched; shipping integration should registerRawrXDCodingTools() on it.
    static AgentToolRegistry bootstrap;
    static std::once_flag once;
    std::call_once(once, [&] {
        registerGateTools(bootstrap);
        registerRawrXDCodingTools(bootstrap);
        if (!IsAgentToolAuthorityBound()) BindAgentToolAuthority(bootstrap);
    });
    return bootstrap;
}

struct Reply {
    bool tool = false;
    bool protocolError = false;
    std::string toolName;
    std::string args;
    std::string finalText;
};

std::string between(const std::string& s, const std::string& a, const std::string& b) {
    const size_t p = s.find(a);
    if (p == std::string::npos) return {};
    const size_t q = s.find(b, p + a.size());
    if (q == std::string::npos) return {};
    return s.substr(p + a.size(), q - (p + a.size()));
}

Reply parseReply(const std::string& raw) {
    Reply r;
    std::string s = trim(raw);
    const size_t im = s.find("<|im_end|>");
    if (im != std::string::npos) s.resize(im);

    const std::string taggedTool = trim(between(s, "<tool>", "</tool>"));
    if (!taggedTool.empty()) {
        r.tool = true;
        r.toolName = taggedTool;
        r.args = trim(between(s, "<args>", "</args>"));
        if (r.args.empty()) r.args = "{}";
        return r;
    }

    // Accepted compact spellings:
    //   TOOL agent.file.read {"path":"..."}
    //   agent.file.read {"path":"..."}
    std::string line = s;
    const size_t nl = line.find('\n');
    if (nl != std::string::npos) line.resize(nl);
    line = trim(line);
    if (line.rfind("TOOL ", 0) == 0) line = trim(line.substr(5));
    const size_t brace = line.find('{');
    if (brace != std::string::npos) {
        const std::string name = trim(line.substr(0, brace));
        if (name.rfind("agent.", 0) == 0) {
            const size_t close = line.rfind('}');
            if (close == std::string::npos || close < brace) {
                r.protocolError = true;
                return r;
            }
            r.tool = true;
            r.toolName = name;
            r.args = line.substr(brace, close - brace + 1);
            return r;
        }
    }

    if (s.find("<args>") != std::string::npos || s.find("<tool>") != std::string::npos) {
        r.protocolError = true;
        return r;
    }

    r.finalText = trim(s);
    return r;
}

struct Transaction {
    std::string tool;
    std::string args;
    ToolResult result;
};

std::string nextRequired(const AgenticE2EReceipt& r) {
    if (!r.fileRead) return "agent.file.read";
    if (!r.fileEdit) return "agent.file.replace";
    if (!r.buildPassed) return "agent.build";
    if (!r.testPassed) return "agent.test";
    return "FINAL";
}

std::string makePrompt(const std::filesystem::path& fixtureRel,
                       const AgenticE2EReceipt& receipt,
                       const std::vector<Transaction>& history,
                       uint32_t timeoutMs) {
    const std::string rel = fixtureRel.generic_string();
    std::ostringstream p;
    p << "RAWRXD_WIN32IDE_AGENTIC_001 CERTIFICATION\n"
         "You are the real local model controlling RawrXD Tool Authority.\n"
         "You must perform the requested tool transaction; do not claim a tool ran unless its result appears below.\n"
         "Emit exactly ONE tool call per turn using:\n"
         "<tool>tool.name</tool>\n<args>{JSON}</args>\n"
         "Only after the real test tool reports TEST_PASS may you emit a short final answer with no tool tags.\n\n"
         "TOOLS:\n"
         "agent.file.read {\"path\":\"relative/path\"}\n"
         "agent.file.write {\"path\":\"relative/path\",\"content\":\"...\"}\n"
         "agent.file.replace {\"path\":\"relative/path\",\"find\":\"...\",\"replace\":\"...\",\"expected\":1}\n"
         "agent.build {\"dir\":\"relative/gate/dir\"}\n"
         "agent.test {\"dir\":\"relative/gate/dir\"}\n\n"
         "TASK:\n"
         "1. Read " << rel << "/agentic_probe.cpp.\n"
         "2. Edit it so it prints AGENTIC_E2E_OK and returns 0.\n"
         "3. Build the fixture with agent.build.\n"
         "4. Run it with agent.test.\n"
         "5. Finish only after TEST_PASS.\n\n";

    if (!history.empty()) {
        p << "REAL TOOL HISTORY:\n";
        const size_t start = history.size() > 6 ? history.size() - 6 : 0;
        for (size_t i = start; i < history.size(); ++i) {
            const auto& h = history[i];
            p << "CALL " << h.tool << " " << h.args << "\n";
            p << "RESULT exit_code=" << h.result.exit_code << "\n";
            const std::string& body = h.result.ok() ? h.result.stdout_text : h.result.stderr_text;
            p << body.substr(0, 8192) << "\n---\n";
        }
    }

    p << "NEXT_REQUIRED_TOOL=" << nextRequired(receipt) << "\n";
    if (nextRequired(receipt) == "agent.file.read") {
        p << "Use path \"" << rel << "/agentic_probe.cpp\".\n";
    } else if (nextRequired(receipt) == "agent.file.replace") {
        p << "Replace exactly this text in \"" << rel << "/agentic_probe.cpp\":\n"
             "FIND: std::puts(\"AGENTIC_E2E_BROKEN\");\\n    return 7;\n"
             "REPLACE: std::puts(\"AGENTIC_E2E_OK\");\\n    return 0;\n";
    } else if (nextRequired(receipt) == "agent.build" ||
               nextRequired(receipt) == "agent.test") {
        p << "Use dir \"" << rel << "\" and timeout_ms=" << timeoutMs << ".\n";
    } else {
        p << "The real read/edit/build/test chain has passed. Emit final answer now.\n";
    }
    p << "ASSISTANT:\n";
    return p.str();
}

bool seedFixture(const AgenticE2EOptions& options, std::string& error) {
    std::filesystem::path gateDir;
    if (!resolveWorkspacePath(options.workspaceRoot, options.fixtureDir.generic_string(), gateDir, error))
        return false;

    std::error_code ec;
    if (!options.keepFixture) std::filesystem::remove_all(gateDir, ec);
    ec.clear();
    std::filesystem::create_directories(gateDir, ec);
    if (ec) {
        error = "cannot create gate fixture: " + ec.message();
        return false;
    }

    {
        std::ofstream f(gateDir / "agentic_probe.cpp", std::ios::binary | std::ios::trunc);
        if (!f) {
            error = "cannot seed agentic_probe.cpp";
            return false;
        }
        f << "#include <cstdio>\n"
             "int main() {\n"
             "    std::puts(\"AGENTIC_E2E_BROKEN\");\n"
             "    return 7;\n"
             "}\n";
    }
    {
        std::ofstream f(gateDir / "CMakeLists.txt", std::ios::binary | std::ios::trunc);
        if (!f) {
            error = "cannot seed CMakeLists.txt";
            return false;
        }
        f << "cmake_minimum_required(VERSION 3.20)\n"
             "project(rawrxd_agentic_probe LANGUAGES CXX)\n"
             "add_executable(agentic_probe agentic_probe.cpp)\n"
             "set_target_properties(agentic_probe PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED YES)\n";
    }
    return true;
}

} // namespace

void registerRawrXDCodingTools(AgentToolRegistry& authority) {
    if (!authority.contains("file.read"))
        authority.registerTool(
            {"file.read", {"read_file"}, "Read a workspace-relative file."}, readTool);
    if (!authority.contains("file.write"))
        authority.registerTool(
            {"file.write", {"write_file"}, "Atomically write a workspace-relative file."}, writeTool);
    if (!authority.contains("file.replace"))
        authority.registerTool(
            {"file.replace", {"edit_file"}, "Exact-cardinality atomic text replacement."}, replaceTool);
    if (!authority.contains("process.run"))
        authority.registerTool(
            {"process.run", {"exec_process"}, "Run a real child process without a shell and capture exit/output."}, processTool);
}

std::string rawrXDCodingToolCatalog() {
    return
        "CODING TOOLS (real operations; workspace-relative paths only):\n"
        "file.read {\"path\":\"src/file.cpp\"}\n"
        "file.write {\"path\":\"src/file.cpp\",\"content\":\"complete file text\"}\n"
        "file.replace {\"path\":\"src/file.cpp\",\"find\":\"exact old text\",\"replace\":\"new text\",\"expected\":1}\n"
        "process.run {\"exe\":\"cmake.exe\",\"args\":\"--build ...\",\"cwd\":\".\",\"timeout_ms\":120000}\n"
        "Never report an edit/build/test as successful unless the corresponding tool result says exit_code=0.\n";
}

std::string rawrXDCodingSystemPrompt() {
    return std::string(
        "You are RawrXD's local coding agent. Use real tools for repository facts and mutations.\n"
        "PROTOCOL: emit exactly one tool call as <tool>name</tool> followed by "
        "<args>{JSON}</args>. After a tool result, continue from that result.\n"
        "For coding tasks: inspect before editing; make the smallest complete edit; build; "
        "run the relevant test; only then give a final answer. Never fabricate tool output.\n\n") +
        rawrXDCodingToolCatalog();
}

AgenticE2EReceipt runAgenticE2EGate(
    Deep2::Deep2Engine& engine,
    const AgenticE2EOptions& options) {
    AgenticE2EReceipt receipt;

    if (options.workspaceRoot.empty()) {
        receipt.failStage = "WORKSPACE";
        receipt.failMessage = "workspaceRoot is empty";
        return receipt;
    }

    std::string seedError;
    if (!seedFixture(options, seedError)) {
        receipt.failStage = "FIXTURE";
        receipt.failMessage = seedError;
        return receipt;
    }

    AgentToolRegistry& authority = gateAuthority();
    receipt.toolAuthority = true;
    std::vector<Transaction> history;

    for (uint32_t step = 0; step < options.maxSteps; ++step) {
        receipt.steps = step + 1;
        const std::string prompt = makePrompt(options.fixtureDir, receipt, history, options.processTimeoutMs);
        if (!history.empty()) receipt.toolResultFedBack = true;

        Deep2::GenerationOptions gen{};
        gen.maxTokens = options.maxTokensPerStep;
        gen.temperature = 0.0f;
        gen.topK = 1;
        gen.topP = 1.0f;
        gen.repeatPenalty = 1.0f;
        gen.seed = 1;

        std::string text;
        engine.reset();
        const auto generated = engine.generateStream(
            prompt, gen,
            [&](int32_t, const std::string& piece) -> bool {
                text += piece;
                return text.find("<|im_end|>") == std::string::npos;
            });

        receipt.generatedTokens += generated.generatedTokens;
        receipt.modelInference = receipt.modelInference || generated.generatedTokens > 0 || !text.empty();
        if (text.empty()) {
            receipt.failStage = "INFERENCE";
            receipt.failMessage = "model returned empty output";
            break;
        }

        Reply reply = parseReply(text);
        if (reply.protocolError) {
            receipt.failStage = "PROTOCOL";
            receipt.failMessage = "malformed model tool protocol: " + text.substr(0, 512);
            break;
        }
        if (!reply.tool) {
            receipt.reachedFinal = true;
            receipt.finalText = reply.finalText;
            if (!receipt.testPassed) {
                receipt.failStage = "EARLY_FINAL";
                receipt.failMessage = "model finalized before real read/edit/build/test completion";
            }
            break;
        }

        ++receipt.toolCalls;
        if (receipt.firstTool.empty()) receipt.firstTool = reply.toolName;

        ToolRequest request;
        request.run_id = 1;
        request.action_id = receipt.toolCalls;
        request.surface = AgentToolSurface::AgentCore;
        request.tool_id = reply.toolName;
        request.stdin_text = reply.args;
        request.working_directory = options.workspaceRoot;

        ToolContext context;
        context.cancelled = [] { return false; };
        ToolResult tr = authority.invoke(request, context);

        if (tr.ok()) ++receipt.successfulToolCalls;
        else ++receipt.failedToolCalls;

        const std::string canon = AgentToolRegistry::canonicalId(reply.toolName);
        if (canon == AgentToolRegistry::canonicalId("agent.file.read") && tr.ok())
            receipt.fileRead = true;
        if ((canon == AgentToolRegistry::canonicalId("agent.file.write") ||
             canon == AgentToolRegistry::canonicalId("agent.file.replace")) && tr.ok())
            receipt.fileEdit = true;
        if (canon == AgentToolRegistry::canonicalId("agent.build")) {
            receipt.buildRan = tr.exit_code != 127;
            receipt.buildPassed = tr.ok() && tr.stdout_text.find("BUILD_PASS") != std::string::npos;
        }
        if (canon == AgentToolRegistry::canonicalId("agent.test")) {
            receipt.testRan = tr.exit_code != 127;
            receipt.childExitCode = tr.exit_code;
            receipt.testPassed = tr.ok() && tr.stdout_text.find("TEST_PASS") != std::string::npos &&
                                 tr.stdout_text.find("AGENTIC_E2E_OK") != std::string::npos;
        }

        history.push_back(Transaction{reply.toolName, reply.args, tr});
    }

    if (!receipt.reachedFinal && receipt.failStage.empty()) {
        receipt.failStage = "STEP_LIMIT";
        receipt.failMessage = "model did not reach final within maxSteps";
    }
    if (receipt.reachedFinal && !receipt.pass() && receipt.failStage.empty()) {
        receipt.failStage = "INCOMPLETE_CHAIN";
        receipt.failMessage = "one or more mandatory real-agent fields did not pass";
    }

    if (!options.keepFixture) {
        // Keep failed fixtures for diagnosis; only clean successful receipts.
        if (receipt.pass()) {
            std::filesystem::path gateDir;
            std::string err;
            if (resolveWorkspacePath(options.workspaceRoot, options.fixtureDir.generic_string(), gateDir, err)) {
                std::error_code ec;
                std::filesystem::remove_all(gateDir, ec);
            }
        }
    }

    return receipt;
}

std::string formatAgenticE2EReceipt(const AgenticE2EReceipt& r) {
    auto pf = [](bool v) { return v ? "PASS" : "FAIL"; };
    std::ostringstream o;
    o << "=== RAWRXD_WIN32IDE_AGENTIC_001 ===\n"
      << "IDE_LAUNCH=" << pf(r.ideLaunch) << "\n"
      << "COMMAND_DISPATCH=" << pf(r.commandDispatch) << "\n"
      << "REAL_MODEL_INFERENCE=" << pf(r.modelInference) << "\n"
      << "TOOL_AUTHORITY=" << pf(r.toolAuthority) << "\n"
      << "FILE_READ=" << pf(r.fileRead) << "\n"
      << "FILE_EDIT=" << pf(r.fileEdit) << "\n"
      << "BUILD_RAN=" << pf(r.buildRan) << "\n"
      << "BUILD_PASS=" << pf(r.buildPassed) << "\n"
      << "TEST_RAN=" << pf(r.testRan) << "\n"
      << "TEST_PASS=" << pf(r.testPassed) << "\n"
      << "TOOL_RESULT_IN_CONTEXT=" << pf(r.toolResultFedBack) << "\n"
      << "MODEL_FINAL=" << pf(r.reachedFinal) << "\n"
      << "STEPS=" << r.steps << "\n"
      << "TOOL_CALLS=" << r.toolCalls << "\n"
      << "SUCCESSFUL_TOOL_CALLS=" << r.successfulToolCalls << "\n"
      << "FAILED_TOOL_CALLS=" << r.failedToolCalls << "\n"
      << "GENERATED_TOKEN_COUNT=" << r.generatedTokens << "\n"
      << "CHILD_EXIT_CODE=" << r.childExitCode << "\n"
      << "SYNTHETIC_TOKEN_OUTPUT=" << (r.syntheticTokenOutput ? 1 : 0) << "\n"
      << "STUB_FALLBACKS=" << r.stubFallbacks << "\n";
    if (!r.firstTool.empty()) o << "FIRST_TOOL=" << r.firstTool << "\n";
    if (!r.failStage.empty()) o << "FAIL_STAGE=" << r.failStage << "\n";
    if (!r.failMessage.empty()) o << "FAIL_MESSAGE=" << r.failMessage << "\n";
    o << "VERDICT=" << (r.pass() ? "PASS" : "FAIL") << "\n";
    return o.str();
}

} // namespace rawrxd::agentic_e2e
