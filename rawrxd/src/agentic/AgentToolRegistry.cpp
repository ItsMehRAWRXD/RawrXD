// ============================================================================
// AgentToolRegistry.cpp — RAWRXD_AGENTIC_TOOL_REGISTRY_001
// ============================================================================
#include "agentic/AgentToolRegistry.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <sstream>

#include "agentic/CommandExecutor.h"

namespace rawrxd {
namespace agentic {
namespace {

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    const int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return std::string();
    std::string out(static_cast<std::size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &out[0], needed,
                        nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                           nullptr, 0);
    if (needed <= 0) return std::wstring();
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &out[0], needed);
    return out;
}

std::string LastErrorText(const std::string& prefix) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%lu", static_cast<unsigned long>(GetLastError()));
    return prefix + " (win32=" + buf + ")";
}

// Joins `root` and `leaf` then canonicalises, rejecting traversal by requiring
// the canonical result to still live under the canonical root.
bool ResolveUnderRoot(const std::string& root, const std::string& leaf, std::wstring& outWide,
                      std::string& outError) {
    if (root.empty() || leaf.empty()) {
        outError = "empty path component";
        return false;
    }
    if (leaf.find('\0') != std::string::npos) {
        outError = "path contains NUL";
        return false;
    }
    // Reject UNC and device paths outright.
    if (leaf.size() >= 2 && leaf[0] == '\\' && leaf[1] == '\\') {
        outError = "UNC paths are not permitted";
        return false;
    }

    std::wstring rootWide = Utf8ToWide(root);
    if (rootWide.empty() || rootWide.back() != L'\\') rootWide.push_back(L'\\');

    const std::size_t colon = leaf.find(':');
    if (colon != std::string::npos) {
        const std::string scheme = leaf.substr(0, colon);
        const bool drive = (scheme.size() == 2 && std::isalpha(static_cast<unsigned char>(scheme[0])) &&
                            scheme[1] == '\\');
        if (!drive) {
            outError = "device, stream and non-drive schemes are not permitted";
            return false;
        }
    }

    const std::wstring full = rootWide + Utf8ToWide(leaf);

    // GetFullPathNameW normalises "." and ".." without touching the filesystem.
    DWORD needed = GetFullPathNameW(full.c_str(), 0, nullptr, nullptr);
    if (needed == 0) {
        outError = LastErrorText("GetFullPathNameW failed");
        return false;
    }
    std::wstring canonical(needed, L'\0');
    const DWORD written = GetFullPathNameW(full.c_str(), needed, &canonical[0], nullptr);
    if (written == 0 || written >= needed) {
        outError = LastErrorText("GetFullPathNameW failed");
        return false;
    }
    canonical.resize(written);
    if (canonical.size() < rootWide.size() ||
        ::CompareStringOrdinal(canonical.c_str(), static_cast<int>(rootWide.size()),
                               rootWide.c_str(), static_cast<int>(rootWide.size()), TRUE) !=
            CSTR_EQUAL) {
        outError = "resolved path escapes the allowed root";
        return false;
    }
    outWide = canonical;
    return true;
}

} // namespace

ToolPolicy ToolPolicy::DefaultDenyAll() {
    ToolPolicy p;
    p.allowedRoots.clear();
    p.allowWrite = false;
    p.allowExecute = false;
    return p;
}

bool IsPathAllowed(const ToolPolicy& policy, const std::string& candidate,
                   std::string& outCanonical) {
    outCanonical.clear();
    if (policy.allowedRoots.empty()) {
        return false;
    }
    for (const auto& root : policy.allowedRoots) {
        std::wstring wide;
        std::string error;
        if (ResolveUnderRoot(root, candidate, wide, error)) {
            outCanonical = WideToUtf8(wide);
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------

ToolRegistry& ToolRegistry::Instance() {
    static ToolRegistry inst;
    return inst;
}

void ToolRegistry::Register(const ToolDef& def, ToolExecutor exec) {
    if (def.name.empty() || !exec) return;
    std::lock_guard<std::mutex> lk(mtx_);
    defs_[def.name] = def;
    executors_[def.name] = std::move(exec);
}

bool ToolRegistry::Unregister(const std::string& name) {
    std::lock_guard<std::mutex> lk(mtx_);
    executors_.erase(name);
    return defs_.erase(name) > 0;
}

ToolResult ToolRegistry::Execute(const std::string& name,
                                 const std::unordered_map<std::string, std::string>& params) {
    ToolExecutor executor;
    ToolPolicy policy;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const auto it = executors_.find(name);
        if (it == executors_.end()) {
            ToolResult r;
            r.success = false;
            r.error = "tool not found: " + name;
            return r;
        }
        // Copy out, then run unlocked. A non-recursive mutex held across the
        // call would deadlock any executor that calls back into this registry.
        executor = it->second;
        policy = policy_;
    }

    const ULONGLONG start = GetTickCount64();
    ToolResult result = executor(params);
    result.elapsedMicros = (GetTickCount64() - start) * 1000ULL;
    CapOutput(result, policy);
    return result;
}

void ToolRegistry::CapOutput(ToolResult& result, const ToolPolicy& policy) {
    const std::size_t cap = policy.maxOutputBytes;
    if (cap == 0) return;
    if (result.output.size() > cap) {
        result.outputBytesTruncated = static_cast<std::uint32_t>(result.output.size() - cap);
        result.output.resize(cap);
        result.output += "\n...[truncated]";
    }
    if (result.error.size() > 4096) {
        result.error.resize(4096);
        result.error += "...[truncated]";
    }
}

std::string ToolRegistry::BuildSystemPrompt() const {
    std::vector<ToolDef> snapshot;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        snapshot.reserve(defs_.size());
        for (const auto& kv : defs_) snapshot.push_back(kv.second);
    }
    // Deterministic order: the prompt must not depend on unordered_map layout,
    // otherwise the same conversation produces different token streams.
    std::sort(snapshot.begin(), snapshot.end(),
              [](const ToolDef& a, const ToolDef& b) { return a.name < b.name; });

    std::ostringstream oss;
    oss << "You have access to these tools.\n"
        << "To call exactly one tool, emit a single block in this format and then stop:\n"
        << "  " << "<<<TOOL:tool_name|{\"param\":\"value\"}>>>\n"
        << "Rules:\n"
        << "  - Emit at most one tool block per reply, then stop and wait for the result.\n"
        << "  - Use only tool names listed below.\n"
        << "  - Values are JSON strings; escape quotes and backslashes.\n\n";
    for (const auto& def : snapshot) {
        oss << "Tool: " << def.name << "\n" << def.description << "\n";
        if (!def.params.empty()) {
            oss << "Params:\n";
            for (const auto& p : def.params) {
                oss << "  " << p.name << " (" << p.type << ")"
                    << (p.required ? " [required]" : " [optional]") << ": " << p.description
                    << "\n";
            }
        }
        oss << "\n";
    }
    return oss.str();
}

std::vector<std::string> ToolRegistry::GetToolNames() const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::vector<std::string> names;
    names.reserve(defs_.size());
    for (const auto& kv : defs_) names.push_back(kv.first);
    std::sort(names.begin(), names.end());
    return names;
}

bool ToolRegistry::HasTool(const std::string& name) const {
    std::lock_guard<std::mutex> lk(mtx_);
    return executors_.find(name) != executors_.end();
}

std::size_t ToolRegistry::Size() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return defs_.size();
}

void ToolRegistry::SetPolicy(const ToolPolicy& policy) { policy_ = policy; }

ToolPolicy ToolRegistry::GetPolicy() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return policy_;
}

// ---------------------------------------------------------------------------
// Built-in tools
// ---------------------------------------------------------------------------

void ToolRegistry::InstallBuiltinTools() {
    Register({"read_file", "Read a UTF-8 or binary file and return its contents.",
              {{"path", "string", "File path relative to an allowed root.", true}}},
             [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                 // Read the live policy rather than a copy captured at
                 // registration time. Safe: Execute releases the registry lock
                 // before invoking any executor, so this cannot self-deadlock.
                 const ToolPolicy policy = ToolRegistry::Instance().GetPolicy();
                 ToolResult r;
                 const auto it = p.find("path");
                 if (it == p.end()) {
                     r.error = "missing required parameter: path";
                     return r;
                 }
                 std::string canonical;
                 if (!IsPathAllowed(policy, it->second, canonical)) {
                     r.error = "path rejected by sandbox: " + it->second;
                     return r;
                 }
                 const std::wstring wide = Utf8ToWide(canonical);
                 HANDLE h = CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                 if (h == INVALID_HANDLE_VALUE) {
                     r.error = LastErrorText("cannot open " + canonical);
                     return r;
                 }
                 LARGE_INTEGER size{};
                 if (!GetFileSizeEx(h, &size) || size.QuadPart < 0) {
                     CloseHandle(h);
                     r.error = LastErrorText("GetFileSizeEx failed");
                     return r;
                 }
                 const std::size_t want =
                     static_cast<std::size_t>(size.QuadPart) > policy.maxFileReadBytes
                         ? policy.maxFileReadBytes
                         : static_cast<std::size_t>(size.QuadPart);
                 r.output.assign(want, '\0');
                 DWORD read = 0;
                 const BOOL ok = (want == 0) ? TRUE
                                            : ReadFile(h, &r.output[0], static_cast<DWORD>(want),
                                                       &read, nullptr);
                 CloseHandle(h);
                 if (!ok) {
                     r.output.clear();
                     r.error = LastErrorText("ReadFile failed");
                     return r;
                 }
                 r.output.resize(read);
                 if (static_cast<std::size_t>(size.QuadPart) > want) {
                     r.outputBytesTruncated =
                         static_cast<std::uint32_t>(static_cast<std::size_t>(size.QuadPart) - want);
                     r.output += "\n...[truncated]";
                 }
                 r.success = true;
                 return r;
             });

    Register({"list_directory", "List entries in a directory.",
              {{"path", "string", "Directory path relative to an allowed root.", true}}},
             [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                 const ToolPolicy policy = ToolRegistry::Instance().GetPolicy();
                 ToolResult r;
                 const auto it = p.find("path");
                 if (it == p.end()) {
                     r.error = "missing required parameter: path";
                     return r;
                 }
                 std::string canonical;
                 if (!IsPathAllowed(policy, it->second, canonical)) {
                     r.error = "path rejected by sandbox: " + it->second;
                     return r;
                 }
                 const std::wstring pattern = Utf8ToWide(canonical) + L"\\*";
                 WIN32_FIND_DATAW fd{};
                 HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
                 if (h == INVALID_HANDLE_VALUE) {
                     const DWORD err = GetLastError();
                     if (err == ERROR_FILE_NOT_FOUND) {
                         r.success = true;  // empty directory is not an error
                         return r;
                     }
                     r.error = LastErrorText("FindFirstFileW failed");
                     return r;
                 }
                 std::ostringstream oss;
                 do {
                     const bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                     oss << WideToUtf8(fd.cFileName) << (isDir ? "/\n" : "\n");
                 } while (FindNextFileW(h, &fd));
                 FindClose(h);
                 r.output = oss.str();
                 r.success = true;
                 return r;
             });

    Register({"search_code", "Search a file for a literal substring and return matching lines.",
              {{"path", "string", "File to search.", true},
               {"pattern", "string", "Literal substring to find.", true},
               {"max_matches", "string", "Optional cap on returned matches.", false}}},
             [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                 const ToolPolicy policy = ToolRegistry::Instance().GetPolicy();
                 ToolResult r;
                 const auto pathIt = p.find("path");
                 const auto patIt = p.find("pattern");
                 if (pathIt == p.end() || patIt == p.end()) {
                     r.error = "missing required parameter: path and pattern";
                     return r;
                 }
                 if (patIt->second.empty()) {
                     r.error = "pattern must not be empty";
                     return r;
                 }
                 // Re-implement the scan locally rather than calling Execute on
                 // read_file, so this tool has no dependency on registry state.
                 std::string canonical;
                 if (!IsPathAllowed(policy, pathIt->second, canonical)) {
                     r.error = "path rejected by sandbox: " + pathIt->second;
                     return r;
                 }
                 const std::wstring wide = Utf8ToWide(canonical);
                 HANDLE h = CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                 if (h == INVALID_HANDLE_VALUE) {
                     r.error = LastErrorText("cannot open " + canonical);
                     return r;
                 }
                 LARGE_INTEGER size{};
                 if (!GetFileSizeEx(h, &size) || size.QuadPart < 0 ||
                     static_cast<std::size_t>(size.QuadPart) > policy.maxSearchFileBytes) {
                     CloseHandle(h);
                     r.error = "file too large or size query failed";
                     return r;
                 }
                 std::string content(static_cast<std::size_t>(size.QuadPart), '\0');
                 DWORD read = 0;
                 const BOOL ok = content.empty()
                                     ? TRUE
                                     : ReadFile(h, &content[0], static_cast<DWORD>(content.size()),
                                                &read, nullptr);
                 CloseHandle(h);
                 if (!ok) {
                     r.error = LastErrorText("ReadFile failed");
                     return r;
                 }
                 content.resize(read);

                 std::uint32_t cap = policy.maxSearchMatches;
                 const auto capIt = p.find("max_matches");
                 if (capIt != p.end() && !capIt->second.empty()) {
                     char* end = nullptr;
                     const unsigned long parsed = std::strtoul(capIt->second.c_str(), &end, 10);
                     if (end != capIt->second.c_str() && parsed > 0) {
                         cap = static_cast<std::uint32_t>(parsed);
                     }
                 }

                 std::ostringstream oss;
                 std::istringstream iss(content);
                 std::string line;
                 unsigned long lineNo = 0;
                 std::uint32_t emitted = 0;
                 while (std::getline(iss, line)) {
                     ++lineNo;
                     if (line.find(patIt->second) == std::string::npos) continue;
                     if (emitted >= cap) {
                         oss << "...[match cap reached]\n";
                         break;
                     }
                     oss << lineNo << ": " << line << "\n";
                     ++emitted;
                 }
                 r.output = oss.str();
                 r.success = true;
                 return r;
             });

    Register({"write_file", "Create or overwrite a file with text content.",
              {{"path", "string", "File path relative to an allowed root.", true},
               {"content", "string", "Full file content to write.", true}}},
             [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                 const ToolPolicy policy = ToolRegistry::Instance().GetPolicy();
                 ToolResult r;
                 if (!policy.allowWrite) {
                     r.error = "write_file is disabled by the active tool policy";
                     return r;
                 }
                 const auto pathIt = p.find("path");
                 const auto contentIt = p.find("content");
                 if (pathIt == p.end() || contentIt == p.end()) {
                     r.error = "missing required parameter: path and content";
                     return r;
                 }
                 std::string canonical;
                 if (!IsPathAllowed(policy, pathIt->second, canonical)) {
                     r.error = "path rejected by sandbox: " + pathIt->second;
                     return r;
                 }
                 const std::wstring wide = Utf8ToWide(canonical);
                 HANDLE h = CreateFileW(wide.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                        FILE_ATTRIBUTE_NORMAL, nullptr);
                 if (h == INVALID_HANDLE_VALUE) {
                     r.error = LastErrorText("cannot create " + canonical);
                     return r;
                 }
                 const std::string& content = contentIt->second;
                 DWORD written = 0;
                 BOOL ok = TRUE;
                 if (!content.empty()) {
                     ok = WriteFile(h, content.data(), static_cast<DWORD>(content.size()),
                                    &written, nullptr);
                 }
                 CloseHandle(h);
                 if (!ok) {
                     r.error = LastErrorText("WriteFile failed");
                     return r;
                 }
                 r.output = "wrote " + std::to_string(written) + " bytes to " + canonical;
                 r.success = true;
                 return r;
             });

    Register({"execute_command",
              "Run a console command and capture its output. Disabled unless the tool "
              "policy enables execution.",
              {{"command", "string", "Command line to run.", true},
               {"cwd", "string", "Optional working directory under an allowed root.", false},
               {"timeout_ms", "string", "Optional timeout override in milliseconds.", false}}},
             [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                 const ToolPolicy policy = ToolRegistry::Instance().GetPolicy();
                 ToolResult r;
                 if (!policy.allowExecute) {
                     r.error = "execute_command is disabled by the active tool policy";
                     return r;
                 }
                 const auto cmdIt = p.find("command");
                 if (cmdIt == p.end() || cmdIt->second.empty()) {
                     r.error = "missing required parameter: command";
                     return r;
                 }
                 std::wstring workingDir;
                 const auto cwdIt = p.find("cwd");
                 if (cwdIt != p.end() && !cwdIt->second.empty()) {
                     std::string canonical;
                     if (!IsPathAllowed(policy, cwdIt->second, canonical)) {
                         r.error = "cwd rejected by sandbox: " + cwdIt->second;
                         return r;
                     }
                     workingDir = Utf8ToWide(canonical);
                 }
                 DWORD timeout = policy.executeTimeoutMs;
                 const auto timeoutIt = p.find("timeout_ms");
                 if (timeoutIt != p.end() && !timeoutIt->second.empty()) {
                     char* end = nullptr;
                     const unsigned long parsed =
                         std::strtoul(timeoutIt->second.c_str(), &end, 10);
                     if (end != timeoutIt->second.c_str() && parsed > 0) {
                         timeout = static_cast<DWORD>(parsed);
                     }
                 }
                 CommandExecutor::Options options;
                 options.workingDir = workingDir;
                 options.timeoutMs = timeout;
                 options.allowShell = true;  // explicit model-requested console command
                 const CommandExecutor::Result result =
                     CommandExecutor::Run(cmdIt->second, options);
                 r.success = result.success;
                 r.output = result.stdoutText;
                 r.error = result.stderrText;
                 if (!result.error.empty()) {
                     if (!r.error.empty()) r.error += " | ";
                     r.error += result.error;
                 }
                 return r;
             });
}

} // namespace agentic
} // namespace rawrxd
