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
#include "agentic/CheckpointRollbackAuthority.h"

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

// RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001
// A path that starts with a drive ("C:\dir\file") is already absolute: joining
// it to the root produces "F:\ws\C:\dir\file", which is not under the root by
// any reading. It must be canonicalised on its own and then held to the same
// containment check, so an absolute in-root path works and an absolute
// out-of-root path is refused BY THE SANDBOX rather than by the filesystem
// happening to reject the nonsense name later.
bool IsAbsoluteDrivePath(const std::string& s) {
    if (s.size() < 3 || s[1] != ':') return false;
    if (!std::isalpha(static_cast<unsigned char>(s[0]))) return false;
    return s[2] == '\\' || s[2] == '/';
}

// A colon anywhere else -- "file:", "\\\\.\\pipe:", "name:stream", "http://" --
// is a device, stream or URL scheme and is refused outright.
//
// The previous test read the two characters BEFORE the colon and demanded
// scheme[1] == '\\', which no well-formed path can satisfy: for "F:\dir" the
// colon is at index 1, so scheme is the single character "F" and the size test
// fails; for "AB:\dir" scheme is "AB" and scheme[1] is 'B'. The effect was that
// EVERY absolute Windows path was rejected as a "device, stream or non-drive
// scheme". It stayed invisible while the only caller passed root-relative
// candidates, and it broke the moment the transactional write profile had to
// canonicalise an absolute RAWRXD_TOOL_ROOT, refusing every tool with "path
// rejected by sandbox".
bool HasNonDriveColon(const std::string& s) {
    const std::size_t colon = s.find(':');
    return colon != std::string::npos && !IsAbsoluteDrivePath(s);
}

// Rejects a canonical path that reaches its target through a reparse point.
//
// GetFullPathNameW normalises LEXICALLY. It does not follow junctions, symlinks
// or mount points, so "F:\ws\link\a.txt" canonicalises to itself, satisfies the
// prefix test against the root "F:\ws", and then opens whatever "link" points
// at -- which can be anywhere on any drive, including a path the policy never
// authorised. That is a read escape today and a WRITE escape the moment
// write_file is enabled, so it is checked here, once, for every tool.
//
// The walk starts BELOW the root: a reparse point at the configured root itself
// is the operator's choice and is accepted. A component that does not exist yet
// is accepted (it is the file being created); a missing intermediate component
// is accepted too, because the open that follows will fail on its own.
bool CrossesReparsePoint(const std::wstring& canonical, const std::size_t fromOffset) {
    std::size_t i = fromOffset;
    while (i < canonical.size()) {
        while (i < canonical.size() && (canonical[i] == L'\\' || canonical[i] == L'/')) ++i;
        std::size_t end = i;
        while (end < canonical.size() && canonical[end] != L'\\' && canonical[end] != L'/') ++end;
        if (end > i) {
            std::wstring prefix(canonical.begin(), canonical.begin() + static_cast<long>(end));
            const DWORD attrs = ::GetFileAttributesW(prefix.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
                return true;
            }
        }
        i = end;
    }
    return false;
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

    if (HasNonDriveColon(leaf)) {
        outError = "device, stream and non-drive schemes are not permitted";
        return false;
    }

    const std::wstring full =
        IsAbsoluteDrivePath(leaf) ? Utf8ToWide(leaf) : (rootWide + Utf8ToWide(leaf));

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
    // Lexical containment is not containment on disk. A junction or symlink
    // below the root canonicalises to itself and then opens somewhere else.
    if (CrossesReparsePoint(canonical, rootWide.size())) {
        outError = "path crosses a reparse point (junction or link) inside the root";
        return false;
    }
    outWide = canonical;
    return true;
}

// RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001
// Containment test for two ALREADY-CANONICAL absolute paths. ResolveUnderRoot
// cannot be reused here: it joins root+leaf, and both sides of this comparison
// are absolute, so a join would produce "F:\ws\\F:\ws\a.txt".
//
// Fails closed on any mismatch (case-folded ordinal compare, separator
// required at the boundary) so "F:\workspace" cannot match
// "F:\workspace-other\a.txt".
bool IsUnderCanonicalRoot(const std::string& root, const std::string& candidate) {
    if (root.empty() || candidate.empty()) return false;
    std::string r = root;
    while (r.size() > 1 && (r.back() == '\\' || r.back() == '/')) r.pop_back();
    if (candidate.size() < r.size()) return false;
    // CompareStringOrdinal takes LPCWCH; these are narrow strings. _strnicmp is
    // the length-limited, case-folded ordinal compare this test means. The
    // previous CompareStringOrdinal(candidate.data(), ...) could not convert a
    // const char* to LPCWCH and failed to compile (C2664).
    if (_strnicmp(candidate.data(), r.data(), r.size()) != 0) {
        return false;
    }
    if (candidate.size() == r.size()) return true;
    const char sep = candidate[r.size()];
    return sep == '\\' || sep == '/';
}

// RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001
// Absolute, separator-normalised form of a path that may be relative, bare "."
// or carry redundant separators. No filesystem access: GetFullPathNameW
// normalises lexically, which is the same property the sandbox relies on.
bool CanonicalizeAbsolute(const std::string& path, std::wstring& outWide, std::string& outError) {
    if (path.empty()) {
        outError = "empty path";
        return false;
    }
    if (path.find('\0') != std::string::npos) {
        outError = "path contains NUL";
        return false;
    }
    if (path.size() >= 2 && path[0] == '\\' && path[1] == '\\') {
        outError = "UNC paths are not permitted";
        return false;
    }
    if (HasNonDriveColon(path)) {
        outError = "device, stream and non-drive schemes are not permitted";
        return false;
    }
    const std::wstring wide = Utf8ToWide(path);
    const DWORD needed = GetFullPathNameW(wide.c_str(), 0, nullptr, nullptr);
    if (needed == 0) {
        outError = LastErrorText("GetFullPathNameW failed");
        return false;
    }
    std::wstring canonical(needed, L'\0');
    const DWORD written = GetFullPathNameW(wide.c_str(), needed, &canonical[0], nullptr);
    if (written == 0 || written >= needed) {
        outError = LastErrorText("GetFullPathNameW failed");
        return false;
    }
    canonical.resize(written);
    // Keep "C:\" but drop every other trailing separator, so root+leaf never
    // produces a doubled separator and containment compares stay exact.
    while (canonical.size() > 3 && (canonical.back() == L'\\' || canonical.back() == L'/')) {
        canonical.pop_back();
    }
    outWide = canonical;
    return true;
}

} // namespace

// RAWRXD_GIT_TRANSACTION_AUTHORITY_001 / G4
//
// Declared in the public header, so defined OUTSIDE the anonymous namespace.
// Defining them inside it as well made every internal call ambiguous between
// the anonymous-namespace copy and the declared one.
bool IsTransactionRequired(const std::string& toolName, const ToolPolicy& policy) {
    for (const auto& n : policy.transactionRequiredTools) {
        if (n == toolName) return true;
    }
    return false;
}

// True when the tool's own NAME implies it mutates something. This is a
// cross-check on the policy list, not a substitute for it: a name that looks
// mutating and is absent from policy.transactionRequiredTools is a policy typo,
// and a typo in a security list is a silent hole. UncoveredMutatingTools()
// reports those so the hole is visible instead of merely inferred.
bool ToolNameLooksMutating(const std::string& toolName) {
    static const char* const kMutatingVerbs[] = {
        "stage",   "unstage",  "commit",  "branch",  "checkout", "stash",   "worktree",
        "rollback", "push",    "write",   "edit",    "delete",   "remove",  "apply",
        "revert",  "reset",    "merge",   "rebase",  "tag",      "rename",  "update"};
    std::string lower = toolName;
    for (char& c : lower) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    for (const char* verb : kMutatingVerbs) {
        const std::string v(verb);
        if (lower.find(v) != std::string::npos) return true;
    }
    return false;
}

std::vector<std::string> UncoveredMutatingTools(const ToolRegistry& registry,
                                               const ToolPolicy& policy) {
    std::vector<std::string> missing;
    for (const auto& name : registry.GetToolNames()) {
        if (ToolNameLooksMutating(name) && !IsTransactionRequired(name, policy)) {
            missing.push_back(name);
        }
    }
    return missing;
}

ToolPolicy ToolPolicy::DefaultDenyAll() {
    ToolPolicy p;
    p.allowedRoots.clear();
    p.allowWrite = false;
    p.allowExecute = false;
    return p;
}

bool IsPathAllowed(const ToolPolicy& policy, const std::string& candidate,
                   std::string& outCanonical, std::string* outError) {
    outCanonical.clear();
    if (outError) outError->clear();
    if (policy.allowedRoots.empty()) {
        if (outError) *outError = "the tool policy has no allowed root";
        return false;
    }
    for (const auto& root : policy.allowedRoots) {
        std::wstring wide;
        std::string error;
        if (ResolveUnderRoot(root, candidate, wide, error)) {
            outCanonical = WideToUtf8(wide);
            return true;
        }
        if (outError && outError->empty()) *outError = error;
    }
    return false;
}

bool CanonicalizeRoot(const std::string& path, std::string& outCanonical, std::string& outError) {
    outCanonical.clear();
    std::wstring wide;
    if (!CanonicalizeAbsolute(path, wide, outError)) return false;
    outCanonical = WideToUtf8(wide);
    return !outCanonical.empty();
}

bool IsCanonicalPathAllowed(const ToolPolicy& policy, const std::string& absPath) {
    if (policy.allowedRoots.empty() || absPath.empty()) return false;
    // Canonicalise the candidate too: a caller that passes "F:\ws\..\other"
    // must not pass a lexical prefix test that the tools themselves would fail.
    std::wstring wide;
    std::string error;
    if (!CanonicalizeAbsolute(absPath, wide, error)) return false;
    const std::string canonical = WideToUtf8(wide);
    for (const auto& root : policy.allowedRoots) {
        if (IsUnderCanonicalRoot(root, canonical)) return true;
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

    // RAWRXD_GIT_TRANSACTION_AUTHORITY_001 / G4
    //
    // write_file refuses to run without a checkpoint transaction, so every file
    // the agent writes is journalled and undoable. The git tools were not held
    // to that: with capability and scope both granted, `git_stage` moved the
    // index with NO transaction open and wrote ZERO journal records. Measured,
    // not hypothesised -- see the gate receipt.
    //
    // The promise a write profile makes is about MUTATION, not about which
    // function performs it. A gate that only covers write_file leaves the same
    // hole open through any other registered tool that changes state, so this
    // gate sits at the one point every tool passes through.
    //
    // The set of gated tools is a policy list rather than hardcoded names,
    // because a registry cannot infer which tool mutates: git_status and
    // git_stage have identical signatures. What the registry does enforce is
    // that the list cannot be quietly wrong -- see TransactionRequired() and the
    // coverage check beside it.
    if (policy.writeRequiresTransaction && IsTransactionRequired(name, policy) &&
        !ckpt::Transaction::Active()) {
        ToolResult r;
        r.error = name +
                  " requires an open checkpoint transaction; open one first "
                  "(POST /api/agent/transaction {\"op\":\"begin\"})";
        return r;
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

std::vector<ToolDef> ToolRegistry::GetDefs() const {
    std::vector<ToolDef> snapshot;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        snapshot.reserve(defs_.size());
        for (const auto& kv : defs_) snapshot.push_back(kv.second);
    }
    // Same name order as BuildSystemPrompt, so a prompt and the validation that
    // follows it are describing one list, not two.
    std::sort(snapshot.begin(), snapshot.end(),
              [](const ToolDef& a, const ToolDef& b) { return a.name < b.name; });
    return snapshot;
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
              {{"path", "string", "File path, root-relative or absolute; absolute paths must resolve inside an allowed root.", true}}},
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
                 std::string why;
                 if (!IsPathAllowed(policy, it->second, canonical, &why)) {
                     r.error = "path rejected by sandbox: " + it->second + " (" + why + ")";
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
              {{"path", "string", "Directory path, root-relative or absolute; absolute paths must resolve inside an allowed root.", true}}},
             [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                 const ToolPolicy policy = ToolRegistry::Instance().GetPolicy();
                 ToolResult r;
                 const auto it = p.find("path");
                 if (it == p.end()) {
                     r.error = "missing required parameter: path";
                     return r;
                 }
                 std::string canonical;
                 std::string why;
                 if (!IsPathAllowed(policy, it->second, canonical, &why)) {
                     r.error = "path rejected by sandbox: " + it->second + " (" + why + ")";
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
                  std::string why;
                  if (!IsPathAllowed(policy, pathIt->second, canonical, &why)) {
                      r.error = "path rejected by sandbox: " + pathIt->second + " (" + why + ")";
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
              {{"path", "string", "File path, root-relative or absolute; absolute paths must resolve inside an allowed root.", true},
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
                  std::string why;
                  if (!IsPathAllowed(policy, pathIt->second, canonical, &why)) {
                      r.error = "path rejected by sandbox: " + pathIt->second + " (" + why + ")";
                      return r;
                  }
                  // RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001
                  // Three refusals, in order, before a single byte is written.
                  // Each closes a way for an edit to escape the rollback that is
                  // the only reason an autonomous edit is allowed here.
                  if (policy.writeRequiresTransaction) {
                      if (!ckpt::Transaction::Active()) {
                          r.error =
                              "write_file requires an open checkpoint transaction; open one "
                              "first (POST /api/agent/transaction {\"op\":\"begin\"})";
                          return r;
                      }
                      const std::string txRoot = ckpt::Transaction::ActiveWorkspaceRoot();
                      if (!IsUnderCanonicalRoot(txRoot, canonical)) {
                          r.error = "path is outside the active transaction workspace: " +
                                    canonical;
                          return r;
                      }
                      // The journal and the content-addressed before-state blobs
                      // live under <root>\.rawrxd\ckpt. An agent that can write
                      // there can erase the record of its own edit, which turns a
                      // recoverable transaction into an unrecoverable one.
                      if (IsUnderCanonicalRoot(txRoot + "\\.rawrxd", canonical)) {
                          r.error =
                              "write refused: the checkpoint tree is not writable by the "
                              "agent: " + canonical;
                          return r;
                      }
                  }
// RAWRXD_IDE_CHECKPOINT_ROLLBACK_AUTHORITY_001
                  // This used to be CreateFileW(CREATE_ALWAYS) + WriteFile,
                  // which truncates the target before a byte is written, with no
                  // flush, no backup and no record. A crash mid-write left a
                  // truncated source file and nothing that could undo it.
                  // The authority publishes through a temp file plus an atomic
                  // rename and, when a transaction is open, journals the
                  // before-state, the write and the after-state.
                  const ULONGLONG startedAt = GetTickCount64();
                  std::string writeError;
                  if (!ckpt::Transaction::WriteFile(canonical, contentIt->second, &writeError)) {
                      r.error = writeError;
                      return r;
                  }
                  const ULONGLONG elapsed = (GetTickCount64() - startedAt) * 1000ULL;
                  r.elapsedMicros = elapsed;
                  r.output = "wrote " + std::to_string(contentIt->second.size()) +
                             " bytes to " + canonical;
                  r.success = true;
                  ckpt::Transaction::RecordToolResult(
                      "write_file",
                      "path=" + canonical + "|contentSha=" + ckpt::sha256Hex(contentIt->second),
                      true, r.output, std::string(), elapsed);
                  return r;
              });

    Register({"execute_command",
              "Run a console command and capture its output. Disabled unless the tool "
              "policy enables execution.",
              {{"command", "string", "Command line to run.", true},
               {"cwd", "string", "Optional working directory, root-relative or absolute; absolute paths must resolve inside an allowed root.", false},
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
                      std::string why;
                      if (!IsPathAllowed(policy, cwdIt->second, canonical, &why)) {
                          r.error = "cwd rejected by sandbox: " + cwdIt->second + " (" + why + ")";
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
                  // RAWRXD_IDE_CHECKPOINT_ROLLBACK_AUTHORITY_001
                  // A command's stdout is frequently the only durable record of
                  // what the agent ran (a build, a test, a migration). Without
                  // this, a crashed transaction loses the commands entirely.
                  ckpt::Transaction::RecordCommand(cmdIt->second,
                                                   static_cast<int>(result.exitCode),
                                                   result.stdoutText, result.stderrText,
                                                   result.elapsedMicros);
                  ckpt::Transaction::RecordToolResult("execute_command",
                                                      "command=" + cmdIt->second + "|cwd=" +
                                                          (cwdIt != p.end() ? cwdIt->second
                                                                            : std::string()),
                                                      r.success, r.output, r.error,
                                                      result.elapsedMicros);
                  return r;
              });
}

} // namespace agentic
} // namespace rawrxd
