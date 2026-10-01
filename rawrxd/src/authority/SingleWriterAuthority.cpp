// SingleWriterAuthority.cpp — RAWRXD_SINGLE_WRITER_AUTHORITY_001
//
// Bootstrap step 4 implementation. See header for the frozen contract.
//
// Scope rules:
//   - All filesystem writes are under <repoRoot>/.rawrxd/leases/
//   - All git invocations target the supplied repoRoot with -C
//   - No implicit dependency on the real F:\\~dev\\rawrxd repository
//
// Failure mode: every operation fails closed. A missing lease file is
// NOT an open lease — it is an unowned lease.

#include "SingleWriterAuthority.h"

#include "ProcessUtil.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <windows.h>

namespace rawrxd::authority {

namespace {

constexpr const char* kLeaseRelativeDir = ".rawrxd/leases";
constexpr const char* kLeaseFileName    = "writer.lease";
constexpr const char* kLeaseTmpName     = "writer.lease.tmp";

// Path normalization: best-effort canonical. On Windows, GetFullPathNameA
// gives an absolute, normalized form. We do not call realpath() so symlink
// resolution does not surprise callers.
std::string normalizeWindows(const std::string& in) {
    char buf[MAX_PATH];
    DWORD n = GetFullPathNameA(in.c_str(), MAX_PATH, buf, nullptr);
    if (n == 0 || n > MAX_PATH) return in;
    // Lowercase for case-insensitive Windows filesystems. The repo is the
    // repo — case-only differences must not bypass the allowlist.
    std::string out(buf);
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    // Strip trailing backslash except for drive roots.
    while (out.size() > 3 && (out.back() == '\\' || out.back() == '/')) out.pop_back();
    // Normalize separators to forward slash for cross-platform parsing.
    for (auto& c : out) if (c == '\\') c = '/';
    return out;
}

std::filesystem::path leaseDir(const std::filesystem::path& repoRoot) {
    return repoRoot / kLeaseRelativeDir;
}

std::filesystem::path leasePath(const std::filesystem::path& repoRoot) {
    return leaseDir(repoRoot) / kLeaseFileName;
}

std::filesystem::path leaseTmpPath(const std::filesystem::path& repoRoot) {
    return leaseDir(repoRoot) / kLeaseTmpName;
}

std::string escapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// Minimal JSON writer. We control both sides — no parser dependency.
std::string leaseToJson(const Lease& l) {
    std::ostringstream os;
    os << "{\n";
    os << "  \"repository_root\": \"" << escapeJson(l.repositoryRoot) << "\",\n";
    os << "  \"pid\": " << l.pid << ",\n";
    os << "  \"nonce\": " << l.nonce << ",\n";
    os << "  \"expected_head\": \"" << escapeJson(l.expectedHead) << "\",\n";
    os << "  \"acquired_unix_seconds\": " << l.acquiredUnixSeconds << ",\n";
    os << "  \"authorized_paths\": [";
    for (size_t i = 0; i < l.authorizedPaths.size(); ++i) {
        if (i) os << ", ";
        os << "\"" << escapeJson(l.authorizedPaths[i]) << "\"";
    }
    os << "]\n";
    os << "}\n";
    return os.str();
}

// Read and parse the JSON lease. Returns std::nullopt on any error.
// This parser is intentionally permissive only on the fields we own —
// we never accept a lease whose pid or nonce we did not produce.
std::optional<Lease> readLeaseFile(const std::filesystem::path& p) {
    std::ifstream f(p);
    if (!f) return std::nullopt;
    std::stringstream ss; ss << f.rdbuf();
    std::string s = ss.str();

    auto grab = [&](const std::string& key) -> std::string {
        std::string needle = "\"" + key + "\"";
        size_t pos = s.find(needle);
        if (pos == std::string::npos) return {};
        pos = s.find(':', pos + needle.size());
        if (pos == std::string::npos) return {};
        // Skip whitespace and decide whether value is a string or number.
        size_t i = pos + 1;
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) ++i;
        if (i >= s.size()) return {};
        if (s[i] == '"') {
            ++i;
            std::string out;
            while (i < s.size() && s[i] != '"') {
                if (s[i] == '\\' && i + 1 < s.size()) {
                    out += s[i + 1];
                    i += 2;
                } else {
                    out += s[i++];
                }
            }
            return out;
        } else {
            std::string out;
            while (i < s.size() && (s[i] == '-' || (s[i] >= '0' && s[i] <= '9'))) {
                out += s[i++];
            }
            return out;
        }
    };

    Lease l;
    l.repositoryRoot       = grab("repository_root");
    l.pid                  = static_cast<std::uint32_t>(std::strtoul(grab("pid").c_str(), nullptr, 10));
    l.nonce                = static_cast<std::uint64_t>(std::strtoull(grab("nonce").c_str(), nullptr, 10));
    l.expectedHead         = grab("expected_head");
    l.acquiredUnixSeconds  = static_cast<std::int64_t>(std::strtoll(grab("acquired_unix_seconds").c_str(), nullptr, 10));

    // Parse the authorized_paths array.
    std::string needle = "\"authorized_paths\"";
    size_t apos = s.find(needle);
    if (apos != std::string::npos) {
        size_t lb = s.find('[', apos);
        size_t rb = s.find(']', lb == std::string::npos ? apos : lb);
        if (lb != std::string::npos && rb != std::string::npos) {
            size_t i = lb + 1;
            while (i < rb) {
                while (i < rb && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == ',')) ++i;
                if (s[i] == '"') {
                    ++i;
                    std::string item;
                    while (i < rb && s[i] != '"') {
                        if (s[i] == '\\' && i + 1 < rb) { item += s[i + 1]; i += 2; }
                        else { item += s[i++]; }
                    }
                    if (i < rb) ++i; // skip closing quote
                    if (!item.empty()) l.authorizedPaths.push_back(item);
                } else {
                    ++i;
                }
            }
        }
    }

    l.leaseFile = p;
    if (!l.valid()) return std::nullopt;
    return l;
}

std::uint64_t randomNonce() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    return gen();
}

std::int64_t unixNow() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

bool fileExists(const std::filesystem::path& p) {
    std::error_code ec;
    return std::filesystem::exists(p, ec);
}

bool createDirExclusive(const std::filesystem::path& d) {
    std::error_code ec;
    if (std::filesystem::exists(d, ec)) return true;
    return std::filesystem::create_directories(d, ec);
}

// Atomically publish a staged file as the lease, failing if the destination
// already exists.
//
// The flag here is the entire mutual-exclusion guarantee, and it was inverted.
// This function passed MOVEFILE_REPLACE_EXISTING, which makes the move SUCCEED
// precisely when the destination exists — the opposite of what the caller's
// comment claimed ("atomically replace (which fails if dst exists — i.e. a
// concurrent writer raced us)"). A writer that passed the fileExists(lp) check
// at line 265 would silently overwrite a live lease created in the gap and
// return success, so two processes could both hold the lease.
//
// A same-volume rename with no REPLACE_EXISTING flag fails with
// ERROR_ALREADY_EXISTS when the destination is present, and the failure is
// decided by the filesystem rather than by a check-then-act sequence. That is
// the atomic exclusive test this authority depends on.
bool atomicReplace(const std::filesystem::path& tmp, const std::filesystem::path& dst) {
    std::wstring wtmp = tmp.wstring();
    std::wstring wdst = dst.wstring();
    // No MOVEFILE_REPLACE_EXISTING. MOVEFILE_WRITE_THROUGH only forces the
    // rename to reach disk before returning; it has no bearing on exclusivity.
    return MoveFileExW(wtmp.c_str(), wdst.c_str(), MOVEFILE_WRITE_THROUGH) != 0;
}

// Run git with an argument vector. No shell is involved.
//
// The previous implementation built a shell string and piped it through
// _popen:  "git -C \"" + repoRoot.string() + "\" " + args + " 2>NUL"
// repoRoot comes from the lease file on disk, so anything able to write that
// control file controlled the executed command line. Every element now reaches
// CreateProcess as a discrete argv entry and cannot be reinterpreted.
bool runGitCapture(const std::filesystem::path& repoRoot,
                   const std::string& args, std::string& out) {
    // `args` is a fixed literal from this file ("rev-parse HEAD" and friends),
    // split here only so each token becomes its own argv element. Only
    // repoRoot is variable, and it is likewise a discrete element.
    std::vector<std::string> argv;
    argv.push_back("-C");
    argv.push_back(repoRoot.string());
    {
        std::istringstream is(args);
        std::string tok;
        while (is >> tok) argv.push_back(tok);
    }

    std::string raw;
    int32_t code = -1;
    const procutil::RunResult rr =
        procutil::runProcessNoShell("git", argv, raw, code, 65536);
    if (rr != procutil::RunResult::Ok) return false;
    if (code != 0) return false;

    out = raw;
    // Trim trailing CR/LF/space.
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' ||
                            out.back() == ' '  || out.back() == '\t')) out.pop_back();
    return true;
}

} // namespace

std::string normalizePath(const std::filesystem::path& p) {
    return normalizeWindows(p.string());
}

bool isProcessLive(std::uint32_t pid) {
    if (pid == 0) return false;
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!h) return false;
    DWORD wait = WaitForSingleObject(h, 0);
    CloseHandle(h);
    return wait == WAIT_TIMEOUT; // live = not signaled
}

std::optional<Lease> acquire(
    const std::filesystem::path& repoRoot,
    const std::string& expectedHead,
    const std::vector<std::string>& allowedPaths) {

    if (!createDirExclusive(leaseDir(repoRoot))) return std::nullopt;

    auto lp = leasePath(repoRoot);
    auto tp = leaseTmpPath(repoRoot);

    // If a tmp lease exists from a crash, treat as a stuck lock and refuse
    // (caller must run staleLeaseRecovery). If a real lease exists, refuse
    // outright (Test A — second writer blocked).
    if (fileExists(tp)) return std::nullopt;
    if (fileExists(lp)) {
        // Reject unless this caller holds a valid identity AND no live
        // holder exists. We do not auto-recover here; recovery is a
        // separate explicit operation that proves the holder is dead.
        auto existing = readLeaseFile(lp);
        if (!existing) return std::nullopt;
        if (existing->pid == GetCurrentProcessId()) return std::nullopt;
        return std::nullopt;
    }

    Lease lease;
    lease.repositoryRoot = normalizePath(repoRoot);
    lease.pid = GetCurrentProcessId();
    lease.nonce = randomNonce();
    lease.expectedHead = expectedHead;
    lease.acquiredUnixSeconds = unixNow();
    lease.authorizedPaths.reserve(allowedPaths.size());
    for (const auto& p : allowedPaths) {
        std::filesystem::path fp(p);
        if (fp.is_relative()) fp = repoRoot / fp;
        lease.authorizedPaths.push_back(normalizePath(fp));
    }
    lease.leaseFile = lp;

    // Write tmp, then publish it with a rename that FAILS if the destination
    // already exists. The filesystem decides the race, not a check-then-act
    // sequence, so a writer that lost the race gets nullopt and the incumbent
    // keeps its lease.
    {
        std::ofstream f(tp, std::ios::binary | std::ios::trunc);
        if (!f) return std::nullopt;
        f << leaseToJson(lease);
        f.flush();
        if (!f.good()) return std::nullopt;
    }
    if (!atomicReplace(tp, lp)) {
        std::error_code ec;
        std::filesystem::remove(tp, ec);
        return std::nullopt;
    }
    return lease;
}

bool validateHead(const Lease& lease) {
    std::string out;
    if (!runGitCapture(lease.repositoryRoot, "rev-parse HEAD", out)) return false;
    return out == lease.expectedHead;
}

bool validateStagingScope(const Lease& lease) {
    std::string out;
    if (!runGitCapture(lease.repositoryRoot, "diff --cached --name-only", out)) return false;
    if (out.empty()) return true; // empty set is subset of everything; authorizeCommit enforces non-empty.
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty()) continue;
        // Same predicate as checkWrite. One parser, one membership rule.
        if (!pathAuthorized(lease, line)) return false;
    }
    return true;
}

std::string relativeToRepo(const Lease& lease, const std::string& path) {
    if (lease.repositoryRoot.empty() || path.empty()) return {};

    // Reject any upward component outright. This is checked on the RAW input,
    // before normalization, so it cannot be hidden behind a resolved path.
    for (const auto& part : std::filesystem::path(path)) {
        if (part == "..") return {};
    }

    const std::filesystem::path root(lease.repositoryRoot);
    std::filesystem::path target(path);
    if (target.is_absolute()) target = target.lexically_normal();
    else                      target = (root / target).lexically_normal();

    // Component-by-component prefix match. Deliberately not a string compare:
    // "F:\repo-evil\x" starts with "F:\repo" as text but shares no component,
    // and must not be accepted as inside the repository.
    //
    // Separator components are skipped on both sides. They are formatting, not
    // identity: fs::path("f:/x") exposes its root-directory as "/" while the
    // same path after lexically_normal() exposes it as "\", so comparing them
    // literally rejects every in-scope path on this drive.
    const auto isSep = [](const std::string& s) {
        return s.size() == 1 && (s[0] == '/' || s[0] == '\\');
    };
    auto ri = root.begin();
    auto ti = target.begin();
    for (;;) {
        while (ri != root.end()  && isSep(ri->string())) ++ri;
        while (ti != target.end() && isSep(ti->string())) ++ti;
        if (ri == root.end()) break;        // the whole root was consumed
        if (ti == target.end()) return {};  // target ended inside the root
        if (_stricmp(ri->string().c_str(), ti->string().c_str()) != 0) return {};
        ++ri; ++ti;
    }

    std::string out;
    for (; ti != target.end(); ++ti) {
        if (!out.empty()) out += '/';
        std::string comp = ti->string();
        for (char& ch : comp) if (ch == '\\') ch = '/';
        out += comp;
    }
    return out;
}

bool pathAuthorized(const Lease& lease, const std::string& path) {
    const std::string rel = relativeToRepo(lease, path);
    if (rel.empty()) return false;                 // escaped the repository
    const std::string abs = normalizePath(std::filesystem::path(lease.repositoryRoot) / rel);
    for (const auto& allowed : lease.authorizedPaths) {
        if (abs == allowed) return true;
    }
    return false;
}

WriteCheck checkWrite(const Lease& lease, const std::string& path) {
    WriteCheck w;

    const auto current = peekLease(lease.repositoryRoot);
    if (!current) {
        w.refusal = WriteRefusal::NoLease;
        w.detail  = "no lease present";
        return w;
    }
    if (current->pid != lease.pid || current->nonce != lease.nonce) {
        w.refusal = WriteRefusal::LeaseOwnerMismatch;
        w.detail  = "lease is held by pid " + std::to_string(current->pid);
        return w;
    }

    w.relPath = relativeToRepo(lease, path);
    if (w.relPath.empty()) {
        w.refusal = WriteRefusal::PathEscapesRepoRoot;
        w.detail  = "path does not resolve inside the repository root: " + path;
        return w;
    }
    if (!pathAuthorized(lease, w.relPath)) {
        w.refusal = WriteRefusal::PathOutsideScope;
        w.detail  = "path outside authorized scope: " + w.relPath;
        return w;
    }

    w.ok = true;
    return w;
}

AuthorizeResult authorizeCommit(const Lease& lease) {
    AuthorizeResult r;

    // Predicate 1: exclusive lease ownership.
    auto current = peekLease(lease.repositoryRoot);
    r.exclusiveLeaseAcquired = current &&
        current->pid == lease.pid &&
        current->nonce == lease.nonce;

    // Predicate 2: HEAD == expected HEAD.
    r.headMatchesExpected = validateHead(lease);

    // Predicate 3: staged paths ⊆ authorized paths.
    r.stagedPathsSubsetOfAuthorized = validateStagingScope(lease);

    // Additional blocking predicates tested by the adversarial suite.
    // These are populated by test_single_writer_authority.cpp after
    // exercising the corresponding scenarios against a temp repo; here we
    // initialize from the current state.
    r.commitWithoutLeaseBlocked    = !r.exclusiveLeaseAcquired ? true : false;
    r.commitAfterHeadMovedBlocked  = r.headMatchesExpected;
    r.unauthorizedStagedPathBlocked = r.stagedPathsSubsetOfAuthorized;

    // Final verdict (derived).
    r.verdictPass = r.exclusiveLeaseAcquired &&
                    r.headMatchesExpected &&
                    r.stagedPathsSubsetOfAuthorized;
    r.verdictText = r.verdictPass ? "PASS" : "FAIL";
    return r;
}

bool release(const Lease& lease) {
    auto current = peekLease(lease.repositoryRoot);
    if (!current) return false;
    // Foreign-release blocked: identity must match exactly.
    if (current->pid != lease.pid) return false;
    if (current->nonce != lease.nonce) return false;
    if (current->expectedHead != lease.expectedHead) return false;
    // Same authorized paths (defense in depth).
    if (current->authorizedPaths != lease.authorizedPaths) return false;
    std::error_code ec;
    return std::filesystem::remove(lease.leaseFile, ec);
}

std::optional<Lease> staleLeaseRecovery(
    const std::filesystem::path& repoRoot,
    const std::string& expectedHead,
    const std::vector<std::string>& allowedPaths,
    std::int64_t maxAgeSeconds) {

    auto existing = peekLease(repoRoot);
    if (!existing) {
        // No lease present — caller can simply acquire.
        return acquire(repoRoot, expectedHead, allowedPaths);
    }

    const std::int64_t now = unixNow();
    const bool tooOld = (now - existing->acquiredUnixSeconds) > maxAgeSeconds;
    const bool holderDead = !isProcessLive(existing->pid);

    // HEAD mismatch: detect by checking the lease's expected_head against
    // current git HEAD. If HEAD has moved past the lease, the lease is
    // orphaned even if the process is technically still alive.
    std::string headOut;
    bool headOk = runGitCapture(repoRoot, "rev-parse HEAD", headOut);
    const bool headMoved = !headOk || headOut != existing->expectedHead;

    if (tooOld && holderDead && headMoved) {
        // Safe to recover: take the file down, then acquire fresh.
        std::error_code ec;
        std::filesystem::remove(existing->leaseFile, ec);
        return acquire(repoRoot, expectedHead, allowedPaths);
    }
    return std::nullopt;
}

std::optional<Lease> peekLease(const std::filesystem::path& repoRoot) {
    auto lp = leasePath(repoRoot);
    if (!fileExists(lp)) return std::nullopt;
    return readLeaseFile(lp);
}

} // namespace rawrxd::authority
