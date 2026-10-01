// WriterLeaseAuthority.cpp — RAWRXD_SINGLE_WRITER_AUTHORITY_001
#include "agentmodes/WriterLeaseAuthority.h"

#include "ProcessUtil.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <windows.h>
#include <bcrypt.h>

namespace fs = std::filesystem;

namespace rawrxd { namespace lease {

namespace {

std::vector<std::string> g_authorized;

// Self-contained SHA-256 helper, used by scopeHashOf.
// Lives in this file so the canonical four-path allowlist does not need
// to pull in RawrCertAuthority. Uses Windows BCrypt (already a project
// dependency via src/deep2/ReceiptAuthority.cpp).
std::string sha256Hex(const void* data, size_t size) {
    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        return {};
    }
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<void*>(data)),
                   static_cast<ULONG>(size), 0);
    UCHAR hash[32];
    BCryptFinishHash(hHash, hash, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    static const char* hex = "0123456789abcdef";
    std::string out(64, '0');
    for (int i = 0; i < 32; ++i) {
        out[2 * i]     = hex[(hash[i] >> 4) & 0xF];
        out[2 * i + 1] = hex[hash[i] & 0xF];
    }
    return out;
}

std::string utcNow() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_s(&tm, &t);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

std::string utcPlus(int seconds) {
    const std::time_t t = std::time(nullptr) + seconds;
    std::tm tm{};
    gmtime_s(&tm, &t);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// Run git with an argument vector. There is deliberately no shell anywhere in
// this file.
//
// The previous implementation built a command STRING and passed it to _popen:
//
//     runCapture("git -C \"" + repoRoot + "\" commit -m \"" + message + "\"")
//
// repoRoot and message were interpolated with no escaping, so a repository
// path or a commit message containing a double quote escaped the argument and
// the remainder of the string was parsed by cmd.exe. This function hands
// CreateProcess an argv; nothing in any element can become a metacharacter.
std::string runGit(const std::string& repoRoot, const std::vector<std::string>& args) {
    std::vector<std::string> full;
    full.reserve(args.size() + 2);
    full.push_back("-C");
    full.push_back(repoRoot);
    for (const auto& a : args) full.push_back(a);

    std::string out;
    int32_t code = -1;
    procutil::runProcessNoShell("git", full, out, code, 65536);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

} // namespace

std::string leasePath(const std::string& repoRoot) {
    return (fs::path(repoRoot) / ".rawr" / "lease.lock").string();
}

uint32_t currentPid() { return ::GetCurrentProcessId(); }

uint64_t currentProcessStartTime() {
    // GetProcessTimes writes to all four out-parameters; passing nullptr for
    // any of them is an access violation, not a graceful failure.
    FILETIME c{}, e{}, k{}, u{};
    if (!GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)) return 0;
    return (static_cast<uint64_t>(c.dwHighDateTime) << 32) | c.dwLowDateTime;
}

bool processAlive(uint32_t pid, uint64_t startTime) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;                       // no such process
    FILETIME c{}, e{}, k{}, u{};
    const BOOL ok = GetProcessTimes(h, &c, &e, &k, &u);
    if (!ok) { CloseHandle(h); return false; }
    const uint64_t actual = (static_cast<uint64_t>(c.dwHighDateTime) << 32) | c.dwLowDateTime;
    // Same pid but a different creation time means the pid was recycled.
    if (startTime != 0 && actual != startTime) { CloseHandle(h); return false; }
    // A terminated process remains openable while any handle to it is still
    // open, so OpenProcess success proves nothing about liveness. Measured in
    // BATCH_0: a process killed with TerminateProcess and confirmed dead by
    // WaitForSingleObject(WAIT_OBJECT_0) with exit code 1 was still reported
    // alive here, which would have made a crashed writer's lease permanently
    // unrecoverable. The exit state has to be consulted as well.
    DWORD code = 0;
    const BOOL haveCode = GetExitCodeProcess(h, &code);
    CloseHandle(h);
    if (!haveCode) return false;                // cannot prove liveness
    return code == STILL_ACTIVE;
}

std::string serialize(const LeaseRecord& r) {
    std::ostringstream os;
    os << "LEASE_SCHEMA_VERSION=1\n"
       << "LEASE_ID=" << r.leaseId << "\n"
       << "LEASE_OWNER_PID=" << r.ownerPid << "\n"
       << "LEASE_OWNER_PROCESS_START_TIME=" << r.ownerStartTime << "\n"
       << "LEASE_NONCE=" << r.nonce << "\n"
       << "EXPECTED_HEAD=" << r.expectedHead << "\n"
       << "LEASE_HOST=" << r.host << "\n"
       << "LEASE_ACQUIRED_UTC=" << r.acquiredUtc << "\n"
       << "LEASE_EXPIRES_UTC=" << r.expiresUtc << "\n"
       << "LEASE_TTL_SECONDS=" << r.ttlSeconds << "\n";
    return os.str();
}

bool parse(const std::string& text, LeaseRecord& out) {
    std::istringstream is(text);
    std::string line;
    bool sawId = false;
    while (std::getline(is, line)) {
        const size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        if (k == "LEASE_ID") { out.leaseId = v; sawId = !v.empty(); }
        else if (k == "LEASE_OWNER_PID") out.ownerPid = (uint32_t)std::strtoul(v.c_str(), nullptr, 10);
        else if (k == "LEASE_OWNER_PROCESS_START_TIME") out.ownerStartTime = std::strtoull(v.c_str(), nullptr, 10);
        else if (k == "LEASE_NONCE") out.nonce = v;
        else if (k == "EXPECTED_HEAD") out.expectedHead = v;
        else if (k == "LEASE_HOST") out.host = v;
        else if (k == "LEASE_ACQUIRED_UTC") out.acquiredUtc = v;
        else if (k == "LEASE_EXPIRES_UTC") out.expiresUtc = v;
        else if (k == "LEASE_TTL_SECONDS") out.ttlSeconds = std::atoi(v.c_str());
    }
    return sawId;
}

bool load(const std::string& repoRoot, LeaseRecord& out) {
    std::ifstream in(leasePath(repoRoot), std::ios::binary);
    if (!in) return false;
    std::ostringstream ss; ss << in.rdbuf();
    return parse(ss.str(), out);
}

AcquireResult acquire(const std::string& repoRoot, const std::string& expectedHead, int ttlSeconds) {
    AcquireResult res;
    const std::string path = leasePath(repoRoot);

    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);

    // The record we would write, built first so the handle can be written to
    // immediately after the exclusive open succeeds.
    LeaseRecord rec;
    rec.leaseId          = std::to_string(currentPid()) + "-" + std::to_string(
                               currentProcessStartTime()) + "-" + std::to_string(::GetTickCount64());
    rec.ownerPid         = currentPid();
    rec.ownerStartTime   = currentProcessStartTime();
    rec.nonce            = rec.leaseId;   // unique per acquisition attempt
    rec.expectedHead     = expectedHead;
    char host[256] = {0};
    DWORD hostLen = sizeof host;
    GetComputerNameA(host, &hostLen);
    rec.host             = host;
    rec.acquiredUtc      = utcNow();
    rec.ttlSeconds        = ttlSeconds;
    rec.expiresUtc       = utcPlus(ttlSeconds);

    // Atomic acquisition. CREATE_NEW fails if the file already exists, so two
    // contenders can never both succeed. This is the whole primitive.
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        const std::string body = serialize(rec);
        DWORD written = 0;
        WriteFile(h, body.data(), (DWORD)body.size(), &written, nullptr);
        CloseHandle(h);
        res.outcome = AcquireOutcome::Acquired;
        res.record  = rec;
        res.detail  = "lease created exclusively";
        return res;
    }

    const DWORD err = GetLastError();
    if (err != ERROR_FILE_EXISTS && err != ERROR_ALREADY_EXISTS) {
        res.outcome = AcquireOutcome::Failed;
        res.detail  = "CreateFileA failed with " + std::to_string(err);
        return res;
    }

    // A lease file exists. Determine whether its owner is actually alive.
    LeaseRecord held;
    if (!load(repoRoot, held)) {
        res.outcome = AcquireOutcome::HeldUnreadable;
        res.detail  = "lease file exists but does not parse; refusing to steal";
        return res;
    }
    res.record = held;

    if (processAlive(held.ownerPid, held.ownerStartTime)) {
        res.outcome = AcquireOutcome::HeldByLiveProcess;
        res.detail  = "held by live pid " + std::to_string(held.ownerPid);
        return res;
    }

    // Owner is proven dead. Recovering the lease is allowed, but the recovery
    // must be atomic with respect to every other contender, or two writers can
    // both end up holding it.
    //
    // The previous code was:
    //
    //     DeleteFileA(path);
    //     HANDLE h2 = CreateFileA(path, ..., CREATE_NEW, ...);
    //
    // A second contender that had already completed its own delete-and-create
    // between our liveness check and our DeleteFileA had its FRESH lease
    // deleted out from under it, after which our CREATE_NEW succeeded too. Two
    // holders, both reported as owning the lease. That is the failure that let
    // two sessions write rawrxd/src/deep2/Deep2Engine.cpp on 2026-09-30 while
    // this file was in the build.
    //
    // The fix is to make the delete conditional on the file still being the one
    // we evaluated. Open it with DELETE access and WITHOUT FILE_SHARE_DELETE,
    // so no other process can delete or replace it while the handle is held.
    // Re-read the record through that handle and confirm identity. Only then
    // mark it deleted via the handle. Closing the handle performs the delete
    // atomically, and the following CREATE_NEW means only one racer can win:
    // the loser gets ERROR_FILE_EXISTS and reports held.
    {
        HANDLE h = CreateFileA(path.c_str(), GENERIC_READ | DELETE, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            // Someone else has it open for delete, or it vanished. Either way
            // this contender did not observe a recoverable lease.
            res.outcome = AcquireOutcome::HeldByLiveProcess;
            res.detail  = "lease is open by another contender; refusing to steal";
            return res;
        }

        // Re-verify through the held handle that this is still the stale
        // record we judged, not one a racer has already replaced.
        LeaseRecord current;
        bool identical = false;
        {
            LARGE_INTEGER li{};
            if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0 ||
                static_cast<uint64_t>(li.QuadPart) > 65536) {
                CloseHandle(h);
                res.outcome = AcquireOutcome::HeldUnreadable;
                res.detail  = "lease file size is implausible; refusing to steal";
                return res;
            }
            std::string body(static_cast<size_t>(li.QuadPart), '\0');
            DWORD got = 0;
            const BOOL ok = ReadFile(h, body.data(), (DWORD)body.size(), &got, nullptr);
            CloseHandle(h);
            if (!ok) {
                res.outcome = AcquireOutcome::HeldUnreadable;
                res.detail  = "lease file unreadable while held; refusing to steal";
                return res;
            }
            body.resize(got);
            identical = parse(body, current) &&
                        current.ownerPid     == held.ownerPid &&
                        current.ownerStartTime == held.ownerStartTime &&
                        current.nonce         == held.nonce;
        }

        if (!identical) {
            res.outcome = AcquireOutcome::HeldByLiveProcess;
            res.detail  = "lease changed identity during recovery; not stealing";
            return res;
        }

        // Mark for deletion through a freshly opened handle. Reopening is safe
        // because CREATE_NEW below is still the authoritative test: if anyone
        // recreated the file in the gap, our CREATE_NEW fails.
        HANDLE hd = CreateFileA(path.c_str(), DELETE, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hd != INVALID_HANDLE_VALUE) {
            FILE_DISPOSITION_INFO di{};
            di.DeleteFile = TRUE;
            SetFileInformationByHandle(hd, FileDispositionInfo, &di, sizeof di);
            CloseHandle(hd);        // the delete happens here, atomically
        }
    }

    HANDLE h2 = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h2 == INVALID_HANDLE_VALUE) {
        res.outcome = AcquireOutcome::HeldByLiveProcess;
        res.detail  = "lost the stale-recovery race to another contender";
        return res;
    }
    const std::string body = serialize(rec);
    DWORD written = 0;
    WriteFile(h2, body.data(), (DWORD)body.size(), &written, nullptr);
    CloseHandle(h2);
    res.outcome = AcquireOutcome::StaleRecovered;
    res.record  = rec;
    res.detail  = "previous owner proven dead (pid " + std::to_string(held.ownerPid) + ")";
    return res;
}

bool release(const std::string& repoRoot, const LeaseRecord& held) {
    LeaseRecord current;
    if (!load(repoRoot, current)) return false;   // nothing to release
    // Never release a lease we do not own: identity must match on pid,
    // process creation time and nonce.
    if (current.ownerPid != held.ownerPid ||
        current.ownerStartTime != held.ownerStartTime ||
        current.nonce != held.nonce) {
        return false;
    }
    return DeleteFileA(leasePath(repoRoot).c_str()) != 0;
}

void setAuthorizedPaths(const std::vector<std::string>& paths) {
    g_authorized = paths;
    std::sort(g_authorized.begin(), g_authorized.end());
}

std::string scopeHashOf(const std::vector<std::string>& sortedPaths) {
    std::string joined;
    for (const auto& p : sortedPaths) { joined += p; joined += "\n"; }
    return sha256Hex(joined.data(), joined.size());
}

std::string authorizedScopeHash() { return scopeHashOf(g_authorized); }

CommitCheck checkCommit(const std::string& repoRoot, const LeaseRecord& held) {
    CommitCheck c;
    c.expectedHead = held.expectedHead;
    c.currentHead  = runGit(repoRoot, { "rev-parse", "HEAD" });
    c.authorizedScopeHash = authorizedScopeHash();

    LeaseRecord current;
    if (!load(repoRoot, current)) {
        c.refusal = CommitRefusal::NoLease;
        c.detail  = "no lease present";
        return c;
    }
    if (current.ownerPid != held.ownerPid ||
        current.ownerStartTime != held.ownerStartTime ||
        current.nonce != held.nonce) {
        c.refusal = CommitRefusal::LeaseOwnerMismatch;
        c.detail  = "lease is held by pid " + std::to_string(current.ownerPid);
        return c;
    }
    // Expiry is evaluated against the recorded expiry, in UTC epoch seconds.
    {
        std::tm tm{};
        if (sscanf_s(current.expiresUtc.c_str(), "%d-%d-%dT%d:%d:%dZ",
                   &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                   &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
            tm.tm_year -= 1900; tm.tm_mon -= 1;
            const std::time_t exp = _mkgmtime(&tm);
            if (exp != static_cast<std::time_t>(-1) && std::time(nullptr) > exp) {
                c.refusal = CommitRefusal::LeaseExpired;
                c.detail  = "lease expired at " + current.expiresUtc;
                return c;
            }
        }
    }
    if (c.currentHead != held.expectedHead) {
        c.refusal = CommitRefusal::HeadMoved;
        c.detail  = "HEAD moved from " + held.expectedHead + " to " + c.currentHead;
        return c;
    }

    const std::string staged = runGit(repoRoot, { "diff", "--cached", "--name-only" });
    std::vector<std::string> paths;
    std::istringstream is(staged);
    std::string line;
    while (std::getline(is, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) paths.push_back(line);
    }
    std::sort(paths.begin(), paths.end());
    c.stagedCount     = (int)paths.size();
    c.stagedScopeHash = scopeHashOf(paths);

    // Scope must be a subset of what was authorized, not merely equal: an
    // authorized-but-unstaged path is harmless, an unapproved path is not.
    for (const auto& p : paths) {
        if (std::find(g_authorized.begin(), g_authorized.end(), p) == g_authorized.end()) {
            c.refusal = CommitRefusal::StagedScopeExpanded;
            c.detail  = "staged path outside authorized scope: " + p;
            return c;
        }
    }

    c.ok = true;
    return c;
}

CommitCheck guardedCommit(const std::string& repoRoot, const LeaseRecord& held,
                          const std::string& message) {
    const CommitCheck c = checkCommit(repoRoot, held);
    if (!c.ok) return c;
    // -m takes the message as one argv element. Previously this was a shell
    // string, so a message containing `"` or `&` broke out of the argument.
    runGit(repoRoot, { "commit", "-m", message });
    return c;
}

// ---------------------------------------------------------------------------
// Write-time scope enforcement
// ---------------------------------------------------------------------------

namespace {

// Shared lease-validity predicates, so checkWrite cannot drift from checkCommit
// on what counts as a live, owned, unexpired lease.
bool leaseIsOurs(const LeaseRecord& current, const LeaseRecord& held) {
    return current.ownerPid == held.ownerPid &&
           current.ownerStartTime == held.ownerStartTime &&
           current.nonce == held.nonce;
}

bool leaseExpired(const LeaseRecord& current) {
    std::tm tm{};
    if (sscanf_s(current.expiresUtc.c_str(), "%d-%d-%dT%d:%d:%dZ",
                 &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                 &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
        return false;   // unparseable expiry is not treated as expired
    }
    tm.tm_year -= 1900; tm.tm_mon -= 1;
    const std::time_t exp = _mkgmtime(&tm);
    return exp != static_cast<std::time_t>(-1) && std::time(nullptr) > exp;
}

} // namespace

std::string relativeToRepo(const std::string& repoRoot, const std::string& relPath) {
    if (repoRoot.empty() || relPath.empty()) return {};
    std::error_code ec;
    fs::path root = fs::weakly_canonical(fs::path(repoRoot), ec);
    if (ec) root = fs::path(repoRoot);

    fs::path target = relPath;
    if (target.is_absolute()) target = target.lexically_normal();
    else                     target = (root / target).lexically_normal();

    // Walk the root's own components against the leading components of the
    // target. Comparing the normalized prefix is what stops "..\..\outside".
    // This is a textual comparison on purpose: fs::equivalent would need the
    // path to exist, and an authorized path is checked before it is written.
    auto ti = target.begin();
    for (auto ri = root.begin(); ri != root.end(); ++ri, ++ti) {
        if (ti == target.end()) return {};
        if (_stricmp(ri->string().c_str(), ti->string().c_str()) != 0) return {};
    }

    std::string out;
    for (; ti != target.end(); ++ti) {
        const std::string comp = ti->string();
        if (comp == "..") return {};                  // never walk upward
        if (!out.empty()) out += '/';
        for (char ch : comp) out += (ch == '\\') ? '/' : ch;
    }
    return out;
}

bool pathAuthorized(const std::string& path) {
    return std::find(g_authorized.begin(), g_authorized.end(), path) != g_authorized.end();
}

WriteCheck checkWrite(const std::string& repoRoot, const LeaseRecord& held,
                      const std::string& relPath) {
    WriteCheck w;
    w.relPath = relativeToRepo(repoRoot, relPath);
    if (w.relPath.empty()) {
        w.refusal = WriteRefusal::PathEscapesRepoRoot;
        w.detail  = "path does not resolve inside the repository root: " + relPath;
        return w;
    }

    LeaseRecord current;
    if (!load(repoRoot, current)) {
        w.refusal = WriteRefusal::NoLease;
        w.detail  = "no lease present";
        return w;
    }
    if (!leaseIsOurs(current, held)) {
        w.refusal = WriteRefusal::LeaseOwnerMismatch;
        w.detail  = "lease is held by pid " + std::to_string(current.ownerPid);
        return w;
    }
    if (leaseExpired(current)) {
        w.refusal = WriteRefusal::LeaseExpired;
        w.detail  = "lease expired at " + current.expiresUtc;
        return w;
    }
    if (!pathAuthorized(w.relPath)) {
        w.refusal = WriteRefusal::PathOutsideScope;
        w.detail  = "path outside authorized scope: " + w.relPath;
        return w;
    }

    w.ok = true;
    return w;
}

}} // namespace rawrxd::lease
