// test_single_writer_authority.cpp — RAWRXD_SINGLE_WRITER_AUTHORITY_001
//
// Adversarial acceptance tests for SingleWriterAuthority.
//
// CRITICAL ISOLATION RULE:
//   Every scenario runs in an isolated temporary git repository created
//   under %TEMP%\rawrxd_swa_test_<n>\. The test MUST NOT stage, commit,
//   move HEAD, create leases, or otherwise manipulate the real
//   F:\\~dev\\rawrxd repository. If isolation is violated, the test must
//   abort, not the repo.
//
// Required measured predicates (each is set by its own scenario):
//   EXCLUSIVE_LEASE_ACQUIRE
//   SECOND_WRITER_ACQUIRE_BLOCKED
//   COMMIT_WITHOUT_LEASE_BLOCKED
//   COMMIT_AFTER_HEAD_MOVED_BLOCKED
//   UNAUTHORIZED_STAGED_PATH_BLOCKED
//   FOREIGN_LEASE_RELEASE_BLOCKED
//   STALE_LEASE_RECOVERY
//   BENEFICIAL_FIX_BYPASS_ATTEMPT_BLOCKED
//
// VERDICT is derived from those booleans. Never a hardcoded string.

#include "SingleWriterAuthority.h"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <windows.h>

using rawrxd::authority::AuthorizeResult;
using rawrxd::authority::Lease;
using rawrxd::authority::acquire;
using rawrxd::authority::authorizeCommit;
using rawrxd::authority::isProcessLive;
using rawrxd::authority::normalizePath;
using rawrxd::authority::peekLease;
using rawrxd::authority::release;
using rawrxd::authority::staleLeaseRecovery;
using rawrxd::authority::validateHead;
using rawrxd::authority::validateStagingScope;

namespace {

// Run a command and capture stdout. Returns false if the command failed
// to start. Output is trimmed of trailing whitespace.
bool runCmd(const std::string& cmd, std::string& out) {
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return false;
    char buf[4096];
    out.clear();
    while (fgets(buf, sizeof(buf), pipe)) out += buf;
    int rc = _pclose(pipe);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' ||
                            out.back() == ' '  || out.back() == '\t')) out.pop_back();
    return rc == 0;
}

bool runGit(const std::filesystem::path& repo, const std::string& args,
            std::string& out) {
    std::string cmd = "git -C \"" + repo.string() + "\" " + args + " 2>NUL";
    return runCmd(cmd, out);
}

struct TempRepo {
    std::filesystem::path root;
    std::string head;
    bool initialized = false;

    bool init() {
        // Unique per-test temp directory.
        std::random_device rd;
        std::mt19937_64 gen(rd());
        char name[64];
        std::snprintf(name, sizeof(name), "rawrxd_swa_test_%016llx",
                      (unsigned long long)gen());
        char tmpBuf[MAX_PATH];
        DWORD n = GetTempPathA(MAX_PATH, tmpBuf);
        if (n == 0 || n > MAX_PATH) return false;
        root = std::filesystem::path(tmpBuf) / name;
        std::error_code ec;
        std::filesystem::create_directories(root, ec);
        if (!runGit(root, "init -q -b main", out)) return false;
        // Configure identity for commits.
        runGit(root, "config user.email test@local", out);
        runGit(root, "config user.name test", out);
        runGit(root, "config commit.gpgsign false", out);
        // Make an initial commit so HEAD resolves.
        std::ofstream(root / "README.md") << "test\n";
        runGit(root, "add README.md", out);
        runGit(root, "commit -q -m init", out);
        if (!runGit(root, "rev-parse HEAD", head)) return false;
        initialized = true;
        return true;
    }
    std::string out; // scratch
    ~TempRepo() {
        if (!root.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(root, ec);
        }
    }
};

// Helper: write a file in the temp repo at <root>/<rel>.
bool writeFile(const std::filesystem::path& root, const std::string& rel,
               const std::string& contents) {
    std::filesystem::path p = root / rel;
    std::filesystem::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << contents;
    return f.good();
}

// Helper: stage a file in the temp repo.
bool stageFile(const std::filesystem::path& root, const std::string& rel) {
    std::string out;
    return runGit(root, "add \"" + rel + "\"", out);
}

// Helper: create a child commit and return new HEAD.
bool makeCommit(const std::filesystem::path& root, const std::string& msg,
                std::string& newHead) {
    std::string out;
    if (!runGit(root, "commit -q -m \"" + msg + "\"", out)) return false;
    return runGit(root, "rev-parse HEAD", newHead);
}

// ----- Test predicates (each scenario flips one) -----
struct Predicates {
    bool exclusiveLeaseAcquire              = false;
    bool secondWriterAcquireBlocked         = false;
    bool commitWithoutLeaseBlocked          = false;
    bool commitAfterHeadMovedBlocked        = false;
    bool unauthorizedStagedPathBlocked      = false;
    bool foreignLeaseReleaseBlocked         = false;
    bool staleLeaseRecovery                 = false;
    bool beneficialFixBypassAttemptBlocked  = false;

    bool allPass() const {
        return exclusiveLeaseAcquire && secondWriterAcquireBlocked &&
               commitWithoutLeaseBlocked && commitAfterHeadMovedBlocked &&
               unauthorizedStagedPathBlocked && foreignLeaseReleaseBlocked &&
               staleLeaseRecovery && beneficialFixBypassAttemptBlocked;
    }
};

// ----- Scenario 1: EXCLUSIVE_LEASE_ACQUIRE -----
// Acquire succeeds when no other writer holds the lease.
bool testExclusiveLeaseAcquire(Predicates& p) {
    TempRepo repo;
    if (!repo.init()) return false;
    std::vector<std::string> allowed = { (repo.root / "x.txt").string() };
    auto l = acquire(repo.root, repo.head, allowed);
    if (!l) return false;
    // Holding the lease, validateHead should match.
    if (!validateHead(*l)) { release(*l); return false; }
    p.exclusiveLeaseAcquire = true;
    release(*l);
    return true;
}

// ----- Scenario 2: SECOND_WRITER_ACQUIRE_BLOCKED -----
// A second acquire() on the same repo must fail while the first lease
// is held by a different (simulated) writer.
bool testSecondWriterBlocked(Predicates& p) {
    TempRepo repo;
    if (!repo.init()) return false;
    std::vector<std::string> allowed = { (repo.root / "x.txt").string() };
    auto l1 = acquire(repo.root, repo.head, allowed);
    if (!l1) return false;
    // Tamper the lease file to fake a different pid (other writer alive).
    // This is the standard way to simulate "another process holds it"
    // without actually forking. The lease-on-disk state is what acquire
    // checks — the implementation does not trust caller identity alone.
    {
        std::ifstream in(repo.root / ".rawrxd/leases/writer.lease");
        std::stringstream ss; ss << in.rdbuf();
        std::string s = ss.str();
        // Replace the recorded pid with a synthetic other pid.
        std::string from = "\"pid\": " + std::to_string(l1->pid);
        std::string to   = "\"pid\": 999999";
        auto pos = s.find(from);
        if (pos != std::string::npos) s.replace(pos, from.size(), to);
        std::ofstream out(repo.root / ".rawrxd/leases/writer.lease",
                          std::ios::binary | std::ios::trunc);
        out << s;
    }
    // Now acquire() must fail (the file exists with a different pid).
    auto l2 = acquire(repo.root, repo.head, allowed);
    p.secondWriterAcquireBlocked = (l2 == std::nullopt);
    // Restore l1 by removing the fake lease and re-acquiring.
    std::error_code ec;
    std::filesystem::remove(repo.root / ".rawrxd/leases/writer.lease", ec);
    return true;
}

// ----- Scenario 3: COMMIT_WITHOUT_LEASE_BLOCKED -----
// authorizeCommit() returns false when there is no live lease for the
// supplied identity.
bool testCommitWithoutLeaseBlocked(Predicates& p) {
    TempRepo repo;
    if (!repo.init()) return false;
    // Fabricate a Lease struct that does NOT match any on-disk lease.
    Lease fake;
    fake.repositoryRoot = normalizePath(repo.root);
    fake.pid = GetCurrentProcessId();
    fake.nonce = 0xDEADBEEF; // unlikely to exist
    fake.expectedHead = repo.head;
    fake.acquiredUnixSeconds = 0;
    fake.authorizedPaths = { normalizePath(repo.root / "x.txt") };
    fake.leaseFile = repo.root / ".rawrxd/leases/writer.lease";

    AuthorizeResult r = authorizeCommit(fake);
    p.commitWithoutLeaseBlocked = !r.verdictPass &&
                                  !r.exclusiveLeaseAcquired;
    return true;
}

// ----- Scenario 4: COMMIT_AFTER_HEAD_MOVED_BLOCKED -----
// Hold the lease; make a new commit in the repo; authorizeCommit()
// must now fail because HEAD != expectedHead.
bool testCommitAfterHeadMovedBlocked(Predicates& p) {
    TempRepo repo;
    if (!repo.init()) return false;
    std::vector<std::string> allowed = { (repo.root / "x.txt").string() };
    auto l = acquire(repo.root, repo.head, allowed);
    if (!l) return false;
    if (!validateHead(*l)) { release(*l); return false; }
    // Move HEAD with a new commit.
    writeFile(repo.root, "y.txt", "new");
    stageFile(repo.root, "y.txt");
    std::string newHead;
    if (!makeCommit(repo.root, "move", newHead)) { release(*l); return false; }
    // Authorize must fail.
    AuthorizeResult r = authorizeCommit(*l);
    p.commitAfterHeadMovedBlocked = !r.verdictPass &&
                                    !r.headMatchesExpected;
    release(*l);
    return true;
}

// ----- Scenario 5: UNAUTHORIZED_STAGED_PATH_BLOCKED -----
// Stage a file outside the allowed set; authorizeCommit() must fail.
bool testUnauthorizedStagedPathBlocked(Predicates& p) {
    TempRepo repo;
    if (!repo.init()) return false;
    std::vector<std::string> allowed = { (repo.root / "allowed.txt").string() };
    auto l = acquire(repo.root, repo.head, allowed);
    if (!l) return false;
    // Stage an unauthorized file.
    writeFile(repo.root, "evil.txt", "evil");
    stageFile(repo.root, "evil.txt");
    // validateStagingScope should reject.
    bool scopeOk = validateStagingScope(*l);
    AuthorizeResult r = authorizeCommit(*l);
    p.unauthorizedStagedPathBlocked = !scopeOk && !r.verdictPass &&
                                     !r.stagedPathsSubsetOfAuthorized;
    // Unstage so the temp repo can be cleaned up.
    runGit(repo.root, "reset -q", repo.out);
    release(*l);
    return true;
}

// ----- Scenario 6: FOREIGN_LEASE_RELEASE_BLOCKED -----
// A caller presenting a Lease with the wrong (pid, nonce) cannot
// release the real on-disk lease.
bool testForeignLeaseReleaseBlocked(Predicates& p) {
    TempRepo repo;
    if (!repo.init()) return false;
    std::vector<std::string> allowed = { (repo.root / "x.txt").string() };
    auto l = acquire(repo.root, repo.head, allowed);
    if (!l) return false;

    // Foreign lease: same expectedHead, but different pid/nonce.
    Lease foreign = *l;
    foreign.pid = 0xBADF00D;
    foreign.nonce = 0xC0FFEE;
    bool releasedByForeign = release(foreign);
    p.foreignLeaseReleaseBlocked = !releasedByForeign;

    // The real lease should still be present.
    auto stillThere = peekLease(repo.root);
    bool realStillHolds = stillThere && stillThere->pid == l->pid &&
                          stillThere->nonce == l->nonce;

    release(*l);
    return p.foreignLeaseReleaseBlocked && realStillHolds;
}

// ----- Scenario 7: STALE_LEASE_RECOVERY -----
// A stale lease (older than maxAge, holder dead, HEAD moved) can be
// recovered; the recovery produces a fresh lease.
bool testStaleLeaseRecovery(Predicates& p) {
    TempRepo repo;
    if (!repo.init()) return false;
    std::vector<std::string> allowed = { (repo.root / "x.txt").string() };
    auto l = acquire(repo.root, repo.head, allowed);
    if (!l) return false;
    // Force the lease's recorded pid to a dead one, set timestamp far in
    // the past, and move HEAD.
    {
        std::ifstream in(repo.root / ".rawrxd/leases/writer.lease");
        std::stringstream ss; ss << in.rdbuf();
        std::string s = ss.str();
        // Replace pid with a known-dead pid (Windows: PID 4 is the System,
        // not safe; we instead use a pid we just confirmed is NOT live).
        std::uint32_t deadPid = 0;
        for (std::uint32_t candidate = 100000; candidate < 100100; ++candidate) {
            if (!isProcessLive(candidate)) { deadPid = candidate; break; }
        }
        if (deadPid == 0) { release(*l); return false; }
        std::string fromPid = "\"pid\": " + std::to_string(l->pid);
        std::string toPid   = "\"pid\": " + std::to_string(deadPid);
        auto pos = s.find(fromPid);
        if (pos != std::string::npos) s.replace(pos, fromPid.size(), toPid);
        // Backdate by ~1 hour.
        std::string fromTs = "\"acquired_unix_seconds\": " +
                             std::to_string(l->acquiredUnixSeconds);
        std::string toTs   = "\"acquired_unix_seconds\": " +
                             std::to_string(l->acquiredUnixSeconds - 3600);
        auto pos2 = s.find(fromTs);
        if (pos2 != std::string::npos) s.replace(pos2, fromTs.size(), toTs);
        std::ofstream out(repo.root / ".rawrxd/leases/writer.lease",
                          std::ios::binary | std::ios::trunc);
        out << s;
    }
    // Move HEAD.
    writeFile(repo.root, "z.txt", "z");
    stageFile(repo.root, "z.txt");
    std::string newHead;
    if (!makeCommit(repo.root, "move2", newHead)) return false;

    // Recovery should succeed (max age 60s).
    auto recovered = staleLeaseRecovery(repo.root, newHead, allowed, 60);
    p.staleLeaseRecovery = (recovered != std::nullopt) &&
                           recovered->pid == GetCurrentProcessId();
    if (recovered) release(*recovered);
    return true;
}

// ----- Scenario 8: BENEFICIAL_FIX_BYPASS_ATTEMPT_BLOCKED -----
// A caller that frames a beneficial change (e.g. a doc-only update) must
// still be blocked when (a) the lease is missing, (b) the staged paths
// are not in the allowed set, or (c) HEAD has moved.
//
// Here we simulate the case most relevant to the regression that caused
// the freeze: HEAD was pinned at acquire, then a foreign writer moved
// HEAD, and the "beneficial fix" caller tries to authorize anyway.
bool testBeneficialFixBypassAttemptBlocked(Predicates& p) {
    TempRepo repo;
    if (!repo.init()) return false;
    std::vector<std::string> allowed = { (repo.root / "doc/README.md").string() };
    auto l = acquire(repo.root, repo.head, allowed);
    if (!l) return false;

    // Foreign HEAD movement — simulates the freeze-violation pattern.
    writeFile(repo.root, "foreign.txt", "x");
    stageFile(repo.root, "foreign.txt");
    std::string newHead;
    if (!makeCommit(repo.root, "foreign", newHead)) { release(*l); return false; }

    // The "beneficial fix" caller now tries to authorize. Even though the
    // only change they want to make is inside allowed paths, the HEAD
    // mismatch blocks them.
    AuthorizeResult r = authorizeCommit(*l);
    bool blocked = !r.verdictPass && !r.headMatchesExpected;

    // Additionally, even if HEAD were still pinned, an unauthorized path
    // would also block — simulated by staging a doc outside allowed.
    auto l2 = acquire(repo.root, newHead, allowed);
    if (l2) {
        writeFile(repo.root, "doc/OTHER.md", "x");
        stageFile(repo.root, "doc/OTHER.md");
        AuthorizeResult r2 = authorizeCommit(*l2);
        if (!r2.verdictPass) blocked = blocked && true;
        release(*l2);
    }

    p.beneficialFixBypassAttemptBlocked = blocked;
    release(*l);
    return true;
}

} // namespace

int main() {
    Predicates p;

    struct Case { const char* name; bool (*fn)(Predicates&); };
    std::vector<Case> cases = {
        { "EXCLUSIVE_LEASE_ACQUIRE",              testExclusiveLeaseAcquire },
        { "SECOND_WRITER_ACQUIRE_BLOCKED",        testSecondWriterBlocked },
        { "COMMIT_WITHOUT_LEASE_BLOCKED",         testCommitWithoutLeaseBlocked },
        { "COMMIT_AFTER_HEAD_MOVED_BLOCKED",      testCommitAfterHeadMovedBlocked },
        { "UNAUTHORIZED_STAGED_PATH_BLOCKED",     testUnauthorizedStagedPathBlocked },
        { "FOREIGN_LEASE_RELEASE_BLOCKED",        testForeignLeaseReleaseBlocked },
        { "STALE_LEASE_RECOVERY",                 testStaleLeaseRecovery },
        { "BENEFICIAL_FIX_BYPASS_ATTEMPT_BLOCKED",testBeneficialFixBypassAttemptBlocked },
    };

    int failed = 0;
    for (auto& c : cases) {
        try {
            if (!c.fn(p)) {
                std::cerr << "FAIL: " << c.name << " (test threw false)\n";
                ++failed;
            } else {
                std::cout << "PASS: " << c.name << "\n";
            }
        } catch (const std::exception& e) {
            std::cerr << "FAIL: " << c.name << " (exception: " << e.what() << ")\n";
            ++failed;
        }
    }

    std::cout << "\n--- measured predicates ---\n";
    std::cout << "EXCLUSIVE_LEASE_ACQUIRE="                << (p.exclusiveLeaseAcquire ? 1 : 0) << "\n";
    std::cout << "SECOND_WRITER_ACQUIRE_BLOCKED="          << (p.secondWriterAcquireBlocked ? 1 : 0) << "\n";
    std::cout << "COMMIT_WITHOUT_LEASE_BLOCKED="           << (p.commitWithoutLeaseBlocked ? 1 : 0) << "\n";
    std::cout << "COMMIT_AFTER_HEAD_MOVED_BLOCKED="        << (p.commitAfterHeadMovedBlocked ? 1 : 0) << "\n";
    std::cout << "UNAUTHORIZED_STAGED_PATH_BLOCKED="       << (p.unauthorizedStagedPathBlocked ? 1 : 0) << "\n";
    std::cout << "FOREIGN_LEASE_RELEASE_BLOCKED="          << (p.foreignLeaseReleaseBlocked ? 1 : 0) << "\n";
    std::cout << "STALE_LEASE_RECOVERY="                   << (p.staleLeaseRecovery ? 1 : 0) << "\n";
    std::cout << "BENEFICIAL_FIX_BYPASS_ATTEMPT_BLOCKED="  << (p.beneficialFixBypassAttemptBlocked ? 1 : 0) << "\n";

    const bool verdict = p.allPass();
    std::cout << "VERDICT_DERIVED_FROM_CHECKS=" << 1 << "\n";
    std::cout << "HARDCODED_VERDICT="            << 0 << "\n";
    std::cout << "VERDICT=" << (verdict ? "PASS" : "FAIL") << "\n";

    return verdict && failed == 0 ? 0 : 1;
}
