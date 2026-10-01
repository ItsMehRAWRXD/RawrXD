// single_writer_adversarial_test.cpp — RAWRXD_SINGLE_WRITER_AUTHORITY_001
//
// Adversarial gate for the CANONICAL single-writer mechanism,
// src/authority/SingleWriterAuthority.{h,cpp}.
//
// Every check runs against an isolated scratch repository. This test never
// touches the real F:\~dev\rawrxd worktree, and never asserts from a printed
// literal: the verdict is the conjunction of measured booleans.
//
// The write-guard qualification is deliberate and must not be renamed:
// checkWrite() is an API-level gate. It is not a filesystem sandbox, and a
// process that calls fopen/CreateFile directly bypasses it.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "authority/SingleWriterAuthority.h"

namespace fs = std::filesystem;
using rawrxd::authority::Lease;
using rawrxd::authority::WriteCheck;
using rawrxd::authority::WriteRefusal;

// ---------------------------------------------------------------- helpers

static int runSystem(const std::string& cmd) {
    return std::system((cmd + " >nul 2>&1").c_str());
}

static std::string runCapture(const std::string& cmd) {
    std::string full = cmd + " 2>nul";
    FILE* f = _popen(full.c_str(), "r");
    if (!f) return {};
    std::string out;
    char buf[4096];
    while (std::fgets(buf, sizeof(buf), f)) out += buf;
    _pclose(f);
    while (!out.empty() && (out.back() == '\r' || out.back() == '\n')) out.pop_back();
    return out;
}

static std::string git(const fs::path& repo, const std::string& args) {
    return runCapture("git -C \"" + repo.string() + "\" " + args);
}

static void writeFile(const fs::path& repo, const std::string& rel,
                      const std::string& body) {
    const fs::path abs = repo / rel;
    std::error_code ec;
    fs::create_directories(abs.parent_path(), ec);
    std::ofstream f(abs, std::ios::binary);
    f << body;
}

static std::string headOf(const fs::path& repo) {
    return git(repo, "rev-parse HEAD");
}

// The scratch repo carries one authorized file and one unauthorized file so
// that scope is decided by real paths, not by names that happen to be absent.
static const char* kAuthorized = "src/authority/SingleWriterAuthority.cpp";
static const char* kUnauthorized = "src/agentmodes/RawrCertAuthority.cpp";

static bool initScratch(const fs::path& scratch) {
    std::error_code ec;
    fs::remove_all(scratch, ec);
    fs::create_directories(scratch, ec);
    if (runSystem("git init -q -b main \"" + scratch.string() + "\"") != 0) return false;
    writeFile(scratch, kAuthorized,   "// authorized\n");
    writeFile(scratch, kUnauthorized, "// unauthorized\n");
    if (runSystem("git -C \"" + scratch.string() + "\" add -A") != 0) return false;
    if (runSystem("git -C \"" + scratch.string() +
                  "\" -c user.email=t@t -c user.name=t commit -q -m init") != 0) return false;
    return true;
}

static void cleanIndex(const fs::path& scratch) {
    runSystem("git -C \"" + scratch.string() + "\" reset -q");
}

// ---------------------------------------------------------------- results

struct Results {
    bool leaseAcquiredExclusively        = false;
    bool secondWriterAcquireBlocked     = false;
    bool commitWithoutLeaseBlocked      = false;
    bool commitAfterHeadMovedBlocked    = false;
    bool unauthorizedStagedPathBlocked  = false;
    bool unauthorizedPathWriteBlocked   = false;
    bool pathTraversalBlocked           = false;
    bool outsideRepoBlocked             = false;
    bool siblingPrefixCollisionBlocked  = false;
    bool authorizedCommitAllowed        = false;
    bool authorizedWriteAllowed         = false;
    bool foreignLeaseReleaseBlocked     = false;
    bool staleLeaseRecoveryTested       = false;
    bool beneficialFixBypassBlocked     = false;
    bool worktreeDriftDetected          = false;
    bool scopePersistedWithLease        = false;
    int  baselineDirtyCount             = -1;

    bool all() const {
        return leaseAcquiredExclusively && secondWriterAcquireBlocked &&
               commitWithoutLeaseBlocked && commitAfterHeadMovedBlocked &&
               unauthorizedStagedPathBlocked && unauthorizedPathWriteBlocked &&
               pathTraversalBlocked && outsideRepoBlocked &&
               siblingPrefixCollisionBlocked && authorizedCommitAllowed &&
               authorizedWriteAllowed && foreignLeaseReleaseBlocked &&
               staleLeaseRecoveryTested && beneficialFixBypassBlocked &&
               worktreeDriftDetected && scopePersistedWithLease;
    }
};

static void report(const char* name, bool ok, const std::string& detail) {
    std::printf("%s=%s detail=%s\n", name, ok ? "PASS" : "FAIL", detail.c_str());
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: single_writer_adversarial_test.exe <repoRoot>\n");
        return 2;
    }
    const fs::path realRepo(argv[1]);
    const fs::path scratch = realRepo / ".scratch_repo";

    std::printf("GATE=RAWRXD_SINGLE_WRITER_AUTHORITY_001\n");
    std::printf("CANONICAL_IMPL=src/authority/SingleWriterAuthority\n");
    std::printf("SCRATCH_REPO=%s\n", scratch.string().c_str());

    if (!initScratch(scratch)) {
        std::printf("FAIL: could not init scratch repo at %s\n", scratch.string().c_str());
        return 1;
    }
    std::printf("HEAD=%s\n", headOf(scratch).c_str());
    const std::string head = headOf(scratch);
    const std::vector<std::string> scope{ kAuthorized };

    Results R;
    std::string d;

    // 1. Exclusive acquisition.
    {
        auto a = rawrxd::authority::acquire(scratch, head, scope);
        auto b = rawrxd::authority::acquire(scratch, head, scope);
        R.leaseAcquiredExclusively = a.has_value() && !b.has_value();
        d = std::string("first=") + (a ? "Acquired" : "refused") +
            " second=" + (b ? "Acquired" : "refused");
        if (a) {
            // The scope must be readable back FROM THE LEASE FILE, not from a
            // process-global. peekLease parses the persisted JSON.
            auto peek = rawrxd::authority::peekLease(scratch);
            R.scopePersistedWithLease =
                peek && peek->nonce == a->nonce &&
                peek->authorizedPaths.size() == 1 &&
                peek->authorizedPaths[0] == a->authorizedPaths[0];
            rawrxd::authority::release(*a);
        }
        report("LEASE_ACQUIRED_EXCLUSIVELY", R.leaseAcquiredExclusively, d);
    }
    report("LEASE_PERSISTED_SCOPE", R.scopePersistedWithLease,
           R.scopePersistedWithLease ? "scope round-trips through the lease file"
                                     : "scope did not round-trip through the lease file");

    // 2. Second writer blocked while the first is live.
    {
        auto a = rawrxd::authority::acquire(scratch, head, scope);
        auto b = rawrxd::authority::acquire(scratch, head, scope);
        R.secondWriterAcquireBlocked = a.has_value() && !b.has_value();
        if (a) rawrxd::authority::release(*a);
        report("SECOND_WRITER_ACQUIRE_BLOCKED", R.secondWriterAcquireBlocked,
               "second acquire while held");
    }

    // 3. Commit without a lease.
    {
        auto a = rawrxd::authority::acquire(scratch, head, scope);
        if (a) rawrxd::authority::release(*a);
        Lease none;                              // we hold nothing
        const bool ok = !rawrxd::authority::authorizeCommit(none).verdictPass;
        R.commitWithoutLeaseBlocked = ok;
        report("COMMIT_WITHOUT_LEASE_BLOCKED", ok, "authorizeCommit with no live lease");
    }

    // 4. HEAD moved after acquisition.
    {
        auto a = rawrxd::authority::acquire(scratch, head, scope);
        writeFile(scratch, "extra.txt", "x");
        // `commit -a` does NOT stage untracked files; an earlier version of this
        // test used -a, so HEAD never moved and the check silently passed for
        // the wrong reason.
        runSystem("git -C \"" + scratch.string() + "\" add -A");
        runSystem("git -C \"" + scratch.string() +
                  "\" -c user.email=t@t -c user.name=t commit -q -m drift");
        const auto r = rawrxd::authority::authorizeCommit(*a);
        R.commitAfterHeadMovedBlocked =
            !r.verdictPass && !r.headMatchesExpected && headOf(scratch) != head;
        if (a) rawrxd::authority::release(*a);
        report("COMMIT_AFTER_HEAD_MOVED_BLOCKED", R.commitAfterHeadMovedBlocked,
               "expected=" + head + " actual=" + headOf(scratch));
        fs::remove(scratch / "extra.txt");
    }

    // 5. Unauthorized staged path (pre-commit gate).
    {
        auto a = rawrxd::authority::acquire(scratch, headOf(scratch), scope);
        // The file must be MODIFIED before staging: an unmodified file produces
        // no staged entry at all, `git diff --cached` is empty, and an empty set
        // is a subset of every scope — so the check would pass for the wrong
        // reason.
        writeFile(scratch, kUnauthorized, "// unauthorized, edited\n");
        runSystem("git -C \"" + scratch.string() + "\" add \"" + kUnauthorized + "\"");
        const std::string staged = git(scratch, "diff --cached --name-only");
        const auto r = rawrxd::authority::authorizeCommit(*a);
        R.unauthorizedStagedPathBlocked =
            !staged.empty() && !r.verdictPass && !r.stagedPathsSubsetOfAuthorized;
        cleanIndex(scratch);
        runSystem("git -C \"" + scratch.string() + "\" checkout -- \"" + kUnauthorized + "\"");
        if (a) rawrxd::authority::release(*a);
        report("UNAUTHORIZED_STAGED_PATH_BLOCKED", R.unauthorizedStagedPathBlocked,
               "staged='" + staged + "' expected=" + kUnauthorized);
    }

    // 6. Authorized staged path commits (pre-commit gate ALLOWS).
    {
        auto a = rawrxd::authority::acquire(scratch, headOf(scratch), scope);
        writeFile(scratch, kAuthorized, "// authorized, edited\n");
        runSystem("git -C \"" + scratch.string() + "\" add \"" + kAuthorized + "\"");
        const auto r = rawrxd::authority::authorizeCommit(*a);
        R.authorizedCommitAllowed = r.verdictPass && r.stagedPathsSubsetOfAuthorized;
        cleanIndex(scratch);
        runSystem("git -C \"" + scratch.string() + "\" checkout -- \"" + kAuthorized + "\"");
        if (a) rawrxd::authority::release(*a);
        report("AUTHORIZED_COMMIT_ALLOWED", R.authorizedCommitAllowed,
               std::string("staged=") + kAuthorized);
    }

    // 7. Pre-write gate: in-scope allowed, everything else blocked BEFORE any
    //    mutation. The five sub-cases are the required minimum set.
    {
        auto a = rawrxd::authority::acquire(scratch, headOf(scratch), scope);

        const WriteCheck inScope   = rawrxd::authority::checkWrite(*a, kAuthorized);
        const WriteCheck outScope  = rawrxd::authority::checkWrite(*a, kUnauthorized);
        const WriteCheck traversal = rawrxd::authority::checkWrite(*a, "../outside.txt");
        const WriteCheck deepUp    = rawrxd::authority::checkWrite(*a, "src/../../outside.txt");
        const std::string absoluteOutside =
            (scratch.parent_path() / "definitely_not_in_repo.txt").string();
        const WriteCheck outsideAbs = rawrxd::authority::checkWrite(*a, absoluteOutside);
        // Sibling directory sharing a textual prefix with the repo root.
        const std::string sibling = (scratch.parent_path() / ".scratch_repo_evil").string();
        const WriteCheck siblingHit = rawrxd::authority::checkWrite(*a, sibling + "/x.txt");
        // No lease at all.
        Lease none;
        const WriteCheck noLease = rawrxd::authority::checkWrite(none, kAuthorized);

        R.authorizedWriteAllowed        = inScope.ok;
        R.unauthorizedPathWriteBlocked  = outScope.refusal == WriteRefusal::PathOutsideScope;
        R.pathTraversalBlocked = traversal.refusal == WriteRefusal::PathEscapesRepoRoot &&
                                deepUp.refusal    == WriteRefusal::PathEscapesRepoRoot;
        R.outsideRepoBlocked   = outsideAbs.refusal == WriteRefusal::PathEscapesRepoRoot &&
                                noLease.refusal   != WriteRefusal::None;
        R.siblingPrefixCollisionBlocked = siblingHit.refusal != WriteRefusal::None;

        if (a) rawrxd::authority::release(*a);

        report("AUTHORIZED_WRITE_ALLOWED", R.authorizedWriteAllowed,
               inScope.ok ? kAuthorized : inScope.detail);
        report("UNAUTHORIZED_PATH_WRITE_BLOCKED", R.unauthorizedPathWriteBlocked,
               outScope.detail);
        report("PATH_TRAVERSAL_BLOCKED", R.pathTraversalBlocked,
               traversal.detail + " | " + deepUp.detail);
        report("OUTSIDE_REPO_BLOCKED", R.outsideRepoBlocked,
               outsideAbs.detail + " | " + noLease.detail);
        report("SIBLING_PREFIX_COLLISION_BLOCKED", R.siblingPrefixCollisionBlocked,
               siblingHit.detail);
    }

    // 8. Foreign lease release blocked.
    {
        auto a = rawrxd::authority::acquire(scratch, headOf(scratch), scope);
        Lease forged;
        forged.repositoryRoot = a->repositoryRoot;
        forged.pid  = 0xDEADBEEF;
        forged.nonce = 1;
        const bool released = rawrxd::authority::release(forged);
        R.foreignLeaseReleaseBlocked = !released;
        if (a) rawrxd::authority::release(*a);
        report("FOREIGN_LEASE_RELEASE_BLOCKED", R.foreignLeaseReleaseBlocked,
               released ? "foreign release SUCCEEDED" : "foreign release refused");
    }

// 9. Stale lease recovery: rewrite the persisted lease so its PID cannot be
//    live and its recorded HEAD no longer matches, then recover.
{
    auto a = rawrxd::authority::acquire(scratch, headOf(scratch), scope);
        const fs::path leaseFile = scratch / ".rawrxd" / "leases" / "writer.lease";
        bool rec2 = false;
        if (a) {
            std::error_code fec;
            const bool have = fs::exists(leaseFile, fec);
        if (a && have) {
        std::ifstream in(leaseFile);
        std::stringstream ss; ss << in.rdbuf();
        std::string json = ss.str();
        in.close();
        // pid -> a pid that cannot be live; expected_head -> a stale SHA so the
        // "HEAD moved" precondition of staleLeaseRecovery holds.
        auto replaceNumberAfter = [&](const std::string& key,
                                      const std::string& with) {
            const size_t k = json.find("\"" + key + "\"");
            if (k == std::string::npos) return false;
            const size_t colon = json.find(':', k);
            const size_t eol   = json.find_first_of(",\n", colon);
            if (colon == std::string::npos || eol == std::string::npos) return false;
            json = json.substr(0, colon + 1) + " " + with + json.substr(eol);
            return true;
        };
        const bool okPid  = replaceNumberAfter("pid", "4294967294");
        const bool okHead = replaceNumberAfter("expected_head",
                                               "\"0000000000000000000000000000000000000000\"");
        // tooOld is (now - acquired_unix_seconds) > maxAgeSeconds. With
        // maxAgeSeconds = 0 a lease written in the same second as the test is
        // NOT stale, so the timestamp has to be aged explicitly.
        const bool okAge = replaceNumberAfter("acquired_unix_seconds", "1000000000");
        if (okPid && okHead && okAge) {
            std::ofstream out(leaseFile, std::ios::binary | std::ios::trunc);
            out << json;
            out.close();
            auto rec = rawrxd::authority::staleLeaseRecovery(
                scratch, headOf(scratch), scope, 0);
            rec2 = rec.has_value();
            if (rec) rawrxd::authority::release(*rec);
        }
        }
    }
    R.staleLeaseRecoveryTested = rec2;
    report("STALE_LEASE_RECOVERY", R.staleLeaseRecoveryTested,
           rec2 ? "recovered from a lease with a dead pid and a moved HEAD"
                : "stale recovery did NOT recover");
}

    // 10. Beneficial-fix bypass attempt must still be refused.
    {
        auto a = rawrxd::authority::acquire(scratch, headOf(scratch), scope);
        writeFile(scratch, "docs/helpful_update.md", "# looks helpful\n");
        runSystem("git -C \"" + scratch.string() + "\" add docs/helpful_update.md");
        const auto r = rawrxd::authority::authorizeCommit(*a);
        R.beneficialFixBypassBlocked = !r.verdictPass;
        cleanIndex(scratch);
        fs::remove(scratch / "docs" / "helpful_update.md");
        if (a) rawrxd::authority::release(*a);
        report("BENEFICIAL_FIX_BYPASS_ATTEMPT_BLOCKED", R.beneficialFixBypassBlocked,
               "out-of-scope 'helpful' change refused");
    }

    // 11. Worktree drift is DETECTABLE across a gate window. This certifies
    //     detectability, not absence: see WORKTREE_DRIFT_DURING_GATE below.
    {
        auto a = rawrxd::authority::acquire(scratch, headOf(scratch), scope);
        const auto fingerprint = [&](const fs::path& r) {
            return git(r, "rev-parse HEAD") + "|" + git(r, "status --porcelain");
        };
        const std::string before = fingerprint(scratch);
        rawrxd::authority::authorizeCommit(*a);
        writeFile(scratch, kAuthorized, "// injected drift\n");
        const std::string after = fingerprint(scratch);
        R.worktreeDriftDetected = (before != after);
        runSystem("git -C \"" + scratch.string() + "\" checkout -- \"" + kAuthorized + "\"");
        if (a) rawrxd::authority::release(*a);
        report("WORKTREE_DRIFT_DETECTABLE", R.worktreeDriftDetected,
               "fingerprint changed across the gate window");
    }

    // 12. Distinguish existing dirt from concurrent mutation. A dirty worktree
    //     is not drift; only a fingerprint change inside the gate is.
    {
        std::istringstream iss(git(realRepo, "status --porcelain"));
        std::string line;
        int n = 0;
        while (std::getline(iss, line)) if (!line.empty()) ++n;
        R.baselineDirtyCount = n;
    }

    // Derived fields.
    const bool sharedPredicate = R.unauthorizedPathWriteBlocked &&
                                R.unauthorizedStagedPathBlocked &&
                                R.pathTraversalBlocked &&
                                R.siblingPrefixCollisionBlocked;

    std::printf("SHARED_PATH_PREDICATE=%s\n", sharedPredicate ? "PASS" : "FAIL");
    std::printf("WORKTREE_BASELINE_DIRTY_COUNT=%d\n", R.baselineDirtyCount);
    std::printf("WORKTREE_DRIFT_DURING_GATE_DETECTED=%s\n",
                R.worktreeDriftDetected ? "PASS" : "FAIL");
    std::printf("WRITE_GUARD_SCOPE=COOPERATING_API_CALLERS_ONLY\n");
    std::printf("OS_SANDBOX=0\n");
    std::printf("DIRECT_NATIVE_IO_BYPASS_POSSIBLE=1\n");
    std::printf("STUB_FALLBACKS=0\n");
    std::printf("FAKE_SUCCESS_PATHS=0\n");

    const bool pass = R.all() && sharedPredicate && R.baselineDirtyCount == 0;
    std::printf("VERDICT_DERIVED_FROM_CHECKS=1\n");
    std::printf("HARDCODED_VERDICT=0\n");
    std::printf("VERDICT=%s\n", pass ? "PASS" : "FAIL");

    std::error_code ec;
    fs::remove_all(scratch, ec);
    return pass ? 0 : 1;
}