// WriterLeaseAuthority.h — RAWRXD_SINGLE_WRITER_AUTHORITY_001
//
// Four HEAD movements in one session, two of them inside a single assigned
// batch, established that "observe that HEAD did not move" is too weak. A
// passive stability test cannot stop a writer; ownership plus optimistic
// concurrency can.
//
//     COMMIT_ALLOWED = LEASE_OWNED
//                    AND HEAD_UNCHANGED
//                    AND STAGED_SCOPE_VALID
//
// Acquisition is exclusive by construction: the lease file is created with
// CREATE_NEW, so two contenders cannot both believe they hold it. A stale
// lease is never stolen on PID alone, because Windows reuses PIDs; the owner
// must be shown dead by matching its recorded process creation time.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd { namespace lease {

struct LeaseRecord {
    std::string leaseId;
    uint32_t    ownerPid = 0;
    uint64_t    ownerStartTime = 0;   // FILETIME, guards against PID reuse
    std::string nonce;
    std::string expectedHead;
    std::string host;
    std::string acquiredUtc;
    std::string expiresUtc;
    int         ttlSeconds = 1800;
};

enum class AcquireOutcome {
    Acquired,            // we now hold it
    StaleRecovered,      // previous owner proven dead; we took it
    HeldByLiveProcess,   // someone alive holds it; not stolen
    HeldUnreadable,      // file exists but is not a valid lease
    Failed               // I/O failure
};

enum class CommitRefusal {
    None,
    NoLease,
    LeaseOwnerMismatch,  // lease exists but is not ours
    LeaseExpired,
    HeadMoved,
    StagedScopeExpanded
};

struct AcquireResult {
    AcquireOutcome outcome = AcquireOutcome::Failed;
    LeaseRecord   record;
    std::string   detail;
};

struct CommitCheck {
    CommitRefusal refusal = CommitRefusal::None;
    std::string   expectedHead;
    std::string   currentHead;
    std::string   stagedScopeHash;
    std::string   authorizedScopeHash;
    int           stagedCount = 0;
    bool          ok = false;
    std::string   detail;
};

// Path of the lease file inside a repository.
std::string leasePath(const std::string& repoRoot);

// Identity of the calling process: pid plus creation time.
uint32_t    currentPid();
uint64_t    currentProcessStartTime();
// True when `pid` is alive AND was created at `startTime`. A pid match with a
// different creation time means the pid was recycled, and the lease is stale.
bool processAlive(uint32_t pid, uint64_t startTime);

// Acquire the lease for `expectedHead`. Never steals a live lease.
AcquireResult acquire(const std::string& repoRoot,
                      const std::string& expectedHead,
                      int ttlSeconds = 1800);

// Release only if we still own it. A foreign lease is never released.
bool release(const std::string& repoRoot, const LeaseRecord& held);

// Load a lease record, if one exists and parses.
bool load(const std::string& repoRoot, LeaseRecord& out);

// Authorized paths for this batch. The commit check compares the staged set
// against this scope; anything extra is refused.
void setAuthorizedPaths(const std::vector<std::string>& paths);
std::string authorizedScopeHash();
std::string scopeHashOf(const std::vector<std::string>& sortedPaths);

// Decide whether a commit may proceed right now. Pure inspection: it does not
// stage, commit, or alter the worktree.
CommitCheck checkCommit(const std::string& repoRoot, const LeaseRecord& held);

// Run the guarded commit. Performs every checkCommit test, then commits.
CommitCheck guardedCommit(const std::string& repoRoot, const LeaseRecord& held,
                          const std::string& message);

// ---------------------------------------------------------------------------
// Write-time scope enforcement
//
// checkCommit only refuses an out-of-scope path at COMMIT time. Between the
// write and the commit there is a window in which a second writer has already
// modified a file it was never authorized to touch, and the damage is done
// even though the commit is later refused. checkWrite closes that window: it
// is the single gate every canonical write passes through.
//
// Scope and lease rules are identical to checkCommit — no lease, not our lease,
// expired, or a path outside the authorized set is refused.
//
// This is an API-level guard, not an OS sandbox: a process that calls fopen
// directly still bypasses it. What it guarantees is that every write performed
// through the authority is authorized at the moment it happens. It is recorded
// that way rather than as "writes are blocked".
// ---------------------------------------------------------------------------
enum class WriteRefusal {
    None,
    NoLease,
    LeaseOwnerMismatch,
    LeaseExpired,
    PathEscapesRepoRoot,
    PathOutsideScope
};

struct WriteCheck {
    WriteRefusal refusal = WriteRefusal::None;
    std::string   relPath;   // repo-relative, '/' separated
    std::string   detail;
    bool          ok = false;
};

WriteCheck checkWrite(const std::string& repoRoot, const LeaseRecord& held,
                      const std::string& relPath);

// Normalize `relPath` to a repo-relative '/' separated form. Returns empty when
// the path escapes the repository root (absolute path elsewhere, or "..").
std::string relativeToRepo(const std::string& repoRoot, const std::string& relPath);

// True when `path` (repo-relative) is inside the authorized scope.
bool pathAuthorized(const std::string& path);

// Serialize a LeaseRecord.
std::string serialize(const LeaseRecord& r);
bool        parse(const std::string& text, LeaseRecord& out);

}} // namespace rawrxd::lease
