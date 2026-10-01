// SingleWriterAuthority.h — RAWRXD_SINGLE_WRITER_AUTHORITY_001
//
// Frozen contract per bootstrap step 2:
//   acquire(expectedHead, allowedPaths)
//   validateHead()
//   validateStagingScope()
//   authorizeCommit()   — REQUIRES ALL THREE PREDICATES SIMULTANEOUSLY
//   release()
//   staleLeaseRecovery(...)
//
// Lease identity (unforgeable enough for local authority):
//   repository identity, PID, random nonce, expected HEAD, acquisition
//   timestamp, normalized authorized path set. A caller that knows only
//   another writer's PID cannot release its lease.
//
// Authorization model:
//   authorizeCommit() returns true only if
//     owns exclusive lease
//     AND current HEAD == expected HEAD
//     AND staged paths ⊆ authorized paths
//   Failure of any predicate fails closed.
//
// All destructive/adversarial scenarios (HEAD movement, staging
// violations, competing leases, stale leases, foreign releases) MUST be
// exercised against isolated temporary repositories in the test. This
// authority implementation must not manipulate the real F:\~dev\rawrxd
// repository.
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <optional>

namespace rawrxd::authority {

// Result of an authorizeCommit call. Every field is measured/derived.
struct AuthorizeResult {
    bool exclusiveLeaseAcquired = false;
    bool headMatchesExpected    = false;
    bool stagedPathsSubsetOfAuthorized = false;

    // Per-test booleans. Each is set by the corresponding validation
    // step. The final verdict is derived from these booleans, not printed.
    bool secondWriterAcquireBlocked   = false; // Test A
    bool commitWithoutLeaseBlocked    = false; // implies exclusiveLease
    bool commitAfterHeadMovedBlocked  = false; // Test B
    bool unauthorizedStagedPathBlocked = false; // Layer 3
    bool foreignLeaseReleaseBlocked   = false;
    bool staleLeaseRecoveryTested     = false;
    bool beneficialFixBypassAttemptBlocked = false;

    // Final verdict (derived).
    bool verdictPass = false;
    std::string verdictText;
};

// Lease token returned by acquire(). Carries all identity fields.
struct Lease {
    std::string repositoryRoot;       // normalized canonical path
    std::uint32_t pid = 0;
    std::uint64_t nonce = 0;
    std::string expectedHead;          // hex SHA
    std::int64_t acquiredUnixSeconds = 0;
    std::vector<std::string> authorizedPaths; // normalized
    std::filesystem::path leaseFile;  // absolute

    bool valid() const { return !repositoryRoot.empty() && nonce != 0; }
};

// Acquire an exclusive lease for the repository rooted at repoRoot.
// expectedHead MUST be the SHA the caller believes HEAD currently is.
// allowedPaths are normalized to absolute paths; relative paths are
// resolved against repoRoot.
//
// Returns std::nullopt if the lease cannot be acquired (someone else
// owns it OR the lease file is malformed OR identity constraints fail).
std::optional<Lease> acquire(
    const std::filesystem::path& repoRoot,
    const std::string& expectedHead,
    const std::vector<std::string>& allowedPaths);

// Run validateHead against the lease's expected HEAD.
// Returns true iff `git rev-parse HEAD` in repoRoot equals lease.expectedHead.
// On false, the lease remains valid until release() — the test of HEAD
// movement is the gate, not lease revocation.
bool validateHead(const Lease& lease);

// Run validateStagingScope against the lease.
// Returns true iff `git diff --cached --name-only` paths are all members
// of lease.authorizedPaths (after normalization). Empty staging set is
// rejected for authorizeCommit() but reported here as scope-match.
bool validateStagingScope(const Lease& lease);

// Run the three-predicate conjunction. Fills the result struct and
// returns verdictPass.
AuthorizeResult authorizeCommit(const Lease& lease);

// Release the lease owned by the caller (must match lease.pid + nonce).
// Foreign release is BLOCKED — the caller's identity must match.
bool release(const Lease& lease);

// Attempt recovery of a stale lease:
//   - Lease file exists but is older than maxAgeSeconds AND
//   - The PID recorded in the lease is no longer live AND
//   - The HEAD recorded in the lease no longer matches repo HEAD
// Recovery writes a NEW lease under a fresh nonce only if all three hold.
// Returns the new lease on success, std::nullopt otherwise.
std::optional<Lease> staleLeaseRecovery(
    const std::filesystem::path& repoRoot,
    const std::string& expectedHead,
    const std::vector<std::string>& allowedPaths,
    std::int64_t maxAgeSeconds);

// Test helper: is the given pid currently live on the local machine?
// Used by staleLeaseRecovery and by the foreign-lease test.
bool isProcessLive(std::uint32_t pid);

// Test helper: read the current lease file for a repo root without
// acquiring it. Used by adversarial tests.
std::optional<Lease> peekLease(const std::filesystem::path& repoRoot);

// Normalize a path: convert to absolute, canonicalize separators, and
// resolve symlinks (best-effort; no-throw on filesystem errors).
std::string normalizePath(const std::filesystem::path& p);

// ---------------------------------------------------------------------------
// Pre-write authorization — RAWRXD_SINGLE_WRITER_AUTHORITY_001
//
// validateStagingScope refuses an out-of-scope path at COMMIT time. Between the
// write and the commit there is a window in which a second writer has already
// modified a file it was never authorized to touch, and the damage survives the
// later refusal. checkWrite closes that window.
//
// checkWrite and validateStagingScope consume the SAME predicate,
// pathAuthorized, and the SAME path resolution, relativeToRepo. There is one
// parser and one membership rule in this authority, not two.
//
// Scope comes from lease.authorizedPaths — the copy persisted in the lease file
// — not from any process-global set, so it survives a second process reading
// the lease back.
// ---------------------------------------------------------------------------

enum class WriteRefusal {
    None,
    NoLease,
    LeaseOwnerMismatch,
    PathEscapesRepoRoot,
    PathOutsideScope
};

struct WriteCheck {
    WriteRefusal refusal = WriteRefusal::None;
    std::string   relPath;   // repo-relative, '/' separated
    std::string   detail;
    bool          ok = false;
};

// Resolve `path` to a repo-relative, '/' separated form.
//
// Returns empty — meaning REFUSED — when the path escapes the repository:
//   - a ".." component anywhere in the input,
//   - an absolute path that does not begin with the repository root,
//   - a sibling directory that merely shares a textual prefix with the root
//     ("F:\repo-evil" is NOT inside "F:\repo").
//
// Comparison is component-by-component, never a string prefix, so the sibling
// case cannot pass.
std::string relativeToRepo(const Lease& lease, const std::string& path);

// The single authorization predicate. True iff the resolved path is inside the
// repository AND is a member of lease.authorizedPaths.
bool pathAuthorized(const Lease& lease, const std::string& path);

// Pre-write gate. Refuses when there is no lease, the lease on disk is not ours,
// the path escapes the repository, or the path is outside the authorized set.
//
// WRITE_GUARD_SCOPE: this is an API-level guard, not an OS sandbox. A process
// that calls fopen/CreateFile directly bypasses it. What it guarantees is that
// every write performed THROUGH the authority is authorized when it happens.
WriteCheck checkWrite(const Lease& lease, const std::string& path);

} // namespace rawrxd::authority
