// ============================================================================
// GitSafetyAuthority.h — RAWRXD_GIT_SAFETY_AUTHORITY_001
//
// Git being IMPLEMENTED is not git being SAFE. `git status` and `git commit`
// both work today in this tree (src/core/feature_handlers.cpp shells out to
// _popen, and AgentCore/ResponseCodedAgent read git_status through a
// no-shell runner). What does not exist anywhere is a gate that decides
// whether an AUTONOMOUS agent may perform a MUTATING git operation against a
// working tree that may already contain someone else's uncommitted work.
//
// This authority is that gate. It provides all twelve certified capabilities:
//
//   status          git.status      read-only
//   diff            git.diff        read-only
//   stage/unstage   git.stage       MUTATES THE INDEX
//   commit          git.commit      MUTATES HISTORY
//   branch          git.branch      MUTATES REFS
//   checkout        git.checkout    MUTATES THE WORKTREE
//   conflicts       git.conflicts   read-only
//   dirty-tree      git.dirty_tree  read-only baseline
//   stash/recovery  git.stash       MUTATES THE WORKTREE
//   worktree        git.worktree    MUTATES THE WORKTREE
//   diff review     git.review      read-only
//   rollback        git.rollback    MUTATES THE WORKTREE
//
// Three rules make the difference between "implemented" and "safe":
//
//  1. DEFAULT DENY. A capability that is not explicitly granted is refused
//     with a reason. There is no capability that mutates anything without an
//     explicit grant, and no grant implies scope.
//
//  2. THE BASELINE IS NOT DIRT. A dirty working tree is a normal state, not
//     drift, and it is not a reason to refuse. The authority records the
//     pre-existing state at beginSession() — the HEAD, the staged set, the
//     unstaged set, the untracked set, and a content fingerprint per dirty
//     path — and that baseline is what every later check is measured against.
//     (This is the same distinction the project ledger records as
//     WORKTREE_BASELINE_DIRTY_COUNT vs WORKTREE_DRIFT_DURING_GATE. They are
//     separate properties and are certified separately.)
//
//  3. UNRELATED WORK SURVIVES. A mutating call is refused, or scoped, unless
//     every path it would touch is inside the caller's authorized scope. A
//     path that was dirty BEFORE the session began and is outside the scope
//     must come back byte-identical after any agent operation. That property
//     is the dangerous test, and it is measured here, not asserted.
//
// Threading: a Session is NOT thread-safe and is deliberately not made so. It
// is scoped to one agent turn against one repository. Concurrent mutation is
// detected structurally, by re-reading git immediately before each mutating
// call and comparing against the baseline — not by locking, because a lock
// cannot see a second process.
// ============================================================================
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace rawrxd {
namespace agentic {

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

// One bit per mutating capability. Read-only capabilities are listed for
// receipt completeness but are not gated: they cannot change repository state.
enum class GitCapability : std::uint32_t {
    None            = 0,
    Stage           = 1u << 0,
    Unstage         = 1u << 1,
    Commit          = 1u << 2,
    Branch          = 1u << 3,
    Checkout        = 1u << 4,
    Stash           = 1u << 5,
    Worktree        = 1u << 6,
    Rollback        = 1u << 7,
    ReadOnly        = 1u << 8,   // status / diff / conflicts / dirty_tree / review
};

constexpr GitCapability operator|(GitCapability a, GitCapability b) {
    return static_cast<GitCapability>(static_cast<std::uint32_t>(a) |
                                      static_cast<std::uint32_t>(b));
}
constexpr bool HasCapability(std::uint32_t granted, GitCapability c) {
    return (granted & static_cast<std::uint32_t>(c)) == static_cast<std::uint32_t>(c) &&
           static_cast<std::uint32_t>(c) != 0u;
}

struct GitPolicy {
    // Capabilities actually granted. DEFAULT IS EMPTY: nothing mutates.
    std::uint32_t granted = 0;

    // Repository-relative path prefixes this caller may mutate. Empty means
    // no path is mutable, so every mutating call is refused for scope even if
    // the capability bit is set. A grant without scope is not an authorization.
    std::vector<std::string> authorizedPrefixes;

    // Absolute roots the repository itself may live under. The authority
    // refuses to operate on a repository outside these roots, so a caller
    // cannot point the agent at an arbitrary directory.
    std::vector<std::string> repositoryRoots;

    // Refuse checkout/reset/rollback style operations that would discard
    // uncommitted work. Default true. Setting it false is a deliberate,
    // recorded loss of protection, not a default.
    bool requireCleanForDestructive = true;

    // Never allow push. It is not an enum value. Pushing is not a
    // certification target for a local agent and is structurally absent.
    static GitPolicy DefaultDenyAll();
};

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

enum class GitRefusal : std::uint8_t {
    None = 0,
    CapabilityNotGranted,
    NoScope,
    PathEscapesRepository,
    PathOutsideScope,
    NotAGitRepository,
    RepositoryRootNotAllowed,
    UnmergedPathsPresent,   // conflict marker state: refuse rather than guess
    DirtyTreeDestructive,   // would discard uncommitted work
    NothingToDo,
    GitFailed,
};

const char* GitRefusalName(GitRefusal r);

struct GitResult {
    bool ok = false;
    GitRefusal refusal = GitRefusal::None;
    std::string detail;          // refusal reason, or measured summary
    std::string output;          // captured stdout (bounded)
    std::string errorOutput;     // captured stderr (bounded)
    int exitCode = 0;
    bool timedOut = false;

    bool refused() const { return refusal != GitRefusal::None; }
};

// One dirty path, classified. `staged` and `worktree` are the two independent
// axes git reports; a path can be modified in the worktree and still unstaged.
struct PathState {
    std::string path;            // repository-relative, '/' separated
    char indexStatus = ' ';      // git status --porcelain column 1
    char worktreeStatus = ' ';   // git status --porcelain column 2
    bool untracked = false;
    bool unmerged = false;

    bool staged() const { return indexStatus != ' ' && indexStatus != '?'; }
    bool modifiedInWorktree() const { return worktreeStatus != ' '; }
};

// The pre-existing state, captured before any agent action. This is the
// reference every preservation check is measured against.
struct GitBaseline {
    bool captured = false;
    std::string head;                       // 40-hex or empty on unborn HEAD
    std::string branch;                     // symbolic name, may be empty
    std::vector<PathState> paths;           // every dirty path at capture time
    // path -> "size:sha256hex" of the working-tree bytes at capture time.
    // A path absent from this map was clean (or untracked-and-absent) then.
    std::map<std::string, std::string> fingerprints;

    std::size_t dirtyCount() const;
    std::size_t stagedCount() const;
    std::size_t untrackedCount() const;
    std::size_t unmergedCount() const;
    std::vector<std::string> dirtyPathList() const;
};

// The outcome of a full safety sweep, written to the receipt.
struct GitSafetyReceipt {
    std::string repositoryRoot;
    std::string headAtBegin;
    std::string headAtEnd;
    std::string branchAtBegin;
    std::string branchAtEnd;

    std::uint32_t capabilitiesGranted = 0;

    // Measured counts, all read from git at their own moment.
    std::size_t baselineDirtyCount = 0;
    std::size_t baselineStagedCount = 0;
    std::size_t baselineUntrackedCount = 0;
    std::size_t finalDirtyCount = 0;

    // The preservation property, measured per path.
    std::size_t unrelatedPathsTracked = 0;
    std::size_t unrelatedPathsPreserved = 0;
    std::vector<std::string> unrelatedPathsViolated;

    // Refusal behaviour, measured.
    std::size_t mutatingCallsAttempted = 0;
    std::size_t mutatingCallsRefused = 0;
    std::size_t mutatingCallsExecuted = 0;

    // Per-capability measured outcome. True means "the capability was
    // exercised and produced its expected result", never "it was skipped".
    std::map<std::string, bool> capabilityChecks;

    bool verdictPass = false;
    std::string verdictText;
};

// ---------------------------------------------------------------------------
// The authority
// ---------------------------------------------------------------------------

class GitSafetyAuthority {
public:
    explicit GitSafetyAuthority(GitPolicy policy);
    ~GitSafetyAuthority();

    GitSafetyAuthority(const GitSafetyAuthority&) = delete;
    GitSafetyAuthority& operator=(const GitSafetyAuthority&) = delete;

    // Opens `repoPath` and records the pre-existing state. Fails if the path
    // is not a git work tree, or is not under a policy repositoryRoot.
    GitResult beginSession(const std::filesystem::path& repoPath);

    // Re-reads status without mutating. The baseline is NOT re-captured; that
    // would erase the record of what the user had before the agent started.
    GitResult refresh(std::vector<PathState>& outPaths);

    const GitBaseline& baseline() const { return baseline_; }
    const GitPolicy& policy() const { return policy_; }
    const std::string& repositoryRoot() const { return repoRoot_; }
    const std::vector<std::string>& violations() const { return violations_; }

    // ---- read-only capabilities ----
    GitResult status();
    GitResult diff(bool staged, std::size_t maxBytes);
    GitResult conflicts();
    GitResult dirtyTree();
    // Agent-generated diff review: the diff restricted to the caller's scope,
    // plus the paths that are dirty OUTSIDE that scope, so a reviewer sees the
    // work the agent did NOT do alongside the work it did.
    GitResult reviewAgentDiff(std::size_t maxBytes);

    // ---- mutating capabilities ----
    GitResult stage(const std::vector<std::string>& paths);
    GitResult unstage(const std::vector<std::string>& paths);
    // Commits only the paths given. Refuses if any staged path outside the
    // authorized scope exists, so an agent cannot sweep a user's staged work
    // into its own commit.
    GitResult commit(const std::string& message, const std::vector<std::string>& paths);
    GitResult createBranch(const std::string& name);
    GitResult checkout(const std::string& ref);
    GitResult stash(const std::string& message);
    GitResult stashPop();
    GitResult addWorktree(const std::string& relativeDir);
    GitResult removeWorktree(const std::string& relativeDir, bool force);
    GitResult listWorktrees();
    // Restores a path to its baseline content. Only in-scope paths, only to
    // bytes recorded in the baseline, and never when the repository has
    // unmerged paths.
    GitResult rollback(const std::vector<std::string>& paths);

    // Verifies that every path which was dirty at beginSession and is outside
    // the authorized scope is still byte-identical. This is the dangerous
    // test's predicate, exposed so the certification driver can measure it
    // rather than trust a return code.
    bool verifyUnrelatedPreserved(std::vector<std::string>& outViolations);

    // Compares current state to the baseline. Fills the receipt from live
    // measurements. verdictPass is derived from measured booleans only.
    GitSafetyReceipt finalize();

private:
    struct RunOutput {
        int exitCode = 0;
        std::string out;
        std::string err;
        bool timedOut = false;
        bool spawnFailed = false;
    };

    GitPolicy policy_;
    std::string repoRoot_;
    GitBaseline baseline_;
    std::vector<std::string> violations_;
    std::size_t mutatingAttempted_ = 0;
    std::size_t mutatingRefused_ = 0;
    std::size_t mutatingExecuted_ = 0;
    bool sessionOpen_ = false;

    RunOutput runGit(const std::vector<std::string>& args, std::size_t capBytes = 1u << 18) const;
    GitResult fail(GitRefusal r, std::string detail) const;

    // Resolves a caller-supplied path to a repository-relative form and
    // confirms it stays inside the repository. Empty on refusal.
    std::string resolveInsideRepo(const std::string& candidate,
                                  GitRefusal& refusal,
                                  std::string& detail) const;

    // True when the repository-relative path is inside an authorized prefix.
    bool inScope(const std::string& relPath) const;
    // True when the repository-relative path was dirty at beginSession and is
    // outside the authorized scope.
    bool isUnrelatedUserPath(const std::string& relPath) const;

    std::string headSha() const;
    std::string currentBranch() const;
    std::vector<PathState> readStatus() const;
    std::vector<std::string> readStagedPaths() const;
    std::vector<std::string> readUnmergedPaths() const;
    std::string fingerprintOf(const std::string& relPath) const;
    bool repositoryRootAllowed(const std::filesystem::path& canonical) const;

    // Gates every mutating call. Returns a refusal result, or an ok-marked
    // sentinel when the call may proceed.
    GitResult authorizeMutation(GitCapability capability,
                                const std::vector<std::string>& targetPaths,
                                bool destructive);
    void recordViolation(const std::string& path);
};

// Exposed for testing: the status parser. Kept next to the authority so the
// parsing rule and its consumer cannot drift apart.
std::vector<PathState> ParsePorcelainStatus(const std::string& porcelain);

} // namespace agentic
} // namespace rawrxd
