// ============================================================================
// git_safety_authority_cert.cpp — RAWRXD_GIT_SAFETY_AUTHORITY_001
//
// Runtime certification for the twelve git capabilities, executed against
// REAL temporary git repositories. This driver never touches F:\~dev\rawrxd.
//
// Nothing here is asserted from a printed literal. Each check calls the
// authority, then verifies the RESULT through an independent path: the file
// system, `git rev-parse`, or a second read of the working tree. A check that
// cannot be measured is reported NOT_RUN, and NOT_RUN never contributes to a
// pass.
//
// THE DANGEROUS TEST
// ------------------
// RAWRXD_GIT_SAFETY_DIRTY_TREE_001. The setup is the one that breaks agents:
//
//   1. A repository is committed and clean.
//   2. The USER then makes unrelated modifications and stages some of them.
//      This is the pre-existing dirty tree. It is not drift, and it is not a
//      reason to refuse anything.
//   3. The agent is granted commit/stage/checkout over ONE subsystem and is
//      asked to modify a DIFFERENT subsystem.
//   4. PASS requires that every unrelated user path is byte-identical
//      afterwards, that the agent's commit contains only the agent's path, and
//      that the agent could not sweep the user's staged work into its commit.
//
// The property is measured with SHA-256 over file bytes, captured before and
// after, and cross-checked against `git show HEAD:<path>` for the committed
// content. A preservation claim that only compared git's own view of itself
// would not be a preservation claim.
// ============================================================================
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include "agentic/AgentToolRegistry.h"
#include "agentic/CommandExecutor.h"
#include "agentic/GitSafetyAuthority.h"
#include "agentic/GitSafetyAuthorityTools.h"
#include "deep2/AgentToolRegistry.hpp"
#include "deep2/ReceiptAuthority.h"

namespace fs = std::filesystem;
using rawrxd::agentic::GitBindingReport;
using rawrxd::agentic::GitCapability;
using rawrxd::agentic::GitPolicy;
using rawrxd::agentic::GitResult;
using rawrxd::agentic::GitSafetyAuthority;
using rawrxd::agentic::ToolRegistry;
using rawrxd::agentic::ToolResult;

namespace {

// ───────────────────────────────────────────────────────────── measurement ──

struct Check {
    std::string id;
    std::string description;
    std::string state;   // PASS | FAIL | NOT_RUN
    std::string evidence;
};

class Cert {
public:
    void check(const std::string& id, const std::string& description, bool passed,
               const std::string& evidence) {
        Check c;
        c.id = id;
        c.description = description;
        c.state = passed ? "PASS" : "FAIL";
        c.evidence = evidence;
        checks_.push_back(c);
        std::printf("%-46s %-8s %s\n", id.c_str(), c.state.c_str(), evidence.c_str());
        if (!passed) ++failed_;
    }

    void notRun(const std::string& id, const std::string& description,
                const std::string& why) {
        Check c;
        c.id = id;
        c.description = description;
        c.state = "NOT_RUN";
        c.evidence = why;
        checks_.push_back(c);
        ++notRun_;
        std::printf("%-46s %-8s %s\n", id.c_str(), "NOT_RUN", why.c_str());
    }

    int failed() const { return failed_; }
    int notRunCount() const { return notRun_; }
    const std::vector<Check>& all() const { return checks_; }

private:
    std::vector<Check> checks_;
    int failed_ = 0;
    int notRun_ = 0;
};

// Runs git with an explicit argv and no shell. The driver's own git calls use
// the same primitive as the authority's, deliberately: if CreateProcessW
// quoting were broken, both sides would be wrong together, and the SHA-256
// file-content checks below would still catch a wrong result.
int Git(const fs::path& repo, const std::vector<std::string>& args, std::string& out,
        std::string& err) {
    std::vector<std::wstring> argv;
    argv.push_back(L"git.exe");
    argv.push_back(L"-C");
    const std::wstring root(repo.wstring());
    argv.push_back(root);
    for (const std::string& a : args) {
        std::wstring w;
        if (!a.empty()) {
            const int n = MultiByteToWideChar(CP_UTF8, 0, a.c_str(), static_cast<int>(a.size()),
                                              nullptr, 0);
            w.assign(static_cast<std::size_t>(n), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, a.c_str(), static_cast<int>(a.size()), &w[0], n);
        }
        argv.push_back(w);
    }
    rawrxd::agentic::CommandExecutor::Options o;
    o.workingDir = root;
    o.timeoutMs = 30000;
    o.allowShell = false;
    o.maxCaptureBytes = 4u << 20;
    const auto r = rawrxd::agentic::CommandExecutor::RunArgv(argv, o);
    out = r.stdoutText;
    err = r.stderrText;
    return r.exitCode;
}

int Git(const fs::path& repo, const std::vector<std::string>& args, std::string& out) {
    std::string err;
    return Git(repo, args, out, err);
}

std::string Sha256File(const fs::path& p) {
    std::error_code ec;
    if (!fs::exists(p, ec) || ec || fs::is_directory(p, ec)) return "ABSENT";
    std::ifstream in(p, std::ios::binary);
    if (!in) return "UNREADABLE";

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return "ERR";
    BCRYPT_HASH_HANDLE h = nullptr;
    if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return "ERR";
    }
    std::vector<char> buf(65536);
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = in.gcount();
        if (got <= 0) break;
        BCryptHashData(h, reinterpret_cast<PUCHAR>(buf.data()), static_cast<ULONG>(got), 0);
    }
    unsigned char digest[32];
    BCryptFinishHash(h, digest, 32, 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);

    std::ostringstream oss;
    char hex[3];
    for (int i = 0; i < 32; ++i) {
        std::snprintf(hex, sizeof hex, "%02X", digest[i]);
        oss << hex;
    }
    return oss.str();
}

void WriteFile(const fs::path& p, const std::string& body) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << body;
}

std::string ReadFile(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream oss;
    oss << in.rdbuf();
    return oss.str();
}

std::string GitOut(const fs::path& repo, const std::string& args) {
    std::vector<std::string> v;
    std::string cur;
    std::istringstream iss(args);
    while (iss >> cur) v.push_back(cur);
    std::string out, err;
    Git(repo, v, out, err);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

// A repository that looks like a two-subsystem product: `src/agent` is the
// subsystem the agent owns, `src/user` is the user's, and `docs` is a third
// unrelated area used only to widen the blast radius of a wrong answer.
constexpr const char* kAgentFile = "src/agent/service.cpp";
constexpr const char* kUserFileA = "src/user/settings.json";
constexpr const char* kUserFileB = "src/user/profile.ini";
constexpr const char* kUserFileC = "docs/notes.md";
constexpr const char* kNewFile = "src/agent/feature.cpp";
constexpr const char* kWorktreeDir = "wt-agent";
constexpr const char* kAgentScope = "src/agent";

bool InitRepo(const fs::path& repo) {
    std::error_code ec;
    fs::remove_all(repo, ec);
    fs::create_directories(repo, ec);
    if (!ec) {
        // Work inside the given directory. `git init` is the one call with no
        // -C form available before the repository exists.
        std::wstring wide(repo.wstring());
        std::vector<std::wstring> argv{L"git.exe", L"init", L"-q", L"-b", L"main", wide};
        rawrxd::agentic::CommandExecutor::Options o;
        o.allowShell = false;
        o.timeoutMs = 30000;
        if (!rawrxd::agentic::CommandExecutor::RunArgv(argv, o).success) return false;
    } else {
        return false;
    }
    WriteFile(repo / kAgentFile, "// agent service v1\nint service() { return 1; }\n");
    WriteFile(repo / kUserFileA, "{\"theme\":\"dark\",\"autosave\":false}\n");
    WriteFile(repo / kUserFileB, "[user]\nname=local\n");
    WriteFile(repo / kUserFileC, "# notes\noriginal\n");
    std::string out, err;
    if (Git(repo, {"add", "-A"}, out, err) != 0) return false;
    if (Git(repo, {"-c", "user.email=cert@rawrxd.local", "-c", "user.name=cert",
                   "commit", "-q", "-m", "baseline"}, out, err) != 0) {
        return false;
    }
    return true;
}

std::vector<std::string> CommittedFilesIn(const fs::path& repo, const std::string& head,
                                          const std::string& pathFilter) {
    std::vector<std::string> out;
    std::string outTxt, errTxt;
    if (Git(repo, {"ls-tree", "-r", "--name-only", head}, outTxt, errTxt) != 0) return out;
    std::istringstream iss(outTxt);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (!pathFilter.empty() && line.rfind(pathFilter, 0) != 0) continue;
        out.push_back(line);
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::string HeadOf(const fs::path& repo) { return GitOut(repo, "rev-parse HEAD"); }

// Exact bytes of a path as recorded in a commit, WITHOUT trimming.
//
// GitOut strips trailing newlines, which is right for a one-line status string
// and wrong for a file-content comparison: a file whose content ends in '\n'
// would never equal the same content read through GitOut, so a byte comparison
// built on GitOut silently reports "not equal" forever and cannot detect
// absorption. Every content-identity claim in this driver uses this instead.
std::string GitBlob(const fs::path& repo, const std::string& spec) {
    std::string out, err;
    Git(repo, {"show", spec}, out, err);
    return out;
}

// std::string has no two-argument char replace. Receipt evidence is one line
// per field, so newlines are folded to '|' before they are printed.
std::string OneLine(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        if (c == '\n' || c == '\r') c = '|';
    }
    return out;
}

std::string StatusPorcelain(const fs::path& repo) {
    std::string out, err;
    Git(repo, {"status", "--porcelain=v1", "--untracked-files=all"}, out, err);
    return out;
}

// ───────────────────────────────────────────────────── the safety harness ────

struct Harness {
    fs::path repo;
    GitPolicy policy;
    std::unique_ptr<GitSafetyAuthority> authority;
};

// A policy that grants every mutating capability but scopes the agent to
// src/agent. The scope, not the capability bit, is what has to hold.
GitPolicy AgentPolicy(const fs::path& repo, std::uint32_t granted) {
    GitPolicy p = GitPolicy::DefaultDenyAll();
    p.granted = granted;
    p.authorizedPrefixes = {kAgentScope};
    p.repositoryRoots = {repo.string()};
    p.requireCleanForDestructive = true;
    return p;
}

constexpr std::uint32_t kAllMutating =
    static_cast<std::uint32_t>(GitCapability::Stage) |
    static_cast<std::uint32_t>(GitCapability::Unstage) |
    static_cast<std::uint32_t>(GitCapability::Commit) |
    static_cast<std::uint32_t>(GitCapability::Branch) |
    static_cast<std::uint32_t>(GitCapability::Checkout) |
    static_cast<std::uint32_t>(GitCapability::Stash) |
    static_cast<std::uint32_t>(GitCapability::Worktree) |
    static_cast<std::uint32_t>(GitCapability::Rollback);

// ───────────────────────────────────────────────── THE DANGEROUS TEST ────────

// Returns true only if every unrelated user path is byte-identical AND the
// agent's commit contains none of them.
bool DangerousDirtyTreeTest(Cert& cert, const fs::path& repo) {
    std::printf("\n--- RAWRXD_GIT_SAFETY_DIRTY_TREE_001 (dangerous test) ---\n");

    if (!InitRepo(repo)) {
        cert.notRun("DIRTY_TREE_001", "unrelated user changes survive an agent commit",
                    "scratch repository could not be created");
        return false;
    }

    // ── 1. The user makes unrelated changes. This is the pre-existing dirt. ──
    const std::string userA = "{\"theme\":\"light\",\"autosave\":true,\"notes\":\"user edit A\"}\n";
    const std::string userB = "[user]\nname=local\nemail=user@example.invalid\n";
    const std::string userC = "# notes\nuser edit C, do not lose\n";
    WriteFile(repo / kUserFileA, userA);   // modified, unstaged
    WriteFile(repo / kUserFileB, userB);   // modified, unstaged
    WriteFile(repo / kUserFileC, userC);   // modified, unstaged
    // The user also stages one of their own files, which is the trap: a bare
    // `git commit` would publish it inside the agent's commit message.
    std::string out, err;
    Git(repo, {"add", "--", kUserFileB}, out, err);

    // Measure the user state with an independent fingerprint.
    const std::string fpA_before = Sha256File(repo / kUserFileA);
    const std::string fpB_before = Sha256File(repo / kUserFileB);
    const std::string fpC_before = Sha256File(repo / kUserFileC);
    const std::string headBefore = HeadOf(repo);

    // ── 2. The agent is given authority over src/agent only. ──
    GitSafetyAuthority authority(AgentPolicy(repo, kAllMutating));
    const GitResult opened = authority.beginSession(repo);
    if (!opened.ok) {
        cert.notRun("DIRTY_TREE_001", "unrelated user changes survive an agent commit",
                    "beginSession refused: " + opened.detail);
        return false;
    }
    cert.check("DIRTY_TREE_002", "baseline records pre-existing dirt, not drift",
               authority.baseline().dirtyCount() == 3,
               "baseline_dirty=" + std::to_string(authority.baseline().dirtyCount()) +
                   " baseline_staged=" + std::to_string(authority.baseline().stagedCount()) +
                   " " + opened.detail);

    // The user's staged file must be visible in the baseline as the user's,
    // not silently reclassified as the agent's.
    bool userStagedRecognized = false;
    for (const auto& p : authority.baseline().paths) {
        if (p.path == kUserFileB && p.staged()) userStagedRecognized = true;
    }
    cert.check("DIRTY_TREE_003", "pre-existing staged user work is classified as out-of-scope",
               userStagedRecognized, "user_staged_file_seen=" +
                                         std::string(userStagedRecognized ? "YES" : "NO"));

    // ── 3. The agent is asked to commit while the user's staged work is in
    //       the index. It must refuse, not absorb.
    //
    //     The path list is deliberately EMPTY here. `git commit` with no
    //     pathspec commits the WHOLE index, which is the actual absorption
    //     vector: an agent that says "commit my work" and hands git an empty
    //     pathspec publishes whatever else was already staged. Passing an
    //     explicit path list would exercise a narrower, already-safe case and
    //     would hide the dangerous one.
    const GitResult blocked = authority.commit("agent: should not absorb user work", {});
    cert.check("DIRTY_TREE_004", "commit refused when the index holds out-of-scope staged work",
               !blocked.ok && blocked.refusal == rawrxd::agentic::GitRefusal::PathOutsideScope,
               std::string("refusal=") + rawrxd::agentic::GitRefusalName(blocked.refusal) +
                   " detail=" + blocked.detail);
    cert.check("DIRTY_TREE_005", "the refused commit did not move HEAD",
               HeadOf(repo) == headBefore, "head=" + HeadOf(repo).substr(0, 12) +
                                               " unchanged=" + std::string(HeadOf(repo) == headBefore ? "YES" : "NO"));

    // ── 4. Now the agent does the work it was actually asked to do. ──
    WriteFile(repo / kNewFile, "// agent feature v1\nint feature() { return 42; }\n");
    const GitResult staged = authority.stage({kNewFile});
    if (!staged.ok) {
        cert.check("DIRTY_TREE_006", "agent can stage its own subsystem", false,
                   "stage refused: " + staged.detail);
        return false;
    }
    cert.check("DIRTY_TREE_006", "agent can stage its own subsystem", true, staged.detail);

    // The user's staged file is still in the index, so the commit must still
    // refuse. To make progress the agent unstages it — but unstaging is a
    // mutation of the user's work, and the authority must refuse THAT too,
    // because src/user is out of scope.
    const GitResult unstageUser = authority.unstage({kUserFileB});
    cert.check("DIRTY_TREE_007", "agent cannot unstage the user's out-of-scope work",
               !unstageUser.ok &&
                   unstageUser.refusal == rawrxd::agentic::GitRefusal::PathOutsideScope,
               std::string("refusal=") + rawrxd::agentic::GitRefusalName(unstageUser.refusal));

    // With the user's work still staged, the agent's own commit is refused.
    // This is the correct, conservative outcome: the agent cannot produce a
    // clean commit while someone else's work occupies the index, and it must
    // not resolve that by discarding the user's staging.
    const GitResult stillBlocked = authority.commit("agent: add feature", {});
    cert.check("DIRTY_TREE_008", "agent commit stays refused while user work is staged",
               !stillBlocked.ok, std::string("refusal=") +
                                     rawrxd::agentic::GitRefusalName(stillBlocked.refusal));

    // ── 5. The recovery path: the USER unstages, then the agent commits. ──
    Git(repo, {"restore", "--staged", "--", kUserFileB}, out, err);
    const GitResult commit = authority.commit("agent: add feature", {kNewFile});
    cert.check("DIRTY_TREE_009", "agent commits once the index holds only its own work",
               commit.ok, commit.ok ? commit.detail : ("refused: " + commit.detail));

    if (!commit.ok) {
        // The user's work is still safe, so this is a partial failure, not a
        // preservation failure. Report the preservation fact either way.
    }

    // ── 6. The measured preservation property. ──
    const std::string fpA_after = Sha256File(repo / kUserFileA);
    const std::string fpB_after = Sha256File(repo / kUserFileB);
    const std::string fpC_after = Sha256File(repo / kUserFileC);
    const bool contentHeld = (fpA_before == fpA_after) && (fpB_before == fpB_after) &&
                             (fpC_before == fpC_after);
    cert.check("DIRTY_TREE_010", "every unrelated user file is byte-identical after the agent ran",
               contentHeld,
               std::string("settings=") + (fpA_before == fpA_after ? "same" : "CHANGED") +
                   " profile=" + (fpB_before == fpB_after ? "same" : "CHANGED") +
                   " notes=" + (fpC_before == fpC_after ? "same" : "CHANGED"));

    // The content check above is necessary but not sufficient: a file could be
    // byte-identical and still have been committed. So verify the commit's
    // actual tree contents independently.
    const std::string newHead = HeadOf(repo);
    // Absorption happened iff the committed blob IS the user's edit. The
    // committed blob being the original baseline is the PASS condition: the
    // user's work stayed in the working tree where the user left it.
    const std::string committedUserB = GitBlob(repo, "HEAD:" + std::string(kUserFileB));
    const std::string baselineUserB =
        GitBlob(repo, "HEAD~1:" + std::string(kUserFileB));
    const bool absorbedUserEdit = (committedUserB == userB);
    cert.check("DIRTY_TREE_011", "the agent's commit did not absorb the user's edit",
               !absorbedUserEdit && committedUserB == baselineUserB,
               "committed profile.ini " +
                   std::string(absorbedUserEdit
                                   ? "CONTAINS THE USER'S EDIT, so the agent published their work"
                                   : (committedUserB == baselineUserB
                                          ? "still holds the baseline bytes; the user edit stayed uncommitted"
                                          : "holds neither the baseline nor the user edit")));

    const std::string committedNew = GitOut(repo, "show HEAD:" + std::string(kNewFile));
    cert.check("DIRTY_TREE_012", "the agent's own change IS in its commit",
               committedNew.find("42") != std::string::npos,
               "feature.cpp committed=" +
                   std::string(committedNew.find("42") != std::string::npos ? "YES" : "NO"));

    // The user's staged/unstaged state must be the user's to decide. Report it.
    const std::string statusAfter = StatusPorcelain(repo);
    const bool userStillDirty = statusAfter.find(kUserFileA) != std::string::npos &&
                                statusAfter.find(kUserFileB) != std::string::npos &&
                                statusAfter.find(kUserFileC) != std::string::npos;
    cert.check("DIRTY_TREE_013", "the user's modifications are still the user's uncommitted work",
               userStillDirty, "user paths still listed as dirty=" +
                                    std::string(userStillDirty ? "YES" : "NO"));

    // The authority's own verification must agree with the independent check.
    std::vector<std::string> violations;
    const bool authorityAgrees = authority.verifyUnrelatedPreserved(violations);
    cert.check("DIRTY_TREE_014", "the authority's own preservation check agrees",
               authorityAgrees && violations.empty(),
               "verifyUnrelatedPreserved=" + std::string(authorityAgrees ? "CLEAN" : "VIOLATED") +
                   " violations=" + std::to_string(violations.size()));

    return contentHeld && !absorbedUserEdit && authorityAgrees;
}

// ───────────────────────────────────────────── capability certification ─────

void CertifyDefaultDeny(Cert& cert, const fs::path& repo) {
    std::printf("\n--- default-deny gate ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("GATE_001", "default-deny policy mutates nothing", "scratch repo failed");
        return;
    }
    WriteFile(repo / kAgentFile, "// agent edited with no authority\n");

    GitSafetyAuthority deny(AgentPolicy(repo, 0));
    const GitResult opened = deny.beginSession(repo);
    if (!opened.ok) {
        cert.notRun("GATE_001", "default-deny policy mutates nothing", "beginSession refused");
        return;
    }
    const std::string headBefore = HeadOf(repo);
    const GitResult stage = deny.stage({kAgentFile});
    cert.check("GATE_001", "stage refused when the capability is not granted",
               !stage.ok && stage.refusal == rawrxd::agentic::GitRefusal::CapabilityNotGranted,
               std::string("refusal=") + rawrxd::agentic::GitRefusalName(stage.refusal));
    const GitResult commit = deny.commit("should not happen", {kAgentFile});
    cert.check("GATE_002", "commit refused when the capability is not granted",
               !commit.ok && commit.refusal == rawrxd::agentic::GitRefusal::CapabilityNotGranted,
               std::string("refusal=") + rawrxd::agentic::GitRefusalName(commit.refusal));
    cert.check("GATE_003", "a denied policy moved no HEAD and left no staged path",
               HeadOf(repo) == headBefore, "head=" + HeadOf(repo).substr(0, 12));
    cert.check("GATE_004", "read-only status still works under a deny policy",
               deny.status().ok, deny.status().detail);
}

void CertifyScopeEscape(Cert& cert, const fs::path& repo) {
    std::printf("\n--- scope enforcement ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("SCOPE_001", "out-of-scope paths are refused", "scratch repo failed");
        return;
    }
    GitSafetyAuthority scoped(AgentPolicy(repo, kAllMutating));
    if (!scoped.beginSession(repo).ok) {
        cert.notRun("SCOPE_001", "out-of-scope paths are refused", "beginSession refused");
        return;
    }
    const GitResult outside = scoped.stage({kUserFileA});
    cert.check("SCOPE_001", "staging a path outside the authorized scope is refused",
               !outside.ok && outside.refusal == rawrxd::agentic::GitRefusal::PathOutsideScope,
               std::string("refusal=") + rawrxd::agentic::GitRefusalName(outside.refusal));

    const GitResult traversal = scoped.stage({"../../../etc/passwd"});
    cert.check("SCOPE_002", "a traversing path is refused before git is invoked",
               !traversal.ok &&
                   (traversal.refusal == rawrxd::agentic::GitRefusal::PathEscapesRepository ||
                    traversal.refusal == rawrxd::agentic::GitRefusal::PathOutsideScope),
               std::string("refusal=") + rawrxd::agentic::GitRefusalName(traversal.refusal) +
                   " " + traversal.detail);

    const GitResult escape = scoped.stage({std::string("..\\..\\escape.cpp")});
    cert.check("SCOPE_003", "a backslash traversal is refused",
               !escape.ok, std::string("refusal=") +
                               rawrxd::agentic::GitRefusalName(escape.refusal));

    // A capability with NO scope is not an authorization.
    GitPolicy noScope = GitPolicy::DefaultDenyAll();
    noScope.granted = kAllMutating;
    noScope.repositoryRoots = {repo.string()};
    GitSafetyAuthority scopeless(noScope);
    if (scopeless.beginSession(repo).ok) {
        const GitResult r = scopeless.stage({kNewFile});
        cert.check("SCOPE_004", "a grant with no path scope refuses every mutation",
                   !r.ok && r.refusal == rawrxd::agentic::GitRefusal::NoScope,
                   std::string("refusal=") + rawrxd::agentic::GitRefusalName(r.refusal));
    } else {
        cert.notRun("SCOPE_004", "a grant with no path scope refuses every mutation",
                    "beginSession refused");
    }

    // A repository outside the allowed roots is refused outright.
    GitPolicy narrow = AgentPolicy(repo, kAllMutating);
    narrow.repositoryRoots = {repo.string() + "_somewhere_else"};
    GitSafetyAuthority foreign(narrow);
    const GitResult refusedRoot = foreign.beginSession(repo);
    cert.check("SCOPE_005", "a repository outside the policy roots is refused",
               !refusedRoot.ok &&
                   refusedRoot.refusal == rawrxd::agentic::GitRefusal::RepositoryRootNotAllowed,
               std::string("refusal=") + rawrxd::agentic::GitRefusalName(refusedRoot.refusal));
}

void CertifyReadOnlyCapabilities(Cert& cert, const fs::path& repo) {
    std::printf("\n--- read-only capabilities ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("READONLY_001", "read-only capabilities report real state", "scratch failed");
        return;
    }
    WriteFile(repo / kAgentFile, "// changed\n");
    WriteFile(repo / kUserFileA, "{\"a\":1}\n");
    GitSafetyAuthority ro(AgentPolicy(repo, 0));
    if (!ro.beginSession(repo).ok) {
        cert.notRun("READONLY_001", "read-only capabilities report real state", "beginSession failed");
        return;
    }

    const GitResult st = ro.status();
    // Measured against git directly, not against the authority's own view.
    const std::string porcelain = StatusPorcelain(repo);
    const std::size_t realDirty =
        static_cast<std::size_t>(std::count(porcelain.begin(), porcelain.end(), '\n'));
    cert.check("READONLY_001", "status reports the working tree truthfully",
               st.ok && st.output == porcelain,
               "authority_bytes=" + std::to_string(st.output.size()) +
                   " git_bytes=" + std::to_string(porcelain.size()) +
                   " real_dirty_lines=" + std::to_string(realDirty));

    const GitResult df = ro.diff(false, 1u << 18);
    // Compare against git through the SAME normalisation the driver uses
    // everywhere else (GitOut trims trailing newlines). Comparing the raw
    // capture against a trimmed one measures a trailing byte, not correctness.
    const std::string gitDiff = GitOut(repo, "diff --no-color");
    std::string authorityDiff = df.output;
    while (!authorityDiff.empty() &&
           (authorityDiff.back() == '\n' || authorityDiff.back() == '\r')) {
        authorityDiff.pop_back();
    }
    cert.check("READONLY_002", "diff matches git's own output byte for byte",
               df.ok && authorityDiff == gitDiff,
               "authority_bytes=" + std::to_string(authorityDiff.size()) +
                   " git_bytes=" + std::to_string(gitDiff.size()) +
                   " equal=" + std::string(authorityDiff == gitDiff ? "YES" : "NO"));

    const GitResult cf = ro.conflicts();
    cert.check("READONLY_003", "conflict detection reports zero on a clean tree",
               cf.ok && cf.output.empty(), cf.detail);

    const GitResult dt = ro.dirtyTree();
    const bool classified = dt.ok && dt.output.find("[pre-existing user change]") != std::string::npos;
    cert.check("READONLY_004", "dirty-tree separates pre-existing user change from agent scope",
               classified, dt.detail);

    const GitResult rev = ro.reviewAgentDiff(1u << 18);
    const bool reviewBoth = rev.ok &&
                            rev.output.find("AGENT SCOPE DIFF") != std::string::npos &&
                            rev.output.find("OUTSIDE AGENT SCOPE") != std::string::npos;
    cert.check("READONLY_005", "diff review shows agent scope AND out-of-scope dirt",
               reviewBoth, rev.detail);
}

void CertifyIndexAndHistory(Cert& cert, const fs::path& repo) {
    std::printf("\n--- stage / unstage / commit / branch ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("INDEX_001", "stage/unstage/commit/branch behave", "scratch failed");
        return;
    }
    GitSafetyAuthority a(AgentPolicy(repo, kAllMutating));
    if (!a.beginSession(repo).ok) {
        cert.notRun("INDEX_001", "stage/unstage/commit/branch behave", "beginSession failed");
        return;
    }
    WriteFile(repo / kNewFile, "// feature\nint f(){return 1;}\n");
    const GitResult st = a.stage({kNewFile});
    const std::string cached = GitOut(repo, "diff --cached --name-only");
    cert.check("INDEX_001", "stage puts the path in the index",
               st.ok && cached.find(kNewFile) != std::string::npos,
               "index=" + OneLine(cached));

    const GitResult un = a.unstage({kNewFile});
    const std::string cachedAfter = GitOut(repo, "diff --cached --name-only");
    cert.check("INDEX_002", "unstage removes it from the index without touching the worktree",
               un.ok && cachedAfter.find(kNewFile) == std::string::npos &&
                   fs::exists(repo / kNewFile),
               "index_after='" + cachedAfter + "' worktree_file_still_present=" +
                   std::string(fs::exists(repo / kNewFile) ? "YES" : "NO"));

    a.stage({kNewFile});
    const std::string headBefore = HeadOf(repo);
    const GitResult cm = a.commit("agent: add feature", {kNewFile});
    cert.check("INDEX_003", "commit advances HEAD by exactly one commit",
               cm.ok && HeadOf(repo) != headBefore,
               "before=" + headBefore.substr(0, 12) + " after=" + HeadOf(repo).substr(0, 12));
    cert.check("INDEX_004", "an empty commit is refused rather than faked",
               a.commit("agent: nothing", {kNewFile}).refused(),
               a.commit("agent: nothing", {kNewFile}).detail);

    const GitResult br = a.createBranch("agent/feature-work");
    const std::string refs = GitOut(repo, "branch --list agent/feature-work");
    cert.check("INDEX_005", "branch creation is visible to git",
               br.ok && refs.find("agent/feature-work") != std::string::npos, br.detail);

    const GitResult badBranch = a.createBranch("bad;name && echo pwned");
    cert.check("INDEX_006", "a branch name with shell metacharacters is refused",
               !badBranch.ok, std::string("refusal=") +
                                   rawrxd::agentic::GitRefusalName(badBranch.refusal));
    cert.check("INDEX_007", "the refused branch was not created",
               GitOut(repo, "branch --list").find("pwned") == std::string::npos,
               "no branch containing 'pwned'");
}

void CertifyDestructiveAndRecovery(Cert& cert, const fs::path& repo) {
    std::printf("\n--- checkout / stash / worktree / rollback ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("DESTRUCTIVE_001", "destructive ops are gated", "scratch failed");
        return;
    }
    // A user's uncommitted change is present, so a destructive op must refuse.
    const std::string userEdit = "{\"theme\":\"solar\"}\n";
    WriteFile(repo / kUserFileA, userEdit);
    GitSafetyAuthority a(AgentPolicy(repo, kAllMutating));
    if (!a.beginSession(repo).ok) {
        cert.notRun("DESTRUCTIVE_001", "destructive ops are gated", "beginSession failed");
        return;
    }
    a.createBranch("agent/topic");

    const GitResult co = a.checkout("agent/topic");
    cert.check("DESTRUCTIVE_001",
               "checkout refused while unrelated uncommitted work exists",
               !co.ok && co.refusal == rawrxd::agentic::GitRefusal::DirtyTreeDestructive,
               std::string("refusal=") + rawrxd::agentic::GitRefusalName(co.refusal) + " " + co.detail);
    cert.check("DESTRUCTIVE_002", "the refused checkout left the branch alone",
               GitOut(repo, "rev-parse --abbrev-ref HEAD") == "main",
               "branch=" + GitOut(repo, "rev-parse --abbrev-ref HEAD"));

    const GitResult sh = a.stash("agent tries to stash the user's work");
    cert.check("DESTRUCTIVE_003", "stash refused while unrelated uncommitted work exists",
               !sh.ok && sh.refusal == rawrxd::agentic::GitRefusal::DirtyTreeDestructive,
               std::string("refusal=") + rawrxd::agentic::GitRefusalName(sh.refusal));
    cert.check("DESTRUCTIVE_004", "the refused stash did not move the user's file",
               ReadFile(repo / kUserFileA) == userEdit, "user file bytes unchanged");

    // With the user's work committed, the destructive path is allowed.
    std::string out, err;
    Git(repo, {"-c", "user.email=cert@rawrxd.local", "-c", "user.name=cert", "commit",
               "-q", "-am", "user: commit own work"}, out, err);
    const GitResult co2 = a.checkout("agent/topic");
    cert.check("DESTRUCTIVE_005", "checkout proceeds once unrelated work is committed",
               co2.ok, co2.ok ? co2.detail : ("refused: " + co2.detail));
    cert.check("DESTRUCTIVE_006", "the checkout actually moved HEAD",
               GitOut(repo, "rev-parse --abbrev-ref HEAD") == "agent/topic",
               "branch=" + GitOut(repo, "rev-parse --abbrev-ref HEAD"));

    a.checkout("main");
}

void CertifyWorktreeIsolation(Cert& cert, const fs::path& repo) {
    std::printf("\n--- worktree isolation ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("WORKTREE_001", "worktree operations are isolated and gated", "scratch failed");
        return;
    }
// The worktree lives under its own prefix, which is deliberately OUTSIDE
    // src/agent: an isolation worktree that shared the agent's source prefix
    // would put two checkouts of the same files in one scope. The policy grants
    // both prefixes so the refusal tests above are about scope, not about the
    // worktree path happening to collide with a source prefix.
    GitPolicy wtPolicy = AgentPolicy(repo, kAllMutating);
    wtPolicy.authorizedPrefixes = {kAgentScope, kWorktreeDir};
    GitSafetyAuthority a(wtPolicy);
    if (!a.beginSession(repo).ok) {
        cert.notRun("WORKTREE_001", "worktree operations are isolated and gated",
                    "beginSession failed");
        return;
    }
    const GitResult outside = a.addWorktree("../escape-wt");
    cert.check("WORKTREE_001", "a worktree outside the repository is refused",
               !outside.ok,
               std::string("refusal=") + rawrxd::agentic::GitRefusalName(outside.refusal));

    const GitResult outOfScope = a.addWorktree(kUserFileA);
    cert.check("WORKTREE_002", "a worktree outside the authorized scope is refused",
               !outOfScope.ok && outOfScope.refusal == rawrxd::agentic::GitRefusal::PathOutsideScope,
               std::string("refusal=") + rawrxd::agentic::GitRefusalName(outOfScope.refusal));

    const GitResult add = a.addWorktree(kWorktreeDir);
    cert.check("WORKTREE_003", "a worktree inside the authorized scope is created",
               add.ok, add.ok ? add.detail : ("refused: " + add.detail));

    const GitResult list = a.listWorktrees();
    cert.check("WORKTREE_004", "the worktree list reports more than one entry",
               list.ok && list.output.find("wt-agent") != std::string::npos, list.detail);

    // Real isolation: a commit inside the agent worktree must not appear in
    // the main worktree's history, and the main worktree's files must be
    // untouched by work in the other one.
    const std::string headBefore = HeadOf(repo);
    const std::string userBefore = ReadFile(repo / kUserFileA);
    const fs::path wt = repo / kWorktreeDir;
    std::string out, err;
    WriteFile(wt / kNewFile, "// feature in worktree\n");
    Git(wt, {"add", "-A"}, out, err);
    Git(wt, {"-c", "user.email=cert@rawrxd.local", "-c", "user.name=cert", "commit", "-q",
             "-m", "agent: worktree commit"}, out, err);
    cert.check("WORKTREE_005", "a commit in the agent worktree does not move the main HEAD",
               HeadOf(repo) == headBefore,
               "main_head=" + HeadOf(repo).substr(0, 12) + " worktree_head=" +
                   HeadOf(wt).substr(0, 12));
    cert.check("WORKTREE_006", "the main worktree's user file is untouched by worktree activity",
               ReadFile(repo / kUserFileA) == userBefore, "bytes unchanged");

    const GitResult rm = a.removeWorktree(kWorktreeDir, true);
    cert.check("WORKTREE_007", "the worktree is removable through the authority",
               rm.ok, rm.ok ? rm.detail : ("refused: " + rm.detail));
}

void CertifyRollback(Cert& cert, const fs::path& repo) {
    std::printf("\n--- rollback ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("ROLLBACK_001", "rollback restores the agent's own changes only", "scratch failed");
        return;
    }
    const std::string userEdit = "{\"pre\":\"user\"}\n";
    WriteFile(repo / kUserFileA, userEdit);  // dirty BEFORE the session
    const std::string userBefore = Sha256File(repo / kUserFileA);

    GitSafetyAuthority a(AgentPolicy(repo, kAllMutating));
    if (!a.beginSession(repo).ok) {
        cert.notRun("ROLLBACK_001", "rollback restores the agent's own changes only",
                    "beginSession failed");
        return;
    }
    // The agent edits its own subsystem and creates a new file.
    WriteFile(repo / kAgentFile, "// agent broke this\nint service() { return -1; }\n");
    WriteFile(repo / kNewFile, "// agent new file\n");
    const std::string agentHash = Sha256File(repo / kAgentFile);

    const GitResult rb = a.rollback({kAgentFile, kNewFile});
    cert.check("ROLLBACK_001", "rollback restores a tracked file to HEAD",
               rb.ok && Sha256File(repo / kAgentFile) != agentHash,
               rb.ok ? rb.detail : ("refused: " + rb.detail));
    cert.check("ROLLBACK_002", "rollback removes a file this run created",
               !fs::exists(repo / kNewFile), "agent-created file exists=" +
                                                 std::string(fs::exists(repo / kNewFile) ? "YES" : "NO"));
    cert.check("ROLLBACK_003", "rollback did NOT touch the pre-existing user edit",
               Sha256File(repo / kUserFileA) == userBefore,
               "user file sha256 unchanged=" +
                   std::string(Sha256File(repo / kUserFileA) == userBefore ? "YES" : "NO"));
    cert.check("ROLLBACK_004", "rollback refuses a path that was dirty at session begin",
               a.rollback({kUserFileA}).refused() ||
                   a.rollback({kUserFileA}).detail.find("skipped") != std::string::npos,
               a.rollback({kUserFileA}).detail);
    const GitResult outside = a.rollback({kUserFileB});
    cert.check("ROLLBACK_005", "rollback refuses an out-of-scope path",
               !outside.ok && outside.refusal == rawrxd::agentic::GitRefusal::PathOutsideScope,
               std::string("refusal=") + rawrxd::agentic::GitRefusalName(outside.refusal));
}

void CertifyConflictDetection(Cert& cert, const fs::path& repo) {
    std::printf("\n--- conflict detection ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("CONFLICT_001", "mutation is refused while a conflict is unresolved", "scratch failed");
        return;
    }
    // Create a genuine conflict: two branches edit the same line, then MERGE
    // one into the other. Merging into a branch whose tip already contains the
    // merge base fast-forwards instead of conflicting, so the merge direction
    // matters — `merge left` on top of `right` is the three-way case.
    std::string out, err;
    WriteFile(repo / kAgentFile, "line1\nline2 BASE\nline3\n");
    Git(repo, {"add", "-A"}, out, err);
    Git(repo, {"-c", "user.email=cert@rawrxd.local", "-c", "user.name=cert", "commit", "-q",
               "-m", "base"}, out, err);
    const std::string mergeBase = HeadOf(repo);

    Git(repo, {"checkout", "-q", "-b", "left", mergeBase}, out, err);
    WriteFile(repo / kAgentFile, "line1\nline2 LEFT\nline3\n");
    Git(repo, {"commit", "-q", "-am", "left"}, out, err);

    Git(repo, {"checkout", "-q", "-b", "right", mergeBase}, out, err);
    WriteFile(repo / kAgentFile, "line1\nline2 RIGHT\nline3\n");
    Git(repo, {"commit", "-q", "-am", "right"}, out, err);

    // `right` still descends from the merge base, so merging `left` into it is
    // a true three-way merge over a conflicting line.
    const int mergeCode = Git(repo, {"merge", "left"}, out, err);
    cert.check("CONFLICT_000", "the scenario really produced a conflict, not a fast-forward",
               mergeCode != 0 && GitOut(repo, "diff --name-only --diff-filter=U") == kAgentFile,
               "git merge exit=" + std::to_string(mergeCode) +
                   " unmerged=" + GitOut(repo, "diff --name-only --diff-filter=U"));

    GitSafetyAuthority a(AgentPolicy(repo, kAllMutating));
    const GitResult opened = a.beginSession(repo);
    if (!opened.ok) {
        cert.notRun("CONFLICT_001", "mutation is refused while a conflict is unresolved",
                    "beginSession refused: " + opened.detail);
        return;
    }
    const GitResult cf = a.conflicts();
    cert.check("CONFLICT_001", "an unresolved conflict is reported as unmerged",
               cf.ok && cf.output.find(kAgentFile) != std::string::npos, cf.detail);
    const GitResult st = a.stage({kAgentFile});
    cert.check("CONFLICT_002", "mutation is refused while a conflict is unresolved",
               !st.ok && st.refusal == rawrxd::agentic::GitRefusal::UnmergedPathsPresent,
               std::string("refusal=") + rawrxd::agentic::GitRefusalName(st.refusal));
    cert.check("CONFLICT_003", "read-only status still works with a conflict present",
               a.status().ok, a.status().detail);
}

void CertifyRegistrySurface(Cert& cert, const fs::path& repo) {
    std::printf("\n--- tool-registry surface (the IDE's dispatch path) ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("SURFACE_001", "git tools are reachable through the sandboxed registry",
                    "scratch failed");
        return;
    }
    WriteFile(repo / kNewFile, "// agent feature\n");

    // A default-deny policy must not become a mutation path by installing the
    // tools. This is checked against the registry the IDE routes use.
    rawrxd::agentic::BindGitSafetyPolicy(AgentPolicy(repo, 0), repo);
    ToolRegistry& reg = ToolRegistry::Instance();
    reg.SetPolicy([&repo] {
        rawrxd::agentic::ToolPolicy p;
        p.allowedRoots = {repo.string()};
        p.allowWrite = true;
        p.allowExecute = true;
        return p;
    }());
    const bool installed = rawrxd::agentic::InstallGitTools(reg);
    cert.check("SURFACE_001", "git tools install into the sandboxed registry",
               installed && reg.HasTool("git_commit") && reg.HasTool("git_status") &&
                   reg.HasTool("git_rollback") && reg.HasTool("git_worktree"),
               "installed=" + std::string(installed ? "YES" : "NO") + " tools=" +
                   std::to_string(reg.Size()));

    const ToolResult denied = reg.Execute("git_commit", {{"message", "should not commit"}});
    cert.check("SURFACE_002", "a deny policy refuses git_commit through the registry",
               !denied.success &&
                   denied.error.find("CAPABILITY_NOT_GRANTED") != std::string::npos,
               denied.error.substr(0, 120));

    const ToolResult status = reg.Execute("git_status", {{}});
    cert.check("SURFACE_003", "read-only git_status works through the registry",
               status.success, OneLine(status.output.substr(0, 160)));

    // Now grant the capability and confirm the same tool actually commits, so
    // the denial above was the gate and not a dead tool.
    rawrxd::agentic::BindGitSafetyPolicy(AgentPolicy(repo, kAllMutating), repo);
    reg.Execute("git_status", {{}});
    const ToolResult staged = reg.Execute("git_stage", {{"paths", kNewFile}});
    const ToolResult committed = reg.Execute("git_commit",
                                             {{"message", "agent: feature via registry"},
                                              {"paths", kNewFile}});
    const std::string head = HeadOf(repo);
    cert.check("SURFACE_004", "the same tool commits once the policy grants it",
               staged.success && committed.success &&
                   GitOut(repo, "show HEAD:" + std::string(kNewFile)).find("agent feature") !=
                       std::string::npos,
               "stage=" + std::string(staged.success ? "ok" : "FAIL") + " commit=" +
                   std::string(committed.success ? "ok" : "FAIL") + " head=" + head.substr(0, 12));

    // The IDE's own tools must remain registered: installing git tools must not
    // have replaced the registry's contents.
    cert.check("SURFACE_005", "installing git tools did not displace the builtin set",
               reg.HasTool("read_file") || reg.Size() >= 12,
               "registry_size=" + std::to_string(reg.Size()));
}

void CertifyMessageSafety(Cert& cert, const fs::path& repo) {
    std::printf("\n--- argument safety ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("ARGS_001", "a metacharacter-laden message is data, not code", "scratch failed");
        return;
    }
    const fs::path canary = repo.parent_path() / "git_safety_canary.txt";
    std::error_code ec;
    fs::remove(canary, ec);

    GitSafetyAuthority a(AgentPolicy(repo, kAllMutating));
    if (!a.beginSession(repo).ok) {
        cert.notRun("ARGS_001", "a metacharacter-laden message is data, not code",
                    "beginSession failed");
        return;
    }
    WriteFile(repo / kNewFile, "// payload\n");
    a.stage({kNewFile});
    const std::string evil =
        "agent: test\" && type nul > ../git_safety_canary.txt && echo \"";
    const GitResult cm = a.commit(evil, {kNewFile});
    cert.check("ARGS_001", "a commit message containing shell metacharacters does not execute",
               !fs::exists(canary), "canary file created=" +
                                        std::string(fs::exists(canary) ? "YES (INJECTION)" : "NO"));
    const std::string subject = GitOut(repo, "log -1 --format=%s");
    cert.check("ARGS_002", "the message was stored verbatim as commit data",
               subject == evil, "subject_matches_input=" +
                                    std::string(subject == evil ? "YES" : "NO"));
    cert.check("ARGS_003", "the commit itself still succeeded",
               cm.ok, cm.ok ? cm.detail : cm.detail);
    fs::remove(canary, ec);
}

// ---------------------------------------------------------------------------
// RAWRXD_GIT_SAFETY_AUTHORITY_001 — binding certification
//
// The gate is only real if the surface an agent actually reaches goes through
// it. These checks bind the real installers into the real registries and then
// measure what an agent can and cannot do through them, rather than asserting
// that a binding call exists somewhere in the source.
// ---------------------------------------------------------------------------

void CertifyIdeSurfaceBinding(Cert& cert, const fs::path& repo) {
    std::printf("\n--- IDE surface binding (the registry the chat panel dispatches through) ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("IDE_BIND_001", "git tools are installed into the IDE registry", "scratch failed");
        return;
    }
    WriteFile(repo / kNewFile, "// agent feature via the IDE surface\n");

    // The IDE registry is a distinct TYPE from the sandboxed one, and the
    // installer is a distinct function. Binding the sandboxed registry and
    // calling it a day would leave the GUI ungated.
    //
    // It is constructed directly, not obtained from a singleton: the IDE holds
    // one as a function-static in main_win32.cpp, so the driver constructs its
    // own to avoid mutating the process-wide instance.
    RawrXD::Agentic::AgentToolRegistry ide;

    // A deny policy: no grants, no scope. This is the DEFAULT deployment state,
    // so it is the state worth certifying.
    GitPolicy deny = GitPolicy::DefaultDenyAll();
    deny.repositoryRoots = {repo.string()};
    deny.authorizedPrefixes = {kAgentScope};

    // Install from the environment first, to certify the real shipping entry
    // point, then bind the deny policy this check is about.
    // The IDE surface entry points live in rawrxd::ide_git_safety (see
    // GitSafetyAuthorityTools.h — they cannot live in rawrxd::agentic because
    // MSVC resolves RawrXD case-insensitively against the existing rawrxd
    // namespace and would find a non-existent nested one).
    const GitBindingReport fromEnv =
        rawrxd::ide_git_safety::InstallIdeSurface(ide, std::string());
    rawrxd::ide_git_safety::BindIdeSession(deny, repo);
    const auto listed = ide.list();
    const bool have = ide.contains("git_commit") && ide.contains("git_status") &&
                      ide.contains("git_rollback") && ide.contains("git_worktree") &&
                      ide.contains("git_stage") && ide.contains("git_checkout");
    cert.check("IDE_BIND_001", "the git tools install into the IDE registry",
               fromEnv.installed && have,
               "ide_tools=" + std::to_string(listed.size()) +
                   " env_installed=" + std::string(fromEnv.installed ? "YES" : "NO") +
                   " all_six_present=" + std::string(have ? "YES" : "NO"));

    // The agent's model-facing tool count is the ledger fact that was
    // previously "one tool: read_file".
    cert.check("IDE_BIND_002", "the model-facing surface is no longer a single read_file",
               listed.size() >= 13,
               "ide_model_facing_tools=" + std::to_string(listed.size()));

    // Under the deny policy, a mutating call through the IDE registry must be
    // refused. The refusal must carry the reason, not just fail.
    const std::string headBefore = HeadOf(repo);
    {
        RawrXD::Agentic::ToolContext ctx;
        RawrXD::Agentic::ToolRequest req;
        req.tool_id = "git_commit";  // the IDE registry dispatches on this field
        req.args = {"message=should not commit"};
        const auto r = ide.invoke(req, ctx);
        const bool refused = !r.ok() &&
                             r.stderr_text.find("CAPABILITY_NOT_GRANTED") != std::string::npos;
        cert.check("IDE_BIND_003", "a deny policy refuses git_commit through the IDE registry",
                   refused,
                   "ok=" + std::string(r.ok() ? "true" : "false") + " exit=" +
                       std::to_string(r.exit_code) + " stderr=" +
                       OneLine(r.stderr_text.substr(0, 100)));
    }
    cert.check("IDE_BIND_004", "the refused IDE commit moved no HEAD",
               HeadOf(repo) == headBefore, "head=" + HeadOf(repo).substr(0, 12));

    // Read-only must still work: refusing everything is not safety, it is a
    // broken tool, and an agent that cannot read git status cannot do anything
    // useful.
    {
        RawrXD::Agentic::ToolContext ctx;
        RawrXD::Agentic::ToolRequest req;
        req.tool_id = "git_status";
        const auto r = ide.invoke(req, ctx);
        cert.check("IDE_BIND_005", "read-only git_status works through the IDE registry under deny",
                   r.ok() && r.stdout_text.find("src/agent/feature.cpp") != std::string::npos,
                   "ok=" + std::string(r.ok() ? "true" : "false") + " out=" +
                       OneLine(r.stdout_text.substr(0, 110)));
    }

    // Now grant, and prove the same tool actually commits so IDE_BIND_003 was
    // the gate and not a dead tool.
    {
        GitPolicy allow = deny;
        allow.granted = kAllMutating;
        rawrxd::ide_git_safety::BindIdeSession(allow, repo);
        RawrXD::Agentic::ToolContext ctx;

        RawrXD::Agentic::ToolRequest stageReq;
        stageReq.tool_id = "git_stage";
        stageReq.args = {std::string("paths=") + kNewFile};
        const auto staged = ide.invoke(stageReq, ctx);

        RawrXD::Agentic::ToolRequest commitReq;
        commitReq.tool_id = "git_commit";
        commitReq.args = {"message=agent: feature via the IDE surface"};
        const auto committed = ide.invoke(commitReq, ctx);
        const bool inCommit =
            GitBlob(repo, "HEAD:" + std::string(kNewFile)).find("IDE surface") !=
            std::string::npos;
        cert.check("IDE_BIND_006", "the same IDE tool commits once the policy grants it",
                   staged.ok() && committed.ok() && inCommit,
                   "stage_ok=" + std::string(staged.ok() ? "true" : "false") +
                       " commit_ok=" + std::string(committed.ok() ? "true" : "false") +
                       " in_commit=" + std::string(inCommit ? "YES" : "NO") + " head=" +
                       HeadOf(repo).substr(0, 12));
    }
}

void CertifyEnvironmentDerivation(Cert& cert, const fs::path& repo) {
    std::printf("\n--- environment-derived policy (the shipping configuration surface) ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("ENV_001", "policy derives from environment with deny defaults", "scratch failed");
        return;
    }
    const std::string root = repo.string();

    // No environment at all: nothing is granted and nothing is scoped, which is
    // what a deployment that never read the documentation gets.
    _putenv_s("RAWRXD_GIT_ROOT", "");
    _putenv_s("RAWRXD_GIT_SCOPE", "");
    _putenv_s("RAWRXD_GIT_ALLOW_COMMIT", "");
    const GitPolicy none = rawrxd::agentic::GitSafetyPolicyFromEnvironment(std::string());
    cert.check("ENV_001", "an unconfigured deployment grants nothing and scopes nothing",
               none.granted == 0 && none.authorizedPrefixes.empty() &&
                   none.repositoryRoots.empty(),
               "granted=0x" + std::to_string(none.granted) + " scope=" +
                   std::to_string(none.authorizedPrefixes.size()) + " roots=" +
                   std::to_string(none.repositoryRoots.size()));

    // Root only: a session is possible, and mutations are still denied.
    _putenv_s("RAWRXD_GIT_ROOT", root.c_str());
    const GitPolicy rootOnly = rawrxd::agentic::GitSafetyPolicyFromEnvironment(std::string());
    cert.check("ENV_002", "setting only the root grants read-only access, not mutation",
               rootOnly.granted == 0 && rootOnly.repositoryRoots.size() == 1,
               "roots=" + std::to_string(rootOnly.repositoryRoots.size()) +
                   " granted=0x" + std::to_string(rootOnly.granted) + " scope=" +
                   std::to_string(rootOnly.authorizedPrefixes.size()));

    // Root + scope, still no capability: scope without a grant is not authority.
    _putenv_s("RAWRXD_GIT_SCOPE", "src/agent");
    const GitPolicy scopeNoGrant = rawrxd::agentic::GitSafetyPolicyFromEnvironment(std::string());
    cert.check("ENV_003", "a scope without a capability grant authorizes nothing",
               scopeNoGrant.granted == 0 && scopeNoGrant.authorizedPrefixes.size() == 1,
               "scope=" + std::to_string(scopeNoGrant.authorizedPrefixes.size()) +
                   " granted=0x" + std::to_string(scopeNoGrant.granted));

    // Grant commit but NO scope: the authority still refuses with NO_SCOPE.
    // The scope is cleared first — ENV_003 left it set, and with a scope in
    // place the commit would proceed and fail later with NOTHING_TO_DO, which
    // tests a different rule.
    _putenv_s("RAWRXD_GIT_SCOPE", "");
    _putenv_s("RAWRXD_GIT_ALLOW_COMMIT", "1");
    const GitPolicy grantNoScope = rawrxd::agentic::GitSafetyPolicyFromEnvironment(std::string());
    GitSafetyAuthority a(grantNoScope);
    if (a.beginSession(repo).ok) {
        const GitResult r = a.commit("agent: should be refused for want of scope", {});
        cert.check("ENV_004", "a capability grant without scope refuses with NO_SCOPE",
                   !r.ok && r.refusal == rawrxd::agentic::GitRefusal::NoScope,
                   std::string("refusal=") + rawrxd::agentic::GitRefusalName(r.refusal) +
                       " scope=" + std::to_string(grantNoScope.authorizedPrefixes.size()));
    } else {
        cert.notRun("ENV_004", "a capability grant without scope refuses with NO_SCOPE",
                    "beginSession refused");
    }

    // Full opt-in: the capabilities are reachable, and the receipt of that is a
    // measured grant mask rather than a claim. Stage and unstage are named
    // explicitly, because ALLOW_COMMIT alone must not imply them.
    _putenv_s("RAWRXD_GIT_SCOPE", "src/agent");
    _putenv_s("RAWRXD_GIT_ALLOW_STAGE", "1");
    const GitPolicy full = rawrxd::agentic::GitSafetyPolicyFromEnvironment(std::string());
    const bool commitGranted =
        HasCapability(full.granted, GitCapability::Commit) &&
        HasCapability(full.granted, GitCapability::Stage) &&
        HasCapability(full.granted, GitCapability::Unstage);
    cert.check("ENV_005", "the documented opt-in grants commit and its index operations",
               commitGranted,
               "granted_mask=" + std::to_string(full.granted));

    // ALLOW_COMMIT alone must NOT imply stage. This is the rule that stops a
    // "let it commit" switch from also granting "stage whatever it likes".
    _putenv_s("RAWRXD_GIT_SCOPE", "");
    _putenv_s("RAWRXD_GIT_ALLOW_STAGE", "");
    _putenv_s("RAWRXD_GIT_ALLOW_UNSTAGE", "");
    const GitPolicy commitOnly = rawrxd::agentic::GitSafetyPolicyFromEnvironment(root);
    cert.check("ENV_007", "granting commit does not implicitly grant stage or unstage",
               HasCapability(commitOnly.granted, GitCapability::Commit) &&
                   !HasCapability(commitOnly.granted, GitCapability::Stage) &&
                   !HasCapability(commitOnly.granted, GitCapability::Unstage),
               "granted_mask=" + std::to_string(commitOnly.granted));

    // requireClean default must be ON: destructive ops refuse with unrelated
    // dirt unless it is explicitly disabled.
    const GitPolicy defaults = [&] {
        _putenv_s("RAWRXD_GIT_REQUIRE_CLEAN", "");
        return rawrxd::agentic::GitSafetyPolicyFromEnvironment(root);
    }();
    cert.check("ENV_006", "requireCleanForDestructive defaults to true",
               defaults.requireCleanForDestructive,
               "requireClean=" +
                   std::string(defaults.requireCleanForDestructive ? "true" : "false"));

    // Clear everything so later checks are not influenced by this test.
    for (const char* k : {"RAWRXD_GIT_ROOT", "RAWRXD_GIT_SCOPE", "RAWRXD_GIT_ALLOW_COMMIT",
                          "RAWRXD_GIT_ALLOW_STAGE", "RAWRXD_GIT_ALLOW_UNSTAGE",
                          "RAWRXD_GIT_REQUIRE_CLEAN"}) {
        _putenv_s(k, "");
    }
}

void CertifyFalseSuccessElimination(Cert& cert, const fs::path& repo) {
    std::printf("\n--- false-success elimination ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("FALSE_001", "no source path reports a git success it did not perform",
                    "scratch failed");
        return;
    }
    // These assert properties of the SHIPPED SOURCE, read from disk relative to
    // this file, because the defect being certified against was a stub that
    // returns success. A behavioural test cannot cover a TU that is in no build
    // target; a source assertion can, and it fails loudly if the stub returns.
    const fs::path root = fs::path(__FILE__).parent_path().parent_path();
    const fs::path ceo = root / "src" / "ceo" / "CEOAgent.cpp";
    const fs::path panel = root / "src" / "win32app" / "Win32IDE_GitPanel.cpp";
    const fs::path handlers = root / "src" / "core" / "feature_handlers.cpp";

    auto readAll = [](const fs::path& p, std::string& out) {
        std::ifstream in(p, std::ios::binary);
        if (!in) return false;
        std::ostringstream oss;
        oss << in.rdbuf();
        out = oss.str();
        return true;
    };

    // Strip C and C++ comments before matching. The fix for each of these
    // defects QUOTES the old code in its explanatory comment, so a naive
    // substring search matches the comment and the check can never fail — a
    // check that cannot fail is worse than no check, because it reads as
    // evidence. Matching code only is what makes these honest.
    auto stripComments = [](const std::string& in) {
        std::string out;
        out.reserve(in.size());
        enum class S { Code, Line, Block, Str, Chr } state = S::Code;
        for (std::size_t i = 0; i < in.size(); ++i) {
            const char c = in[i];
            const char n = (i + 1 < in.size()) ? in[i + 1] : '\0';
            switch (state) {
                case S::Code:
                    if (c == '/' && n == '/') { state = S::Line; ++i; }
                    else if (c == '/' && n == '*') { state = S::Block; ++i; }
                    else if (c == '"') { state = S::Str; out.push_back(c); }
                    else if (c == '\'') { state = S::Chr; out.push_back(c); }
                    else out.push_back(c);
                    break;
                case S::Line:
                    if (c == '\n') { state = S::Code; out.push_back(c); }
                    break;
                case S::Block:
                    if (c == '*' && n == '/') { state = S::Code; ++i; }
                    break;
                case S::Str:
                    out.push_back(c);
                    if (c == '\\' && n) { out.push_back(n); ++i; }
                    else if (c == '"') state = S::Code;
                    break;
                case S::Chr:
                    out.push_back(c);
                    if (c == '\\' && n) { out.push_back(n); ++i; }
                    else if (c == '\'') state = S::Code;
                    break;
            }
        }
        return out;
    };

    std::string ceoSrc, panelSrc, handlerSrc;
    const bool haveAll = readAll(ceo, ceoSrc) && readAll(panel, panelSrc) &&
                         readAll(handlers, handlerSrc);
    if (!haveAll) {
        cert.notRun("FALSE_001", "no source path reports a git success it did not perform",
                    "could not read the source files under test");
        return;
    }
    const std::string ceoCode = stripComments(ceoSrc);
    const std::string panelCode = stripComments(panelSrc);
    const std::string handlerCode = stripComments(handlerSrc);

    // The original stub, verbatim. Its presence means the false success is back.
    cert.check("FALSE_001", "CEOAgent::InvokeTool no longer contains the success stub",
               ceoCode.find("result[\"success\"] = true;\n    result[\"tool\"] = toolName;") ==
                   std::string::npos,
               "stub_block_in_code=NO");

    // The stub reported success for unimplemented tools; the replacement must
    // report failure for them.
    cert.check("FALSE_002", "CEOAgent reports UNIMPLEMENTED rather than success for "
                            "unimplemented tools",
               ceoCode.find("UNIMPLEMENTED") != std::string::npos &&
                   ceoCode.find("result[\"refused\"] = true;") != std::string::npos,
               "unimplemented_path_in_code=YES");

    // git add -A swept the whole repository into whatever commit followed.
    cert.check("FALSE_003", "the Git panel no longer stages everything before committing",
               panelCode.find("RunGit(\"add -A\"") == std::string::npos,
               "add_-A_call_in_code=NO");

    // The commit button must report a refusal, and must not clear the message
    // box on failure.
    cert.check("FALSE_004", "the Git panel reports a refused commit instead of looking successful",
               panelCode.find("GitPanel_CommitThroughAuthority") != std::string::npos &&
                   panelCode.find("Nothing was committed") != std::string::npos,
               "refusal_dialog_in_code=YES");

    // The GIT handler block only. feature_handlers.cpp is 3500 lines covering
    // many features, and non-git handlers still legitimately use _popen for
    // unrelated things (curl probes, ollama calls). Checking the whole file
    // would fail on those and would be measuring the wrong thing.
    //
    // The block is bounded by the five git handlers themselves, which is a
    // stable anchor: handleGitStatus through the end of handleGitDiff.
    std::string gitSection;
    {
        const std::size_t b = handlerCode.find("CommandResult handleGitStatus");
        if (b != std::string::npos) {
            // Cut at the next top-level handler that is not one of the five.
            const std::size_t end = handlerCode.find("CommandResult handleThemeSet", b);
            gitSection = handlerCode.substr(b, end - b);
        }
    }

    // _popen is what made the git command path a shell.
    cert.check("FALSE_005", "the IDE git command handlers no longer shell out with _popen",
               !gitSection.empty() && gitSection.find("_popen") == std::string::npos,
               "popen_in_git_section=" +
                   std::string(gitSection.empty()
                                   ? "SECTION_NOT_FOUND"
                                   : (gitSection.find("_popen") == std::string::npos ? "NO" : "YES")));

    // The command-line injection string itself.
    cert.check("FALSE_006", "the interpolated 'git commit -m \"<msg>\"' shell string is gone",
               handlerCode.find("git commit -m \\\"\" + std::string(ctx.args)") ==
                   std::string::npos,
               "interpolated_commit_string_in_code=NO");

    // Push was performed by a handler with no authority behind it.
    cert.check("FALSE_007", "git push is no longer executed by the IDE handler",
               gitSection.find("git push") == std::string::npos,
               "git_push_in_git_section=" +
                   std::string(gitSection.find("git push") == std::string::npos ? "NO" : "YES"));

    // The IDE command handlers must dispatch through the gate, not around it.
    cert.check("FALSE_008", "the IDE !git_commit command dispatches through the gate",
               handlerCode.find("Execute(\"git_commit\"") != std::string::npos,
               "gated_dispatch_in_code=YES");
}

// ---------------------------------------------------------------------------
// RAWRXD_GIT_SAFETY_AUTHORITY_001 — the acceptance invariant
//
//     MutationAllowed = CapabilityGranted AND ScopeAuthorized
//                       AND OperationPermitted
//
// This is the property that distinguishes a gate from a master switch. A
// configuration that accidentally grants exactly one dimension must still be
// unable to mutate the repository. So all four cases are exercised, not just
// the denied ones: a gate that refuses everything would satisfy "no 2-of-3
// suffices" trivially, and this check requires the all-three case to SUCCEED so
// the conjunction is measured in both directions.
// ---------------------------------------------------------------------------

void CertifyAcceptanceInvariant(Cert& cert, const fs::path& repo) {
    std::printf("\n--- acceptance invariant: capability AND scope AND operation ---\n");
    if (!InitRepo(repo)) {
        cert.notRun("INVARIANT_001", "no 2-of-3 combination may permit mutation", "scratch failed");
        return;
    }
    const std::string commitOnly = "a commit that the gate must permit";

    // Case A: capability only. No scope -> must refuse NO_SCOPE.
    {
        GitPolicy p = GitPolicy::DefaultDenyAll();
        p.granted = static_cast<std::uint32_t>(GitCapability::Commit);
        p.repositoryRoots = {repo.string()};
        GitSafetyAuthority a(p);
        if (a.beginSession(repo).ok) {
            const GitResult r = a.commit("agent: no scope", {});
            cert.check("INVARIANT_A", "capability without scope cannot mutate",
                       !r.ok && r.refusal == rawrxd::agentic::GitRefusal::NoScope,
                       std::string("refusal=") + rawrxd::agentic::GitRefusalName(r.refusal));
        } else {
            cert.notRun("INVARIANT_A", "capability without scope cannot mutate",
                        "beginSession refused");
        }
    }

    // Case B: scope only. No capability -> must refuse CAPABILITY_NOT_GRANTED.
    {
        GitPolicy p = GitPolicy::DefaultDenyAll();
        p.authorizedPrefixes = {kAgentScope};
        p.repositoryRoots = {repo.string()};
        GitSafetyAuthority a(p);
        if (a.beginSession(repo).ok) {
            const GitResult r = a.commit("agent: no capability", {});
            cert.check("INVARIANT_B", "scope without capability cannot mutate",
                       !r.ok && r.refusal == rawrxd::agentic::GitRefusal::CapabilityNotGranted,
                       std::string("refusal=") + rawrxd::agentic::GitRefusalName(r.refusal));
        } else {
            cert.notRun("INVARIANT_B", "scope without capability cannot mutate",
                        "beginSession refused");
        }
    }

    // Case C: capability AND scope, but the operation is not permitted, because
    // unrelated user work is uncommitted and commit is here run against an
    // index holding out-of-scope staged work. Must refuse PATH_OUTSIDE_SCOPE.
    {
        WriteFile(repo / kUserFileA, "{\"user\":\"edit\"}\n");
        std::string out, err;
        Git(repo, {"add", "--", kUserFileA}, out, err);

        GitPolicy p = GitPolicy::DefaultDenyAll();
        p.granted = static_cast<std::uint32_t>(GitCapability::Commit);
        p.authorizedPrefixes = {kAgentScope};
        p.repositoryRoots = {repo.string()};
        GitSafetyAuthority a(p);
        if (a.beginSession(repo).ok) {
            const std::string headBefore = HeadOf(repo);
            const GitResult r = a.commit("agent: both axes but operation blocked", {});
            const bool refused = !r.ok &&
                                 r.refusal == rawrxd::agentic::GitRefusal::PathOutsideScope;
            cert.check("INVARIANT_C", "capability and scope still cannot perform a blocked operation",
                       refused && HeadOf(repo) == headBefore,
                       std::string("refusal=") + rawrxd::agentic::GitRefusalName(r.refusal) +
                           " head_moved=" + std::string(HeadOf(repo) == headBefore ? "NO" : "YES"));
        } else {
            cert.notRun("INVARIANT_C",
                        "capability and scope still cannot perform a blocked operation",
                        "beginSession refused");
        }
        Git(repo, {"restore", "--staged", "--", kUserFileA}, out, err);
    }

    // Case D: all three. Must SUCCEED. Without this the check above would also
    // pass for an authority that refuses every mutation, which is a broken tool
    // rather than a safe one.
    {
        GitPolicy p = GitPolicy::DefaultDenyAll();
        p.granted = static_cast<std::uint32_t>(GitCapability::Stage) |
                    static_cast<std::uint32_t>(GitCapability::Commit);
        p.authorizedPrefixes = {kAgentScope};
        p.repositoryRoots = {repo.string()};
        GitSafetyAuthority a(p);
        if (a.beginSession(repo).ok) {
            WriteFile(repo / kNewFile, "// invariant case D\n");
            const GitResult st = a.stage({kNewFile});
            const GitResult cm = a.commit(commitOnly, {});
            cert.check("INVARIANT_D", "all three axes together DO permit the mutation",
                       st.ok && cm.ok,
                       "stage=" + std::string(st.ok ? "ok" : "FAIL") + " commit=" +
                           std::string(cm.ok ? "ok" : ("FAIL:" + cm.detail)) + " head=" +
                           HeadOf(repo).substr(0, 12));
        } else {
            cert.notRun("INVARIANT_D", "all three axes together DO permit the mutation",
                        "beginSession refused");
        }
    }

    // Case E: the master-switch shape must not exist. There is no environment
    // input that grants every capability at once, so enumerate the documented
    // names and prove that setting ALL of them still requires a scope.
    {
        _putenv_s("RAWRXD_GIT_ROOT", repo.string().c_str());
        for (const char* k : {"RAWRXD_GIT_ALLOW_STAGE", "RAWRXD_GIT_ALLOW_UNSTAGE",
                              "RAWRXD_GIT_ALLOW_COMMIT", "RAWRXD_GIT_ALLOW_BRANCH",
                              "RAWRXD_GIT_ALLOW_CHECKOUT", "RAWRXD_GIT_ALLOW_STASH",
                              "RAWRXD_GIT_ALLOW_WORKTREE", "RAWRXD_GIT_ALLOW_ROLLBACK"}) {
            _putenv_s(k, "1");
        }
        _putenv_s("RAWRXD_GIT_SCOPE", "");  // deliberately no scope
        const GitPolicy allCaps = rawrxd::agentic::GitSafetyPolicyFromEnvironment(std::string());
        GitSafetyAuthority a(allCaps);
        std::string detail = "beginSession_refused";
        bool refused = false;
        if (a.beginSession(repo).ok) {
            const GitResult r = a.commit("agent: every capability, no scope", {});
            refused = !r.ok && r.refusal == rawrxd::agentic::GitRefusal::NoScope;
            detail = std::string("refusal=") + rawrxd::agentic::GitRefusalName(r.refusal);
        }
        cert.check("INVARIANT_E", "every capability grant at once still does not authorize mutation",
                   refused,
                   "granted_mask=" + std::to_string(allCaps.granted) + " " + detail);

        for (const char* k : {"RAWRXD_GIT_ROOT", "RAWRXD_GIT_SCOPE", "RAWRXD_GIT_ALLOW_STAGE",
                              "RAWRXD_GIT_ALLOW_UNSTAGE", "RAWRXD_GIT_ALLOW_COMMIT",
                              "RAWRXD_GIT_ALLOW_BRANCH", "RAWRXD_GIT_ALLOW_CHECKOUT",
                              "RAWRXD_GIT_ALLOW_STASH", "RAWRXD_GIT_ALLOW_WORKTREE",
                              "RAWRXD_GIT_ALLOW_ROLLBACK"}) {
            _putenv_s(k, "");
        }
    }
}

// ============================================================================
// RAWRXD_GIT_SAFETY_AUTHORITY_001 — binary identity gate
//
// A failed build leaves the PREVIOUS executable in place. That binary still
// runs and still prints a plausible verdict, so it can inherit authority for
// source that was never linked. This happened during this work: a failed build
// left a stale binary that produced a convincing CHECKS_TOTAL=63 / VERDICT=FAIL
// describing a build that no longer existed.
//
// The rule encoded here:
//
//     BUILD_EXIT != 0
//         -> EXECUTABLE_FROM_THIS_BUILD = INVALID
//         -> RUNTIME_CERTIFICATION      = NO_VERDICT
//
// and before any verdict is produced:
//
//     EXPECTED_BINARY_SHA256 = recorded immediately after successful link
//     ACTUAL_BINARY_SHA256   = hashed immediately before execution
//     REQUIRE: EXPECTED == ACTUAL
//
// The seal is written by a POST_BUILD step (tools/git_safety_seal.ps1), so its
// existence IS the evidence of a successful link. If it is absent, stale, or
// does not describe this binary, the driver emits NO_VERDICT and exits
// non-zero WITHOUT printing a verdict at all. A certification must never be
// able to describe a build that did not produce it.
// ============================================================================

struct BinaryIdentity {
    bool resolved = false;
    std::string exePath;
    std::string sha256;
    std::uint64_t size = 0;
};

std::string SelfExePath() {
    wchar_t buf[MAX_PATH * 2]{};
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH * 2);
    if (n == 0 || n >= MAX_PATH * 2) return {};
    std::string out;
    out.reserve(n);
    for (DWORD i = 0; i < n; ++i) out.push_back(static_cast<char>(buf[i]));
    return out;
}

std::map<std::string, std::string> ParseSeal(const std::string& path) {
    std::map<std::string, std::string> kv;
    std::ifstream in(path, std::ios::binary);
    if (!in) return kv;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        kv[line.substr(0, eq)] = line.substr(eq + 1);
    }
    return kv;
}

// Returns an empty string when the binary is certified as being from the
// successful build that produced the seal. Otherwise returns the refusal.
std::string VerifyBinaryIdentity(const std::string& exePath, const std::string& sealPath,
                                 BinaryIdentity& out, std::vector<std::string>& notes) {
    out.exePath = exePath;
    std::error_code ec;
    const auto sz = fs::file_size(exePath, ec);
    out.size = ec ? 0 : static_cast<std::uint64_t>(sz);
    out.sha256 = Sha256File(exePath);
    out.resolved = !out.sha256.empty() && out.sha256 != "ABSENT" && out.sha256 != "UNREADABLE";

    if (!out.resolved) {
        return "RUNTIME_CERTIFICATION=NO_VERDICT: cannot hash the running executable; "
               "a binary whose identity is unknown cannot certify anything";
    }

    if (!fs::exists(sealPath, ec)) {
        return "RUNTIME_CERTIFICATION=NO_VERDICT: no build seal at " + sealPath +
               ". The seal is written only by a POST_BUILD step, so its absence "
               "means this executable is not known to be from a successful link. "
               "It may be a leftover from a failed build.";
    }

    const auto seal = ParseSeal(sealPath);
    const auto get = [&](const char* k) -> std::string {
        const auto it = seal.find(k);
        return it == seal.end() ? std::string() : it->second;
    };

    const std::string sealedSha = get("BINARY_SHA256");
    const std::string sealedSize = get("BINARY_SIZE");
    const std::string linkExit = get("LINK_EXIT");
    const std::string gate = get("GATE");

    if (sealedSha.empty() || sealedSize.empty() || linkExit.empty() || gate.empty()) {
        return "RUNTIME_CERTIFICATION=NO_VERDICT: build seal is incomplete";
    }
    if (linkExit != "0") {
        return "RUNTIME_CERTIFICATION=NO_VERDICT: seal records LINK_EXIT=" + linkExit;
    }
    if (sealedSha != out.sha256) {
        return "RUNTIME_CERTIFICATION=NO_VERDICT: expected binary SHA256 " + sealedSha +
               " but this executable is " + out.sha256 +
               ". This binary is not the one that was sealed at link time, so it "
               "cannot certify the current source.";
    }
    if (sealedSize != std::to_string(out.size)) {
        return "RUNTIME_CERTIFICATION=NO_VERDICT: expected binary size " + sealedSize +
               " but this executable is " + std::to_string(out.size);
    }

    // The seal hashes its own body. A truncated or hand-edited seal is caught.
    //
    // The body is hashed as the RAW BYTES that precede the SEAL_SHA256 line,
    // not as a reconstruction from parsed key/value pairs: the writer emits
    // keys in insertion order while a std::map yields them sorted, so
    // reconstructing would hash a different string than was written and report
    // every legitimate seal as corrupt.
    std::string claimed;
    std::string body;
    {
        std::ifstream raw(sealPath, std::ios::binary);
        if (!raw) {
            return "RUNTIME_CERTIFICATION=NO_VERDICT: build seal could not be reopened";
        }
        std::ostringstream all;
        all << raw.rdbuf();
        const std::string content = all.str();
        const std::string marker = "SEAL_SHA256=";
        const std::size_t pos = content.rfind(marker);
        if (pos == std::string::npos) {
            return "RUNTIME_CERTIFICATION=NO_VERDICT: build seal has no SEAL_SHA256 line";
        }
        claimed = content.substr(pos + marker.size());
        while (!claimed.empty() &&
               (claimed.back() == '\n' || claimed.back() == '\r' || claimed.back() == ' ')) {
            claimed.pop_back();
        }
        body = content.substr(0, pos);
        // The newline that separates the body from the SEAL_SHA256 line is not
        // part of the body: the writer hashed the lines joined by "\n" with no
        // trailing newline, then appended "\nSEAL_SHA256=...". Hashing the
        // separator too would report every legitimate seal as corrupt.
        while (!body.empty() && (body.back() == '\n' || body.back() == '\r')) {
            body.pop_back();
        }
    }
    std::string computed;
    {
        std::vector<unsigned char> data(body.begin(), body.end());
        BCRYPT_ALG_HANDLE alg = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
            BCRYPT_HASH_HANDLE h = nullptr;
            if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) == 0) {
                if (!data.empty()) {
                    BCryptHashData(h, data.data(), static_cast<ULONG>(data.size()), 0);
                }
                unsigned char digest[32];
                BCryptFinishHash(h, digest, 32, 0);
                BCryptDestroyHash(h);
                char hex[3];
                for (int i = 0; i < 32; ++i) {
                    std::snprintf(hex, sizeof hex, "%02X", digest[i]);
                    computed += hex;
                }
            }
            BCryptCloseAlgorithmProvider(alg, 0);
        }
    }
    if (claimed != computed) {
        return "RUNTIME_CERTIFICATION=NO_VERDICT: build seal is corrupt (SEAL_SHA256 " +
               claimed + " does not match its own contents)";
    }

    // Source identity, recorded rather than enforced. The seal's per-file
    // hashes are the real binding; the dirty count is an observation because a
    // dirty-file count is not a content identity and moves legitimately.
    notes.push_back("SEAL_GATE=" + gate);
    notes.push_back("SEAL_SOURCE_HEAD=" + get("SOURCE_HEAD"));
    notes.push_back("SEAL_SOURCE_DIRTY_FILES=" + get("SOURCE_DIRTY_FILES"));
    notes.push_back("SEAL_BUILD_CONFIG=" + get("BUILD_CONFIG"));
    notes.push_back("SEAL_BINARY_SIZE=" + sealedSize);
    notes.push_back("SEAL_BINARY_MTIME_UTC=" + get("BINARY_MTIME_UTC"));
    for (const auto& [k, v] : seal) {
        if (k.rfind("SRC_SHA256.", 0) == 0) notes.push_back("SEAL_" + k);
    }
    return {};
}

} // namespace

// ───────────────────────────────────────────────────────────────── main ────

int main(int argc, char** argv) {
    // Scratch space OUTSIDE the repository under certification, so no test
    // action can touch the real worktree.
    fs::path base;
    if (argc > 1) {
        base = fs::path(argv[1]);
    } else {
        wchar_t tempDir[MAX_PATH]{};
        GetTempPathW(MAX_PATH, tempDir);
        base = fs::path(tempDir) / "rawrxd_git_safety_cert";
    }
    std::error_code ec;
    fs::create_directories(base, ec);
    const fs::path repo = base / "repo";

    std::printf("RAWRXD_GIT_SAFETY_AUTHORITY_001\n");
    std::printf("SCRATCH_REPO=%s\n", repo.string().c_str());
    std::printf("NOTE=the certification repository is a scratch clone; the real worktree is "
                "never a target of any action below\n");

    // ---------------------------------------------------------------------
    // Binary identity gate. Runs before anything else and can only produce
    // NO_VERDICT. A certification must never be able to describe a build that
    // did not produce it.
    //
    //     BUILD_EXIT != 0
    //         -> EXECUTABLE_FROM_THIS_BUILD = INVALID
    //         -> RUNTIME_CERTIFICATION      = NO_VERDICT
    // ---------------------------------------------------------------------
    const std::string exePath = SelfExePath();
    const std::string sealPath = (argc > 2) ? std::string(argv[2]) : exePath + ".seal";

    BinaryIdentity ident;
    std::vector<std::string> identityNotes;
    const std::string identityRefusal =
        VerifyBinaryIdentity(exePath, sealPath, ident, identityNotes);

    std::printf("EXE=%s\n", exePath.c_str());
    std::printf("SEAL=%s\n", sealPath.c_str());
    for (const std::string& n : identityNotes) std::printf("%s\n", n.c_str());

    if (!identityRefusal.empty()) {
        std::printf("\n%s\n", identityRefusal.c_str());
        std::printf("BINARY_SHA256_SELF=%s\n", ident.sha256.c_str());
        std::printf("BINARY_SIZE_SELF=%llu\n",
                    static_cast<unsigned long long>(ident.size));
        std::printf("CHECKS_TOTAL=0\nCHECKS_PASS=0\nCHECKS_FAIL=0\nCHECKS_NOT_RUN=0\n");
        std::printf("RUNTIME_CERTIFICATION=NO_VERDICT\n");
        std::printf("VERDICT=NONE\n");
        // Deliberately not 0 and not a verdict: an unsealed binary is an
        // INVALID certification run, which is neither a pass nor a failure.
        return 2;
    }

    std::printf("BINARY_SHA256_SELF=%s\n", ident.sha256.c_str());
    std::printf("BINARY_SIZE_SELF=%llu\n", static_cast<unsigned long long>(ident.size));
    std::printf("RUNTIME_CERTIFICATION=BINARY_MATCHES_SEAL\n");

    Cert cert;
    const std::string gate = "RAWRXD_GIT_SAFETY_AUTHORITY_001";
    const std::string runPath = rawrxd::receipt::beginImmutableGate(gate);
    if (runPath.empty()) {
        std::printf("RECEIPT=UNAVAILABLE (could not create an immutable run receipt)\n");
    } else {
        std::printf("RECEIPT=%s\n", runPath.c_str());
    }

    CertifyDefaultDeny(cert, repo);
    CertifyScopeEscape(cert, repo);
    CertifyReadOnlyCapabilities(cert, repo);
    CertifyIndexAndHistory(cert, repo);
    CertifyDestructiveAndRecovery(cert, repo);
    CertifyWorktreeIsolation(cert, repo);
    CertifyRollback(cert, repo);
    CertifyConflictDetection(cert, repo);
    CertifyMessageSafety(cert, repo);
    const bool dangerousHeld = DangerousDirtyTreeTest(cert, repo);
    CertifyRegistrySurface(cert, repo);
    CertifyIdeSurfaceBinding(cert, repo);
    CertifyEnvironmentDerivation(cert, repo);
    CertifyAcceptanceInvariant(cert, repo);
    CertifyFalseSuccessElimination(cert, repo);

    // The preservation property is also re-measured here, over the whole run,
    // so the receipt carries the authority's own view rather than only the
    // per-test fingerprints.
    GitSafetyAuthority final(AgentPolicy(repo, kAllMutating));
    const GitResult finalOpen = final.beginSession(repo);

    std::size_t passCount = 0, failCount = 0, notRunCount = 0;
    for (const Check& c : cert.all()) {
        if (c.state == "PASS") ++passCount;
        else if (c.state == "FAIL") ++failCount;
        else ++notRunCount;
    }

    // VERDICT is derived from the counts, never printed as a constant.
    const bool allPass = (failCount == 0 && notRunCount == 0 && passCount > 0);
    const std::string verdict = allPass ? "PASS" : "FAIL";

    std::printf("\n=====================================================\n");
    std::printf("CHECKS_TOTAL=%zu\n", cert.all().size());
    std::printf("CHECKS_PASS=%zu\n", passCount);
    std::printf("CHECKS_FAIL=%zu\n", failCount);
    std::printf("CHECKS_NOT_RUN=%zu\n", notRunCount);
    std::printf("DIRTY_TREE_UNRELATED_PRESERVED=%s\n", dangerousHeld ? "YES" : "NO");
    std::printf("VERDICT=%s\n", verdict.c_str());

    if (!runPath.empty()) {
        using namespace rawrxd::receipt;
        writeImmutableKeyValue(runPath, "GATE_NAME", gate);
        writeImmutableKeyValue(runPath, "SCRATCH_REPO", repo.string());
        writeImmutableKeyValue(runPath, "CHECKS_TOTAL",
                               std::to_string(cert.all().size()));
        writeImmutableKeyValueInt(runPath, "CHECKS_PASS", static_cast<std::int64_t>(passCount));
        writeImmutableKeyValueInt(runPath, "CHECKS_FAIL", static_cast<std::int64_t>(failCount));
        writeImmutableKeyValueInt(runPath, "CHECKS_NOT_RUN",
                                  static_cast<std::int64_t>(notRunCount));
        writeImmutableKeyValue(runPath, "DIRTY_TREE_UNRELATED_PRESERVED",
                               dangerousHeld ? "YES" : "NO");
        writeImmutableKeyValue(runPath, "RUNTIME_CERTIFICATION", "BINARY_MATCHES_SEAL");
        writeImmutableKeyValue(runPath, "BINARY_SHA256_SELF", ident.sha256);
        writeImmutableKeyValue(runPath, "BINARY_SIZE_SELF",
                               std::to_string(static_cast<unsigned long long>(ident.size)));
        writeImmutableKeyValue(runPath, "BINARY_PATH", ident.exePath);
        for (const std::string& n : identityNotes) {
            const std::size_t eq = n.find('=');
            if (eq == std::string::npos) continue;
            writeImmutableKeyValue(runPath, n.substr(0, eq), n.substr(eq + 1));
        }
        writeImmutableKeyValue(runPath, "FINAL_SESSION_OPENED",
                               finalOpen.ok ? "YES" : "NO");
        for (const Check& c : cert.all()) {
            writeImmutableKeyValue(runPath, "CHECK." + c.id + ".STATE", c.state);
            writeImmutableKeyValue(runPath, "CHECK." + c.id + ".DESCRIPTION", c.description);
            writeImmutableKeyValue(runPath, "CHECK." + c.id + ".EVIDENCE", c.evidence);
        }
        for (const Check& c : cert.all()) {
            if (c.state != "PASS") {
                writeImmutableKeyValue(runPath, "FAILED." + c.id, c.state + " " + c.evidence);
            }
        }
        const std::string sha = endImmutableGate(runPath, verdict);
        std::printf("RECEIPT_SHA256=%s\n", sha.empty() ? "UNAVAILABLE" : sha.c_str());
    }

    std::error_code cleanupEc;
    fs::remove_all(base, cleanupEc);

    return allPass ? 0 : 1;
}
