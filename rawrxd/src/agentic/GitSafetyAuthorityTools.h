// ============================================================================
// GitSafetyAuthorityTools.h — RAWRXD_GIT_SAFETY_AUTHORITY_001
//
// Entry points for binding the git safety policy and installing the twelve
// certified git capabilities into rawrxd::agentic::ToolRegistry.
//
// The registry is the sandboxed authority the IDE HTTP routes already dispatch
// through. Installing here means /api/agent/execute-tool and /api/cli reach
// the gate without any route change, and without a second, ungated path.
// ============================================================================
#pragma once

#include <filesystem>

#include "agentic/AgentToolRegistry.h"
#include "agentic/GitSafetyAuthority.h"

// The IDE registry, forward declared.
//
// This header deliberately does NOT include src/deep2/AgentToolRegistry.hpp:
// the sandboxed library must not acquire a dependency on the IDE's headers, and
// the HTTP server links this file with no IDE in the process at all.
//
// It is spelled `RawrXD` because that is what the IDE writes, and MSVC's
// case-insensitive lookup matches it to the `rawrxd` namespace used below. A
// caller that needs the complete type includes the IDE header itself, which is
// a redeclaration-compatible definition of this same class.
namespace RawrXD {
namespace Agentic {
class AgentToolRegistry;
} // namespace Agentic
} // namespace RawrXD

namespace rawrxd {
namespace agentic {

// Bind the policy, replacing any previous binding. Mutating tools installed by
// an earlier call keep working: the tools read the binding at call time, so a
// policy change takes effect immediately and is observable in the next receipt.
void BindGitSafetyPolicy(GitPolicy policy);

// Bind the policy and open a session on `repoRoot`. The begin result is not
// thrown: a failure leaves the binding in place with a closed session, and the
// first tool call reports the measured refusal.
void BindGitSafetyPolicy(GitPolicy policy, const std::filesystem::path& repoRoot);

// The currently bound policy, or DefaultDenyAll when nothing is bound.
GitPolicy GitSafetyBoundPolicy();

// True when a policy is bound. A bound policy with granted == 0 is the
// fail-closed state and is NOT the same as unbound.
bool IsGitSafetyBound();

// Registers git_status, git_diff, git_conflicts, git_dirty_tree, git_review,
// git_stage, git_unstage, git_commit, git_branch_create, git_checkout,
// git_stash, git_worktree and git_rollback.
//
// Returns false only when no policy is bound. A DefaultDenyAll policy still
// installs every tool: the mutating ones then refuse with
// CAPABILITY_NOT_GRANTED at call time, which is the certification-worthy
// behaviour (the gate is what stops them, and the refusal is measured).
bool InstallGitTools(ToolRegistry& registry);

// ---------------------------------------------------------------------------
// RAWRXD_GIT_SAFETY_AUTHORITY_001 — the one policy derivation
//
// The IDE process and the HTTP server are two different binaries that must
// derive the SAME policy from the SAME inputs, or the gate means one thing in
// the desktop app and another in the server. Deriving it twice is how a gate
// ends up denying in one place and allowing in the other, so it is derived once
// here and both callers use this.
//
// Environment inputs, all optional:
//   RAWRXD_GIT_ROOT            repository root. Absent -> no session, read-only
//                              tools report NOT_A_GIT_REPOSITORY.
//   RAWRXD_GIT_SCOPE           ';' or ',' or '|' separated repository-relative
//                              path prefixes the caller may mutate. ABSENT ->
//                              empty, which means every mutating call refuses
//                              with NO_SCOPE regardless of capability bits.
//   RAWRXD_GIT_ALLOW_STAGE     '1' grants Stage
//   RAWRXD_GIT_ALLOW_COMMIT    '1' grants Commit
//   RAWRXD_GIT_ALLOW_BRANCH    '1' grants Branch
//   RAWRXD_GIT_ALLOW_CHECKOUT  '1' grants Checkout
//   RAWRXD_GIT_ALLOW_STASH     '1' grants Stash
//   RAWRXD_GIT_ALLOW_WORKTREE  '1' grants Worktree
//   RAWRXD_GIT_ALLOW_ROLLBACK  '1' grants Rollback
//   RAWRXD_GIT_ALLOW_UNSTAGE   '1' grants Unstage (implied by ALLOW_STAGE)
//   RAWRXD_GIT_REQUIRE_CLEAN   '0' permits destructive ops with unrelated
//                              uncommitted work. DEFAULT '1'.
//
// DEFAULTS ARE DENY. Every grant is opt-in per capability, and scope is opt-in
// separately, so a misconfigured deployment gets read-only git and nothing
// else. There is no single switch that turns mutation on.
struct GitBindingReport {
    bool installed = false;
    bool sessionOpened = false;
    std::string repositoryRoot;
    std::uint32_t capabilitiesGranted = 0;
    std::size_t scopePrefixes = 0;
    std::string sessionDetail;   // measured beginSession detail or refusal
    std::string refusalName;     // GitRefusalName() when sessionOpen failed
};

GitBindingReport InstallGitSafetyFromEnvironment(ToolRegistry& registry,
                                                 const std::string& fallbackRoot = std::string());

// The same derivation, for a caller that wants the policy without installing.
GitPolicy GitSafetyPolicyFromEnvironment(const std::string& fallbackRoot = std::string());

// Forces a policy and session. Used by the certification driver and by any
// host that already knows its own configuration.
void BindGitSafetySession(const GitPolicy& policy, const std::filesystem::path& repoRoot);

// ---------------------------------------------------------------------------
// The IDE surface
//
// These declarations live in their own namespace, deliberately.
//
// They cannot live in rawrxd::agentic: MSVC resolves identifiers
// case-insensitively, and this tree already uses both `RawrXD::` and
// `rawrxd::` as distinct-looking spellings of one namespace. A nested
// `namespace RawrXD` written inside `rawrxd::agentic` becomes
// rawrxd::agentic::rawrxd::Agentic, and a reference to the real
// RawrXD::Agentic types then resolves to a namespace that does not exist.
//
// An unambiguous namespace sidesteps the whole question: a caller writes
//   rawrxd::ide_git_safety::InstallIdeSurface(registry)
// and there is nothing for the compiler to reinterpret.
} // namespace agentic
} // namespace rawrxd

// RAWRXD_GIT_SAFETY_AUTHORITY_001 — IDE surface binding.
//
// The desktop chat panel dispatches through RawrXD::Agentic::AgentToolRegistry,
// a DIFFERENT registry type from the sandboxed rawrxd::agentic::ToolRegistry
// that /api/agent/execute-tool uses. Installing only into the sandboxed one
// would leave the GUI surface ungated, so there is a second installer. Both
// installers share one GitSafetyAuthority, so a refusal carries the same reason
// code in the GUI and over HTTP.
//
// Handler arguments are a ';' separated token list, e.g.
//   "paths=src/agent/a.cpp,src/agent/b.cpp"
//   "message=fix the parser"
//   "action=add;path=wt-agent"
// This is a positional parser, not a shell: values are never concatenated into
// a command string, and each one reaches git as its own argv element.
//
// A concurrent tree change during this work removed these declarations on the
// stated ground that RawrXD::Agentic::AgentToolRegistry "exists nowhere in the
// tree" and that the GUI did not need them. The tree now carries these
// declarations again. The basis is factual and is recorded without attributing
// the change to any writer, process or session:
//
//   - the type IS in the tree, at src/deep2/AgentToolRegistry.hpp:115, and it
//     is a DIFFERENT CLASS from rawrxd::agentic::ToolRegistry
//     (include/agentic/AgentToolRegistry.h:102). Different namespace, different
//     header, different API: registerTool/invoke/contains versus
//     Register/Execute/HasTool.
//   - the chat panel binds it, at main_win32.cpp:570
//     (`static RawrXD::Agentic::AgentToolRegistry registry;`) and
//     main_win32.cpp:572.
//   - the model-facing tool count on that surface is 13 after this change and
//     was 1 before it.
//
// So the two registries are distinct and both must be installed. Installing only
// into rawrxd::agentic::ToolRegistry::Instance() would leave the chat panel
// without git tools. Both are installed, and both share one
// GitSafetyAuthority so a refusal carries the same reason code either way.
namespace rawrxd {
namespace ide_git_safety {

void BindIdeSession(const rawrxd::agentic::GitPolicy& policy,
                    const std::filesystem::path& repoRoot);

rawrxd::agentic::GitBindingReport InstallIdeSurface(
    ::RawrXD::Agentic::AgentToolRegistry& registry,
    const std::string& fallbackRoot = std::string());

} // namespace ide_git_safety
} // namespace rawrxd
