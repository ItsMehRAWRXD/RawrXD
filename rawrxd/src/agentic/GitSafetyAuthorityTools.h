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

} // namespace agentic
} // namespace rawrxd
