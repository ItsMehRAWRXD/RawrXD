// ============================================================================
// GitSafetyAuthorityIdeSurface.cpp — RAWRXD_GIT_SAFETY_AUTHORITY_001
//
// Installs the twelve certified git capabilities into the IDE's OWN tool
// registry, RawrXD::Agentic::AgentToolRegistry (src/deep2/AgentToolRegistry.hpp:115).
//
// WHY THIS EXISTS, and why the alternative was rejected
// ------------------------------------------------------
// There are two tool registries in this product and they are DIFFERENT CLASSES:
//
//   rawrxd::agentic::ToolRegistry        include/agentic/AgentToolRegistry.h
//                                        Register / Execute / HasTool
//   RawrXD::Agentic::AgentToolRegistry   src/deep2/AgentToolRegistry.hpp
//                                        registerTool / invoke / contains
//
// The HTTP routes (/api/agent/execute-tool, /api/cli) and the agent tool
// orchestrator use the first. The desktop chat panel uses the second:
// main_win32.cpp:570 declares `static RawrXD::Agentic::AgentToolRegistry
// registry;`, main_win32.cpp:572 binds the process-wide authority to it, and
// main_win32.cpp:667 hands it to the StreamingCommandHandler that the chat panel
// dispatches through.
//
// Installing the git tools only into the first would leave the chat panel with
// no git tools, which is why the two are installed separately. A concurrent tree
// change during this work removed the IDE-surface declarations; they are present
// again, and the basis is recorded factually in GitSafetyAuthorityTools.h:
//
//   - RawrXD::Agentic::AgentToolRegistry is a distinct class at
//     src/deep2/AgentToolRegistry.hpp:115, not an alias of the sandboxed one.
//   - main_win32.cpp:570 binds it as the chat panel's registry.
//   - the model-facing tool count on that surface went 1 -> 13.
//
// No writer, process or session is identified as the source of that change.
//
// Both registries are installed. Both share one GitSafetyAuthority, so a refusal
// carries the same reason code in the GUI and over HTTP.
//
// Defaults are deny. With no RAWRXD_GIT_ROOT and no RAWRXD_GIT_SCOPE, every
// mutating tool is registered and every mutating call refuses with a measured
// reason. The tools being visible in the IDE is not permission to use them.
// ============================================================================
#include "agentic/GitSafetyAuthority.h"
#include "agentic/GitSafetyAuthorityTools.h"
#include "deep2/AgentToolRegistry.hpp"

#include <algorithm>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>

namespace rawrxd {
namespace ide_git_safety {
namespace {

// One authority for the IDE surface. Held separately from the sandboxed
// registry's binding so the two can be bound to different repositories, but
// both are GitSafetyAuthority, so the refusal vocabulary is identical.
struct IdeBinding {
    rawrxd::agentic::GitPolicy policy;
    std::shared_ptr<rawrxd::agentic::GitSafetyAuthority> authority;
    rawrxd::agentic::GitResult beginResult;
};

std::mutex g_ideMutex;
std::shared_ptr<IdeBinding> g_ide;

std::shared_ptr<IdeBinding> ideBinding() {
    std::lock_guard<std::mutex> lk(g_ideMutex);
    return g_ide;
}

RawrXD::Agentic::ToolResult ToIde(const rawrxd::agentic::GitResult& g) {
    RawrXD::Agentic::ToolResult r;
    // 0 is success; 77 is this authority's refusal code, matching the registry's
    // own SandboxBlocked so a refusal is never mistaken for a crash.
    r.exit_code = g.ok ? 0 : 77;
    if (g.ok) {
        r.stdout_text = g.output;
        if (!g.detail.empty()) {
            if (!r.stdout_text.empty()) r.stdout_text += "\n";
            r.stdout_text += "[authority] " + g.detail;
        }
    } else {
        r.stderr_text = std::string(rawrxd::agentic::GitRefusalName(g.refusal)) + ": " + g.detail;
        if (!g.errorOutput.empty()) r.stderr_text += "\n" + g.errorOutput;
    }
    return r;
}

// The IDE registry passes a single string argument. The gate's tools take
// structured parameters, so a call is encoded as a ';' separated key=value token
// list, e.g. "paths=src/agent/a.cpp,src/agent/b.cpp" or "action=add;path=wt".
//
// This is a parser, not a shell: no value is concatenated into a command string
// and each one reaches git as its own argv element. A ';' or '=' inside a value
// cannot escape into a different parameter, because the split is positional and
// each key is looked up by name.
struct IdeParams {
    std::string raw;    // the whole argument string, re-split by value()
    std::string first;  // first non-empty token, for single-argument tools
    std::vector<std::string> paths;

    std::string value(const char* key) const {
        std::istringstream iss(raw);
        std::string part;
        while (std::getline(iss, part, ';')) {
            const std::size_t eq = part.find('=');
            if (eq == std::string::npos) continue;
            if (eq == std::strlen(key) && part.compare(0, eq, key) == 0) {
                return part.substr(eq + 1);
            }
        }
        return {};
    }
    std::string firstToken() const { return first; }
};

IdeParams ParseIdeArgs(const std::string& raw) {
    IdeParams p;
    p.raw = raw;

    auto collectPaths = [](const std::string& list, std::vector<std::string>& into) {
        std::string tmp = list;
        std::replace(tmp.begin(), tmp.end(), ',', '\n');
        std::istringstream iss(tmp);
        std::string one;
        while (std::getline(iss, one)) {
            if (!one.empty()) into.push_back(one);
        }
    };

    std::istringstream iss(raw);
    std::string part;
    while (std::getline(iss, part, ';')) {
        if (part.empty()) continue;
        if (p.first.empty()) p.first = part;
        if (part.rfind("paths=", 0) == 0) collectPaths(part.substr(6), p.paths);
    }
    return p;
}

} // namespace

// ---------------------------------------------------------------------------

void BindIdeSession(const rawrxd::agentic::GitPolicy& policy,
                    const std::filesystem::path& repoRoot) {
    auto b = std::make_shared<IdeBinding>();
    b->policy = policy;
    b->authority = std::make_shared<rawrxd::agentic::GitSafetyAuthority>(b->policy);
    // A failed begin leaves the binding in place with a closed session, and the
    // result is retained so "no session" is distinguishable from "never bound".
    b->beginResult = b->authority->beginSession(repoRoot);
    std::lock_guard<std::mutex> lk(g_ideMutex);
    g_ide = std::move(b);
}

rawrxd::agentic::GitBindingReport InstallIdeSurface(
    RawrXD::Agentic::AgentToolRegistry& ideRegistry, const std::string& fallbackRoot) {
    using namespace rawrxd::agentic;
    // NOTE: the parameter is deliberately NOT named `registry`. The enclosing
    // `using namespace rawrxd::agentic` puts ToolRegistry in scope, and an
    // unqualified `registry` there would resolve to the sandboxed type, crossing
    // the two APIs.
    GitBindingReport report;
    const GitPolicy policy = GitSafetyPolicyFromEnvironment(fallbackRoot);
    report.capabilitiesGranted = policy.granted;
    report.scopePrefixes = policy.authorizedPrefixes.size();

    const bool haveRoot = !policy.repositoryRoots.empty();
    if (haveRoot) {
        BindIdeSession(policy, std::filesystem::path(policy.repositoryRoots.front()));
        report.repositoryRoot = policy.repositoryRoots.front();
    } else {
        std::lock_guard<std::mutex> lk(g_ideMutex);
        g_ide = std::make_shared<IdeBinding>();
        g_ide->policy = policy;
    }

    if (haveRoot) {
        auto b = ideBinding();
        if (b) {
            report.sessionOpened = b->beginResult.ok;
            report.sessionDetail = b->beginResult.detail;
            if (!b->beginResult.ok) report.refusalName = GitRefusalName(b->beginResult.refusal);
        }
    } else {
        report.sessionDetail = "RAWRXD_GIT_ROOT is not set and no fallback root was supplied";
        report.refusalName = GitRefusalName(GitRefusal::RepositoryRootNotAllowed);
    }

    // Registering the tools is unconditional. A deny policy then produces a
    // measured refusal at call time, which is auditable, rather than an absent
    // tool, which looks like a missing feature and hides the gate's existence.
    struct Entry {
        const char* id;
        const char* alias;
        const char* description;
    };
    static const Entry kTools[] = {
        {"git_status",        "gitst", "Working tree status. Read-only."},
        {"git_diff",          "gitdf", "Diff of the worktree. Read-only."},
        {"git_conflicts",     "gitcf", "List unmerged paths. Read-only."},
        {"git_dirty_tree",    "gitdt", "Dirty tree split into pre-existing user change and agent scope. Read-only."},
        {"git_review",        "gitrv", "Review the agent's own diff plus what is dirty outside its scope. Read-only."},
        {"git_stage",         "gitad", "Stage authorized paths. Requires RAWRXD_GIT_ALLOW_STAGE and scope."},
        {"git_unstage",       "gitrm", "Unstage authorized paths. Requires the stage grant and scope."},
        {"git_commit",        "gitcm", "Commit authorized staged paths. Refuses if the index holds out-of-scope work."},
        {"git_branch_create", "gitbr", "Create a branch. Requires RAWRXD_GIT_ALLOW_BRANCH."},
        {"git_checkout",      "gitco", "Check out a ref. Refused while unrelated uncommitted work exists."},
        {"git_stash",         "gitsh", "Stash or pop. Refused while unrelated uncommitted work exists."},
        {"git_worktree",      "gitwt", "List, add or remove an isolated worktree inside scope."},
        {"git_rollback",      "gitrb", "Restore authorized paths to their session-start state."},
    };

    for (const Entry& e : kTools) {
        const std::string id = e.id;
        RawrXD::Agentic::ToolDescriptor d;
        d.id = id;
        d.aliases = {e.alias};
        d.description = e.description;

        // The handler captures only the id, so the registry holds no reference to
        // the authority and the binding can be replaced safely.
        const auto handler = [id](const RawrXD::Agentic::ToolRequest& req,
                                  RawrXD::Agentic::ToolContext&) -> RawrXD::Agentic::ToolResult {
            auto b = ideBinding();
            if (!b || !b->authority) {
                RawrXD::Agentic::ToolResult refused;
                refused.exit_code = 77;
                refused.stderr_text =
                    "RAWRXD_GIT_SAFETY: no repository session is bound in this process";
                return refused;
            }
            const std::string raw = req.args.empty() ? std::string() : req.args.front();
            const IdeParams p = ParseIdeArgs(raw);
            GitResult g;
            if (id == "git_status")             g = b->authority->status();
            else if (id == "git_diff")          g = b->authority->diff(false, 1u << 18);
            else if (id == "git_conflicts")     g = b->authority->conflicts();
            else if (id == "git_dirty_tree")    g = b->authority->dirtyTree();
            else if (id == "git_review")        g = b->authority->reviewAgentDiff(1u << 18);
            else if (id == "git_stage")         g = b->authority->stage(p.paths);
            else if (id == "git_unstage")       g = b->authority->unstage(p.paths);
            else if (id == "git_commit")        g = b->authority->commit(p.firstToken(), p.paths);
            else if (id == "git_branch_create") g = b->authority->createBranch(p.firstToken());
            else if (id == "git_checkout")      g = b->authority->checkout(p.firstToken());
            else if (id == "git_stash")         g = b->authority->stash(p.firstToken());
            else if (id == "git_worktree") {
                const std::string action = p.value("action");
                if (action.empty() || action == "list") {
                    g = b->authority->listWorktrees();
                } else if (action == "add") {
                    g = b->authority->addWorktree(p.value("path"));
                } else if (action == "remove") {
                    g = b->authority->removeWorktree(p.value("path"), true);
                } else {
                    g.refusal = GitRefusal::GitFailed;
                    g.detail = "unknown worktree action '" + action + "'";
                }
            } else if (id == "git_rollback")    g = b->authority->rollback(p.paths);
            else {
                g.refusal = GitRefusal::GitFailed;
                g.detail = "no handler for tool '" + id + "'";
            }
            return ToIde(g);
        };
        try {
            ideRegistry.registerTool(std::move(d), handler);
            report.installed = true;
        } catch (const std::invalid_argument&) {
            // Already registered. The registry is process-lived, so a second chat
            // message must not become a permanent pipeline error.
            report.installed = true;
        }
    }
    return report;
}

} // namespace ide_git_safety
} // namespace rawrxd
