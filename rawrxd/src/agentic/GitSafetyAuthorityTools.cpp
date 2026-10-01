// ============================================================================
// GitSafetyAuthorityTools.cpp — RAWRXD_GIT_SAFETY_AUTHORITY_001
//
// Registers the twelve certified git capabilities into the sandboxed tool
// authority, rawrxd::agentic::ToolRegistry — the SAME registry the IDE HTTP
// routes dispatch through (deep2_openai_server.cpp: /api/cli and
// /api/agent/execute-tool). That is the point. A gate that lives next to the
// tools instead of inside the dispatch path is a gate the agent never meets.
//
// The parameters of every tool are a fixed enumeration, not a command line.
// There is no tool that accepts a subcommand, and no tool that accepts a
// shell string, so the class of attack where a model emits
// git_commit(message="x\"; rm -rf /") does not exist here: the message is one
// argv element handed to CreateProcessW, never re-parsed.
//
// InstallGitTools is idempotent and refuses to install a mutating tool while
// the policy is DefaultDenyAll, so a default-constructed registry cannot
// acquire a mutation path by accident.
// ============================================================================
#include "agentic/GitSafetyAuthority.h"
#include "agentic/GitSafetyAuthorityTools.h"
#include "agentic/AgentToolRegistry.h"

#include <memory>
#include <mutex>
#include <sstream>

namespace rawrxd {
namespace agentic {
namespace {

// One authority per tool registry. The tools hold a shared_ptr so a ToolResult
// in flight cannot outlive a destroyed authority.
struct Binding {
    GitPolicy policy;
    std::shared_ptr<GitSafetyAuthority> authority;
};

std::mutex g_bindingMutex;
std::shared_ptr<Binding> g_binding;

std::shared_ptr<Binding> binding() {
    std::lock_guard<std::mutex> lk(g_bindingMutex);
    return g_binding;
}

void setBinding(std::shared_ptr<Binding> b) {
    std::lock_guard<std::mutex> lk(g_bindingMutex);
    g_binding = std::move(b);
}

bool Param(const std::unordered_map<std::string, std::string>& p, const char* key,
           std::string& out) {
    const auto it = p.find(key);
    if (it == p.end() || it->second.empty()) return false;
    out = it->second;
    return true;
}

std::vector<std::string> ParamList(const std::unordered_map<std::string, std::string>& p,
                                   const char* key) {
    std::vector<std::string> out;
    const auto it = p.find(key);
    if (it == p.end() || it->second.empty()) return out;
    // A newline- or comma-separated list. Each element is still a single argv
    // element afterwards, so this is splitting, not shell parsing.
    std::string current;
    for (char c : it->second) {
        if (c == '\n' || c == ',') {
            if (!current.empty()) out.push_back(current);
            current.clear();
        } else if (c != '\r') {
            current.push_back(c);
        }
    }
    if (!current.empty()) out.push_back(current);
    return out;
}

ToolResult FromGitResult(const GitResult& g) {
    ToolResult r;
    r.success = g.ok;
    if (g.ok) {
        r.output = g.output;
        if (!g.detail.empty()) {
            if (!r.output.empty()) r.output += "\n";
            r.output += "[authority] " + g.detail;
        }
    } else {
        r.error = std::string(GitRefusalName(g.refusal)) + ": " + g.detail;
        if (!g.errorOutput.empty()) r.error += "\n" + g.errorOutput;
    }
    return r;
}

ToolResult Refused(const char* why) {
    ToolResult r;
    r.success = false;
    r.error = std::string("RAWRXD_GIT_SAFETY_UNBOUND: ") + why;
    return r;
}

} // namespace

// ---------------------------------------------------------------------------

void BindGitSafetyPolicy(GitPolicy policy) {
    setBinding(std::make_shared<Binding>(Binding{std::move(policy), nullptr}));
}

void BindGitSafetyPolicy(GitPolicy policy, const std::filesystem::path& repoRoot) {
    auto b = std::make_shared<Binding>();
    b->policy = std::move(policy);
    b->authority = std::make_shared<GitSafetyAuthority>(b->policy);
    // A failed begin leaves authority non-null but the session closed, so the
    // first tool call reports a measured refusal rather than a crash.
    b->authority->beginSession(repoRoot);
    setBinding(std::move(b));
}

GitPolicy GitSafetyBoundPolicy() {
    auto b = binding();
    return b ? b->policy : GitPolicy::DefaultDenyAll();
}

bool IsGitSafetyBound() { return binding() != nullptr; }

// Returns false when the policy grants no mutating capability, so a
// default-deny policy cannot be widened by calling this.
bool InstallGitTools(ToolRegistry& registry) {
    auto b = binding();
    if (!b) return false;
    const std::uint32_t mutatingMask = static_cast<std::uint32_t>(GitCapability::Stage) |
                                       static_cast<std::uint32_t>(GitCapability::Unstage) |
                                       static_cast<std::uint32_t>(GitCapability::Commit) |
                                       static_cast<std::uint32_t>(GitCapability::Branch) |
                                       static_cast<std::uint32_t>(GitCapability::Checkout) |
                                       static_cast<std::uint32_t>(GitCapability::Stash) |
                                       static_cast<std::uint32_t>(GitCapability::Worktree) |
                                       static_cast<std::uint32_t>(GitCapability::Rollback);
    if ((b->policy.granted & mutatingMask) == 0) {
        // Read-only tools are still installed: status/diff/conflicts do not
        // change repository state and are useful without a grant. Nothing
        // that mutates is reachable.
        std::lock_guard<std::mutex> lk(g_bindingMutex);
        g_binding->authority = std::make_shared<GitSafetyAuthority>(b->policy);
    } else if (!b->authority) {
        std::lock_guard<std::mutex> lk(g_bindingMutex);
        g_binding->authority = std::make_shared<GitSafetyAuthority>(b->policy);
    }

    registry.Register({"git_status",
                       "Read-only working tree status. Cannot change repository state.",
                       {{"path", "string", "Repository path. Optional; defaults to the bound session.", false}}},
                      [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                          auto b = binding();
                          if (!b || !b->authority) return Refused("no repository session is open");
                          std::string path;
                          if (Param(p, "path", path)) {
                              const GitResult opened = b->authority->beginSession(path);
                              if (!opened.ok) return FromGitResult(opened);
                          }
                          return FromGitResult(b->authority->status());
                      });

    registry.Register({"git_diff",
                       "Read-only diff. staged=1 shows the index, otherwise the worktree.",
                       {{"staged", "string", "1 to diff the index.", false},
                        {"max_bytes", "string", "Output cap in bytes.", false}}},
                      [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                          auto b = binding();
                          if (!b || !b->authority) return Refused("no repository session is open");
                          std::string staged;
                          const bool isStaged = Param(p, "staged", staged) && staged == "1";
                          return FromGitResult(b->authority->diff(isStaged, 1u << 18));
                      });

    registry.Register({"git_conflicts",
                       "Read-only list of unmerged paths.",
                       {{}}},
                      [](const std::unordered_map<std::string, std::string>&) -> ToolResult {
                          auto b = binding();
                          if (!b || !b->authority) return Refused("no repository session is open");
                          return FromGitResult(b->authority->conflicts());
                      });

    registry.Register({"git_dirty_tree",
                       "Read-only dirty-tree classification, separating pre-existing user "
                       "changes from changes inside the agent's authorized scope.",
                       {{}}},
                      [](const std::unordered_map<std::string, std::string>&) -> ToolResult {
                          auto b = binding();
                          if (!b || !b->authority) return Refused("no repository session is open");
                          return FromGitResult(b->authority->dirtyTree());
                      });

    registry.Register({"git_review",
                       "Read-only review of the agent's own diff, together with the paths "
                       "dirty outside its scope.",
                       {{}}},
                      [](const std::unordered_map<std::string, std::string>&) -> ToolResult {
                          auto b = binding();
                          if (!b || !b->authority) return Refused("no repository session is open");
                          return FromGitResult(b->authority->reviewAgentDiff(1u << 18));
                      });

    // ---- mutating ---------------------------------------------------------
    // Each of these is registered unconditionally. A default-deny policy then
    // refuses them with a measured CAPABILITY_NOT_GRANTED at call time, which
    // is the behaviour worth certifying: the tool exists, the gate is what
    // stops it, and the refusal is observable in the receipt.

    registry.Register({"git_stage",
                       "Stage paths. Refused unless the policy grants stage and the paths "
                       "are inside the authorized scope.",
                       {{"paths", "string", "Newline or comma separated repository-relative paths.", true}}},
                      [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                          auto b = binding();
                          if (!b || !b->authority) return Refused("no repository session is open");
                          return FromGitResult(b->authority->stage(ParamList(p, "paths")));
                      });

    registry.Register({"git_unstage",
                       "Unstage paths, or the whole index when none are given.",
                       {{"paths", "string", "Optional repository-relative paths.", false}}},
                      [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                          auto b = binding();
                          if (!b || !b->authority) return Refused("no repository session is open");
                          return FromGitResult(b->authority->unstage(ParamList(p, "paths")));
                      });

    registry.Register({"git_commit",
                       "Commit authorized staged paths. Refused if the index holds any path "
                       "outside the authorized scope.",
                       {{"message", "string", "Commit message.", true},
                        {"paths", "string", "Optional explicit path list.", false}}},
                      [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                          auto b = binding();
                          if (!b || !b->authority) return Refused("no repository session is open");
                          std::string message;
                          if (!Param(p, "message", message)) {
                              ToolResult r;
                              r.success = false;
                              r.error = "missing required parameter: message";
                              return r;
                          }
                          return FromGitResult(
                              b->authority->commit(message, ParamList(p, "paths")));
                      });

    registry.Register({"git_branch_create",
                       "Create a branch at the current HEAD.",
                       {{"name", "string", "Branch name.", true}}},
                      [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                          auto b = binding();
                          if (!b || !b->authority) return Refused("no repository session is open");
                          std::string name;
                          if (!Param(p, "name", name)) {
                              ToolResult r;
                              r.success = false;
                              r.error = "missing required parameter: name";
                              return r;
                          }
                          return FromGitResult(b->authority->createBranch(name));
                      });

    registry.Register({"git_checkout",
                       "Check out a ref. Refused while unrelated uncommitted work exists.",
                       {{"ref", "string", "Ref to check out.", true}}},
                      [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                          auto b = binding();
                          if (!b || !b->authority) return Refused("no repository session is open");
                          std::string ref;
                          if (!Param(p, "ref", ref)) {
                              ToolResult r;
                              r.success = false;
                              r.error = "missing required parameter: ref";
                              return r;
                          }
                          return FromGitResult(b->authority->checkout(ref));
                      });

    registry.Register({"git_stash",
                       "Stash uncommitted work. Refused while unrelated uncommitted work exists.",
                       {{"message", "string", "Stash message.", false},
                        {"pop", "string", "1 to pop instead of push.", false}}},
                      [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                          auto b = binding();
                          if (!b || !b->authority) return Refused("no repository session is open");
                          std::string pop;
                          if (Param(p, "pop", pop) && pop == "1") {
                              return FromGitResult(b->authority->stashPop());
                          }
                          std::string message;
                          Param(p, "message", message);
                          return FromGitResult(b->authority->stash(message));
                      });

    registry.Register({"git_worktree",
                       "List, add or remove an isolated worktree inside the authorized scope.",
                       {{"action", "string", "list | add | remove", true},
                        {"path", "string", "Repository-relative worktree path for add/remove.", false},
                        {"force", "string", "1 to force removal.", false}}},
                      [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                          auto b = binding();
                          if (!b || !b->authority) return Refused("no repository session is open");
                          std::string action;
                          if (!Param(p, "action", action)) {
                              ToolResult r;
                              r.success = false;
                              r.error = "missing required parameter: action";
                              return r;
                          }
                          if (action == "list") return FromGitResult(b->authority->listWorktrees());
                          std::string path;
                          if (!Param(p, "path", path)) {
                              ToolResult r;
                              r.success = false;
                              r.error = "missing required parameter: path";
                              return r;
                          }
                          if (action == "add") return FromGitResult(b->authority->addWorktree(path));
                          if (action == "remove") {
                              std::string force;
                              const bool f = Param(p, "force", force) && force == "1";
                              return FromGitResult(b->authority->removeWorktree(path, f));
                          }
                          ToolResult r;
                          r.success = false;
                          r.error = "unknown action '" + action + "'; expected list, add or remove";
                          return r;
                      });

    registry.Register({"git_rollback",
                       "Restore authorized paths to their session-start state. Paths that were "
                       "already dirty when the session began are reported and left alone.",
                       {{"paths", "string", "Newline or comma separated paths.", true}}},
                      [](const std::unordered_map<std::string, std::string>& p) -> ToolResult {
                          auto b = binding();
                          if (!b || !b->authority) return Refused("no repository session is open");
                          return FromGitResult(b->authority->rollback(ParamList(p, "paths")));
                      });

    return true;
}

} // namespace agentic
} // namespace rawrxd
