// =============================================================================
// AgentMode.h — Agent Execution Profiles with Enforced Permissions
// =============================================================================
// Modes are execution profiles over ONE agent system, not separate engines.
// Every mode uses the same model session, tool registry, backend router and
// audit ledger. A mode defines ONLY the permission policy applied to the
// native tool executor.
//
// CRITICAL: permissions are enforced in the tool executor, never by
// instructing the model what it may do. A model cannot talk its way into
// Write access from Ask mode. Mode switching recalculates permissions and
// must never retain authorization granted by the previous mode.
//
// A delegated swarm agent must never receive MORE authority than its parent.
// =============================================================================
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

#include "tool_core.hpp"

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// Execution modes
// ---------------------------------------------------------------------------
enum class AgentMode : uint8_t {
    Code        = 0,   // Default: inspect, modify, build, test
    Ask         = 1,   // Q&A without changing anything
    Debug       = 2,   // Diagnose crashes, apply and verify fixes
    Plan        = 3,   // Research and write plan files only
    Swarm       = 4,   // Coordinate specialized subagents
    Review      = 5,   // Read-only code/diff/architecture review
    Test        = 6,   // Discover, generate, execute tests
    Repair      = 7,   // Fix build/test failures
    Refactor    = 8,   // Restructure preserving behavior
    Research    = 9,   // Read-only source + approved docs
    Architect   = 10,  // Design components/interfaces (plan files only)
    Benchmark   = 11,  // Performance measurements (evidence outputs)
    Audit       = 12,  // Completeness check + audit artifacts (read-only src)
    Autonomous  = 13,  // Persistent engineering backlog, checkpointed
};

inline const char* AgentModeName(AgentMode m) {
    switch (m) {
        case AgentMode::Code:       return "code";
        case AgentMode::Ask:        return "ask";
        case AgentMode::Debug:      return "debug";
        case AgentMode::Plan:       return "plan";
        case AgentMode::Swarm:      return "swarm";
        case AgentMode::Review:     return "review";
        case AgentMode::Test:       return "test";
        case AgentMode::Repair:     return "repair";
        case AgentMode::Refactor:   return "refactor";
        case AgentMode::Research:   return "research";
        case AgentMode::Architect:  return "architect";
        case AgentMode::Benchmark:  return "benchmark";
        case AgentMode::Audit:      return "audit";
        case AgentMode::Autonomous: return "autonomous";
        default:                    return "unknown";
    }
}

inline bool AgentModeParse(const std::string& s, AgentMode& out) {
    static const std::map<std::string, AgentMode> lookup = {
        {"code", AgentMode::Code},
        {"ask", AgentMode::Ask},
        {"debug", AgentMode::Debug},
        {"plan", AgentMode::Plan},
        {"swarm", AgentMode::Swarm},
        {"orchestrator", AgentMode::Swarm},  // deprecated alias
        {"review", AgentMode::Review},
        {"test", AgentMode::Test},
        {"repair", AgentMode::Repair},
        {"refactor", AgentMode::Refactor},
        {"research", AgentMode::Research},
        {"architect", AgentMode::Architect},
        {"benchmark", AgentMode::Benchmark},
        {"audit", AgentMode::Audit},
        {"autonomous", AgentMode::Autonomous},
        // Product-facing alias: the GUI and external agent contract call the
        // full mutation-capable mode "agent". Keep the persisted internal
        // name "autonomous" for backward-compatible ledgers.
        {"agent", AgentMode::Autonomous},
    };
    std::string key = s;
    for (auto& c : key) c = static_cast<char>(::tolower(c));
    auto it = lookup.find(key);
    if (it == lookup.end()) return false;
    out = it->second;
    return true;
}

// ---------------------------------------------------------------------------
// Tool capability levels (highest wins)
// ---------------------------------------------------------------------------
enum class ToolAuthority : uint8_t {
    Denied       = 0,   // tool unavailable
    ReadOnly     = 1,   // tools that only read the workspace
    PlanFiles    = 2,   // write permitted only inside the plan directory
    Controlled   = 3,   // write/execute allowed inside the workspace
    Full         = 4,   // includes approval-gated commits/deploy
};

inline const char* ToolAuthorityName(ToolAuthority a) {
    switch (a) {
        case ToolAuthority::Denied:     return "denied";
        case ToolAuthority::ReadOnly:   return "read-only";
        case ToolAuthority::PlanFiles:  return "plan-files";
        case ToolAuthority::Controlled: return "controlled";
        case ToolAuthority::Full:       return "full";
        default:                        return "unknown";
    }
}

// ---------------------------------------------------------------------------
// Mode permission policy
// ---------------------------------------------------------------------------
struct ModePolicy {
    AgentMode     mode;
    const char*   description;
    ToolAuthority authority;

    // Per-tool overrides. An entry here REPLACES the authority derived from
    // the mode's ToolAuthority, so a mode can forbid one specific tool
    // (e.g. Ask denying execute_command) while allowing the rest.
    std::map<std::string, ToolAuthority> tool_overrides;

    bool may_execute_builds = false;
    bool may_commit         = false;
    bool may_deploy         = false;
};

// ---------------------------------------------------------------------------
// Mode registry
// ---------------------------------------------------------------------------
class ModeRegistry {
public:
    static ModeRegistry& Instance();

    // Register the canonical mode table.
    const ModePolicy* Get(AgentMode mode) const;
    std::vector<AgentMode> AllModes() const;

    // Resolve the authority a tool would get under a mode.
    ToolAuthority AuthorityFor(AgentMode mode, const std::string& tool_name) const;

    // Human-readable one-liner for CLI display.
    std::string Describe(AgentMode mode) const;

private:
    ModeRegistry();
    std::map<AgentMode, ModePolicy> m_policies;
};

// ---------------------------------------------------------------------------
// PermissionGate — the single enforcement point for tool calls
// ---------------------------------------------------------------------------
// The tool executor MUST consult this before invoking any tool. It maps
// (mode, tool risk, tool name) to an allow/deny decision. Approval callbacks
// are layered on top: Controlled/Full authority still requires an explicit
// approval for mutating tools, but the authority ceiling is what makes
// Ask mode structurally incapable of writing.
// ---------------------------------------------------------------------------
class PermissionGate {
public:
    explicit PermissionGate(AgentMode initial = AgentMode::Code);

    // ---- Mode management ----
    void SetMode(AgentMode mode);
    AgentMode GetMode() const { return m_mode; }
    void ParentMode(AgentMode mode);           // for delegated subagents
    ToolAuthority EffectiveAuthority() const;

    // ---- Enforcement ----
    // Returns true if the tool may be invoked under the current mode.
    bool Allows(const rawrxd::tools::Tool& tool) const;

    // Returns true if the tool may be invoked, considering approval.
    // `approver` is called for mutating tools; returning false denies.
    bool AllowsWithApproval(const rawrxd::tools::Tool& tool,
                            const rawrxd::tools::Request& req,
                            const rawrxd::tools::Approval& approver) const;

    // ---- Plan-file policy ----
    // PlanFiles authority permits writes only under the plan directory.
    void SetPlanDirectory(std::string dir) { m_planDir = std::move(dir); }
    const std::string& PlanDirectory() const { return m_planDir; }
    bool IsPlanFilePath(const std::string& path) const;

    // ---- Delegated agent clamping ----
    // A subagent's authority can never exceed the parent's.
    void InheritFrom(const PermissionGate& parent);

    // ---- Diagnostics ----
    std::string ExplainDenial(const rawrxd::tools::Tool& tool) const;

private:
    AgentMode     m_mode;
    AgentMode     m_parentMode = AgentMode::Code;
    ToolAuthority m_ceiling   = ToolAuthority::Full;
    bool          m_clamped   = false;
    std::string   m_planDir   = ".rawrxd/plans";
    mutable std::mutex m_mtx;
};

// ---------------------------------------------------------------------------
// ToolPolicyBridge — reuses the existing rawrxd::tools::Registry
// ---------------------------------------------------------------------------
// Wraps rawrxd::tools::Registry::call with mode enforcement so that ALL
// backends (Deep2 and Ollama) share the exact same permission behaviour.
// =============================================================================
class ToolPolicyBridge {
public:
    ToolPolicyBridge(rawrxd::tools::Registry* registry, PermissionGate* gate)
        : m_registry(registry), m_gate(gate) {}

    // Execute a tool if, and only if, the current mode permits it.
    rawrxd::tools::Result Call(const rawrxd::tools::Request& req,
                               const rawrxd::tools::Approval& approve) const;

    rawrxd::tools::Registry* Registry() const { return m_registry; }
    PermissionGate* Gate() const { return m_gate; }

private:
    rawrxd::tools::Registry* m_registry;
    PermissionGate*          m_gate;
};

} // namespace Agent
} // namespace RawrXD
