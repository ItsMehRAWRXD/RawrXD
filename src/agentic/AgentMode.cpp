// =============================================================================
// AgentMode.cpp — Mode registry and permission enforcement
// =============================================================================
#include "AgentMode.h"
#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// Helpers: map ToolAuthority <-> rawrxd::tools::Risk
// ---------------------------------------------------------------------------
static ToolAuthority AuthorityForRisk(rawrxd::tools::Risk risk, ToolAuthority ceiling) {
    switch (risk) {
        case rawrxd::tools::Risk::ReadOnly:
            return (ceiling >= ToolAuthority::ReadOnly) ? ToolAuthority::ReadOnly
                                                        : ToolAuthority::Denied;
        case rawrxd::tools::Risk::Write:
            if (ceiling >= ToolAuthority::Controlled) return ToolAuthority::Controlled;
            if (ceiling >= ToolAuthority::PlanFiles)  return ToolAuthority::PlanFiles;
            return ToolAuthority::Denied;
        case rawrxd::tools::Risk::Execute:
            if (ceiling >= ToolAuthority::Controlled) return ToolAuthority::Controlled;
            return ToolAuthority::Denied;
        case rawrxd::tools::Risk::Network:
            if (ceiling >= ToolAuthority::Controlled) return ToolAuthority::Controlled;
            return ToolAuthority::Denied;
        case rawrxd::tools::Risk::External:
            // External authority is never granted by mode; only an explicit
            // per-tool override may raise it, and only in Full modes.
            return ToolAuthority::Denied;
    }
    return ToolAuthority::Denied;
}

// ---------------------------------------------------------------------------
// ModeRegistry
// ---------------------------------------------------------------------------
ModeRegistry& ModeRegistry::Instance() {
    static ModeRegistry instance;
    return instance;
}

ModeRegistry::ModeRegistry() {
    // Authority ceilings per mode. Overrides below refine specific tools.
    m_policies[AgentMode::Code] = {AgentMode::Code,
        "Inspect, modify, build and test projects", ToolAuthority::Controlled, {}, true, false, false};
    m_policies[AgentMode::Ask] = {AgentMode::Ask,
        "Answer questions and explain code without changing it", ToolAuthority::ReadOnly, {}, false, false, false};
    m_policies[AgentMode::Debug] = {AgentMode::Debug,
        "Diagnose crashes, apply and verify fixes", ToolAuthority::Controlled, {}, true, false, false};
    m_policies[AgentMode::Plan] = {AgentMode::Plan,
        "Research and create implementation plans", ToolAuthority::PlanFiles, {}, false, false, false};
    m_policies[AgentMode::Swarm] = {AgentMode::Swarm,
        "Coordinate specialized subagents on parallel tasks", ToolAuthority::Controlled, {}, true, false, false};
    m_policies[AgentMode::Review] = {AgentMode::Review,
        "Review code, diffs, architecture and security", ToolAuthority::ReadOnly, {}, false, false, false};
    m_policies[AgentMode::Test] = {AgentMode::Test,
        "Discover, generate and execute tests", ToolAuthority::Controlled, {}, true, false, false};
    m_policies[AgentMode::Repair] = {AgentMode::Repair,
        "Fix build failures and failing tests", ToolAuthority::Controlled, {}, true, false, false};
    m_policies[AgentMode::Refactor] = {AgentMode::Refactor,
        "Restructure implementations preserving behavior", ToolAuthority::Controlled, {}, true, false, false};
    m_policies[AgentMode::Research] = {AgentMode::Research,
        "Investigate local sources and approved documentation", ToolAuthority::ReadOnly, {}, false, false, false};
    m_policies[AgentMode::Architect] = {AgentMode::Architect,
        "Design components and interfaces", ToolAuthority::PlanFiles, {}, false, false, false};
    m_policies[AgentMode::Benchmark] = {AgentMode::Benchmark,
        "Measure inference and system performance", ToolAuthority::Controlled, {}, true, false, false};
    m_policies[AgentMode::Audit] = {AgentMode::Audit,
        "Check implementation completeness and write audit artifacts", ToolAuthority::PlanFiles, {}, false, false, false};
    m_policies[AgentMode::Autonomous] = {AgentMode::Autonomous,
        "Execute a persistent engineering backlog across sessions", ToolAuthority::Full, {}, true, false, false};

    // Per-tool overrides. Ask/Research/Review/Audit must be structurally
    // unable to mutate, regardless of what the model asks for.
    const std::vector<AgentMode> read_only_modes = {
        AgentMode::Ask, AgentMode::Review, AgentMode::Research,
    };
    for (AgentMode m : read_only_modes) {
        auto& p = m_policies[m];
        p.tool_overrides["readFile"]       = ToolAuthority::ReadOnly;
        p.tool_overrides["listDirectory"]  = ToolAuthority::ReadOnly;
        p.tool_overrides["fileSearch"]     = ToolAuthority::ReadOnly;
        p.tool_overrides["textSearch"]     = ToolAuthority::ReadOnly;
        p.tool_overrides["createDirectory"] = ToolAuthority::Denied;
        p.tool_overrides["createFile"]     = ToolAuthority::Denied;
        p.tool_overrides["editFiles"]      = ToolAuthority::Denied;
        p.tool_overrides["runInTerminal"]  = ToolAuthority::Denied;
    }

    // Plan/Architect may write only inside the plan directory.
    for (AgentMode m : {AgentMode::Plan, AgentMode::Architect, AgentMode::Audit}) {
        auto& p = m_policies[m];
        p.tool_overrides["readFile"]       = ToolAuthority::ReadOnly;
        p.tool_overrides["listDirectory"]  = ToolAuthority::ReadOnly;
        p.tool_overrides["fileSearch"]     = ToolAuthority::ReadOnly;
        p.tool_overrides["textSearch"]     = ToolAuthority::ReadOnly;
        p.tool_overrides["createFile"]     = ToolAuthority::PlanFiles;
        p.tool_overrides["editFiles"]      = ToolAuthority::PlanFiles;
        p.tool_overrides["createDirectory"] = ToolAuthority::PlanFiles;
        p.tool_overrides["runInTerminal"]  = ToolAuthority::Denied;
    }

    // Benchmark writes evidence outputs only.
    auto& bench = m_policies[AgentMode::Benchmark];
    bench.tool_overrides["readFile"]      = ToolAuthority::ReadOnly;
    bench.tool_overrides["listDirectory"] = ToolAuthority::ReadOnly;
    bench.tool_overrides["fileSearch"]    = ToolAuthority::ReadOnly;
    bench.tool_overrides["textSearch"]    = ToolAuthority::ReadOnly;
    bench.tool_overrides["runInTerminal"] = ToolAuthority::Controlled;

    // Autonomous mirrors Code (Full ceiling) but commits still gated.
    auto& auton = m_policies[AgentMode::Autonomous];
    auton.tool_overrides["readFile"]     = ToolAuthority::ReadOnly;
    auton.tool_overrides["listDirectory"]= ToolAuthority::ReadOnly;
    auton.tool_overrides["fileSearch"]   = ToolAuthority::ReadOnly;
    auton.tool_overrides["textSearch"]   = ToolAuthority::ReadOnly;
}

const ModePolicy* ModeRegistry::Get(AgentMode mode) const {
    auto it = m_policies.find(mode);
    return (it != m_policies.end()) ? &it->second : nullptr;
}

std::vector<AgentMode> ModeRegistry::AllModes() const {
    std::vector<AgentMode> out;
    out.reserve(m_policies.size());
    for (const auto& p : m_policies) out.push_back(p.first);
    std::sort(out.begin(), out.end());
    return out;
}

ToolAuthority ModeRegistry::AuthorityFor(AgentMode mode, const std::string& tool_name) const {
    const ModePolicy* p = Get(mode);
    if (!p) return ToolAuthority::Denied;

    auto it = p->tool_overrides.find(tool_name);
    if (it != p->tool_overrides.end()) {
        // Explicit override wins, but it cannot exceed the mode ceiling.
        ToolAuthority ceiling = p->authority;
        if (ceiling == ToolAuthority::Denied) return ToolAuthority::Denied;
        return (it->second > ceiling) ? ceiling : it->second;
    }
    return p->authority;
}

std::string ModeRegistry::Describe(AgentMode mode) const {
    const ModePolicy* p = Get(mode);
    if (!p) return "unknown";
    return std::string(AgentModeName(mode)) + " — " + p->description +
           " (authority: " + ToolAuthorityName(p->authority) + ")";
}

// ---------------------------------------------------------------------------
// PermissionGate
// ---------------------------------------------------------------------------
PermissionGate::PermissionGate(AgentMode initial) : m_mode(initial) {
    const ModePolicy* p = ModeRegistry::Instance().Get(initial);
    m_ceiling = p ? p->authority : ToolAuthority::Denied;
}

void PermissionGate::SetMode(AgentMode mode) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_mode = mode;
    // Recompute the ceiling. If a parent exists, clamp to the parent's ceiling.
    const ModePolicy* p = ModeRegistry::Instance().Get(mode);
    m_ceiling = p ? p->authority : ToolAuthority::Denied;

    if (m_clamped) {
        const ModePolicy* parent = ModeRegistry::Instance().Get(m_parentMode);
        ToolAuthority parent_ceiling = parent ? parent->authority : ToolAuthority::Denied;
        if (parent_ceiling < m_ceiling) m_ceiling = parent_ceiling;
    }
}

void PermissionGate::ParentMode(AgentMode mode) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_parentMode = mode;
    m_clamped = true;
    const ModePolicy* parent = ModeRegistry::Instance().Get(mode);
    if (parent && parent->authority < m_ceiling) {
        m_ceiling = parent->authority;
    }
}

ToolAuthority PermissionGate::EffectiveAuthority() const {
    std::lock_guard<std::mutex> lock(m_mtx);
    return m_ceiling;
}

void PermissionGate::InheritFrom(const PermissionGate& parent) {
    std::lock_guard<std::mutex> lock(m_mtx);
    if (parent.m_clamped) {
        m_parentMode = parent.m_parentMode;
        m_clamped = true;
    } else {
        m_parentMode = parent.m_mode;
        m_clamped = true;
    }
    const ModePolicy* p = ModeRegistry::Instance().Get(m_parentMode);
    ToolAuthority parent_ceiling = p ? p->authority : ToolAuthority::Denied;
    if (parent_ceiling < m_ceiling) m_ceiling = parent_ceiling;
}

bool PermissionGate::IsPlanFilePath(const std::string& path) const {
    if (m_planDir.empty()) return false;
    // Normalise separators for comparison.
    auto norm = [](std::string s) {
        std::replace(s.begin(), s.end(), '\\', '/');
        return s;
    };
    std::string p = norm(path);
    std::string d = norm(m_planDir);
    if (d.size() > 1 && d.back() == '/') d.pop_back();
    return p.rfind(d + "/", 0) == 0 || p == d ||
           p.find("/" + d + "/") != std::string::npos;
}

bool PermissionGate::Allows(const rawrxd::tools::Tool& tool) const {
    std::lock_guard<std::mutex> lock(m_mtx);

    ToolAuthority granted = ModeRegistry::Instance().AuthorityFor(m_mode, tool.name);

    // Clamp by the effective ceiling.
    if (granted > m_ceiling) granted = m_ceiling;
    if (granted == ToolAuthority::Denied) return false;

    // Read-only authority permits read-only tools only.
    if (granted == ToolAuthority::ReadOnly) {
        return tool.risk == rawrxd::tools::Risk::ReadOnly;
    }

    // PlanFiles authority: writing tools permitted only for plan paths.
    if (granted == ToolAuthority::PlanFiles) {
        return tool.risk == rawrxd::tools::Risk::ReadOnly;
    }

    // Controlled / Full.
    return true;
}

bool PermissionGate::AllowsWithApproval(const rawrxd::tools::Tool& tool,
                                        const rawrxd::tools::Request& req,
                                        const rawrxd::tools::Approval& approver) const {
    std::lock_guard<std::mutex> lock(m_mtx);

    ToolAuthority granted = ModeRegistry::Instance().AuthorityFor(m_mode, tool.name);
    if (granted > m_ceiling) granted = m_ceiling;
    if (granted == ToolAuthority::Denied) return false;

    // Read-only tools always allowed under ReadOnly+ authority.
    if (tool.risk == rawrxd::tools::Risk::ReadOnly) return true;

    if (granted == ToolAuthority::ReadOnly) return false;

    // PlanFiles: check that every path-ish argument is inside the plan dir.
    if (granted == ToolAuthority::PlanFiles) {
        static const char* path_keys[] = {"path", "file", "target", "filename"};
        for (const char* key : path_keys) {
            auto it = req.args.find(key);
            if (it != req.args.end()) {
                if (!IsPlanFilePath(it->second)) return false;
            }
        }
        return true;
    }

    // Controlled / Full: mutating tools require explicit approval.
    if (!approver) return false;
    return approver(tool, req);
}

std::string PermissionGate::ExplainDenial(const rawrxd::tools::Tool& tool) const {
    std::lock_guard<std::mutex> lock(m_mtx);
    ToolAuthority granted = ModeRegistry::Instance().AuthorityFor(m_mode, tool.name);
    std::ostringstream oss;
    oss << "Tool '" << tool.name << "' denied in mode '" << AgentModeName(m_mode)
        << "' (granted: " << ToolAuthorityName(granted)
        << ", ceiling: " << ToolAuthorityName(m_ceiling) << ")";
    if (granted == ToolAuthority::PlanFiles) {
        oss << "; writes allowed only under " << m_planDir;
    }
    return oss.str();
}

// ---------------------------------------------------------------------------
// ToolPolicyBridge
// ---------------------------------------------------------------------------
rawrxd::tools::Result ToolPolicyBridge::Call(const rawrxd::tools::Request& req,
                                             const rawrxd::tools::Approval& approve) const {
    if (!m_registry || !m_gate) {
        return {false, "", "tool executor not initialised"};
    }

    // Resolve the tool descriptor first so the gate can enforce the mode
    // policy before any side effect occurs.
    rawrxd::tools::Tool tool;
    if (!m_registry->find(req.name, tool)) {
        return {false, "", "unknown tool: " + req.name};
    }

    // Enforce the mode policy. The approver passed in is the human/IDE gate;
    // it is consulted only after the mode allows the tool at all.
    if (!m_gate->AllowsWithApproval(tool, req, approve)) {
        return {false, "", m_gate->ExplainDenial(tool)};
    }

    return m_registry->call(req, approve);
}

} // namespace Agent
} // namespace RawrXD
