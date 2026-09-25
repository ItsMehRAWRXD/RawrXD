#include "ScreenPilotToolAuthorityBridge.hpp"

#include <algorithm>
#include <sstream>

namespace RawrXD::ScreenPilot {
namespace {

std::string toString(RawrXD_SP_StringV2 value) {
    if (!value.data || value.size == 0) return {};
    return std::string(value.data, value.size);
}

Agentic::ToolResult failResult(int code, std::string message) {
    Agentic::ToolResult r;
    r.exit_code = code;
    r.stderr_text = std::move(message);
    return r;
}

bool argLooksPathBearing(std::string_view arg) noexcept {
    return arg.find('/') != std::string_view::npos ||
           arg.find('\\') != std::string_view::npos ||
           arg.find(':') != std::string_view::npos ||
           arg == "." || arg == "..";
}

} // namespace

bool ScreenPilotAuthorityReceipt::pass() const noexcept {
    return requests > 0 && registryInvocations > 0 && directBypassAttempts == 0 && failures == 0;
}

std::string ScreenPilotAuthorityReceipt::text() const {
    std::ostringstream o;
    o << "=== RAWRXD_SCREENPILOT_TOOL_AUTHORITY_001 ===\n";
    o << "REQUESTS=" << requests << "\n";
    o << "REGISTRY_INVOCATIONS=" << registryInvocations << "\n";
    o << "APPROVALS_REQUESTED=" << approvalsRequested << "\n";
    o << "APPROVALS_DENIED=" << approvalsDenied << "\n";
    o << "PERMISSION_DENIED=" << permissionDenied << "\n";
    o << "WORKSPACE_DENIED=" << workspaceDenied << "\n";
    o << "CANCELLATIONS=" << cancellations << "\n";
    o << "DIRECT_BYPASS_ATTEMPTS=" << directBypassAttempts << "\n";
    o << "FAILURES=" << failures << "\n";
    o << "VERDICT=" << (pass() ? "PASS" : "FAIL") << "\n";
    return o.str();
}

ScreenPilotToolAuthorityBridge::ScreenPilotToolAuthorityBridge(Agentic::AgentToolRegistry& registry)
    : registry_(registry) {}

bool ScreenPilotToolAuthorityBridge::pathWithinWorkspace(
    const std::filesystem::path& workspace,
    const std::filesystem::path& candidate) noexcept {
    std::error_code ec;
    const auto root = std::filesystem::weakly_canonical(workspace, ec);
    if (ec || root.empty()) return false;
    const auto full = std::filesystem::weakly_canonical(candidate.is_absolute() ? candidate : root / candidate, ec);
    if (ec || full.empty()) return false;

    auto r = root.begin();
    auto f = full.begin();
    for (; r != root.end(); ++r, ++f) {
        if (f == full.end() || *r != *f) return false;
    }
    return true;
}

Agentic::ToolResult ScreenPilotToolAuthorityBridge::invoke(
    const RawrXD_SP_AgentRequestV2& request,
    std::string toolId,
    std::vector<std::string> args,
    std::string stdinText,
    std::uint64_t requiredPermission,
    const char* summary,
    const char* risk,
    RawrXD_SP_IsCancelledFnV2 isCancelled,
    void* cancelUser,
    RawrXD_SP_RequestApprovalFnV2 requestApproval,
    void* approvalUser) {

    requests_.fetch_add(1, std::memory_order_relaxed);

    if ((request.permission_mask & requiredPermission) != requiredPermission) {
        permissionDenied_.fetch_add(1, std::memory_order_relaxed);
        failures_.fetch_add(1, std::memory_order_relaxed);
        return failResult(126, "ScreenPilot permission denied for tool: " + toolId);
    }

    if (isCancelled && isCancelled(cancelUser)) {
        cancellations_.fetch_add(1, std::memory_order_relaxed);
        failures_.fetch_add(1, std::memory_order_relaxed);
        return failResult(130, "ScreenPilot request cancelled");
    }

    const std::filesystem::path workspace(toString(request.workspace));
    if (request.workspace_only) {
        for (const auto& arg : args) {
            if (!argLooksPathBearing(arg)) continue;
            const std::filesystem::path p(arg);
            // Only enforce path containment for arguments that resolve as paths.
            // Commands/flags containing ':' are ignored unless the path exists or is relative path syntax.
            std::error_code ec;
            const bool candidatePath = p.is_absolute() || arg.rfind("..", 0) == 0 || arg.rfind(".", 0) == 0 ||
                                       std::filesystem::exists(workspace / p, ec) || std::filesystem::exists(p, ec);
            if (candidatePath && !pathWithinWorkspace(workspace, p)) {
                workspaceDenied_.fetch_add(1, std::memory_order_relaxed);
                failures_.fetch_add(1, std::memory_order_relaxed);
                return failResult(126, "ScreenPilot workspace escape rejected: " + arg);
            }
        }
    }

    if ((request.approval_required_mask & requiredPermission) != 0) {
        approvalsRequested_.fetch_add(1, std::memory_order_relaxed);
        if (!requestApproval || requestApproval(
                approvalUser,
                toolId.c_str(),
                summary ? summary : "",
                risk ? risk : "",
                requiredPermission) != 1) {
            approvalsDenied_.fetch_add(1, std::memory_order_relaxed);
            failures_.fetch_add(1, std::memory_order_relaxed);
            return failResult(126, "ScreenPilot approval denied");
        }
    }

    Agentic::ToolRequest tool;
    tool.surface = Agentic::AgentToolSurface::LocalServer;
    tool.tool_id = std::move(toolId);
    tool.args = std::move(args);
    tool.stdin_text = std::move(stdinText);
    tool.working_directory = workspace;

    Agentic::ToolContext ctx;
    ctx.cancelled = [isCancelled, cancelUser]() {
        return isCancelled && isCancelled(cancelUser) != 0;
    };

    registryInvocations_.fetch_add(1, std::memory_order_relaxed);
    auto result = registry_.invoke(std::move(tool), std::move(ctx));
    if (!result.ok()) failures_.fetch_add(1, std::memory_order_relaxed);
    return result;
}

void ScreenPilotToolAuthorityBridge::noteDirectBypassAttempt() noexcept {
    directBypassAttempts_.fetch_add(1, std::memory_order_relaxed);
    failures_.fetch_add(1, std::memory_order_relaxed);
}

ScreenPilotAuthorityReceipt ScreenPilotToolAuthorityBridge::receipt() const noexcept {
    ScreenPilotAuthorityReceipt r;
    r.requests = requests_.load(std::memory_order_relaxed);
    r.registryInvocations = registryInvocations_.load(std::memory_order_relaxed);
    r.approvalsRequested = approvalsRequested_.load(std::memory_order_relaxed);
    r.approvalsDenied = approvalsDenied_.load(std::memory_order_relaxed);
    r.permissionDenied = permissionDenied_.load(std::memory_order_relaxed);
    r.workspaceDenied = workspaceDenied_.load(std::memory_order_relaxed);
    r.cancellations = cancellations_.load(std::memory_order_relaxed);
    r.directBypassAttempts = directBypassAttempts_.load(std::memory_order_relaxed);
    r.failures = failures_.load(std::memory_order_relaxed);
    return r;
}

} // namespace RawrXD::ScreenPilot
