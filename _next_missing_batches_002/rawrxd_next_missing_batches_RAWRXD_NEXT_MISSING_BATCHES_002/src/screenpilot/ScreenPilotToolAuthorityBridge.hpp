#pragma once

#include "deep2/AgentToolRegistry.hpp"
#include "screenpilot/rawrxd_screenpilot_agent_v2.h"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace RawrXD::ScreenPilot {

struct ScreenPilotAuthorityReceipt final {
    std::uint64_t requests{};
    std::uint64_t registryInvocations{};
    std::uint64_t approvalsRequested{};
    std::uint64_t approvalsDenied{};
    std::uint64_t permissionDenied{};
    std::uint64_t workspaceDenied{};
    std::uint64_t cancellations{};
    std::uint64_t directBypassAttempts{};
    std::uint64_t failures{};

    [[nodiscard]] bool pass() const noexcept;
    [[nodiscard]] std::string text() const;
};

class ScreenPilotToolAuthorityBridge final {
public:
    explicit ScreenPilotToolAuthorityBridge(Agentic::AgentToolRegistry& registry);

    Agentic::ToolResult invoke(
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
        void* approvalUser);

    void noteDirectBypassAttempt() noexcept;
    [[nodiscard]] ScreenPilotAuthorityReceipt receipt() const noexcept;

    static bool pathWithinWorkspace(
        const std::filesystem::path& workspace,
        const std::filesystem::path& candidate) noexcept;

private:
    Agentic::AgentToolRegistry& registry_;
    mutable std::atomic<std::uint64_t> requests_{0};
    mutable std::atomic<std::uint64_t> registryInvocations_{0};
    mutable std::atomic<std::uint64_t> approvalsRequested_{0};
    mutable std::atomic<std::uint64_t> approvalsDenied_{0};
    mutable std::atomic<std::uint64_t> permissionDenied_{0};
    mutable std::atomic<std::uint64_t> workspaceDenied_{0};
    mutable std::atomic<std::uint64_t> cancellations_{0};
    mutable std::atomic<std::uint64_t> directBypassAttempts_{0};
    mutable std::atomic<std::uint64_t> failures_{0};
};

} // namespace RawrXD::ScreenPilot
