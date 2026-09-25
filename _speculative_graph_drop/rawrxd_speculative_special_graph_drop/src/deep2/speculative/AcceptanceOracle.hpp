#pragma once
#include "SpeculativeBatch.hpp"

#include <cstdint>
#include <span>

namespace rawrxd::deep2::spec {

// POD command description that the existing Vulkan authority can translate into
// its own buffers/dispatch. No Vulkan headers are required in this layer.
struct AcceptanceScanCommand final {
    const TokenId* proposalTokens{};
    const TokenId* targetTokens{};
    std::uint32_t count{};
};

struct AcceptanceScanResult final {
    std::uint32_t accepted{};
    bool mismatch{};
    TokenId replacement{-1};
};

[[nodiscard]] AcceptanceScanResult runAcceptanceReference(
    const AcceptanceScanCommand& command) noexcept;

[[nodiscard]] AcceptanceScanResult runAcceptanceReference(
    std::span<const TokenProposal> proposals,
    std::span<const VerifyToken> verified) noexcept;

} // namespace rawrxd::deep2::spec
