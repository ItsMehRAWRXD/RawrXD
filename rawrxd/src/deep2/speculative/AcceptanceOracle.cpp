#include "AcceptanceOracle.hpp"

#include <algorithm>

namespace rawrxd::deep2::spec {

AcceptanceScanResult runAcceptanceReference(
    const AcceptanceScanCommand& command) noexcept {

    AcceptanceScanResult out{};
    if (!command.proposalTokens || !command.targetTokens || command.count == 0) {
        return out;
    }

    while (out.accepted < command.count &&
           command.proposalTokens[out.accepted] ==
           command.targetTokens[out.accepted]) {
        ++out.accepted;
    }

    if (out.accepted < command.count) {
        out.mismatch = true;
        out.replacement = command.targetTokens[out.accepted];
    }
    return out;
}

AcceptanceScanResult runAcceptanceReference(
    std::span<const TokenProposal> proposals,
    std::span<const VerifyToken> verified) noexcept {

    const auto n = std::min(proposals.size(), verified.size());
    AcceptanceScanResult out{};
    while (out.accepted < n &&
           proposals[out.accepted].token == verified[out.accepted].targetToken) {
        ++out.accepted;
    }
    if (out.accepted < n) {
        out.mismatch = true;
        out.replacement = verified[out.accepted].targetToken;
    }
    return out;
}

} // namespace rawrxd::deep2::spec
