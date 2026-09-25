#include "VerifyBatch.hpp"

#include <limits>

namespace rawrxd::deep2::spec {

bool VerifyBatch::build(
    std::size_t prefixCount,
    std::span<const TokenProposal> proposals) {

    if (prefixCount > std::numeric_limits<std::uint32_t>::max()) return false;
    if (proposals.size() >
        std::numeric_limits<std::uint32_t>::max() - static_cast<std::uint32_t>(prefixCount)) {
        return false;
    }

    tokens_.resize(proposals.size());
    positions_.resize(proposals.size());

    for (std::size_t i = 0; i < proposals.size(); ++i) {
        tokens_[i] = proposals[i].token;
        positions_[i] = static_cast<std::uint32_t>(prefixCount + i);
    }
    return true;
}

VerifyBatchView VerifyBatch::view() const noexcept {
    return VerifyBatchView{
        tokens_.data(),
        positions_.data(),
        static_cast<std::uint32_t>(tokens_.size())
    };
}

} // namespace rawrxd::deep2::spec
