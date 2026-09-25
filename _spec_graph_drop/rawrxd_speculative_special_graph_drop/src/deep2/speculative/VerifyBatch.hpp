#pragma once
#include "SpeculativeBatch.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace rawrxd::deep2::spec {

struct VerifyBatchView final {
    const TokenId* tokens{};
    const std::uint32_t* positions{};
    std::uint32_t count{};
};

class VerifyBatch final {
public:
    bool build(
        std::size_t prefixCount,
        std::span<const TokenProposal> proposals);

    [[nodiscard]] VerifyBatchView view() const noexcept;
    [[nodiscard]] const std::vector<TokenId>& tokens() const noexcept { return tokens_; }
    [[nodiscard]] const std::vector<std::uint32_t>& positions() const noexcept { return positions_; }

private:
    std::vector<TokenId> tokens_{};
    std::vector<std::uint32_t> positions_{};
};

} // namespace rawrxd::deep2::spec
