#pragma once
#include "SpeculativeExecutor.hpp"

#include <cstdint>
#include <string>

namespace rawrxd::deep2::spec {

struct SpeculativeCertInput final {
    ExecutorStats stats{};
    std::uint64_t targetOnlyTokens{};
    std::uint64_t parityMismatches{};
    std::uint64_t stubFallbacks{};
    bool kvRollbackVerified{};
    bool strictGpuAuthority{};
};

struct SpeculativeCert final {
    bool pass{};
    std::string text{};
};

[[nodiscard]] SpeculativeCert makeSpeculativeCert(
    const SpeculativeCertInput& input);

} // namespace rawrxd::deep2::spec
