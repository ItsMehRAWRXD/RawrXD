#pragma once
#include "SpeculativeExecutor.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace rawrxd::deep2::spec {

// Thin bridge state for wiring the generic speculative engine into Deep2.
// No Deep2Engine headers are included here intentionally: the shipping engine
// can own this state and provide lambdas/static wrappers to BackendCallbacks.
struct Deep2SpeculativeState final {
    std::uint64_t activeSequence{};
    std::size_t checkpointPrefix{};
    std::vector<TokenId> stagedTokens{};
    std::uint64_t cacheGeneration{};
    bool checkpointValid{};
};

inline bool beginCheckpoint(
    Deep2SpeculativeState& state,
    std::uint64_t sequence,
    std::size_t prefixCount) noexcept {
    state.activeSequence = sequence;
    state.checkpointPrefix = prefixCount;
    state.stagedTokens.clear();
    state.checkpointValid = true;
    return true;
}

inline bool rollbackCheckpoint(
    Deep2SpeculativeState& state,
    std::uint64_t sequence,
    std::size_t keepPrefixCount) noexcept {
    if (!state.checkpointValid || sequence != state.activeSequence) return false;
    if (keepPrefixCount != state.checkpointPrefix) return false;
    state.stagedTokens.clear();
    ++state.cacheGeneration;
    return true;
}

inline bool commitCheckpoint(
    Deep2SpeculativeState& state,
    std::uint64_t sequence,
    const TokenId* tokens,
    std::uint32_t count) {
    if (!state.checkpointValid || sequence != state.activeSequence) return false;
    state.stagedTokens.assign(tokens, tokens + count);
    state.checkpointValid = false;
    ++state.cacheGeneration;
    return true;
}

} // namespace rawrxd::deep2::spec
