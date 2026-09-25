#pragma once
#include "SpecialGraph.hpp"
#include "SpeculativeBatch.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace rawrxd::deep2::spec {

// Zero-dependency ABI surface. Deep2/Vulkan/CPU code can adapt to these callbacks
// without SpeculativeExecutor depending on any backend implementation.
struct BackendCallbacks final {
    void* user{};

    // Produce up to capacity draft tokens from prefix.
    bool (*draft)(
        void* user,
        const TokenId* prefix,
        std::size_t prefixCount,
        TokenProposal* out,
        std::uint32_t capacity,
        std::uint32_t* produced){};

    // Teacher-force the proposal batch through the target model. Each returned
    // targetToken is the target model's selected token at that proposal position.
    bool (*verify)(
        void* user,
        const TokenId* prefix,
        std::size_t prefixCount,
        const TokenProposal* proposals,
        std::uint32_t proposalCount,
        VerifyToken* out,
        std::uint32_t* verifiedCount){};

    // Optional cache hooks. They let a real backend keep KV state coherent.
    bool (*checkpoint)(void* user, std::uint64_t sequence, std::size_t prefixCount){};
    bool (*rollback)(void* user, std::uint64_t sequence, std::size_t keepPrefixCount){};
    bool (*commit)(void* user, std::uint64_t sequence, const TokenId* tokens, std::uint32_t count){};
};

struct ExecutorConfig final {
    std::uint32_t maxNewTokens{128};
    BatchPolicy batch{};
    bool requireFullVerify{true};
};

struct ExecutorStats final {
    std::uint64_t graphSteps{};
    std::uint64_t draftCalls{};
    std::uint64_t verifyCalls{};
    std::uint64_t rollbackCalls{};
    std::uint64_t commitCalls{};
    std::uint64_t proposedTokens{};
    std::uint64_t acceptedDraftTokens{};
    std::uint64_t replacementTokens{};
    std::uint64_t committedTokens{};
    float finalAcceptanceEma{1.0f};
    std::uint32_t finalDraftWidth{1};
};

enum class ExecutorStatus : std::uint8_t {
    Ok,
    InvalidGraph,
    InvalidCallbacks,
    BackendFailure,
    VerifyUnderflow,
    GraphRoutingFailure
};

struct ExecutorResult final {
    ExecutorStatus status{ExecutorStatus::Ok};
    std::string message{};
    std::vector<TokenId> tokens{};
    ExecutorStats stats{};
};

class SpeculativeExecutor final {
public:
    explicit SpeculativeExecutor(ExecutorConfig config = {});

    [[nodiscard]] ExecutorResult run(
        std::span<const TokenId> prompt,
        const BackendCallbacks& backend);

    [[nodiscard]] const SpecialGraph& graph() const noexcept { return graph_; }

private:
    ExecutorConfig config_{};
    SpecialGraph graph_{};
};

[[nodiscard]] const char* toString(ExecutorStatus status) noexcept;

} // namespace rawrxd::deep2::spec
