#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace rawrxd::deep2::spec {

using TokenId = std::int32_t;

struct TokenProposal final {
    TokenId token{-1};
    float draftScore{0.0f};
};

struct VerifyToken final {
    TokenId targetToken{-1};
    float targetScore{0.0f};
};

struct SpeculativeBatch final {
    std::uint64_t sequence{};
    std::size_t prefixCount{};
    std::vector<TokenProposal> proposals{};
    std::vector<VerifyToken> verified{};
    std::size_t acceptedPrefix{};
    bool mismatch{};
    TokenId replacementToken{-1};

    void reset(std::uint64_t seq, std::size_t prefix);
};

struct BatchPolicy final {
    std::uint32_t minDraft{1};
    std::uint32_t maxDraft{8};
    std::uint32_t warmupDraft{2};
    float growAcceptance{0.85f};
    float shrinkAcceptance{0.45f};
};

class BatchPlanner final {
public:
    explicit BatchPlanner(BatchPolicy policy = {});

    [[nodiscard]] std::uint32_t draftWidth(std::size_t remainingBudget) const noexcept;
    void observe(std::size_t proposed, std::size_t accepted) noexcept;

    [[nodiscard]] float acceptanceEma() const noexcept { return acceptanceEma_; }
    [[nodiscard]] std::uint32_t currentWidth() const noexcept { return currentWidth_; }

private:
    BatchPolicy policy_{};
    std::uint32_t currentWidth_{};
    float acceptanceEma_{1.0f};
    bool observed_{false};
};

struct AcceptanceResult final {
    std::size_t accepted{};
    bool mismatch{};
    TokenId replacement{-1};
};

[[nodiscard]] AcceptanceResult compareTeacherForced(
    std::span<const TokenProposal> proposals,
    std::span<const VerifyToken> verified) noexcept;

} // namespace rawrxd::deep2::spec
