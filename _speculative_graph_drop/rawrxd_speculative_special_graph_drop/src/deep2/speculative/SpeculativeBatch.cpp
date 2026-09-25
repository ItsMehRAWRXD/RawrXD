#include "SpeculativeBatch.hpp"

namespace rawrxd::deep2::spec {

void SpeculativeBatch::reset(std::uint64_t seq, std::size_t prefix) {
    sequence = seq;
    prefixCount = prefix;
    proposals.clear();
    verified.clear();
    acceptedPrefix = 0;
    mismatch = false;
    replacementToken = -1;
}

BatchPlanner::BatchPlanner(BatchPolicy policy)
    : policy_(policy),
      currentWidth_(std::clamp(policy.warmupDraft, policy.minDraft, policy.maxDraft)) {
    if (policy_.minDraft == 0) policy_.minDraft = 1;
    if (policy_.maxDraft < policy_.minDraft) policy_.maxDraft = policy_.minDraft;
    currentWidth_ = std::clamp(currentWidth_, policy_.minDraft, policy_.maxDraft);
}

std::uint32_t BatchPlanner::draftWidth(std::size_t remainingBudget) const noexcept {
    if (remainingBudget == 0) return 0;
    return static_cast<std::uint32_t>(
        std::min<std::size_t>(currentWidth_, remainingBudget));
}

void BatchPlanner::observe(std::size_t proposed, std::size_t accepted) noexcept {
    if (proposed == 0) return;

    const float instant = static_cast<float>(accepted) / static_cast<float>(proposed);
    if (!observed_) {
        acceptanceEma_ = instant;
        observed_ = true;
    } else {
        constexpr float alpha = 0.20f;
        acceptanceEma_ = (1.0f - alpha) * acceptanceEma_ + alpha * instant;
    }

    if (acceptanceEma_ >= policy_.growAcceptance && currentWidth_ < policy_.maxDraft) {
        ++currentWidth_;
    } else if (acceptanceEma_ <= policy_.shrinkAcceptance && currentWidth_ > policy_.minDraft) {
        --currentWidth_;
    }
}

AcceptanceResult compareTeacherForced(
    std::span<const TokenProposal> proposals,
    std::span<const VerifyToken> verified) noexcept {

    AcceptanceResult out{};
    const auto n = std::min(proposals.size(), verified.size());

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
