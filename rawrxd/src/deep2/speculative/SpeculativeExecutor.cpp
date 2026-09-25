#include "SpeculativeExecutor.hpp"

#include <algorithm>
#include <limits>

namespace rawrxd::deep2::spec {

namespace {
constexpr std::uint32_t kInvalidNode = std::numeric_limits<std::uint32_t>::max();

std::uint32_t findOp(const SpecialGraph& graph, GraphOp op) {
    for (const auto& node : graph.nodes()) {
        if (node.op == op) return node.id;
    }
    return kInvalidNode;
}
}

SpeculativeExecutor::SpeculativeExecutor(ExecutorConfig config)
    : config_(config), graph_(SpecialGraph::makeSpeculativeDecodeGraph()) {}

ExecutorResult SpeculativeExecutor::run(
    std::span<const TokenId> prompt,
    const BackendCallbacks& backend) {

    ExecutorResult result{};

    std::string why;
    if (!graph_.validate(&why)) {
        result.status = ExecutorStatus::InvalidGraph;
        result.message = std::move(why);
        return result;
    }
    if (!backend.draft || !backend.verify) {
        result.status = ExecutorStatus::InvalidCallbacks;
        result.message = "draft and verify callbacks are required";
        return result;
    }

    result.tokens.assign(prompt.begin(), prompt.end());
    const std::size_t promptCount = prompt.size();

    BatchPlanner planner(config_.batch);
    SpeculativeBatch batch;
    std::uint64_t sequence = 0;

    auto current = findOp(graph_, GraphOp::Draft);
    if (current == kInvalidNode) {
        result.status = ExecutorStatus::InvalidGraph;
        result.message = "draft node not found";
        return result;
    }

    std::vector<TokenId> pendingCommit;

    auto fail = [&](ExecutorStatus status, const char* msg) {
        result.status = status;
        result.message = msg;
        result.stats.finalAcceptanceEma = planner.acceptanceEma();
        result.stats.finalDraftWidth = planner.currentWidth();
        return result;
    };

    while (true) {
        ++result.stats.graphSteps;
        const auto* node = graph_.node(current);
        if (!node) return fail(ExecutorStatus::GraphRoutingFailure, "invalid graph node");

        const std::size_t generated = result.tokens.size() - promptCount;
        const std::size_t remaining =
            generated < config_.maxNewTokens ? config_.maxNewTokens - generated : 0;

        switch (node->op) {
            case GraphOp::Draft: {
                if (remaining == 0) {
                    current = graph_.next(current, EdgeCond::DraftEmpty);
                    break;
                }

                batch.reset(++sequence, result.tokens.size());

                if (backend.checkpoint &&
                    !backend.checkpoint(backend.user, batch.sequence, batch.prefixCount)) {
                    return fail(ExecutorStatus::BackendFailure, "checkpoint callback failed");
                }

                const auto width = planner.draftWidth(remaining);
                batch.proposals.resize(width);
                std::uint32_t produced = 0;
                ++result.stats.draftCalls;

                if (!backend.draft(
                        backend.user,
                        result.tokens.data(),
                        result.tokens.size(),
                        batch.proposals.data(),
                        width,
                        &produced)) {
                    return fail(ExecutorStatus::BackendFailure, "draft callback failed");
                }

                produced = std::min(produced, width);
                batch.proposals.resize(produced);
                result.stats.proposedTokens += produced;

                current = graph_.next(
                    current,
                    produced ? EdgeCond::DraftProduced : EdgeCond::DraftEmpty);
                break;
            }

            case GraphOp::Verify: {
                batch.verified.resize(batch.proposals.size());
                std::uint32_t verifiedCount = 0;
                ++result.stats.verifyCalls;

                if (!backend.verify(
                        backend.user,
                        result.tokens.data(),
                        result.tokens.size(),
                        batch.proposals.data(),
                        static_cast<std::uint32_t>(batch.proposals.size()),
                        batch.verified.data(),
                        &verifiedCount)) {
                    return fail(ExecutorStatus::BackendFailure, "verify callback failed");
                }

                verifiedCount = std::min<std::uint32_t>(
                    verifiedCount, static_cast<std::uint32_t>(batch.verified.size()));
                batch.verified.resize(verifiedCount);

                if (config_.requireFullVerify &&
                    batch.verified.size() != batch.proposals.size()) {
                    return fail(ExecutorStatus::VerifyUnderflow,
                                "target verifier returned fewer positions than proposed");
                }

                current = graph_.next(current, EdgeCond::Always);
                break;
            }

            case GraphOp::Accept: {
                const auto acceptance = compareTeacherForced(
                    batch.proposals, batch.verified);

                batch.acceptedPrefix = acceptance.accepted;
                batch.mismatch = acceptance.mismatch;
                batch.replacementToken = acceptance.replacement;

                planner.observe(batch.proposals.size(), batch.acceptedPrefix);
                result.stats.acceptedDraftTokens += batch.acceptedPrefix;

                pendingCommit.clear();
                const auto remainingNow =
                    config_.maxNewTokens - (result.tokens.size() - promptCount);

                const auto acceptedToCommit =
                    std::min<std::size_t>(batch.acceptedPrefix, remainingNow);
                pendingCommit.reserve(acceptedToCommit + 1);

                for (std::size_t i = 0; i < acceptedToCommit; ++i) {
                    pendingCommit.push_back(batch.proposals[i].token);
                }

                if (batch.mismatch &&
                    pendingCommit.size() < remainingNow &&
                    batch.replacementToken >= 0) {
                    pendingCommit.push_back(batch.replacementToken);
                    ++result.stats.replacementTokens;
                }

                current = graph_.next(
                    current,
                    batch.mismatch ? EdgeCond::Rejected : EdgeCond::AllAccepted);
                break;
            }

            case GraphOp::Rollback: {
                ++result.stats.rollbackCalls;
                if (backend.rollback &&
                    !backend.rollback(backend.user, batch.sequence, batch.prefixCount)) {
                    return fail(ExecutorStatus::BackendFailure, "rollback callback failed");
                }
                current = graph_.next(current, EdgeCond::Always);
                break;
            }

            case GraphOp::Commit: {
                if (pendingCommit.empty()) {
                    // An all-accepted batch is assembled here if Accept did not create it
                    // due to a verifier truncation mode.
                    const auto remainingNow =
                        config_.maxNewTokens - (result.tokens.size() - promptCount);
                    const auto n = std::min<std::size_t>(
                        batch.acceptedPrefix, remainingNow);
                    for (std::size_t i = 0; i < n; ++i) {
                        pendingCommit.push_back(batch.proposals[i].token);
                    }
                }

                if (pendingCommit.empty()) {
                    return fail(ExecutorStatus::BackendFailure,
                                "speculative iteration made no forward progress");
                }

                ++result.stats.commitCalls;
                if (backend.commit &&
                    !backend.commit(
                        backend.user,
                        batch.sequence,
                        pendingCommit.data(),
                        static_cast<std::uint32_t>(pendingCommit.size()))) {
                    return fail(ExecutorStatus::BackendFailure, "commit callback failed");
                }

                result.tokens.insert(
                    result.tokens.end(), pendingCommit.begin(), pendingCommit.end());
                result.stats.committedTokens += pendingCommit.size();
                pendingCommit.clear();

                const auto nowGenerated = result.tokens.size() - promptCount;
                current = graph_.next(
                    current,
                    nowGenerated >= config_.maxNewTokens
                        ? EdgeCond::BudgetExhausted
                        : EdgeCond::BudgetRemaining);
                break;
            }

            case GraphOp::Stop:
                result.status = ExecutorStatus::Ok;
                result.message = "speculative decode complete";
                result.stats.finalAcceptanceEma = planner.acceptanceEma();
                result.stats.finalDraftWidth = planner.currentWidth();
                return result;
        }

        if (current == kInvalidNode) {
            return fail(ExecutorStatus::GraphRoutingFailure,
                        "no graph edge matched current condition");
        }
    }
}

const char* toString(ExecutorStatus status) noexcept {
    switch (status) {
        case ExecutorStatus::Ok: return "Ok";
        case ExecutorStatus::InvalidGraph: return "InvalidGraph";
        case ExecutorStatus::InvalidCallbacks: return "InvalidCallbacks";
        case ExecutorStatus::BackendFailure: return "BackendFailure";
        case ExecutorStatus::VerifyUnderflow: return "VerifyUnderflow";
        case ExecutorStatus::GraphRoutingFailure: return "GraphRoutingFailure";
    }
    return "Unknown";
}

} // namespace rawrxd::deep2::spec
