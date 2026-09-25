#include "../src/deep2/speculative/SpeculativeExecutor.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <vector>

using namespace rawrxd::deep2::spec;

namespace {

struct FakeBackend {
    std::uint32_t round{};
    std::uint64_t checkpoints{};
    std::uint64_t rollbacks{};
    std::uint64_t commits{};
};

bool draftFn(
    void* user,
    const TokenId*,
    std::size_t,
    TokenProposal* out,
    std::uint32_t capacity,
    std::uint32_t* produced) {

    auto& s = *static_cast<FakeBackend*>(user);
    const std::uint32_t n = std::min<std::uint32_t>(capacity, 4);
    for (std::uint32_t i = 0; i < n; ++i) {
        out[i] = TokenProposal{
            static_cast<TokenId>(1000 + s.round * 10 + i),
            1.0f
        };
    }
    *produced = n;
    return true;
}

bool verifyFn(
    void* user,
    const TokenId*,
    std::size_t,
    const TokenProposal* proposals,
    std::uint32_t proposalCount,
    VerifyToken* out,
    std::uint32_t* verifiedCount) {

    auto& s = *static_cast<FakeBackend*>(user);

    for (std::uint32_t i = 0; i < proposalCount; ++i) {
        out[i] = VerifyToken{proposals[i].token, 1.0f};
    }

    // Force one rejection on the second decode round. This validates that
    // accepted prefix tokens are preserved and the target replacement is committed.
    if (s.round == 1 && proposalCount > 2) {
        out[2].targetToken = 4242;
    }

    *verifiedCount = proposalCount;
    ++s.round;
    return true;
}

bool checkpointFn(void* user, std::uint64_t, std::size_t) {
    ++static_cast<FakeBackend*>(user)->checkpoints;
    return true;
}

bool rollbackFn(void* user, std::uint64_t, std::size_t) {
    ++static_cast<FakeBackend*>(user)->rollbacks;
    return true;
}

bool commitFn(void* user, std::uint64_t, const TokenId*, std::uint32_t) {
    ++static_cast<FakeBackend*>(user)->commits;
    return true;
}

} // namespace

int main() {
    ExecutorConfig cfg;
    cfg.maxNewTokens = 11;
    cfg.batch.minDraft = 1;
    cfg.batch.maxDraft = 6;
    cfg.batch.warmupDraft = 4;

    SpeculativeExecutor exec(cfg);

    std::string why;
    if (!exec.graph().validate(&why)) {
        std::cerr << "GRAPH_VALIDATE=FAIL " << why << "\n";
        return 1;
    }

    FakeBackend fake;
    BackendCallbacks cb;
    cb.user = &fake;
    cb.draft = &draftFn;
    cb.verify = &verifyFn;
    cb.checkpoint = &checkpointFn;
    cb.rollback = &rollbackFn;
    cb.commit = &commitFn;

    const std::vector<TokenId> prompt{1, 2, 3};
    const auto result = exec.run(prompt, cb);

    const auto generated = result.tokens.size() - prompt.size();

    std::cout << "RAWRXD_SPEC_SPECIAL_GRAPH_001\n";
    std::cout << "STATUS=" << toString(result.status) << "\n";
    std::cout << "GRAPH_VALIDATE=PASS\n";
    std::cout << "GENERATED=" << generated << "\n";
    std::cout << "PROPOSED=" << result.stats.proposedTokens << "\n";
    std::cout << "ACCEPTED_DRAFT=" << result.stats.acceptedDraftTokens << "\n";
    std::cout << "REPLACEMENTS=" << result.stats.replacementTokens << "\n";
    std::cout << "ROLLBACKS=" << result.stats.rollbackCalls << "\n";
    std::cout << "COMMITS=" << result.stats.commitCalls << "\n";
    std::cout << "FINAL_WIDTH=" << result.stats.finalDraftWidth << "\n";

    if (result.status != ExecutorStatus::Ok) return 2;
    if (generated != cfg.maxNewTokens) return 3;
    if (result.stats.rollbackCalls != 1) return 4;
    if (std::find(result.tokens.begin(), result.tokens.end(), 4242) == result.tokens.end()) return 5;

    std::cout << "VERDICT=PASS\n";
    return 0;
}
