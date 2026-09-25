#include "../src/deep2/speculative/AcceptanceOracle.hpp"
#include "../src/deep2/speculative/DraftPolicy.hpp"
#include "../src/deep2/speculative/DualGpuOverlap.hpp"
#include "../src/deep2/speculative/KvTransaction.hpp"
#include "../src/deep2/speculative/SpeculativeCert.hpp"
#include "../src/deep2/speculative/VerifyBatch.hpp"

#include <iostream>
#include <vector>

using namespace rawrxd::deep2::spec;

namespace {
struct FakeKv {
    std::size_t tokens{12};
    std::uint64_t generation{7};
    bool restored{};
    bool sealed{};
};

bool capture(void* u, KvSnapshot* out) {
    auto& kv = *static_cast<FakeKv*>(u);
    *out = KvSnapshot{kv.tokens, kv.generation, 11, 22};
    return true;
}
bool restore(void* u, const KvSnapshot* s) {
    auto& kv = *static_cast<FakeKv*>(u);
    kv.tokens = s->tokenCount;
    kv.generation = s->generation;
    kv.restored = true;
    return true;
}
bool seal(void* u, const KvSnapshot* s, std::size_t committed) {
    auto& kv = *static_cast<FakeKv*>(u);
    kv.tokens = s->tokenCount + committed;
    kv.sealed = true;
    return true;
}
}

int main() {
    const std::vector<TokenProposal> proposals{
        {10, 1.0f}, {11, 1.0f}, {12, 1.0f}, {13, 1.0f}
    };
    const std::vector<VerifyToken> verified{
        {10, 1.0f}, {11, 1.0f}, {99, 1.0f}, {13, 1.0f}
    };

    VerifyBatch vb;
    if (!vb.build(32, proposals)) return 1;
    if (vb.positions().size() != 4 || vb.positions()[3] != 35) return 2;

    const auto scan = runAcceptanceReference(proposals, verified);
    if (scan.accepted != 2 || !scan.mismatch || scan.replacement != 99) return 3;

    DraftRouteMetrics metrics;
    metrics.acceptanceEma = 0.9f;
    metrics.sameModelMilliseconds = 4.0f;
    metrics.secondaryMilliseconds = 2.0f;
    metrics.secondaryAvailable = true;
    if (chooseDraftRoute({}, metrics) != DraftRoute::SecondaryModel) return 4;

    const auto dual = buildDualGpuPlan(
        DualGpuCapabilities{false, true, true});
    if (dual.transfer != TransferPath::HostVisibleStaging ||
        dual.steps.size() != 6) return 5;

    FakeKv kv;
    KvAuthority authority{&kv, &capture, &restore, &seal};
    KvTransaction tx;
    if (!tx.begin(authority)) return 6;
    if (!tx.rollback(authority) || !kv.restored) return 7;

    if (!tx.begin(authority)) return 8;
    if (!tx.commit(authority, 3) || !kv.sealed || kv.tokens != 15) return 9;

    ExecutorStats stats;
    stats.committedTokens = 11;
    stats.proposedTokens = 12;
    stats.acceptedDraftTokens = 10;
    stats.replacementTokens = 1;
    stats.rollbackCalls = 1;

    const auto cert = makeSpeculativeCert(
        SpeculativeCertInput{stats, 11, 0, 0, true, true});
    if (!cert.pass) return 10;

    std::cout << "RAWRXD_SPEC_INFRASTRUCTURE_001\n";
    std::cout << "VERIFY_BATCH=PASS\n";
    std::cout << "ACCEPTANCE_ORACLE=PASS\n";
    std::cout << "DRAFT_ROUTE=PASS\n";
    std::cout << "DUAL_GPU_STAGING_PLAN=PASS\n";
    std::cout << "KV_TRANSACTION=PASS\n";
    std::cout << cert.text;
    return 0;
}
