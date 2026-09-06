// ============================================================================
// P1_REALTIME_GENERATION_CONSISTENCY_001 — RCU generation under concurrent read
// Proves: single-gen token reads, atomic N→N+1, inflight N survives commit,
//         failed validation never swaps, old image lives until last release.
// Exit: 0 all PASS, 1 otherwise.
// ============================================================================
#include "execution_policy/RealtimeKernel.hpp"

#include <atomic>
#include <cstdio>
#include <cmath>
#include <set>
#include <thread>
#include <vector>

using namespace Deep2::Exec;

static int g_fail = 0;
#define PRED(cond, name)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::printf("[CERT_FAIL] %s\n", name);                              \
            ++g_fail;                                                          \
        } else {                                                               \
            std::printf("[CERT_PASS] %s\n", name);                              \
        }                                                                      \
    } while (0)

static RealtimeStateSnapshot MakeSnap(RealtimeKernel* kernel, uint64_t token,
                                        uint64_t proofId) {
    RealtimeStateSnapshot s;
    s.expectedSchemaHash = kernel->schemaHash;
    s.expectedAuthorityHash = kernel->authorityHash;
    s.source = "cert";
    s.state.timing.baselineDecodeMs = 250.0;
    s.state.timing.targetDecodeMs = 100.0;
    s.state.telemetry.tokenIndex = token;
    s.state.policySha = "policy-cert-v1";
    if (proofId)
        s.state.patches.active.push_back(
            CompileReuseRule(proofId, 1, 0x1ULL, proofId, 1000.0));
    return s;
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== P1_REALTIME_GENERATION_CONSISTENCY_001 ===\n");

    RealtimeKernel* kernel = MakeSealedKernel();
    RealtimeEngine engine(kernel);

    // --- single-generation token read ---
    RealtimeReadView view0 = engine.AcquireState();
    PRED(view0.valid(), "TOKEN_READS_SINGLE_GENERATION");
    const uint64_t genAtStart = view0.generation();
    for (int i = 0; i < 64; ++i) {
        PRED(view0.generation() == genAtStart, "TOKEN_READS_SINGLE_GENERATION");
        PRED(view0.raw() != nullptr && view0.raw()->frozen,
             "NO_PARTIAL_IMAGE_VISIBLE");
        PRED(view0.stateImageSha() == view0.raw()->stateHash,
             "HASH_MATCHES_VISIBLE_IMAGE");
        PRED(view0.authorityHash() == kernel->authorityHash,
             "AUTHORITY_HASH_MATCHES");
    }

    // --- commit N → N+1 ---
    CommitResult c1 = engine.CommitRealtimeState(MakeSnap(kernel, 1, 101));
    PRED(c1.ok && c1.newGeneration == 1, "COMMIT_N_TO_N1_ATOMIC");

    RealtimeReadView view1 = engine.AcquireState();
    PRED(view1.generation() == 1, "NEXT_TOKEN_OBSERVES_N1");
    PRED(view0.generation() == 0, "INFLIGHT_N_COMPLETES_ON_N");
    PRED(view0.readerRefCount() >= 1, "OLD_IMAGE_NOT_FREED_WHILE_REFERENCED");

    // view0 still reads gen-0 state after publish of gen-1
    PRED(view0.state().telemetry.tokenIndex == 0,
         "INFLIGHT_N_STATE_STABLE");
    PRED(view1.state().telemetry.tokenIndex == 1,
         "NEXT_TOKEN_OBSERVES_N1_STATE");

    view0 = RealtimeReadView(); // release gen-0 handle

    CommitResult c2 = engine.CommitRealtimeState(MakeSnap(kernel, 2, 102));
    PRED(c2.ok && c2.newGeneration == 2, "COMMIT_N1_TO_N2");
    PRED(engine.lastIssuedGeneration() == 2, "GENERATION_MONOTONIC");

    // --- failed paths never swap ---
    const uint64_t genBeforeFail = engine.AcquireState().generation();
    RealtimeStateSnapshot badSchema = MakeSnap(kernel, 99, 999);
    badSchema.expectedSchemaHash = kernel->schemaHash ^ 0xBADULL;
    CommitResult cf1 = engine.CommitRealtimeState(badSchema);
    PRED(!cf1.ok, "FAILED_VALIDATION_NO_SWAP");
    PRED(engine.AcquireState().generation() == genBeforeFail,
         "FAILED_VALIDATION_NO_SWAP_GEN");

    RealtimeStateSnapshot badProof = MakeSnap(kernel, 100, 0);
    badProof.state.patches.active.clear();
    ExecutionRule wr;
    wr.touchesWeights = true;
    wr.proofId = 0;
    badProof.state.patches.active.push_back(wr);
    CommitResult cf2 = engine.CommitRealtimeState(badProof);
    PRED(!cf2.ok, "FAILED_PROOF_NO_SWAP");
    PRED(engine.AcquireState().generation() == genBeforeFail,
         "FAILED_PROOF_NO_SWAP_GEN");

    RealtimeStateSnapshot bl = MakeSnap(kernel, 101, 555);
    bl.state.patches.blacklist.push_back(555);
    CommitResult cf3 = engine.CommitRealtimeState(bl);
    PRED(!cf3.ok, "BLACKLISTED_RULE_NO_SWAP");
    PRED(engine.AcquireState().generation() == genBeforeFail,
         "BLACKLISTED_RULE_NO_SWAP_GEN");

    // --- generation history: no ABA reuse ---
    std::set<uint64_t> seen;
    seen.insert(0);
    seen.insert(1);
    seen.insert(2);
    for (uint64_t i = 0; i < 5; ++i) {
        RealtimeStateSnapshot s = MakeSnap(kernel, 200 + i, 1000 + i);
        CommitResult cr = engine.CommitRealtimeState(s);
        PRED(cr.ok, "COMMIT_OK_IN_SEQUENCE");
        PRED(seen.find(cr.newGeneration) == seen.end(), "NO_ABA_GENERATION_REUSE");
        seen.insert(cr.newGeneration);
        PRED(cr.newGeneration > genBeforeFail, "GENERATION_MONOTONIC");
    }

    // --- provenance bundle ---
    RealtimeReadView vFinal = engine.AcquireState();
    TokenProvenance prov = ProvenanceFromView(vFinal);
    PRED(prov.stateGeneration == vFinal.generation(), "PROVENANCE_GENERATION");
    PRED(prov.stateImageSha == vFinal.stateImageSha(), "PROVENANCE_IMAGE_SHA");
    PRED(prov.authoritySha == kernel->authorityHash, "PROVENANCE_AUTHORITY_SHA");
    PRED(prov.rulesetSha == vFinal.rulesetSha(), "PROVENANCE_RULESET_SHA");
    PRED(prov.proofSetSha == vFinal.proofSetSha(), "PROVENANCE_PROOF_SET_SHA");

    std::printf("--- provenance gen=%llu imageSha=%llx authoritySha=%llx ---\n",
                (unsigned long long)prov.stateGeneration,
                (unsigned long long)prov.stateImageSha,
                (unsigned long long)prov.authoritySha);

    // --- concurrent reader + commit (stress) ---
    {
        std::atomic<bool> readerDone{false};
        std::atomic<uint64_t> readerGen{UINT64_MAX};
        std::atomic<bool> readerStable{true};

        RealtimeReadView inflight = engine.AcquireState();
        const uint64_t inflightGen = inflight.generation();

        std::thread reader([&]() {
            RealtimeReadView local = engine.AcquireState();
            readerGen.store(local.generation());
            for (int spin = 0; spin < 10000; ++spin) {
                if (local.generation() != readerGen.load())
                    readerStable.store(false);
                if (!local.valid() || !local.raw()->frozen)
                    readerStable.store(false);
            }
            readerDone.store(true);
        });

        CommitResult cc =
            engine.CommitRealtimeState(MakeSnap(kernel, 9999, 9999));
        PRED(cc.ok, "CONCURRENT_COMMIT_OK");

        RealtimeReadView after = engine.AcquireState();
        PRED(after.generation() == cc.newGeneration,
             "CONCURRENT_NEXT_TOKEN_N1");
        PRED(inflight.generation() == inflightGen,
             "CONCURRENT_INFLIGHT_N_STABLE");

        reader.join();
        PRED(readerStable.load(), "CONCURRENT_READER_SINGLE_GEN");
        PRED(readerDone.load(), "CONCURRENT_READER_COMPLETED");
    }

    delete kernel;
    std::printf("=== %s: %s (%d fail) ===\n",
                "P1_REALTIME_GENERATION_CONSISTENCY_001",
                g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
