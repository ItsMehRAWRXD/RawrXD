// ============================================================================
// P1_REALTIME_STATE_IMAGE_001 — sealed structure; atomic replaceable data
// REALTIME_STRUCTURE_MUTATION = FORBIDDEN
// REALTIME_STATE_REPLACEMENT  = ALLOWED (validated + atomic)
// Exit: 0 all PASS, 1 otherwise.
// ============================================================================
#include "execution_policy/RealtimeKernel.hpp"
#include "execution_policy/LiveTimeDisappearance.hpp"
#include "execution_policy/HotpatchSynthesizer.hpp"

#include <cstdio>
#include <cmath>

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

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== P1_REALTIME_STATE_IMAGE_001 ===\n");

    RealtimeKernel* kernel = MakeSealedKernel();
    PRED(kernel != nullptr, "SEALED_KERNEL_CONSTRUCTED");
    PRED(kernel->authority.forbidStructureMutation, "STRUCTURE_MUTATION_FORBIDDEN_FLAG");
    PRED(kernel->authority.forbidGraphRewrite, "GRAPH_REWRITE_FORBIDDEN_FLAG");
    PRED(kernel->authority.forbidAuthorityRewrite, "AUTHORITY_REWRITE_FORBIDDEN_FLAG");

    {
    RealtimeEngine engine(kernel);

    // Forbidden mutation seams must fail closed.
    PRED(!engine.ModifyRealtimeKernel(), "MODIFY_KERNEL_REJECTED");
    PRED(!engine.RewriteExecutionGraph(), "REWRITE_GRAPH_REJECTED");
    PRED(!engine.PatchAuthorityRules(), "PATCH_AUTHORITY_REJECTED");

    const RealtimeImage* gen0 = engine.active();
    PRED(gen0 != nullptr && gen0->generation == 0, "INITIAL_GENERATION_ZERO");
    PRED(gen0->schemaHash == kernel->schemaHash, "SCHEMA_HASH_BOUND");
    PRED(gen0->authorityHash == kernel->authorityHash, "AUTHORITY_HASH_BOUND");
    PRED(gen0->frozen, "IMAGE_FROZEN");

    // Latency → time debt → live budget
    LiveTimeDisappearance live{};
    SeedLiveBudget(live, 250.0, 100.0);
    PRED(std::fabs(live.mustDisappearMs - 150.0) < 1e-9, "MUST_DISAPPEAR_150");
    PRED(std::fabs(live.targetSpeedup - 2.5) < 1e-9, "TARGET_SPEEDUP_2_5");
    PRED(std::fabs(live.targetTps - 10.0) < 1e-9, "TARGET_TPS_10");

    LatencyBudgetSlice slice{};
    slice.ffnMs = 110;
    slice.attentionMs = 45;
    slice.nvmeMs = 25;
    slice.migrationMs = 15;
    slice.memoryStallMs = 35;
    slice.syncMs = 10;
    slice.otherMs = 10;
    SeedClassBaselines(live, slice);

    UpdateLiveDisappearance(live, 156.3, 20.0, 4.0);
    SetCurrentClassMs(live, WorkClass::Ffn, 53);
    SetCurrentClassMs(live, WorkClass::Attention, 34);
    SetCurrentClassMs(live, WorkClass::Nvme, 7);
    SetCurrentClassMs(live, WorkClass::Migration, 2);
    SetCurrentClassMs(live, WorkClass::MemStall, 21);

    PRED(live.netDisappearedMs > 0.0, "NET_DISAPPEARED_POSITIVE");
    PRED(live.remainingMs > 0.0 && live.remainingMs < 150.0, "REMAINING_IN_RANGE");
    PRED(live.currentSpeedup > 1.0 && live.currentSpeedup < 2.5,
         "PARTIAL_SPEEDUP_BELOW_TARGET");
    PRED(live.progress > 0.0 && live.progress < 1.0, "PROGRESS_PARTIAL");

    // Outside-time discovery → data rule → atomic commit
    RealtimeStateSnapshot snap;
    snap.expectedSchemaHash = kernel->schemaHash;
    snap.expectedAuthorityHash = kernel->authorityHash;
    snap.source = "hexmag";
    snap.state.timing.baselineDecodeMs = 250.0;
    snap.state.timing.targetDecodeMs = 100.0;
    snap.state.patches.active.push_back(
        CompileReuseRule(/*id=*/17, /*region=*/3, /*pred=*/0xABCULL,
                         /*proof=*/123, /*us=*/34600.0));
    WriteTelemetryIntoState(snap.state, live);

    CommitResult c1 = engine.CommitRealtimeState(snap);
    PRED(c1.ok, "COMMIT_STATE_OK");
    PRED(c1.newGeneration == 1, "GENERATION_BUMPED_TO_1");

    const RealtimeImage* gen1 = engine.active();
    PRED(gen1 && gen1->generation == 1, "ACTIVE_IS_GEN1");
    PRED(gen1->state.patches.active.size() == 1, "PATCH_DATA_PRESENT");
    PRED(gen1->state.timing.mustDisappearMs == 150.0, "COMMIT_MUST_DISAPPEAR");
    PRED(std::fabs(gen1->state.timing.targetRealSpeedup - 2.5) < 1e-9,
         "COMMIT_DERIVED_SPEEDUP");

    // Token boundary: gen for token uses active generation (N+1 after commit).
    PRED(engine.generationForToken(182) == 1, "TOKEN_SEES_NEW_GENERATION");

    // Schema mismatch must reject
    RealtimeStateSnapshot bad = snap;
    bad.expectedSchemaHash = kernel->schemaHash ^ 0xDEADULL;
    CommitResult cBad = engine.CommitRealtimeState(bad);
    PRED(!cBad.ok, "SCHEMA_MISMATCH_REJECTED");
    PRED(engine.active()->generation == 1, "GENERATION_UNCHANGED_ON_REJECT");

    // Blacklisted rule rejected
    RealtimeStateSnapshot bl = snap;
    bl.state.patches.blacklist.push_back(123);
    CommitResult cBl = engine.CommitRealtimeState(bl);
    PRED(!cBl.ok, "BLACKLISTED_RULE_REJECTED");

    // Weight rule without proof rejected
    RealtimeStateSnapshot wt = snap;
    wt.state.patches.active.clear();
    ExecutionRule wr;
    wr.id = 99;
    wr.action = RuleAction::QuantSpecialize;
    wr.touchesWeights = true;
    wr.proofId = 0;
    wt.state.patches.active.push_back(wr);
    CommitResult cWt = engine.CommitRealtimeState(wt);
    PRED(!cWt.ok, "WEIGHT_RULE_WITHOUT_PROOF_REJECTED");

    // Second commit advances generation (atomic overwrite)
    snap.state.telemetry.tokenIndex = 183;
    CommitResult c2 = engine.CommitRealtimeState(snap);
    PRED(c2.ok && c2.newGeneration == 2, "SECOND_COMMIT_GEN2");
    PRED(engine.active()->generation == 2, "ACTIVE_IS_GEN2");

    // Latency reverse math
    PRED(std::fabs(RequiredSpeedupFromLatency(250.0, 100.0) - 2.5) < 1e-9,
         "LATENCY_TO_SPEEDUP");
    PRED(std::fabs(MsPerTokenFromTps(4.0) - 250.0) < 1e-9, "TPS_TO_MS");
    PRED(std::fabs(TpsFromMsPerToken(100.0) - 10.0) < 1e-9, "MS_TO_TPS");

    const auto banner = FormatTimeDisappearanceBanner(live);
    PRED(banner.find("DISAPPEARANCE") != std::string::npos, "BANNER_RENDERED");
    const auto table = FormatTimeDisappearanceTable(live);
    PRED(table.find("FFN") != std::string::npos, "TABLE_HAS_FFN");

    std::printf("--- banner ---\n%s", banner.c_str());
    std::printf("--- table ---\n%s", table.c_str());
    } // engine destroyed before kernel

    delete kernel;
    std::printf("=== %s: %s (%d fail) ===\n", "P1_REALTIME_STATE_IMAGE_001",
                g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
