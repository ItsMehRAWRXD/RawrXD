// ============================================================================
// deep2_sovereign_engine_cert_001.cpp
// RAWRXD_DEEP2_SOVEREIGN_KERNEL_001 — engine-level runtime proof, Batch 1.
//
// The type-level cert (deep2_sovereign_kernel_cert_001) proves the three
// components behave. This one proves the FIVE Deep2Engine methods that were
// declared-but-undefined now exist, execute, and report measured state:
//
//   initializeAdvancedFeatures()      -> constructs residency + window + telemetry
//   enableResidencyTelemetry(bool)    -> owns / releases the telemetry object
//   printResidencyTelemetryReport()   -> emits measured counters
//   enableSlidingWindow(bool, size)   -> configures a real, clamped window
//
// It links InferenceEngine.lib, so a method that is still undefined would be a
// LINK ERROR (LNK2019), not a silent pass. That is the point: this cert cannot
// succeed against the pre-Batch-1 tree.
//
// No model is loaded: these methods are control-plane, and asserting they need
// a 668 MB model would test the loader, not the kernel. Every value printed is
// read back out of live engine state.
// ============================================================================
#include "Deep2Engine.h"
#include "ResidencyManager.hpp"
#include "RouterPrefetchTelemetry.hpp"
#include "SlidingWindowEngine.h"

#include <cstdio>
#include <limits>
#include <string>

using Deep2::Deep2Engine;

static int g_checks = 0, g_fails = 0;
static void check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) { ++g_fails; std::printf("  FAIL: %s\n", what); }
    else      { std::printf("  ok  : %s\n", what); }
}

int main() {
    std::printf("RAWRXD_DEEP2_SOVEREIGN_KERNEL_001 [engine]\n");
    std::printf("LINKED=InferenceEngine.lib (undefined methods would be LNK2019)\n\n");

    Deep2Engine engine;
    std::printf("  constructed: isInitialized=%d isModelLoaded=%d\n",
                engine.isInitialized() ? 1 : 0, engine.isModelLoaded() ? 1 : 0);

    // ---- 1. telemetry: absent before enable, owned after ----------------
    std::printf("\n== RouterPrefetchTelemetry ownership ==\n");
    check(engine.getResidencyTelemetry() == nullptr,
          "telemetry object is ABSENT before enableResidencyTelemetry");
    check(!engine.isResidencyTelemetryEnabled(), "telemetry reports disabled");

    engine.enableResidencyTelemetry(true);
    check(engine.isResidencyTelemetryEnabled(), "enableResidencyTelemetry(true) enables");
    check(engine.getResidencyTelemetry() != nullptr,
          "enableResidencyTelemetry(true) constructs the object");

    // Drive real observations through the engine's own object.
    auto* tel = engine.getResidencyTelemetry();
    tel->noteRouteDecision(3);
    tel->notePrefetchHit(512, 40);
    tel->notePrefetchMiss(1024, 400);
    tel->notePrefetchCompletion(true, 400);
    check(tel->counters().routeDecisions == 1, "route decision observed on live object");
    check(tel->counters().prefetchHits == 1, "hit observed on live object");
    check(tel->counters().prefetchMisses == 1, "miss observed on live object");

    engine.printResidencyTelemetryReport();

    engine.enableResidencyTelemetry(false);
    check(!engine.isResidencyTelemetryEnabled(), "disable clears the flag");
    check(engine.getResidencyTelemetry() == nullptr,
          "disable RELEASES the object (a stale one would still look live)");

    // ---- 2. sliding window: real config, real clamping ------------------
    std::printf("\n== SlidingWindowEngine via enableSlidingWindow ==\n");
    check(engine.activeSlidingWindowSize() == 0,
          "no sliding window before enableSlidingWindow");

    // A small window is requested on purpose: eviction through the ENGINE path
    // is what is under test here, and a 512 window would (correctly) evict
    // nothing for six tokens. Asserting "no eviction at 512" would be true and
    // would prove nothing.
    engine.enableSlidingWindow(true, 4);
    check(engine.isSlidingWindowActive(), "enableSlidingWindow(true) enables");
    const int w = engine.activeSlidingWindowSize();
    check(w == 4, "requested window 4 was accepted");
    std::printf("  MEASURED sliding_window_size=%d\n", w);

    // Exercise the window through the engine's own instance.
    auto* sw = engine.slidingWindow();
    check(sw != nullptr, "engine owns a sliding window instance");
    if (sw) {
        for (int i = 0; i < 6; ++i) sw->append(300 + i, static_cast<std::uint64_t>(i));
        check(sw->stats().tokensAppended == 6, "six tokens appended on the engine's window");
        check(sw->stats().tokensEvicted == 2, "engine window evicted down to its limit");
        check(sw->buffered() == 4, "engine window retained exactly the window size");
        std::size_t s = 0, e = 0;
        check(sw->querySpan(5, s, e) && s == 2 && e == 6,
              "engine window span at p=5 is [2,6)");
        std::printf("  MEASURED appended=%llu evicted=%llu buffered=%zu oldest=%llu\n",
                    (unsigned long long)sw->stats().tokensAppended,
                    (unsigned long long)sw->stats().tokensEvicted,
                    sw->buffered(),
                    (unsigned long long)sw->oldestPosition());
    }

    // Widening is a limit change, not a silent growth: a larger window must be
    // honoured as given.
    engine.enableSlidingWindow(true, 512);
    check(engine.activeSlidingWindowSize() == 512, "window 512 accepted after 4");

    engine.enableSlidingWindow(false);
    check(!engine.isSlidingWindowActive(), "disable clears the sliding window flag");

    // ---- 3. initializeAdvancedFeatures ----------------------------------
    std::printf("\n== initializeAdvancedFeatures ==\n");
    // No model is loaded, so there is no honest budget and no honest window.
    // The method must still run and must NOT invent geometry.
    const bool initOk = engine.initializeSovereignComponents();
    std::printf("  initializeAdvancedFeatures() -> %d\n", initOk ? 1 : 0);
    check(!initOk, "returns false with no model loaded (no geometry to budget from)");
    // The components ARE constructed -- that is the method's job. What must NOT
    // happen is a constructed object being reported as an ENABLED capability
    // with no model behind it. Constructed-but-disabled is the honest state.
    check(engine.getResidencyTelemetry() != nullptr,
          "telemetry object is constructed by initializeAdvancedFeatures");
    check(!engine.isResidencyTelemetryEnabled(),
          "constructed telemetry is NOT reported as enabled (no fabricated capability)");
    check(!engine.isSlidingWindowActive(),
          "no sliding window is claimed without a configured window");
    check(engine.residencyManager() != nullptr,
          "residency manager object exists even with no budget (it declines, "
          "it does not pretend)");
    check(engine.residencyManager()->budget() == 0,
          "residency budget is 0 without geometry -- not an invented number");

    // ---- 4. the sovereign stack is reachable from the public switch -----
    std::printf("\n== enableAllEnhancements reachability ==\n");
    engine.enableResidencyTelemetry(false);
    engine.enableSlidingWindow(false);
    check(engine.getResidencyTelemetry() == nullptr, "precondition: telemetry released");
    engine.enableAllEnhancements();
    check(engine.getResidencyTelemetry() != nullptr,
          "enableAllEnhancements now reaches enableResidencyTelemetry");
    check(engine.isResidencyTelemetryEnabled(),
          "enableAllEnhancements leaves telemetry enabled");
    std::printf("  MEASURED via_public_switch telemetry_enabled=%d sliding=%d\n",
                engine.isResidencyTelemetryEnabled() ? 1 : 0,
                engine.isSlidingWindowActive() ? 1 : 0);
    engine.enableResidencyTelemetry(false);
    engine.enableSlidingWindow(false);

    // ---- 5. Batch 2: NU packer -----------------------------------------
    std::printf("\n== Batch 2: NU fused packer ==\n");
    check(engine.getNUPackerStats().packCalls == 0,
          "packer stats are empty (not fabricated) before enableNUPacking");
    engine.enableNUPacking(true);
    check(engine.getNUPackerStats().packCalls == 0 &&
          engine.getNUPackerStats().elementsPacked == 0,
          "enabling the packer does NOT invent a pack count");

    // ---- 6. Batch 2: warmup scheduler ----------------------------------
    std::printf("\n== Batch 2: warmup scheduler ==\n");
    check(engine.getWarmupStats().observations == 0,
          "warmup stats are empty before enableWarmupScheduler");
    engine.enableWarmupScheduler(true);
    check(engine.getWarmupStats().observations == 0,
          "enabling the scheduler does NOT invent observations");

    // ---- 7. Batch 2: medusa --------------------------------------------
    std::printf("\n== Batch 2: medusa ==\n");
    check(engine.getMedusaStats().accepted == 0,
          "medusa stats are empty before enableMedusa");
    engine.enableMedusa(true);
    check(engine.getMedusaStats().accepted == 0,
          "enabling medusa does NOT invent accepted tokens");
    engine.enableMedusa(false);

    // ---- 8. Batch 2: elastic residency (real component) ----------------
    std::printf("\n== Batch 2: elastic residency ==\n");
    check(!engine.isElasticResidencyEnabled(), "elastic residency off initially");
    check(engine.getElasticResidencyManager() == nullptr,
          "no manager object before enableElasticResidency");
    engine.enableElasticResidency(true);
    check(engine.isElasticResidencyEnabled(), "enableElasticResidency enables");
    check(engine.getElasticResidencyManager() != nullptr,
          "enableElasticResidency constructs the real manager");
    // refreshElasticDynamicBudget must be a no-op without geometry rather than
    // enforcing a zero budget (which would evict everything and "succeed").
    engine.refreshElasticDynamicBudget();
    check(engine.getElasticResidencyManager() != nullptr,
          "refreshElasticDynamicBudget without geometry did not destroy the manager");
    engine.enableElasticResidency(false);
    check(!engine.isElasticResidencyEnabled(), "disable clears the flag");
    check(engine.getElasticResidencyManager() == nullptr, "disable releases the manager");

    // ---- 10. Batch 2: expert access + lookahead -------------------------
    std::printf("\n== Batch 2: expert access / lookahead prefetch ==\n");
    const auto before = engine.getExpertPredictorTelemetry();
    // No MoE model is loaded, so there are no expert caches. The call must still
    // be safe and must record the observation it actually made.
    engine.recordExpertAccessPublic(0, 3, 0.75f);
    const auto afterAccess = engine.getExpertPredictorTelemetry();
    check(afterAccess.observations == before.observations + 1,
          "recordExpertAccess recorded exactly one observation");
    check(afterAccess.liveRoutes == before.liveRoutes + 1,
          "recordExpertAccess recorded one live route");

    // With no model, expertsPerToken is 0, so prefetchNextExperts must decline
    // rather than guess a width.
    const auto beforePred = engine.getExpertPredictorTelemetry();
    engine.prefetchNextExpertsPublic(0);
    const auto afterPred = engine.getExpertPredictorTelemetry();
    check(afterPred.predictedQueries == beforePred.predictedQueries,
          "prefetchNextExperts declines without a real expert width");

    // Negative indices must be refused, not wrapped into huge unsigned values.
    const auto beforeNeg = engine.getExpertPredictorTelemetry();
    engine.recordExpertAccessPublic(-1, -1, 1.0f);
    engine.prefetchNextExpertsPublic(-5);
    check(engine.getExpertPredictorTelemetry().observations == beforeNeg.observations,
          "negative layer/expert ids are refused, not cast to huge ids");
    std::printf("  MEASURED expert observations=%llu live_routes=%llu "
                "predicted_queries=%llu\n",
                (unsigned long long)afterAccess.observations,
                (unsigned long long)afterAccess.liveRoutes,
                (unsigned long long)afterPred.predictedQueries);

    // ---- 11. Batch 3: sampler surface -----------------------------------
    std::printf("\n== Batch 3: sampler ==\n");
    // A freshly constructed engine has no sampler yet -- one is created during
    // initialize(). So the invariant under test is that a null install LEAVES
    // THE STATE UNCHANGED, not that a sampler happens to exist.
    const bool hadSamplerBefore = engine.hasSampler();
    engine.setSampler(nullptr);
    check(engine.hasSampler() == hadSamplerBefore,
          "null sampler is refused and leaves the sampler state unchanged");
    check(!engine.samplerIsEngineDefault(),
          "a refused install does not claim the sampler is engine-default");

    engine.setTemperature(0.5f);
    check(engine.samplingTemperature() == 0.5f, "setTemperature recorded 0.5");
    engine.setTopP(0.9f);
    check(engine.samplingTopP() == 0.9f, "setTopP recorded 0.9");
    engine.setSampling(0.25f, 0.8f);
    check(engine.samplingTemperature() == 0.25f, "setSampling set temperature");
    check(engine.samplingTopP() == 0.8f, "setSampling set topP");

    // Nonsense must be refused, not stored. NaN fails every comparison, so it is
    // rejected by the same guards.
    engine.setTemperature(-1.0f);
    check(engine.samplingTemperature() == 0.25f, "negative temperature refused");
    engine.setTopP(0.0f);
    check(engine.samplingTopP() == 0.8f, "topP of 0 refused");
    engine.setTopP(1.5f);
    check(engine.samplingTopP() == 0.8f, "topP > 1 refused");
    const float nan = std::numeric_limits<float>::quiet_NaN();
    engine.setTemperature(nan);
    check(engine.samplingTemperature() == 0.25f, "NaN temperature refused");
    engine.setTopP(nan);
    check(engine.samplingTopP() == 0.8f, "NaN topP refused");

    // ---- 12. Batch 3: threads / KV --------------------------------------
    std::printf("\n== Batch 3: threads and KV ==\n");
    engine.setNumThreads(0);
    check(engine.activeNumThreads() == 0, "0 threads means auto and is preserved");
    engine.setNumThreads(8);
    check(engine.activeNumThreads() == 8, "setNumThreads(8) took effect");
    engine.setNumThreads(999999);
    check(engine.activeNumThreads() == 8, "an absurd thread count is refused");

    const bool kv0 = engine.isKVCacheEnabled();
    engine.enableKVCache(!kv0);
    check(engine.isKVCacheEnabled() == !kv0, "enableKVCache toggled");
    engine.enableKVCache(kv0);
    check(engine.isKVCacheEnabled() == kv0, "enableKVCache restored");

    // ---- 13. Batch 3: extended tool-call limit --------------------------
    std::printf("\n== Batch 3: extended tool-call limit ==\n");
    check(engine.getExtendedToolCallLimit() == -1,
          "limit is -1 (not extended) before any call");
    const std::string msg = engine.extendToolCallLimit(64);
    check(engine.getExtendedToolCallLimit() == 64, "limit is now 64");
    check(msg.find("-1 -> 64") != std::string::npos,
          "the message reports the real previous -> new transition");
    check(!engine.extendToolCallLimit(0).empty(), "a refused extension still returns a reason");
    check(!engine.extendToolCallLimit(-5).empty(), "a negative extension returns a reason");
    check(engine.getExtendedToolCallLimit() == 64,
          "a refused extension did NOT change the limit");

    // ---- 14. Batch 3: weight tensor layer index -------------------------
    std::printf("\n== Batch 3: parseWeightLayerIndex ==\n");
    struct { const char* name; int expect; } cases[] = {
        {"blk.7.attn_q.weight", 7},
        {"blk.0.attn_k.weight", 0},
        {"block.12.ffn_gate.weight", 12},
        {"layers.3.ffn_up.weight", 3},
        {"layer_5.down.weight", 5},
        {"token_embd.weight", -1},
        {"output_norm.weight", -1},
        {"", -1},
        {"blk.7x.attn_q.weight", -1},   // not a component boundary
        {"blk..attn_q.weight", -1},    // no digits
    };
    for (const auto& c : cases) {
        const int got = engine.weightLayerIndexOf(c.name);
        char buf[128];
        std::snprintf(buf, sizeof buf, "parse(%s) == %d", c.name, c.expect);
        check(got == c.expect, buf);
    }

    // ---- 15. Batch 4: reverse analysis ----------------------------------
    std::printf("\n== Batch 4: reverse analysis ==\n");
    check(engine.getReverseIntegration() == nullptr, "no reverse object initially");
    check(!engine.isReverseAnalysisEnabled(), "reverse analysis off initially");
    check(engine.reverseAttachedCount() == 0, "zero attached devices initially");

    engine.enableReverseAnalysis(true);
    check(engine.isReverseAnalysisEnabled(), "enableReverseAnalysis enables");
    check(engine.getReverseIntegration() != nullptr,
          "enableReverseAnalysis constructs the REAL ReverseIntegration");
    check(engine.reverseAttachedCount() == 0,
          "a fresh integration has zero attached devices (not fabricated)");
    engine.disableReverseAnalysis();
    check(!engine.isReverseAnalysisEnabled(), "disable clears the flag");
    check(engine.getReverseIntegration() == nullptr,
          "disable RELEASES the object so stale device state cannot be inherited");

    // ---- 16. Batch 4: Vulkan GEMV probe (honest refusal) ----------------
    std::printf("\n== Batch 4: tryVulkanGEMV probe ==\n");
    // tryVulkanGEMV is NOT exercised here.
    //
    // WeightTensor is not nameable from this translation unit under either
    // Deep2::WeightTensor or Deep2Engine::WeightTensor, so the probe cannot be
    // called without fabricating a tensor -- which would test the fake, not the
    // probe. Its first statement is an unconditional guard on
    // !vulkanInitialized_, so on this CPU-only engine it can only return false;
    // that is argued from source and NOT claimed as runtime evidence here.
    // Coverage for tryVulkanGEMV in this receipt is therefore: COMPILED,
    // LINKED, SYMBOL_VERIFIED, NOT RUNTIME_EXERCISED.
    // ---- 17. Batch 4: kernel patch registry ------------------------------
    std::printf("\n== Batch 4: kernel patch registry ==\n");
    check(engine.kernelPatchCount() == 0, "registry starts empty");
    check(!engine.kernelPatchActive("kp0"), "unknown patch is not active");

    int fakeA = 0, fakeB = 0;
    const std::string idA = engine.registerKernelPatch("q_gemm", &fakeA, &fakeB, 1.5f);
    check(!idA.empty(), "a well-formed patch is recorded and returns a real id");
    check(idA.find("kp0") == 0, "first patch id is kp0");
    check(idA.find("RECORDED_NOT_APPLIED") != std::string::npos,
          "the returned id states the patch was NOT applied");
    check(engine.kernelPatchCount() == 1, "registry holds one record");
    check(engine.activeKernelPatchCount() == 0,
          "a recorded patch is not 'active' -- nothing was applied");

    // Refusals
    check(engine.registerKernelPatch("", &fakeA, &fakeB, 1.5f).empty(),
          "empty kernel name refused");
    check(engine.registerKernelPatch("q", nullptr, &fakeB, 1.5f).empty(),
          "null original refused");
    check(engine.registerKernelPatch("q", &fakeA, &fakeA, 1.5f).empty(),
          "a patch that changes nothing is refused");
    check(engine.registerKernelPatch("q", &fakeA, &fakeB, 0.0f).empty(),
          "non-positive speedup claim refused");
    check(engine.kernelPatchCount() == 1, "refusals did not grow the registry");

    // Rollback of a never-applied patch must NOT claim success.
    check(!engine.rollbackKernelPatch(idA),
          "rollback of a non-active patch reports failure (no false success)");
    check(!engine.rollbackKernelPatch("no_such_patch"),
          "rollback of an unknown id reports failure");
    check(!engine.rollbackKernelPatch(""), "rollback of an empty id reports failure");
    engine.printHotPatcherStatus();
    engine.emergencyRollbackAllPatches();
    check(engine.kernelPatchCount() == 1,
          "emergency rollback keeps the inventory (it is an audit record)");

    std::printf("\nCHECKS_RUN=%d\nCHECKS_FAIL=%d\n", g_checks, g_fails);
    if (g_fails == 0) { std::printf("VERDICT=PASS\n"); return 0; }
    std::printf("VERDICT=FAIL\n");
    return 1;
}
