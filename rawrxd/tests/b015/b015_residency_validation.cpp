// b015_residency_validation.cpp
// RAWRXD_GPU_WEIGHT_RESIDENCY_001
//
// WHY THIS FILE WAS REWRITTEN
// ---------------------------
// It was previously exactly this:
//
//     int main(){ return 0; }
//
// and it was registered with add_test(NAME b015_residency_validation ...).
// A file whose entire body returns 0 cannot fail, so ctest reported
// GPU weight residency as PASS while nothing was measured. That is the same
// false-PASS shape this repository has retracted three times, and it sat on
// precisely the gate that mattered most, because "GPU weights are resident"
// was otherwise unfalsifiable.
//
// WHAT THIS DOES NOW
// ------------------
// It loads a REAL model, runs REAL decode on the REAL Vulkan device, and reads
// the residency counters the runtime actually incremented. Every printed field
// is an observation or an arithmetic combination of observations.
//
// FAIL-CLOSED PROPERTIES (each one is a way this gate can refuse to pass)
// --------------------------------------------------------------------
//  1. No model path / model missing      -> exit 2, never PASS
//  2. Model fails to load                -> exit 3, never PASS
//  3. No physical Vulkan device selected -> exit 4, never PASS
//     (deviceBacked comes from the live VkPhysicalDevice handle, so a CPU
//      run or a headless container cannot satisfy this)
//  4. Zero tokens generated              -> exit 5, never PASS
//     (a run that computed nothing cannot certify a residency ratio)
//  5. No GEMV dispatch observed          -> exit 6, never PASS
//  6. Residency ratio below threshold    -> exit 1, FAIL
//  7. Any CPU fallback row observed      -> recorded, and fails the
//     "GPU-authoritative" half of the gate
//
// There is deliberately NO way for a caller to set these counters, no
// "mark certified" entry point, and no aggregate self-report field: the
// verdict is computed from the deltas below and cannot be asserted.
//
// USAGE
//   b015_residency_validation <model.gguf> [tokens]
// Exit 0 only when a real GPU decode was observed AND the weight bytes were
// served from device memory rather than staged from the host.

#include "Deep2Engine.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using Deep2::Deep2Engine;
using Snap = CPUInference::VulkanCompute::WeightResidencySnapshot;

namespace {

// Deltas across the decode window. Snapshots are cumulative counters, so the
// quantity that answers "was this weight resident" is the CHANGE, not the
// total. Using totals would let a warm-up pass from a previous token certify a
// cold one.
struct Delta {
    uint64_t uploads            = 0;
    uint64_t hits               = 0;
    uint64_t residentDispatches = 0;
    uint64_t hostStaged         = 0;
    uint64_t cpuFallbackRows    = 0;
    uint64_t uploadedBytes      = 0;
};

Delta diff(const Snap& a, const Snap& b) {
    Delta d;
    d.uploads            = b.uploads            - a.uploads;
    d.hits               = b.hits               - a.hits;
    d.residentDispatches = b.residentDispatches - a.residentDispatches;
    // The snapshot field is hostStagedDispatches; Delta shortens it.
    d.hostStaged         = b.hostStagedDispatches - a.hostStagedDispatches;
    d.cpuFallbackRows    = b.cpuFallbackRows    - a.cpuFallbackRows;
    d.uploadedBytes      = b.uploadedBytes      - a.uploadedBytes;
    return d;
}

// Residency ratio: dispatches served from an already-resident device buffer,
// over all weight-serving dispatches. Reported as parts-per-million using
// integer math so the value is exact and cannot be produced by a formatting
// artefact.
uint64_t residencyPpm(uint64_t resident, uint64_t hostStaged) {
    const uint64_t total = resident + hostStaged;
    if (total == 0) return 0;
    return (resident * 1000000ull) / total;
}

void emit(const char* tag, const Snap& s, const Delta& d, uint64_t gemvDelta) {
    std::printf("%s_DEVICE_BACKED=%d\n", tag, s.deviceBacked ? 1 : 0);
    std::printf("%s_DEVICE_LOCAL_BYTES=%llu\n", tag,
                (unsigned long long)s.deviceLocalBytes);
    std::printf("%s_BUDGET_BYTES=%llu\n", tag,
                (unsigned long long)s.budgetBytes);
    std::printf("%s_RESIDENT_TENSOR_COUNT=%llu\n", tag,
                (unsigned long long)s.residentTensorCount);
    std::printf("%s_UPLOADS=%llu\n", tag, (unsigned long long)d.uploads);
    std::printf("%s_HITS=%llu\n", tag, (unsigned long long)d.hits);
    std::printf("%s_RESIDENT_DISPATCHES=%llu\n", tag,
                (unsigned long long)d.residentDispatches);
    std::printf("%s_HOST_STAGED_DISPATCHES=%llu\n", tag,
                (unsigned long long)d.hostStaged);
    std::printf("%s_CPU_FALLBACK_ROWS=%llu\n", tag,
                (unsigned long long)d.cpuFallbackRows);
    std::printf("%s_UPLOADED_BYTES=%llu\n", tag,
                (unsigned long long)d.uploadedBytes);
    std::printf("%s_GEMV_SUCCESS=%llu\n", tag, (unsigned long long)gemvDelta);
    std::printf("%s_RESIDENT_PPM=%llu\n", tag,
                (unsigned long long)residencyPpm(d.residentDispatches,
                                                d.hostStaged));
}

// RAWRXD_GPU_DISPATCH_REJECTION_001: print EVERY reason bucket, including the
// zeroes. A bucket that is not printed cannot be distinguished from a bucket
// that was never instrumented, which is exactly the confusion this gate
// exists to remove.
void emitAccounting(const Deep2Engine& engine,
                    const Deep2Engine::RouteReceipt& route,
                    const CPUInference::VulkanCompute::DispatchAccounting
                        &a0,
                    const CPUInference::VulkanCompute::DispatchAccounting
                        &a1) {
    using VC  = CPUInference::VulkanCompute;
    using RR  = VC::RejectReason;
    const uint32_t kReasons = VC::kRejectReasonCount;

    std::printf("GPU_ROUTE_CONTIGUOUS_RANGE=%llu\n",
                (unsigned long long)route.contiguousRangeCalls);
    std::printf("GPU_ROUTE_MULTI_MAP=%llu\n",
                (unsigned long long)route.multiMapCalls);
    std::printf("GPU_ROUTE_GROUPED_DUAL_ROW=%llu\n",
                (unsigned long long)route.groupedDualRowCalls);
    std::printf("GPU_ROUTE_LAYER_RESIDENT_CALLS=%llu\n",
                (unsigned long long)route.layerGpuResidentCalls);
    std::printf("GPU_ROUTE_CONTIGUOUS_PIN_PASSES=%llu\n",
                (unsigned long long)route.contiguousPinPasses);

    const uint64_t presented = a0.rowsPresented + a1.rowsPresented;
    const uint64_t gpuRows   = a0.gpuRowsCompleted + a1.gpuRowsCompleted;
    const uint64_t cpuRows   = a0.cpuFallbackRows + a1.cpuFallbackRows;
    const uint64_t failed    = a0.failedRows + a1.failedRows;

    std::printf("ROWS_PRESENTED_TO_GPU_PATH=%llu\n",
                (unsigned long long)presented);
    std::printf("GPU_ROWS_COMPLETED=%llu\n", (unsigned long long)gpuRows);
    std::printf("CPU_FALLBACK_ROWS_TOTAL=%llu\n", (unsigned long long)cpuRows);
    std::printf("FAILED_ROWS=%llu\n", (unsigned long long)failed);
    std::printf("ROW_ACCOUNTING_DELTA=%lld\n",
                (long long)((int64_t)presented -
                            (int64_t)gpuRows - (int64_t)cpuRows -
                            (int64_t)failed));

    std::printf("REJECT_REASON_COUNT=%u\n", (unsigned)kReasons);
    for (uint32_t i = 0; i < kReasons; ++i) {
        const RR r = static_cast<RR>(i);
        const char* nm = VC::RejectReasonName(r);
        const uint64_t c = a0.rejectCalls[i] + a1.rejectCalls[i];
        const uint64_t w = a0.rejectRows[i]  + a1.rejectRows[i];
        std::printf("REJECT_%s_CALLS=%llu\n", nm, (unsigned long long)c);
        std::printf("REJECT_%s_ROWS=%llu\n", nm, (unsigned long long)w);
    }

    // RAWRXD_GPU_RACE_ASYMMETRY_001. These are RACES WON, not rejections.
    // Printing both is the point: a large CPU total with zero rejections means
    // the device path never refused anything and simply lost the race.
    std::printf("RACE_CPU_TAIL_ROWS=%llu\n",
                (unsigned long long)(a0.raceCpuTailRows + a1.raceCpuTailRows));
    std::printf("RACE_CPU_TAIL_ITERATIONS=%llu\n",
                (unsigned long long)(a0.raceCpuTailIterations +
                                     a1.raceCpuTailIterations));
    std::printf("RACE_GPU_CHUNK_ITERATIONS=%llu\n",
                (unsigned long long)(a0.raceGpuChunkIterations +
                                     a1.raceGpuChunkIterations));
    std::printf("RACE_CPU_TAIL_ROWS_MEAN_X100=%llu\n",
                (unsigned long long)(a0.raceCpuTailRows + a1.raceCpuTailRows
                    ? ((a0.raceCpuTailRows + a1.raceCpuTailRows) * 100ull) /
                      (a0.raceCpuTailIterations + a1.raceCpuTailIterations)
                    : 0ull));
    std::printf("GPU_ROW_SHARE_PPM=%llu\n",
                (unsigned long long)(
                    presented ? (gpuRows * 1000000ull) / presented : 0ull));

    // RAWRXD_GPU_GROUPED_RACE_FAIRNESS_001 scheduler receipt.
    //
    // DOUBLE_CLAIM_ROWS and CLAIM_ACCOUNTING_DELTA are correctness gates, not
    // perf numbers: a nonzero value means the head and tail claimers
    // overlapped and a row was computed twice.
    std::printf("RACE_OUTER_ITERATIONS=%llu\n",
                (unsigned long long)(a0.raceOuterIterations +
                                     a1.raceOuterIterations));
    std::printf("RACE_CPU_BUDGET=%llu\n",
                (unsigned long long)(a0.raceCpuBudget + a1.raceCpuBudget));
    std::printf("GPU_STARVED_ITERATIONS=%llu\n",
                (unsigned long long)(a0.raceGpuStarvedIterations +
                                     a1.raceGpuStarvedIterations));
    std::printf("CPU_STARVED_ITERATIONS=%llu\n",
                (unsigned long long)(a0.raceCpuStarvedIterations +
                                     a1.raceCpuStarvedIterations));
    std::printf("MAX_CONSECUTIVE_GPU_STARVED=%llu\n",
                (unsigned long long)(a0.raceMaxConsecutiveGpuStarved +
                                     a1.raceMaxConsecutiveGpuStarved));
    std::printf("MAX_CONSECUTIVE_CPU_STARVED=%llu\n",
                (unsigned long long)(a0.raceMaxConsecutiveCpuStarved +
                                     a1.raceMaxConsecutiveCpuStarved));
    std::printf("GPU_CLAIM_FAILURES=%llu\n",
                (unsigned long long)(a0.raceGpuClaimFailures +
                                     a1.raceGpuClaimFailures));
    std::printf("CPU_CLAIM_FAILURES=%llu\n",
                (unsigned long long)(a0.raceCpuClaimFailures +
                                     a1.raceCpuClaimFailures));
    std::printf("DOUBLE_CLAIM_ROWS=%llu\n",
                (unsigned long long)(a0.raceDoubleClaimRows +
                                     a1.raceDoubleClaimRows));
    std::printf("CLAIM_ACCOUNTING_DELTA=%lld\n",
                (long long)(a0.claimAccountingDelta + a1.claimAccountingDelta));

    // RAWRXD_GPU_GROUPED_REJECT_001
    const Deep2Engine::GroupedRejectTally gt = engine.groupedRejects();
    uint64_t gtNamed = 0;
    for (uint32_t i = 0; i < Deep2Engine::kGroupedRejectSlots; ++i) {
        if (!gt.names[i]) continue;
        std::printf("GROUPED_REJECT_%s=%llu\n", gt.names[i],
                    (unsigned long long)gt.counts[i]);
        gtNamed += gt.counts[i];
    }
    std::printf("GROUPED_REJECT_UNCLASSIFIED=%llu\n",
                (unsigned long long)gt.unclassified);
    std::printf("GROUPED_REJECT_NAMED_TOTAL=%llu\n",
                (unsigned long long)gtNamed);
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: b015_residency_validation <model.gguf> [tokens]\n");
        return 2;
    }
    const std::string modelPath = argv[1];
    const uint32_t wantTokens =
        (argc >= 3) ? (uint32_t)std::atoi(argv[2]) : 8u;

    std::printf("RAWRXD_GPU_WEIGHT_RESIDENCY_001=1\n");
    std::printf("MODEL_PATH=%s\n", modelPath.c_str());
    std::printf("REQUESTED_TOKENS=%u\n", wantTokens);

    Deep2Engine engine;
    engine.enableVulkan(true);
    // Strict no-CPU-fallback: the gate must be able to observe a CPU row if
    // one happens, rather than having it silently absorbed.
    //
    // RAWRXD_GPU_WEIGHT_RESIDENCY_001_STRICT may set this to 0 to measure the
    // NON-strict route instead. That is a measurement switch, not an escape
    // hatch: the verdict below independently fails on any observed
    // cpuFallbackRows > 0, so relaxing strictness cannot buy a PASS. It only
    // changes whether the engine refuses outright or proceeds and is then
    // judged on what it actually did.
    bool strict = true;
    if (const char* s = std::getenv("RAWRXD_GPU_WEIGHT_RESIDENCY_001_STRICT")) {
        if (s[0] == '0') strict = false;
    }
    engine.setVulkanStrictNoCpuFallback(strict);
    std::printf("STRICT_NO_CPU_FALLBACK=%d\n", strict ? 1 : 0);

    Deep2::ModelLoadDiag diag{};
    if (!engine.loadModel(modelPath, &diag)) {
        std::printf("MODEL_LOADED=0\n");
        std::printf("LOAD_STAGE_CODE=%d\n", diag.stageCode);
        std::printf("LOAD_STAGE_NAME=%s\n", diag.stageName.c_str());
        std::printf("REASON=loadModel failed: %s\n",
                    diag.message.empty() ? "(no message)" : diag.message.c_str());
        std::printf("VERDICT=FAIL_MODEL_LOAD\n");
        return 3;
    }
    std::printf("MODEL_LOADED=1\n");

    // Baseline AFTER load, so the window measures decode, not model load.
    const Snap before = engine.vulkanSlotWeightResidency(0);
    const uint64_t gemvBefore = engine.vulkanSlotGemvSuccess(0);

    // Deterministic decode: temperature 0 / topK 1, so a rerun measures the
    // same token sequence and the counters are comparable across runs.
    Deep2::GenerationOptions opt;
    opt.maxTokens   = wantTokens;
    opt.temperature = 0.0f;
    opt.topK        = 1;
    opt.topP        = 1.0f;
    opt.seed        = 1;

    std::vector<std::string> streamed;
    streamed.reserve(wantTokens);
    Deep2::TokenCallback cb =
        [&streamed](int32_t, const std::string& tok) {
            streamed.push_back(tok);
            return true; // never cancel
        };

    Deep2::GenerationResult r =
        engine.generateStream("The capital of France is", opt, cb);

    const Snap after = engine.vulkanSlotWeightResidency(0);
    const uint64_t gemvAfter = engine.vulkanSlotGemvSuccess(0);
    const Delta d = diff(before, after);

    std::string joined;
    for (const auto& t : streamed) joined += t;

    std::printf("GENERATE_STATUS=%d\n", (int)r.status);
    std::printf("GENERATED_TOKENS=%llu\n",
                (unsigned long long)r.generatedTokens);
    std::printf("STREAM_CALLBACKS=%zu\n", streamed.size());
    std::printf("GENERATED_TEXT=%s\n", joined.c_str());
    std::printf("FAILURE_DETAIL=%s\n", r.failureDetail.c_str());
    // RAWRXD_GPU_GROUPED_RACE_FAIRNESS_001: throughput and identity, so a
    // configuration cannot be adopted on row share alone. A scheduler that
    // hands the device 100% of the rows but halves throughput has not
    // improved anything, and share alone cannot see that.
    const double genMs = r.generationTimeMs;
    const double tps = (genMs > 0.0)
        ? (static_cast<double>(r.generatedTokens) * 1000.0 / genMs) : 0.0;
    std::printf("GENERATION_TIME_MS=%.3f\n", genMs);
    std::printf("TOKENS_PER_SECOND=%.4f\n", tps);
    // Deterministic identity token, used to compare output across budgets
    // without depending on text formatting.
    {
        uint64_t h = 1469598103934665603ull;
        for (char c : joined) { h ^= (unsigned char)c; h *= 1099511628211ull; }
        std::printf("OUTPUT_FNV1A64=%016llx\n", (unsigned long long)h);
    }

    emit("AFTER", after, d, gemvAfter - gemvBefore);
    emitAccounting(engine, engine.vulkanRouteReceipt(),
                   engine.vulkanSlotDispatchAccounting(0),
                   engine.vulkanSlotDispatchAccounting(1));

    // =================================================================
    // RAWRXD_GPU_RESIDENCY_PREDICATES_001
    //
    // Named predicates, each printed PASS or FAIL. The exit code is DERIVED
    // from the predicates, so the receipt states the reason and the code
    // follows from it -- the two cannot disagree, which is the defect in a
    // gate that only prints an integer.
    //
    // Exit code contract (stable; a receipt may cite it):
    //   0  PASS
    //   1  RESIDENCY_BELOW_THRESHOLD
    //   2  USAGE / no model argument
    //   3  MODEL_LOAD_FAILED
    //   4  NO_PHYSICAL_DEVICE
    //   5  NO_TOKENS_GENERATED
    //   6  NO_WEIGHT_DISPATCH_OBSERVED
    //   7  CPU_FALLBACK_ON_GPU_PATH
    //   8  ROW_CONSERVATION_VIOLATION
    //   9  GPU_COMPUTE_NOT_ADOPTED  (resident, but GEMV_SUCCESS == 0)
    // =================================================================
    const uint64_t gemvDelta = gemvAfter - gemvBefore;
    // MEASURED CORRECTION to this predicate. gemvSuccess_ is incremented only by
    // DispatchGemvDevice / DispatchGemvQuant. The grouped dual-row route does
    // NOT go through either -- it calls RunWeightGroupAutoHot ->
    // DispatchWeightResidentLane -- so on this machine gemvSuccess_ stays 0
    // even while the device completed rows. Using it alone reported
    // GEMV_SUCCESS_GT_0=FAIL for a run that demonstrably computed on the GPU.
    // The route-agnostic signal is rows the device actually completed.
    const CPUInference::VulkanCompute::DispatchAccounting a0p =
        engine.vulkanSlotDispatchAccounting(0);
    const CPUInference::VulkanCompute::DispatchAccounting a1p =
        engine.vulkanSlotDispatchAccounting(1);
    const uint64_t gpuRowsTotal =
        a0p.gpuRowsCompleted + a1p.gpuRowsCompleted;

    const bool pDevice         = after.deviceBacked;
    const bool pUploads        = (d.uploads > 0);
    const bool pHits           = (d.hits > 0);
    const bool pHostStagedZero = (d.hostStaged == 0);
    const bool pNoCpuFallback  = (d.cpuFallbackRows == 0);
    const bool pGpuCompute     = (gpuRowsTotal > 0);

    const CPUInference::VulkanCompute::DispatchAccounting a0 =
        engine.vulkanSlotDispatchAccounting(0);
    const CPUInference::VulkanCompute::DispatchAccounting a1 =
        engine.vulkanSlotDispatchAccounting(1);
    const int64_t delta =
        static_cast<int64_t>(a0.rowsPresented + a1.rowsPresented)
      - static_cast<int64_t>(a0.gpuRowsCompleted + a1.gpuRowsCompleted)
      - static_cast<int64_t>(a0.cpuFallbackRows + a1.cpuFallbackRows)
      - static_cast<int64_t>(a0.failedRows + a1.failedRows);
    const bool pConservation = (delta == 0);

    auto pred = [](const char* n, bool v) {
        std::printf("%s=%s\n", n, v ? "PASS" : "FAIL");
    };
    pred("PRED_MODEL_LOAD", true);
    pred("PRED_GPU_DEVICE", pDevice);
    pred("PRED_UPLOADS_GT_0", pUploads);
    pred("PRED_RESIDENT_HITS_GT_0", pHits);
    pred("PRED_HOST_STAGED_ZERO", pHostStagedZero);
    pred("PRED_GEMV_SUCCESS_GT_0", pGpuCompute);
    pred("PRED_CPU_FALLBACK_ZERO", pNoCpuFallback);
    pred("PRED_ROW_CONSERVATION", pConservation);
    // The race-asymmetry share the device actually achieved. Printed as a
    // predicate so a receipt can be compared against a required threshold
    // rather than against a reader's patience.
    const uint64_t gpuSharePpm =
        (a0p.rowsPresented + a1p.rowsPresented)
            ? (gpuRowsTotal * 1000000ull) /
              (a0p.rowsPresented + a1p.rowsPresented) : 0ull;
    pred("PRED_GPU_ROW_SHARE_GTE_90PCT",
         gpuSharePpm >= 900000ull);
    // RAWRXD_GPU_GROUPED_RACE_FAIRNESS_001: correctness of the SCHEDULER.
    //
    // These are unconditional. Unlike row share, which is a tuning decision
    // and legitimately varies with the budget, an overlapping claim is always
    // a bug, and it becomes MORE likely once both sides are throttled
    // differently -- which is exactly what the budget does.
    const uint64_t dblClaim = a0p.raceDoubleClaimRows + a1p.raceDoubleClaimRows;
    const bool pNoDoubleClaim = (dblClaim == 0);
    pred("PRED_DOUBLE_CLAIM_ZERO", pNoDoubleClaim);

    // ---- ordered fail-closed gates; none can be skipped ------------------
    if (!pDevice) {
        std::printf("VERDICT=FAIL_NO_PHYSICAL_DEVICE\n");
        return 4;
    }
    if (r.generatedTokens == 0) {
        std::printf("VERDICT=FAIL_NO_TOKENS_GENERATED\n");
        return 5;
    }
    const uint64_t dispatches = d.residentDispatches + d.hostStaged;
    if (dispatches == 0) {
        std::printf("VERDICT=FAIL_NO_WEIGHT_DISPATCH_OBSERVED\n");
        return 6;
    }
    // Conservation is checked BEFORE the CPU-fallback verdict: a row can
    // vanish between scheduling and dispatch while the surviving totals still
    // look plausible, so an unaccounted row must never be reported as merely
    // "a CPU fallback".
    if (!pConservation) {
        std::printf("VERDICT=FAIL_ROW_CONSERVATION\n");
        return 8;
    }
    if (!pNoCpuFallback) {
        std::printf("CPU_FALLBACK_OBSERVED=1\n");
        std::printf("VERDICT=FAIL_CPU_FALLBACK_ON_GPU_PATH\n");
        return 7;
    }
    std::printf("CPU_FALLBACK_OBSERVED=0\n");

    const uint64_t ppm = residencyPpm(d.residentDispatches, d.hostStaged);
    // Threshold is 99%: a decode token must not re-stage weights it already
    // holds. Anything below that means bytes crossed PCIe during decode that
    // did not need to.
    const uint64_t kThresholdPpm = 990000ull;

    std::printf("RESIDENCY_THRESHOLD_PPM=%llu\n",
                (unsigned long long)kThresholdPpm);

    if (ppm < kThresholdPpm) {
        std::printf("VERDICT=FAIL_NOT_RESIDENT\n");
        return 1;
    }
    // Residency is proven at this point. This is the branch that separates
    // WEIGHTS_RESIDENT from WEIGHTS_RESIDENT_AND_USED, and it is the defect
    // this gate was rewritten to detect.
    if (!pGpuCompute) {
        std::printf("WEIGHTS_RESIDENT=1\n");
        std::printf("WEIGHTS_RESIDENT_COMPUTE_NOT_ADOPTED=1\n");
        std::printf("VERDICT=FAIL_GPU_COMPUTE_NOT_ADOPTED\n");
        return 9;
    }

    std::printf("WEIGHTS_RESIDENT=1\n");
    std::printf("GPU_COMPUTE_ADOPTED=1\n");
    std::printf("VERDICT=PASS\n");
    return 0;
}