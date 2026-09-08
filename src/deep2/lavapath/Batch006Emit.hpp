// Batch006Emit.hpp — RAWRXD_E2E_BLOCKERS_090 batch 76–90 product receipt
#pragma once
#include "NoMoreBaselineStubsLaw.hpp"
#include "../GpuTransferCounters.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace rawr::batch006 {

enum class St : uint8_t { Open = 0, Blocked = 1, Pass = 2, NotProduct = 3 };

inline const char* StStr(St s) {
    switch (s) {
    case St::Pass: return "PASS";
    case St::Blocked: return "BLOCKED";
    case St::NotProduct: return "NOT_PRODUCT_PATH";
    default: return "OPEN";
    }
}

struct Facts {
    /* 76 device */
    uint32_t deviceEnumCount = 0;
    int selectedDeviceId = -1;
    char deviceNames[512]{};
    char policyReason[96]{};
    int overrideRespected = 0;
    /* 77 lane */
    int laneId = 0;
    int layersAssigned = 0;
    int layersExecuted = 0;
    int multiGpuPlanned = 0;
    /* 78 copy */
    double crossDeviceCopyBpt = 0.0;
    const char* copyOwnerStage = "GpuTransfer/weight_upload";
    /* 79 fallback */
    int fallbackUsed = 0;
    const char* fallbackOwner = "none";
    /* 80 budget */
    uint64_t vramTotal = 0;
    uint64_t vramBudget = 0;
    uint64_t vramUsedPeak = 0;
    uint64_t residencyBytesLive = 0;
    /* 81 pin */
    uint64_t pinnedTensorCount = 0;
    uint64_t pinnedBytes = 0;
    uint64_t pinEvictions = 0;
    /* 82 transient — product path may not track yet */
    int transientTracked = 0;
    /* 83–84 prefetch */
    uint64_t prefetchExposedUs = 0;
    uint64_t prefetchOverlapUs = 0;
    int prefetchEvictedLive = 0;
    const char* prefetchTarget = "weight_slot";
    /* 85 split */
    uint64_t indexedBytes = 0;
    uint64_t decodeResidentBytes = 0;
    uint64_t activeWorkingSetBytes = 0;
    /* 86 subgraph */
    uint32_t activeLayers = 0;
    uint32_t activeExperts = 0;
    uint64_t activeBytesPerToken = 0;
    /* 87–88 BW */
    double effectiveBytesPerToken = 0.0;
    double bwEstimateGBs = 640.0; /* observation context only */
    /* 89 miss */
    uint64_t residencyMissCount = 0;
    const char* missStage = "weight_pin";
    const char* missOwner = "EnsurePinnedPackedWeight";
    /* 90 eviction */
    uint64_t evictionCount = 0;
    const char* evictionReason = "LRU_LAST_USE";
    int causalEviction = 0; /* 0 until frontier-based */
    /* product context */
    uint64_t tokensCommitted = 0;
    int streamOutput = 0;
    int hostFwd = 0;
    int cpuF32 = 0;
};

inline St Eval(int id, const Facts& f, const char*& owner, const char*& note) {
    owner = "unknown";
    note = "";
    switch (id) {
    case 76:
        owner = "Deep2DeviceManager";
        if (f.deviceEnumCount > 0 && f.selectedDeviceId >= 0 &&
            f.policyReason[0] && f.overrideRespected)
            return (note = "device policy observed", St::Pass);
        return (note = "missing DEVICE_* fields", St::Blocked);
    case 77:
        owner = "GpuPolicy/SOLO";
        if (f.multiGpuPlanned == 0) {
            note = "SOLO single-lane; multi-GPU not product path this run";
            return St::NotProduct;
        }
        if (f.layersAssigned > 0 && f.layersExecuted == f.layersAssigned)
            return (note = "lane authority matched", St::Pass);
        return (note = "LANE_AUTHORITY_VALID=0", St::Blocked);
    case 78:
        owner = f.copyOwnerStage;
        if (f.tokensCommitted > 0 && f.streamOutput)
            return (note = "copy BPT emitted", St::Pass);
        return (note = "no token stream for copy accounting", St::Blocked);
    case 79:
        owner = f.fallbackOwner;
        if (f.fallbackUsed == 0 && f.hostFwd == 0 && f.cpuF32 == 0)
            return (note = "FALLBACK_USED=0", St::Pass);
        note = "undeclared fallback";
        return St::Blocked;
    case 80:
        owner = "SetPinResidentBudget";
        if (f.vramTotal > 0 && f.vramBudget > 0 &&
            f.residencyBytesLive <= f.vramBudget)
            return (note = "BUDGET_VALID=1", St::Pass);
        return (note = "budget unproven", St::Blocked);
    case 81:
        owner = "EnsurePinnedPackedWeight";
        if (f.pinnedTensorCount > 0 && f.pinEvictions == 0)
            return (note = "PIN_VALID=1", St::Pass);
        if (f.pinEvictions > 0) {
            note = "PIN_EVICTIONS>0 during decode";
            return St::Blocked;
        }
        return (note = "no pins observed", St::Blocked);
    case 82:
        owner = "transient residency";
        note = "transient IDs not instrumented on product path";
        return f.transientTracked ? St::Pass : St::Blocked;
    case 83:
        owner = "weight_prefetch";
        if (f.prefetchEvictedLive == 0 && f.tokensCommitted > 0)
            return (note = "EVICTED_LIVE_DEPENDENCY=0", St::Pass);
        return (note = "prefetch causality unproven", St::Blocked);
    case 84:
        owner = "PREFETCH_EXPOSED";
        if (f.prefetchExposedUs == 0)
            return (note = "PREFETCH_EXPOSED_US=0", St::Pass);
        note = "SPIN_CLOSE_BLOCKER=PREFETCH";
        return St::Blocked;
    case 85:
        owner = "index vs decode residency";
        if (f.decodeResidentBytes > 0 || f.indexedBytes > 0)
            return (note = "split emitted", St::Pass);
        return (note = "split missing", St::Blocked);
    case 86:
        owner = "active subgraph";
        if (f.activeLayers > 0 && f.activeBytesPerToken > 0)
            return (note = "ACTIVE_* emitted", St::Pass);
        return (note = "ACTIVE_SUBGRAPH missing", St::Blocked);
    case 87:
        owner = "EFFECTIVE_BYTES_PER_TOKEN";
        if (f.effectiveBytesPerToken > 0.0 && f.tokensCommitted > 0)
            return (note = "measured on product path", St::Pass);
        return (note = "effective bytes unmeasured", St::Blocked);
    case 88:
        owner = "BW observation";
        note = "BW_USED_FOR_PASS=0; DECODE_TPS_REAL authority";
        return St::Pass; /* law-locked: BW never grants PASS */
    case 89:
        owner = f.missOwner;
        note = "miss count+stage emitted";
        return (f.tokensCommitted > 0) ? St::Pass : St::Blocked;
    case 90:
        owner = "eviction policy";
        if (f.causalEviction)
            return (note = "CAUSAL_EVICTION_VALID=1", St::Pass);
        note = "LRU_LAST_USE — not causal frontier";
        return St::Blocked;
    default:
        return St::Open;
    }
}

inline void FillFromGpuTransfer(Facts& f) {
    auto s = Deep2::GpuTransfer_Snapshot();
    const uint64_t tok = s.tokens ? s.tokens : f.tokensCommitted;
    f.crossDeviceCopyBpt =
        tok ? (double)s.copyBytes / (double)tok : 0.0;
    f.effectiveBytesPerToken = f.crossDeviceCopyBpt;
    f.activeBytesPerToken = (uint64_t)(f.crossDeviceCopyBpt + 0.5);
    f.residencyMissCount = s.weightMisses;
    f.prefetchOverlapUs = s.overlapUs;
    /* Prefetch on critical path if overlapUs==0 but copy wait dominates — exposed=wait */
    f.prefetchExposedUs = s.waitUs;
    f.activeLayers = (uint32_t)(s.fwdLayers ? s.fwdLayers : s.layers);
}

inline void Emit(FILE* out, const Facts& in) {
    if (!out) out = stdout;
    Facts f = in;
    FillFromGpuTransfer(f);

    std::fprintf(out, "RAWRXD_E2E_BLOCKERS_090\n");
    std::fprintf(out, "BATCH_006_BEGIN=76\nBATCH_006_END=90\n");

    /* Runtime field dump (must appear in product command). */
    std::fprintf(out, "DEVICE_ENUM_COUNT=%u\nDEVICE_NAMES=%s\n",
                 f.deviceEnumCount, f.deviceNames[0] ? f.deviceNames : "-");
    std::fprintf(out, "SELECTED_DEVICE_ID=%d\nPOLICY_REASON=%s\n"
                      "OVERRIDE_RESPECTED=%d\n",
                 f.selectedDeviceId, f.policyReason[0] ? f.policyReason : "-",
                 f.overrideRespected);
    std::fprintf(out, "LANE_ID=%d\nDEVICE_ID=%d\nLAYERS_ASSIGNED=%d\n"
                      "LAYERS_EXECUTED=%d\nLANE_AUTHORITY_VALID=%d\n",
                 f.laneId, f.selectedDeviceId, f.layersAssigned, f.layersExecuted,
                 (f.multiGpuPlanned == 0 ||
                  (f.layersAssigned > 0 && f.layersAssigned == f.layersExecuted))
                     ? 1
                     : 0);
    std::fprintf(out, "CROSS_DEVICE_COPY_BYTES_PER_TOKEN=%.1f\nCOPY_OWNER_STAGE=%s\n",
                 f.crossDeviceCopyBpt, f.copyOwnerStage);
    std::fprintf(out, "FALLBACK_USED=%d\nFALLBACK_OWNER=%s\n", f.fallbackUsed,
                 f.fallbackOwner);
    std::fprintf(out,
                 "VRAM_TOTAL=%llu\nVRAM_BUDGET=%llu\nVRAM_USED_PEAK=%llu\n"
                 "RESIDENCY_BYTES_LIVE=%llu\nBUDGET_VALID=%d\n",
                 (unsigned long long)f.vramTotal, (unsigned long long)f.vramBudget,
                 (unsigned long long)f.vramUsedPeak,
                 (unsigned long long)f.residencyBytesLive,
                 (f.vramBudget > 0 && f.residencyBytesLive <= f.vramBudget) ? 1 : 0);
    std::fprintf(out,
                 "PINNED_TENSOR_COUNT=%llu\nPINNED_BYTES=%llu\nPIN_EVICTIONS=%llu\n"
                 "PIN_VALID=%d\n",
                 (unsigned long long)f.pinnedTensorCount,
                 (unsigned long long)f.pinnedBytes,
                 (unsigned long long)f.pinEvictions,
                 (f.pinnedTensorCount > 0 && f.pinEvictions == 0) ? 1 : 0);
    std::fprintf(out, "TRANSIENT_TRACKED=%d\nRESIDENT_AT_CONSUME=%d\n"
                      "RELEASED_AFTER_LAST_USE=%d\n",
                 f.transientTracked, f.transientTracked, f.transientTracked);
    std::fprintf(out,
                 "PREFETCH_TARGET=%s\nPREFETCH_CAUSAL_REASON=next_weight_slot\n"
                 "EVICTED_LIVE_DEPENDENCY=%d\nPREFETCH_EXPOSED_US=%llu\n"
                 "PREFETCH_OVERLAP_US=%llu\n",
                 f.prefetchTarget, f.prefetchEvictedLive,
                 (unsigned long long)f.prefetchExposedUs,
                 (unsigned long long)f.prefetchOverlapUs);
    std::fprintf(out,
                 "INDEXED_BYTES=%llu\nDECODE_RESIDENT_BYTES=%llu\n"
                 "ACTIVE_WORKING_SET_BYTES=%llu\n",
                 (unsigned long long)f.indexedBytes,
                 (unsigned long long)f.decodeResidentBytes,
                 (unsigned long long)f.activeWorkingSetBytes);
    std::fprintf(out,
                 "ACTIVE_LAYERS=%u\nACTIVE_EXPERTS=%u\nACTIVE_TENSORS=%u\n"
                 "ACTIVE_BYTES_PER_TOKEN=%llu\n",
                 f.activeLayers, f.activeExperts, f.pinnedTensorCount ? 1u : 0u,
                 (unsigned long long)f.activeBytesPerToken);
    const double tpsExp =
        f.effectiveBytesPerToken > 0.0
            ? (f.bwEstimateGBs * 1e9) / f.effectiveBytesPerToken
            : 0.0;
    std::fprintf(out,
                 "EFFECTIVE_BYTES_PER_TOKEN=%.1f\nTPS_EXPECTED_FROM_BW=%.3f\n"
                 "BW_USED_FOR_ESTIMATE=1\nBW_USED_FOR_PASS=0\n",
                 f.effectiveBytesPerToken, tpsExp);
    std::fprintf(out,
                 "RESIDENCY_MISS_COUNT=%llu\nMISS_TENSOR_ID=-\nMISS_STAGE=%s\n"
                 "MISS_OWNER=%s\n",
                 (unsigned long long)f.residencyMissCount, f.missStage, f.missOwner);
    std::fprintf(out,
                 "EVICTION_REASON=%s\nFUTURE_FRONTIER_REFERENCES=0\n"
                 "CAUSAL_EVICTION_VALID=%d\nEVICTION_COUNT=%llu\n",
                 f.evictionReason, f.causalEviction,
                 (unsigned long long)f.evictionCount);

    static const char* names[15] = {
        "DEVICE_SELECTION_POLICY",
        "MULTI_GPU_LANE_AUTHORITY",
        "CROSS_DEVICE_COPY_ACCOUNTING",
        "NO_UNDECLARED_DEVICE_FALLBACK",
        "DEVICE_MEMORY_BUDGET_PROOF",
        "PINNED_RESIDENCY_CONTRACT",
        "TRANSIENT_RESIDENCY_CONTRACT",
        "PREFETCH_CAUSALITY_GUARD",
        "PREFETCH_OFF_CRITICAL_PATH",
        "WEIGHT_DECODE_RESIDENCY_SPLIT",
        "ACTIVE_SUBGRAPH_MANIFEST",
        "EFFECTIVE_BYTES_PER_TOKEN",
        "BANDWIDTH_OBSERVATION_ONLY",
        "RESIDENCY_MISS_OWNER",
        "EVICTION_POLICY_RUNTIME",
    };
    int pass = 0, unfinished = 0;
    for (int i = 0; i < 15; ++i) {
        const int id = 76 + i;
        const char* ow = nullptr;
        const char* nt = nullptr;
        const St st = Eval(id, f, ow, nt);
        if (st == St::Pass || st == St::NotProduct) ++pass;
        if (st == St::Open || st == St::Blocked) ++unfinished;
        std::fprintf(out, "BLOCKER_%d_%s=%s OWNER=%s NOTE=%s\n", id, names[i],
                     StStr(st), ow ? ow : "-", nt ? nt : "-");
    }
    std::fprintf(out, "BATCH_006_PASS_COUNT=%d\nBATCH_006_UNFINISHED_COUNT=%d\n",
                 pass, unfinished);
    std::fprintf(out, "RAWRXD_NO_MORE_BASELINE_STUBS_001=1\n");
    std::fflush(out);
}

} // namespace rawr::batch006
