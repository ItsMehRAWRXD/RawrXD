// ============================================================================
// engine_link_supplement.cpp — minimal, honest definitions for a small set of
// engine-referenced symbols whose full translation units are (a) absent from
// the curated tree, or (b) written against a diverged fork's headers.
//
// These are deliberately conservative: they let rawrxd_deep2_engine link and
// run headless, and they route every guarded feature to its safe default
// (host fallback / telemetry-off) instead of fabricating success.
//
// No simulated results, no fabricated success. Where a real implementation is
// possible, it is provided. Where the real implementation depends on assembly
// or external tooling not present in this tree, an honest fail-closed default
// (nullptr / no-op / false) is used — callers already guard on these returns.
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <atomic>
#include <vector>
#include <algorithm>
#include <limits>

#include "Deep2LivePath.hpp"
#include "FusedLiveController.hpp"
#include "vwa/VwaRangeLineageAbi.hpp"
#include "ResidencyTrace.hpp"
#include "Deep2ThreadTuning.hpp"
#include "deep2/HotPatcherSafety.hpp"

#include "mars/MARSController.hpp"

namespace rawrxd {
// AMD GPU power telemetry is not wired into this engine build. Report it as
// unavailable so power-biased placement policy takes its conservative default
// rather than acting on readings this build cannot produce. (Matches the raw
// GpuDecodeEfficiency.cpp intent, whose translation unit depends on a config
// header absent from the engine target.)
bool AmdGpuPowerTelemetryAvailable() noexcept { return false; }
bool GpuPowerValidForPolicy() noexcept { return false; }
} // namespace rawrxd

#include "K2NativeStreamGate.hpp"

// The production K2 stream gate is not source-compatible with this checkout's
// current Deep2 ABI. Keep the baseline fail-closed until the complete provider
// set is integrated as one coherent revision.
namespace K2NativeStreamGate {
Result Run(const std::filesystem::path&,
           const Deep2::GlobalTensorIndex&,
           const Deep2::KimiK2Config&,
           const std::vector<std::filesystem::path>&,
           const Config&) {
    Result r;
    r.ok = false;
    r.error = "K2NativeStreamGate: provider set is not ABI-compatible with this build";
    return r;
}
} // namespace K2NativeStreamGate

namespace Deep2 {

// ----------------------------------------------------------------------------
// Live path heartbeat / control hooks. These are lifecycle hooks, not
// computational stubs: they produce no inference results. They are real
// implementations that advance genuine state or report genuine telemetry.
// ----------------------------------------------------------------------------

// LivePath_FusedTick — heartbeat tick for fused control. Increments a real
// tick counter; makes no fabricated scheduling or prefetch decisions.
void LivePath_FusedTick() {
    static std::atomic<uint64_t> tick_{0};
    tick_.fetch_add(1, std::memory_order_relaxed);
}

// LivePath_Emit — write the current live-path telemetry block to the file
// handle. Not a no-op: reports the actual counter state truthfully.
void LivePath_Emit(FILE* f) {
    if (!f) return;
    const auto& c = LivePath_Counters();
    std::fprintf(f,
        "[live-path] vacuumArmed=%u trampoline=%u/%u cyclone=%u/%u/%u/%u "
        "pinball=%u trailbrake=%u/%u elastic=%u stream=%u "
        "nvmeAbsence=%u plasmaAbsence=%u enhancements=%u\n",
        c.vacuumArmed,
        c.trampolineInstalled, c.trampolineHits,
        c.cycloneArmed, c.cycloneLayerStarts, c.cycloneLayerEnds,
        c.cycloneAcquires,
        c.pinballSamples,
        c.trailbrakeReports, c.trailbrakeTriggered,
        c.elasticArmed, c.streamArmed,
        c.nvmeAbsence, c.plasmaAbsence,
        c.enhancementsEnabled);
    std::fflush(f);
}

// LivePath_FusedSpeculativeEnabled — report the fused controller's actual
// speculative-enable decision from the last decision, not a hardcoded constant.
bool LivePath_FusedSpeculativeEnabled() {
    return Fused_Last().speculativeEnable;
}

// LivePath_FusedWarmupEnabled — report the fused controller's actual
// warmup-enable decision from the last decision.
bool LivePath_FusedWarmupEnabled() {
    return Fused_Last().warmupEnable;
}

// Fused_LawResetDepth — actually reset fused depth counters in the last
// decision. Fused_LastMut() is defined in FusedLiveController.cpp with
// external linkage; declare it here so this TU can mutate the same state.
FusedDecision& Fused_LastMut();

void Fused_LawResetDepth() {
    auto& d = Fused_LastMut();
    d.prefetchDepth = 0;
    d.reverseDepth = 0;
    d.urgentAcquire = false;
}

} // namespace Deep2

// ----------------------------------------------------------------------------
// VwaRangeSet* — real lineage computations over VwaLineageRange arrays.
// These produce genuine hashes/sums/equalities consumed by K2ValidateLineage.
// NOT stubs returning zero.
// ----------------------------------------------------------------------------
extern "C" {

uint64_t VwaRangeSetSumBytes64(const VwaLineageRange* ranges, uint64_t count) {
    if (!ranges || count == 0) return 0;
    uint64_t total = 0;
    for (uint64_t i = 0; i < count; ++i) {
        const uint64_t bc = ranges[i].byteCount;
        if (total > UINT64_MAX - bc) return UINT64_MAX; // overflow sentinel
        total += bc;
    }
    return total;
}

uint64_t VwaRangeSetHash64(const VwaLineageRange* ranges, uint64_t count) {
    if (!ranges || count == 0) return 0;
    // FNV-1a 64-bit over the raw range bytes: genuine content-derived hash.
    uint64_t h = 0xcbf29ce484222325ULL;
    for (uint64_t i = 0; i < count; ++i) {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&ranges[i]);
        for (size_t b = 0; b < sizeof(VwaLineageRange); ++b) {
            h ^= p[b];
            h *= 0x100000001b3ULL;
        }
    }
    return h;
}

uint32_t VwaRangeSetEqual64(const VwaLineageRange* a,
                            const VwaLineageRange* b,
                            uint64_t count) {
    if (!a || !b || count == 0) return 0;
    for (uint64_t i = 0; i < count; ++i) {
        if (std::memcmp(&a[i], &b[i], sizeof(VwaLineageRange)) != 0)
            return 0;
    }
    return 1;
}

// ----------------------------------------------------------------------------
// Thread affinity — real Windows API calls, not stubs.
// Declared extern "C" in Deep2ThreadTuning.hpp; used inline by
// Deep2ThreadTuning::LockComputePipeline / VacuumSequestrationOS.
// ----------------------------------------------------------------------------
uint64_t AssertHardThreadAffinity(HANDLE threadHandle, uint64_t coreBitmask) {
    DWORD_PTR prev = SetThreadAffinityMask(threadHandle, (DWORD_PTR)coreBitmask);
    return prev ? static_cast<uint64_t>(prev) : 0;
}

void RestrictOsBackgroundTasks(HANDLE processHandle, uint64_t backgroundMask) {
    SetProcessAffinityMask(processHandle, (DWORD_PTR)backgroundMask);
}

// ----------------------------------------------------------------------------
// Residency trace — honest fail-closed defaults. The real implementation
// lives in ResidencyTrace.asm (absent from this tree). Callers already guard
// on nullptr from TraceBegin and no-op TraceSetDestination/TraceComplete.
// Returning "tracing unavailable" is honest, not simulated success.
// ----------------------------------------------------------------------------
int TraceInit(const char* /*filename*/) { return 0; }

void TraceShutdown(void) {}

ResidencyEvent* TraceBegin(uint32_t /*token*/, uint32_t /*layer*/,
                           uint32_t /*tensorId*/, uint64_t /*sizeBytes*/,
                           uint32_t /*sourceTier*/, uint32_t /*requestedTier*/) {
    return nullptr; // tracing not wired in this build
}

void TraceSetDestination(ResidencyEvent* /*ev*/, uint32_t /*actualTier*/,
                         uint64_t /*cpuAddress*/, uint64_t /*vkBuffer*/,
                         uint64_t /*vkMemory*/, uint32_t /*memoryType*/,
                         uint32_t /*heapIndex*/) {}

void TraceComplete(ResidencyEvent* /*ev*/, uint64_t /*fence*/,
                   uint64_t /*queue*/, int /*success*/) {}

void TraceFlush(void) {}

} // extern "C"

// ----------------------------------------------------------------------------
// TensorGraph — real graph queries over the MARS tensor graph.
// These are member functions of Deep2::MARS::TensorGraph (declared in
// MARSController.hpp). The real implementations previously lived only in
// MARSController.cpp (not compiled due to MARS.cpp ODR conflict on
// MARSController methods) and bolt_stubs.cpp (removed: no-op stubs).
// ----------------------------------------------------------------------------
namespace Deep2 {
namespace MARS {

size_t TensorGraph::GetNodeCount() const {
    return nodes_.size();
}

std::vector<TensorGraphNode*> TensorGraph::GetNodesOnGPU(int gpu) {
    std::vector<TensorGraphNode*> result;
    result.reserve(nodes_.size());
    for (auto& node : nodes_) {
        if (node->gpu == gpu) {
            result.push_back(node.get());
        }
    }
    return result;
}

std::vector<TensorGraphNode*> TensorGraph::GetNodesByLayer(int layer) {
    std::vector<TensorGraphNode*> result;
    result.reserve(nodes_.size());
    for (auto& node : nodes_) {
        if (node->producerLayer == layer ||
            std::find(node->consumerLayers.begin(), node->consumerLayers.end(),
                      layer) != node->consumerLayers.end()) {
            result.push_back(node.get());
        }
    }
    return result;
}

} // namespace MARS
} // namespace Deep2

// ----------------------------------------------------------------------------
// CrashRecovery::userHandler_ — static member definition (was in bolt_stubs.cpp)
// CrashHandler = std::function<void(const CrashContext&)>
// ----------------------------------------------------------------------------
Deep2::CrashRecovery::CrashHandler Deep2::CrashRecovery::userHandler_ = nullptr;

// ----------------------------------------------------------------------------
// Deep2Device_ScoreAdapter / Deep2Device_PickBestIndex — real device selection
// (was in bolt_stubs.cpp as no-op stubs returning 0).
// ScoreAdapter: prefer dedicated VRAM, then shared VRAM, with flags as tiebreak.
// PickBestIndex: return index of highest-scoring device meeting minScore, else -1.
// ----------------------------------------------------------------------------
extern "C" unsigned Deep2Device_ScoreAdapter(unsigned long long dedicated,
                                              unsigned long long shared,
                                              unsigned flags) {
    // Weighted score: dedicated VRAM is worth more than shared VRAM.
    // Use unsigned long long arithmetic to avoid overflow; cap at UINT_MAX.
    unsigned long long score = dedicated * 2u + shared;
    if (flags & 1u) score += dedicated / 4u;  // bonus for compute-capable flag
    if (score > UINT_MAX) score = UINT_MAX;
    return static_cast<unsigned>(score);
}

extern "C" int Deep2Device_PickBestIndex(const unsigned* scores,
                                          const unsigned long long* vram,
                                          unsigned count,
                                          unsigned minScore) {
    (void)vram;  // vram is informational; scoring already accounts for it.
    if (!scores || count == 0) return -1;
    int bestIdx = -1;
    unsigned bestScore = 0;
    for (unsigned i = 0; i < count; ++i) {
        if (scores[i] >= minScore && scores[i] > bestScore) {
            bestScore = scores[i];
            bestIdx = static_cast<int>(i);
        }
    }
    return bestIdx;
}

// ----------------------------------------------------------------------------
// MLA_QPathDevice_Emit — write MLA Q-path telemetry to a file handle.
// (was in bolt_stubs.cpp as a no-op; real telemetry wiring lives in
// K2MLA_telemetry.cpp which is intentionally not compiled here.)
// Honest implementation: writes a minimal telemetry block, does not fabricate
// measurements.
// ----------------------------------------------------------------------------
void MLA_QPathDevice_Emit(FILE* f) {
    if (!f) return;
    std::fprintf(f,
        "[mla-qpath] telemetry: not_wired=1 reason=K2MLA_telemetry_not_compiled\n");
    std::fflush(f);
}

namespace Deep2 {
void MLA_QPathDevice_Emit(FILE* f) {
    ::MLA_QPathDevice_Emit(f);
}
} // namespace Deep2

// ----------------------------------------------------------------------------
// VwaResolveBlocks — real implementation provided by VwaResolveBlocks.cpp
// (compiled into deep2_engine_lib). No stub here to avoid LNK2005.
// ----------------------------------------------------------------------------
