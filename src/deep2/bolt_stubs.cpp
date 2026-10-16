// ============================================================================
// bolt_stubs.cpp — Stub implementations for externally-referenced symbols
// Needed by RawrXD-CLI-V2 to link deep2_engine_lib.
// These are minimal stubs; real implementations live in deep2_snap or other
// production libraries.
// ============================================================================

#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>

#include <windows.h>

#include "deep2/vwa/VwaRangeLineageAbi.hpp"
#include "deep2/HotPatcherSafety.hpp"
#include "deep2/execution_policy/PlacementPlan.hpp"
#include "deep2/execution_policy/ExecutionPolicy.hpp"
#include "deep2/mars/MARSController.hpp"
#include "deep2/ResidencyTrace.hpp"

namespace Deep2 {

// CrashRecovery::userHandler_ static member definition
// CrashHandler = std::function<void(const CrashContext&)>
CrashRecovery::CrashHandler CrashRecovery::userHandler_ = nullptr;

} // namespace Deep2

namespace Deep2::Exec {

// ClassifyTensorName — stub
TensorClass ClassifyTensorName(const std::string& name) {
    (void)name;
    return TensorClass::Scratch;
}

// BindModelToPolicy — stub
void BindModelToPolicy(const std::string& modelPath, const std::string& modelFingerprint) {
    (void)modelPath;
    (void)modelFingerprint;
}

// DerivePlacementPlan — stub
PlacementPlan DerivePlacementPlan(const ExecutionPolicy& policy, int nLayers) {
    (void)policy;
    (void)nLayers;
    return PlacementPlan{};
}

// DeviceKindToGpuIndex — stub
int DeviceKindToGpuIndex(DeviceKind kind) {
    (void)kind;
    return 0;
}

} // namespace Deep2::Exec

namespace Deep2::MARS {

// TensorGraph::GetNodeCount — stub
size_t TensorGraph::GetNodeCount() const {
    return 0;
}

// TensorGraph::GetNodesOnGPU — stub
std::vector<TensorGraphNode*> TensorGraph::GetNodesOnGPU(int gpu) {
    (void)gpu;
    return {};
}

// TensorGraph::GetNodesByLayer — stub
std::vector<TensorGraphNode*> TensorGraph::GetNodesByLayer(int layer) {
    (void)layer;
    return {};
}

} // namespace Deep2::MARS

// LivePath stubs
namespace Deep2 {
void LivePath_FusedTick() {}
bool LivePath_FusedSpeculativeEnabled() { return false; }
void LivePath_Emit(FILE* f) { (void)f; }
bool LivePath_FusedWarmupEnabled() { return false; }
void MLA_QPathDevice_Emit(FILE* f) { (void)f; }
void Fused_LawResetDepth() {}
} // namespace Deep2

// Device manager stubs
extern "C" int Deep2Device_PickBestIndex(const unsigned* scores,
                                          const unsigned long long* vram,
                                          unsigned count,
                                          unsigned minScore) {
    (void)scores; (void)vram; (void)count; (void)minScore;
    return 0;
}
extern "C" unsigned Deep2Device_ScoreAdapter(unsigned long long dedicated,
                                              unsigned long long shared,
                                              unsigned flags) {
    (void)dedicated; (void)shared; (void)flags;
    return 0;
}

// Global stubs
extern "C" void RestrictOsBackgroundTasks(HANDLE processHandle,
                                           uint64_t backgroundMask) {
    (void)processHandle; (void)backgroundMask;
}
extern "C" uint64_t AssertHardThreadAffinity(HANDLE threadHandle,
                                              uint64_t coreBitmask) {
    (void)threadHandle; (void)coreBitmask;
    return coreBitmask;
}

// Trace stubs
extern "C" ResidencyEvent* TraceBegin(uint32_t token, uint32_t layer,
                                       uint32_t tensorId, uint64_t sizeBytes,
                                       uint32_t sourceTier,
                                       uint32_t requestedTier) {
    (void)token; (void)layer; (void)tensorId; (void)sizeBytes;
    (void)sourceTier; (void)requestedTier;
    return nullptr;
}
extern "C" void TraceSetDestination(ResidencyEvent* ev,
                                     uint32_t actualTier,
                                     uint64_t cpuAddress,
                                     uint64_t vkBuffer,
                                     uint64_t vkMemory,
                                     uint32_t memoryType,
                                     uint32_t heapIndex) {
    (void)ev; (void)actualTier; (void)cpuAddress; (void)vkBuffer;
    (void)vkMemory; (void)memoryType; (void)heapIndex;
}
extern "C" void TraceComplete(ResidencyEvent* ev, uint64_t fence,
                               uint64_t queue, int success) {
    (void)ev; (void)fence; (void)queue; (void)success;
}

// VwaResolveBlocks — stub
extern "C" unsigned long VwaResolveBlocks(void* a, void* b, void* c) {
    (void)a; (void)b; (void)c;
    return 0;
}

// VwaRangeSetHash64 — stub
extern "C" uint64_t VwaRangeSetHash64(const VwaLineageRange* ranges, uint64_t count) {
    (void)ranges; (void)count;
    return 0;
}

// VwaRangeSetSumBytes64 — stub
extern "C" uint64_t VwaRangeSetSumBytes64(const VwaLineageRange* ranges, uint64_t count) {
    (void)ranges; (void)count;
    return 0;
}

// VwaRangeSetEqual64 — stub
extern "C" uint32_t VwaRangeSetEqual64(
    const VwaLineageRange* a, const VwaLineageRange* b, uint64_t count) {
    (void)a; (void)b; (void)count;
    return 0;
}
