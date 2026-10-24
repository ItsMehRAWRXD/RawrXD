// ============================================================================
// Deep2Engine_missing_members.cpp — out-of-class Deep2Engine definitions
// ============================================================================
// Deep2Engine declares five members in Deep2Engine.h that Deep2Engine.cpp only
// ever CALLS. They are defined here so the engine links as a real program
// instead of leaving a hole in the symbol table.
//
// Every definition below is compiled from real engine state:
//   resetGpuForwardCounters  clears the engine's own GpuForwardCounters and the
//                            gemv/planned counters its getters expose.
//   gpuResidentDecodeEnabled reflects the real GPU-residency commit flag.
//   forwardTokenAllLayers    runs the real layer loop that Deep2Engine.cpp's
//                            B3_StageDigest path performs inline (same elastic
//                            prefetch, same forwardLayer call, same swap and
//                            final copy).
//   emit*Witnesses           use the engine's real witness emitter,
//                            Deep2GpuForward_Emit, over the real counters.
// ============================================================================
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include "ResidencyCounters.hpp"
#include "Deep2LivePath.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <windows.h>

// ----------------------------------------------------------------------------
// Deep2Engine lives in namespace Deep2 (src/Deep2Engine.h:66); every definition
// below must be qualified the same way the declarations are.
// ----------------------------------------------------------------------------
namespace Deep2 {

const GpuForwardCounters& Deep2Engine::gpuForwardCounters() const {
    return gpuFwd_;
}

// ----------------------------------------------------------------------------
// resetGpuForwardCounters — clear the real forward-path counters.
// Mirrors what Deep2Engine::reset() does for gpuFwd_ and additionally clears
// the gemv/planned counters the public getters report, because this entry
// point is the one generate() calls at the start of a run.
// ----------------------------------------------------------------------------
void Deep2Engine::resetGpuForwardCounters() {
    gpuFwd_ = GpuForwardCounters{};
    vulkanGemvOk_ = 0;
    vulkanGemvFail_ = 0;
    vulkanUnplannedFallbacks_ = 0;
    plannedCpuGemvOps_ = 0;
    plannedGpuGemvOps_ = 0;
}

// ----------------------------------------------------------------------------
// gpuResidentDecodeEnabled — true when the GPU-resident forward arena has been
// committed. Nothing in the engine commits it yet, so this reports the flag
// truthfully rather than asserting a capability that does not exist.
// ----------------------------------------------------------------------------
bool Deep2Engine::gpuResidentDecodeEnabled() const {
    return gpuFwdCommitted_;
}

// ----------------------------------------------------------------------------
// forwardTokenAllLayers — run one token through every model layer.
// This is the same control law Deep2Engine.cpp applies inline in its
// B3_StageDigest path: elastic prefetch of the next layer's weights, one
// forwardLayer call per layer, buffer swap, and a final copy back into the
// caller's hidden buffer. Returns false only on a real per-layer failure.
// ----------------------------------------------------------------------------
bool Deep2Engine::forwardTokenAllLayers(float* hidden, size_t seqLen) {
    if (!hidden) return false;
    if (modelWeights.numLayers == 0) return false;
    if (!attentionOutput) return false;

    float* layerInput = hidden;
    float* layerOutput = attentionOutput;

    for (size_t layer = 0; layer < modelWeights.numLayers; ++layer) {
        // ── Batch 15: Prefetch next layer weights into residency ──
        if (elasticResidencyEnabled_ && elasticResidency_ && !vulkanEnabled_ &&
            layer + 1 < modelWeights.numLayers) {
            const size_t boost = static_cast<size_t>(LivePath_PrefetchBoost());
            const size_t target = layer + 1 + boost;
            if (target < modelWeights.numLayers) {
                const auto& nextLw = modelWeights.layers[target];
                auto prefetchWt = [&](const WeightTensor& wt) {
                    if (!wt.name.empty())
                        elasticResidency_->PrefetchToGpu(wt.name,
                                                        static_cast<uint32_t>(target));
                };
                prefetchWt(nextLw.wq); prefetchWt(nextLw.wk); prefetchWt(nextLw.wv);
                prefetchWt(nextLw.wo); prefetchWt(nextLw.attnNorm); prefetchWt(nextLw.ffnNorm);
                prefetchWt(nextLw.wGate); prefetchWt(nextLw.wUp); prefetchWt(nextLw.wDown);
            }
        }

        // Heap validation before each layer: catch silent buffer overflows
        // from previous operations that corrupt heap metadata without raising
        // an immediate access violation.
        if (!HeapValidate(GetProcessHeap(), 0, NULL))
        {
            fprintf(stderr,
                    "[HEAP_CORRUPT] detected before layer=%zu, stopping generation\n",
                    layer);
            fflush(stderr);
            return false;
        }

        auto layerT0 = std::chrono::high_resolution_clock::now();
        if (!safeForwardLayer(layer, layerInput, layerOutput, seqLen)) {
            // Always emit the first failing boundary. No changes to model math,
            // token state, or the layer-buffer swap contract.
            fprintf(stderr,
                    "[DEEP2_FORWARD_FAILURE] layer=%zu seqLen=%zu input=%p output=%p hidden=%p layers=%zu\n",
                    layer, seqLen, static_cast<void*>(layerInput),
                    static_cast<void*>(layerOutput), static_cast<void*>(hidden),
                    modelWeights.numLayers);
            fflush(stderr);
            return false;
        }
        auto layerT1 = std::chrono::high_resolution_clock::now();
        const double layerMs =
            std::chrono::duration<double, std::milli>(layerT1 - layerT0).count();
        ResidencyCounters::RecordLayerTime(layer, layerMs);

        // Swap buffers: after the swap layerInput holds the layer's output.
        float* temp = layerInput;
        layerInput = layerOutput;
        layerOutput = temp;
    }

    // The final hidden state is in layerInput after the last swap.
    if (layerInput != hidden) {
        memcpy(hidden, layerInput, static_cast<size_t>(config.hiddenDim) * sizeof(float));
    }
    return true;
}

// ----------------------------------------------------------------------------
// emitHotpathWitnesses — emit the real GPU-forward witness block.
// Deep2GpuForward_Emit writes to stdout once when handed stdout.
// ----------------------------------------------------------------------------
static uint64_t Deep2CpuFallbackTotal(const Deep2::GpuForwardCounters& c) {
    return c.hostForwardLayerCalls + c.cpuF32Expands;
}

void Deep2Engine::emitHotpathWitnesses() {
    Deep2GpuForward_Emit(stdout, gpuFwd_, Deep2CpuFallbackTotal(gpuFwd_));
    fflush(stdout);
}

// ----------------------------------------------------------------------------
// emitLiveDecodeWitnesses — same witness block, additionally mirrored to f.
// A null f keeps the emit on stdout only, matching Deep2GpuForward_Emit.
// ----------------------------------------------------------------------------
void Deep2Engine::emitLiveDecodeWitnesses(FILE* f) {
    Deep2GpuForward_Emit(f, gpuFwd_, Deep2CpuFallbackTotal(gpuFwd_));
    fflush(stdout);
}

// ----------------------------------------------------------------------------
// safeForwardLayer — SEH-safe wrapper around forwardLayer.  Catches access
// violations from buffer overflows during inference so the engine can return
// false and shut down cleanly instead of corrupting the heap and crashing
// during teardown.  This function has no local objects with destructors so
// __try/__except compiles here (unlike in forwardTokenAllLayers, which uses
// std::chrono::time_point and other RAII types).
// ----------------------------------------------------------------------------
bool Deep2Engine::safeForwardLayer(size_t layer, float* input, float* output, size_t seqLen)
{
    __try
    {
        forwardLayer(layer, input, output, seqLen);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        fprintf(stderr,
                "[B3_ABORT] forwardLayer access violation at layer=%zu, "
                "stopping generation\n", layer);
        fflush(stderr);
        return false;
    }
}

} // namespace Deep2
