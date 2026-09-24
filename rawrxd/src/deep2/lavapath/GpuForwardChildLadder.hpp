#pragma once
// ============================================================================
// GpuForwardChildLadder — LivePath adapter for CycloneScheduler
// ============================================================================
#include <cstdint>
#include "../CycloneScheduler.hpp"

namespace rawr { namespace gpu_iso {
struct Run {
    static constexpr int G0 = 0;
};
inline void Begin() {}
}} // namespace rawr::gpu_iso

namespace Deep2 {

// Engine-owned Cyclone binding; lifetime strictly bounded to enableCyclone/disableCyclone.
// Do not bind from arbitrary TUs; only Deep2Engine::enableCyclone/disableCyclone.
extern CycloneScheduler* g_boundCyclone;

inline bool LivePath_Active() noexcept {
    return g_boundCyclone != nullptr;
}

inline CycloneScheduler* LivePath_ActiveCyclone() noexcept {
    return g_boundCyclone;
}

inline void LivePath_BindCyclone(CycloneScheduler* scheduler) noexcept {
    g_boundCyclone = scheduler;
}

inline void LivePath_UnbindCyclone() noexcept {
    g_boundCyclone = nullptr;
}

inline void LivePath_OnLayerStart(CycloneScheduler* cyc, uint32_t layer, uint64_t seq) {
    if (cyc) cyc->onLayerStart(layer, seq);
}

inline void LivePath_OnLayerEnd(CycloneScheduler* cyc, uint32_t layer, uint64_t seq, uint64_t dur) {
    if (cyc) cyc->onLayerEnd(layer, seq, dur);
}

inline void LivePath_OnLayerAbort(CycloneScheduler* cyc, uint32_t layer, uint64_t seq) {
    if (cyc) cyc->onLayerAbort(layer, seq);
}

} // namespace Deep2
