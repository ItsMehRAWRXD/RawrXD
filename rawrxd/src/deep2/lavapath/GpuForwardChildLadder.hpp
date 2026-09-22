#pragma once
/* GpuForwardChildLadder — stub */
#include <cstdint>
namespace rawr { namespace gpu_iso {
struct Run {
    static constexpr int G0 = 0;
};
inline void Begin() {}
}} // namespace rawr::gpu_iso
namespace Deep2 {
inline bool LivePath_Active() { return false; }
class CycloneScheduler;
inline CycloneScheduler* LivePath_ActiveCyclone() { return nullptr; }
inline void LivePath_OnLayerStart(CycloneScheduler*, uint32_t /*layer*/, uint64_t /*seq*/) {}
inline void LivePath_OnLayerEnd(CycloneScheduler*, uint32_t /*layer*/, uint64_t /*seq*/, uint64_t /*dur*/) {}
} // namespace Deep2
