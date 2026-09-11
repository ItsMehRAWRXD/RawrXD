#pragma once
/* WeightLease — quant stays through disk/RAM/VRAM; unpack only at kernel edge.
   BAN persistent f16/f32 weight windows. LIVE=0. ≤99. */
#include "ScoreboardTypes.hpp"
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct WeightLease {
    TensorId id = 0;
    PhysicalWindow* window = nullptr;
    const void* quantBase = nullptr; /* still quantized */
    void* tileScratch = nullptr;     /* register-edge tile only */
    uint32_t tileBytes = 0;
    DeviceId deviceId = -1;
};

inline int weightLeaseOpen(WeightLease& lease, TensorScore& t, uint32_t tileBytes,
                           void* tileScratch) {
    if (!t.gpuWindow && !t.ramWindow)
        return 0;
    PhysicalWindow* w = t.gpuWindow ? t.gpuWindow : t.ramWindow;
    lease.id = t.id;
    lease.window = w;
    lease.quantBase = w->base;
    lease.tileScratch = tileScratch;
    lease.tileBytes = tileBytes;
    lease.deviceId = w->deviceId;
    return 1;
}

inline void weightLeaseClose(WeightLease& lease) {
    lease.quantBase = nullptr;
    lease.tileScratch = nullptr;
    lease.tileBytes = 0;
    lease.window = nullptr;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
