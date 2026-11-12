#pragma once
// Shared VRAM / KV-cache / layer eviction controls (C55) — local DXGI + offload.
#include <cstdint>

namespace RawrXD {
namespace Perf {

struct VramSnapshot {
    double totalMB = 0.0;
    double usedMB = 0.0;
    double availableMB = 0.0;
};

VramSnapshot QueryLocalVram();
void SetGpuLayerOffload(int layers);
int GetGpuLayerOffload();
void EvictLayers(int count);
int GetEvictedLayers();

}  // namespace Perf
}  // namespace RawrXD
