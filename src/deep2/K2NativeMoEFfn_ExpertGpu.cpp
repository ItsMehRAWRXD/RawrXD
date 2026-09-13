/* K2NativeMoEFfn_ExpertGpu.cpp — DualStick stick-VRAM Gate/Up/Down GEMV. */
#include "K2NativeMoEFfn.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "vulkan_compute.h"
#include <cmath>
#include <cstring>
#include <vector>

namespace Deep2 {
namespace {

void SiluMulGpu(float* gate, const float* up, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        const float x = gate[i];
        gate[i] = (x / (1.0f + std::exp(-x))) * up[i];
    }
}

uint64_t ExpertPin(uint32_t layer, int expertId, uint8_t tag) {
    return ((uint64_t)layer << 24) | ((uint64_t)(expertId & 0xffff) << 8) |
           (uint64_t)tag;
}

bool StickGemv(CPUInference::VulkanCompute* vc, int ggmlType, const uint8_t* w,
               size_t bytes, const float* x, float* y, uint32_t rows,
               uint32_t cols, uint64_t pin) {
    if (!vc || !w || !x || !y || !rows || !cols) return false;
    std::memset(y, 0, (size_t)rows * sizeof(float));
    return vc->DispatchGEMVQuant(ggmlType, w, bytes, x, y, rows, cols, pin);
}

} // namespace

bool K2MoEExecExpertGpu(unsigned stick, int ggmlGate, const uint8_t* g,
                        size_t gb, int ggmlUp, const uint8_t* u, size_t ub,
                        int ggmlDown, const uint8_t* d, size_t db,
                        const float* hidden, float* expertOut, size_t H,
                        size_t I, uint32_t layer, int expertId) {
    auto* vc = DualStickVc(stick);
    if (!vc || !hidden || !expertOut || !H || !I) return false;
    if (!g || !u || !d || !gb || !ub || !db) return false;

    MoEPlaceLive().expert_gpu_acquire++;
    DualStickAcquire(stick, g, gb, 0, layer, (uint32_t)expertId);
    DualStickAcquire(stick, u, ub, 0, layer, (uint32_t)expertId);
    DualStickAcquire(stick, d, db, 0, layer, (uint32_t)expertId);

    std::vector<float> gate(I), up(I);
    const uint32_t rI = (uint32_t)I, cH = (uint32_t)H, rH = (uint32_t)H,
                   cI = (uint32_t)I;
    if (!StickGemv(vc, ggmlGate, g, gb, hidden, gate.data(), rI, cH,
                   ExpertPin(layer, expertId, 1)))
        return false;
    if (!StickGemv(vc, ggmlUp, u, ub, hidden, up.data(), rI, cH,
                   ExpertPin(layer, expertId, 2)))
        return false;
    SiluMulGpu(gate.data(), up.data(), I);
    if (!StickGemv(vc, ggmlDown, d, db, gate.data(), expertOut, rH, cI,
                   ExpertPin(layer, expertId, 3)))
        return false;

    const uint64_t eb = (uint64_t)gb + (uint64_t)ub + (uint64_t)db;
    DualStickNoteExpertGpu(stick, (size_t)eb);
    DualStickNoteExpertResident((int)layer, expertId, stick, eb);
    MoEPlaceLive().expert_gpu_exec++;
    return true;
}

} // namespace Deep2
