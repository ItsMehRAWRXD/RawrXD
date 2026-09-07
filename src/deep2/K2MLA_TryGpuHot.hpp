// K2MLA_TryGpuHot.hpp — packed exec modes under MLA_Gemv (no live TryGpu bypass).
#pragma once
#include "VirtualTensorRange.hpp"
#include <cstdint>
#include <cstdio>

namespace Deep2 {

enum class MlaPackedExecMode : uint8_t {
    FullGemv = 0,
    RangeGemv = 1,
    RangeArgmax = 2,
};

struct PackedArgmax {
    float value = -1e30f;
    uint32_t row = 0;
};

struct MlaPackedExec {
    MlaPackedExecMode mode = MlaPackedExecMode::FullGemv;
    uint32_t rowStart = 0;
    uint32_t rowCount = 0; // 0 → use rows arg
    PackedArgmax* argmaxOut = nullptr;
    // Observational provenance only — never re-resolved inside TryGpu.
    const PhysicalTensorRange* sourceRanges = nullptr;
    size_t sourceRangeCount = 0;
};

// RANGE_ARGMAX via MLA_Gemv authority (increments gemv entry, not tryEntry).
// sourceRanges must be resolved upstream; this path does not ResolveQuantBlockRange.
bool MLA_GemvRangeArgmax(int ggmlType, const void* packed, size_t bytes,
                         const float* input, uint32_t rowStart,
                         uint32_t rowCount, uint32_t cols,
                         const PhysicalTensorRange* sourceRanges,
                         size_t sourceRangeCount,
                         PackedArgmax& out);

void MLA_TryGpuHot_Emit(FILE* f);
void MLA_TryGpuHot_Reset();

uint64_t MLA_Q6PackedOps();
uint64_t MLA_RangeArgmaxOps();
uint64_t MLA_GpuArgmaxBytes();     // committed winner payload
uint64_t MLA_GpuRangeOutBytes();  // staging readback (range F32)
uint64_t MLA_GpuFullReadback();   // 1 if ever read full vocab logits

} // namespace Deep2
