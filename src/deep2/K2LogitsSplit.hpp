// K2LogitsSplit.hpp — CPU Q6×Q8 || GPU Q6 range under MLA_Gemv hotpatch.
#pragma once
#include "VirtualTensorDesc.hpp"
#include <cstdint>
#include <cstdio>

namespace Deep2 {

struct LogitsSplitSnap {
    uint64_t calls = 0;
    uint64_t gpuRows = 0;
    uint64_t cpuRows = 0;
    uint64_t rowsTotal = 0;
    uint64_t cpuBranchUs = 0;
    uint64_t gpuBranchUs = 0;
    uint64_t splitWallUs = 0;
    uint64_t serialBaseUs = 0;
    int32_t cpuTok = -1;
    int32_t gpuTok = -1;
    int32_t finalTok = -1;
    float cpuVal = 0.f;
    float gpuVal = 0.f;
    float finalVal = 0.f;
    uint32_t modeSplit = 0; // 1 = CPU||GPU
    uint64_t gpuArgmaxBytes = 0;
    uint64_t gpuRangeOutBytes = 0;
    uint64_t fullReadback = 0;
    float cpuRowsPerUs = 0.f;
    float gpuRowsPerUs = 0.f;
};

void LogitsSplit_Reset();
LogitsSplitSnap LogitsSplit_Snapshot();
void LogitsSplit_Emit(FILE* f);

// Opt-in: DEEP2_LOGITS_GPU_SPLIT=1 (or unset while DEEP2_K2_GPU_MLA=1).
// =0 → classic CPU-only ArgmaxPacked.
bool LogitsSplit_Wanted();

// logitsDesc: RMV VirtualTensorDesc for output.weight (required for GPU cut).
// ResolveQuantBlockRange runs once here — never inside TryGpuHot.
bool LogitsSplit_ArgmaxPacked(const uint8_t* base, size_t baseBytes,
                              size_t vocabSize, size_t hiddenDim,
                              const float* hidden,
                              const VirtualTensorDesc* logitsDesc,
                              int32_t& bestTok, float* bestValOut);

// Compat: no desc → CPU climb only (no GPU cut attribution).
inline bool LogitsSplit_ArgmaxPacked(const uint8_t* base, size_t baseBytes,
                                     size_t vocabSize, size_t hiddenDim,
                                     const float* hidden, int32_t& bestTok,
                                     float* bestValOut) {
    return LogitsSplit_ArgmaxPacked(base, baseBytes, vocabSize, hiddenDim,
                                    hidden, nullptr, bestTok, bestValOut);
}

} // namespace Deep2
