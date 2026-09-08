#pragma once
/* Three independent questions — never collapse into one gate. */
#include "CapabilitySolve.hpp"
#include <climits>
#include <cstdint>
#include <cstdio>

namespace rawr::tune {

/* CAN_RUN != RUNS_CORRECTLY != RUNS_FASTEST */
#define CAN_RUN_NE_PARITY 1
#define PARITY_NE_FASTEST 1
#define LEGAL_IS_NOT_WINNER 1

struct Candidate {
    RawrKernelShape shape{};
    bool legal = false;          // CAN_RUN
    bool parityOk = false;       // RUNS_CORRECTLY
    bool measureComplete = false;
    uint64_t gpuUs = UINT64_MAX;
    uint64_t wallUs = UINT64_MAX;
};

inline uint32_t SharedXBytes(uint32_t xTileFloats, uint32_t reduceBytes,
                             uint32_t otherBytes) noexcept {
    return xTileFloats * 4u + reduceBytes + otherBytes;
}

inline void MakeQkvSharedX(uint32_t rowsPerWG, RawrKernelShape& s) noexcept {
    s.LocalX = rowsPerWG;
    s.LocalY = 1;
    s.LocalZ = 1;
    s.RowsPerWG = rowsPerWG;
    s.SharedBytes = SharedXBytes(256u, 0u, 0u);
    s.PrefetchDepth = 0;
    s.WindowCount = 1;
    s.EstimatedLiveBytes = 0;
    s.MeasuredTicks = 0;
}

inline uint32_t FilterLegal(Candidate* c, uint32_t n,
                            const RawrGpuCaps& gpu) noexcept {
    uint32_t w = 0;
    for (uint32_t i = 0; i < n; ++i) {
        c[i].legal = RawrShapeLegal(&c[i].shape, &gpu) != 0;
        if (c[i].legal) {
            if (w != i) c[w] = c[i];
            ++w;
        }
    }
    return w;
}

/* Winner = fastest among MEASURE_COMPLETE && PARITY. Legal alone never wins. */
inline int PickFastestValid(const Candidate* c, uint32_t n) noexcept {
    int best = -1;
    uint64_t bestUs = UINT64_MAX;
    for (uint32_t i = 0; i < n; ++i) {
        if (!c[i].legal || !c[i].parityOk || !c[i].measureComplete)
            continue;
        if (c[i].wallUs < bestUs) {
            bestUs = c[i].wallUs;
            best = (int)i;
        }
    }
    return best;
}

inline void EmitMeasureReceipt(const Candidate* c, uint32_t n,
                               int winner) noexcept {
    std::printf("MEASURE_RECEIPT_BEGIN\n");
    std::printf("CAN_RUN_NE_PARITY=1 PARITY_NE_FASTEST=1 LEGAL_IS_NOT_WINNER=1\n");
    for (uint32_t i = 0; i < n; ++i) {
        std::printf("ROWS=%u LEGAL=%u PARITY=%u MEASURE_COMPLETE=%u "
                    "GPU_TIME_US=%llu WALL_TIME_US=%llu\n",
                    c[i].shape.RowsPerWG, c[i].legal ? 1u : 0u,
                    c[i].parityOk ? 1u : 0u, c[i].measureComplete ? 1u : 0u,
                    (unsigned long long)(c[i].gpuUs == UINT64_MAX ? 0 : c[i].gpuUs),
                    (unsigned long long)(c[i].wallUs == UINT64_MAX ? 0
                                                                   : c[i].wallUs));
    }
    if (winner >= 0 && (uint32_t)winner < n) {
        std::printf("WINNER_INDEX=%d WINNER_ROWS=%u\n", winner,
                    c[winner].shape.RowsPerWG);
    } else {
        std::printf("WINNER_INDEX=-1 WINNER_ROWS=NONE\n");
        std::printf("REASON=await_dispatch_parity_wall\n");
    }
    std::printf("MEASURE_RECEIPT_END\n");
}

} // namespace rawr::tune
