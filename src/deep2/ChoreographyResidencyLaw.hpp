#pragma once
// Choreography is the top-level runtime primitive — not monolithic load.
// MODEL SIZE ≠ RESIDENCY REQUIREMENT. TPS limited only by physics.
#include "RawrNoTpResidency.hpp"
#include <cstdio>
#include <cstdlib>
#ifdef _WIN32
#include <stdlib.h>
#endif

namespace Deep2 {
namespace choreo {

enum class Tier : uint8_t {
    GpuLocal = 0,
    GpuPeer = 1,
    Ram = 2,
    Pinned = 3,
    Nvme = 4,
    Fault = 5
};

enum class TensorState : uint8_t {
    Unknown = 0,
    Disk = 1,
    Reading = 2,
    Ram = 3,
    Pinned = 4,
    Gpu = 5,
    Executing = 6,
    Retire = 7
};

struct ReadyDecision {
    Tier action = Tier::Fault;
    int deviceId = -1;
    int scheduleOther = 0; // 1 when issuing disk read — do not stall
};

inline ReadyDecision ScoreboardReady(TensorState st, int localGpu, int peerGpu) {
    ReadyDecision d{};
    if (st == TensorState::Gpu) {
        d.action = Tier::GpuLocal;
        d.deviceId = localGpu;
        return d;
    }
    if (st == TensorState::Pinned || st == TensorState::Ram) {
        d.action = (st == TensorState::Pinned) ? Tier::Pinned : Tier::Ram;
        d.deviceId = localGpu;
        return d;
    }
    if (st == TensorState::Disk || st == TensorState::Reading) {
        d.action = Tier::Nvme;
        d.scheduleOther = 1;
        return d;
    }
    if (peerGpu >= 0 && st == TensorState::Gpu) {
        d.action = Tier::GpuPeer;
        d.deviceId = peerGpu;
        return d;
    }
    d.action = Tier::Fault;
    return d;
}

// Hard law — no artificial TPS / residency ceilings.
struct ResidencyLaw {
    int tpsLimitNone = 1;
    int tokenPacingOff = 1;
    int decodeSleep0 = 1;
    int syncPerLayer0 = 1;
    int fullModelResidency0 = 1;
    int fullLayerExpand0 = 1;
    int maxModelUnbounded = 1;
    int quantUntilKernel = 1;
    int rangeReads = 1;
    int asyncPipeline = 1;
    int circulatingWindows = 1;
    int kvPagingSeparate = 1;
};

inline ResidencyLaw DefaultLaw() { return ResidencyLaw{}; }

inline int LawHolds(const ResidencyLaw& L) {
    return L.tpsLimitNone && L.tokenPacingOff && L.decodeSleep0 &&
           L.syncPerLayer0 && L.fullModelResidency0 && L.fullLayerExpand0 &&
           L.maxModelUnbounded && L.quantUntilKernel && L.rangeReads &&
           L.asyncPipeline && L.circulatingWindows && L.kvPagingSeparate;
}

inline void ApplyLawEnv() {
#ifdef _WIN32
    _putenv_s("TPS_LIMIT", "NONE");
    /* Artificial pacing is anti-TPS — always force OFF. */
    _putenv_s("TOKEN_PACING", "OFF");
    _putenv_s("DECODE_SLEEP", "0");
    _putenv_s("SYNC_PER_LAYER", "0");
    _putenv_s("FULL_MODEL_RESIDENCY_REQUIRED", "0");
    _putenv_s("FULL_LAYER_EXPANSION_REQUIRED", "0");
    _putenv_s("MAX_MODEL_BYTES", "UNBOUNDED_ADDRESS_SPACE");
    _putenv_s("DEEP2_TPS_DISPLAY_SCALE", "1");
    _putenv_s("RAWRXD_BOUNDED_RESIDENCY", "1");
    _putenv_s("RAWRXD_NO_TP", "1");
    _putenv_s("CYCLONE_FIXED_TICK", "OFF");
    _putenv_s("TRAILBRAKE_TPS_LIMIT", "OFF");
    _putenv_s("RAWRXD_TPS_LIMIT", "NONE");
#endif
}

inline void EmitLaw(FILE* f, const ResidencyLaw& L) {
    if (!f) f = stdout;
    RawrEmitNoTpContract(f);
    std::fprintf(f, "TPS_LIMIT=%s\n", L.tpsLimitNone ? "NONE" : "SET");
    std::fprintf(f, "TOKEN_PACING=%s\n", L.tokenPacingOff ? "OFF" : "ON");
    std::fprintf(f, "DECODE_SLEEP=%d\n", L.decodeSleep0 ? 0 : 1);
    std::fprintf(f, "SYNC_PER_LAYER=%d\n", L.syncPerLayer0 ? 0 : 1);
    std::fprintf(f, "FULL_LAYER_EXPANSION_REQUIRED=%d\n",
                 L.fullLayerExpand0 ? 0 : 1);
    std::fprintf(f, "MAX_MODEL_BYTES=%s\n",
                 L.maxModelUnbounded ? "UNBOUNDED_ADDRESS_SPACE" : "CAPPED");
    std::fprintf(f, "QUANT_UNTIL_KERNEL=%d\n", L.quantUntilKernel);
    std::fprintf(f, "TENSOR_RANGE_READS=%d\n", L.rangeReads);
    std::fprintf(f, "ASYNC_READ_PIN_XFER_EXEC=%d\n", L.asyncPipeline);
    std::fprintf(f, "CIRCULATING_WINDOWS=%d\n", L.circulatingWindows);
    std::fprintf(f, "KV_PAGING_SEPARATE=%d\n", L.kvPagingSeparate);
    std::fprintf(f, "MODEL_SIZE_EQ_RESIDENCY=0\n");
    std::fprintf(f, "VRAM_REQUIRED=0\n");
    std::fprintf(f, "TPS_DISPLAY_SCALE=1\n");
    std::fprintf(f, "CYCLONE_FIXED_TICK=OFF\n");
    std::fprintf(f, "TRAILBRAKE_TPS_LIMIT=OFF\n");
    std::fprintf(f, "CHOREOGRAPHY_TOP_LEVEL=1\n");
    std::fprintf(f, "ONE_TENSOR_ONE_OWNER=1\n");
    std::fprintf(f, "MODEL_PARALLEL_ALLOWED=1\n");
    std::fprintf(f, "TENSOR_PARALLEL_ALLOWED=0\n");
    std::fprintf(f, "WEIGHTS_CROSS_LANES=0\n");
    std::fprintf(f, "TP_SHARDS=1\n");
    std::fprintf(f, "CHOREOGRAPHY_RESIDENCY_LAW=%s\n",
                 LawHolds(L) ? "PASS" : "FAIL");
}

} // namespace choreo
} // namespace Deep2
