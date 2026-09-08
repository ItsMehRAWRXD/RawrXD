// RawrChoreography.hpp — top-level primitive: schedule tensors, not load models
// TPS limited only by hardware; no runtime-imposed ceiling.
#pragma once
#include "RawrNoTpResidency.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace Deep2 {

inline bool RawrDecodeSleepAllowed() {
    const char* e = std::getenv("DECODE_SLEEP");
    if (e && e[0] == '0') return false;
    const char* t = std::getenv("RAWRXD_TPS_LIMIT");
    if (t && (std::strcmp(t, "NONE") == 0 || t[0] == '0')) return false;
    const char* p = std::getenv("TOKEN_PACING");
    if (p && (std::strcmp(p, "OFF") == 0 || p[0] == '0')) return false;
    // Default: no artificial decode sleep on production path.
    return false;
}

inline bool RawrSyncPerLayerWanted() {
    const char* e = std::getenv("SYNC_PER_LAYER");
    return e && e[0] == '1'; // default OFF
}

inline void RawrEmitChoreographyContract(FILE* f) {
    if (!f) return;
    RawrEmitNoTpContract(f);
    fprintf(f,
            "TPS_LIMIT=NONE\n"
            "TOKEN_PACING=OFF\n"
            "DECODE_SLEEP=0\n"
            "SYNC_PER_LAYER=%d\n"
            "FULL_LAYER_EXPANSION_REQUIRED=0\n"
            "MAX_MODEL_BYTES=UNBOUNDED_ADDRESS_SPACE\n"
            "CHOREOGRAPHY_TOP_LEVEL=1\n"
            "SCOREBOARD_READY_EXECUTE=1\n"
            "PREFETCH_GRAPH_DRIVEN=1\n"
            "VRAM_REQUIRED=0\n"
            "PER_LAYER_JOIN=0\n"
            "LAST_USE_EVICTION=1\n"
            "KV_LAZY_PAGED=1\n"
            "TPS_DISPLAY_SCALE=1\n",
            RawrSyncPerLayerWanted() ? 1 : 0);
}

// Scoreboard tip: where to source operand bytes for execute.
enum class ReadyTier : int {
    GpuResident = 0,
    PeerGpu = 1,
    Ram = 2,
    Disk = 3,
    Fault = 4
};

inline ReadyTier ScoreboardReady(int gpuHit, int peerHit, int ramHit, int diskHit) {
    if (gpuHit) return ReadyTier::GpuResident;
    if (peerHit) return ReadyTier::PeerGpu;
    if (ramHit) return ReadyTier::Ram;
    if (diskHit) return ReadyTier::Disk;
    return ReadyTier::Fault;
}

} // namespace Deep2
