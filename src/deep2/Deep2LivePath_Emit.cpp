// Deep2LivePath_Emit.cpp — LIVE_PATH_* + hard counter witnesses
#include "Deep2LivePath.hpp"
#include "Deep2LivePath_Internal.hpp"
#include "GpuTransferCounters.hpp"
#include "StreamTransferCounters.hpp"
#include "FusedLiveController.hpp"
#include "NULiveConsumer.hpp"
#include "TpsScaleHotpatch.hpp"

namespace Deep2 {

void LivePath_Emit(FILE* f) {
    if (!f) f = stdout;
    const auto& c = LivePath_Ctr();
    fprintf(f, "LIVE_PATH_VACUUM=%u\n", c.vacuumArmed);
    fprintf(f, "LIVE_PATH_TRAMPOLINE_INSTALLED=%u\n", c.trampolineInstalled);
    fprintf(f, "LIVE_PATH_TRAMPOLINE_HITS=%u\n", c.trampolineHits);
    fprintf(f, "LIVE_PATH_CYCLONE=%u\n", c.cycloneArmed);
    fprintf(f, "LIVE_PATH_CYCLONE_LAYER_STARTS=%u\n", c.cycloneLayerStarts);
    fprintf(f, "LIVE_PATH_CYCLONE_LAYER_ENDS=%u\n", c.cycloneLayerEnds);
    fprintf(f, "LIVE_PATH_CYCLONE_DEMANDS=%u\n", c.cycloneAcquires);
    fprintf(f, "LIVE_PATH_PINBALL_SAMPLES=%u\n", c.pinballSamples);
    fprintf(f, "LIVE_PATH_ELASTIC=%u\n", c.elasticArmed);
    fprintf(f, "LIVE_PATH_STREAM=%u\n", c.streamArmed);
    fprintf(f, "LIVE_PATH_STREAM_ALIVE=%u\n", c.streamAlive);
    fprintf(f, "LIVE_PATH_NVME_HOPS=%u\n", c.nvmeHops);
    fprintf(f, "LIVE_PATH_PLASMA_SAMPLES=%u\n", c.plasmaSamples);
    fprintf(f, "LIVE_PATH_REVERSAL_US=%.3f\n", c.reversalUsPerToken);
    fprintf(f, "LIVE_PATH_ENHANCEMENTS=%u\n", c.enhancementsEnabled);
    fprintf(f, "LIVE_PATH_BRAKE=%u\n", LivePath_ShouldBrake() ? 1u : 0u);
    fprintf(f, "LIVE_PATH_ACTIVE=%u\n", LivePath_Active() ? 1u : 0u);
    fprintf(f, "STREAM_BYTES_READ_TOTAL=%llu\n", (unsigned long long)c.streamBytesRead);
    fprintf(f, "STREAM_BYTES_TO_GPU_TOTAL=%llu\n", (unsigned long long)c.streamBytesToGpu);
    fprintf(f, "STREAM_BYTES_RECONSTRUCTED_TOTAL=%llu\n",
            (unsigned long long)c.streamBytesReconstructed);
    fprintf(f, "STREAM_READ_OPS=%llu\n", (unsigned long long)c.streamReadOps);
    fprintf(f, "STREAM_GPU_UPLOAD_OPS=%llu\n", (unsigned long long)c.streamGpuUploadOps);
    fprintf(f, "VRAM_PEAK=%llu\n", (unsigned long long)c.vramPeak);
    fprintf(f, "RESIDENT_WEIGHT_PEAK=%llu\n", (unsigned long long)c.residentWeightPeak);
    fprintf(f, "CACHE_HITS=%llu\n", (unsigned long long)c.streamCacheHits);
    fprintf(f, "CACHE_MISSES=%llu\n", (unsigned long long)c.streamCacheMisses);
    fprintf(f, "CYCLONE_PREFETCH_REQUESTS=%llu\n", (unsigned long long)c.cycloneAcquires);
    fprintf(f, "CYCLONE_PREFETCH_PROMOTIONS=%llu\n",
            (unsigned long long)c.cyclonePrefetchHits);
    fprintf(f, "CYCLONE_STALL_CYCLES=%llu\n", (unsigned long long)c.cycloneStallCycles);
    fprintf(f, "PINBALL_BOOST_TRIGGERS=%u\n", c.pinballBoostTriggers);
    fprintf(f, "REVERSAL_PREFETCH_BOOSTS=%u\n",
            (c.reversalUsPerToken >= 800.f) ? c.pinballBoostTriggers : 0u);
    fprintf(f, "QUEUE_PEAK=%u\n", c.cycloneQueuePeak);
    fprintf(f, "PER_TOKEN_ALLOCS=%llu\n", (unsigned long long)c.perTokenAllocs);
    fprintf(f, "FALLBACK_COUNT=%llu\n", (unsigned long long)c.fallbackCount);
    fprintf(f, "TRAILBRAKE_CHECKS=%u\n", c.trailbrakeChecks);
    fprintf(f, "TRAILBRAKE_TRIGGERED=%u\n", c.trailbrakeTriggered);
    fprintf(f, "TRAILBRAKE_TOKENS_AVOIDED=%u\n", c.trailbrakeTokensAvoided);
    fprintf(f, "ABSENCE_NVME=%u\n", c.nvmeAbsence);
    fprintf(f, "ABSENCE_PLASMA=%u\n", c.plasmaAbsence);
    Fused_Emit(f);
    NU_LiveEmit(f);
    // TPS reverse-scale witness (0.313→313; TPB 2e-8→BPT).
    TpsScale_Emit(f, 0, 0.0, StreamTransfer_BptForNormTps() > 0.0
                   ? (1.0 / StreamTransfer_BptForNormTps()) : 0.0);
    fflush(f);
}

} // namespace Deep2
