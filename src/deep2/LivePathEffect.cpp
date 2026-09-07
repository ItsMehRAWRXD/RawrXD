// LivePathEffect.cpp — emit A/B snapshots + deltas
#include "LivePathEffect.hpp"
#include "StreamTransferCounters.hpp"
#include "TpsScaleHotpatch.hpp"

namespace Deep2 {

void LivePath_FillEffectFromCounters(LivePathEffectSnap& s) {
    const auto& c = LivePath_Counters();
    const auto x = StreamTransfer_Snapshot();
    s.enhancements = c.enhancementsEnabled;
    // Prefer STC for physical transfer; LivePath mirrors after EndGenerate.
    if (x.bytesRead || x.readOps || x.gpuUploadOps) {
        s.streamBytesRead = x.bytesRead;
        s.streamBytesToGpu = x.bytesToGpu;
        s.streamBytesRecon = x.bytesReconstructed;
        s.streamReadOps = x.readOps;
        s.streamGpuUploadOps = x.gpuUploadOps;
        s.cacheHits = x.cacheHits;
        s.cacheMisses = x.cacheMisses;
        if (s.tokens > 0)
            s.streamBytesPerToken = StreamTransfer_BptForNormTps();
    } else if (c.streamBytesRead || c.streamReadOps) {
        s.streamBytesRead = c.streamBytesRead;
        s.streamBytesToGpu = c.streamBytesToGpu;
        s.streamBytesRecon = c.streamBytesReconstructed;
        s.streamReadOps = c.streamReadOps;
        s.streamGpuUploadOps = c.streamGpuUploadOps;
        s.cacheHits = c.streamCacheHits;
        s.cacheMisses = c.streamCacheMisses;
    }
    if (!s.vramPeak) s.vramPeak = c.vramPeak;
    if (!s.residentWeightPeak) s.residentWeightPeak = c.residentWeightPeak;
    s.prefetchRequests = c.cycloneAcquires;
    s.prefetchPromotions = c.cyclonePrefetchHits;
    s.activeCycles = c.cycloneActiveCycles;
    s.stallCycles = c.cycloneStallCycles;
    s.queuePeak = c.cycloneQueuePeak;
    s.pinballSamples = c.pinballSamples;
    s.pinballBoostTriggers = c.pinballBoostTriggers;
    s.pinballLookaheadMax = c.pinballLookaheadMax;
    s.reversalUsTotal = (double)c.reversalUsPerToken * (double)s.tokens;
    s.reversalPrefetchBoosts =
        (c.reversalUsPerToken >= 800.f) ? c.pinballBoostTriggers : 0;
    s.trailbrakeChecks = c.trailbrakeChecks;
    s.trailbrakeTriggered = c.trailbrakeTriggered;
    s.trailbrakeTokensAvoided = c.trailbrakeTokensAvoided;
    if (!s.perTokenAllocs) s.perTokenAllocs = c.perTokenAllocs;
    if (!s.fallbackCount) s.fallbackCount = c.fallbackCount;
    s.nvmeHops = c.nvmeHops;
    s.nvmeAbsence = c.nvmeAbsence;
    s.plasmaSamples = c.plasmaSamples;
    s.plasmaAbsence = c.plasmaAbsence;
}

void LivePath_EmitEffect(FILE* f, const char* label, const LivePathEffectSnap& s) {
    if (!f) f = stdout;
    fprintf(f, "=== %s enhancements=%u ===\n", label ? label : "RUN", s.enhancements);
    fprintf(f, "PERF WALL_MS=%.3f DECODE_TPS=%.3f DECODE_TPS_DISPLAY=%.1f TOKENS=%u DEPTH=%u\n",
            s.wallMs, s.decodeTps, TpsScale_Display(s.decodeTps), s.tokens, s.layerDepth);
    fprintf(f, "STREAM_BYTES_READ_TOTAL=%llu\n", (unsigned long long)s.streamBytesRead);
    fprintf(f, "STREAM_BYTES_TO_GPU_TOTAL=%llu\n", (unsigned long long)s.streamBytesToGpu);
    fprintf(f, "STREAM_BYTES_RECONSTRUCTED_TOTAL=%llu\n",
            (unsigned long long)s.streamBytesRecon);
    fprintf(f, "STREAM_READ_OPS=%llu\n", (unsigned long long)s.streamReadOps);
    fprintf(f, "STREAM_GPU_UPLOAD_OPS=%llu\n", (unsigned long long)s.streamGpuUploadOps);
    fprintf(f, "VRAM_PEAK=%llu\n", (unsigned long long)s.vramPeak);
    fprintf(f, "RESIDENT_WEIGHT_PEAK=%llu\n", (unsigned long long)s.residentWeightPeak);
    fprintf(f, "CACHE_HITS=%llu\n", (unsigned long long)s.cacheHits);
    fprintf(f, "CACHE_MISSES=%llu\n", (unsigned long long)s.cacheMisses);
    fprintf(f, "CYCLONE_PREFETCH_REQUESTS=%llu\n", (unsigned long long)s.prefetchRequests);
    fprintf(f, "CYCLONE_PREFETCH_PROMOTIONS=%llu\n",
            (unsigned long long)s.prefetchPromotions);
    fprintf(f, "CYCLONE_STALL_CYCLES=%llu\n", (unsigned long long)s.stallCycles);
    fprintf(f, "PINBALL_BOOST_TRIGGERS=%u\n", s.pinballBoostTriggers);
    fprintf(f, "REVERSAL_PREFETCH_BOOSTS=%u\n", s.reversalPrefetchBoosts);
    fprintf(f, "WARMUP_EXPERT_HITS=%llu\n", (unsigned long long)s.expertHits);
    fprintf(f, "QUEUE_PEAK=%u\n", s.queuePeak);
    fprintf(f, "PER_TOKEN_ALLOCS=%llu\n", (unsigned long long)s.perTokenAllocs);
    fprintf(f, "FALLBACK_COUNT=%llu\n", (unsigned long long)s.fallbackCount);
    fprintf(f, "BYTES_PER_TOKEN=%.1f\n", s.streamBytesPerToken);
    fprintf(f, "STREAM_NORM_TPS=%.3f\n", StreamTransfer_NormTps());
    fprintf(f, "STREAM_REF_BW_BPS=%.0f\n", StreamTransfer_RefBwBps());
    // Reverse of cost: tokens per brute-forced BPT byte.
    const double tpb = (s.streamBytesPerToken > 0.0)
        ? (1.0 / s.streamBytesPerToken) : 0.0;
    fprintf(f, "TOKENS_PER_BYTE_READ=%.9e\n", tpb);
    fprintf(f, "ABSENCE_NVME=%u\n", s.nvmeAbsence);
    fprintf(f, "ABSENCE_PLASMA=%u\n", s.plasmaAbsence);
    fflush(f);
}

LivePathEffectDelta LivePath_ComputeDelta(const LivePathEffectSnap& a,
                                          const LivePathEffectSnap& b) {
    LivePathEffectDelta d;
    d.tpsDelta = b.decodeTps - a.decodeTps;
    d.bytesPerTokenDelta = b.streamBytesPerToken - a.streamBytesPerToken;
    d.stallDelta = (double)b.stallCycles - (double)a.stallCycles;
    d.vramPeakDelta = (int64_t)b.vramPeak - (int64_t)a.vramPeak;
    const double aHit = (a.cacheHits + a.cacheMisses)
        ? (double)a.cacheHits / (double)(a.cacheHits + a.cacheMisses) : 0.0;
    const double bHit = (b.cacheHits + b.cacheMisses)
        ? (double)b.cacheHits / (double)(b.cacheHits + b.cacheMisses) : 0.0;
    d.cacheHitDelta = bHit - aHit;
    d.prefetchEfficiency = b.prefetchRequests
        ? (double)b.prefetchPromotions / (double)b.prefetchRequests : 0.0;
    return d;
}

void LivePath_EmitDelta(FILE* f, const LivePathEffectDelta& d) {
    if (!f) f = stdout;
    fprintf(f, "TPS_DELTA=%.3f\n", d.tpsDelta);
    fprintf(f, "BYTES_PER_TOKEN_DELTA=%.1f\n", d.bytesPerTokenDelta);
    fprintf(f, "STALL_DELTA=%.0f\n", d.stallDelta);
    fprintf(f, "VRAM_DELTA=%lld\n", (long long)d.vramPeakDelta);
    fprintf(f, "CACHE_HIT_DELTA=%.4f\n", d.cacheHitDelta);
    fprintf(f, "PREFETCH_EFFICIENCY=%.4f\n", d.prefetchEfficiency);
    fflush(f);
}

} // namespace Deep2
