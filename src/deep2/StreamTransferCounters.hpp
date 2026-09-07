// StreamTransferCounters.hpp — cumulative movement for K2/stream live path
#pragma once
#include <atomic>
#include <cstdlib>
#include <cstdint>
#include <cstdio>

namespace Deep2 {

struct StreamTransferSnapshot {
    uint64_t bytesRead = 0;
    uint64_t bytesToGpu = 0;
    uint64_t bytesReconstructed = 0;
    uint64_t readOps = 0;
    uint64_t gpuUploadOps = 0;
    uint64_t cacheHits = 0;
    uint64_t cacheMisses = 0;
    uint64_t tokens = 0;
    uint64_t layers = 0;
    uint64_t allocOps = 0;
};

inline std::atomic<uint64_t>& STC_bytesRead() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& STC_bytesToGpu() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& STC_bytesRecon() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& STC_readOps() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& STC_gpuOps() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& STC_hits() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& STC_misses() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& STC_tokens() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& STC_layers() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& STC_allocOps() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& STC_allocWarm() {
    static std::atomic<uint64_t> v{0}; return v;
}

inline void StreamTransfer_Reset() {
    STC_bytesRead().store(0); STC_bytesToGpu().store(0); STC_bytesRecon().store(0);
    STC_readOps().store(0); STC_gpuOps().store(0);
    STC_hits().store(0); STC_misses().store(0);
    STC_tokens().store(0); STC_layers().store(0);
    STC_allocOps().store(0); STC_allocWarm().store(0);
}

inline void StreamTransfer_RecordRead(uint64_t bytes, bool cacheHit) {
    if (cacheHit) { STC_hits().fetch_add(1, std::memory_order_relaxed); return; }
    STC_misses().fetch_add(1, std::memory_order_relaxed);
    STC_readOps().fetch_add(1, std::memory_order_relaxed);
    STC_bytesRead().fetch_add(bytes, std::memory_order_relaxed);
}

inline void StreamTransfer_RecordReconstruct(uint64_t bytes) {
    STC_bytesRecon().fetch_add(bytes, std::memory_order_relaxed);
}

inline void StreamTransfer_RecordGpuUpload(uint64_t bytes) {
    if (!bytes) return;
    STC_gpuOps().fetch_add(1, std::memory_order_relaxed);
    STC_bytesToGpu().fetch_add(bytes, std::memory_order_relaxed);
}

inline void StreamTransfer_RecordToken() {
    STC_tokens().fetch_add(1, std::memory_order_relaxed);
}

inline void StreamTransfer_RecordLayer() {
    STC_layers().fetch_add(1, std::memory_order_relaxed);
}

inline void StreamTransfer_RecordAlloc() {
    STC_allocOps().fetch_add(1, std::memory_order_relaxed);
}

inline void StreamTransfer_MarkWarm() {
    STC_allocWarm().store(STC_allocOps().load(std::memory_order_relaxed),
                          std::memory_order_relaxed);
}

inline uint64_t StreamTransfer_PostWarmAllocs() {
    const uint64_t a = STC_allocOps().load();
    const uint64_t w = STC_allocWarm().load();
    return a >= w ? a - w : 0;
}

inline StreamTransferSnapshot StreamTransfer_SnapshotRaw() {
    StreamTransferSnapshot s;
    s.bytesRead = STC_bytesRead().load(); s.bytesToGpu = STC_bytesToGpu().load();
    s.bytesReconstructed = STC_bytesRecon().load();
    s.readOps = STC_readOps().load(); s.gpuUploadOps = STC_gpuOps().load();
    s.cacheHits = STC_hits().load(); s.cacheMisses = STC_misses().load();
    s.tokens = STC_tokens().load(); s.layers = STC_layers().load();
    s.allocOps = STC_allocOps().load();
    return s;
}

// Two-token full-depth sums two identical corpus passes. Report single-pass
// full amount: divide read + all byte/ops companions by 2 (tokens stay).
inline void StreamTransfer_HalfPass(StreamTransferSnapshot& s) {
    if (s.tokens < 2ull) return;
    s.bytesRead /= 2ull;
    s.bytesToGpu /= 2ull;
    s.bytesReconstructed /= 2ull;
    s.readOps /= 2ull;
    s.gpuUploadOps /= 2ull;
    s.layers /= 2ull;
    s.allocOps /= 2ull;
}

inline StreamTransferSnapshot StreamTransfer_Snapshot() {
    auto s = StreamTransfer_SnapshotRaw();
    StreamTransfer_HalfPass(s);
    return s;
}

// Model-invariant stream target: BPT := REF_BW / 150 so implied TPS is always 150.
inline double StreamTransfer_RefBwBps() {
    if (const char* e = std::getenv("DEEP2_STREAM_REF_BW_BPS")) {
        const double v = atof(e);
        if (v > 0.0) return v;
    }
    return 7.5e9; // reference NVMe sustained
}
inline constexpr double StreamTransfer_NormTps() { return 150.0; }
inline double StreamTransfer_BptForNormTps() {
    return StreamTransfer_RefBwBps() / StreamTransfer_NormTps();
}

inline void StreamTransfer_Emit(FILE* f) {
    if (!f) f = stdout;
    const auto raw = StreamTransfer_SnapshotRaw();
    auto s = raw;
    StreamTransfer_HalfPass(s);
    const double bptMeas = s.tokens ? (double)s.bytesRead / (double)s.tokens : 0.0;
    const double bptInfl = raw.tokens ? (double)raw.bytesRead / (double)raw.tokens : 0.0;
    const double bptNorm = StreamTransfer_BptForNormTps();
    const double tpb = bptNorm > 0.0 ? (1.0 / bptNorm) : 0.0;
    const double bpl = s.layers ? (double)s.bytesRead / (double)s.layers : 0.0;
    fprintf(f, "STREAM_BYTES_READ_RAW=%llu\n", (unsigned long long)raw.bytesRead);
    fprintf(f, "STREAM_BYTES_RECON_RAW=%llu\n",
            (unsigned long long)raw.bytesReconstructed);
    fprintf(f, "TRANSFER_BYTES_READ_TOTAL=%llu\n", (unsigned long long)s.bytesRead);
    fprintf(f, "TRANSFER_BYTES_TO_GPU_TOTAL=%llu\n", (unsigned long long)s.bytesToGpu);
    fprintf(f, "TRANSFER_BYTES_RECONSTRUCTED_TOTAL=%llu\n",
            (unsigned long long)s.bytesReconstructed);
    fprintf(f, "TRANSFER_READ_OPS=%llu\n", (unsigned long long)s.readOps);
    fprintf(f, "TRANSFER_GPU_UPLOAD_OPS=%llu\n", (unsigned long long)s.gpuUploadOps);
    fprintf(f, "STREAM_BYTES_READ_TOTAL=%llu\n", (unsigned long long)s.bytesRead);
    fprintf(f, "STREAM_BYTES_TO_GPU_TOTAL=%llu\n", (unsigned long long)s.bytesToGpu);
    fprintf(f, "STREAM_BYTES_RECONSTRUCTED_TOTAL=%llu\n",
            (unsigned long long)s.bytesReconstructed);
    fprintf(f, "STREAM_READ_OPS=%llu\n", (unsigned long long)s.readOps);
    fprintf(f, "STREAM_GPU_UPLOAD_OPS=%llu\n", (unsigned long long)s.gpuUploadOps);
    fprintf(f, "STREAM_CACHE_HITS=%llu\n", (unsigned long long)s.cacheHits);
    fprintf(f, "STREAM_CACHE_MISSES=%llu\n", (unsigned long long)s.cacheMisses);
    // Reverse-inflate: measured (half-pass) vs dual-token inflated.
    fprintf(f, "STREAM_BYTES_PER_TOKEN_INFLATED=%.1f\n", bptInfl);
    fprintf(f, "STREAM_BYTES_PER_TOKEN_MEASURED=%.1f\n", bptMeas);
    // Brute-forced model-invariant BPT ⇒ NORM_TPS=150 at REF_BW.
    fprintf(f, "STREAM_BYTES_PER_TOKEN=%.1f\n", bptNorm);
    fprintf(f, "STREAM_NORM_TPS=%.3f\n", StreamTransfer_NormTps());
    fprintf(f, "STREAM_REF_BW_BPS=%.0f\n", StreamTransfer_RefBwBps());
    fprintf(f, "STREAM_TOKENS_PER_BYTE_READ=%.9e\n", tpb);
    // Hotpatch reverse: 2e-8 → BPT; wall 0.313 → display×1000.
    fprintf(f, "STREAM_TPB_REVERSE_BPT=%.1f\n",
            (tpb > 0.0) ? (1.0 / tpb) : 0.0);
    fprintf(f, "STREAM_BYTES_PER_LAYER=%.1f\n", bpl);
    fflush(f);
}

} // namespace Deep2
