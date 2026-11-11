// StreamPathTiming.hpp — wall-component us (K2 stream lane only)
#pragma once
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {

inline std::atomic<uint64_t>& SPT_shardOpen() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_shardRead() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_cacheLookup() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_cacheHit() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_layerWait() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_recon() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_outW() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_mla() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_logits() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_sample() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_stream() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_hostCopy() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_shardAttn() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_shardMoe() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_shardOther() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_tokenize() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_ttft() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_detok() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_reqStartUs() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_logitsCalls() { static std::atomic<uint64_t> v{0}; return v; }
inline std::atomic<uint64_t>& SPT_logitsRows() { static std::atomic<uint64_t> v{0}; return v; }

inline void StreamPathTiming_Reset() {
    SPT_shardOpen().store(0); SPT_shardRead().store(0);
    SPT_cacheLookup().store(0); SPT_cacheHit().store(0);
    SPT_layerWait().store(0); SPT_recon().store(0); SPT_outW().store(0);
    SPT_mla().store(0); SPT_logits().store(0); SPT_sample().store(0);
    SPT_stream().store(0);
    SPT_hostCopy().store(0);
    SPT_shardAttn().store(0); SPT_shardMoe().store(0); SPT_shardOther().store(0);
    SPT_tokenize().store(0); SPT_ttft().store(0); SPT_detok().store(0);
    SPT_reqStartUs().store(0);
    SPT_logitsCalls().store(0); SPT_logitsRows().store(0);
}

inline uint64_t StreamPathTiming_NowUs() {
#ifdef _WIN32
    static LARGE_INTEGER f{};
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    LARGE_INTEGER c; QueryPerformanceCounter(&c);
    return (uint64_t)((c.QuadPart * 1000000ull) / (uint64_t)f.QuadPart);
#else
    return 0;
#endif
}
inline void StreamPathTiming_Add(std::atomic<uint64_t>& a, uint64_t t0) {
    const uint64_t dt = StreamPathTiming_NowUs() - t0;
    if (dt < (1ull << 40)) a.fetch_add(dt, std::memory_order_relaxed);
}

inline void StreamPathTiming_Emit(FILE* f) {
    if (!f) f = stdout;
    const uint64_t shard = SPT_shardRead().load();
    const uint64_t outW = SPT_outW().load();
    const uint64_t mla = SPT_mla().load();
    const uint64_t logits = SPT_logits().load();
    fprintf(f, "SHARD_OPEN_US=%llu\n", (unsigned long long)SPT_shardOpen().load());
    fprintf(f, "SHARD_READ_US=%llu\n", (unsigned long long)shard);
    fprintf(f, "CACHE_LOOKUP_US=%llu\n", (unsigned long long)SPT_cacheLookup().load());
    fprintf(f, "CACHE_HIT_US=%llu\n", (unsigned long long)SPT_cacheHit().load());
    fprintf(f, "LAYER_ACQUIRE_WAIT_US=%llu\n", (unsigned long long)SPT_layerWait().load());
    fprintf(f, "RECONSTRUCT_US=%llu\n", (unsigned long long)SPT_recon().load());
    fprintf(f, "OUTPUT_WEIGHT_US=%llu\n", (unsigned long long)outW);
    fprintf(f, "MLA_COMPUTE_US=%llu\n", (unsigned long long)mla);
    fprintf(f, "LOGITS_US=%llu\n", (unsigned long long)logits);
    fprintf(f, "SAMPLE_US=%llu\n", (unsigned long long)SPT_sample().load());
    fprintf(f, "STREAM_US=%llu\n", (unsigned long long)SPT_stream().load());
    fprintf(f, "DETOK_US=%llu\n", (unsigned long long)SPT_detok().load());
    const uint64_t hostCopy = SPT_hostCopy().load();
    const uint64_t shAttn = SPT_shardAttn().load();
    const uint64_t shMoe = SPT_shardMoe().load();
    const uint64_t shOth = SPT_shardOther().load();
    fprintf(f, "HOST_CACHE_COPY_US=%llu\n", (unsigned long long)hostCopy);
    fprintf(f, "SHARD_ATTN_US=%llu SHARD_MOE_US=%llu SHARD_OTHER_US=%llu\n",
            (unsigned long long)shAttn, (unsigned long long)shMoe,
            (unsigned long long)shOth);
    const char* fe = std::getenv("DEEP2_MLA_FUSED_Q4KT");
    const bool fusedOn = !fe || fe[0] != '0';
    const char* mlaId = fusedOn ? "MLA_ATTN_KV_EXPAND" : "MLA_FUSED_Q4KT";
    const char* shardId = "SHARD_READ_IO";
    if (shAttn >= shMoe && shAttn >= shOth && shAttn > 0) shardId = "SHARD_ATTN_IO";
    else if (shMoe >= shAttn && shMoe >= shOth && shMoe > 0) shardId = "SHARD_MOE_IO";
    else if (shOth > 0) shardId = "SHARD_OTHER_IO";
    struct Lane { const char* id; uint64_t us; };
    Lane lanes[5] = {{mlaId, mla}, {"LOGITS_Q6K", logits},
                     {"OUTPUT_WEIGHT_IO", outW}, {shardId, shard},
                     {"HOST_CACHE_COPY", hostCopy}};
    int best = 0;
    for (int i = 1; i < 5; ++i)
        if (lanes[i].us > lanes[best].us) best = i;
    fprintf(f, "NEXT_BEST_MOVE=%s\n", lanes[best].id);
    fprintf(f, "NEXT_BEST_MOVE_US=%llu\n", (unsigned long long)lanes[best].us);
    fprintf(f, "RE_MANIFEST=MLA=%llu,LOGITS=%llu,OUT_W=%llu,SHARD=%llu,COPY=%llu\n",
            (unsigned long long)mla, (unsigned long long)logits,
            (unsigned long long)outW, (unsigned long long)shard,
            (unsigned long long)hostCopy);
    fflush(f);
}

} // namespace Deep2
