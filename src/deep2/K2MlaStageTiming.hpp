// K2MlaStageTiming.hpp — split MLA_COMPUTE into QKV / KV_EXPAND / ATTN / O
#pragma once
#include "StreamPathTiming.hpp"
#include <atomic>
#include <cstdint>
#include <cstdio>

namespace Deep2 {

inline std::atomic<uint64_t>& MlaStage_QkvUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& MlaStage_KvExpandUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& MlaStage_AttnUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& MlaStage_OProjUs() {
    static std::atomic<uint64_t> v{0}; return v;
}

inline void MlaStage_Reset() {
    MlaStage_QkvUs().store(0);
    MlaStage_KvExpandUs().store(0);
    MlaStage_AttnUs().store(0);
    MlaStage_OProjUs().store(0);
}

inline void MlaStage_Emit(FILE* f) {
    if (!f) f = stdout;
    const uint64_t q = MlaStage_QkvUs().load();
    const uint64_t k = MlaStage_KvExpandUs().load();
    const uint64_t a = MlaStage_AttnUs().load();
    const uint64_t o = MlaStage_OProjUs().load();
    const uint64_t sum = q + k + a + o;
    const uint64_t mla = SPT_mla().load();
    const char* owner = "QKV_PROJ";
    uint64_t best = q;
    if (k > best) { best = k; owner = "KV_EXPAND"; }
    if (a > best) { best = a; owner = "ATTN"; }
    if (o > best) { best = o; owner = "O_PROJ"; }
    fprintf(f,
            "MLA_STAGE_QKV_US=%llu MLA_STAGE_KV_EXPAND_US=%llu "
            "MLA_STAGE_ATTN_US=%llu MLA_STAGE_O_PROJ_US=%llu\n"
            "MLA_STAGE_SUM_US=%llu MLA_COMPUTE_US=%llu "
            "MLA_STAGE_OWNER=%s OWNER_US=%llu\n",
            (unsigned long long)q, (unsigned long long)k,
            (unsigned long long)a, (unsigned long long)o,
            (unsigned long long)sum, (unsigned long long)mla, owner,
            (unsigned long long)best);
    fflush(f);
}

} // namespace Deep2
