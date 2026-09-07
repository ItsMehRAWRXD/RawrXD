// K2MlaStageTiming.hpp — split MLA_COMPUTE into QKV / KV_EXPAND / ATTN / O
// QKV further splits into Q_A / Q_B / KV_A for owner climb.
#pragma once
#include "K2MLA_GpuGemv.hpp"
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
inline std::atomic<uint64_t>& MlaStage_QaUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& MlaStage_QbUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& MlaStage_KvaUs() {
    static std::atomic<uint64_t> v{0}; return v;
}

inline void MlaStage_Reset() {
    MlaStage_QkvUs().store(0);
    MlaStage_KvExpandUs().store(0);
    MlaStage_AttnUs().store(0);
    MlaStage_OProjUs().store(0);
    MlaStage_QaUs().store(0);
    MlaStage_QbUs().store(0);
    MlaStage_KvaUs().store(0);
}

inline void MlaStage_Emit(FILE* f) {
    if (!f) f = stdout;
    const uint64_t q = MlaStage_QkvUs().load();
    const uint64_t k = MlaStage_KvExpandUs().load();
    const uint64_t a = MlaStage_AttnUs().load();
    const uint64_t o = MlaStage_OProjUs().load();
    const uint64_t qa = MlaStage_QaUs().load();
    const uint64_t qb = MlaStage_QbUs().load();
    const uint64_t kva = MlaStage_KvaUs().load();
    const uint64_t sum = q + k + a + o;
    const uint64_t mla = SPT_mla().load();
    const char* owner = "QKV_PROJ";
    uint64_t best = q;
    if (k > best) { best = k; owner = "KV_EXPAND"; }
    if (a > best) { best = a; owner = "ATTN"; }
    if (o > best) { best = o; owner = "O_PROJ"; }
    // Owner names match climb brief: q_a | q_b | kv_a
    const char* qOwner = "q_a";
    uint64_t qBest = qa;
    if (qb > qBest) { qBest = qb; qOwner = "q_b"; }
    if (kva > qBest) { qBest = kva; qOwner = "kv_a"; }
    // QKV uploads: pin tags 1/2 (Q) + 3 (KV_A). With host fused KV expand,
    // UploadK is dominated by kv_a (tag 4 expand stays off GPU).
    const uint64_t qkvUp = MLA_UploadQ() + MLA_UploadK();
    const uint64_t qkvHit = MLA_HitQ() + MLA_HitK();
    const uint64_t qkvFail = MLA_GpuGemvFail();
    fprintf(f,
            "MLA_STAGE_QKV_US=%llu MLA_STAGE_KV_EXPAND_US=%llu "
            "MLA_STAGE_ATTN_US=%llu MLA_STAGE_O_PROJ_US=%llu\n"
            "MLA_STAGE_SUM_US=%llu MLA_COMPUTE_US=%llu "
            "MLA_STAGE_OWNER=%s OWNER_US=%llu\n"
            "MLA_QA_US=%llu MLA_QB_US=%llu MLA_KVA_US=%llu "
            "MLA_QKV_PROJ_US=%llu\n"
            "MLA_QKV_PROJ_OWNER=%s SUB_OWNER_US=%llu\n"
            "MLA_QKV_UPLOADS=%llu MLA_QKV_HITS=%llu MLA_QKV_FAIL=%llu\n",
            (unsigned long long)q, (unsigned long long)k,
            (unsigned long long)a, (unsigned long long)o,
            (unsigned long long)sum, (unsigned long long)mla, owner,
            (unsigned long long)best,
            (unsigned long long)qa, (unsigned long long)qb,
            (unsigned long long)kva, (unsigned long long)q,
            qOwner, (unsigned long long)qBest,
            (unsigned long long)qkvUp, (unsigned long long)qkvHit,
            (unsigned long long)qkvFail);
    fflush(f);
}

} // namespace Deep2
