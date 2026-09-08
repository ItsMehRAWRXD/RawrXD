// K2MlaStageTiming.hpp — split MLA_COMPUTE into QKV / KV_EXPAND / ATTN / O
// QKV further splits into Q_A / Q_B / KV_A + topology overlap probes.
#pragma once
#include "K2MLA_GpuGemv.hpp"
#include "K2MlaQBranchTiming.hpp"
#include "K2MlaOProjTiming.hpp"
#include "K2MlaQkvTiming.hpp"
#include "lavapath/LiveInGenTune.hpp"
#include "StreamPathTiming.hpp"
#include <algorithm>
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
// Topology: branch walls + join bubble under GPU Q || host KV (or reverse).
inline std::atomic<uint64_t>& MlaStage_QBranchUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& MlaStage_KvBranchUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& MlaStage_QkvJoinUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& MlaStage_QkvOverlapUs() {
    static std::atomic<uint64_t> v{0}; return v;
}
inline std::atomic<uint64_t>& MlaStage_QkvBubbleUs() {
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
    MlaStage_QBranchUs().store(0);
    MlaStage_KvBranchUs().store(0);
    MlaStage_QkvJoinUs().store(0);
    MlaStage_QkvOverlapUs().store(0);
    MlaStage_QkvBubbleUs().store(0);
    QBr_Reset();
    OProj_Reset();
    Qkv_Reset();
    rawr::live::ResetLiveTune();
}

inline void MlaStage_NoteSplitTopology(uint64_t wallUs, uint64_t qBranchUs,
                                       uint64_t kvBranchUs, uint64_t joinUs) {
    MlaStage_QBranchUs().fetch_add(qBranchUs, std::memory_order_relaxed);
    MlaStage_KvBranchUs().fetch_add(kvBranchUs, std::memory_order_relaxed);
    MlaStage_QkvJoinUs().fetch_add(joinUs, std::memory_order_relaxed);
    const uint64_t sum = qBranchUs + kvBranchUs;
    const uint64_t mx = (std::max)(qBranchUs, kvBranchUs);
    if (sum > wallUs)
        MlaStage_QkvOverlapUs().fetch_add(sum - wallUs, std::memory_order_relaxed);
    if (wallUs > mx)
        MlaStage_QkvBubbleUs().fetch_add(wallUs - mx, std::memory_order_relaxed);
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
    const uint64_t qBr = MlaStage_QBranchUs().load();
    const uint64_t kvBr = MlaStage_KvBranchUs().load();
    const uint64_t join = MlaStage_QkvJoinUs().load();
    const uint64_t ov = MlaStage_QkvOverlapUs().load();
    const uint64_t bub = MlaStage_QkvBubbleUs().load();
    const uint64_t sum = q + k + a + o;
    const uint64_t mla = SPT_mla().load();
    const char* owner = "QKV_PROJ";
    uint64_t best = q;
    if (k > best) { best = k; owner = "KV_EXPAND"; }
    if (a > best) { best = a; owner = "ATTN"; }
    if (o > best) { best = o; owner = "O_PROJ"; }
    const char* qOwner = "q_a";
    uint64_t qBest = qa;
    if (qb > qBest) { qBest = qb; qOwner = "q_b"; }
    if (kva > qBest) { qBest = kva; qOwner = "kv_a"; }
    const uint64_t qkvUp = MLA_UploadQ() + MLA_UploadK();
    const uint64_t qkvHit = MLA_HitQ() + MLA_HitK();
    const uint64_t qkvFail = MLA_GpuGemvFail();
    const uint64_t brMax = (std::max)(qBr, kvBr);
    const double wallVsMax =
        brMax ? (double)q / (double)brMax : 0.0;
    // Routing: under overlap, critical-path branch owns — not component kv_a.
    const char* critOwner = (qBr >= kvBr) ? "Q_BRANCH" : "KV_BRANCH";
    fprintf(f,
            "MLA_STAGE_QKV_US=%llu MLA_STAGE_KV_EXPAND_US=%llu "
            "MLA_STAGE_ATTN_US=%llu MLA_STAGE_O_PROJ_US=%llu\n"
            "MLA_STAGE_SUM_US=%llu MLA_COMPUTE_US=%llu "
            "MLA_STAGE_OWNER=%s OWNER_US=%llu\n"
            "MLA_QA_US=%llu MLA_QB_US=%llu MLA_KVA_US=%llu "
            "MLA_QKV_PROJ_US=%llu\n"
            "MLA_QKV_PROJ_OWNER=%s SUB_OWNER_US=%llu "
            "(component; not routing)\n"
            "MLA_QKV_CRITICAL_OWNER=%s\n"
            "MLA_QKV_UPLOADS=%llu MLA_QKV_HITS=%llu MLA_QKV_FAIL=%llu\n"
            "Q_BRANCH_US=%llu KV_BRANCH_US=%llu QKV_JOIN_US=%llu\n"
            "QKV_OVERLAP_US=%llu QKV_BUBBLE_US=%llu "
            "QKV_WALL_VS_MAX_BRANCH=%.3f\n",
            (unsigned long long)q, (unsigned long long)k,
            (unsigned long long)a, (unsigned long long)o,
            (unsigned long long)sum, (unsigned long long)mla, owner,
            (unsigned long long)best,
            (unsigned long long)qa, (unsigned long long)qb,
            (unsigned long long)kva, (unsigned long long)q,
            qOwner, (unsigned long long)qBest, critOwner,
            (unsigned long long)qkvUp, (unsigned long long)qkvHit,
            (unsigned long long)qkvFail,
            (unsigned long long)qBr, (unsigned long long)kvBr,
            (unsigned long long)join,
            (unsigned long long)ov, (unsigned long long)bub, wallVsMax);
    QBr_Emit(f);
    Qkv_Emit(f);
    OProj_Emit(f);
    fflush(f);
}

} // namespace Deep2
