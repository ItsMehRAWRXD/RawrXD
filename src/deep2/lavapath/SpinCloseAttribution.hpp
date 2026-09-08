#pragma once
/* Name SPIN_CLOSE wall owner from live MLA/O_PROJ/logits counters.
   DO_NOT_REOPEN KvaInversion. Attribution only — not GEMV microtune. */
#include "K2MlaStageTiming.hpp"
#include "K2MlaOProjTiming.hpp"
#include "StreamPathTiming.hpp"
#include <cstdint>
#include <cstdio>

namespace rawr::spin_close {

inline void Emit(FILE* f = nullptr) noexcept {
    if (!f) f = stdout;
    using namespace Deep2;
    const uint64_t qkv = MlaStage_QkvUs().load();
    const uint64_t kve = MlaStage_KvExpandUs().load();
    const uint64_t attn = MlaStage_AttnUs().load();
    const uint64_t oSt = MlaStage_OProjUs().load();
    const uint64_t qa = MlaStage_QaUs().load();
    const uint64_t qb = MlaStage_QbUs().load();
    const uint64_t kva = MlaStage_KvaUs().load();
    const uint64_t qBr = MlaStage_QBranchUs().load();
    const uint64_t kvBr = MlaStage_KvBranchUs().load();
    const uint64_t oExp = OProj_WallUs().load();
    const uint64_t logits = SPT_logits().load();
    const uint64_t shard = SPT_shardRead().load();
    const uint64_t awaitUs = OProj_WaitUs().load();

    /* Exposed = on critical path (not overlapped under a longer peer). */
    const uint64_t qkvExp = qkv;
    const uint64_t kvaExp = (kvBr > qBr) ? kva : 0ull;
    const uint64_t oExpUs = oExp ? oExp : oSt;
    const uint64_t logitsExp = logits;
    const uint64_t kveExp = kve;
    const uint64_t attnExp = attn;
    const uint64_t resExp = shard;

    const char* stage = "QKV_PROJ";
    uint64_t best = qkvExp;
    if (kveExp > best) {
        best = kveExp;
        stage = "KV_EXPAND";
    }
    if (attnExp > best) {
        best = attnExp;
        stage = "ATTN";
    }
    if (oExpUs > best) {
        best = oExpUs;
        stage = "O_PROJ";
    }
    if (logitsExp > best) {
        best = logitsExp;
        stage = "LOGITS";
    }
    if (resExp > best) {
        best = resExp;
        stage = "RESIDENCY";
    }

    const char* leaf = stage;
    uint64_t leafUs = best;
    if (stage[0] == 'Q') {
        if (qBr >= kvBr) {
            leaf = (qb >= qa) ? "q_b" : "q_a";
            leafUs = (qb >= qa) ? qb : qa;
        } else {
            leaf = "kv_a";
            leafUs = kva ? kva : kvBr;
        }
    } else if (stage[0] == 'O') {
        leaf = "O_PROJ_SERIAL";
        leafUs = oExpUs;
    } else if (stage[0] == 'L') {
        leaf = "LOGITS_SPLIT";
        leafUs = logitsExp;
    } else if (stage[0] == 'K') {
        leaf = "KV_EXPAND";
        leafUs = kveExp;
    } else if (stage[0] == 'R') {
        leaf = "SHARD_READ";
        leafUs = resExp;
    }

    std::fprintf(f, "RAWRXD_CAUSAL_EXPOSURE_ATTRIBUTION_001=1\n");
    std::fprintf(f, "RAWRXD_SPIN_CLOSE_WALL_ATTRIB_001=1\n");
    std::fprintf(f, "KVA_INVERSION_WIRING=RETIRED\n");
    std::fprintf(f, "DO_NOT_REOPEN=KvaInversion\n");
    std::fprintf(f, "QKV_EXPOSED_US=%llu\n", (unsigned long long)qkvExp);
    std::fprintf(f, "KVA_EXPOSED_US=%llu\n", (unsigned long long)kvaExp);
    std::fprintf(f, "O_PROJ_EXPOSED_US=%llu\n", (unsigned long long)oExpUs);
    std::fprintf(f, "SSM_ATTN_EXPOSED_US=0\n");
    std::fprintf(f, "FINAL_NORM_EXPOSED_US=0\n");
    std::fprintf(f, "LOGITS_EXPOSED_US=%llu\n", (unsigned long long)logitsExp);
    std::fprintf(f, "RESIDENCY_EXPOSED_US=%llu\n", (unsigned long long)resExp);
    std::fprintf(f, "AWAIT_EXPOSED_US=%llu\n", (unsigned long long)awaitUs);
    std::fprintf(f, "SPIN_CLOSE_BLOCKER=%s\n", stage);
    std::fprintf(f, "SPIN_CLOSE_BLOCKER_OWNER=%s\n",
                 leaf[0] == 'L' ? "LOGITS_CPU_GPU_SPLIT" : leaf);
    std::fprintf(f, "SPIN_CLOSE_BLOCKER_US=%llu\n",
                 (unsigned long long)leafUs);
    std::fprintf(f, "SPIN_CLOSE_STAGE_US=%llu\n", (unsigned long long)best);
    std::fprintf(f, "MEASURED_LARGEST_OWNER=%s\n",
                 leaf[0] == 'L' ? "LOGITS_CPU_GPU_SPLIT" : leaf);
    /* Policy ≠ rank: declared order drives next delta. */
    std::fprintf(f, "OPTIMIZATION_ORDER_NEXT=REMOVE_KVA_FROM_EXPOSED_CAUSAL_DEPTH\n");
    std::fprintf(f, "THEN=QKV_KVA_TRUE_OVERLAP\n");
    std::fprintf(f, "LOGITS_SPLIT_CUT=DEFERRED\n");
    std::fprintf(f, "NEXT_OWNER=REMOVE_KVA_FROM_EXPOSED_CAUSAL_DEPTH\n");
    std::fprintf(f, "QKV_US=%llu KV_EXPAND_US=%llu ATTN_US=%llu O_PROJ_US=%llu\n",
                 (unsigned long long)qkv, (unsigned long long)kve,
                 (unsigned long long)attn, (unsigned long long)oSt);
    std::fprintf(f, "O_PROJ_OVERLAPPED_US=0\n");
    std::fprintf(f, "LOGITS_US=%llu QA_US=%llu QB_US=%llu KVA_US=%llu\n",
                 (unsigned long long)logits, (unsigned long long)qa,
                 (unsigned long long)qb, (unsigned long long)kva);
    std::fprintf(f,
                 "NEXT_RUNTIME_ACTION=REMOVE_KVA_FROM_EXPOSED_CAUSAL_DEPTH\n");
    std::fflush(f);
}

} // namespace rawr::spin_close
