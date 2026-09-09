#pragma once
/* Name SPIN_CLOSE wall owner from live counters. Rank→NEXT; no KVA reopen. ≤99 */
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
    const uint64_t attn = MlaStage_AttnUs().load();
    const uint64_t kva = MlaStage_KvaUs().load();
    const uint64_t qa = MlaStage_QaUs().load();
    const uint64_t qb = MlaStage_QbUs().load();
    const uint64_t qBr = MlaStage_QBranchUs().load();
    const uint64_t kvBr = MlaStage_KvBranchUs().load();
    const uint64_t oExpUs = OProj_WallUs().load() ? OProj_WallUs().load()
                                                 : MlaStage_OProjUs().load();
    const uint64_t logitsExp = SPT_logits().load();
    const uint64_t sampleExp = SPT_sample().load();
    const uint64_t resExp = SPT_shardRead().load();
    const uint64_t awaitUs = OProj_WaitUs().load();
    const uint64_t kvaExp = (kvBr > qBr) ? kva : 0ull;

    const char* stage = "QKV";
    uint64_t best = qkv;
    if (attn > best) {
        best = attn;
        stage = "ATTENTION";
    }
    if (kvaExp > best) {
        best = kvaExp;
        stage = "KVA";
    }
    if (oExpUs > best) {
        best = oExpUs;
        stage = "O_PROJ";
    }
    if (logitsExp > best) {
        best = logitsExp;
        stage = "LOGITS";
    }
    if (sampleExp > best) {
        best = sampleExp;
        stage = "SAMPLE";
    }
    if (resExp > best) {
        best = resExp;
        stage = "OTHER";
    }

    const char* leaf = stage;
    uint64_t leafUs = best;
    const char* next = "INSPECT_OWNER";
    if (stage[0] == 'Q') {
        leaf = (qBr >= kvBr) ? ((qb >= qa) ? "q_b" : "q_a") : "kv_a";
        leafUs = (qBr >= kvBr) ? ((qb >= qa) ? qb : qa) : (kva ? kva : kvBr);
        next = "QKV_EXPOSURE_CUT";
    } else if (stage[0] == 'A') {
        next = "ATTENTION_EXPOSURE_CUT";
    } else if (stage[0] == 'K') {
        next = "KVA_EXPOSURE_AUDIT_ONLY";
    } else if (stage[0] == 'O') {
        leaf = "O_PROJ_SERIAL";
        leafUs = oExpUs;
        next = "O_PROJ_OVERLAP";
    } else if (stage[0] == 'L') {
        leaf = "LOGITS_CPU_GPU_SPLIT";
        leafUs = logitsExp;
        next = "LOGITS_SPLIT_CUT";
    } else if (stage[0] == 'S') {
        next = "SAMPLE_CUT";
    } else {
        leaf = "SHARD_READ";
        leafUs = resExp;
        next = "RESIDENCY_CUT";
    }

    std::fprintf(f, "RAWRXD_SPIN_CLOSE_WALL_ATTRIB_001=1\n");
    std::fprintf(f, "KVA_ROWS_CLIMB=SEALED\nDO_NOT_REOPEN=KvaInversion\n");
    std::fprintf(f, "QKV_EXPOSED_US=%llu\nKVA_EXPOSED_US=%llu\n",
                 (unsigned long long)qkv, (unsigned long long)kvaExp);
    std::fprintf(f, "ATTENTION_EXPOSED_US=%llu\nO_PROJ_EXPOSED_US=%llu\n",
                 (unsigned long long)attn, (unsigned long long)oExpUs);
    std::fprintf(f, "LOGITS_EXPOSED_US=%llu\nSAMPLE_EXPOSED_US=%llu\n",
                 (unsigned long long)logitsExp, (unsigned long long)sampleExp);
    std::fprintf(f, "OTHER_EXPOSED_US=%llu\nAWAIT_EXPOSED_US=%llu\n",
                 (unsigned long long)resExp, (unsigned long long)awaitUs);
    std::fprintf(f, "SPIN_CLOSE_BLOCKER=%s\nSPIN_CLOSE_BLOCKER_OWNER=%s\n",
                 stage, leaf);
    std::fprintf(f, "SPIN_CLOSE_BLOCKER_US=%llu\nSPIN_CLOSE_STAGE_US=%llu\n",
                 (unsigned long long)leafUs, (unsigned long long)best);
    std::fprintf(f, "MEASURED_LARGEST_OWNER=%s\n", leaf);
    std::fprintf(f, "NEXT_RUNTIME_ACTION=%s\n", next);
    std::fprintf(f, "LOGITS_SPLIT_CUT=%s\n",
                 stage[0] == 'L' ? "ACTIVE" : "NOT_LARGEST");
    std::fflush(f);
}

} // namespace rawr::spin_close
