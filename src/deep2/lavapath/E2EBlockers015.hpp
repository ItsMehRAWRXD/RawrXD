// E2EBlockers015.hpp — RAWRXD_E2E_BLOCKERS_015_LOCK burn-down receipt
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace rawr::e2e15 {

enum class Class : uint8_t { Unfinished = 0, Runtime = 1, NotProduct = 2, Blocked = 3 };

struct Item {
    const char* id;
    Class cls;
    const char* owner;
    const char* note;
};

struct RunFacts {
    int inputAccepted = 0;
    int modelAuthority = 0;
    int runtimeBacked = 0;
    int productionDecode = 0;
    uint64_t hostFwd = 0;
    uint64_t cpuF32 = 0;
    uint64_t tokensReq = 64;
    uint64_t tokensCommitted = 0;
    int streamOut = 0;
    int completionReceipt = 0;
    double decodeTps = 0.0;
    int kvaClimbEmit = 0;     // both CAND lines seen
    int kvaCausal = 0;        // compute/await/residency emitted
    int spinCloseNamed = 0;   // SPIN_CLOSE_BLOCKER != TBD
    int reverseCompletion = 0;
    int noHostFallback = 0;
    int residencyMeasured = 0;
    const char* blockedAt = nullptr;
    const char* blockedOwner = nullptr;
    const char* nextAction = nullptr;
};

inline int CountUnfinished(const Item* items, int n) {
    int u = 0;
    for (int i = 0; i < n; ++i)
        if (items[i].cls == Class::Unfinished) ++u;
    return u;
}

inline const char* ClsStr(Class c) {
    switch (c) {
    case Class::Runtime: return "RUNTIME_BACKED=1";
    case Class::NotProduct: return "NOT_PRODUCT_PATH=1";
    case Class::Blocked: return "BLOCKER=1";
    default: return "UNFINISHED=1";
    }
}

/* Classify from this run's facts — never from law-only files. */
inline void Classify(const RunFacts& f, Item* out15) {
    const Item base[15] = {
        {"01_PRODUCT_5TPS_WALL", Class::Unfinished, "generateStream", "need DECODE_TPS>=5"},
        {"02_KVA_CLIMB_EMIT", Class::Unfinished, "ClimbQ8KvaOnce", "need both CAND lines"},
        {"03_KVA_CAUSAL_OWNER", Class::Unfinished, "kva_inv::EmitFooter", "compute/await/res"},
        {"04_QKV_KVA_FUSION", Class::Unfinished, "MLA fuse", "exposed SPIN depth"},
        {"05_FINAL_NORM_LOGITS_EXPOSED", Class::Unfinished, "logits wall", "same 64 receipt"},
        {"06_SPIN_CLOSE_BLOCKER", Class::Unfinished, "SPIN_CLOSE", "exact owner"},
        {"07_COMPLETION_OUTPUT_RULES", Class::Unfinished, "receipt", "PASS/OPEN/BLOCKED"},
        {"08_REVERSE_COMPLETION", Class::Unfinished, "RawrReverseCompletion", "walk back"},
        {"09_ENV_FAILURE_RECOVERY", Class::NotProduct, "env classifier", "env≠product"},
        {"10_CRASH_SAFE_GENERATESTREAM", Class::Unfinished, "crash identity", "partial receipt"},
        {"11_RUNTIME_VS_LAW_SEPARATION", Class::Runtime, "receipt", "law≠PASS"},
        {"12_HISTORICAL_TPS_PROVENANCE", Class::NotProduct, "PERF_OWNER", "14.x/150 sealed off"},
        {"13_NO_HOST_FALLBACK_REGRESSION", Class::Unfinished, "HOST_FWD", "CPU_F32=0"},
        {"14_RESIDENCY_SCHEDULER_RUNTIME", Class::Unfinished, "BG/BM", "resident subgraph"},
        {"15_PRODUCT_UMBRELLA_SEAL", Class::Unfinished, "deep2_benchmark", "one command"},
    };
    for (int i = 0; i < 15; ++i) out15[i] = base[i];

    if (f.decodeTps >= 5.0 && f.tokensCommitted >= f.tokensReq && f.streamOut)
        out15[0] = {"01_PRODUCT_5TPS_WALL", Class::Runtime, "generateStream", "TPS>=5"};
    else if (f.runtimeBacked && f.streamOut)
        out15[0] = {"01_PRODUCT_5TPS_WALL", Class::Blocked, "WALL_WITHIN_BUDGET",
                    "raise DECODE_TPS_REAL to >=5"};

    if (f.kvaClimbEmit)
        out15[1] = {"02_KVA_CLIMB_EMIT", Class::Runtime, "ClimbQ8KvaOnce", "CAND 16+64"};
    if (f.kvaCausal)
        out15[2] = {"03_KVA_CAUSAL_OWNER", Class::Runtime, "kva_inv", "attribution"};
    if (f.spinCloseNamed)
        out15[5] = {"06_SPIN_CLOSE_BLOCKER", Class::Runtime, "SPIN_CLOSE", "named"};
    if (f.completionReceipt)
        out15[6] = {"07_COMPLETION_OUTPUT_RULES", Class::Runtime, "receipt", "emitted"};
    if (f.reverseCompletion)
        out15[7] = {"08_REVERSE_COMPLETION", Class::Runtime, "ReverseCompletion", "emitted"};
    if (f.cpuF32 == 0 && f.hostFwd == 0 && f.productionDecode)
        out15[12] = {"13_NO_HOST_FALLBACK_REGRESSION", Class::Runtime, "decode", "GPU path"};
    if (f.residencyMeasured)
        out15[13] = {"14_RESIDENCY_SCHEDULER_RUNTIME", Class::Runtime, "BG/BM", "measured"};
    if (f.runtimeBacked && f.streamOut && f.completionReceipt)
        out15[14] = {"15_PRODUCT_UMBRELLA_SEAL", Class::Runtime, "deep2_benchmark",
                     "stream+receipt"};
}

inline void EmitProductReceipt(FILE* f, const RunFacts& facts) {
    if (!f) f = stdout;
    Item items[15];
    Classify(facts, items);
    const int unfinished = CountUnfinished(items, 15);
    const int productPass =
        (facts.decodeTps >= 5.0 && facts.tokensCommitted >= facts.tokensReq &&
         facts.streamOut && facts.completionReceipt && facts.cpuF32 == 0 &&
         facts.hostFwd == 0 && unfinished == 0)
            ? 1
            : 0;

    std::fprintf(f, "RAWRXD_E2E_BLOCKERS_015_LOCK=1\n");
    for (int i = 0; i < 15; ++i) {
        std::fprintf(f, "E2E15_%s %s OWNER=%s NOTE=%s\n", items[i].id, ClsStr(items[i].cls),
                     items[i].owner, items[i].note);
    }
    std::fprintf(f, "UNFINISHED_BLOCKERS_REMAINING=%d\n", unfinished);

    std::fprintf(f, "RAWRXD_PRODUCT_E2E_001\n");
    std::fprintf(f, "INPUT_ACCEPTED=%d\nMODEL_AUTHORITY=%d\nRUNTIME_BACKED=%d\n",
                 facts.inputAccepted, facts.modelAuthority, facts.runtimeBacked);
    std::fprintf(f, "PRODUCTION_DECODE_PATH=%d\nHOST_FORWARD_LAYER_CALLS=%llu\n"
                    "CPU_F32_EXPANDS=%llu\n",
                 facts.productionDecode, (unsigned long long)facts.hostFwd,
                 (unsigned long long)facts.cpuF32);
    std::fprintf(f, "TOKENS_REQUESTED=%llu\nTOKENS_COMMITTED=%llu\n"
                    "STREAM_OUTPUT_PRESENT=%d\nCOMPLETION_RECEIPT_PRESENT=%d\n",
                 (unsigned long long)facts.tokensReq,
                 (unsigned long long)facts.tokensCommitted, facts.streamOut,
                 facts.completionReceipt);
    std::fprintf(f, "DECODE_TPS_REAL=%.3f\nPRODUCT_FLOOR_TPS=5.000\nPRODUCT_PASS=%d\n",
                 facts.decodeTps, productPass);
    if (!productPass) {
        const char* at = facts.blockedAt ? facts.blockedAt : "01_PRODUCT_5TPS_WALL";
        const char* ow =
            facts.blockedOwner ? facts.blockedOwner : "QKV_PROJ/KVA_EXPOSED";
        const char* nx = facts.nextAction
                             ? facts.nextAction
                             : "cut exposed SPIN bytes; re-run 64-tok generateStream";
        std::fprintf(f, "BLOCKED_AT=%s\nBLOCKED_OWNER=%s\nNEXT_RUNTIME_ACTION=%s\n",
                     at, ow, nx);
        std::fprintf(f, "RAWRXD_PRODUCT_E2E_001=OPEN\n");
    } else {
        std::fprintf(f, "RAWRXD_PRODUCT_E2E_001=PASS\n");
    }
    std::fflush(f);
}

} // namespace rawr::e2e15
