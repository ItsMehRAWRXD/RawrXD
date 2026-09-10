// Deep2SessionPrefill_Emit.hpp — prefill receipt emitter. ≤99.
#pragma once
#include "Deep2SessionPrefill.hpp"
#include <cstdio>

namespace rawr::olma {

inline void EmitPrefill(FILE* f, const PrefillSeal& p) {
    if (!f) f = stdout;
    if (!p.PASS) {
        std::fprintf(f, "DEEP2_SESSION_PREFILL_001=BLOCKED\n");
        std::fprintf(f, "BLOCKED_AT=%s\nBLOCKED_OWNER=DEEP2_SESSION_PREFILL\n",
                     p.BLOCKED_AT.c_str());
        std::fprintf(f, "REASON=%s\nFIRST_DELTA=%s\n", p.REASON.c_str(),
                     p.FIRST_DELTA.c_str());
        return;
    }
    std::fprintf(f, "PATH=%s\n", p.MODEL_PATH.c_str());
    std::fprintf(f, "AUTHORITY_LADDER_COMPLETE=%d\n", p.AUTHORITY_LADDER_COMPLETE);
    std::fprintf(f, "SESSION_WEIGHT_LOAD=%d\n", p.SESSION_WEIGHT_LOAD);
    std::fprintf(f, "DEEP2_SESSION=%d\n", p.DEEP2_SESSION);
    std::fprintf(f, "REAL_PREFILL=%d\n", p.REAL_PREFILL);
    std::fprintf(f, "FIRST_TOKEN=%d\n", p.FIRST_TOKEN);
    std::fprintf(f, "TOKENS_PRODUCED=%d\n", p.TOKENS_PRODUCED);
    std::fprintf(f, "PREFILL_TOKENS=%u\nDECODE_TOKENS=%u\n", p.PREFILL_TOKENS,
                 p.DECODE_TOKENS);
    std::fprintf(f, "GEOMETRY_UNCHANGED=%d\nONE_LOCAL_MODEL_AUTHORITY=%d\n",
                 p.GEOMETRY_UNCHANGED, p.ONE_LOCAL_MODEL_AUTHORITY);
    std::fprintf(f, "DEEP2_SESSION_PREFILL_001=PASS\n");
    std::fprintf(f, "FIRST_DELTA=DEEP2_GENERATE_STREAM\n");
}

} // namespace rawr::olma
