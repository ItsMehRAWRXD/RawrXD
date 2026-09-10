#pragma once
/* Emit QUANT_DISPATCH_001 receipt. ≤99. */
#include "QuantDispatch.hpp"
#include <cstdio>

namespace rawr::olma {

inline void EmitQuantDispatch(FILE* f, const QuantDispatchSeal& q) {
    if (!f) f = stdout;
    if (!q.PASS) {
        std::fprintf(f, "QUANT_DISPATCH_001=BLOCKED\n");
        std::fprintf(f, "BLOCKED_AT=%s\nBLOCKED_OWNER=QUANT_DISPATCH\n", q.BLOCKED_AT.c_str());
        std::fprintf(f, "EXPECTED=%s\nOBSERVED=%s\n", q.EXPECTED.c_str(), q.OBSERVED.c_str());
        std::fprintf(f, "REASON=%s\nFIRST_DELTA=%s\n", q.REASON.c_str(), q.FIRST_DELTA.c_str());
        return;
    }
    std::fprintf(f, "BINDINGS_CHECKED=%u\nBINDINGS_DISPATCHABLE=%u\n", q.BINDINGS_CHECKED,
                 q.BINDINGS_DISPATCHABLE);
    std::fprintf(f, "UNSUPPORTED_TYPE=%u\nSPAN_MISMATCH=%u\n", q.UNSUPPORTED_TYPE,
                 q.SPAN_MISMATCH);
    std::fprintf(f, "TYPE_F32=%u\nTYPE_Q4_K=%u\nTYPE_Q6_K=%u\nTYPE_OTHER=%u\n", q.TYPE_F32,
                 q.TYPE_Q4_K, q.TYPE_Q6_K, q.TYPE_OTHER);
    std::fprintf(f, "QUANT_FROM_TENSOR=%d\nNO_SILENT_F32_FALLBACK=%d\nNO_ZERO_FALLBACK=%d\n",
                 q.QUANT_FROM_TENSOR, q.NO_SILENT_F32_FALLBACK, q.NO_ZERO_FALLBACK);
    std::fprintf(f, "DISPATCH_TABLE_COMPLETE=%d\nBYTE_SPAN_MATCHES_TYPE=%d\n",
                 q.DISPATCH_TABLE_COMPLETE, q.BYTE_SPAN_MATCHES_TYPE);
    std::fprintf(f, "GEOMETRY_UNCHANGED=%d\nONE_LOCAL_MODEL_AUTHORITY=%d\n",
                 q.GEOMETRY_UNCHANGED, q.ONE_LOCAL_MODEL_AUTHORITY);
    std::fprintf(f, "QUANT_DISPATCH_001=PASS\nFIRST_DELTA=TOKENIZER_TEMPLATE_EOG\n");
}

} // namespace rawr::olma
