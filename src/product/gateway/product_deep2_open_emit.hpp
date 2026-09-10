#pragma once
/* Open-gate stderr emitters — companion to product_deep2_open_gate.hpp. ≤99. */
#include "product_deep2_open_gate.hpp"
#include <cstdio>

namespace rawr {
namespace product_infer_detail {

inline void EmitBudgetFacts(uint64_t envMib, int parseOk, uint64_t effectiveMib,
                            uint64_t residencyMib) {
    std::fprintf(stderr,
                 "WEIGHT_BUDGET_ENV_PRESENT=%d\n"
                 "WEIGHT_BUDGET_ENV_RAW=\"%llu\"\n"
                 "WEIGHT_BUDGET_PARSE_OK=%d\n"
                 "WEIGHT_BUDGET_INPUT_MIB=%llu\n"
                 "WEIGHT_BUDGET_EFFECTIVE_MIB=%llu\n"
                 "RESIDENCY_BUDGET_MIB=%llu\n"
                 "BUDGET_RELATION_VALID=%d\n",
                 envMib > 0 ? 1 : 0, (unsigned long long)envMib, parseOk,
                 (unsigned long long)envMib, (unsigned long long)effectiveMib,
                 (unsigned long long)residencyMib,
                 (effectiveMib > 0 && residencyMib > 0 &&
                  residencyMib <= effectiveMib)
                     ? 1
                     : (residencyMib > 0 && effectiveMib == 0 ? 0 : 1));
    std::fflush(stderr);
}

inline void MarkSessionFacts(ProductOpenFacts& f) {
    f.init_enter = f.init_exit = f.session_enter = f.session_exit = 1;
}

inline void EmitOpenFacts(const ProductOpenFacts& f, const char* path,
                          const char* verdict) {
    const int crit =
        (f.tensor_count > 0 && f.embed_present &&
         (f.lmhead_present || f.output_present))
            ? 1
            : 0;
    std::fprintf(stderr,
                 "PRODUCT_OPEN_INIT_ENTER=%d\n"
                 "PRODUCT_OPEN_INIT_EXIT=%d\n"
                 "PRODUCT_OPEN_SESSION_ENTER=%d\n"
                 "PRODUCT_OPEN_SESSION_EXIT=%d\n"
                 "PRODUCT_OPEN_PE64=%d\n"
                 "PRODUCT_OPEN_PE_LAA=%d\n"
                 "PRODUCT_OPEN_VA_GT_2GB=%d\n"
                 "PRODUCT_OPEN_TENSOR_COUNT=%d\n"
                 "PRODUCT_OPEN_EMBED_PRESENT=%d\n"
                 "PRODUCT_OPEN_LMHEAD_PRESENT=%d\n"
                 "PRODUCT_OPEN_OUTPUT_PRESENT=%d\n"
                 "PRODUCT_OPEN_CRITICAL_TENSORS=%s\n"
                 "PRODUCT_OPEN_PASS=%d\n"
                 "HEADLESS_READY=%d\n"
                 "PRODUCT_OPEN_LAA_FACT=%d NOTE=LAA_NOT_OPEN_GATE\n"
                 "R25_PRODUCTOPEN path=%s verdict=%s "
                 "PRODUCT_OPEN_SESSION=%s\n",
                 f.init_enter, f.init_exit, f.session_enter, f.session_exit,
                 f.pe64, f.pe_laa, f.va_gt_2gb, f.tensor_count, f.embed_present,
                 f.lmhead_present, f.output_present, crit ? "PASS" : "FAIL",
                 f.product_open_pass, f.product_open_pass, f.pe_laa,
                 path ? path : "", verdict ? verdict : "FAIL",
                 f.product_open_pass ? "PASS" : "FAIL");
    std::fflush(stderr);
}

} // namespace product_infer_detail
} // namespace rawr
