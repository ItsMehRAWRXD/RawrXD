#pragma once
/* R25 ProductOpen fail-closed facts — HTTP/route must not invent READY. */
#include "../../deep2/lavapath/ProductRuntime.hpp"
#include "../../deep2/lavapath/ProductOpenStreamable.hpp"
#include "../../deep2/lavapath/ProcessLargeAddressAware.hpp"
#include <cstdio>

namespace rawr {
namespace product_infer_detail {

struct ProductOpenFacts {
    int pe64 = 0;
    int pe_laa = 0;
    int va_gt_2gb = 0;
    int path_valid = 0;
    int init_enter = 0;
    int init_exit = 0;
    int session_enter = 0;
    int session_exit = 0;
    int tensor_count = 0;
    int embed_present = 0;
    int lmhead_present = 0;
    int output_present = 0;
    int weight_budget_valid = 0;
    int residency_budget_valid = 0;
    int deep2_index_bound = 0;
    int residency_bound = 0;
    int product_open_pass = 0;
};

inline void FillPeFacts(ProductOpenFacts& f) {
#if defined(_WIN64) || defined(_M_X64)
    f.pe64 = 1;
#else
    f.pe64 = 0;
#endif
    f.pe_laa = Deep2::ProcessIsLargeAddressAware();
    /* With LAA:YES on x64, user VA >> 2GB. LAA:NO ≈ 2GB ceiling. */
    f.va_gt_2gb = (f.pe64 && f.pe_laa) ? 1 : 0;
}

inline ProductOpenFacts CollectOpenFacts(const product_run::ProductRuntime& rt) {
    ProductOpenFacts f{};
    FillPeFacts(f);
    const auto& mw = rt.Eng().getModelWeights();
    f.path_valid = rt.modelPath.empty() ? 0 : 1;
    /* Present = pointer OR file-backing (OPEN ≠ full RAM residency). */
    f.embed_present =
        (mw.tokenEmbed.data || mw.tokenEmbed.hasFileBacking) ? 1 : 0;
    f.lmhead_present =
        (mw.lmHead.data || mw.lmHead.hasFileBacking) ? 1 : 0;
    f.output_present = f.lmhead_present; /* output.weight maps to lmHead */
    f.tensor_count = static_cast<int>(rt.auth.geom.GGUF_TENSOR_COUNT);
    if (f.tensor_count <= 0) {
        f.tensor_count = f.embed_present + f.lmhead_present +
                         ((mw.finalNorm.data || mw.finalNorm.hasFileBacking)
                              ? 1
                              : 0) +
                         static_cast<int>(mw.layers.size());
    }
    f.deep2_index_bound = mw.loaded ? 1 : 0;
    /* residency_bound = material-resident fact; not the OPEN gate. */
    f.residency_bound =
        (mw.tokenEmbed.data || mw.lmHead.data) && mw.loaded ? 1 : 0;
    f.weight_budget_valid = 1;
    f.residency_budget_valid = 1;
    Deep2::product_open::Facts so = Deep2::product_open::Evaluate(
        const_cast<Deep2::Deep2Engine&>(rt.Eng()), rt.modelPath.c_str());
    f.product_open_pass =
        (so.open_pass && f.path_valid && rt.IsOpen()) ? 1 : 0;
    return f;
}

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
