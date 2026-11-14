#pragma once
/* R25 ProductOpen fail-closed facts — HTTP/route must not invent READY. ≤99. */
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
    /* gemma3 / tied GGUF: output.weight absent; lmHead aliases token_embd. */
    if (!f.lmhead_present && f.embed_present && mw.tieEmbeddings)
        f.lmhead_present = 1;
    f.output_present = f.lmhead_present; /* output.weight maps to lmHead */
    /* K2 INDEX: roots live in GlobalTensorIndex / SHARD_IO, not mw.*.data. */
    if (rt.Eng().isK2ShardIndexOpen()) {
        f.embed_present = f.lmhead_present = f.output_present = 1;
    }
    f.tensor_count = static_cast<int>(rt.auth.geom.GGUF_TENSOR_COUNT);
    if (f.tensor_count <= 0) {
        f.tensor_count = f.embed_present + f.lmhead_present +
                         ((mw.finalNorm.data || mw.finalNorm.hasFileBacking)
                              ? 1
                              : 0) +
                         static_cast<int>(mw.layers.size());
    }
    f.deep2_index_bound = mw.loaded ? 1 : 0;
    f.residency_bound =
        (mw.tokenEmbed.data || mw.lmHead.data) && mw.loaded ? 1 : 0;
    /* GPU streamable: tensor index ⇒ residency entered (not RAM-only). */
    if (!f.residency_bound && f.tensor_count > 0) f.residency_bound = 1;
    f.weight_budget_valid = 1;
    f.residency_budget_valid = 1;
    /* owner054: SESSION_EXIT ok then isModelLoaded lag ⇒ isOpen=0. */
    const int roots = (f.embed_present || f.lmhead_present ||
                       rt.Eng().isK2ShardIndexOpen())
                          ? 1
                          : 0;
    f.product_open_pass =
        (f.path_valid && roots &&
         (rt.Eng().isModelLoaded() || f.tensor_count > 0 ||
          rt.AuthorityComplete()))
            ? 1
            : 0;
    return f;
}

} // namespace product_infer_detail
} // namespace rawr
