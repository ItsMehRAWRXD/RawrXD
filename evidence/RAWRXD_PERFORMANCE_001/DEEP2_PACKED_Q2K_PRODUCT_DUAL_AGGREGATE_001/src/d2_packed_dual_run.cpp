/* d2_packed_dual_run.cpp — product ABI entry for packed Q2_K dual aggregate */
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "../include/d2_product_packed_dual_q2k.h"
#include "d2_nodep.h"
#include "../../DEEP2_DUAL_AGGREGATE_SSVK_BIND_001/src/d2_live_vk.h"

struct D2Q2kSlice {
    const uint8_t* data; uint64_t bytes; uint32_t rows, cols; HANDLE map; void* view;
};
extern "C" int d2_gguf_load_q2k_matrix(const char* path, D2Q2kSlice* out);
extern "C" void d2_gguf_unload_q2k(D2Q2kSlice* s);
int d2_packed_dual_exec(D2LiveCtx* live, const D2Q2kSlice* sl, uint32_t tokens,
                        D2PackedDualResult* out);

extern "C" int d2_product_packed_dual_q2k_run(const char* gguf_path, uint32_t token_iters,
                                              D2PackedDualResult* out) {
    if (!gguf_path || !out || token_iters < 1) return 0;
    memset(out, 0, sizeof *out);
    out->product_linked = 1;
    out->full_dequant = 0;
    out->materialized_weight_bytes = 0;
    D2Q2kSlice sl{};
    if (!d2_gguf_load_q2k_matrix(gguf_path, &sl)) {
        printf("GGUF_Q2K_LOAD=FAIL path=%s\n", gguf_path);
        return 0;
    }
    printf("Q2K_TENSOR rows=%u cols=%u bytes=%llu\n", sl.rows, sl.cols,
           (unsigned long long)sl.bytes);
    uint32_t use_rows = sl.rows > 8192u ? 8192u : sl.rows;
    uint32_t use_cols = sl.cols > 4096u ? 4096u : sl.cols;
    uint64_t nblk = ((uint64_t)use_cols + 255) / 256;
    D2Q2kSlice use = sl;
    use.rows = use_rows; use.cols = use_cols;
    use.bytes = (uint64_t)use_rows * nblk * 84ull;
    if (!d2_packed_q2k_contract(use.bytes, 1ull << 20, 0)) {
        printf("Q2K_CONTRACT=FAIL\n"); d2_gguf_unload_q2k(&sl); return 0;
    }
    D2LiveCtx live{};
    if (!d2_live_open(&live)) { d2_gguf_unload_q2k(&sl); return 0; }
    int ok = d2_packed_dual_exec(&live, &use, token_iters, out);
    d2_live_close(&live);
    d2_gguf_unload_q2k(&sl);
    out->packed_q2k_live = ok ? 1u : 0u;
    out->product_linked = 1;
    if (ok && out->material_overlap && out->packed_q2k_live && out->product_linked &&
        !out->serial_chain && !out->weight_migration && !out->synthetic_io &&
        !out->device_lost && out->compact_merge && out->tokens_run >= 8)
        out->aggregate_bw_authority = 1;
    else
        out->aggregate_bw_authority = 0;
    return ok;
}
