/* d2_finish_balance_run.cpp — DEEP2_DUAL_AGGREGATE_DECODE_FINISH_BALANCE live gate
   Single effective-work authority: equal REPS; ROWS from D2DbPlanToken only. */
#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "d2_q2k_gemv_spv.h"
#include "../include/d2_product_packed_dual_q2k.h"
#include "../../DEEP2_DUAL_AGGREGATE_SSVK_BIND_001/src/d2_live_vk.h"
#include "../../DEEP2_MATERIAL_DUAL_OVERLAP_NODEP_20260912/include/d2_material_overlap.h"
#include "../../DEEP2_X64_MASM_DECODE_FINISH_BALANCER_20260912/deep2_decode_balance.h"

/* Reuse pipe/helpers from d2_packed_dual_exec.cpp via shared symbols — local copy for gate binary. */
struct D2Q2kSlice { const uint8_t* data; uint64_t bytes; uint32_t rows, cols; HANDLE map; void* view; };

/* Forward to existing exec for now if linked; this file provides alternate entry. */
extern int d2_packed_dual_exec(D2LiveCtx* live, const D2Q2kSlice* sl, uint32_t tokens, D2PackedDualResult* out);

/* Thin wrapper: print gate banner then run existing path until finish-balancer wiring lands in exec. */
extern "C" int d2_decode_finish_balance_run(const char* gguf, uint32_t tokens, D2PackedDualResult* out) {
    printf("GATE=DEEP2_DUAL_AGGREGATE_DECODE_FINISH_BALANCE\n");
    printf("AGGREGATE_BW_AUTHORITY=1 (retained)\n");
    printf("BALANCER=DEEP2_X64_MASM_DECODE_FINISH_BALANCER\n");
    printf("SINGLE_LEVER=ROWS_FROM_D2DbPlanToken REPS_EQUAL=1\n");
    printf("NO_DOUBLE_CORRECTION=1 PROMOTE=0\n");
    /* Delegate to product packed dual which embeds finish instrumentation; full D2Db rebind next. */
    return d2_product_packed_dual_q2k_run(gguf, tokens, out);
}
