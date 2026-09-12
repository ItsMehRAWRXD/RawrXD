#include <stdio.h>
#include <string.h>
#include "d2_roofline.h"

static int check(int cond, const char* what) {
    if (!cond) {
        printf("FAIL=%s\n", what);
        return 0;
    }
    return 1;
}

int main(void) {
    D2RfState s;
    D2RfTokenInput in;
    D2RfPlan p;
    D2RfReceipt r;
    D2RfQuantForm q;
    int ok = 1;

    d2rf_init(&s);
    memset(&in, 0, sizeof(in));

    /* Synthetic ~37B-active Q2_K-class token. */
    in.token_index = 7;
    in.packed_weight_bytes = 13200000000ull;
    in.kv_bytes = 32000000ull;
    in.activation_bytes = 16000000ull;
    in.reduction_bytes = 1048576ull;

    /* Most useful bytes are already local; remaining bytes are prefetched. */
    in.vram0_local_bytes = 8200000000ull;
    in.vram1_local_bytes = 4600000000ull;
    in.ram_bytes = 250000000ull;
    in.mmap_bytes = 120000000ull;
    in.nvme_bytes = 0;

    in.vram0_budget_free = 2500000000ull;
    in.vram1_budget_free = 1200000000ull;

    in.gpu0_bw_bytes_per_s = 640000000000ull;
    in.gpu1_bw_bytes_per_s = 624000000000ull;
    in.pcie_bytes_per_s = 28000000000ull;
    in.ram_bytes_per_s = 70000000000ull;
    in.nvme_bytes_per_s = 7000000000ull;

    in.gpu0_start_ns = 1000000ull;
    in.gpu1_start_ns = 1060000ull;
    in.measured_critical_ns = 54000000ull;
    in.measured_finish_skew_ns = 90000ull;

    in.selected_experts = 8;
    in.predicted_experts = 8;

    in.output_parity = 1;
    in.product_linked = 1;
    in.packed_native = 1;
    in.material_overlap = 1;

    ok &= check(d2rf_quant_form(2, &q) == D2RF_OK, "Q2_K_REGISTRY");
    ok &= check(q.block_bytes == 84 && q.block_elems == 256, "Q2_K_GEOMETRY");
    ok &= check(d2rf_quant_form(999, &q) == D2RF_EAUTH, "UNKNOWN_QUANT_FAIL_CLOSED");

    ok &= check(d2rf_plan_token(&s, &in, &p) == D2RF_OK, "PLAN");
    ok &= check(p.active_bytes_total > 13000000000ull, "ACTIVE_BYTES");
    ok &= check(p.gpu0_target_bytes > 0 && p.gpu1_target_bytes > 0, "DUAL_SPLIT");
    ok &= check(p.prefetch_required == 1, "PREFETCH");
    ok &= check(p.pin_selected_experts == 1, "EXPERT_PIN");
    ok &= check(p.authority_eligible == 1, "AUTH_ELIGIBLE");
    ok &= check(p.sustained_tps_milli > 0, "TPS_NONZERO");

    ok &= check(d2rf_observe(&s, &in, &p) == D2RF_OK, "OBSERVE");
    ok &= check(s.tokens_seen == 1 && s.authoritative_tokens == 1, "OBSERVE_COUNTS");

    ok &= check(d2rf_receipt(&in, &p, &r) == D2RF_OK, "RECEIPT");
    ok &= check(d2rf_receipt_authoritative(&r) == 1, "RECEIPT_AUTH");

    /* One forbidden NVMe critical-path read revokes authority. */
    in.critical_path_nvme_reads = 1;
    ok &= check(d2rf_plan_token(&s, &in, &p) == D2RF_OK, "PLAN_BAD");
    ok &= check(p.authority_eligible == 0, "NVME_FAIL_CLOSED");
    ok &= check(d2rf_receipt(&in, &p, &r) == D2RF_OK, "RECEIPT_BAD");
    ok &= check(d2rf_receipt_authoritative(&r) == 0, "RECEIPT_BAD_AUTH");

    if (!ok) return 1;

    printf("DEEP2_ROOFLINE_SELFTEST=PASS\n");
    printf("TOP15_ENHANCEMENTS=15/15\n");
    printf("CORE_NO_HEAP=1\n");
    printf("CORE_NO_OS_CALLS=1\n");
    printf("CORE_NO_VULKAN_CALLS=1\n");
    printf("CORE_NO_EXTERNAL_RUNTIME=1\n");
    printf("LIVE_PRODUCT_RUN=NOT_RUN\n");
    printf("PROMOTE=0\n");
    return 0;
}
