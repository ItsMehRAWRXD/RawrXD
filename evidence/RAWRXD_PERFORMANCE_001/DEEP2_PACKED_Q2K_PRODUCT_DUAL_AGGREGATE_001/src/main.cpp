#include "../include/d2_product_packed_dual_q2k.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    const char* path = argc > 1 ? argv[1] : "G:\\~dev\\rawrxd\\llama3.2-3b-Q2_K.gguf";
    uint32_t tokens = argc > 2 ? (uint32_t)atoi(argv[2]) : 16;
    printf("GATE=DEEP2_PACKED_Q2K_PRODUCT_DUAL_AGGREGATE_001\n");
    printf("FULL_MODEL_TPS_AUTHORITY=1\nPROMOTE=0\nTIP_CLIMB=HOLD\n");
    D2PackedDualResult r{};
    int ok = d2_product_packed_dual_q2k_run(path, tokens, &r);
    printf("PRODUCT_LINKED=%u\nPACKED_Q2K_LIVE=%u\n", r.product_linked, r.packed_q2k_live);
    printf("FULL_DEQUANT_BUFFER=%u\nMATERIALIZED_WEIGHT_BYTES=%u\n", r.full_dequant, r.materialized_weight_bytes);
    printf("GPU0_BYTES=%llu GPU1_BYTES=%llu\n", (unsigned long long)r.gpu0_bytes, (unsigned long long)r.gpu1_bytes);
    printf("GPU0_REAL_FORWARDS=%llu GPU1_REAL_FORWARDS=%llu\n",
           (unsigned long long)r.gpu0_fwd, (unsigned long long)r.gpu1_fwd);
    printf("OVERLAP_NS=%llu CRITICAL_PATH_NS=%llu\n",
           (unsigned long long)r.overlap_ns, (unsigned long long)r.critical_path_ns);
    printf("MATERIAL_SAME_TOKEN_OVERLAP=%u\n", r.material_overlap);
    printf("SERIAL_GPU_CHAIN=%u WEIGHT_MIGRATION=%u SYNTHETIC_IO=%u DEVICE_LOST=%u\n",
           r.serial_chain, r.weight_migration, r.synthetic_io, r.device_lost);
    printf("COMPACT_MERGE_REAL=%u TOKENS_RUN=%u\n", r.compact_merge, r.tokens_run);
    printf("AGGREGATE_EFFECTIVE_BPS=%llu\n", (unsigned long long)r.aggregate_bps);
    printf("AGGREGATE_BW_AUTHORITY=%u\n", r.aggregate_bw_authority);
    printf("STATUS=%s\n", ok && r.packed_q2k_live ? (r.aggregate_bw_authority ? "PASS_AGGREGATE_BW" : "PASS_PACKED_PARTIAL") : "FAIL_CLOSED");
    printf("NEXT_GATE=DEEP2_DUAL_AGGREGATE_CRITICAL_PATH_BALANCE\n");
    printf("PROMOTE=0\n");
    return (ok && r.packed_q2k_live) ? 0 : 20;
}
