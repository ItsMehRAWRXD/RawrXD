/* live_main.cpp — P0 chain: bind → plan → same-token submit → overlap seal */
#include "../../DEEP2_MISSING15_NODEP_SOURCE_20260912/DEEP2_MISSING15_NODEP_SOURCE_20260912/src/d2_nodep.h"
#include <stdio.h>

extern "C" int d2_ssvk_live_install(void);
extern "C" void d2_ssvk_live_shutdown(void);

int main() {
    printf("GATE=DEEP2_DUAL_AGGREGATE_SSVK_BIND_001\n");
    printf("FULL_MODEL_TPS_AUTHORITY=1\nPROMOTE=0\n");
    if (!d2_ssvk_live_install()) {
        printf("STATUS=FAIL_OPEN_DEVICES\nAGGREGATE_BW_AUTHORITY=0\n");
        return 10;
    }
    D2FabricPlan plan{};
    const uint64_t bpr = 16384ull; /* modeled bytes/row */
    if (!d2_plan_rows_bw(8192, 640ull << 30, 624ull << 30, bpr, &plan)) {
        printf("STATUS=FAIL_PLAN\n"); d2_ssvk_live_shutdown(); return 11;
    }
    if (!d2_validate_local_plan(&plan)) {
        printf("STATUS=FAIL_LOCALITY\n"); d2_ssvk_live_shutdown(); return 12;
    }
    printf("ROWS=%u/%u\n", plan.lane[0].row_count, plan.lane[1].row_count);
    printf("BYTES=%llu/%llu\n",
           (unsigned long long)plan.lane[0].local_weight_bytes,
           (unsigned long long)plan.lane[1].local_weight_bytes);

    D2FabricMetrics m{};
    if (!d2_submit_same_token(&plan, 1, &m)) {
        printf("STATUS=FAIL_SUBMIT\nAGGREGATE_BW_AUTHORITY=0\n");
        d2_ssvk_live_shutdown(); return 13;
    }
    printf("GPU0_REAL_FORWARDS=%llu\nGPU1_REAL_FORWARDS=%llu\n",
           (unsigned long long)m.gpu0_real_forwards, (unsigned long long)m.gpu1_real_forwards);
    printf("GPU0_LOCAL_BYTES=%llu\nGPU1_LOCAL_BYTES=%llu\n",
           (unsigned long long)m.gpu0_local_bytes, (unsigned long long)m.gpu1_local_bytes);
    printf("OVERLAP_NS=%llu\nCRITICAL_PATH_NS=%llu\n",
           (unsigned long long)m.overlap_ns, (unsigned long long)m.critical_path_ns);
    printf("SERIAL_GPU_CHAIN=%u\nWEIGHT_MIGRATION_NONZERO=%u\n",
           m.serial_gpu_chain, m.weight_migration_bytes_nonzero);
    printf("SYNTHETIC_DEVICE_IO=%u\nDEVICE_LOST=%u\nCOMPACT_MERGE_REAL=%u\n",
           m.synthetic_device_io, m.device_lost, m.compact_merge_real);
    printf("AGGREGATE_EFFECTIVE_BPS=%llu\n",
           (unsigned long long)m.aggregate_effective_bps);

    const int pass =
        m.gpu0_real_forwards > 0 && m.gpu1_real_forwards > 0 &&
        m.gpu0_local_bytes > 0 && m.gpu1_local_bytes > 0 &&
        m.overlap_ns > 0 && m.overlap_ratio_measured == 1 &&
        m.serial_gpu_chain == 0 && m.weight_migration_bytes_nonzero == 0 &&
        m.synthetic_device_io == 0 && m.device_lost == 0 &&
        m.compact_merge_real == 1;

    /* AGGREGATE_BW still requires packed-Q2K + product_linked — keep 0 */
    printf("SSVK_LIVE_OVERLAP=%d\n", pass ? 1 : 0);
    printf("AGGREGATE_BW_AUTHORITY=0\n");
    printf("STATUS=%s\n", pass ? "PASS_LIVE_OVERLAP" : "FAIL_CLOSED");
    printf("NOTE=PRODUCT_LINKED=0 PACKED_Q2K_LIVE=0 TPS_UNTOUCHED=1\n");

    D2AuthorityInput ai{};
    ai.product_linked = 0;
    ai.runtime_bind_real = pass ? 1u : 0u;
    ai.aggregate_bw_authority_requested = 1;
    ai.critical_path_nvme_reads_per_token = 0;
    ai.fabric = m;
    printf("AUTHORITY_GATE=%s\n", d2_authority_gate(&ai) ? "WOULD_PASS" : "FAIL_CLOSED_OK");

    d2_ssvk_live_shutdown();
    return pass ? 0 : 20;
}
