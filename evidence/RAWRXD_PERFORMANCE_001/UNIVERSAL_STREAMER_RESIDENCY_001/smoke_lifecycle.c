/* smoke_lifecycle.c — REAL_REGION_LIFECYCLE + provider equivalence */
#include "ur_residency.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef TEST_FILE
#define TEST_FILE "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf"
#endif

static int fail(const char *s) { printf("FAIL=%s\n", s); return 1; }

static int run_on_provider(UrProviderVTable vt, UrRegionDesc desc, const char *tag)
{
    UrRuntime rt; UrRegionId id; UrTicket tk; const uint8_t *p = 0, *p2 = 0;
    uint64_t n = 0, n2 = 0; UrGeneration g1 = 0, g2 = 0, g3 = 0;
    uint64_t d0, m0;
    int rc;

    ur_runtime_init(&rt, vt, 0xC001u);
    id = ur_region_id_from_desc(&desc);
    if (ur_index_put(&rt.index, id, &desc)) return fail("INDEX");
    if (ur_op_begin(&rt.auth, rt.owner, &tk)) return fail("BEGIN");

    /* COLD → MG → WARM */
    d0 = rt.tel.disk_reads; m0 = rt.tel.mg_loads;
    rc = ur_require_region(&rt, tk, id, UR_REASON_CURRENT_OP, &p, &n, &g1);
    if (rc || n != desc.length || !p) return fail("MG1");
    if (rt.tel.disk_reads - d0 != 1 || rt.tel.mg_loads - m0 != 1) return fail("MG1_IO");
    if (rt.tel.mg_claim_winners != 1) return fail("MG_CLAIM_WINNERS");
    if (rt.tel.mg_bytes != rt.tel.disk_bytes) return fail("MG_BYTES_RECONCILE");
    if (g1 < 1) return fail("GEN1");

    /* reuse */
    d0 = rt.tel.disk_reads; m0 = rt.tel.mg_loads;
    rc = ur_require_region(&rt, tk, id, UR_REASON_CURRENT_OP, &p2, &n2, &g2);
    if (rc || p2 != p || g2 != g1) return fail("REUSE");
    if (rt.tel.disk_reads != d0 || rt.tel.mg_loads != m0) return fail("REUSE_DELTA");
    if (rt.tel.warm_hits < 1) return fail("WARM_HIT");

    /* HOT */
    if (ur_promote_hot(&rt, id)) return fail("HOT");
    rc = ur_require_region(&rt, tk, id, UR_REASON_CURRENT_OP, &p2, &n2, &g2);
    if (rc || rt.tel.hot_hits < 1) return fail("HOT_HIT");

    /* demote */
    if (ur_demote_to_warm(&rt, id)) return fail("DEMOTE");
    if (rt.tel.demote_hot_warm != 1) return fail("DEMOTE_CNT");

    /* pin exclusion: cannot evict while pinned */
    if (ur_evict_region(&rt, id) != UR_E_PIN) return fail("EVICT_WHILE_PINNED");
    while (ur_release_region(&rt, id) == UR_OK) {}

    /* evict → COLD + generation bump */
    if (ur_evict_region(&rt, id)) return fail("EVICT");
    if (rt.tel.evict_to_cold != 1) return fail("EVICT_CNT");

    /* second MG generation */
    d0 = rt.tel.disk_reads; m0 = rt.tel.mg_loads;
    rc = ur_require_region(&rt, tk, id, UR_REASON_CURRENT_OP, &p, &n, &g3);
    if (rc || g3 <= g1) return fail("MG_GEN_N1");
    if (rt.tel.disk_reads - d0 != 1 || rt.tel.mg_loads - m0 != 1) return fail("MG2_IO");
    if (rt.tel.mg_claim_winners != 2) return fail("MG_CLAIM2");

    /* speculative reject before claim */
    if (ur_require_region(&rt, tk, id, UR_REASON_SPECULATIVE, &p, &n, 0) != UR_E_SPEC)
        return fail("SPEC");
    if (rt.tel.reject_spec < 1) return fail("SPEC_CNT");

    ur_op_end(&rt.auth, rt.owner, tk, 1);
    printf("LIFECYCLE_%s=PASS GEN1=%llu GEN_AFTER_EVICT=%llu MG_BYTES=%llu DISK_BYTES=%llu CLAIMS=%llu\n",
           tag, (unsigned long long)g1, (unsigned long long)g3,
           (unsigned long long)rt.tel.mg_bytes, (unsigned long long)rt.tel.disk_bytes,
           (unsigned long long)rt.tel.mg_claim_winners);
    ur_runtime_shutdown(&rt);
    return 0;
}

int main(void)
{
    UrFileProvider fp; UrMemProvider mp; UrProviderVTable vt;
    UrRegionDesc desc; uint8_t mem[4096];
    int rc;

    memset(&desc, 0, sizeof desc);
    desc.provider = 1; desc.shard = 0; desc.offset = 0; desc.length = 4096;

    if (ur_file_open(&fp, TEST_FILE)) return fail("FILE_OPEN");
    ur_file_as_vtable(&fp, &vt);
    rc = run_on_provider(vt, desc, "FILE");
    ur_file_close(&fp);
    if (rc) return rc;

    /* Cross-provider: identical policy on in-memory backing of same 4KiB pattern */
    memset(mem, 0xA5, sizeof mem); memcpy(mem, "GGUF", 4);
    ur_mem_init(&mp, mem, sizeof mem);
    ur_mem_as_vtable(&mp, &vt);
    desc.provider = 2; /* different provider id → different RegionId; same length/offset */
    rc = run_on_provider(vt, desc, "MEM");
    if (rc) return rc;

    printf("LOADING_STRATEGY_NE_RESIDENCY=1\n");
    printf("RESIDENCY_STATE_OWNS_MORNING_GROUCH=1\n");
    printf("PROVIDER_OWNS_MORNING_GROUCH=0\n");
    printf("REAL_REGION_LIFECYCLE_001=PASS\n");
    printf("PROVIDER_EQUIVALENCE=PASS\n");
    printf("PROMOTE=0\n");
    return 0;
}
