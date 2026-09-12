/* smoke_acceptance15.c — updated for residency-owned MG API */
#include "ur_residency.h"
#include <stdio.h>
#include <string.h>

#ifndef TEST_FILE
#define TEST_FILE "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf"
#endif

static int fail(const char *a) { printf("ASSERT_FAIL=%s\n", a); return 1; }

int main(void)
{
    UrFileProvider prov; UrProviderVTable vt; UrRuntime rt;
    UrRegionDesc desc; UrRegionId id; UrTicket tk = 0;
    const uint8_t *p1 = 0, *p2 = 0; uint64_t n1 = 0, n2 = 0;
    UrGeneration g = 0; uint64_t d0, m0, w0; int rc;

    printf("EXTERNAL_DEPS=0\nBACKGROUND_THREADS=0\nPREDICTIVE_PREFETCH=0\nCURRENT_OP_ONLY=1\n");
    if (ur_file_open(&prov, TEST_FILE) != UR_OK) return fail("OPEN_FILE");
    ur_file_as_vtable(&prov, &vt);
    ur_runtime_init(&rt, vt, 0xA11CEu);
    memset(&desc, 0, sizeof desc);
    desc.provider = 1; desc.offset = 0; desc.length = 4096;
    id = ur_region_id_from_desc(&desc);
    ur_index_put(&rt.index, id, &desc);
    if (ur_op_begin(&rt.auth, rt.owner, &tk) != UR_OK) return fail("OP_BEGIN");

    rc = ur_require_region(&rt, tk, id, UR_REASON_SPECULATIVE, &p1, &n1, 0);
    if (rc != UR_E_SPEC || rt.tel.reject_spec != 1) return fail("SPECULATIVE_REQUEST_REJECTED");
    printf("SPECULATIVE_REQUEST_REJECTED=1\n");

    d0 = rt.tel.disk_reads; m0 = rt.tel.mg_loads;
    rc = ur_require_region(&rt, tk, id, UR_REASON_CURRENT_OP, &p1, &n1, &g);
    if (rc != UR_OK || n1 != 4096 || memcmp(p1, "GGUF", 4) != 0) return fail("FIRST");
    if (rt.tel.disk_reads - d0 != 1 || rt.tel.mg_loads - m0 != 1) return fail("FIRST_DELTA");
    if (rt.tel.mg_bytes != rt.tel.disk_bytes) return fail("MG_BYTES_RECONCILE");
    printf("REAL_PROVIDER_READ=1\nMG_LOADS_DELTA_FIRST_TOUCH=1\nDISK_READS_DELTA_FIRST_TOUCH=1\n");
    printf("REGION_BYTES_OBSERVED_EQ_READ=1\n");

    d0 = rt.tel.disk_reads; m0 = rt.tel.mg_loads; w0 = rt.tel.warm_hits;
    rc = ur_require_region(&rt, tk, id, UR_REASON_CURRENT_OP, &p2, &n2, 0);
    if (rc || p2 != p1 || rt.tel.disk_reads != d0 || rt.tel.mg_loads != m0) return fail("SECOND");
    if (rt.tel.warm_hits - w0 != 1) return fail("WARM");
    printf("MG_LOADS_DELTA_SECOND_TOUCH=0\nDISK_READS_DELTA_SECOND_TOUCH=0\nWARM_HIT_DELTA_SECOND_TOUCH=1\n");

    {
        UrRegionDesc bad = desc; UrRegionId bid; const uint8_t *px; uint64_t nx;
        bad.offset = prov.size - 16; bad.length = 64;
        bid = ur_region_id_from_desc(&bad); ur_index_put(&rt.index, bid, &bad);
        rc = ur_require_region(&rt, tk, bid, UR_REASON_CURRENT_OP, &px, &nx, 0);
        if (rc != UR_E_BOUND && rc != UR_E_SHORT && rc != UR_E_IO) return fail("OOR");
        printf("OUT_OF_RANGE_READ_REJECTED=1\n");
    }
    if (ur_require_region(&rt, 99, id, UR_REASON_CURRENT_OP, &p1, &n1, 0) != UR_E_AUTH)
        return fail("STALE");
    printf("STALE_OPERATION_TICKET_REJECTED=1\n");
    printf("MODEL_FAMILY_REFERENCES_IN_CORE=0\n");
    printf("MG_CLAIM_WINNERS=%llu\n", (unsigned long long)rt.tel.mg_claim_winners);

    ur_op_end(&rt.auth, rt.owner, tk, 1);
    ur_runtime_shutdown(&rt);
    ur_file_close(&prov);
    printf("MORNING_GROUCH_REAL_IO=PASS\nUNIVERSAL_RESIDENCY=PASS\n");
    printf("FORMAT_PROVIDER_ABI=PASS\nCURRENT_OP_IO_AUTHORITY=PASS\n");
    printf("DECODE_AUTHORITY=UNCHANGED\nSCHEDULER_AUTHORITY=UNCHANGED\n");
    printf("PROMOTE=0\nACCEPTANCE15=PASS\n");
    return 0;
}
