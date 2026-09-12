/* smoke_hot.c — REAL_DEVICE_HOT_UPLOAD_001 */
#include "ur_residency.h"
#include <stdio.h>
#include <string.h>

static int fail(const char *s) { printf("FAIL=%s\n", s); return 1; }

int main(void)
{
    uint8_t mem[4096]; UrMemProvider mp; UrHostDevice hd;
    UrProviderVTable vt; UrDeviceVTable dv; UrRuntime rt;
    UrRegionDesc desc; UrRegionId id; UrTicket tk;
    const uint8_t *p = 0, *p2 = 0; uint64_t n = 0, n2 = 0;
    UrGeneration g = 0; UrHotIdentity hot; UrAllocGeneration old_ag;
    uint64_t d0, m0, c0;

    memset(mem, 0x3C, sizeof mem); memcpy(mem, "GGUF", 4);
    ur_mem_init(&mp, mem, sizeof mem); ur_mem_as_vtable(&mp, &vt);
    ur_hostdev_init(&hd, 7); ur_hostdev_as_vtable(&hd, &dv);
    ur_runtime_init(&rt, vt, 0x7071u);
    ur_runtime_set_device(&rt, dv);
    memset(&desc, 0, sizeof desc);
    desc.provider = 5; desc.length = 4096;
    id = ur_region_id_from_desc(&desc);
    if (ur_index_put(&rt.index, id, &desc) || ur_op_begin(&rt.auth, rt.owner, &tk))
        return fail("SETUP");
    if (ur_require_region(&rt, tk, id, UR_REASON_CURRENT_OP, &p, &n, &g) || n != 4096)
        return fail("WARM");
    if (ur_promote_hot(&rt, id)) return fail("UPLOAD");
    if (ur_hot_identity(&rt, id, &hot)) return fail("IDENT");
    if (hot.device != 7 || hot.bytes != 4096 || !hot.handle) return fail("DEV");
    if (hot.source_gen != g || rt.tel.device_copy_bytes != 4096) return fail("COPY");
    if (rt.tel.device_uploads != 1) return fail("UPLOADS");
    if (memcmp(hot.handle, "GGUF", 4) != 0) return fail("DEV_BYTES");
    old_ag = hot.alloc_gen;
    if (!ur_hot_valid(&rt, id, old_ag)) return fail("VALID");

    d0 = rt.tel.disk_reads; m0 = rt.tel.mg_loads; c0 = rt.tel.device_copy_bytes;
    if (ur_require_region(&rt, tk, id, UR_REASON_CURRENT_OP, &p2, &n2, 0))
        return fail("HOT2");
    if (rt.tel.disk_reads != d0 || rt.tel.mg_loads != m0) return fail("HOT2_DISK");
    if (rt.tel.device_copy_bytes != c0) return fail("HOT2_COPY");
    if (rt.tel.hot_hits < 1) return fail("HOT_HIT");

    if (ur_hot_reset(&rt, id)) return fail("RESET");
    if (ur_hot_valid(&rt, id, old_ag)) return fail("STALE_LIVE");
    if (ur_promote_hot(&rt, id)) return fail("REUPLOAD");
    if (ur_hot_identity(&rt, id, &hot)) return fail("IDENT2");
    if (hot.alloc_gen == old_ag || hot.source_gen != g) return fail("NEW_ALLOC");
    if (ur_hot_valid(&rt, id, old_ag)) return fail("OLD_AGEN");
    if (!ur_hot_valid(&rt, id, hot.alloc_gen)) return fail("NEW_AGEN");
    if (rt.tel.device_copy_bytes != 8192 || rt.tel.device_uploads != 2)
        return fail("RECOPY");
    if (rt.tel.device_invalidations < 1) return fail("INVAL");

    printf("REAL_DEVICE_HOT_UPLOAD_001=PASS DEV=7 COPY=%llu SRC_GEN=%llu NEW_ALLOC_GEN=%llu GPU=0\n",
           (unsigned long long)rt.tel.device_copy_bytes,
           (unsigned long long)g, (unsigned long long)hot.alloc_gen);
    printf("DEVICE_KIND=HOST_VIRTUAL_ALLOC MG_OWNERSHIP_UNCHANGED=1 PROMOTE=0\n");
    ur_op_end(&rt.auth, rt.owner, tk, 1);
    ur_runtime_shutdown(&rt);
    return 0;
}
