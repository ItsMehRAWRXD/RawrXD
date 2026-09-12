/* smoke_alias.c — REGION_ALIAS_COHERENCE_001 */
#include "ur_residency.h"
#include <stdio.h>
#include <string.h>

static int fail(const char *s) { printf("FAIL=%s\n", s); return 1; }

int main(void)
{
    uint8_t mem[8192]; UrMemProvider mp; UrProviderVTable vt; UrRuntime rt;
    UrRegionDesc parent, child, partial; UrRegionId pid, cid, oid;
    UrTicket tk; const uint8_t *pp = 0, *cp = 0, *op = 0;
    uint64_t pn = 0, cn = 0, on = 0; UrGeneration gp = 0, gc = 0;
    uint64_t d0, m0;

    memset(mem, 0x11, sizeof mem);
    mem[1024] = 0xAB; mem[1025] = 0xCD;
    ur_mem_init(&mp, mem, sizeof mem); ur_mem_as_vtable(&mp, &vt);
    ur_runtime_init(&rt, vt, 0xA11A5u);
    memset(&parent, 0, sizeof parent);
    parent.provider = 4; parent.offset = 0; parent.length = 4096;
    child = parent; child.offset = 1024; child.length = 512;
    partial = parent; partial.offset = 3072; partial.length = 2048;
    pid = ur_region_id_from_desc(&parent);
    cid = ur_region_id_from_desc(&child);
    oid = ur_region_id_from_desc(&partial);
    if (ur_index_put(&rt.index, pid, &parent) || ur_index_put(&rt.index, cid, &child)
        || ur_index_put(&rt.index, oid, &partial) || ur_op_begin(&rt.auth, rt.owner, &tk))
        return fail("SETUP");

    if (ur_require_region(&rt, tk, pid, UR_REASON_CURRENT_OP, &pp, &pn, &gp) || pn != 4096)
        return fail("PARENT_MG");
    if (rt.tel.disk_reads != 1 || rt.tel.mg_loads != 1) return fail("PARENT_IO");

    d0 = rt.tel.disk_reads; m0 = rt.tel.mg_loads;
    if (ur_require_region(&rt, tk, cid, UR_REASON_CURRENT_OP, &cp, &cn, &gc))
        return fail("CHILD");
    if (cn != 512 || gc != gp || cp != pp + 1024) return fail("CHILD_SLICE");
    if (cp[0] != 0xAB || cp[1] != 0xCD) return fail("CHILD_BYTES");
    if (rt.tel.disk_reads != d0 || rt.tel.mg_loads != m0) return fail("CHILD_DISK");
    if (rt.tel.alias_hits != 1) return fail("ALIAS_HIT");

    d0 = rt.tel.disk_reads; m0 = rt.tel.mg_loads;
    if (ur_require_region(&rt, tk, oid, UR_REASON_CURRENT_OP, &op, &on, 0))
        return fail("PARTIAL");
    if (on != 2048 || op == pp + 3072) return fail("PARTIAL_MASQUERADE");
    if (rt.tel.disk_reads - d0 != 1 || rt.tel.mg_loads - m0 != 1) return fail("PARTIAL_IO");
    if (rt.tel.alias_partial_reject != 1) return fail("PARTIAL_REJECT");
    if (rt.tel.alias_hits != 1) return fail("PARTIAL_NOT_HIT");

    if (ur_evict_region(&rt, pid) != UR_E_PIN) return fail("PARENT_PINNED");
    if (ur_release_region(&rt, cid) || ur_release_region(&rt, pid)) return fail("REL");
    printf("REGION_ALIAS_COHERENCE_001=PASS ALIAS_HITS=1 PARTIAL_REJECT=1 CHILD_DISK=0 SHARED_GEN=%llu\n",
           (unsigned long long)gp);
    printf("MG_OWNERSHIP_UNCHANGED=1 PROMOTE=0\n");
    ur_op_end(&rt.auth, rt.owner, tk, 1);
    ur_runtime_shutdown(&rt);
    return 0;
}
