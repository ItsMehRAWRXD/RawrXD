/* smoke_join.c — RESIDENCY_JOIN_WAIT_001 */
#include "ur_residency.h"
#include <stdio.h>
#include <string.h>

#define NTHR 8
#define RLEN 4096

typedef struct {
    UrMemProvider mem;
    volatile LONG reads;
} SlowProv;

typedef struct {
    UrRuntime *rt; UrTicket tk; UrRegionId id;
    HANDLE start; int rc; UrGeneration gen; const uint8_t *p; uint64_t n;
} JoinArg;

static int fail(const char *s) { printf("FAIL=%s\n", s); return 1; }

static int slow_rr(void *ctx, uint64_t o, uint64_t n, void *d, uint64_t *on)
{
    SlowProv *s = (SlowProv *)ctx;
    InterlockedIncrement(&s->reads);
    Sleep(200);
    return ur_mem_read_range(&s->mem, o, n, d, on);
}
static uint64_t slow_sz(void *ctx) { return ((SlowProv *)ctx)->mem.size; }

static DWORD WINAPI join_thr(void *arg)
{
    JoinArg *a = (JoinArg *)arg;
    WaitForSingleObject(a->start, INFINITE);
    a->rc = ur_require_region(a->rt, a->tk, a->id, UR_REASON_CURRENT_OP,
                              &a->p, &a->n, &a->gen);
    return 0;
}

int main(void)
{
    uint8_t mem[RLEN]; SlowProv sp; UrProviderVTable vt; UrRuntime rt;
    UrRegionDesc desc; UrRegionId id; UrTicket tk; JoinArg args[NTHR];
    HANDLE th[NTHR], start; int i; UrGeneration g0;

    memset(mem, 0x5A, sizeof mem);
    ur_mem_init(&sp.mem, mem, sizeof mem); sp.reads = 0;
    vt.ctx = &sp; vt.read_range = slow_rr; vt.size_fn = slow_sz;
    ur_runtime_init(&rt, vt, 0x4A01u);
    memset(&desc, 0, sizeof desc);
    desc.provider = 3; desc.length = RLEN;
    id = ur_region_id_from_desc(&desc);
    if (ur_index_put(&rt.index, id, &desc) || ur_op_begin(&rt.auth, rt.owner, &tk))
        return fail("SETUP");
    start = CreateEventA(0, 1, 0, 0);
    if (!start) return fail("EVENT");
    for (i = 0; i < NTHR; i++) {
        memset(&args[i], 0, sizeof args[i]);
        args[i].rt = &rt; args[i].tk = tk; args[i].id = id; args[i].start = start;
        th[i] = CreateThread(0, 0, join_thr, &args[i], 0, 0);
        if (!th[i]) return fail("THREAD");
    }
    SetEvent(start);
    WaitForMultipleObjects(NTHR, th, 1, INFINITE);
    g0 = args[0].gen;
    for (i = 0; i < NTHR; i++) {
        CloseHandle(th[i]);
        if (args[i].rc || args[i].n != RLEN || !args[i].p) return fail("THR_RC");
        if (args[i].gen != g0 || args[i].p != args[0].p) return fail("GEN_OR_PTR");
    }
    CloseHandle(start);
    if (sp.reads != 1) return fail("PROVIDER_READS");
    if (rt.tel.mg_claim_winners != 1) return fail("CLAIM_WINNERS");
    if (rt.tel.disk_reads != 1 || rt.tel.mg_loads != 1) return fail("MG_IO");
    if (rt.tel.duplicate_first_touch != 0) return fail("DUP_FIRST");
    if (rt.tel.join_waits < 1 || rt.tel.join_commits < 1) return fail("NO_CONTENTION");
    if (rt.tel.mg_bytes != rt.tel.disk_bytes || rt.tel.mg_bytes != RLEN)
        return fail("BYTES");
    printf("RESIDENCY_JOIN_WAIT_001=PASS THREADS=%d READS=%ld CLAIMS=%llu WAITS=%llu COMMITS=%llu GEN=%llu DUP=0\n",
           NTHR, (long)sp.reads, (unsigned long long)rt.tel.mg_claim_winners,
           (unsigned long long)rt.tel.join_waits, (unsigned long long)rt.tel.join_commits,
           (unsigned long long)g0);
    printf("MG_OWNERSHIP_UNCHANGED=1 PROMOTE=0\n");
    ur_op_end(&rt.auth, rt.owner, tk, 1);
    ur_runtime_shutdown(&rt);
    return 0;
}
