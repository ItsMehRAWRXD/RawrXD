/* smoke_gpu.c — RAM_TO_GPU_PROMOTION_001 (fence + readback parity) */
#include "ur_residency.h"
#include <stdio.h>
#include <string.h>

#define RLEN 4096
typedef struct { UrRuntime *rt; UrRegionId id; int rc; } PromoArg;
static int fail(const char *s) { printf("FAIL=%s\n", s); return 1; }
static DWORD WINAPI promo_thr(void *arg)
{
    PromoArg *a = (PromoArg *)arg;
    a->rc = ur_promote_hot(a->rt, a->id);
    return 0;
}

int main(void)
{
    uint8_t mem[RLEN]; UrMemProvider mp; UrGpuDevice gd; UrProviderVTable pvt;
    UrDeviceVTable gvt; UrRuntime rt; UrRegionDesc desc; UrRegionId id; UrTicket tk;
    const uint8_t *p = 0, *p2 = 0; uint64_t n = 0, n2 = 0, d0, m0, c0;
    UrGeneration g = 0; UrHotIdentity hot; UrAllocGeneration old_ag;
    UrResidencyState st; PromoArg pa; HANDLE th;

    memset(mem, 0xA5, sizeof mem); memcpy(mem, "GGUF", 4);
    ur_mem_init(&mp, mem, sizeof mem); ur_mem_as_vtable(&mp, &pvt);
    if (ur_gpudev_init(&gd)) return fail("GPU_INIT");
    if (!gd.discrete || gd.uma) return fail("NOT_DISCRETE");
    gd.after_signal = CreateEventA(0, 1, 0, 0);
    gd.wait_go = CreateEventA(0, 1, 0, 0);
    ur_gpudev_as_vtable(&gd, &gvt);
    ur_runtime_init(&rt, pvt, 0x601u); ur_runtime_set_device(&rt, gvt);
    memset(&desc, 0, sizeof desc); desc.provider = 9; desc.length = RLEN;
    id = ur_region_id_from_desc(&desc);
    if (ur_index_put(&rt.index, id, &desc) || ur_op_begin(&rt.auth, rt.owner, &tk))
        return fail("SETUP");
    if (ur_require_region(&rt, tk, id, UR_REASON_CURRENT_OP, &p, &n, &g) || n != RLEN)
        return fail("WARM");
    if (ur_promote_hot_at(&rt, id, g + 1) != UR_E_AUTH || rt.tel.gpu_copy_issued)
        return fail("STALE");
    pa.rt = &rt; pa.id = id; pa.rc = -99;
    th = CreateThread(0, 0, promo_thr, &pa, 0, 0);
    if (WaitForSingleObject((HANDLE)gd.after_signal, 10000) != WAIT_OBJECT_0)
        return fail("SIGNAL");
    if (!ur_copy_inflight(&rt, id) || ur_region_state(&rt, id, &st) || st != UR_WARM)
        return fail("HOT_BEFORE_FENCE");
    if (gd.fence_signaled < 1 || gd.fence_completed != 0) return fail("FENCE_WINDOW");
    if (ur_evict_region(&rt, id) != UR_E_BUSY) return fail("EVICT_INFLIGHT");
    SetEvent((HANDLE)gd.wait_go);
    WaitForSingleObject(th, INFINITE); CloseHandle(th);
    if (pa.rc) return fail("PROMO");
    if (ur_region_state(&rt, id, &st) || st != UR_HOT) return fail("HOT_AFTER_FENCE");
    if (gd.fence_completed < 1 || !gd.byte_parity) return fail("PARITY");
    if (ur_hot_identity(&rt, id, &hot) || hot.source_gen != g || !ur_gpudev_handle_parity(hot.handle))
        return fail("IDENT");
    if (gd.default_created < 1 || gd.upload_created < 1 || gd.readback_created < 1)
        return fail("HEAPS");
    if (ur_promote_hot(&rt, id) != UR_E_DUP) return fail("DUP");
    d0 = rt.tel.disk_reads; m0 = rt.tel.mg_loads; c0 = rt.tel.gpu_copy_bytes;
    if (ur_require_region(&rt, tk, id, UR_REASON_CURRENT_OP, &p2, &n2, 0)) return fail("HOT2");
    if (rt.tel.disk_reads != d0 || rt.tel.mg_loads != m0 || rt.tel.gpu_copy_bytes != c0)
        return fail("HOT2_DELTA");
    old_ag = hot.alloc_gen;
    if (ur_hot_reset(&rt, id) || ur_hot_valid(&rt, id, old_ag)) return fail("RESET");
    if (ur_promote_hot_at(&rt, id, g) || ur_hot_identity(&rt, id, &hot) || hot.alloc_gen <= old_ag)
        return fail("REUP");
    printf("RAM_TO_GPU_PROMOTION_001=PASS GPU=1 DEVICE_KIND=D3D12_PHYSICAL_GPU PCI=0x%04X UMA=0 DISCRETE=1\n",
           gd.pci);
    printf("GPU_BYTE_PARITY=1 FENCE_SIG=%llu FENCE_DONE=%llu READBACK=%llu D3D12_MAY_DECLARE_HOT=0 PROMOTE=0\n",
           (unsigned long long)gd.fence_signaled, (unsigned long long)gd.fence_completed,
           (unsigned long long)gd.readback_created);
    ur_op_end(&rt.auth, rt.owner, tk, 1);
    ur_runtime_shutdown(&rt);
    CloseHandle((HANDLE)gd.after_signal); CloseHandle((HANDLE)gd.wait_go);
    gd.after_signal = gd.wait_go = 0;
    ur_gpudev_shutdown(&gd);
    return 0;
}
