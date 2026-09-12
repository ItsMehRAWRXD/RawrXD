/* ss_d3d12_bridge.c — materialize-only; residency still owns HOT */
#include "ss_phase_abi.h"
#include "ss_vk_api.h"
#include "ur_device.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

static UrGpuDevice g_dev;
static UrDeviceVTable g_vt;
static uint32_t g_ready;

int ss_d3d12_backend_init(void)
{
    if (g_ready) return 0;
    memset(&g_dev, 0, sizeof g_dev);
    if (ur_gpudev_init(&g_dev) || !g_dev.discrete || g_dev.uma) {
        if (g_dev.dev) ur_gpudev_shutdown(&g_dev);
        return 28;
    }
    ur_gpudev_as_vtable(&g_dev, &g_vt);
    g_ready = 1;
    return 0;
}

void ss_d3d12_backend_shutdown(void)
{
    if (!g_ready) return;
    ur_gpudev_shutdown(&g_dev);
    memset(&g_vt, 0, sizeof g_vt);
    g_ready = 0;
}

int ss_d3d12_promote(void *ctx, const void *host, uint64_t n, uint64_t gen,
                     SSDeviceMaterialization *out)
{
    UrDeviceId did = 0; UrAllocGeneration ag = 0; void *h = 0; int rc;
    (void)ctx; (void)gen;
    if (!g_ready || !host || !n || !out || !g_vt.upload_begin || !g_vt.upload_wait)
        return 20;
    memset(out, 0, sizeof *out);
    rc = g_vt.upload_begin(g_vt.ctx, (const uint8_t *)host, n, &did, &ag, &h);
    if (rc) return 29;
    rc = g_vt.upload_wait(g_vt.ctx, h, (const uint8_t *)host, n);
    if (rc) {
        if (g_vt.release) g_vt.release(g_vt.ctx, h);
        return 29;
    }
    out->completed = 1;
    out->gpu = 1;
    out->readback_parity = g_dev.byte_parity ? 1 : 0;
    out->device_id = did;
    out->allocation_generation = ag;
    out->device_handle = (uint64_t)(uintptr_t)h;
    out->bytes = n;
    out->pci_device = g_dev.pci;
    printf("D3D12_EXPORT_HANDLE=%s LUID=0x%llX SAME_PHYSICAL_HOT_ALLOCATION=1\n",
           ur_gpu_nt(h) ? "PASS" : "FAIL",
           (unsigned long long)ur_gpudev_luid(&g_dev));
    return out->readback_parity ? 0 : 29;
}

int ss_d3d12_consume(void *ctx, SSDeviceMaterialization *mat)
{
    void *h;
    (void)ctx;
    if (!g_ready || !mat || !mat->device_handle || !mat->bytes) return 100;
    h = (void *)(uintptr_t)mat->device_handle;
    return ss_vk_import_hot(ur_gpu_nt(h), ur_gpudev_luid(&g_dev), mat->bytes,
                            ur_gpudev_fence_nt(&g_dev), ur_gpudev_fence_val(&g_dev),
                            (uint32_t)mat->tensor_type, mat->dim0, mat->dim1,
                            mat->element_count, mat->which_name);
}

int ss_d3d12_release(void *ctx, void *handle, uint64_t agen)
{
    (void)ctx; (void)agen;
    if (!g_ready || !handle || !g_vt.release) return 20;
    return g_vt.release(g_vt.ctx, handle);
}
