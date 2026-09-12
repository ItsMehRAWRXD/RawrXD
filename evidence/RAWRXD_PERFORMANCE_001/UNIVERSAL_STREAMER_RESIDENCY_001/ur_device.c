/* ur_device.c — host VirtualAlloc device + HOT upload/reset */
#include "ur_internal.h"
#include <string.h>

void ur_hostdev_init(UrHostDevice *d, UrDeviceId device)
{
    if (!d) return;
    d->device = device ? device : 1;
    d->next_gen = 0;
}

static int host_alloc_copy(void *ctx, const uint8_t *src, uint64_t n,
                           UrDeviceId *dev, UrAllocGeneration *agen,
                           void **handle)
{
    UrHostDevice *d = (UrHostDevice *)ctx;
    void *p;
    if (!d || !src || !n || !dev || !agen || !handle) return UR_E_ARG;
    p = VirtualAlloc(0, (SIZE_T)n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) return UR_E_OOM;
    memcpy(p, src, (size_t)n);
    *dev = d->device;
    *agen = ++d->next_gen;
    *handle = p;
    return UR_OK;
}

static int host_release(void *ctx, void *handle)
{
    (void)ctx;
    if (!handle) return UR_E_ARG;
    return VirtualFree(handle, 0, MEM_RELEASE) ? UR_OK : UR_E_IO;
}

void ur_hostdev_as_vtable(UrHostDevice *d, UrDeviceVTable *vt)
{
    memset(vt, 0, sizeof *vt);
    vt->ctx = d;
    vt->kind = UR_DEVKIND_HOST;
    vt->physical_gpu = 0;
    vt->alloc_copy = host_alloc_copy;
    vt->release = host_release;
}

void ur_slot_drop_device(UrRuntime *r, UrCacheSlot *s)
{
    if (!r || !s || !s->dev_handle) return;
    if (r->device.release) r->device.release(r->device.ctx, s->dev_handle);
    s->dev_handle = 0;
    s->device_id = 0;
    s->dev_alloc_gen = 0;
    s->hot_source_gen = 0;
    r->tel.device_invalidations++;
}

