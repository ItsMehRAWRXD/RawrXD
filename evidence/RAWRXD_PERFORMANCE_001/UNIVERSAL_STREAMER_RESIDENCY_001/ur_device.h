/* ur_device.h — HOT materialization ABI (residency-owned lifetime) */
#ifndef UR_DEVICE_H
#define UR_DEVICE_H
#include "ur_types.h"
#ifdef __cplusplus
extern "C" {
#endif

#define UR_DEVKIND_NONE 0
#define UR_DEVKIND_HOST 1
#define UR_DEVKIND_GPU  2

typedef struct UrDeviceVTable {
    void *ctx;
    uint32_t kind;
    uint32_t physical_gpu;
    int (*alloc_copy)(void *ctx, const uint8_t *src, uint64_t n,
                      UrDeviceId *device_out, UrAllocGeneration *agen_out,
                      void **handle_out);
    int (*upload_begin)(void *ctx, const uint8_t *src, uint64_t n,
                        UrDeviceId *device_out, UrAllocGeneration *agen_out,
                        void **handle_out);
    int (*upload_wait)(void *ctx, void *handle, const uint8_t *src, uint64_t n);
    int (*release)(void *ctx, void *handle);
} UrDeviceVTable;

typedef struct UrGpuDevice {
    UrDeviceId device_id;
    UrAllocGeneration next_gen;
    uint32_t vendor;
    uint32_t pci;
    uint32_t uma;
    uint32_t discrete;
    uint32_t cache_coherent_uma;
    uint32_t isolated_mmu;
    uint64_t vram;
    void *adapter;
    void *dev;
    void *queue;
    void *allocator;
    void *list;
    void *fence;
    void *fence_event;
    void *after_signal;
    void *wait_go;
    uint64_t fence_value;
    uint64_t default_created;
    uint64_t upload_created;
    uint64_t readback_created;
    uint64_t fence_signaled;
    uint64_t fence_completed;
    uint64_t byte_parity;
    uint64_t adapter_luid;
    void *share_fence;
    void *share_fence_nt;
    uint64_t share_fence_val;
} UrGpuDevice;

int ur_gpudev_init(UrGpuDevice *g);
void ur_gpudev_shutdown(UrGpuDevice *g);
void ur_gpudev_as_vtable(UrGpuDevice *g, UrDeviceVTable *vt);
uint64_t ur_gpudev_handle_bytes(void *handle);
int ur_gpudev_handle_parity(void *handle);
uint64_t ur_gpudev_luid(const UrGpuDevice *g);
void *ur_gpu_nt(void *handle);
void *ur_gpudev_fence_nt(const UrGpuDevice *g);
uint64_t ur_gpudev_fence_val(const UrGpuDevice *g);
int ur_gpu_share_fence(UrGpuDevice *g);

typedef struct UrHostDevice {
    UrDeviceId device;
    UrAllocGeneration next_gen;
} UrHostDevice;

void ur_hostdev_init(UrHostDevice *d, UrDeviceId device);
void ur_hostdev_as_vtable(UrHostDevice *d, UrDeviceVTable *vt);

#ifdef __cplusplus
}
#endif
#endif
