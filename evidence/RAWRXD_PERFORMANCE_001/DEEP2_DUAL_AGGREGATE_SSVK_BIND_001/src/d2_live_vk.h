#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Live dual-lane Vulkan context for DEEP2_DUAL_AGGREGATE_SSVK_BIND_001 */
struct D2LiveLane {
    void* phys;   /* VkPhysicalDevice */
    void* dev;    /* VkDevice */
    void* q;      /* VkQueue */
    void* pool;   /* VkCommandPool */
    void* buf;    /* VkBuffer local */
    void* mem;    /* VkDeviceMemory */
    void* cb;     /* VkCommandBuffer pending */
    uint32_t qfam;
    uint64_t local_bytes;
    uint64_t start_ns;
    uint64_t end_ns;
    uint32_t submitted;
    uint32_t collected;
    uint32_t real_forwards;
    uint32_t device_lost;
};
struct D2LiveCtx {
    void* inst; /* VkInstance */
    void* lib;  /* HMODULE */
    D2LiveLane lane[2];
    uint32_t ready;
};
uint64_t d2_live_qpc_ns(void);
int d2_live_open(D2LiveCtx* c);
void d2_live_close(D2LiveCtx* c);
int d2_live_enqueue_lane(D2LiveCtx* c, uint32_t gpu, uint64_t bytes);
int d2_live_collect_lane(D2LiveCtx* c, uint32_t gpu);
#ifdef __cplusplus
}
#endif
