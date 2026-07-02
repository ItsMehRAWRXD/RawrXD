/* RawrXD_Integration_Stubs.c
 * Stub implementations for integration testing
 * Provides minimal implementations to avoid C++ compilation freeze
 */

#include <stdint.h>
#include <windows.h>

/* =============================================================================
 * Thread Pool Stubs
 * ============================================================================= */

static uint32_t g_thread_count = 0;
static uint32_t g_task_count = 0;

int ThreadPool_Init(uint32_t num_threads) {
    g_thread_count = num_threads;
    return 1;  // Success
}

int ThreadPool_Submit(void (*task)(void*), void* context) {
    // Execute immediately for testing
    if (task) {
        task(context);
    }
    g_task_count++;
    return 1;  // Success
}

void ThreadPool_Shutdown(void) {
    g_thread_count = 0;
    g_task_count = 0;
}

/* =============================================================================
 * Ring Attention Stubs - REMOVED (provided by RawrXD_Ring_Attention_Simple.obj)
 * ============================================================================= */
/*
typedef struct {
    uint64_t kv_chunks_sent;
    uint64_t kv_chunks_received;
    uint64_t attention_computed;
    uint64_t ring_rotations;
    uint64_t recovery_events;
    uint32_t node_count;
    uint32_t local_node_id;
    uint8_t  is_token_holder;
    uint8_t  ring_active;
    uint8_t  reserved[14];
} RingStats;

static RingStats g_ring_stats = {0};

int RingAttention_Init(int node_count, int local_node_id, int layer_count) {
    memset(&g_ring_stats, 0, sizeof(g_ring_stats));
    g_ring_stats.node_count = node_count;
    g_ring_stats.local_node_id = local_node_id;
    g_ring_stats.ring_active = 1;
    return 1;  // Success
}

int RingAttention_SendKVCache(int layer_id) {
    g_ring_stats.kv_chunks_sent++;
    g_ring_stats.kv_chunks_received++;  // Simulate receive
    return 1;  // Success
}

void RingAttention_GetStats(void* stats) {
    if (stats) {
        memcpy(stats, &g_ring_stats, sizeof(RingStats));
    }
}
*/

/* =============================================================================
 * ASM Loader Stubs
 * ============================================================================= */

typedef void* RawrXD_ModelHandle;

RawrXD_ModelHandle RawrXD_LoadModel(const char* path) {
    (void)path;
    return (void*)0x12345678;  // Dummy handle
}

void RawrXD_UnloadModel(RawrXD_ModelHandle handle) {
    (void)handle;
}

void* RawrXD_GetLayer(RawrXD_ModelHandle handle, uint32_t layer_idx) {
    (void)handle;
    (void)layer_idx;
    return (void*)0x87654321;  // Dummy pointer
}

int RawrXD_KVCache_Init(RawrXD_ModelHandle handle) {
    (void)handle;
    return 1;  // Success
}

/* =============================================================================
 * Ring Attention Additional Stubs
 * ============================================================================= */
int RingAttention_SendKVCache(int layer_id) {
    (void)layer_id;
    return 1;  // Success stub
}
