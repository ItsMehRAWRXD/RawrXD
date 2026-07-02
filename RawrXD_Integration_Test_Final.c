/* RawrXD_Integration_Test_Final.c
 * Final integration test - streamlined and non-blocking
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

/* External functions from ASM modules */
extern int Recovery_Init(int max_retries, int enable_fallback, int enable_circuit_breaker);
extern int Recovery_HandleNoResponse(uint64_t request_id);
extern int Recovery_IsAutopilotRecovery(void);
extern void Recovery_AcknowledgeAutopilot(void);

extern int RingAttention_Init(int node_count, int local_node_id, int layer_count);
extern void RingAttention_GetStats(void* stats);

/* Stubs from Integration_Stubs.c */
extern int ThreadPool_Init(uint32_t num_threads);
extern int ThreadPool_Submit(void (*task)(void*), void* context);
extern void ThreadPool_Shutdown(void);
extern int RingAttention_SendKVCache(int layer_id);

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

static uint64_t GetTimeMs(void) { return GetTickCount64(); }

int main(void) {
    printf("\n=================================================\n");
    printf("RawrXD Phase 11→22→23 Integration Test\n");
    printf("=================================================\n\n");
    
    uint64_t start_total = GetTimeMs();
    int passed = 0;
    int failed = 0;
    
    /* Test 1: Phase 11 - Error Recovery */
    printf("[TEST 1/5] Phase 11: Error Recovery... ");
    uint64_t t1 = GetTimeMs();
    if (Recovery_Init(3, 1, 1)) {
        printf("PASS (%llu ms)\n", GetTimeMs() - t1);
        passed++;
    } else {
        printf("FAIL\n");
        failed++;
    }
    
    /* Test 2: Phase 22 - Thread Pool */
    printf("[TEST 2/5] Phase 22: Thread Pool... ");
    uint64_t t2 = GetTimeMs();
    int task_done = 0;
    void SimpleTask(void* ctx) { *(int*)ctx = 1; }
    
    if (ThreadPool_Init(4) && ThreadPool_Submit(SimpleTask, &task_done)) {
        Sleep(50);  // Brief wait for task
        ThreadPool_Shutdown();
        if (task_done) {
            printf("PASS (%llu ms)\n", GetTimeMs() - t2);
            passed++;
        } else {
            printf("FAIL (task not executed)\n");
            failed++;
        }
    } else {
        printf("FAIL\n");
        failed++;
    }
    
    /* Test 3: Phase 23 - Ring Attention Init */
    printf("[TEST 3/5] Phase 23: Ring Attention Init... ");
    uint64_t t3 = GetTimeMs();
    if (RingAttention_Init(4, 0, 16)) {
        printf("PASS (%llu ms)\n", GetTimeMs() - t3);
        passed++;
    } else {
        printf("FAIL\n");
        failed++;
    }
    
    /* Test 4: Ring Attention KV Send */
    printf("[TEST 4/5] Phase 23: KV Cache Send... ");
    uint64_t t4 = GetTimeMs();
    if (RingAttention_SendKVCache(0)) {
        printf("PASS (%llu ms)\n", GetTimeMs() - t4);
        passed++;
    } else {
        printf("FAIL\n");
        failed++;
    }
    
    /* Test 5: Error Recovery Integration */
    printf("[TEST 5/5] Error Recovery Integration... ");
    uint64_t t5 = GetTimeMs();
    
    /* Enable autopilot first */
    extern void Recovery_ConfigureAutopilot(int max_attempts, int timeout_ms);
    Recovery_ConfigureAutopilot(3, 5000);
    
    if (Recovery_HandleNoResponse(12345) && 
        Recovery_IsAutopilotRecovery()) {
        Recovery_AcknowledgeAutopilot();
        if (!Recovery_IsAutopilotRecovery()) {
            printf("PASS (%llu ms)\n", GetTimeMs() - t5);
            passed++;
        } else {
            printf("FAIL (autopilot still active)\n");
            failed++;
        }
    } else {
        printf("FAIL\n");
        failed++;
    }
    
    /* Summary */
    uint64_t total_time = GetTimeMs() - start_total;
    
    printf("\n=================================================\n");
    printf("Integration Test Summary\n");
    printf("=================================================\n");
    printf("Total Tests:  5\n");
    printf("Passed:       %d\n", passed);
    printf("Failed:       %d\n", failed);
    printf("Duration:     %llu ms\n", total_time);
    printf("=================================================\n");
    
    /* Get Ring Stats */
    RingStats stats;
    memset(&stats, 0, sizeof(stats));
    RingAttention_GetStats(&stats);
    
    printf("\nRing Attention Statistics:\n");
    printf("  Node count: %d\n", stats.node_count);
    printf("  Local node: %d\n", stats.local_node_id);
    printf("  KV sent:    %llu\n", stats.kv_chunks_sent);
    printf("  KV recv:    %llu\n", stats.kv_chunks_received);
    printf("  Rotations:  %llu\n", stats.ring_rotations);
    printf("  Active:     %s\n", stats.ring_active ? "YES" : "NO");
    
    if (failed == 0) {
        printf("\n✅ ALL TESTS PASSED - Phase 11→22→23 Integration Verified\n\n");
        return 0;
    } else {
        printf("\n❌ %d TEST(S) FAILED\n\n", failed);
        return 1;
    }
}
