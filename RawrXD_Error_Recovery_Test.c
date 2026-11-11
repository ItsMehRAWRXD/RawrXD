/* RawrXD_Error_Recovery_Test.c
 * Simple C test harness for error recovery system
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <windows.h>

/* Error codes */
#define ERR_NONE                0
#define ERR_OUT_OF_MEMORY       0xE001
#define ERR_MODEL_LOAD_FAILED   0xE002
#define ERR_INFERENCE_TIMEOUT   0xE003
#define ERR_INVALID_INPUT       0xE004
#define ERR_KV_CACHE_FULL       0xE005
#define ERR_GPU_OOM             0xE006
#define ERR_NETWORK_TIMEOUT     0xE007
#define ERR_WORKER_DIED         0xE008
#define ERR_NO_RESPONSE         0xE009
#define ERR_AUTOPILOT_RECOVERY  0xE00A

/* Circuit breaker states */
#define CB_STATE_CLOSED     0
#define CB_STATE_OPEN       1
#define CB_STATE_HALF_OPEN  2

/* Recovery statistics structure */
typedef struct {
    uint64_t total_requests;
    uint64_t successful_requests;
    uint64_t failed_requests;
    uint64_t recovered_requests;
    uint64_t no_response_count;
    uint64_t autopilot_recovery_count;
    int32_t  cb_state;
    bool     fallback_active;
    bool     autopilot_recovery_active;
} RecoveryStats;

/* External assembly functions */
extern int Recovery_Init(int max_retries, int enable_fallback, int enable_circuit_breaker);
extern int Recovery_ShouldAttemptRequest(void);
extern void Recovery_GetStats(RecoveryStats* stats);
extern void Recovery_Reset(void);
extern void Recovery_ConfigureAutopilot(int max_autopilot_attempts, uint32_t autopilot_timeout_ms);
extern int Recovery_HandleNoResponse(uint64_t request_id);
extern int Recovery_IsAutopilotRecovery(void);
extern void Recovery_AcknowledgeAutopilot(void);
extern uint32_t Recovery_GetRetryDelay(void);

/* Test counters */
static int tests_passed = 0;
static int tests_failed = 0;

/* Test macros */
#define TEST_START(name) printf("[TEST] %-50s ", name)
#define TEST_PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)
#define ASSERT_TRUE(cond, msg) if (!(cond)) { TEST_FAIL(msg); return; }
#define ASSERT_EQ(a, b, msg) if ((a) != (b)) { TEST_FAIL(msg); return; }

/* =============================================================================
 * Test 1: Circuit Breaker Initialization
 * ============================================================================= */
void test_circuit_breaker_init(void) {
    TEST_START("Circuit breaker initialization");
    
    /* Initialize with circuit breaker enabled */
    int result = Recovery_Init(3, 1, 1);
    ASSERT_EQ(result, 1, "Recovery_Init failed");
    
    /* Check circuit is closed */
    int should_attempt = Recovery_ShouldAttemptRequest();
    ASSERT_EQ(should_attempt, 1, "Circuit should be closed initially");
    
    /* Reset for next tests */
    Recovery_Reset();
    
    TEST_PASS();
}

/* =============================================================================
 * Test 2: No Response Handling
 * ============================================================================= */
void test_no_response_handling(void) {
    TEST_START("No response handling");
    
    /* Initialize recovery */
    Recovery_Init(5, 1, 1);
    
    /* Configure autopilot */
    Recovery_ConfigureAutopilot(3, 5000);
    
    /* Simulate no response */
    int result = Recovery_HandleNoResponse(12345);
    ASSERT_EQ(result, 1, "HandleNoResponse should succeed");
    
    /* Check autopilot is active */
    int autopilot_active = Recovery_IsAutopilotRecovery();
    ASSERT_EQ(autopilot_active, 1, "Autopilot should be active");
    
    /* Acknowledge recovery */
    Recovery_AcknowledgeAutopilot();
    
    /* Verify autopilot is no longer active */
    autopilot_active = Recovery_IsAutopilotRecovery();
    ASSERT_EQ(autopilot_active, 0, "Autopilot should be inactive after ack");
    
    Recovery_Reset();
    TEST_PASS();
}

/* =============================================================================
 * Test 3: Autopilot Recovery Mode
 * ============================================================================= */
void test_autopilot_recovery_mode(void) {
    TEST_START("Autopilot recovery mode");
    
    Recovery_Init(5, 1, 1);
    Recovery_ConfigureAutopilot(2, 1000);  /* 2 attempts max */
    
    /* First no-response should activate autopilot */
    int result = Recovery_HandleNoResponse(1);
    ASSERT_EQ(result, 1, "First no-response should activate autopilot");
    
    int autopilot_active = Recovery_IsAutopilotRecovery();
    ASSERT_EQ(autopilot_active, 1, "Autopilot should be active");
    
    /* Second attempt should still work */
    result = Recovery_HandleNoResponse(2);
    ASSERT_EQ(result, 1, "Second no-response should continue");
    
    /* Third attempt should fail (exceeds max of 2) */
    result = Recovery_HandleNoResponse(3);
    ASSERT_EQ(result, 0, "Third no-response should fail (exceeded max)");
    
    /* Verify autopilot deactivated after giving up */
    autopilot_active = Recovery_IsAutopilotRecovery();
    ASSERT_EQ(autopilot_active, 0, "Autopilot should deactivate after giving up");
    
    Recovery_Reset();
    TEST_PASS();
}

/* =============================================================================
 * Test 4: Statistics Tracking
 * ============================================================================= */
void test_statistics_tracking(void) {
    TEST_START("Statistics tracking");
    
    RecoveryStats stats;
    
    Recovery_Init(5, 1, 1);
    Recovery_ConfigureAutopilot(3, 5000);
    
    /* Trigger no response */
    Recovery_HandleNoResponse(100);
    
    /* Acknowledge */
    Recovery_AcknowledgeAutopilot();
    
    /* Get statistics */
    memset(&stats, 0, sizeof(stats));
    Recovery_GetStats(&stats);
    
    /* Verify no_response_count is non-zero */
    ASSERT_TRUE(stats.no_response_count > 0, "no_response_count should be > 0");
    
    /* Verify autopilot_recovery_count is non-zero */
    ASSERT_TRUE(stats.autopilot_recovery_count > 0, "autopilot_recovery_count should be > 0");
    
    Recovery_Reset();
    TEST_PASS();
}

/* =============================================================================
 * Test 5: Retry Delay Calculation
 * ============================================================================= */
void test_retry_delay(void) {
    TEST_START("Retry delay calculation");
    
    Recovery_Init(5, 0, 0);
    
    /* Get initial retry delay */
    uint32_t delay = Recovery_GetRetryDelay();
    ASSERT_TRUE(delay >= 100, "Initial delay should be >= 100ms");
    ASSERT_TRUE(delay <= 5000, "Delay should be capped at 5000ms");
    
    Recovery_Reset();
    TEST_PASS();
}

/* =============================================================================
 * Main Entry Point
 * ============================================================================= */
int main(void) {
    printf("\n");
    printf("=================================================\n");
    printf("RawrXD Error Recovery Test Suite\n");
    printf("=================================================\n\n");
    
    /* Run all tests */
    test_circuit_breaker_init();
    test_no_response_handling();
    test_autopilot_recovery_mode();
    test_statistics_tracking();
    test_retry_delay();
    
    /* Print summary */
    printf("\n=================================================\n");
    printf("Test Summary\n");
    printf("=================================================\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    /* Print final statistics */
    RecoveryStats stats;
    memset(&stats, 0, sizeof(stats));
    Recovery_GetStats(&stats);
    
    printf("\nRecovery Statistics:\n");
    printf("  No Response Count:      %llu\n", (unsigned long long)stats.no_response_count);
    printf("  Autopilot Recoveries:   %llu\n", (unsigned long long)stats.autopilot_recovery_count);
    printf("  Circuit State:          %d (%s)\n", 
           stats.cb_state,
           stats.cb_state == CB_STATE_CLOSED ? "CLOSED" :
           stats.cb_state == CB_STATE_OPEN ? "OPEN" : "HALF_OPEN");
    printf("  Autopilot Active:       %s\n", stats.autopilot_recovery_active ? "YES" : "NO");
    
    printf("\n=================================================\n");
    
    return (tests_failed > 0) ? 1 : 0;
}
