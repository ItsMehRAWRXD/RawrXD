// =============================================================================
// test_c_api.cpp
// Phase 22B: C-API Language Bindings Test Suite
// =============================================================================

#include "../bindings/sovereign_c_api.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

// =============================================================================
// Test Framework
// =============================================================================

struct TestResult {
    const char* name;
    int passed;
    double duration_ms;
    char message[256];
};

static TestResult g_results[20];
static int g_num_results = 0;

double get_time_ms() {
    LARGE_INTEGER freq, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    return (double)now.QuadPart * 1000.0 / freq.QuadPart;
}

void record_result(const char* name, int passed, double duration, const char* msg) {
    if (g_num_results < 20) {
        g_results[g_num_results].name = name;
        g_results[g_num_results].passed = passed;
        g_results[g_num_results].duration_ms = duration;
        strncpy(g_results[g_num_results].message, msg, 255);
        g_results[g_num_results].message[255] = '\0';
        g_num_results++;
    }
}

// =============================================================================
// Test 1: Version Information
// =============================================================================

void test_version() {
    printf("\n[Test 1] Version Information\n");
    
    double start = get_time_ms();
    
    const char* version = sovereign_version_string();
    int major, minor, patch;
    sovereign_get_version(&major, &minor, &patch);
    
    double duration = get_time_ms() - start;
    
    int passed = (version != NULL && major == 1 && minor == 0 && patch == 0) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Version: %s (%d.%d.%d)", 
             version ? version : "NULL", major, minor, patch);
    
    record_result("Version_Info", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 2: Library Initialization
// =============================================================================

void test_init() {
    printf("\n[Test 2] Library Initialization\n");
    
    double start = get_time_ms();
    
    sovereign_error_t err = sovereign_init();
    
    double duration = get_time_ms() - start;
    
    int passed = (err == SOVEREIGN_OK) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Init result: %d", err);
    
    record_result("Library_Init", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
    
    // Cleanup
    sovereign_shutdown();
}

// =============================================================================
// Test 3: Engine Creation
// =============================================================================

void test_engine_creation() {
    printf("\n[Test 3] Engine Creation\n");
    
    double start = get_time_ms();
    
    sovereign_init();
    
    sovereign_loader_config_t loader_config = {};
    loader_config.use_memory_mapping = 1;
    loader_config.use_zero_copy = 1;
    loader_config.num_threads = 4;
    loader_config.max_memory_bytes = 8ULL * 1024 * 1024 * 1024;
    
    sovereign_inference_config_t inference_config = {};
    inference_config.max_tokens = 100;
    inference_config.temperature = 0.8f;
    inference_config.top_p = 0.9f;
    inference_config.top_k = 40;
    inference_config.num_threads = 4;
    inference_config.use_amx = 1;
    inference_config.use_int8 = 1;
    inference_config.enable_kv_cache = 1;
    inference_config.max_memory_bytes = 8ULL * 1024 * 1024 * 1024;
    
    sovereign_engine_t engine = NULL;
    sovereign_error_t err = sovereign_engine_create(
        &loader_config, &inference_config, &engine);
    
    double duration = get_time_ms() - start;
    
    int passed = (err == SOVEREIGN_OK && engine != NULL) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Engine created: %s, Error: %d", 
             engine ? "Yes" : "No", err);
    
    record_result("Engine_Creation", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
    
    if (engine) {
        sovereign_engine_destroy(engine);
    }
    sovereign_shutdown();
}

// =============================================================================
// Test 4: Session Management
// =============================================================================

void test_session_management() {
    printf("\n[Test 4] Session Management\n");
    
    double start = get_time_ms();
    
    sovereign_init();
    
    sovereign_loader_config_t loader_config = {};
    sovereign_inference_config_t inference_config = {};
    inference_config.num_threads = 4;
    
    sovereign_engine_t engine = NULL;
    sovereign_engine_create(&loader_config, &inference_config, &engine);
    
    int session_created = 0;
    int session_destroyed = 0;
    
    if (engine) {
        sovereign_session_t session = NULL;
        sovereign_error_t err = sovereign_session_create(engine, 1, &session);
        session_created = (err == SOVEREIGN_OK && session != NULL) ? 1 : 0;
        
        if (session) {
            sovereign_session_destroy(session);
            session_destroyed = 1;
        }
        
        sovereign_engine_destroy(engine);
    }
    
    sovereign_shutdown();
    
    double duration = get_time_ms() - start;
    
    int passed = (session_created && session_destroyed) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Created: %s, Destroyed: %s",
             session_created ? "Yes" : "No",
             session_destroyed ? "Yes" : "No");
    
    record_result("Session_Management", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 5: Hardware Information
// =============================================================================

void test_hardware_info() {
    printf("\n[Test 5] Hardware Information\n");
    
    double start = get_time_ms();
    
    sovereign_hardware_info_t info;
    sovereign_error_t err = sovereign_get_hardware_info(&info);
    
    double duration = get_time_ms() - start;
    
    int passed = (err == SOVEREIGN_OK) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Cores: %d/%d, Memory: %llu GB, AVX2: %d",
             info.num_physical_cores, info.num_logical_cores,
             (unsigned long long)(info.total_memory_bytes / (1024ULL * 1024 * 1024)),
             info.has_avx2);
    
    record_result("Hardware_Info", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 6: Error Handling
// =============================================================================

void test_error_handling() {
    printf("\n[Test 6] Error Handling\n");
    
    double start = get_time_ms();
    
    // Test NULL engine
    sovereign_error_t err1 = sovereign_engine_load_model(NULL, "test.gguf");
    
    // Test NULL session
    sovereign_error_t err2 = sovereign_session_reset(NULL);
    
    // Test invalid argument
    sovereign_error_t err3 = sovereign_engine_create(NULL, NULL, NULL);
    
    double duration = get_time_ms() - start;
    
    int passed = (err1 == SOVEREIGN_ERROR_INVALID_ARGUMENT &&
                  err2 == SOVEREIGN_ERROR_INVALID_ARGUMENT &&
                  err3 == SOVEREIGN_ERROR_INVALID_ARGUMENT) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Errors: load=%d, reset=%d, create=%d",
             err1, err2, err3);
    
    record_result("Error_Handling", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 7: End-to-End C-API
// =============================================================================

void test_end_to_end() {
    printf("\n[Test 7] End-to-End C-API\n");
    
    double start = get_time_ms();
    
    sovereign_init();
    
    // Create engine
    sovereign_loader_config_t loader_config = {};
    sovereign_inference_config_t inference_config = {};
    inference_config.max_tokens = 10;
    inference_config.num_threads = 4;
    
    sovereign_engine_t engine = NULL;
    sovereign_engine_create(&loader_config, &inference_config, &engine);
    
    int session_ok = 0;
    int generate_ok = 0;
    
    if (engine) {
        // Create session
        sovereign_session_t session = NULL;
        if (sovereign_session_create(engine, 1, &session) == SOVEREIGN_OK) {
            session_ok = 1;
            
            // Generate (will use mock since no model loaded)
            char response[256];
            size_t response_len = sizeof(response);
            uint32_t num_tokens = 0;
            
            sovereign_error_t err = sovereign_generate(
                session, "Hello", response, &response_len, &num_tokens);
            
            generate_ok = (err == SOVEREIGN_OK) ? 1 : 0;
            
            sovereign_session_destroy(session);
        }
        
        sovereign_engine_destroy(engine);
    }
    
    sovereign_shutdown();
    
    double duration = get_time_ms() - start;
    
    int passed = (session_ok && generate_ok) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Session: %s, Generate: %s",
             session_ok ? "OK" : "FAIL",
             generate_ok ? "OK" : "FAIL");
    
    record_result("End_to_End_C_API", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Main
// =============================================================================

int main() {
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Phase 22B: C-API Language Bindings Test Suite            ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    // Run all tests
    test_version();
    test_init();
    test_engine_creation();
    test_session_management();
    test_hardware_info();
    test_error_handling();
    test_end_to_end();
    
    // Print summary
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Test Summary                                                    ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    int total_passed = 0;
    int total_failed = 0;
    double total_duration = 0;
    
    for (int i = 0; i < g_num_results; i++) {
        const char* status = g_results[i].passed ? "PASS" : "FAIL";
        printf("\n[%s] %-30s %.1fms\n", status, g_results[i].name, g_results[i].duration_ms);
        printf("      %s\n", g_results[i].message);
        
        if (g_results[i].passed) total_passed++;
        else total_failed++;
        total_duration += g_results[i].duration_ms;
    }
    
    printf("\n────────────────────────────────────────────────────────────────\n");
    printf("Total: %d tests, %d passed, %d failed\n", g_num_results, total_passed, total_failed);
    printf("Duration: %.1f ms\n", total_duration);
    printf("────────────────────────────────────────────────────────────────\n");
    
    if (total_failed == 0) {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  ALL TESTS PASSED - C-API Ready for Language Bindings        ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        return 0;
    } else {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  SOME TESTS FAILED - Review output above                       ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        return 1;
    }
}
