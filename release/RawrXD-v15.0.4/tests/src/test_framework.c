//=============================================================================
// test_framework.c - RawrXD Production Test Framework Implementation
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include "test_framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#else
#include <sys/time.h>
#include <unistd.h>
#endif

//=============================================================================
// Global State
//=============================================================================

static TestSuite* g_current_suite = NULL;
static FILE* g_log_file = NULL;

//=============================================================================
// Suite Management
//=============================================================================

TestSuite* test_suite_create(const char* name, const char* description) {
    TestSuite* suite = (TestSuite*)calloc(1, sizeof(TestSuite));
    if (!suite) return NULL;
    
    suite->name = name;
    suite->description = description;
    suite->head = NULL;
    suite->tail = NULL;
    suite->stats.total_tests = 0;
    suite->stats.passed = 0;
    suite->stats.failed = 0;
    suite->stats.skipped = 0;
    suite->stats.errors = 0;
    suite->stats.total_time_ms = 0.0;
    suite->log_file = NULL;
    suite->verbose = 1;
    
    return suite;
}

void test_suite_destroy(TestSuite* suite) {
    if (!suite) return;
    
    TestCase* current = suite->head;
    while (current) {
        TestCase* next = current->next;
        free(current);
        current = next;
    }
    
    if (suite->log_file && suite->log_file != stdout) {
        fclose(suite->log_file);
    }
    
    free(suite);
}

void test_suite_register(TestSuite* suite, const char* name, const char* description,
                         const char* file, int line, TestResult (*run)(void)) {
    if (!suite) return;
    
    TestCase* test = (TestCase*)calloc(1, sizeof(TestCase));
    if (!test) return;
    
    test->name = name;
    test->description = description;
    test->file = file;
    test->line = line;
    test->run = run;
    test->next = NULL;
    
    if (suite->tail) {
        suite->tail->next = test;
        suite->tail = test;
    } else {
        suite->head = test;
        suite->tail = test;
    }
    
    suite->stats.total_tests++;
}

TestResult test_suite_run(TestSuite* suite) {
    if (!suite) return TEST_ERROR;
    
    test_log_start(suite);
    
    TestCase* current = suite->head;
    while (current) {
        double start_time = test_get_time_ms();
        
        test_log_test_start(suite, current);
        
        TestResult result = TEST_ERROR;
        if (current->run) {
            result = current->run();
        }
        
        double end_time = test_get_time_ms();
        double elapsed = end_time - start_time;
        
        suite->stats.total_time_ms += elapsed;
        
        switch (result) {
            case TEST_PASS:
                suite->stats.passed++;
                break;
            case TEST_FAIL:
                suite->stats.failed++;
                break;
            case TEST_SKIP:
                suite->stats.skipped++;
                break;
            case TEST_ERROR:
                suite->stats.errors++;
                break;
        }
        
        test_log_test_end(suite, current, result, elapsed);
        
        current = current->next;
    }
    
    test_log_end(suite);
    
    return (suite->stats.failed == 0 && suite->stats.errors == 0) ? TEST_PASS : TEST_FAIL;
}

void test_suite_print_results(TestSuite* suite) {
    if (!suite) return;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Test Suite: %s\n", suite->name);
    printf("=============================================================================\n");
    printf("  Total Tests:  %d\n", suite->stats.total_tests);
    printf("  Passed:       %d (%.1f%%)\n", suite->stats.passed,
           (suite->stats.total_tests > 0) ? (100.0 * suite->stats.passed / suite->stats.total_tests) : 0);
    printf("  Failed:       %d\n", suite->stats.failed);
    printf("  Skipped:      %d\n", suite->stats.skipped);
    printf("  Errors:       %d\n", suite->stats.errors);
    printf("  Total Time:   %.2f ms\n", suite->stats.total_time_ms);
    printf("=============================================================================\n");
    
    if (suite->stats.failed == 0 && suite->stats.errors == 0) {
        printf("  ✅ ALL TESTS PASSED\n");
    } else {
        printf("  ❌ SOME TESTS FAILED\n");
    }
    printf("=============================================================================\n");
}

//=============================================================================
// Logging
//=============================================================================

void test_log_start(TestSuite* suite) {
    if (!suite) return;
    
    FILE* out = suite->log_file ? suite->log_file : stdout;
    
    fprintf(out, "\n");
    fprintf(out, "=============================================================================\n");
    fprintf(out, "  Starting Test Suite: %s\n", suite->name);
    fprintf(out, "  Description: %s\n", suite->description);
    fprintf(out, "  Time: %s", ctime(&(time_t){time(NULL)}));
    fprintf(out, "=============================================================================\n");
    fprintf(out, "\n");
}

void test_log_end(TestSuite* suite) {
    if (!suite) return;
    
    FILE* out = suite->log_file ? suite->log_file : stdout;
    
    fprintf(out, "\n");
    fprintf(out, "=============================================================================\n");
    fprintf(out, "  Test Suite Complete: %s\n", suite->name);
    fprintf(out, "  Results: %d/%d passed\n", suite->stats.passed, suite->stats.total_tests);
    fprintf(out, "=============================================================================\n");
}

void test_log_test_start(TestSuite* suite, TestCase* test) {
    if (!suite || !test) return;
    
    if (suite->verbose) {
        FILE* out = suite->log_file ? suite->log_file : stdout;
        fprintf(out, "  [RUN] %s\n", test->name);
    }
}

void test_log_test_end(TestSuite* suite, TestCase* test, TestResult result, double time_ms) {
    if (!suite || !test) return;
    
    FILE* out = suite->log_file ? suite->log_file : stdout;
    
    const char* status_str = "UNKNOWN";
    const char* status_color = "";
    
    switch (result) {
        case TEST_PASS:
            status_str = "PASS";
            break;
        case TEST_FAIL:
            status_str = "FAIL";
            break;
        case TEST_SKIP:
            status_str = "SKIP";
            break;
        case TEST_ERROR:
            status_str = "ERROR";
            break;
    }
    
    fprintf(out, "  [%s] %s (%.2f ms)\n", status_str, test->name, time_ms);
}

void test_log_fail(const char* file, int line, const char* message) {
    fprintf(stderr, "  ❌ ASSERTION FAILED at %s:%d\n", file, line);
    fprintf(stderr, "     %s\n", message);
}

void test_log_fail_eq(const char* file, int line, const char* expected_str,
                      const char* actual_str, long long expected, long long actual) {
    fprintf(stderr, "  ❌ ASSERTION FAILED at %s:%d\n", file, line);
    fprintf(stderr, "     Expected: %s = %lld\n", expected_str, expected);
    fprintf(stderr, "     Actual:   %s = %lld\n", actual_str, actual);
}

void test_log_fail_ne(const char* file, int line, const char* expected_str,
                      const char* actual_str) {
    fprintf(stderr, "  ❌ ASSERTION FAILED at %s:%d\n", file, line);
    fprintf(stderr, "     Expected: %s != %s\n", expected_str, actual_str);
    fprintf(stderr, "     But they were equal\n");
}

void test_log_fail_str(const char* file, int line, const char* expected_str,
                       const char* actual_str, const char* expected, const char* actual) {
    fprintf(stderr, "  ❌ ASSERTION FAILED at %s:%d\n", file, line);
    fprintf(stderr, "     Expected: %s = \"%s\"\n", expected_str, expected);
    fprintf(stderr, "     Actual:   %s = \"%s\"\n", actual_str, actual);
}

//=============================================================================
// Utilities
//=============================================================================

void test_sleep_ms(int ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

double test_get_time_ms(void) {
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart * 1000.0 / freq.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
#endif
}

char* test_read_file(const char* filename, size_t* size) {
    FILE* f = fopen(filename, "rb");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* buffer = (char*)malloc(file_size + 1);
    if (!buffer) {
        fclose(f);
        return NULL;
    }
    
    size_t read_size = fread(buffer, 1, file_size, f);
    buffer[read_size] = '\0';
    
    fclose(f);
    
    if (size) *size = read_size;
    return buffer;
}

int test_write_file(const char* filename, const void* data, size_t size) {
    FILE* f = fopen(filename, "wb");
    if (!f) return -1;
    
    size_t written = fwrite(data, 1, size, f);
    fclose(f);
    
    return (written == size) ? 0 : -1;
}

void test_generate_random_data(void* buffer, size_t size) {
    unsigned char* buf = (unsigned char*)buffer;
    for (size_t i = 0; i < size; i++) {
        buf[i] = (unsigned char)(rand() % 256);
    }
}

//=============================================================================
// Memory Tracking (Stub - would need platform-specific implementation)
//=============================================================================

static size_t g_allocations = 0;
static size_t g_bytes_allocated = 0;

void test_memory_tracking_start(void) {
    g_allocations = 0;
    g_bytes_allocated = 0;
}

void test_memory_tracking_stop(void) {
    // Report leaks if any
    if (g_allocations > 0) {
        fprintf(stderr, "  ⚠️  Memory leak detected: %zu allocations, %zu bytes\n",
                g_allocations, g_bytes_allocated);
    }
}

size_t test_memory_get_allocations(void) {
    return g_allocations;
}

size_t test_memory_get_bytes_allocated(void) {
    return g_bytes_allocated;
}

//=============================================================================
// Coverage Reporting (Stub)
//=============================================================================

void test_coverage_start(const char* module_name) {
    (void)module_name;
    // Would integrate with coverage tool
}

void test_coverage_stop(void) {
    // Would stop coverage collection
}

void test_coverage_report(void) {
    // Would generate coverage report
}
