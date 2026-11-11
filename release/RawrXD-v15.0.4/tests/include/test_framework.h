//=============================================================================
// test_framework.h - RawrXD Production Test Framework
// Comprehensive testing infrastructure for native toolchain
//=============================================================================

#ifndef RAWRXD_TEST_FRAMEWORK_H
#define RAWRXD_TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#endif

//=============================================================================
// Test Result Types
//=============================================================================

typedef enum {
    TEST_PASS,
    TEST_FAIL,
    TEST_SKIP,
    TEST_ERROR
} TestResult;

//=============================================================================
// Test Statistics
//=============================================================================

typedef struct {
    int total_tests;
    int passed;
    int failed;
    int skipped;
    int errors;
    double total_time_ms;
} TestSuiteStats;

//=============================================================================
// Test Case Structure
//=============================================================================

typedef struct TestCase {
    const char* name;
    const char* description;
    const char* file;
    int line;
    TestResult (*run)(void);
    struct TestCase* next;
} TestCase;

//=============================================================================
// Test Suite Structure
//=============================================================================

typedef struct {
    const char* name;
    const char* description;
    TestCase* head;
    TestCase* tail;
    TestSuiteStats stats;
    FILE* log_file;
    int verbose;
} TestSuite;

//=============================================================================
// Assertion Macros
//=============================================================================

#define TEST_ASSERT(condition) \
    do { \
        if (!(condition)) { \
            test_log_fail(__FILE__, __LINE__, #condition); \
            return TEST_FAIL; \
        } \
    } while(0)

#define TEST_ASSERT_EQ(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            test_log_fail_eq(__FILE__, __LINE__, #expected, #actual, \
                            (long long)(expected), (long long)(actual)); \
            return TEST_FAIL; \
        } \
    } while(0)

#define TEST_ASSERT_NE(expected, actual) \
    do { \
        if ((expected) == (actual)) { \
            test_log_fail_ne(__FILE__, __LINE__, #expected, #actual); \
            return TEST_FAIL; \
        } \
    } while(0)

#define TEST_ASSERT_NULL(ptr) \
    do { \
        if ((ptr) != NULL) { \
            test_log_fail(__FILE__, __LINE__, #ptr " should be NULL"); \
            return TEST_FAIL; \
        } \
    } while(0)

#define TEST_ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            test_log_fail(__FILE__, __LINE__, #ptr " should not be NULL"); \
            return TEST_FAIL; \
        } \
    } while(0)

#define TEST_ASSERT_STR_EQ(expected, actual) \
    do { \
        if (strcmp((expected), (actual)) != 0) { \
            test_log_fail_str(__FILE__, __LINE__, #expected, #actual, \
                             (expected), (actual)); \
            return TEST_FAIL; \
        } \
    } while(0)

//=============================================================================
// Test Registration Macros
//=============================================================================

#define TEST_CASE(suite, name, desc) \
    static TestResult test_##name(void); \
    static void __attribute__((constructor)) register_##name(void) { \
        test_suite_register(suite, #name, desc, __FILE__, __LINE__, test_##name); \
    } \
    static TestResult test_##name(void)

//=============================================================================
// Function Declarations
//=============================================================================

// Suite management
TestSuite* test_suite_create(const char* name, const char* description);
void test_suite_destroy(TestSuite* suite);
void test_suite_register(TestSuite* suite, const char* name, const char* description,
                         const char* file, int line, TestResult (*run)(void));
TestResult test_suite_run(TestSuite* suite);
void test_suite_print_results(TestSuite* suite);

// Logging
void test_log_start(TestSuite* suite);
void test_log_end(TestSuite* suite);
void test_log_test_start(TestSuite* suite, TestCase* test);
void test_log_test_end(TestSuite* suite, TestCase* test, TestResult result, double time_ms);
void test_log_fail(const char* file, int line, const char* message);
void test_log_fail_eq(const char* file, int line, const char* expected_str,
                      const char* actual_str, long long expected, long long actual);
void test_log_fail_ne(const char* file, int line, const char* expected_str,
                      const char* actual_str);
void test_log_fail_str(const char* file, int line, const char* expected_str,
                       const char* actual_str, const char* expected, const char* actual);

// Utilities
void test_sleep_ms(int ms);
double test_get_time_ms(void);
char* test_read_file(const char* filename, size_t* size);
int test_write_file(const char* filename, const void* data, size_t size);
void test_generate_random_data(void* buffer, size_t size);

// Memory tracking (for leak detection)
void test_memory_tracking_start(void);
void test_memory_tracking_stop(void);
size_t test_memory_get_allocations(void);
size_t test_memory_get_bytes_allocated(void);

// Coverage reporting
void test_coverage_start(const char* module_name);
void test_coverage_stop(void);
void test_coverage_report(void);

#endif // RAWRXD_TEST_FRAMEWORK_H
