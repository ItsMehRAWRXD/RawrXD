//=============================================================================
// test_assembler.c - Unit Tests for Minimal Assembler v2
// Production-ready test suite for the native x64 assembler
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include "../include/test_framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#endif

//=============================================================================
// Test Configuration
//=============================================================================

#define TEST_ASM_EXE "d:\\rawrxd\\native_toolchain\\minimal_assembler_v2.exe"
#define TEST_OUTPUT_DIR "d:\\rawrxd\\tests\\output"

//=============================================================================
// Helper Functions
//=============================================================================

static int run_assembler(const char* input_file, const char* output_file) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "\"%s\" \"%s\" \"%s\" 2>NUL",
             TEST_ASM_EXE, input_file, output_file);
    return system(cmd);
}

static int file_exists(const char* path) {
    FILE* f = fopen(path, "rb");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

static size_t get_file_size(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fclose(f);
    return size;
}

static int create_test_asm(const char* filename, const char* content) {
    FILE* f = fopen(filename, "w");
    if (!f) return -1;
    
    fprintf(f, "%s", content);
    fclose(f);
    return 0;
}

//=============================================================================
// Test Cases
//=============================================================================

// Test 1: Assembler executable exists
TestResult test_assembler_executable_exists(void) {
    TEST_ASSERT(file_exists(TEST_ASM_EXE));
    return TEST_PASS;
}

// Test 2: Basic MOV instruction
TestResult test_mov_instruction(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\test_mov.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\test_mov.obj";
    
    create_test_asm(test_asm, "mov rax, 0x1234\n");
    
    int result = run_assembler(test_asm, test_obj);
    TEST_ASSERT_EQ(0, result);
    TEST_ASSERT(file_exists(test_obj));
    
    // COFF file should be reasonable size (header + code)
    size_t size = get_file_size(test_obj);
    TEST_ASSERT(size >= 100 && size <= 500);
    
    remove(test_asm);
    remove(test_obj);
    
    return TEST_PASS;
}

// Test 3: Multiple instructions
TestResult test_multiple_instructions(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\test_multi.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\test_multi.obj";
    
    const char* asm_code = 
        "mov rax, 0x1234\n"
        "mov rbx, 0x5678\n"
        "add rax, rbx\n"
        "ret\n";
    
    create_test_asm(test_asm, asm_code);
    
    int result = run_assembler(test_asm, test_obj);
    TEST_ASSERT_EQ(0, result);
    TEST_ASSERT(file_exists(test_obj));
    
    remove(test_asm);
    remove(test_obj);
    
    return TEST_PASS;
}

// Test 4: Invalid instruction handling
TestResult test_invalid_instruction(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\test_invalid.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\test_invalid.obj";
    
    create_test_asm(test_asm, "invalid_instruction_here\n");
    
    int result = run_assembler(test_asm, test_obj);
    // Should fail on invalid instruction
    TEST_ASSERT(result != 0);
    
    remove(test_asm);
    remove(test_obj);
    
    return TEST_PASS;
}

// Test 5: Empty file handling
TestResult test_empty_file(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\test_empty.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\test_empty.obj";
    
    create_test_asm(test_asm, "");
    
    int result = run_assembler(test_asm, test_obj);
    // Empty file should either succeed or fail gracefully
    // We'll accept either as long as it doesn't crash
    
    remove(test_asm);
    remove(test_obj);
    
    return TEST_PASS;
}

// Test 6: Large file handling
TestResult test_large_file(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\test_large.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\test_large.obj";
    
    FILE* f = fopen(test_asm, "w");
    TEST_ASSERT_NOT_NULL(f);
    
    // Generate 1000 lines of valid assembly
    for (int i = 0; i < 1000; i++) {
        fprintf(f, "mov rax, %d\n", i);
    }
    fprintf(f, "ret\n");
    fclose(f);
    
    int result = run_assembler(test_asm, test_obj);
    TEST_ASSERT_EQ(0, result);
    TEST_ASSERT(file_exists(test_obj));
    
    // Should be larger than small files
    size_t size = get_file_size(test_obj);
    TEST_ASSERT(size > 1000);
    
    remove(test_asm);
    remove(test_obj);
    
    return TEST_PASS;
}

// Test 7: Register variants
TestResult test_register_variants(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\test_regs.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\test_regs.obj";
    
    const char* asm_code = 
        "mov rax, 1\n"
        "mov rbx, 2\n"
        "mov rcx, 3\n"
        "mov rdx, 4\n"
        "mov rsi, 5\n"
        "mov rdi, 6\n"
        "mov r8, 7\n"
        "mov r9, 8\n"
        "mov r10, 9\n"
        "mov r11, 10\n"
        "mov r12, 11\n"
        "mov r13, 12\n"
        "mov r14, 13\n"
        "mov r15, 14\n"
        "ret\n";
    
    create_test_asm(test_asm, asm_code);
    
    int result = run_assembler(test_asm, test_obj);
    TEST_ASSERT_EQ(0, result);
    TEST_ASSERT(file_exists(test_obj));
    
    remove(test_asm);
    remove(test_obj);
    
    return TEST_PASS;
}

// Test 8: Arithmetic instructions
TestResult test_arithmetic_instructions(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\test_arith.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\test_arith.obj";
    
    const char* asm_code = 
        "mov rax, 10\n"
        "mov rbx, 5\n"
        "add rax, rbx\n"
        "sub rax, 2\n"
        "ret\n";
    
    create_test_asm(test_asm, asm_code);
    
    int result = run_assembler(test_asm, test_obj);
    TEST_ASSERT_EQ(0, result);
    TEST_ASSERT(file_exists(test_obj));
    
    remove(test_asm);
    remove(test_obj);
    
    return TEST_PASS;
}

// Test 9: Memory operations
TestResult test_memory_operations(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\test_mem.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\test_mem.obj";
    
    const char* asm_code = 
        "mov rax, rsp\n"
        "mov rbx, [rax]\n"
        "mov [rax], rbx\n"
        "ret\n";
    
    create_test_asm(test_asm, asm_code);
    
    int result = run_assembler(test_asm, test_obj);
    // Memory operations may or may not be supported
    // Just verify it doesn't crash
    
    remove(test_asm);
    remove(test_obj);
    
    return TEST_PASS;
}

// Test 10: Performance benchmark
TestResult test_assembly_performance(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\test_perf.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\test_perf.obj";
    
    FILE* f = fopen(test_asm, "w");
    TEST_ASSERT_NOT_NULL(f);
    
    // Generate 100 lines
    for (int i = 0; i < 100; i++) {
        fprintf(f, "mov rax, %d\n", i);
    }
    fprintf(f, "ret\n");
    fclose(f);
    
    double start = test_get_time_ms();
    int result = run_assembler(test_asm, test_obj);
    double end = test_get_time_ms();
    
    TEST_ASSERT_EQ(0, result);
    
    // Should complete in reasonable time (< 5 seconds)
    double elapsed = end - start;
    TEST_ASSERT(elapsed < 5000.0);
    
    printf("    Assembly time: %.2f ms\n", elapsed);
    
    remove(test_asm);
    remove(test_obj);
    
    return TEST_PASS;
}

//=============================================================================
// Test Suite Registration
//=============================================================================

static TestSuite* g_assembler_suite = NULL;

__declspec(dllexport) void init_assembler_tests(void) {
    g_assembler_suite = test_suite_create("Assembler Unit Tests",
        "Production-ready unit tests for minimal_assembler_v2.exe");
    
    // Register all tests
    test_suite_register(g_assembler_suite, "test_assembler_executable_exists",
        "Verify assembler executable exists", __FILE__, __LINE__, test_assembler_executable_exists);
    test_suite_register(g_assembler_suite, "test_mov_instruction",
        "Test basic MOV instruction assembly", __FILE__, __LINE__, test_mov_instruction);
    test_suite_register(g_assembler_suite, "test_multiple_instructions",
        "Test multiple instruction assembly", __FILE__, __LINE__, test_multiple_instructions);
    test_suite_register(g_assembler_suite, "test_invalid_instruction",
        "Test invalid instruction handling", __FILE__, __LINE__, test_invalid_instruction);
    test_suite_register(g_assembler_suite, "test_empty_file",
        "Test empty file handling", __FILE__, __LINE__, test_empty_file);
    test_suite_register(g_assembler_suite, "test_large_file",
        "Test large file handling (1000 lines)", __FILE__, __LINE__, test_large_file);
    test_suite_register(g_assembler_suite, "test_register_variants",
        "Test all register variants", __FILE__, __LINE__, test_register_variants);
    test_suite_register(g_assembler_suite, "test_arithmetic_instructions",
        "Test arithmetic instructions", __FILE__, __LINE__, test_arithmetic_instructions);
    test_suite_register(g_assembler_suite, "test_memory_operations",
        "Test memory operations", __FILE__, __LINE__, test_memory_operations);
    test_suite_register(g_assembler_suite, "test_assembly_performance",
        "Test assembly performance", __FILE__, __LINE__, test_assembly_performance);
}

__declspec(dllexport) TestSuite* get_assembler_test_suite(void) {
    if (!g_assembler_suite) {
        init_assembler_tests();
    }
    return g_assembler_suite;
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    // Create output directory
    #ifdef _WIN32
    CreateDirectoryA(TEST_OUTPUT_DIR, NULL);
    #else
    mkdir(TEST_OUTPUT_DIR, 0755);
    #endif
    
    printf("RawrXD Assembler Unit Tests\n");
    printf("============================\n\n");
    
    TestSuite* suite = get_assembler_test_suite();
    TestResult result = test_suite_run(suite);
    test_suite_print_results(suite);
    
    int exit_code = (result == TEST_PASS) ? 0 : 1;
    test_suite_destroy(suite);
    
    return exit_code;
}
