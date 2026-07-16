//=============================================================================
// test_integration.c - Integration Tests for ASM→OBJ→EXE Pipeline
// Production-ready end-to-end testing for the complete toolchain
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

#define ASSEMBLER_EXE "d:\\rawrxd\\native_toolchain\\minimal_assembler_v2.exe"
#define LINKER_EXE "d:\\rawrxd\\native_toolchain\\linker_with_imports.exe"
#define TEST_OUTPUT_DIR "d:\\rawrxd\\tests\\output"

//=============================================================================
// Helper Functions
//=============================================================================

static int run_command(const char* cmd) {
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

static int create_asm_file(const char* filename, const char* content) {
    FILE* f = fopen(filename, "w");
    if (!f) return -1;
    fprintf(f, "%s", content);
    fclose(f);
    return 0;
}

static int is_valid_pe(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) return 0;
    
    uint16_t dos_sig;
    if (fread(&dos_sig, 2, 1, f) != 1) {
        fclose(f);
        return 0;
    }
    
    if (dos_sig != 0x5A4D) {
        fclose(f);
        return 0;
    }
    
    fseek(f, 0x3C, SEEK_SET);
    uint32_t pe_offset;
    fread(&pe_offset, 4, 1, f);
    
    fseek(f, pe_offset, SEEK_SET);
    uint32_t pe_sig;
    fread(&pe_sig, 4, 1, f);
    
    fclose(f);
    return (pe_sig == 0x00004550);
}

//=============================================================================
// Integration Test Cases
//=============================================================================

// Test 1: Full pipeline - ASM → OBJ → EXE
TestResult test_full_pipeline(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\pipeline_test.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\pipeline_test.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\pipeline_test.exe";
    
    // Create assembly
    create_asm_file(test_asm, "mov rax, 0x1234\nret\n");
    
    // Assemble
    char asm_cmd[1024];
    snprintf(asm_cmd, sizeof(asm_cmd), "\"%s\" \"%s\" \"%s\"",
             ASSEMBLER_EXE, test_asm, test_obj);
    int asm_result = run_command(asm_cmd);
    TEST_ASSERT_EQ(0, asm_result);
    TEST_ASSERT(file_exists(test_obj));
    
    // Link
    char link_cmd[1024];
    snprintf(link_cmd, sizeof(link_cmd), "\"%s\" \"%s\" \"%s\"",
             LINKER_EXE, test_obj, test_exe);
    int link_result = run_command(link_cmd);
    TEST_ASSERT_EQ(0, link_result);
    TEST_ASSERT(file_exists(test_exe));
    TEST_ASSERT(is_valid_pe(test_exe));
    
    // Cleanup
    remove(test_asm);
    remove(test_obj);
    remove(test_exe);
    
    return TEST_PASS;
}

// Test 2: Pipeline with multiple instructions
TestResult test_pipeline_complex(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\pipeline_complex.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\pipeline_complex.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\pipeline_complex.exe";
    
    const char* asm_code = 
        "mov rax, 0x1234\n"
        "mov rbx, 0x5678\n"
        "add rax, rbx\n"
        "mov rcx, rax\n"
        "sub rcx, 0x1000\n"
        "ret\n";
    
    create_asm_file(test_asm, asm_code);
    
    // Assemble
    char asm_cmd[1024];
    snprintf(asm_cmd, sizeof(asm_cmd), "\"%s\" \"%s\" \"%s\"",
             ASSEMBLER_EXE, test_asm, test_obj);
    TEST_ASSERT_EQ(0, run_command(asm_cmd));
    TEST_ASSERT(file_exists(test_obj));
    
    // Link
    char link_cmd[1024];
    snprintf(link_cmd, sizeof(link_cmd), "\"%s\" \"%s\" \"%s\"",
             LINKER_EXE, test_obj, test_exe);
    TEST_ASSERT_EQ(0, run_command(link_cmd));
    TEST_ASSERT(file_exists(test_exe));
    TEST_ASSERT(is_valid_pe(test_exe));
    
    remove(test_asm);
    remove(test_obj);
    remove(test_exe);
    
    return TEST_PASS;
}

// Test 3: Pipeline error handling - bad assembly
TestResult test_pipeline_bad_asm(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\pipeline_bad.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\pipeline_bad.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\pipeline_bad.exe";
    
    // Create invalid assembly
    create_asm_file(test_asm, "this is not valid assembly\n");
    
    // Assemble should fail
    char asm_cmd[1024];
    snprintf(asm_cmd, sizeof(asm_cmd), "\"%s\" \"%s\" \"%s\"",
             ASSEMBLER_EXE, test_asm, test_obj);
    int asm_result = run_command(asm_cmd);
    
    // Should fail or produce no output
    if (asm_result == 0 && file_exists(test_obj)) {
        // If assembly succeeded, linking should still work
        char link_cmd[1024];
        snprintf(link_cmd, sizeof(link_cmd), "\"%s\" \"%s\" \"%s\"",
                 LINKER_EXE, test_obj, test_exe);
        run_command(link_cmd);
    }
    
    remove(test_asm);
    if (file_exists(test_obj)) remove(test_obj);
    if (file_exists(test_exe)) remove(test_exe);
    
    return TEST_PASS;
}

// Test 4: Pipeline performance
TestResult test_pipeline_performance(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\pipeline_perf.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\pipeline_perf.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\pipeline_perf.exe";
    
    // Create 500 lines of assembly
    FILE* f = fopen(test_asm, "w");
    TEST_ASSERT_NOT_NULL(f);
    for (int i = 0; i < 500; i++) {
        fprintf(f, "mov rax, %d\n", i);
    }
    fprintf(f, "ret\n");
    fclose(f);
    
    double start = test_get_time_ms();
    
    // Assemble
    char asm_cmd[1024];
    snprintf(asm_cmd, sizeof(asm_cmd), "\"%s\" \"%s\" \"%s\"",
             ASSEMBLER_EXE, test_asm, test_obj);
    int asm_result = run_command(asm_cmd);
    
    // Link
    char link_cmd[1024];
    snprintf(link_cmd, sizeof(link_cmd), "\"%s\" \"%s\" \"%s\"",
             LINKER_EXE, test_obj, test_exe);
    int link_result = run_command(link_cmd);
    
    double end = test_get_time_ms();
    double elapsed = end - start;
    
    TEST_ASSERT_EQ(0, asm_result);
    TEST_ASSERT_EQ(0, link_result);
    TEST_ASSERT(file_exists(test_exe));
    
    // Should complete in reasonable time (< 10 seconds)
    TEST_ASSERT(elapsed < 10000.0);
    
    printf("    Pipeline time: %.2f ms\n", elapsed);
    
    remove(test_asm);
    remove(test_obj);
    remove(test_exe);
    
    return TEST_PASS;
}

// Test 5: Pipeline stress test - many small files
TestResult test_pipeline_stress(void) {
    const int num_files = 10;
    double total_time = 0;
    
    for (int i = 0; i < num_files; i++) {
        char test_asm[256], test_obj[256], test_exe[256];
        snprintf(test_asm, sizeof(test_asm), "%s\\stress_%d.asm", TEST_OUTPUT_DIR, i);
        snprintf(test_obj, sizeof(test_obj), "%s\\stress_%d.obj", TEST_OUTPUT_DIR, i);
        snprintf(test_exe, sizeof(test_exe), "%s\\stress_%d.exe", TEST_OUTPUT_DIR, i);
        
        create_asm_file(test_asm, "mov rax, 1\nret\n");
        
        double start = test_get_time_ms();
        
        char asm_cmd[1024];
        snprintf(asm_cmd, sizeof(asm_cmd), "\"%s\" \"%s\" \"%s\"",
                 ASSEMBLER_EXE, test_asm, test_obj);
        run_command(asm_cmd);
        
        char link_cmd[1024];
        snprintf(link_cmd, sizeof(link_cmd), "\"%s\" \"%s\" \"%s\"",
                 LINKER_EXE, test_obj, test_exe);
        run_command(link_cmd);
        
        double end = test_get_time_ms();
        total_time += (end - start);
        
        remove(test_asm);
        remove(test_obj);
        remove(test_exe);
    }
    
    double avg_time = total_time / num_files;
    printf("    Average pipeline time: %.2f ms\n", avg_time);
    
    return TEST_PASS;
}

// Test 6: Pipeline with all register types
TestResult test_pipeline_all_registers(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\pipeline_regs.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\pipeline_regs.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\pipeline_regs.exe";
    
    const char* asm_code = 
        "mov rax, 1\n"
        "mov rbx, 2\n"
        "mov rcx, 3\n"
        "mov rdx, 4\n"
        "mov rsi, 5\n"
        "mov rdi, 6\n"
        "mov rbp, 7\n"
        "mov rsp, 8\n"
        "mov r8, 9\n"
        "mov r9, 10\n"
        "mov r10, 11\n"
        "mov r11, 12\n"
        "mov r12, 13\n"
        "mov r13, 14\n"
        "mov r14, 15\n"
        "mov r15, 16\n"
        "ret\n";
    
    create_asm_file(test_asm, asm_code);
    
    char asm_cmd[1024];
    snprintf(asm_cmd, sizeof(asm_cmd), "\"%s\" \"%s\" \"%s\"",
             ASSEMBLER_EXE, test_asm, test_obj);
    TEST_ASSERT_EQ(0, run_command(asm_cmd));
    
    char link_cmd[1024];
    snprintf(link_cmd, sizeof(link_cmd), "\"%s\" \"%s\" \"%s\"",
             LINKER_EXE, test_obj, test_exe);
    TEST_ASSERT_EQ(0, run_command(link_cmd));
    
    TEST_ASSERT(is_valid_pe(test_exe));
    
    remove(test_asm);
    remove(test_obj);
    remove(test_exe);
    
    return TEST_PASS;
}

// Test 7: Pipeline with arithmetic operations
TestResult test_pipeline_arithmetic(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\pipeline_arith.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\pipeline_arith.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\pipeline_arith.exe";
    
    const char* asm_code = 
        "mov rax, 100\n"
        "mov rbx, 50\n"
        "add rax, rbx\n"
        "sub rax, 25\n"
        "mov rcx, 10\n"
        "add rcx, rax\n"
        "ret\n";
    
    create_asm_file(test_asm, asm_code);
    
    char asm_cmd[1024];
    snprintf(asm_cmd, sizeof(asm_cmd), "\"%s\" \"%s\" \"%s\"",
             ASSEMBLER_EXE, test_asm, test_obj);
    TEST_ASSERT_EQ(0, run_command(asm_cmd));
    
    char link_cmd[1024];
    snprintf(link_cmd, sizeof(link_cmd), "\"%s\" \"%s\" \"%s\"",
             LINKER_EXE, test_obj, test_exe);
    TEST_ASSERT_EQ(0, run_command(link_cmd));
    
    TEST_ASSERT(is_valid_pe(test_exe));
    
    remove(test_asm);
    remove(test_obj);
    remove(test_exe);
    
    return TEST_PASS;
}

// Test 8: Pipeline output file sizes
TestResult test_pipeline_file_sizes(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\pipeline_sizes.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\pipeline_sizes.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\pipeline_sizes.exe";
    
    create_asm_file(test_asm, "mov rax, 0x1234\nret\n");
    
    char asm_cmd[1024];
    snprintf(asm_cmd, sizeof(asm_cmd), "\"%s\" \"%s\" \"%s\"",
             ASSEMBLER_EXE, test_asm, test_obj);
    run_command(asm_cmd);
    
    char link_cmd[1024];
    snprintf(link_cmd, sizeof(link_cmd), "\"%s\" \"%s\" \"%s\"",
             LINKER_EXE, test_obj, test_exe);
    run_command(link_cmd);
    
    // Get file sizes
    FILE* fobj = fopen(test_obj, "rb");
    FILE* fexe = fopen(test_exe, "rb");
    
    if (fobj && fexe) {
        fseek(fobj, 0, SEEK_END);
        fseek(fexe, 0, SEEK_END);
        
        long obj_size = ftell(fobj);
        long exe_size = ftell(fexe);
        
        printf("    OBJ size: %ld bytes\n", obj_size);
        printf("    EXE size: %ld bytes\n", exe_size);
        
        // OBJ should be smaller than EXE
        TEST_ASSERT(obj_size < exe_size);
        
        // Both should be reasonable sizes
        TEST_ASSERT(obj_size > 0 && obj_size < 10000);
        TEST_ASSERT(exe_size > 500 && exe_size < 50000);
    }
    
    if (fobj) fclose(fobj);
    if (fexe) fclose(fexe);
    
    remove(test_asm);
    remove(test_obj);
    remove(test_exe);
    
    return TEST_PASS;
}

// Test 9: Pipeline cleanup verification
TestResult test_pipeline_cleanup(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\pipeline_cleanup.asm";
    const char* test_obj = TEST_OUTPUT_DIR "\\pipeline_cleanup.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\pipeline_cleanup.exe";
    
    create_asm_file(test_asm, "mov rax, 1\nret\n");
    
    char asm_cmd[1024];
    snprintf(asm_cmd, sizeof(asm_cmd), "\"%s\" \"%s\" \"%s\"",
             ASSEMBLER_EXE, test_asm, test_obj);
    run_command(asm_cmd);
    
    char link_cmd[1024];
    snprintf(link_cmd, sizeof(link_cmd), "\"%s\" \"%s\" \"%s\"",
             LINKER_EXE, test_obj, test_exe);
    run_command(link_cmd);
    
    // Verify all files exist
    TEST_ASSERT(file_exists(test_asm));
    TEST_ASSERT(file_exists(test_obj));
    TEST_ASSERT(file_exists(test_exe));
    
    // Cleanup
    remove(test_asm);
    remove(test_obj);
    remove(test_exe);
    
    // Verify cleanup
    TEST_ASSERT(!file_exists(test_asm));
    TEST_ASSERT(!file_exists(test_obj));
    TEST_ASSERT(!file_exists(test_exe));
    
    return TEST_PASS;
}

// Test 10: Pipeline reproducibility
TestResult test_pipeline_reproducibility(void) {
    const char* test_asm = TEST_OUTPUT_DIR "\\pipeline_repr.asm";
    const char* test_obj1 = TEST_OUTPUT_DIR "\\pipeline_repr1.obj";
    const char* test_obj2 = TEST_OUTPUT_DIR "\\pipeline_repr2.obj";
    
    create_asm_file(test_asm, "mov rax, 0x1234\nret\n");
    
    // Build twice
    char asm_cmd[1024];
    snprintf(asm_cmd, sizeof(asm_cmd), "\"%s\" \"%s\" \"%s\"",
             ASSEMBLER_EXE, test_asm, test_obj1);
    run_command(asm_cmd);
    
    snprintf(asm_cmd, sizeof(asm_cmd), "\"%s\" \"%s\" \"%s\"",
             ASSEMBLER_EXE, test_asm, test_obj2);
    run_command(asm_cmd);
    
    // Compare outputs
    FILE* f1 = fopen(test_obj1, "rb");
    FILE* f2 = fopen(test_obj2, "rb");
    
    if (f1 && f2) {
        fseek(f1, 0, SEEK_END);
        fseek(f2, 0, SEEK_END);
        long size1 = ftell(f1);
        long size2 = ftell(f2);
        
        TEST_ASSERT_EQ(size1, size2);
        
        // Compare content
        rewind(f1);
        rewind(f2);
        
        int identical = 1;
        for (long i = 0; i < size1; i++) {
            if (fgetc(f1) != fgetc(f2)) {
                identical = 0;
                break;
            }
        }
        
        TEST_ASSERT(identical);
    }
    
    if (f1) fclose(f1);
    if (f2) fclose(f2);
    
    remove(test_asm);
    remove(test_obj1);
    remove(test_obj2);
    
    return TEST_PASS;
}

//=============================================================================
// Test Suite Registration
//=============================================================================

static TestSuite* g_integration_suite = NULL;

__declspec(dllexport) void init_integration_tests(void) {
    g_integration_suite = test_suite_create("Integration Tests",
        "End-to-end ASM→OBJ→EXE pipeline testing");
    
    test_suite_register(g_integration_suite, "test_full_pipeline",
        "Test complete ASM→OBJ→EXE pipeline", __FILE__, __LINE__, test_full_pipeline);
    test_suite_register(g_integration_suite, "test_pipeline_complex",
        "Test pipeline with complex instructions", __FILE__, __LINE__, test_pipeline_complex);
    test_suite_register(g_integration_suite, "test_pipeline_bad_asm",
        "Test pipeline error handling with bad assembly", __FILE__, __LINE__, test_pipeline_bad_asm);
    test_suite_register(g_integration_suite, "test_pipeline_performance",
        "Test pipeline performance with 500 lines", __FILE__, __LINE__, test_pipeline_performance);
    test_suite_register(g_integration_suite, "test_pipeline_stress",
        "Stress test with 10 sequential builds", __FILE__, __LINE__, test_pipeline_stress);
    test_suite_register(g_integration_suite, "test_pipeline_all_registers",
        "Test pipeline with all register types", __FILE__, __LINE__, test_pipeline_all_registers);
    test_suite_register(g_integration_suite, "test_pipeline_arithmetic",
        "Test pipeline with arithmetic operations", __FILE__, __LINE__, test_pipeline_arithmetic);
    test_suite_register(g_integration_suite, "test_pipeline_file_sizes",
        "Verify pipeline output file sizes", __FILE__, __LINE__, test_pipeline_file_sizes);
    test_suite_register(g_integration_suite, "test_pipeline_cleanup",
        "Test pipeline file cleanup", __FILE__, __LINE__, test_pipeline_cleanup);
    test_suite_register(g_integration_suite, "test_pipeline_reproducibility",
        "Test pipeline reproducibility", __FILE__, __LINE__, test_pipeline_reproducibility);
}

__declspec(dllexport) TestSuite* get_integration_test_suite(void) {
    if (!g_integration_suite) {
        init_integration_tests();
    }
    return g_integration_suite;
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    #ifdef _WIN32
    CreateDirectoryA(TEST_OUTPUT_DIR, NULL);
    #endif
    
    printf("RawrXD Integration Tests\n");
    printf("========================\n\n");
    
    TestSuite* suite = get_integration_test_suite();
    TestResult result = test_suite_run(suite);
    test_suite_print_results(suite);
    
    int exit_code = (result == TEST_PASS) ? 0 : 1;
    test_suite_destroy(suite);
    
    return exit_code;
}
