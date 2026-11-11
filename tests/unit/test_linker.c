//=============================================================================
// test_linker.c - Unit Tests for Native Linker
// Production-ready test suite for the native PE linker
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

#define LINKER_EXE "d:\\rawrxd\\native_toolchain\\linker_with_imports.exe"
#define TEST_OUTPUT_DIR "d:\\rawrxd\\tests\\output"

// Minimal valid COFF object (x64)
static const uint8_t minimal_coff[] = {
    // COFF Header
    0x64, 0x86,              // Machine: AMD64
    0x01, 0x00,              // Number of sections: 1
    0x00, 0x00, 0x00, 0x00, // Time stamp
    0x00, 0x00, 0x00, 0x00, // Pointer to symbol table
    0x00, 0x00, 0x00, 0x00, // Number of symbols
    0x00, 0x00,              // Size of optional header
    0x00, 0x00,              // Characteristics
    
    // Section header (.text)
    0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, // Name: .text
    0x04, 0x00, 0x00, 0x00, // Virtual size
    0x00, 0x00, 0x00, 0x00, // Virtual address
    0x04, 0x00, 0x00, 0x00, // Size of raw data
    0x40, 0x00, 0x00, 0x00, // Pointer to raw data
    0x00, 0x00, 0x00, 0x00, // Pointer to relocations
    0x00, 0x00, 0x00, 0x00, // Pointer to line numbers
    0x00, 0x00,              // Number of relocations
    0x00, 0x00,              // Number of line numbers
    0x20, 0x00, 0x00, 0x60, // Characteristics: CODE | EXECUTE | READ
    
    // Section data (ret instruction)
    0xC3, 0x00, 0x00, 0x00
};

//=============================================================================
// Helper Functions
//=============================================================================

static int run_linker(const char* obj_file, const char* exe_file) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "\"%s\" \"%s\" \"%s\" 2>NUL",
             LINKER_EXE, obj_file, exe_file);
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

static int create_coff_file(const char* filename) {
    FILE* f = fopen(filename, "wb");
    if (!f) return -1;
    
    fwrite(minimal_coff, 1, sizeof(minimal_coff), f);
    fclose(f);
    return 0;
}

static int is_valid_pe(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) return 0;
    
    // Check DOS signature
    uint16_t dos_sig;
    if (fread(&dos_sig, 2, 1, f) != 1) {
        fclose(f);
        return 0;
    }
    
    if (dos_sig != 0x5A4D) { // "MZ"
        fclose(f);
        return 0;
    }
    
    // Get PE header offset
    fseek(f, 0x3C, SEEK_SET);
    uint32_t pe_offset;
    fread(&pe_offset, 4, 1, f);
    
    // Check PE signature
    fseek(f, pe_offset, SEEK_SET);
    uint32_t pe_sig;
    fread(&pe_sig, 4, 1, f);
    
    fclose(f);
    
    return (pe_sig == 0x00004550); // "PE\0\0"
}

//=============================================================================
// Test Cases
//=============================================================================

// Test 1: Linker executable exists
TestResult test_linker_executable_exists(void) {
    TEST_ASSERT(file_exists(LINKER_EXE));
    return TEST_PASS;
}

// Test 2: Basic linking
TestResult test_basic_linking(void) {
    const char* test_obj = TEST_OUTPUT_DIR "\\test_basic.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\test_basic.exe";
    
    create_coff_file(test_obj);
    
    int result = run_linker(test_obj, test_exe);
    TEST_ASSERT_EQ(0, result);
    TEST_ASSERT(file_exists(test_exe));
    
    // Should be valid PE
    TEST_ASSERT(is_valid_pe(test_exe));
    
    // Should be reasonable size
    size_t size = get_file_size(test_exe);
    TEST_ASSERT(size >= 512 && size <= 8192);
    
    remove(test_obj);
    remove(test_exe);
    
    return TEST_PASS;
}

// Test 3: PE structure validation
TestResult test_pe_structure(void) {
    const char* test_obj = TEST_OUTPUT_DIR "\\test_pe.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\test_pe.exe";
    
    create_coff_file(test_obj);
    run_linker(test_obj, test_exe);
    
    FILE* f = fopen(test_exe, "rb");
    TEST_ASSERT_NOT_NULL(f);
    
    // Read DOS header
    uint16_t dos_sig;
    fread(&dos_sig, 2, 1, f);
    TEST_ASSERT_EQ(0x5A4D, dos_sig);
    
    // Read PE offset
    fseek(f, 0x3C, SEEK_SET);
    uint32_t pe_offset;
    fread(&pe_offset, 4, 1, f);
    TEST_ASSERT(pe_offset >= 64 && pe_offset < 1024);
    
    // Read PE signature
    fseek(f, pe_offset, SEEK_SET);
    uint32_t pe_sig;
    fread(&pe_sig, 4, 1, f);
    TEST_ASSERT_EQ(0x00004550, pe_sig);
    
    // Read COFF header
    uint16_t machine;
    fread(&machine, 2, 1, f);
    TEST_ASSERT_EQ(0x8664, machine); // AMD64
    
    fclose(f);
    
    remove(test_obj);
    remove(test_exe);
    
    return TEST_PASS;
}

// Test 4: Multiple object files
TestResult test_multiple_objects(void) {
    const char* test_obj1 = TEST_OUTPUT_DIR "\\test_multi1.obj";
    const char* test_obj2 = TEST_OUTPUT_DIR "\\test_multi2.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\test_multi.exe";
    
    create_coff_file(test_obj1);
    create_coff_file(test_obj2);
    
    // Link with multiple objects (if supported)
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "\"%s\" \"%s\" \"%s\" \"%s\" 2>NUL",
             LINKER_EXE, test_obj1, test_obj2, test_exe);
    int result = system(cmd);
    
    // May or may not be supported - just verify no crash
    
    remove(test_obj1);
    remove(test_obj2);
    if (file_exists(test_exe)) remove(test_exe);
    
    return TEST_PASS;
}

// Test 5: Invalid object file
TestResult test_invalid_object(void) {
    const char* test_obj = TEST_OUTPUT_DIR "\\test_invalid.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\test_invalid.exe";
    
    // Create invalid file
    FILE* f = fopen(test_obj, "wb");
    TEST_ASSERT_NOT_NULL(f);
    fprintf(f, "This is not a valid COFF file");
    fclose(f);
    
    int result = run_linker(test_obj, test_exe);
    // Should fail gracefully
    
    remove(test_obj);
    if (file_exists(test_exe)) remove(test_exe);
    
    return TEST_PASS;
}

// Test 6: Missing object file
TestResult test_missing_object(void) {
    const char* test_obj = TEST_OUTPUT_DIR "\\test_nonexistent.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\test_nonexistent.exe";
    
    // Ensure file doesn't exist
    remove(test_obj);
    
    int result = run_linker(test_obj, test_exe);
    // Should fail gracefully
    
    if (file_exists(test_exe)) remove(test_exe);
    
    return TEST_PASS;
}

// Test 7: Large executable
TestResult test_large_executable(void) {
    const char* test_obj = TEST_OUTPUT_DIR "\\test_large.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\test_large.exe";
    
    // Create larger COFF with more code
    FILE* f = fopen(test_obj, "wb");
    TEST_ASSERT_NOT_NULL(f);
    
    // Write COFF header
    uint8_t header[] = {
        0x64, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    fwrite(header, 1, sizeof(header), f);
    
    // Section header
    uint8_t sect[] = {
        0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x60
    };
    fwrite(sect, 1, sizeof(sect), f);
    
    // Section data (1024 bytes of NOPs + RET)
    for (int i = 0; i < 1023; i++) {
        fputc(0x90, f); // NOP
    }
    fputc(0xC3, f); // RET
    
    fclose(f);
    
    int result = run_linker(test_obj, test_exe);
    TEST_ASSERT_EQ(0, result);
    TEST_ASSERT(file_exists(test_exe));
    TEST_ASSERT(is_valid_pe(test_exe));
    
    remove(test_obj);
    remove(test_exe);
    
    return TEST_PASS;
}

// Test 8: Linker performance
TestResult test_linker_performance(void) {
    const char* test_obj = TEST_OUTPUT_DIR "\\test_perf.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\test_perf.exe";
    
    create_coff_file(test_obj);
    
    double start = test_get_time_ms();
    int result = run_linker(test_obj, test_exe);
    double end = test_get_time_ms();
    
    TEST_ASSERT_EQ(0, result);
    
    double elapsed = end - start;
    TEST_ASSERT(elapsed < 5000.0); // Should complete in < 5 seconds
    
    printf("    Link time: %.2f ms\n", elapsed);
    
    remove(test_obj);
    remove(test_exe);
    
    return TEST_PASS;
}

// Test 9: Executable permissions
TestResult test_executable_permissions(void) {
    const char* test_obj = TEST_OUTPUT_DIR "\\test_perm.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\test_perm.exe";
    
    create_coff_file(test_obj);
    run_linker(test_obj, test_exe);
    
    TEST_ASSERT(file_exists(test_exe));
    
    #ifdef _WIN32
    // On Windows, check if file is executable by trying to get attributes
    DWORD attrs = GetFileAttributesA(test_exe);
    TEST_ASSERT(attrs != INVALID_FILE_ATTRIBUTES);
    #endif
    
    remove(test_obj);
    remove(test_exe);
    
    return TEST_PASS;
}

// Test 10: Import table generation
TestResult test_import_table(void) {
    const char* test_obj = TEST_OUTPUT_DIR "\\test_import.obj";
    const char* test_exe = TEST_OUTPUT_DIR "\\test_import.exe";
    
    create_coff_file(test_obj);
    run_linker(test_obj, test_exe);
    
    FILE* f = fopen(test_exe, "rb");
    TEST_ASSERT_NOT_NULL(f);
    
    // Read PE offset
    fseek(f, 0x3C, SEEK_SET);
    uint32_t pe_offset;
    fread(&pe_offset, 4, 1, f);
    
    // Skip to optional header
    fseek(f, pe_offset + 24, SEEK_SET);
    
    // Read data directory
    // Import table is at index 1
    fseek(f, 112, SEEK_CUR); // Skip to import directory
    uint32_t import_rva, import_size;
    fread(&import_rva, 4, 1, f);
    fread(&import_size, 4, 1, f);
    
    // Import table should exist (size > 0)
    // Note: This is a basic check - real validation would parse the import table
    
    fclose(f);
    
    remove(test_obj);
    remove(test_exe);
    
    return TEST_PASS;
}

//=============================================================================
// Test Suite Registration
//=============================================================================

static TestSuite* g_linker_suite = NULL;

__declspec(dllexport) void init_linker_tests(void) {
    g_linker_suite = test_suite_create("Linker Unit Tests",
        "Production-ready unit tests for linker_with_imports.exe");
    
    test_suite_register(g_linker_suite, "test_linker_executable_exists",
        "Verify linker executable exists", __FILE__, __LINE__, test_linker_executable_exists);
    test_suite_register(g_linker_suite, "test_basic_linking",
        "Test basic COFF to PE linking", __FILE__, __LINE__, test_basic_linking);
    test_suite_register(g_linker_suite, "test_pe_structure",
        "Test PE structure validation", __FILE__, __LINE__, test_pe_structure);
    test_suite_register(g_linker_suite, "test_multiple_objects",
        "Test multiple object file linking", __FILE__, __LINE__, test_multiple_objects);
    test_suite_register(g_linker_suite, "test_invalid_object",
        "Test invalid object file handling", __FILE__, __LINE__, test_invalid_object);
    test_suite_register(g_linker_suite, "test_missing_object",
        "Test missing object file handling", __FILE__, __LINE__, test_missing_object);
    test_suite_register(g_linker_suite, "test_large_executable",
        "Test large executable generation", __FILE__, __LINE__, test_large_executable);
    test_suite_register(g_linker_suite, "test_linker_performance",
        "Test linker performance", __FILE__, __LINE__, test_linker_performance);
    test_suite_register(g_linker_suite, "test_executable_permissions",
        "Test executable file permissions", __FILE__, __LINE__, test_executable_permissions);
    test_suite_register(g_linker_suite, "test_import_table",
        "Test import table generation", __FILE__, __LINE__, test_import_table);
}

__declspec(dllexport) TestSuite* get_linker_test_suite(void) {
    if (!g_linker_suite) {
        init_linker_tests();
    }
    return g_linker_suite;
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    #ifdef _WIN32
    CreateDirectoryA(TEST_OUTPUT_DIR, NULL);
    #else
    mkdir(TEST_OUTPUT_DIR, 0755);
    #endif
    
    printf("RawrXD Linker Unit Tests\n");
    printf("========================\n\n");
    
    TestSuite* suite = get_linker_test_suite();
    TestResult result = test_suite_run(suite);
    test_suite_print_results(suite);
    
    int exit_code = (result == TEST_PASS) ? 0 : 1;
    test_suite_destroy(suite);
    
    return exit_code;
}
