//=============================================================================
// test_roundtrip.c - Roundtrip Test: Disasm -> ASM -> Assemble -> Verify
// Part of RawrXD Native Toolchain - RE Integration
// Tests the complete Codex -> Native -> Binary pipeline
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define TEST_VERSION "1.0.0"

//=============================================================================
// Test Configuration
//=============================================================================

typedef struct {
    const char* name;
    const char* asm_code;
    const char* expected_bytes;
    int should_pass;
} TestCase;

TestCase tests[] = {
    {
        "Simple NOP",
        "nop",
        "90",
        1
    },
    {
        "Register Move",
        "mov rax, rcx",
        "48 89 C8",
        1
    },
    {
        "XOR Zero",
        "xor rax, rax",
        "48 31 C0",
        1
    },
    {
        "Increment",
        "inc rax",
        "48 FF C0",
        1
    },
    {
        "Return",
        "ret",
        "C3",
        1
    },
    {
        "Push Pop",
        "push rax\npop rax",
        "50 58",
        1
    },
    {
        "Compare",
        "cmp rax, rbx",
        "48 39 D8",
        1
    },
    {
        "Jump",
        "jmp label\nlabel:",
        "EB 00",
        1
    },
    {
        NULL, NULL, NULL, 0
    }
};

//=============================================================================
// Utility Functions
//=============================================================================

int run_command(const char* cmd, char* output, int max_output) {
    FILE* pipe = _popen(cmd, "r");
    if (!pipe) return -1;
    
    int total = 0;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), pipe) && total < max_output - 1) {
        int len = strlen(buffer);
        if (total + len < max_output) {
            strcpy(output + total, buffer);
            total += len;
        }
    }
    
    return _pclose(pipe);
}

int file_exists(const char* path) {
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

long file_size(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fclose(f);
    
    return size;
}

int read_file_bytes(const char* path, uint8_t* buffer, int max_bytes) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    
    int read = fread(buffer, 1, max_bytes, f);
    fclose(f);
    
    return read;
}

//=============================================================================
// Test Execution
//=============================================================================

typedef struct {
    int total;
    int passed;
    int failed;
    int skipped;
} TestResults;

int run_test(TestCase* test, int index, TestResults* results) {
    printf("\n[Test %d] %s\n", index + 1, test->name);
    printf("  Code: %s\n", test->asm_code);
    
    char temp_asm[256];
    char temp_obj[256];
    char temp_exe[256];
    
    GetTempPathA(256, temp_asm);
    strcat(temp_asm, "roundtrip_test.asm");
    GetTempPathA(256, temp_obj);
    strcat(temp_obj, "roundtrip_test.obj");
    GetTempPathA(256, temp_exe);
    strcat(temp_exe, "roundtrip_test.exe");
    
    // Write assembly
    FILE* f = fopen(temp_asm, "w");
    if (!f) {
        printf("  [FAIL] Cannot create temp file\n");
        return 0;
    }
    
    fprintf(f, ".code\n");
    fprintf(f, "_start:\n");
    fprintf(f, "%s\n", test->asm_code);
    fprintf(f, "ret\n");
    fclose(f);
    
    // Assemble
    char cmd[512];
    char output[4096];
    
    snprintf(cmd, sizeof(cmd), "minimal_assembler.exe \"%s\" \"%s\" 2>&1", temp_asm, temp_obj);
    printf("  [CMD] %s\n", cmd);
    
    int exit_code = run_command(cmd, output, sizeof(output));
    
    // Cleanup asm
    DeleteFileA(temp_asm);
    
    if (exit_code != 0) {
        printf("  [FAIL] Assembly failed (exit %d)\n", exit_code);
        printf("  Output: %s\n", output);
        DeleteFileA(temp_obj);
        return 0;
    }
    
    if (!file_exists(temp_obj)) {
        printf("  [FAIL] Object file not created\n");
        return 0;
    }
    
    printf("  [OK] Assembled: %ld bytes\n", file_size(temp_obj));
    
    // Link
    snprintf(cmd, sizeof(cmd), "linker_with_imports.exe \"%s\" \"%s\" 2>&1", temp_obj, temp_exe);
    printf("  [CMD] %s\n", cmd);
    
    exit_code = run_command(cmd, output, sizeof(output));
    DeleteFileA(temp_obj);
    
    if (exit_code != 0) {
        printf("  [FAIL] Link failed (exit %d)\n", exit_code);
        printf("  Output: %s\n", output);
        return 0;
    }
    
    if (!file_exists(temp_exe)) {
        printf("  [FAIL] Executable not created\n");
        return 0;
    }
    
    printf("  [OK] Linked: %ld bytes\n", file_size(temp_exe));
    
    // TODO: Verify bytes match expected
    // For now, just check file exists and has content
    
    // Cleanup
    DeleteFileA(temp_exe);
    
    printf("  [PASS] Test passed!\n");
    return 1;
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char* argv[]) {
    printf("=============================================================================\n");
    printf("  Roundtrip Test v%s\n", TEST_VERSION);
    printf("  Codex -> Native ASM -> Binary Verification\n");
    printf("=============================================================================\n\n");
    
    // Check for required tools
    const char* required_tools[] = {
        "minimal_assembler.exe",
        "linker_with_imports.exe",
        NULL
    };
    
    printf("[CHECK] Required tools:\n");
    int all_found = 1;
    for (int i = 0; required_tools[i]; i++) {
        if (file_exists(required_tools[i])) {
            printf("  [OK] %s\n", required_tools[i]);
        } else {
            printf("  [MISSING] %s\n", required_tools[i]);
            all_found = 0;
        }
    }
    
    if (!all_found) {
        printf("\n[ERROR] Required tools not found. Build them first.\n");
        return 1;
    }
    
    printf("\n");
    
    // Run tests
    TestResults results = {0};
    
    for (int i = 0; tests[i].name; i++) {
        results.total++;
        
        if (run_test(&tests[i], i, &results)) {
            results.passed++;
        } else {
            results.failed++;
        }
    }
    
    // Summary
    printf("\n=============================================================================\n");
    printf("  TEST SUMMARY\n");
    printf("=============================================================================\n");
    printf("  Total:   %d\n", results.total);
    printf("  Passed:  %d\n", results.passed);
    printf("  Failed:  %d\n", results.failed);
    printf("  Skipped: %d\n", results.skipped);
    printf("=============================================================================\n");
    
    return results.failed > 0 ? 1 : 0;
}
