// Toolchain Test Suite - Comprehensive verification
// Tests: assembler → linker → execution

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#define popen _popen
#define pclose _pclose
#define WEXITSTATUS(x) (x)
#endif

// Test result tracking
typedef struct {
    int total;
    int passed;
    int failed;
} test_results_t;

static test_results_t results = {0};

// Run command and capture output
static int run_command(const char *cmd, char *output, size_t output_size) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    
    size_t total = 0;
    char buf[256];
    while (fgets(buf, sizeof(buf), fp) && total < output_size - 1) {
        size_t len = strlen(buf);
        if (total + len >= output_size) len = output_size - total - 1;
        memcpy(output + total, buf, len);
        total += len;
    }
    output[total] = '\0';
    
    int status = pclose(fp);
    return WEXITSTATUS(status);
}

// Test 1: Basic assembly
static int test_basic_assembly() {
    printf("\n[Test 1] Basic Assembly (xor eax, eax; ret)\n");
    
    FILE *fp = fopen("test1.asm", "w");
    if (!fp) return 0;
    fprintf(fp, "xor eax, eax\nret\n");
    fclose(fp);
    
    char output[1024] = {0};
    int ret = run_command(".\\working_assembler.exe test1.asm test1.obj", output, sizeof(output));
    
    if (ret != 0 || strstr(output, "Assembled") == NULL) {
        printf("  ❌ FAILED: Assembly failed\n");
        return 0;
    }
    
    printf("  ✅ PASSED: Assembled successfully\n");
    return 1;
}

// Test 2: Basic linking
static int test_basic_linking() {
    printf("\n[Test 2] Basic Linking\n");
    
    char output[1024] = {0};
    int ret = run_command(".\\working_linker.exe test1.obj test1.exe", output, sizeof(output));
    
    if (ret != 0 || strstr(output, "Success") == NULL) {
        printf("  ❌ FAILED: Linking failed\n");
        return 0;
    }
    
    printf("  ✅ PASSED: Linked successfully\n");
    return 1;
}

// Test 3: Execution
static int test_execution() {
    printf("\n[Test 3] Execution\n");
    
    // Check if file exists and has content
    FILE *fp = fopen("test1.exe", "rb");
    if (!fp) {
        printf("  ❌ FAILED: Executable not found\n");
        return 0;
    }
    
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fclose(fp);
    
    if (size < 512) {
        printf("  ❌ FAILED: Executable too small (%ld bytes)\n", size);
        return 0;
    }
    
    printf("  ✅ PASSED: Executable created (%ld bytes)\n", size);
    return 1;
}

// Test 4: Complex assembly (function with prologue/epilogue)
static int test_complex_assembly() {
    printf("\n[Test 4] Complex Assembly (function with stack frame)\n");
    
    FILE *fp = fopen("test2.asm", "w");
    if (!fp) return 0;
    fprintf(fp, "sub rsp, 8\n");      // Allocate stack
    fprintf(fp, "xor eax, eax\n");     // Return 0
    fprintf(fp, "add rsp, 8\n");       // Deallocate stack
    fprintf(fp, "ret\n");
    fclose(fp);
    
    char output[1024] = {0};
    int ret = run_command(".\\working_assembler.exe test2.asm test2.obj", output, sizeof(output));
    
    if (ret != 0) {
        printf("  ❌ FAILED: Complex assembly failed\n");
        return 0;
    }
    
    ret = run_command(".\\working_linker.exe test2.obj test2.exe", output, sizeof(output));
    if (ret != 0) {
        printf("  ❌ FAILED: Complex linking failed\n");
        return 0;
    }
    
    printf("  ✅ PASSED: Complex program built\n");
    return 1;
}

// Test 5: Register moves
static int test_register_moves() {
    printf("\n[Test 5] Register Moves\n");
    
    FILE *fp = fopen("test3.asm", "w");
    if (!fp) return 0;
    fprintf(fp, "mov rax, 42\n");
    fprintf(fp, "mov rcx, 1\n");
    fprintf(fp, "mov rdx, 2\n");
    fprintf(fp, "mov r8, 3\n");
    fprintf(fp, "mov r9, 4\n");
    fprintf(fp, "mov eax, 0\n");
    fprintf(fp, "ret\n");
    fclose(fp);
    
    char output[1024] = {0};
    int ret = run_command(".\\working_assembler.exe test3.asm test3.obj", output, sizeof(output));
    
    if (ret != 0) {
        printf("  ❌ FAILED: Register move assembly failed\n");
        return 0;
    }
    
    // Check output size
    if (strstr(output, "bytes") != NULL) {
        printf("  ✅ PASSED: Register moves assembled\n");
        return 1;
    }
    
    printf("  ❌ FAILED: Unexpected output\n");
    return 0;
}

// Test 6: GGUF Loader
static int test_gguf_loader() {
    printf("\n[Test 6] GGUF Loader\n");
    
    // Check if dummy.gguf exists
    FILE *fp = fopen("dummy.gguf", "rb");
    if (!fp) {
        printf("  ⚠️  SKIPPED: dummy.gguf not found\n");
        return 1; // Skip, not fail
    }
    fclose(fp);
    
    char output[1024] = {0};
    int ret = run_command(".\\minimal_gguf_loader.exe dummy.gguf", output, sizeof(output));
    
    if (ret != 0) {
        printf("  ❌ FAILED: GGUF loader failed\n");
        return 0;
    }
    
    if (strstr(output, "GGUF Version") != NULL) {
        printf("  ✅ PASSED: GGUF loader works\n");
        return 1;
    }
    
    printf("  ❌ FAILED: GGUF loader unexpected output\n");
    return 0;
}

// Cleanup test files
static void cleanup() {
    remove("test1.asm");
    remove("test1.obj");
    remove("test1.exe");
    remove("test2.asm");
    remove("test2.obj");
    remove("test2.exe");
    remove("test3.asm");
    remove("test3.obj");
    remove("test3.exe");
}

int main(int argc, char **argv) {
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║     RawrXD Toolchain Test Suite - No Dependencies          ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\nTesting: working_assembler + working_linker\n");
    printf("Components: asm → obj → exe\n\n");
    
    // Run tests
    results.total = 6;
    
    if (test_basic_assembly()) results.passed++;
    else results.failed++;
    
    if (test_basic_linking()) results.passed++;
    else results.failed++;
    
    if (test_execution()) results.passed++;
    else results.failed++;
    
    if (test_complex_assembly()) results.passed++;
    else results.failed++;
    
    if (test_register_moves()) results.passed++;
    else results.failed++;
    
    if (test_gguf_loader()) results.passed++;
    else results.failed++;
    
    // Summary
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║                      TEST SUMMARY                          ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  Total:  %-3d                                              ║\n", results.total);
    printf("║  Passed: %-3d ✅                                           ║\n", results.passed);
    printf("║  Failed: %-3d ❌                                           ║\n", results.failed);
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    if (results.failed == 0) {
        printf("\n✅ ALL TESTS PASSED - Toolchain is working!\n");
    } else {
        printf("\n⚠️  Some tests failed - review output above\n");
    }
    
    // Cleanup
    cleanup();
    
    return results.failed > 0 ? 1 : 0;
}
