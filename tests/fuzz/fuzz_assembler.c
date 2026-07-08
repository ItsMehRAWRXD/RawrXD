//=============================================================================
// fuzz_assembler.c - Fuzz Testing for Minimal Assembler
// Production-ready fuzz testing with mutation strategies
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include "../include/test_framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#endif

//=============================================================================
// Fuzz Configuration
//=============================================================================

#define FUZZ_ITERATIONS 1000
#define MAX_ASM_SIZE 4096
#define TEST_OUTPUT_DIR "d:\\rawrxd\\tests\\output"
#define ASSEMBLER_EXE "d:\\rawrxd\\native_toolchain\\minimal_assembler_v2.exe"

//=============================================================================
// Fuzz Statistics
//=============================================================================

typedef struct {
    int total_runs;
    int crashes;
    int hangs;
    int normal_exits;
    int mutations;
    double total_time_ms;
} FuzzStats;

static FuzzStats g_stats = {0};

//=============================================================================
// Mutation Strategies
//=============================================================================

// Strategy 1: Random byte insertion
void mutate_insert_random(char* buffer, size_t* len, size_t max_len) {
    if (*len >= max_len - 1) return;
    
    size_t pos = rand() % (*len + 1);
    char byte = (char)(rand() % 256);
    
    memmove(buffer + pos + 1, buffer + pos, *len - pos);
    buffer[pos] = byte;
    (*len)++;
    buffer[*len] = '\0';
}

// Strategy 2: Random byte deletion
void mutate_delete_random(char* buffer, size_t* len) {
    if (*len == 0) return;
    
    size_t pos = rand() % *len;
    memmove(buffer + pos, buffer + pos + 1, *len - pos);
    (*len)--;
}

// Strategy 3: Random byte substitution
void mutate_substitute_random(char* buffer, size_t len) {
    if (len == 0) return;
    
    size_t pos = rand() % len;
    buffer[pos] = (char)(rand() % 256);
}

// Strategy 4: Duplicate line
void mutate_duplicate_line(char* buffer, size_t* len, size_t max_len) {
    char* lines[100];
    int num_lines = 0;
    
    char* temp = strdup(buffer);
    char* line = strtok(temp, "\n");
    while (line && num_lines < 100) {
        lines[num_lines++] = strdup(line);
        line = strtok(NULL, "\n");
    }
    
    if (num_lines > 0) {
        int idx = rand() % num_lines;
        size_t line_len = strlen(lines[idx]);
        if (*len + line_len + 1 < max_len) {
            strcat(buffer, "\n");
            strcat(buffer, lines[idx]);
            *len += line_len + 1;
        }
    }
    
    for (int i = 0; i < num_lines; i++) free(lines[i]);
    free(temp);
}

// Strategy 5: Swap lines
void mutate_swap_lines(char* buffer, size_t len) {
    // Simple implementation - shuffle characters
    if (len < 2) return;
    
    size_t pos1 = rand() % len;
    size_t pos2 = rand() % len;
    
    char temp = buffer[pos1];
    buffer[pos1] = buffer[pos2];
    buffer[pos2] = temp;
}

// Strategy 6: Insert valid instruction
void mutate_insert_valid_instruction(char* buffer, size_t* len, size_t max_len) {
    const char* valid_instructions[] = {
        "mov rax, 0x1234",
        "mov rbx, 0x5678",
        "add rax, rbx",
        "sub rax, 1",
        "ret",
        "nop",
        "push rax",
        "pop rax"
    };
    
    int idx = rand() % (sizeof(valid_instructions) / sizeof(valid_instructions[0]));
    size_t inst_len = strlen(valid_instructions[idx]);
    
    if (*len + inst_len + 1 < max_len) {
        if (*len > 0) strcat(buffer, "\n");
        strcat(buffer, valid_instructions[idx]);
        *len += inst_len + ((*len > 0) ? 1 : 0);
    }
}

// Strategy 7: Bit flip
void mutate_bit_flip(char* buffer, size_t len) {
    if (len == 0) return;
    
    size_t pos = rand() % len;
    int bit = rand() % 8;
    buffer[pos] ^= (1 << bit);
}

// Strategy 8: Truncate
void mutate_truncate(char* buffer, size_t* len) {
    if (*len == 0) return;
    
    size_t new_len = rand() % *len;
    buffer[new_len] = '\0';
    *len = new_len;
}

//=============================================================================
// Fuzz Runner
//=============================================================================

void apply_mutation(char* buffer, size_t* len, size_t max_len) {
    int strategy = rand() % 8;
    
    switch (strategy) {
        case 0: mutate_insert_random(buffer, len, max_len); break;
        case 1: mutate_delete_random(buffer, len); break;
        case 2: mutate_substitute_random(buffer, *len); break;
        case 3: mutate_duplicate_line(buffer, len, max_len); break;
        case 4: mutate_swap_lines(buffer, *len); break;
        case 5: mutate_insert_valid_instruction(buffer, len, max_len); break;
        case 6: mutate_bit_flip(buffer, *len); break;
        case 7: mutate_truncate(buffer, len); break;
    }
    
    g_stats.mutations++;
}

int run_assembler_with_timeout(const char* input_file, const char* output_file, int timeout_ms) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "\"%s\" \"%s\" \"%s\"",
             ASSEMBLER_EXE, input_file, output_file);
    
    #ifdef _WIN32
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return -1;
    }
    
    DWORD wait_result = WaitForSingleObject(pi.hProcess, timeout_ms);
    
    if (wait_result == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -2; // Hang
    }
    
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return (int)exit_code;
    #else
    // Unix fallback - no timeout support
    (void)timeout_ms;
    return system(cmd);
    #endif
}

TestResult fuzz_assembler_iteration(int iteration) {
    char input_file[256];
    char output_file[256];
    
    snprintf(input_file, sizeof(input_file), "%s\\fuzz_%d.asm", TEST_OUTPUT_DIR, iteration);
    snprintf(output_file, sizeof(output_file), "%s\\fuzz_%d.obj", TEST_OUTPUT_DIR, iteration);
    
    // Seed with valid assembly
    char buffer[MAX_ASM_SIZE];
    strcpy(buffer, "mov rax, 0x1234\nret\n");
    size_t len = strlen(buffer);
    
    // Apply mutations
    int num_mutations = 1 + (rand() % 10);
    for (int i = 0; i < num_mutations; i++) {
        apply_mutation(buffer, &len, MAX_ASM_SIZE);
    }
    
    // Write input file
    FILE* f = fopen(input_file, "w");
    if (!f) return TEST_ERROR;
    fprintf(f, "%s", buffer);
    fclose(f);
    
    // Run assembler with timeout
    double start = test_get_time_ms();
    int result = run_assembler_with_timeout(input_file, output_file, 5000);
    double end = test_get_time_ms();
    
    g_stats.total_time_ms += (end - start);
    g_stats.total_runs++;
    
    // Analyze result
    if (result == -2) {
        g_stats.hangs++;
        printf("  [!] Hang detected on iteration %d\n", iteration);
        
        // Save crashing input
        char crash_file[256];
        snprintf(crash_file, sizeof(crash_file), "%s\\hang_%d.asm", TEST_OUTPUT_DIR, iteration);
        CopyFileA(input_file, crash_file, FALSE);
    } else if (result < 0) {
        g_stats.crashes++;
        printf("  [!] Crash detected on iteration %d\n", iteration);
        
        // Save crashing input
        char crash_file[256];
        snprintf(crash_file, sizeof(crash_file), "%s\\crash_%d.asm", TEST_OUTPUT_DIR, iteration);
        CopyFileA(input_file, crash_file, FALSE);
    } else {
        g_stats.normal_exits++;
    }
    
    // Cleanup
    remove(input_file);
    remove(output_file);
    
    return TEST_PASS;
}

//=============================================================================
// Test Cases
//=============================================================================

TestResult test_fuzz_basic(void) {
    printf("\n  Running %d fuzz iterations...\n", FUZZ_ITERATIONS);
    
    srand((unsigned int)time(NULL));
    
    for (int i = 0; i < FUZZ_ITERATIONS; i++) {
        if (i % 100 == 0) {
            printf("    Progress: %d/%d\r", i, FUZZ_ITERATIONS);
        }
        fuzz_assembler_iteration(i);
    }
    
    printf("\n    Fuzzing complete!\n");
    printf("    Total runs: %d\n", g_stats.total_runs);
    printf("    Crashes: %d\n", g_stats.crashes);
    printf("    Hangs: %d\n", g_stats.hangs);
    printf("    Normal exits: %d\n", g_stats.normal_exits);
    printf("    Mutations: %d\n", g_stats.mutations);
    printf("    Avg time: %.2f ms\n", g_stats.total_time_ms / g_stats.total_runs);
    
    // Fuzzing passes if no crashes or hangs
    TEST_ASSERT_EQ(0, g_stats.crashes);
    TEST_ASSERT_EQ(0, g_stats.hangs);
    
    return TEST_PASS;
}

TestResult test_fuzz_seed_corpus(void) {
    printf("\n  Testing with seed corpus...\n");
    
    const char* seeds[] = {
        "mov rax, 0\nret\n",
        "mov rax, rbx\nret\n",
        "add rax, rbx\nsub rcx, rdx\nret\n",
        "push rax\npop rbx\nret\n",
        "nop\nnop\nnop\nret\n"
    };
    
    int num_seeds = sizeof(seeds) / sizeof(seeds[0]);
    int failures = 0;
    
    for (int i = 0; i < num_seeds; i++) {
        char input_file[256];
        char output_file[256];
        
        snprintf(input_file, sizeof(input_file), "%s\\seed_%d.asm", TEST_OUTPUT_DIR, i);
        snprintf(output_file, sizeof(output_file), "%s\\seed_%d.obj", TEST_OUTPUT_DIR, i);
        
        FILE* f = fopen(input_file, "w");
        if (!f) continue;
        fprintf(f, "%s", seeds[i]);
        fclose(f);
        
        int result = run_assembler_with_timeout(input_file, output_file, 5000);
        
        if (result == -2) {
            printf("    [!] Hang on seed %d\n", i);
            failures++;
        } else if (result < 0) {
            printf("    [!] Crash on seed %d\n", i);
            failures++;
        }
        
        remove(input_file);
        remove(output_file);
    }
    
    TEST_ASSERT_EQ(0, failures);
    return TEST_PASS;
}

TestResult test_fuzz_edge_cases(void) {
    printf("\n  Testing edge cases...\n");
    
    const char* edge_cases[] = {
        "",                                    // Empty
        "\n",                                  // Just newline
        "mov",                                 // Incomplete
        "mov ",                                // Trailing space
        "12345",                               // Just numbers
        "rax",                                 // Just register
        "mov rax, 0xFFFFFFFFFFFFFFFF",       // Large immediate
        "mov rax, rbx, rcx",                   // Extra operand
        "MOV RAX, 1",                          // Uppercase
        "\t\tmov\t\trax,\t\t1\t\t",           // Tabs
    };
    
    int num_cases = sizeof(edge_cases) / sizeof(edge_cases[0]);
    int failures = 0;
    
    for (int i = 0; i < num_cases; i++) {
        char input_file[256];
        char output_file[256];
        
        snprintf(input_file, sizeof(input_file), "%s\\edge_%d.asm", TEST_OUTPUT_DIR, i);
        snprintf(output_file, sizeof(output_file), "%s\\edge_%d.obj", TEST_OUTPUT_DIR, i);
        
        FILE* f = fopen(input_file, "w");
        if (!f) continue;
        fprintf(f, "%s", edge_cases[i]);
        fclose(f);
        
        int result = run_assembler_with_timeout(input_file, output_file, 5000);
        
        if (result == -2) {
            printf("    [!] Hang on edge case %d: '%.20s...'\n", i, edge_cases[i]);
            failures++;
        }
        
        remove(input_file);
        remove(output_file);
    }
    
    TEST_ASSERT_EQ(0, failures);
    return TEST_PASS;
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    #ifdef _WIN32
    CreateDirectoryA(TEST_OUTPUT_DIR, NULL);
    #endif
    
    printf("RawrXD Assembler Fuzz Tests\n");
    printf("===========================\n");
    
    TestSuite* suite = test_suite_create("Assembler Fuzz Tests",
        "Fuzz testing with mutation strategies");
    
    test_suite_register(suite, "test_fuzz_basic",
        "Basic fuzzing with %d iterations", __FILE__, __LINE__, test_fuzz_basic);
    test_suite_register(suite, "test_fuzz_seed_corpus",
        "Fuzz with seed corpus", __FILE__, __LINE__, test_fuzz_seed_corpus);
    test_suite_register(suite, "test_fuzz_edge_cases",
        "Edge case testing", __FILE__, __LINE__, test_fuzz_edge_cases);
    
    TestResult result = test_suite_run(suite);
    test_suite_print_results(suite);
    
    int exit_code = (result == TEST_PASS) ? 0 : 1;
    test_suite_destroy(suite);
    
    return exit_code;
}
