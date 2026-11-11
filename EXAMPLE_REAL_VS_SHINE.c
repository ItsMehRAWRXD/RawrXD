//=============================================================================
// EXAMPLE: Real Implementation vs. Shine Box
// This shows the difference between simulated and real functionality
//=============================================================================

// ============================================================================
// SHINE BOX VERSION (What we currently have)
// ============================================================================

void shine_box_test_runner() {
    printf("Running tests...\n");
    
    // Simulated test execution
    for (int i = 0; i < 10; i++) {
        printf("  Test %d: ", i + 1);
        
        // Random "pass" or "fail"
        if (rand() % 10 > 2) {
            printf("✓ PASS\n");
        } else {
            printf("✗ FAIL\n");
        }
    }
    
    printf("\nTest Results: 8 passed, 2 failed\n");
    printf("Exit code: 0\n");
}

// ============================================================================
// REAL VERSION (What we need)
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[256];
    int passed;
    int failed;
    int exit_code;
    double duration_seconds;
    char output[4096];
} TestResult;

int real_test_runner(const char* test_executable, TestResult* result) {
    // Initialize result
    strncpy(result->name, test_executable, sizeof(result->name) - 1);
    result->passed = 0;
    result->failed = 0;
    result->exit_code = -1;
    result->duration_seconds = 0.0;
    result->output[0] = '\0';
    
    // Check if test executable exists
    if (GetFileAttributes(test_executable) == INVALID_FILE_ATTRIBUTES) {
        printf("Error: Test executable not found: %s\n", test_executable);
        return -1;
    }
    
    // Set up process execution
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    // Create pipes for capturing output
    HANDLE hStdOutRead, hStdOutWrite;
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    
    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
        printf("Error: Failed to create pipe\n");
        return -1;
    }
    
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdOutWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;
    
    // Execute the actual test
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "\"%s\"", test_executable);
    
    printf("Executing: %s\n", test_executable);
    
    if (!CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        printf("Error: Failed to create process (error: %lu)\n", GetLastError());
        CloseHandle(hStdOutRead);
        CloseHandle(hStdOutWrite);
        return -1;
    }
    
    // Close write end of pipe
    CloseHandle(hStdOutWrite);
    
    // Read output
    DWORD bytesRead;
    char buffer[1024];
    int output_len = 0;
    
    while (ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        
        // Append to result output
        int remaining = sizeof(result->output) - output_len - 1;
        if (remaining > 0) {
            strncat(result->output + output_len, buffer, remaining);
            output_len += strlen(buffer);
        }
        
        // Also print to console
        printf("%s", buffer);
    }
    
    // Wait for process to complete
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    // Get exit code
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    result->exit_code = (int)exit_code;
    
    // Calculate duration
    QueryPerformanceCounter(&end);
    result->duration_seconds = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    
    // Determine pass/fail from exit code
    if (exit_code == 0) {
        result->passed = 1;
        result->failed = 0;
    } else {
        result->passed = 0;
        result->failed = 1;
    }
    
    // Cleanup
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hStdOutRead);
    
    printf("\nCompleted in %.3f seconds\n", result->duration_seconds);
    printf("Exit code: %d (%s)\n", result->exit_code, 
           result->exit_code == 0 ? "PASS" : "FAIL");
    
    return 0;
}

// ============================================================================
// COMPARISON
// ============================================================================

/*
SHINE BOX VERSION:
- Compiles: YES
- Runs: YES  
- Produces output: YES
- Does real work: NO - just prints simulated results
- Can be used in production: NO

REAL VERSION:
- Compiles: YES
- Runs: YES
- Produces output: YES
- Does real work: YES - actually executes test binaries
- Can be used in production: YES

KEY DIFFERENCES:
1. Shine box uses printf() for "results"
   Real version uses CreateProcess() to execute actual tests

2. Shine box generates random pass/fail
   Real version checks actual exit codes from processes

3. Shine box has fake timing (always 0.00 seconds)
   Real version uses QueryPerformanceCounter() for real timing

4. Shine box doesn't handle errors
   Real version checks file existence, process creation, etc.

5. Shine box output is hardcoded
   Real version captures actual output from test execution

COST:
- Shine box: 20 lines, 30 minutes to write
- Real version: 150 lines, 2-3 hours to write and test

VALUE:
- Shine box: $0 (can't be used)
- Real version: $5K-10K (actually works)
*/

int main() {
    printf("=== SHINE BOX VERSION ===\n");
    shine_box_test_runner();
    
    printf("\n\n=== REAL VERSION ===\n");
    TestResult result;
    
    // Try to run a real test (if one exists)
    if (real_test_runner("test_example.exe", &result) == 0) {
        printf("\nTest execution completed successfully!\n");
    } else {
        printf("\nTest execution failed (expected if test_example.exe doesn't exist)\n");
        printf("This demonstrates the tool actually tries to run something real.\n");
    }
    
    return 0;
}
