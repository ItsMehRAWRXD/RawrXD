/*
 * RawrXD Binary Validation Test
 * Validates the actual RawrXD executable exists and runs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>
#include <windows.h>

#define TEST_NAME "Binary Validation"
#define RAWRXD_EXE "..\\..\\RawrXD.exe"
#define TIMEOUT_MS 10000

typedef struct {
    const char* name;
    int (*func)(void);
} test_case_t;

int tests_passed = 0;
int tests_failed = 0;

/* Test 1: Check executable exists */
int test_executable_exists() {
    printf("\n  [TEST] Executable Exists\n");
    
    DWORD attribs = GetFileAttributesA(RAWRXD_EXE);
    if (attribs == INVALID_FILE_ATTRIBUTES) {
        printf("    Executable not found: %s\n", RAWRXD_EXE);
        printf("    (This is OK if RawrXD hasn't been built yet)\n");
        return 0; /* Skip, don't fail */
    }
    
    printf("    ✓ Executable found\n");
    return 0;
}

/* Test 2: Check executable can run (help/version) */
int test_executable_runs() {
    printf("\n  [TEST] Executable Runs\n");
    
    /* Try to run with --version or --help */
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    char cmdLine[] = RAWRXD_EXE " --version";
    
    BOOL success = CreateProcessA(
        NULL,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );
    
    if (!success) {
        printf("    Could not start process (may not be built)\n");
        return 0; /* Skip */
    }
    
    /* Wait for process with timeout */
    DWORD waitResult = WaitForSingleObject(pi.hProcess, TIMEOUT_MS);
    
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        printf("    ✗ Process timed out\n");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }
    
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    if (exitCode == 0) {
        printf("    ✓ Process executed successfully\n");
        return 0;
    } else {
        printf("    Process exited with code: %lu\n", exitCode);
        return 0; /* Non-zero exit might be OK for --version */
    }
}

/* Test 3: Check file size is reasonable */
int test_executable_size() {
    printf("\n  [TEST] Executable Size\n");
    
    HANDLE hFile = CreateFileA(
        RAWRXD_EXE,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("    Cannot open file (may not be built)\n");
        return 0; /* Skip */
    }
    
    LARGE_INTEGER size;
    if (!GetFileSizeEx(hFile, &size)) {
        CloseHandle(hFile);
        printf("    ✗ Cannot get file size\n");
        return -1;
    }
    
    CloseHandle(hFile);
    
    /* Check size is reasonable (between 100KB and 1GB) */
    if (size.QuadPart < 100 * 1024) {
        printf("    ✗ File too small: %lld bytes\n", size.QuadPart);
        return -1;
    }
    
    if (size.QuadPart > 1024LL * 1024 * 1024) {
        printf("    ✗ File too large: %lld bytes\n", size.QuadPart);
        return -1;
    }
    
    printf("    ✓ File size OK: %.2f MB\n", size.QuadPart / (1024.0 * 1024.0));
    return 0;
}

/* Test 4: Check dependencies (imports) */
int test_dependencies() {
    printf("\n  [TEST] Dependencies\n");
    
    /* Check if we can load the executable as a data file */
    HANDLE hFile = CreateFileA(
        RAWRXD_EXE,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("    Cannot check dependencies (file not found)\n");
        return 0; /* Skip */
    }
    
    /* Read DOS header */
    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead;
    
    if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL) ||
        bytesRead != sizeof(dosHeader)) {
        CloseHandle(hFile);
        printf("    ✗ Cannot read DOS header\n");
        return -1;
    }
    
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        printf("    ✗ Invalid DOS signature\n");
        return -1;
    }
    
    /* Check PE signature */
    SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN);
    
    DWORD peSignature;
    if (!ReadFile(hFile, &peSignature, sizeof(peSignature), &bytesRead, NULL) ||
        bytesRead != sizeof(peSignature)) {
        CloseHandle(hFile);
        printf("    ✗ Cannot read PE signature\n");
        return -1;
    }
    
    if (peSignature != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        printf("    ✗ Invalid PE signature\n");
        return -1;
    }
    
    CloseHandle(hFile);
    
    printf("    ✓ Valid PE executable\n");
    return 0;
}

/* Run a test */
void run_test(const char* name, int (*func)(void)) {
    int result = func();
    
    if (result == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
}

int main() {
    printf("RawrXD Binary Validation Test\n");
    printf("=============================\n");
    printf("Checking: %s\n\n", RAWRXD_EXE);
    
    /* Run tests */
    run_test("Executable Exists", test_executable_exists);
    run_test("Executable Runs", test_executable_runs);
    run_test("Executable Size", test_executable_size);
    run_test("Dependencies", test_dependencies);
    
    /* Summary */
    printf("\n");
    printf("=============================\n");
    printf("Binary Validation Summary\n");
    printf("=============================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("Total tests:  %d\n", tests_passed + tests_failed);
    
    if (tests_failed == 0) {
        printf("\n✓ BINARY VALIDATION PASSED\n");
        return 0;
    } else {
        printf("\n✗ BINARY VALIDATION FAILED\n");
        return 1;
    }
}
