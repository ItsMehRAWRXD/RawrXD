// ============================================================================
// test_integration.c
// Integration test for RawrXD components
// Compile: gcc -O2 test_integration.c -o test_integration.exe
// ============================================================================

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "winhttp.lib")

#define TEST_PASS "[PASS]"
#define TEST_FAIL "[FAIL]"
#define TEST_SKIP "[SKIP]"

typedef struct {
    int passed;
    int failed;
    int skipped;
} TestResults;

void test_start(const char* name) {
    printf("\n[Test] %s\n", name);
}

void test_pass(TestResults* r, const char* msg) {
    printf("  %s %s\n", TEST_PASS, msg);
    r->passed++;
}

void test_fail(TestResults* r, const char* msg) {
    printf("  %s %s\n", TEST_FAIL, msg);
    r->failed++;
}

void test_skip(TestResults* r, const char* msg) {
    printf("  %s %s\n", TEST_SKIP, msg);
    r->skipped++;
}

// Test 1: Native Toolchain
void test_toolchain(TestResults* r) {
    test_start("Native Toolchain");
    
    const char* tools[] = {
        "compilers/native_toolchain/rawrxd_native_assembler.exe",
        "compilers/native_toolchain/rawrxd_native_linker.exe",
        "compilers/native_toolchain/rawrxd_native_librarian.exe",
        NULL
    };
    
    int found = 0;
    for (int i = 0; tools[i]; i++) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "d:\\rawrxd\\%s", tools[i]);
        
        DWORD attribs = GetFileAttributesA(path);
        if (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
            found++;
        }
    }
    
    if (found >= 3) {
        test_pass(r, "Core toolchain tools present");
    } else {
        test_fail(r, "Missing toolchain tools");
    }
}

// Test 2: Heap Patch
void test_heap_patch(TestResults* r) {
    test_start("Heap Patch");
    
    const char* patch = "d:\\rawrxd\\compilers\\native_toolchain\\sovereign_memory_patch.obj";
    DWORD attribs = GetFileAttributesA(patch);
    
    if (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
        test_pass(r, "Heap patch object exists");
    } else {
        test_fail(r, "Heap patch not found");
    }
}

// Test 3: Sovereign Objects
void test_sovereign_objects(TestResults* r) {
    test_start("Sovereign Build Objects");
    
    const char* objs[] = {
        "d:\\sovereign_build\\Sovereign_GGUF_Loader.obj",
        "d:\\sovereign_build\\Sovereign_Memory_Manager.obj",
        "d:\\sovereign_build\\Sovereign_Forward_Pass.obj",
        NULL
    };
    
    int found = 0;
    for (int i = 0; objs[i]; i++) {
        DWORD attribs = GetFileAttributesA(objs[i]);
        if (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
            found++;
        }
    }
    
    if (found >= 2) {
        test_pass(r, "Sovereign objects available");
    } else {
        test_skip(r, "Sovereign objects not found (run sovereign build first)");
    }
}

// Test 4: Ollama Connectivity
void test_ollama(TestResults* r) {
    test_start("Ollama Integration");
    
    HINTERNET hSession = WinHttpOpen(L"RawrXD-Test/1.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, 
        WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) {
        test_fail(r, "Failed to create WinHTTP session");
        return;
    }
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"localhost", 11434, 0);
    if (!hConnect) {
        test_fail(r, "Cannot connect to Ollama");
        WinHttpCloseHandle(hSession);
        return;
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/tags",
        NULL, WINHTTP_NO_REFERER, 
        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    
    if (!hRequest) {
        test_fail(r, "Failed to create request");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }
    
    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        if (WinHttpReceiveResponse(hRequest, NULL)) {
            test_pass(r, "Ollama responding");
        } else {
            test_fail(r, "Ollama not responding");
        }
    } else {
        test_fail(r, "Failed to send request to Ollama");
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

// Test 5: Model Availability
void test_models(TestResults* r) {
    test_start("Model Availability");
    
    // Check for known model paths
    const char* models[] = {
        "F:\\OllamaModels\\Phi-3-mini-4k-instruct-q8_0.gguf",
        "F:\\OllamaModels\\codestral-22b-v0.1.Q8_0.gguf",
        NULL
    };
    
    int found = 0;
    for (int i = 0; models[i]; i++) {
        DWORD attribs = GetFileAttributesA(models[i]);
        if (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
            found++;
        }
    }
    
    if (found > 0) {
        test_pass(r, "GGUF models available locally");
    } else {
        test_skip(r, "No local GGUF models found (using Ollama API instead)");
    }
}

// Test 6: IDE Components
void test_ide(TestResults* r) {
    test_start("IDE Components");
    
    // Check for Qt project files or IDE executables
    const char* ide_files[] = {
        "d:\\rawrxd\\RawrXD.pro",
        "d:\\rawrxd\\CMakeLists.txt",
        NULL
    };
    
    int found = 0;
    for (int i = 0; ide_files[i]; i++) {
        DWORD attribs = GetFileAttributesA(ide_files[i]);
        if (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
            found++;
        }
    }
    
    if (found > 0) {
        test_pass(r, "IDE project files present");
    } else {
        test_skip(r, "IDE project files not in expected location");
    }
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RawrXD Integration Test Suite\n");
    printf("========================================\n");
    printf("Testing component integration...\n");
    
    TestResults results = {0, 0, 0};
    
    test_toolchain(&results);
    test_heap_patch(&results);
    test_sovereign_objects(&results);
    test_ollama(&results);
    test_models(&results);
    test_ide(&results);
    
    printf("\n========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Passed:  %d\n", results.passed);
    printf("Failed:  %d\n", results.failed);
    printf("Skipped: %d\n", results.skipped);
    printf("========================================\n");
    
    if (results.failed == 0) {
        printf("\n✅ Integration tests passed!\n");
        printf("System is ready for final build.\n");
        return 0;
    } else {
        printf("\n⚠️  Some tests failed.\n");
        printf("Review failures above.\n");
        return 1;
    }
}
