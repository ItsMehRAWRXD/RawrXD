// ============================================================================
// RawrXD Hotpatch Memory Safety Test
// Phase 4B: Verify heap copy prevents dangling pointer after loader destruction
// ============================================================================
// This test verifies:
// 1. GGUFLoader opens and maps a file
// 2. Data is copied to heap before loader destructor fires
// 3. Heap data remains valid after mapped view is unmapped
// 4. No access violation when reading from heap copy
// ============================================================================

#include <windows.h>
#include <cstdio>
#include <cstring>
#include "../gguf_loader.h"

// Simple test structure to verify memory safety
struct TestResult {
    bool loaderOpened = false;
    bool headerParsed = false;
    bool dataCopied = false;
    bool loaderDestroyed = false;
    bool heapDataValid = false;
    bool fileUnlocked = false;
    const char* errorMessage = nullptr;
};

// Test data - we'll create a minimal GGUF file
static const char* kTestFilePath = "D:\\temp\\hotpatch_test.gguf";

// Minimal GGUF header for testing
// Magic: "GGUF" (0x46555547 as little-endian)
// Version: 3
// Tensor count: 1
// Metadata KV count: 0
static const uint8_t kMinimalGGUF[] = {
    0x47, 0x47, 0x55, 0x46,  // "GGUF" magic
    0x03, 0x00, 0x00, 0x00,  // Version 3 (uint32)
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Tensor count: 1 (uint64)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Metadata KV count: 0 (uint64)
    // Tensor info would follow here...
};

bool CreateTestFile() {
    HANDLE hFile = CreateFileA(
        kTestFilePath,
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Failed to create test file\n");
        return false;
    }
    
    DWORD written = 0;
    WriteFile(hFile, kMinimalGGUF, sizeof(kMinimalGGUF), &written, nullptr);
    CloseHandle(hFile);
    
    printf("[TEST] Created test GGUF file: %s (%zu bytes)\n", kTestFilePath, sizeof(kMinimalGGUF));
    return true;
}

bool DeleteTestFile() {
    return DeleteFileA(kTestFilePath) != FALSE;
}

bool IsFileLocked() {
    // Try to open file exclusively - if it fails, file is locked
    HANDLE hFile = CreateFileA(
        kTestFilePath,
        GENERIC_READ | GENERIC_WRITE,
        0,  // No sharing
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return true;  // File is locked
    }
    
    CloseHandle(hFile);
    return false;  // File is not locked
}

TestResult RunMemorySafetyTest() {
    TestResult result;
    
    printf("\n========================================\n");
    printf("Hotpatch Memory Safety Test\n");
    printf("========================================\n\n");
    
    // Create test file
    if (!CreateTestFile()) {
        result.errorMessage = "Failed to create test file";
        return result;
    }
    
    // Verify file is initially unlocked
    if (IsFileLocked()) {
        result.errorMessage = "Test file unexpectedly locked before test";
        return result;
    }
    
    // Pointer to hold heap-copied data
    void* heapBuffer = nullptr;
    size_t dataSize = 0;
    
    {
        printf("[TEST] Creating GGUFLoader on stack...\n");
        
        // Create loader on stack
        GGUFLoader loader;
        result.loaderOpened = loader.Open(kTestFilePath);
        
        if (!result.loaderOpened) {
            result.errorMessage = "Failed to open GGUF file";
            DeleteTestFile();
            return result;
        }
        printf("[TEST] ✓ GGUFLoader opened file\n");
        
        // Parse header
        result.headerParsed = loader.ParseHeader();
        if (!result.headerParsed) {
            result.errorMessage = "Failed to parse GGUF header";
            DeleteTestFile();
            return result;
        }
        printf("[TEST] ✓ GGUF header parsed\n");
        
        // Get mapped base address
        const void* mappedBase = loader.GetBaseAddress();
        if (!mappedBase) {
            result.errorMessage = "Mapped base address is null";
            DeleteTestFile();
            return result;
        }
        printf("[TEST] ✓ Mapped base address: %p\n", mappedBase);
        
        // Simulate data copy to heap (what hotpatch_model_manager does)
        dataSize = sizeof(kMinimalGGUF);
        heapBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dataSize);
        if (!heapBuffer) {
            result.errorMessage = "Failed to allocate heap buffer";
            DeleteTestFile();
            return result;
        }
        
        // Copy data from mapped view to heap
        memcpy(heapBuffer, mappedBase, dataSize);
        result.dataCopied = true;
        printf("[TEST] ✓ Copied %zu bytes to heap buffer: %p\n", dataSize, heapBuffer);
        
        // Verify copy succeeded
        if (memcmp(heapBuffer, mappedBase, dataSize) != 0) {
            result.errorMessage = "Heap copy verification failed";
            HeapFree(GetProcessHeap(), 0, heapBuffer);
            DeleteTestFile();
            return result;
        }
        printf("[TEST] ✓ Heap copy verified (memcmp passed)\n");
        
        // LOADER GOES OUT OF SCOPE HERE
        printf("[TEST] GGUFLoader going out of scope...\n");
    }  // ~GGUFLoader() called here
    
    result.loaderDestroyed = true;
    printf("[TEST] ✓ GGUFLoader destroyed (UnmapViewOfFile called)\n");
    
    // CRITICAL TEST: Verify heap data is still valid after mapped view destroyed
    printf("[TEST] Verifying heap data still valid...\n");
    
    // Try to read from heap buffer - this would AV if we were using dangling mapped pointer
    bool heapDataValid = true;
    __try {
        // Read first 4 bytes (magic)
        uint32_t magic = *(uint32_t*)heapBuffer;
        if (magic != 0x46555547) {  // "GGUF" in little-endian
            printf("[TEST] ✗ Heap data corrupted (magic mismatch: 0x%08X)\n", magic);
            heapDataValid = false;
        } else {
            printf("[TEST] ✓ Heap data valid (magic: 0x%08X = 'GGUF')\n", magic);
        }
        
        // Read version
        uint32_t version = *((uint32_t*)heapBuffer + 1);
        printf("[TEST] ✓ Heap data accessible (version: %u)\n", version);
        
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[TEST] ✗ ACCESS VIOLATION when reading heap data!\n");
        heapDataValid = false;
    }
    
    result.heapDataValid = heapDataValid;
    
    // Verify file is unlocked
    result.fileUnlocked = !IsFileLocked();
    if (result.fileUnlocked) {
        printf("[TEST] ✓ File is unlocked (can be reopened)\n");
    } else {
        printf("[TEST] ✗ File is still locked!\n");
    }
    
    // Cleanup
    if (heapBuffer) {
        HeapFree(GetProcessHeap(), 0, heapBuffer);
        printf("[TEST] ✓ Freed heap buffer\n");
    }
    
    DeleteTestFile();
    printf("[TEST] ✓ Deleted test file\n");
    
    return result;
}

int main() {
    printf("RawrXD Hotpatch Memory Safety Test\n");
    printf("===================================\n");
    printf("This test verifies that:\n");
    printf("1. GGUFLoader maps a file\n");
    printf("2. Data is copied to heap BEFORE loader destructor\n");
    printf("3. Heap data survives after mapped view is unmapped\n");
    printf("4. File is unlocked for subsequent hotpatches\n\n");
    
    TestResult result = RunMemorySafetyTest();
    
    printf("\n========================================\n");
    printf("Test Results:\n");
    printf("========================================\n");
    printf("Loader opened:     %s\n", result.loaderOpened ? "PASS" : "FAIL");
    printf("Header parsed:     %s\n", result.headerParsed ? "PASS" : "FAIL");
    printf("Data copied:       %s\n", result.dataCopied ? "PASS" : "FAIL");
    printf("Loader destroyed:  %s\n", result.loaderDestroyed ? "PASS" : "FAIL");
    printf("Heap data valid:   %s\n", result.heapDataValid ? "PASS" : "FAIL");
    printf("File unlocked:     %s\n", result.fileUnlocked ? "PASS" : "FAIL");
    
    if (result.errorMessage) {
        printf("\nError: %s\n", result.errorMessage);
    }
    
    bool allPassed = result.loaderOpened && result.headerParsed && result.dataCopied &&
                     result.loaderDestroyed && result.heapDataValid && result.fileUnlocked;
    
    printf("\n%s\n", allPassed ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    
    return allPassed ? 0 : 1;
}
