//=============================================================================
// GGUFVerifier.cpp - Diagnostic tool for GGUF file integrity
// Checks for corruption, alignment issues, and validates tensor offsets
//=============================================================================

#include "GGUFLoader.hpp"
#include <cstdio>
#include <cstring>
#include <windows.h>
#include "gguf_loader.h"

using namespace Deep2;

//=============================================================================
// File Integrity Check
//=============================================================================
bool VerifyFileIntegrity(const char* filepath) {
    printf("[GGUFVerifier] Checking file integrity: %s\n", filepath);
    
    // Check file exists and get size
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, nullptr, 
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[GGUFVerifier] ERROR: Cannot open file (error %lu)\n", GetLastError());
        return false;
    }
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        printf("[GGUFVerifier] ERROR: Cannot get file size\n");
        CloseHandle(hFile);
        return false;
    }
    
    printf("[GGUFVerifier] File size: %llu bytes (%.2f MB)\n", 
           (unsigned long long)fileSize.QuadPart,
           fileSize.QuadPart / (1024.0 * 1024.0));
    
    CloseHandle(hFile);
    
    // Try to load just metadata first
    GGUFLoadOptions opts;
    opts.loadTensors = false;
    opts.verbose = true;
    
    GGUFLoadResult result = Deep2::GGUFLoader::Load(filepath, opts);
    if (!result.success) {
        printf("[GGUFVerifier] ERROR: Failed to parse metadata: %s\n", result.error);
        return false;
    }
    
    printf("[GGUFVerifier] Metadata parsed successfully:\n");
    result.metadata.Print();
    printf("[GGUFVerifier] Tensor count: %zu\n", result.tensors.size());
    
    // Validate tensor offsets
    uint64_t dataOffset = 0; // Will be calculated
    bool hasErrors = false;
    
    // Calculate expected data offset (after header + metadata + tensor info)
    // This is approximate - actual offset depends on GGUF structure
    size_t headerSize = 4 + 4 + 8 + 8; // magic + version + tensor_count + kv_count
    
    printf("[GGUFVerifier] Validating tensor offsets...\n");
    
    for (size_t i = 0; i < result.tensors.size(); ++i) {
        const auto& t = result.tensors[i];
        uint64_t tensorStart = t.offset;
        uint64_t tensorEnd = tensorStart + t.size;
        
        printf("  Tensor[%zu]: %s\n", i, t.name.c_str());
        printf("    Offset: %llu, Size: %zu, End: %llu\n",
               (unsigned long long)tensorStart, t.size, (unsigned long long)tensorEnd);
        
        // Check alignment
        if (tensorStart % 64 != 0) {
            printf("    WARNING: Offset not 64-byte aligned!\n");
        }
        
        // Check bounds
        if (tensorEnd > (uint64_t)fileSize.QuadPart) {
            printf("    ERROR: Tensor extends beyond file!\n");
            hasErrors = true;
        }
        
        // Check for overlap with previous tensor
        if (i > 0) {
            const auto& prev = result.tensors[i-1];
            uint64_t prevEnd = prev.offset + prev.size;
            if (tensorStart < prevEnd) {
                printf("    ERROR: Overlaps with previous tensor!\n");
                hasErrors = true;
            }
        }
    }
    
    if (hasErrors) {
        printf("[GGUFVerifier] FAILED: File has integrity errors\n");
        return false;
    }
    
    printf("[GGUFVerifier] All tensor offsets valid\n");
    return true;
}

//=============================================================================
// Test Load with Detailed Error Reporting
//=============================================================================
bool TestFullLoad(const char* filepath) {
    printf("\n[GGUFVerifier] Testing full tensor load...\n");
    
    GGUFLoadOptions opts;
    opts.loadTensors = true;
    opts.verbose = true;
    opts.maxMemoryMB = 0; // No limit
    
    GGUFLoadResult result = Deep2::GGUFLoader::Load(filepath, opts);
    
    if (!result.success) {
        printf("[GGUFVerifier] FAILED: %s\n", result.error);
        return false;
    }
    
    printf("[GGUFVerifier] SUCCESS: Loaded %zu tensors in %.2f ms\n",
           result.tensors.size(), result.loadTimeMs);
    printf("[GGUFVerifier] Total memory: %.2f MB\n", 
           result.totalSize / (1024.0 * 1024.0));
    
    // Verify a few tensors
    printf("[GGUFVerifier] Verifying tensor data...\n");
    int verified = 0;
    for (const auto& t : result.tensors) {
        if (t.data == nullptr) {
            printf("  ERROR: %s has null data pointer\n", t.name.c_str());
            return false;
        }
        
        // Check first few bytes are not all zeros (basic sanity check)
        bool allZero = true;
        const uint8_t* bytes = (const uint8_t*)t.data;
        for (size_t j = 0; j < 16 && j < t.size; ++j) {
            if (bytes[j] != 0) {
                allZero = false;
                break;
            }
        }
        
        if (allZero && t.size > 0) {
            printf("  WARNING: %s first 16 bytes are all zero\n", t.name.c_str());
        }
        
        if (++verified >= 5) break; // Just check first 5
    }
    
    printf("[GGUFVerifier] Data verification passed\n");
    return true;
}

//=============================================================================
// Main Entry Point
//=============================================================================
int main(int argc, char** argv) {
    printf("========================================\n");
    printf("  GGUF Verifier Tool v1.0\n");
    printf("  RawrXD Deep2 Engine\n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <gguf_file>\n", argv[0]);
        printf("\nThis tool verifies GGUF file integrity and tests loading.\n");
        return 1;
    }
    
    const char* filepath = argv[1];
    
    bool ok = true;
    
    // Phase 1: Verify metadata and offsets
    if (!VerifyFileIntegrity(filepath)) {
        ok = false;
    }
    
    // Phase 2: Test full load
    if (ok && !TestFullLoad(filepath)) {
        ok = false;
    }
    
    printf("\n========================================\n");
    if (ok) {
        printf("  VERIFICATION PASSED\n");
        printf("  File is valid and loadable\n");
    } else {
        printf("  VERIFICATION FAILED\n");
        printf("  File has errors - see above\n");
    }
    printf("========================================\n");
    
    return ok ? 0 : 1;
}

