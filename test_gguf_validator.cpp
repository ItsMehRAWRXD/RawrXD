// ============================================================================
// RawrXD GGUF Validator Test - Phase 6
// ============================================================================

#include "src/cli/gguf_validator.hpp"
#include <cstdio>
#include <cstring>

using namespace RawrXD;

// Create a minimal valid GGUF file for testing
bool CreateTestGGUF(const char* path, uint32_t version, uint64_t tensorCount) {
    FILE* f = nullptr;
    fopen_s(&f, path, "wb");
    if (!f) return false;
    
    // Write magic
    uint32_t magic = 0x46554747; // "GGUF"
    fwrite(&magic, sizeof(magic), 1, f);
    
    // Write version
    fwrite(&version, sizeof(version), 1, f);
    
    // Write tensor count
    fwrite(&tensorCount, sizeof(tensorCount), 1, f);
    
    // Write metadata kv count
    uint64_t kvCount = 0;
    fwrite(&kvCount, sizeof(kvCount), 1, f);
    
    // Pad to reasonable size
    uint8_t padding[256] = {0};
    fwrite(padding, sizeof(padding), 1, f);
    
    fclose(f);
    return true;
}

bool CreateInvalidFile(const char* path) {
    FILE* f = nullptr;
    fopen_s(&f, path, "wb");
    if (!f) return false;
    
    // Write invalid magic
    uint32_t magic = 0x12345678;
    fwrite(&magic, sizeof(magic), 1, f);
    
    fclose(f);
    return true;
}

int main() {
    printf("========================================\n");
    printf("RawrXD GGUF Validator Test\n");
    printf("========================================\n\n");
    
    int passed = 0;
    int failed = 0;
    
    // Test 1: Valid GGUF v2
    printf("Test 1: Valid GGUF v2...\n");
    if (CreateTestGGUF("test_v2.gguf", 2, 10)) {
        auto result = GGUFValidator::QuickValidate("test_v2.gguf");
        if (result.has_value() && result.value()) {
            printf("  [PASS] Valid GGUF v2 recognized\n");
            passed++;
        } else {
            printf("  [FAIL] Valid GGUF v2 rejected: %s\n", 
                   GGUFValidator::ErrorToString(result.error()));
            failed++;
        }
        remove("test_v2.gguf");
    } else {
        printf("  [SKIP] Could not create test file\n");
    }
    
    // Test 2: Valid GGUF v3
    printf("Test 2: Valid GGUF v3...\n");
    if (CreateTestGGUF("test_v3.gguf", 3, 10)) {
        auto result = GGUFValidator::QuickValidate("test_v3.gguf");
        if (result.has_value() && result.value()) {
            printf("  [PASS] Valid GGUF v3 recognized\n");
            passed++;
        } else {
            printf("  [FAIL] Valid GGUF v3 rejected: %s\n",
                   GGUFValidator::ErrorToString(result.error()));
            failed++;
        }
        remove("test_v3.gguf");
    } else {
        printf("  [SKIP] Could not create test file\n");
    }
    
    // Test 3: Invalid magic
    printf("Test 3: Invalid magic...\n");
    if (CreateInvalidFile("test_invalid.gguf")) {
        auto result = GGUFValidator::QuickValidate("test_invalid.gguf");
        if (!result.has_value() && result.error() == GGUFValidationError::InvalidMagic) {
            printf("  [PASS] Invalid magic correctly rejected\n");
            passed++;
        } else {
            printf("  [FAIL] Invalid magic not rejected\n");
            failed++;
        }
        remove("test_invalid.gguf");
    } else {
        printf("  [SKIP] Could not create test file\n");
    }
    
    // Test 4: Non-existent file
    printf("Test 4: Non-existent file...\n");
    {
        auto result = GGUFValidator::QuickValidate("nonexistent.gguf");
        if (!result.has_value() && result.error() == GGUFValidationError::FileNotFound) {
            printf("  [PASS] Non-existent file correctly rejected\n");
            passed++;
        } else {
            printf("  [FAIL] Non-existent file not rejected properly\n");
            failed++;
        }
    }
    
    // Test 5: Unsupported version
    printf("Test 5: Unsupported version (v1)...\n");
    if (CreateTestGGUF("test_v1.gguf", 1, 10)) {
        auto result = GGUFValidator::QuickValidate("test_v1.gguf");
        if (!result.has_value() && result.error() == GGUFValidationError::UnsupportedVersion) {
            printf("  [PASS] Unsupported version correctly rejected\n");
            passed++;
        } else {
            printf("  [FAIL] Unsupported version not rejected\n");
            failed++;
        }
        remove("test_v1.gguf");
    } else {
        printf("  [SKIP] Could not create test file\n");
    }
    
    // Test 6: Full validation
    printf("Test 6: Full validation...\n");
    if (CreateTestGGUF("test_full.gguf", 3, 5)) {
        auto result = GGUFValidator::FullValidate("test_full.gguf");
        if (result.valid && result.version == 3 && result.tensorCount == 5) {
            printf("  [PASS] Full validation works correctly\n");
            printf("    Version: %u, Tensors: %llu\n", result.version, result.tensorCount);
            passed++;
        } else {
            printf("  [FAIL] Full validation failed: %s\n", result.errorMessage.c_str());
            failed++;
        }
        remove("test_full.gguf");
    } else {
        printf("  [SKIP] Could not create test file\n");
    }
    
    // Summary
    printf("\n========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n", failed);
    printf("Total:  %d\n", passed + failed);
    
    if (failed == 0) {
        printf("\n[PASS] All tests passed!\n");
        return 0;
    } else {
        printf("\n[FAIL] Some tests failed!\n");
        return 1;
    }
}
