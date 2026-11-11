// ============================================================================
// RawrXD Hash Kernel Test
// Phase 7C: Immutable Execution Fabric Verification
// ============================================================================

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <windows.h>

// External MASM functions
extern "C" {
    uint64_t RawrXD_Hash64(const void* data, size_t len, uint64_t seed);
    uint64_t RawrXD_Hash64_Simple(const void* data, size_t len, uint64_t seed);
    uint64_t RawrXD_HashCombine(uint64_t h1, uint64_t h2);
    uint64_t RawrXD_HashFloat32(const float* data, size_t count, uint64_t seed);
}

// Format hash as hex
void FormatHash(uint64_t hash, char* buf, size_t size) {
    static const char hex[] = "0123456789ABCDEF";
    for (int i = 15; i >= 0; --i) {
        buf[i] = hex[hash & 0xF];
        hash >>= 4;
    }
    buf[16] = '\0';
}

int main() {
    printf("========================================\n");
    printf("RawrXD Hash Kernel Test\n");
    printf("Phase 7C: Immutable Execution Fabric\n");
    printf("========================================\n\n");

    char hash_str[32];
    
    // Test 1: Basic string hashing
    printf("Test 1: Basic String Hashing\n");
    printf("------------------------------\n");
    
    const char* test_str = "Hello, World!";
    uint64_t hash1 = RawrXD_Hash64(test_str, strlen(test_str), 0);
    FormatHash(hash1, hash_str, sizeof(hash_str));
    printf("  Input: \"%s\"\n", test_str);
    printf("  Hash:  %s\n\n", hash_str);
    
    // Test 2: Same input, same seed = same hash (deterministic)
    printf("Test 2: Determinism Check\n");
    printf("------------------------------\n");
    uint64_t hash2 = RawrXD_Hash64(test_str, strlen(test_str), 0);
    FormatHash(hash2, hash_str, sizeof(hash_str));
    printf("  Hash 1: %s\n", hash_str);
    FormatHash(hash1, hash_str, sizeof(hash_str));
    printf("  Hash 2: %s\n", hash_str);
    printf("  Match:  %s\n\n", (hash1 == hash2) ? "PASS" : "FAIL");
    
    // Test 3: Different seeds = different hashes
    printf("Test 3: Seed Sensitivity\n");
    printf("------------------------------\n");
    uint64_t hash3 = RawrXD_Hash64(test_str, strlen(test_str), 12345);
    FormatHash(hash3, hash_str, sizeof(hash_str));
    printf("  Seed 0:    ");
    FormatHash(hash1, hash_str, sizeof(hash_str));
    printf("%s\n", hash_str);
    printf("  Seed 12345: ");
    FormatHash(hash3, hash_str, sizeof(hash_str));
    printf("%s\n", hash_str);
    printf("  Different: %s\n\n", (hash1 != hash3) ? "PASS" : "FAIL");
    
    // Test 4: Empty string
    printf("Test 4: Empty String\n");
    printf("------------------------------\n");
    uint64_t hash_empty = RawrXD_Hash64("", 0, 0);
    FormatHash(hash_empty, hash_str, sizeof(hash_str));
    printf("  Hash: %s\n\n", hash_str);
    
    // Test 5: Hash combine
    printf("Test 5: Hash Combine\n");
    printf("------------------------------\n");
    uint64_t combined = RawrXD_HashCombine(hash1, hash3);
    FormatHash(combined, hash_str, sizeof(hash_str));
    printf("  Hash 1:    ");
    FormatHash(hash1, hash_str, sizeof(hash_str));
    printf("%s\n", hash_str);
    printf("  Hash 2:    ");
    FormatHash(hash3, hash_str, sizeof(hash_str));
    printf("%s\n", hash_str);
    printf("  Combined:  %s\n\n", hash_str);
    
    // Test 6: Float array hashing with NaN normalization
    printf("Test 6: Float Array Hashing\n");
    printf("------------------------------\n");
    float floats[] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    uint64_t float_hash = RawrXD_HashFloat32(floats, 5, 0);
    FormatHash(float_hash, hash_str, sizeof(hash_str));
    printf("  Input: [1.0, 2.0, 3.0, 4.0, 5.0]\n");
    printf("  Hash:  %s\n\n", hash_str);
    
    // Test 7: NaN normalization
    printf("Test 7: NaN Normalization\n");
    printf("------------------------------\n");
    float with_nan[] = {1.0f, 0.0f / 0.0f, 3.0f};  // 0/0 = NaN
    float with_canonical[] = {1.0f, 0.0f / 0.0f, 3.0f};  // Same NaN
    uint64_t hash_nan1 = RawrXD_HashFloat32(with_nan, 3, 0);
    uint64_t hash_nan2 = RawrXD_HashFloat32(with_canonical, 3, 0);
    FormatHash(hash_nan1, hash_str, sizeof(hash_str));
    printf("  Hash 1: %s\n", hash_str);
    FormatHash(hash_nan2, hash_str, sizeof(hash_str));
    printf("  Hash 2: %s\n", hash_str);
    printf("  Match:  %s (NaN normalized)\n\n", (hash_nan1 == hash_nan2) ? "PASS" : "FAIL");
    
    // Test 8: Negative zero normalization
    printf("Test 8: Negative Zero Normalization\n");
    printf("------------------------------\n");
    float neg_zero = -0.0f;
    float pos_zero = 0.0f;
    float arr1[] = {1.0f, neg_zero, 2.0f};
    float arr2[] = {1.0f, pos_zero, 2.0f};
    uint64_t hash_nz = RawrXD_HashFloat32(arr1, 3, 0);
    uint64_t hash_pz = RawrXD_HashFloat32(arr2, 3, 0);
    FormatHash(hash_nz, hash_str, sizeof(hash_str));
    printf("  Hash (-0.0): %s\n", hash_str);
    FormatHash(hash_pz, hash_str, sizeof(hash_str));
    printf("  Hash (+0.0): %s\n", hash_str);
    printf("  Match:       %s (-0.0 == +0.0)\n\n", (hash_nz == hash_pz) ? "PASS" : "FAIL");
    
    // Test 9: Large buffer performance
    printf("Test 9: Large Buffer Performance\n");
    printf("------------------------------\n");
    const size_t large_size = 1024 * 1024;  // 1MB
    uint8_t* large_buf = new uint8_t[large_size];
    for (size_t i = 0; i < large_size; ++i) {
        large_buf[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    uint64_t large_hash = RawrXD_Hash64(large_buf, large_size, 0);
    
    QueryPerformanceCounter(&end);
    double elapsed = static_cast<double>(end.QuadPart - start.QuadPart) / freq.QuadPart;
    double throughput = (large_size / (1024.0 * 1024.0)) / elapsed;  // MB/s
    
    FormatHash(large_hash, hash_str, sizeof(hash_str));
    printf("  Size:      %zu MB\n", large_size / (1024 * 1024));
    printf("  Time:      %.3f ms\n", elapsed * 1000);
    printf("  Speed:     %.1f MB/s\n", throughput);
    printf("  Hash:      %s\n\n", hash_str);
    
    delete[] large_buf;
    
    printf("========================================\n");
    printf("Hash Kernel Tests Complete\n");
    printf("========================================\n");
    
    return 0;
}
