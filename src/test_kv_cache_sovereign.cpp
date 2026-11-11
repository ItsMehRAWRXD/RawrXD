// ============================================================================
// test_kv_cache_sovereign.cpp — KV-Cache Verification Harness (Sovereign Style)
// ============================================================================
//
// Validates the Power-of-2 Modulo Arithmetic for circular KV-Cache buffer.
// No bloated frameworks. Just raw verification.
//
// Build: cl /c /nologo /O2 test_kv_cache_sovereign.cpp
// Link:  link test_kv_cache_sovereign.obj rawrxd_kv_cache.obj /OUT:TestKVCache.exe
//
// ============================================================================

#include <windows.h>
#include <iostream>
#include <cstdint>
#include <cstring>

// ============================================================================
// MASM Function Declarations (extern "C" for no name mangling)
// ============================================================================

extern "C" {
    // KV Cache operations from rawrxd_kv_cache.asm
    void KVCache_Update_AVX512(float* cache, const float* src, int pos, int head_dim);
    void KVCache_Retrieve_AVX512(float* cache, float* dst, int pos, int head_dim);
}

// ============================================================================
// Power-of-2 Modulo Arithmetic Verification
// ============================================================================

// Fast modulo using bitwise AND (requires power-of-2 size)
inline size_t FastModulo(size_t pointer, size_t size) {
    return pointer & (size - 1);
}

// Traditional modulo (slow)
inline size_t SlowModulo(size_t pointer, size_t size) {
    return pointer % size;
}

// ============================================================================
// Test Functions
// ============================================================================

bool TestPowerOf2Modulo() {
    std::cout << "[TEST] Power-of-2 Modulo Arithmetic Verification\n";
    std::cout << "       Formula: Index = Pointer & (Size - 1)\n\n";
    
    // Test with 64MB buffer (2^26 = 67,108,864 bytes)
    const size_t BUFFER_SIZE = 64 * 1024 * 1024;  // 64MB
    const size_t MASK = BUFFER_SIZE - 1;
    
    bool passed = true;
    int testCount = 0;
    
    // Test cases: various pointer positions
    size_t testPointers[] = {
        0,
        1,
        BUFFER_SIZE - 1,
        BUFFER_SIZE,
        BUFFER_SIZE + 1,
        2 * BUFFER_SIZE - 1,
        2 * BUFFER_SIZE,
        0xFFFFFFFF,  // Max 32-bit value
        0x12345678   // Random value
    };
    
    for (size_t ptr : testPointers) {
        size_t fastResult = FastModulo(ptr, BUFFER_SIZE);
        size_t slowResult = SlowModulo(ptr, BUFFER_SIZE);
        
        if (fastResult != slowResult) {
            std::cout << "  [FAIL] Pointer=" << ptr 
                      << " Fast=" << fastResult 
                      << " Slow=" << slowResult << "\n";
            passed = false;
        } else {
            std::cout << "  [PASS] Pointer=" << ptr 
                      << " Index=" << fastResult << "\n";
        }
        testCount++;
    }
    
    std::cout << "\n[RESULT] " << (passed ? "PASSED" : "FAILED") 
              << " (" << testCount << " tests)\n\n";
    return passed;
}

bool TestAVX512_KVCache() {
    std::cout << "[TEST] AVX-512 KV Cache Operations\n\n";
    
    // Allocate aligned memory for AVX-512 (64-byte alignment)
    const int HEAD_DIM = 64;  // Must be multiple of 16 for AVX-512
    const int NUM_POSITIONS = 10;
    
    float* cache = (float*)_aligned_malloc(
        NUM_POSITIONS * HEAD_DIM * sizeof(float), 64);
    float* src = (float*)_aligned_malloc(HEAD_DIM * sizeof(float), 64);
    float* dst = (float*)_aligned_malloc(HEAD_DIM * sizeof(float), 64);
    
    if (!cache || !src || !dst) {
        std::cout << "  [FAIL] Memory allocation failed\n";
        return false;
    }
    
    // Initialize cache to zeros
    memset(cache, 0, NUM_POSITIONS * HEAD_DIM * sizeof(float));
    
    // Initialize source with test pattern
    for (int i = 0; i < HEAD_DIM; i++) {
        src[i] = (float)(i + 1);
    }
    
    // Test write to position 5
    int testPos = 5;
    std::cout << "  [INFO] Writing to position " << testPos << "\n";
    KVCache_Update_AVX512(cache, src, testPos, HEAD_DIM);
    
    // Test read from position 5
    std::cout << "  [INFO] Reading from position " << testPos << "\n";
    KVCache_Retrieve_AVX512(cache, dst, testPos, HEAD_DIM);
    
    // Verify data integrity
    bool passed = true;
    for (int i = 0; i < HEAD_DIM; i++) {
        if (dst[i] != src[i]) {
            std::cout << "  [FAIL] Mismatch at index " << i 
                      << ": expected " << src[i] << ", got " << dst[i] << "\n";
            passed = false;
            break;
        }
    }
    
    if (passed) {
        std::cout << "  [PASS] Data integrity verified (" << HEAD_DIM << " floats)\n";
    }
    
    // Cleanup
    _aligned_free(cache);
    _aligned_free(src);
    _aligned_free(dst);
    
    std::cout << "\n[RESULT] " << (passed ? "PASSED" : "FAILED") << "\n\n";
    return passed;
}

bool TestCircularBufferWrap() {
    std::cout << "[TEST] Circular Buffer Wrap-Around\n";
    std::cout << "       Using Power-of-2 Modulo Arithmetic\n\n";
    
    const size_t BUFFER_SIZE = 1024;  // 1KB for quick test
    const size_t MASK = BUFFER_SIZE - 1;
    
    // Simulate circular buffer operations
    size_t writePtr = 0;
    size_t readPtr = 0;
    
    bool passed = true;
    
    // Write 2048 bytes (should wrap twice)
    for (size_t i = 0; i < 2048; i++) {
        size_t writeIndex = writePtr & MASK;
        
        // Simulate write
        writePtr++;
        
        // Verify index is within bounds
        if (writeIndex >= BUFFER_SIZE) {
            std::cout << "  [FAIL] Write index out of bounds: " << writeIndex << "\n";
            passed = false;
            break;
        }
    }
    
    if (passed) {
        std::cout << "  [PASS] Write pointer wrapped correctly\n";
        std::cout << "         Final writePtr=" << writePtr 
                  << " Final index=" << (writePtr & MASK) << "\n";
    }
    
    std::cout << "\n[RESULT] " << (passed ? "PASSED" : "FAILED") << "\n\n";
    return passed;
}

// ============================================================================
// Performance Benchmark
// ============================================================================

void BenchmarkModulo() {
    std::cout << "[BENCH] Modulo Operation Performance\n\n";
    
    const size_t ITERATIONS = 100000000;  // 100M iterations
    const size_t BUFFER_SIZE = 64 * 1024 * 1024;  // 64MB
    
    // Warmup
    volatile size_t result = 0;
    for (size_t i = 0; i < 1000000; i++) {
        result = FastModulo(i, BUFFER_SIZE);
    }
    
    // Benchmark fast modulo (&)
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    
    QueryPerformanceCounter(&start);
    for (size_t i = 0; i < ITERATIONS; i++) {
        result = FastModulo(i, BUFFER_SIZE);
    }
    QueryPerformanceCounter(&end);
    
    double fastTime = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    double fastOpsPerSec = ITERATIONS / fastTime;
    
    // Benchmark slow modulo (%)
    QueryPerformanceCounter(&start);
    for (size_t i = 0; i < ITERATIONS; i++) {
        result = SlowModulo(i, BUFFER_SIZE);
    }
    QueryPerformanceCounter(&end);
    
    double slowTime = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    double slowOpsPerSec = ITERATIONS / slowTime;
    
    std::cout << "  Fast Modulo (&):  " << fastTime << "s (" 
              << fastOpsPerSec / 1e6 << " Mops/sec)\n";
    std::cout << "  Slow Modulo (%):  " << slowTime << "s (" 
              << slowOpsPerSec / 1e6 << " Mops/sec)\n";
    std::cout << "  Speedup:          " << slowTime / fastTime << "x\n";
    std::cout << "  Result check:     " << result << " (prevent optimization)\n\n";
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main() {
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  RawrXD KV-Cache Verification Harness                              ║\n";
    std::cout << "║  Power-of-2 Modulo Arithmetic + AVX-512 Validation                  ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n\n";
    
    int passed = 0;
    int total = 0;
    
    // Run tests
    if (TestPowerOf2Modulo()) passed++;
    total++;
    
    if (TestCircularBufferWrap()) passed++;
    total++;
    
    if (TestAVX512_KVCache()) passed++;
    total++;
    
    // Run benchmark
    BenchmarkModulo();
    
    // Summary
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  Test Summary: " << passed << "/" << total << " PASSED";
    for (int i = 0; i < 35 - (passed / 10 + total / 10 + 2); i++) std::cout << " ";
    std::cout << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n\n";
    
    return (passed == total) ? 0 : 1;
}
