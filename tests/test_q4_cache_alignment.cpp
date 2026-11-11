//=============================================================================
// Q4_0 Cache Alignment Validation
// Ensures Q4PreparedBlock is 64-byte cache line aligned
// Validates memory layout for optimal cache performance
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <random>
#include <chrono>
#include <intrin.h>
#include "../src/memory/Q4WeightPreprocess.hpp"

using namespace RawrXD::Memory;

// Cache line size (typically 64 bytes on x86_64)
constexpr size_t CACHE_LINE_SIZE = 64;

// Test alignment of PreprocessedQ4Block
bool test_block_alignment() {
    printf("=============================================================================\n");
    printf("CACHE ALIGNMENT VALIDATION\n");
    printf("=============================================================================\n\n");
    
    printf("Testing PreprocessedQ4Block alignment...\n\n");
    
    // Test 1: Check struct size is multiple of cache line
    size_t struct_size = sizeof(PreprocessedQ4Block);
    printf("Struct Analysis:\n");
    printf("  sizeof(PreprocessedQ4Block): %zu bytes\n", struct_size);
    printf("  CACHE_LINE_SIZE: %zu bytes\n", CACHE_LINE_SIZE);
    printf("  Alignment: %zu bytes\n", alignof(PreprocessedQ4Block));
    printf("\n");
    
    bool size_ok = (struct_size % CACHE_LINE_SIZE) == 0;
    printf("  Size multiple of cache line: %s\n", size_ok ? "PASS" : "FAIL");
    
    if (!size_ok) {
        printf("  WARNING: Struct size (%zu) is not multiple of cache line (%zu)\n",
               struct_size, CACHE_LINE_SIZE);
        printf("  Padding needed: %zu bytes\n", CACHE_LINE_SIZE - (struct_size % CACHE_LINE_SIZE));
    }
    printf("\n");
    
    // Test 2: Check actual allocation alignment
    printf("Allocation Alignment Test:\n");
    
    std::vector<PreprocessedQ4Block*> blocks;
    blocks.reserve(100);
    
    bool all_aligned = true;
    for (int i = 0; i < 100; i++) {
        PreprocessedQ4Block* block = new PreprocessedQ4Block;
        blocks.push_back(block);
        
        uintptr_t addr = reinterpret_cast<uintptr_t>(block);
        bool aligned = (addr % CACHE_LINE_SIZE) == 0;
        
        if (!aligned) {
            printf("  Block %d: MISALIGNED at %p (offset %zu)\n",
                   i, static_cast<void*>(block), addr % CACHE_LINE_SIZE);
            all_aligned = false;
        }
    }
    
    // Cleanup
    for (auto* block : blocks) {
        delete block;
    }
    
    if (all_aligned) {
        printf("  All 100 allocations: CACHE LINE ALIGNED\n");
    } else {
        printf("  Some allocations misaligned - check allocator!\n");
    }
    printf("\n");
    
    // Test 3: Check member offsets within struct
    printf("Member Offset Analysis:\n");
    printf("  offsetof(header):     %zu\n", offsetof(PreprocessedQ4Block, header));
    printf("  offsetof(scale):      %zu\n", offsetof(PreprocessedQ4Block, scale));
    printf("  offsetof(weights):    %zu\n", offsetof(PreprocessedQ4Block, weights));
    printf("\n");
    
    // Verify weights start at cache line boundary
    size_t weights_offset = offsetof(PreprocessedQ4Block, weights);
    bool weights_aligned = (weights_offset % CACHE_LINE_SIZE) == 0;
    printf("  Weights array cache-aligned: %s\n", weights_aligned ? "PASS" : "INFO");
    printf("\n");
    
    // Test 4: Performance comparison - aligned vs unaligned
    printf("Performance Impact Test:\n");
    
    const int num_blocks = 10000;
    const int num_iterations = 100000;
    
    // Allocate aligned blocks
    std::vector<PreprocessedQ4Block*> aligned_blocks;
    aligned_blocks.reserve(num_blocks);
    for (int i = 0; i < num_blocks; i++) {
        void* mem = nullptr;
        #ifdef _WIN32
        mem = _aligned_malloc(sizeof(PreprocessedQ4Block), CACHE_LINE_SIZE);
        #else
        posix_memalign(&mem, CACHE_LINE_SIZE, sizeof(PreprocessedQ4Block));
        #endif
        aligned_blocks.push_back(new(mem) PreprocessedQ4Block);
    }
    
    // Allocate unaligned blocks (force misalignment)
    std::vector<uint8_t*> unaligned_mem;
    std::vector<PreprocessedQ4Block*> unaligned_blocks;
    unaligned_mem.reserve(num_blocks);
    unaligned_blocks.reserve(num_blocks);
    for (int i = 0; i < num_blocks; i++) {
        uint8_t* mem = new uint8_t[sizeof(PreprocessedQ4Block) + 32];
        unaligned_mem.push_back(mem);
        // Force 32-byte offset (half cache line)
        PreprocessedQ4Block* block = reinterpret_cast<PreprocessedQ4Block*>(mem + 32);
        new(block) PreprocessedQ4Block;
        unaligned_blocks.push_back(block);
    }
    
    // Initialize blocks with test data
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    
    for (auto* block : aligned_blocks) {
        block->scale = dist(rng);
        for (int i = 0; i < 64; i++) {
            block->weights[i] = static_cast<int8_t>(dist(rng) * 8);
        }
    }
    
    for (auto* block : unaligned_blocks) {
        block->scale = dist(rng);
        for (int i = 0; i < 64; i++) {
            block->weights[i] = static_cast<int8_t>(dist(rng) * 8);
        }
    }
    
    // Benchmark aligned access
    volatile float sum_aligned = 0.0f;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int iter = 0; iter < num_iterations; iter++) {
        for (int i = 0; i < num_blocks; i++) {
            auto* block = aligned_blocks[i];
            sum_aligned += block->scale * block->weights[iter % 64];
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto aligned_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    // Benchmark unaligned access
    volatile float sum_unaligned = 0.0f;
    start = std::chrono::high_resolution_clock::now();
    
    for (int iter = 0; iter < num_iterations; iter++) {
        for (int i = 0; i < num_blocks; i++) {
            auto* block = unaligned_blocks[i];
            sum_unaligned += block->scale * block->weights[iter % 64];
        }
    }
    
    end = std::chrono::high_resolution_clock::now();
    auto unaligned_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    printf("  Aligned access:   %.2f ms\n", aligned_us / 1000.0);
    printf("  Unaligned access: %.2f ms\n", unaligned_us / 1000.0);
    printf("  Performance delta: %.2f%%\n", 
           100.0 * (unaligned_us - aligned_us) / aligned_us);
    printf("\n");
    
    // Cleanup
    for (auto* block : aligned_blocks) {
        block->~PreprocessedQ4Block();
        #ifdef _WIN32
        _aligned_free(block);
        #else
        free(block);
        #endif
    }
    
    for (auto* mem : unaligned_mem) {
        delete[] mem;
    }
    
    // Summary
    printf("=============================================================================\n");
    printf("CACHE ALIGNMENT SUMMARY\n");
    printf("=============================================================================\n");
    printf("  Struct size multiple of cache line: %s\n", size_ok ? "PASS" : "FAIL");
    printf("  Allocations cache-aligned: %s\n", all_aligned ? "PASS" : "FAIL");
    printf("  Weights array cache-aligned: %s\n", weights_aligned ? "PASS" : "INFO");
    printf("\n");
    
    bool passed = size_ok && all_aligned;
    if (passed) {
        printf("STATUS: PASS\n");
        printf("PreprocessedQ4Block is properly cache-aligned.\n");
    } else {
        printf("STATUS: FAIL\n");
        printf("Cache alignment issues detected.\n");
    }
    printf("=============================================================================\n");
    
    return passed;
}

// Test prefetch effectiveness
bool test_prefetch_effectiveness() {
    printf("\n");
    printf("=============================================================================\n");
    printf("PREFETCH EFFECTIVENESS TEST\n");
    printf("=============================================================================\n\n");
    
    const int num_blocks = 1000;
    const int num_iterations = 10000;
    
    // Allocate blocks
    std::vector<PreprocessedQ4Block*> blocks;
    blocks.reserve(num_blocks);
    for (int i = 0; i < num_blocks; i++) {
        void* mem = nullptr;
        #ifdef _WIN32
        mem = _aligned_malloc(sizeof(PreprocessedQ4Block), CACHE_LINE_SIZE);
        #else
        posix_memalign(&mem, CACHE_LINE_SIZE, sizeof(PreprocessedQ4Block));
        #endif
        blocks.push_back(new(mem) PreprocessedQ4Block);
    }
    
    // Initialize
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    for (auto* block : blocks) {
        block->scale = dist(rng);
        for (int j = 0; j < 64; j++) {
            block->weights[j] = static_cast<int8_t>(dist(rng) * 8);
        }
    }
    
    // Benchmark without prefetch
    volatile float sum_no_prefetch = 0.0f;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int iter = 0; iter < num_iterations; iter++) {
        for (int i = 0; i < num_blocks; i++) {
            auto* block = blocks[i];
            // Simulate dot product without prefetch
            for (int j = 0; j < 64; j++) {
                sum_no_prefetch += block->scale * block->weights[j];
            }
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto no_prefetch_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    // Benchmark with software prefetch
    volatile float sum_with_prefetch = 0.0f;
    start = std::chrono::high_resolution_clock::now();
    
    for (int iter = 0; iter < num_iterations; iter++) {
        for (int i = 0; i < num_blocks; i++) {
            // Prefetch next block
            if (i + 1 < num_blocks) {
                #ifdef _WIN32
                _mm_prefetch(reinterpret_cast<const char*>(blocks[i + 1]), _MM_HINT_T0);
                #else
                __builtin_prefetch(blocks[i + 1], 0, 3);
                #endif
            }
            
            auto* block = blocks[i];
            for (int j = 0; j < 64; j++) {
                sum_with_prefetch += block->scale * block->weights[j];
            }
        }
    }
    
    end = std::chrono::high_resolution_clock::now();
    auto with_prefetch_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    printf("Performance Comparison:\n");
    printf("  Without prefetch: %.2f ms\n", no_prefetch_us / 1000.0);
    printf("  With prefetch:    %.2f ms\n", with_prefetch_us / 1000.0);
    printf("  Improvement:      %.2f%%\n",
           100.0 * (no_prefetch_us - with_prefetch_us) / no_prefetch_us);
    printf("\n");
    
    // Cleanup
    for (auto* block : blocks) {
        block->~PreprocessedQ4Block();
        #ifdef _WIN32
        _aligned_free(block);
        #else
        free(block);
        #endif
    }
    
    printf("STATUS: INFO\n");
    printf("Prefetch effectiveness measured.\n");
    printf("=============================================================================\n");
    
    return true;
}

int main(int argc, char** argv) {
    printf("\n");
    printf("RawrXD Q4_0 Cache Alignment Test\n");
    printf("Validates: Memory layout and cache line alignment\n");
    printf("\n");
    
    bool passed = true;
    
    // Run alignment tests
    passed &= test_block_alignment();
    
    // Run prefetch test
    passed &= test_prefetch_effectiveness();
    
    printf("\n");
    printf("Final Status: %s\n", passed ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    printf("\n");
    
    return passed ? 0 : 1;
}
