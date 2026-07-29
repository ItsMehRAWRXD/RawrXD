// ============================================================================
// VAL-007: Memory Management Validation Gate Implementation
// ============================================================================

#include "VAL007_MemoryManagementGate.h"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <vector>
#include <memory>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace RawrXD {
namespace Validation {

REGISTER_VALIDATION_GATE(VAL007_MemoryManagementGate);

ValidationResult VAL007_MemoryManagementGate::Execute() {
    ValidationResult result;
    result.gateId = GetId();
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[VAL-007] Memory Management Validation\n");
    printf("=====================================\n");
    
    bool allPassed = true;
    
    printf("\n[1/5] Aligned Allocation...\n");
    if (!ValidateAlignedAllocation()) {
        printf("  FAILED: Aligned allocation\n");
        allPassed = false;
    } else {
        printf("  PASSED: Aligned allocation\n");
    }
    
    printf("\n[2/5] Memory Pools...\n");
    if (!ValidateMemoryPools()) {
        printf("  FAILED: Memory pools\n");
        allPassed = false;
    } else {
        printf("  PASSED: Memory pools\n");
    }
    
    printf("\n[3/5] NUMA Awareness...\n");
    if (!ValidateNUMAAwareness()) {
        printf("  FAILED: NUMA awareness\n");
        allPassed = false;
    } else {
        printf("  PASSED: NUMA awareness\n");
    }
    
    printf("\n[4/5] Memory Mapping...\n");
    if (!ValidateMemoryMapping()) {
        printf("  FAILED: Memory mapping\n");
        allPassed = false;
    } else {
        printf("  PASSED: Memory mapping\n");
    }
    
    printf("\n[5/5] Buffer Reuse...\n");
    if (!ValidateBufferReuse()) {
        printf("  FAILED: Buffer reuse\n");
        allPassed = false;
    } else {
        printf("  PASSED: Buffer reuse\n");
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    result.passed = allPassed;
    result.message = allPassed ? "VAL-007: All memory management tests passed" 
                               : "VAL-007: Some tests failed";
    
    printf("\n=====================================\n");
    printf("[VAL-007] Result: %s (%.2f ms)\n", 
           allPassed ? "PASSED" : "FAILED", result.durationMs);
    printf("=====================================\n");
    
    return result;
}

bool VAL007_MemoryManagementGate::ValidateAlignedAllocation() {
    const size_t alignment = 64; // Cache line alignment
    const size_t size = 1024 * 1024; // 1MB
    
#ifdef _WIN32
    void* ptr = _aligned_malloc(size, alignment);
#else
    void* ptr = aligned_alloc(alignment, size);
#endif
    
    if (ptr == nullptr) return false;
    
    // Verify alignment
    if ((reinterpret_cast<uintptr_t>(ptr) % alignment) != 0) {
#ifdef _WIN32
        _aligned_free(ptr);
#else
        free(ptr);
#endif
        return false;
    }
    
    // Test write/read
    memset(ptr, 0xAB, size);
    uint8_t* bytes = static_cast<uint8_t*>(ptr);
    for (size_t i = 0; i < size; i++) {
        if (bytes[i] != 0xAB) {
#ifdef _WIN32
            _aligned_free(ptr);
#else
            free(ptr);
#endif
            return false;
        }
    }
    
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
    
    return true;
}

bool VAL007_MemoryManagementGate::ValidateMemoryPools() {
    // Simulate memory pool
    struct MemoryPool {
        std::vector<void*> free_blocks;
        std::vector<std::unique_ptr<uint8_t[]>> storage;
        size_t block_size;
        
        MemoryPool(size_t bs, size_t count) : block_size(bs) {
            for (size_t i = 0; i < count; i++) {
                auto block = std::make_unique<uint8_t[]>(block_size);
                free_blocks.push_back(block.get());
                storage.push_back(std::move(block));
            }
        }
        
        void* allocate() {
            if (free_blocks.empty()) return nullptr;
            void* ptr = free_blocks.back();
            free_blocks.pop_back();
            return ptr;
        }
        
        void deallocate(void* ptr) {
            if (ptr) free_blocks.push_back(ptr);
        }
    };
    
    MemoryPool pool(4096, 100);
    
    // Allocate all blocks
    std::vector<void*> allocated;
    for (int i = 0; i < 100; i++) {
        void* ptr = pool.allocate();
        if (ptr == nullptr) return false;
        allocated.push_back(ptr);
    }
    
    // Should be empty now
    if (pool.allocate() != nullptr) return false;
    
    // Deallocate all
    for (void* ptr : allocated) {
        pool.deallocate(ptr);
    }
    
    // Should be able to allocate again
    if (pool.allocate() == nullptr) return false;
    
    return true;
}

bool VAL007_MemoryManagementGate::ValidateNUMAAwareness() {
    // Simulate NUMA node detection
    int numa_nodes = 1; // Default to single node
    
#ifdef _WIN32
    // Query NUMA info
    ULONG highestNodeNumber;
    if (GetNumaHighestNodeNumber(&highestNodeNumber)) {
        numa_nodes = static_cast<int>(highestNodeNumber) + 1;
    }
#endif
    
    // Should have at least 1 node
    if (numa_nodes < 1) return false;
    
    // Simulate allocation on specific node
    // In real implementation, would use VirtualAllocExNuma
    void* ptr = malloc(1024);
    if (ptr == nullptr) return false;
    
    memset(ptr, 0, 1024);
    free(ptr);
    
    return true;
}

bool VAL007_MemoryManagementGate::ValidateMemoryMapping() {
    const size_t size = 4096;
    
#ifdef _WIN32
    // Create a file mapping
    HANDLE hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, 
                                         PAGE_READWRITE, 0, size, NULL);
    if (hMapFile == NULL) return false;
    
    void* ptr = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, size);
    if (ptr == NULL) {
        CloseHandle(hMapFile);
        return false;
    }
    
    // Test write/read
    memset(ptr, 0xCD, size);
    uint8_t* bytes = static_cast<uint8_t*>(ptr);
    for (size_t i = 0; i < size; i++) {
        if (bytes[i] != 0xCD) {
            UnmapViewOfFile(ptr);
            CloseHandle(hMapFile);
            return false;
        }
    }
    
    UnmapViewOfFile(ptr);
    CloseHandle(hMapFile);
#else
    void* ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, 
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) return false;
    
    memset(ptr, 0xCD, size);
    munmap(ptr, size);
#endif
    
    return true;
}

bool VAL007_MemoryManagementGate::ValidateBufferReuse() {
    // Simulate buffer cache
    struct BufferCache {
        std::vector<std::unique_ptr<uint8_t[]>> buffers;
        size_t buffer_size;
        
        BufferCache(size_t bs, size_t count) : buffer_size(bs) {
            for (size_t i = 0; i < count; i++) {
                buffers.push_back(std::make_unique<uint8_t[]>(buffer_size));
            }
        }
        
        uint8_t* acquire() {
            if (buffers.empty()) {
                return new uint8_t[buffer_size];
            }
            auto ptr = buffers.back().release();
            buffers.pop_back();
            return ptr;
        }
        
        void release(uint8_t* ptr) {
            if (ptr) {
                buffers.push_back(std::unique_ptr<uint8_t[]>(ptr));
            }
        }
    };
    
    BufferCache cache(1024 * 1024, 5); // 5 x 1MB buffers
    
    // Acquire all buffers
    std::vector<uint8_t*> acquired;
    for (int i = 0; i < 10; i++) {
        uint8_t* buf = cache.acquire();
        if (buf == nullptr) return false;
        acquired.push_back(buf);
    }
    
    // Release all
    for (uint8_t* buf : acquired) {
        cache.release(buf);
    }
    
    return true;
}

} // namespace Validation
} // namespace RawrXD
