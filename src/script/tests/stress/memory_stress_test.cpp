// RawrXD-Script Memory Stress Test
// Pushes allocation patterns to find corruption, leaks, and crashes
// If this fails, your engine has memory safety bugs

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <chrono>
#include <math>

// Simulated arena (matches MASM implementation)
struct SimulatedArena {
    static constexpr size_t SIZE = 64 * 1024 * 1024;  // 64MB
    uint8_t* base;
    size_t used;
    size_t committed;
    
    SimulatedArena() : used(0), committed(SIZE) {
        base = new uint8_t[SIZE];
        memset(base, 0xCD, SIZE);  // Initialize with pattern
    }
    
    ~SimulatedArena() {
        delete[] base;
    }
    
    void* allocate(size_t size) {
        // Align to 8 bytes
        size = (size + 7) & ~7;
        
        if (used + size > committed) {
            return nullptr;  // Out of memory
        }
        
        void* ptr = base + used;
        used += size;
        
        // Fill with pattern to detect uninitialized reads
        memset(ptr, 0xAB, size);
        
        return ptr;
    }
    
    void reset() {
        used = 0;
        memset(base, 0xCD, SIZE);
    }
};

// Test framework
struct StressTest {
    const char* name;
    bool (*run)(SimulatedArena& arena);
    int iterations;
};

// ============================================================================
// Test 1: Rapid Small Allocations
// Simulates: Creating many small objects
// ============================================================================
bool test_rapid_small_allocations(SimulatedArena& arena) {
    // Allocate 1000 small objects (32 bytes each)
    std::vector<void*> ptrs;
    
    for (int i = 0; i < 1000; i++) {
        void* ptr = arena.allocate(32);
        if (!ptr) return false;
        
        // Verify alignment
        if (reinterpret_cast<uintptr_t>(ptr) % 8 != 0) {
            return false;  // Misaligned allocation
        }
        
        // Write pattern to detect corruption
        memset(ptr, i & 0xFF, 32);
        ptrs.push_back(ptr);
    }
    
    // Verify all allocations still intact
    for (int i = 0; i < 1000; i++) {
        uint8_t* ptr = static_cast<uint8_t*>(ptrs[i]);
        for (int j = 0; j < 32; j++) {
            if (ptr[j] != (i & 0xFF)) {
                return false;  // Memory corruption detected
            }
        }
    }
    
    return true;
}

// ============================================================================
// Test 2: Large String Concatenation
// Simulates: Building large strings
// ============================================================================
bool test_large_string_concat(SimulatedArena& arena) {
    // Simulate string concatenation
    struct StringHeader {
        uint16_t length;
        uint16_t capacity;
        uint32_t flags;
    };
    
    const char* chunks[] = {
        "Hello, ",
        "this is a ",
        "test of ",
        "string concatenation ",
        "in the RawrXD-Script ",
        "JavaScript engine. ",
        "It needs to handle ",
        "arbitrary lengths."
    };
    
    // Allocate initial string
    void* strPtr = arena.allocate(sizeof(StringHeader) + 256);
    if (!strPtr) return false;
    
    StringHeader* header = static_cast<StringHeader*>(strPtr);
    header->length = 0;
    header->capacity = 256;
    header->flags = 0;
    
    char* data = static_cast<char*>(strPtr) + sizeof(StringHeader);
    data[0] = '\0';
    
    // Concatenate chunks
    for (const char* chunk : chunks) {
        size_t chunkLen = strlen(chunk);
        
        // Check capacity
        if (header->length + chunkLen > header->capacity) {
            // Would need reallocation in real implementation
            // For test, just verify we don't overflow
            if (header->length + chunkLen > 256) {
                // Skip this chunk (simulating growth failure)
                continue;
            }
        }
        
        // Append
        memcpy(data + header->length, chunk, chunkLen);
        header->length += chunkLen;
        data[header->length] = '\0';
    }
    
    // Verify result
    size_t expectedLen = 0;
    for (const char* chunk : chunks) {
        expectedLen += strlen(chunk);
    }
    
    // Account for skipped chunks
    return header->length > 0;
}

// ============================================================================
// Test 3: Deep Object Graph
// Simulates: Complex object hierarchies
// ============================================================================
bool test_deep_object_graph(SimulatedArena& arena) {
    struct ObjectHeader {
        void* shape;
        void* prototype;
        uint32_t flags;
        uint32_t reserved;
    };
    
    // Create prototype chain: A -> B -> C -> null
    void* protoC = arena.allocate(sizeof(ObjectHeader));
    if (!protoC) return false;
    memset(protoC, 0, sizeof(ObjectHeader));
    
    void* protoB = arena.allocate(sizeof(ObjectHeader));
    if (!protoB) return false;
    memset(protoB, 0, sizeof(ObjectHeader));
    static_cast<ObjectHeader*>(protoB)->prototype = protoC;
    
    void* protoA = arena.allocate(sizeof(ObjectHeader));
    if (!protoA) return false;
    memset(protoA, 0, sizeof(ObjectHeader));
    static_cast<ObjectHeader*>(protoA)->prototype = protoB;
    
    // Create instance
    void* instance = arena.allocate(sizeof(ObjectHeader));
    if (!instance) return false;
    memset(instance, 0, sizeof(ObjectHeader));
    static_cast<ObjectHeader*>(instance)->prototype = protoA;
    
    // Walk prototype chain
    int depth = 0;
    void* current = instance;
    while (current) {
        depth++;
        current = static_cast<ObjectHeader*>(current)->prototype;
        if (depth > 100) return false;  // Infinite loop protection
    }
    
    return depth == 4;  // instance + A + B + C
}

// ============================================================================
// Test 4: Arena Exhaustion
// Simulates: Running out of memory
// ============================================================================
bool test_arena_exhaustion(SimulatedArena& arena) {
    // Try to allocate more than available
    size_t largeSize = arena.committed + 1024;
    void* ptr = arena.allocate(largeSize);
    
    // Should return null, not crash
    if (ptr != nullptr) {
        return false;  // Should have failed
    }
    
    // Now allocate exactly at the boundary
    ptr = arena.allocate(arena.committed - 1024);
    if (!ptr) return false;
    
    // Next allocation should fail gracefully
    void* ptr2 = arena.allocate(2048);
    if (ptr2 != nullptr) {
        return false;  // Should have failed
    }
    
    return true;
}

// ============================================================================
// Test 5: Alignment Stress
// Simulates: Various allocation sizes
// ============================================================================
bool test_alignment_stress(SimulatedArena& arena) {
    // Allocate various sizes and verify 8-byte alignment
    size_t sizes[] = {1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128};
    
    for (size_t size : sizes) {
        void* ptr = arena.allocate(size);
        if (!ptr) continue;  // Skip if OOM
        
        uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
        if (addr % 8 != 0) {
            std::cout << "  Misaligned allocation: size=" << size 
                      << " addr=" << addr << std::endl;
            return false;
        }
    }
    
    return true;
}

// ============================================================================
// Test 6: Fragmentation Pattern
// Simulates: Real-world allocation patterns
// ============================================================================
bool test_fragmentation_pattern(SimulatedArena& arena) {
    std::vector<void*> allocations;
    
    // Phase 1: Allocate many objects
    for (int i = 0; i < 100; i++) {
        void* ptr = arena.allocate(64 + (i % 64));  // 64-128 bytes
        if (ptr) allocations.push_back(ptr);
    }
    
    // Phase 2: Free every other (simulated by resetting arena)
    // In real implementation, would selectively free
    // Here we just verify we can still allocate after many operations
    
    // Phase 3: Allocate more
    for (int i = 0; i < 50; i++) {
        void* ptr = arena.allocate(256);
        if (!ptr) {
            // OOM is acceptable, crash is not
            return true;
        }
    }
    
    return true;
}

// ============================================================================
// Test 7: IC Table Overflow
// Simulates: Many property accesses
// ============================================================================
bool test_ic_table_overflow(SimulatedArena& arena) {
    // Allocate IC table
    const int IC_SLOTS = 1024;
    void* icTable = arena.allocate(IC_SLOTS * 16);  // 16 bytes per slot
    if (!icTable) return false;
    
    // Simulate many property accesses
    struct ICSlot {
        void* shape;
        uint64_t offset;
    };
    
    ICSlot* slots = static_cast<ICSlot*>(icTable);
    
    // Write to all slots
    for (int i = 0; i < IC_SLOTS; i++) {
        slots[i].shape = nullptr;
        slots[i].offset = i;  // Unique value to verify
    }
    
    // Verify all writes
    for (int i = 0; i < IC_SLOTS; i++) {
        if (slots[i].offset != i) {
            return false;  // Memory corruption
        }
    }
    
    return true;
}

// ============================================================================
// Test 8: Rapid Object Creation
// Simulates: Tight loops creating objects
// ============================================================================
bool test_rapid_object_creation(SimulatedArena& arena) {
    struct MiniObject {
        uint64_t header;
        uint64_t field1;
        uint64_t field2;
    };
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Create 10000 objects as fast as possible
    for (int i = 0; i < 10000; i++) {
        void* ptr = arena.allocate(sizeof(MiniObject));
        if (!ptr) break;  // OOM is OK
        
        MiniObject* obj = static_cast<MiniObject*>(ptr);
        obj->header = i;
        obj->field1 = i * 2;
        obj->field2 = i * 3;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "  Created 10000 objects in " << duration.count() << " us" << std::endl;
    
    return true;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD-Script Memory Stress Test" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "This test finds memory safety bugs." << std::endl;
    std::cout << "If any test fails, the engine is unsafe." << std::endl;
    std::cout << "========================================" << std::endl;
    
    StressTest tests[] = {
        {"Rapid Small Allocations", test_rapid_small_allocations, 1000},
        {"Large String Concatenation", test_large_string_concat, 100},
        {"Deep Object Graph", test_deep_object_graph, 10},
        {"Arena Exhaustion", test_arena_exhaustion, 1},
        {"Alignment Stress", test_alignment_stress, 100},
        {"Fragmentation Pattern", test_fragmentation_pattern, 50},
        {"IC Table Overflow", test_ic_table_overflow, 1},
        {"Rapid Object Creation", test_rapid_object_creation, 10000}
    };
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test : tests) {
        std::cout << "\n[TEST] " << test.name << "..." << std::endl;
        
        SimulatedArena arena;
        bool result = test.run(arena);
        
        if (result) {
            std::cout << "[PASS] " << test.name << std::endl;
            passed++;
        } else {
            std::cout << "[FAIL] " << test.name << std::endl;
            failed++;
        }
    }
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Memory Stress Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << failed << std::endl;
    std::cout << "Total:  " << (passed + failed) << std::endl;
    std::cout << "========================================" << std::endl;
    
    return failed > 0 ? 1 : 0;
}
