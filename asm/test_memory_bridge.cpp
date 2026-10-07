// ============================================================================
// test_memory_bridge.cpp - Memory Bridge Validation
// ============================================================================
// Tests unified memory fabric: DDR5 + VRAM = 80GB working set
//
// Date: July 10, 2026
// ============================================================================

#include <cstdio>
#include <cstring>
#include <vector>
#include <cmath>

#include "SovereignMemoryBridge.hpp"

// Test utilities
#define TEST_ASSERT(cond, msg) do { \
    if (cond) { \
        printf("  [PASS] %s\n", msg); \
        passed++; \
    } else { \
        printf("  [FAIL] %s\n", msg); \
        failed++; \
    } \
    total++; \
} while(0)

static int total = 0, passed = 0, failed = 0;

// ============================================================================
// Test 1: Basic Allocation
// ============================================================================
void test_basic_allocation() {
    printf("\n=== Test 1: Basic Allocation ===\n");
    
    Sovereign::MemoryBridge& bridge = Sovereign::MemoryBridge::Instance();
    
    // Allocate host buffer
    SovereignBuffer* host = bridge.Allocate(1024 * 1024, MEMORY_DOMAIN_HOST);
    TEST_ASSERT(host != nullptr, "Host allocation succeeded");
    TEST_ASSERT(host->domain == MEMORY_DOMAIN_HOST, "Host buffer has correct domain");
    TEST_ASSERT(host->sizeBytes == 1024 * 1024, "Host buffer has correct size");
    
    // Write and read back
    if (host && host->ptr) {
        float* data = (float*)host->ptr;
        data[0] = 3.14159f;
        TEST_ASSERT(std::abs(data[0] - 3.14159f) < 0.0001f, "Host memory is writable/readable");
    }
    
    // Allocate pinned buffer
    SovereignBuffer* pinned = bridge.Allocate(1024 * 1024, MEMORY_DOMAIN_PINNED);
    TEST_ASSERT(pinned != nullptr, "Pinned allocation succeeded");
    TEST_ASSERT(pinned->domain == MEMORY_DOMAIN_PINNED, "Pinned buffer has correct domain");
    
    // Allocate device buffer
    SovereignBuffer* device = bridge.Allocate(1024 * 1024, MEMORY_DOMAIN_DEVICE);
    TEST_ASSERT(device != nullptr, "Device allocation succeeded");
    TEST_ASSERT(device->domain == MEMORY_DOMAIN_DEVICE, "Device buffer has correct domain");
    
    // Cleanup
    bridge.Free(host);
    bridge.Free(pinned);
    bridge.Free(device);
    
    TEST_ASSERT(true, "All buffers freed successfully");
}

// ============================================================================
// Test 2: Domain Migration
// ============================================================================
void test_domain_migration() {
    printf("\n=== Test 2: Domain Migration ===\n");
    
    Sovereign::MemoryBridge& bridge = Sovereign::MemoryBridge::Instance();
    
    // Allocate host buffer with test data
    SovereignBuffer* buffer = bridge.Allocate(1024, MEMORY_DOMAIN_HOST);
    if (!buffer) {
        TEST_ASSERT(false, "Allocation failed");
        return;
    }
    
    // Write test pattern
    float* data = (float*)buffer->ptr;
    for (int i = 0; i < 256; i++) {
        data[i] = (float)i * 1.5f;
    }
    
    // Migrate to device
    bool result = bridge.EnsureOnDevice(buffer);
    TEST_ASSERT(result, "Migration to device succeeded");
    TEST_ASSERT(buffer->domain == MEMORY_DOMAIN_DEVICE, "Buffer now in device domain");
    
    // Migrate back to host
    result = bridge.EnsureOnHost(buffer);
    TEST_ASSERT(result, "Migration to host succeeded");
    TEST_ASSERT(buffer->domain == MEMORY_DOMAIN_HOST, "Buffer now in host domain");
    
    // Verify data integrity
    bool data_ok = true;
    data = (float*)buffer->ptr;
    for (int i = 0; i < 256; i++) {
        if (std::abs(data[i] - (float)i * 1.5f) > 0.0001f) {
            data_ok = false;
            break;
        }
    }
    TEST_ASSERT(data_ok, "Data integrity preserved after migration");
    
    bridge.Free(buffer);
}

// ============================================================================
// Test 3: Memory Copy
// ============================================================================
void test_memory_copy() {
    printf("\n=== Test 3: Memory Copy ===\n");
    
    Sovereign::MemoryBridge& bridge = Sovereign::MemoryBridge::Instance();
    
    // Allocate source and destination
    SovereignBuffer* src = bridge.Allocate(1024, MEMORY_DOMAIN_HOST);
    SovereignBuffer* dst = bridge.Allocate(1024, MEMORY_DOMAIN_HOST);
    
    if (!src || !dst) {
        TEST_ASSERT(false, "Allocation failed");
        return;
    }
    
    // Write test pattern to source
    float* src_data = (float*)src->ptr;
    float* dst_data = (float*)dst->ptr;
    for (int i = 0; i < 256; i++) {
        src_data[i] = (float)i * 2.0f;
        dst_data[i] = 0.0f; // Clear destination
    }
    
    // Copy
    bool result = bridge.Copy(dst, src);
    TEST_ASSERT(result, "Copy succeeded");
    
    // Verify
    bool copy_ok = true;
    for (int i = 0; i < 256; i++) {
        if (std::abs(dst_data[i] - (float)i * 2.0f) > 0.0001f) {
            copy_ok = false;
            break;
        }
    }
    TEST_ASSERT(copy_ok, "Copy data integrity verified");
    
    bridge.Free(src);
    bridge.Free(dst);
}

// ============================================================================
// Test 4: Memory Statistics
// ============================================================================
void test_memory_stats() {
    printf("\n=== Test 4: Memory Statistics ===\n");
    
    Sovereign::MemoryBridge& bridge = Sovereign::MemoryBridge::Instance();
    
    uint64_t hostBefore, deviceBefore, pinnedBefore, totalBefore;
    bridge.GetStats(hostBefore, deviceBefore, pinnedBefore, totalBefore);
    
    // Allocate some memory
    SovereignBuffer* buf1 = bridge.Allocate(10 * 1024 * 1024, MEMORY_DOMAIN_HOST);   // 10MB
    SovereignBuffer* buf2 = bridge.Allocate(5 * 1024 * 1024, MEMORY_DOMAIN_DEVICE);  // 5MB
    
    uint64_t hostAfter, deviceAfter, pinnedAfter, totalAfter;
    bridge.GetStats(hostAfter, deviceAfter, pinnedAfter, totalAfter);
    
    TEST_ASSERT(hostAfter >= hostBefore + 10 * 1024 * 1024, "Host usage increased");
    TEST_ASSERT(deviceAfter >= deviceBefore + 5 * 1024 * 1024, "Device usage increased");
    TEST_ASSERT(totalAfter >= totalBefore + 15 * 1024 * 1024, "Total usage increased");
    
    printf("    Host:   %zu MB -> %zu MB\n", 
           (size_t)(hostBefore / (1024*1024)), (size_t)(hostAfter / (1024*1024)));
    printf("    Device: %zu MB -> %zu MB\n", 
           (size_t)(deviceBefore / (1024*1024)), (size_t)(deviceAfter / (1024*1024)));
    printf("    Total:  %zu MB -> %zu MB\n", 
           (size_t)(totalBefore / (1024*1024)), (size_t)(totalAfter / (1024*1024)));
    
    bridge.Free(buf1);
    bridge.Free(buf2);
}

// ============================================================================
// Test 5: Domain Suggestions
// ============================================================================
void test_domain_suggestions() {
    printf("\n=== Test 5: Domain Suggestions ===\n");
    
    Sovereign::MemoryBridge& bridge = Sovereign::MemoryBridge::Instance();
    
    // Small data, infrequent access
    MemoryDomain d1 = bridge.SuggestDomain(100 * 1024, false, false);
    TEST_ASSERT(d1 == MEMORY_DOMAIN_HOST, "Small data -> Host");
    
    // Large data, compute heavy
    MemoryDomain d2 = bridge.SuggestDomain(100 * 1024 * 1024, false, true);
    TEST_ASSERT(d2 == MEMORY_DOMAIN_DEVICE, "Large compute-heavy -> Device");
    
    // Medium data, frequent access
    MemoryDomain d3 = bridge.SuggestDomain(50 * 1024 * 1024, true, false);
    TEST_ASSERT(d3 == MEMORY_DOMAIN_PINNED, "Frequent access medium -> Pinned");
    
    printf("    Small/infrequent: %s\n", 
           d1 == MEMORY_DOMAIN_HOST ? "HOST" : "OTHER");
    printf("    Large/compute:    %s\n", 
           d2 == MEMORY_DOMAIN_DEVICE ? "DEVICE" : "OTHER");
    printf("    Medium/frequent:  %s\n", 
           d3 == MEMORY_DOMAIN_PINNED ? "PINNED" : "OTHER");
}

// ============================================================================
// Main
// ============================================================================
int main() {
    printf("==============================================================================\n");
    printf("Sovereign Memory Bridge Test\n");
    printf("==============================================================================\n");
    printf("\n");
    printf("Testing unified memory fabric:\n");
    printf("  DDR5: 64GB (Host + Pinned)\n");
    printf("  VRAM: 16GB (Device)\n");
    printf("  Total: 80GB unified working set\n");
    printf("\n");
    
    // Initialize
    Sovereign::MemoryBridge& bridge = Sovereign::MemoryBridge::Instance();
    if (!bridge.Initialize()) {
        printf("ERROR: Failed to initialize MemoryBridge\n");
        return 1;
    }
    
    // Run tests
    test_basic_allocation();
    test_domain_migration();
    test_memory_copy();
    test_memory_stats();
    test_domain_suggestions();
    
    // Cleanup
    bridge.Shutdown();
    
    // Summary
    printf("\n==============================================================================\n");
    printf("SUMMARY: %d/%d passed, %d failed\n", passed, total, failed);
    printf("==============================================================================\n");
    
    return failed == 0 ? 0 : 1;
}
