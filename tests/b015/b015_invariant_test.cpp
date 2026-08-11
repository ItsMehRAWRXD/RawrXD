// ============================================================================
// B015 Gate 1 + TouchWeight Invariant Test
// ============================================================================
// Verifies:
//   1. DRP_TouchWeight does NOT change ResidencyState (Tier).
//   2. Referenced-bit second-chance eviction works correctly.
//   3. BlockIndex fast path vs fallback produce identical results.
//
// Build:
//   cl /O2 /W4 /EHsc /Fe:b015_invariant_test.exe b015_invariant_test.cpp
//     d:\src\asm\ResidencyBackends.obj
// ============================================================================

#include "../../src/runtime/memory/ResidencyBackends.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <chrono>

using namespace rawrxd;

struct TestResult {
    const char* name;
    bool passed;
    const char* reason;
};

static std::vector<TestResult> g_results;

static void Check(bool condition, const char* name, const char* failReason) {
    g_results.push_back({name, condition, condition ? "" : failReason});
    printf("  %s: %s\n", name, condition ? "PASS" : failReason);
}

// ---------------------------------------------------------------------------
// Helper: allocate and init a pool with N blocks
// ---------------------------------------------------------------------------
static ResidencyPool* MakePool(uint32_t nBlocks, uint32_t blockSize) {
    size_t tableBytes = nBlocks * sizeof(DynamicBlock);
    size_t indexBytes = nBlocks * sizeof(uint64_t);

    DynamicBlock* table = (DynamicBlock*)VirtualAlloc(nullptr, tableBytes,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint64_t* index = (uint64_t*)VirtualAlloc(nullptr, indexBytes,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint8_t* ssdBase = (uint8_t*)VirtualAlloc(nullptr, (size_t)nBlocks * blockSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint8_t* ramBase = (uint8_t*)VirtualAlloc(nullptr, (size_t)nBlocks * blockSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!table || !index || !ssdBase || !ramBase) return nullptr;

    std::memset(table, 0, tableBytes);
    std::memset(index, 0, indexBytes);

    ResidencyPool* pool = (ResidencyPool*)VirtualAlloc(nullptr, sizeof(ResidencyPool),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pool) return nullptr;
    std::memset(pool, 0, sizeof(ResidencyPool));

    for (uint32_t i = 0; i < nBlocks; ++i) {
        table[i].BlockID = i;
        table[i].Tier    = TIER_SSD;   // start on SSD
        table[i].State   = BLOCK_STATE_CLEAN;
        table[i].DataPtr = (uint64_t)(ssdBase + (size_t)i * blockSize);
        index[i]         = (uint64_t)&table[i];
    }

    pool->SSD.BasePtr    = (uint64_t)ssdBase;
    pool->SSD.Capacity   = (uint64_t)nBlocks * blockSize;
    pool->SSD.Used       = (uint64_t)nBlocks * blockSize;
    pool->SSD.BlockSize  = blockSize;
    pool->SSD.MaxBlocks  = nBlocks;

    pool->RAM.BasePtr    = (uint64_t)ramBase;
    pool->RAM.Capacity   = (uint64_t)nBlocks * blockSize;
    pool->RAM.Used       = 0;
    pool->RAM.BlockSize  = blockSize;
    pool->RAM.MaxBlocks  = nBlocks;

    pool->BlockTable     = (uint64_t)table;
    pool->BlockIndex     = (uint64_t)index;
    pool->TotalBlocks    = nBlocks;
    pool->ClockHand      = 0;
    pool->GlobalLock      = 0;
    pool->CycleCounter    = 0;

    return pool;
}

// ---------------------------------------------------------------------------
// Test 1: TouchWeight invariant — Tier must not change
// ---------------------------------------------------------------------------
static void TestTouchInvariant(ResidencyPool* pool) {
    printf("\nTest 1: TouchWeight ResidencyState Invariant\n");

    uint32_t testId = 5;
    uint8_t tiersBefore[4] = { TIER_SSD, TIER_RAM, TIER_VRAM, TIER_SSD };
    uint8_t tiersAfter[4];

    for (int t = 0; t < 4; ++t) {
        // Set block to known tier
        DynamicBlock* blk = (DynamicBlock*)pool->BlockTable + testId;
        blk->Tier = tiersBefore[t];
        blk->Referenced = 0;
        blk->LastAccess = 0;

        uint8_t tierBefore = blk->Tier;
        uint64_t dataBefore = blk->DataPtr;
        uint8_t stateBefore = blk->State;

        // Touch
        DynamicBlock* ret = DRP_TouchWeight(pool, testId, 42);

        uint8_t tierAfter  = blk->Tier;
        uint64_t dataAfter = blk->DataPtr;
        uint8_t stateAfter = blk->State;

        Check(ret != nullptr, "touch_returns_block",
              "TouchWeight returned nullptr for existing block");
        Check(tierAfter == tierBefore, "touch_no_tier_change",
              "TouchWeight CHANGED Tier — invariant violated!");
        Check(dataAfter == dataBefore, "touch_no_data_ptr_change",
              "TouchWeight changed DataPtr — invariant violated!");
        Check(stateAfter == stateBefore, "touch_no_state_change",
              "TouchWeight changed State — invariant violated!");
        Check(blk->Referenced == 1, "touch_sets_referenced",
              "TouchWeight did not set Referenced bit");
        Check(blk->LastAccess == 42, "touch_sets_lastaccess",
              "TouchWeight did not set LastAccess");
    }
}

// ---------------------------------------------------------------------------
// Test 2: BlockIndex fast path vs fallback produce identical results
// ---------------------------------------------------------------------------
static void TestIndexFastPath(ResidencyPool* pool) {
    printf("\nTest 2: BlockIndex fast path parity\n");

    // With BlockIndex populated
    DynamicBlock* r1 = DRP_TouchWeight(pool, 3, 100);
    Check(r1 != nullptr, "index_fast_hit", "BlockIndex fast path returned nullptr");
    Check(r1->BlockID == 3, "index_fast_id", "BlockIndex returned wrong block");
    Check(r1->Referenced == 1, "index_fast_referenced", "BlockIndex fast path did not set Referenced");

    // With BlockIndex = nullptr (forces fallback)
    uint64_t savedIndex = pool->BlockIndex;
    pool->BlockIndex = 0;

    DynamicBlock* r2 = DRP_TouchWeight(pool, 3, 200);
    Check(r2 != nullptr, "fallback_hit", "Fallback linear scan returned nullptr");
    Check(r2->BlockID == 3, "fallback_id", "Fallback returned wrong block");
    Check(r2->Referenced == 1, "fallback_referenced", "Fallback did not set Referenced");
    Check(r2->LastAccess == 200, "fallback_lastaccess", "Fallback did not set LastAccess");

    // Restore
    pool->BlockIndex = savedIndex;
}

// ---------------------------------------------------------------------------
// Test 3: Referenced-bit second chance in eviction scan
// ---------------------------------------------------------------------------
static void TestReferencedSecondChance(ResidencyPool* pool) {
    printf("\nTest 3: Referenced-bit second chance\n");

    // Promote blocks 0..3 to RAM
    DynamicBlock* table = (DynamicBlock*)pool->BlockTable;
    for (int i = 0; i < 4; ++i) {
        table[i].Tier = TIER_RAM;
        table[i].State = BLOCK_STATE_CLEAN;
        table[i].DataPtr = pool->RAM.BasePtr + (size_t)i * pool->RAM.BlockSize;
    }
    pool->RAM.Used = 4 * pool->RAM.BlockSize;

    // Touch block 1 and 2
    DRP_TouchWeight(pool, 1, 10);
    DRP_TouchWeight(pool, 2, 10);

    // Set low threshold so age check would normally evict
    struct FakeBackend {
        uint64_t pad[8];
        uint64_t ThresholdCycles = 0;
        uint64_t PressureLimit   = 1;  // always under pressure
        uint64_t EvictedCount  = 0;
        uint64_t FlushedCount  = 0;
    };
    FakeBackend backend;
    std::memset(&backend, 0, sizeof(backend));
    backend.ThresholdCycles = 0;
    backend.PressureLimit   = 1;

    uint64_t evicted = DRP_RunEvictionScan(pool, &backend);

    // Blocks 1 and 2 got second chance (Referenced=1), so only 0 or 3 should evict
    Check(evicted <= 2, "second_chance_limits_eviction",
          "Evicted too many blocks despite Referenced bits");

    // Verify block 1 and 2 are still RAM (second chance preserved them)
    Check(table[1].Tier == TIER_RAM, "block1_second_chance",
          "Block 1 was evicted despite Referenced=1");
    Check(table[2].Tier == TIER_RAM, "block2_second_chance",
          "Block 2 was evicted despite Referenced=1");

    // Verify their Referenced bits were consumed (cleared)
    Check(table[1].Referenced == 0, "block1_ref_consumed",
          "Block 1 Referenced bit not consumed by eviction scan");
    Check(table[2].Referenced == 0, "block2_ref_consumed",
          "Block 2 Referenced bit not consumed by eviction scan");
}

// ---------------------------------------------------------------------------
// Test 4: Performance — TouchWeight must be sub-microsecond
// ---------------------------------------------------------------------------
static void TestTouchPerformance(ResidencyPool* pool) {
    printf("\nTest 4: TouchWeight performance\n");

    const int iterations = 100000;
    auto t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        DRP_TouchWeight(pool, i % pool->TotalBlocks, (uint64_t)i);
    }
    auto t1 = std::chrono::high_resolution_clock::now();

    double totalUs = std::chrono::duration<double, std::micro>(t1 - t0).count();
    double usPerOp = totalUs / iterations;

    printf("    %d touches: %.3f us total (%.4f us/op)\n", iterations, totalUs, usPerOp);
    Check(usPerOp < 1.0, "touch_sub_microsecond",
          "TouchWeight too slow for hot path (>= 1 us/op)");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    printf("=================================================================\n");
    printf("  B015 — TouchWeight Invariant + Eviction Gate Test\n");
    printf("=================================================================\n");

    ResidencyPool* pool = MakePool(256, 4096);
    if (!pool) {
        printf("FAIL: Could not allocate test pool\n");
        return 1;
    }

    TestTouchInvariant(pool);
    TestIndexFastPath(pool);
    TestReferencedSecondChance(pool);
    TestTouchPerformance(pool);

    // Summary
    printf("\n=================================================================\n");
    printf("  SUMMARY\n");
    printf("=================================================================\n\n");

    int passed = 0, failed = 0;
    for (const auto& r : g_results) {
        if (r.passed) ++passed;
        else {
            ++failed;
            printf("  FAIL: %s — %s\n", r.name, r.reason);
        }
    }

    printf("  Total: %d tests, %d passed, %d failed\n", passed + failed, passed, failed);
    printf("  OVERALL: %s\n", failed == 0 ? "PASS" : "FAIL");
    printf("=================================================================\n");

    return failed == 0 ? 0 : 1;
}
