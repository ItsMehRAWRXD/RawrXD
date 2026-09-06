// ============================================================================
// test_mars_controller.cpp - MARS Controller Smoke Test
// ============================================================================

#include "mars/MARSController.hpp"
#include "mars/VRAMManager.hpp"
#include "mars/TensorHotpatch.hpp"
#include "mars/DualGPUBackend.hpp"
#include <cstdio>
#include <cassert>
#if defined(_WIN32)
#include <process.h>
#endif

using namespace Deep2::MARS;

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("=== MARS Controller Smoke Test ===\n\n");

    // ------------------------------------------------------------------------
    // Test 1: VRAMManager initialization
    // ------------------------------------------------------------------------
    printf("[Test 1] VRAMManager initialization\n");
    {
        VRAMManager vm;
        bool ok = vm.Initialize(32ULL * 1024 * 1024 * 1024,  // 32 GB GPU0
                                16ULL * 1024 * 1024 * 1024); // 16 GB GPU1
        assert(ok);
        assert(vm.GetTotalVRAM(0) == 32ULL * 1024 * 1024 * 1024);
        assert(vm.GetTotalVRAM(1) == 16ULL * 1024 * 1024 * 1024);
        assert(vm.GetFreeVRAM(0) == 32ULL * 1024 * 1024 * 1024);
        assert(vm.GetFreeVRAM(1) == 16ULL * 1024 * 1024 * 1024);
        printf("  PASS: GPU0=32GB, GPU1=16GB\n\n");
    }

    // ------------------------------------------------------------------------
    // Test 2: Tensor allocation and lease
    // ------------------------------------------------------------------------
    printf("[Test 2] Tensor allocation and lease\n");
    {
        VRAMManager vm;
        vm.Initialize(32ULL * 1024 * 1024 * 1024, 16ULL * 1024 * 1024 * 1024);

        VRAMLease* lease = vm.Allocate(1, "blk.0.attn_q.weight", 1024 * 1024 * 4, 5.0f, true);
        assert(lease != nullptr);
        assert(lease->currentGPU == 0); // Should prefer GPU0 (more free VRAM)
        assert(lease->IsResident());
        assert(vm.GetUsedVRAM(0) == 1024 * 1024 * 4);
        printf("  PASS: Allocated 'blk.0.attn_q.weight' on GPU %d\n\n", lease->currentGPU);
    }

    // ------------------------------------------------------------------------
    // Test 3: Tensor migration (hotpatch)
    // ------------------------------------------------------------------------
    printf("[Test 3] Tensor migration (hotpatch)\n");
    {
        VRAMManager vm;
        vm.Initialize(32ULL * 1024 * 1024 * 1024, 16ULL * 1024 * 1024 * 1024);

        VRAMLease* lease = vm.Allocate(2, "blk.0.attn_k.weight", 1024 * 1024 * 4, 3.0f, true);
        assert(lease->currentGPU == 0);

        TensorHotpatch th;
        th.AttachVRAMManager(&vm);

        HotpatchResult r = th.Redirect(lease, 1);
        assert(r == HotpatchResult::OK);
        assert(lease->currentGPU == 1);
        assert(lease->migrateCount == 1);
        printf("  PASS: Migrated to GPU 1\n\n");
    }

    // ------------------------------------------------------------------------
    // Test 4: Rollback
    // ------------------------------------------------------------------------
    printf("[Test 4] Rollback\n");
    {
        VRAMManager vm;
        vm.Initialize(32ULL * 1024 * 1024 * 1024, 16ULL * 1024 * 1024 * 1024);

        VRAMLease* lease = vm.Allocate(3, "blk.0.attn_v.weight", 1024 * 1024 * 4, 3.0f, true);
        TensorHotpatch th;
        th.AttachVRAMManager(&vm);

        th.Redirect(lease, 1);
        assert(lease->currentGPU == 1);

        HotpatchResult r = th.Rollback(3);
        assert(r == HotpatchResult::ROLLBACK_OK);
        assert(lease->currentGPU == 0);
        printf("  PASS: Rolled back to GPU 0\n\n");
    }

    // ------------------------------------------------------------------------
    // Test 5: Reverse recovery (tensor fault)
    // ------------------------------------------------------------------------
    printf("[Test 5] Reverse recovery (tensor fault)\n");
    {
        VRAMManager vm;
        vm.Initialize(32ULL * 1024 * 1024 * 1024, 16ULL * 1024 * 1024 * 1024);

        VRAMLease* lease = vm.Allocate(4, "blk.0.ffn_gate.weight", 1024 * 1024 * 4, 2.0f, true);
        TensorHotpatch th;
        th.AttachVRAMManager(&vm);

        // Simulate fault
        lease->state = LeaseState::FAILED;
        HotpatchResult r = th.ReverseRecover(4);
        assert(r == HotpatchResult::OK || r == HotpatchResult::NO_VRAM);
        printf("  PASS: Reverse recovery handled\n\n");
    }

    // ------------------------------------------------------------------------
    // Test 6: Dual GPU backend queues
    // ------------------------------------------------------------------------
    printf("[Test 6] Dual GPU backend queues\n");
    {
        DualGPUBackend backend;
        bool ok = backend.Initialize();
        assert(ok);

        ComputeTask task;
        task.kernelName = "test_kernel";
        task.workSize = 1024;
        task.priority = 1;

        auto future = backend.SubmitAuto(task);
        bool success = future.get();
        assert(success);
        printf("  PASS: Task submitted and executed\n\n");

        backend.Shutdown();
    }

    // ------------------------------------------------------------------------
    // Test 7: MARS Controller full integration
    // ------------------------------------------------------------------------
    printf("[Test 7] MARS Controller full integration\n");
    {
        MARSController mars;
        bool ok = mars.Initialize(32ULL * 1024 * 1024 * 1024, 16ULL * 1024 * 1024 * 1024);
        assert(ok);

        // Place some tensors
        VRAMLease* t1 = mars.PlaceTensor(10, "token_embd.weight", 1024 * 1024 * 4, 10.0f);
        VRAMLease* t2 = mars.PlaceTensor(11, "lm_head.weight", 1024 * 1024 * 4, 9.0f);
        VRAMLease* t3 = mars.PlaceTensor(12, "blk.0.attn_q.weight", 512 * 1024 * 4, 5.0f);

        assert(t1 != nullptr);
        assert(t2 != nullptr);
        assert(t3 != nullptr);

        // Rebalance
        mars.Rebalance();

        // Check parity
        auto dp = mars.GetCurrentParity();
        printf("  GPU0 free: %.2f GB\n", dp.vramFree(0) / (1024.0 * 1024.0 * 1024.0));
        printf("  GPU1 free: %.2f GB\n", dp.vramFree(1) / (1024.0 * 1024.0 * 1024.0));

        auto stats = mars.GetStats();
        printf("  Rebalance count: %llu\n", (unsigned long long)stats.rebalanceCount);
        printf("  PASS: Full integration\n\n");

        mars.Shutdown();
    }

    // ------------------------------------------------------------------------
    // Test 8: Dynamic parity queries
    // ------------------------------------------------------------------------
    printf("[Test 8] Dynamic parity queries\n");
    {
        MARSController mars;
        mars.Initialize(32ULL * 1024 * 1024 * 1024, 16ULL * 1024 * 1024 * 1024);

        auto dp = mars.GetCurrentParity();
        assert(dp.canMoveTensor(0, 1));
        assert(dp.canMoveTensor(1, 0));
        assert(dp.canMoveTensor(0, 0)); // same GPU is a no-op move
        assert(!dp.canMoveTensor(-1, 0)); // invalid

        int bestBandwidth = dp.bestGPUForBandwidth(1024);
        assert(bestBandwidth == 0); // GPU0 has more free VRAM
        printf("  PASS: Dynamic parity logic\n\n");

        mars.Shutdown();
    }

    printf("=== All MARS tests PASSED ===\n");
    fflush(stdout);
#if defined(_WIN32)
    _Exit(0);
#else
    std::_Exit(0);
#endif
}
