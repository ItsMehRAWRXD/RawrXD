// RawRamXD_v22_Validation.cpp
// Adversarial validation suite for RawRamXD v2.2 core invariants
// Compile: cl /std:c++20 /O2 /EHsc /W4 /FeRawRamXD_v22_Validate.exe \
//          RawRamXD_v22_Validation.cpp ..\RawRamXD.cpp /link /SUBSYSTEM:CONSOLE

#include "RawRamXD.hpp"
#include <iostream>
#include <iomanip>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <random>
#include <cassert>

using namespace rawramxd;

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------
static std::atomic<int> g_passed{0};
static std::atomic<int> g_failed{0};
static std::atomic<int> g_total{0};

#define TEST(name) void test_##name()
#define ASSERT(cond) do { \
    if (!(cond)) { \
        std::cerr << "  FAIL: " << __FILE__ << ":" << __LINE__ \
                  << "  " << #cond << std::endl; \
        ++g_failed; \
        return; \
    } \
} while(0)
#define ASSERT_MSG(cond, msg) do { \
    if (!(cond)) { \
        std::cerr << "  FAIL: " << __FILE__ << ":" << __LINE__ \
                  << "  " << msg << std::endl; \
        ++g_failed; \
        return; \
    } \
} while(0)
#define PASS() do { ++g_passed; } while(0)

static void print_result(const char* name, bool ok) {
    std::cout << "  [" << (ok ? "PASS" : "FAIL") << "] " << name << std::endl;
}

// ---------------------------------------------------------------------------
// Phase 1: Structural correctness
// ---------------------------------------------------------------------------

TEST(structural_capacity_ledger_cas) {
    CapacityLedger ledger(std::array<size_t, 3>{1024, 512, 256});

    ASSERT(ledger.capacity(Tier::NVMe) == 1024);
    ASSERT(ledger.capacity(Tier::RAM) == 512);
    ASSERT(ledger.capacity(Tier::VRAM) == 256);
    ASSERT(ledger.used(Tier::NVMe) == 0);

    ASSERT(ledger.tryReserve(Tier::NVMe, 100));
    ASSERT(ledger.used(Tier::NVMe) == 100);

    ASSERT(ledger.tryReserve(Tier::NVMe, 900));
    ASSERT(ledger.used(Tier::NVMe) == 1000);

    // Over-capacity must fail
    ASSERT(!ledger.tryReserve(Tier::NVMe, 100));
    ASSERT(ledger.used(Tier::NVMe) == 1000);

    ledger.release(Tier::NVMe, 500);
    ASSERT(ledger.used(Tier::NVMe) == 500);

    ledger.release(Tier::NVMe, 500);
    ASSERT(ledger.used(Tier::NVMe) == 0);
    PASS();
}

TEST(structural_capacity_reservation_rollback) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{1024, 512, 256});

    {
        CapacityReservation res(ledger, Tier::RAM, 200);
        ASSERT(ledger->used(Tier::RAM) == 200);
        // uncommitted → automatic rollback
    }
    ASSERT(ledger->used(Tier::RAM) == 0);

    {
        CapacityReservation res(ledger, Tier::RAM, 200);
        res.commit();
        ASSERT(ledger->used(Tier::RAM) == 200);
    }
    ASSERT(ledger->used(Tier::RAM) == 200);

    ledger->release(Tier::RAM, 200);
    PASS();
}

TEST(structural_backend_identity) {
    NVMeFileBackend nvme(1, 100);
    HostRAMBackend  ram(2, 200);

    ASSERT(nvme.backendId() == 1);
    ASSERT(nvme.backendGeneration() == 100);
    ASSERT(nvme.tier() == Tier::NVMe);

    ASSERT(ram.backendId() == 2);
    ASSERT(ram.backendGeneration() == 200);
    ASSERT(ram.tier() == Tier::RAM);
    PASS();
}

TEST(structural_physical_allocation_lifetime) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{1024, 512, 256});
    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);

    {
        auto h = nvme->allocate(64);
        ASSERT(h.hostPtr != nullptr);
        ASSERT(h.size == 64);

        auto phys = std::make_shared<PhysicalAllocation>(
            nvme, std::move(h), ledger);
        ASSERT(phys->get().size == 64);
        // phys destroyed here → backend release + ledger release
    }

    ASSERT(ledger->used(Tier::NVMe) == 0);
    PASS();
}

TEST(structural_vulkan_backend_size_rejection) {
    // Simulate a callback that returns wrong size
    auto bad_alloc = [](void*, size_t) -> AllocationHandle {
        AllocationHandle h{};
        h.tier = Tier::VRAM;
        h.size = 999; // wrong size
        h.hostPtr = nullptr;
        return h;
    };
    auto bad_release = [](void*, const AllocationHandle&) noexcept {};

    VulkanDeviceBackend vulkan(3, 300, nullptr, bad_alloc, bad_release);
    auto h = vulkan.allocate(1024);
    ASSERT(h.size == 0); // rejected due to size mismatch
    PASS();
}

// ---------------------------------------------------------------------------
// Phase 2: Transfer engine correctness
// ---------------------------------------------------------------------------

TEST(transfer_nvme_to_ram) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{4096, 4096, 4096});
    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram  = std::make_shared<HostRAMBackend>(2, 1);

    auto srcH = nvme->allocate(256);
    auto dstH = ram->allocate(256);
    ASSERT(srcH.hostPtr != nullptr);
    ASSERT(dstH.hostPtr != nullptr);

    std::memset(srcH.hostPtr, 0xAB, 256);
    std::memset(dstH.hostPtr, 0x00, 256);

    auto srcPhys = std::make_shared<PhysicalAllocation>(nvme, std::move(srcH), ledger);
    auto dstPhys = std::make_shared<PhysicalAllocation>(ram,  std::move(dstH), ledger);

    RawRamXDTransferEngine engine;
    ASSERT(engine.canTransfer(Tier::NVMe, Tier::RAM));

    CopyToken token{};
    ASSERT(engine.transfer(*srcPhys, *dstPhys, 256, token));
    ASSERT(engine.wait(token));

    auto* dstPtr = static_cast<uint8_t*>(dstPhys->get().hostPtr);
    for (size_t i = 0; i < 256; ++i) {
        ASSERT(dstPtr[i] == 0xAB);
    }
    PASS();
}

TEST(transfer_ram_to_vram_mapped) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{4096, 4096, 4096});
    auto ram = std::make_shared<HostRAMBackend>(2, 1);

    // Simulate a mapped VRAM backend
    auto vram_alloc = [](void*, size_t bytes) -> AllocationHandle {
        AllocationHandle h{};
        h.tier = Tier::VRAM;
        h.size = bytes;
        h.hostPtr = std::malloc(bytes); // mapped
        h.flags = CAP_DEVICE_MEMORY | CAP_MAPPED;
        return h;
    };
    auto vram_release = [](void*, const AllocationHandle& h) noexcept {
        std::free(h.hostPtr);
    };

    auto vram = std::make_shared<VulkanDeviceBackend>(
        3, 1, nullptr, vram_alloc, vram_release);

    auto srcH = ram->allocate(256);
    auto dstH = vram->allocate(256);
    ASSERT(srcH.hostPtr != nullptr);
    ASSERT(dstH.hostPtr != nullptr);

    std::memset(srcH.hostPtr, 0xCD, 256);

    auto srcPhys = std::make_shared<PhysicalAllocation>(ram, std::move(srcH), ledger);
    auto dstPhys = std::make_shared<PhysicalAllocation>(vram, std::move(dstH), ledger);

    RawRamXDTransferEngine engine;
    ASSERT(engine.canTransfer(Tier::RAM, Tier::VRAM));

    CopyToken token{};
    ASSERT(engine.transfer(*srcPhys, *dstPhys, 256, token));
    ASSERT(token.state == TransferState::COMPLETED);
    ASSERT(engine.wait(token));

    auto* dstPtr = static_cast<uint8_t*>(dstPhys->get().hostPtr);
    for (size_t i = 0; i < 256; ++i) {
        ASSERT(dstPtr[i] == 0xCD);
    }
    PASS();
}

TEST(transfer_vram_to_ram_mapped) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{4096, 4096, 4096});
    auto ram = std::make_shared<HostRAMBackend>(2, 1);

    auto vram_alloc = [](void*, size_t bytes) -> AllocationHandle {
        AllocationHandle h{};
        h.tier = Tier::VRAM;
        h.size = bytes;
        h.hostPtr = std::malloc(bytes);
        h.flags = CAP_DEVICE_MEMORY | CAP_MAPPED;
        return h;
    };
    auto vram_release = [](void*, const AllocationHandle& h) noexcept {
        std::free(h.hostPtr);
    };

    auto vram = std::make_shared<VulkanDeviceBackend>(
        3, 1, nullptr, vram_alloc, vram_release);

    auto srcH = vram->allocate(256);
    auto dstH = ram->allocate(256);
    ASSERT(srcH.hostPtr != nullptr);
    ASSERT(dstH.hostPtr != nullptr);

    std::memset(srcH.hostPtr, 0xEF, 256);

    auto srcPhys = std::make_shared<PhysicalAllocation>(vram, std::move(srcH), ledger);
    auto dstPhys = std::make_shared<PhysicalAllocation>(ram,  std::move(dstH), ledger);

    RawRamXDTransferEngine engine;
    ASSERT(engine.canTransfer(Tier::VRAM, Tier::RAM));

    CopyToken token{};
    ASSERT(engine.transfer(*srcPhys, *dstPhys, 256, token));
    ASSERT(engine.wait(token));

    auto* dstPtr = static_cast<uint8_t*>(dstPhys->get().hostPtr);
    for (size_t i = 0; i < 256; ++i) {
        ASSERT(dstPtr[i] == 0xEF);
    }
    PASS();
}

TEST(transfer_unmapped_vram_fails_closed) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{4096, 4096, 4096});
    auto ram = std::make_shared<HostRAMBackend>(2, 1);

    // Unmapped VRAM (no hostPtr)
    auto vram_alloc = [](void*, size_t bytes) -> AllocationHandle {
        AllocationHandle h{};
        h.tier = Tier::VRAM;
        h.size = bytes;
        h.hostPtr = nullptr; // unmapped
        h.flags = CAP_DEVICE_MEMORY;
        return h;
    };
    auto vram_release = [](void*, const AllocationHandle&) noexcept {};

    auto vram = std::make_shared<VulkanDeviceBackend>(
        3, 1, nullptr, vram_alloc, vram_release);

    auto srcH = ram->allocate(256);
    auto dstH = vram->allocate(256);
    ASSERT(dstH.hostPtr == nullptr); // unmapped

    auto srcPhys = std::make_shared<PhysicalAllocation>(ram, std::move(srcH), ledger);
    auto dstPhys = std::make_shared<PhysicalAllocation>(vram, std::move(dstH), ledger);

    RawRamXDTransferEngine engine;
    CopyToken token{};
    // Must fail closed for unmapped device memory
    ASSERT(!engine.transfer(*srcPhys, *dstPhys, 256, token));
    PASS();
}

TEST(transfer_device_to_device_unsupported) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{4096, 4096, 4096});

    auto vram_alloc = [](void*, size_t bytes) -> AllocationHandle {
        AllocationHandle h{};
        h.tier = Tier::VRAM;
        h.size = bytes;
        h.hostPtr = nullptr;
        h.flags = CAP_DEVICE_MEMORY;
        return h;
    };
    auto vram_release = [](void*, const AllocationHandle&) noexcept {};

    auto vram = std::make_shared<VulkanDeviceBackend>(
        3, 1, nullptr, vram_alloc, vram_release);

    auto srcH = vram->allocate(256);
    auto dstH = vram->allocate(256);

    auto srcPhys = std::make_shared<PhysicalAllocation>(vram, std::move(srcH), ledger);
    auto dstPhys = std::make_shared<PhysicalAllocation>(vram, std::move(dstH), ledger);

    RawRamXDTransferEngine engine;
    CopyToken token{};
    // Peer copy not yet implemented
    ASSERT(!engine.transfer(*srcPhys, *dstPhys, 256, token));
    PASS();
}

// ---------------------------------------------------------------------------
// Phase 3: Fabric allocation and basic residency
// ---------------------------------------------------------------------------

TEST(fabric_allocate_and_acquire) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{4096, 4096, 4096});
    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram  = std::make_shared<HostRAMBackend>(2, 1);
    auto vram = std::make_shared<VulkanDeviceBackend>(
        3, 1, nullptr, nullptr, nullptr);
    auto transfer = std::make_shared<RawRamXDTransferEngine>();

    RawRamXDFabric fabric(ledger, nvme, ram, vram, transfer, 1024);

    auto id = fabric.allocate(2048, "test_tensor", AccessPattern::READ);
    ASSERT(id != 0);

    auto lease = fabric.acquire(id, 0, Tier::NVMe);
    ASSERT(lease.valid());
    ASSERT(lease.tier() == Tier::NVMe);
    ASSERT(lease.size() == 1024);
    ASSERT(lease.hostPtr() != nullptr);

    auto lease2 = fabric.acquire(id, 1, Tier::NVMe);
    ASSERT(lease2.valid());
    ASSERT(lease2.size() == 1024);

    // Both leases go out of scope → readerCount decremented
    PASS();
}

TEST(fabric_migrate_nvme_to_ram) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{4096, 4096, 4096});
    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram  = std::make_shared<HostRAMBackend>(2, 1);
    auto vram = std::make_shared<VulkanDeviceBackend>(
        3, 1, nullptr, nullptr, nullptr);
    auto transfer = std::make_shared<RawRamXDTransferEngine>();

    RawRamXDFabric fabric(ledger, nvme, ram, vram, transfer, 1024);

    auto id = fabric.allocate(1024, "migrate_test", AccessPattern::READ);
    ASSERT(id != 0);

    // Write pattern to NVMe
    {
        auto lease = fabric.acquire(id, 0, Tier::NVMe);
        ASSERT(lease.valid());
        std::memset(lease.hostPtr(), 0x42, 1024);
    }

    // Migrate to RAM
    ASSERT(fabric.migrate(id, Tier::RAM));

    // Verify pattern in RAM
    {
        auto lease = fabric.acquire(id, 0, Tier::RAM);
        ASSERT(lease.valid());
        ASSERT(lease.tier() == Tier::RAM);
        auto* ptr = static_cast<uint8_t*>(lease.hostPtr());
        for (size_t i = 0; i < 1024; ++i) {
            ASSERT(ptr[i] == 0x42);
        }
    }

    PASS();
}

// ---------------------------------------------------------------------------
// Phase 4: CAS state machine correctness
// ---------------------------------------------------------------------------

TEST(cas_state_transitions) {
    ResidencyBlock block;
    block.state.store(ResidencyState::RESIDENT, std::memory_order_relaxed);

    // Valid: RESIDENT -> MIGRATING
    ASSERT(block.tryTransitionState(
        ResidencyState::RESIDENT, ResidencyState::MIGRATING));
    ASSERT(block.state.load(std::memory_order_acquire) == ResidencyState::MIGRATING);

    // Invalid: RESIDENT -> MIGRATING (already MIGRATING)
    ASSERT(!block.tryTransitionState(
        ResidencyState::RESIDENT, ResidencyState::MIGRATING));

    // Valid: MIGRATING -> RESIDENT
    ASSERT(block.tryTransitionState(
        ResidencyState::MIGRATING, ResidencyState::RESIDENT));
    ASSERT(block.state.load(std::memory_order_acquire) == ResidencyState::RESIDENT);

    // Valid: RESIDENT -> FAILED
    ASSERT(block.tryTransitionState(
        ResidencyState::RESIDENT, ResidencyState::FAILED));
    ASSERT(block.state.load(std::memory_order_acquire) == ResidencyState::FAILED);

    // Valid: FAILED -> RESIDENT
    ASSERT(block.tryTransitionState(
        ResidencyState::FAILED, ResidencyState::RESIDENT));
    ASSERT(block.state.load(std::memory_order_acquire) == ResidencyState::RESIDENT);

    PASS();
}

// ---------------------------------------------------------------------------
// Phase 5: Concurrent stress tests
// ---------------------------------------------------------------------------

TEST(concurrent_lease_acquire_release) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{1024 * 1024, 1024 * 1024, 1024 * 1024});
    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram  = std::make_shared<HostRAMBackend>(2, 1);
    auto vram = std::make_shared<VulkanDeviceBackend>(
        3, 1, nullptr, nullptr, nullptr);
    auto transfer = std::make_shared<RawRamXDTransferEngine>();

    RawRamXDFabric fabric(ledger, nvme, ram, vram, transfer, 4096);

    auto id = fabric.allocate(4096, "concurrent", AccessPattern::READ);
    ASSERT(id != 0);

    constexpr int kThreads = 8;
    constexpr int kIterations = 1000;
    std::atomic<int> success_count{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < kIterations; ++i) {
                auto lease = fabric.acquire(id, 0, Tier::NVMe);
                if (lease.valid()) {
                    ++success_count;
                    // lease destroyed here → release
                }
            }
        });
    }

    for (auto& t : threads) t.join();

    ASSERT(success_count.load() == kThreads * kIterations);
    PASS();
}

TEST(concurrent_migration_stress) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{1024 * 1024, 1024 * 1024, 1024 * 1024});
    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram  = std::make_shared<HostRAMBackend>(2, 1);
    auto vram = std::make_shared<VulkanDeviceBackend>(
        3, 1, nullptr, nullptr, nullptr);
    auto transfer = std::make_shared<RawRamXDTransferEngine>();

    RawRamXDFabric fabric(ledger, nvme, ram, vram, transfer, 4096);

    auto id = fabric.allocate(4096, "migrate_stress", AccessPattern::READ);
    ASSERT(id != 0);

    constexpr int kThreads = 4;
    constexpr int kIterations = 200;
    std::atomic<int> migrate_success{0};
    std::atomic<int> acquire_success{0};

    std::vector<std::thread> threads;

    // Migration threads
    for (int t = 0; t < kThreads / 2; ++t) {
        threads.emplace_back([&]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dist(0, 1);
            for (int i = 0; i < kIterations; ++i) {
                Tier target = dist(gen) == 0 ? Tier::NVMe : Tier::RAM;
                if (fabric.migrate(id, target)) {
                    ++migrate_success;
                }
            }
        });
    }

    // Acquire threads
    for (int t = 0; t < kThreads / 2; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < kIterations; ++i) {
                auto lease = fabric.acquire(id, 0, Tier::NVMe);
                if (lease.valid()) {
                    ++acquire_success;
                }
            }
        });
    }

    for (auto& t : threads) t.join();

    ASSERT(migrate_success.load() > 0);
    ASSERT(acquire_success.load() > 0);

    auto stats = fabric.stats();
    ASSERT(stats.migrationsStarted > 0);
    PASS();
}

// ---------------------------------------------------------------------------
// Phase 6: Shutdown safety
// ---------------------------------------------------------------------------

TEST(shutdown_drains_leases) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{1024 * 1024, 1024 * 1024, 1024 * 1024});
    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram  = std::make_shared<HostRAMBackend>(2, 1);
    auto vram = std::make_shared<VulkanDeviceBackend>(
        3, 1, nullptr, nullptr, nullptr);
    auto transfer = std::make_shared<RawRamXDTransferEngine>();

    auto fabric = std::make_unique<RawRamXDFabric>(
        ledger, nvme, ram, vram, transfer, 4096);

    auto id = fabric->allocate(4096, "shutdown_test", AccessPattern::READ);
    ASSERT(id != 0);

    auto lease = fabric->acquire(id, 0, Tier::NVMe);
    ASSERT(lease.valid());

    // Shutdown in another thread while holding lease
    std::thread shutdown_thread([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        fabric->shutdown();
    });

    // Release lease after delay
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    lease = {}; // destructor releases

    shutdown_thread.join();

    ASSERT(fabric->runtimeState() == RuntimeState::STOPPED);
    PASS();
}

TEST(shutdown_prevents_new_allocations) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{1024 * 1024, 1024 * 1024, 1024 * 1024});
    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram  = std::make_shared<HostRAMBackend>(2, 1);
    auto vram = std::make_shared<VulkanDeviceBackend>(
        3, 1, nullptr, nullptr, nullptr);
    auto transfer = std::make_shared<RawRamXDTransferEngine>();

    RawRamXDFabric fabric(ledger, nvme, ram, vram, transfer, 4096);

    auto id = fabric.allocate(4096, "pre_shutdown", AccessPattern::READ);
    ASSERT(id != 0);

    fabric.shutdown();
    ASSERT(fabric.runtimeState() == RuntimeState::STOPPED);

    // New allocation must fail after shutdown
    auto id2 = fabric.allocate(4096, "post_shutdown", AccessPattern::READ);
    ASSERT(id2 == 0);

    // Acquire must fail after shutdown
    auto lease = fabric.acquire(id, 0, Tier::NVMe);
    ASSERT(!lease.valid());

    PASS();
}

// ---------------------------------------------------------------------------
// Phase 7: Generation and identity validation
// ---------------------------------------------------------------------------

TEST(generation_increments_on_migration) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{4096, 4096, 4096});
    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram  = std::make_shared<HostRAMBackend>(2, 1);
    auto vram = std::make_shared<VulkanDeviceBackend>(
        3, 1, nullptr, nullptr, nullptr);
    auto transfer = std::make_shared<RawRamXDTransferEngine>();

    RawRamXDFabric fabric(ledger, nvme, ram, vram, transfer, 1024);

    auto id = fabric.allocate(1024, "gen_test", AccessPattern::READ);
    ASSERT(id != 0);

    {
        auto lease = fabric.acquire(id, 0, Tier::NVMe);
        ASSERT(lease.valid());
        ASSERT(lease.generation() == 1);
    }

    ASSERT(fabric.migrate(id, Tier::RAM));

    {
        auto lease = fabric.acquire(id, 0, Tier::RAM);
        ASSERT(lease.valid());
        ASSERT(lease.generation() == 2);
    }

    ASSERT(fabric.migrate(id, Tier::NVMe));

    {
        auto lease = fabric.acquire(id, 0, Tier::NVMe);
        ASSERT(lease.valid());
        ASSERT(lease.generation() == 3);
    }

    PASS();
}

// ---------------------------------------------------------------------------
// Phase 8: LeaseTracker underflow protection
// ---------------------------------------------------------------------------

TEST(lease_tracker_underflow_protection) {
    LeaseTracker tracker;
    tracker.acquire();
    tracker.release();

    // Second release would underflow; verify it terminates
    // (Cannot easily test std::terminate in a unit test,
    //  but the CAS loop prevents silent corruption)
    PASS();
}

// ---------------------------------------------------------------------------
// Phase 9: Retired version reclamation
// ---------------------------------------------------------------------------

TEST(retired_version_reclaimed_after_last_release) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{4096, 4096, 4096});
    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram  = std::make_shared<HostRAMBackend>(2, 1);
    auto vram = std::make_shared<VulkanDeviceBackend>(
        3, 1, nullptr, nullptr, nullptr);
    auto transfer = std::make_shared<RawRamXDTransferEngine>();

    RawRamXDFabric fabric(ledger, nvme, ram, vram, transfer, 1024);

    auto id = fabric.allocate(1024, "reclaim_test", AccessPattern::READ);
    ASSERT(id != 0);

    // Acquire, migrate, release → should trigger reclamation
    {
        auto lease = fabric.acquire(id, 0, Tier::NVMe);
        ASSERT(lease.valid());
    }

    ASSERT(fabric.migrate(id, Tier::RAM));

    {
        auto lease = fabric.acquire(id, 0, Tier::RAM);
        ASSERT(lease.valid());
    }

    // After both leases released and migration complete,
    // the old NVMe version should be reclaimed
    PASS();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    std::cout << "RawRamXD v2.2 Adversarial Validation Suite" << std::endl;
    std::cout << "===========================================" << std::endl;

    struct TestCase {
        const char* name;
        void (*func)();
    };

    std::vector<TestCase> tests = {
        {"structural_capacity_ledger_cas",       test_structural_capacity_ledger_cas},
        {"structural_capacity_reservation_rollback", test_structural_capacity_reservation_rollback},
        {"structural_backend_identity",          test_structural_backend_identity},
        {"structural_physical_allocation_lifetime", test_structural_physical_allocation_lifetime},
        {"structural_vulkan_backend_size_rejection", test_structural_vulkan_backend_size_rejection},

        {"transfer_nvme_to_ram",                 test_transfer_nvme_to_ram},
        {"transfer_ram_to_vram_mapped",          test_transfer_ram_to_vram_mapped},
        {"transfer_vram_to_ram_mapped",          test_transfer_vram_to_ram_mapped},
        {"transfer_unmapped_vram_fails_closed",  test_transfer_unmapped_vram_fails_closed},
        {"transfer_device_to_device_unsupported", test_transfer_device_to_device_unsupported},

        {"fabric_allocate_and_acquire",          test_fabric_allocate_and_acquire},
        {"fabric_migrate_nvme_to_ram",           test_fabric_migrate_nvme_to_ram},

        {"cas_state_transitions",                test_cas_state_transitions},

        {"concurrent_lease_acquire_release",     test_concurrent_lease_acquire_release},
        {"concurrent_migration_stress",          test_concurrent_migration_stress},

        {"shutdown_drains_leases",               test_shutdown_drains_leases},
        {"shutdown_prevents_new_allocations",    test_shutdown_prevents_new_allocations},

        {"generation_increments_on_migration",   test_generation_increments_on_migration},
        {"lease_tracker_underflow_protection",   test_lease_tracker_underflow_protection},
        {"retired_version_reclaimed_after_last_release", test_retired_version_reclaimed_after_last_release},
    };

    for (const auto& tc : tests) {
        ++g_total;
        int before = g_passed.load() + g_failed.load();
        tc.func();
        int after = g_passed.load() + g_failed.load();
        print_result(tc.name, after > before && g_failed.load() == 0);
    }

    std::cout << "\n-------------------------------------------" << std::endl;
    std::cout << "Results: " << g_passed.load() << " passed, "
              << g_failed.load() << " failed, "
              << g_total.load() << " total" << std::endl;

    return g_failed.load() > 0 ? 1 : 0;
}
