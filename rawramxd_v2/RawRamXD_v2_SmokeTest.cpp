// RawRamXD_v2_SmokeTest.cpp
// Validates v2.2 core invariants: capacity, allocation, migration, leases, shutdown

#include "RawRamXD.hpp"
#include <iostream>
#include <cassert>
#include <thread>
#include <vector>

using namespace rawramxd;

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name) void test_##name()
#define ASSERT(cond) do { if (!(cond)) { std::cerr << "FAIL: " << __FILE__ << ":" << __LINE__ << "  " << #cond << std::endl; ++g_failed; return; } } while(0)
#define PASS() do { ++g_passed; } while(0)

// ---------------------------------------------------------------------------
// Test 1: CapacityLedger reservation and release
// ---------------------------------------------------------------------------
TEST(capacity_ledger_basic) {
    CapacityLedger ledger(std::array<size_t, 3>{1024, 512, 256});

    ASSERT(ledger.capacity(Tier::NVMe) == 1024);
    ASSERT(ledger.capacity(Tier::RAM) == 512);
    ASSERT(ledger.capacity(Tier::VRAM) == 256);
    ASSERT(ledger.used(Tier::NVMe) == 0);

    ASSERT(ledger.tryReserve(Tier::NVMe, 100));
    ASSERT(ledger.used(Tier::NVMe) == 100);

    ASSERT(ledger.tryReserve(Tier::NVMe, 900));
    ASSERT(ledger.used(Tier::NVMe) == 1000);

    // Over-capacity reservation must fail
    ASSERT(!ledger.tryReserve(Tier::NVMe, 100));
    ASSERT(ledger.used(Tier::NVMe) == 1000);

    ledger.release(Tier::NVMe, 500);
    ASSERT(ledger.used(Tier::NVMe) == 500);

    ledger.release(Tier::NVMe, 500);
    ASSERT(ledger.used(Tier::NVMe) == 0);

    PASS();
}

// ---------------------------------------------------------------------------
// Test 2: CapacityReservation RAII rollback
// ---------------------------------------------------------------------------
TEST(capacity_reservation_rollback) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{1024, 512, 256});

    {
        CapacityReservation res(ledger, Tier::RAM, 200);
        ASSERT(ledger->used(Tier::RAM) == 200);
        // res goes out of scope uncommitted → automatic rollback
    }
    ASSERT(ledger->used(Tier::RAM) == 0);

    {
        CapacityReservation res(ledger, Tier::RAM, 200);
        res.commit();
        ASSERT(ledger->used(Tier::RAM) == 200);
        // committed → no rollback
    }
    ASSERT(ledger->used(Tier::RAM) == 200);

    ledger->release(Tier::RAM, 200);
    PASS();
}

// ---------------------------------------------------------------------------
// Test 3: NVMe + RAM backend allocation and release
// ---------------------------------------------------------------------------
TEST(backend_allocate_release) {
    NVMeFileBackend nvme(1, 1);
    HostRAMBackend ram(2, 1);

    auto nh = nvme.allocate(1024);
    ASSERT(nh.hostPtr != nullptr);
    ASSERT(nh.size == 1024);
    ASSERT(nh.tier == Tier::NVMe);
    ASSERT((nh.flags & CAP_FILE_BACKED) != 0);

    auto rh = ram.allocate(1024);
    ASSERT(rh.hostPtr != nullptr);
    ASSERT(rh.size == 1024);
    ASSERT(rh.tier == Tier::RAM);
    ASSERT((rh.flags & CAP_HOST_MEMORY) != 0);

    nvme.release(nh);
    ram.release(rh);
    PASS();
}

// ---------------------------------------------------------------------------
// Test 4: RawRamXDFabric construction and basic allocation
// ---------------------------------------------------------------------------
TEST(fabric_allocate) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{1024 * 1024, 512 * 1024, 256 * 1024});

    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram = std::make_shared<HostRAMBackend>(2, 1);
    auto transfer = std::make_shared<RawRamXDTransferEngine>();

    // Vulkan backend with null callbacks → allocate returns empty handle
    auto vram = std::make_shared<VulkanDeviceBackend>(
        3, 1, nullptr, nullptr, nullptr);

    RawRamXDFabric fabric(ledger, nvme, ram, vram, transfer, 4096);

    uint64_t h = fabric.allocate(8192, "test_tensor", AccessPattern::READ_WRITE);
    ASSERT(h != 0);

    auto s = fabric.stats();
    std::cout << "DEBUG nvmeUsed=" << s.nvmeUsed << " ramUsed=" << s.ramUsed << " vramUsed=" << s.vramUsed << std::endl;
    ASSERT(s.nvmeUsed == 8192);
    ASSERT(s.ramUsed == 0);
    ASSERT(s.vramUsed == 0);

    fabric.shutdown();
    PASS();
}

// ---------------------------------------------------------------------------
// Test 5: Migration NVMe → RAM and lease acquisition
// ---------------------------------------------------------------------------
TEST(fabric_migration_and_lease) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{1024 * 1024, 512 * 1024, 256 * 1024});

    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram = std::make_shared<HostRAMBackend>(2, 1);
    auto transfer = std::make_shared<RawRamXDTransferEngine>();
    auto vram = std::make_shared<VulkanDeviceBackend>(3, 1, nullptr, nullptr, nullptr);

    RawRamXDFabric fabric(ledger, nvme, ram, vram, transfer, 4096);

    uint64_t h = fabric.allocate(8192, "migratable", AccessPattern::READ_WRITE);
    ASSERT(h != 0);

    // Initially in NVMe
    auto lease_nvme = fabric.acquire(h, 0, Tier::NVMe);
    ASSERT(lease_nvme.valid());
    ASSERT(lease_nvme.tier() == Tier::NVMe);
    ASSERT(lease_nvme.hostPtr() != nullptr);
    ASSERT(lease_nvme.size() == 4096);

    // Migrate block 0 to RAM
    ASSERT(fabric.migrate(lease_nvme.blockId(), Tier::RAM));

    auto lease_ram = fabric.acquire(h, 0, Tier::RAM);
    ASSERT(lease_ram.valid());
    ASSERT(lease_ram.tier() == Tier::RAM);
    ASSERT(lease_ram.hostPtr() != nullptr);

    auto s = fabric.stats();
    ASSERT(s.migrationsStarted > 0);
    ASSERT(s.migrationsCompleted > 0);
    ASSERT(s.migrationsFailed == 0);

    fabric.shutdown();
    PASS();
}

// ---------------------------------------------------------------------------
// Test 6: Multi-block tensor, partial migration
// ---------------------------------------------------------------------------
TEST(fabric_multi_block) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{1024 * 1024, 512 * 1024, 256 * 1024});

    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram = std::make_shared<HostRAMBackend>(2, 1);
    auto transfer = std::make_shared<RawRamXDTransferEngine>();
    auto vram = std::make_shared<VulkanDeviceBackend>(3, 1, nullptr, nullptr, nullptr);

    RawRamXDFabric fabric(ledger, nvme, ram, vram, transfer, 4096);

    // 3 blocks: 4096 + 4096 + 2048 = 10240
    uint64_t h = fabric.allocate(10240, "three_block", AccessPattern::READ);
    ASSERT(h != 0);

    // Migrate only block 1 to RAM
    auto lease_block1 = fabric.acquire(h, 1, Tier::NVMe);
    ASSERT(lease_block1.valid());
    ASSERT(fabric.migrate(lease_block1.blockId(), Tier::RAM));

    // Block 0 should still be in NVMe
    auto l0 = fabric.acquire(h, 0, Tier::NVMe);
    ASSERT(l0.valid());
    ASSERT(l0.tier() == Tier::NVMe);

    // Block 1 should be in RAM
    auto l1 = fabric.acquire(h, 1, Tier::RAM);
    ASSERT(l1.valid());
    ASSERT(l1.tier() == Tier::RAM);

    // Block 2 should still be in NVMe
    auto l2 = fabric.acquire(h, 2, Tier::NVMe);
    ASSERT(l2.valid());
    ASSERT(l2.tier() == Tier::NVMe);

    fabric.shutdown();
    PASS();
}

// ---------------------------------------------------------------------------
// Test 7: Shutdown drains active leases
// ---------------------------------------------------------------------------
TEST(fabric_shutdown_drain) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{1024 * 1024, 512 * 1024, 256 * 1024});

    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram = std::make_shared<HostRAMBackend>(2, 1);
    auto transfer = std::make_shared<RawRamXDTransferEngine>();
    auto vram = std::make_shared<VulkanDeviceBackend>(3, 1, nullptr, nullptr, nullptr);

    {
        RawRamXDFabric fabric(ledger, nvme, ram, vram, transfer, 4096);

        uint64_t h = fabric.allocate(4096, "drain_test", AccessPattern::READ);
        ASSERT(h != 0);

        auto lease = fabric.acquire(h, 0, Tier::NVMe);
        ASSERT(lease.valid());

        // shutdown() must wait for lease to be released
        fabric.shutdown();
        ASSERT(fabric.runtimeState() == RuntimeState::STOPPED);

        // Lease is now invalid (backend freed)
        // But the Lease object itself is still destructible
    }
    PASS();
}

// ---------------------------------------------------------------------------
// Test 8: Concurrent lease acquisition (thread safety)
// ---------------------------------------------------------------------------
TEST(fabric_concurrent_leases) {
    auto ledger = std::make_shared<CapacityLedger>(
        std::array<size_t, 3>{1024 * 1024, 512 * 1024, 256 * 1024});

    auto nvme = std::make_shared<NVMeFileBackend>(1, 1);
    auto ram = std::make_shared<HostRAMBackend>(2, 1);
    auto transfer = std::make_shared<RawRamXDTransferEngine>();
    auto vram = std::make_shared<VulkanDeviceBackend>(3, 1, nullptr, nullptr, nullptr);

    RawRamXDFabric fabric(ledger, nvme, ram, vram, transfer, 4096);

    uint64_t h = fabric.allocate(4096, "concurrent", AccessPattern::READ_WRITE);
    ASSERT(h != 0);

    std::vector<std::thread> threads;
    std::atomic<int> successes{0};

    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&]() {
            auto lease = fabric.acquire(h, 0, Tier::NVMe);
            if (lease.valid()) {
                // Touch memory to prove it's real
                std::memset(lease.hostPtr(), 0xAB, 64);
                successes.fetch_add(1);
            }
        });
    }

    for (auto& t : threads) t.join();
    ASSERT(successes.load() == 8);

    fabric.shutdown();
    PASS();
}

// ---------------------------------------------------------------------------
// Test 9: RawRamXDTransferEngine fail-closed for unsupported tiers
// ---------------------------------------------------------------------------
TEST(transfer_engine_fail_closed) {
    RawRamXDTransferEngine engine;

    // NVMe ↔ RAM is supported
    ASSERT(engine.canTransfer(Tier::NVMe, Tier::RAM));
    ASSERT(engine.canTransfer(Tier::RAM, Tier::NVMe));

    // VRAM paths are NOT supported by RawRamXDTransferEngine
    ASSERT(!engine.canTransfer(Tier::NVMe, Tier::VRAM));
    ASSERT(!engine.canTransfer(Tier::VRAM, Tier::RAM));
    ASSERT(!engine.canTransfer(Tier::RAM, Tier::VRAM));

    PASS();
}

// ---------------------------------------------------------------------------
// Test 10: CapacityLedger underflow protection
// ---------------------------------------------------------------------------
TEST(capacity_ledger_underflow) {
    CapacityLedger ledger(std::array<size_t, 3>{1024, 512, 256});

    ledger.tryReserve(Tier::RAM, 100);
    ASSERT(ledger.used(Tier::RAM) == 100);

    ledger.release(Tier::RAM, 50);
    ASSERT(ledger.used(Tier::RAM) == 50);

    // Underflow must throw
    bool threw = false;
    try {
        ledger.release(Tier::RAM, 100);
    } catch (const std::logic_error&) {
        threw = true;
    }
    ASSERT(threw);
    PASS();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "=== RawRamXD v2.2 Smoke Test Harness ===" << std::endl;
    std::cout << std::endl;

    test_capacity_ledger_basic();
    test_capacity_reservation_rollback();
    test_backend_allocate_release();
    test_fabric_allocate();
    test_fabric_migration_and_lease();
    test_fabric_multi_block();
    test_fabric_shutdown_drain();
    test_fabric_concurrent_leases();
    test_transfer_engine_fail_closed();
    test_capacity_ledger_underflow();

    std::cout << std::endl;
    std::cout << "Results: " << g_passed << " passed, " << g_failed << " failed" << std::endl;

    return g_failed > 0 ? 1 : 0;
}
