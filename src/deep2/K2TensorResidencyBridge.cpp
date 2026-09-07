// K2TensorResidencyBridge.cpp — bridge implementation
#include "K2TensorResidencyBridge.hpp"
#include <mutex>
#include <unordered_map>
#include <vector>
#include <atomic>

namespace Deep2 {
namespace {

struct TensorEntry {
    uint64_t tensorId = 0;
    size_t   bytes = 0;
    std::string name;
    rawramxd::ResidencyLease lease;
};

std::mutex g_mu;
std::shared_ptr<rawramxd::RawRamXDFabric> g_fabric;
std::unordered_map<std::string, TensorEntry> g_registry;
K2FabricCounters g_counters{};
std::atomic<bool> g_available{false};

TensorEntry* FindEntry(const char* name) {
    if (!name || !name[0]) return nullptr;
    auto it = g_registry.find(name);
    return (it != g_registry.end()) ? &it->second : nullptr;
}

} // namespace

void K2Fabric_Init(std::shared_ptr<rawramxd::RawRamXDFabric> fabric) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_fabric = std::move(fabric);
    g_registry.clear();
    g_counters = K2FabricCounters{};
    g_available.store(g_fabric != nullptr, std::memory_order_release);
}

uint64_t K2Fabric_RegisterWeight(const char* name, size_t bytes,
                                  const void* initialData) {
    if (!name || !name[0] || bytes == 0) return 0;
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_fabric) return 0;
    if (g_registry.find(name) != g_registry.end()) {
        // Already registered — return existing handle
        return g_registry[name].tensorId;
    }
    uint64_t tid = g_fabric->allocate(bytes, name);
    if (tid == 0) return 0;
    // If initial data provided, copy into block 0 (NVMe backing)
    if (initialData) {
        auto lease = g_fabric->acquire(tid, 0, rawramxd::Tier::NVMe);
        if (void* p = lease.hostPtr()) {
            std::memcpy(p, initialData, bytes);
        }
    }
    TensorEntry e;
    e.tensorId = tid;
    e.bytes = bytes;
    e.name = name;
    g_registry.emplace(name, std::move(e));
    return tid;
}

bool K2Fabric_TryGetDeviceAddress(const char* name, size_t bytes,
                                   uint64_t& devAddr,
                                   bool triggerMigrate) {
    devAddr = 0;
    if (!name || !name[0]) return false;
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_fabric) return false;
    TensorEntry* e = FindEntry(name);
    if (!e) return false;
    if (e->bytes != bytes) return false;

    g_counters.acquireCalls++;

    // Release any stale lease first
    if (e->lease) {
        e->lease = rawramxd::ResidencyLease();
        g_counters.leaseEarlyRelease++;
    }

    // Try VRAM acquire
    auto lease = g_fabric->acquire(e->tensorId, 0, rawramxd::Tier::VRAM);
    if (lease) {
        uint64_t addr = lease.deviceAddress();
        if (addr != 0) {
            devAddr = addr;
            e->lease = std::move(lease);
            g_counters.vramHits++;
            return true;
        }
        g_counters.deviceAddressZero++;
    }

    g_counters.vramMisses++;

    if (triggerMigrate) {
        // Trigger migration to VRAM (synchronous for Gate 1)
        g_counters.migrationsStarted++;
        bool migrated = g_fabric->migrate(e->tensorId, rawramxd::Tier::VRAM);
        if (migrated) {
            g_counters.migrationsCompleted++;
            // Re-acquire after migration
            lease = g_fabric->acquire(e->tensorId, 0, rawramxd::Tier::VRAM);
            if (lease) {
                uint64_t addr = lease.deviceAddress();
                if (addr != 0) {
                    devAddr = addr;
                    e->lease = std::move(lease);
                    return true;
                }
                g_counters.deviceAddressZero++;
            }
        } else {
            g_counters.migrationsFailed++;
        }
    }

    g_counters.fallbackToLegacy++;
    return false;
}

void K2Fabric_ReleaseLease(const char* name) {
    if (!name || !name[0]) return;
    std::lock_guard<std::mutex> lock(g_mu);
    TensorEntry* e = FindEntry(name);
    if (e && e->lease) {
        e->lease = rawramxd::ResidencyLease();
    }
}

void K2Fabric_ResetCounters() {
    std::lock_guard<std::mutex> lock(g_mu);
    g_counters = K2FabricCounters{};
}

K2FabricCounters K2Fabric_GetCounters() {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_counters;
}

void K2Fabric_EmitCounters(FILE* f) {
    if (!f) f = stdout;
    std::lock_guard<std::mutex> lock(g_mu);
    fprintf(f,
        "FABRIC_ACQUIRE=%llu FABRIC_VRAM_HIT=%llu FABRIC_VRAM_MISS=%llu\n"
        "FABRIC_MIGRATE_START=%llu FABRIC_MIGRATE_COMPLETE=%llu FABRIC_MIGRATE_FAIL=%llu\n"
        "FABRIC_DEVADDR_ZERO=%llu FABRIC_LEASE_EARLY=%llu FABRIC_FALLBACK=%llu\n",
        (unsigned long long)g_counters.acquireCalls,
        (unsigned long long)g_counters.vramHits,
        (unsigned long long)g_counters.vramMisses,
        (unsigned long long)g_counters.migrationsStarted,
        (unsigned long long)g_counters.migrationsCompleted,
        (unsigned long long)g_counters.migrationsFailed,
        (unsigned long long)g_counters.deviceAddressZero,
        (unsigned long long)g_counters.leaseEarlyRelease,
        (unsigned long long)g_counters.fallbackToLegacy);
    fflush(f);
}

bool K2Fabric_Available() {
    return g_available.load(std::memory_order_acquire);
}

void K2Fabric_Shutdown() {
    std::lock_guard<std::mutex> lock(g_mu);
    for (auto& kv : g_registry) {
        kv.second.lease = rawramxd::ResidencyLease();
    }
    g_registry.clear();
    g_fabric.reset();
    g_counters = K2FabricCounters{};
    g_available.store(false, std::memory_order_release);
}

} // namespace Deep2
