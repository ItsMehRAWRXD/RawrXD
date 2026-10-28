// unlinked_symbols_batch_006.cpp
// Batch 6: Omega continued (!RAWR_HAS_MASM) + mesh brain.
// MagBag: asm_mesh_init publishes node handle for batch_001 MagShutdown.
// Omega cathedral ABI: omega_orchestrator.hpp / omega_asm_native_kernel.cpp.
// When RAWR_HAS_MASM: omega_* owned by omega_asm_native_kernel (no ODR).

#include "mag_registry.hpp"

#include <cstdint>
#include <cstring>
#include <atomic>
#include <mutex>
#include <new>

namespace {

struct OmegaStats {
    std::atomic<uint64_t> worldUpdates{0};
    std::atomic<uint64_t> agentsSpawned{0};
    std::atomic<uint64_t> agentSteps{0};
    std::atomic<uint64_t> pipelinesExecuted{0};
} g_omegaStats;

struct MeshState {
    std::mutex mtx;
    std::atomic<bool> initialized{false};
    std::atomic<int> activeNodes{0};
    std::atomic<uint64_t> gossipMessages{0};
    std::atomic<uint64_t> quorumVotes{0};
    void* rootNode = nullptr;
    uint64_t magEpoch = ~0ull;
} g_mesh;

} // namespace

extern "C" {

#if !defined(RAWR_HAS_MASM)

// Cathedral ABI (int returns) — matches omega_orchestrator.hpp
int asm_omega_world_model_update(int metricType, int value) {
    g_omegaStats.worldUpdates.fetch_add(1, std::memory_order_relaxed);
    (void)metricType;
    return value;
}

int asm_omega_agent_spawn(int role) {
    if (role < 0) {
        return -1;
    }
    const auto id = g_omegaStats.agentsSpawned.fetch_add(1, std::memory_order_relaxed) + 1;
    return static_cast<int>(id);
}

int asm_omega_agent_step(int agentId) {
    if (agentId <= 0) {
        return -1;
    }
    g_omegaStats.agentSteps.fetch_add(1, std::memory_order_relaxed);
    return 1;
}

int asm_omega_execute_pipeline() {
    g_omegaStats.pipelinesExecuted.fetch_add(1, std::memory_order_relaxed);
    return 0;
}

void* asm_omega_get_stats() {
    static uint64_t stats[4] = {0, 0, 0, 0};
    stats[0] = g_omegaStats.worldUpdates.load(std::memory_order_relaxed);
    stats[1] = g_omegaStats.agentsSpawned.load(std::memory_order_relaxed);
    stats[2] = g_omegaStats.agentSteps.load(std::memory_order_relaxed);
    stats[3] = g_omegaStats.pipelinesExecuted.load(std::memory_order_relaxed);
    return stats;
}

#endif // !RAWR_HAS_MASM

// Mesh brain — C fallback when Digestion_scanner.asm not linked
int asm_mesh_init() {
    std::lock_guard<std::mutex> lock(g_mesh.mtx);
    const uint64_t ep = mag_registry_epoch();
    if (g_mesh.rootNode != nullptr && ep == g_mesh.magEpoch) {
        g_mesh.initialized.store(true, std::memory_order_relaxed);
        return 0;
    }
    // MagShutdown frees prior handle; allocate fresh and republish.
    g_mesh.rootNode = ::operator new(64, std::nothrow);
    if (g_mesh.rootNode == nullptr) {
        return -1;
    }
        std::memset(g_mesh.rootNode, 0, 64);
        // MagBuf owns delete via asm_mesh_shutdown (batch_001).
        asm_magbuf_register_mesh(g_mesh.rootNode);
    g_mesh.magEpoch = mag_registry_epoch();
    g_mesh.initialized.store(true, std::memory_order_relaxed);
    g_mesh.activeNodes.store(1, std::memory_order_relaxed);
    return 0;
}

int asm_mesh_topology_update(const void* node_info, size_t size) {
    if (!g_mesh.initialized.load(std::memory_order_relaxed) || node_info == nullptr || size == 0) {
        return 0;
    }
    const int delta = static_cast<int>((size & 3u) + 1u);
    g_mesh.activeNodes.fetch_add(delta, std::memory_order_relaxed);
    return 1;
}

uint32_t asm_mesh_topology_active_count() {
    return static_cast<uint32_t>(g_mesh.activeNodes.load(std::memory_order_relaxed));
}

int asm_mesh_dht_xor_distance(const uint8_t* id1, const uint8_t* id2,
                              uint8_t* out_distance) {
    if (id1 == nullptr || id2 == nullptr || out_distance == nullptr) {
        return 0;
    }
    for (int i = 0; i < 32; ++i) {
        out_distance[i] = static_cast<uint8_t>(id1[i] ^ id2[i]);
    }
    return 1;
}

int asm_mesh_dht_find_closest(const uint8_t* target_id, int k, void* out_nodes) {
    if (target_id == nullptr || k <= 0 || out_nodes == nullptr) {
        return 0;
    }
    auto* ids = static_cast<uint32_t*>(out_nodes);
    for (int i = 0; i < k; ++i) {
        ids[i] = static_cast<uint32_t>(target_id[i & 31]) + static_cast<uint32_t>(i);
    }
    return k;
}

int asm_mesh_shard_hash(const void* data, size_t size, uint8_t* out_hash) {
    if (data == nullptr || size == 0 || out_hash == nullptr) {
        return 0;
    }
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint8_t h = 0;
    for (size_t i = 0; i < size; ++i) {
        h ^= static_cast<uint8_t>(bytes[i] + static_cast<uint8_t>(i));
    }
    out_hash[0] = h;
    return 1;
}

int asm_mesh_shard_bitfield(int shard_id, void* out_bitfield) {
    if (shard_id < 0 || out_bitfield == nullptr) {
        return 0;
    }
    *static_cast<uint64_t*>(out_bitfield) = (1ULL << (shard_id & 63));
    return 1;
}

int asm_mesh_gossip_disseminate(const void* message, size_t size) {
    if (message == nullptr || size == 0) {
        return 0;
    }
    g_mesh.gossipMessages.fetch_add(1, std::memory_order_relaxed);
    return 1;
}

int asm_mesh_quorum_vote(int proposal_id, bool vote, void* out_result) {
    if (proposal_id <= 0 || out_result == nullptr) {
        return 0;
    }
    g_mesh.quorumVotes.fetch_add(1, std::memory_order_relaxed);
    *static_cast<int*>(out_result) = vote ? 1 : 0;
    return 1;
}

int asm_mesh_crdt_merge(void* local_state, const void* remote_state, void* out_merged) {
    if (local_state == nullptr || remote_state == nullptr || out_merged == nullptr) {
        return 0;
    }
    std::memcpy(out_merged, local_state, 32);
    const auto* r = static_cast<const uint8_t*>(remote_state);
    auto* m = static_cast<uint8_t*>(out_merged);
    for (int i = 0; i < 32; ++i) {
        if (r[i] > m[i]) {
            m[i] = r[i];
        }
    }
    return 1;
}

} // extern "C"
