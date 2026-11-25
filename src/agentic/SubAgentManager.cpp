// =============================================================================
// SubAgentManager.cpp — RawrXD::Agentic swarm/sharding manager (real state).
// =============================================================================
// Singleton managing swarm topology + model-shard registry. Task execution
// delegates to the global subagent_core SubAgentManager (one persistent
// instance); without an inference engine the delegate fails closed and no
// fabricated result is produced. Shard "loading" validates the shard file
// and records its size — it does not fake model weights.
// =============================================================================
#include "SubAgentManager.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>

#include "../subagent_core.h"

namespace RawrXD::Agentic {

SubAgentManager& SubAgentManager::instance() {
    static SubAgentManager mgr;
    return mgr;
}

bool SubAgentManager::initializeSwarm(const SwarmTopology& topology,
                                      const std::string& coordinatorModel) {
    std::lock_guard<std::mutex> lock(m_mtx);
    if (m_initialized) return false;
    if (topology.workerCount == 0) return false;
    m_topology = topology;
    m_coordinatorModel = coordinatorModel;
    m_initialized = true;
    return true;
}

void SubAgentManager::shutdownSwarm() {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_initialized = false;
    m_activeShards.clear();
    m_shardMap.clear();
}

uint32_t SubAgentManager::executeSwarmTask(
    const std::string& taskDescription) {
    if (taskDescription.empty()) return 0;
    std::string queued;
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        if (!m_initialized) return 0;  // fail closed: swarm not initialized
        if (!m_pendingBroadcasts.empty()) {
            queued = m_pendingBroadcasts.front();
            m_pendingBroadcasts.erase(m_pendingBroadcasts.begin());
        }
    }
    const std::string task = queued.empty() ? taskDescription
                                            : queued + " " + taskDescription;
    // Delegate to the real subagent_core manager (global class, single
    // process-wide instance). Without an engine it throws -> fail closed.
    try {
        static ::SubAgentManager& core = []() -> ::SubAgentManager& {
            static ::SubAgentManager mgr(nullptr);
            return mgr;
        }();
        const std::string id = core.spawnSubAgent("swarm", task, task);
        return id.empty() ? 0u : 1u;
    } catch (...) {
        return 0;
    }
}

bool SubAgentManager::isSwarmActive() const {
    std::lock_guard<std::mutex> lock(m_mtx);
    return m_initialized;
}

bool SubAgentManager::loadModelShard(const std::string& shardPath,
                                     uint32_t gpuIndex) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(shardPath, ec)) return false;
    const auto size = std::filesystem::file_size(shardPath, ec);
    if (ec || size == 0) return false;
    std::lock_guard<std::mutex> lock(m_mtx);
    ShardStatus st;
    st.path = shardPath;
    st.gpuIndex = gpuIndex;
    st.isLoaded = true;
    st.sizeInBytes = (size_t)size;
    m_shardMap[shardPath] = st;
    if (std::find(m_activeShards.begin(), m_activeShards.end(), shardPath) ==
        m_activeShards.end())
        m_activeShards.push_back(shardPath);
    return true;
}

void SubAgentManager::synchronizeShards() {
    std::lock_guard<std::mutex> lock(m_mtx);
    internal_verifyShardIntegrity();
    internal_rebalanceLoad();
}

size_t SubAgentManager::getActiveShardCount() const {
    std::lock_guard<std::mutex> lock(m_mtx);
    return m_activeShards.size();
}

void SubAgentManager::broadcastCommand(const std::string& command) {
    std::lock_guard<std::mutex> lock(m_mtx);
    if (command.empty() || !m_initialized) return;
    // Queue the command for workers; execution happens on the next
    // executeSwarmTask cycle (never re-enter the task path under this lock).
    m_pendingBroadcasts.push_back(command);
}

float SubAgentManager::getSwarmLoadAverage() const {
    std::lock_guard<std::mutex> lock(m_mtx);
    if (m_activeShards.empty()) return 0.0f;
    return (float)m_activeShards.size() / (float)(m_topology.workerCount + 1);
}

void SubAgentManager::internal_rebalanceLoad() {
    // Round-robin shard->gpu assignment by index.
    uint32_t gpu = 0;
    for (auto& [path, st] : m_shardMap) {
        st.gpuIndex = gpu;
        gpu = (gpu + 1) % 8;
    }
}

void SubAgentManager::internal_verifyShardIntegrity() {
    for (auto it = m_shardMap.begin(); it != m_shardMap.end();) {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(it->first, ec) ||
            std::filesystem::file_size(it->first, ec) == 0) {
            it = m_shardMap.erase(it);
        } else {
            ++it;
        }
    }
    m_activeShards.erase(
        std::remove_if(m_activeShards.begin(), m_activeShards.end(),
                       [this](const std::string& p) {
                           return m_shardMap.find(p) == m_shardMap.end();
                       }),
        m_activeShards.end());
}

}  // namespace RawrXD::Agentic