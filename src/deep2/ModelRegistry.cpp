// ============================================================================
// ModelRegistry.cpp — Model Registry Implementation
// ============================================================================

#include "ModelRegistry.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <algorithm>

namespace rawr {

ModelRegistry& ModelRegistry::Get() {
    static ModelRegistry instance;
    return instance;
}

uint32_t ModelRegistry::RegisterModel(const char* path, const char* name) {
    std::lock_guard<std::mutex> lock(m_mutex);

    uint32_t id = m_nextId++;
    ModelInfo info = {};
    info.path = path ? path : "";
    info.name = name ? name : "unknown";
    info.loaded = false;
    info.activeSessions = 0;

    m_models[id] = info;
    RawrRuntime::Get().Log(LogLevel::Info, "Model registered");
    return id;
}

bool ModelRegistry::UnregisterModel(uint32_t modelId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_models.find(modelId);
    if (it == m_models.end()) return false;
    m_models.erase(it);
    RawrRuntime::Get().Log(LogLevel::Info, "Model unregistered");
    return true;
}

ModelInfo* ModelRegistry::GetModel(uint32_t modelId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_models.find(modelId);
    return (it != m_models.end()) ? &it->second : nullptr;
}

ModelInfo* ModelRegistry::FindModel(const char* name) {
    if (!name) return nullptr;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& [id, info] : m_models) {
        if (info.name == name) return &info;
    }
    return nullptr;
}

void ModelRegistry::SetModelLoaded(uint32_t modelId, bool loaded) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_models.find(modelId);
    if (it != m_models.end()) {
        it->second.loaded = loaded;
    }
}

void ModelRegistry::AddSession(uint32_t modelId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_models.find(modelId);
    if (it != m_models.end()) {
        it->second.activeSessions++;
    }
}

void ModelRegistry::RemoveSession(uint32_t modelId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_models.find(modelId);
    if (it != m_models.end() && it->second.activeSessions > 0) {
        it->second.activeSessions--;
    }
}

uint32_t ModelRegistry::GetModelCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<uint32_t>(m_models.size());
}

uint32_t ModelRegistry::GetLoadedCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<uint32_t>(std::count_if(m_models.begin(), m_models.end(),
        [](const auto& pair) { return pair.second.loaded; }));
}

uint64_t ModelRegistry::GetTotalVRAMUsage() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    uint64_t total = 0;
    for (const auto& [id, info] : m_models) {
        total += info.vramUsage;
    }
    return total;
}

std::vector<ModelInfo> ModelRegistry::ListModels() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ModelInfo> result;
    for (const auto& [id, info] : m_models) {
        result.push_back(info);
    }
    return result;
}

} // namespace rawr
