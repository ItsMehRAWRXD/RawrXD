#include "metacognitive/MetaCognitiveEngine.hpp"
#include <chrono>
#include <algorithm>

namespace MetaCognitive {

std::mutex MetaCognitiveEngine::s_mutex;
bool MetaCognitiveEngine::s_initialized = false;
std::map<std::string, ReflectionPool> MetaCognitiveEngine::s_pools;
std::map<std::string, IntrospectionModule> MetaCognitiveEngine::s_modules;
std::map<std::string, SelfModel> MetaCognitiveEngine::s_models;
std::map<std::string, AwarenessMonitor> MetaCognitiveEngine::s_monitors;
std::map<std::string, CognitiveBias> MetaCognitiveEngine::s_biases;
int64_t MetaCognitiveEngine::s_tickCount = 0;

void MetaCognitiveEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
}

void MetaCognitiveEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_pools.clear();
    s_modules.clear();
    s_models.clear();
    s_monitors.clear();
    s_biases.clear();
}

std::string MetaCognitiveEngine::CreateReflectionPool(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int poolCounter = 0;
    std::string poolId = "reflection_pool_" + std::to_string(++poolCounter);
    
    ReflectionPool pool;
    pool.poolId = poolId;
    pool.name = name;
    pool.depth = 1.0f;
    pool.clarity = 1.0f;
    pool.createdTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_pools[poolId] = pool;
    return poolId;
}

bool MetaCognitiveEngine::AddReflection(const std::string& poolId, const std::string& reflectionId, const nlohmann::json& reflection) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_pools.find(poolId);
    if (it == s_pools.end()) return false;
    it->second.reflectionIds.push_back(reflectionId);
    it->second.insights[reflectionId] = reflection;
    return true;
}

bool MetaCognitiveEngine::DeepenPool(const std::string& poolId, float depth) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_pools.find(poolId);
    if (it == s_pools.end()) return false;
    it->second.depth = std::min(10.0f, it->second.depth + depth);
    return true;
}

bool MetaCognitiveEngine::ClarifyPool(const std::string& poolId, float clarity) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_pools.find(poolId);
    if (it == s_pools.end()) return false;
    it->second.clarity = std::min(1.0f, std::max(0.0f, clarity));
    return true;
}

ReflectionPool MetaCognitiveEngine::GetPool(const std::string& poolId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_pools.find(poolId);
    if (it != s_pools.end()) return it->second;
    return ReflectionPool{};
}

std::vector<ReflectionPool> MetaCognitiveEngine::GetAllPools() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<ReflectionPool> result;
    for (const auto& [id, pool] : s_pools) {
        result.push_back(pool);
    }
    return result;
}

std::string MetaCognitiveEngine::InstallIntrospectionModule(const std::string& name, const std::string& target) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int moduleCounter = 0;
    std::string moduleId = "introspection_module_" + std::to_string(++moduleCounter);
    
    IntrospectionModule module;
    module.moduleId = moduleId;
    module.name = name;
    module.targetSystem = target;
    module.sensitivity = 0.5f;
    module.accuracy = 0.8f;
    module.isActive = false;
    module.installedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_modules[moduleId] = module;
    return moduleId;
}

bool MetaCognitiveEngine::CalibrateSensitivity(const std::string& moduleId, float sensitivity) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_modules.find(moduleId);
    if (it == s_modules.end()) return false;
    it->second.sensitivity = std::min(1.0f, std::max(0.0f, sensitivity));
    return true;
}

bool MetaCognitiveEngine::ImproveAccuracy(const std::string& moduleId, float accuracy) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_modules.find(moduleId);
    if (it == s_modules.end()) return false;
    it->second.accuracy = std::min(1.0f, std::max(0.0f, accuracy));
    return true;
}

bool MetaCognitiveEngine::ActivateModule(const std::string& moduleId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_modules.find(moduleId);
    if (it == s_modules.end()) return false;
    it->second.isActive = true;
    return true;
}

bool MetaCognitiveEngine::DeactivateModule(const std::string& moduleId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_modules.find(moduleId);
    if (it == s_modules.end()) return false;
    it->second.isActive = false;
    return true;
}

IntrospectionModule MetaCognitiveEngine::GetModule(const std::string& moduleId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_modules.find(moduleId);
    if (it != s_modules.end()) return it->second;
    return IntrospectionModule{};
}

std::vector<IntrospectionModule> MetaCognitiveEngine::GetAllModules() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<IntrospectionModule> result;
    for (const auto& [id, module] : s_modules) {
        result.push_back(module);
    }
    return result;
}

std::string MetaCognitiveEngine::ConstructSelfModel(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int modelCounter = 0;
    std::string modelId = "self_model_" + std::to_string(++modelCounter);
    
    SelfModel model;
    model.modelId = modelId;
    model.name = name;
    model.fidelity = 0.5f;
    model.completeness = 0.3f;
    model.consistency = 1.0f;
    model.constructedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_models[modelId] = model;
    return modelId;
}

bool MetaCognitiveEngine::RefineFidelity(const std::string& modelId, float fidelity) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_models.find(modelId);
    if (it == s_models.end()) return false;
    it->second.fidelity = std::min(1.0f, std::max(0.0f, fidelity));
    return true;
}

bool MetaCognitiveEngine::ExpandCompleteness(const std::string& modelId, float completeness) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_models.find(modelId);
    if (it == s_models.end()) return false;
    it->second.completeness = std::min(1.0f, std::max(0.0f, completeness));
    return true;
}

bool MetaCognitiveEngine::EnsureConsistency(const std::string& modelId, float consistency) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_models.find(modelId);
    if (it == s_models.end()) return false;
    it->second.consistency = std::min(1.0f, std::max(0.0f, consistency));
    return true;
}

bool MetaCognitiveEngine::UpdateAttribute(const std::string& modelId, const std::string& attr, const nlohmann::json& value) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_models.find(modelId);
    if (it == s_models.end()) return false;
    it->second.attributes[attr] = value;
    return true;
}

SelfModel MetaCognitiveEngine::GetModel(const std::string& modelId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_models.find(modelId);
    if (it != s_models.end()) return it->second;
    return SelfModel{};
}

std::vector<SelfModel> MetaCognitiveEngine::GetAllModels() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<SelfModel> result;
    for (const auto& [id, model] : s_models) {
        result.push_back(model);
    }
    return result;
}

std::string MetaCognitiveEngine::ActivateAwarenessMonitor(const std::string& name, const std::string& type) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int monitorCounter = 0;
    std::string monitorId = "awareness_monitor_" + std::to_string(++monitorCounter);
    
    AwarenessMonitor monitor;
    monitor.monitorId = monitorId;
    monitor.name = name;
    monitor.awarenessType = type;
    monitor.level = 0.5f;
    monitor.stability = 1.0f;
    monitor.activatedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    monitor.isMonitoring = false;
    
    s_monitors[monitorId] = monitor;
    return monitorId;
}

bool MetaCognitiveEngine::AdjustLevel(const std::string& monitorId, float level) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_monitors.find(monitorId);
    if (it == s_monitors.end()) return false;
    it->second.level = std::min(1.0f, std::max(0.0f, level));
    return true;
}

bool MetaCognitiveEngine::StabilizeMonitor(const std::string& monitorId, float stability) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_monitors.find(monitorId);
    if (it == s_monitors.end()) return false;
    it->second.stability = std::min(1.0f, std::max(0.0f, stability));
    return true;
}

bool MetaCognitiveEngine::StartMonitoring(const std::string& monitorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_monitors.find(monitorId);
    if (it == s_monitors.end()) return false;
    it->second.isMonitoring = true;
    return true;
}

bool MetaCognitiveEngine::StopMonitoring(const std::string& monitorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_monitors.find(monitorId);
    if (it == s_monitors.end()) return false;
    it->second.isMonitoring = false;
    return true;
}

AwarenessMonitor MetaCognitiveEngine::GetMonitor(const std::string& monitorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_monitors.find(monitorId);
    if (it != s_monitors.end()) return it->second;
    return AwarenessMonitor{};
}

std::vector<AwarenessMonitor> MetaCognitiveEngine::GetAllMonitors() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<AwarenessMonitor> result;
    for (const auto& [id, monitor] : s_monitors) {
        result.push_back(monitor);
    }
    return result;
}

std::string MetaCognitiveEngine::IdentifyBias(const std::string& name, const std::string& type) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int biasCounter = 0;
    std::string biasId = "cognitive_bias_" + std::to_string(++biasCounter);
    
    CognitiveBias bias;
    bias.biasId = biasId;
    bias.name = name;
    bias.biasType = type;
    bias.strength = 0.5f;
    bias.detectability = 0.3f;
    bias.isMitigated = false;
    bias.identifiedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_biases[biasId] = bias;
    return biasId;
}

bool MetaCognitiveEngine::MeasureStrength(const std::string& biasId, float strength) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_biases.find(biasId);
    if (it == s_biases.end()) return false;
    it->second.strength = std::min(1.0f, std::max(0.0f, strength));
    return true;
}

bool MetaCognitiveEngine::ImproveDetectability(const std::string& biasId, float detectability) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_biases.find(biasId);
    if (it == s_biases.end()) return false;
    it->second.detectability = std::min(1.0f, std::max(0.0f, detectability));
    return true;
}

bool MetaCognitiveEngine::MitigateBias(const std::string& biasId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_biases.find(biasId);
    if (it == s_biases.end()) return false;
    it->second.isMitigated = true;
    it->second.strength *= 0.5f;
    return true;
}

CognitiveBias MetaCognitiveEngine::GetBias(const std::string& biasId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_biases.find(biasId);
    if (it != s_biases.end()) return it->second;
    return CognitiveBias{};
}

std::vector<CognitiveBias> MetaCognitiveEngine::GetAllBiases() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CognitiveBias> result;
    for (const auto& [id, bias] : s_biases) {
        result.push_back(bias);
    }
    return result;
}

float MetaCognitiveEngine::CalculateAverageReflectionDepth() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_pools.empty()) return 0.0f;
    float total = 0.0f;
    for (const auto& [id, pool] : s_pools) {
        total += pool.depth;
    }
    return total / s_pools.size();
}

float MetaCognitiveEngine::CalculateTotalIntrospectionAccuracy() {
    std::lock_guard<std::mutex> lock(s_mutex);
    float total = 0.0f;
    for (const auto& [id, module] : s_modules) {
        if (module.isActive) {
            total += module.accuracy;
        }
    }
    return total;
}

int MetaCognitiveEngine::GetActiveMonitorCount() {
    std::lock_guard<std::mutex> lock(s_mutex);
    int count = 0;
    for (const auto& [id, monitor] : s_monitors) {
        if (monitor.isMonitoring) count++;
    }
    return count;
}

nlohmann::json MetaCognitiveEngine::GetMetaCognitiveMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json metrics;
    metrics["poolCount"] = s_pools.size();
    metrics["moduleCount"] = s_modules.size();
    metrics["modelCount"] = s_models.size();
    metrics["monitorCount"] = s_monitors.size();
    metrics["biasCount"] = s_biases.size();
    metrics["averageReflectionDepth"] = CalculateAverageReflectionDepth();
    metrics["totalIntrospectionAccuracy"] = CalculateTotalIntrospectionAccuracy();
    metrics["activeMonitors"] = GetActiveMonitorCount();
    metrics["mitigatedBiases"] = std::count_if(s_biases.begin(), s_biases.end(), 
        [](const auto& b) { return b.second.isMitigated; });
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json MetaCognitiveEngine::GenerateMetaCognitiveReport() {
    nlohmann::json report;
    report["metrics"] = GetMetaCognitiveMetrics();
    report["reflectionPools"] = nlohmann::json::array();
    report["introspectionModules"] = nlohmann::json::array();
    report["selfModels"] = nlohmann::json::array();
    
    for (const auto& pool : GetAllPools()) {
        nlohmann::json p;
        p["id"] = pool.poolId;
        p["name"] = pool.name;
        p["depth"] = pool.depth;
        p["clarity"] = pool.clarity;
        report["reflectionPools"].push_back(p);
    }
    
    return report;
}

void MetaCognitiveEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, model] : s_models) {
        if (model.fidelity < 1.0f) {
            model.fidelity = std::min(1.0f, model.fidelity + 0.0001f);
        }
    }
}

bool MetaCognitiveEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace MetaCognitive
