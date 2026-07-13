// RawrXD Model Residency Manager Implementation
// Phase O.3: Track model locations across cluster, avoid redundant reloads

#include "ModelResidencyManager.hpp"
#include "ClusterManager.hpp"
#include "DistributedScheduler.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Distributed {

ModelResidencyManager::ModelResidencyManager(std::shared_ptr<ClusterManager> clusterManager)
    : running_(false)
    , initialized_(false)
    , clusterManager_(clusterManager)
    , scheduler_(nullptr)
    , residencyCallback_(nullptr)
{
}

ModelResidencyManager::~ModelResidencyManager() {
    shutdown();
}

bool ModelResidencyManager::initialize(const ResidencyConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    running_ = true;
    
    // Start background threads
    residencyThread_ = std::thread(
        &ModelResidencyManager::residencyLoop, this);
    migrationThread_ = std::thread(
        &ModelResidencyManager::migrationLoop, this);
    predictiveThread_ = std::thread(
        &ModelResidencyManager::predictiveLoop, this);
    
    initialized_ = true;
    return true;
}

bool ModelResidencyManager::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    
    // Stop threads
    if (residencyThread_.joinable()) {
        residencyThread_.join();
    }
    if (migrationThread_.joinable()) {
        migrationThread_.join();
    }
    if (predictiveThread_.joinable()) {
        predictiveThread_.join();
    }
    
    initialized_ = false;
    return true;
}

// Model registration
bool ModelResidencyManager::registerModel(const ModelInfo& modelInfo) {
    std::lock_guard<std::mutex> lock(modelsMutex_);
    
    if (registeredModels_.find(modelInfo.modelId) != registeredModels_.end()) {
        return false; // Already registered
    }
    
    registeredModels_[modelInfo.modelId] = modelInfo;
    
    // Initialize residency tracking for all nodes
    auto nodes = clusterManager_->getAllNodes();
    for (const auto& node : nodes) {
        ModelResidency residency;
        residency.modelId = modelInfo.modelId;
        residency.nodeId = node.nodeId;
        residency.state = ResidencyState::NOT_LOADED;
        
        std::lock_guard<std::mutex> resLock(residenciesMutex_);
        residencies_[modelInfo.modelId][node.nodeId] = residency;
    }
    
    return true;
}

bool ModelResidencyManager::unregisterModel(const std::string& modelId) {
    std::lock_guard<std::mutex> lock(modelsMutex_);
    
    auto it = registeredModels_.find(modelId);
    if (it == registeredModels_.end()) {
        return false;
    }
    
    // Unload from all nodes first
    {
        std::lock_guard<std::mutex> resLock(residenciesMutex_);
        auto resIt = residencies_.find(modelId);
        if (resIt != residencies_.end()) {
            for (auto& pair : resIt->second) {
                if (pair.second.state == ResidencyState::LOADED) {
                    requestModelUnload(modelId, pair.first);
                }
            }
            residencies_.erase(resIt);
        }
    }
    
    registeredModels_.erase(it);
    return true;
}

bool ModelResidencyManager::updateModelInfo(const std::string& modelId, const ModelInfo& info) {
    std::lock_guard<std::mutex> lock(modelsMutex_);
    
    auto it = registeredModels_.find(modelId);
    if (it == registeredModels_.end()) {
        return false;
    }
    
    it->second = info;
    return true;
}

// Model catalog
std::vector<ModelInfo> ModelResidencyManager::getRegisteredModels() const {
    std::lock_guard<std::mutex> lock(modelsMutex_);
    
    std::vector<ModelInfo> result;
    for (const auto& pair : registeredModels_) {
        result.push_back(pair.second);
    }
    return result;
}

ModelInfo ModelResidencyManager::getModelInfo(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(modelsMutex_);
    
    auto it = registeredModels_.find(modelId);
    if (it != registeredModels_.end()) {
        return it->second;
    }
    return ModelInfo();
}

bool ModelResidencyManager::isModelRegistered(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(modelsMutex_);
    return registeredModels_.find(modelId) != registeredModels_.end();
}

// Residency queries
std::vector<ModelResidency> ModelResidencyManager::getResidencies(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(residenciesMutex_);
    
    std::vector<ModelResidency> result;
    auto it = residencies_.find(modelId);
    if (it != residencies_.end()) {
        for (const auto& pair : it->second) {
            result.push_back(pair.second);
        }
    }
    return result;
}

std::vector<ModelResidency> ModelResidencyManager::getResidenciesOnNode(const std::string& nodeId) const {
    std::lock_guard<std::mutex> lock(residenciesMutex_);
    
    std::vector<ModelResidency> result;
    for (const auto& modelPair : residencies_) {
        auto it = modelPair.second.find(nodeId);
        if (it != modelPair.second.end()) {
            result.push_back(it->second);
        }
    }
    return result;
}

ModelResidency ModelResidencyManager::getResidency(const std::string& modelId, const std::string& nodeId) const {
    std::lock_guard<std::mutex> lock(residenciesMutex_);
    
    auto modelIt = residencies_.find(modelId);
    if (modelIt != residencies_.end()) {
        auto nodeIt = modelIt->second.find(nodeId);
        if (nodeIt != modelIt->second.end()) {
            return nodeIt->second;
        }
    }
    return ModelResidency();
}

// Placement decisions
PlacementDecision ModelResidencyManager::decidePlacement(const std::string& modelId, 
                                                           const std::vector<std::string>& candidateNodes) {
    PlacementDecision decision;
    decision.modelId = modelId;
    decision.shouldLoad = false;
    decision.shouldMigrate = false;
    
    auto modelInfo = getModelInfo(modelId);
    if (modelInfo.modelId.empty()) {
        decision.reason = "Model not registered";
        return decision;
    }
    
    // Check if already loaded on any candidate
    for (const auto& nodeId : candidateNodes) {
        auto residency = getResidency(modelId, nodeId);
        if (residency.state == ResidencyState::LOADED) {
            decision.targetNodeId = nodeId;
            decision.shouldLoad = false;
            decision.reason = "Model already loaded on node";
            return decision;
        }
    }
    
    // Find best node to load on
    std::vector<std::pair<std::string, float>> scores;
    for (const auto& nodeId : candidateNodes) {
        float score = calculateAffinityScore(modelId, nodeId);
        score += calculateLoadScore(nodeId);
        scores.push_back({nodeId, score});
    }
    
    // Sort by score
    std::sort(scores.begin(), scores.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    if (!scores.empty()) {
        decision.targetNodeId = scores[0].first;
        decision.shouldLoad = true;
        decision.reason = "Selected based on placement strategy";
        decision.estimatedLoadTimeMs = static_cast<uint32_t>(modelInfo.fileSize / (100 * 1024 * 1024)); // Estimate
        decision.estimatedMemoryUsage = modelInfo.memorySize;
        
        // Add alternatives
        for (size_t i = 1; i < scores.size() && i < 3; i++) {
            decision.alternativeNodes.push_back(scores[i].first);
        }
    } else {
        decision.reason = "No suitable nodes found";
    }
    
    return decision;
}

std::vector<std::string> ModelResidencyManager::findNodesWithModel(const std::string& modelId) const {
    std::vector<std::string> result;
    auto residencies = getResidencies(modelId);
    
    for (const auto& residency : residencies) {
        if (residency.state == ResidencyState::LOADED) {
            result.push_back(residency.nodeId);
        }
    }
    
    return result;
}

std::vector<std::string> ModelResidencyManager::findNodesWithoutModel(const std::string& modelId) const {
    std::vector<std::string> result;
    auto nodes = clusterManager_->getAllNodes();
    auto loadedNodes = findNodesWithModel(modelId);
    
    for (const auto& node : nodes) {
        if (std::find(loadedNodes.begin(), loadedNodes.end(), node.nodeId) == loadedNodes.end()) {
            result.push_back(node.nodeId);
        }
    }
    
    return result;
}

std::string ModelResidencyManager::findBestNodeForModel(const std::string& modelId) const {
    auto nodes = clusterManager_->getHealthyNodes();
    if (nodes.empty()) {
        return "";
    }
    
    // Score nodes
    std::vector<std::pair<std::string, float>> scores;
    for (const auto& node : nodes) {
        float score = calculateAffinityScore(modelId, node.nodeId);
        score += calculateLoadScore(node.nodeId);
        scores.push_back({node.nodeId, score});
    }
    
    // Return best
    auto it = std::max_element(scores.begin(), scores.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    
    return it != scores.end() ? it->first : "";
}

// Residency management
bool ModelResidencyManager::requestModelLoad(const std::string& modelId, const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(residenciesMutex_);
    
    auto modelIt = residencies_.find(modelId);
    if (modelIt == residencies_.end()) {
        return false;
    }
    
    auto nodeIt = modelIt->second.find(nodeId);
    if (nodeIt == modelIt->second.end()) {
        return false;
    }
    
    auto oldState = nodeIt->second.state;
    nodeIt->second.state = ResidencyState::LOADING;
    nodeIt->second.loadingProgress = 0;
    
    notifyResidencyChange(modelId, nodeId, oldState, ResidencyState::LOADING);
    
    return true;
}

bool ModelResidencyManager::requestModelUnload(const std::string& modelId, const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(residenciesMutex_);
    
    auto modelIt = residencies_.find(modelId);
    if (modelIt == residencies_.end()) {
        return false;
    }
    
    auto nodeIt = modelIt->second.find(nodeId);
    if (nodeIt == modelIt->second.end()) {
        return false;
    }
    
    auto oldState = nodeIt->second.state;
    nodeIt->second.state = ResidencyState::UNLOADING;
    
    notifyResidencyChange(modelId, nodeId, oldState, ResidencyState::UNLOADING);
    
    return true;
}

bool ModelResidencyManager::updateResidencyState(const std::string& modelId, const std::string& nodeId,
                                                   ResidencyState state) {
    std::lock_guard<std::mutex> lock(residenciesMutex_);
    
    auto modelIt = residencies_.find(modelId);
    if (modelIt == residencies_.end()) {
        return false;
    }
    
    auto nodeIt = modelIt->second.find(nodeId);
    if (nodeIt == modelIt->second.end()) {
        return false;
    }
    
    auto oldState = nodeIt->second.state;
    nodeIt->second.state = state;
    
    if (state == ResidencyState::LOADED) {
        nodeIt->second.loadedAt = std::chrono::steady_clock::now();
        nodeIt->second.loadingProgress = 100;
        
        // Update stats
        auto loadTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - nodeIt->second.loadedAt).count();
        stats_.totalLoadTimeMs += loadTime;
        stats_.loadCount++;
    }
    
    notifyResidencyChange(modelId, nodeId, oldState, state);
    
    return true;
}

bool ModelResidencyManager::recordModelAccess(const std::string& modelId, const std::string& nodeId,
                                               uint64_t tokens, uint64_t inferenceTimeMs) {
    std::lock_guard<std::mutex> lock(residenciesMutex_);
    
    auto modelIt = residencies_.find(modelId);
    if (modelIt == residencies_.end()) {
        return false;
    }
    
    auto nodeIt = modelIt->second.find(nodeId);
    if (nodeIt == modelIt->second.end()) {
        return false;
    }
    
    nodeIt->second.requestCount++;
    nodeIt->second.tokenCount += tokens;
    nodeIt->second.totalInferenceTimeMs += inferenceTimeMs;
    nodeIt->second.lastUsedAt = std::chrono::steady_clock::now();
    nodeIt->second.lastAccessedAt = std::chrono::steady_clock::now();
    
    return true;
}

// Migration
std::string ModelResidencyManager::startMigration(const std::string& modelId, 
                                                    const std::string& sourceNodeId,
                                                    const std::string& targetNodeId) {
    std::string taskId = generateTaskId();
    
    MigrationTask task;
    task.taskId = taskId;
    task.modelId = modelId;
    task.sourceNodeId = sourceNodeId;
    task.targetNodeId = targetNodeId;
    task.status = MigrationTask::Status::PENDING;
    task.progress = 0;
    task.startedAt = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(migrationsMutex_);
        migrations_[taskId] = task;
    }
    
    // Update residency states
    updateResidencyState(modelId, sourceNodeId, ResidencyState::MIGRATING);
    
    stats_.totalMigrations++;
    
    return taskId;
}

bool ModelResidencyManager::cancelMigration(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(migrationsMutex_);
    
    auto it = migrations_.find(taskId);
    if (it == migrations_.end()) {
        return false;
    }
    
    it->second.status = MigrationTask::Status::FAILED;
    it->second.errorMessage = "Cancelled by user";
    
    return true;
}

MigrationTask ModelResidencyManager::getMigrationStatus(const std::string& taskId) const {
    std::lock_guard<std::mutex> lock(migrationsMutex_);
    
    auto it = migrations_.find(taskId);
    if (it != migrations_.end()) {
        return it->second;
    }
    return MigrationTask();
}

std::vector<MigrationTask> ModelResidencyManager::getActiveMigrations() const {
    std::lock_guard<std::mutex> lock(migrationsMutex_);
    
    std::vector<MigrationTask> result;
    for (const auto& pair : migrations_) {
        if (pair.second.status == MigrationTask::Status::IN_PROGRESS ||
            pair.second.status == MigrationTask::Status::COPYING ||
            pair.second.status == MigrationTask::Status::VERIFYING) {
            result.push_back(pair.second);
        }
    }
    return result;
}

// Preloading
std::vector<std::string> ModelResidencyManager::getPreloadRecommendations() const {
    std::vector<std::string> recommendations;
    
    if (!config_.enablePredictiveLoading) {
        return recommendations;
    }
    
    // Analyze access patterns
    for (const auto& pair : accessPatterns_) {
        if (pair.second.confidence > 0.7f) {
            recommendations.push_back(pair.first);
        }
    }
    
    return recommendations;
}

bool ModelResidencyManager::preloadModel(const std::string& modelId, const std::string& nodeId) {
    auto decision = decidePlacement(modelId, {nodeId});
    if (!decision.shouldLoad) {
        return false;
    }
    
    return requestModelLoad(modelId, decision.targetNodeId);
}

// Replication
bool ModelResidencyManager::replicateModel(const std::string& modelId, uint32_t targetReplicas) {
    auto currentReplicas = findNodesWithModel(modelId);
    
    if (currentReplicas.size() >= targetReplicas) {
        return true; // Already replicated enough
    }
    
    auto availableNodes = findNodesWithoutModel(modelId);
    uint32_t needed = targetReplicas - static_cast<uint32_t>(currentReplicas.size());
    
    for (uint32_t i = 0; i < needed && i < availableNodes.size(); i++) {
        requestModelLoad(modelId, availableNodes[i]);
    }
    
    return true;
}

bool ModelResidencyManager::ensureReplication(const std::string& modelId) {
    return replicateModel(modelId, config_.minReplicas);
}

// Cleanup
std::vector<std::string> ModelResidencyManager::getUnloadRecommendations() const {
    std::vector<std::string> recommendations;
    
    if (!config_.autoUnloadUnused) {
        return recommendations;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto threshold = std::chrono::minutes(config_.unloadAfterIdleMinutes);
    
    std::lock_guard<std::mutex> lock(residenciesMutex_);
    for (const auto& modelPair : residencies_) {
        for (const auto& nodePair : modelPair.second) {
            if (nodePair.second.state == ResidencyState::LOADED) {
                auto idleTime = now - nodePair.second.lastUsedAt;
                if (idleTime > threshold) {
                    recommendations.push_back(modelPair.first + ":" + nodePair.first);
                }
            }
        }
    }
    
    return recommendations;
}

bool ModelResidencyManager::unloadUnusedModels() {
    auto recommendations = getUnloadRecommendations();
    
    for (const auto& rec : recommendations) {
        auto colonPos = rec.find(':');
        if (colonPos != std::string::npos) {
            std::string modelId = rec.substr(0, colonPos);
            std::string nodeId = rec.substr(colonPos + 1);
            requestModelUnload(modelId, nodeId);
        }
    }
    
    return !recommendations.empty();
}

bool ModelResidencyManager::handleMemoryPressure(const std::string& nodeId) {
    if (!config_.aggressiveCleanupUnderPressure) {
        return false;
    }
    
    // Find least recently used models on this node
    std::vector<std::pair<std::string, std::chrono::steady_clock::time_point>> candidates;
    
    {
        std::lock_guard<std::mutex> lock(residenciesMutex_);
        for (const auto& modelPair : residencies_) {
            auto nodeIt = modelPair.second.find(nodeId);
            if (nodeIt != modelPair.second.end() &&
                nodeIt->second.state == ResidencyState::LOADED) {
                candidates.push_back({modelPair.first, nodeIt->second.lastUsedAt});
            }
        }
    }
    
    // Sort by last used time
    std::sort(candidates.begin(), candidates.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    
    // Unload oldest models until pressure relieved
    bool unloaded = false;
    for (const auto& candidate : candidates) {
        if (requestModelUnload(candidate.first, nodeId)) {
            unloaded = true;
            // Check if we've freed enough memory
            break;
        }
    }
    
    return unloaded;
}

// Statistics
ModelResidencyManager::ResidencyStats ModelResidencyManager::getStats() const {
    ResidencyStats stats;
    
    stats.totalModelsRegistered = registeredModels_.size();
    
    uint64_t totalResidencies = 0;
    for (const auto& modelPair : residencies_) {
        totalResidencies += modelPair.second.size();
    }
    stats.totalResidencies = totalResidencies;
    
    stats.totalMigrations = stats_.totalMigrations.load();
    stats.totalPreloads = stats_.totalPreloads.load();
    stats.totalEvictions = stats_.totalEvictions.load();
    
    uint64_t loadCount = stats_.loadCount.load();
    if (loadCount > 0) {
        stats.avgLoadTimeMs = stats_.totalLoadTimeMs.load() / loadCount;
    }
    
    return stats;
}

void ModelResidencyManager::resetStats() {
    stats_.totalMigrations = 0;
    stats_.totalPreloads = 0;
    stats_.totalEvictions = 0;
    stats_.totalLoadTimeMs = 0.0;
    stats_.totalMigrationTimeMs = 0.0;
    stats_.loadCount = 0;
    stats_.migrationCount = 0;
}

// Configuration
bool ModelResidencyManager::updateConfig(const ResidencyConfig& config) {
    config_ = config;
    return true;
}

// Callbacks
void ModelResidencyManager::setResidencyChangeCallback(ResidencyChangeCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    residencyCallback_ = callback;
}

// Capacity planning
std::vector<std::string> ModelResidencyManager::getOverloadedNodes() const {
    std::vector<std::string> result;
    auto nodes = clusterManager_->getAllNodes();
    
    for (const auto& node : nodes) {
        float memoryPressure = 1.0f - (static_cast<float>(node.resources.availableVRAM) /
                                       static_cast<float>(node.resources.totalVRAM));
        if (memoryPressure > config_.migrationThreshold) {
            result.push_back(node.nodeId);
        }
    }
    
    return result;
}

std::vector<std::string> ModelResidencyManager::getUnderutilizedNodes() const {
    std::vector<std::string> result;
    auto nodes = clusterManager_->getAllNodes();
    
    for (const auto& node : nodes) {
        float memoryPressure = 1.0f - (static_cast<float>(node.resources.availableVRAM) /
                                       static_cast<float>(node.resources.totalVRAM));
        if (memoryPressure < 0.3f) {
            result.push_back(node.nodeId);
        }
    }
    
    return result;
}

bool ModelResidencyManager::canNodeAcceptModel(const std::string& nodeId, const std::string& modelId) const {
    auto node = clusterManager_->getNode(nodeId);
    auto model = getModelInfo(modelId);
    
    if (node.nodeId.empty() || model.modelId.empty()) {
        return false;
    }
    
    return node.resources.availableVRAM >= model.memorySize;
}

// Internal methods
void ModelResidencyManager::residencyLoop() {
    while (running_) {
        // Periodic maintenance tasks
        cleanupCompletedMigrations();
        
        // Check for replication needs
        if (config_.replicateHotModels) {
            checkReplicationNeeds();
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

void ModelResidencyManager::migrationLoop() {
    while (running_) {
        // Process pending migrations
        processMigrations();
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void ModelResidencyManager::predictiveLoop() {
    while (running_) {
        if (config_.enablePredictiveLoading) {
            updateAccessPatterns();
            
            // Preload recommended models
            auto recommendations = getPreloadRecommendations();
            for (const auto& modelId : recommendations) {
                auto bestNode = findBestNodeForModel(modelId);
                if (!bestNode.empty()) {
                    preloadModel(modelId, bestNode);
                    stats_.totalPreloads++;
                }
            }
        }
        
        std::this_thread::sleep_for(std::chrono::minutes(1));
    }
}

void ModelResidencyManager::updateAccessPattern(const std::string& modelId) {
    // Update access pattern for predictive loading
    auto now = std::chrono::system_clock::now();
    
    auto& pattern = accessPatterns_[modelId];
    pattern.modelId = modelId;
    pattern.accessTimes.push_back(now);
    
    // Keep only recent accesses
    auto cutoff = now - std::chrono::hours(24);
    pattern.accessTimes.erase(
        std::remove_if(pattern.accessTimes.begin(), pattern.accessTimes.end(),
            [cutoff](const auto& time) { return time < cutoff; }),
        pattern.accessTimes.end());
    
    // Calculate confidence based on pattern regularity
    if (pattern.accessTimes.size() > 5) {
        pattern.confidence = 0.8f; // Simplified
    }
}

float ModelResidencyManager::calculateAffinityScore(const std::string& modelId, const std::string& nodeId) const {
    auto residency = getResidency(modelId, nodeId);
    
    if (residency.state == ResidencyState::LOADED) {
        return 1.0f; // Model already loaded
    }
    
    if (residency.state == ResidencyState::LOADING) {
        return 0.5f; // Model loading
    }
    
    return 0.0f;
}

float ModelResidencyManager::calculateLoadScore(const std::string& nodeId) const {
    auto node = clusterManager_->getNode(nodeId);
    
    if (node.nodeId.empty()) {
        return 0.0f;
    }
    
    // Higher available resources = higher score
    float vramRatio = static_cast<float>(node.resources.availableVRAM) / 
                     static_cast<float>(std::max(node.resources.totalVRAM, size_t(1)));
    
    return vramRatio;
}

std::string ModelResidencyManager::generateTaskId() {
    uint64_t id = taskIdCounter_.fetch_add(1);
    
    std::stringstream ss;
    ss << "mig-" << std::hex << std::setw(16) << std::setfill('0') << id;
    return ss.str();
}

void ModelResidencyManager::cleanupCompletedMigrations() {
    std::lock_guard<std::mutex> lock(migrationsMutex_);
    
    auto now = std::chrono::steady_clock::now();
    std::vector<std::string> toRemove;
    
    for (const auto& pair : migrations_) {
        if (pair.second.status == MigrationTask::Status::COMPLETED ||
            pair.second.status == MigrationTask::Status::FAILED) {
            auto age = now - pair.second.completedAt;
            if (age > std::chrono::hours(1)) {
                toRemove.push_back(pair.first);
            }
        }
    }
    
    for (const auto& taskId : toRemove) {
        migrations_.erase(taskId);
    }
}

void ModelResidencyManager::notifyResidencyChange(const std::string& modelId, const std::string& nodeId,
                                                   ResidencyState oldState, ResidencyState newState) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (residencyCallback_) {
        residencyCallback_(modelId, nodeId, oldState, newState);
    }
}

void ModelResidencyManager::checkReplicationNeeds() {
    // Check each model for replication needs
    for (const auto& pair : registeredModels_) {
        auto loadedNodes = findNodesWithModel(pair.first);
        
        if (loadedNodes.size() < config_.minReplicas) {
            replicateModel(pair.first, config_.minReplicas);
        }
    }
}

void ModelResidencyManager::processMigrations() {
    std::lock_guard<std::mutex> lock(migrationsMutex_);
    
    for (auto& pair : migrations_) {
        if (pair.second.status == MigrationTask::Status::PENDING) {
            pair.second.status = MigrationTask::Status::IN_PROGRESS;
            
            // Simulate migration progress
            pair.second.progress += 10;
            
            if (pair.second.progress >= 100) {
                pair.second.status = MigrationTask::Status::COMPLETED;
                pair.second.completedAt = std::chrono::steady_clock::now();
                
                // Update residency states
                updateResidencyState(pair.second.modelId, pair.second.sourceNodeId, 
                                      ResidencyState::NOT_LOADED);
                updateResidencyState(pair.second.modelId, pair.second.targetNodeId, 
                                      ResidencyState::LOADED);
            }
        }
    }
}

void ModelResidencyManager::updateAccessPatterns() {
    // Update all access patterns
    for (const auto& pair : registeredModels_) {
        updateAccessPattern(pair.first);
    }
}

} // namespace Distributed
} // namespace RawrXD
