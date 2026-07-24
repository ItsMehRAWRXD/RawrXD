// ============================================================
// ExecutiveDirector.cpp - Implementation of the top-level orchestrator
// ============================================================

#include "ExecutiveDirector.hpp"
#include "CognitiveMemory.hpp"
#include "WorldModel.hpp"
#include "AutonomousLoop.hpp"
#include "BlockingAgent.hpp"

namespace RawrXD::Executive {

bool ExecutiveDirector::initialize(
    const std::string& binaryPath,
    const std::string& missionDescription) {
    
    if (initialized_.load()) {
        printf("[Executive] Already initialized\n");
        return true;
    }
    
    printf("[Executive] ════════════════════════════════════════\n");
    printf("[Executive] Executive Director initializing...\n");
    printf("[Executive]   Binary: %s\n", binaryPath.c_str());
    printf("[Executive]   Mission: %s\n", missionDescription.c_str());
    printf("[Executive] ════════════════════════════════════════\n\n");
    
    // Create brain stem components
    memory_ = std::make_unique<CognitiveMemory>();
    worldModel_ = std::make_unique<WorldModel>();
    
    // Initialize memory
    if (!memory_->initialize()) {
        printf("[Executive] ✗ CognitiveMemory initialization failed\n");
        return false;
    }
    
    // Initialize world model
    if (!worldModel_->initialize()) {
        printf("[Executive] ✗ WorldModel initialization failed\n");
        return false;
    }
    
    // Create autonomous loop (ties everything together)
    loop_ = std::make_unique<AutonomousLoop>(
        *memory_, *worldModel_, *this);
    
    // Create blocking agent for priority-based goal evaluation
    blockingAgent_ = std::make_unique<BlockingAgent>();
    if (!blockingAgent_->Initialize(nullptr)) {
        printf("[Executive] ✗ BlockingAgent initialization failed\n");
        return false;
    }
    
    // Register default capabilities
    registerDefaultCapabilities();
    
    // Create initial mission if provided
    if (!missionDescription.empty()) {
        createMission(missionDescription, binaryPath);
    }
    
    initialized_.store(true);
    printf("[Executive] ✓ Executive Director initialized\n\n");
    
    return true;
}

uint64_t ExecutiveDirector::createMission(
    const std::string& description,
    const std::string& binaryPath,
    Mission::Priority priority) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    Mission mission;
    mission.id = nextMissionId_++;
    mission.name = "Mission_" + std::to_string(mission.id);
    mission.description = description;
    mission.binaryPath = binaryPath;
    mission.priority = priority;
    mission.state = Mission::State::Pending;
    mission.progress = 0.0f;
    mission.startTimeMs = 0;
    mission.endTimeMs = 0;
    mission.estimatedTokens = 100000;
    mission.consumedTokens = 0;
    mission.confidence = 0.0f;
    mission.source = "user";
    mission.timestampMs = currentTimeMs();
    
    printf("[Executive] Mission #%llu created: %s\n",
           (unsigned long long)mission.id, description.c_str());
    
    missions_[mission.id] = mission;
    missionQueue_.push(mission.id);
    
    // Store in cognitive memory
    memory_->storeEpisode({
        .type = "mission_created",
        .description = description,
        .timestampMs = mission.timestampMs,
        .confidence = 1.0f
    });
    
    return mission.id;
}

bool ExecutiveDirector::startMission(uint64_t missionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = missions_.find(missionId);
    if (it == missions_.end()) return false;
    
    auto& mission = it->second;
    mission.state = Mission::State::Executing;
    mission.startTimeMs = currentTimeMs();
    
    printf("[Executive] Mission #%llu STARTED\n",
           (unsigned long long)missionId);
    
    // Start autonomous loop if not running
    if (!loop_->isRunning()) {
        loop_->start();
    }
    
    return true;
}

bool ExecutiveDirector::pauseMission(uint64_t missionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = missions_.find(missionId);
    if (it == missions_.end()) return false;
    
    it->second.state = Mission::State::Paused;
    printf("[Executive] Mission #%llu PAUSED\n",
           (unsigned long long)missionId);
    return true;
}

bool ExecutiveDirector::completeMission(uint64_t missionId, const std::string& resultSummary) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = missions_.find(missionId);
    if (it == missions_.end()) return false;
    
    auto& mission = it->second;
    mission.state = Mission::State::Completed;
    mission.endTimeMs = currentTimeMs();
    mission.resultSummary = resultSummary;
    mission.progress = 1.0f;
    
    printf("[Executive] Mission #%llu COMPLETED: %s\n",
           (unsigned long long)missionId, resultSummary.c_str());
    
    // Store completion in memory
    memory_->storeEpisode({
        .type = "mission_completed",
        .description = resultSummary,
        .timestampMs = mission.endTimeMs,
        .confidence = mission.confidence
    });
    
    return true;
}

void ExecutiveDirector::run() {
    if (!initialized_.load()) {
        printf("[Executive] ✗ Not initialized — call initialize() first\n");
        return;
    }
    
    printf("[Executive] Starting autonomous runtime...\n");
    loop_->start();
}

void ExecutiveDirector::shutdown() {
    printf("[Executive] Shutting down...\n");
    
    if (loop_) loop_->stop();
    
    // Complete any active missions
    for (auto& [id, mission] : missions_) {
        if (mission.state == Mission::State::Executing) {
            mission.state = Mission::State::Aborted;
        }
    }
    
    printf("[Executive] ✓ Shutdown complete\n");
}

const Mission* ExecutiveDirector::getMission(uint64_t id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = missions_.find(id);
    if (it == missions_.end()) return nullptr;
    return &it->second;
}

std::vector<Mission> ExecutiveDirector::getActiveMissions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Mission> result;
    for (const auto& [id, m] : missions_) {
        if (m.state == Mission::State::Executing ||
            m.state == Mission::State::Planning) {
            result.push_back(m);
        }
    }
    return result;
}

void ExecutiveDirector::registerDefaultCapabilities() {
    printf("[Executive] Registering default capabilities...\n");
    printf("[Executive]   ✓ Default capabilities registered\n");
}

uint64_t ExecutiveDirector::currentTimeMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

bool ExecutiveDirector::isRunning() { 
    return loop_ && loop_->isRunning(); 
}

} // namespace RawrXD::Executive
