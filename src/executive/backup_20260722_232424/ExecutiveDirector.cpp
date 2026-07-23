// ============================================================================
// ExecutiveDirector.cpp - Implementation of the Central Cognitive Controller
// ============================================================================

#include "ExecutiveDirector.hpp"
#include "CognitiveMemory.hpp"
#include "WorldModel.hpp"
#include "MetaAgentLayer.hpp"
#include "CapabilityRegistry.hpp"
#include "LearningEngine.hpp"
#include "MultiLevelPlanner.hpp"
#include "AutonomousLoop.hpp"
#include "GoalManager.hpp"
#include "ReflectionEngine.hpp"
#include "RecoveryManager.hpp"

#include <iostream>
#include <chrono>

namespace RawrXD {
namespace Executive {

// Singleton instance
static std::unique_ptr<ExecutiveDirector> g_executiveDirector;

ExecutiveDirector* GetExecutiveDirector() {
    return g_executiveDirector.get();
}

void InitializeExecutiveDirector(const ExecutiveConfig& config) {
    if (!g_executiveDirector) {
        g_executiveDirector = std::make_unique<ExecutiveDirector>();
        g_executiveDirector->Initialize(config);
    }
}

void ShutdownExecutiveDirector() {
    if (g_executiveDirector) {
        g_executiveDirector->Shutdown();
        g_executiveDirector.reset();
    }
}

// ============================================================================
// ExecutiveDirector Implementation
// ============================================================================

ExecutiveDirector::ExecutiveDirector() = default;

ExecutiveDirector::~ExecutiveDirector() {
    Shutdown();
}

bool ExecutiveDirector::Initialize(const ExecutiveConfig& config) {
    config_ = config;
    startTime_ = std::chrono::steady_clock::now();
    
    std::cout << "[ExecutiveDirector] Initializing cognitive runtime...\n";
    
    // Initialize subsystems in dependency order
    
    // 1. Cognitive Memory (foundation)
    cognitiveMemory_ = std::make_unique<CognitiveMemory>();
    if (!cognitiveMemory_->Initialize(config.maxEpisodeMemorySize, config.maxSemanticMemorySize)) {
        std::cerr << "[ExecutiveDirector] Failed to initialize CognitiveMemory\n";
        return false;
    }
    std::cout << "[ExecutiveDirector] CognitiveMemory initialized\n";
    
    // 2. World Model (depends on memory)
    worldModel_ = std::make_unique<WorldModel>();
    if (!worldModel_->Initialize(cognitiveMemory_.get())) {
        std::cerr << "[ExecutiveDirector] Failed to initialize WorldModel\n";
        return false;
    }
    std::cout << "[ExecutiveDirector] WorldModel initialized\n";
    
    // 3. Capability Registry
    capabilityRegistry_ = std::make_unique<CapabilityRegistry>();
    if (!capabilityRegistry_->Initialize(this)) {
        std::cerr << "[ExecutiveDirector] Failed to initialize CapabilityRegistry\n";
        return false;
    }
    std::cout << "[ExecutiveDirector] CapabilityRegistry initialized\n";
    
    // 4. Learning Engine
    learningEngine_ = std::make_unique<LearningEngine>();
    if (!learningEngine_->Initialize(this, cognitiveMemory_.get())) {
        std::cerr << "[ExecutiveDirector] Failed to initialize LearningEngine\n";
        return false;
    }
    std::cout << "[ExecutiveDirector] LearningEngine initialized\n";
    
    // 5. Multi-Level Planner
    planner_ = std::make_unique<MultiLevelPlanner>();
    if (!planner_->Initialize(this)) {
        std::cerr << "[ExecutiveDirector] Failed to initialize MultiLevelPlanner\n";
        return false;
    }
    std::cout << "[ExecutiveDirector] MultiLevelPlanner initialized\n";
    
    // 6. Meta-Agent Layer
    metaAgentLayer_ = std::make_unique<MetaAgentLayer>();
    if (!metaAgentLayer_->Initialize(this)) {
        std::cerr << "[ExecutiveDirector] Failed to initialize MetaAgentLayer\n";
        return false;
    }
    std::cout << "[ExecutiveDirector] MetaAgentLayer initialized\n";
    
    // 7. Goal Manager
    goalManager_ = std::make_unique<GoalManager>();
    if (!goalManager_->Initialize(this)) {
        std::cerr << "[ExecutiveDirector] Failed to initialize GoalManager\n";
        return false;
    }
    std::cout << "[ExecutiveDirector] GoalManager initialized\n";
    
    // 8. Reflection Engine
    reflectionEngine_ = std::make_unique<ReflectionEngine>();
    if (!reflectionEngine_->Initialize(this)) {
        std::cerr << "[ExecutiveDirector] Failed to initialize ReflectionEngine\n";
        return false;
    }
    std::cout << "[ExecutiveDirector] ReflectionEngine initialized\n";
    
    // 9. Recovery Manager
    recoveryManager_ = std::make_unique<RecoveryManager>();
    if (!recoveryManager_->Initialize(this)) {
        std::cerr << "[ExecutiveDirector] Failed to initialize RecoveryManager\n";
        return false;
    }
    std::cout << "[ExecutiveDirector] RecoveryManager initialized\n";
    
    // 10. Autonomous Loop (last, depends on all others)
    autonomousLoop_ = std::make_unique<AutonomousLoop>();
    if (!autonomousLoop_->Initialize(this)) {
        std::cerr << "[ExecutiveDirector] Failed to initialize AutonomousLoop\n";
        return false;
    }
    std::cout << "[ExecutiveDirector] AutonomousLoop initialized\n";
    
    // Resource Manager
    resourceManager_ = std::make_unique<ResourceManager>();
    resourceManager_->Initialize(this);
    std::cout << "[ExecutiveDirector] ResourceManager initialized\n";
    
    TransitionTo(ExecutiveState::SLEEPING);
    std::cout << "[ExecutiveDirector] Initialization complete. Ready for autonomous operation.\n";
    
    return true;
}

void ExecutiveDirector::Shutdown() {
    if (shouldShutdown_.exchange(true)) {
        return;  // Already shutting down
    }
    
    std::cout << "[ExecutiveDirector] Shutting down...\n";
    
    TransitionTo(ExecutiveState::SHUTTING_DOWN);
    
    // Stop autonomous operation
    StopAutonomousOperation();
    
    // Shutdown subsystems in reverse order
    if (autonomousLoop_) autonomousLoop_->Shutdown();
    if (recoveryManager_) recoveryManager_->Shutdown();
    if (reflectionEngine_) reflectionEngine_->Shutdown();
    if (goalManager_) goalManager_->Shutdown();
    if (metaAgentLayer_) metaAgentLayer_->Shutdown();
    if (planner_) planner_->Shutdown();
    if (learningEngine_) learningEngine_->Shutdown();
    if (capabilityRegistry_) capabilityRegistry_->Shutdown();
    if (worldModel_) worldModel_->Shutdown();
    if (cognitiveMemory_) cognitiveMemory_->Shutdown();
    
    std::cout << "[ExecutiveDirector] Shutdown complete.\n";
}

void ExecutiveDirector::StartAutonomousOperation() {
    if (isRunning_.exchange(true)) {
        return;  // Already running
    }
    
    std::cout << "[ExecutiveDirector] Starting autonomous operation...\n";
    
    // Start the autonomous loop
    autonomousLoop_->Start();
    
    // Start executive thread for high-level coordination
    executiveThread_ = std::make_unique<std::thread>(&ExecutiveDirector::ExecutiveLoop, this);
    
    std::cout << "[ExecutiveDirector] Autonomous operation started.\n";
}

void ExecutiveDirector::StopAutonomousOperation() {
    if (!isRunning_.exchange(false)) {
        return;  // Not running
    }
    
    std::cout << "[ExecutiveDirector] Stopping autonomous operation...\n";
    
    // Stop the autonomous loop
    if (autonomousLoop_) {
        autonomousLoop_->Stop();
    }
    
    // Signal executive thread to stop
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        stateCv_.notify_all();
    }
    
    // Wait for executive thread
    if (executiveThread_ && executiveThread_->joinable()) {
        executiveThread_->join();
    }
    
    std::cout << "[ExecutiveDirector] Autonomous operation stopped.\n";
}

// ============================================================================
// Mission Management
// ============================================================================

std::string ExecutiveDirector::SubmitMission(const std::string& objective, 
                                               const std::string& domain,
                                               float priority) {
    MissionContext mission;
    mission.missionId = "mission_" + std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    mission.objective = objective;
    mission.domain = domain;
    mission.priority = priority;
    mission.createdAt = std::chrono::steady_clock::now();
    mission.status = "submitted";
    
    // Store mission (implementation would use proper storage)
    // For now, just notify meta-agents
    if (metaAgentLayer_) {
        metaAgentLayer_->GetMissionDirector()->OnMissionSubmitted(mission);
    }
    
    // Update stats
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.totalMissions++;
    }
    
    std::cout << "[ExecutiveDirector] Mission submitted: " << mission.missionId 
              << " (" << objective << ")\n";
    
    return mission.missionId;
}

void ExecutiveDirector::CancelMission(const std::string& missionId) {
    std::cout << "[ExecutiveDirector] Cancelling mission: " << missionId << "\n";
    // Implementation would cancel the mission
}

MissionContext* ExecutiveDirector::GetMission(const std::string& missionId) {
    // Implementation would retrieve from storage
    return nullptr;
}

std::vector<MissionContext> ExecutiveDirector::GetActiveMissions() {
    // Implementation would retrieve from storage
    return {};
}

// ============================================================================
// State Management
// ============================================================================

void ExecutiveDirector::TransitionTo(ExecutiveState newState) {
    ExecutiveState oldState = currentState_.exchange(newState);
    if (oldState != newState) {
        std::cout << "[ExecutiveDirector] State transition: " 
                  << GetStateString() << "\n";
    }
}

std::string ExecutiveDirector::GetStateString() const {
    switch (currentState_.load()) {
        case ExecutiveState::INITIALIZING: return "INITIALIZING";
        case ExecutiveState::OBSERVING: return "OBSERVING";
        case ExecutiveState::THINKING: return "THINKING";
        case ExecutiveState::PLANNING: return "PLANNING";
        case ExecutiveState::EXECUTING: return "EXECUTING";
        case ExecutiveState::REFLECTING: return "REFLECTING";
        case ExecutiveState::LEARNING: return "LEARNING";
        case ExecutiveState::SLEEPING: return "SLEEPING";
        case ExecutiveState::SHUTTING_DOWN: return "SHUTTING_DOWN";
        case ExecutiveState::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Executive Loop
// ============================================================================

void ExecutiveDirector::ExecutiveLoop() {
    while (isRunning_.load() && !shouldShutdown_.load()) {
        auto cycleStart = std::chrono::steady_clock::now();
        
        // Execute meta-agents
        if (metaAgentLayer_) {
            metaAgentLayer_->ExecuteAll();
        }
        
        // Update statistics
        {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.totalCycles++;
        }
        
        // Sleep until next cycle
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// ============================================================================
// Statistics
// ============================================================================

ExecutiveDirector::Stats ExecutiveDirector::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    Stats s = stats_;
    
    // Calculate uptime
    auto now = std::chrono::steady_clock::now();
    s.uptimeSeconds = std::chrono::duration<double>(now - startTime_).count();
    
    return s;
}

} // namespace Executive
} // namespace RawrXD
