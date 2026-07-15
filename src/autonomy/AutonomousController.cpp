/**
 * AutonomousController.cpp
 *
 * Phase C.3 Batch 4/5: Autonomous Runtime Loop
 */

#include "AutonomousController.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

namespace Autonomy {

// ============================================================================
// Runtime Mode Utilities
// ============================================================================

std::string RuntimeModeToString(RuntimeMode mode) {
    switch (mode) {
        case RuntimeMode::MANUAL: return "MANUAL";
        case RuntimeMode::ASSISTED: return "ASSISTED";
        case RuntimeMode::AUTONOMOUS: return "AUTONOMOUS";
        case RuntimeMode::SELF_OPTIMIZING: return "SELF_OPTIMIZING";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// AutonomousControllerConfig Implementation
// ============================================================================

std::string AutonomousControllerConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"mode\":\"" << RuntimeModeToString(mode) << "\",";
    json << "\"decisionIntervalMs\":" << decisionIntervalMs << ",";
    json << "\"executionIntervalMs\":" << executionIntervalMs << ",";
    json << "\"stabilityThreshold\":" << stabilityThreshold << ",";
    json << "\"maxConsecutiveFailures\":" << maxConsecutiveFailures << ",";
    json << "\"enableSelfOptimization\":" << (enableSelfOptimization ? "true" : "false") << ",";
    json << "\"enableEmergencyStop\":" << (enableEmergencyStop ? "true" : "false");
    json << "}";
    return json.str();
}

// ============================================================================
// ControllerState Implementation
// ============================================================================

std::string ControllerState::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"currentMode\":\"" << RuntimeModeToString(currentMode) << "\",";
    json << "\"isRunning\":" << (isRunning ? "true" : "false") << ",";
    json << "\"isPaused\":" << (isPaused ? "true" : "false") << ",";
    json << "\"cycleCount\":" << cycleCount << ",";
    json << "\"decisionsThisCycle\":" << decisionsThisCycle << ",";
    json << "\"consecutiveFailures\":" << consecutiveFailures << ",";
    json << "\"currentStability\":" << currentStability << ",";
    json << "\"startTimeMs\":" << startTimeMs;
    json << "}";
    return json.str();
}

void ControllerState::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           CONTROLLER STATE                                       ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Mode:              " << std::left << std::setw(10) << RuntimeModeToString(currentMode) << std::string(26, ' ') << "║\n";
    std::cout << "║  Running:           " << std::setw(10) << (isRunning ? "YES" : "NO") << std::string(26, ' ') << "║\n";
    std::cout << "║  Paused:            " << std::setw(10) << (isPaused ? "YES" : "NO") << std::string(26, ' ') << "║\n";
    std::cout << "║  Cycles:             " << std::setw(10) << cycleCount << std::string(26, ' ') << "║\n";
    std::cout << "║  Stability:         " << std::setw(9) << std::fixed << std::setprecision(1) << (currentStability * 100) << "%" << std::string(26, ' ') << "║\n";
    std::cout << "║  Failures:           " << std::setw(10) << consecutiveFailures << std::string(26, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// ControlLoopMetrics Implementation
// ============================================================================

void ControlLoopMetrics::RecordCycle(double cycleTimeMs) {
    totalCycles++;
    averageCycleTimeMs = (averageCycleTimeMs * (totalCycles - 1) + cycleTimeMs) / totalCycles;
}

void ControlLoopMetrics::RecordDecision(bool executed) {
    decisionsGenerated++;
    if (executed) {
        decisionsExecuted++;
    } else {
        decisionsRejected++;
    }
}

void ControlLoopMetrics::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           CONTROL LOOP METRICS                                   ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total Cycles:       " << std::setw(10) << totalCycles << std::string(26, ' ') << "║\n";
    std::cout << "║  Decisions Generated:  " << std::setw(10) << decisionsGenerated << std::string(26, ' ') << "║\n";
    std::cout << "║  Decisions Executed:  " << std::setw(10) << decisionsExecuted << std::string(26, ' ') << "║\n";
    std::cout << "║  Decisions Rejected:  " << std::setw(10) << decisionsRejected << std::string(26, ' ') << "║\n";
    std::cout << "║  Avg Cycle Time:     " << std::setw(9) << std::fixed << std::setprecision(2) << averageCycleTimeMs << " ms" << std::string(24, ' ') << "║\n";
    std::cout << "║  Avg Stability:      " << std::setw(9) << std::setprecision(1) << (averageStability * 100) << "%" << std::string(25, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// AutonomousController Implementation
// ============================================================================

AutonomousController::AutonomousController() = default;

AutonomousController::~AutonomousController() {
    Shutdown();
}

bool AutonomousController::Initialize(const AutonomousControllerConfig& config) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    config_ = config;
    state_.currentMode = config.mode;
    
    std::cout << "[AutonomousController] Initialized in " << RuntimeModeToString(config.mode) << " mode\n";
    return true;
}

void AutonomousController::Shutdown() {
    Stop();
    
    std::lock_guard<std::mutex> lock(stateMutex_);
    runtime_.reset();
    decisionEngine_.reset();
    mutationEngine_.reset();
    swarm_.reset();
    
    std::cout << "[AutonomousController] Shutdown complete\n";
}

void AutonomousController::SetRuntime(std::shared_ptr<Runtime::SovereignRuntime> runtime) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    runtime_ = runtime;
}

void AutonomousController::SetDecisionEngine(std::shared_ptr<AutonomousDecisionEngine> engine) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    decisionEngine_ = engine;
}

void AutonomousController::SetMutationEngine(std::shared_ptr<SEGMutationEngine> mutationEngine) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    mutationEngine_ = mutationEngine;
}

void AutonomousController::SetSwarmCoordinator(std::shared_ptr<Swarm::SwarmCoordinator> swarm) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    swarm_ = swarm;
}

bool AutonomousController::Start() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    if (running_) {
        return false;
    }
    
    running_ = true;
    shutdownRequested_ = false;
    state_.isRunning = true;
    state_.startTimeMs = GetCurrentTimeMs();
    
    // Start control thread
    controlThread_ = std::make_unique<std::thread>(&AutonomousController::ControlLoop, this);
    
    std::cout << "[AutonomousController] Control loop started\n";
    return true;
}

void AutonomousController::Stop() {
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        if (!running_) return;
        
        shutdownRequested_ = true;
        running_ = false;
        state_.isRunning = false;
    }
    
    stateCv_.notify_all();
    
    if (controlThread_ && controlThread_->joinable()) {
        controlThread_->join();
    }
    
    controlThread_.reset();
    std::cout << "[AutonomousController] Control loop stopped\n";
}

void AutonomousController::Pause() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    state_.isPaused = true;
    std::cout << "[AutonomousController] Paused\n";
}

void AutonomousController::Resume() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    state_.isPaused = false;
    stateCv_.notify_all();
    std::cout << "[AutonomousController] Resumed\n";
}

bool AutonomousController::IsPaused() const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    return state_.isPaused;
}

void AutonomousController::SetMode(RuntimeMode mode) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    if (state_.currentMode != mode) {
        std::cout << "[AutonomousController] Mode transition: " 
                  << RuntimeModeToString(state_.currentMode) << " -> " 
                  << RuntimeModeToString(mode) << "\n";
        state_.currentMode = mode;
        
        // Update decision engine
        if (decisionEngine_) {
            decisionEngine_->SetAutonomousMode(mode == RuntimeMode::AUTONOMOUS || 
                                                  mode == RuntimeMode::SELF_OPTIMIZING);
        }
    }
}

RuntimeMode AutonomousController::GetMode() const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    return state_.currentMode;
}

void AutonomousController::EmergencyStop() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    std::cout << "[AutonomousController] EMERGENCY STOP ACTIVATED\n";
    
    // Stop all autonomous activity
    if (decisionEngine_) {
        decisionEngine_->EmergencyStop();
    }
    
    // Downgrade mode
    state_.currentMode = RuntimeMode::MANUAL;
    state_.consecutiveFailures = 0;
}

void AutonomousController::ClearEmergency() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    if (decisionEngine_) {
        decisionEngine_->ResumeAutonomy();
    }
    
    std::cout << "[AutonomousController] Emergency cleared\n";
}

bool AutonomousController::IsEmergencyStopped() const {
    return decisionEngine_ ? decisionEngine_->IsEmergencyStopped() : false;
}

ControllerState AutonomousController::GetState() const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    return state_;
}

ControlLoopMetrics AutonomousController::GetMetrics() const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    return metrics_;
}

void AutonomousController::ExecuteControlCycle() {
    int64_t cycleStart = GetCurrentTimeMs();
    
    // 1. Process telemetry
    ProcessTelemetry();
    
    // 2. Generate and execute decisions (if in autonomous mode)
    if (state_.currentMode == RuntimeMode::AUTONOMOUS || 
        state_.currentMode == RuntimeMode::SELF_OPTIMIZING) {
        GenerateAndExecuteDecisions();
    }
    
    // 3. Update mode based on stability
    UpdateModeBasedOnStability();
    
    // 4. Record metrics
    int64_t cycleEnd = GetCurrentTimeMs();
    RecordCycleTime(cycleEnd - cycleStart);
    
    // Update state
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        state_.cycleCount++;
    }
}

bool AutonomousController::WaitForStableState(int timeoutMs) {
    std::unique_lock<std::mutex> lock(stateMutex_);
    
    auto result = stateCv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [this] {
        return state_.currentStability >= config_.stabilityThreshold || shutdownRequested_;
    });
    
    return result;
}

void AutonomousController::PrintStatus() const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     AUTONOMOUS CONTROLLER STATUS                                 ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Mode:              " << std::left << std::setw(10) << RuntimeModeToString(state_.currentMode) << std::string(26, ' ') << "║\n";
    std::cout << "║  Running:           " << std::setw(10) << (state_.isRunning ? "YES" : "NO") << std::string(26, ' ') << "║\n";
    std::cout << "║  Paused:            " << std::setw(10) << (state_.isPaused ? "YES" : "NO") << std::string(26, ' ') << "║\n";
    std::cout << "║  Cycles:             " << std::setw(10) << state_.cycleCount << std::string(26, ' ') << "║\n";
    std::cout << "║  Stability:         " << std::setw(9) << std::fixed << std::setprecision(1) << (state_.currentStability * 100) << "%" << std::string(26, ' ') << "║\n";
    std::cout << "║  Components:                                                     ║\n";
    std::cout << "║    Runtime:         " << std::setw(10) << (runtime_ ? "ATTACHED" : "NONE") << std::string(26, ' ') << "║\n";
    std::cout << "║    Decision Engine:  " << std::setw(10) << (decisionEngine_ ? "ATTACHED" : "NONE") << std::string(26, ' ') << "║\n";
    std::cout << "║    Mutation Engine:  " << std::setw(10) << (mutationEngine_ ? "ATTACHED" : "NONE") << std::string(26, ' ') << "║\n";
    std::cout << "║    Swarm:           " << std::setw(10) << (swarm_ ? "ATTACHED" : "NONE") << std::string(26, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// Control Loop
// ============================================================================

void AutonomousController::ControlLoop() {
    while (running_ && !shutdownRequested_) {
        {
            std::unique_lock<std::mutex> lock(stateMutex_);
            stateCv_.wait_for(lock, std::chrono::milliseconds(config_.executionIntervalMs), [this] {
                return shutdownRequested_ || !state_.isPaused;
            });
            
            if (state_.isPaused) continue;
        }
        
        ExecuteControlCycle();
    }
}

void AutonomousController::ProcessTelemetry() {
    // Would collect telemetry from runtime
    // For now, simulate stability
    std::lock_guard<std::mutex> lock(stateMutex_);
    state_.currentStability = 0.8 + (0.2 * (rand() % 100) / 100.0);
}

void AutonomousController::GenerateAndExecuteDecisions() {
    if (!decisionEngine_) return;
    
    // Generate decisions
    auto decisions = decisionEngine_->GenerateDecisions();
    
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        state_.decisionsThisCycle = static_cast<int>(decisions.size());
    }
    
    // Execute approved decisions
    for (const auto& decision : decisions) {
        if (decision.CanExecute()) {
            bool executed = decisionEngine_->ExecuteDecision(decision.decisionId);
            metrics_.RecordDecision(executed);
            
            if (!executed) {
                HandleDecisionFailure(decision);
            }
        } else {
            metrics_.RecordDecision(false);
        }
    }
    
    // Apply mutations if in self-optimizing mode
    if (state_.currentMode == RuntimeMode::SELF_OPTIMIZING && mutationEngine_) {
        ApplyMutations(decisions);
    }
}

void AutonomousController::ApplyMutations(const std::vector<Decision>& decisions) {
    for (const auto& decision : decisions) {
        auto mutations = mutationEngine_->GenerateMutations(decision);
        for (const auto& mutation : mutations) {
            mutationEngine_->ApplyMutation(mutation);
        }
    }
}

void AutonomousController::UpdateModeBasedOnStability() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    // Downgrade mode if stability is low
    if (state_.currentStability < config_.stabilityThreshold) {
        if (state_.currentMode == RuntimeMode::SELF_OPTIMIZING) {
            state_.currentMode = RuntimeMode::AUTONOMOUS;
            std::cout << "[AutonomousController] Downgraded to AUTONOMOUS due to low stability\n";
        } else if (state_.currentMode == RuntimeMode::AUTONOMOUS) {
            state_.currentMode = RuntimeMode::ASSISTED;
            std::cout << "[AutonomousController] Downgraded to ASSISTED due to low stability\n";
        }
    }
    
    // Upgrade mode if stable for long enough
    if (state_.currentStability > 0.9 && state_.cycleCount % 100 == 0) {
        if (state_.currentMode == RuntimeMode::ASSISTED && config_.enableSelfOptimization) {
            state_.currentMode = RuntimeMode::AUTONOMOUS;
            std::cout << "[AutonomousController] Upgraded to AUTONOMOUS\n";
        }
    }
}

bool AutonomousController::ValidateDecisionSafety(const Decision& decision) const {
    // Would check against safety envelope
    return decision.riskScore < 0.8;
}

void AutonomousController::HandleDecisionFailure(const Decision& decision) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    state_.consecutiveFailures++;
    
    if (state_.consecutiveFailures >= config_.maxConsecutiveFailures) {
        std::cout << "[AutonomousController] Too many failures, downgrading mode\n";
        state_.consecutiveFailures = 0;
        
        if (state_.currentMode == RuntimeMode::SELF_OPTIMIZING) {
            state_.currentMode = RuntimeMode::AUTONOMOUS;
        } else if (state_.currentMode == RuntimeMode::AUTONOMOUS) {
            state_.currentMode = RuntimeMode::ASSISTED;
        }
    }
}

int64_t AutonomousController::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void AutonomousController::RecordCycleTime(int64_t durationMs) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    metrics_.RecordCycle(static_cast<double>(durationMs));
}

// ============================================================================
// CLI Implementation
// ============================================================================

void AutonomousControllerCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     AUTONOMOUS CONTROLLER - Phase C.3                            ║\n";
    std::cout << "║     Closed Autonomous Control Loop                               ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void AutonomousControllerCLI::PrintUsage() {
    std::cout << "Usage: autonomy-controller [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --mode MODE          Runtime mode (manual/assisted/autonomous/self-optimizing)\n";
    std::cout << "  --interval MS        Decision interval in milliseconds\n";
    std::cout << "  --cycles N           Number of cycles to run\n";
    std::cout << "  --help               Show this help\n\n";
}

AutonomousControllerConfig AutonomousControllerCLI::ParseArgs(int argc, char* argv[]) {
    AutonomousControllerConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--mode" && i + 1 < argc) {
            std::string mode = argv[++i];
            if (mode == "manual") config.mode = RuntimeMode::MANUAL;
            else if (mode == "assisted") config.mode = RuntimeMode::ASSISTED;
            else if (mode == "autonomous") config.mode = RuntimeMode::AUTONOMOUS;
            else if (mode == "self-optimizing") config.mode = RuntimeMode::SELF_OPTIMIZING;
        } else if (arg == "--interval" && i + 1 < argc) {
            config.decisionIntervalMs = std::stoi(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            exit(0);
        }
    }
    
    return config;
}

int AutonomousControllerCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    AutonomousControllerConfig config = ParseArgs(argc, argv);
    
    // Create controller
    AutonomousController controller;
    if (!controller.Initialize(config)) {
        std::cerr << "Failed to initialize controller\n";
        return 1;
    }
    
    // Create and attach decision engine
    auto engine = std::make_shared<AutonomousDecisionEngine>();
    DecisionEngineConfig engineConfig;
    engine->Initialize(engineConfig);
    controller.SetDecisionEngine(engine);
    
    // Print initial status
    controller.PrintStatus();
    
    // Start controller
    controller.Start();
    
    // Run for a few cycles
    std::cout << "\n[Demo] Running control loop for 5 cycles...\n";
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    // Stop
    controller.Stop();
    
    // Print final status
    controller.PrintStatus();
    controller.GetMetrics().Print();
    
    return 0;
}

} // namespace Autonomy
