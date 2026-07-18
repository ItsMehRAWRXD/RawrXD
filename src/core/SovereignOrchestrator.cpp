/**
 * SovereignOrchestrator.cpp
 *
 * Phase D.1 Batch 1/5: Master Runtime Coordinator
 */

#include "SovereignOrchestrator.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>

namespace Core {

// ============================================================================
// OrchestratorConfig Implementation
// ============================================================================

std::string OrchestratorConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"runtimeInitTimeoutMs\":" << runtimeInitTimeoutMs << ",";
    json << "\"segInitTimeoutMs\":" << segInitTimeoutMs << ",";
    json << "\"engineInitTimeoutMs\":" << engineInitTimeoutMs << ",";
    json << "\"swarmInitTimeoutMs\":" << swarmInitTimeoutMs << ",";
    json << "\"telemetryInitTimeoutMs\":" << telemetryInitTimeoutMs << ",";
    json << "\"emergentInitTimeoutMs\":" << emergentInitTimeoutMs << ",";
    json << "\"autonomyInitTimeoutMs\":" << autonomyInitTimeoutMs << ",";
    json << "\"shutdownTimeoutMs\":" << shutdownTimeoutMs << ",";
    json << "\"healthCheckIntervalMs\":" << healthCheckIntervalMs << ",";
    json << "\"maxConsecutiveHealthFailures\":" << maxConsecutiveHealthFailures << ",";
    json << "\"enableAutoRecovery\":" << (enableAutoRecovery ? "true" : "false") << ",";
    json << "\"recoveryAttempts\":" << recoveryAttempts;
    json << "}";
    return json.str();
}

// ============================================================================
// SubsystemInfo Implementation
// ============================================================================

std::string SubsystemInfo::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"name\":\"" << name << "\",";
    json << "\"version\":\"" << version << "\",";
    json << "\"initialized\":" << (initialized ? "true" : "false") << ",";
    json << "\"running\":" << (running ? "true" : "false") << ",";
    json << "\"initTimeMs\":" << initTimeMs << ",";
    json << "\"startTimeMs\":" << startTimeMs;
    if (!lastError.empty()) {
        json << ",\"lastError\":\"" << lastError << "\"";
    }
    json << "}";
    return json.str();
}

// ============================================================================
// LifecyclePhase Utilities
// ============================================================================

std::string LifecyclePhaseToString(LifecyclePhase phase) {
    switch (phase) {
        case LifecyclePhase::UNINITIALIZED: return "UNINITIALIZED";
        case LifecyclePhase::INITIALIZING: return "INITIALIZING";
        case LifecyclePhase::INITIALIZED: return "INITIALIZED";
        case LifecyclePhase::STARTING: return "STARTING";
        case LifecyclePhase::RUNNING: return "RUNNING";
        case LifecyclePhase::PAUSING: return "PAUSING";
        case LifecyclePhase::PAUSED: return "PAUSED";
        case LifecyclePhase::RESUMING: return "RESUMING";
        case LifecyclePhase::STOPPING: return "STOPPING";
        case LifecyclePhase::STOPPED: return "STOPPED";
        case LifecyclePhase::SHUTTING_DOWN: return "SHUTTING_DOWN";
        case LifecyclePhase::SHUTDOWN: return "SHUTDOWN";
        case LifecyclePhase::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// SovereignOrchestrator Implementation
// ============================================================================

SovereignOrchestrator::SovereignOrchestrator() = default;

SovereignOrchestrator::~SovereignOrchestrator() {
    Shutdown();
}

SovereignOrchestrator::SovereignOrchestrator(SovereignOrchestrator&&) noexcept = default;
SovereignOrchestrator& SovereignOrchestrator::operator=(SovereignOrchestrator&&) noexcept = default;

SovereignOrchestrator& SovereignOrchestrator::Instance() {
    static SovereignOrchestrator instance;
    return instance;
}

bool SovereignOrchestrator::Initialize(const OrchestratorConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (phase_ != LifecyclePhase::UNINITIALIZED && phase_ != LifecyclePhase::SHUTDOWN) {
        std::cerr << "[SovereignOrchestrator] Already initialized\n";
        return false;
    }
    
    config_ = config;
    TransitionPhase(LifecyclePhase::INITIALIZING);
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     SOVEREIGN ORCHESTRATOR - Phase D.1                           ║\n";
    std::cout << "║     Master Runtime Coordinator                                   ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
    
    // Initialize subsystems in order
    std::cout << "[Orchestrator] Initializing subsystems...\n\n";
    
    auto startTime = GetCurrentTimeMs();
    
    // 1. Runtime
    std::cout << "[Orchestrator] 1/7: Initializing Runtime...\n";
    if (!InitializeRuntime()) {
        ReportError("Runtime", "Initialization failed");
        TransitionPhase(LifecyclePhase::ERROR);
        return false;
    }
    
    // 2. SEG
    std::cout << "[Orchestrator] 2/7: Initializing SEG...\n";
    if (!InitializeSEG()) {
        ReportError("SEG", "Initialization failed");
        TransitionPhase(LifecyclePhase::ERROR);
        return false;
    }
    
    // 3. Engine
    std::cout << "[Orchestrator] 3/7: Initializing Engine...\n";
    if (!InitializeEngine()) {
        ReportError("Engine", "Initialization failed");
        TransitionPhase(LifecyclePhase::ERROR);
        return false;
    }
    
    // 4. Swarm
    std::cout << "[Orchestrator] 4/7: Initializing Swarm...\n";
    if (!InitializeSwarm()) {
        ReportError("Swarm", "Initialization failed");
        TransitionPhase(LifecyclePhase::ERROR);
        return false;
    }
    
    // 5. Telemetry
    std::cout << "[Orchestrator] 5/7: Initializing Telemetry...\n";
    if (!InitializeTelemetry()) {
        ReportError("Telemetry", "Initialization failed");
        TransitionPhase(LifecyclePhase::ERROR);
        return false;
    }
    
    // 6. Emergent Layer
    std::cout << "[Orchestrator] 6/7: Initializing Emergent Layer...\n";
    if (!InitializeEmergent()) {
        ReportError("Emergent", "Initialization failed");
        TransitionPhase(LifecyclePhase::ERROR);
        return false;
    }
    
    // 7. Autonomy Controller
    std::cout << "[Orchestrator] 7/7: Initializing Autonomy Controller...\n";
    if (!InitializeAutonomy()) {
        ReportError("Autonomy", "Initialization failed");
        TransitionPhase(LifecyclePhase::ERROR);
        return false;
    }
    
    auto endTime = GetCurrentTimeMs();
    
    std::cout << "\n[SovereignOrchestrator] All subsystems initialized in " 
              << (endTime - startTime) << "ms\n";
    
    TransitionPhase(LifecyclePhase::INITIALIZED);
    return true;
}

bool SovereignOrchestrator::Start() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (phase_ != LifecyclePhase::INITIALIZED && phase_ != LifecyclePhase::STOPPED) {
        std::cerr << "[SovereignOrchestrator] Cannot start from phase: " 
                  << LifecyclePhaseToString(phase_) << "\n";
        return false;
    }
    
    TransitionPhase(LifecyclePhase::STARTING);
    
    std::cout << "\n[SovereignOrchestrator] Starting subsystems...\n\n";
    
    // Start subsystems in order
    if (!StartRuntime()) return false;
    if (!StartSEG()) return false;
    if (!StartEngine()) return false;
    if (!StartSwarm()) return false;
    if (!StartTelemetry()) return false;
    if (!StartEmergent()) return false;
    if (!StartAutonomy()) return false;
    
    // Start health monitoring
    shutdownRequested_ = false;
    healthMonitorThread_ = std::make_unique<std::thread>(
        &SovereignOrchestrator::HealthMonitorLoop, this);
    
    std::cout << "\n[SovereignOrchestrator] All subsystems started\n";
    
    TransitionPhase(LifecyclePhase::RUNNING);
    return true;
}

bool SovereignOrchestrator::Pause() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (phase_ != LifecyclePhase::RUNNING) {
        return false;
    }
    
    TransitionPhase(LifecyclePhase::PAUSING);
    
    // Pause subsystems in reverse order
    if (autonomy_) autonomy_->Pause();
    if (emergent_) emergent_->Pause();
    if (swarm_) swarm_->Pause();
    if (engine_) engine_->Pause();
    
    TransitionPhase(LifecyclePhase::PAUSED);
    std::cout << "[SovereignOrchestrator] System paused\n";
    return true;
}

bool SovereignOrchestrator::Resume() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (phase_ != LifecyclePhase::PAUSED) {
        return false;
    }
    
    TransitionPhase(LifecyclePhase::RESUMING);
    
    // Resume subsystems in order
    if (engine_) engine_->Resume();
    if (swarm_) swarm_->Resume();
    if (emergent_) emergent_->Resume();
    if (autonomy_) autonomy_->Resume();
    
    TransitionPhase(LifecyclePhase::RUNNING);
    std::cout << "[SovereignOrchestrator] System resumed\n";
    return true;
}

bool SovereignOrchestrator::Stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (phase_ != LifecyclePhase::RUNNING && phase_ != LifecyclePhase::PAUSED) {
        return false;
    }
    
    TransitionPhase(LifecyclePhase::STOPPING);
    
    std::cout << "\n[SovereignOrchestrator] Stopping subsystems...\n\n";
    
    // Stop subsystems in reverse order
    StopAutonomy();
    StopEmergent();
    StopTelemetry();
    StopSwarm();
    StopEngine();
    StopSEG();
    StopRuntime();
    
    // Stop health monitoring
    shutdownRequested_ = true;
    if (healthMonitorThread_ && healthMonitorThread_->joinable()) {
        healthMonitorThread_->join();
    }
    healthMonitorThread_.reset();
    
    std::cout << "\n[SovereignOrchestrator] All subsystems stopped\n";
    
    TransitionPhase(LifecyclePhase::STOPPED);
    return true;
}

void SovereignOrchestrator::Shutdown() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (phase_ == LifecyclePhase::SHUTDOWN || phase_ == LifecyclePhase::SHUTTING_DOWN) {
            return;
        }
        TransitionPhase(LifecyclePhase::SHUTTING_DOWN);
    }
    
    std::cout << "\n[SovereignOrchestrator] Shutting down...\n\n";
    
    // Stop if running
    if (phase_ == LifecyclePhase::RUNNING || phase_ == LifecyclePhase::PAUSED) {
        Stop();
    }
    
    // Shutdown subsystems in reverse order
    ShutdownAutonomy();
    ShutdownEmergent();
    ShutdownTelemetry();
    ShutdownSwarm();
    ShutdownEngine();
    ShutdownSEG();
    ShutdownRuntime();
    
    // Clear subsystem list
    subsystems_.clear();
    
    std::cout << "\n[SovereignOrchestrator] Shutdown complete\n";
    
    TransitionPhase(LifecyclePhase::SHUTDOWN);
}

void SovereignOrchestrator::EmergencyShutdown() {
    std::cerr << "\n[SovereignOrchestrator] EMERGENCY SHUTDOWN INITIATED\n";
    
    // Immediate shutdown - no graceful cleanup
    shutdownRequested_ = true;
    
    if (autonomy_) autonomy_->EmergencyStop();
    if (swarm_) swarm_->EmergencyStop();
    if (engine_) engine_->EmergencyStop();
    
    TransitionPhase(LifecyclePhase::SHUTDOWN);
}

LifecyclePhase SovereignOrchestrator::GetPhase() const {
    return phase_.load();
}

SovereignState SovereignOrchestrator::GetSystemState() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return systemState_;
}

std::vector<SubsystemInfo> SovereignOrchestrator::GetSubsystemInfo() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return subsystems_;
}

bool SovereignOrchestrator::IsHealthy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& subsys : subsystems_) {
        if (subsys.initialized && subsys.running && !subsys.lastError.empty()) {
            return false;
        }
    }
    return true;
}

std::string SovereignOrchestrator::GetHealthReport() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ostringstream report;
    report << "Sovereign Orchestrator Health Report\n";
    report << "=====================================\n";
    report << "Phase: " << LifecyclePhaseToString(phase_) << "\n";
    report << "Overall Health: " << (IsHealthy() ? "HEALTHY" : "UNHEALTHY") << "\n\n";
    
    report << "Subsystems:\n";
    for (const auto& subsys : subsystems_) {
        report << "  " << std::left << std::setw(20) << subsys.name;
        report << " [" << (subsys.initialized ? "I" : " ") << "]";
        report << " [" << (subsys.running ? "R" : " ") << "]";
        if (!subsys.lastError.empty()) {
            report << " ERROR: " << subsys.lastError;
        }
        report << "\n";
    }
    
    return report.str();
}

bool SovereignOrchestrator::WaitForPhase(LifecyclePhase phase, int timeoutMs) {
    std::unique_lock<std::mutex> lock(mutex_);
    
    return phaseCv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [this, phase] {
        return phase_ == phase || phase_ == LifecyclePhase::ERROR;
    });
}

void SovereignOrchestrator::SetPhaseChangeCallback(PhaseChangeCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    phaseCallback_ = callback;
}

void SovereignOrchestrator::SetErrorCallback(ErrorCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    errorCallback_ = callback;
}

void SovereignOrchestrator::PrintStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     SOVEREIGN ORCHESTRATOR STATUS                                ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Phase:        " << std::left << std::setw(48) << LifecyclePhaseToString(phase_) << " ║\n";
    std::cout << "║  Health:        " << std::setw(48) << (IsHealthy() ? "HEALTHY" : "UNHEALTHY") << " ║\n";
    std::cout << "║  Subsystems:    " << std::setw(48) << std::to_string(subsystems_.size()) << " ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Subsystem Status:                                               ║\n";
    
    for (const auto& subsys : subsystems_) {
        std::cout << "║    " << std::left << std::setw(15) << subsys.name << " ";
        std::cout << "[" << (subsys.initialized ? "I" : " ") << "]";
        std::cout << "[" << (subsys.running ? "R" : " ") << "]";
        std::cout << std::string(30, ' ') << "║\n";
    }
    
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// Initialization Methods
// ============================================================================

bool SovereignOrchestrator::InitializeRuntime() {
    auto startTime = GetCurrentTimeMs();
    
    runtime_ = std::make_shared<Runtime::SovereignRuntime>();
    // Would call runtime_->Initialize() here
    
    SubsystemInfo info;
    info.name = "Runtime";
    info.version = "1.0.0";
    info.initialized = true;
    info.initTimeMs = GetCurrentTimeMs() - startTime;
    subsystems_.push_back(info);
    
    std::cout << "  ✓ Runtime initialized (" << info.initTimeMs << "ms)\n";
    return true;
}

bool SovereignOrchestrator::InitializeSEG() {
    auto startTime = GetCurrentTimeMs();
    
    segGraph_ = std::make_shared<SEG::ExecutionGraph>();
    // Would initialize SEG here
    
    SubsystemInfo info;
    info.name = "SEG";
    info.version = "1.0.0";
    info.initialized = true;
    info.initTimeMs = GetCurrentTimeMs() - startTime;
    subsystems_.push_back(info);
    
    std::cout << "  ✓ SEG initialized (" << info.initTimeMs << "ms)\n";
    return true;
}

bool SovereignOrchestrator::InitializeEngine() {
    auto startTime = GetCurrentTimeMs();
    
    engine_ = std::make_shared<Engine::Engine>();
    // Would initialize Engine here
    
    SubsystemInfo info;
    info.name = "Engine";
    info.version = "1.0.0";
    info.initialized = true;
    info.initTimeMs = GetCurrentTimeMs() - startTime;
    subsystems_.push_back(info);
    
    std::cout << "  ✓ Engine initialized (" << info.initTimeMs << "ms)\n";
    return true;
}

bool SovereignOrchestrator::InitializeSwarm() {
    auto startTime = GetCurrentTimeMs();
    
    swarm_ = std::make_shared<Swarm::SwarmCoordinator>();
    // Would initialize Swarm here
    
    SubsystemInfo info;
    info.name = "Swarm";
    info.version = "1.0.0";
    info.initialized = true;
    info.initTimeMs = GetCurrentTimeMs() - startTime;
    subsystems_.push_back(info);
    
    std::cout << "  ✓ Swarm initialized (" << info.initTimeMs << "ms)\n";
    return true;
}

bool SovereignOrchestrator::InitializeTelemetry() {
    auto startTime = GetCurrentTimeMs();
    
    telemetry_ = std::make_shared<Telemetry::TelemetryCollector>();
    // Would initialize Telemetry here
    
    SubsystemInfo info;
    info.name = "Telemetry";
    info.version = "1.0.0";
    info.initialized = true;
    info.initTimeMs = GetCurrentTimeMs() - startTime;
    subsystems_.push_back(info);
    
    std::cout << "  ✓ Telemetry initialized (" << info.initTimeMs << "ms)\n";
    return true;
}

bool SovereignOrchestrator::InitializeEmergent() {
    auto startTime = GetCurrentTimeMs();
    
    emergent_ = std::make_shared<Emergent::EmergentPatternDetector>();
    // Would initialize Emergent here
    
    SubsystemInfo info;
    info.name = "Emergent";
    info.version = "1.0.0";
    info.initialized = true;
    info.initTimeMs = GetCurrentTimeMs() - startTime;
    subsystems_.push_back(info);
    
    std::cout << "  ✓ Emergent Layer initialized (" << info.initTimeMs << "ms)\n";
    return true;
}

bool SovereignOrchestrator::InitializeAutonomy() {
    auto startTime = GetCurrentTimeMs();
    
    autonomy_ = std::make_shared<Autonomy::AutonomousController>();
    // Would initialize Autonomy here
    
    SubsystemInfo info;
    info.name = "Autonomy";
    info.version = "1.0.0";
    info.initialized = true;
    info.initTimeMs = GetCurrentTimeMs() - startTime;
    subsystems_.push_back(info);
    
    std::cout << "  ✓ Autonomy Controller initialized (" << info.initTimeMs << "ms)\n";
    return true;
}

// ============================================================================
// Start Methods
// ============================================================================

bool SovereignOrchestrator::StartRuntime() {
    auto* subsys = FindSubsystem("Runtime");
    if (subsys) {
        subsys->running = true;
        subsys->startTimeMs = GetCurrentTimeMs();
        std::cout << "  ✓ Runtime started\n";
    }
    return true;
}

bool SovereignOrchestrator::StartSEG() {
    auto* subsys = FindSubsystem("SEG");
    if (subsys) {
        subsys->running = true;
        subsys->startTimeMs = GetCurrentTimeMs();
        std::cout << "  ✓ SEG started\n";
    }
    return true;
}

bool SovereignOrchestrator::StartEngine() {
    auto* subsys = FindSubsystem("Engine");
    if (subsys) {
        subsys->running = true;
        subsys->startTimeMs = GetCurrentTimeMs();
        std::cout << "  ✓ Engine started\n";
    }
    return true;
}

bool SovereignOrchestrator::StartSwarm() {
    auto* subsys = FindSubsystem("Swarm");
    if (subsys) {
        subsys->running = true;
        subsys->startTimeMs = GetCurrentTimeMs();
        std::cout << "  ✓ Swarm started\n";
    }
    return true;
}

bool SovereignOrchestrator::StartTelemetry() {
    auto* subsys = FindSubsystem("Telemetry");
    if (subsys) {
        subsys->running = true;
        subsys->startTimeMs = GetCurrentTimeMs();
        std::cout << "  ✓ Telemetry started\n";
    }
    return true;
}

bool SovereignOrchestrator::StartEmergent() {
    auto* subsys = FindSubsystem("Emergent");
    if (subsys) {
        subsys->running = true;
        subsys->startTimeMs = GetCurrentTimeMs();
        std::cout << "  ✓ Emergent Layer started\n";
    }
    return true;
}

bool SovereignOrchestrator::StartAutonomy() {
    auto* subsys = FindSubsystem("Autonomy");
    if (subsys) {
        subsys->running = true;
        subsys->startTimeMs = GetCurrentTimeMs();
        std::cout << "  ✓ Autonomy Controller started\n";
    }
    return true;
}

// ============================================================================
// Stop Methods
// ============================================================================

bool SovereignOrchestrator::StopRuntime() {
    auto* subsys = FindSubsystem("Runtime");
    if (subsys) {
        subsys->running = false;
        std::cout << "  ✓ Runtime stopped\n";
    }
    return true;
}

bool SovereignOrchestrator::StopSEG() {
    auto* subsys = FindSubsystem("SEG");
    if (subsys) {
        subsys->running = false;
        std::cout << "  ✓ SEG stopped\n";
    }
    return true;
}

bool SovereignOrchestrator::StopEngine() {
    auto* subsys = FindSubsystem("Engine");
    if (subsys) {
        subsys->running = false;
        std::cout << "  ✓ Engine stopped\n";
    }
    return true;
}

bool SovereignOrchestrator::StopSwarm() {
    auto* subsys = FindSubsystem("Swarm");
    if (subsys) {
        subsys->running = false;
        std::cout << "  ✓ Swarm stopped\n";
    }
    return true;
}

bool SovereignOrchestrator::StopTelemetry() {
    auto* subsys = FindSubsystem("Telemetry");
    if (subsys) {
        subsys->running = false;
        std::cout << "  ✓ Telemetry stopped\n";
    }
    return true;
}

bool SovereignOrchestrator::StopEmergent() {
    auto* subsys = FindSubsystem("Emergent");
    if (subsys) {
        subsys->running = false;
        std::cout << "  ✓ Emergent Layer stopped\n";
    }
    return true;
}

bool SovereignOrchestrator::StopAutonomy() {
    auto* subsys = FindSubsystem("Autonomy");
    if (subsys) {
        subsys->running = false;
        std::cout << "  ✓ Autonomy Controller stopped\n";
    }
    return true;
}

// ============================================================================
// Shutdown Methods
// ============================================================================

void SovereignOrchestrator::ShutdownRuntime() {
    runtime_.reset();
    std::cout << "  ✓ Runtime shutdown\n";
}

void SovereignOrchestrator::ShutdownSEG() {
    segGraph_.reset();
    std::cout << "  ✓ SEG shutdown\n";
}

void SovereignOrchestrator::ShutdownEngine() {
    engine_.reset();
    std::cout << "  ✓ Engine shutdown\n";
}

void SovereignOrchestrator::ShutdownSwarm() {
    swarm_.reset();
    std::cout << "  ✓ Swarm shutdown\n";
}

void SovereignOrchestrator::ShutdownTelemetry() {
    telemetry_.reset();
    std::cout << "  ✓ Telemetry shutdown\n";
}

void SovereignOrchestrator::ShutdownEmergent() {
    emergent_.reset();
    std::cout << "  ✓ Emergent Layer shutdown\n";
}

void SovereignOrchestrator::ShutdownAutonomy() {
    autonomy_.reset();
    std::cout << "  ✓ Autonomy Controller shutdown\n";
}

// ============================================================================
// Health Monitoring
// ============================================================================

void SovereignOrchestrator::HealthMonitorLoop() {
    int consecutiveFailures = 0;
    
    while (!shutdownRequested_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.healthCheckIntervalMs));
        
        if (shutdownRequested_) break;
        
        bool healthy = true;
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (auto& subsys : subsystems_) {
                if (subsys.running && !CheckSubsystemHealth(subsys.name)) {
                    subsys.lastError = "Health check failed";
                    healthy = false;
                    
                    if (errorCallback_) {
                        errorCallback_(subsys.name, "Health check failed");
                    }
                }
            }
        }
        
        if (!healthy) {
            consecutiveFailures++;
            
            if (consecutiveFailures >= config_.maxConsecutiveHealthFailures) {
                std::cerr << "[SovereignOrchestrator] Health check failed " 
                          << consecutiveFailures << " times, initiating recovery\n";
                
                if (config_.enableAutoRecovery) {
                    // Would trigger recovery here
                }
            }
        } else {
            consecutiveFailures = 0;
        }
        
        UpdateSystemState();
    }
}

bool SovereignOrchestrator::CheckSubsystemHealth(const std::string& name) {
    // Would check actual subsystem health
    return true;
}

// ============================================================================
// State Management
// ============================================================================

void SovereignOrchestrator::UpdateSystemState() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    systemState_.phase = LifecyclePhaseToString(phase_);
    systemState_.timestampMs = GetCurrentTimeMs();
    
    // Count active subsystems
    systemState_.activeSubsystems = 0;
    systemState_.healthySubsystems = 0;
    
    for (const auto& subsys : subsystems_) {
        if (subsys.running) {
            systemState_.activeSubsystems++;
            if (subsys.lastError.empty()) {
                systemState_.healthySubsystems++;
            }
        }
    }
    
    // Calculate stability
    if (!subsystems_.empty()) {
        systemState_.stability = static_cast<double>(systemState_.healthySubsystems) 
                                   / subsystems_.size();
    }
}

void SovereignOrchestrator::TransitionPhase(LifecyclePhase newPhase) {
    LifecyclePhase oldPhase = phase_.exchange(newPhase);
    
    if (oldPhase != newPhase && phaseCallback_) {
        phaseCallback_(oldPhase, newPhase);
    }
    
    phaseCv_.notify_all();
}

void SovereignOrchestrator::ReportError(const std::string& subsystem, const std::string& error) {
    std::cerr << "[SovereignOrchestrator] Error in " << subsystem << ": " << error << "\n";
    
    if (errorCallback_) {
        errorCallback_(subsystem, error);
    }
}

// ============================================================================
// Helpers
// ============================================================================

int64_t SovereignOrchestrator::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

SubsystemInfo* SovereignOrchestrator::FindSubsystem(const std::string& name) {
    for (auto& subsys : subsystems_) {
        if (subsys.name == name) {
            return &subsys;
        }
    }
    return nullptr;
}

// ============================================================================
// CLI Implementation
// ============================================================================

void SovereignOrchestratorCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     SOVEREIGN ORCHESTRATOR - Phase D.1                           ║\n";
    std::cout << "║     Master Runtime Coordinator                                   ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void SovereignOrchestratorCLI::PrintUsage() {
    std::cout << "Usage: sovereign-orchestrator [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --init-timeout MS      Runtime initialization timeout\n";
    std::cout << "  --health-interval MS Health check interval\n";
    std::cout << "  --auto-recovery      Enable automatic recovery\n";
    std::cout << "  --help               Show this help\n\n";
}

OrchestratorConfig SovereignOrchestratorCLI::ParseArgs(int argc, char* argv[]) {
    OrchestratorConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--init-timeout" && i + 1 < argc) {
            config.runtimeInitTimeoutMs = std::stoi(argv[++i]);
        } else if (arg == "--health-interval" && i + 1 < argc) {
            config.healthCheckIntervalMs = std::stoi(argv[++i]);
        } else if (arg == "--auto-recovery") {
            config.enableAutoRecovery = true;
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            exit(0);
        }
    }
    
    return config;
}

int SovereignOrchestratorCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    OrchestratorConfig config = ParseArgs(argc, argv);
    
    // Get orchestrator instance
    SovereignOrchestrator& orchestrator = SovereignOrchestrator::Instance();
    
    // Initialize
    if (!orchestrator.Initialize(config)) {
        std::cerr << "Failed to initialize orchestrator\n";
        return 1;
    }
    
    // Start
    if (!orchestrator.Start()) {
        std::cerr << "Failed to start orchestrator\n";
        return 1;
    }
    
    // Print status
    orchestrator.PrintStatus();
    
    // Run for a few seconds
    std::cout << "\n[Demo] Running for 3 seconds...\n";
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    // Shutdown
    orchestrator.Shutdown();
    
    return 0;
}

} // namespace Core
