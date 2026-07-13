// SovereignUnifiedRuntime.cpp
// Phase D.4 Batch 1/5 — Unified Runtime Integration Implementation

#include "SovereignUnifiedRuntime.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <iostream>

// Include component headers (would be actual includes in production)
// #include "../autonomy/AutonomousController.hpp"
// #include "../autonomy/StabilityEnvelope.hpp"
// etc.

namespace RawrXD {

// ============================================================================
// Singleton Implementation
// ============================================================================

SovereignUnifiedRuntime& SovereignUnifiedRuntime::Instance() {
    static SovereignUnifiedRuntime instance;
    return instance;
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

SovereignUnifiedRuntime::SovereignUnifiedRuntime()
    : config_()
    , state_()
    , stats_{}
{
    // Initialize all component pointers to nullptr
    // They will be created during Initialize()
}

SovereignUnifiedRuntime::~SovereignUnifiedRuntime() {
    if (state_.phase != RuntimePhase::SHUTDOWN && 
        state_.phase != RuntimePhase::UNINITIALIZED) {
        EmergencyShutdown("Destructor called on running runtime");
    }
}

// ============================================================================
// Configuration
// ============================================================================

void SovereignUnifiedRuntime::Configure(const ComponentConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    if (state_.phase != RuntimePhase::UNINITIALIZED && 
        state_.phase != RuntimePhase::SHUTDOWN) {
        throw std::runtime_error("Cannot configure while runtime is active");
    }
    
    config_ = config;
}

ComponentConfig SovereignUnifiedRuntime::GetConfiguration() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
}

// ============================================================================
// Lifecycle
// ============================================================================

bool SovereignUnifiedRuntime::Initialize() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    if (state_.phase != RuntimePhase::UNINITIALIZED) {
        std::cerr << "Runtime already initialized" << std::endl;
        return false;
    }
    
    TransitionToPhase(RuntimePhase::INITIALIZING);
    NotifyEvent(LifecycleEvent::PRE_INIT, "Starting initialization");
    
    // Validate configuration
    if (!ValidateConfiguration()) {
        TransitionToPhase(RuntimePhase::ERROR);
        NotifyEvent(LifecycleEvent::ERROR_OCCURRED, "Configuration validation failed");
        return false;
    }
    
    // Create components
    if (!InitializeComponents()) {
        TransitionToPhase(RuntimePhase::ERROR);
        NotifyEvent(LifecycleEvent::ERROR_OCCURRED, "Component initialization failed");
        return false;
    }
    
    TransitionToPhase(RuntimePhase::BOOTING);
    NotifyEvent(LifecycleEvent::POST_INIT, "Initialization complete");
    
    return true;
}

bool SovereignUnifiedRuntime::Boot(RuntimeMode mode) {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        
        if (state_.phase != RuntimePhase::BOOTING) {
            std::cerr << "Runtime not in BOOTING phase" << std::endl;
            return false;
        }
        
        state_.mode = mode;
        state_.boot_time = std::chrono::steady_clock::now();
    }
    
    NotifyEvent(LifecycleEvent::PRE_BOOT, "Starting boot sequence");
    
    // Boot all components
    if (!BootComponents()) {
        EmergencyShutdown("Boot sequence failed");
        return false;
    }
    
    // Start health monitoring
    StartHealthMonitoring();
    
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        TransitionToPhase(RuntimePhase::RUNNING);
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_boots++;
    }
    
    NotifyEvent(LifecycleEvent::POST_BOOT, "Boot complete, runtime running");
    
    return true;
}

bool SovereignUnifiedRuntime::Pause() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    if (state_.phase != RuntimePhase::RUNNING) {
        return false;
    }
    
    TransitionToPhase(RuntimePhase::PAUSED);
    
    // Pause components
    // autonomy_controller_->Pause();
    // adaptive_scheduler_->Pause();
    
    return true;
}

bool SovereignUnifiedRuntime::Resume() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    if (state_.phase != RuntimePhase::PAUSED) {
        return false;
    }
    
    // Resume components
    // autonomy_controller_->Resume();
    // adaptive_scheduler_->Resume();
    
    TransitionToPhase(RuntimePhase::RUNNING);
    
    return true;
}

bool SovereignUnifiedRuntime::Shutdown() {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        
        if (state_.phase == RuntimePhase::SHUTDOWN ||
            state_.phase == RuntimePhase::SHUTTING_DOWN) {
            return true;
        }
        
        if (!RuntimeUtils::IsOperationalPhase(state_.phase)) {
            return false;
        }
        
        TransitionToPhase(RuntimePhase::SHUTTING_DOWN);
    }
    
    NotifyEvent(LifecycleEvent::PRE_SHUTDOWN, "Starting shutdown sequence");
    
    // Stop health monitoring
    StopHealthMonitoring();
    
    // Shutdown components
    ShutdownComponents();
    
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        TransitionToPhase(RuntimePhase::SHUTDOWN);
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_shutdowns++;
    }
    
    NotifyEvent(LifecycleEvent::POST_SHUTDOWN, "Shutdown complete");
    
    return true;
}

bool SovereignUnifiedRuntime::EmergencyShutdown(const std::string& reason) {
    std::cerr << "EMERGENCY SHUTDOWN: " << reason << std::endl;
    
    // Immediate shutdown without graceful cleanup
    // In production, this would still attempt minimal cleanup
    
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        state_.phase = RuntimePhase::SHUTDOWN;
    }
    
    // Force cleanup
    ShutdownComponents();
    
    return true;
}

// ============================================================================
// State Queries
// ============================================================================

RuntimeState SovereignUnifiedRuntime::GetState() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return state_;
}

RuntimePhase SovereignUnifiedRuntime::GetPhase() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return state_.phase;
}

RuntimeMode SovereignUnifiedRuntime::GetMode() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return state_.mode;
}

bool SovereignUnifiedRuntime::IsRunning() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return state_.phase == RuntimePhase::RUNNING;
}

bool SovereignUnifiedRuntime::IsHealthy() const {
    auto report = GenerateHealthReport();
    return report.overall_healthy;
}

// ============================================================================
// Health
// ============================================================================

HealthReport SovereignUnifiedRuntime::GenerateHealthReport() const {
    HealthReport report;
    report.generated_at = std::chrono::steady_clock::now();
    
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    // Check each component
    for (const auto& [name, healthy] : state_.component_health) {
        HealthReport::ComponentHealth comp;
        comp.name = name;
        comp.healthy = healthy;
        comp.status = state_.component_status.count(name) ? 
                      state_.component_status.at(name) : "unknown";
        comp.last_check = std::chrono::steady_clock::now();
        
        report.components.push_back(comp);
        
        if (!healthy) {
            report.overall_healthy = false;
        }
    }
    
    report.overall_status = report.overall_healthy ? "HEALTHY" : "DEGRADED";
    
    return report;
}

std::vector<std::string> SovereignUnifiedRuntime::GetUnhealthyComponents() const {
    std::vector<std::string> unhealthy;
    
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    for (const auto& [name, healthy] : state_.component_health) {
        if (!healthy) {
            unhealthy.push_back(name);
        }
    }
    
    return unhealthy;
}

// ============================================================================
// Unified State Export
// ============================================================================

UnifiedState SovereignUnifiedRuntime::ExportUnifiedState() const {
    UnifiedState unified;
    unified.timestamp = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        unified.runtime = state_;
    }
    
    // Serialize component states (simplified)
    unified.autonomy_state = "{\"enabled\":" + 
        std::string(state_.autonomy_enabled ? "true" : "false") + "}";
    unified.scheduler_state = "{\"active\":true}";
    unified.swarm_state = "{\"agents\":" + std::to_string(state_.active_agents) + "}";
    unified.telemetry_state = "{\"collecting\":true}";
    unified.seg_state = "{\"enabled\":" + 
        std::string(config_.enable_seg ? "true" : "false") + "}";
    
    // Current metrics
    unified.metrics["cpu_utilization"] = state_.cpu_utilization;
    unified.metrics["memory_utilization"] = state_.memory_utilization;
    unified.metrics["gpu_utilization"] = state_.gpu_utilization;
    unified.metrics["active_agents"] = static_cast<double>(state_.active_agents);
    unified.metrics["current_tps"] = state_.current_tps;
    
    return unified;
}

std::string SovereignUnifiedRuntime::ExportStateAsJson() const {
    auto unified = ExportUnifiedState();
    
    std::stringstream json;
    json << "{\n";
    json << "  \"timestamp\": " <> 
        std::chrono::duration_cast<std::chrono::seconds>(
            unified.timestamp.time_since_epoch()).count() << ",\n";
    json << "  \"runtime\": {\n";
    json << "    \"phase\": \"" << RuntimeUtils::PhaseToString(unified.runtime.phase) << "\",\n";
    json << "    \"mode\": \"" << RuntimeUtils::ModeToString(unified.runtime.mode) << "\",\n";
    json << "    \"autonomy_enabled\": " <> 
        (unified.runtime.autonomy_enabled ? "true" : "false") << ",\n";
    json << "    \"active_agents\": " << unified.runtime.active_agents << ",\n";
    json << "    \"current_tps\": " << unified.runtime.current_tps << "\n";
    json << "  },\n";
    json << "  \"metrics\": {\n";
    
    bool first = true;
    for (const auto& [key, value] : unified.metrics) {
        if (!first) json << ",\n";
        json << "    \"" << key << "\": " << value;
        first = false;
    }
    json << "\n  }\n";
    json << "}\n";
    
    return json.str();
}

bool SovereignUnifiedRuntime::ImportState(const UnifiedState& state) {
    // In production, this would restore component states
    // For now, just update runtime state
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        state_ = state.runtime;
    }
    
    return true;
}

// ============================================================================
// Component Access
// ============================================================================

// These would return actual component pointers in production
// For now, return nullptr as placeholders

Autonomy::AutonomousController* SovereignUnifiedRuntime::GetAutonomyController() {
    return nullptr; // autonomy_controller_.get();
}

Autonomy::StabilityEnvelope* SovereignUnifiedRuntime::GetStabilityEnvelope() {
    return nullptr; // stability_envelope_.get();
}

Predictive::WorkloadForecaster* SovereignUnifiedRuntime::GetWorkloadForecaster() {
    return nullptr; // workload_forecaster_.get();
}

Scheduler::AdaptiveScheduler* SovereignUnifiedRuntime::GetAdaptiveScheduler() {
    return nullptr; // adaptive_scheduler_.get();
}

Interface::SovereignAPIGateway* SovereignUnifiedRuntime::GetAPIGateway() {
    return nullptr; // api_gateway_.get();
}

Interface::SovereignQueryEngine* SovereignUnifiedRuntime::GetQueryEngine() {
    return nullptr; // query_engine_.get();
}

Telemetry::TelemetryCollector* SovereignUnifiedRuntime::GetTelemetryCollector() {
    return nullptr; // telemetry_collector_.get();
}

Swarm::SwarmCoordinator* SovereignUnifiedRuntime::GetSwarmCoordinator() {
    return nullptr; // swarm_coordinator_.get();
}

Checkpoint::CheckpointManager* SovereignUnifiedRuntime::GetCheckpointManager() {
    return nullptr; // checkpoint_manager_.get();
}

// ============================================================================
// Event Handling
// ============================================================================

void SovereignUnifiedRuntime::RegisterLifecycleCallback(LifecycleCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    lifecycle_callbacks_.push_back(callback);
}

void SovereignUnifiedRuntime::NotifyEvent(LifecycleEvent event, const std::string& details) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    
    for (auto& callback : lifecycle_callbacks_) {
        try {
            callback(event, details);
        } catch (...) {
            // Log but don't propagate
        }
    }
}

// ============================================================================
// Health Monitoring
// ============================================================================

void SovereignUnifiedRuntime::StartHealthMonitoring() {
    if (health_monitoring_running_.exchange(true)) {
        return; // Already running
    }
    
    health_monitor_thread_ = std::thread(&SovereignUnifiedRuntime::HealthMonitorLoop, this);
}

void SovereignUnifiedRuntime::StopHealthMonitoring() {
    health_monitoring_running_ = false;
    
    if (health_monitor_thread_.joinable()) {
        health_monitor_thread_.join();
    }
}

void SovereignUnifiedRuntime::HealthMonitorLoop() {
    while (health_monitoring_running_) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        if (!health_monitoring_running_) break;
        
        UpdateComponentHealth();
    }
}

void SovereignUnifiedRuntime::UpdateComponentHealth() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    // Update health for each component
    // In production, this would check actual component health
    
    state_.component_health["autonomy"] = true;
    state_.component_health["scheduler"] = true;
    state_.component_health["swarm"] = true;
    state_.component_health["telemetry"] = true;
    state_.component_health["api_gateway"] = true;
    state_.component_health["checkpoint"] = true;
}

// ============================================================================
// Statistics
// ============================================================================

SovereignUnifiedRuntime::RuntimeStatistics SovereignUnifiedRuntime::GetStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void SovereignUnifiedRuntime::ResetStatistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = RuntimeStatistics{};
}

// ============================================================================
// CLI Integration
// ============================================================================

bool SovereignUnifiedRuntime::ExecuteCommand(const std::string& command, std::string& output) {
    if (command == "status") {
        output = ExportStateAsJson();
        return true;
    } else if (command == "health") {
        auto report = GenerateHealthReport();
        std::stringstream ss;
        ss << "Health: " << report.overall_status << "\n";
        for (const auto& comp : report.components) {
            ss << "  " << comp.name << ": " << (comp.healthy ? "OK" : "FAIL") << "\n";
        }
        output = ss.str();
        return true;
    } else if (command == "pause") {
        return Pause();
    } else if (command == "resume") {
        return Resume();
    } else if (command == "shutdown") {
        return Shutdown();
    }
    
    output = "Unknown command: " + command;
    return false;
}

std::vector<std::string> SovereignUnifiedRuntime::GetAvailableCommands() const {
    return {"status", "health", "pause", "resume", "shutdown"};
}

// ============================================================================
// Signal Handling
// ============================================================================

void SovereignUnifiedRuntime::HandleSignal(int signal) {
    switch (signal) {
        case 2:  // SIGINT
            std::cout << "\nReceived SIGINT, initiating graceful shutdown..." << std::endl;
            Shutdown();
            break;
        case 15: // SIGTERM
            std::cout << "Received SIGTERM, initiating graceful shutdown..." << std::endl;
            Shutdown();
            break;
        default:
            break;
    }
}

void SovereignUnifiedRuntime::RegisterSignalHandlers() {
    // In production, this would register actual signal handlers
    // std::signal(SIGINT, [](int sig) { SovereignUnifiedRuntime::Instance().HandleSignal(sig); });
}

// ============================================================================
// Private Methods
// ============================================================================

bool SovereignUnifiedRuntime::InitializeComponents() {
    // Create all enabled components
    
    if (config_.enable_autonomy) {
        if (!CreateAutonomyComponents()) return false;
    }
    
    if (config_.enable_adaptive_scheduler || config_.enable_distributed_scheduler) {
        if (!CreateSchedulerComponents()) return false;
    }
    
    if (config_.enable_api_gateway || config_.enable_query_engine) {
        if (!CreateInterfaceComponents()) return false;
    }
    
    if (config_.enable_telemetry) {
        if (!CreateTelemetryComponents()) return false;
    }
    
    if (config_.enable_swarm) {
        if (!CreateSwarmComponents()) return false;
    }
    
    if (config_.enable_checkpoints) {
        if (!CreateCheckpointComponents()) return false;
    }
    
    if (config_.enable_seg) {
        if (!CreateSEGComponents()) return false;
    }
    
    return true;
}

bool SovereignUnifiedRuntime::BootComponents() {
    // Boot all created components in dependency order
    
    // 1. Telemetry first (for monitoring)
    // if (telemetry_collector_) telemetry_collector_->Start();
    
    // 2. Checkpoints (for recovery)
    // if (checkpoint_manager_) checkpoint_manager_->Initialize();
    
    // 3. Scheduler (for task management)
    // if (adaptive_scheduler_) adaptive_scheduler_->Start();
    
    // 4. Swarm (for agent coordination)
    // if (swarm_coordinator_) swarm_coordinator_->Start();
    
    // 5. Autonomy (decision making)
    // if (autonomy_controller_) autonomy_controller_->Start();
    
    // 6. Stability envelope (safety)
    // if (stability_envelope_) stability_envelope_->Start();
    
    // 7. Interface layer (external access)
    // if (api_gateway_) api_gateway_->Start();
    // if (query_engine_) query_engine_->Start();
    
    return true;
}

bool SovereignUnifiedRuntime::ShutdownComponents() {
    // Shutdown in reverse order
    
    // 1. Interface layer
    // if (api_gateway_) api_gateway_->Stop();
    // if (query_engine_) query_engine_->Stop();
    
    // 2. Autonomy
    // if (autonomy_controller_) autonomy_controller_->Stop();
    // if (stability_envelope_) stability_envelope_->Stop();
    
    // 3. Swarm
    // if (swarm_coordinator_) swarm_coordinator_->Stop();
    
    // 4. Scheduler
    // if (adaptive_scheduler_) adaptive_scheduler_->Stop();
    
    // 5. Checkpoints
    // if (checkpoint_manager_) checkpoint_manager_->Shutdown();
    
    // 6. Telemetry
    // if (telemetry_collector_) telemetry_collector_->Stop();
    
    // Release all components
    autonomy_controller_.reset();
    stability_envelope_.reset();
    workload_forecaster_.reset();
    adaptive_scheduler_.reset();
    distributed_scheduler_.reset();
    seg_bridge_.reset();
    api_gateway_.reset();
    query_engine_.reset();
    human_protocol_.reset();
    telemetry_collector_.reset();
    performance_store_.reset();
    swarm_coordinator_.reset();
    checkpoint_manager_.reset();
    decision_memory_.reset();
    
    return true;
}

void SovereignUnifiedRuntime::TransitionToPhase(RuntimePhase new_phase) {
    state_.phase = new_phase;
    state_.last_state_change = std::chrono::steady_clock::now();
    NotifyEvent(LifecycleEvent::STATE_CHANGE, RuntimeUtils::PhaseToString(new_phase));
}

bool SovereignUnifiedRuntime::ValidateConfiguration() const {
    // Validate port ranges
    if (config_.api_port == 0 || config_.api_port > 65535) {
        std::cerr << "Invalid API port: " << config_.api_port << std::endl;
        return false;
    }
    
    // Validate swarm size
    if (config_.max_swarm_size == 0 || config_.max_swarm_size > 256) {
        std::cerr << "Invalid swarm size: " << config_.max_swarm_size << std::endl;
        return false;
    }
    
    return true;
}

// Component factory methods (placeholders)
bool SovereignUnifiedRuntime::CreateAutonomyComponents() { return true; }
bool SovereignUnifiedRuntime::CreateSchedulerComponents() { return true; }
bool SovereignUnifiedRuntime::CreateInterfaceComponents() { return true; }
bool SovereignUnifiedRuntime::CreateTelemetryComponents() { return true; }
bool SovereignUnifiedRuntime::CreateSwarmComponents() { return true; }
bool SovereignUnifiedRuntime::CreateCheckpointComponents() { return true; }
bool SovereignUnifiedRuntime::CreateSEGComponents() { return true; }

// ============================================================================
// Runtime Facade Implementation
// ============================================================================

bool RuntimeFacade::Start(RuntimeMode mode) {
    auto& runtime = SovereignUnifiedRuntime::Instance();
    
    if (!runtime.Initialize()) {
        return false;
    }
    
    return runtime.Boot(mode);
}

bool RuntimeFacade::Stop() {
    return SovereignUnifiedRuntime::Instance().Shutdown();
}

bool RuntimeFacade::Restart() {
    if (!Stop()) return false;
    return Start();
}

RuntimeState RuntimeFacade::GetCurrentState() {
    return SovereignUnifiedRuntime::Instance().GetState();
}

HealthReport RuntimeFacade::GetHealth() {
    return SovereignUnifiedRuntime::Instance().GenerateHealthReport();
}

std::string RuntimeFacade::GetStatusJson() {
    return SovereignUnifiedRuntime::Instance().ExportStateAsJson();
}

bool RuntimeFacade::EnableAutonomy(bool enable) {
    // Would toggle autonomy controller
    (void)enable;
    return true;
}

bool RuntimeFacade::TriggerCheckpoint() {
    auto* cm = SovereignUnifiedRuntime::Instance().GetCheckpointManager();
    if (!cm) return false;
    // return cm->CreateCheckpoint();
    return true;
}

bool RuntimeFacade::RestoreCheckpoint(const std::string& checkpoint_id) {
    auto* cm = SovereignUnifiedRuntime::Instance().GetCheckpointManager();
    if (!cm) return false;
    // return cm->RestoreCheckpoint(checkpoint_id);
    (void)checkpoint_id;
    return true;
}

std::vector<std::string> RuntimeFacade::GetActiveAgents() {
    // Would query swarm coordinator
    return {};
}

bool RuntimeFacade::SpawnAgent(const std::string& agent_type) {
    // Would use swarm coordinator
    (void)agent_type;
    return true;
}

// ============================================================================
// RuntimeUtils Implementation
// ============================================================================

namespace RuntimeUtils {

std::string PhaseToString(RuntimePhase phase) {
    switch (phase) {
        case RuntimePhase::UNINITIALIZED: return "UNINITIALIZED";
        case RuntimePhase::INITIALIZING: return "INITIALIZING";
        case RuntimePhase::BOOTING: return "BOOTING";
        case RuntimePhase::RUNNING: return "RUNNING";
        case RuntimePhase::PAUSED: return "PAUSED";
        case RuntimePhase::SHUTTING_DOWN: return "SHUTTING_DOWN";
        case RuntimePhase::SHUTDOWN: return "SHUTDOWN";
        case RuntimePhase::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

std::string ModeToString(RuntimeMode mode) {
    switch (mode) {
        case RuntimeMode::STANDALONE: return "STANDALONE";
        case RuntimeMode::IDE_INTEGRATED: return "IDE_INTEGRATED";
        case RuntimeMode::SERVER: return "SERVER";
        case RuntimeMode::DISTRIBUTED: return "DISTRIBUTED";
        default: return "UNKNOWN";
    }
}

RuntimePhase StringToPhase(const std::string& str) {
    if (str == "UNINITIALIZED") return RuntimePhase::UNINITIALIZED;
    if (str == "INITIALIZING") return RuntimePhase::INITIALIZING;
    if (str == "BOOTING") return RuntimePhase::BOOTING;
    if (str == "RUNNING") return RuntimePhase::RUNNING;
    if (str == "PAUSED") return RuntimePhase::PAUSED;
    if (str == "SHUTTING_DOWN") return RuntimePhase::SHUTTING_DOWN;
    if (str == "SHUTDOWN") return RuntimePhase::SHUTDOWN;
    if (str == "ERROR") return RuntimePhase::ERROR;
    return RuntimePhase::UNINITIALIZED;
}

RuntimeMode StringToMode(const std::string& str) {
    if (str == "STANDALONE") return RuntimeMode::STANDALONE;
    if (str == "IDE_INTEGRATED") return RuntimeMode::IDE_INTEGRATED;
    if (str == "SERVER") return RuntimeMode::SERVER;
    if (str == "DISTRIBUTED") return RuntimeMode::DISTRIBUTED;
    return RuntimeMode::STANDALONE;
}

bool IsTerminalPhase(RuntimePhase phase) {
    return phase == RuntimePhase::SHUTDOWN || phase == RuntimePhase::ERROR;
}

bool IsOperationalPhase(RuntimePhase phase) {
    return phase == RuntimePhase::RUNNING || phase == RuntimePhase::PAUSED;
}

std::string GenerateRuntimeId() {
    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    return "rawrxd-" + std::to_string(ms);
}

std::string GetVersionString() {
    return "1.0.0-sovereign";
}

std::string GetBuildInfo() {
    return "Build: " __DATE__ " " __TIME__;
}

} // namespace RuntimeUtils

} // namespace RawrXD
