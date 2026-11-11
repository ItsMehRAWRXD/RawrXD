// SovereignIDEIntegration.cpp
// Implementation of RawrXD IDE Integration

#include "SovereignIDEIntegration.hpp"
#include "../terminal/TerminalOwnership.hpp"
#include <thread>
#include <chrono>

namespace Sovereign {
namespace IDE {

SovereignIDEIntegration::~SovereignIDEIntegration() {
    Shutdown();
}

SovereignIDEIntegration& SovereignIDEIntegration::Instance() {
    static SovereignIDEIntegration instance;
    return instance;
}

bool SovereignIDEIntegration::Initialize(const IDEWindowHandles& handles, 
                                          const IDEIntegrationConfig& config) {
    if (state_ != IDEIntegrationState::DISCONNECTED) {
        return false;
    }
    
    state_ = IDEIntegrationState::CONNECTING;
    handles_ = handles;
    config_ = config;
    
    // Initialize the sovereign capsule
    if (config.enable_sovereign_capsule) {
        if (!InitializeCapsule()) {
            state_ = IDEIntegrationState::ERROR;
            return false;
        }
    }
    
    // Setup beacon subscriptions
    SetupBeaconSubscriptions();
    
    // Setup UI threads
    SetupUIThreads();
    
    state_ = IDEIntegrationState::READY;
    return true;
}

void SovereignIDEIntegration::Shutdown() {
    if (state_ == IDEIntegrationState::DISCONNECTED) {
        return;
    }
    
    state_ = IDEIntegrationState::DISCONNECTED;
    
    // Terminate all agents
    for (const auto& [agent_id, lease_id] : agent_leases_) {
        if (capsule_) {
            capsule_->TerminateAgent(lease_id);
        }
    }
    agent_leases_.clear();
    
    // Release all terminals
    for (const auto& [terminal_id, lease_id] : terminal_leases_) {
        (void)terminal_id;
        (void)lease_id;
        // Terminal cleanup handled by TerminalOwnership destructor
    }
    terminal_leases_.clear();
    
    // Unsubscribe from beacons
    if (capsule_ && !capsule_subscription_.empty()) {
        capsule_->Unsubscribe(capsule_subscription_);
    }
    
    // Shutdown capsule
    if (capsule_) {
        capsule_->Shutdown();
        capsule_ = nullptr;
    }
}

bool SovereignIDEIntegration::InitializeCapsule() {
    CapsuleConfig capsule_config;
    capsule_config.enable_spine = true;
    capsule_config.enable_terminal_ownership = config_.enable_terminal_ownership;
    capsule_config.enable_build_graph = true;
    capsule_config.enable_agent_leases = true;
    capsule_config.enable_beacon_bus = true;
    capsule_config.enable_intent_compression = config_.enable_intent_compression;
    capsule_config.enable_awareness = true;
    capsule_config.enable_validator = true;
    capsule_config.enable_recovery = true;
    capsule_config.enable_control_plane = false;  // IDE has its own UI
    capsule_config.heartbeat_interval_ms = config_.capsule_heartbeat_ms;
    
    capsule_ = &ExecutionCapsule::Instance();
    return capsule_->Initialize(capsule_config);
}

void SovereignIDEIntegration::SetupBeaconSubscriptions() {
    if (!capsule_) return;
    
    capsule_subscription_ = capsule_->Subscribe([this](const Beacon& beacon) {
        ProcessBeacon(beacon);
    });
}

void SovereignIDEIntegration::SetupUIThreads() {
    // Start UI refresh thread
    std::thread([this]() {
        while (state_ == IDEIntegrationState::READY) {
            UpdateBuildPanel();
            UpdateAgentPanel();
            UpdateTerminalPanel();
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.ui_refresh_ms));
        }
    }).detach();
}

// Editor commands
bool SovereignIDEIntegration::OpenFile(const std::string& path) {
    // Send beacon
    if (capsule_) {
        BeaconBus::Instance().EmitInfo(BeaconType::FILE_CREATED, "ide", "Opened: " + path);
    }
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.files_opened++;
    return true;
}

bool SovereignIDEIntegration::EditFile(const std::string& path, const std::string& content) {
    (void)content;
    
    if (capsule_) {
        BeaconBus::Instance().EmitInfo(BeaconType::FILE_MODIFIED, "ide", "Edited: " + path);
    }
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.files_edited++;
    return true;
}

bool SovereignIDEIntegration::SaveFile(const std::string& path) {
    if (capsule_) {
        BeaconBus::Instance().EmitInfo(BeaconType::FILE_MODIFIED, "ide", "Saved: " + path);
    }
    return true;
}

bool SovereignIDEIntegration::CloseFile(const std::string& path) {
    (void)path;
    return true;
}

std::string SovereignIDEIntegration::GetCurrentFile() const {
    return "";  // Would query IDE
}

std::string SovereignIDEIntegration::GetSelectedText() const {
    return "";  // Would query IDE
}

// Terminal commands
std::string SovereignIDEIntegration::CreateTerminal(const std::string& name) {
    if (!config_.enable_terminal_ownership) {
        return "";
    }
    
    uint64_t sessionId = terminal_ownership_.CreateSession("ide", "cmd.exe /c echo Terminal: " + name);
    if (sessionId == 0) {
        return "";
    }
    
    std::string terminal_id = std::to_string(sessionId);
    terminal_leases_[name] = sessionId;
    
    return name;
}

bool SovereignIDEIntegration::ExecuteInTerminal(const std::string& terminal_id, 
                                                const std::string& command) {
    auto it = terminal_leases_.find(terminal_id);
    if (it == terminal_leases_.end()) {
        return false;
    }
    
    return terminal_ownership_.WriteInput(it->second, command + "\n");
}

bool SovereignIDEIntegration::KillTerminal(const std::string& terminal_id) {
    auto it = terminal_leases_.find(terminal_id);
    if (it == terminal_leases_.end()) {
        return false;
    }
    
    bool result = terminal_ownership_.Terminate(it->second);
    terminal_leases_.erase(it);
    
    return result;
}

std::string SovereignIDEIntegration::GetTerminalOutput(const std::string& terminal_id) {
    auto it = terminal_leases_.find(terminal_id);
    if (it == terminal_leases_.end()) {
        return "";
    }
    
    auto output = terminal_ownership_.ReadOutput(it->second);
    return output.stdout_data;
}

// Build commands
bool SovereignIDEIntegration::TriggerBuild(const std::string& target) {
    if (!capsule_) return false;
    
    BuildConfiguration config;
    config.name = "IDE_Build";
    
    bool result = capsule_->ExecuteBuild(target, config);
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.builds_triggered++;
    
    return result;
}

bool SovereignIDEIntegration::CancelBuild() {
    if (!capsule_) return false;
    return capsule_->CancelBuild();
}

BuildState SovereignIDEIntegration::GetBuildState() const {
    if (!capsule_) return BuildState::IDLE;
    auto status = capsule_->GetBuildStatus();
    return status.state;
}

std::vector<std::string> SovereignIDEIntegration::GetBuildTargets() const {
    return {};  // Would query build system
}

// Agent commands
std::string SovereignIDEIntegration::SpawnEditorAgent(const std::string& purpose) {
    if (!capsule_) return "";
    
    AgentDescriptor desc;
    desc.agent_type = "editor";
    desc.purpose = purpose;
    desc.requested_tier = LeaseTier::STANDARD;
    desc.required_capabilities = {"FILE_READ", "FILE_WRITE"};
    
    auto lease_id = capsule_->SpawnAgent(desc);
    if (lease_id) {
        agent_leases_[*lease_id] = *lease_id;
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.agents_spawned++;
    }
    
    return lease_id.value_or("");
}

std::string SovereignIDEIntegration::SpawnBuildAgent(const std::string& purpose) {
    if (!capsule_) return "";
    
    AgentDescriptor desc;
    desc.agent_type = "builder";
    desc.purpose = purpose;
    desc.requested_tier = LeaseTier::PRIVILEGED;
    desc.required_capabilities = {"BUILD_TRIGGER", "TERMINAL_EXECUTE"};
    
    auto lease_id = capsule_->SpawnAgent(desc);
    if (lease_id) {
        agent_leases_[*lease_id] = *lease_id;
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.agents_spawned++;
    }
    
    return lease_id.value_or("");
}

std::string SovereignIDEIntegration::SpawnDebugAgent(const std::string& purpose) {
    if (!capsule_) return "";
    
    AgentDescriptor desc;
    desc.agent_type = "debugger";
    desc.purpose = purpose;
    desc.requested_tier = LeaseTier::PRIVILEGED;
    desc.required_capabilities = {"TERMINAL_EXECUTE", "TERMINAL_KILL"};
    
    auto lease_id = capsule_->SpawnAgent(desc);
    if (lease_id) {
        agent_leases_[*lease_id] = *lease_id;
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.agents_spawned++;
    }
    
    return lease_id.value_or("");
}

bool SovereignIDEIntegration::TerminateAgent(const std::string& agent_id) {
    if (!capsule_) return false;
    
    auto it = agent_leases_.find(agent_id);
    if (it == agent_leases_.end()) {
        return false;
    }
    
    bool result = capsule_->TerminateAgent(it->second);
    agent_leases_.erase(it);
    return result;
}

std::vector<std::string> SovereignIDEIntegration::GetActiveAgents() const {
    std::vector<std::string> agents;
    for (const auto& [agent_id, lease_id] : agent_leases_) {
        (void)lease_id;
        agents.push_back(agent_id);
    }
    return agents;
}

// Chat/Intent commands
std::string SovereignIDEIntegration::ProcessChatIntent(const std::string& message) {
    if (!capsule_) return "";
    
    FullIntent intent;
    intent.original_prompt = message;
    intent.interpreted_goal = message;
    intent.type = IntentType::CHAT_MESSAGE;
    
    auto result = capsule_->ExecuteIntent(intent);
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.intents_processed++;
    
    return std::get<std::string>(result.data);
}

std::string SovereignIDEIntegration::ProcessCodeIntent(const std::string& intent_str) {
    if (!capsule_) return "";
    
    auto result = capsule_->ExecuteIntent(intent_str);
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.intents_processed++;
    
    return std::get<std::string>(result.data);
}

// Event handling
void SovereignIDEIntegration::OnFileOpened(const std::string& path) {
    if (capsule_) {
        BeaconBus::Instance().EmitInfo(BeaconType::FILE_CREATED, "ide", path);
    }
}

void SovereignIDEIntegration::OnFileModified(const std::string& path) {
    if (capsule_) {
        BeaconBus::Instance().EmitInfo(BeaconType::FILE_MODIFIED, "ide", path);
    }
}

void SovereignIDEIntegration::OnBuildStarted() {
    if (capsule_) {
        BeaconBus::Instance().EmitInfo(BeaconType::BUILD_STARTED, "ide", "Build started");
    }
}

void SovereignIDEIntegration::OnBuildCompleted(bool success) {
    if (capsule_) {
        auto type = success ? BeaconType::BUILD_COMPLETED : BeaconType::BUILD_FAILED;
        BeaconBus::Instance().EmitInfo(type, "ide", success ? "Build succeeded" : "Build failed");
    }
}

void SovereignIDEIntegration::OnTerminalOutput(const std::string& terminal_id, 
                                                  const std::string& output) {
    (void)terminal_id;
    (void)output;
    // Would update terminal panel
}

void SovereignIDEIntegration::OnAgentSpawned(const std::string& agent_id) {
    (void)agent_id;
    UpdateAgentPanel();
}

void SovereignIDEIntegration::OnAgentTerminated(const std::string& agent_id) {
    (void)agent_id;
    UpdateAgentPanel();
}

// UI Updates
void SovereignIDEIntegration::UpdateStatusBar(const std::string& message) {
    (void)message;
    // Would update Win32 status bar
}

void SovereignIDEIntegration::UpdateBuildPanel() {
    // Would update build panel with current state
}

void SovereignIDEIntegration::UpdateAgentPanel() {
    // Would update agent panel with active agents
}

void SovereignIDEIntegration::UpdateTerminalPanel() {
    // Would update terminal panel
}

// Beacon handling
void SovereignIDEIntegration::ProcessBeacon(const Beacon& beacon) {
    switch (beacon.type) {
        case BeaconType::BUILD_STARTED:
            OnBuildStarted();
            break;
        case BeaconType::BUILD_COMPLETED:
            OnBuildCompleted(true);
            break;
        case BeaconType::BUILD_FAILED:
            OnBuildCompleted(false);
            break;
        case BeaconType::AGENT_SPAWNED:
            if (auto id = beacon.GetPayload<std::string>()) {
                OnAgentSpawned(*id);
            }
            break;
        case BeaconType::AGENT_TERMINATED:
            if (auto id = beacon.GetPayload<std::string>()) {
                OnAgentTerminated(*id);
            }
            break;
        default:
            break;
    }
}

// Statistics
SovereignIDEIntegration::IDEStats SovereignIDEIntegration::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

// Convenience function
SovereignIDEIntegration& GetIDEIntegration() {
    return SovereignIDEIntegration::Instance();
}

// RAII guard
IDEIntegrationGuard::IDEIntegrationGuard(const IDEWindowHandles& handles) {
    initialized_ = SovereignIDEIntegration::Instance().Initialize(handles);
}

IDEIntegrationGuard::~IDEIntegrationGuard() {
    if (initialized_) {
        SovereignIDEIntegration::Instance().Shutdown();
    }
}

bool IDEIntegrationGuard::IsReady() const {
    return initialized_ && SovereignIDEIntegration::Instance().IsReady();
}

} // namespace IDE
} // namespace Sovereign
