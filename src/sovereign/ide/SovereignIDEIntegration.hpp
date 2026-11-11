// SovereignIDEIntegration.hpp
// RawrXD IDE Integration - connects 10 coordination primitives to the IDE
// This is the bridge between the sovereign system and the Win32 IDE

#pragma once
#include "../capsule/ExecutionCapsule.hpp"
#include "../terminal/TerminalOwnership.hpp"

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <map>
#include <mutex>

// Forward declarations for IDE types
struct HWND__;
typedef HWND__* HWND;

namespace Sovereign {
namespace IDE {

// IDE integration state
enum class IDEIntegrationState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    READY,
    ERROR
};

// IDE window handles
struct IDEWindowHandles {
    void* main_window;           // HWND
    void* editor_window;         // HWND
    void* terminal_panel;        // HWND
    void* build_panel;           // HWND
    void* agent_panel;           // HWND
    void* status_bar;            // HWND
};

// IDE integration configuration
struct IDEIntegrationConfig {
    bool enable_sovereign_capsule = true;
    bool enable_agent_panel = true;
    bool enable_build_graph_panel = true;
    bool enable_terminal_ownership = true;
    bool enable_beacon_overlay = true;
    bool enable_intent_compression = true;
    
    uint32_t capsule_heartbeat_ms = 1000;
    uint32_t ui_refresh_ms = 100;
    std::string default_agent_tier = "STANDARD";
};

// The Sovereign IDE Integration
class SovereignIDEIntegration {
public:
    static SovereignIDEIntegration& Instance();
    
    // Lifecycle
    bool Initialize(const IDEWindowHandles& handles, const IDEIntegrationConfig& config = IDEIntegrationConfig{});
    void Shutdown();
    bool IsInitialized() const { return state_ != IDEIntegrationState::DISCONNECTED; }
    bool IsReady() const { return state_ == IDEIntegrationState::READY; }
    IDEIntegrationState GetState() const { return state_; }
    
    // IDE Commands - these integrate with the capsule
    
    // Editor commands
    bool OpenFile(const std::string& path);
    bool EditFile(const std::string& path, const std::string& content);
    bool SaveFile(const std::string& path);
    bool CloseFile(const std::string& path);
    std::string GetCurrentFile() const;
    std::string GetSelectedText() const;
    
    // Terminal commands (with ownership)
    std::string CreateTerminal(const std::string& name);
    bool ExecuteInTerminal(const std::string& terminal_id, const std::string& command);
    bool KillTerminal(const std::string& terminal_id);
    std::string GetTerminalOutput(const std::string& terminal_id);
    
    // Build commands (with state graph)
    bool TriggerBuild(const std::string& target);
    bool CancelBuild();
    BuildState GetBuildState() const;
    std::vector<std::string> GetBuildTargets() const;
    
    // Agent commands (with leases)
    std::string SpawnEditorAgent(const std::string& purpose);
    std::string SpawnBuildAgent(const std::string& purpose);
    std::string SpawnDebugAgent(const std::string& purpose);
    bool TerminateAgent(const std::string& agent_id);
    std::vector<std::string> GetActiveAgents() const;
    
    // Chat/Intent commands (with compression)
    std::string ProcessChatIntent(const std::string& message);
    std::string ProcessCodeIntent(const std::string& intent);
    
    // Event handling
    void OnFileOpened(const std::string& path);
    void OnFileModified(const std::string& path);
    void OnBuildStarted();
    void OnBuildCompleted(bool success);
    void OnTerminalOutput(const std::string& terminal_id, const std::string& output);
    void OnAgentSpawned(const std::string& agent_id);
    void OnAgentTerminated(const std::string& agent_id);
    
    // UI Updates
    void UpdateStatusBar(const std::string& message);
    void UpdateBuildPanel();
    void UpdateAgentPanel();
    void UpdateTerminalPanel();
    
    // Beacon handling
    void ProcessBeacon(const Beacon& beacon);
    
    // Statistics
    struct IDEStats {
        uint64_t files_opened;
        uint64_t files_edited;
        uint64_t builds_triggered;
        uint64_t agents_spawned;
        uint64_t intents_processed;
        double average_response_time_ms;
    };
    IDEStats GetStats() const;

private:
    SovereignIDEIntegration() = default;
    ~SovereignIDEIntegration();
    
    SovereignIDEIntegration(const SovereignIDEIntegration&) = delete;
    SovereignIDEIntegration& operator=(const SovereignIDEIntegration&) = delete;
    
    // Internal helpers
    bool InitializeCapsule();
    void SetupBeaconSubscriptions();
    void SetupUIThreads();
    void ProcessBeaconQueue();
    
    IDEIntegrationState state_ = IDEIntegrationState::DISCONNECTED;
    IDEWindowHandles handles_;
    IDEIntegrationConfig config_;
    
    // Capsule reference
    ExecutionCapsule* capsule_ = nullptr;
    std::string capsule_subscription_;
    
    // Agent tracking
    std::map<std::string, std::string> agent_leases_;  // agent_id -> lease_id
    std::map<std::string, uint64_t> terminal_leases_;  // terminal_id -> session_id
    
    // Terminal ownership
    TerminalOwnership terminal_ownership_;
    
    // Statistics
    IDEStats stats_;
    mutable std::mutex stats_mutex_;
};

// Convenience function
SovereignIDEIntegration& GetIDEIntegration();

// RAII guard for IDE integration
class IDEIntegrationGuard {
public:
    IDEIntegrationGuard(const IDEWindowHandles& handles);
    ~IDEIntegrationGuard();
    
    IDEIntegrationGuard(const IDEIntegrationGuard&) = delete;
    IDEIntegrationGuard& operator=(const IDEIntegrationGuard&) = delete;
    
    bool IsReady() const;
    SovereignIDEIntegration* operator->() { return &SovereignIDEIntegration::Instance(); }

private:
    bool initialized_;
};

} // namespace IDE
} // namespace Sovereign
