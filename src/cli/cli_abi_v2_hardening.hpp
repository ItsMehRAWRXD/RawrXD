// ============================================================================
// CLI ABI v2: Agent-Native Execution Layer
// Contract Hardening — Execution IDs, Streaming, Capabilities, Manifest
// ============================================================================

#pragma once

#include "unified_execution_abi.hpp"
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>

namespace RawrXD {
namespace CLI {
namespace ABIv2 {

// ============================================================================
// Execution ID — Unique handle for every command invocation
// ============================================================================

struct ExecutionID {
    uint64_t id;
    uint64_t timestamp;
    uint32_t sequence;
    
    ExecutionID() : id(0), timestamp(0), sequence(0) {}
    ExecutionID(uint64_t i, uint64_t t, uint32_t s) : id(i), timestamp(t), sequence(s) {}
    
    std::string ToString() const {
        return "0x" + std::to_string(id);
    }
    
    bool IsValid() const { return id != 0; }
};

// ============================================================================
// Execution Event — Streaming results for long-running operations
// ============================================================================

enum class EventType {
    Progress,      // Percent complete, stage info
    Log,           // Diagnostic output
    Artifact,      // File/result produced
    Warning,       // Non-fatal issue
    Error,         // Fatal error
    Complete,      // Success completion
    Cancelled      // User/system cancellation
};

struct CLIExecutionEvent {
    ExecutionID execution_id;
    EventType type;
    std::string message;
    double progress_percent;  // 0.0 - 100.0
    nlohmann::json payload;
    uint64_t timestamp_ms;
    
    CLIExecutionEvent() : type(EventType::Log), progress_percent(0.0), timestamp_ms(0) {}
};

// ============================================================================
// Capability System — Security boundary for powerful primitives
// ============================================================================

enum class Capability {
    None = 0,
    ReadFile = 1 << 0,
    WriteFile = 1 << 1,
    ExecuteBinary = 1 << 2,
    ModifyBinary = 1 << 3,
    NetworkAccess = 1 << 4,
    SystemInfo = 1 << 5,
    ProcessControl = 1 << 6,
    MemoryInspect = 1 << 7,
    All = 0xFFFFFFFF
};

inline Capability operator|(Capability a, Capability b) {
    return static_cast<Capability>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline Capability operator&(Capability a, Capability b) {
    return static_cast<Capability>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline bool HasCapability(Capability granted, Capability required) {
    return (static_cast<uint32_t>(granted) & static_cast<uint32_t>(required)) == static_cast<uint32_t>(required);
}

std::string CapabilityToString(Capability cap);
Capability CapabilityFromString(const std::string& str);

// ============================================================================
// Command Manifest — Introspection for agent systems
// ============================================================================

struct CommandManifest {
    std::string name;
    std::string category;
    std::string description;
    std::vector<std::string> aliases;
    std::vector<Capability> requires_capabilities;
    std::vector<std::string> required_backends;
    bool supports_streaming;
    bool supports_cancellation;
    int estimated_duration_ms;  // -1 for unknown
    nlohmann::json schema;      // JSON schema for args validation
};

// ============================================================================
// Execution Context v2 — Enhanced with security and streaming
// ============================================================================

struct ExecutionContextV2 : public ExecutionContext {
    ExecutionID execution_id;
    Capability granted_capabilities;
    std::function<void(const CLIExecutionEvent&)> event_callback;
    std::atomic<bool>* cancellation_token;
    
    ExecutionContextV2() : granted_capabilities(Capability::None), cancellation_token(nullptr) {}
    
    bool IsCancelled() const {
        return cancellation_token && cancellation_token->load();
    }
    
    void EmitEvent(const CLIExecutionEvent& event) const {
        if (event_callback) {
            event_callback(event);
        }
    }
    
    void EmitProgress(double percent, const std::string& stage) const {
        CLIExecutionEvent evt;
        evt.execution_id = execution_id;
        evt.type = EventType::Progress;
        evt.progress_percent = percent;
        evt.message = stage;
        evt.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        EmitEvent(evt);
    }
    
    void EmitArtifact(const std::string& path, const std::string& type) const {
        CLIExecutionEvent evt;
        evt.execution_id = execution_id;
        evt.type = EventType::Artifact;
        evt.message = path;
        evt.payload = {{"type", type}, {"path", path}};
        evt.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        EmitEvent(evt);
    }
    
    bool CheckCapability(Capability required) const {
        return HasCapability(granted_capabilities, required);
    }
};

// ============================================================================
// Execution Result v2 — Enhanced with execution ID
// ============================================================================

struct CLIExecutionResultV2 : public CLIExecutionResult {
    ExecutionID execution_id;
    std::vector<CLIExecutionEvent> event_history;
    bool was_cancelled;
    uint64_t start_time_ms;
    uint64_t end_time_ms;
    
    CLIExecutionResultV2() : was_cancelled(false), start_time_ms(0), end_time_ms(0) {}
    
    nlohmann::json ToJSON() const {
        nlohmann::json j = CLIExecutionResult::ToJSON();
        j["execution_id"] = execution_id.ToString();
        j["was_cancelled"] = was_cancelled;
        j["duration_ms"] = end_time_ms - start_time_ms;
        j["event_count"] = event_history.size();
        return j;
    }
};

// ============================================================================
// Execution Registry v2 — Async execution with event streaming
// ============================================================================

class ExecutionRegistryV2 {
public:
    using CommandHandlerV2 = std::function<CLIExecutionResultV2(const ExecutionContextV2&)>;
    using EventHandler = std::function<void(const CLIExecutionEvent&)>;
    
    static ExecutionRegistryV2& Instance();
    
    // Registration
    void Register(const CommandManifest& manifest, CommandHandlerV2 handler);
    void Unregister(const std::string& name);
    
    // Introspection
    std::vector<CommandManifest> GetManifest() const;
    std::optional<CommandManifest> GetCommandInfo(const std::string& name) const;
    bool HasCommand(const std::string& name) const;
    
    // Execution
    ExecutionID ExecuteAsync(const std::string& command, 
                              const std::vector<std::string>& args,
                              Capability granted_caps,
                              EventHandler event_handler = nullptr);
    
    CLIExecutionResultV2 ExecuteSync(const std::string& command,
                                     const std::vector<std::string>& args,
                                     Capability granted_caps);
    
    // Control
    bool CancelExecution(const ExecutionID& id);
    std::optional<CLIExecutionResultV2> GetResult(const ExecutionID& id) const;
    std::vector<ExecutionID> GetActiveExecutions() const;
    std::vector<ExecutionID> GetExecutionHistory(int limit = 100) const;
    
    // Security
    bool CheckPermission(const std::string& command, Capability required) const;
    
private:
    ExecutionRegistryV2() = default;
    
    struct RegisteredCommand {
        CommandManifest manifest;
        CommandHandlerV2 handler;
    };
    
    struct ActiveExecution {
        ExecutionID id;
        std::string command;
        std::thread thread;
        std::atomic<bool> cancelled{false};
        std::optional<CLIExecutionResultV2> result;
        EventHandler event_handler;
        std::mutex result_mutex;
    };
    
    mutable std::mutex commands_mutex_;
    std::unordered_map<std::string, RegisteredCommand> commands_;
    
    mutable std::mutex executions_mutex_;
    std::unordered_map<uint64_t, std::shared_ptr<ActiveExecution>> active_executions_;
    std::deque<ExecutionID> execution_history_;
    
    std::atomic<uint32_t> sequence_counter_{0};
    
    ExecutionID GenerateExecutionID();
    void CleanupExecution(const ExecutionID& id);
};

// ============================================================================
// Capability Policy — Policy enforcement for agent/IDE requests
// ============================================================================

class CapabilityPolicy {
public:
    static CapabilityPolicy& Instance();
    
    // Policy configuration
    void SetDefaultPolicy(Capability allowed);
    void AddCommandPolicy(const std::string& command, Capability required);
    void RemoveCommandPolicy(const std::string& command);
    
    // Policy evaluation
    bool Evaluate(const std::string& command, Capability requested, std::string& denial_reason) const;
    Capability GetRequiredCapabilities(const std::string& command) const;
    
    // Policy sources
    void LoadFromJSON(const nlohmann::json& policy);
    nlohmann::json SaveToJSON() const;
    
private:
    CapabilityPolicy() : default_policy_(Capability::ReadFile | Capability::SystemInfo) {}
    
    Capability default_policy_;
    std::unordered_map<std::string, Capability> command_policies_;
    mutable std::mutex policy_mutex_;
};

// ============================================================================
// Execution Graph Integration — Bridge to ExecutionPolicyRouter
// ============================================================================

// Forward declaration for integration with existing RawrXD stack
namespace Execution {
    class GraphNode;
    class GraphBuilder;
}

class ExecutionGraphBridge {
public:
    static ExecutionGraphBridge& Instance();
    
    // Convert CLI command to graph node
    std::shared_ptr<Execution::GraphNode> CommandToNode(const std::string& command,
                                                         const std::vector<std::string>& args);
    
    // Execute via graph
    ExecutionID ExecuteViaGraph(const std::string& command,
                                   const std::vector<std::string>& args,
                                   Capability granted_caps);
    
    // Register CLI commands as graph primitives
    void RegisterGraphPrimitives();
    
private:
    ExecutionGraphBridge() = default;
    bool primitives_registered_ = false;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick execute with default capabilities
CLIExecutionResultV2 QuickExecute(const std::string& command, 
                                   const std::vector<std::string>& args = {});

// Execute with full event streaming
ExecutionID StreamingExecute(const std::string& command,
                               const std::vector<std::string>& args,
                               ExecutionRegistryV2::EventHandler handler);

// Get command manifest for agent discovery
nlohmann::json GetCommandManifestJSON();

} // namespace ABIv2
} // namespace CLI
} // namespace RawrXD
