#pragma once
// ============================================================================
// Unified Execution ABI — RawrXD CLI v4.0
// ============================================================================
// Provides a single execution contract for all CLI commands
// Every command resolves to CLIExecutionResult
// ============================================================================

#include <string>
#include <vector>
#include <chrono>
#include <nlohmann/json.hpp>
#include <functional>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace CLI {

// ============================================================================
// Execution Result Contract
// ============================================================================

struct CLIExecutionResult {
    bool success = false;
    std::string command;
    std::string output;
    std::string error;
    double executionMs = 0.0;
    std::vector<std::string> artifacts;
    std::string backendUsed;
    nlohmann::json metadata;
    
    // Timestamp
    std::chrono::system_clock::time_point timestamp;
    
    // Validation
    bool IsValid() const {
        return !command.empty() && (success || !error.empty());
    }
    
    // Serialization
    nlohmann::json ToJSON() const {
        return {
            {"success", success},
            {"command", command},
            {"output", output},
            {"error", error},
            {"executionMs", executionMs},
            {"artifacts", artifacts},
            {"backendUsed", backendUsed},
            {"metadata", metadata},
            {"timestamp", std::chrono::system_clock::to_time_t(timestamp)}
        };
    }
    
    static CLIExecutionResult FromJSON(const nlohmann::json& json) {
        CLIExecutionResult result;
        result.success = json.value("success", false);
        result.command = json.value("command", "");
        result.output = json.value("output", "");
        result.error = json.value("error", "");
        result.executionMs = json.value("executionMs", 0.0);
        if (json.contains("artifacts")) {
            result.artifacts = json["artifacts"].get<std::vector<std::string>>();
        }
        result.backendUsed = json.value("backendUsed", "");
        result.metadata = json.value("metadata", nlohmann::json::object());
        result.timestamp = std::chrono::system_clock::now();
        return result;
    }
};

// ============================================================================
// Execution Context
// ============================================================================

struct ExecutionContext {
    std::string command;
    std::vector<std::string> args;
    std::unordered_map<std::string, std::string> env;
    std::string workingDirectory;
    std::string user;
    int timeoutMs = 30000;
    bool verbose = false;
    nlohmann::json sessionData;
    
    // Capability hints
    enum class Capability {
        OPTIMIZATION,
        COMPRESSION,
        INFERENCE,
        CODE_GENERATION,
        ANALYSIS,
        DEBUGGING,
        RESEARCH,
        SYNTHESIS
    };
    std::vector<Capability> requiredCapabilities;
};

// ============================================================================
// Command Handler Type
// ============================================================================

using CommandHandler = std::function<CLIExecutionResult(const ExecutionContext&)>;

// ============================================================================
// Command Registry
// ============================================================================

struct CommandRegistration {
    std::string name;
    std::vector<std::string> aliases;
    std::string description;
    std::string usage;
    ExecutionContext::Capability primaryCapability;
    CommandHandler handler;
    bool requiresBackend = false;
    bool requiresEngine = false;
};

class CommandRegistry {
public:
    static CommandRegistry& Instance();
    
    // Registration
    void Register(const CommandRegistration& cmd);
    void Unregister(const std::string& name);
    
    // Resolution
    std::optional<CommandRegistration> Resolve(const std::string& name) const;
    std::vector<CommandRegistration> GetAll() const;
    std::vector<CommandRegistration> GetByCapability(ExecutionContext::Capability cap) const;
    
    // Execution
    CLIExecutionResult Execute(const std::string& command, const std::vector<std::string>& args);
    CLIExecutionResult Execute(const ExecutionContext& ctx);
    
    // Validation
    bool ValidateCommand(const std::string& name) const;
    
private:
    CommandRegistry() = default;
    std::unordered_map<std::string, CommandRegistration> m_commands;
    mutable std::mutex m_mutex;
};

// ============================================================================
// Execution Pipeline
// ============================================================================

class ExecutionPipeline {
public:
    static ExecutionPipeline& Instance();
    
    // Pipeline stages
    CLIExecutionResult Execute(const ExecutionContext& ctx);
    
    // Stage hooks
    using PreExecuteHook = std::function<void(ExecutionContext&)>;
    using PostExecuteHook = std::function<void(CLIExecutionResult&)>;
    
    void AddPreExecuteHook(PreExecuteHook hook);
    void AddPostExecuteHook(PostExecuteHook hook);
    
    // Telemetry
    struct ExecutionStats {
        uint64_t totalExecutions = 0;
        uint64_t successfulExecutions = 0;
        uint64_t failedExecutions = 0;
        double averageExecutionMs = 0.0;
        std::unordered_map<std::string, uint64_t> commandCounts;
    };
    ExecutionStats GetStats() const;
    void ResetStats();
    
private:
    ExecutionPipeline() = default;
    std::vector<PreExecuteHook> m_preHooks;
    std::vector<PostExecuteHook> m_postHooks;
    ExecutionStats m_stats;
    mutable std::mutex m_mutex;
};

// ============================================================================
// Runtime Status Commands
// ============================================================================

class RuntimeStatusCommands {
public:
    // Engine status
    static CLIExecutionResult EngineStatus(const ExecutionContext& ctx);
    static CLIExecutionResult BackendStatus(const ExecutionContext& ctx);
    static CLIExecutionResult MemoryStatus(const ExecutionContext& ctx);
    static CLIExecutionResult CompressionStatus(const ExecutionContext& ctx);
    static CLIExecutionResult KernelStatus(const ExecutionContext& ctx);
    
    // Model intelligence
    static CLIExecutionResult ModelInspect(const ExecutionContext& ctx);
    static CLIExecutionResult ModelList(const ExecutionContext& ctx);
    
    // Profiling
    static CLIExecutionResult ProfileStart(const ExecutionContext& ctx);
    static CLIExecutionResult ProfileStop(const ExecutionContext& ctx);
    static CLIExecutionResult ProfileBottlenecks(const ExecutionContext& ctx);
    
    // Compression controls
    static CLIExecutionResult CompressionTune(const ExecutionContext& ctx);
    static CLIExecutionResult CompressionProfile(const ExecutionContext& ctx);
};

// ============================================================================
// Initialization
// ============================================================================

void InitializeUnifiedExecutionABI();

} // namespace CLI
} // namespace RawrXD
