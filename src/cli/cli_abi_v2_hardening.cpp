// ============================================================================
// CLI ABI v2: Agent-Native Execution Layer — Implementation
// ============================================================================

#include "cli_abi_v2_hardening.hpp"
#include <random>
#include <sstream>

namespace RawrXD {
namespace CLI {
namespace ABIv2 {

// ============================================================================
// Capability String Conversion
// ============================================================================

std::string CapabilityToString(Capability cap) {
    switch (cap) {
        case Capability::None: return "none";
        case Capability::ReadFile: return "read_file";
        case Capability::WriteFile: return "write_file";
        case Capability::ExecuteBinary: return "execute_binary";
        case Capability::ModifyBinary: return "modify_binary";
        case Capability::NetworkAccess: return "network_access";
        case Capability::SystemInfo: return "system_info";
        case Capability::ProcessControl: return "process_control";
        case Capability::MemoryInspect: return "memory_inspect";
        case Capability::All: return "all";
        default: return "unknown";
    }
}

Capability CapabilityFromString(const std::string& str) {
    if (str == "read_file") return Capability::ReadFile;
    if (str == "write_file") return Capability::WriteFile;
    if (str == "execute_binary") return Capability::ExecuteBinary;
    if (str == "modify_binary") return Capability::ModifyBinary;
    if (str == "network_access") return Capability::NetworkAccess;
    if (str == "system_info") return Capability::SystemInfo;
    if (str == "process_control") return Capability::ProcessControl;
    if (str == "memory_inspect") return Capability::MemoryInspect;
    if (str == "all") return Capability::All;
    return Capability::None;
}

// ============================================================================
// ExecutionRegistryV2 Implementation
// ============================================================================

ExecutionRegistryV2& ExecutionRegistryV2::Instance() {
    static ExecutionRegistryV2 instance;
    return instance;
}

void ExecutionRegistryV2::Register(const CommandManifest& manifest, CommandHandlerV2 handler) {
    std::lock_guard<std::mutex> lock(commands_mutex_);
    commands_[manifest.name] = {manifest, handler};
}

void ExecutionRegistryV2::Unregister(const std::string& name) {
    std::lock_guard<std::mutex> lock(commands_mutex_);
    commands_.erase(name);
}

std::vector<CommandManifest> ExecutionRegistryV2::GetManifest() const {
    std::lock_guard<std::mutex> lock(commands_mutex_);
    std::vector<CommandManifest> result;
    for (const auto& [name, cmd] : commands_) {
        result.push_back(cmd.manifest);
    }
    return result;
}

std::optional<CommandManifest> ExecutionRegistryV2::GetCommandInfo(const std::string& name) const {
    std::lock_guard<std::mutex> lock(commands_mutex_);
    auto it = commands_.find(name);
    if (it != commands_.end()) {
        return it->second.manifest;
    }
    return std::nullopt;
}

bool ExecutionRegistryV2::HasCommand(const std::string& name) const {
    std::lock_guard<std::mutex> lock(commands_mutex_);
    return commands_.find(name) != commands_.end();
}

ExecutionID ExecutionRegistryV2::GenerateExecutionID() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    
    uint64_t id = dis(gen);
    uint64_t timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    uint32_t seq = sequence_counter_++;
    
    return ExecutionID(id, timestamp, seq);
}

ExecutionID ExecutionRegistryV2::ExecuteAsync(const std::string& command,
                                                 const std::vector<std::string>& args,
                                                 Capability granted_caps,
                                                 EventHandler event_handler) {
    std::lock_guard<std::mutex> lock(commands_mutex_);
    auto it = commands_.find(command);
    if (it == commands_.end()) {
        // Return invalid ID for unknown command
        return ExecutionID();
    }
    
    // Check capabilities
    Capability required = Capability::None;
    for (const auto& cap : it->second.manifest.requires_capabilities) {
        required = required | cap;
    }
    
    if (!HasCapability(granted_caps, required)) {
        // Emit capability denial event
        if (event_handler) {
            CLIExecutionEvent evt;
            evt.type = EventType::Error;
            evt.message = "Capability denied for command: " + command;
            event_handler(evt);
        }
        return ExecutionID();
    }
    
    ExecutionID id = GenerateExecutionID();
    
    auto exec = std::make_shared<ActiveExecution>();
    exec->id = id;
    exec->command = command;
    exec->event_handler = event_handler;
    
    {
        std::lock_guard<std::mutex> elock(executions_mutex_);
        active_executions_[id.id] = exec;
        execution_history_.push_back(id);
        if (execution_history_.size() > 1000) {
            execution_history_.pop_front();
        }
    }
    
    exec->thread = std::thread([this, exec, &it, args, granted_caps]() {
        ExecutionContextV2 ctx;
        ctx.execution_id = exec->id;
        ctx.command = exec->command;
        ctx.args = args;
        ctx.granted_capabilities = granted_caps;
        ctx.cancellation_token = &exec->cancelled;
        ctx.event_callback = [exec](const CLIExecutionEvent& evt) {
            if (exec->event_handler) {
                exec->event_handler(evt);
            }
        };
        
        CLIExecutionResultV2 result = it->second.handler(ctx);
        result.execution_id = exec->id;
        
        {
            std::lock_guard<std::mutex> rlock(exec->result_mutex);
            exec->result = result;
        }
        
        // Emit completion event
        if (exec->event_handler) {
            CLIExecutionEvent evt;
            evt.execution_id = exec->id;
            evt.type = result.success ? EventType::Complete : EventType::Error;
            evt.message = result.success ? "Completed" : result.error;
            evt.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            exec->event_handler(evt);
        }
        
        CleanupExecution(exec->id);
    });
    
    exec->thread.detach();
    return id;
}

CLIExecutionResultV2 ExecutionRegistryV2::ExecuteSync(const std::string& command,
                                                       const std::vector<std::string>& args,
                                                       Capability granted_caps) {
    std::lock_guard<std::mutex> lock(commands_mutex_);
    auto it = commands_.find(command);
    if (it == commands_.end()) {
        CLIExecutionResultV2 result;
        result.success = false;
        result.error = "Unknown command: " + command;
        return result;
    }
    
    // Check capabilities
    Capability required = Capability::None;
    for (const auto& cap : it->second.manifest.requires_capabilities) {
        required = required | cap;
    }
    
    if (!HasCapability(granted_caps, required)) {
        CLIExecutionResultV2 result;
        result.success = false;
        result.error = "Capability denied for command: " + command;
        return result;
    }
    
    ExecutionID id = GenerateExecutionID();
    
    ExecutionContextV2 ctx;
    ctx.execution_id = id;
    ctx.command = command;
    ctx.args = args;
    ctx.granted_capabilities = granted_caps;
    ctx.cancellation_token = nullptr;
    
    uint64_t start = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    CLIExecutionResultV2 result = it->second.handler(ctx);
    result.execution_id = id;
    result.start_time_ms = start;
    result.end_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    return result;
}

bool ExecutionRegistryV2::CancelExecution(const ExecutionID& id) {
    std::lock_guard<std::mutex> lock(executions_mutex_);
    auto it = active_executions_.find(id.id);
    if (it != active_executions_.end()) {
        it->second->cancelled.store(true);
        return true;
    }
    return false;
}

std::optional<CLIExecutionResultV2> ExecutionRegistryV2::GetResult(const ExecutionID& id) const {
    std::lock_guard<std::mutex> lock(executions_mutex_);
    auto it = active_executions_.find(id.id);
    if (it != active_executions_.end()) {
        std::lock_guard<std::mutex> rlock(it->second->result_mutex);
        return it->second->result;
    }
    return std::nullopt;
}

std::vector<ExecutionID> ExecutionRegistryV2::GetActiveExecutions() const {
    std::lock_guard<std::mutex> lock(executions_mutex_);
    std::vector<ExecutionID> result;
    for (const auto& [id, exec] : active_executions_) {
        result.push_back(exec->id);
    }
    return result;
}

std::vector<ExecutionID> ExecutionRegistryV2::GetExecutionHistory(int limit) const {
    std::lock_guard<std::mutex> lock(executions_mutex_);
    std::vector<ExecutionID> result;
    int count = 0;
    for (auto it = execution_history_.rbegin(); it != execution_history_.rend() && count < limit; ++it, ++count) {
        result.push_back(*it);
    }
    return result;
}

bool ExecutionRegistryV2::CheckPermission(const std::string& command, Capability required) const {
    std::lock_guard<std::mutex> lock(commands_mutex_);
    auto it = commands_.find(command);
    if (it == commands_.end()) return false;
    
    Capability cmd_required = Capability::None;
    for (const auto& cap : it->second.manifest.requires_capabilities) {
        cmd_required = cmd_required | cap;
    }
    
    return HasCapability(required, cmd_required);
}

void ExecutionRegistryV2::CleanupExecution(const ExecutionID& id) {
    std::lock_guard<std::mutex> lock(executions_mutex_);
    active_executions_.erase(id.id);
}

// ============================================================================
// CapabilityPolicy Implementation
// ============================================================================

CapabilityPolicy& CapabilityPolicy::Instance() {
    static CapabilityPolicy instance;
    return instance;
}

void CapabilityPolicy::SetDefaultPolicy(Capability allowed) {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    default_policy_ = allowed;
}

void CapabilityPolicy::AddCommandPolicy(const std::string& command, Capability required) {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    command_policies_[command] = required;
}

void CapabilityPolicy::RemoveCommandPolicy(const std::string& command) {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    command_policies_.erase(command);
}

bool CapabilityPolicy::Evaluate(const std::string& command, Capability requested, std::string& denial_reason) const {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    
    auto it = command_policies_.find(command);
    if (it != command_policies_.end()) {
        if (!HasCapability(requested, it->second)) {
            denial_reason = "Command '" + command + "' requires capabilities not granted";
            return false;
        }
    } else {
        if (!HasCapability(requested, default_policy_)) {
            denial_reason = "Default policy denies command '" + command + "'";
            return false;
        }
    }
    
    return true;
}

Capability CapabilityPolicy::GetRequiredCapabilities(const std::string& command) const {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    auto it = command_policies_.find(command);
    if (it != command_policies_.end()) {
        return it->second;
    }
    return default_policy_;
}

void CapabilityPolicy::LoadFromJSON(const nlohmann::json& policy) {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    
    if (policy.contains("default")) {
        std::string def = policy["default"];
        if (def == "read_only") {
            default_policy_ = Capability::ReadFile | Capability::SystemInfo;
        } else if (def == "standard") {
            default_policy_ = Capability::ReadFile | Capability::WriteFile | Capability::SystemInfo | Capability::NetworkAccess;
        } else if (def == "full") {
            default_policy_ = Capability::All;
        }
    }
    
    if (policy.contains("commands")) {
        for (const auto& [cmd, caps] : policy["commands"].items()) {
            Capability required = Capability::None;
            for (const auto& cap : caps) {
                required = required | CapabilityFromString(cap);
            }
            command_policies_[cmd] = required;
        }
    }
}

nlohmann::json CapabilityPolicy::SaveToJSON() const {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    
    nlohmann::json policy;
    policy["default"] = CapabilityToString(default_policy_);
    
    for (const auto& [cmd, caps] : command_policies_) {
        policy["commands"][cmd] = CapabilityToString(caps);
    }
    
    return policy;
}

// ============================================================================
// ExecutionGraphBridge Implementation
// ============================================================================

ExecutionGraphBridge& ExecutionGraphBridge::Instance() {
    static ExecutionGraphBridge instance;
    return instance;
}

void ExecutionGraphBridge::RegisterGraphPrimitives() {
    if (primitives_registered_) return;
    
    // Register CLI commands as graph primitives
    // This bridges to the existing ExecutionPolicyRouter
    
    primitives_registered_ = true;
}

// ============================================================================
// Convenience Functions
// ============================================================================

CLIExecutionResultV2 QuickExecute(const std::string& command, const std::vector<std::string>& args) {
    return ExecutionRegistryV2::Instance().ExecuteSync(command, args, 
        Capability::ReadFile | Capability::WriteFile | Capability::SystemInfo);
}

ExecutionID StreamingExecute(const std::string& command,
                               const std::vector<std::string>& args,
                               ExecutionRegistryV2::EventHandler handler) {
    return ExecutionRegistryV2::Instance().ExecuteAsync(command, args,
        Capability::ReadFile | Capability::WriteFile | Capability::SystemInfo, handler);
}

nlohmann::json GetCommandManifestJSON() {
    auto manifest = ExecutionRegistryV2::Instance().GetManifest();
    nlohmann::json result = nlohmann::json::array();
    
    for (const auto& cmd : manifest) {
        nlohmann::json j;
        j["name"] = cmd.name;
        j["category"] = cmd.category;
        j["description"] = cmd.description;
        j["aliases"] = cmd.aliases;
        j["supports_streaming"] = cmd.supports_streaming;
        j["supports_cancellation"] = cmd.supports_cancellation;
        j["estimated_duration_ms"] = cmd.estimated_duration_ms;
        
        nlohmann::json caps = nlohmann::json::array();
        for (const auto& cap : cmd.requires_capabilities) {
            caps.push_back(CapabilityToString(cap));
        }
        j["requires_capabilities"] = caps;
        
        result.push_back(j);
    }
    
    return result;
}

} // namespace ABIv2
} // namespace CLI
} // namespace RawrXD
