// ============================================================================
// ToolDispatcher.cpp — Centralized Tool Execution Authority
// ============================================================================

#include "ToolDispatcher.hpp"
#include "AgentToolHandlers.h"
#include <thread>
#include <future>
#include <chrono>

namespace RawrXD {
namespace Agent {

// ============================================================================
// ToolRegistry
// ============================================================================
ToolRegistry::ToolRegistry() = default;
ToolRegistry::~ToolRegistry() = default;

void ToolRegistry::Register(const std::string& name,
                            const ToolMetadata& meta,
                            ToolHandler handler) {
    std::lock_guard<std::mutex> lock(m_mutex);
    ToolEntry entry;
    entry.meta = meta;
    entry.handler = std::move(handler);
    m_tools[name] = std::move(entry);
}

bool ToolRegistry::HasTool(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_tools.find(name) != m_tools.end();
}

const ToolMetadata* ToolRegistry::GetMetadata(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_tools.find(name);
    if (it != m_tools.end()) return &(it->second.meta);
    return nullptr;
}

ToolHandler ToolRegistry::GetHandler(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_tools.find(name);
    if (it != m_tools.end()) return it->second.handler;
    return nullptr;
}

nlohmann::json ToolRegistry::GetAllSchemas() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    nlohmann::json schemas = nlohmann::json::array();
    for (const auto& [name, entry] : m_tools) {
        if (!entry.meta.schema.empty()) {
            schemas.push_back(entry.meta.schema);
        }
    }
    return schemas;
}

nlohmann::json ToolRegistry::GetSchema(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_tools.find(name);
    if (it != m_tools.end()) return it->second.meta.schema;
    return nullptr;
}

// ListTools() defined in RawrXD_ToolRegistry.cpp — do not duplicate here

std::vector<std::string> ToolRegistry::ListToolsByPermission(ToolPermission perm) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> names;
    for (const auto& [name, entry] : m_tools) {
        for (const auto& p : entry.meta.permissions) {
            if (p == perm) {
                names.push_back(name);
                break;
            }
        }
    }
    return names;
}

void ToolRegistry::RegisterBuiltInTools() {
    // Register all AgentToolHandlers through the new dispatcher
    // These wrap the static handlers with AgentRun context

    auto wrap = [](auto handler) -> ToolHandler {
        return [handler](const nlohmann::json& args, AgentRun& run) -> ToolCallResult {
            (void)run; // Budget already checked by dispatcher
            return handler(args);
        };
    };

    ToolMetadata meta;

    // read_file
    meta = ToolMetadata{
        "read_file", "Read file contents",
        AgentToolHandlers::GetSchema("read_file"),
        {ToolPermission::Read}, 300, 1, true, false, "filesystem"
    };
    Register("read_file", meta, wrap(AgentToolHandlers::ToolReadFile));

    // write_file
    meta = ToolMetadata{
        "write_file", "Write file contents",
        AgentToolHandlers::GetSchema("write_file"),
        {ToolPermission::Write}, 300, 1, false, true, "filesystem"
    };
    Register("write_file", meta, wrap(AgentToolHandlers::WriteFile));

    // replace_in_file
    meta = ToolMetadata{
        "replace_in_file", "Replace text in file",
        AgentToolHandlers::GetSchema("replace_in_file"),
        {ToolPermission::Write}, 300, 1, false, true, "filesystem"
    };
    Register("replace_in_file", meta, wrap(AgentToolHandlers::ReplaceInFile));

    // list_dir
    meta = ToolMetadata{
        "list_dir", "List directory contents",
        AgentToolHandlers::GetSchema("list_dir"),
        {ToolPermission::Read}, 60, 1, true, false, "filesystem"
    };
    Register("list_dir", meta, wrap(AgentToolHandlers::ListDir));

    // execute_command
    meta = ToolMetadata{
        "execute_command", "Execute shell command",
        AgentToolHandlers::GetSchema("execute_command"),
        {ToolPermission::Execute, ToolPermission::Process}, 300, 5, false, true, "shell"
    };
    Register("execute_command", meta, wrap(AgentToolHandlers::ExecuteCommand));

    // search_code
    meta = ToolMetadata{
        "search_code", "Search code in workspace",
        AgentToolHandlers::GetSchema("search_code"),
        {ToolPermission::Read}, 120, 1, true, false, "search"
    };
    Register("search_code", meta, wrap(AgentToolHandlers::SearchCode));

    // get_diagnostics
    meta = ToolMetadata{
        "get_diagnostics", "Get diagnostics for file",
        AgentToolHandlers::GetSchema("get_diagnostics"),
        {ToolPermission::Read}, 60, 1, true, false, "analysis"
    };
    Register("get_diagnostics", meta, wrap(AgentToolHandlers::GetDiagnostics));
}

// ============================================================================
// PermissionPolicy
// ============================================================================
PermissionPolicy::PermissionPolicy() {
    // Default: READ allowed, everything else requires approval
    m_permLevels[ToolPermission::Read] = PermissionLevel::Allowed;
    m_permLevels[ToolPermission::Write] = PermissionLevel::ApprovalRequired;
    m_permLevels[ToolPermission::Execute] = PermissionLevel::ApprovalRequired;
    m_permLevels[ToolPermission::Network] = PermissionLevel::Blocked;
    m_permLevels[ToolPermission::Process] = PermissionLevel::ApprovalRequired;
    m_permLevels[ToolPermission::System] = PermissionLevel::Blocked;
    m_permLevels[ToolPermission::Git] = PermissionLevel::ApprovalRequired;
    m_permLevels[ToolPermission::Model] = PermissionLevel::Allowed;
}

PermissionPolicy::~PermissionPolicy() = default;

void PermissionPolicy::SetLevel(ToolPermission perm, PermissionLevel level) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_permLevels[perm] = level;
}

void PermissionPolicy::SetLevel(const std::string& toolName, PermissionLevel level) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_toolLevels[toolName] = level;
}

bool PermissionPolicy::IsAllowed(const std::string& toolName,
                                 const ToolMetadata& meta,
                                 const nlohmann::json& args) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Check tool-specific override first
    auto toolIt = m_toolLevels.find(toolName);
    if (toolIt != m_toolLevels.end()) {
        if (toolIt->second == PermissionLevel::Blocked) return false;
        if (toolIt->second == PermissionLevel::Allowed) return true;
        // ApprovalRequired falls through
    }

    // Check permissions
    for (const auto& perm : meta.permissions) {
        auto permIt = m_permLevels.find(perm);
        if (permIt == m_permLevels.end() || permIt->second == PermissionLevel::Blocked) {
            return false;
        }
        if (permIt->second == PermissionLevel::ApprovalRequired) {
            // Need approval callback
            if (m_approvalCb) {
                std::string reason = "Tool '" + toolName + "' requires approval";
                return m_approvalCb(toolName, args, reason);
            }
            // No callback = deny
            return false;
        }
    }

    return true;
}

void PermissionPolicy::SetApprovalCallback(ApprovalCallback cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_approvalCb = std::move(cb);
}

// ============================================================================
// ToolDispatcher
// ============================================================================
ToolDispatcher::ToolDispatcher() = default;
ToolDispatcher::~ToolDispatcher() = default;

void ToolDispatcher::SetRegistry(std::shared_ptr<ToolRegistry> registry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_registry = std::move(registry);
}

void ToolDispatcher::SetPermissionPolicy(std::shared_ptr<PermissionPolicy> policy) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_policy = std::move(policy);
}

ToolCallResult ToolDispatcher::Dispatch(AgentRun& run,
                                        const std::string& toolName,
                                        const nlohmann::json& args) {
    m_totalDispatched.fetch_add(1);

    // 1. Validate
    std::string validationError;
    if (!ValidateArgs(toolName, args, validationError)) {
        m_totalFailed.fetch_add(1);
        return ToolCallResult::Validation(validationError);
    }

    // 2. Budget check
    if (!run.CanCallTool(1)) {
        m_totalBlocked.fetch_add(1);
        return ToolCallResult::Error(
            "Tool budget exhausted: " + run.GetToolBudget().toString(),
            ToolOutcome::RateLimited);
    }

    // 3. Lookup tool
    if (!m_registry || !m_registry->HasTool(toolName)) {
        m_totalFailed.fetch_add(1);
        return ToolCallResult::NotFound(toolName);
    }

    const ToolMetadata* meta = m_registry->GetMetadata(toolName);
    ToolHandler handler = m_registry->GetHandler(toolName);
    if (!meta || !handler) {
        m_totalFailed.fetch_add(1);
        return ToolCallResult::Error("Tool handler not found: " + toolName);
    }

    // 4. Authorize
    if (m_policy && !m_policy->IsAllowed(toolName, *meta, args)) {
        m_totalBlocked.fetch_add(1);
        return ToolCallResult::Sandbox(
            "Permission denied for tool: " + toolName);
    }

    // 5. Consume budget
    if (!run.ConsumeToolCalls(1)) {
        m_totalBlocked.fetch_add(1);
        return ToolCallResult::Error(
            "Tool budget exhausted after pre-check",
            ToolOutcome::RateLimited);
    }

    // 6. Execute with timeout
    ToolCallResult result = ExecuteWithTimeout(run, *meta, handler, args);

    // 7. Account
    if (!result.isSuccess()) {
        m_totalFailed.fetch_add(1);
    }

    // Record in transcript
    ToolCall call(toolName, args, run.GetRunId(), run.GetTurnCount(), run.GetToolCallCount());
    ToolResult tr(result, call.id);
    run.RecordToolCall(call);
    run.RecordToolResult(tr);

    return result;
}

std::future<ToolCallResult> ToolDispatcher::DispatchAsync(AgentRun& run,
                                                              const std::string& toolName,
                                                              const nlohmann::json& args) {
    return std::async(std::launch::async, [&run, toolName, args, this]() {
        return Dispatch(run, toolName, args);
    });
}

std::vector<ToolCallResult> ToolDispatcher::DispatchBatch(
    AgentRun& run,
    const std::vector<std::pair<std::string, nlohmann::json>>& calls) {

    // Pre-check budget for all calls
    if (!run.CanCallTool(static_cast<uint32_t>(calls.size()))) {
        std::vector<ToolCallResult> results;
        results.reserve(calls.size());
        for (size_t i = 0; i < calls.size(); ++i) {
            results.push_back(ToolCallResult::Error(
                "Batch budget exhausted", ToolOutcome::RateLimited));
        }
        return results;
    }

    // Launch all async
    std::vector<std::future<ToolCallResult>> futures;
    futures.reserve(calls.size());
    for (const auto& [name, args] : calls) {
        futures.push_back(DispatchAsync(run, name, args));
    }

    // Collect results
    std::vector<ToolCallResult> results;
    results.reserve(calls.size());
    for (auto& f : futures) {
        results.push_back(f.get());
    }
    return results;
}

bool ToolDispatcher::ValidateArgs(const std::string& toolName,
                                  const nlohmann::json& args,
                                  std::string& errorOut) const {
    if (!m_registry) {
        errorOut = "No tool registry configured";
        return false;
    }
    const ToolMetadata* meta = m_registry->GetMetadata(toolName);
    if (!meta) {
        errorOut = "Unknown tool: " + toolName;
        return false;
    }
    // Basic validation: args must be an object
    if (!args.is_object()) {
        errorOut = "Tool arguments must be a JSON object";
        return false;
    }
    // TODO: Schema validation against meta.schema
    return true;
}

bool ToolDispatcher::CanAfford(AgentRun& run, uint32_t callCount) const {
    return run.CanCallTool(callCount);
}

ToolCallResult ToolDispatcher::ExecuteWithTimeout(AgentRun& run,
                                                  const ToolMetadata& meta,
                                                  ToolHandler handler,
                                                  const nlohmann::json& args) {
    (void)run; // Budget already consumed

    if (meta.timeoutSec == 0) {
        // No timeout
        return handler(args, run);
    }

    // Execute with timeout using async + future
    auto future = std::async(std::launch::async, [&handler, &args, &run]() {
        return handler(args, run);
    });

    auto status = future.wait_for(std::chrono::seconds(meta.timeoutSec));
    if (status == std::future_status::timeout) {
        return ToolCallResult::TimedOut("");
    }

    try {
        return future.get();
    } catch (...) {
        return ToolCallResult::Error("Tool execution threw exception");
    }
}

} // namespace Agent
} // namespace RawrXD
