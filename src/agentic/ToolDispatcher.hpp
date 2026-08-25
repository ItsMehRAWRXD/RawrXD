// ============================================================================
// ToolDispatcher.hpp — Centralized Tool Execution Authority
// ============================================================================
// Every tool invocation must pass through this gate.
//
// Responsibilities:
//   - validate()      — schema/argument validation
//   - authorize()     — permission policy check
//   - check_budget()  — ToolBudget consumption
//   - execute()       — dispatch to handler, capture stdout/stderr
//   - account()       — record usage, update budgets
//   - timeout()       — enforce per-tool timeout
//
// Architecture:
//   AgentRun
//     └── ToolDispatcher
//           ├── ToolRegistry (name → handler + metadata)
//           ├── PermissionPolicy (READ/WRITE/EXECUTE/NETWORK)
//           └── BudgetPolicy (ToolBudget enforcement)
//
// Pattern: PatchResult-style, no exceptions, thread-safe.
// Rule:    NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#pragma once

#include "AgentRun.hpp"
#include "ToolCallResult.h"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <future>
#include <chrono>

namespace RawrXD {
namespace Agent {

// ============================================================================
// Permission classes
// ============================================================================
enum class ToolPermission {
    Read,       // READ_FILE, SEARCH, LIST_DIR
    Write,      // WRITE_FILE, REPLACE_IN_FILE
    Execute,    // RUN_PROCESS, COMPILE, SHELL
    Network,    // HTTP requests, API calls
    Process,    // Spawn subprocesses
    System,     // Registry, env vars
    Git,        // Git operations
    Model       // Model inference calls
};

// ============================================================================
// Permission policy level
// ============================================================================
enum class PermissionLevel {
    Allowed,           // Automatic execution
    ApprovalRequired,  // Requires human approval
    Blocked            // Never allowed
};

// ============================================================================
// Tool metadata (registry entry)
// ============================================================================
struct ToolMetadata {
    std::string name;
    std::string description;
    nlohmann::json schema;           // OpenAI function schema
    std::vector<ToolPermission> permissions;
    uint32_t timeoutSec             = 300;
    uint32_t estimatedCost          = 1;  // Budget cost per invocation
    bool parallelizable             = true;
    bool requiresConfirmation       = false;
    std::string category;            // "filesystem", "build", "search", etc.
};

// ============================================================================
// Tool handler signature
// ============================================================================
using ToolHandler = std::function<ToolCallResult(const nlohmann::json& args, AgentRun& run)>;

// ============================================================================
// ToolRegistry — authoritative tool catalog
// ============================================================================
class ToolRegistry {
public:
    ToolRegistry();
    ~ToolRegistry();

    // Register a tool
    void Register(const std::string& name,
                    const ToolMetadata& meta,
                    ToolHandler handler);

    // Lookup
    bool HasTool(const std::string& name) const;
    const ToolMetadata* GetMetadata(const std::string& name) const;
    ToolHandler GetHandler(const std::string& name) const;

    // Schema generation for LLM
    nlohmann::json GetAllSchemas() const;
    nlohmann::json GetSchema(const std::string& name) const;

    // List tools
    std::vector<std::string> ListTools() const;
    std::vector<std::string> ListToolsByPermission(ToolPermission perm) const;

    // Built-in registration
    void RegisterBuiltInTools();

private:
    struct ToolEntry {
        ToolMetadata meta;
        ToolHandler handler;
    };
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, ToolEntry> m_tools;
};

// ============================================================================
// PermissionPolicy — security gate
// ============================================================================
class PermissionPolicy {
public:
    PermissionPolicy();
    ~PermissionPolicy();

    // Set permission level for a category or specific tool
    void SetLevel(ToolPermission perm, PermissionLevel level);
    void SetLevel(const std::string& toolName, PermissionLevel level);

    // Check if a tool is allowed
    bool IsAllowed(const std::string& toolName,
                   const ToolMetadata& meta,
                   const nlohmann::json& args) const;

    // Approval callback (set by UI or runtime)
    using ApprovalCallback = std::function<bool(const std::string& toolName,
                                                   const nlohmann::json& args,
                                                   const std::string& reason)>;
    void SetApprovalCallback(ApprovalCallback cb);

private:
    mutable std::mutex m_mutex;
    std::unordered_map<ToolPermission, PermissionLevel> m_permLevels;
    std::unordered_map<std::string, PermissionLevel> m_toolLevels;
    ApprovalCallback m_approvalCb;
};

// ============================================================================
// ToolDispatcher — single authoritative execution gate
// ============================================================================
class ToolDispatcher {
public:
    ToolDispatcher();
    ~ToolDispatcher();

    // ---- Configuration ----
    void SetRegistry(std::shared_ptr<ToolRegistry> registry);
    void SetPermissionPolicy(std::shared_ptr<PermissionPolicy> policy);

    // ---- Execution ----
    // Main dispatch gate. Every tool call goes through here.
    ToolCallResult Dispatch(AgentRun& run,
                            const std::string& toolName,
                            const nlohmann::json& args);

    // Async dispatch for parallel tool execution
    std::future<ToolCallResult> DispatchAsync(AgentRun& run,
                                                 const std::string& toolName,
                                                 const nlohmann::json& args);

    // Batch dispatch (parallel, budget-checked upfront)
    std::vector<ToolCallResult> DispatchBatch(AgentRun& run,
                                                const std::vector<std::pair<std::string, nlohmann::json>>& calls);

    // ---- Validation ----
    bool ValidateArgs(const std::string& toolName,
                      const nlohmann::json& args,
                      std::string& errorOut) const;

    // ---- Budget pre-check ----
    bool CanAfford(AgentRun& run, uint32_t callCount) const;

    // ---- Statistics ----
    uint64_t GetTotalDispatched() const { return m_totalDispatched.load(); }
    uint64_t GetTotalFailed() const { return m_totalFailed.load(); }
    uint64_t GetTotalBlocked() const { return m_totalBlocked.load(); }

private:
    // Internal execution with timeout
    ToolCallResult ExecuteWithTimeout(AgentRun& run,
                                      const ToolMetadata& meta,
                                      ToolHandler handler,
                                      const nlohmann::json& args);

    std::shared_ptr<ToolRegistry> m_registry;
    std::shared_ptr<PermissionPolicy> m_policy;

    std::atomic<uint64_t> m_totalDispatched{0};
    std::atomic<uint64_t> m_totalFailed{0};
    std::atomic<uint64_t> m_totalBlocked{0};

    mutable std::mutex m_mutex;
};

} // namespace Agent
} // namespace RawrXD
