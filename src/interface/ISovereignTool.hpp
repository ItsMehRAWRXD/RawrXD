/**
 * ISovereignTool.hpp
 *
 * Phase D.2 Batch 3/5: External Tool Contract Layer
 *
 * Defines the interface for external tools to integrate with the sovereign runtime.
 * Provides a plugin system for tool registration and execution.
 *
 * Tool Contract:
 *   - Tools implement ISovereignTool interface
 *   - Tools register with SovereignToolRegistry
 *   - Runtime invokes tools via standardized contract
 *   - Tools return structured results
 */

#pragma once

#include "../core/SovereignState.hpp"

#include <string>
#include <vector>
#include <map>
#include <variant>
#include <memory>
#include <functional>
#include <future>

namespace Interface {

/**
 * Tool parameter types
 */
using ToolParamValue = std::variant<
    std::monostate,  // null
    bool,
    int,
    double,
    std::string,
    std::vector<ToolParamValue>,
    std::map<std::string, ToolParamValue>
>;

/**
 * Tool parameter definition
 */
struct ToolParam {
    std::string name;
    std::string type;  // "bool", "int", "double", "string", "array", "object"
    std::string description;
    bool required{false};
    ToolParamValue defaultValue;
    
    std::string ToJson() const;
};

/**
 * Tool result
 */
struct ToolResult {
    bool success{false};
    std::string toolId;
    std::string operation;
    ToolParamValue data;
    std::string errorMessage;
    int64_t executionTimeMs{0};
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Tool context
 */
struct ToolContext {
    Core::SovereignState state;
    std::map<std::string, std::string> metadata;
    std::map<std::string, ToolParamValue> environment;
    
    std::string ToJson() const;
};

/**
 * Tool capability flags
 */
enum class ToolCapability : uint32_t {
    NONE = 0,
    READ_STATE = 1 << 0,      // Can read runtime state
    WRITE_STATE = 1 << 1,     // Can modify runtime state
    ASYNC_EXEC = 1 << 2,       // Supports async execution
    BATCH_EXEC = 1 << 3,       // Supports batch operations
    STREAMING = 1 << 4,       // Supports streaming results
    CANCELABLE = 1 << 5,      // Can be cancelled
    RETRYABLE = 1 << 6,        // Supports retry on failure
    
    ALL = READ_STATE | WRITE_STATE | ASYNC_EXEC | BATCH_EXEC | 
          STREAMING | CANCELABLE | RETRYABLE
};

inline ToolCapability operator|(ToolCapability a, ToolCapability b) {
    return static_cast<ToolCapability>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline ToolCapability operator&(ToolCapability a, ToolCapability b) {
    return static_cast<ToolCapability>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline bool HasCapability(ToolCapability flags, ToolCapability cap) {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(cap)) != 0;
}

/**
 * Tool metadata
 */
struct ToolMetadata {
    std::string toolId;
    std::string name;
    std::string description;
    std::string version;
    std::string author;
    ToolCapability capabilities{ToolCapability::NONE};
    std::vector<ToolParam> parameters;
    std::vector<std::string> tags;
    
    std::string ToJson() const;
};

/**
 * ISovereignTool interface
 *
 * All external tools must implement this interface to integrate with the sovereign runtime.
 */
class ISovereignTool {
public:
    virtual ~ISovereignTool() = default;

    /**
     * Get tool metadata
     */
    virtual ToolMetadata GetMetadata() const = 0;

    /**
     * Initialize the tool
     */
    virtual bool Initialize(const std::map<std::string, ToolParamValue>& config) = 0;

    /**
     * Shutdown the tool
     */
    virtual void Shutdown() = 0;

    /**
     * Execute the tool synchronously
     */
    virtual ToolResult Execute(const std::string& operation,
                               const std::map<std::string, ToolParamValue>& params,
                               const ToolContext& context) = 0;

    /**
     * Execute the tool asynchronously (optional)
     */
    virtual std::future<ToolResult> ExecuteAsync(const std::string& operation,
                                                   const std::map<std::string, ToolParamValue>& params,
                                                   const ToolContext& context) {
        std::promise<ToolResult> promise;
        promise.set_value(Execute(operation, params, context));
        return promise.get_future();
    }

    /**
     * Check if tool supports an operation
     */
    virtual bool SupportsOperation(const std::string& operation) const = 0;

    /**
     * Get operation documentation
     */
    virtual std::string GetOperationDocs(const std::string& operation) const = 0;

    /**
     * Cancel an ongoing operation (if CANCELABLE)
     */
    virtual bool Cancel(const std::string& operationId) {
        return false;
    }

    /**
     * Get tool health status
     */
    virtual std::string GetHealthStatus() const {
        return "healthy";
    }
};

/**
 * Tool factory function type
 */
using ToolFactory = std::function<std::unique_ptr<ISovereignTool>()>;

/**
 * Tool registration info
 */
struct ToolRegistration {
    std::string toolId;
    ToolFactory factory;
    ToolMetadata metadata;
    bool autoStart{false};
};

/**
 * Tool execution request
 */
struct ToolExecutionRequest {
    std::string toolId;
    std::string operation;
    std::map<std::string, ToolParamValue> parameters;
    int timeoutMs{30000};
    bool async{false};
    std::string requestId;
};

/**
 * Tool execution response
 */
struct ToolExecutionResponse {
    std::string requestId;
    bool accepted{false};
    std::string status;  // "pending", "running", "completed", "failed", "cancelled"
    ToolResult result;
    std::string errorMessage;
    int64_t queuedAtMs{0};
    int64_t startedAtMs{0};
    int64_t completedAtMs{0};
    
    std::string ToJson() const;
};

/**
 * Tool registry configuration
 */
struct ToolRegistryConfig {
    int maxConcurrentTools{10};
    int defaultTimeoutMs{30000};
    bool enableSandbox{true};
    std::vector<std::string> allowedToolPaths;
    std::vector<std::string> blockedToolIds;
    
    std::string ToJson() const;
};

/**
 * Sovereign Tool Registry
 *
 * Manages registration and execution of external tools.
 */
class SovereignToolRegistry {
public:
    SovereignToolRegistry();
    ~SovereignToolRegistry();

    // Disable copy
    SovereignToolRegistry(const SovereignToolRegistry&) = delete;
    SovereignToolRegistry& operator=(const SovereignToolRegistry&) = delete;

    /**
     * Initialize the registry
     */
    bool Initialize(const ToolRegistryConfig& config);

    /**
     * Register a tool
     */
    bool RegisterTool(const ToolRegistration& registration);

    /**
     * Unregister a tool
     */
    bool UnregisterTool(const std::string& toolId);

    /**
     * Create and initialize a tool instance
     */
    std::shared_ptr<ISovereignTool> CreateTool(const std::string& toolId,
                                                 const std::map<std::string, ToolParamValue>& config);

    /**
     * Execute a tool
     */
    ToolExecutionResponse Execute(const ToolExecutionRequest& request,
                                  const ToolContext& context);

    /**
     * Execute a tool asynchronously
     */
    std::future<ToolExecutionResponse> ExecuteAsync(const ToolExecutionRequest& request,
                                                   const ToolContext& context);

    /**
     * Cancel a tool execution
     */
    bool CancelExecution(const std::string& requestId);

    /**
     * Get execution status
     */
    ToolExecutionResponse GetExecutionStatus(const std::string& requestId) const;

    /**
     * List registered tools
     */
    std::vector<ToolMetadata> ListTools() const;

    /**
     * Get tool metadata
     */
    std::optional<ToolMetadata> GetToolMetadata(const std::string& toolId) const;

    /**
     * Check if tool is registered
     */
    bool IsToolRegistered(const std::string& toolId) const;

    /**
     * Get tool health status
     */
    std::string GetToolHealth(const std::string& toolId) const;

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    ToolRegistryConfig config_;
    bool initialized_{false};
    
    // Registered tool factories
    std::map<std::string, ToolRegistration> registrations_;
    mutable std::mutex registrationsMutex_;
    
    // Active tool instances
    std::map<std::string, std::shared_ptr<ISovereignTool>> instances_;
    mutable std::mutex instancesMutex_;
    
    // Active executions
    struct ActiveExecution {
        ToolExecutionRequest request;
        ToolExecutionResponse response;
        std::shared_ptr<std::promise<ToolExecutionResponse>> promise;
        std::thread executionThread;
        std::atomic<bool> cancelled{false};
    };
    std::map<std::string, std::shared_ptr<ActiveExecution>> executions_;
    mutable std::mutex executionsMutex_;
    
    // Execution counter
    std::atomic<int64_t> executionCounter_{0};
    
    // Helpers
    std::string GenerateRequestId();
    bool ValidateRequest(const ToolExecutionRequest& request, std::string& error) const;
    void CleanupExecutions();
};

/**
 * Built-in tools
 */

/**
 * StateQueryTool - Query runtime state
 */
class StateQueryTool : public ISovereignTool {
public:
    StateQueryTool();
    ~StateQueryTool() override;

    ToolMetadata GetMetadata() const override;
    bool Initialize(const std::map<std::string, ToolParamValue>& config) override;
    void Shutdown() override;
    ToolResult Execute(const std::string& operation,
                       const std::map<std::string, ToolParamValue>& params,
                       const ToolContext& context) override;
    bool SupportsOperation(const std::string& operation) const override;
    std::string GetOperationDocs(const std::string& operation) const override;

private:
    bool initialized_{false};
    
    ToolResult HandleQuery(const std::map<std::string, ToolParamValue>& params,
                           const ToolContext& context);
    ToolResult HandleSnapshot(const std::map<std::string, ToolParamValue>& params,
                              const ToolContext& context);
};

/**
 * GraphMutationTool - Mutate execution graph
 */
class GraphMutationTool : public ISovereignTool {
public:
    GraphMutationTool();
    ~GraphMutationTool() override;

    ToolMetadata GetMetadata() const override;
    bool Initialize(const std::map<std::string, ToolParamValue>& config) override;
    void Shutdown() override;
    ToolResult Execute(const std::string& operation,
                       const std::map<std::string, ToolParamValue>& params,
                       const ToolContext& context) override;
    bool SupportsOperation(const std::string& operation) const override;
    std::string GetOperationDocs(const std::string& operation) const override;

private:
    bool initialized_{false};
    
    ToolResult HandleAddNode(const std::map<std::string, ToolParamValue>& params,
                             const ToolContext& context);
    ToolResult HandleRemoveNode(const std::map<std::string, ToolParamValue>& params,
                                const ToolContext& context);
    ToolResult HandleAddEdge(const std::map<std::string, ToolParamValue>& params,
                             const ToolContext& context);
};

/**
 * CheckpointTool - Create and restore checkpoints
 */
class CheckpointTool : public ISovereignTool {
public:
    CheckpointTool();
    ~CheckpointTool() override;

    ToolMetadata GetMetadata() const override;
    bool Initialize(const std::map<std::string, ToolParamValue>& config) override;
    void Shutdown() override;
    ToolResult Execute(const std::string& operation,
                       const std::map<std::string, ToolParamValue>& params,
                       const ToolContext& context) override;
    bool SupportsOperation(const std::string& operation) const override;
    std::string GetOperationDocs(const std::string& operation) const override;

private:
    bool initialized_{false};
    std::string checkpointDir_{"./checkpoints"};
    
    ToolResult HandleCreate(const std::map<std::string, ToolParamValue>& params,
                            const ToolContext& context);
    ToolResult HandleRestore(const std::map<std::string, ToolParamValue>& params,
                             const ToolContext& context);
    ToolResult HandleList(const std::map<std::string, ToolParamValue>& params,
                          const ToolContext& context);
    ToolResult HandleDelete(const std::map<std::string, ToolParamValue>& params,
                            const ToolContext& context);
};

/**
 * CLI for testing the tool registry
 */
class SovereignToolRegistryCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static ToolRegistryConfig ParseArgs(int argc, char* argv[]);
    static void InteractiveMode(SovereignToolRegistry& registry);
    static void PrintToolList(const std::vector<ToolMetadata>& tools);
};

} // namespace Interface
