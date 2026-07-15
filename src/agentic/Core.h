/**
 * @file Core.h
 * @brief Unified Agentic Core API - Layer 3
 * 
 * Consolidates all AgenticEngine implementations into a single interface.
 * Replaces:
 *   - agentic_engine.h/cpp
 *   - agentic_core.h/cpp
 *   - agentic_core_win32.h
 *   - agentic_executor.h/cpp
 *   - agentic_bridge.cpp
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Forward declarations for Layer 2
namespace RawrXD { namespace Inference {
    class InferenceEngine;
}}

namespace RawrXD {
namespace Agentic {

// ============================================================================
// Forward Declarations
// ============================================================================

class TaskScheduler;
class ToolRegistry;
class HistoryRecorder;
class PolicyEngine;
class SubAgentManager;

// ============================================================================
// Configuration Structures
// ============================================================================

/**
 * @brief Core configuration parameters
 */
struct CoreConfig {
    // Workspace
    std::string workspaceRoot;         ///< Root directory for file operations
    std::string historyPath;         ///< Path to history JSONL file
    
    // Concurrency
    size_t maxConcurrentTasks = 4;   ///< Maximum parallel tasks
    size_t maxSubAgents = 8;         ///< Maximum sub-agent workers
    
    // Timeouts
    std::chrono::milliseconds defaultTaskTimeout{60000};
    std::chrono::milliseconds fileOpTimeout{30000};
    std::chrono::milliseconds terminalTimeout{120000};
    std::chrono::milliseconds inferenceTimeout{300000};
    
    // Features
    bool enableHistory = true;         ///< Record all operations
    bool enablePolicies = true;        ///< Enforce safety policies
    bool enableSubAgents = true;       ///< Allow sub-agent spawning
    bool enableStreaming = true;       ///< Stream results when possible
    
    // Safety
    bool sandboxFileOps = true;      ///< Restrict file operations to workspace
    bool requireConfirmation = false;  ///< Require user confirmation for destructive ops
    std::vector<std::string> allowedPaths;  ///< Additional allowed paths
    std::vector<std::string> blockedCommands; ///< Blocked terminal commands
};

// ============================================================================
// Task Definitions
// ============================================================================

/**
 * @brief Task types supported by the agentic core
 */
enum class TaskType {
    File,           ///< File read/write/list/delete operations
    Terminal,       ///< Terminal/shell command execution
    Search,         ///< Codebase search and indexing
    Inference,      ///< LLM inference/generation
    Tool,           ///< Registered tool execution
    SubAgent,       ///< Spawn sub-agent for parallel work
    Composite,      ///< Multi-step composed task
    Custom          ///< User-defined task type
};

/**
 * @brief Task priority levels
 */
enum class TaskPriority : int {
    Critical = 1,   ///< System-critical, execute immediately
    High = 3,       ///< User-facing, high priority
    Normal = 5,     ///< Default priority
    Low = 7,        ///< Background tasks
    Background = 9  ///< Lowest priority, deferrable
};

/**
 * @brief Tool category
 */
enum class ToolCategory {
    File,           ///< File operations
    Terminal,       ///< Terminal/shell commands
    Search,         ///< Search operations
    Inference,      ///< LLM inference
    Custom          ///< User-defined tools
};

/**
 * @brief Task status
 */
enum class TaskStatus {
    Pending,        ///< Waiting in queue
    Running,        ///< Currently executing
    Completed,      ///< Finished successfully
    Failed,         ///< Finished with error
    Cancelled,      ///< Cancelled before completion
    Timeout         ///< Timed out
};

/**
 * @brief Task definition
 */
struct Task {
    std::string id;                  ///< Unique task ID (auto-generated if empty)
    TaskType type;                   ///< Task type
    std::string instruction;         ///< Primary instruction/prompt
    std::string label;               ///< Human-readable label
    TaskPriority priority = TaskPriority::Normal;
    std::chrono::milliseconds timeout;
    
    // Type-specific parameters
    struct FileParams {
        std::string operation;       ///< "read", "write", "list", "delete"
        std::string path;
        std::string content;         ///< For write operations
        bool createDirs = false;
    } fileParams;
    
    struct TerminalParams {
        std::string command;
        std::string workingDir;
        std::vector<std::string> envVars;
        bool captureOutput = true;
        bool captureError = true;
    } terminalParams;
    
    struct SearchParams {
        std::string query;
        std::vector<std::string> paths;
        bool regex = false;
        bool caseSensitive = false;
        int maxResults = 100;
    } searchParams;
    
    struct InferenceParams {
        std::string prompt;
        std::string model;           ///< Model identifier or "default"
        float temperature = 0.7f;
        int maxTokens = 256;
        bool stream = true;
    } inferenceParams;
    
    // Metadata
    std::string parentTaskId;        ///< Parent task for sub-tasks
    std::string requestingUser;      ///< User who submitted task
    std::chrono::steady_clock::time_point submitTime;
};

// ============================================================================
// Result Structures
// ============================================================================

/**
 * @brief Task execution result
 */
struct TaskResult {
    bool success = false;
    std::string output;              ///< Primary output (text, file content, etc.)
    std::string errorMessage;        ///< Error details if failed
    TaskStatus status = TaskStatus::Pending;
    
    // Metrics
    int64_t durationMs = 0;
    int64_t queueWaitMs = 0;         ///< Time spent in queue
    size_t bytesProcessed = 0;
    int tokensGenerated = 0;         ///< For inference tasks
    
    // Metadata
    std::string taskId;
    std::string taskType;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    
    // Sub-results (for composite tasks)
    std::vector<TaskResult> subResults;
    
    // Streaming
    bool isStreaming = false;
    bool isComplete = true;          ///< false if more data coming
};

/**
 * @brief Task progress update
 */
struct TaskProgress {
    std::string taskId;
    float percentComplete;           ///< 0.0 to 100.0
    std::string statusMessage;       ///< Human-readable status
    std::string currentStep;         ///< Current operation name
    int currentStepNum;
    int totalSteps;
};

// ============================================================================
// Event Callbacks
// ============================================================================

/**
 * @brief Task event callback types
 */
using TaskStartCallback = std::function<void(const Task&)>;
using TaskCompleteCallback = std::function<void(const Task&, const TaskResult&)>;
using TaskProgressCallback = std::function<void(const TaskProgress&)>;
using TaskOutputCallback = std::function<void(const std::string& taskId, const std::string& output)>;

// ============================================================================
// Statistics Structure
// ============================================================================

/**
 * @brief Core statistics
 */
struct CoreStats {
    int64_t tasksSubmitted;
    int64_t tasksCompleted;
    int64_t tasksFailed;
    int64_t tasksCancelled;
    double avgTaskDurationMs;
    double avgQueueWaitMs;
    size_t currentMemoryUsage;
    size_t peakMemoryUsage;
};

// ============================================================================
// Main Interface
// ============================================================================

/**
 * @brief Unified agentic core interface
 * 
 * This is the single, consolidated agentic core that replaces all
 * previous AgenticEngine implementations.
 * 
 * Thread Safety:
 * - All methods are thread-safe unless otherwise noted
 * - Tasks can be submitted from any thread
 * - Callbacks may be called from worker threads
 */
class Core {
public:
    virtual ~Core() = default;

    // ------------------------------------------------------------------------
    // Factory
    // ------------------------------------------------------------------------
    
    /**
     * @brief Create a new agentic core instance
     * @param config Core configuration
     * @return Unique pointer to core instance
     */
    static std::unique_ptr<Core> Create(const CoreConfig& config);
    
    /**
     * @brief Create with default configuration
     * @return Unique pointer to core instance
     */
    static std::unique_ptr<Core> Create();

    // ------------------------------------------------------------------------
    // Factory - Legacy Adapter
    // ------------------------------------------------------------------------
    
    /**
     * @brief Create adapter wrapping existing legacy agentic engine
     * @param legacyEngine Existing agentic engine instance (AgenticEngine*)
     * @param config Core configuration
     * @return Adapter instance implementing Core interface
     * 
     * This factory method allows gradual migration from legacy code.
     * The adapter wraps the existing engine behind the new unified API.
     */
    static std::unique_ptr<Core> CreateLegacyAdapter(
        void* legacyEngine,
        const CoreConfig& config = CoreConfig{});

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    
    /**
     * @brief Initialize the core
     * @return true if successful
     */
    virtual bool Initialize() = 0;
    
    /**
     * @brief Shutdown the core (wait for pending tasks)
     * @param timeout Maximum time to wait
     * @return true if shutdown cleanly
     */
    virtual bool Shutdown(std::chrono::milliseconds timeout = std::chrono::milliseconds{30000}) = 0;
    
    /**
     * @brief Check if core is initialized
     * @return true if ready to accept tasks
     */
    virtual bool IsInitialized() const = 0;

    // ------------------------------------------------------------------------
    // Task Execution - Async
    // ------------------------------------------------------------------------
    
    /**
     * @brief Submit a task for async execution
     * @param task Task definition
     * @return Future result
     */
    virtual std::future<TaskResult> SubmitTask(const Task& task) = 0;
    
    /**
     * @brief Submit a task with callbacks
     * @param task Task definition
     * @param onProgress Progress callback (optional)
     * @param onOutput Output callback for streaming (optional)
     * @return Future result
     */
    virtual std::future<TaskResult> SubmitTask(
        const Task& task,
        TaskProgressCallback onProgress,
        TaskOutputCallback onOutput = nullptr
    ) = 0;
    
    /**
     * @brief Submit multiple tasks as a batch
     * @param tasks Vector of tasks
     * @return Vector of futures (same order as input)
     */
    virtual std::vector<std::future<TaskResult>> SubmitBatch(
        const std::vector<Task>& tasks
    ) = 0;

    // ------------------------------------------------------------------------
    // Task Execution - Sync
    // ------------------------------------------------------------------------
    
    /**
     * @brief Execute a task synchronously
     * @param task Task definition
     * @return Task result
     */
    virtual TaskResult ExecuteSync(const Task& task) = 0;
    
    /**
     * @brief Execute with timeout
     * @param task Task definition
     * @param timeout Maximum time to wait
     * @return Task result (timeout status if exceeded)
     */
    virtual TaskResult ExecuteSync(
        const Task& task,
        std::chrono::milliseconds timeout
    ) = 0;

    // ------------------------------------------------------------------------
    // Task Management
    // ------------------------------------------------------------------------
    
    /**
     * @brief Cancel a pending or running task
     * @param taskId Task ID to cancel
     * @return true if task was found and cancelled
     */
    virtual bool CancelTask(const std::string& taskId) = 0;
    
    /**
     * @brief Get task status
     * @param taskId Task ID
     * @return Current status
     */
    virtual TaskStatus GetTaskStatus(const std::string& taskId) = 0;
    
    /**
     * @brief Get task result (if complete)
     * @param taskId Task ID
     * @return Result (empty if not complete)
     */
    virtual std::optional<TaskResult> GetTaskResult(const std::string& taskId) = 0;
    
    /**
     * @brief Wait for a task to complete
     * @param taskId Task ID
     * @param timeout Maximum time to wait
     * @return true if task completed
     */
    virtual bool WaitForTask(
        const std::string& taskId,
        std::chrono::milliseconds timeout = std::chrono::milliseconds{-1}
    ) = 0;

    // ------------------------------------------------------------------------
    // Task Queries
    // ------------------------------------------------------------------------
    
    /**
     * @brief Get number of pending tasks
     * @return Queue size
     */
    virtual size_t GetPendingCount() const = 0;
    
    /**
     * @brief Get number of running tasks
     * @return Active task count
     */
    virtual size_t GetRunningCount() const = 0;
    
    /**
     * @brief Get total task count (pending + running)
     * @return Total tasks
     */
    virtual size_t GetTotalTaskCount() const = 0;
    
    /**
     * @brief Get IDs of active tasks
     * @return Vector of task IDs
     */
    virtual std::vector<std::string> GetActiveTaskIds() const = 0;
    
    /**
     * @brief Get task details
     * @param taskId Task ID
     * @return Task definition (empty if not found)
     */
    virtual std::optional<Task> GetTaskInfo(const std::string& taskId) = 0;

    // ------------------------------------------------------------------------
    // Event Registration
    // ------------------------------------------------------------------------
    
    /**
     * @brief Register task start callback
     * @param callback Called when task starts
     * @return Callback ID for unregistering
     */
    virtual int OnTaskStart(TaskStartCallback callback) = 0;
    
    /**
     * @brief Register task complete callback
     * @param callback Called when task completes
     * @return Callback ID for unregistering
     */
    virtual int OnTaskComplete(TaskCompleteCallback callback) = 0;
    
    /**
     * @brief Unregister a callback
     * @param callbackId ID from OnTaskStart/OnTaskComplete
     */
    virtual void UnregisterCallback(int callbackId) = 0;

    // ------------------------------------------------------------------------
    // Subsystem Access
    // ------------------------------------------------------------------------
    
    /**
     * @brief Get task scheduler
     * @return Task scheduler reference
     */
    virtual TaskScheduler& GetScheduler() = 0;
    
    /**
     * @brief Get tool registry
     * @return Tool registry reference
     */
    virtual ToolRegistry& GetToolRegistry() = 0;
    
    /**
     * @brief Get history recorder
     * @return History recorder reference
     */
    virtual HistoryRecorder& GetHistory() = 0;
    
    /**
     * @brief Get policy engine
     * @return Policy engine reference
     */
    virtual PolicyEngine& GetPolicies() = 0;
    
    /**
     * @brief Get sub-agent manager
     * @return Sub-agent manager reference
     */
    virtual SubAgentManager& GetSubAgentManager() = 0;
    
    /**
     * @brief Set inference engine (Layer 2)
     * @param engine Inference engine instance
     */
    virtual void SetInferenceEngine(
        std::shared_ptr<Inference::InferenceEngine> engine
    ) = 0;
    
    /**
     * @brief Get inference engine
     * @return Inference engine (may be null if not set)
     */
    virtual std::shared_ptr<Inference::InferenceEngine> GetInferenceEngine() = 0;

    // ------------------------------------------------------------------------
    // Convenience Methods
    // ------------------------------------------------------------------------
    
    /**
     * @brief Read a file (convenience)
     * @param path File path
     * @return File content or error message
     */
    virtual std::string ReadFile(const std::string& path) = 0;
    
    /**
     * @brief Write a file (convenience)
     * @param path File path
     * @param content Content to write
     * @return true if successful
     */
    virtual bool WriteFile(const std::string& path, const std::string& content) = 0;
    
    /**
     * @brief Execute terminal command (convenience)
     * @param command Command to execute
     * @return Command output
     */
    virtual std::string ExecuteCommand(const std::string& command) = 0;
    
    /**
     * @brief Search codebase (convenience)
     * @param query Search query
     * @return Search results
     */
    virtual std::string SearchCodebase(const std::string& query) = 0;
    
    /**
     * @brief Generate text via LLM (convenience)
     * @param prompt Prompt text
     * @return Generated text
     */
    virtual std::string Generate(const std::string& prompt) = 0;

    // ------------------------------------------------------------------------
    // Diagnostics
    // ------------------------------------------------------------------------
    
    /**
     * @brief Get core statistics
     */
    virtual CoreStats GetStats() const = 0;
    
    /**
     * @brief Reset statistics
     */
    virtual void ResetStats() = 0;
    
    /**
     * @brief Get last error message
     * @return Error description
     */
    virtual std::string GetLastError() const = 0;
    
    /**
     * @brief Validate configuration
     * @return true if configuration is valid
     */
    virtual bool ValidateConfig() const = 0;
};

// ============================================================================
// Subsystem Interfaces
// ============================================================================

/**
 * @brief Tool definition
 */
struct Tool {
    std::string id;
    std::string name;
    std::string description;
    ToolCategory category;
    std::vector<std::string> parameters;
};

/**
 * @brief Task history entry
 */
struct TaskHistoryEntry {
    std::string taskId;
    TaskType type;
    TaskResult result;
    std::chrono::system_clock::time_point timestamp;
};

/**
 * @brief Sub-agent configuration
 */
struct SubAgentConfig {
    std::string name;
    std::vector<std::string> capabilities;
    size_t maxTasks;
};

/**
 * @brief Sub-agent information
 */
struct SubAgentInfo {
    std::string id;
    std::string name;
    bool isActive;
    size_t tasksCompleted;
};

/**
 * @brief Task scheduler interface
 */
class TaskScheduler {
public:
    virtual ~TaskScheduler() = default;
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual std::string ScheduleTask(const Task& task) = 0;
    virtual bool CancelTask(const std::string& taskId) = 0;
    virtual TaskStatus GetTaskStatus(const std::string& taskId) = 0;
    virtual std::vector<std::string> GetActiveTasks() = 0;
    virtual void SetMaxConcurrent(size_t max) = 0;
    virtual size_t GetMaxConcurrent() const = 0;
};

/**
 * @brief Tool registry interface
 */
class ToolRegistry {
public:
    virtual ~ToolRegistry() = default;
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual bool RegisterTool(const Tool& tool) = 0;
    virtual bool UnregisterTool(const std::string& toolId) = 0;
    virtual std::optional<Tool> GetTool(const std::string& toolId) = 0;
    virtual std::vector<Tool> GetAllTools() = 0;
    virtual std::vector<Tool> GetToolsByCategory(ToolCategory category) = 0;
    virtual bool ExecuteTool(const std::string& toolId, const std::string& params, std::string& output) = 0;
};

/**
 * @brief History recorder interface
 */
class HistoryRecorder {
public:
    virtual ~HistoryRecorder() = default;
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual void RecordTask(const Task& task, const TaskResult& result) = 0;
    virtual std::vector<TaskHistoryEntry> GetHistory(size_t limit) = 0;
    virtual std::vector<TaskHistoryEntry> GetHistoryByType(TaskType type, size_t limit) = 0;
    virtual void ClearHistory() = 0;
    virtual void SetMaxHistorySize(size_t max) = 0;
};

/**
 * @brief Policy types
 */
enum class PolicyType {
    AllowFileOperations,
    AllowTerminalCommands,
    AllowNetworkAccess,
    AllowSubAgents,
    RequireConfirmation
};

/**
 * @brief Policy engine interface
 */
class PolicyEngine {
public:
    virtual ~PolicyEngine() = default;
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual bool ValidateTask(const Task& task, std::string& reason) = 0;
    virtual bool CheckPermission(const std::string& action, const std::string& resource) = 0;
    virtual void SetPolicy(PolicyType type, bool enabled) = 0;
    virtual bool GetPolicy(PolicyType type) const = 0;
};

/**
 * @brief Sub-agent manager interface
 */
class SubAgentManager {
public:
    virtual ~SubAgentManager() = default;
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual std::string CreateSubAgent(const SubAgentConfig& config) = 0;
    virtual bool DestroySubAgent(const std::string& agentId) = 0;
    virtual std::optional<SubAgentInfo> GetSubAgentInfo(const std::string& agentId) = 0;
    virtual std::vector<SubAgentInfo> GetAllSubAgents() = 0;
    virtual bool SendMessageToSubAgent(const std::string& agentId, const std::string& message) = 0;
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Generate a unique task ID
 * @return Task ID string
 */
std::string GenerateTaskId();

/**
 * @brief Get library version
 * @return Version string
 */
const char* GetAgenticVersion();

/**
 * @brief Convert task type to string
 * @param type Task type
 * @return String representation
 */
const char* TaskTypeToString(TaskType type);

/**
 * @brief Convert string to task type
 * @param str String representation
 * @return Task type (Custom if unknown)
 */
TaskType StringToTaskType(const std::string& str);

/**
 * @brief Convert task status to string
 * @param status Task status
 * @return String representation
 */
const char* TaskStatusToString(TaskStatus status);

} // namespace Agentic
} // namespace RawrXD
