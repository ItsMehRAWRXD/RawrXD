// ============================================================================
// AgenticDeepThinkingEngine.hpp — Autonomous Intelligence & Recovery Core
// ============================================================================
// Mission 2: Activate the Deep Thinking Engine
// 
// This engine provides:
//   - Event monitoring and anomaly detection
//   - Crash detection and classification
//   - Recovery strategy selection and execution
//   - Background task orchestration
//   - Tool scheduling and dispatch
//   - Autonomous workflow execution
//
// Integration: Wired into AutonomyManager for high-level orchestration
//              and AutonomousRecoveryOrchestrator for low-level recovery
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <queue>
#include <chrono>
#include <map>

#include "nlohmann/json.hpp"

namespace RawrXD {
namespace Agent {

// Forward declarations
class AutonomousRecoveryOrchestrator;
struct RecoveryResult;
struct DivergenceEvent;

// ============================================================================
// Event Types for Monitoring
// ============================================================================
enum class EventType {
    UNKNOWN = 0,
    CRASH,              // Application/process crash
    HANG,               // Unresponsive/deadlock
    MEMORY_PRESSURE,    // High memory usage
    PERFORMANCE_DEGRADATION,
    ASSERTION_FAILURE,
    EXCEPTION_THROWN,
    RECOVERY_ATTEMPTED,
    RECOVERY_SUCCEEDED,
    RECOVERY_FAILED,
    WORKFLOW_STARTED,
    WORKFLOW_COMPLETED,
    WORKFLOW_FAILED,
    TOOL_DISPATCHED,
    TOOL_COMPLETED,
    THINKING_STARTED,
    THINKING_COMPLETED
};

struct MonitoredEvent {
    EventType type = EventType::UNKNOWN;
    std::string timestamp;
    std::string source;
    std::string description;
    nlohmann::json metadata;
    uint64_t eventId = 0;
    
    MonitoredEvent() = default;
    MonitoredEvent(EventType t, const std::string& src, const std::string& desc)
        : type(t), source(src), description(desc) {
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        timestamp = std::to_string(ms);
    }
};

// ============================================================================
// Recovery Strategy Types
// ============================================================================
// Unified RecoveryStrategy for both AgenticDeepThinkingEngine and AutonomousRecoveryOrchestrator
enum class RecoveryStrategy {
    NONE = 0,
    RESTART_SERVICE,
    RESTART_PROCESS,
    ROLLBACK_STATE,
    CLEAR_CACHE,
    RELOAD_MODEL,
    RESET_BRIDGE,
    ESCALATE_TO_USER,
    AUTOMATIC_RETRY,
    FALLBACK_MODE,
    // Additional strategies used by AutonomousRecoveryOrchestrator
    SourceEdit,
    HotpatchRedirect,
    ReduceBatchSize,
    SwapKVToDisk,
    FreezeHotpatching
};

// Convert RecoveryStrategy to string
inline const char* RecoveryStrategyString(RecoveryStrategy s) {
    switch (s) {
        case RecoveryStrategy::RESTART_SERVICE: return "RESTART_SERVICE";
        case RecoveryStrategy::RESTART_PROCESS: return "RESTART_PROCESS";
        case RecoveryStrategy::ROLLBACK_STATE: return "ROLLBACK_STATE";
        case RecoveryStrategy::CLEAR_CACHE: return "CLEAR_CACHE";
        case RecoveryStrategy::RELOAD_MODEL: return "RELOAD_MODEL";
        case RecoveryStrategy::RESET_BRIDGE: return "RESET_BRIDGE";
        case RecoveryStrategy::ESCALATE_TO_USER: return "ESCALATE_TO_USER";
        case RecoveryStrategy::AUTOMATIC_RETRY: return "AUTOMATIC_RETRY";
        case RecoveryStrategy::FALLBACK_MODE: return "FALLBACK_MODE";
        case RecoveryStrategy::SourceEdit: return "SourceEdit";
        case RecoveryStrategy::HotpatchRedirect: return "HotpatchRedirect";
        case RecoveryStrategy::ReduceBatchSize: return "ReduceBatchSize";
        case RecoveryStrategy::SwapKVToDisk: return "SwapKVToDisk";
        case RecoveryStrategy::FreezeHotpatching: return "FreezeHotpatching";
        case RecoveryStrategy::NONE: return "NONE";
        default: return "UNKNOWN";
    }
}

struct RecoveryPlan {
    RecoveryStrategy strategy = RecoveryStrategy::NONE;
    std::string target;
    std::string reason;
    int maxRetries = 3;
    int currentAttempt = 0;
    std::vector<std::string> prerequisites;
    nlohmann::json context;
};

// ============================================================================
// Thinking Context & Results
// ============================================================================
struct ThinkingContext {
    std::string prompt;
    std::string model;
    int maxTokens = 1024;
    float temperature = 0.7f;
    std::vector<std::string> contextHistory;
    nlohmann::json toolResults;
    bool enableReasoning = true;
    
    nlohmann::json toJson() const {
        nlohmann::json j;
        j["prompt"] = prompt;
        j["model"] = model;
        j["maxTokens"] = maxTokens;
        j["temperature"] = temperature;
        j["enableReasoning"] = enableReasoning;
        return j;
    }
};

struct ThinkingResult {
    bool success = false;
    std::string output;
    std::string reasoning;
    std::vector<std::string> suggestedActions;
    float confidence = 0.0f;
    uint64_t processingTimeMs = 0;
    
    nlohmann::json toJson() const {
        nlohmann::json j;
        j["success"] = success;
        j["output"] = output;
        j["reasoning"] = reasoning;
        j["confidence"] = confidence;
        j["processingTimeMs"] = processingTimeMs;
        j["suggestedActions"] = suggestedActions;
        return j;
    }
};

// ============================================================================
// Workflow Definition
// ============================================================================
struct WorkflowStep {
    std::string id;
    std::string toolName;
    nlohmann::json parameters;
    std::vector<std::string> dependencies;
    bool async = false;
    int timeoutMs = 30000;
};

struct Workflow {
    std::string id;
    std::string name;
    std::vector<WorkflowStep> steps;
    mutable std::atomic<bool> isRunning{false};
    mutable std::atomic<bool> isCompleted{false};
    std::string error;
    
    // Default constructor
    Workflow() = default;
    
    // Copy constructor - required for std::map
    Workflow(const Workflow& other)
        : id(other.id), name(other.name), steps(other.steps),
          isRunning(other.isRunning.load()),
          isCompleted(other.isCompleted.load()),
          error(other.error) {}
    
    // Copy assignment
    Workflow& operator=(const Workflow& other) {
        if (this != &other) {
            id = other.id;
            name = other.name;
            steps = other.steps;
            isRunning.store(other.isRunning.load());
            isCompleted.store(other.isCompleted.load());
            error = other.error;
        }
        return *this;
    }
};

// ============================================================================
// Main Engine Class
// ============================================================================
class AgenticDeepThinkingEngine {
public:
    // Singleton access
    static AgenticDeepThinkingEngine& instance();
    
    // Lifecycle
    void initialize();
    void shutdown();
    bool isInitialized() const { return m_initialized.load(); }
    
    // Core thinking capability
    ThinkingResult think(const ThinkingContext& ctx);
    
    // Event monitoring
    void recordEvent(const MonitoredEvent& event);
    void recordEvent(EventType type, const std::string& source, const std::string& description);
    std::vector<MonitoredEvent> getRecentEvents(size_t count = 100) const;
    std::vector<MonitoredEvent> getEventsByType(EventType type) const;
    
    // Crash detection & recovery
    bool detectAnomaly(const std::vector<MonitoredEvent>& events);
    RecoveryPlan planRecovery(const MonitoredEvent& triggerEvent);
    bool executeRecovery(const RecoveryPlan& plan);
    
    // Background monitoring
    void startMonitoring();
    void stopMonitoring();
    bool isMonitoring() const { return m_monitoring.load(); }
    
    // Workflow orchestration
    std::string startWorkflow(const Workflow& workflow);
    bool cancelWorkflow(const std::string& workflowId);
    Workflow getWorkflowStatus(const std::string& workflowId) const;
    
    // Tool scheduling
    void scheduleTool(const std::string& toolName, const nlohmann::json& params, 
                      std::chrono::milliseconds delay);
    void cancelScheduledTool(const std::string& taskId);
    
    // Status & diagnostics
    std::string getStatus() const;
    nlohmann::json getDiagnostics() const;
    
    // Callbacks for integration
    using EventCallback = std::function<void(const MonitoredEvent&)>;
    using RecoveryCallback = std::function<void(const RecoveryPlan&, bool success)>;
    void setEventCallback(EventCallback cb) { m_eventCallback = std::move(cb); }
    void setRecoveryCallback(RecoveryCallback cb) { m_recoveryCallback = std::move(cb); }

private:
    AgenticDeepThinkingEngine();
    ~AgenticDeepThinkingEngine();
    
    // Non-copyable
    AgenticDeepThinkingEngine(const AgenticDeepThinkingEngine&) = delete;
    AgenticDeepThinkingEngine& operator=(const AgenticDeepThinkingEngine&) = delete;
    
    // Internal methods
    void monitoringLoop();
    void processEventQueue();
    void analyzeEventPatterns();
    RecoveryStrategy selectRecoveryStrategy(const MonitoredEvent& event);
    bool executeRecoveryStrategy(RecoveryStrategy strategy, const std::string& target);
    
    // Event pattern analysis
    bool isCrashPattern(const std::vector<MonitoredEvent>& events);
    bool isHangPattern(const std::vector<MonitoredEvent>& events);
    bool isMemoryPressurePattern(const std::vector<MonitoredEvent>& events);
    
    // Member variables
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_monitoring{false};
    std::atomic<bool> m_shutdown{false};
    std::atomic<uint64_t> m_eventCounter{0};
    
    mutable std::mutex m_eventsMutex;
    std::vector<MonitoredEvent> m_eventHistory;
    std::queue<MonitoredEvent> m_eventQueue;
    
    mutable std::mutex m_workflowsMutex;
    std::map<std::string, Workflow> m_activeWorkflows;
    
    std::thread m_monitorThread;
    std::thread m_processingThread;
    
    EventCallback m_eventCallback;
    RecoveryCallback m_recoveryCallback;
    
    // Recovery orchestrator integration
    AutonomousRecoveryOrchestrator* m_recoveryOrchestrator = nullptr;
    
    // Configuration
    size_t m_maxEventHistory = 10000;
    std::chrono::milliseconds m_monitoringInterval{1000};
};

} // namespace Agent
} // namespace RawrXD

// C-compatible exports for MASM/assembly integration
extern "C" {
    void* RAWRXD_AgenticDeepThinkingEngine_GetInstance();
    int RAWRXD_AgenticDeepThinkingEngine_Initialize(void* engine);
    int RAWRXD_AgenticDeepThinkingEngine_RecordEvent(void* engine, int eventType, 
                                                       const char* source, 
                                                       const char* description);
    int RAWRXD_AgenticDeepThinkingEngine_StartMonitoring(void* engine);
    int RAWRXD_AgenticDeepThinkingEngine_StopMonitoring(void* engine);
}
