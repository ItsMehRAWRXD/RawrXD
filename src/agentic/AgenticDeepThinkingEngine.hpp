// ============================================================================
// AgenticDeepThinkingEngine.hpp — Header for Deep Thinking Engine
// ============================================================================
// Mission 2: Activate the Deep Thinking Engine
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <chrono>
#include <unordered_map>
#include <functional>
#include "nlohmann/json.hpp"

namespace RawrXD {
namespace Agent {

// Forward declarations
class AutonomousRecoveryOrchestrator;

// ============================================================================
// Enums
// ============================================================================
enum class EventType {
    WORKFLOW_STARTED,
    WORKFLOW_COMPLETED,
    THINKING_STARTED,
    THINKING_COMPLETED,
    CRASH,
    EXCEPTION_THROWN,
    HANG,
    MEMORY_PRESSURE,
    PERFORMANCE_DEGRADATION,
    RECOVERY_ATTEMPTED,
    RECOVERY_SUCCEEDED,
    RECOVERY_FAILED,
    TOOL_DISPATCHED
};

enum class RecoveryStrategy {
    NONE,
    RESTART_SERVICE,
    RESTART_PROCESS,
    CLEAR_CACHE,
    RELOAD_MODEL,
    RESET_BRIDGE,
    ROLLBACK_STATE,
    AUTOMATIC_RETRY,
    FALLBACK_MODE,
    ESCALATE_TO_USER,
    SourceEdit,
    HotpatchRedirect,
    ReduceBatchSize,
    SwapKVToDisk,
    FreezeHotpatching
};

// Stable string form for a recovery strategy. Used by the recovery orchestrator
// to emit a machine-readable strategy in its JSON result and its telemetry
// event (e.g. "strategy=RESTART_SERVICE"). ADL resolves this from any code that
// holds a RecoveryStrategy, so callers need no qualification.
inline const char* RecoveryStrategyString(RecoveryStrategy s) {
    switch (s) {
        case RecoveryStrategy::NONE:              return "none";
        case RecoveryStrategy::RESTART_SERVICE:   return "restart_service";
        case RecoveryStrategy::RESTART_PROCESS:   return "restart_process";
        case RecoveryStrategy::CLEAR_CACHE:       return "clear_cache";
        case RecoveryStrategy::RELOAD_MODEL:      return "reload_model";
        case RecoveryStrategy::RESET_BRIDGE:      return "reset_bridge";
        case RecoveryStrategy::ROLLBACK_STATE:    return "rollback_state";
        case RecoveryStrategy::AUTOMATIC_RETRY:   return "automatic_retry";
        case RecoveryStrategy::FALLBACK_MODE:     return "fallback_mode";
        case RecoveryStrategy::ESCALATE_TO_USER:  return "escalate_to_user";
        case RecoveryStrategy::SourceEdit:        return "source_edit";
        case RecoveryStrategy::HotpatchRedirect:  return "hotpatch_redirect";
        case RecoveryStrategy::ReduceBatchSize:   return "reduce_batch_size";
        case RecoveryStrategy::SwapKVToDisk:      return "swap_kv_to_disk";
        case RecoveryStrategy::FreezeHotpatching: return "freeze_hotpatching";
        default:                                  return "unknown";
    }
}

// ============================================================================
// Structs
// ============================================================================
struct MonitoredEvent {
    uint64_t eventId = 0;
    EventType type;
    std::string source;
    std::string description;
    std::chrono::system_clock::time_point timestamp;
    
    MonitoredEvent() = default;
    MonitoredEvent(EventType t, const std::string& s, const std::string& d)
        : type(t), source(s), description(d), timestamp(std::chrono::system_clock::now()) {}
};

struct ThinkingContext {
    std::string prompt;
    std::string context;
    std::vector<std::string> recentEvents;
    float confidenceThreshold = 0.5f;
};

struct ThinkingResult {
    bool success = false;
    std::string output;
    std::string reasoning;
    std::vector<std::string> suggestedActions;
    float confidence = 0.0f;
    int64_t processingTimeMs = 0;
};

struct RecoveryPlan {
    RecoveryStrategy strategy = RecoveryStrategy::NONE;
    std::string target;
    std::string reason;
    int maxRetries = 0;
    int currentAttempt = 0;
};

struct Workflow {
    std::string id;
    std::string name;
    std::string description;
    std::atomic<bool> isRunning{false};
    std::chrono::system_clock::time_point startTime;
};

// ============================================================================
// AgenticDeepThinkingEngine Class
// ============================================================================
class AgenticDeepThinkingEngine {
public:
    // Singleton
    static AgenticDeepThinkingEngine& instance();
    
    // Construction/Destruction
    AgenticDeepThinkingEngine();
    ~AgenticDeepThinkingEngine();
    
    // Disable copy/move
    AgenticDeepThinkingEngine(const AgenticDeepThinkingEngine&) = delete;
    AgenticDeepThinkingEngine& operator=(const AgenticDeepThinkingEngine&) = delete;
    
    // Lifecycle
    void initialize();
    void shutdown();
    bool isInitialized() const { return m_initialized.load(); }
    
    // Core Thinking
    ThinkingResult think(const ThinkingContext& ctx);
    
    // Event Monitoring
    void recordEvent(const MonitoredEvent& event);
    void recordEvent(EventType type, const std::string& source, const std::string& description);
    std::vector<MonitoredEvent> getRecentEvents(size_t count) const;
    std::vector<MonitoredEvent> getEventsByType(EventType type) const;
    
    // Anomaly Detection
    bool detectAnomaly(const std::vector<MonitoredEvent>& events);
    bool isCrashPattern(const std::vector<MonitoredEvent>& events);
    bool isHangPattern(const std::vector<MonitoredEvent>& events);
    bool isMemoryPressurePattern(const std::vector<MonitoredEvent>& events);
    
    // Recovery Planning
    RecoveryPlan planRecovery(const MonitoredEvent& triggerEvent);
    bool executeRecovery(const RecoveryPlan& plan);
    RecoveryStrategy selectRecoveryStrategy(const MonitoredEvent& event);
    bool executeRecoveryStrategy(RecoveryStrategy strategy, const std::string& target);
    
    // Background Monitoring
    void startMonitoring();
    void stopMonitoring();
    bool isMonitoring() const { return m_monitoring.load(); }
    
    // Workflow Orchestration
    std::string startWorkflow(const Workflow& workflow);
    bool cancelWorkflow(const std::string& workflowId);
    Workflow getWorkflowStatus(const std::string& workflowId) const;
    
    // Tool Scheduling
    void scheduleTool(const std::string& toolName, 
                      const nlohmann::json& params,
                      std::chrono::milliseconds delay);
    
    // Callbacks
    using EventCallback = std::function<void(const MonitoredEvent&)>;
    using RecoveryCallback = std::function<void(const RecoveryPlan&, bool)>;
    
    void setEventCallback(EventCallback cb) { m_eventCallback = cb; }
    void setRecoveryCallback(RecoveryCallback cb) { m_recoveryCallback = cb; }

private:
    // Background loops
    void monitoringLoop();
    void processEventQueue();
    void analyzeEventPatterns();
    
    // Member variables
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_shutdown{false};
    std::atomic<bool> m_monitoring{false};
    
    AutonomousRecoveryOrchestrator* m_recoveryOrchestrator;
    
    // Event history
    mutable std::mutex m_eventsMutex;
    std::vector<MonitoredEvent> m_eventHistory;
    std::queue<MonitoredEvent> m_eventQueue;
    uint64_t m_eventCounter = 0;
    static constexpr size_t m_maxEventHistory = 1000;
    
    // Threads
    std::thread m_monitorThread;
    std::thread m_processingThread;
    std::chrono::milliseconds m_monitoringInterval{5000}; // 5 seconds
    
    // Workflows
    mutable std::mutex m_workflowsMutex;
    std::unordered_map<std::string, Workflow> m_activeWorkflows;
    
    // Callbacks
    EventCallback m_eventCallback;
    RecoveryCallback m_recoveryCallback;
};

} // namespace Agent
} // namespace RawrXD
