// Sovereign Control Plane UI - Live System Visualization
//
// Exposes agents, intents, resources, builds, patches, memory, and failures
// in a unified live view. This is the "dashboard" for the autonomous system.
//
// Architecture:
//   Agent Kernel (events)
//        |
//        v
//   Control Plane WebSocket Server
//        |
//        v
//   Web UI (or Native UI)
//        |
//        v
//   Human Operator

#pragma once

#include "../kernel/AgentKernel.hpp"
#include "../kernel/IntentExecutionPipeline.hpp"
#include "../memory/RepositoryMemoryGraph.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <functional>
#include <atomic>
#include <mutex>
#include <thread>

namespace RawrXD {
namespace ControlPlane {

// Forward declarations
class WebSocketServer;
class DashboardSession;

// ============================================================================
// View Types - What can be visualized
// ============================================================================

enum class ViewType : uint32_t {
    AGENTS = 0,           // Active agents and their states
    INTENTS = 1,          // Intent queue and execution
    RESOURCES = 2,        // Resource leases and contention
    BUILDS = 3,           // Build progress and telemetry
    PATCHES = 4,          // Hotpatch history and rollback points
    MEMORY = 5,           // Repository graph statistics
    TELEMETRY = 6,        // Performance metrics
    LOGS = 7,             // System logs
    
    COUNT = 8
};

// ============================================================================
// Agent View - Live agent status
// ============================================================================

struct AgentView {
    uint64_t agentId;
    std::string agentType;
    std::string modelBackend;
    std::string status;           // "IDLE", "EXECUTING", "WAITING"
    
    // Current work
    uint64_t currentIntentId;
    std::string currentIntentType;
    double executionTimeMs;
    
    // Resources
    uint32_t activeLeaseCount;
    std::vector<std::string> activeResources;
    
    // Performance
    uint64_t intentsCompleted;
    uint64_t intentsFailed;
    double successRate;
    double averageLatencyMs;
    
    // Timeline
    std::string lastActivity;
    std::string startedAt;
    
    std::string ToJson() const;
};

// ============================================================================
// Intent View - Intent execution flow
// ============================================================================

struct IntentView {
    uint64_t intentId;
    uint64_t agentId;
    std::string intentType;
    std::string status;           // "QUEUED", "EXECUTING", "COMPLETED", "FAILED"
    std::string priority;
    
    // Progress
    std::string currentStage;     // "VALIDATE", "FIREWALL", "EXECUTE", "COMMIT"
    uint32_t stageProgress;       // 0-100
    
    // Timing
    std::string submittedAt;
    std::string startedAt;
    std::string completedAt;
    double elapsedMs;
    
    // Resources
    std::vector<std::string> requiredResources;
    std::vector<std::string> acquiredResources;
    
    // Result
    bool success;
    std::string errorMessage;
    bool wasRolledBack;
    
    std::string ToJson() const;
};

// ============================================================================
// Resource View - Resource allocation
// ============================================================================

struct ResourceView {
    std::string resourceType;
    uint64_t resourceId;
    std::string status;           // "AVAILABLE", "LEASED", "CONTESTED"
    
    // Current lease
    uint64_t leaseId;
    uint64_t ownerAgentId;
    std::string ownerAgentType;
    std::string purpose;
    std::string acquiredAt;
    std::string expiresAt;
    
    // Contention
    uint32_t waitingAgentCount;
    std::vector<uint64_t> waitingAgentIds;
    
    // Capabilities
    std::vector<std::string> grantedCapabilities;
    
    std::string ToJson() const;
};

// ============================================================================
// Build View - Build system telemetry
// ============================================================================

struct BuildView {
    uint64_t buildId;
    std::string buildType;        // "DEBUG", "RELEASE", "TEST"
    std::string status;           // "IDLE", "RUNNING", "COMPLETED", "FAILED"
    
    // Progress
    uint32_t totalTargets;
    uint32_t completedTargets;
    uint32_t failedTargets;
    uint32_t progressPercent;
    
    // Current operation
    std::string currentTarget;
    std::string currentOperation; // "COMPILING", "LINKING", "TESTING"
    std::string currentFile;
    
    // Errors/Warnings
    uint32_t errorCount;
    uint32_t warningCount;
    std::vector<std::string> recentErrors;
    
    // Performance
    double buildTimeMs;
    double estimatedTimeRemainingMs;
    uint64_t memoryUsageMB;
    
    // Timeline
    std::string startedAt;
    std::string estimatedCompletion;
    
    std::string ToJson() const;
};

// ============================================================================
// Patch View - Hotpatch history
// ============================================================================

struct PatchView {
    uint64_t patchId;
    uint64_t intentId;
    uint64_t agentId;
    std::string patchType;        // "FUNCTION_SWAP", "AST_MUTATION", etc.
    std::string status;           // "PENDING", "APPLIED", "ROLLED_BACK", "FAILED"
    
    // Target
    std::string targetSymbol;
    std::string targetFile;
    uint64_t targetAddress;
    
    // Content
    std::string patchHash;
    uint32_t patchSize;
    
    // Transaction
    uint64_t transactionId;
    std::string transactionStatus;
    std::vector<uint64_t> rollbackPoints;
    
    // Validation
    bool validationPassed;
    std::vector<std::string> validationResults;
    
    // Timeline
    std::string createdAt;
    std::string appliedAt;
    std::string rolledBackAt;
    
    std::string ToJson() const;
};

// ============================================================================
// Memory Graph View - Repository statistics
// ============================================================================

struct MemoryGraphView {
    // Files
    uint64_t totalFiles;
    uint64_t dirtyFiles;
    uint64_t parsedFiles;
    uint64_t generatedFiles;
    
    // Symbols
    uint64_t totalSymbols;
    uint64_t definedSymbols;
    uint64_t referencedSymbols;
    
    // Dependencies
    uint64_t totalEdges;
    uint64_t dependencyEdges;
    uint64_t callEdges;
    uint64_t referenceEdges;
    
    // Build graph
    uint64_t buildTargets;
    uint64_t buildEdges;
    std::vector<std::string> criticalPath;
    
    // Performance
    double memoryUsageMB;
    double queryLatencyMs;
    uint64_t cacheHits;
    uint64_t cacheMisses;
    
    // Recent activity
    std::vector<std::string> recentlyModifiedFiles;
    std::vector<std::string> recentlyAccessedSymbols;
    
    std::string ToJson() const;
};

// ============================================================================
// Telemetry View - Performance metrics
// ============================================================================

struct TelemetryView {
    // Intent metrics
    uint64_t intentsPerSecond;
    uint64_t intentsPerMinute;
    double averageIntentLatencyMs;
    double p99IntentLatencyMs;
    
    // Resource metrics
    double resourceUtilization;
    uint32_t contestedResources;
    double averageWaitTimeMs;
    
    // Build metrics
    double buildsPerHour;
    double averageBuildTimeMs;
    double buildSuccessRate;
    
    // Patch metrics
    uint64_t patchesApplied;
    uint64_t patchesRolledBack;
    double patchSuccessRate;
    
    // Error metrics
    uint64_t violationsPerMinute;
    std::unordered_map<std::string, uint64_t> violationsByType;
    
    // System health
    double cpuUsage;
    double memoryUsage;
    double diskIO;
    uint32_t activeThreads;
    
    std::string ToJson() const;
};

// ============================================================================
// System Event - Real-time updates
// ============================================================================

struct SystemEvent {
    uint64_t eventId;
    std::string eventType;        // "AGENT_REGISTERED", "INTENT_STARTED", etc.
    std::string timestamp;
    std::string severity;         // "INFO", "WARNING", "ERROR", "CRITICAL"
    
    // Source
    uint64_t agentId;
    uint64_t intentId;
    std::string component;
    
    // Content
    std::string message;
    std::string details;
    std::unordered_map<std::string, std::string> metadata;
    
    std::string ToJson() const;
};

// ============================================================================
// Dashboard State - Complete system snapshot
// ============================================================================

struct DashboardState {
    std::string timestamp;
    std::string systemStatus;     // "HEALTHY", "DEGRADED", "CRITICAL"
    
    // Views
    std::vector<AgentView> agents;
    std::vector<IntentView> intents;
    std::vector<ResourceView> resources;
    std::vector<BuildView> builds;
    std::vector<PatchView> patches;
    MemoryGraphView memoryGraph;
    TelemetryView telemetry;
    std::vector<SystemEvent> recentEvents;
    
    // Summary
    uint32_t activeAgentCount;
    uint32_t executingIntentCount;
    uint32_t queuedIntentCount;
    uint32_t failedIntentCount;
    uint32_t availableResources;
    uint32_t contestedResources;
    
    std::string ToJson() const;
    static DashboardState Capture();  // Live snapshot from system
};

// ============================================================================
// Control Plane Server - WebSocket endpoint
// ============================================================================

class ControlPlaneServer {
public:
    static ControlPlaneServer& Instance();
    
    // Lifecycle
    bool Initialize(uint16_t port = 8080);
    void Shutdown();
    bool IsRunning() const { return running_.load(); }
    
    // Dashboard sessions
    void SubscribeSession(std::shared_ptr<DashboardSession> session);
    void UnsubscribeSession(std::shared_ptr<DashboardSession> session);
    uint32_t GetActiveSessionCount() const;
    
    // Broadcasting
    void BroadcastState(const DashboardState& state);
    void BroadcastEvent(const SystemEvent& event);
    void BroadcastToView(ViewType view, const std::string& json);
    
    // Real-time updates
    void StartUpdateLoop(uint32_t intervalMs = 1000);
    void StopUpdateLoop();
    void ForceUpdate();
    
    // Configuration
    void SetUpdateInterval(uint32_t intervalMs);
    void EnableView(ViewType view, bool enable);
    bool IsViewEnabled(ViewType view) const;
    
    // Statistics
    struct Stats {
        uint64_t totalConnections;
        uint64_t totalMessagesSent;
        uint64_t totalBytesSent;
        uint32_t currentConnections;
        double averageLatencyMs;
    };
    Stats GetStats() const;

private:
    ControlPlaneServer() = default;
    void UpdateLoop();
    void CaptureAndBroadcast();
    
    std::atomic<bool> running_{false};
    std::atomic<bool> updateLoopRunning_{false};
    std::atomic<uint32_t> updateIntervalMs_{1000};
    
    std::unique_ptr<WebSocketServer> wsServer_;
    std::vector<std::weak_ptr<DashboardSession>> sessions_;
    mutable std::mutex sessionsMutex_;
    
    std::thread updateThread_;
    
    std::unordered_map<ViewType, bool> enabledViews_;
    mutable std::mutex viewsMutex_;
    
    Stats stats_;
    mutable std::mutex statsMutex_;
};

// ============================================================================
// Dashboard Session - Connected client
// ============================================================================

class DashboardSession : public std::enable_shared_from_this<DashboardSession> {
public:
    DashboardSession(uint64_t sessionId);
    
    // Connection
    void OnConnect();
    void OnDisconnect();
    bool IsConnected() const { return connected_.load(); }
    
    // Messaging
    void SendState(const DashboardState& state);
    void SendEvent(const SystemEvent& event);
    void SendMessage(const std::string& json);
    
    // View subscription
    void SubscribeToView(ViewType view);
    void UnsubscribeFromView(ViewType view);
    bool IsSubscribedTo(ViewType view) const;
    std::vector<ViewType> GetSubscribedViews() const;
    
    // Configuration
    void SetUpdateInterval(uint32_t intervalMs);
    uint32_t GetUpdateInterval() const { return updateIntervalMs_.load(); }
    
    // Statistics
    uint64_t GetMessagesSent() const { return messagesSent_.load(); }
    uint64_t GetBytesSent() const { return bytesSent_.load(); }
    std::string GetConnectionTime() const;

private:
    uint64_t sessionId_;
    std::atomic<bool> connected_{false};
    std::chrono::steady_clock::time_point connectedAt_;
    
    std::unordered_set<ViewType> subscribedViews_;
    mutable std::mutex viewsMutex_;
    
    std::atomic<uint32_t> updateIntervalMs_{1000};
    std::atomic<uint64_t> messagesSent_{0};
    std::atomic<uint64_t> bytesSent_{0};
};

// ============================================================================
// Control Plane UI - Main interface
// ============================================================================

class ControlPlaneUI {
public:
    static ControlPlaneUI& Instance();
    
    // Lifecycle
    bool Initialize(uint16_t port = 8080);
    void Shutdown();
    bool IsInitialized() const { return initialized_.load(); }
    
    // Access to server
    ControlPlaneServer& GetServer() { return ControlPlaneServer::Instance(); }
    
    // Quick views
    DashboardState CaptureSnapshot() const;
    void PrintSummary() const;  // Console output
    
    // Event logging
    void LogEvent(const std::string& component, 
                  const std::string& message,
                  const std::string& severity = "INFO");
    void LogIntentStarted(uint64_t intentId, uint64_t agentId);
    void LogIntentCompleted(uint64_t intentId, bool success);
    void LogResourceContention(const std::string& resourceType, 
                               uint64_t agentId);
    void LogPatchApplied(uint64_t patchId, const std::string& symbol);
    void LogPatchRolledBack(uint64_t patchId, const std::string& reason);
    void LogViolation(const std::string& intentType,
                      const std::string& violation,
                      const std::string& details);
    
    // Emergency controls
    void EmergencyStop(const std::string& reason);
    void EmergencyRevokeAllResources(uint64_t agentId);
    void EmergencyRollbackAllPatches();

private:
    ControlPlaneUI() = default;
    
    std::atomic<bool> initialized_{false};
    std::atomic<uint64_t> nextEventId_{1};
};

// ============================================================================
// HTML Dashboard - Embedded web UI
// ============================================================================

class HTMLDashboard {
public:
    static std::string GetDashboardHTML();
    static std::string GetDashboardCSS();
    static std::string GetDashboardJS();
    
    // Component templates
    static std::string GetAgentPanelTemplate();
    static std::string GetIntentPanelTemplate();
    static std::string GetResourcePanelTemplate();
    static std::string GetBuildPanelTemplate();
    static std::string GetPatchPanelTemplate();
    static std::string GetMemoryPanelTemplate();
    static std::string GetTelemetryPanelTemplate();
    static std::string GetEventLogTemplate();
};

} // namespace ControlPlane
} // namespace RawrXD
