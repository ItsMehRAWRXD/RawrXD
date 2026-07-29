// Sovereign Control Plane UI - Implementation
// Live visualization of the autonomous system

#include "ControlPlaneUI.hpp"
#include "../kernel/AgentKernel.hpp"
#include "../kernel/IntentExecutionPipeline.hpp"
#include "../memory/RepositoryMemoryGraph.hpp"

#include <sstream>
#include <iomanip>
#include <chrono>

namespace RawrXD {
namespace ControlPlane {

// ============================================================================
// Utility Functions
// ============================================================================

static std::string GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

static std::string FormatDuration(double ms) {
    if (ms < 1000) {
        return std::to_string(static_cast<int>(ms)) + "ms";
    } else if (ms < 60000) {
        return std::to_string(static_cast<int>(ms / 1000)) + "s";
    } else {
        return std::to_string(static_cast<int>(ms / 60000)) + "m";
    }
}

// ============================================================================
// View Serialization
// ============================================================================

std::string AgentView::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"agentId\":" << agentId << ",";
    ss << "\"agentType\":\"" << agentType << "\",";
    ss << "\"modelBackend\":\"" << modelBackend << "\",";
    ss << "\"status\":\"" << status << "\",";
    ss << "\"currentIntentId\":" << currentIntentId << ",";
    ss << "\"currentIntentType\":\"" << currentIntentType << "\",";
    ss << "\"executionTimeMs\":" << executionTimeMs << ",";
    ss << "\"activeLeaseCount\":" << activeLeaseCount << ",";
    ss << "\"intentsCompleted\":" << intentsCompleted << ",";
    ss << "\"intentsFailed\":" << intentsFailed << ",";
    ss << "\"successRate\":" << successRate << ",";
    ss << "\"averageLatencyMs\":" << averageLatencyMs << ",";
    ss << "\"lastActivity\":\"" << lastActivity << "\",";
    ss << "\"startedAt\":\"" << startedAt << "\"";
    ss << "}";
    return ss.str();
}

std::string IntentView::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"intentId\":" << intentId << ",";
    ss << "\"agentId\":" << agentId << ",";
    ss << "\"intentType\":\"" << intentType << "\",";
    ss << "\"status\":\"" << status << "\",";
    ss << "\"priority\":\"" << priority << "\",";
    ss << "\"currentStage\":\"" << currentStage << "\",";
    ss << "\"stageProgress\":" << stageProgress << ",";
    ss << "\"submittedAt\":\"" << submittedAt << "\",";
    ss << "\"startedAt\":\"" << startedAt << "\",";
    ss << "\"completedAt\":\"" << completedAt << "\",";
    ss << "\"elapsedMs\":" << elapsedMs << ",";
    ss << "\"success\":" << (success ? "true" : "false") << ",";
    ss << "\"errorMessage\":\"" << errorMessage << "\",";
    ss << "\"wasRolledBack\":" << (wasRolledBack ? "true" : "false") << "";
    ss << "}";
    return ss.str();
}

std::string ResourceView::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"resourceType\":\"" << resourceType << "\",";
    ss << "\"resourceId\":" << resourceId << ",";
    ss << "\"status\":\"" << status << "\",";
    ss << "\"leaseId\":" << leaseId << ",";
    ss << "\"ownerAgentId\":" << ownerAgentId << ",";
    ss << "\"ownerAgentType\":\"" << ownerAgentType << "\",";
    ss << "\"purpose\":\"" << purpose << "\",";
    ss << "\"acquiredAt\":\"" << acquiredAt << "\",";
    ss << "\"expiresAt\":\"" << expiresAt << "\",";
    ss << "\"waitingAgentCount\":" << waitingAgentCount << ",";
    ss << "\"grantedCapabilities\":[";
    for (size_t i = 0; i < grantedCapabilities.size(); ++i) {
        if (i > 0) ss << ",";
        ss << "\"" << grantedCapabilities[i] << "\"";
    }
    ss << "]}";
    return ss.str();
}

std::string BuildView::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"buildId\":" << buildId << ",";
    ss << "\"buildType\":\"" << buildType << "\",";
    ss << "\"status\":\"" << status << "\",";
    ss << "\"totalTargets\":" << totalTargets << ",";
    ss << "\"completedTargets\":" << completedTargets << ",";
    ss << "\"failedTargets\":" << failedTargets << ",";
    ss << "\"progressPercent\":" << progressPercent << ",";
    ss << "\"currentTarget\":\"" << currentTarget << "\",";
    ss << "\"currentOperation\":\"" << currentOperation << "\",";
    ss << "\"currentFile\":\"" << currentFile << "\",";
    ss << "\"errorCount\":" << errorCount << ",";
    ss << "\"warningCount\":" << warningCount << ",";
    ss << "\"buildTimeMs\":" << buildTimeMs << ",";
    ss << "\"memoryUsageMB\":" << memoryUsageMB << ",";
    ss << "\"startedAt\":\"" << startedAt << "\"";
    ss << "}";
    return ss.str();
}

std::string PatchView::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"patchId\":" << patchId << ",";
    ss << "\"intentId\":" << intentId << ",";
    ss << "\"agentId\":" << agentId << ",";
    ss << "\"patchType\":\"" << patchType << "\",";
    ss << "\"status\":\"" << status << "\",";
    ss << "\"targetSymbol\":\"" << targetSymbol << "\",";
    ss << "\"targetFile\":\"" << targetFile << "\",";
    ss << "\"patchHash\":\"" << patchHash << "\",";
    ss << "\"patchSize\":" << patchSize << ",";
    ss << "\"transactionId\":" << transactionId << ",";
    ss << "\"validationPassed\":" << (validationPassed ? "true" : "false") << ",";
    ss << "\"createdAt\":\"" << createdAt << "\",";
    ss << "\"appliedAt\":\"" << appliedAt << "\"";
    ss << "}";
    return ss.str();
}

std::string MemoryGraphView::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"totalFiles\":" << totalFiles << ",";
    ss << "\"dirtyFiles\":" << dirtyFiles << ",";
    ss << "\"parsedFiles\":" << parsedFiles << ",";
    ss << "\"totalSymbols\":" << totalSymbols << ",";
    ss << "\"definedSymbols\":" << definedSymbols << ",";
    ss << "\"totalEdges\":" << totalEdges << ",";
    ss << "\"dependencyEdges\":" << dependencyEdges << ",";
    ss << "\"buildTargets\":" << buildTargets << ",";
    ss << "\"memoryUsageMB\":" << memoryUsageMB << ",";
    ss << "\"queryLatencyMs\":" << queryLatencyMs << ",";
    ss << "\"cacheHits\":" << cacheHits << ",";
    ss << "\"cacheMisses\":" << cacheMisses << "";
    ss << "}";
    return ss.str();
}

std::string TelemetryView::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"intentsPerSecond\":" << intentsPerSecond << ",";
    ss << "\"averageIntentLatencyMs\":" << averageIntentLatencyMs << ",";
    ss << "\"p99IntentLatencyMs\":" << p99IntentLatencyMs << ",";
    ss << "\"resourceUtilization\":" << resourceUtilization << ",";
    ss << "\"contestedResources\":" << contestedResources << ",";
    ss << "\"buildSuccessRate\":" << buildSuccessRate << ",";
    ss << "\"patchesApplied\":" << patchesApplied << ",";
    ss << "\"patchesRolledBack\":" << patchesRolledBack << ",";
    ss << "\"patchSuccessRate\":" << patchSuccessRate << ",";
    ss << "\"cpuUsage\":" << cpuUsage << ",";
    ss << "\"memoryUsage\":" << memoryUsage << ",";
    ss << "\"activeThreads\":" << activeThreads << "";
    ss << "}";
    return ss.str();
}

std::string SystemEvent::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"eventId\":" << eventId << ",";
    ss << "\"eventType\":\"" << eventType << "\",";
    ss << "\"timestamp\":\"" << timestamp << "\",";
    ss << "\"severity\":\"" << severity << "\",";
    ss << "\"agentId\":" << agentId << ",";
    ss << "\"intentId\":" << intentId << ",";
    ss << "\"component\":\"" << component << "\",";
    ss << "\"message\":\"" << message << "\",";
    ss << "\"details\":\"" << details << "\"";
    ss << "}";
    return ss.str();
}

// ============================================================================
// Dashboard State
// ============================================================================

std::string DashboardState::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"timestamp\":\"" << timestamp << "\",";
    ss << "\"systemStatus\":\"" << systemStatus << "\",";
    ss << "\"activeAgentCount\":" << activeAgentCount << ",";
    ss << "\"executingIntentCount\":" << executingIntentCount << ",";
    ss << "\"queuedIntentCount\":" << queuedIntentCount << ",";
    ss << "\"failedIntentCount\":" << failedIntentCount << ",";
    ss << "\"availableResources\":" << availableResources << ",";
    ss << "\"contestedResources\":" << contestedResources << ",";
    
    // Agents
    ss << "\"agents\":[";
    for (size_t i = 0; i < agents.size(); ++i) {
        if (i > 0) ss << ",";
        ss << agents[i].ToJson();
    }
    ss << "],";
    
    // Intents
    ss << "\"intents\":[";
    for (size_t i = 0; i < intents.size(); ++i) {
        if (i > 0) ss << ",";
        ss << intents[i].ToJson();
    }
    ss << "],";
    
    // Resources
    ss << "\"resources\":[";
    for (size_t i = 0; i < resources.size(); ++i) {
        if (i > 0) ss << ",";
        ss << resources[i].ToJson();
    }
    ss << "],";
    
    // Memory Graph
    ss << "\"memoryGraph\":" << memoryGraph.ToJson() << ",";
    
    // Telemetry
    ss << "\"telemetry\":" << telemetry.ToJson() << ",";
    
    // Events
    ss << "\"recentEvents\":[";
    for (size_t i = 0; i < recentEvents.size() && i < 50; ++i) {
        if (i > 0) ss << ",";
        ss << recentEvents[i].ToJson();
    }
    ss << "]";
    
    ss << "}";
    return ss.str();
}

DashboardState DashboardState::Capture() {
    DashboardState state;
    state.timestamp = GetTimestamp();
    
    // Capture from Agent Kernel
    auto& kernel = Kernel::AgentKernel::Instance();
    
    // TODO: Populate from actual kernel state
    // This is a simplified version
    
    state.systemStatus = "HEALTHY";
    state.activeAgentCount = 0;
    state.executingIntentCount = 0;
    state.queuedIntentCount = 0;
    state.failedIntentCount = 0;
    state.availableResources = 0;
    state.contestedResources = 0;
    
    // Capture memory graph stats
    auto& graph = Memory::RepositoryGraph::Instance();
    if (graph.IsInitialized()) {
        auto stats = graph.GetStats();
        state.memoryGraph.totalFiles = stats.fileCount;
        state.memoryGraph.totalSymbols = stats.symbolCount;
        state.memoryGraph.totalEdges = stats.edgeCount;
        state.memoryGraph.memoryUsageMB = stats.memoryUsageMB;
    }
    
    return state;
}

// ============================================================================
// Control Plane UI
// ============================================================================

ControlPlaneUI& ControlPlaneUI::Instance() {
    static ControlPlaneUI instance;
    return instance;
}

bool ControlPlaneUI::Initialize(uint16_t port) {
    if (initialized_.load()) return true;
    
    // Initialize the WebSocket server
    if (!ControlPlaneServer::Instance().Initialize(port)) {
        return false;
    }
    
    // Start update loop
    ControlPlaneServer::Instance().StartUpdateLoop(1000);
    
    initialized_.store(true);
    
    LogEvent("ControlPlane", "Control Plane UI initialized", "INFO");
    
    return true;
}

void ControlPlaneUI::Shutdown() {
    if (!initialized_.load()) return;
    
    ControlPlaneServer::Instance().StopUpdateLoop();
    ControlPlaneServer::Instance().Shutdown();
    
    initialized_.store(false);
}

DashboardState ControlPlaneUI::CaptureSnapshot() const {
    return DashboardState::Capture();
}

void ControlPlaneUI::PrintSummary() const {
    auto state = CaptureSnapshot();
    
    std::cout << "\n========================================\n";
    std::cout << "Sovereign Control Plane - System Summary\n";
    std::cout << "========================================\n";
    std::cout << "Status: " << state.systemStatus << "\n";
    std::cout << "Timestamp: " << state.timestamp << "\n\n";
    
    std::cout << "Agents: " << state.activeAgentCount << " active\n";
    std::cout << "Intents: " << state.executingIntentCount << " executing, "
              << state.queuedIntentCount << " queued\n";
    std::cout << "Resources: " << state.availableResources << " available, "
              << state.contestedResources << " contested\n";
    
    std::cout << "Memory Graph: " << state.memoryGraph.totalFiles << " files, "
              << state.memoryGraph.totalSymbols << " symbols\n";
    
    std::cout << "========================================\n\n";
}

void ControlPlaneUI::LogEvent(const std::string& component,
                               const std::string& message,
                               const std::string& severity) {
    SystemEvent event;
    event.eventId = nextEventId_++;
    event.eventType = "SYSTEM_LOG";
    event.timestamp = GetTimestamp();
    event.severity = severity;
    event.component = component;
    event.message = message;
    
    // Broadcast to connected dashboards
    ControlPlaneServer::Instance().BroadcastEvent(event);
    
    // Also log to console
    std::cout << "[" << severity << "] " << component << ": " << message << "\n";
}

void ControlPlaneUI::LogIntentStarted(uint64_t intentId, uint64_t agentId) {
    LogEvent("IntentExecution", 
             "Intent " + std::to_string(intentId) + " started by agent " + std::to_string(agentId),
             "INFO");
}

void ControlPlaneUI::LogIntentCompleted(uint64_t intentId, bool success) {
    LogEvent("IntentExecution",
             "Intent " + std::to_string(intentId) + " " + (success ? "completed" : "failed"),
             success ? "INFO" : "WARNING");
}

void ControlPlaneUI::LogResourceContention(const std::string& resourceType, uint64_t agentId) {
    LogEvent("ResourceScheduler",
             "Contention on " + resourceType + " requested by agent " + std::to_string(agentId),
             "WARNING");
}

void ControlPlaneUI::LogPatchApplied(uint64_t patchId, const std::string& symbol) {
    LogEvent("Hotpatch",
             "Patch " + std::to_string(patchId) + " applied to " + symbol,
             "INFO");
}

void ControlPlaneUI::LogPatchRolledBack(uint64_t patchId, const std::string& reason) {
    LogEvent("Hotpatch",
             "Patch " + std::to_string(patchId) + " rolled back: " + reason,
             "WARNING");
}

void ControlPlaneUI::LogViolation(const std::string& intentType,
                                   const std::string& violation,
                                   const std::string& details) {
    LogEvent("Guardrails",
             "Violation in " + intentType + ": " + violation,
             "ERROR");
}

void ControlPlaneUI::EmergencyStop(const std::string& reason) {
    LogEvent("EMERGENCY", "EMERGENCY STOP: " + reason, "CRITICAL");
    
    // Broadcast emergency to all dashboards
    SystemEvent event;
    event.eventId = nextEventId_++;
    event.eventType = "EMERGENCY_STOP";
    event.timestamp = GetTimestamp();
    event.severity = "CRITICAL";
    event.message = reason;
    
    ControlPlaneServer::Instance().BroadcastEvent(event);
}

void ControlPlaneUI::EmergencyRevokeAllResources(uint64_t agentId) {
    LogEvent("EMERGENCY",
             "Emergency revoke all resources for agent " + std::to_string(agentId),
             "CRITICAL");
}

void ControlPlaneUI::EmergencyRollbackAllPatches() {
    LogEvent("EMERGENCY", "Emergency rollback all patches", "CRITICAL");
}

// ============================================================================
// Control Plane Server (Stub - would need WebSocket library)
// ============================================================================

ControlPlaneServer& ControlPlaneServer::Instance() {
    static ControlPlaneServer instance;
    return instance;
}

bool ControlPlaneServer::Initialize(uint16_t port) {
    running_.store(true);
    
    // Initialize all views as enabled
    for (uint32_t i = 0; i < static_cast<uint32_t>(ViewType::COUNT); ++i) {
        enabledViews_[static_cast<ViewType>(i)] = true;
    }
    
    return true;
}

void ControlPlaneServer::Shutdown() {
    running_.store(false);
    updateLoopRunning_.store(false);
    
    if (updateThread_.joinable()) {
        updateThread_.join();
    }
}

void ControlPlaneServer::StartUpdateLoop(uint32_t intervalMs) {
    updateIntervalMs_.store(intervalMs);
    updateLoopRunning_.store(true);
    
    updateThread_ = std::thread(&ControlPlaneServer::UpdateLoop, this);
}

void ControlPlaneServer::StopUpdateLoop() {
    updateLoopRunning_.store(false);
}

void ControlPlaneServer::UpdateLoop() {
    while (updateLoopRunning_.load()) {
        CaptureAndBroadcast();
        
        // Sleep for interval
        std::this_thread::sleep_for(
            std::chrono::milliseconds(updateIntervalMs_.load())
        );
    }
}

void ControlPlaneServer::CaptureAndBroadcast() {
    auto state = DashboardState::Capture();
    BroadcastState(state);
}

void ControlPlaneServer::BroadcastState(const DashboardState& state) {
    std::string json = state.ToJson();
    
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    for (auto& weakSession : sessions_) {
        if (auto session = weakSession.lock()) {
            session->SendState(state);
        }
    }
    
    // Update stats
    std::lock_guard<std::mutex> statsLock(statsMutex_);
    stats_.totalMessagesSent++;
    stats_.totalBytesSent += json.length();
}

void ControlPlaneServer::BroadcastEvent(const SystemEvent& event) {
    std::string json = event.ToJson();
    
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    for (auto& weakSession : sessions_) {
        if (auto session = weakSession.lock()) {
            session->SendEvent(event);
        }
    }
}

void ControlPlaneServer::SubscribeSession(std::shared_ptr<DashboardSession> session) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    sessions_.push_back(session);
    
    std::lock_guard<std::mutex> statsLock(statsMutex_);
    stats_.totalConnections++;
    stats_.currentConnections++;
}

void ControlPlaneServer::UnsubscribeSession(std::shared_ptr<DashboardSession> session) {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    sessions_.erase(
        std::remove_if(sessions_.begin(), sessions_.end(),
            [&session](const std::weak_ptr<DashboardSession>& weak) {
                if (auto s = weak.lock()) {
                    return s.get() == session.get();
                }
                return true; // Remove expired
            }),
        sessions_.end()
    );
    
    std::lock_guard<std::mutex> statsLock(statsMutex_);
    stats_.currentConnections--;
}

uint32_t ControlPlaneServer::GetActiveSessionCount() const {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    return static_cast<uint32_t>(sessions_.size());
}

void ControlPlaneServer::SetUpdateInterval(uint32_t intervalMs) {
    updateIntervalMs_.store(intervalMs);
}

void ControlPlaneServer::EnableView(ViewType view, bool enable) {
    std::lock_guard<std::mutex> lock(viewsMutex_);
    enabledViews_[view] = enable;
}

bool ControlPlaneServer::IsViewEnabled(ViewType view) const {
    std::lock_guard<std::mutex> lock(viewsMutex_);
    auto it = enabledViews_.find(view);
    if (it != enabledViews_.end()) {
        return it->second;
    }
    return false;
}

ControlPlaneServer::Stats ControlPlaneServer::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

// ============================================================================
// Dashboard Session
// ============================================================================

DashboardSession::DashboardSession(uint64_t sessionId) 
    : sessionId_(sessionId) {}

void DashboardSession::OnConnect() {
    connected_.store(true);
    connectedAt_ = std::chrono::steady_clock::now();
}

void DashboardSession::OnDisconnect() {
    connected_.store(false);
}

void DashboardSession::SendState(const DashboardState& state) {
    if (!connected_.load()) return;
    
    std::string json = state.ToJson();
    SendMessage(json);
}

void DashboardSession::SendEvent(const SystemEvent& event) {
    if (!connected_.load()) return;
    
    std::string json = event.ToJson();
    SendMessage(json);
}

void DashboardSession::SendMessage(const std::string& json) {
    if (!connected_.load()) return;
    
    // In real implementation, send via WebSocket
    messagesSent_++;
    bytesSent_ += json.length();
}

void DashboardSession::SubscribeToView(ViewType view) {
    std::lock_guard<std::mutex> lock(viewsMutex_);
    subscribedViews_.insert(view);
}

void DashboardSession::UnsubscribeFromView(ViewType view) {
    std::lock_guard<std::mutex> lock(viewsMutex_);
    subscribedViews_.erase(view);
}

bool DashboardSession::IsSubscribedTo(ViewType view) const {
    std::lock_guard<std::mutex> lock(viewsMutex_);
    return subscribedViews_.find(view) != subscribedViews_.end();
}

std::vector<ViewType> DashboardSession::GetSubscribedViews() const {
    std::lock_guard<std::mutex> lock(viewsMutex_);
    return std::vector<ViewType>(subscribedViews_.begin(), subscribedViews_.end());
}

std::string DashboardSession::GetConnectionTime() const {
    auto duration = std::chrono::steady_clock::now() - connectedAt_;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    
    if (seconds < 60) {
        return std::to_string(seconds) + "s";
    } else if (seconds < 3600) {
        return std::to_string(seconds / 60) + "m";
    } else {
        return std::to_string(seconds / 3600) + "h";
    }
}

// ============================================================================
// HTML Dashboard (Stub - would generate full HTML/JS/CSS)
// ============================================================================

std::string HTMLDashboard::GetDashboardHTML() {
    return R"(<!DOCTYPE html>
<html>
<head>
    <title>Sovereign Control Plane</title>
    <style>
        body { font-family: monospace; background: #1a1a1a; color: #00ff00; }
        .panel { border: 1px solid #00ff00; margin: 10px; padding: 10px; }
        .header { font-size: 24px; border-bottom: 2px solid #00ff00; }
        .metric { display: inline-block; margin: 10px; }
        .healthy { color: #00ff00; }
        .warning { color: #ffff00; }
        .critical { color: #ff0000; }
    </style>
</head>
<body>
    <div class="header">Sovereign Control Plane</div>
    <div id="content">Loading...</div>
    <script>
        // WebSocket connection would go here
        console.log('Sovereign Control Plane Dashboard');
    </script>
</body>
</html>)";
}

std::string HTMLDashboard::GetDashboardCSS() {
    return "/* Dashboard CSS */";
}

std::string HTMLDashboard::GetDashboardJS() {
    return "// Dashboard JavaScript";
}

std::string HTMLDashboard::GetAgentPanelTemplate() {
    return "<!-- Agent Panel Template -->";
}

std::string HTMLDashboard::GetIntentPanelTemplate() {
    return "<!-- Intent Panel Template -->";
}

std::string HTMLDashboard::GetResourcePanelTemplate() {
    return "<!-- Resource Panel Template -->";
}

std::string HTMLDashboard::GetBuildPanelTemplate() {
    return "<!-- Build Panel Template -->";
}

std::string HTMLDashboard::GetPatchPanelTemplate() {
    return "<!-- Patch Panel Template -->";
}

std::string HTMLDashboard::GetMemoryPanelTemplate() {
    return "<!-- Memory Panel Template -->";
}

std::string HTMLDashboard::GetTelemetryPanelTemplate() {
    return "<!-- Telemetry Panel Template -->";
}

std::string HTMLDashboard::GetEventLogTemplate() {
    return "<!-- Event Log Template -->";
}

} // namespace ControlPlane
} // namespace RawrXD
