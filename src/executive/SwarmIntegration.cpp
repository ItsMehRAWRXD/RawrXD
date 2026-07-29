// ============================================================================
// SwarmIntegration.cpp - Unified Swarm Integration Implementation
// ============================================================================

#include "SwarmIntegration.hpp"
#include <cstdio>
#include <cstring>
#include <sstream>
#include <fstream>

namespace RawrXD {
namespace Executive {

// ============================================================================
// Initialize both swarms
// ============================================================================
void SwarmIntegrationManager::initialize() {
    if (initialized_) return;
    
    printf("[SwarmIntegration] Initializing unified swarm system...\n");
    
    // Initialize TokenEfficiencySwarm
    auto& efficiencySwarm = TokenEfficiencySwarm::getInstance();
    SwarmConfig efficiencyConfig;
    efficiencyConfig.triggerThreshold = 2.0f;        // Trigger at 2x (more sensitive)
    efficiencyConfig.retriggerThreshold = 1.5f;    // Hysteresis
    efficiencyConfig.minTriggerIntervalMs = 500;   // 2 triggers/sec max
    efficiencyConfig.nonBlocking = true;
    efficiencyConfig.enableTelemetry = true;
    efficiencySwarm.configure(efficiencyConfig);
    
    // TokenEstimatorSwarm is self-initializing
    printf("[SwarmIntegration] \u2713 TokenEstimatorSwarm ready\n");
    
    initialized_ = true;
    printf("[SwarmIntegration] \u2713 Unified swarm system initialized\n");
}

// ============================================================================
// Process cycle start - record estimates
// ============================================================================
void SwarmIntegrationManager::processCycleStart(uint64_t goalId, 
                                                   const char* operation,
                                                   const char* agent,
                                                   float estimatedTokens) {
    if (!initialized_) initialize();
    
    // Create and store estimate
    TokenEstimate estimate;
    estimate.goalId = goalId;
    estimate.totalEstimated = estimatedTokens;
    estimate.timestamp = std::chrono::steady_clock::now();
    estimate.operationType = operation;
    estimate.agentName = agent;
    
    // Store for later use
    activeEstimates_[goalId] = estimate;
    
    // Record in TokenEstimatorSwarm
    TokenEstimatorSwarm::getInstance().recordEstimate(goalId, estimate);
    
    printf("[SwarmIntegration] Cycle %llu start: estimated %.0f tokens [%s/%s]\n",
           (unsigned long long)goalId, estimatedTokens, 
           operation ? operation : "?", agent ? agent : "?");
}

// ============================================================================
// Process cycle end - record actuals and trigger analysis if needed
// ============================================================================
void SwarmIntegrationManager::processCycleEnd(uint64_t goalId, 
                                                float actualTokens,
                                                uint32_t retryCount) {
    if (!initialized_) initialize();
    
    // Get the original estimate
    auto it = activeEstimates_.find(goalId);
    if (it == activeEstimates_.end()) {
        printf("[SwarmIntegration] Warning: No estimate found for goal %llu\n",
               (unsigned long long)goalId);
        return;
    }
    
    float estimatedTokens = it->second.totalEstimated;
    
    // Create actuals record
    TokenEstimate actuals;
    actuals.goalId = goalId;
    actuals.totalActual = actualTokens;
    actuals.timestamp = std::chrono::steady_clock::now();
    actuals.operationType = it->second.operationType;
    actuals.agentName = it->second.agentName;
    actuals.retryCount = retryCount;
    
    // Record in TokenEstimatorSwarm (triggers swarm if >20% slack)
    TokenEstimatorSwarm::getInstance().recordActuals(goalId, actuals);
    
    // Check efficiency and trigger deep analysis if needed
    checkEfficiencyAndAnalyze(goalId, actualTokens, estimatedTokens);
    
    // Clean up
    activeEstimates_.erase(it);
    
    printf("[SwarmIntegration] Cycle %llu end: actual %.0f tokens (%.1f%% of estimate)\n",
           (unsigned long long)goalId, actualTokens, 
           (actualTokens / estimatedTokens) * 100.0f);
}

// ============================================================================
// Check efficiency and trigger deep analysis
// ============================================================================
void SwarmIntegrationManager::checkEfficiencyAndAnalyze(uint64_t goalId,
                                                         float actual, 
                                                         float estimated) {
    if (estimated <= 0) return;
    
    float ratio = actual / estimated;
    
    // If efficiency threshold exceeded, trigger TokenEstimatorSwarm analysis
    auto& efficiencySwarm = TokenEfficiencySwarm::getInstance();
    if (efficiencySwarm.wouldTrigger(actual, estimated)) {
        printf("[SwarmIntegration] Efficiency threshold exceeded (%.1fx) - triggering deep analysis...\n",
               ratio);
        
        // Force run the estimation swarm for detailed analysis
        TokenEstimatorSwarm::getInstance().runEstimationSwarm(goalId);
        
        // Also trigger efficiency swarm
        efficiencySwarm.trigger(goalId, "efficiency_alert", actual, estimated, 1, "swarm_integration");
    }
}

// ============================================================================
// Get combined recommendations
// ============================================================================
std::vector<const char*> SwarmIntegrationManager::getRecommendations(uint64_t goalId) {
    std::vector<const char*> recommendations;
    
    // Get slack analysis
    auto analysis = TokenEstimatorSwarm::getInstance().analyzeSlack(goalId);
    
    // Add recommendations from slack analysis
    for (const auto& rec : analysis.recommendations) {
        recommendations.push_back(rec);
    }
    
    return recommendations;
}

// ============================================================================
// Export telemetry
// ============================================================================
void SwarmIntegrationManager::exportTelemetry(const char* filename) {
    TokenEstimatorSwarm::getInstance().exportToCSV(filename);
    
    // Also export efficiency swarm telemetry
    auto& efficiencySwarm = TokenEfficiencySwarm::getInstance();
    printf("[SwarmIntegration] Efficiency triggers: %u\n", 
           efficiencySwarm.getTriggerCount());
}

// ============================================================================
// Export Prometheus metrics
// ============================================================================
void SwarmIntegrationManager::exportPrometheusMetrics(const char* filename) {
    std::ofstream file(filename);
    if (!file.is_open()) return;
    
    auto& estimatorSwarm = TokenEstimatorSwarm::getInstance();
    auto& efficiencySwarm = TokenEfficiencySwarm::getInstance();
    
    // Write Prometheus-style metrics
    file << "# HELP rawrxd_token_estimates_total Total token estimates recorded\n";
    file << "# TYPE rawrxd_token_estimates_total counter\n";
    file << "rawrxd_token_estimates_total " << estimatorSwarm.getHistory(0, 1000).size() << "\n\n";
    
    file << "# HELP rawrxd_efficiency_triggers_total Total efficiency threshold triggers\n";
    file << "# TYPE rawrxd_efficiency_triggers_total counter\n";
    file << "rawrxd_efficiency_triggers_total " << efficiencySwarm.getTriggerCount() << "\n\n";
    
    file << "# HELP rawrxd_last_trigger_timestamp_ms Last trigger timestamp\n";
    file << "# TYPE rawrxd_last_trigger_timestamp_ms gauge\n";
    auto lastTrigger = efficiencySwarm.getLastTriggerTime();
    auto now = std::chrono::steady_clock::now();
    auto msSinceLast = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastTrigger).count();
    file << "rawrxd_last_trigger_timestamp_ms " << msSinceLast << "\n";
    
    file.close();
    printf("[SwarmIntegration] Exported Prometheus metrics to %s\n", filename);
}

// ============================================================================
// Reset all state
// ============================================================================
void SwarmIntegrationManager::reset() {
    activeEstimates_.clear();
    TokenEstimatorSwarm::getInstance().clearHistory();
    initialized_ = false;
}

// ============================================================================
// C-API Implementation
// ============================================================================
extern "C" {

void InitializeSwarmIntegration() {
    RawrXD::Executive::SwarmIntegrationManager::getInstance().initialize();
}

void SwarmCycleStart(uint64_t goalId, const char* operation, const char* agent,
                     float estimatedTokens) {
    RawrXD::Executive::SwarmIntegrationManager::getInstance()
        .processCycleStart(goalId, operation, agent, estimatedTokens);
}

void SwarmCycleEnd(uint64_t goalId, float actualTokens, uint32_t retryCount) {
    RawrXD::Executive::SwarmIntegrationManager::getInstance()
        .processCycleEnd(goalId, actualTokens, retryCount);
}

void GetSwarmRecommendations(uint64_t goalId, char* buffer, size_t bufferSize) {
    auto recs = RawrXD::Executive::SwarmIntegrationManager::getInstance()
        .getRecommendations(goalId);
    
    std::stringstream ss;
    ss << "Swarm Recommendations for Goal " << goalId << ":\n";
    for (size_t i = 0; i < recs.size(); i++) {
        ss << "  " << (i + 1) << ". " << recs[i] << "\n";
    }
    
    if (recs.empty()) {
        ss << "  No specific recommendations at this time.\n";
    }
    
    std::string result = ss.str();
    strncpy(buffer, result.c_str(), bufferSize - 1);
    buffer[bufferSize - 1] = '\0';
}

} // extern "C"

} // namespace Executive
} // namespace RawrXD
