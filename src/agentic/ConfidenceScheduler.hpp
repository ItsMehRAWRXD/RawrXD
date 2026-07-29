// ============================================================================
// ConfidenceScheduler.hpp - Schedule work where confidence is weakest
// ============================================================================

#pragma once

#include "AgentTypes.hpp"
#include "Blackboard.hpp"
#include <queue>
#include <vector>
#include <mutex>
#include <chrono>
#include <optional>
#include <iostream>

namespace RawrXD::Agentic {

// ============================================================================
// Scheduled Work Item
// ============================================================================

struct ScheduledWorkItem {
    std::string taskId;
    std::string agentType;
    std::string target;
    double currentConfidence = 0.0;
    double urgency = 0.0; // 0-1 based on mission priority
    std::chrono::milliseconds estimatedDuration{0};
    uint64_t targetAddress = 0;
    std::vector<std::string> requiredCapabilities;
    std::chrono::steady_clock::time_point scheduledAt;
    
    // Higher urgency, lower confidence = higher priority
    double getPriority() const { return urgency * (1.0 - currentConfidence); }
    
    bool operator<(const ScheduledWorkItem& other) const {
        // Reverse comparison for max-heap behavior
        return getPriority() < other.getPriority();
    }
};

// ============================================================================
// Confidence Scheduler
// ============================================================================

class ConfidenceScheduler {
public:
    explicit ConfidenceScheduler(Blackboard* blackboard) : blackboard_(blackboard) {}
    ~ConfidenceScheduler() = default;
    
    // Schedule next work item based on confidence gaps
    std::optional<ScheduledWorkItem> getNextWorkItem();
    
    // Find analysis entries below confidence threshold
    std::vector<BlackboardEntry> findLowConfidenceEntries(double threshold = 0.7);
    
    // Schedule validator agents for low-confidence entries
    std::vector<ScheduledWorkItem> scheduleValidators(
        const std::vector<BlackboardEntry>& entries,
        double urgency = 0.5);
    
    // Schedule specific agent type for entries
    std::vector<ScheduledWorkItem> scheduleAgents(
        const std::vector<BlackboardEntry>& entries,
        const std::string& agentType,
        const std::vector<std::string>& capabilities,
        double urgency = 0.5);
    
    // Recalculate priorities when new evidence arrives
    void recalculatePriorities(const std::vector<AgentObservation>& newEvidence);
    
    // Add work item to queue
    void enqueueWorkItem(const ScheduledWorkItem& item);
    
    // Get queue size
    size_t queueSize() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    // Clear queue
    void clearQueue() {
        std::lock_guard<std::mutex> lock(mutex_);
        while (!queue_.empty()) queue_.pop();
    }
    
    // Metrics
    struct SchedulerMetrics {
        int tasksScheduled = 0;
        int validatorsSpawned = 0;
        double averageConfidenceImprovement = 0.0;
        std::chrono::milliseconds averageScheduleTime{0};
        int totalProcessed = 0;
        int totalSkipped = 0;
    };
    SchedulerMetrics getMetrics() const {
        std::lock_guard<std::mutex> lock(metricsMutex_);
        return metrics_;
    }
    void resetMetrics() {
        std::lock_guard<std::mutex> lock(metricsMutex_);
        metrics_ = {};
    }
    
private:
    Blackboard* blackboard_;
    std::priority_queue<ScheduledWorkItem> queue_;
    mutable std::mutex mutex_;
    
    std::unordered_map<std::string, double> confidenceCache_;
    mutable std::mutex cacheMutex_;
    
    SchedulerMetrics metrics_;
    mutable std::mutex metricsMutex_;
    
    // Helper methods
    double calculateUrgency(const BlackboardEntry& entry);
    double estimateConfidenceGain(const BlackboardEntry& entry, 
                                    const std::string& agentType);
    std::string selectBestAgent(const BlackboardEntry& entry);
    std::chrono::milliseconds estimateDuration(const BlackboardEntry& entry, 
                                                const std::string& agentType);
};

} // namespace RawrXD::Agentic
