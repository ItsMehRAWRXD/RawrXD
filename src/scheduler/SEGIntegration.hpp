// SEGIntegration.hpp
// Phase C.2 Batch 2/5 — SEG Scheduler Integration
// Bridges AdaptiveScheduler with Sovereign Execution Graph

#ifndef SEG_INTEGRATION_HPP
#define SEG_INTEGRATION_HPP

#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>
#include "AdaptiveScheduler.hpp"

// Forward declaration for SEG namespace
namespace SEG {
    class SovereignExecutionGraph;
    struct ExecutionNode;
    struct ExecutionEdge;
}

namespace Scheduler {

// ============================================================================
// SEG Task Mapping
// ============================================================================

struct SEGTaskMapping {
    uint64_t scheduler_task_id;
    uint64_t seg_node_id;
    std::vector<uint64_t> seg_edge_ids;
    
    // Execution tracking
    std::chrono::steady_clock::time_point seg_submit_time;
    std::chrono::steady_clock::time_point seg_start_time;
    std::chrono::steady_clock::time_point seg_end_time;
    
    // Results
    double seg_execution_time_ms;
    double seg_resource_usage;
    bool seg_success;
    
    SEGTaskMapping()
        : scheduler_task_id(0)
        , seg_node_id(0)
        , seg_execution_time_ms(0.0)
        , seg_resource_usage(0.0)
        , seg_success(false) {}
};

// ============================================================================
// SEG Path Recommendation
// ============================================================================

struct SEGPathRecommendation {
    std::vector<uint64_t> node_path;
    std::vector<uint64_t> edge_path;
    
    // Predicted metrics
    double predicted_execution_time_ms;
    double predicted_resource_usage;
    double predicted_success_rate;
    double path_confidence;
    
    // Utility score
    double utility_score;
    
    // Alternative paths
    std::vector<std::vector<uint64_t>> alternative_paths;
    
    SEGPathRecommendation()
        : predicted_execution_time_ms(0.0)
        , predicted_resource_usage(0.0)
        , predicted_success_rate(0.0)
        , path_confidence(0.0)
        , utility_score(0.0) {}
};

// ============================================================================
// SEG Learning State
// ============================================================================

struct SEGLearningState {
    // Edge weight learning
    std::map<std::pair<uint64_t, uint64_t>, double> edge_weights;
    std::map<std::pair<uint64_t, uint64_t>, uint32_t> edge_usage_count;
    std::map<std::pair<uint64_t, uint64_t>, double> edge_success_rate;
    
    // Node performance tracking
    std::map<uint64_t, double> node_average_execution_time;
    std::map<uint64_t, double> node_success_rate;
    std::map<uint64_t, uint32_t> node_execution_count;
    
    // Path performance
    std::map<std::string, double> path_average_time; // Key: "node1->node2->node3"
    std::map<std::string, double> path_success_rate;
    
    // Learning parameters
    double learning_rate = 0.1;
    double exploration_bonus = 0.1;
    double decay_factor = 0.99;
    
    void UpdateEdgeWeight(uint64_t from, uint64_t to, 
                         double observed_time, bool success);
    double GetEdgeWeight(uint64_t from, uint64_t to) const;
    double GetPathConfidence(const std::vector<uint64_t>& path) const;
};

// ============================================================================
// SEG Scheduler Bridge
// ============================================================================

class SEGSchedulerBridge {
public:
    SEGSchedulerBridge(SEG::SovereignExecutionGraph* graph,
                      const AdaptiveSchedulerConfig& config);
    ~SEGSchedulerBridge();
    
    // Initialization
    void Initialize();
    void Shutdown();
    
    // Task mapping
    SEGTaskMapping MapTaskToNode(const ScheduledTask& task);
    void UnmapTask(uint64_t scheduler_task_id);
    SEGTaskMapping GetMapping(uint64_t scheduler_task_id) const;
    
    // Path recommendations
    SEGPathRecommendation GetRecommendedPath(
        uint64_t start_node,
        uint64_t end_node,
        const TaskPriority& priority);
    
    std::vector<SEGPathRecommendation> GetAlternativePaths(
        uint64_t start_node,
        uint64_t end_node,
        uint32_t max_alternatives);
    
    // Execution feedback
    void ReportNodeExecution(uint64_t node_id,
                             double execution_time_ms,
                             double resource_usage,
                             bool success);
    
    void ReportPathExecution(const std::vector<uint64_t>& path,
                            double total_time_ms,
                            bool success);
    
    // Learning
    void UpdateEdgeWeightsFromExperience();
    void ApplyExplorationBonus(const std::vector<uint64_t>& explored_path);
    void DecayWeights();
    
    // Query
    double GetNodePredictedTime(uint64_t node_id) const;
    double GetNodeSuccessRate(uint64_t node_id) const;
    double GetPathPredictedTime(const std::vector<uint64_t>& path) const;
    
    // Batch operations
    std::map<uint64_t, double> GetAllNodePredictions() const;
    std::map<std::pair<uint64_t, uint64_t>, double> GetAllEdgeWeights() const;
    
    // State management
    void SaveLearningState(const std::string& path) const;
    void LoadLearningState(const std::string& path);
    void ResetLearningState();
    
    // Statistics
    SEGLearningState GetLearningState() const;
    uint64_t GetTotalMappings() const;
    uint64_t GetActiveMappings() const;
    
private:
    SEG::SovereignExecutionGraph* graph_;
    AdaptiveSchedulerConfig config_;
    
    // Task mappings
    std::map<uint64_t, SEGTaskMapping> task_mappings_;
    std::map<uint64_t, uint64_t> node_to_task_map_;
    mutable std::mutex mapping_mutex_;
    
    // Learning state
    SEGLearningState learning_state_;
    mutable std::mutex learning_mutex_;
    
    // Statistics
    std::atomic<uint64_t> total_mappings_{0};
    std::atomic<uint64_t> active_mappings_{0};
    
    // Internal methods
    double CalculatePathUtility(const std::vector<uint64_t>& path,
                               const TaskPriority& priority) const;
    std::string PathToKey(const std::vector<uint64_t>& path) const;
    void CleanupCompletedMappings();
};

// ============================================================================
// SEG Adaptive Router
// ============================================================================

class SEGAdaptiveRouter {
public:
    SEGAdaptiveRouter(SEGSchedulerBridge* bridge,
                     const AdaptiveSchedulerConfig& config);
    
    // Route selection
    std::vector<uint64_t> SelectRoute(
        const std::vector<std::vector<uint64_t>>& candidates,
        const TaskPriority& priority);
    
    // Dynamic routing
    std::vector<uint64_t> RerouteOnFailure(
        const std::vector<uint64_t>& failed_path,
        uint64_t failure_node);
    
    // Load balancing
    std::vector<uint64_t> SelectLeastLoadedPath(
        const std::vector<std::vector<uint64_t>>& candidates);
    
    // Exploration routing
    std::vector<uint64_t> SelectExplorationPath(
        uint64_t start_node,
        uint64_t end_node,
        double exploration_rate);
    
    // Real-time adaptation
    void ReportCongestion(uint64_t node_id, double congestion_level);
    void ReportFailure(uint64_t node_id, const std::string& failure_type);
    
private:
    SEGSchedulerBridge* bridge_;
    AdaptiveSchedulerConfig config_;
    
    // Congestion tracking
    std::map<uint64_t, double> node_congestion_;
    std::map<uint64_t, uint32_t> node_failures_;
    mutable std::mutex congestion_mutex_;
    
    // Scoring
    double ScoreRoute(const std::vector<uint64_t>& route,
                     const TaskPriority& priority) const;
};

// ============================================================================
// SEG Performance Monitor
// ============================================================================

class SEGPerformanceMonitor {
public:
    SEGPerformanceMonitor(SEGSchedulerBridge* bridge,
                         std::chrono::milliseconds window_size);
    
    void StartMonitoring();
    void StopMonitoring();
    
    // Data collection
    void RecordNodeMetrics(uint64_t node_id,
                          double execution_time,
                          double resource_usage);
    
    void RecordPathMetrics(const std::vector<uint64_t>& path,
                          double total_time,
                          double throughput);
    
    // Analysis
    double GetNodeAverageTime(uint64_t node_id) const;
    double GetNodeThroughput(uint64_t node_id) const;
    double GetPathAverageTime(const std::vector<uint64_t>& path) const;
    
    // Bottleneck detection
    std::vector<uint64_t> IdentifyBottlenecks(double threshold_percentile) const;
    std::vector<uint64_t> IdentifyUnderutilizedNodes(double threshold_percentile) const;
    
    // Trend analysis
    bool IsPerformanceDegrading(uint64_t node_id, double threshold) const;
    bool IsPerformanceImproving(uint64_t node_id, double threshold) const;
    
    // Reports
    std::string GeneratePerformanceReport() const;
    void ExportMetricsToCSV(const std::string& filename) const;
    
private:
    SEGSchedulerBridge* bridge_;
    std::chrono::milliseconds window_size_;
    
    // Metrics storage
    struct NodeMetrics {
        std::vector<double> execution_times;
        std::vector<double> resource_usage;
        std::chrono::steady_clock::time_point last_update;
    };
    
    std::map<uint64_t, NodeMetrics> node_metrics_;
    mutable std::mutex metrics_mutex_;
    
    // Monitoring thread
    std::atomic<bool> monitoring_active_{false};
    std::thread monitor_thread_;
    
    void MonitoringLoop();
    void CleanupOldMetrics();
};

// ============================================================================
// SEG Scheduler Integration Manager
// ============================================================================

class SEGSchedulerIntegrationManager {
public:
    SEGSchedulerIntegrationManager(
        SEG::SovereignExecutionGraph* graph,
        AdaptiveScheduler* scheduler,
        const AdaptiveSchedulerConfig& config);
    
    ~SEGSchedulerIntegrationManager();
    
    // Lifecycle
    void Initialize();
    void Start();
    void Stop();
    void Shutdown();
    
    // Task execution flow
    uint64_t SubmitTaskToSEG(const ScheduledTask& task);
    void CompleteTaskFromSEG(uint64_t task_id, 
                            double execution_time_ms,
                            bool success);
    
    // Synchronization
    void SyncSchedulerToSEG();
    void SyncSEGToScheduler();
    
    // Optimization
    void OptimizeGraphBasedOnHistory();
    void RebalanceLoad();
    void PruneUnusedPaths();
    
    // Query
    SEGSchedulerBridge* GetBridge() const { return bridge_.get(); }
    SEGAdaptiveRouter* GetRouter() const { return router_.get(); }
    SEGPerformanceMonitor* GetMonitor() const { return monitor_.get(); }
    
    // Statistics
    struct IntegrationStats {
        uint64_t tasks_submitted_to_seg;
        uint64_t tasks_completed_from_seg;
        uint64_t reroutes_triggered;
        uint64_t optimizations_applied;
        double average_scheduling_latency_ms;
        double average_execution_latency_ms;
    };
    
    IntegrationStats GetStatistics() const;
    
private:
    SEG::SovereignExecutionGraph* graph_;
    AdaptiveScheduler* scheduler_;
    AdaptiveSchedulerConfig config_;
    
    // Components
    std::unique_ptr<SEGSchedulerBridge> bridge_;
    std::unique_ptr<SEGAdaptiveRouter> router_;
    std::unique_ptr<SEGPerformanceMonitor> monitor_;
    
    // Statistics
    IntegrationStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Running state
    std::atomic<bool> running_{false};
};

} // namespace Scheduler

#endif // SEG_INTEGRATION_HPP
