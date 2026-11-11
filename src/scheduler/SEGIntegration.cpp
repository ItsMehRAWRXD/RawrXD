// SEGIntegration.cpp
// Phase C.2 Batch 2/5 — SEG Scheduler Integration Implementation

#include "SEGIntegration.hpp"
#include "../../seg/SovereignExecutionGraph.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace Scheduler {

// ============================================================================
// SEGLearningState Implementation
// ============================================================================

void SEGLearningState::UpdateEdgeWeight(uint64_t from, uint64_t to,
                                      double observed_time, bool success) {
    auto edge_key = std::make_pair(from, to);
    
    // Update usage count
    edge_usage_count[edge_key]++;
    
    // Update success rate with exponential moving average
    double current_success = edge_success_rate[edge_key];
    double alpha = 0.3; // Learning rate for success rate
    edge_success_rate[edge_key] = alpha * (success ? 1.0 : 0.0) + (1.0 - alpha) * current_success;
    
    // Update weight based on observed time and success
    double target_weight = success ? (1.0 / (1.0 + observed_time / 1000.0)) : 0.1;
    double current_weight = edge_weights[edge_key];
    edge_weights[edge_key] = learning_rate * target_weight + (1.0 - learning_rate) * current_weight;
    
    // Update node statistics
    node_execution_count[from]++;
    double node_alpha = 0.2;
    node_average_execution_time[from] = node_alpha * observed_time + 
                                         (1.0 - node_alpha) * node_average_execution_time[from];
    node_success_rate[from] = node_alpha * (success ? 1.0 : 0.0) + 
                               (1.0 - node_alpha) * node_success_rate[from];
}

double SEGLearningState::GetEdgeWeight(uint64_t from, uint64_t to) const {
    auto edge_key = std::make_pair(from, to);
    auto it = edge_weights.find(edge_key);
    
    if (it != edge_weights.end()) {
        return it->second;
    }
    
    // Return default weight for unknown edges
    return 0.5;
}

double SEGLearningState::GetPathConfidence(const std::vector<uint64_t>& path) const {
    if (path.size() < 2) {
        return 1.0;
    }
    
    double confidence = 1.0;
    
    for (size_t i = 0; i < path.size() - 1; ++i) {
        auto edge_key = std::make_pair(path[i], path[i + 1]);
        
        // Confidence based on success rate and usage count
        auto success_it = edge_success_rate.find(edge_key);
        auto usage_it = edge_usage_count.find(edge_key);
        
        if (success_it != edge_success_rate.end() && usage_it != edge_usage_count.end()) {
            double usage_confidence = std::min(1.0, usage_it->second / 10.0);
            confidence *= (success_it->second * 0.7 + usage_confidence * 0.3);
        } else {
            // Unknown edge reduces confidence
            confidence *= 0.5;
        }
    }
    
    return confidence;
}

// ============================================================================
// SEGSchedulerBridge Implementation
// ============================================================================

SEGSchedulerBridge::SEGSchedulerBridge(SEG::SovereignExecutionGraph* graph,
                                       const AdaptiveSchedulerConfig& config)
    : graph_(graph)
    , config_(config) {}

SEGSchedulerBridge::~SEGSchedulerBridge() {
    Shutdown();
}

void SEGSchedulerBridge::Initialize() {
    std::lock_guard<std::mutex> lock(mapping_mutex_);
    
    task_mappings_.clear();
    node_to_task_map_.clear();
    
    // Initialize learning state with default values
    learning_state_.learning_rate = config_.edge_weight_learning_rate;
    learning_state_.decay_factor = config_.edge_weight_decay;
}

void SEGSchedulerBridge::Shutdown() {
    std::lock_guard<std::mutex> lock(mapping_mutex_);
    
    task_mappings_.clear();
    node_to_task_map_.clear();
}

SEGTaskMapping SEGSchedulerBridge::MapTaskToNode(const ScheduledTask& task) {
    std::lock_guard<std::mutex> lock(mapping_mutex_);
    
    SEGTaskMapping mapping;
    mapping.scheduler_task_id = task.task_id;
    mapping.seg_submit_time = std::chrono::steady_clock::now();
    
    // Create or find appropriate SEG node
    // In a real implementation, this would interact with the SEG
    // For now, we simulate node assignment
    static uint64_t next_node_id = 1000;
    mapping.seg_node_id = next_node_id++;
    
    // Store mapping
    task_mappings_[task.task_id] = mapping;
    node_to_task_map_[mapping.seg_node_id] = task.task_id;
    
    total_mappings_++;
    active_mappings_++;
    
    return mapping;
}

void SEGSchedulerBridge::UnmapTask(uint64_t scheduler_task_id) {
    std::lock_guard<std::mutex> lock(mapping_mutex_);
    
    auto it = task_mappings_.find(scheduler_task_id);
    if (it != task_mappings_.end()) {
        node_to_task_map_.erase(it->second.seg_node_id);
        task_mappings_.erase(it);
        
        active_mappings_--;
    }
}

SEGTaskMapping SEGSchedulerBridge::GetMapping(uint64_t scheduler_task_id) const {
    std::lock_guard<std::mutex> lock(mapping_mutex_);
    
    auto it = task_mappings_.find(scheduler_task_id);
    if (it != task_mappings_.end()) {
        return it->second;
    }
    
    return SEGTaskMapping{};
}

SEGPathRecommendation SEGSchedulerBridge::GetRecommendedPath(
    uint64_t start_node,
    uint64_t end_node,
    const TaskPriority& priority) {
    
    std::lock_guard<std::mutex> lock(learning_mutex_);
    
    SEGPathRecommendation recommendation;
    
    // In a real implementation, this would query the SEG for paths
    // and use Dijkstra/A* with learned weights
    // For now, return a direct path
    recommendation.node_path = {start_node, end_node};
    recommendation.edge_path = {start_node}; // Simplified
    
    // Calculate predicted metrics based on learning state
    double predicted_time = learning_state_.GetEdgeWeight(start_node, end_node) * 1000.0;
    recommendation.predicted_execution_time_ms = predicted_time;
    recommendation.predicted_success_rate = learning_state_.GetPathConfidence(recommendation.node_path);
    recommendation.path_confidence = recommendation.predicted_success_rate;
    
    // Calculate utility
    recommendation.utility_score = CalculatePathUtility(recommendation.node_path, priority);
    
    return recommendation;
}

std::vector<SEGPathRecommendation> SEGSchedulerBridge::GetAlternativePaths(
    uint64_t start_node,
    uint64_t end_node,
    uint32_t max_alternatives) {
    
    std::vector<SEGPathRecommendation> alternatives;
    
    // In a real implementation, this would find multiple paths
    // For now, return variations of the direct path
    for (uint32_t i = 0; i < max_alternatives; ++i) {
        SEGPathRecommendation rec;
        rec.node_path = {start_node, end_node};
        rec.predicted_execution_time_ms = 100.0 * (1.0 + i * 0.1);
        rec.predicted_success_rate = 0.9 - i * 0.05;
        rec.path_confidence = rec.predicted_success_rate;
        rec.utility_score = rec.predicted_success_rate / rec.predicted_execution_time_ms;
        
        alternatives.push_back(rec);
    }
    
    return alternatives;
}

void SEGSchedulerBridge::ReportNodeExecution(uint64_t node_id,
                                             double execution_time_ms,
                                             double resource_usage,
                                             bool success) {
    std::lock_guard<std::mutex> lock(learning_mutex_);
    
    // Update learning state
    learning_state_.node_average_execution_time[node_id] = execution_time_ms;
    learning_state_.node_success_rate[node_id] = success ? 1.0 : 0.0;
    learning_state_.node_execution_count[node_id]++;
}

void SEGSchedulerBridge::ReportPathExecution(const std::vector<uint64_t>& path,
                                            double total_time_ms,
                                            bool success) {
    std::lock_guard<std::mutex> lock(learning_mutex_);
    
    // Update edge weights along the path
    for (size_t i = 0; i < path.size() - 1; ++i) {
        learning_state_.UpdateEdgeWeight(path[i], path[i + 1], 
                                        total_time_ms / (path.size() - 1), success);
    }
    
    // Update path statistics
    std::string path_key = PathToKey(path);
    learning_state_.path_average_time[path_key] = total_time_ms;
    learning_state_.path_success_rate[path_key] = success ? 1.0 : 0.0;
}

void SEGSchedulerBridge::UpdateEdgeWeightsFromExperience() {
    std::lock_guard<std::mutex> lock(learning_mutex_);
    
    // Apply learned weights to SEG graph
    // In a real implementation, this would update the actual SEG edges
    for (const auto& [edge, weight] : learning_state_.edge_weights) {
        // graph_->UpdateEdgeWeight(edge.first, edge.second, weight);
        (void)weight; // Suppress unused warning
    }
}

void SEGSchedulerBridge::ApplyExplorationBonus(const std::vector<uint64_t>& explored_path) {
    std::lock_guard<std::mutex> lock(learning_mutex_);
    
    // Boost weights for explored paths to encourage diversity
    for (size_t i = 0; i < explored_path.size() - 1; ++i) {
        auto edge_key = std::make_pair(explored_path[i], explored_path[i + 1]);
        learning_state_.edge_weights[edge_key] += learning_state_.exploration_bonus;
        learning_state_.edge_weights[edge_key] = std::min(1.0, learning_state_.edge_weights[edge_key]);
    }
}

void SEGSchedulerBridge::DecayWeights() {
    std::lock_guard<std::mutex> lock(learning_mutex_);
    
    for (auto& [edge, weight] : learning_state_.edge_weights) {
        weight *= learning_state_.decay_factor;
    }
}

double SEGSchedulerBridge::GetNodePredictedTime(uint64_t node_id) const {
    std::lock_guard<std::mutex> lock(learning_mutex_);
    
    auto it = learning_state_.node_average_execution_time.find(node_id);
    if (it != learning_state_.node_average_execution_time.end()) {
        return it->second;
    }
    
    return 100.0; // Default prediction
}

double SEGSchedulerBridge::GetNodeSuccessRate(uint64_t node_id) const {
    std::lock_guard<std::mutex> lock(learning_mutex_);
    
    auto it = learning_state_.node_success_rate.find(node_id);
    if (it != learning_state_.node_success_rate.end()) {
        return it->second;
    }
    
    return 0.5; // Default rate
}

double SEGSchedulerBridge::GetPathPredictedTime(const std::vector<uint64_t>& path) const {
    std::lock_guard<std::mutex> lock(learning_mutex_);
    
    double total_time = 0.0;
    
    for (size_t i = 0; i < path.size() - 1; ++i) {
        total_time += learning_state_.GetEdgeWeight(path[i], path[i + 1]) * 1000.0;
    }
    
    return total_time;
}

std::map<uint64_t, double> SEGSchedulerBridge::GetAllNodePredictions() const {
    std::lock_guard<std::mutex> lock(learning_mutex_);
    return learning_state_.node_average_execution_time;
}

std::map<std::pair<uint64_t, uint64_t>, double> SEGSchedulerBridge::GetAllEdgeWeights() const {
    std::lock_guard<std::mutex> lock(learning_mutex_);
    return learning_state_.edge_weights;
}

void SEGSchedulerBridge::SaveLearningState(const std::string& path) const {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return;
    }
    
    // Serialize learning state
    // In production, use proper serialization
    std::lock_guard<std::mutex> lock(learning_mutex_);
    
    size_t edge_count = learning_state_.edge_weights.size();
    file.write(reinterpret_cast<const char*>(&edge_count), sizeof(edge_count));
    
    for (const auto& [edge, weight] : learning_state_.edge_weights) {
        file.write(reinterpret_cast<const char*>(&edge.first), sizeof(edge.first));
        file.write(reinterpret_cast<const char*>(&edge.second), sizeof(edge.second));
        file.write(reinterpret_cast<const char*>(&weight), sizeof(weight));
    }
}

void SEGSchedulerBridge::LoadLearningState(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(learning_mutex_);
    learning_state_.edge_weights.clear();
    
    size_t edge_count;
    file.read(reinterpret_cast<char*>(&edge_count), sizeof(edge_count));
    
    for (size_t i = 0; i < edge_count; ++i) {
        uint64_t from, to;
        double weight;
        
        file.read(reinterpret_cast<char*>(&from), sizeof(from));
        file.read(reinterpret_cast<char*>(&to), sizeof(to));
        file.read(reinterpret_cast<char*>(&weight), sizeof(weight));
        
        learning_state_.edge_weights[std::make_pair(from, to)] = weight;
    }
}

void SEGSchedulerBridge::ResetLearningState() {
    std::lock_guard<std::mutex> lock(learning_mutex_);
    
    learning_state_.edge_weights.clear();
    learning_state_.edge_usage_count.clear();
    learning_state_.edge_success_rate.clear();
    learning_state_.node_average_execution_time.clear();
    learning_state_.node_success_rate.clear();
    learning_state_.node_execution_count.clear();
    learning_state_.path_average_time.clear();
    learning_state_.path_success_rate.clear();
}

SEGLearningState SEGSchedulerBridge::GetLearningState() const {
    std::lock_guard<std::mutex> lock(learning_mutex_);
    return learning_state_;
}

uint64_t SEGSchedulerBridge::GetTotalMappings() const {
    return total_mappings_.load();
}

uint64_t SEGSchedulerBridge::GetActiveMappings() const {
    return active_mappings_.load();
}

double SEGSchedulerBridge::CalculatePathUtility(const std::vector<uint64_t>& path,
                                                const TaskPriority& priority) const {
    double convergence = priority.confidence_factor;
    double throughput = 1.0 / (GetPathPredictedTime(path) + 1.0);
    double reliability = learning_state_.GetPathConfidence(path);
    double resource_cost = static_cast<double>(path.size());
    
    return (convergence * throughput * reliability) / resource_cost;
}

std::string SEGSchedulerBridge::PathToKey(const std::vector<uint64_t>& path) const {
    std::ostringstream oss;
    for (size_t i = 0; i < path.size(); ++i) {
        if (i > 0) oss << "->";
        oss << path[i];
    }
    return oss.str();
}

void SEGSchedulerBridge::CleanupCompletedMappings() {
    std::lock_guard<std::mutex> lock(mapping_mutex_);
    
    // Remove mappings for completed tasks
    for (auto it = task_mappings_.begin(); it != task_mappings_.end();) {
        // In a real implementation, check if task is completed
        // For now, keep all mappings
        ++it;
    }
}

// ============================================================================
// SEGAdaptiveRouter Implementation
// ============================================================================

SEGAdaptiveRouter::SEGAdaptiveRouter(SEGSchedulerBridge* bridge,
                                     const AdaptiveSchedulerConfig& config)
    : bridge_(bridge)
    , config_(config) {}

std::vector<uint64_t> SEGAdaptiveRouter::SelectRoute(
    const std::vector<std::vector<uint64_t>>& candidates,
    const TaskPriority& priority) {
    
    if (candidates.empty()) {
        return {};
    }
    
    // Score each candidate
    std::vector<std::pair<std::vector<uint64_t>, double>> scored_routes;
    
    for (const auto& route : candidates) {
        double score = ScoreRoute(route, priority);
        scored_routes.push_back({route, score});
    }
    
    // Sort by score (highest first)
    std::sort(scored_routes.begin(), scored_routes.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    return scored_routes[0].first;
}

std::vector<uint64_t> SEGAdaptiveRouter::RerouteOnFailure(
    const std::vector<uint64_t>& failed_path,
    uint64_t failure_node) {
    
    // Find alternative path avoiding the failure node
    // In a real implementation, this would query the SEG for alternatives
    std::vector<uint64_t> alternative = failed_path;
    
    // Remove the failure node and try to find a bypass
    auto it = std::find(alternative.begin(), alternative.end(), failure_node);
    if (it != alternative.end()) {
        alternative.erase(it);
    }
    
    return alternative;
}

std::vector<uint64_t> SEGAdaptiveRouter::SelectLeastLoadedPath(
    const std::vector<std::vector<uint64_t>>& candidates) {
    
    if (candidates.empty()) {
        return {};
    }
    
    std::lock_guard<std::mutex> lock(congestion_mutex_);
    
    // Score by congestion
    std::vector<std::pair<std::vector<uint64_t>, double>> scored_routes;
    
    for (const auto& route : candidates) {
        double total_congestion = 0.0;
        for (uint64_t node : route) {
            auto it = node_congestion_.find(node);
            if (it != node_congestion_.end()) {
                total_congestion += it->second;
            }
        }
        
        double score = 1.0 / (1.0 + total_congestion);
        scored_routes.push_back({route, score});
    }
    
    // Sort by score (highest first = least congested)
    std::sort(scored_routes.begin(), scored_routes.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    return scored_routes[0].first;
}

std::vector<uint64_t> SEGAdaptiveRouter::SelectExplorationPath(
    uint64_t start_node,
    uint64_t end_node,
    double exploration_rate) {
    
    // With probability exploration_rate, choose a random path
    // Otherwise, choose the best known path
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    
    if (dis(gen) < exploration_rate) {
        // Exploration: return a random variation
        return {start_node, end_node}; // Simplified
    } else {
        // Exploitation: return best known path
        return {start_node, end_node}; // Simplified
    }
}

void SEGAdaptiveRouter::ReportCongestion(uint64_t node_id, double congestion_level) {
    std::lock_guard<std::mutex> lock(congestion_mutex_);
    node_congestion_[node_id] = congestion_level;
}

void SEGAdaptiveRouter::ReportFailure(uint64_t node_id, const std::string& failure_type) {
    std::lock_guard<std::mutex> lock(congestion_mutex_);
    node_failures_[node_id]++;
    
    // Increase congestion to avoid this node
    node_congestion_[node_id] += 0.5;
    
    (void)failure_type; // Could log failure type for analysis
}

double SEGAdaptiveRouter::ScoreRoute(const std::vector<uint64_t>& route,
                                     const TaskPriority& priority) const {
    double score = 0.0;
    
    // Predicted execution time
    double predicted_time = bridge_->GetPathPredictedTime(route);
    score += (1.0 / (1.0 + predicted_time / 1000.0)) * 0.3;
    
    // Path confidence
    double confidence = bridge_->GetLearningState().GetPathConfidence(route);
    score += confidence * 0.3;
    
    // Priority alignment
    score += priority.total_priority * 0.2;
    
    // Congestion
    std::lock_guard<std::mutex> lock(congestion_mutex_);
    double total_congestion = 0.0;
    for (uint64_t node : route) {
        auto it = node_congestion_.find(node);
        if (it != node_congestion_.end()) {
            total_congestion += it->second;
        }
    }
    score += (1.0 / (1.0 + total_congestion)) * 0.2;
    
    return score;
}

// ============================================================================
// SEGPerformanceMonitor Implementation
// ============================================================================

SEGPerformanceMonitor::SEGPerformanceMonitor(SEGSchedulerBridge* bridge,
                                             std::chrono::milliseconds window_size)
    : bridge_(bridge)
    , window_size_(window_size) {}

void SEGPerformanceMonitor::StartMonitoring() {
    monitoring_active_ = true;
    monitor_thread_ = std::thread(&SEGPerformanceMonitor::MonitoringLoop, this);
}

void SEGPerformanceMonitor::StopMonitoring() {
    monitoring_active_ = false;
    
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

void SEGPerformanceMonitor::RecordNodeMetrics(uint64_t node_id,
                                              double execution_time,
                                              double resource_usage) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    NodeMetrics& metrics = node_metrics_[node_id];
    metrics.execution_times.push_back(execution_time);
    metrics.resource_usage.push_back(resource_usage);
    metrics.last_update = std::chrono::steady_clock::now();
    
    // Keep only recent metrics
    while (metrics.execution_times.size() > 100) {
        metrics.execution_times.erase(metrics.execution_times.begin());
    }
    while (metrics.resource_usage.size() > 100) {
        metrics.resource_usage.erase(metrics.resource_usage.begin());
    }
}

void SEGPerformanceMonitor::RecordPathMetrics(const std::vector<uint64_t>& path,
                                               double total_time,
                                               double throughput) {
    // In a real implementation, store path-level metrics
    (void)path;
    (void)total_time;
    (void)throughput;
}

double SEGPerformanceMonitor::GetNodeAverageTime(uint64_t node_id) const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    auto it = node_metrics_.find(node_id);
    if (it == node_metrics_.end() || it->second.execution_times.empty()) {
        return 0.0;
    }
    
    const auto& times = it->second.execution_times;
    double sum = std::accumulate(times.begin(), times.end(), 0.0);
    return sum / times.size();
}

double SEGPerformanceMonitor::GetNodeThroughput(uint64_t node_id) const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    auto it = node_metrics_.find(node_id);
    if (it == node_metrics_.end() || it->second.execution_times.empty()) {
        return 0.0;
    }
    
    // Throughput = 1 / average execution time
    double avg_time = GetNodeAverageTime(node_id);
    return avg_time > 0.0 ? 1000.0 / avg_time : 0.0;
}

double SEGPerformanceMonitor::GetPathAverageTime(const std::vector<uint64_t>& path) const {
    return bridge_->GetPathPredictedTime(path);
}

std::vector<uint64_t> SEGPerformanceMonitor::IdentifyBottlenecks(double threshold_percentile) const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    // Collect average times
    std::vector<std::pair<uint64_t, double>> node_times;
    for (const auto& [node_id, metrics] : node_metrics_) {
        if (!metrics.execution_times.empty()) {
            double avg = std::accumulate(metrics.execution_times.begin(), 
                                        metrics.execution_times.end(), 0.0) 
                        / metrics.execution_times.size();
            node_times.push_back({node_id, avg});
        }
    }
    
    if (node_times.empty()) {
        return {};
    }
    
    // Sort by time (descending)
    std::sort(node_times.begin(), node_times.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Return top percentile
    size_t count = static_cast<size_t>(node_times.size() * threshold_percentile / 100.0);
    count = std::max(size_t(1), count);
    
    std::vector<uint64_t> bottlenecks;
    for (size_t i = 0; i < count && i < node_times.size(); ++i) {
        bottlenecks.push_back(node_times[i].first);
    }
    
    return bottlenecks;
}

std::vector<uint64_t> SEGPerformanceMonitor::IdentifyUnderutilizedNodes(double threshold_percentile) const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    // Collect throughputs
    std::vector<std::pair<uint64_t, double>> node_throughputs;
    for (const auto& [node_id, metrics] : node_metrics_) {
        if (!metrics.execution_times.empty()) {
            double avg_time = std::accumulate(metrics.execution_times.begin(), 
                                             metrics.execution_times.end(), 0.0) 
                            / metrics.execution_times.size();
            double throughput = avg_time > 0.0 ? 1000.0 / avg_time : 0.0;
            node_throughputs.push_back({node_id, throughput});
        }
    }
    
    if (node_throughputs.empty()) {
        return {};
    }
    
    // Sort by throughput (ascending)
    std::sort(node_throughputs.begin(), node_throughputs.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    
    // Return bottom percentile
    size_t count = static_cast<size_t>(node_throughputs.size() * threshold_percentile / 100.0);
    count = std::max(size_t(1), count);
    
    std::vector<uint64_t> underutilized;
    for (size_t i = 0; i < count && i < node_throughputs.size(); ++i) {
        underutilized.push_back(node_throughputs[i].first);
    }
    
    return underutilized;
}

bool SEGPerformanceMonitor::IsPerformanceDegrading(uint64_t node_id, double threshold) const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    auto it = node_metrics_.find(node_id);
    if (it == node_metrics_.end() || it->second.execution_times.size() < 10) {
        return false;
    }
    
    const auto& times = it->second.execution_times;
    
    // Compare recent vs older times
    double recent_avg = std::accumulate(times.end() - 5, times.end(), 0.0) / 5.0;
    double older_avg = std::accumulate(times.begin(), times.begin() + 5, 0.0) / 5.0;
    
    return recent_avg > older_avg * (1.0 + threshold);
}

bool SEGPerformanceMonitor::IsPerformanceImproving(uint64_t node_id, double threshold) const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    auto it = node_metrics_.find(node_id);
    if (it == node_metrics_.end() || it->second.execution_times.size() < 10) {
        return false;
    }
    
    const auto& times = it->second.execution_times;
    
    // Compare recent vs older times
    double recent_avg = std::accumulate(times.end() - 5, times.end(), 0.0) / 5.0;
    double older_avg = std::accumulate(times.begin(), times.begin() + 5, 0.0) / 5.0;
    
    return recent_avg < older_avg * (1.0 - threshold);
}

std::string SEGPerformanceMonitor::GeneratePerformanceReport() const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    std::ostringstream oss;
    oss << "SEG Performance Report\n";
    oss << "======================\n\n";
    
    for (const auto& [node_id, metrics] : node_metrics_) {
        if (metrics.execution_times.empty()) continue;
        
        double avg_time = std::accumulate(metrics.execution_times.begin(), 
                                         metrics.execution_times.end(), 0.0) 
                         / metrics.execution_times.size();
        double throughput = avg_time > 0.0 ? 1000.0 / avg_time : 0.0;
        
        oss << "Node " << node_id << ":\n";
        oss << "  Average execution time: " << std::fixed << std::setprecision(2) 
            << avg_time << " ms\n";
        oss << "  Throughput: " << throughput << " tasks/sec\n";
        oss << "  Samples: " << metrics.execution_times.size() << "\n\n";
    }
    
    return oss.str();
}

void SEGPerformanceMonitor::ExportMetricsToCSV(const std::string& filename) const {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    std::ofstream file(filename);
    if (!file.is_open()) {
        return;
    }
    
    // Header
    file << "node_id,execution_time_ms,resource_usage,timestamp\n";
    
    // Data
    for (const auto& [node_id, metrics] : node_metrics_) {
        for (size_t i = 0; i < metrics.execution_times.size(); ++i) {
            file << node_id << ","
                 << metrics.execution_times[i] << ","
                 << (i < metrics.resource_usage.size() ? metrics.resource_usage[i] : 0.0) << ","
                 << "0\n"; // Simplified timestamp
        }
    }
}

void SEGPerformanceMonitor::MonitoringLoop() {
    while (monitoring_active_) {
        std::this_thread::sleep_for(window_size_);
        
        if (!monitoring_active_) {
            break;
        }
        
        CleanupOldMetrics();
    }
}

void SEGPerformanceMonitor::CleanupOldMetrics() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    auto cutoff = std::chrono::steady_clock::now() - window_size_;
    
    for (auto it = node_metrics_.begin(); it != node_metrics_.end();) {
        if (it->second.last_update < cutoff) {
            it = node_metrics_.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================================
// SEGSchedulerIntegrationManager Implementation
// ============================================================================

SEGSchedulerIntegrationManager::SEGSchedulerIntegrationManager(
    SEG::SovereignExecutionGraph* graph,
    AdaptiveScheduler* scheduler,
    const AdaptiveSchedulerConfig& config)
    : graph_(graph)
    , scheduler_(scheduler)
    , config_(config)
    , stats_{} {}

SEGSchedulerIntegrationManager::~SEGSchedulerIntegrationManager() {
    Shutdown();
}

void SEGSchedulerIntegrationManager::Initialize() {
    // Create components
    bridge_ = std::make_unique<SEGSchedulerBridge>(graph_, config_);
    router_ = std::make_unique<SEGAdaptiveRouter>(bridge_.get(), config_);
    monitor_ = std::make_unique<SEGPerformanceMonitor>(bridge_.get(), 
                                                      std::chrono::seconds(60));
    
    // Initialize components
    bridge_->Initialize();
}

void SEGSchedulerIntegrationManager::Start() {
    if (monitor_) {
        monitor_->StartMonitoring();
    }
    
    running_ = true;
}

void SEGSchedulerIntegrationManager::Stop() {
    running_ = false;
    
    if (monitor_) {
        monitor_->StopMonitoring();
    }
}

void SEGSchedulerIntegrationManager::Shutdown() {
    Stop();
    
    if (bridge_) {
        bridge_->Shutdown();
    }
}

uint64_t SEGSchedulerIntegrationManager::SubmitTaskToSEG(const ScheduledTask& task) {
    if (!bridge_) {
        return 0;
    }
    
    // Map task to SEG node
    SEGTaskMapping mapping = bridge_->MapTaskToNode(task);
    
    // Get recommended path
    SEGPathRecommendation path = bridge_->GetRecommendedPath(
        mapping.seg_node_id, mapping.seg_node_id + 1000, task.priority);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.tasks_submitted_to_seg++;
    }
    
    return mapping.scheduler_task_id;
}

void SEGSchedulerIntegrationManager::CompleteTaskFromSEG(uint64_t task_id,
                                                         double execution_time_ms,
                                                         bool success) {
    if (!bridge_) {
        return;
    }
    
    // Get mapping
    SEGTaskMapping mapping = bridge_->GetMapping(task_id);
    
    // Report to bridge
    bridge_->ReportNodeExecution(mapping.seg_node_id, execution_time_ms, 
                                0.0, success);
    
    // Unmap task
    bridge_->UnmapTask(task_id);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.tasks_completed_from_seg++;
    }
}

void SEGSchedulerIntegrationManager::SyncSchedulerToSEG() {
    // Sync task states from scheduler to SEG
    if (!scheduler_ || !bridge_) {
        return;
    }
    
    // Get pending tasks from scheduler
    std::vector<ScheduledTask> pending = scheduler_->GetPendingTasks();
    
    // Map any unmapped tasks
    for (const auto& task : pending) {
        SEGTaskMapping mapping = bridge_->GetMapping(task.task_id);
        if (mapping.scheduler_task_id == 0) {
            bridge_->MapTaskToNode(task);
        }
    }
}

void SEGSchedulerIntegrationManager::SyncSEGToScheduler() {
    // Sync execution results from SEG to scheduler
    // In a real implementation, this would poll the SEG for completed tasks
}

void SEGSchedulerIntegrationManager::OptimizeGraphBasedOnHistory() {
    if (!bridge_) {
        return;
    }
    
    // Update edge weights from learning
    bridge_->UpdateEdgeWeightsFromExperience();
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.optimizations_applied++;
    }
}

void SEGSchedulerIntegrationManager::RebalanceLoad() {
    if (!monitor_ || !router_) {
        return;
    }
    
    // Identify bottlenecks
    std::vector<uint64_t> bottlenecks = monitor_->IdentifyBottlenecks(20.0);
    
    // Identify underutilized nodes
    std::vector<uint64_t> underutilized = monitor_->IdentifyUnderutilizedNodes(20.0);
    
    // In a real implementation, this would trigger load rebalancing
    // by adjusting routing weights or migrating tasks
}

void SEGSchedulerIntegrationManager::PruneUnusedPaths() {
    // Decay weights to prune unused paths
    if (bridge_) {
        bridge_->DecayWeights();
    }
}

SEGSchedulerIntegrationManager::IntegrationStats 
SEGSchedulerIntegrationManager::GetStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

} // namespace Scheduler
