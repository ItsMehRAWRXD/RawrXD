// policy.cpp
// Layer 3: Statistical Policy Learner Implementation

#include "policy.h"
#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <numeric>

namespace rawrxd::policy {

// ═══════════════════════════════════════════════════════════════════════════════
// Internal Implementation
// ═══════════════════════════════════════════════════════════════════════════════

struct ArchitectureStats {
    std::vector<Trace> traces;
    std::map<std::string, uint32_t> backend_usage;  // backend -> count
    double total_latency_ms = 0.0;
    uint32_t success_count = 0;
    uint32_t failure_count = 0;
};

class PolicyLearnerImpl {
public:
    std::map<std::string, ArchitectureStats> arch_stats_;
    std::vector<Trace> all_traces_;
    mutable std::mutex mutex_;
    
    // Configuration
    uint32_t min_traces_for_recommendation_ = 10;
    float confidence_threshold_ = 0.8f;
    std::chrono::seconds max_snapshot_age_{3600};  // 1 hour
    
    // Versioning
    std::atomic<PolicyVersion> current_version_{1};
    std::atomic<uint64_t> total_traces_{0};
};

// ═══════════════════════════════════════════════════════════════════════════════
// StatisticalPolicyLearner Implementation
// ═══════════════════════════════════════════════════════════════════════════════

StatisticalPolicyLearner::StatisticalPolicyLearner() 
    : impl_(std::make_unique<PolicyLearnerImpl>()) {
}

StatisticalPolicyLearner::~StatisticalPolicyLearner() = default;

void StatisticalPolicyLearner::Observe(const Trace& trace) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    // Store trace
    impl_->all_traces_.push_back(trace);
    impl_->total_traces_++;
    
    // Update architecture stats
    auto& stats = impl_->arch_stats_[trace.model_architecture];
    stats.traces.push_back(trace);
    stats.backend_usage[trace.backend_used]++;
    stats.total_latency_ms += trace.latency.count() / 1000.0;
    
    if (trace.success) {
        stats.success_count++;
    } else {
        stats.failure_count++;
    }
    
    // Increment version periodically
    if (impl_->total_traces_ % 100 == 0) {
        impl_->current_version_++;
    }
}

void StatisticalPolicyLearner::ObserveBatch(const std::vector<Trace>& traces) {
    for (const auto& trace : traces) {
        Observe(trace);
    }
}

std::optional<Recommendation> StatisticalPolicyLearner::Recommend(
    const std::string& architecture) const {
    
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->arch_stats_.find(architecture);
    if (it == impl_->arch_stats_.end()) {
        return std::nullopt;
    }
    
    const auto& stats = it->second;
    
    // Check minimum traces
    if (stats.traces.size() < impl_->min_traces_for_recommendation_) {
        return std::nullopt;
    }
    
    // Find best backend
    std::string best_backend;
    uint32_t best_count = 0;
    double best_latency = std::numeric_limits<double>::max();
    
    for (const auto& [backend, count] : stats.backend_usage) {
        // Compute average latency for this backend
        double backend_latency = 0.0;
        uint32_t backend_samples = 0;
        
        for (const auto& trace : stats.traces) {
            if (trace.backend_used == backend) {
                backend_latency += trace.latency.count() / 1000.0;
                backend_samples++;
            }
        }
        
        if (backend_samples > 0) {
            backend_latency /= backend_samples;
        }
        
        // Score: prefer lower latency, but also consider usage
        if (backend_latency < best_latency || 
            (backend_latency == best_latency && count > best_count)) {
            best_backend = backend;
            best_count = count;
            best_latency = backend_latency;
        }
    }
    
    if (best_backend.empty()) {
        return std::nullopt;
    }
    
    // Build recommendation
    Recommendation rec;
    rec.target_architecture = architecture;
    rec.recommended_backend = best_backend;
    rec.confidence = std::min(1.0f, static_cast<float>(stats.traces.size()) / 
                              (impl_->min_traces_for_recommendation_ * 2));
    rec.rationale = "Lowest average latency (" + std::to_string(static_cast<int>(best_latency)) + 
                    "ms) across " + std::to_string(stats.traces.size()) + " traces";
    rec.supporting_traces = static_cast<uint32_t>(stats.traces.size());
    rec.observed_latency_ms = best_latency;
    rec.observed_success_rate = stats.traces.empty() ? 0.0 : 
        static_cast<double>(stats.success_count) / stats.traces.size();
    
    return rec;
}

DriftBand StatisticalPolicyLearner::ComputeEquivalence(const std::string& metric,
                                                        float threshold) const {
    DriftBand band;
    band.metric = metric;
    band.threshold = threshold;
    return band;
}

PolicySnapshot StatisticalPolicyLearner::ProduceSnapshot() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    PolicySnapshot snapshot;
    snapshot.version = impl_->current_version_.load();
    snapshot.created_at = std::chrono::steady_clock::now();
    snapshot.total_traces_analyzed = static_cast<uint32_t>(impl_->all_traces_.size());
    
    // Compute recommendations for all architectures
    for (const auto& [arch, stats] : impl_->arch_stats_) {
        if (stats.traces.size() >= impl_->min_traces_for_recommendation_) {
            // Find best backend
            std::string best_backend;
            double best_latency = std::numeric_limits<double>::max();
            
            for (const auto& [backend, count] : stats.backend_usage) {
                double backend_latency = 0.0;
                uint32_t samples = 0;
                
                for (const auto& trace : stats.traces) {
                    if (trace.backend_used == backend) {
                        backend_latency += trace.latency.count() / 1000.0;
                        samples++;
                    }
                }
                
                if (samples > 0) {
                    backend_latency /= samples;
                }
                
                if (backend_latency < best_latency) {
                    best_backend = backend;
                    best_latency = backend_latency;
                }
            }
            
            if (!best_backend.empty()) {
                Recommendation rec;
                rec.target_architecture = arch;
                rec.recommended_backend = best_backend;
                rec.confidence = 0.8f;
                rec.rationale = "Statistical best based on " + 
                               std::to_string(stats.traces.size()) + " traces";
                rec.supporting_traces = static_cast<uint32_t>(stats.traces.size());
                rec.observed_latency_ms = best_latency;
                rec.observed_success_rate = stats.traces.empty() ? 0.0 :
                    static_cast<double>(stats.success_count) / stats.traces.size();
                
                snapshot.routing_recommendations[arch] = rec;
            }
        }
    }
    
    // Compute drift bands
    snapshot.drift_bands["latency"] = ComputeEquivalence("latency", 50.0f);  // 50ms
    snapshot.drift_bands["quality"] = ComputeEquivalence("quality", 0.1f);     // 0.1 score
    snapshot.drift_bands["cost"] = ComputeEquivalence("cost", 0.001f);       // $0.001
    
    // Compute overall statistics
    if (!impl_->all_traces_.empty()) {
        double total_latency = 0.0;
        uint32_t success_count = 0;
        std::vector<double> latencies;
        
        for (const auto& trace : impl_->all_traces_) {
            double lat_ms = trace.latency.count() / 1000.0;
            total_latency += lat_ms;
            latencies.push_back(lat_ms);
            if (trace.success) success_count++;
        }
        
        snapshot.avg_latency_ms = total_latency / impl_->all_traces_.size();
        snapshot.overall_success_rate = static_cast<double>(success_count) / 
                                        impl_->all_traces_.size();
        
        // P99 latency
        std::sort(latencies.begin(), latencies.end());
        size_t p99_idx = latencies.size() * 99 / 100;
        snapshot.p99_latency_ms = latencies[p99_idx];
    }
    
    return snapshot;
}

std::vector<TraceId> StatisticalPolicyLearner::DetectAnomalies() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::vector<TraceId> anomalies;
    
    // Simple anomaly detection: latency > 5x average
    for (const auto& [arch, stats] : impl_->arch_stats_) {
        if (stats.traces.size() < 10) continue;
        
        double avg_latency = stats.total_latency_ms / stats.traces.size();
        
        for (const auto& trace : stats.traces) {
            double lat_ms = trace.latency.count() / 1000.0;
            if (lat_ms > avg_latency * 5.0) {
                anomalies.push_back(trace.id);
            }
        }
    }
    
    return anomalies;
}

std::vector<TraceId> StatisticalPolicyLearner::FindSimilar(const Trace& pattern,
                                                            float similarity_threshold) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::vector<TraceId> similar;
    
    for (const auto& trace : impl_->all_traces_) {
        if (trace.id == pattern.id) continue;
        
        // Simple similarity: same architecture, similar token count
        if (trace.model_architecture == pattern.model_architecture) {
            float token_ratio = static_cast<float>(trace.input_tokens) / 
                               std::max(1u, pattern.input_tokens);
            if (token_ratio >= similarity_threshold && token_ratio <= 1.0f/similarity_threshold) {
                similar.push_back(trace.id);
            }
        }
    }
    
    return similar;
}

StatisticalPolicyLearner::Trend StatisticalPolicyLearner::ComputeTrend(
    const std::string& metric, std::chrono::hours window) const {
    
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto cutoff = std::chrono::steady_clock::now() - window;
    
    // Split traces into recent and older
    std::vector<double> recent_values;
    std::vector<double> older_values;
    
    for (const auto& trace : impl_->all_traces_) {
        double value = 0.0;
        if (metric == "latency") {
            value = trace.latency.count() / 1000.0;
        } else if (metric == "quality") {
            value = trace.quality_score;
        } else if (metric == "success_rate") {
            value = trace.success ? 1.0 : 0.0;
        }
        
        if (trace.timestamp > cutoff) {
            recent_values.push_back(value);
        } else if (trace.timestamp > cutoff - window) {
            older_values.push_back(value);
        }
    }
    
    if (recent_values.size() < 10 || older_values.size() < 10) {
        return Trend::InsufficientData;
    }
    
    double recent_avg = std::accumulate(recent_values.begin(), recent_values.end(), 0.0) / 
                       recent_values.size();
    double older_avg = std::accumulate(older_values.begin(), older_values.end(), 0.0) / 
                      older_values.size();
    
    // For latency, lower is better
    if (metric == "latency") {
        if (recent_avg < older_avg * 0.9) return Trend::Improving;
        if (recent_avg > older_avg * 1.1) return Trend::Degrading;
    } else {
        // For quality/success, higher is better
        if (recent_avg > older_avg * 1.1) return Trend::Improving;
        if (recent_avg < older_avg * 0.9) return Trend::Degrading;
    }
    
    return Trend::Stable;
}

StatisticalPolicyLearner::Statistics StatisticalPolicyLearner::GetStatistics() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    Statistics stats;
    stats.total_traces_observed = impl_->total_traces_.load();
    stats.unique_architectures = static_cast<uint64_t>(impl_->arch_stats_.size());
    
    std::set<std::string> backends;
    for (const auto& [arch, arch_stats] : impl_->arch_stats_) {
        for (const auto& [backend, count] : arch_stats.backend_usage) {
            backends.insert(backend);
        }
    }
    stats.unique_backends = static_cast<uint64_t>(backends.size());
    
    // Compute traces per hour
    if (!impl_->all_traces_.empty()) {
        auto first = impl_->all_traces_.front().timestamp;
        auto last = impl_->all_traces_.back().timestamp;
        auto duration = std::chrono::duration_cast<std::chrono::hours>(last - first).count();
        if (duration > 0) {
            stats.avg_traces_per_hour = static_cast<double>(impl_->all_traces_.size()) / duration;
        }
    }
    
    stats.current_version = impl_->current_version_.load();
    
    return stats;
}

void StatisticalPolicyLearner::ResetStatistics() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    impl_->all_traces_.clear();
    impl_->arch_stats_.clear();
    impl_->total_traces_ = 0;
    impl_->current_version_ = 1;
}

void StatisticalPolicyLearner::SetMinTracesForRecommendation(uint32_t min_traces) {
    impl_->min_traces_for_recommendation_ = min_traces;
}

void StatisticalPolicyLearner::SetConfidenceThreshold(float threshold) {
    impl_->confidence_threshold_ = std::clamp(threshold, 0.0f, 1.0f);
}

void StatisticalPolicyLearner::SetMaxSnapshotAge(std::chrono::seconds age) {
    impl_->max_snapshot_age_ = age;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Global Instance
// ═══════════════════════════════════════════════════════════════════════════════

static std::unique_ptr<StatisticalPolicyLearner> g_policy_learner;
static std::once_flag g_init_flag;

StatisticalPolicyLearner& GetPolicyLearner() {
    std::call_once(g_init_flag, []() {
        g_policy_learner = std::make_unique<StatisticalPolicyLearner>();
    });
    return *g_policy_learner;
}

bool InitializePolicyLearner(const std::string& config_path) {
    GetPolicyLearner();
    return true;
}

void ShutdownPolicyLearner() {
    g_policy_learner.reset();
}

} // namespace rawrxd::policy
