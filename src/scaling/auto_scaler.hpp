// RawrXD Auto-Scaler
// Phase AR: Auto-Scaling & Load Balancing

#pragma once

#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>
#include <atomic>

namespace rawrxd {
namespace scaling {

// Scaling direction
enum class ScalingDirection {
    SCALE_UP,
    SCALE_DOWN,
    HOLD
};

// Scaling metrics
struct ScalingMetrics {
    double cpu_utilization;
    double memory_utilization;
    double gpu_utilization;
    size_t request_queue_depth;
    double request_latency_p99;
    double throughput_rps;
    size_t active_connections;
    
    ScalingMetrics()
        : cpu_utilization(0.0)
        , memory_utilization(0.0)
        , gpu_utilization(0.0)
        , request_queue_depth(0)
        , request_latency_p99(0.0)
        , throughput_rps(0.0)
        , active_connections(0) {}
};

// Scaling decision
struct ScalingDecision {
    ScalingDirection direction;
    int instance_delta;
    std::string reason;
    double confidence;
    std::chrono::system_clock::time_point timestamp;
    
    ScalingDecision()
        : direction(ScalingDirection::HOLD)
        , instance_delta(0)
        , confidence(0.0) {
        timestamp = std::chrono::system_clock::now();
    }
};

// Auto-scaler configuration
struct AutoScalerConfig {
    double cpu_scale_up_threshold;
    double cpu_scale_down_threshold;
    double memory_scale_up_threshold;
    double memory_scale_down_threshold;
    size_t queue_scale_up_threshold;
    size_t queue_scale_down_threshold;
    double latency_scale_up_threshold_ms;
    
    int min_instances;
    int max_instances;
    int scale_up_step;
    int scale_down_step;
    
    std::chrono::seconds cooldown_period;
    std::chrono::seconds evaluation_interval;
    
    bool predictive_scaling;
    double prediction_window_minutes;
    
    AutoScalerConfig()
        : cpu_scale_up_threshold(70.0)
        , cpu_scale_down_threshold(30.0)
        , memory_scale_up_threshold(80.0)
        , memory_scale_down_threshold(40.0)
        , queue_scale_up_threshold(100)
        , queue_scale_down_threshold(10)
        , latency_scale_up_threshold_ms(1000.0)
        , min_instances(1)
        , max_instances(10)
        , scale_up_step(1)
        , scale_down_step(1)
        , cooldown_period(std::chrono::seconds(300))
        , evaluation_interval(std::chrono::seconds(60))
        , predictive_scaling(false)
        , prediction_window_minutes(5.0) {}
};

// Scaling event
struct ScalingEvent {
    std::string id;
    ScalingDirection direction;
    int previous_count;
    int new_count;
    std::string trigger;
    double metric_value;
    std::chrono::system_clock::time_point timestamp;
    
    ScalingEvent()
        : direction(ScalingDirection::HOLD)
        , previous_count(0)
        , new_count(0)
        , metric_value(0.0) {
        timestamp = std::chrono::system_clock::now();
    }
};

// Forward declarations
class AutoScaler;
class MetricsCollector;
class ScalingPolicy;

// Scaling action callback
using ScalingActionCallback = std::function<bool(int target_instances)>;
using MetricsProvider = std::function<ScalingMetrics()>;

/**
 * AutoScaler - Intelligent auto-scaling controller
 */
class AutoScaler {
public:
    AutoScaler();
    ~AutoScaler();
    
    // Initialize
    bool initialize(const AutoScalerConfig& config);
    void shutdown();
    
    // Configuration
    void updateConfig(const AutoScalerConfig& config);
    AutoScalerConfig getConfig() const;
    
    // Metrics
    void setMetricsProvider(MetricsProvider provider);
    ScalingMetrics getCurrentMetrics() const;
    
    // Scaling control
    void start();
    void stop();
    bool isRunning() const;
    
    // Manual scaling
    bool scaleTo(int instance_count);
    bool scaleUp(int delta = 1);
    bool scaleDown(int delta = 1);
    
    // Status
    int getCurrentInstanceCount() const;
    int getTargetInstanceCount() const;
    ScalingDecision getLastDecision() const;
    
    // Event handling
    void setScalingActionCallback(ScalingActionCallback callback);
    std::vector<ScalingEvent> getScalingHistory(size_t count = 100) const;
    
    // Statistics
    size_t getTotalScalingEvents() const;
    size_t getSuccessfulScalingEvents() const;
    size_t getFailedScalingEvents() const;
    
private:
    AutoScalerConfig config_;
    std::atomic<int> current_instances_;
    std::atomic<int> target_instances_;
    std::atomic<bool> running_;
    bool initialized_;
    
    MetricsProvider metrics_provider_;
    ScalingActionCallback scaling_callback_;
    
    ScalingDecision last_decision_;
    std::chrono::system_clock::time_point last_scaling_time_;
    std::vector<ScalingEvent> scaling_history_;
    
    mutable std::mutex mutex_;
    std::thread evaluation_thread_;
    
    size_t total_events_;
    size_t successful_events_;
    size_t failed_events_;
    
    // Internal methods
    void evaluationLoop();
    ScalingDecision evaluateScaling(const ScalingMetrics& metrics);
    bool canScale() const;
    bool executeScaling(int target_count);
    void recordEvent(const ScalingEvent& event);
    void addHistory(const ScalingEvent& event);
};

/**
 * MetricsCollector - System metrics collection
 */
class MetricsCollector {
public:
    MetricsCollector();
    ~MetricsCollector();
    
    bool initialize();
    void shutdown();
    
    // Collection
    ScalingMetrics collect();
    void startCollection(std::chrono::seconds interval);
    void stopCollection();
    
    // Historical data
    std::vector<ScalingMetrics> getHistory(std::chrono::minutes duration) const;
    ScalingMetrics getAverage(std::chrono::minutes window) const;
    ScalingMetrics getPercentile(double p, std::chrono::minutes window) const;
    
    // Custom metrics
    void recordRequestLatency(double latency_ms);
    void recordQueueDepth(size_t depth);
    void recordThroughput(double rps);
    
private:
    std::vector<std::pair<std::chrono::system_clock::time_point, ScalingMetrics>> history_;
    mutable std::mutex mutex_;
    bool running_;
    std::thread collection_thread_;
    
    // Platform-specific metric collection
    double getCPUUtilization() const;
    double getMemoryUtilization() const;
    double getGPUUtilization() const;
};

/**
 * ScalingPolicy - Pluggable scaling policies
 */
class ScalingPolicy {
public:
    virtual ~ScalingPolicy() = default;
    
    virtual ScalingDecision evaluate(const ScalingMetrics& metrics,
                                     const AutoScalerConfig& config,
                                     int current_instances) = 0;
    virtual std::string getName() const = 0;
};

// Threshold-based policy
class ThresholdPolicy : public ScalingPolicy {
public:
    ScalingDecision evaluate(const ScalingMetrics& metrics,
                             const AutoScalerConfig& config,
                             int current_instances) override;
    std::string getName() const override { return "threshold"; }
};

// Predictive policy
class PredictivePolicy : public ScalingPolicy {
public:
    ScalingDecision evaluate(const ScalingMetrics& metrics,
                             const AutoScalerConfig& config,
                             int current_instances) override;
    std::string getName() const override { return "predictive"; }
    
private:
    std::vector<ScalingMetrics> history_;
    mutable std::mutex mutex_;
};

// Step-based policy
class StepPolicy : public ScalingPolicy {
public:
    ScalingDecision evaluate(const ScalingMetrics& metrics,
                             const AutoScalerConfig& config,
                             int current_instances) override;
    std::string getName() const override { return "step"; }
};

// Global accessor
AutoScaler* getAutoScaler();
void setAutoScaler(std::unique_ptr<AutoScaler> scaler);

MetricsCollector* getMetricsCollector();
void setMetricsCollector(std::unique_ptr<MetricsCollector> collector);

// Utility functions
std::string scalingDirectionToString(ScalingDirection direction);
ScalingDirection stringToScalingDirection(const std::string& str);

} // namespace scaling
} // namespace rawrxd
