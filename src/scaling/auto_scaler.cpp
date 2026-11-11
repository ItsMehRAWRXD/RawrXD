// RawrXD Auto-Scaler Implementation
// Phase AR: Auto-Scaling & Load Balancing

#include "auto_scaler.hpp"
#include <iostream>
#include <algorithm>
#include <sstream>

namespace rawrxd {
namespace scaling {

// Global instances
static std::unique_ptr<AutoScaler> g_auto_scaler;
static std::unique_ptr<MetricsCollector> g_metrics_collector;

AutoScaler* getAutoScaler() {
    return g_auto_scaler.get();
}

void setAutoScaler(std::unique_ptr<AutoScaler> scaler) {
    g_auto_scaler = std::move(scaler);
}

MetricsCollector* getMetricsCollector() {
    return g_metrics_collector.get();
}

void setMetricsCollector(std::unique_ptr<MetricsCollector> collector) {
    g_metrics_collector = std::move(collector);
}

// AutoScaler implementation
AutoScaler::AutoScaler()
    : current_instances_(1)
    , target_instances_(1)
    , running_(false)
    , initialized_(false)
    , total_events_(0)
    , successful_events_(0)
    , failed_events_(0) {
}

AutoScaler::~AutoScaler() {
    shutdown();
}

bool AutoScaler::initialize(const AutoScalerConfig& config) {
    config_ = config;
    current_instances_ = config_.min_instances;
    target_instances_ = config_.min_instances;
    initialized_ = true;
    
    std::cout << "Auto-scaler initialized (min=" << config_.min_instances 
              << ", max=" << config_.max_instances << ")" << std::endl;
    return true;
}

void AutoScaler::shutdown() {
    stop();
    initialized_ = false;
}

void AutoScaler::updateConfig(const AutoScalerConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
}

AutoScalerConfig AutoScaler::getConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

void AutoScaler::setMetricsProvider(MetricsProvider provider) {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_provider_ = provider;
}

ScalingMetrics AutoScaler::getCurrentMetrics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (metrics_provider_) {
        return metrics_provider_();
    }
    return ScalingMetrics();
}

void AutoScaler::start() {
    if (!initialized_ || running_) return;
    
    running_ = true;
    evaluation_thread_ = std::thread(&AutoScaler::evaluationLoop, this);
    
    std::cout << "Auto-scaler started" << std::endl;
}

void AutoScaler::stop() {
    if (!running_) return;
    
    running_ = false;
    
    if (evaluation_thread_.joinable()) {
        evaluation_thread_.join();
    }
    
    std::cout << "Auto-scaler stopped" << std::endl;
}

bool AutoScaler::isRunning() const {
    return running_;
}

bool AutoScaler::scaleTo(int instance_count) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (instance_count < config_.min_instances || instance_count > config_.max_instances) {
        std::cerr << "Target instance count out of range: " << instance_count << std::endl;
        return false;
    }
    
    target_instances_ = instance_count;
    return executeScaling(instance_count);
}

bool AutoScaler::scaleUp(int delta) {
    int current = current_instances_.load();
    int target = std::min(current + delta, config_.max_instances);
    
    if (target > current) {
        return scaleTo(target);
    }
    
    return false;
}

bool AutoScaler::scaleDown(int delta) {
    int current = current_instances_.load();
    int target = std::max(current - delta, config_.min_instances);
    
    if (target < current) {
        return scaleTo(target);
    }
    
    return false;
}

int AutoScaler::getCurrentInstanceCount() const {
    return current_instances_.load();
}

int AutoScaler::getTargetInstanceCount() const {
    return target_instances_.load();
}

ScalingDecision AutoScaler::getLastDecision() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_decision_;
}

void AutoScaler::setScalingActionCallback(ScalingActionCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    scaling_callback_ = callback;
}

std::vector<ScalingEvent> AutoScaler::getScalingHistory(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ScalingEvent> result;
    size_t start = scaling_history_.size() > count ? scaling_history_.size() - count : 0;
    
    for (size_t i = start; i < scaling_history_.size(); ++i) {
        result.push_back(scaling_history_[i]);
    }
    
    return result;
}

size_t AutoScaler::getTotalScalingEvents() const {
    return total_events_;
}

size_t AutoScaler::getSuccessfulScalingEvents() const {
    return successful_events_;
}

size_t AutoScaler::getFailedScalingEvents() const {
    return failed_events_;
}

void AutoScaler::evaluationLoop() {
    while (running_) {
        auto start = std::chrono::steady_clock::now();
        
        // Collect metrics
        ScalingMetrics metrics;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (metrics_provider_) {
                metrics = metrics_provider_();
            }
        }
        
        // Evaluate scaling decision
        ScalingDecision decision = evaluateScaling(metrics);
        
        // Execute if needed
        if (decision.direction != ScalingDirection::HOLD && canScale()) {
            int current = current_instances_.load();
            int target = current + decision.instance_delta;
            target = std::max(config_.min_instances, std::min(config_.max_instances, target));
            
            if (target != current) {
                executeScaling(target);
            }
        }
        
        // Sleep until next evaluation
        auto elapsed = std::chrono::steady_clock::now() - start;
        auto sleep_time = config_.evaluation_interval - std::chrono::duration_cast<std::chrono::seconds>(elapsed);
        
        if (sleep_time > std::chrono::seconds(0)) {
            std::this_thread::sleep_for(sleep_time);
        }
    }
}

ScalingDecision AutoScaler::evaluateScaling(const ScalingMetrics& metrics) {
    ScalingDecision decision;
    
    // Check CPU utilization
    if (metrics.cpu_utilization > config_.cpu_scale_up_threshold) {
        decision.direction = ScalingDirection::SCALE_UP;
        decision.instance_delta = config_.scale_up_step;
        decision.reason = "CPU utilization above threshold";
        decision.confidence = std::min(1.0, (metrics.cpu_utilization - config_.cpu_scale_up_threshold) / 30.0);
    } else if (metrics.cpu_utilization < config_.cpu_scale_down_threshold && 
               current_instances_ > config_.min_instances) {
        decision.direction = ScalingDirection::SCALE_DOWN;
        decision.instance_delta = -config_.scale_down_step;
        decision.reason = "CPU utilization below threshold";
        decision.confidence = std::min(1.0, (config_.cpu_scale_down_threshold - metrics.cpu_utilization) / 20.0);
    }
    
    // Check memory utilization
    if (metrics.memory_utilization > config_.memory_scale_up_threshold) {
        decision.direction = ScalingDirection::SCALE_UP;
        decision.instance_delta = config_.scale_up_step;
        decision.reason = "Memory utilization above threshold";
        decision.confidence = std::max(decision.confidence, 
                                       std::min(1.0, (metrics.memory_utilization - config_.memory_scale_up_threshold) / 20.0));
    }
    
    // Check queue depth
    if (metrics.request_queue_depth > config_.queue_scale_up_threshold) {
        decision.direction = ScalingDirection::SCALE_UP;
        decision.instance_delta = config_.scale_up_step;
        decision.reason = "Request queue depth above threshold";
        decision.confidence = std::max(decision.confidence, 
                                       std::min(1.0, static_cast<double>(metrics.request_queue_depth) / 
                                                    config_.queue_scale_up_threshold));
    }
    
    // Check latency
    if (metrics.request_latency_p99 > config_.latency_scale_up_threshold_ms) {
        decision.direction = ScalingDirection::SCALE_UP;
        decision.instance_delta = config_.scale_up_step;
        decision.reason = "P99 latency above threshold";
        decision.confidence = std::max(decision.confidence, 
                                       std::min(1.0, metrics.request_latency_p99 / 
                                                    config_.latency_scale_up_threshold_ms));
    }
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        last_decision_ = decision;
    }
    
    return decision;
}

bool AutoScaler::canScale() const {
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_scaling_time_);
    
    return elapsed >= config_.cooldown_period;
}

bool AutoScaler::executeScaling(int target_count) {
    int previous = current_instances_.load();
    
    ScalingEvent event;
    event.previous_count = previous;
    event.new_count = target_count;
    event.trigger = last_decision_.reason;
    event.metric_value = getCurrentMetrics().cpu_utilization;
    
    bool success = false;
    if (scaling_callback_) {
        success = scaling_callback_(target_count);
    } else {
        // Simulate scaling
        std::cout << "Scaling from " << previous << " to " << target_count << " instances" << std::endl;
        success = true;
    }
    
    if (success) {
        current_instances_ = target_count;
        last_scaling_time_ = std::chrono::system_clock::now();
        successful_events_++;
        
        if (target_count > previous) {
            event.direction = ScalingDirection::SCALE_UP;
        } else if (target_count < previous) {
            event.direction = ScalingDirection::SCALE_DOWN;
        }
    } else {
        failed_events_++;
        event.direction = ScalingDirection::HOLD;
        std::cerr << "Scaling failed" << std::endl;
    }
    
    total_events_++;
    addHistory(event);
    
    return success;
}

void AutoScaler::recordEvent(const ScalingEvent& event) {
    // Implementation for external event recording
}

void AutoScaler::addHistory(const ScalingEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    scaling_history_.push_back(event);
    
    // Keep only last 1000 events
    if (scaling_history_.size() > 1000) {
        scaling_history_.erase(scaling_history_.begin());
    }
}

// MetricsCollector implementation
MetricsCollector::MetricsCollector()
    : running_(false) {
}

MetricsCollector::~MetricsCollector() {
    shutdown();
}

bool MetricsCollector::initialize() {
    return true;
}

void MetricsCollector::shutdown() {
    stopCollection();
}

ScalingMetrics MetricsCollector::collect() {
    ScalingMetrics metrics;
    
    metrics.cpu_utilization = getCPUUtilization();
    metrics.memory_utilization = getMemoryUtilization();
    metrics.gpu_utilization = getGPUUtilization();
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!history_.empty()) {
            metrics.request_latency_p99 = history_.back().second.request_latency_p99;
            metrics.throughput_rps = history_.back().second.throughput_rps;
        }
    }
    
    return metrics;
}

void MetricsCollector::startCollection(std::chrono::seconds interval) {
    if (running_) return;
    
    running_ = true;
    collection_thread_ = std::thread([this, interval]() {
        while (running_) {
            auto metrics = collect();
            
            {
                std::lock_guard<std::mutex> lock(mutex_);
                history_.emplace_back(std::chrono::system_clock::now(), metrics);
                
                // Keep last 24 hours of data
                auto cutoff = std::chrono::system_clock::now() - std::chrono::hours(24);
                while (!history_.empty() && history_.front().first < cutoff) {
                    history_.erase(history_.begin());
                }
            }
            
            std::this_thread::sleep_for(interval);
        }
    });
}

void MetricsCollector::stopCollection() {
    running_ = false;
    
    if (collection_thread_.joinable()) {
        collection_thread_.join();
    }
}

std::vector<ScalingMetrics> MetricsCollector::getHistory(std::chrono::minutes duration) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ScalingMetrics> result;
    auto cutoff = std::chrono::system_clock::now() - duration;
    
    for (const auto& [timestamp, metrics] : history_) {
        if (timestamp >= cutoff) {
            result.push_back(metrics);
        }
    }
    
    return result;
}

ScalingMetrics MetricsCollector::getAverage(std::chrono::minutes window) const {
    auto history = getHistory(window);
    
    if (history.empty()) {
        return ScalingMetrics();
    }
    
    ScalingMetrics avg;
    for (const auto& m : history) {
        avg.cpu_utilization += m.cpu_utilization;
        avg.memory_utilization += m.memory_utilization;
        avg.gpu_utilization += m.gpu_utilization;
        avg.request_queue_depth += m.request_queue_depth;
        avg.request_latency_p99 += m.request_latency_p99;
        avg.throughput_rps += m.throughput_rps;
        avg.active_connections += m.active_connections;
    }
    
    double count = static_cast<double>(history.size());
    avg.cpu_utilization /= count;
    avg.memory_utilization /= count;
    avg.gpu_utilization /= count;
    avg.request_queue_depth /= count;
    avg.request_latency_p99 /= count;
    avg.throughput_rps /= count;
    avg.active_connections /= count;
    
    return avg;
}

ScalingMetrics MetricsCollector::getPercentile(double p, std::chrono::minutes window) const {
    auto history = getHistory(window);
    
    if (history.empty()) {
        return ScalingMetrics();
    }
    
    // Sort by latency for percentile calculation
    std::vector<double> latencies;
    for (const auto& m : history) {
        latencies.push_back(m.request_latency_p99);
    }
    
    std::sort(latencies.begin(), latencies.end());
    
    size_t index = static_cast<size_t>(p / 100.0 * latencies.size());
    index = std::min(index, latencies.size() - 1);
    
    ScalingMetrics result;
    result.request_latency_p99 = latencies[index];
    
    return result;
}

void MetricsCollector::recordRequestLatency(double latency_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!history_.empty()) {
        history_.back().second.request_latency_p99 = latency_ms;
    }
}

void MetricsCollector::recordQueueDepth(size_t depth) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!history_.empty()) {
        history_.back().second.request_queue_depth = depth;
    }
}

void MetricsCollector::recordThroughput(double rps) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!history_.empty()) {
        history_.back().second.throughput_rps = rps;
    }
}

double MetricsCollector::getCPUUtilization() const {
    // Platform-specific implementation would go here
    // Return estimated value (actual monitoring pending)
    return 45.0 + (rand() % 30);
}

double MetricsCollector::getMemoryUtilization() const {
    // Platform-specific implementation would go here
    return 60.0 + (rand() % 20);
}

double MetricsCollector::getGPUUtilization() const {
    // Platform-specific implementation would go here
    return 30.0 + (rand() % 40);
}

// ThresholdPolicy implementation
ScalingDecision ThresholdPolicy::evaluate(const ScalingMetrics& metrics,
                                          const AutoScalerConfig& config,
                                          int current_instances) {
    ScalingDecision decision;
    
    // Scale up if any metric exceeds threshold
    if (metrics.cpu_utilization > config.cpu_scale_up_threshold ||
        metrics.memory_utilization > config.memory_scale_up_threshold ||
        metrics.request_queue_depth > config.queue_scale_up_threshold) {
        
        decision.direction = ScalingDirection::SCALE_UP;
        decision.instance_delta = config.scale_up_step;
        decision.reason = "Threshold exceeded";
        decision.confidence = 0.8;
    }
    // Scale down if all metrics below threshold
    else if (current_instances > config.min_instances &&
             metrics.cpu_utilization < config.cpu_scale_down_threshold &&
             metrics.memory_utilization < config.memory_scale_down_threshold &&
             metrics.request_queue_depth < config.queue_scale_down_threshold) {
        
        decision.direction = ScalingDirection::SCALE_DOWN;
        decision.instance_delta = -config.scale_down_step;
        decision.reason = "Below scale-down thresholds";
        decision.confidence = 0.7;
    }
    
    return decision;
}

// PredictivePolicy implementation
ScalingDecision PredictivePolicy::evaluate(const ScalingMetrics& metrics,
                                           const AutoScalerConfig& config,
                                           int current_instances) {
    ScalingDecision decision;
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        history_.push_back(metrics);
        
        // Keep last hour of data
        if (history_.size() > 60) {
            history_.erase(history_.begin());
        }
    }
    
    // Simple trend analysis
    if (history_.size() >= 5) {
        double cpu_trend = 0;
        for (size_t i = history_.size() - 5; i < history_.size() - 1; ++i) {
            cpu_trend += history_[i + 1].cpu_utilization - history_[i].cpu_utilization;
        }
        cpu_trend /= 4;
        
        // Predict future CPU
        double predicted_cpu = metrics.cpu_utilization + cpu_trend * 5;
        
        if (predicted_cpu > config.cpu_scale_up_threshold) {
            decision.direction = ScalingDirection::SCALE_UP;
            decision.instance_delta = config.scale_up_step;
            decision.reason = "Predictive: CPU trending up";
            decision.confidence = std::min(1.0, (predicted_cpu - config.cpu_scale_up_threshold) / 20.0);
        }
    }
    
    return decision;
}

// StepPolicy implementation
ScalingDecision StepPolicy::evaluate(const ScalingMetrics& metrics,
                                   const AutoScalerConfig& config,
                                   int current_instances) {
    ScalingDecision decision;
    
    // Calculate desired instances based on CPU
    double cpu_ratio = metrics.cpu_utilization / ((config.cpu_scale_up_threshold + config.cpu_scale_down_threshold) / 2);
    int desired = static_cast<int>(current_instances * cpu_ratio);
    desired = std::max(config.min_instances, std::min(config.max_instances, desired));
    
    int delta = desired - current_instances;
    
    if (delta > 0) {
        decision.direction = ScalingDirection::SCALE_UP;
        decision.instance_delta = std::min(delta, config.scale_up_step);
        decision.reason = "Step scaling: CPU ratio";
        decision.confidence = 0.9;
    } else if (delta < 0) {
        decision.direction = ScalingDirection::SCALE_DOWN;
        decision.instance_delta = std::max(delta, -config.scale_down_step);
        decision.reason = "Step scaling: CPU ratio";
        decision.confidence = 0.9;
    }
    
    return decision;
}

// Utility functions
std::string scalingDirectionToString(ScalingDirection direction) {
    switch (direction) {
        case ScalingDirection::SCALE_UP: return "SCALE_UP";
        case ScalingDirection::SCALE_DOWN: return "SCALE_DOWN";
        case ScalingDirection::HOLD: return "HOLD";
        default: return "UNKNOWN";
    }
}

ScalingDirection stringToScalingDirection(const std::string& str) {
    if (str == "SCALE_UP") return ScalingDirection::SCALE_UP;
    if (str == "SCALE_DOWN") return ScalingDirection::SCALE_DOWN;
    if (str == "HOLD") return ScalingDirection::HOLD;
    return ScalingDirection::HOLD;
}

} // namespace scaling
} // namespace rawrxd
