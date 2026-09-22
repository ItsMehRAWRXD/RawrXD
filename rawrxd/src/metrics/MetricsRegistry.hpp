#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace RawrXD::Metrics {

class MetricsRegistry {
public:
    static MetricsRegistry& instance() {
        static MetricsRegistry s;
        return s;
    }

    void gauge(const std::string& name, double value) {
        std::lock_guard<std::mutex> lock(mutex_);
        gauges_[name] = value;
    }

    double getGauge(const std::string& name) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = gauges_.find(name);
        return (it != gauges_.end()) ? it->second : 0.0;
    }

    void increment(const std::string& name, double delta = 1.0) {
        std::lock_guard<std::mutex> lock(mutex_);
        counters_[name] += delta;
    }

    void recordDuration(const std::string& name, double milliseconds) {
        std::lock_guard<std::mutex> lock(mutex_);
        durations_[name] = milliseconds;
    }

private:
    MetricsRegistry() = default;
    ~MetricsRegistry() = default;
    MetricsRegistry(const MetricsRegistry&) = delete;
    MetricsRegistry& operator=(const MetricsRegistry&) = delete;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, double> gauges_;
    std::unordered_map<std::string, double> counters_;
    std::unordered_map<std::string, double> durations_;
};

} // namespace RawrXD::Metrics

// Global convenience macro / object used by many .cpp files
#define METRICS (::RawrXD::Metrics::MetricsRegistry::instance())
