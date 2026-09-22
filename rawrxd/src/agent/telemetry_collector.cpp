#include "telemetry_collector.hpp"
#include <iostream>
#include <vector>
#include <map>

struct TelemetryData {
    std::map<std::string, uint64_t> featureUsage;
    std::map<std::string, double> performance;
    std::map<std::string, uint64_t> errors;
    std::map<std::string, uint64_t> events;
};

static TelemetryCollector s_instance;
static TelemetryData s_data;
static std::mutex s_mutex;

TelemetryCollector* TelemetryCollector::instance() { return &s_instance; }

void TelemetryCollector::trackFeatureUsage(const std::string& feature) {
    std::lock_guard<std::mutex> lock(s_mutex);
    ++s_data.featureUsage[feature];
}

void TelemetryCollector::trackPerformance(const std::string& metric, double value) {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_data.performance[metric] = value;
}

void TelemetryCollector::trackError(const std::string& error) {
    std::lock_guard<std::mutex> lock(s_mutex);
    ++s_data.errors[error];
}

void TelemetryCollector::trackEvent(const std::string& event) {
    std::lock_guard<std::mutex> lock(s_mutex);
    ++s_data.events[event];
}

std::vector<uint8_t> TelemetryCollector::getAllTelemetryData() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {};
}
