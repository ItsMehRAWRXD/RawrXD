#pragma once
#include <string>
#include <cstdint>
#include <vector>
#include <atomic>
#include <mutex>

// Minimal TelemetryCollector for auto_feature_registry.cpp
class TelemetryCollector {
public:
    static TelemetryCollector* instance();
    void trackFeatureUsage(const std::string& feature);
    void trackPerformance(const std::string& metric, double value);
    void trackError(const std::string& error);
    void trackEvent(const std::string& event);
    std::vector<uint8_t> getAllTelemetryData();
};
