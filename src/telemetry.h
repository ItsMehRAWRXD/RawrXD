#pragma once

#include <string>
#include <vector>
#include "../include/nlohmann/json.hpp"

// Forward declarations
void logEvent(const char* name, double v1, double v2);

// High-level telemetry wrapper
class Telemetry {
public:
    Telemetry();
    ~Telemetry();

    void initializeHardware();
    void recordEvent(const std::string& event_name, const nlohmann::json& metadata = nlohmann::json::object());
    bool saveTelemetry(const std::string& filepath);
    nlohmann::json getEvents() const { return events_; }
    void clearEvents() { events_ = nlohmann::json::array(); }
    bool isEnabled() const { return is_enabled_; }

private:
    bool is_enabled_;
    nlohmann::json events_;
};

// Low-level telemetry namespace
namespace telemetry {
    bool Initialize();
    void Shutdown();
    void InitializeHardware();
    void RecordMetric(const std::string& name, double value);
    void RecordEvent(const std::string& name, const std::string& data);
    double GetCounter(const std::string& name);
    void ResetCounters();
}
