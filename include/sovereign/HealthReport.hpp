#pragma once
#include <vector>
#include <string>
#include <ctime>
#include <map>
#include "sovereign/Beaconism.hpp"

namespace Sovereign {

enum class HealthState {
    UNKNOWN,
    OK,
    WARNING,
    FAIL,
    Degraded = WARNING,
    Broken = FAIL
};

struct SubsystemHealth {
    std::string name;
    HealthState state;
    uint64_t durationNs;
    uint32_t beaconCount;
    std::string lastError;
    time_t lastRun;
    time_t lastSuccess;
};

class HealthReport {
public:
    time_t timestamp;
    std::vector<SubsystemHealth> subsystems;
    uint32_t totalBeacons = 0;
    uint32_t passedTests = 0;
    uint32_t failedTests = 0;
    std::string summary;
    
    void ProcessBeacons(BeaconismEmitter& emitter);
    void CalculateHealth();
    
    void GenerateHTML(const std::wstring& path);
    void GenerateJSON(const std::wstring& path);
    void PrintConsole();
    
    HealthState GetOverallHealth() const;
    
private:
    std::map<BeaconID, Beacon> lastStartBeacons;
    std::map<BeaconID, Beacon> lastDoneBeacons;
    
    void UpdateSubsystem(const std::string& name, HealthState state, 
                         uint64_t duration, uint32_t count);
    const char* BeaconName(BeaconID id) const;
    const char* StateEmoji(HealthState state) const;
};

} // namespace Sovereign
