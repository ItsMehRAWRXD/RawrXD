#pragma once
/* PlasmaGovernor — R9700 thermal safety governor */
#include <cstdint>
#include <vector>
#include <cmath>
namespace Deep2 {

struct ThermalState {
    float temp = 0.0f;       // GPU die temperature in °C
    float hotspot = 0.0f;    // Junction/hotspot temperature
    float memTemp = 0.0f;    // VRAM temperature
    float powerW = 0.0f;     // Instantaneous power draw in watts
};

class PlasmaGovernor {
public:
    PlasmaGovernor();

    void update(const ThermalState& state);
    float currentThrottle() const;

    void setTempLimit(float celsius) { tempLimit_ = celsius; }
    void setHotspotLimit(float celsius) { hotspotLimit_ = celsius; }
    void setPowerLimit(float watts) { powerLimit_ = watts; }

    float maxRecordedTemp() const { return maxRecordedTemp_; }
    float avgTemp() const;
    size_t violationCount() const { return violationCount_; }
    void resetHistory();

private:
    // Limits
    float tempLimit_ = 85.0f;      // °C — AMD reference
    float hotspotLimit_ = 105.0f;  // °C — junction limit
    float powerLimit_ = 250.0f;    // W — board TDP

    // EMA parameters
    static constexpr size_t kHistorySize = 64;
    std::vector<ThermalState> history_;
    size_t historyHead_ = 0;
    size_t historyCount_ = 0;
    float maxRecordedTemp_ = 0.0f;
    size_t violationCount_ = 0;

    float emaTemp_ = 0.0f;
    float emaHotspot_ = 0.0f;
    float emaPower_ = 0.0f;
    static constexpr float kEmaAlpha = 0.1f; // smoothing factor

    bool thermalLimitBreached_ = false;
};

class SovereignOutOfCoreRuntime {
public:
    struct OocConfig {
        size_t hostRamBytes = 0;
        size_t nvmeBytes = 0;
        size_t pageSizeBytes = 64 * 1024 * 1024; // 64 MiB default page
    };

    explicit SovereignOutOfCoreRuntime(const OocConfig& cfg = {});

    bool initialize();
    bool isInitialized() const { return initialized_; }
    void shutdown();

    size_t hostRamCapacity() const { return hostRamCapacity_; }
    size_t nvmeCapacity() const { return nvmeCapacity_; }
    size_t pageSize() const { return pageSize_; }

    size_t activePages() const { return activePages_; }
    size_t evictedPages() const { return evictedPages_; }

private:
    OocConfig cfg_;
    bool initialized_ = false;
    size_t hostRamCapacity_ = 0;
    size_t nvmeCapacity_ = 0;
    size_t pageSize_ = 0;
    size_t activePages_ = 0;
    size_t evictedPages_ = 0;
};

} // namespace Deep2
