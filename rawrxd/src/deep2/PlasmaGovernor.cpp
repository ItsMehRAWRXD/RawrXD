/* PlasmaGovernor — R9700 thermal safety governor implementation */
#include "PlasmaGovernor.hpp"
#include <algorithm>
#include <numeric>

namespace Deep2 {

PlasmaGovernor::PlasmaGovernor()
    : history_(kHistorySize)
    , historyHead_(0)
    , historyCount_(0)
    , maxRecordedTemp_(0.0f)
    , violationCount_(0)
    , emaTemp_(0.0f)
    , emaHotspot_(0.0f)
    , emaPower_(0.0f)
    , thermalLimitBreached_(false) {}

void PlasmaGovernor::update(const ThermalState& state) {
    // Store in circular buffer
    history_[historyHead_] = state;
    historyHead_ = (historyHead_ + 1) % kHistorySize;
    if (historyCount_ < kHistorySize) ++historyCount_;

    // Track maximums
    if (std::isfinite(state.temp) && state.temp > maxRecordedTemp_) {
        maxRecordedTemp_ = state.temp;
    }

    // Update EMAs
    if (historyCount_ == 1) {
        emaTemp_ = state.temp;
        emaHotspot_ = state.hotspot;
        emaPower_ = state.powerW;
    } else {
        emaTemp_    = (1.0f - kEmaAlpha) * emaTemp_    + kEmaAlpha * state.temp;
        emaHotspot_ = (1.0f - kEmaAlpha) * emaHotspot_ + kEmaAlpha * state.hotspot;
        emaPower_   = (1.0f - kEmaAlpha) * emaPower_   + kEmaAlpha * state.powerW;
    }

    // Detect violations
    bool violation = false;
    if (std::isfinite(state.temp) && state.temp > tempLimit_) violation = true;
    if (std::isfinite(state.hotspot) && state.hotspot > hotspotLimit_) violation = true;
    if (std::isfinite(state.powerW) && state.powerW > powerLimit_) violation = true;

    if (violation) {
        ++violationCount_;
        thermalLimitBreached_ = true;
    }

    // Auto-clear if back within safe margins
    if (thermalLimitBreached_ &&
        std::isfinite(state.temp) && state.temp < (tempLimit_ - 5.0f) &&
        std::isfinite(state.hotspot) && state.hotspot < (hotspotLimit_ - 5.0f)) {
        thermalLimitBreached_ = false;
    }
}

float PlasmaGovernor::currentThrottle() const {
    if (historyCount_ == 0) return 1.0f;

    float throttle = 1.0f;

    // Temperature-based throttling (linear ramp from limit-15 to limit)
    if (std::isfinite(emaTemp_) && emaTemp_ > (tempLimit_ - 15.0f)) {
        float t = std::clamp((emaTemp_ - (tempLimit_ - 15.0f)) / 15.0f, 0.0f, 1.0f);
        throttle = std::min(throttle, 1.0f - t * 0.7f); // max 70% throttle reduction
    }

    // Hotspot-based throttling (more aggressive)
    if (std::isfinite(emaHotspot_) && emaHotspot_ > (hotspotLimit_ - 10.0f)) {
        float t = std::clamp((emaHotspot_ - (hotspotLimit_ - 10.0f)) / 10.0f, 0.0f, 1.0f);
        throttle = std::min(throttle, 1.0f - t * 0.9f);
    }

    // Power-based throttling
    if (std::isfinite(emaPower_) && emaPower_ > (powerLimit_ - 30.0f)) {
        float t = std::clamp((emaPower_ - (powerLimit_ - 30.0f)) / 30.0f, 0.0f, 1.0f);
        throttle = std::min(throttle, 1.0f - t * 0.5f);
    }

    // Hard floor
    return std::max(throttle, 0.1f);
}

float PlasmaGovernor::avgTemp() const {
    if (historyCount_ == 0) return 0.0f;
    float sum = 0.0f;
    size_t valid = 0;
    for (size_t i = 0; i < historyCount_; ++i) {
        size_t idx = (historyHead_ + kHistorySize - historyCount_ + i) % kHistorySize;
        if (std::isfinite(history_[idx].temp)) {
            sum += history_[idx].temp;
            ++valid;
        }
    }
    return (valid > 0) ? (sum / static_cast<float>(valid)) : 0.0f;
}

void PlasmaGovernor::resetHistory() {
    historyCount_ = 0;
    historyHead_ = 0;
    maxRecordedTemp_ = 0.0f;
    violationCount_ = 0;
    emaTemp_ = 0.0f;
    emaHotspot_ = 0.0f;
    emaPower_ = 0.0f;
    thermalLimitBreached_ = false;
}

// SovereignOutOfCoreRuntime implementation
SovereignOutOfCoreRuntime::SovereignOutOfCoreRuntime(const OocConfig& cfg)
    : cfg_(cfg)
    , hostRamCapacity_(cfg.hostRamBytes)
    , nvmeCapacity_(cfg.nvmeBytes)
    , pageSize_(cfg.pageSizeBytes)
    , activePages_(0)
    , evictedPages_(0) {}

bool SovereignOutOfCoreRuntime::initialize() {
    initialized_ = true;
    activePages_ = 0;
    evictedPages_ = 0;
    return true;
}

void SovereignOutOfCoreRuntime::shutdown() {
    initialized_ = false;
    activePages_ = 0;
    evictedPages_ = 0;
}

} // namespace Deep2
