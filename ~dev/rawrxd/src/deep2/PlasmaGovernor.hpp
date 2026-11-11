#pragma once
/* PlasmaGovernor — stub */
#include <cstdint>
namespace Deep2 {
struct ThermalState { float temp = 0.0f; };
class PlasmaGovernor {
public:
    float currentThrottle() const { return 1.0f; }
    void update(const ThermalState&) {}
};
class SovereignOutOfCoreRuntime {};
} // namespace Deep2
