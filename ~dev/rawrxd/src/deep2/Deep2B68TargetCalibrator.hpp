#pragma once
#include "Deep2B67LiveTelemetry.hpp"
#include <cstdint>
#include <vector>

namespace Deep2 {

struct B68Hardware {
    double aggregateBandwidthGBs = 0.0;
    double aggregateComputeTFLOPs = 0.0;
};

struct B68WorkModel {
    double bytesPerToken = 0.0;
    double flopsPerToken = 0.0;
};

struct B68Calibration {
    bool pass = false;
    const char* failure = "UNSET";
    double memoryRooflineTps = 0.0;
    double computeRooflineTps = 0.0;
    double physicalRooflineTps = 0.0;
    double observedMedianTps = 0.0;
    double safeP10Target = 0.0;
    double safeMedianTarget = 0.0;
    double requiredHeadroom = 1.03;
};

class B68TargetCalibrator {
public:
    static B68Calibration calibrate(const B68Hardware&,
                                    const B68WorkModel&,
                                    const std::vector<B67TokenTelemetry>&,
                                    double safetyFraction=0.92,
                                    double headroom=1.03);
};

} // namespace Deep2
