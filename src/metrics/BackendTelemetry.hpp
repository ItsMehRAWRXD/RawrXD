#pragma once
#include "ProcessorMetrics.hpp"
#include "GpuMetrics.hpp"
#include <string>

class BackendTelemetry {
private:
    ProcessorMetrics m_cpuTracker;
    GpuMetrics m_gpuTracker;
    double m_lastMeasuredTokensPerSec;
    double m_lastMeasuredBuildDurationSec;

public:
    BackendTelemetry();
    void SetInferenceVelocity(double tokensPerSecond);
    void SetCompilerBuildDuration(double durationSeconds);
    std::string CompileAggregatedTelemetryPayload(const std::string& activeBackendName);
};
