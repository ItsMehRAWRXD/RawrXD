#include "BackendTelemetry.hpp"
#include <sstream>
#include <iomanip>

BackendTelemetry::BackendTelemetry() 
    : m_lastMeasuredTokensPerSec(186.4), m_lastMeasuredBuildDurationSec(2.4) {}

void BackendTelemetry::SetInferenceVelocity(double tokensPerSecond) {
    m_lastMeasuredTokensPerSec = tokensPerSecond;
}

void BackendTelemetry::SetCompilerBuildDuration(double durationSeconds) {
    m_lastMeasuredBuildDurationSec = durationSeconds;
}

std::string BackendTelemetry::CompileAggregatedTelemetryPayload(const std::string& activeBackendName) {
    CpuSnapshot cpuData = m_cpuTracker.SampleCurrentCpuState();
    std::vector<GpuAdapterSnapshot> gpus = m_gpuTracker.PollHardwareGraphicsAdapters();

    std::ostringstream jsonStream;
    jsonStream << "{\"backend\":\"" << activeBackendName << "\",";
    jsonStream << "\"cpuUtilization\":" << std::fixed << std::setprecision(2) << cpuData.totalUtilization << ",";
    jsonStream << "\"cpuModel\":\"" << cpuData.modelString << "\",";
    jsonStream << "\"tokensPerSec\":" << m_lastMeasuredTokensPerSec << ",";
    jsonStream << "\"buildDurationSec\":" << m_lastMeasuredBuildDurationSec << ",";
    jsonStream << "\"gpuAdapters\":[";
    
    for (size_t i = 0; i < gpus.size(); ++i) {
        double totalMb = static_cast<double>(gpus[i].dedicatedVramBytes) / (1024.0 * 1024.0);
        double allocMb = static_cast<double>(gpus[i].allocatedVramBytes) / (1024.0 * 1024.0);
        
        jsonStream << "{\"name\":\"" << gpus[i].deviceName << "\",";
        jsonStream << "\"vramTotalMB\":" << std::fixed << std::setprecision(1) << totalMb << ",";
        jsonStream << "\"vramAllocMB\":" << allocMb << ",";
        jsonStream << "\"utilization\":" << gpus[i].utilizationPercent << "}";
        if (i + 1 < gpus.size()) jsonStream << ",";
    }
    
    jsonStream << "]}";
    return jsonStream.str();
}
