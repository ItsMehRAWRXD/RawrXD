#include "sovereign/Profiler.hpp"
#include "sovereign/Beaconism.hpp"
#include "sovereign/Telemetry.hpp"
#include <intrin.h>

namespace Sovereign {
namespace Profiler {

static uint64_t s_frameStart = 0;
static uint64_t s_frameTimeUs = 0;

void BeginFrame() {
    s_frameStart = __rdtsc();
}

void EndFrame() {
    uint64_t frameEnd = __rdtsc();
    // Convert to microseconds (approximate at 3.3GHz)
    s_frameTimeUs = (frameEnd - s_frameStart) / 3300;
    
    BeaconismEmitter::Instance().Emit(BeaconID::ProfilerFrameTime, static_cast<uint32_t>(s_frameTimeUs));
}

void EmitMetrics() {
    // Get telemetry data
    auto tel = Telemetry::GetSnapshot();
    
    // Emit tokens per second
    BeaconismEmitter::Instance().Emit(BeaconID::ProfilerTokPerSec, 
        static_cast<uint32_t>(tel.tokensPerSec));
    
    // Emit NVMe bandwidth
    BeaconismEmitter::Instance().Emit(BeaconID::ProfilerNVMeMBps, 
        static_cast<uint32_t>(tel.nvmeBandwidthMBps));
    
    // Emit thermal
    BeaconismEmitter::Instance().Emit(BeaconID::ProfilerThermal, 
        static_cast<uint32_t>(tel.thermalC));
}

uint64_t GetFrameTimeUs() {
    return s_frameTimeUs;
}

float GetTokensPerSecond() {
    auto tel = Telemetry::GetSnapshot();
    return tel.tokensPerSec;
}

float GetNVMeBandwidthMBps() {
    auto tel = Telemetry::GetSnapshot();
    return tel.nvmeBandwidthMBps;
}

} // namespace Profiler
} // namespace Sovereign
