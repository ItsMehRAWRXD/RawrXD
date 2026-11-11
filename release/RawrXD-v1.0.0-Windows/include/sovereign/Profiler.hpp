#pragma once
#include <cstdint>

namespace Sovereign {
namespace Profiler {

/**
 * @brief Begin profiling frame
 */
void BeginFrame();

/**
 * @brief End profiling frame and emit metrics
 */
void EndFrame();

/**
 * @brief Emit all profiler metrics via Beaconism
 */
void EmitMetrics();

/**
 * @brief Get current frame time in microseconds
 */
uint64_t GetFrameTimeUs();

/**
 * @brief Get current tokens per second
 */
float GetTokensPerSecond();

/**
 * @brief Get current NVMe bandwidth in MB/s
 */
float GetNVMeBandwidthMBps();

} // namespace Profiler
} // namespace Sovereign
