// ============================================================================
// Deep2ExecutionTelemetry.hpp
// Structured execution observability for Deep2 reverse-engineering loop.
// ============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <mutex>

namespace RawrXD {
namespace Deep2 {

enum class ExecutionBackend : uint8_t {
    Unknown = 0, CPU_AVX512 = 1, CPU_AVX2 = 2, CPU_Scalar = 3,
    Vulkan_GEMM = 4, Vulkan_CooperativeMatrix = 5, DMA_Ring = 6,
    StreamRouter = 7, Fallback = 255
};

enum class QuantFormat : uint8_t {
    Unknown = 0, F32 = 1, F16 = 2, BF16 = 3, Q4_0 = 10, Q4_1 = 11,
    Q4_K_M = 12, Q4_K_S = 13, Q5_0 = 14, Q5_1 = 15, Q6_K = 16, Q8_0 = 17, Q8_1 = 18
};

enum class ResidencyTier : uint8_t {
    Unknown = 0, Host_Mapped = 1, Host_Materialized = 2,
    GPU_DeviceLocal = 3, GPU_Staging = 4, WeightResidencyPool = 5
};

struct DispatchEvent {
    std::string tensor_name;
    std::string operation_type;
    uint32_t layer_index = 0;
    uint32_t M = 0, N = 0, K = 0;
    QuantFormat quant_format = QuantFormat::Unknown;
    ResidencyTier weight_residency = ResidencyTier::Unknown;
    ExecutionBackend backend = ExecutionBackend::Unknown;
    uint64_t dispatch_ns = 0, upload_ns = 0, download_ns = 0, total_ns = 0;
    std::string gpu_name;
    uint64_t vram_used_bytes = 0, vram_total_bytes = 0;
    bool success = false;
    std::string error_message;
    std::string inferred_op_family;
    float arithmetic_intensity = 0.0f;
    float memory_bound_score = 0.0f;
};

// Aggregate statistics per layer — outside class for header visibility
struct LayerStats {
    uint32_t layer = 0;
    uint64_t total_ns = 0;
    uint64_t gemm_ns = 0;
    uint64_t transfer_ns = 0;
    uint32_t dispatch_count = 0;
    uint32_t vulkan_count = 0;
    uint32_t cpu_count = 0;
    float avg_arithmetic_intensity = 0.0f;
};

static constexpr size_t DEEP2_TELEMETRY_RING_SIZE = 4096;

class ExecutionTelemetryCollector {
public:
    static ExecutionTelemetryCollector& Instance();
    void RecordEvent(const DispatchEvent& event);
    std::vector<DispatchEvent> GetRecentEvents(size_t count = 100) const;
    std::vector<DispatchEvent> GetEventsForLayer(uint32_t layer) const;
    std::vector<DispatchEvent> GetEventsForTensor(const std::string& tensorName) const;
    std::vector<LayerStats> ComputeLayerStats() const;
    void Reset();
private:
    ExecutionTelemetryCollector() = default;
    mutable std::mutex m_mutex;
    std::vector<DispatchEvent> m_ring;
    size_t m_writeIndex = 0;
    bool m_full = false;
};

const char* BackendToString(ExecutionBackend b);
const char* QuantToString(QuantFormat q);
const char* ResidencyToString(ResidencyTier r);

} // namespace Deep2
} // namespace RawrXD
