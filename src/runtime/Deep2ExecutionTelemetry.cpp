// ============================================================================
// Deep2ExecutionTelemetry.cpp
// Implementation of structured execution observability for Deep2.
// ============================================================================
#include "Deep2ExecutionTelemetry.hpp"
#include <algorithm>

namespace RawrXD {
namespace Deep2 {

ExecutionTelemetryCollector& ExecutionTelemetryCollector::Instance() {
    static ExecutionTelemetryCollector instance;
    return instance;
}

void ExecutionTelemetryCollector::RecordEvent(const DispatchEvent& event) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_ring.size() < DEEP2_TELEMETRY_RING_SIZE) {
        m_ring.push_back(event);
    } else {
        m_ring[m_writeIndex] = event;
        m_writeIndex = (m_writeIndex + 1) % DEEP2_TELEMETRY_RING_SIZE;
        m_full = true;
    }
}

std::vector<DispatchEvent> ExecutionTelemetryCollector::GetRecentEvents(size_t count) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t total = m_full ? DEEP2_TELEMETRY_RING_SIZE : m_ring.size();
    size_t start = total > count ? total - count : 0;
    std::vector<DispatchEvent> result;
    result.reserve(std::min(count, total));
    for (size_t i = start; i < total; ++i) {
        size_t idx = m_full ? (m_writeIndex + i) % DEEP2_TELEMETRY_RING_SIZE : i;
        result.push_back(m_ring[idx]);
    }
    return result;
}

std::vector<DispatchEvent> ExecutionTelemetryCollector::GetEventsForLayer(uint32_t layer) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<DispatchEvent> result;
    for (const auto& e : m_ring) {
        if (e.layer_index == layer) result.push_back(e);
    }
    return result;
}

std::vector<DispatchEvent> ExecutionTelemetryCollector::GetEventsForTensor(const std::string& tensorName) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<DispatchEvent> result;
    for (const auto& e : m_ring) {
        if (e.tensor_name == tensorName) result.push_back(e);
    }
    return result;
}

std::vector<LayerStats> ExecutionTelemetryCollector::ComputeLayerStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<LayerStats> stats;
    for (const auto& e : m_ring) {
        if (!e.success) continue;
        auto it = std::find_if(stats.begin(), stats.end(),
            [e](const LayerStats& s) { return s.layer == e.layer_index; });
        if (it == stats.end()) {
            LayerStats s{};
            s.layer = e.layer_index;
            s.total_ns = e.total_ns;
            s.gemm_ns = e.dispatch_ns;
            s.transfer_ns = e.upload_ns + e.download_ns;
            s.dispatch_count = 1;
            s.vulkan_count = (e.backend == ExecutionBackend::Vulkan_GEMM || e.backend == ExecutionBackend::Vulkan_CooperativeMatrix) ? 1 : 0;
            s.cpu_count = (e.backend == ExecutionBackend::CPU_AVX512 || e.backend == ExecutionBackend::CPU_AVX2 || e.backend == ExecutionBackend::CPU_Scalar) ? 1 : 0;
            s.avg_arithmetic_intensity = e.arithmetic_intensity;
            stats.push_back(s);
        } else {
            it->total_ns += e.total_ns;
            it->gemm_ns += e.dispatch_ns;
            it->transfer_ns += e.upload_ns + e.download_ns;
            it->dispatch_count++;
            it->vulkan_count += (e.backend == ExecutionBackend::Vulkan_GEMM || e.backend == ExecutionBackend::Vulkan_CooperativeMatrix) ? 1 : 0;
            it->cpu_count += (e.backend == ExecutionBackend::CPU_AVX512 || e.backend == ExecutionBackend::CPU_AVX2 || e.backend == ExecutionBackend::CPU_Scalar) ? 1 : 0;
            it->avg_arithmetic_intensity = (it->avg_arithmetic_intensity * (it->dispatch_count - 1) + e.arithmetic_intensity) / it->dispatch_count;
        }
    }
    return stats;
}

void ExecutionTelemetryCollector::Reset() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_ring.clear();
    m_writeIndex = 0;
    m_full = false;
}

const char* BackendToString(ExecutionBackend b) {
    switch (b) {
        case ExecutionBackend::CPU_AVX512: return "CPU_AVX512";
        case ExecutionBackend::CPU_AVX2: return "CPU_AVX2";
        case ExecutionBackend::CPU_Scalar: return "CPU_Scalar";
        case ExecutionBackend::Vulkan_GEMM: return "Vulkan_GEMM";
        case ExecutionBackend::Vulkan_CooperativeMatrix: return "Vulkan_CooperativeMatrix";
        case ExecutionBackend::DMA_Ring: return "DMA_Ring";
        case ExecutionBackend::StreamRouter: return "StreamRouter";
        case ExecutionBackend::Fallback: return "Fallback";
        default: return "Unknown";
    }
}

const char* QuantToString(QuantFormat q) {
    switch (q) {
        case QuantFormat::F32: return "F32";
        case QuantFormat::F16: return "F16";
        case QuantFormat::BF16: return "BF16";
        case QuantFormat::Q4_0: return "Q4_0";
        case QuantFormat::Q4_1: return "Q4_1";
        case QuantFormat::Q4_K_M: return "Q4_K_M";
        case QuantFormat::Q4_K_S: return "Q4_K_S";
        case QuantFormat::Q5_0: return "Q5_0";
        case QuantFormat::Q5_1: return "Q5_1";
        case QuantFormat::Q6_K: return "Q6_K";
        case QuantFormat::Q8_0: return "Q8_0";
        case QuantFormat::Q8_1: return "Q8_1";
        default: return "Unknown";
    }
}

const char* ResidencyToString(ResidencyTier r) {
    switch (r) {
        case ResidencyTier::Host_Mapped: return "Host_Mapped";
        case ResidencyTier::Host_Materialized: return "Host_Materialized";
        case ResidencyTier::GPU_DeviceLocal: return "GPU_DeviceLocal";
        case ResidencyTier::GPU_Staging: return "GPU_Staging";
        case ResidencyTier::WeightResidencyPool: return "WeightResidencyPool";
        default: return "Unknown";
    }
}

} // namespace Deep2
} // namespace RawrXD
