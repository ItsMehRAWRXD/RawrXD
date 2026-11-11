// ============================================================================
// deep2_step04_wiring_check.cpp
// ============================================================================
// Compile-time check of the executor wiring. ModelGenieExecutor.cpp now routes
// its Q4_K / Q6_K projection through RawrXD::Deep2::QuantDot::DotBlocked. The
// full executor cannot be linked here (its generated IR headers live in a
// model-specific worktree), so this translation unit reproduces the exact call
// with the exact argument types used at that call site. If the binding is
// wrong, this fails to compile.
// ============================================================================
#include <cstdint>
#include <vector>

#include "quant_dot_dispatch.hpp"

// Mirrors the executor's DotBlocked wiring exactly:
//   const int kind = (type == Q4_K) ? 0 : 1;
//   QuantDot::CpuDot cpu_dot = [&](const uint8_t* row, const void*, size_t nb) { ... };
//   if (QuantDot::DotBlocked(kind, weight, rows*rowBytes, act, in, out, rows, cpu_dot)) { ... }
namespace WiringCheck {

bool ExecutorDotBlocked(int kind, const uint8_t* weight, size_t rowBytes,
                        const float* act, size_t in, float* out, size_t rows,
                        float (*cpu_row_dot)(const uint8_t*, size_t, size_t),
                        std::vector<float>& /*q8storage*/,
                        bool* usedGpu)
{
    RawrXD::Deep2::QuantDot::CpuDot cpu_dot =
        [cpu_row_dot](const uint8_t* row, const void*, size_t nb) -> float {
            return cpu_row_dot(row, nb, 0u);
        };
    if (RawrXD::Deep2::QuantDot::DotBlocked(
            kind, weight, rows * rowBytes, act, in, out, rows, cpu_dot)) {
        if (usedGpu) *usedGpu = true;
        return true;
    }
    if (usedGpu) *usedGpu = false;
    return true;
}

// Also exercise the counters the executor must consult to report the path.
const char* ReportPath() {
    using namespace RawrXD::Deep2::QuantDot;
    const Stats& s = GetStats();
    if (s.gpu_calls > 0 && s.cpu_calls == 0 && FallbackReason().empty())
        return "gpu";
    return FallbackReason().empty() ? "gpu" : "cpu";
}

}  // namespace WiringCheck
