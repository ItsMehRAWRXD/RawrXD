// RAWRXD_DEEP2_GPU_QUANT_DOT_001 - implementation.
//
// GPU-first dispatch with a real CPU fallback. The GPU kernel lives in
// RawrXD::Deep2::QuantDot (RawrXD_GPU.obj) and is driven through the Vulkan
// wrapper in src/vulkan_compute.cpp. When the GPU path cannot run, this layer
// falls back to the caller's CpuDot so the caller still gets REAL numbers.
//
// Honest accounting: DotBlocked reports which path actually ran via
// LastReceipt(), and the executor increments gpu_calls_ / cpu_calls_ from that
// truth rather than from intent. A GPU failure is therefore visible as a
// cpu-run, not as a silent pretend-success.

#include "quant_dot_dispatch.hpp"

#include "vulkan_compute.h"     // real GPU device, already proven correct

namespace RawrXD {
namespace Deep2 {
namespace QuantDot {

namespace {

bool g_force_cpu = false;
Receipt g_receipt;

VulkanCompute& Gpu()
{
    static VulkanCompute gpu;              // one device for the process
    static bool initialised = false;
    if (!initialised) {
        initialised = true;
        gpu.Initialize();                  // false stays false; receipt explains
    }
    return gpu;
}

} // namespace

void SetForceCpu(bool force) { g_force_cpu = force; }
bool ForceCpu() { return g_force_cpu; }

const Receipt& LastReceipt() { return g_receipt; }

bool DotBlocked(int kind,
                const void* wBytes, size_t wBytesCount,
                const float* x, size_t n_in,
                float* y, size_t n_out,
                const CpuDot& cpu,
                const void* q8_interleaved,
                size_t q8_bytes)
{
    g_receipt = Receipt{};

    if (kind != 0 && kind != 1) {
        g_receipt.fallback_reason = "unsupported kind";
        return false;
    }
    if (!wBytes || !x || !y || n_in == 0 || n_out == 0) {
        g_receipt.fallback_reason = "bad arguments";
        return false;
    }
    if (cpu == nullptr) {
        g_receipt.fallback_reason = "no CPU fallback supplied";
        return false;
    }

    // The caller wants the CPU path (parity harness).
    if (g_force_cpu) {
        for (size_t j = 0; j < n_out; ++j) {
            const uint8_t* row =
                static_cast<const uint8_t*>(wBytes) + j * (n_in / 256) *
                (kind == 0 ? 144u : 210u);
            y[j] = cpu(row, x, j);
        }
    g_receipt.used_gpu = false;
        g_receipt.cpu_rows = n_out;
        g_receipt.fallback_reason = "force_cpu";
        return false;
    }

    // GPU path. The packed kernel is proven; a dispatch failure is reported.
    VulkanCompute& gpu = Gpu();
    const size_t n_blocks = n_in / 256;
    const bool gpuOk = q8_interleaved && q8_bytes >= n_blocks * 273 * sizeof(float)
        ? gpu.ExecuteQuantDot(wBytes, wBytesCount,
                              q8_interleaved, q8_bytes,
                              y, n_out * sizeof(float),
                              n_out, n_in, n_blocks, kind)
        : false;
    if (gpuOk) {
        g_receipt.used_gpu = true;
        g_receipt.gpu_rows = n_out;
        return true;
    }

    // GPU unavailable: use the CPU fallback so the caller still gets real math.
    for (size_t j = 0; j < n_out; ++j) {
        const uint8_t* row =
            static_cast<const uint8_t*>(wBytes) + j * (n_in / 256) *
            (kind == 0 ? 144u : 210u);
        y[j] = cpu(row, x, j);
    }
    g_receipt.used_gpu = false;
    g_receipt.cpu_rows = n_out;
    g_receipt.fallback_reason = "gpu dispatch failed";
    return false;
}

} } }
