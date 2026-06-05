// ============================================================================
// test_rmsnorm_smoke.cpp — Sovereign Data Plane Smoke Test
// ============================================================================
//
// End-to-end validation of the RMSNorm compute pipeline:
//   1. Initialize VulkanAccelerator
//   2. Upload synthetic input + weight tensors
//   3. Load rmsnorm.spv kernel
//   4. Dispatch RMSNorm
//   5. Readback output and verify against CPU reference
//
// Build: cl.exe /std:c++20 /W3 /EHsc /O2 /I d:\rawrxd\src\inference
//        /I "C:\VulkanSDK\1.4.328.1\Include"
//        test_rmsnorm_smoke.cpp
//        d:\rawrxd\src\inference\RawrXD_VulkanAccelerator.cpp
//        d:\rawrxd\src\inference\RawrXD_VulkanShim.asm
//        /link /LIBPATH:"C:\VulkanSDK\1.4.328.1\Lib" vulkan-1.lib
// ============================================================================

#include "RawrXD_VulkanAccelerator.h"
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <vector>

// ============================================================================
// CPU reference RMSNorm (for verification)
// ============================================================================
static void cpu_rmsnorm(const float* x, const float* w, float* y,
                        uint32_t hidden_size, float eps) {
    for (uint32_t row = 0; row < 1; ++row) {
        float sum_sq = 0.0f;
        for (uint32_t i = 0; i < hidden_size; ++i) {
            float v = x[row * hidden_size + i];
            sum_sq += v * v;
        }
        float rms = std::sqrt(sum_sq / static_cast<float>(hidden_size) + eps);
        float inv_rms = 1.0f / rms;
        for (uint32_t i = 0; i < hidden_size; ++i) {
            y[row * hidden_size + i] = x[row * hidden_size + i] * inv_rms * w[i];
        }
    }
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    fprintf(stderr, "[SMOKE] RMSNorm Data Plane Smoke Test Starting...\n");

    // ------------------------------------------------------------------------
    // 1. Init accelerator
    // ------------------------------------------------------------------------
    rawrxd::VulkanAccelerator accel;
    if (!accel.Initialize()) {
        fprintf(stderr, "[FAIL] VulkanAccelerator::Initialize() failed\n");
        return 1;
    }
    fprintf(stderr, "[PASS] VulkanAccelerator initialized\n");

    // ------------------------------------------------------------------------
    // 2. Prepare synthetic tensors (hidden_size = 256, 1 row)
    // ------------------------------------------------------------------------
    constexpr uint32_t hidden_size = 256;
    constexpr uint32_t num_rows  = 1;
    constexpr float    eps       = 1e-6f;

    std::vector<float> host_x(hidden_size * num_rows);
    std::vector<float> host_w(hidden_size);
    std::vector<float> host_y(hidden_size * num_rows);
    std::vector<float> ref_y(hidden_size * num_rows);

    // Fill with deterministic pattern
    for (uint32_t i = 0; i < hidden_size; ++i) {
        host_x[i] = static_cast<float>(i + 1) * 0.01f;   // 0.01, 0.02, ...
        host_w[i] = 1.0f;                                 // unit weights for simplicity
    }

    // ------------------------------------------------------------------------
    // 3. Upload tensors to VRAM
    // ------------------------------------------------------------------------
    rawrxd::TensorDesc desc_x{};
    desc_x.name = "rmsnorm_input";
    desc_x.format = rawrxd::TensorFormat::F32;
    desc_x.rows = num_rows;
    desc_x.cols = hidden_size;
    desc_x.host_ptr = host_x.data();
    desc_x.size_bytes = host_x.size() * sizeof(float);

    rawrxd::TensorDesc desc_w{};
    desc_w.name = "rmsnorm_weight";
    desc_w.format = rawrxd::TensorFormat::F32;
    desc_w.rows = 1;
    desc_w.cols = hidden_size;
    desc_w.host_ptr = host_w.data();
    desc_w.size_bytes = host_w.size() * sizeof(float);

    rawrxd::TensorDesc desc_y{};
    desc_y.name = "rmsnorm_output";
    desc_y.format = rawrxd::TensorFormat::F32;
    desc_y.rows = num_rows;
    desc_y.cols = hidden_size;
    desc_y.host_ptr = nullptr;  // device-only output
    desc_y.size_bytes = host_y.size() * sizeof(float);

    rawrxd::GpuTensorHandle h_x = accel.UploadTensor(desc_x, false);
    rawrxd::GpuTensorHandle h_w = accel.UploadTensor(desc_w, false);
    rawrxd::GpuTensorHandle h_y = accel.UploadTensor(desc_y, false);

    if (!h_x.IsValid() || !h_w.IsValid() || !h_y.IsValid()) {
        fprintf(stderr, "[FAIL] Tensor upload failed\n");
        accel.Shutdown();
        return 1;
    }
    fprintf(stderr, "[PASS] Tensors uploaded (x=%u, w=%u, y=%u)\n",
            h_x.id, h_w.id, h_y.id);

    // ------------------------------------------------------------------------
    // 4. Load RMSNorm kernel
    // ------------------------------------------------------------------------
    const char* spv_path = "d:\\rawrxd\\src\\inference\\kernels\\rmsnorm.spv";
    uint32_t kernel_id = accel.LoadKernel("rmsnorm", spv_path, 3);
    if (kernel_id == 0) {
        fprintf(stderr, "[FAIL] LoadKernel('%s') failed\n", spv_path);
        accel.Shutdown();
        return 1;
    }
    fprintf(stderr, "[PASS] Kernel loaded id=%u\n", kernel_id);

    // ------------------------------------------------------------------------
    // 5. Dispatch RMSNorm
    // ------------------------------------------------------------------------
    rawrxd::RMSNormDesc rms_desc{};
    rms_desc.input = h_x;
    rms_desc.output = h_y;
    rms_desc.weight = h_w;
    rms_desc.hidden_size = hidden_size;
    rms_desc.eps = eps;
    rms_desc.num_rows = num_rows;

    if (!accel.DispatchRMSNorm(rms_desc, kernel_id)) {
        fprintf(stderr, "[FAIL] DispatchRMSNorm failed\n");
        accel.Shutdown();
        return 1;
    }
    fprintf(stderr, "[PASS] RMSNorm dispatched\n");

    // ------------------------------------------------------------------------
    // 6. Wait for completion
    // ------------------------------------------------------------------------
    if (!accel.Wait(10'000'000'000ULL)) {
        fprintf(stderr, "[FAIL] Wait() timed out\n");
        accel.Shutdown();
        return 1;
    }
    fprintf(stderr, "[PASS] GPU work completed\n");

    // ------------------------------------------------------------------------
    // 7. Readback output
    // ------------------------------------------------------------------------
    std::memset(host_y.data(), 0, host_y.size() * sizeof(float));
    if (!accel.ReadbackTensor(h_y, host_y.data())) {
        fprintf(stderr, "[FAIL] ReadbackTensor failed\n");
        accel.Shutdown();
        return 1;
    }
    fprintf(stderr, "[PASS] Output readback complete\n");

    // ------------------------------------------------------------------------
    // 8. Compute CPU reference and compare
    // ------------------------------------------------------------------------
    cpu_rmsnorm(host_x.data(), host_w.data(), ref_y.data(), hidden_size, eps);

    float max_err = 0.0f;
    uint32_t err_idx = 0;
    for (uint32_t i = 0; i < hidden_size; ++i) {
        float diff = std::fabs(host_y[i] - ref_y[i]);
        if (diff > max_err) {
            max_err = diff;
            err_idx = i;
        }
    }

    fprintf(stderr, "[INFO] Max error = %.6e at index %u\n", max_err, err_idx);
    fprintf(stderr, "[INFO] GPU[0] = %.6f  CPU[0] = %.6f\n", host_y[0], ref_y[0]);
    fprintf(stderr, "[INFO] GPU[%u] = %.6f  CPU[%u] = %.6f\n",
            hidden_size - 1, host_y[hidden_size - 1],
            hidden_size - 1, ref_y[hidden_size - 1]);

    // Tolerance: 1e-4 for float32 reduction on GPU vs CPU
    constexpr float tolerance = 1e-4f;
    if (max_err > tolerance) {
        fprintf(stderr, "[FAIL] Numerical mismatch (max_err %.6e > tolerance %.6e)\n",
                max_err, tolerance);
        accel.Shutdown();
        return 1;
    }

    fprintf(stderr, "[PASS] Numerical verification passed (max_err %.6e <= %.6e)\n",
            max_err, tolerance);

    // ------------------------------------------------------------------------
    // 9. Cleanup
    // ------------------------------------------------------------------------
    accel.Shutdown();
    fprintf(stderr, "[PASS] Shutdown clean\n");
    fprintf(stderr, "\n=== SOVEREIGN DATA PLANE RMSNORM SMOKE TEST: ALL GREEN ===\n");
    return 0;
}
