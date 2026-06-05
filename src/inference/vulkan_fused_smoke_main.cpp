// ============================================================================
// vulkan_fused_smoke_main.cpp — Fused RMSNorm+MatMul Smoke Test
// ============================================================================
//
// Standalone executable: tests the fused kernel that eliminates the
// intermediate VRAM roundtrip between RMSNorm and MatMul.
//
// Usage: RawrXD-VulkanFusedSmoke.exe
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <cmath>
#include <algorithm>

#include "RawrXD_VulkanAccelerator.h"

int main(int /*argc*/, char* /*argv*/[]) {
    printf("[VulkanFusedSmoke] Fused RMSNorm+MatMul smoke test\n");

    rawrxd::VulkanAccelerator& accel = rawrxd::GetVulkanAccelerator();
    if (!accel.Initialize()) {
        printf("[VulkanFusedSmoke] FAIL: Initialize() returned false\n");
        return 1;
    }
    if (!accel.IsReady()) {
        printf("[VulkanFusedSmoke] FAIL: accelerator not ready\n");
        return 1;
    }

    printf("[VulkanFusedSmoke] GPU ready. Loading fused kernel...\n");

    const char* spv_paths[] = {
        "kernels/fused_rmsnorm_matmul.spv",
        "../src/inference/kernels/fused_rmsnorm_matmul.spv",
        "../../src/inference/kernels/fused_rmsnorm_matmul.spv",
        "src/inference/kernels/fused_rmsnorm_matmul.spv",
        "fused_rmsnorm_matmul.spv",
    };
    uint32_t kernel_id = 0;
    for (const char* p : spv_paths) {
        kernel_id = accel.LoadKernel("fused_rmsnorm_matmul", p, 4);
        if (kernel_id != 0) {
            printf("[VulkanFusedSmoke] Kernel loaded from '%s' id=%u\n", p, kernel_id);
            break;
        }
    }
    if (kernel_id == 0) {
        printf("[VulkanFusedSmoke] FAIL: LoadKernel returned 0\n");
        return 1;
    }

    // Test: 1 row, hidden_size=256, output_size=256
    constexpr uint32_t hidden_size  = 256;
    constexpr uint32_t output_size  = 256;
    constexpr uint32_t num_rows     = 1;
    constexpr float    eps        = 1e-6f;

    std::vector<float> host_in(hidden_size, 1.0f);
    std::vector<float> host_gamma(hidden_size, 2.0f);
    std::vector<float> host_w(hidden_size * output_size, 0.0f);
    std::vector<float> host_out(output_size, 0.0f);

    // Initialize weight matrix as identity-like for easy verification
    for (uint32_t i = 0; i < hidden_size; ++i) {
        host_w[i * output_size + i] = 1.0f;
    }

    rawrxd::TensorDesc desc_in{};
    desc_in.name = "fused_in";
    desc_in.format = rawrxd::TensorFormat::F32;
    desc_in.rows = num_rows;
    desc_in.cols = hidden_size;
    desc_in.host_ptr = host_in.data();
    desc_in.size_bytes = host_in.size() * sizeof(float);

    rawrxd::TensorDesc desc_gamma{};
    desc_gamma.name = "fused_gamma";
    desc_gamma.format = rawrxd::TensorFormat::F32;
    desc_gamma.rows = 1;
    desc_gamma.cols = hidden_size;
    desc_gamma.host_ptr = host_gamma.data();
    desc_gamma.size_bytes = host_gamma.size() * sizeof(float);

    rawrxd::TensorDesc desc_w{};
    desc_w.name = "fused_w";
    desc_w.format = rawrxd::TensorFormat::F32;
    desc_w.rows = hidden_size;
    desc_w.cols = output_size;
    desc_w.host_ptr = host_w.data();
    desc_w.size_bytes = host_w.size() * sizeof(float);

    rawrxd::TensorDesc desc_out{};
    desc_out.name = "fused_out";
    desc_out.format = rawrxd::TensorFormat::F32;
    desc_out.rows = num_rows;
    desc_out.cols = output_size;
    desc_out.host_ptr = nullptr;
    desc_out.size_bytes = host_out.size() * sizeof(float);

    rawrxd::GpuTensorHandle h_in    = accel.UploadTensor(desc_in, false);
    rawrxd::GpuTensorHandle h_gamma = accel.UploadTensor(desc_gamma, false);
    rawrxd::GpuTensorHandle h_w     = accel.UploadTensor(desc_w, false);
    rawrxd::GpuTensorHandle h_out   = accel.UploadTensor(desc_out, false);

    if (!h_in.IsValid() || !h_gamma.IsValid() || !h_w.IsValid() || !h_out.IsValid()) {
        printf("[VulkanFusedSmoke] FAIL: tensor upload failed\n");
        return 1;
    }
    printf("[VulkanFusedSmoke] Tensors uploaded. Dispatching fused kernel...\n");

    rawrxd::FusedRMSNormMatMulDesc fused{};
    fused.input          = h_in;
    fused.output         = h_out;
    fused.rmsnorm_weight = h_gamma;
    fused.matmul_weight  = h_w;
    fused.hidden_size    = hidden_size;
    fused.output_size    = output_size;
    fused.eps            = eps;
    fused.num_rows       = num_rows;

    if (!accel.DispatchFusedRMSNormMatMul(fused, kernel_id)) {
        printf("[VulkanFusedSmoke] FAIL: DispatchFusedRMSNormMatMul returned false\n");
        return 1;
    }

    if (!accel.Wait(10'000'000'000ULL)) {
        printf("[VulkanFusedSmoke] FAIL: Wait timed out\n");
        return 1;
    }

    if (!accel.ReadbackTensor(h_out, host_out.data())) {
        printf("[VulkanFusedSmoke] FAIL: ReadbackTensor returned false\n");
        return 1;
    }

    // Validate: input=all-ones, gamma=2.0, weight=identity
    // RMSNorm output = 1.0 * 2.0 = 2.0 for each element
    // MatMul(identity, 2.0) = 2.0 for each element
    bool pass = true;
    float max_err = 0.0f;
    for (size_t i = 0; i < host_out.size(); ++i) {
        float expected = 2.0f;
        float err = std::abs(host_out[i] - expected);
        if (err > max_err) max_err = err;
        if (err > 1e-3f) {
            pass = false;
            if (i < 4) {
                printf("[VulkanFusedSmoke] MISMATCH[%zu]: got %.4f expected %.4f\n",
                       i, host_out[i], expected);
            }
        }
    }

    printf("[VulkanFusedSmoke] max_error=%.6f\n", max_err);
    if (pass) {
        printf("[VulkanFusedSmoke] PASS: Fused pipeline verified (output≈2.0)\n");
    } else {
        printf("[VulkanFusedSmoke] FAIL: output deviation exceeds 1e-3\n");
    }

    accel.Shutdown();
    return pass ? 0 : 1;
}
