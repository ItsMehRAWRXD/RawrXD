// ============================================================================
// vulkan_smoke_main.cpp — Minimal Sovereign Vulkan RMSNorm Smoke Test
// ============================================================================
//
// Standalone executable: no snmalloc, no llama.dll, no heavy inference stack.
// Only links RawrXD_VulkanAccelerator + RawrXD_VulkanShim + vulkan-1.lib.
//
// Usage: RawrXD-VulkanSmoke.exe
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <cmath>
#include <algorithm>

#include "RawrXD_VulkanAccelerator.h"

int main(int /*argc*/, char* /*argv*/[]) {
    printf("[VulkanSmoke] Sovereign Data Plane RMSNorm smoke test\n");

    rawrxd::VulkanAccelerator& accel = rawrxd::GetVulkanAccelerator();
    if (!accel.Initialize()) {
        printf("[VulkanSmoke] FAIL: VulkanAccelerator::Initialize() returned false\n");
        return 1;
    }
    if (!accel.IsReady()) {
        printf("[VulkanSmoke] FAIL: accelerator not ready after init\n");
        return 1;
    }

    printf("[VulkanSmoke] GPU ready. Loading RMSNorm kernel...\n");

    // Try multiple candidate paths for the .spv (build dir vs install dir)
    const char* spv_paths[] = {
        "kernels/rmsnorm.spv",
        "../src/inference/kernels/rmsnorm.spv",
        "../../src/inference/kernels/rmsnorm.spv",
        "src/inference/kernels/rmsnorm.spv",
        "rmsnorm.spv",
    };
    uint32_t kernel_id = 0;
    for (const char* p : spv_paths) {
        kernel_id = accel.LoadKernel("rmsnorm", p, 3);
        if (kernel_id != 0) {
            printf("[VulkanSmoke] Kernel loaded from '%s' id=%u\n", p, kernel_id);
            break;
        }
    }
    if (kernel_id == 0) {
        printf("[VulkanSmoke] FAIL: LoadKernel returned 0 (SPIR-V not found)\n");
        return 1;
    }

    // Synthetic test: 1 row, hidden_size = 256, all-ones input, weight=2.0
    constexpr uint32_t hidden_size = 256;
    constexpr uint32_t num_rows    = 1;
    constexpr float    eps         = 1e-6f;

    std::vector<float> host_in(hidden_size, 1.0f);
    std::vector<float> host_w(hidden_size, 2.0f);
    std::vector<float> host_out(hidden_size, 0.0f);

    rawrxd::TensorDesc desc_in{};
    desc_in.name = "rmsnorm_in";
    desc_in.format = rawrxd::TensorFormat::F32;
    desc_in.rows = num_rows;
    desc_in.cols = hidden_size;
    desc_in.host_ptr = host_in.data();
    desc_in.size_bytes = host_in.size() * sizeof(float);

    rawrxd::TensorDesc desc_w{};
    desc_w.name = "rmsnorm_w";
    desc_w.format = rawrxd::TensorFormat::F32;
    desc_w.rows = 1;
    desc_w.cols = hidden_size;
    desc_w.host_ptr = host_w.data();
    desc_w.size_bytes = host_w.size() * sizeof(float);

    rawrxd::TensorDesc desc_out{};
    desc_out.name = "rmsnorm_out";
    desc_out.format = rawrxd::TensorFormat::F32;
    desc_out.rows = num_rows;
    desc_out.cols = hidden_size;
    desc_out.host_ptr = nullptr;  // device-only output
    desc_out.size_bytes = host_out.size() * sizeof(float);

    rawrxd::GpuTensorHandle h_in  = accel.UploadTensor(desc_in, false);
    rawrxd::GpuTensorHandle h_w   = accel.UploadTensor(desc_w, false);
    rawrxd::GpuTensorHandle h_out = accel.UploadTensor(desc_out, false);

    if (!h_in.IsValid() || !h_w.IsValid() || !h_out.IsValid()) {
        printf("[VulkanSmoke] FAIL: tensor upload failed\n");
        return 1;
    }
    printf("[VulkanSmoke] Tensors uploaded. Dispatching RMSNorm...\n");

    rawrxd::RMSNormDesc rms{};
    rms.input      = h_in;
    rms.output     = h_out;
    rms.weight     = h_w;
    rms.hidden_size = hidden_size;
    rms.eps        = eps;
    rms.num_rows   = num_rows;

    if (!accel.DispatchRMSNorm(rms, kernel_id)) {
        printf("[VulkanSmoke] FAIL: DispatchRMSNorm returned false\n");
        return 1;
    }

    // Synchronize and read back
    if (!accel.Wait(10'000'000'000ULL)) {
        printf("[VulkanSmoke] FAIL: Wait timed out\n");
        return 1;
    }

    if (!accel.ReadbackTensor(h_out, host_out.data())) {
        printf("[VulkanSmoke] FAIL: ReadbackTensor returned false\n");
        return 1;
    }

    // Validate: input=all-ones, weight=2.0
    // RMS = sqrt(mean(1^2) + eps) = sqrt(1 + eps) ≈ 1.0
    // output = x / RMS * weight = 1.0 * 2.0 = 2.0
    bool pass = true;
    float max_err = 0.0f;
    for (size_t i = 0; i < host_out.size(); ++i) {
        float expected = 2.0f;
        float err = std::abs(host_out[i] - expected);
        if (err > max_err) max_err = err;
        if (err > 1e-3f) {
            pass = false;
            if (i < 4) {
                printf("[VulkanSmoke] MISMATCH[%zu]: got %.4f expected %.4f\n",
                       i, host_out[i], expected);
            }
        }
    }

    printf("[VulkanSmoke] max_error=%.6f\n", max_err);
    if (pass) {
        printf("[VulkanSmoke] PASS: RMSNorm pipeline verified (output≈2.0 for all-ones*2.0)\n");
    } else {
        printf("[VulkanSmoke] FAIL: output deviation exceeds 1e-3\n");
    }

    accel.Shutdown();
    return pass ? 0 : 1;
}
