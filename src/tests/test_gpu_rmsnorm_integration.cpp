// ============================================================================
// test_gpu_rmsnorm_integration.cpp — Sovereign Hot Lap
// ============================================================================
//
// End-to-end integration: real GGUF weights → GPU RMSNorm → verification.
//
// Pipeline:
//   1. EngineGGUFLoader mmap's the model file (zero-copy Fuel Line)
//   2. Extract blk.0.attn_norm.weight tensor pointer + metadata
//   3. VulkanAccelerator uploads weight + synthetic input to VRAM
//   4. DispatchRMSNorm executes on GPU
//   5. Readback + CPU reference comparison
//
// Build via CMake target: RawrXD-GPU-RMSNorm-Integration
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <vector>
#include <string>

#include "engine/gguf_core.h"
#include "inference/RawrXD_VulkanAccelerator.h"

// ============================================================================
// CPU reference RMSNorm (for verification)
// ============================================================================
static void cpu_rmsnorm(const float* x, const float* w, float* y,
                        uint32_t n, float eps) {
    float ss = 0.0f;
    for (uint32_t i = 0; i < n; ++i) ss += x[i] * x[i];
    float scale = 1.0f / std::sqrt(ss / static_cast<float>(n) + eps);
    for (uint32_t i = 0; i < n; ++i) y[i] = w[i] * (x[i] * scale);
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    const char* model_path = (argc > 1) ? argv[1] : "d:\\models\\ministral-3b-f32.gguf";

    fprintf(stderr, "[HOT LAP] Sovereign GPU RMSNorm Integration Test\n");
    fprintf(stderr, "[HOT LAP] Model: %s\n", model_path);

    // ------------------------------------------------------------------------
    // 1. Fuel Line: mmap GGUF file
    // ------------------------------------------------------------------------
    EngineGGUFLoader loader;
    if (!loader.load(model_path)) {
        fprintf(stderr, "[HOT LAP] FAIL: EngineGGUFLoader::load('%s') failed\n", model_path);
        return 1;
    }
    fprintf(stderr, "[HOT LAP] PASS: GGUF mapped, %zu tensors found\n", loader.tensors.size());

    // ------------------------------------------------------------------------
    // 2. Find blk.0.attn_norm.weight
    // ------------------------------------------------------------------------
    TensorInfo* norm_tensor = loader.getTensor("blk.0.attn_norm.weight");
    if (!norm_tensor) {
        fprintf(stderr, "[HOT LAP] FAIL: blk.0.attn_norm.weight not found in model\n");
        loader.unload();
        return 1;
    }
    fprintf(stderr, "[HOT LAP] PASS: Found blk.0.attn_norm.weight "
            "(type=%d, dims=%zu, size=%zu bytes, offset=%llu)\n",
            (int)norm_tensor->type, norm_tensor->dims.size(),
            norm_tensor->size, (unsigned long long)norm_tensor->offset);

    // Determine hidden_size from dims
    uint32_t hidden_size = 0;
    if (!norm_tensor->dims.empty()) {
        hidden_size = static_cast<uint32_t>(norm_tensor->dims[0]);
    }
    if (hidden_size == 0) {
        fprintf(stderr, "[HOT LAP] FAIL: hidden_size is zero\n");
        loader.unload();
        return 1;
    }
    fprintf(stderr, "[HOT LAP] hidden_size = %u\n", hidden_size);

    // ------------------------------------------------------------------------
    // 3. Init Vulkan Accelerator
    // ------------------------------------------------------------------------
    rawrxd::VulkanAccelerator& accel = rawrxd::GetVulkanAccelerator();
    if (!accel.Initialize()) {
        fprintf(stderr, "[HOT LAP] FAIL: VulkanAccelerator::Initialize() failed\n");
        loader.unload();
        return 1;
    }
    fprintf(stderr, "[HOT LAP] PASS: VulkanAccelerator initialized\n");

    // ------------------------------------------------------------------------
    // 4. Prepare host buffers
    // ------------------------------------------------------------------------
    std::vector<float> host_x(hidden_size);
    std::vector<float> host_w(hidden_size);
    std::vector<float> host_y(hidden_size, 0.0f);
    std::vector<float> ref_y(hidden_size, 0.0f);

    // Fill with deterministic pattern
    for (uint32_t i = 0; i < hidden_size; ++i) {
        host_x[i] = static_cast<float>(i + 1) * 0.001f;
    }

    // Copy weight from GGUF mmap (handle F32 and F16)
    if (norm_tensor->type == GGML_RXD_TYPE_F32) {
        const float* src = reinterpret_cast<const float*>(norm_tensor->data);
        for (uint32_t i = 0; i < hidden_size; ++i) host_w[i] = src[i];
    } else if (norm_tensor->type == GGML_RXD_TYPE_F16) {
        const uint16_t* src = reinterpret_cast<const uint16_t*>(norm_tensor->data);
        for (uint32_t i = 0; i < hidden_size; ++i) {
            uint16_t h = src[i];
            // fp16 -> f32 (simple bit-cast approximation)
            // For production, use proper fp16 conversion
            float sign = (h & 0x8000) ? -1.0f : 1.0f;
            int exp = ((h >> 10) & 0x1F) - 15;
            int mant = h & 0x3FF;
            float f = sign * (1.0f + mant / 1024.0f) * std::pow(2.0f, (float)exp);
            host_w[i] = f;
        }
    } else {
        fprintf(stderr, "[HOT LAP] WARN: Weight type %d not F32/F16; using unit weights\n",
                (int)norm_tensor->type);
        for (uint32_t i = 0; i < hidden_size; ++i) host_w[i] = 1.0f;
    }

    // ------------------------------------------------------------------------
    // 5. Upload tensors to VRAM
    // ------------------------------------------------------------------------
    rawrxd::TensorDesc desc_x{};
    desc_x.name = "input";
    desc_x.format = rawrxd::TensorFormat::F32;
    desc_x.rows = 1;
    desc_x.cols = hidden_size;
    desc_x.host_ptr = host_x.data();
    desc_x.size_bytes = host_x.size() * sizeof(float);

    rawrxd::TensorDesc desc_w{};
    desc_w.name = "weight";
    desc_w.format = rawrxd::TensorFormat::F32;
    desc_w.rows = 1;
    desc_w.cols = hidden_size;
    desc_w.host_ptr = host_w.data();
    desc_w.size_bytes = host_w.size() * sizeof(float);

    rawrxd::TensorDesc desc_y{};
    desc_y.name = "output";
    desc_y.format = rawrxd::TensorFormat::F32;
    desc_y.rows = 1;
    desc_y.cols = hidden_size;
    desc_y.host_ptr = nullptr;
    desc_y.size_bytes = host_y.size() * sizeof(float);

    rawrxd::GpuTensorHandle h_x = accel.UploadTensor(desc_x, false);
    rawrxd::GpuTensorHandle h_w = accel.UploadTensor(desc_w, false);
    rawrxd::GpuTensorHandle h_y = accel.UploadTensor(desc_y, false);

    if (!h_x.IsValid() || !h_w.IsValid() || !h_y.IsValid()) {
        fprintf(stderr, "[HOT LAP] FAIL: Tensor upload failed\n");
        accel.Shutdown();
        loader.unload();
        return 1;
    }
    fprintf(stderr, "[HOT LAP] PASS: Tensors uploaded (x=%u, w=%u, y=%u)\n",
            h_x.id, h_w.id, h_y.id);

    // ------------------------------------------------------------------------
    // 6. Load RMSNorm kernel
    // ------------------------------------------------------------------------
    const char* spv_paths[] = {
        "kernels/rmsnorm.spv",
        "../src/inference/kernels/rmsnorm.spv",
        "../../src/inference/kernels/rmsnorm.spv",
        "src/inference/kernels/rmsnorm.spv",
        "d:/rawrxd/src/inference/kernels/rmsnorm.spv",
    };
    uint32_t kernel_id = 0;
    for (const char* p : spv_paths) {
        kernel_id = accel.LoadKernel("rmsnorm", p, 3);
        if (kernel_id != 0) {
            fprintf(stderr, "[HOT LAP] Kernel loaded from '%s' id=%u\n", p, kernel_id);
            break;
        }
    }
    if (kernel_id == 0) {
        fprintf(stderr, "[HOT LAP] FAIL: LoadKernel failed for all candidate paths\n");
        accel.Shutdown();
        loader.unload();
        return 1;
    }

    // ------------------------------------------------------------------------
    // 7. Dispatch RMSNorm
    // ------------------------------------------------------------------------
    rawrxd::RMSNormDesc rms_desc{};
    rms_desc.input = h_x;
    rms_desc.output = h_y;
    rms_desc.weight = h_w;
    rms_desc.hidden_size = hidden_size;
    rms_desc.eps = 1e-5f;
    rms_desc.num_rows = 1;

    if (!accel.DispatchRMSNorm(rms_desc, kernel_id)) {
        fprintf(stderr, "[HOT LAP] FAIL: DispatchRMSNorm returned false\n");
        accel.Shutdown();
        loader.unload();
        return 1;
    }
    fprintf(stderr, "[HOT LAP] PASS: RMSNorm dispatched\n");

    // ------------------------------------------------------------------------
    // 8. Wait + Readback
    // ------------------------------------------------------------------------
    if (!accel.Wait(10'000'000'000ULL)) {
        fprintf(stderr, "[HOT LAP] FAIL: Wait() timed out\n");
        accel.Shutdown();
        loader.unload();
        return 1;
    }

    std::memset(host_y.data(), 0, host_y.size() * sizeof(float));
    if (!accel.ReadbackTensor(h_y, host_y.data())) {
        fprintf(stderr, "[HOT LAP] FAIL: ReadbackTensor failed\n");
        accel.Shutdown();
        loader.unload();
        return 1;
    }
    fprintf(stderr, "[HOT LAP] PASS: Output readback complete\n");

    // ------------------------------------------------------------------------
    // 9. CPU reference + comparison
    // ------------------------------------------------------------------------
    cpu_rmsnorm(host_x.data(), host_w.data(), ref_y.data(), hidden_size, 1e-5f);

    float max_err = 0.0f;
    uint32_t err_idx = 0;
    for (uint32_t i = 0; i < hidden_size; ++i) {
        float diff = std::fabs(host_y[i] - ref_y[i]);
        if (diff > max_err) { max_err = diff; err_idx = i; }
    }

    fprintf(stderr, "[HOT LAP] Max error = %.6e at index %u\n", max_err, err_idx);
    fprintf(stderr, "[HOT LAP] GPU[0] = %.6f  CPU[0] = %.6f\n", host_y[0], ref_y[0]);

    constexpr float tolerance = 1e-3f;
    bool pass = (max_err <= tolerance);

    // ------------------------------------------------------------------------
    // 10. Cleanup
    // ------------------------------------------------------------------------
    accel.Shutdown();
    loader.unload();

    if (pass) {
        fprintf(stderr, "\n=== HOT LAP PASS: Sovereign GPU RMSNorm verified "
                "(max_err %.6e <= %.6e) ===\n", max_err, tolerance);
        return 0;
    } else {
        fprintf(stderr, "\n=== HOT LAP FAIL: Numerical mismatch "
                "(max_err %.6e > %.6e) ===\n", max_err, tolerance);
        return 1;
    }
}
