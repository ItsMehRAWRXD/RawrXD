#include "vulkan_compute.h"
#include "ggml-quants.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>
#include <limits>

namespace {
constexpr int kQ5K = 13; // GGML_TYPE_Q5_K; fail closed if this changes.

bool referenceGemv(const block_q5_K* w, const float* x,
                   float* y, uint32_t rows, uint32_t cols) {
    const uint32_t blocks = cols / QK_K;
    if (!blocks || cols % QK_K) return false;
    std::vector<float> deq(QK_K);
    for (uint32_t r = 0; r < rows; ++r) {
        const auto* row = w + static_cast<size_t>(r) * blocks;
        double sum = 0.0;
        for (uint32_t b = 0; b < blocks; ++b) {
            dequantize_row_q5_K(row + b, deq.data(), QK_K);
            for (uint32_t j = 0; j < QK_K; ++j)
                sum += static_cast<double>(deq[j]) * x[b * QK_K + j];
        }
        y[r] = static_cast<float>(sum);
    }
    return true;
}
}

int main(int argc, char** argv) {
    uint32_t dispatches = 1;
    if (argc > 1) dispatches = static_cast<uint32_t>(std::stoul(argv[1]));
    const uint64_t rows64 = argc > 2 ? std::stoull(argv[2]) : 1ULL;
    if (rows64 == 0 || rows64 > std::numeric_limits<uint32_t>::max()) return 2;
    const uint32_t rows = static_cast<uint32_t>(rows64);
    constexpr uint32_t cols = 8192; // production K2 Q5_K projection geometry
    constexpr uint32_t blocks = cols / QK_K;
    if (rows64 > std::numeric_limits<size_t>::max() / blocks) return 2;
    const size_t totalBlocks = static_cast<size_t>(rows64) * blocks;
    if (totalBlocks > std::numeric_limits<size_t>::max() / sizeof(block_q5_K)) return 2;
    if (rows64 > std::numeric_limits<size_t>::max() / sizeof(float)) return 2;

    std::mt19937 rng(0x51A5u);
    std::vector<float> source(cols);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    for (float& v : source) v = dist(rng);
    std::vector<block_q5_K> weights(totalBlocks);
    for (uint32_t r = 0; r < rows; ++r)
        quantize_row_q5_K_ref(source.data(), weights.data() + static_cast<size_t>(r) * blocks, cols);
    // Use a different deterministic activation so qh high bits and signed
    // products are both exercised.
    for (float& v : source) v = dist(rng);
    std::vector<float> reference(rows), gpu(rows);
    if (!referenceGemv(weights.data(), source.data(), reference.data(), rows, cols))
        return 2;

    Deep2::VulkanCompute vc(0);
    if (!vc.initialize()) {
        std::fprintf(stderr, "HARNESS=deep2_q5k_gpu_stress INIT=FAIL\n");
        return 3;
    }
    if (kQ5K != 13) return 4;
    Deep2::VulkanCompute::DeviceBuf in{}, out{};
    const VkDeviceSize inBytes = static_cast<VkDeviceSize>(cols) * sizeof(float);
    const VkDeviceSize outBytes = static_cast<VkDeviceSize>(rows) * sizeof(float);
    const auto usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
                       VK_BUFFER_USAGE_TRANSFER_DST_BIT |
                       VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    if (!vc.createBufferPublic(inBytes, usage,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, in) ||
        !vc.createBufferPublic(outBytes, usage,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, out) ||
        !vc.UploadVector(in, source.data(), cols)) {
        std::fprintf(stderr, "HARNESS=deep2_q5k_gpu_stress ALLOC_OR_UPLOAD=FAIL\n");
        return 5;
    }

    std::printf("HARNESS=deep2_q5k_gpu_stress GPU=%s TYPE=%d ROWS=%u COLS=%u DISPATCHES=%u\n",
                vc.physicalInfo().name.c_str(), kQ5K, rows, cols, dispatches);
    for (uint32_t i = 0; i < dispatches; ++i) {
        std::fill(gpu.begin(), gpu.end(), 0.0f);
        const bool ok = vc.DispatchGemvQuant(kQ5K, weights.data(),
            weights.size() * sizeof(weights[0]), in, out, rows, cols, 0);
        if (!ok || !vc.DownloadVector(out, gpu.data(), rows)) {
            std::printf("DISPATCH_INDEX=%u GPU_SUBMIT_OR_WAIT=FAIL DEVICE_LOST=%d\n",
                        i, vc.DeviceIsLost() ? 1 : 0);
            return 10;
        }
        float absErr = 0.0f, relErr = 0.0f;
        uint32_t mismatch = UINT32_MAX;
        for (uint32_t r = 0; r < rows; ++r) {
            const float a = std::fabs(gpu[r] - reference[r]);
            const float rel = a / std::max(1.0f, std::fabs(reference[r]));
            if (a > absErr) { absErr = a; mismatch = r; }
            relErr = std::max(relErr, rel);
        }
        std::printf("DISPATCH_INDEX=%u QUEUE_COMPLETE=1 GPU=%g REF=%g "
                    "MAX_ABS=%g MAX_REL=%g FIRST_MISMATCH=%u DEVICE_LOST=%d\n",
                    i, gpu[0], reference[0], absErr, relErr, mismatch,
                    vc.DeviceIsLost() ? 1 : 0);
        if (!std::isfinite(gpu[0]) || absErr > 1e-2f || relErr > 1e-3f)
            return 11;
    }
    std::printf("Q5K_STRESS_PASS=1 DISPATCHES=%u\n", dispatches);
    return 0;
}
