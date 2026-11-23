// vulkan_int4_program_test.cpp -- Stage 6C: runtime validation of the production
// VulkanInt4Program class (the one Deep2Engine::vulkanInt4Gemv uses). Loads the
// real shader, uploads packed INT4 weights + F16 scales + input, dispatches,
// reads back, and verifies against a CPU INT4 reference. This proves the
// integrated GPU path executes correctly on the R9700, not just standalone.
//
// Build: g++ -std=c++17 -O2 -DRAWRXD_HAVE_ZLIB=0 -I include -I src tools/vulkan_int4_program_test.cpp src/VulkanDevice.cpp -o vi4 -lvulkan-1
// Usage: vi4 [rows=1152] [cols=1024]
#include "VulkanDevice.hpp"
#include "deep2/LossyQuant.hpp"
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace lossy = rawrxd::lossy;

int main(int argc, char** argv) {
    uint32_t rows = argc > 1 ? (uint32_t)std::stoul(argv[1]) : 1152;
    uint32_t cols = argc > 2 ? (uint32_t)std::stoul(argv[2]) : 1024;
    if (cols % 64) { std::fprintf(stderr, "cols must be multiple of 64\n"); return 1; }

    // Build a synthetic matrix + input.
    std::vector<float> W((size_t)rows * cols), x(cols);
    for (size_t i = 0; i < W.size(); ++i) W[i] = (float)((int)(i % 17) - 8) / 100.0f;
    for (size_t i = 0; i < cols; ++i) x[i] = std::sin((double)i) * 0.1f;

    // Quantize to INT4 (the production path).
    lossy::BlockCfg cfg; cfg.bits = lossy::QBits::Int4; cfg.block = 64;
    lossy::QuantTensor q;
    if (!lossy::Quantize(W.data(), W.size(), cfg, q)) { std::fprintf(stderr, "quantize failed\n"); return 1; }

    // CPU INT4 reference (float accumulation, matching the GPU shader's arithmetic).
    auto ref = lossy::Dequantize(q);
    std::vector<float> yCpu(rows);
    for (uint32_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const float* wr = &ref[(size_t)r * cols];
        for (uint32_t c = 0; c < cols; ++c) acc += wr[c] * x[c];
        yCpu[r] = acc;
    }

    // Init Vulkan.
    deep2::VulkanDevice vk;
    if (!vk.init() || vk.gpuCount() == 0) { std::fprintf(stderr, "no Vulkan GPU\n"); return 1; }
    const auto* gpu = vk.primary();
    std::printf("GPU: %s (%llu MB VRAM)\n", gpu->name.c_str(), (unsigned long long)(gpu->vramBytes / (1024 * 1024)));

    // Init the production VulkanInt4Program from the real SPIR-V.
    deep2::VulkanInt4Program prog;
    std::string spv = "shaders/int4_matvec.spv";
    if (!prog.init(gpu->device, spv)) { std::fprintf(stderr, "VulkanInt4Program init failed\n"); return 1; }

    // Host-visible GPU buffers.
    VkBuffer Wbuf, Sbuf, xbuf, ybuf;
    VkDeviceMemory Wmem, Smem, xmem, ymem;
    void *Wm, *Sm, *xm, *ym;
    const VkDeviceSize Wsize = q.packed.size();
    const VkDeviceSize Ssize = q.scales.size() * sizeof(uint16_t);
    const VkDeviceSize xsize = cols * sizeof(float);
    const VkDeviceSize ysize = rows * sizeof(float);
    const VkBufferUsageFlags usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    const VkMemoryPropertyFlags hv = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
    auto mk = [&](VkDeviceSize sz, VkBuffer& b, VkDeviceMemory& m, void*& p) {
        return vk.createBuffer(*gpu, sz, usage, hv, b, m, &p);
    };
    if (!mk(Wsize, Wbuf, Wmem, Wm) || !mk(Ssize, Sbuf, Smem, Sm) ||
        !mk(xsize, xbuf, xmem, xm) || !mk(ysize, ybuf, ymem, ym)) {
        std::fprintf(stderr, "buffer creation failed\n"); return 1;
    }
    std::memcpy(Wm, q.packed.data(), (size_t)Wsize);
    std::memcpy(Sm, q.scales.data(), (size_t)Ssize);
    std::memcpy(xm, x.data(), (size_t)xsize);
    std::memset(ym, 0, (size_t)ysize);

    const uint32_t bpr = cols / 64;
    auto cleanup = [&]() {
        vk.destroyBuffer(*gpu, Wbuf, Wmem); vk.destroyBuffer(*gpu, Sbuf, Smem);
        vk.destroyBuffer(*gpu, xbuf, xmem); vk.destroyBuffer(*gpu, ybuf, ymem);
    };

    // Warmup + dispatch.
    if (!prog.dispatch(*gpu, Wbuf, Sbuf, xbuf, ybuf, rows, cols, bpr)) {
        std::fprintf(stderr, "dispatch failed\n"); cleanup(); return 1;
    }

    // Readback + parity.
    std::vector<float> y(rows);
    std::memcpy(y.data(), ym, (size_t)ysize);
    double maxDiff = 0.0;
    for (uint32_t r = 0; r < rows; ++r)
        maxDiff = std::max(maxDiff, (double)std::fabs(y[r] - yCpu[r]));
    std::printf("RESULT rows=%u cols=%u maxDiff=%g %s\n", rows, cols, maxDiff,
                maxDiff < 1e-2 ? "PASS" : "FAIL");

    // Timed loop.
    const uint32_t steps = 100;
    auto t0 = std::chrono::steady_clock::now();
    for (uint32_t s = 0; s < steps; ++s)
        if (!prog.dispatch(*gpu, Wbuf, Sbuf, xbuf, ybuf, rows, cols, bpr)) { std::fprintf(stderr, "dispatch fail\n"); break; }
    auto t1 = std::chrono::steady_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();
    std::printf("THROUGHPUT %u dispatches in %.4fs = %.1f matvec/s\n",
                steps, sec, sec > 0 ? steps / sec : 0.0);

    cleanup();
    prog.destroy(gpu->device);
    vk.shutdown();
    return maxDiff < 1e-3 ? 0 : 1;
}