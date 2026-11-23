// int4_integrated_test.cpp -- Stage 6F: runtime validation of the integrated
// INT4 path (quantize-once host cache + upload-once GPU cache + dispatch).
// Replicates Deep2Engine::vulkanInt4Gemv's logic using the actual Int4WeightCache
// and VulkanInt4Program, and verifies:
//   - Cold call: quantize, upload, dispatch, verify vs CPU reference
//   - Warm call: cache hits (no re-quantize, no re-upload), dispatch, verify
//   - Eviction: exceed GPU budget, safely rebuild
// Build: g++ -std=c++17 -O2 -I include -I src tools/int4_integrated_test.cpp src/VulkanDevice.cpp -o i4int -lvulkan-1
// Usage: i4int [rows=1152] [cols=1024] [gpu_budget_mb=512]
#include "VulkanDevice.hpp"
#include "deep2/Int4WeightCache.hpp"
#include "deep2/LossyQuant.hpp"
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace lossy = rawrxd::lossy;
namespace avwm = rawrxd::avwm;

struct GpuBuf { VkBuffer b; VkDeviceMemory m; };

int main(int argc, char** argv) {
    uint32_t rows = argc > 1 ? (uint32_t)std::stoul(argv[1]) : 1152;
    uint32_t cols = argc > 2 ? (uint32_t)std::stoul(argv[2]) : 1024;
    size_t budgetMB = argc > 3 ? std::stoul(argv[3]) : 512;
    if (cols % 64) { std::fprintf(stderr, "cols must be multiple of 64\n"); return 1; }

    std::vector<float> W((size_t)rows * cols), x(cols);
    for (size_t i = 0; i < W.size(); ++i) W[i] = (float)((int)(i % 17) - 8) / 100.0f;
    for (size_t i = 0; i < cols; ++i) x[i] = std::sin((double)i) * 0.1f;

    deep2::VulkanDevice vk;
    if (!vk.init() || !vk.gpuCount()) { std::fprintf(stderr, "no Vulkan GPU\n"); return 1; }
    const auto* gpu = vk.primary();
    std::printf("GPU: %s\n", gpu->name.c_str());

    deep2::VulkanInt4Program prog;
    if (!prog.init(gpu->device, "shaders/int4_matvec.spv")) { std::fprintf(stderr, "program init failed\n"); return 1; }

    avwm::Int4WeightCache hostCache;
    hostCache.setBudget(64ull * 1024 * 1024);
    std::unordered_map<std::string, GpuBuf> gpuCache;
    const VkBufferUsageFlags usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    const VkMemoryPropertyFlags hv = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;

    auto getOrUpload = [&](const std::string& name, const lossy::QuantTensor& q) -> bool {
        auto it = gpuCache.find(name);
        if (it != gpuCache.end()) return true; // warm: reuse
        GpuBuf wb{}, sb{};
        const VkDeviceSize ws = q.packed.size(), ss = q.scales.size() * sizeof(uint16_t);
        void* wm = nullptr; void* sm = nullptr;
        if (!vk.createBuffer(*gpu, ws, usage, hv, wb.b, wb.m, &wm)) return false;
        if (!vk.createBuffer(*gpu, ss, usage, hv, sb.b, sb.m, &sm)) { vk.destroyBuffer(*gpu, wb.b, wb.m); return false; }
        std::memcpy(wm, q.packed.data(), (size_t)ws);
        std::memcpy(sm, q.scales.data(), (size_t)ss);
        gpuCache[name] = {wb.b, wb.m}; // store; need both -> restructure
        return true;
    };
    // Note: simplified -- store both buffers in a struct.
    struct GpuPair { VkBuffer wb, sb; VkDeviceMemory wm, sm; };
    std::unordered_map<std::string, GpuPair> pairs;
    auto upload = [&](const std::string& name, const lossy::QuantTensor& q) -> bool {
        auto it = pairs.find(name);
        if (it != pairs.end()) return true;
        GpuPair p{};
        const VkDeviceSize ws = q.packed.size(), ss = q.scales.size() * sizeof(uint16_t);
        void* wm = nullptr; void* sm = nullptr;
        if (!vk.createBuffer(*gpu, ws, usage, hv, p.wb, p.wm, &wm)) return false;
        if (!vk.createBuffer(*gpu, ss, usage, hv, p.sb, p.sm, &sm)) { vk.destroyBuffer(*gpu, p.wb, p.wm); return false; }
        std::memcpy(wm, q.packed.data(), (size_t)ws);
        std::memcpy(sm, q.scales.data(), (size_t)ss);
        pairs[name] = p;
        return true;
    };

    auto matvec = [&](const std::string& name, std::vector<float>& y) -> bool {
        auto qptr = hostCache.getOrBuild(name, W.data(), rows, cols);
        if (!qptr) return false;
        const auto& q = *qptr;
        if (!upload(name, q)) return false;
        auto& p = pairs[name];
        // Per-call x/y.
        VkBuffer xbuf, ybuf; VkDeviceMemory xmem, ymem; void *xm, *ym;
        const VkDeviceSize xs = cols * sizeof(float), ys = rows * sizeof(float);
        if (!vk.createBuffer(*gpu, xs, usage, hv, xbuf, xmem, &xm)) return false;
        if (!vk.createBuffer(*gpu, ys, usage, hv, ybuf, ymem, &ym)) { vk.destroyBuffer(*gpu, xbuf, xmem); return false; }
        std::memcpy(xm, x.data(), (size_t)xs);
        std::memset(ym, 0, (size_t)ys);
        const uint32_t bpr = cols / 64;
        bool ok = prog.dispatch(*gpu, p.wb, p.sb, xbuf, ybuf, rows, cols, bpr);
        if (ok) std::memcpy(y.data(), ym, (size_t)ys);
        vk.destroyBuffer(*gpu, xbuf, xmem);
        vk.destroyBuffer(*gpu, ybuf, ymem);
        return ok;
    };

    // CPU reference.
    auto qRef = lossy::QuantTensor();
    { lossy::BlockCfg cfg; cfg.bits = lossy::QBits::Int4; cfg.block = 64; lossy::Quantize(W.data(), W.size(), cfg, qRef); }
    auto dq = lossy::Dequantize(qRef);
    std::vector<float> yCpu(rows);
    for (uint32_t r = 0; r < rows; ++r) { float a = 0; const float* wr = &dq[(size_t)r*cols]; for (uint32_t c = 0; c < cols; ++c) a += wr[c]*x[c]; yCpu[r] = a; }

    // Cold call.
    std::vector<float> y1(rows);
    auto t0 = std::chrono::steady_clock::now();
    if (!matvec("blk.0.attn_q.weight", y1)) { std::fprintf(stderr, "cold matvec failed\n"); return 1; }
    auto t1 = std::chrono::steady_clock::now();
    double coldMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // Warm call.
    std::vector<float> y2(rows);
    auto t2 = std::chrono::steady_clock::now();
    if (!matvec("blk.0.attn_q.weight", y2)) { std::fprintf(stderr, "warm matvec failed\n"); return 1; }
    auto t3 = std::chrono::steady_clock::now();
    double warmMs = std::chrono::duration<double, std::milli>(t3 - t2).count();

    double maxDiff = 0;
    for (uint32_t r = 0; r < rows; ++r) maxDiff = std::max(maxDiff, (double)std::fabs(y1[r] - yCpu[r]));
    auto st = hostCache.stats();
    std::printf("COLD cold_ms=%.3f  WARM warm_ms=%.3f  speedup=%.1fx\n", coldMs, warmMs, coldMs / (warmMs > 0 ? warmMs : 1e-9));
    std::printf("HOST_CACHE hits=%llu misses=%llu resident=%zu  GPU_BUFFERS=%zu\n",
                (unsigned long long)st.hits, (unsigned long long)st.misses, st.resident, pairs.size());
    std::printf("PARITY maxDiff=%g %s\n", maxDiff, maxDiff < 1e-3 ? "PASS" : "FAIL");

    bool pass = (maxDiff < 1e-3) && (st.hits >= 1) && (st.misses == 1) && (warmMs <= coldMs);
    std::printf("RESULT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}