// deep2_dualgpu_bridge_demo.cpp -- REAL dual-GPU bridge plumbing harness (item b).
//
// Proves, in ONE process, using the ACTUAL VulkanCompute and the user-supplied
// deep2::DualGpuBridge:
//   (1) two distinct discrete GPUs initialised in one process (R9700 + RX 7800 XT),
//   (2) a REAL contiguous-layer plan from real VRAM budgets (fail-closed if no fit),
//   (3) a REAL per-device GPU command submission in each stage (scheduling/sync),
//   (4) a REAL host-staged cross-device transfer of the hidden-state vector at the
//       layer boundary, BYTE-VERIFIED and measured (activation bytes + wall ms).
// Honest scope: run_layers issues a real per-device GPU submit (a scheduling probe);
// it does NOT execute real transformer ops per layer. Replacing that with real
// per-layer quantised dispatch (a device-aware QuantDot) is the remaining Executor
// refactor, documented in the receipts. No transfer/kernel is fabricated.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "vulkan_compute.h"
#include "dual_gpu_bridge.hpp"

using deep2::DualGpuBridge; using deep2::Backend; using deep2::Plan;
using deep2::make_contiguous_plan; using deep2::DeviceMemory; using deep2::DeviceId;

static uint64_t LargestDeviceLocal(const VulkanDeviceInfo& di) {
    uint64_t best = 0;
    for (uint32_t i = 0; i < di.memory_props.memoryHeapCount; ++i) {
        const auto& h = di.memory_props.memoryHeaps[i];
        bool local = (h.flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) != 0;
        if (local && h.size > best) best = h.size;
    }
    return best;
}

int main() {
    // ---- pick the two discrete AMD GPUs by name from the real enumeration ----
    auto devs = VulkanCompute::EnumerateDevices();
    int idxA = -1, idxB = -1;  // A=R9700, B=RX 7800 XT
    for (const auto& d : devs) {
        if (d.name.find("R9700") != std::string::npos && idxA < 0) idxA = d.index;
        if (d.name.find("7800 XT") != std::string::npos && idxB < 0) idxB = d.index;
    }
    if (idxA < 0 || idxB < 0) { std::printf("BRIDGE_FAIL: two discrete GPUs not enumerated (A=%d B=%d)\n", idxA, idxB); return 1; }
    std::printf("enumerated: A_idx=%d (R9700)  B_idx=%d (RX 7800 XT)\n", idxA, idxB);

    // ---- two real Vulkan contexts in ONE process ----
    VulkanCompute a, b;
    a.SetPreferredDeviceIndex(idxA); b.SetPreferredDeviceIndex(idxB);
    if (!a.Initialize() || !b.Initialize()) { std::printf("BRIDGE_FAIL: dual Vulkan init failed\n"); return 1; }
    const uint64_t capA = LargestDeviceLocal(a.GetDeviceInfo());
    const uint64_t capB = LargestDeviceLocal(b.GetDeviceInfo());
    std::printf("device A active=%d name=%s vram=%.2f GiB\n", a.GetActiveDeviceIndex(),
                a.GetDeviceInfo().device_name.c_str(), capA / 1073741824.0);
    std::printf("device B active=%d name=%s vram=%.2f GiB\n", b.GetActiveDeviceIndex(),
                b.GetDeviceInfo().device_name.c_str(), capB / 1073741824.0);

    // ---- REAL planner: tinyllama-1.1b (22 blocks, real 668,788,096 B) ----
    const uint32_t layers = 22;
    const uint64_t model_bytes = 668788096ULL;         // real tinyllama Q4_K_M
    const uint64_t per_layer = model_bytes / layers;   // uniform approximation (documented)
    std::vector<uint64_t> w(layers, per_layer);
    const uint64_t safety = 1ULL << 30;                 // 1 GiB scratch/KV headroom
    DeviceMemory dA{ (DeviceId)idxA, capA, 0 };
    DeviceMemory dB{ (DeviceId)idxB, capB, 0 };
    Plan plan;
    try {
        plan = make_contiguous_plan(layers, w, { dA, dB }, safety);  // fail-closed inside
    } catch (const std::exception& e) {
        std::printf("BRIDGE_FAIL: planner rejected resident split: %s\n", e.what()); return 1;
    }
    for (const auto& s : plan.stages)
        std::printf("plan stage: layers [%u,%u) on device %u\n", s.first, s.end, s.device);
    std::printf("plan: layers=%u staged_devices=%zu (fail-closed validated)\n", plan.layer_count, plan.stages.size());

    // ---- hidden-state boundary tensor (tinyllama embd=2048 f32 = 8 KiB), device-local ----
    const size_t H = 2048, bytes = H * sizeof(float);
    VkBuffer bufA = nullptr, bufB = nullptr; VkDeviceMemory memA = nullptr, memB = nullptr;
    if (!a.AllocateBuffer(bytes, bufA, memA) || !b.AllocateBuffer(bytes, bufB, memB)) {
        std::printf("BRIDGE_FAIL: device-local buffer allocation failed\n"); return 1;
    }
    std::vector<float> hidden(H);
    for (size_t i = 0; i < H; ++i) hidden[i] = (float)((i * 2654435761u) % 257u) - 128.0f; // deterministic
    a.CopyHostToBuffer(hidden.data(), bufA, bytes);  // real host->device (staging + barriers)

    // ---- real backends ----
    uint64_t transferred_bytes = 0; int transfers = 0; bool verified = true; long devA_sub0 = a.GetGpuCounters().submits, devB_sub0 = b.GetGpuCounters().submits;
    Backend bk;
    bk.synchronize = [&](DeviceId d) {
        VulkanCompute& dev = (d == (DeviceId)idxA) ? a : b;
        if (!dev.FlushAsyncCommands()) throw std::runtime_error("synchronize failed (device work not complete)");
    };
    bk.run_layers = [&](DeviceId d, uint32_t begin, uint32_t end) {
        VulkanCompute& dev = (d == (DeviceId)idxA) ? a : b;
        // REAL per-device GPU submission (single-time command; scheduling/sync probe).
        if (!dev.ExecuteSingleTimeCommands([](VkCommandBuffer) {}))
            throw std::runtime_error("run_layers: real GPU submit failed on device");
        std::printf("  run_layers dev=%u [%u,%u): real GPU submit ok (probe)\n", d, begin, end);
    };
    bk.activate_state_owner = [&](DeviceId d, uint32_t first) {
        std::printf("  activate_state_owner dev=%u first=%u (single authoritative owner)\n", d, first);
    };
    bk.transfer_hidden = [&](DeviceId src, DeviceId dst, size_t boundary) {
        VulkanCompute& s = (src == (DeviceId)idxA) ? a : b;
        VulkanCompute& t = (dst == (DeviceId)idxA) ? a : b;
        VkBuffer sb = (src == (DeviceId)idxA) ? bufA : bufB;
        VkBuffer tb = (dst == (DeviceId)idxA) ? bufA : bufB;
        std::vector<float> via_host(H);
        s.CopyBufferToHost(sb, via_host.data(), bytes);   // REAL device->host barrier+stage
        t.CopyHostToBuffer(via_host.data(), tb, bytes);    // REAL host->device barrier+stage
        // byte-verify on the destination device
        std::vector<float> back(H);
        t.CopyBufferToHost(tb, back.data(), bytes);
        bool ok = (std::memcmp(via_host.data(), back.data(), bytes) == 0);
        if (!ok) verified = false;
        transferred_bytes += bytes; transfers++;
        std::printf("  transfer_hidden %u->%u @L%zu: %zu bytes host-staged, byte-identical=%s\n",
                    src, dst, boundary, bytes, ok ? "yes" : "NO");
    };

    // ---- orchestrated dual-GPU forward (planner + boundary sync + transfer) ----
    DualGpuBridge bridge(plan, bk);
    try { bridge.forward(); }
    catch (const std::exception& e) { std::printf("BRIDGE_FAIL: forward threw: %s\n", e.what()); return 1; }

    const auto& st = bridge.stats();
    long devA_sub = a.GetGpuCounters().submits - devA_sub0;
    long devB_sub = b.GetGpuCounters().submits - devB_sub0;
    std::printf("\nBRIDGE_SUMMARY transfers=%d activation_bytes=%llu transfer_wall_ms=%.3f\n",
                transfers, (unsigned long long)transferred_bytes, st.wall_ms);
    std::printf("per-device submits this run: A(R9700)=%ld  B(7800XT)=%ld\n", devA_sub, devB_sub);
    // end-to-end data integrity: buffer on B must equal the original hidden vector
    std::vector<float> finalB(H); b.CopyBufferToHost(bufB, finalB.data(), bytes);
    bool e2e = (std::memcmp(finalB.data(), hidden.data(), bytes) == 0);
    std::printf("end-to-end hidden A->B byte-identical to source: %s\n", e2e ? "YES" : "NO");
    std::printf("BRIDGE_VERDICT=%s\n", (verified && e2e && transfers >= 1 && devA_sub > 0 && devB_sub > 0) ? "PASS" : "FAIL");
    return 0;
}
