// deep2_ucf_bounce_smoke.cpp — BounceChain +RW++ / GenerationMismatch smoke
#include "rawr_uncoherent_object_fabric.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <vector>

using namespace rawr::fabric;

namespace {
struct HostStore {
    std::unordered_map<std::uintptr_t, std::vector<std::uint8_t>> blocks;
    std::uintptr_t next = 0x1000;
};
HostStore g_store;

BackendOps MakeHostOps() {
    BackendOps ops;
    ops.allocate = [](DeviceId, std::uint64_t bytes) -> std::uintptr_t {
        const auto key = g_store.next++;
        g_store.blocks[key].assign(static_cast<size_t>(bytes), 0);
        return key;
    };
    ops.release = [](DeviceId, std::uintptr_t addr, std::uint64_t) {
        g_store.blocks.erase(addr);
    };
    ops.copy = [](DeviceId, std::uintptr_t src, DeviceId, std::uintptr_t dst,
                  std::uint64_t bytes) -> FenceValue {
        auto sit = g_store.blocks.find(src);
        auto dit = g_store.blocks.find(dst);
        if (sit == g_store.blocks.end() || dit == g_store.blocks.end())
            throw std::runtime_error("copy missing block");
        if (sit->second.size() < bytes || dit->second.size() < bytes)
            throw std::runtime_error("copy size");
        std::memcpy(dit->second.data(), sit->second.data(),
                    static_cast<size_t>(bytes));
        return 0;
    };
    ops.wait = [](FenceValue) {};
    return ops;
}
} // namespace

int main() {
    Fabric fabric(MakeHostOps());

    // Opaque discrete accelerators — not ordinal policy.
    DeviceObject a{};
    a.id = 0xA11;
    a.kind = DeviceKind::Accelerator;
    a.capabilities = CapCompute | CapDeviceLocal | CapAsyncCopy;
    a.capacityBytes = 24ull << 30;
    a.usableBytes = 20ull << 30;
    a.localReadBytesPerSec = 960ull << 30;
    a.label = "accel_A";
    fabric.topology().upsertDevice(a);

    DeviceObject b = a;
    b.id = 0xB22;
    b.label = "accel_B";
    fabric.topology().upsertDevice(b);

    DeviceObject host{};
    host.id = 0x100;
    host.kind = DeviceKind::Host;
    host.capabilities = CapHostVisible | CapAsyncCopy;
    host.capacityBytes = 192ull << 30;
    host.usableBytes = 160ull << 30;
    host.label = "host";
    fabric.topology().upsertDevice(host);

    fabric.topology().upsertEdge({0xA11, 0x100, true, false, 32ull << 30, 1000});
    fabric.topology().upsertEdge({0x100, 0xA11, true, false, 32ull << 30, 1000});
    fabric.topology().upsertEdge({0xB22, 0x100, true, false, 32ull << 30, 1000});
    fabric.topology().upsertEdge({0x100, 0xB22, true, false, 32ull << 30, 1000});

    auto weights = fabric.createTensor(4096, true);
    auto state = fabric.createTensor(1024, false);

    const auto wAddr = g_store.next++;
    g_store.blocks[wAddr].assign(4096, 1);
    fabric.attachReplica(weights, 0x100, wAddr, 1);

    const auto sAddr = g_store.next++;
    g_store.blocks[sAddr].assign(1024, 2);
    fabric.attachReplica(state, 0x100, sAddr, 1);

    BounceChain chain(fabric, {0xA11, 0xB22});
    Generation g = 1;
    std::uint32_t hops = 0;
    DeviceId last = 0;

    for (int i = 0; i < 8; ++i) {
        const TensorRef reads[] = {weights};
        g = chain.hop(reads, state, g,
                      [&](DeviceId d, std::span<const PhysicalView>,
                          PhysicalView st) {
                          ++hops;
                          last = d;
                          if (!st || st.generation != g)
                              throw std::runtime_error("view gen");
                          auto& buf = g_store.blocks[st.opaqueAddress];
                          if (!buf.empty()) buf[0] = static_cast<std::uint8_t>(i + 1);
                      });
    }

    // Stale expected must throw GenerationMismatch.
    int mismatch = 0;
    try {
        const TensorRef reads[] = {weights};
        (void)fabric.dispatchRWExpected(
            0xA11, reads, state, g - 1,
            [](DeviceId, std::span<const PhysicalView>, PhysicalView) {});
    } catch (const GenerationMismatch& e) {
        mismatch = 1;
        std::printf("MISMATCH expected=%llu observed=%llu\n",
                    (unsigned long long)e.expected(),
                    (unsigned long long)e.observed());
    }

    const bool pass = (hops == 8) && (g == 9) && mismatch &&
                      (last == 0xB22 || last == 0xA11);
    std::printf("BOUNCE_HOPS=%u GEN=%llu LAST=0x%llx MISMATCH=%d\n", hops,
                (unsigned long long)g, (unsigned long long)last, mismatch);
    std::printf("UCF_BOUNCE_SMOKE=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 2;
}
