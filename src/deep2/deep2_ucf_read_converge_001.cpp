// deep2_ucf_read_converge_001.cpp — UCF_READ_CONVERGE_001
//
// Zipline read: B requests G6 while A holds authoritative G7 →
//   receipt(requested=6, acquired=7), execute immediately.
// Write: reserve current+1 → publish only on commit.
// Strict: acquireExpected still rejects stale expected.
#include "rawr_uncoherent_object_fabric.hpp"
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <vector>

using namespace rawr::fabric;

namespace {
struct Store {
    std::unordered_map<std::uintptr_t, std::vector<std::uint8_t>> blocks;
    std::uintptr_t next = 0x1000;
};
Store g;

BackendOps MakeOps() {
    BackendOps ops;
    ops.allocate = [](DeviceId, std::uint64_t bytes) -> std::uintptr_t {
        const auto key = g.next++;
        g.blocks[key].assign(static_cast<size_t>(bytes), 0);
        return key;
    };
    ops.release = [](DeviceId, std::uintptr_t addr, std::uint64_t) {
        g.blocks.erase(addr);
    };
    ops.copy = [](DeviceId, std::uintptr_t s, DeviceId, std::uintptr_t d,
                  std::uint64_t bytes) -> FenceValue {
        std::memcpy(g.blocks[d].data(), g.blocks[s].data(),
                    static_cast<size_t>(bytes));
        return 0;
    };
    ops.wait = [](FenceValue) {};
    return ops;
}

void Wire(Fabric& f, DeviceId id, DeviceKind kind, const char* label) {
    DeviceObject d{};
    d.id = id;
    d.kind = kind;
    d.capabilities = CapAsyncCopy |
        (kind == DeviceKind::Host ? CapHostVisible
                                  : CapCompute | CapDeviceLocal);
    d.capacityBytes = 1ull << 30;
    d.usableBytes = 1ull << 30;
    d.label = label;
    f.topology().upsertDevice(d);
}
} // namespace

int main() {
    Fabric fabric(MakeOps());
    constexpr DeviceId kHost = 0x100, kA = 0xA11, kB = 0xB22;
    Wire(fabric, kHost, DeviceKind::Host, "host");
    Wire(fabric, kA, DeviceKind::Accelerator, "R9700");
    Wire(fabric, kB, DeviceKind::Accelerator, "7800XT");
    fabric.topology().upsertEdge({kA, kHost, true, false, 32ull << 30, 0});
    fabric.topology().upsertEdge({kHost, kA, true, false, 32ull << 30, 0});
    fabric.topology().upsertEdge({kB, kHost, true, false, 32ull << 30, 0});
    fabric.topology().upsertEdge({kHost, kB, true, false, 32ull << 30, 0});

    auto obj = fabric.createTensor(64, false);
    const auto addr = g.next++;
    g.blocks[addr].assign(64, 0x77);
    fabric.attachReplica(obj, kA, addr, 1);

    // Climb to G7 (scaled stand-in for G777 zipline numbers).
    Generation gcur = 1;
    for (int i = 0; i < 6; ++i) {
        auto w = fabric.acquireWrite(obj, kA, gcur);
        if (w.receipt().acquiredGeneration != gcur + 1) return 2;
        gcur = w.commit();
    }
    if (gcur != 7) return 3;

    AcquireReceipt rr{};
    {
        auto rd = fabric.acquireRead(obj, kB, 6);
        rr = rd.receipt();
    } // release BusyReader before writer reserve

    const bool read_ok =
        (rr.requestedGeneration == 6) &&
        (rr.acquiredGeneration == 7) &&
        rr.converged() && rr.validConvergence() &&
        (rr.physical.generation == 7) &&
        (rr.readerReceipt >= 1);

    AcquireReceipt wrR{};
    Generation published = 0;
    Generation pubBase = 0;
    {
        auto wr = fabric.acquireWrite(obj, kB, 6);
        wrR = wr.receipt();
        pubBase = wr.publishBase();
        published = wr.commit();
    }

    const bool write_reserve_ok =
        (wrR.requestedGeneration == 6) &&
        (wrR.acquiredGeneration == 8) &&
        (pubBase == 7);
    const bool write_pub_ok =
        (published == 8) && (fabric.object(obj)->generation() == 8);

    int strict_reject = 0;
    try {
        (void)fabric.acquireExpected(obj, kA, Access::ReadWrite, 7);
    } catch (const GenerationMismatch&) {
        strict_reject = 1;
    }

    const bool pass =
        read_ok && write_reserve_ok && write_pub_ok && strict_reject;

    std::printf(
        "READ requested=%llu acquired=%llu converged=%d "
        "WRITE reserved=%llu published=%llu STRICT_REJECT=%d\n",
        (unsigned long long)rr.requestedGeneration,
        (unsigned long long)rr.acquiredGeneration,
        rr.converged() ? 1 : 0,
        (unsigned long long)wrR.acquiredGeneration,
        (unsigned long long)published,
        strict_reject);
    std::printf("UCF_READ_CONVERGE_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 4;
}
