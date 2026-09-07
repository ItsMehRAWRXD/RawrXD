// deep2_ucf_no_stale_dispatch_001.cpp — UCF_NO_STALE_DISPATCH_001
//
// Witness:
//   CREATE gen=1 → BIND host → ENSURE A → RW expect=1 on A → COMMIT gen=2
//   TRY dispatch expect=1 on B → GenerationMismatch
//   ENSURE B → RW expect=2 on B → COMMIT gen=3
// Pass: STALE_DISPATCH=0 GEN_MISMATCH_THROW=1 FINAL_GEN=3
//       CURRENT excludes stale-only  P2P_REQUIRED=0  HOST_RELAY allowed
#include "rawr_uncoherent_object_fabric.hpp"
#include <cstdio>
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
int g_host_relay_hops = 0;

BackendOps MakeOps() {
    BackendOps ops;
    ops.allocate = [](DeviceId, std::uint64_t bytes) -> std::uintptr_t {
        const auto key = g_store.next++;
        g_store.blocks[key].assign(static_cast<size_t>(bytes), 0);
        return key;
    };
    ops.release = [](DeviceId, std::uintptr_t addr, std::uint64_t) {
        g_store.blocks.erase(addr);
    };
    ops.copy = [](DeviceId src, std::uintptr_t sAddr, DeviceId dst,
                  std::uintptr_t dAddr, std::uint64_t bytes) -> FenceValue {
        // Count host-edge copies as relay evidence (no A↔B P2P).
        if (src == 0x100 || dst == 0x100)
            ++g_host_relay_hops;
        auto sit = g_store.blocks.find(sAddr);
        auto dit = g_store.blocks.find(dAddr);
        if (sit == g_store.blocks.end() || dit == g_store.blocks.end())
            throw std::runtime_error("copy missing");
        std::memcpy(dit->second.data(), sit->second.data(),
                    static_cast<size_t>(bytes));
        return 0;
    };
    ops.wait = [](FenceValue) {};
    return ops;
}

void UpsertAccel(Fabric& f, DeviceId id, const char* label) {
    DeviceObject d{};
    d.id = id;
    d.kind = DeviceKind::Accelerator;
    d.capabilities = CapCompute | CapDeviceLocal | CapAsyncCopy;
    d.capacityBytes = 24ull << 30;
    d.usableBytes = 20ull << 30;
    d.label = label;
    f.topology().upsertDevice(d);
}
} // namespace

int main() {
    Fabric fabric(MakeOps());

    constexpr DeviceId kHost = 0x100;
    constexpr DeviceId kA = 0xA11;
    constexpr DeviceId kB = 0xB22;

    DeviceObject host{};
    host.id = kHost;
    host.kind = DeviceKind::Host;
    host.capabilities = CapHostVisible | CapAsyncCopy;
    host.capacityBytes = 192ull << 30;
    host.usableBytes = 160ull << 30;
    host.label = "host";
    fabric.topology().upsertDevice(host);
    UpsertAccel(fabric, kA, "accel_A");
    UpsertAccel(fabric, kB, "accel_B");

    // Legal base edges only — no A↔B P2P.
    fabric.topology().upsertEdge({kA, kHost, true, false, 32ull << 30, 1000});
    fabric.topology().upsertEdge({kHost, kA, true, false, 32ull << 30, 1000});
    fabric.topology().upsertEdge({kB, kHost, true, false, 32ull << 30, 1000});
    fabric.topology().upsertEdge({kHost, kB, true, false, 32ull << 30, 1000});

    auto obj = fabric.createTensor(256, false);
    const auto hAddr = g_store.next++;
    g_store.blocks[hAddr].assign(256, 0x11);
    fabric.attachReplica(obj, kHost, hAddr, 1);

    int stale_dispatch = 0;
    int gen_mismatch_throw = 0;
    Generation final_gen = 0;
    int current_excludes_stale = 0;
    const int p2p_required = 0;

    try {
        // ENSURE A + RW expected=1 → COMMIT gen=2
        {
            auto lease = fabric.acquireExpected(
                obj, kA, Access::ReadWrite, 1);
            auto& buf = g_store.blocks[lease.view().opaqueAddress];
            if (!buf.empty()) buf[0] = 0xA1;
            final_gen = lease.commit();
        }
        if (final_gen != 2)
            throw std::runtime_error("after A commit gen!=2");

        // Stale expected=1 on B must throw (not silently select host/A).
        try {
            (void)fabric.dispatchRWExpected(
                kB, {}, obj, 1,
                [](DeviceId, std::span<const PhysicalView>, PhysicalView) {
                });
            stale_dispatch = 1;
        } catch (const GenerationMismatch& e) {
            gen_mismatch_throw = 1;
            std::printf("MISMATCH expected=%llu observed=%llu\n",
                        (unsigned long long)e.expected(),
                        (unsigned long long)e.observed());
            if (e.expected() != 1 || e.observed() != 2)
                throw std::runtime_error("mismatch tuple wrong");
        }

        // ENSURE B + RW expected=2 → COMMIT gen=3
        {
            auto lease = fabric.acquireExpected(
                obj, kB, Access::ReadWrite, 2);
            auto& buf = g_store.blocks[lease.view().opaqueAddress];
            if (!buf.empty()) buf[0] = 0xB2;
            final_gen = lease.commit();
        }

        auto tobj = fabric.object(obj);
        const auto current = tobj->currentReplicas();
        bool b_current = false;
        bool stale_only_selected = false;
        for (const auto& r : current) {
            if (r->device == kB &&
                r->generation.load() == tobj->generation())
                b_current = true;
            if (r->generation.load() != tobj->generation())
                stale_only_selected = true;
        }
        // Host may still be Present at gen=1 but must not be in currentReplicas.
        auto hostRep = tobj->replica(kHost, false);
        const bool host_stale_present =
            hostRep &&
            hostRep->state.load() == ReplicaState::Present &&
            hostRep->generation.load() == 1 &&
            tobj->generation() == 3;
        current_excludes_stale =
            b_current && !stale_only_selected &&
            (!host_stale_present ||
             [&] {
                 for (const auto& r : current)
                     if (r->device == kHost) return false;
                 return true;
             }());
    } catch (const std::exception& ex) {
        std::printf("UCF_NO_STALE_DISPATCH_001=FAIL ex=%s\n", ex.what());
        return 2;
    }

    const bool pass =
        (stale_dispatch == 0) && (gen_mismatch_throw == 1) &&
        (final_gen == 3) && current_excludes_stale &&
        (p2p_required == 0) && (g_host_relay_hops > 0);

    std::printf(
        "STALE_DISPATCH=%d GEN_MISMATCH_THROW=%d FINAL_GEN=%llu "
        "CURRENT_EXCLUDES_STALE=%d HOST_RELAY_USED=%d P2P_REQUIRED=%d\n",
        stale_dispatch, gen_mismatch_throw,
        (unsigned long long)final_gen, current_excludes_stale,
        g_host_relay_hops > 0 ? 1 : 0, p2p_required);
    std::printf("UCF_NO_STALE_DISPATCH_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 3;
}
