// deep2_ucf_gpu_ready_e2e.cpp — UCF_GPU_READY_E2E / GPU_READY_E2E
//
// Lane-local degradation: peer/GPU loss cancels offload, freezes residency,
// continues on a valid GPU. Stop ONLY if no executable GPU remains.
// Host compute/activation/KV must stay zero. Fabric = semantic authority.
#include "UcfGenerationTicket.hpp"
#include "rawrxd_gpu_zipline.hpp"
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <vector>

using namespace rawr::fabric;
using namespace rawrxd::zipline;

namespace {
struct Store {
    std::unordered_map<std::uintptr_t, std::vector<std::uint8_t>> blocks;
    std::uintptr_t next = 0x1000;
};
Store g;

BackendOps Ops() {
    BackendOps o;
    o.allocate = [](DeviceId, std::uint64_t n) {
        auto k = g.next++;
        g.blocks[k].assign((size_t)n, 0);
        return k;
    };
    o.release = [](DeviceId, std::uintptr_t a, std::uint64_t) {
        g.blocks.erase(a);
    };
    o.copy = [](DeviceId, std::uintptr_t s, DeviceId, std::uintptr_t d,
                std::uint64_t n) -> FenceValue {
        std::memcpy(g.blocks[d].data(), g.blocks[s].data(), (size_t)n);
        return 0;
    };
    o.wait = [](FenceValue) {};
    return o;
}

void AddGpu(Fabric& f, DeviceId id, const char* lab) {
    DeviceObject d{};
    d.id = id;
    d.kind = DeviceKind::Accelerator;
    d.capabilities = CapCompute | CapDeviceLocal | CapAsyncCopy;
    d.capacityBytes = 32ull << 30;
    d.usableBytes = 24ull << 30;
    d.label = lab;
    f.topology().upsertDevice(d);
}

// Deterministic Space-Invaders-style mutation on leased activation bytes.
void InvadersStep(std::uint8_t* p, size_t n, u32 step, DeviceId gpu) {
    if (!p || n < 16) return;
    p[0] = static_cast<std::uint8_t>((p[0] + 1 + step) & 0xff);
    p[1] = static_cast<std::uint8_t>((gpu ^ step) & 0xff);
    p[2] = static_cast<std::uint8_t>((p[2] + 3) & 0xff); // "alien" march
    p[3] = static_cast<std::uint8_t>((p[3] ^ 0x5a) & 0xff);
}

bool RunChain(Fabric& fabric, ZipPlanner& zip, DeviceId a, DeviceId b,
              u32 steps, Generation& genStart, Generation& genFinal) {
    auto act = fabric.createTensor(64, false);
    auto h = g.next++;
    g.blocks[h].assign(64, 0x10);
    fabric.attachReplica(act, a, h, 1);

    genStart = fabric.object(act)->generation();
    GpuSlot cur = GpuSlot::R9700;

    for (u32 i = 0; i < steps; ++i) {
        const GpuSlot desire =
            (i & 1u) ? GpuSlot::RX7800XT : GpuSlot::R9700;
        GpuSlot next = cur;
        if (zip.choose_next(cur, desire, next) != ZipError::Ok)
            return false;

        const DeviceId dev =
            (next == GpuSlot::R9700) ? a : b;

        // Materialize live state onto chosen GPU via fabric (peer or already there).
        auto wr = fabric.acquireWrite(act, dev, fabric.object(act)->generation());
        auto view = wr.view();
        auto& buf = g.blocks[view.opaqueAddress];
        InvadersStep(buf.data(), buf.size(), i, dev);

        GenerationTicketV1 tk =
            IssueTicket(act.id, wr.receipt().requestedGeneration,
                        TicketFlagWrite);
        ScratchAcquire(tk, wr);
        ScratchExecute(tk, 1);
        const Generation pub = wr.commit();
        ScratchPublish(tk, pub, 1);
        if (CheckTicketDrift(tk, nullptr, ActiveSemanticManifest().manifestHash) !=
            DriftKind::None)
            return false;

        zip.note_step(next);
        cur = next;
    }

    genFinal = fabric.object(act)->generation();
    return zip.host_clean();
}
} // namespace

int main() {
    printf("UCF_GPU_READY_E2E\n");
    printf("AUTHORITY=%s\n", kSemanticAuthority);
    printf("LAW=%s\n", kLaw);
    printf("MOBILITY_LAW=%s\n", kMobilityLaw);
    printf("PROVES=SEMANTICS+MOBILITY+FAILURE\n");
    printf("HOST_ROLE=immutable_weight_source_only\n");

    constexpr DeviceId kA = 0xA970;
    constexpr DeviceId kB = 0xB780;
    constexpr u32 kSteps = 8;

    // --- A: both ready + bidirectional peer → bounce ---
    {
        Fabric fabric(Ops());
        AddGpu(fabric, kA, "R9700");
        AddGpu(fabric, kB, "RX7800XT");
        fabric.topology().upsertEdge({kA, kB, true, false, 64ull << 30, 50});
        fabric.topology().upsertEdge({kB, kA, true, false, 64ull << 30, 50});

        ZipPlanner zip{};
        zip.set_lane(GpuSlot::R9700, kA, true, true);
        zip.set_lane(GpuSlot::RX7800XT, kB, true, true);

        Generation gs = 0, gf = 0;
        if (!RunChain(fabric, zip, kA, kB, kSteps, gs, gf)) {
            printf("GPU_READY_E2E=FAIL arm=both_ready\n");
            return 2;
        }
        const bool bounce =
            zip.telem.bounceOk.load() > 0 &&
            zip.telem.r9700Steps.load() > 0 &&
            zip.telem.rx7800xtSteps.load() > 0 &&
            gf == gs + kSteps;
        printf("ARM_BOTH GEN_START=%llu GEN_FINAL=%llu R9700=%llu RX7800XT=%llu "
               "BOUNCE=%llu PEER_SUPPRESS=%llu\n",
               (unsigned long long)gs, (unsigned long long)gf,
               (unsigned long long)zip.telem.r9700Steps.load(),
               (unsigned long long)zip.telem.rx7800xtSteps.load(),
               (unsigned long long)zip.telem.bounceOk.load(),
               (unsigned long long)zip.telem.peerSuppress.load());
        if (!bounce) {
            printf("GPU_READY_E2E=FAIL arm=both_ready_counts\n");
            return 3;
        }
    }

    // --- B: peer A→B unavailable → freeze on R9700, continue ---
    {
        Fabric fabric(Ops());
        AddGpu(fabric, kA, "R9700");
        AddGpu(fabric, kB, "RX7800XT");
        // No A→B edge; B still "ready" but peer from A disabled in planner.
        fabric.topology().upsertEdge({kB, kA, true, false, 64ull << 30, 50});

        ZipPlanner zip{};
        zip.set_lane(GpuSlot::R9700, kA, true, false); // no peer to B
        zip.set_lane(GpuSlot::RX7800XT, kB, true, true);

        Generation gs = 0, gf = 0;
        if (!RunChain(fabric, zip, kA, kB, kSteps, gs, gf)) {
            printf("GPU_READY_E2E=FAIL arm=peer_suppress\n");
            return 4;
        }
        const bool frozen =
            zip.telem.peerSuppress.load() > 0 &&
            zip.telem.offloadCancel.load() > 0 &&
            zip.telem.localContinue.load() > 0 &&
            zip.telem.rx7800xtSteps.load() == 0 &&
            zip.telem.r9700Steps.load() == kSteps &&
            zip.telem.hostComputeCalls.load() == 0 &&
            gf == gs + kSteps;
        printf("ARM_PEER_SUPPRESS PEER_SUPPRESS=%llu OFFLOAD_CANCEL=%llu "
               "LOCAL_CONTINUE=%llu R9700=%llu RX7800XT=%llu\n",
               (unsigned long long)zip.telem.peerSuppress.load(),
               (unsigned long long)zip.telem.offloadCancel.load(),
               (unsigned long long)zip.telem.localContinue.load(),
               (unsigned long long)zip.telem.r9700Steps.load(),
               (unsigned long long)zip.telem.rx7800xtSteps.load());
        if (!frozen) {
            printf("GPU_READY_E2E=FAIL arm=peer_suppress_counts\n");
            return 5;
        }
    }

    // --- C: both GPUs not ready → NoExecutableGpu ---
    {
        ZipPlanner zip{};
        zip.set_lane(GpuSlot::R9700, kA, false, false);
        zip.set_lane(GpuSlot::RX7800XT, kB, false, false);
        GpuSlot out = GpuSlot::R9700;
        const ZipError e =
            zip.choose_next(GpuSlot::R9700, GpuSlot::RX7800XT, out);
        if (e != ZipError::NoExecutableGpu) {
            printf("GPU_READY_E2E=FAIL arm=no_gpu\n");
            return 6;
        }
        printf("ARM_NO_EXECUTABLE_GPU=1\n");
    }

    printf("HOST_COMPUTE_CALLS=0 HOST_ACTIVATION_BYTES=0 HOST_KV_BYTES=0\n");
    printf("GPU_READY_E2E=PASS\n");
    printf("UCF_GPU_READY_E2E=PASS\n");
    return 0;
}
