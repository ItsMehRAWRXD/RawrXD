// deep2_ucf_generation_ticket_001.cpp — UCF_GENERATION_TICKET_001
//
// Generation = authority receipt / scratch ticket, not a bare counter.
// Header defines legality; ticket records law applied to one transaction.
#include "UcfGenerationTicket.hpp"
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

void Dev(Fabric& f, DeviceId id, const char* lab) {
    DeviceObject d{};
    d.id = id;
    d.kind = DeviceKind::Accelerator;
    d.capabilities = CapCompute | CapDeviceLocal | CapAsyncCopy;
    d.capacityBytes = 32ull << 30;
    d.usableBytes = 24ull << 30;
    d.label = lab;
    f.topology().upsertDevice(d);
}
} // namespace

int main() {
    printf("UCF_GENERATION_TICKET_001\n");
    printf("LAW=generation is authority receipt; ticket scratches progressively\n");

    const auto& man = ActiveSemanticManifest();
    Fabric fabric(Ops());
    constexpr DeviceId kA = 0xA970;
    constexpr DeviceId kB = 0xB780;
    Dev(fabric, kA, "R9700");
    Dev(fabric, kB, "RX7800XT");
    fabric.topology().upsertEdge({kA, kB, true, false, 64ull << 30, 50});
    fabric.topology().upsertEdge({kB, kA, true, false, 64ull << 30, 50});

    auto t = fabric.createTensor(32, false);
    auto h = g.next++;
    g.blocks[h].assign(32, 1);
    fabric.attachReplica(t, kA, h, 1);

    for (Generation want = 1; want < 777; ++want) {
        auto w = fabric.acquireExpected(t, kA, Access::ReadWrite, want);
        (void)w.commit();
    }

    // READ ticket: requested 776 → acquired 777 (convergence)
    GenerationTicketV1 readTk =
        IssueTicket(t.id, 776, TicketFlagRead);
    DriftKind d0 = DriftKind::None;
    {
        auto rd = fabric.acquireRead(t, kB, 776);
        ScratchAcquire(readTk, rd);
        ScratchExecute(readTk, 1);
        d0 = CheckTicketDrift(readTk, &rd, man.manifestHash);
        ScratchRelease(readTk);
    }

    // WRITE ticket: acquire current 777, candidate 778, publish 778
    GenerationTicketV1 writeTk =
        IssueTicket(t.id, 776, TicketFlagWrite);
    DriftKind d1 = DriftKind::None;
    {
        auto wr = fabric.acquireWrite(t, kA, 776);
        ScratchAcquire(writeTk, wr);
        ScratchExecute(writeTk, 1);
        const Generation pub = wr.commit();
        ScratchPublish(writeTk, pub, 1);
        d1 = CheckTicketDrift(writeTk, nullptr, man.manifestHash);
        ScratchRelease(writeTk);
    }

    // Abandoned write: candidate scratched, published stays 0
    GenerationTicketV1 failTk =
        IssueTicket(t.id, 778, TicketFlagWrite);
    {
        auto wr = fabric.acquireWrite(t, kA, 778);
        ScratchAcquire(failTk, wr);
        ScratchFail(failTk);
    }
    const bool abandon_ok =
        failTk.published == 0 &&
        failTk.status == TicketStatus::Failed &&
        fabric.object(t)->generation() == 778;

    const bool read_ok =
        readTk.requested == 776 && readTk.acquired == 777 &&
        readTk.candidate == 0 && readTk.published == 0 &&
        (readTk.flags & TicketFlagConverged) &&
        d0 == DriftKind::None;

    const bool write_ok =
        writeTk.requested == 776 && writeTk.acquired == 777 &&
        writeTk.candidate == 778 && writeTk.published == 778 &&
        d1 == DriftKind::None;

    const bool truth =
        TruthEquals(readTk, man) && TruthEquals(writeTk, man);

    const bool pass = read_ok && write_ok && abandon_ok && truth;

    printf("MANIFEST_HASH=%llu\n",
           (unsigned long long)man.manifestHash);
    printf("READ_TICKET req=%llu acq=%llu cand=%llu pub=%llu drift=%u\n",
           (unsigned long long)readTk.requested,
           (unsigned long long)readTk.acquired,
           (unsigned long long)readTk.candidate,
           (unsigned long long)readTk.published, (unsigned)d0);
    printf("WRITE_TICKET req=%llu acq=%llu cand=%llu pub=%llu drift=%u\n",
           (unsigned long long)writeTk.requested,
           (unsigned long long)writeTk.acquired,
           (unsigned long long)writeTk.candidate,
           (unsigned long long)writeTk.published, (unsigned)d1);
    printf("TRUTH_DRIFT=%d GENERATION_DRIFT=%d PUBLICATION_DRIFT=%d "
           "ABI_DRIFT=%d BACKEND_DRIFT=%d\n",
           truth ? 0 : 1,
           (d0 == DriftKind::GenerationDrift ||
            d1 == DriftKind::GenerationDrift)
               ? 1
               : 0,
           (d1 == DriftKind::PublicationDrift) ? 1 : 0, 0, 0);
    printf("UCF_GENERATION_TICKET_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 2;
}
