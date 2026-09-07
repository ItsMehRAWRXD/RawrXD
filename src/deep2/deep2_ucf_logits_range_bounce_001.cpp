// deep2_ucf_logits_range_bounce_001.cpp — UCF_LOGITS_RANGE_BOUNCE_001
//
// LAW: BounceChain commits only range-argmax dribble payload, never full F32
// logits. Authority = rawr_uncoherent_object_fabric.hpp (no MASM).
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

// Committed bounce payload — 4'6 dribble (not vocab×F32).
struct alignas(8) LogitsRangeCommit {
    uint32_t winnerRow = 0;
    float winnerValue = -1e30f;
    uint32_t rangeStart = 0;
    uint32_t rangeCount = 0;
};

static_assert(sizeof(LogitsRangeCommit) <= 32, "dribble payload too large");

constexpr uint64_t kFakeVocab = 163840; // K2-class order; must NOT bounce
constexpr uint64_t kFullF32Bytes = kFakeVocab * 4ull;

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
    ops.copy = [](DeviceId, std::uintptr_t s, DeviceId, std::uintptr_t d,
                  std::uint64_t bytes) -> FenceValue {
        auto sit = g_store.blocks.find(s);
        auto dit = g_store.blocks.find(d);
        if (sit == g_store.blocks.end() || dit == g_store.blocks.end())
            throw std::runtime_error("copy missing");
        std::memcpy(dit->second.data(), sit->second.data(),
                    static_cast<size_t>(bytes));
        return 0;
    };
    ops.wait = [](FenceValue) {};
    return ops;
}

void AddLane(Fabric& f, DeviceId id, DeviceKind kind, const char* label) {
    DeviceObject d{};
    d.id = id;
    d.kind = kind;
    d.capabilities = CapCompute | CapAsyncCopy |
        (kind == DeviceKind::Host ? CapHostVisible : CapDeviceLocal);
    d.capacityBytes = 32ull << 30;
    d.usableBytes = 24ull << 30;
    d.label = label;
    f.topology().upsertDevice(d);
}
} // namespace

int main() {
    printf("UCF_LOGITS_RANGE_BOUNCE_001\n");
    printf("AUTHORITY=src/deep2/rawr_uncoherent_object_fabric.hpp\n");
    printf("MASM=non-landed\n");
    printf("LAW=bounce LogitsRangeCommit only; FULL_F32_LOGITS_BOUNCE=0\n");

    Fabric fabric(MakeOps());
    constexpr DeviceId kCpu = 0xC001; // opaque — not "cuda:0"
    constexpr DeviceId kGpu = 0xA970; // R9700-class compute object
    AddLane(fabric, kCpu, DeviceKind::Host, "cpu_bulk");
    AddLane(fabric, kGpu, DeviceKind::Accelerator, "gpu_range_argmax");
    fabric.topology().upsertEdge({kCpu, kGpu, true, false, 64ull << 30, 500});
    fabric.topology().upsertEdge({kGpu, kCpu, true, false, 64ull << 30, 500});

    auto commitObj = fabric.createTensor(sizeof(LogitsRangeCommit), false);
    const auto h0 = g_store.next++;
    g_store.blocks[h0].assign(sizeof(LogitsRangeCommit), 0);
    fabric.attachReplica(commitObj, kCpu, h0, 1);

    BounceChain chain(fabric, {kCpu, kGpu});
    Generation g = 1;
    uint64_t maxPayload = 0;
    uint32_t hops = 0;
    DeviceId last = 0;

    for (int i = 0; i < 8; ++i) {
        g = chain.hop({}, commitObj, g,
                      [&](DeviceId d, std::span<const PhysicalView>,
                          PhysicalView st) {
                          ++hops;
                          last = d;
                          if (st.bytes > maxPayload) maxPayload = st.bytes;
                          if (st.bytes >= kFullF32Bytes)
                              throw std::runtime_error("full F32 logits bounce");
                          if (st.bytes != sizeof(LogitsRangeCommit))
                              throw std::runtime_error("payload size");
                          auto* c = reinterpret_cast<LogitsRangeCommit*>(
                              g_store.blocks[st.opaqueAddress].data());
                          // CPU bulk lane vs GPU range cut — commit winner only.
                          if (d == kGpu) {
                              c->rangeStart = 0;
                              c->rangeCount = 4096;
                              c->winnerRow = 1000u + (uint32_t)i;
                              c->winnerValue = 10.0f + (float)i;
                          } else {
                              c->rangeStart = 4096;
                              c->rangeCount = (uint32_t)(kFakeVocab - 4096);
                              c->winnerRow = 50000u + (uint32_t)i;
                              c->winnerValue = 9.0f + (float)i;
                          }
                      });
    }

    int mismatch = 0;
    try {
        (void)fabric.dispatchRWExpected(
            kGpu, {}, commitObj, g - 1,
            [](DeviceId, std::span<const PhysicalView>, PhysicalView) {});
    } catch (const GenerationMismatch&) {
        mismatch = 1;
    }

    const bool dribble =
        maxPayload == sizeof(LogitsRangeCommit) &&
        maxPayload < kFullF32Bytes &&
        maxPayload <= 32;
    const bool pass =
        (hops == 8) && (g == 9) && mismatch && dribble &&
        (last == kCpu || last == kGpu);

    printf("BOUNCE_HOPS=%u GEN=%llu LAST=0x%llx MISMATCH=%d\n", hops,
           (unsigned long long)g, (unsigned long long)last, mismatch);
    printf("PAYLOAD_BYTES=%llu FULL_F32_LOGITS_BYTES=%llu "
           "FULL_F32_LOGITS_BOUNCE=%d\n",
           (unsigned long long)maxPayload,
           (unsigned long long)kFullF32Bytes, 0);
    printf("COMMIT_FIELDS=winner_row,winner_value,range_start,range_count,"
           "generation\n");
    printf("UCF_LOGITS_RANGE_BOUNCE_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 2;
}
