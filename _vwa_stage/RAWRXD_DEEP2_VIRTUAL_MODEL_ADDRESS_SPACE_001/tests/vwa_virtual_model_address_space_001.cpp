// RAWRXD_DEEP2_VIRTUAL_MODEL_ADDRESS_SPACE_001: actual range reads, packed bytes,
// IR circular eviction, selected experts, exact leases, bounded physical cache.
#include "vwa/VwaScheduler.hpp"
#include "vwa/VwaGeneratedBridge.hpp"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace Deep2;
using namespace Deep2::vwa;
struct Operand { uint32_t domain = 0, id = 0; };
struct Op {
    std::array<Operand,8> inputs{}, weights{};
    uint32_t inputCount = 0, weightCount = 0;
    Operand input(uint32_t i) const { return inputs.at(i); }
    Operand weight(uint32_t i) const { return weights.at(i); }
};
static VirtualTensorDesc Desc(TensorId id, uint64_t offset, uint64_t bytes, uint32_t type) {
    VirtualTensorDesc d{};
    d.id = id; d.shard = 0; d.fileOffset = offset; d.byteLength = bytes;
    d.type = type; d.addressed = true;
    return d;
}
int main() {
    constexpr uint32_t block = 144, elements = 256; // canonical Q4_K
    constexpr uint32_t expertCount = 8, blocksPerExpert = 4;
    constexpr uint64_t tensorBytes = block * blocksPerExpert * expertCount;
    std::vector<uint8_t> gguf(3 * tensorBytes + block * 8);
    for (size_t i = 0; i < gguf.size(); ++i) gguf[i] = static_cast<uint8_t>((i * 73 + 41) % 251);
    uint32_t canonical = 0;
    if (!CompilerTypeToGgml(1, canonical) || canonical != 12 ||
        !CompilerTypeToGgml(3, canonical) || canonical != 14 ||
        CompilerTypeToGgml(99, canonical)) return 21;
    // Two adjacent tensors are distinct logical addresses even in one shard.
    uint64_t merges = 0;
    const auto separate = CoalesceRanges({{0, 0, block, 1}, {0, block, block, 2}}, &merges);
    if (separate.size() != 2 || merges != 0) return 22;
    const uint64_t activation[2] = {800, 200};
    const uint64_t sync[2] = {100, 50};
    const uint64_t available[2] = {8192, 8192};
    const uint64_t penalties[2] = {0, 0};
    const auto plan = ChooseGpuPlacement(1000, activation, sync, available, penalties);
    if (!plan.admissible || plan.gpu != 1 || plan.cost != 1250) return 23;
    MemoryBackend backend; backend.MapShard(0, gguf.data(), gguf.size());
    VwaSpace space; space.SetBackend(&backend);
    for (TensorId t = 1; t <= 3; ++t) {
        if (!space.Register(Desc(t, (t-1) * tensorBytes, tensorBytes, 12),
                            expertCount * blocksPerExpert * elements,
                            expertCount, tensorBytes / expertCount)) return 2;
    }
    if (!space.Register(Desc(4, 3*tensorBytes, block*8, 12), 8*elements)) return 3;

    // ROM ordinal 0 maps to VWA 1. Expert slices are only known AFTER top-k.
    Op ops[4]{};
    ops[0].weightCount = 1; ops[0].weights[0] = {1, 3};
    ops[1].weightCount = 3;
    for (uint32_t i=0;i<3;++i) ops[1].weights[i] = {1, i};
    ops[2].weightCount = 1; ops[2].weights[0] = {1, 3};
    ops[3].weightCount = 1; ops[3].weights[0] = {1, 3};
    VwaScheduler sched(space);
    VwaBudget budget{};
    budget.maxHostBytes = block * 12;
    budget.maxDeviceBytes = block * 12;
    sched.SetBudget(budget);
    if (!sched.BindIR(ops, 4)) return 4;
    if (sched.IR().NextUseOp(1, 1) != 1 ||
        sched.IR().NextUseOp(4, 3) != 0 ||
        sched.IR().Distance(4, 3) != 1 ||
        sched.IR().RefCount(4) != 3) return 5;

    std::vector<OpLease> leases;
    if (!sched.PrepareOp(0, nullptr, 0, leases) || leases.size() != 1) return 6;
    if (std::memcmp(leases[0].packedData,
                    gguf.data()+3*tensorBytes, block*8)) return 7;
    if (sched.Budget().usedDevice != block*8 ||
        sched.Budget().usedHost != 0) return 8;
    // No expert set supplied: fail closed, no bulk loading.
    std::vector<OpLease> invalid;
    if (sched.PrepareOp(1, nullptr, 0, invalid)) return 9;
    if (!sched.ReleaseOp(leases)) return 10;
    const uint32_t selected[] = {1};
    std::vector<BlockRange> expertRanges;
    if (!PlanExpertBlocks(*space.Find(1), *space.Find(2), *space.Find(3),
                          selected, 1, expertRanges)) return 11;
    // Budget can hold 3 expert slices; full tensors would need 24x this budget.
    if (!sched.PrepareOp(1, expertRanges.data(), expertRanges.size(), leases) ||
        leases.size() != 3) return 12;
    for (size_t i=0;i<leases.size();++i) {
        auto& l = leases[i];
        const uint64_t off = i * tensorBytes + block*blocksPerExpert;
        if (std::memcmp(l.packedData, gguf.data()+off,
                        block*blocksPerExpert)) return 13;
    }
    if (sched.Budget().usedDevice > budget.maxDeviceBytes ||
        sched.Budget().usedHost > budget.maxHostBytes) return 14;
    if (sched.Evict(1)) return 24; // mandatory live lease cannot be evicted
    if (!sched.ReleaseOp(leases)) return 15;
    if (!sched.PrepareOp(2, nullptr, 0, leases)) return 16;
    if (!sched.ReleaseOp(leases)) return 17;
    IrPrefetchPipeline prefetch(sched);
    if (!prefetch.PrefetchAhead(2, 1)) return 18;
    if (!sched.Stats().evictions) return 19;
    const auto& st = sched.Stats();
    const bool logicalGreater = space.LogicalBytes() > budget.maxDeviceBytes;
    const bool noF32 = st.fullTensorF32Materializations == 0;
    const bool packed = st.packedWeightBytes > 0 && st.dmaBytes == st.bytesRead;
    std::printf("RAWRXD_DEEP2_VIRTUAL_MODEL_ADDRESS_SPACE_001\n"
        "IR_INDEX=%zu\nIR_DRIVEN_RESIDENCY=1\n"
        "LOGICAL_MODEL_BYTES=%llu\nPEAK_DEVICE_BYTES=%llu\n"
        "HOST_TO_GPU_BYTES_PER_TOKEN=UNVERIFIED_HOST_COPY_BACKEND\n"
        "FULL_TENSOR_F32_MATERIALIZATIONS_PER_TOKEN=%llu\n"
        "PACKED_WEIGHT_RESIDENCY=%d\nLOGICAL_MODEL_GT_PHYSICAL_MEMORY=%d\n"
        "EXPERT_CONDITIONAL=1\nIR_NEXT_USE_WRAP=1\nEVICTIONS=%llu\n"
        "HOST_DMA_BACKEND=1\nVULKAN_GPU_BACKEND_VERIFIED=0\n"
        "LIVE_ENGINE_OP_LOOP_VERIFIED=0\n"
        "VERDICT=%s\n",
        st.opPrepares ? sched.IR().Count() : 0,
        static_cast<unsigned long long>(space.LogicalBytes()),
        static_cast<unsigned long long>(st.peakDeviceBytes),
        static_cast<unsigned long long>(st.fullTensorF32Materializations),
        packed ? 1 : 0, logicalGreater ? 1 : 0,
        static_cast<unsigned long long>(st.evictions),
        logicalGreater && noF32 && packed ? "VWA_COMPONENT_PASS_RUNTIME_HOLD" : "FAIL");
    return logicalGreater && noF32 && packed ? 0 : 20;
}
