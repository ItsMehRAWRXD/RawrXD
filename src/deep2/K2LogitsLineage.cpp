// K2LogitsLineage.cpp — observational fulfilled vs GPU dispatch receipts
#include "K2LogitsLineage.hpp"
#include "K2C1C9.hpp"
#include "VwaNormalizePhysical.hpp"
#include <atomic>
#include <cstring>
#include <mutex>
#include <vector>

namespace Deep2 {
namespace {
std::mutex g_mu;
std::vector<PhysicalTensorRange> g_fulfilled;
std::vector<PhysicalTensorRange> g_dispatched;
uint32_t g_gpuFirst = 0, g_gpuBlocks = 0, g_expected = 0;
uint32_t g_totalBlocks = 0, g_cpuFirst = 0, g_cpuBlocks = 0;
std::atomic<uint32_t> g_nameRelookup{0}, g_secondResolve{0}, g_cpuRebuild{0};
std::atomic<uint32_t> g_secondMount{0};
uint64_t g_freezeA = 0, g_freezeB = 0;
uint32_t g_freezeSamples = 0;
} // namespace

void LogitsLineage_Reset() {
    std::lock_guard<std::mutex> lock(g_mu);
    g_fulfilled.clear();
    g_dispatched.clear();
    g_gpuFirst = g_gpuBlocks = g_expected = 0;
    g_totalBlocks = g_cpuFirst = g_cpuBlocks = 0;
    g_nameRelookup = g_secondResolve = g_cpuRebuild = g_secondMount = 0;
    g_freezeA = g_freezeB = 0;
    g_freezeSamples = 0;
}

void LogitsLineage_NoteFulfilled(const PhysicalTensorRange* ranges, size_t n,
                                 uint32_t gpuFirstBlock, uint32_t gpuBlockCount,
                                 uint32_t expectedBytes) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_fulfilled.clear();
    g_dispatched.clear(); // new cut claim invalidates prior receipt
    if (ranges && n)
        g_fulfilled.assign(ranges, ranges + n);
    g_gpuFirst = gpuFirstBlock;
    g_gpuBlocks = gpuBlockCount;
    g_expected = expectedBytes;
}

void LogitsLineage_NoteBlockMap(uint32_t logitsTotalBlocks,
                                uint32_t gpuFirstBlock, uint32_t gpuBlockCount,
                                uint32_t cpuFirstBlock, uint32_t cpuBlockCount) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_totalBlocks = logitsTotalBlocks;
    g_gpuFirst = gpuFirstBlock;
    g_gpuBlocks = gpuBlockCount;
    g_cpuFirst = cpuFirstBlock;
    g_cpuBlocks = cpuBlockCount;
}

void LogitsLineage_NoteDispatched(const PhysicalTensorRange* ranges, size_t n) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_dispatched.clear();
    if (ranges && n)
        g_dispatched.assign(ranges, ranges + n);
}

void LogitsLineage_NoteNameRelookup() { g_nameRelookup.fetch_add(1); }
void LogitsLineage_NoteSecondResolve() { g_secondResolve.fetch_add(1); }
void LogitsLineage_NoteSecondMountApi() { g_secondMount.fetch_add(1); }
void LogitsLineage_NoteCpuSourceRebuild() { g_cpuRebuild.fetch_add(1); }

void LogitsLineage_CommitFreezeSample() {
    std::lock_guard<std::mutex> lock(g_mu);
    const uint64_t h =
        HashPhysicalRangeSet(g_dispatched.data(), g_dispatched.size());
    if (g_freezeSamples == 0)
        g_freezeA = h;
    else
        g_freezeB = h;
    ++g_freezeSamples;
}

LogitsLineageSnap LogitsLineage_Snapshot() {
    std::lock_guard<std::mutex> lock(g_mu);
    LogitsLineageSnap s{};
    s.fulfilledCount = (uint32_t)g_fulfilled.size();
    s.dispatchCount = (uint32_t)g_dispatched.size();
    for (const auto& r : g_fulfilled) s.fulfilledBytes += r.byteCount;
    for (const auto& r : g_dispatched) s.dispatchBytes += r.byteCount;
    s.fulfilledHash =
        HashPhysicalRangeSet(g_fulfilled.data(), g_fulfilled.size());
    s.dispatchHash =
        HashPhysicalRangeSet(g_dispatched.data(), g_dispatched.size());
    s.logitsTotalBlocks = g_totalBlocks;
    s.gpuFirstBlock = g_gpuFirst;
    s.gpuBlockCount = g_gpuBlocks;
    s.cpuFirstBlock = g_cpuFirst;
    s.cpuBlockCount = g_cpuBlocks;
    s.gpuExpectedBytes = g_expected;
    s.gpuDispatch = s.dispatchCount > 0 ? 1u : 0u;
    s.nameRelookup = g_nameRelookup.load();
    s.secondResolve = g_secondResolve.load();
    s.secondMountApi = g_secondMount.load();
    s.cpuSourceRebuild = g_cpuRebuild.load();
    s.freezeSamples = g_freezeSamples;
    s.freezeHashA = g_freezeA;
    s.freezeHashB = g_freezeB;
    s.freezeRepeatable =
        (g_freezeSamples >= 2 && g_freezeA != 0 && g_freezeA == g_freezeB) ? 1u
                                                                          : 0u;

    const bool ident = PhysicalRangesIdentical(
        g_fulfilled.data(), g_fulfilled.size(),
        g_dispatched.data(), g_dispatched.size());
    s.matchOrder = ident ? 1u : 0u;
    s.matchHash =
        (s.fulfilledHash == s.dispatchHash && s.dispatchCount > 0) ? 1u : 0u;
    s.matchTensor = s.matchShard = s.matchOffset = s.matchLength = 0;
    if (ident && !g_fulfilled.empty()) {
        s.matchTensor = s.matchShard = s.matchOffset = s.matchLength = 1;
    } else if (g_fulfilled.size() == g_dispatched.size() &&
               !g_fulfilled.empty()) {
        s.matchTensor = s.matchShard = s.matchOffset = s.matchLength = 1;
        for (size_t i = 0; i < g_fulfilled.size(); ++i) {
            if (g_fulfilled[i].tensorId != g_dispatched[i].tensorId)
                s.matchTensor = 0;
            if (g_fulfilled[i].shardId != g_dispatched[i].shardId)
                s.matchShard = 0;
            if (g_fulfilled[i].absoluteFileOffset !=
                g_dispatched[i].absoluteFileOffset)
                s.matchOffset = 0;
            if (g_fulfilled[i].byteCount != g_dispatched[i].byteCount)
                s.matchLength = 0;
        }
    }
    return s;
}

void LogitsLineage_Emit(FILE* f) {
    if (!f) f = stdout;
    const auto s = LogitsLineage_Snapshot();
    fprintf(f,
            "VWA_FULFILLED_RANGE_COUNT=%u VWA_DISPATCH_RANGE_COUNT=%u\n"
            "VWA_FULFILLED_BYTES=%llu GPU_SOURCE_RANGE_BYTES=%llu\n"
            "LOGITS_TOTAL_BLOCKS=%u GPU_FIRST_BLOCK=%u GPU_BLOCK_COUNT=%u\n"
            "CPU_FIRST_BLOCK=%u CPU_BLOCK_COUNT=%u\n"
            "GPU_EXPECTED_BYTES=%u GPU_FULFILLED_BYTES=%llu "
            "GPU_DISPATCH_BYTES=%llu\n"
            "FULFILLED_RANGE_HASH=%016llx GPU_SOURCE_RANGE_HASH=%016llx\n"
            "RANGE_TENSOR_ID_MATCH=%u RANGE_SOURCE_ID_MATCH=%u\n"
            "RANGE_OFFSET_MATCH=%u RANGE_LENGTH_MATCH=%u RANGE_ORDER_MATCH=%u\n"
            "RANGE_SET_HASH_MATCH=%u GPU_DISPATCH=%u\n"
            "NAME_RELOOKUP=%u SECOND_RESOLVE=%u SECOND_MOUNT_API=%u "
            "CPU_SOURCE_REBUILD=%u\n"
            "FREEZE_SAMPLES=%u FREEZE_HASH_A=%016llx FREEZE_HASH_B=%016llx "
            "RANGE_HASH_REPEATABLE=%u\n",
            s.fulfilledCount, s.dispatchCount,
            (unsigned long long)s.fulfilledBytes,
            (unsigned long long)s.dispatchBytes, s.logitsTotalBlocks,
            s.gpuFirstBlock, s.gpuBlockCount, s.cpuFirstBlock, s.cpuBlockCount,
            s.gpuExpectedBytes, (unsigned long long)s.fulfilledBytes,
            (unsigned long long)s.dispatchBytes,
            (unsigned long long)s.fulfilledHash,
            (unsigned long long)s.dispatchHash, s.matchTensor, s.matchShard,
            s.matchOffset, s.matchLength, s.matchOrder, s.matchHash,
            s.gpuDispatch, s.nameRelookup, s.secondResolve, s.secondMountApi,
            s.cpuSourceRebuild, s.freezeSamples,
            (unsigned long long)s.freezeHashA,
            (unsigned long long)s.freezeHashB, s.freezeRepeatable);
    fflush(f);
}

bool LogitsLineage_Pass() {
    const auto s = LogitsLineage_Snapshot();
    if (s.gpuDispatch != 1 || s.nameRelookup != 0 || s.secondResolve != 0 ||
        s.secondMountApi != 0 || s.cpuSourceRebuild != 0 ||
        s.freezeRepeatable != 1)
        return false;

    // Drop ABI: exact normalized range-set identity via K2ValidateLineage.
    std::vector<VwaLineageRange> ful(s.fulfilledCount), dis(s.dispatchCount);
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (!NormalizePhysicalSet(g_fulfilled.data(), g_fulfilled.size(),
                                  ful.data()) ||
            !NormalizePhysicalSet(g_dispatched.data(), g_dispatched.size(),
                                  dis.data()))
            return false;
    }
    K2LineageVerdict v{};
    if (K2ValidateLineage(ful.data(), ful.size(), dis.data(), dis.size(),
                          s.gpuDispatch, &v) != K2C_OK ||
        !v.pass)
        return false;

    return s.matchOrder == 1 && s.matchHash == 1 && s.matchTensor == 1 &&
           s.matchShard == 1 && s.matchOffset == 1 && s.matchLength == 1 &&
           s.fulfilledBytes == s.dispatchBytes &&
           s.fulfilledBytes == s.gpuExpectedBytes;
}

} // namespace Deep2
