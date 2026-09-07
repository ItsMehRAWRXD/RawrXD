// K2LogitsSplit.cpp — CPU||GPU packed logits under MLA_Gemv RANGE_ARGMAX.
#include "K2LogitsSplit.hpp"
#include "K2C1C9.hpp"
#include "K2LogitsClimb.hpp"
#include "K2LogitsLineage.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "K2MLA_FusedQ4KT.hpp"
#include "StreamPathTiming.hpp"
#include "VirtualTensorRange.hpp"
#include "VwaNormalizePhysical.hpp"
#include "vwa/VwaRangeLineageAbi.hpp"
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace Deep2 {
namespace {
std::atomic<uint64_t> g_calls{0}, g_gpuRows{0}, g_cpuRows{0}, g_rowsTot{0};
std::atomic<uint64_t> g_cpuUs{0}, g_gpuUs{0}, g_wallUs{0}, g_serialUs{0};
std::atomic<int32_t> g_cpuTok{-1}, g_gpuTok{-1}, g_finalTok{-1};
std::atomic<uint32_t> g_cpuBits{0}, g_gpuBits{0}, g_finalBits{0};
std::atomic<uint32_t> g_mode{0};
std::atomic<uint64_t> g_argmaxB{0}, g_rangeB{0}, g_fullRb{0};
std::atomic<uint32_t> g_cpuRpuBits{0}, g_gpuRpuBits{0};

uint32_t g_cutSticky = 0;
float g_cpuEma = 0.f, g_gpuEma = 0.f;
bool g_emaOk = false;

uint32_t ChooseCut(uint32_t vocab) {
    // Cap GPU rows: Q6 stream slot must not thrash MLA pin residents.
    constexpr uint32_t kMaxGpuRows = 8192u;
    constexpr uint32_t kMinGpuRows = 1024u;
    if (const char* e = std::getenv("DEEP2_LOGITS_GPU_CUT")) {
        const unsigned v = (unsigned)std::strtoul(e, nullptr, 10);
        if (v >= kMinGpuRows && v < vocab)
            return (std::min)((uint32_t)v, kMaxGpuRows);
    }
    uint32_t cut = kMaxGpuRows / 2u; // start modest; EMA grows/shrinks
    if (g_emaOk && g_cpuEma > 0.f && g_gpuEma > 0.f) {
        const float sum = g_cpuEma + g_gpuEma;
        float frac = g_gpuEma / sum;
        if (frac < 0.05f) frac = 0.05f;
        if (frac > 0.50f) frac = 0.50f; // GPU never takes majority until faster
        cut = (uint32_t)(frac * (float)vocab + 0.5f);
    }
    if (cut < kMinGpuRows) cut = kMinGpuRows;
    if (cut > kMaxGpuRows) cut = kMaxGpuRows;
    if (cut > vocab / 2u) cut = vocab / 2u;
    if (g_cutSticky) {
        const int d = (int)cut - (int)g_cutSticky;
        if (d > -512 && d < 512) cut = g_cutSticky;
    }
    g_cutSticky = cut;
    return cut;
}

void NoteEma(uint32_t gpuRows, uint64_t gpuUs, uint32_t cpuRows,
             uint64_t cpuUs) {
    if (gpuUs > 0 && gpuRows > 0) {
        const float r = (float)gpuRows / (float)gpuUs;
        g_gpuEma = g_emaOk ? (0.25f * r + 0.75f * g_gpuEma) : r;
    }
    if (cpuUs > 0 && cpuRows > 0) {
        const float r = (float)cpuRows / (float)cpuUs;
        g_cpuEma = g_emaOk ? (0.25f * r + 0.75f * g_cpuEma) : r;
    }
    g_emaOk = true;
}
} // namespace

void LogitsSplit_Reset() {
    g_calls = g_gpuRows = g_cpuRows = g_rowsTot = 0;
    g_cpuUs = g_gpuUs = g_wallUs = g_serialUs = 0;
    g_cpuTok = g_gpuTok = g_finalTok = -1;
    g_mode = 0;
    g_argmaxB = g_rangeB = g_fullRb = 0;
}

LogitsSplitSnap LogitsSplit_Snapshot() {
    LogitsSplitSnap s;
    s.calls = g_calls.load();
    s.gpuRows = g_gpuRows.load();
    s.cpuRows = g_cpuRows.load();
    s.rowsTotal = g_rowsTot.load();
    s.cpuBranchUs = g_cpuUs.load();
    s.gpuBranchUs = g_gpuUs.load();
    s.splitWallUs = g_wallUs.load();
    s.serialBaseUs = g_serialUs.load();
    s.cpuTok = g_cpuTok.load();
    s.gpuTok = g_gpuTok.load();
    s.finalTok = g_finalTok.load();
    s.modeSplit = g_mode.load();
    s.gpuArgmaxBytes = g_argmaxB.load();
    s.gpuRangeOutBytes = g_rangeB.load();
    s.fullReadback = g_fullRb.load();
    uint32_t cb = g_cpuBits.load(), gb = g_gpuBits.load(), fb = g_finalBits.load();
    std::memcpy(&s.cpuVal, &cb, 4);
    std::memcpy(&s.gpuVal, &gb, 4);
    std::memcpy(&s.finalVal, &fb, 4);
    s.cpuRowsPerUs = g_cpuEma;
    s.gpuRowsPerUs = g_gpuEma;
    return s;
}

void LogitsSplit_Emit(FILE* f) {
    if (!f) f = stdout;
    const auto s = LogitsSplit_Snapshot();
    fprintf(f,
            "LOGITS_MODE=%s\n"
            "LOGITS_GPU_ROWS=%llu LOGITS_CPU_ROWS=%llu "
            "LOGITS_ROWS_TOTAL=%llu LOGITS_ROW_ACCOUNTING=1\n"
            "GPU_LOGITS_FULL_READBACK=%llu GPU_ARGMAX_BYTES=%llu "
            "GPU_RANGE_OUT_BYTES=%llu\n"
            "CPU_ARGMAX_TOKEN=%d GPU_ARGMAX_TOKEN=%d FINAL_ARGMAX_TOKEN=%d\n"
            "CPU_BRANCH_US=%llu GPU_BRANCH_US=%llu LOGITS_SPLIT_WALL_US=%llu\n",
            s.modeSplit ? "CPU_GPU_SPLIT" : "CPU_ONLY",
            (unsigned long long)s.gpuRows, (unsigned long long)s.cpuRows,
            (unsigned long long)s.rowsTotal,
            (unsigned long long)s.fullReadback,
            (unsigned long long)s.gpuArgmaxBytes,
            (unsigned long long)s.gpuRangeOutBytes,
            s.cpuTok, s.gpuTok, s.finalTok,
            (unsigned long long)s.cpuBranchUs,
            (unsigned long long)s.gpuBranchUs,
            (unsigned long long)s.splitWallUs);
    fprintf(f, "CPU_LOGIT_ROWS_PER_US=%.4f GPU_LOGIT_ROWS_PER_US=%.4f\n",
            s.cpuRowsPerUs, s.gpuRowsPerUs);
    fflush(f);
}

bool LogitsSplit_Wanted() {
    const char* e = std::getenv("DEEP2_LOGITS_GPU_SPLIT");
    // Explicit opt-in only — default off preserves MLA pin residency.
    return e && e[0] == '1' && MLA_GpuGemvWanted();
}

bool LogitsSplit_ArgmaxPacked(const uint8_t* base, size_t baseBytes,
                              size_t vocabSize, size_t hiddenDim,
                              const float* hidden,
                              const VirtualTensorDesc* logitsDesc,
                              int32_t& bestTok, float* bestValOut) {
    if (!LogitsSplit_Wanted() || !MLA_GpuGemvWanted() || !logitsDesc ||
        !logitsDesc->addressed) {
        g_mode.store(0);
        return LogitsClimb_ArgmaxPacked(base, baseBytes, vocabSize, hiddenDim,
                                        hidden, bestTok, bestValOut);
    }
    if (vocabSize < 4096u) {
        g_mode.store(0);
        return LogitsClimb_ArgmaxPacked(base, baseBytes, vocabSize, hiddenDim,
                                        hidden, bestTok, bestValOut);
    }

    QuantBlockGeometry geo{};
    if (!GetQuantBlockGeometry(logitsDesc->type, geo) ||
        geo.elementsPerBlock == 0 || geo.bytesPerBlock == 0) {
        g_mode.store(0);
        return LogitsClimb_ArgmaxPacked(base, baseBytes, vocabSize, hiddenDim,
                                        hidden, bestTok, bestValOut);
    }

    const uint32_t cut = ChooseCut((uint32_t)vocabSize);

    // Row→block via MASM only — never invents absolute file offsets.
    K2RowBlockRequest rowReq{};
    rowReq.firstRow = 0;
    rowReq.rowCount = cut;
    rowReq.cols = hiddenDim;
    rowReq.blockElements = geo.elementsPerBlock;
    K2BlockRangeOut br{};
    if (K2RowsToBlockRangeX64_Fixed(&rowReq, &br) != 0) {
        g_mode.store(0);
        return LogitsClimb_ArgmaxPacked(base, baseBytes, vocabSize, hiddenDim,
                                        hidden, bestTok, bestValOut);
    }

    K2RowBlockRequest fullReq = rowReq;
    fullReq.rowCount = vocabSize;
    K2BlockRangeOut fullBr{};
    if (K2RowsToBlockRangeX64_Fixed(&fullReq, &fullBr) != 0) {
        g_mode.store(0);
        return LogitsClimb_ArgmaxPacked(base, baseBytes, vocabSize, hiddenDim,
                                        hidden, bestTok, bestValOut);
    }

    const uint64_t gpuFirstBlock = br.firstBlock;
    const uint64_t gpuBlockCount = br.blockCount;
    const uint64_t logitsTotalBlocks = fullBr.blockCount;
    const uint64_t cpuFirstBlock = gpuBlockCount;
    const uint64_t cpuBlockCount =
        logitsTotalBlocks > gpuBlockCount ? logitsTotalBlocks - gpuBlockCount
                                          : 0;
    const uint64_t rowBytes =
        br.blocksPerRow * (uint64_t)geo.bytesPerBlock;

    QuantBlockRange gpuReq{};
    gpuReq.firstBlock = gpuFirstBlock;
    gpuReq.blockCount = gpuBlockCount;
    PhysicalTensorRange gpuRange{};
    if (!ResolveQuantBlockRange(*logitsDesc, geo.bytesPerBlock, gpuReq,
                                gpuRange)) {
        g_mode.store(0);
        return LogitsClimb_ArgmaxPacked(base, baseBytes, vocabSize, hiddenDim,
                                        hidden, bestTok, bestValOut);
    }

    const uint32_t expectedBytes = (uint32_t)gpuRange.byteCount;
    if (expectedBytes != (uint32_t)(cut * rowBytes)) {
        g_mode.store(0);
        return LogitsClimb_ArgmaxPacked(base, baseBytes, vocabSize, hiddenDim,
                                        hidden, bestTok, bestValOut);
    }
    if (baseBytes < gpuRange.tensorRelativeOffset + gpuRange.byteCount) {
        g_mode.store(0);
        return LogitsClimb_ArgmaxPacked(base, baseBytes, vocabSize, hiddenDim,
                                        hidden, bestTok, bestValOut);
    }

    // Exact cut fulfillment = resident/borrowed slice covering resolved range.
    LogitsLineage_NoteFulfilled(&gpuRange, 1, (uint32_t)gpuFirstBlock,
                                (uint32_t)gpuBlockCount, expectedBytes);
    LogitsLineage_NoteBlockMap((uint32_t)logitsTotalBlocks,
                               (uint32_t)gpuFirstBlock, (uint32_t)gpuBlockCount,
                               (uint32_t)cpuFirstBlock, (uint32_t)cpuBlockCount);

    PackedArgmax gpuBest{};
    int32_t cpuTok = -1;
    float cpuVal = -1e30f;
    bool gpuOk = false, cpuOk = false;
    uint64_t gpuUs = 0, cpuUs = 0;

    const uint64_t tWall0 = MLA_FusedQ4KT_NowUs();
    std::thread gpuTh([&]() {
        const uint64_t t0 = MLA_FusedQ4KT_NowUs();
        // Consume resolved range — no second ResolveQuantBlockRange.
        gpuOk = MLA_GemvRangeArgmax(14, base, baseBytes, hidden, 0, cut,
                                    (uint32_t)hiddenDim, &gpuRange, 1, gpuBest);
        gpuUs = MLA_FusedQ4KT_NowUs() - t0;
    });
    {
        const uint64_t t0 = MLA_FusedQ4KT_NowUs();
        // Float path matches GPU Q6·F32 shader for merge fairness.
        cpuOk = LogitsClimb_ArgmaxPackedRange(
            base, baseBytes, vocabSize, hiddenDim, cut, vocabSize, hidden,
            /*forceFloat=*/true, cpuTok, &cpuVal);
        cpuUs = MLA_FusedQ4KT_NowUs() - t0;
    }
    gpuTh.join();
    const uint64_t wallUs = MLA_FusedQ4KT_NowUs() - tWall0;

    if (!gpuOk || !cpuOk) {
        // Claimed GPU arm failed — do not silently seal as GPU_DISPATCH.
        LogitsLineage_NoteCpuSourceRebuild();
        g_mode.store(0);
        return LogitsClimb_ArgmaxPacked(base, baseBytes, vocabSize, hiddenDim,
                                        hidden, bestTok, bestValOut);
    }

    float bestV = gpuBest.value;
    int32_t best = (int32_t)gpuBest.row;
    if (cpuVal > bestV) { bestV = cpuVal; best = cpuTok; }

    bestTok = best;
    if (bestValOut) *bestValOut = bestV;

    LogitsLineage_CommitFreezeSample();

    NoteEma(cut, gpuUs, (uint32_t)(vocabSize - cut), cpuUs);
    g_calls.fetch_add(1);
    g_gpuRows.store(cut);
    g_cpuRows.store(vocabSize - cut);
    g_rowsTot.store(vocabSize);
    g_cpuUs.fetch_add(cpuUs);
    g_gpuUs.fetch_add(gpuUs);
    g_wallUs.fetch_add(wallUs);
    g_cpuTok.store(cpuTok);
    g_gpuTok.store((int32_t)gpuBest.row);
    g_finalTok.store(best);
    uint32_t bits = 0;
    std::memcpy(&bits, &cpuVal, 4); g_cpuBits.store(bits);
    std::memcpy(&bits, &gpuBest.value, 4); g_gpuBits.store(bits);
    std::memcpy(&bits, &bestV, 4); g_finalBits.store(bits);
    g_mode.store(1);
    g_argmaxB.store(sizeof(PackedArgmax));
    g_rangeB.store((uint64_t)cut * 4ull);
    g_fullRb.store(0);
    return true;
}

} // namespace Deep2
