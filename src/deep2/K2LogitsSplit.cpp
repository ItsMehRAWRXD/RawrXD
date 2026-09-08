// K2LogitsSplit.cpp — CPU||GPU packed logits + LOGITS_SPLIT_AUTO_BAIL_001.
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
std::atomic<uint64_t> g_joinUs{0}, g_cpuOnlyEst{0};
std::atomic<int32_t> g_cpuTok{-1}, g_gpuTok{-1}, g_finalTok{-1};
std::atomic<uint32_t> g_cpuBits{0}, g_gpuBits{0}, g_finalBits{0};
std::atomic<uint32_t> g_mode{0}; // 1=SPLIT selected this emit window
std::atomic<uint64_t> g_argmaxB{0}, g_rangeB{0}, g_fullRb{0};
std::atomic<uint32_t> g_profitable{0}, g_pathSel{0}; // 0=CPU_ONLY 1=SPLIT
std::atomic<uint64_t> g_bailHits{0};

uint32_t g_cutSticky = 0;
float g_cpuEma = 0.f, g_gpuEma = 0.f, g_splitWallEma = 0.f;
bool g_emaOk = false;
bool g_bailSticky = false;
uint64_t g_lastCpuUs = 0, g_lastGpuUs = 0, g_lastWallUs = 0;

uint32_t ChooseCut(uint32_t vocab) {
    constexpr uint32_t kMaxGpuRows = 131072u;
    constexpr uint32_t kMinGpuRows = 4096u;
    if (const char* e = std::getenv("DEEP2_LOGITS_GPU_CUT")) {
        const unsigned v = (unsigned)std::strtoul(e, nullptr, 10);
        if (v >= kMinGpuRows && v < vocab)
            return (std::min)((uint32_t)v, kMaxGpuRows);
    }
    uint32_t cut = 65536u;
    if (g_emaOk && g_cpuEma > 0.f && g_gpuEma > 0.f) {
        const float sum = g_cpuEma + g_gpuEma;
        float frac = g_gpuEma / sum;
        if (frac < 0.20f) frac = 0.20f;
        if (frac > 0.85f) frac = 0.85f;
        cut = (uint32_t)(frac * (float)vocab + 0.5f);
    }
    if (g_lastCpuUs > 0 && g_lastGpuUs > 0) {
        if (g_lastCpuUs > g_lastGpuUs + (g_lastGpuUs / 8ull)) {
            const uint32_t bump = (uint32_t)((vocab / 32u) & ~255u);
            cut += bump ? bump : 4096u;
        } else if (g_lastGpuUs > g_lastCpuUs + (g_lastCpuUs / 8ull)) {
            const uint32_t drop = (uint32_t)((vocab / 32u) & ~255u);
            if (cut > drop + kMinGpuRows) cut -= drop;
        }
    }
    if (cut < kMinGpuRows) cut = kMinGpuRows;
    if (cut > kMaxGpuRows) cut = kMaxGpuRows;
    if (cut >= vocab) cut = vocab / 2u;
    if (g_cutSticky) {
        const int d = (int)cut - (int)g_cutSticky;
        if (d > -1024 && d < 1024) cut = g_cutSticky;
    }
    g_cutSticky = cut;
    return cut;
}

void NoteEma(uint32_t gpuRows, uint64_t gpuUs, uint32_t cpuRows,
             uint64_t cpuUs, uint64_t wallUs, uint32_t vocab) {
    g_lastGpuUs = gpuUs;
    g_lastCpuUs = cpuUs;
    g_lastWallUs = wallUs;
    if (gpuUs > 0 && gpuRows > 0) {
        const float r = (float)gpuRows / (float)gpuUs;
        g_gpuEma = g_emaOk ? (0.25f * r + 0.75f * g_gpuEma) : r;
    }
    if (cpuUs > 0 && cpuRows > 0) {
        const float r = (float)cpuRows / (float)cpuUs;
        g_cpuEma = g_emaOk ? (0.25f * r + 0.75f * g_cpuEma) : r;
    }
    g_splitWallEma =
        g_emaOk ? (0.25f * (float)wallUs + 0.75f * g_splitWallEma)
                : (float)wallUs;
    g_emaOk = true;
    const uint64_t mx = (cpuUs > gpuUs) ? cpuUs : gpuUs;
    const uint64_t join = (wallUs > mx) ? (wallUs - mx) : 0ull;
    g_joinUs.fetch_add(join, std::memory_order_relaxed);
    uint64_t cpuOnly = 0;
    if (g_cpuEma > 0.f)
        cpuOnly = (uint64_t)((float)vocab / g_cpuEma + 0.5f);
    else if (cpuRows > 0 && cpuUs > 0)
        cpuOnly = (cpuUs * (uint64_t)vocab) / (uint64_t)cpuRows;
    g_cpuOnlyEst.store(cpuOnly, std::memory_order_relaxed);
    const int profitable =
        (cpuOnly > 0 && (uint64_t)(g_splitWallEma + 0.5f) < cpuOnly) ? 1 : 0;
    g_profitable.store((uint32_t)profitable, std::memory_order_relaxed);
    // LOGITS_SPLIT_AUTO_BAIL_001: sticky when split wall >= CPU-only est.
    if (cpuOnly > 0 && (uint64_t)(g_splitWallEma + 0.5f) >= cpuOnly)
        g_bailSticky = true;
}

bool RunCpuOnly(const uint8_t* base, size_t baseBytes, size_t vocabSize,
                size_t hiddenDim, const float* hidden, int32_t& bestTok,
                float* bestValOut) {
    const uint64_t t0 = MLA_FusedQ4KT_NowUs();
    const bool ok = LogitsClimb_ArgmaxPacked(base, baseBytes, vocabSize,
                                             hiddenDim, hidden, bestTok,
                                             bestValOut);
    const uint64_t us = MLA_FusedQ4KT_NowUs() - t0;
    g_calls.fetch_add(1);
    g_gpuRows.store(0);
    g_cpuRows.store(vocabSize);
    g_rowsTot.store(vocabSize);
    g_cpuUs.fetch_add(us);
    g_wallUs.fetch_add(us);
    g_serialUs.fetch_add(us);
    g_cpuOnlyEst.store(us, std::memory_order_relaxed);
    g_profitable.store(0, std::memory_order_relaxed);
    g_pathSel.store(0, std::memory_order_relaxed);
    g_mode.store(0);
    g_finalTok.store(bestTok);
    g_cpuTok.store(bestTok);
    g_gpuTok.store(-1);
    if (g_cpuEma <= 0.f && us > 0 && vocabSize > 0)
        g_cpuEma = (float)vocabSize / (float)us;
    return ok;
}
} // namespace

void LogitsSplit_Reset() {
    g_calls = g_gpuRows = g_cpuRows = g_rowsTot = 0;
    g_cpuUs = g_gpuUs = g_wallUs = g_serialUs = 0;
    g_joinUs = g_cpuOnlyEst = 0;
    g_cpuTok = g_gpuTok = g_finalTok = -1;
    g_mode = 0;
    g_argmaxB = g_rangeB = g_fullRb = 0;
    g_profitable = 0;
    g_pathSel = 0;
    g_bailHits = 0;
    g_cutSticky = 0;
    g_cpuEma = g_gpuEma = g_splitWallEma = 0.f;
    g_emaOk = false;
    g_bailSticky = false;
    g_lastCpuUs = g_lastGpuUs = g_lastWallUs = 0;
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
    s.modeSplit = g_pathSel.load();
    s.gpuArgmaxBytes = g_argmaxB.load();
    s.gpuRangeOutBytes = g_rangeB.load();
    s.fullReadback = g_fullRb.load();
    uint32_t cb = g_cpuBits.load(), gb = g_gpuBits.load(), fb = g_finalBits.load();
    std::memcpy(&s.cpuVal, &cb, 4);
    std::memcpy(&s.gpuVal, &gb, 4);
    std::memcpy(&s.finalVal, &fb, 4);
    s.cpuRowsPerUs = g_cpuEma;
    s.gpuRowsPerUs = g_gpuEma;
    s.joinUs = g_joinUs.load();
    s.cpuOnlyEstUs = g_cpuOnlyEst.load();
    s.splitProfitable = g_profitable.load();
    s.pathSelected = g_pathSel.load();
    s.bailHits = g_bailHits.load();
    return s;
}

void LogitsSplit_Emit(FILE* f) {
    if (!f) f = stdout;
    const auto s = LogitsSplit_Snapshot();
    fprintf(f, "LOGITS_SPLIT_AUTO_BAIL_001=1\n");
    fprintf(f, "LOGITS_CPU_ROWS=%llu\n", (unsigned long long)s.cpuRows);
    fprintf(f, "LOGITS_GPU_ROWS=%llu\n", (unsigned long long)s.gpuRows);
    fprintf(f, "LOGITS_CPU_US=%llu\n", (unsigned long long)s.cpuBranchUs);
    fprintf(f, "LOGITS_GPU_US=%llu\n", (unsigned long long)s.gpuBranchUs);
    fprintf(f, "LOGITS_JOIN_US=%llu\n", (unsigned long long)s.joinUs);
    fprintf(f, "LOGITS_SPLIT_WALL_US=%llu\n",
            (unsigned long long)s.splitWallUs);
    fprintf(f, "LOGITS_CPU_ONLY_EST_US=%llu\n",
            (unsigned long long)s.cpuOnlyEstUs);
    fprintf(f, "LOGITS_SPLIT_PROFITABLE=%u\n", s.splitProfitable);
    fprintf(f, "LOGITS_PATH_SELECTED=%s\n",
            s.pathSelected ? "SPLIT" : "CPU_ONLY");
    fprintf(f, "LOGITS_EXPOSED_US=%llu\n",
            (unsigned long long)s.splitWallUs);
    fprintf(f, "LOGITS_BAIL_HITS=%llu\n", (unsigned long long)s.bailHits);
    fprintf(f,
            "LOGITS_MODE=%s\n"
            "LOGITS_ROWS_TOTAL=%llu LOGITS_ROW_ACCOUNTING=1\n"
            "GPU_LOGITS_FULL_READBACK=%llu GPU_ARGMAX_BYTES=%llu "
            "GPU_RANGE_OUT_BYTES=%llu\n"
            "CPU_ARGMAX_TOKEN=%d GPU_ARGMAX_TOKEN=%d FINAL_ARGMAX_TOKEN=%d\n"
            "CPU_BRANCH_US=%llu GPU_BRANCH_US=%llu\n",
            s.pathSelected ? "CPU_GPU_SPLIT" : "CPU_ONLY",
            (unsigned long long)s.rowsTotal,
            (unsigned long long)s.fullReadback,
            (unsigned long long)s.gpuArgmaxBytes,
            (unsigned long long)s.gpuRangeOutBytes, s.cpuTok, s.gpuTok,
            s.finalTok, (unsigned long long)s.cpuBranchUs,
            (unsigned long long)s.gpuBranchUs);
    fprintf(f, "CPU_LOGIT_ROWS_PER_US=%.4f GPU_LOGIT_ROWS_PER_US=%.4f\n",
            s.cpuRowsPerUs, s.gpuRowsPerUs);
    fflush(f);
}

bool LogitsSplit_Wanted() {
    const char* e = std::getenv("DEEP2_LOGITS_GPU_SPLIT");
    return e && e[0] == '1' && MLA_GpuGemvWanted();
}

bool LogitsSplit_ArgmaxPacked(const uint8_t* base, size_t baseBytes,
                              size_t vocabSize, size_t hiddenDim,
                              const float* hidden,
                              const VirtualTensorDesc* logitsDesc,
                              int32_t& bestTok, float* bestValOut) {
    if (!LogitsSplit_Wanted() || !MLA_GpuGemvWanted() || !logitsDesc ||
        !logitsDesc->addressed) {
        return RunCpuOnly(base, baseBytes, vocabSize, hiddenDim, hidden,
                          bestTok, bestValOut);
    }
    if (vocabSize < 4096u) {
        return RunCpuOnly(base, baseBytes, vocabSize, hiddenDim, hidden,
                          bestTok, bestValOut);
    }

    // AUTO_BAIL: after measured split loses to CPU-only estimate, stay CPU.
    if (g_bailSticky) {
        g_bailHits.fetch_add(1, std::memory_order_relaxed);
        return RunCpuOnly(base, baseBytes, vocabSize, hiddenDim, hidden,
                          bestTok, bestValOut);
    }

    QuantBlockGeometry geo{};
    if (!GetQuantBlockGeometry(logitsDesc->type, geo) ||
        geo.elementsPerBlock == 0 || geo.bytesPerBlock == 0) {
        return RunCpuOnly(base, baseBytes, vocabSize, hiddenDim, hidden,
                          bestTok, bestValOut);
    }

    const uint32_t cut = ChooseCut((uint32_t)vocabSize);
    K2RowBlockRequest rowReq{};
    rowReq.firstRow = 0;
    rowReq.rowCount = cut;
    rowReq.cols = hiddenDim;
    rowReq.blockElements = geo.elementsPerBlock;
    K2BlockRangeOut br{};
    if (K2RowsToBlockRangeX64_Fixed(&rowReq, &br) != 0) {
        return RunCpuOnly(base, baseBytes, vocabSize, hiddenDim, hidden,
                          bestTok, bestValOut);
    }

    K2RowBlockRequest fullReq = rowReq;
    fullReq.rowCount = vocabSize;
    K2BlockRangeOut fullBr{};
    if (K2RowsToBlockRangeX64_Fixed(&fullReq, &fullBr) != 0) {
        return RunCpuOnly(base, baseBytes, vocabSize, hiddenDim, hidden,
                          bestTok, bestValOut);
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
        return RunCpuOnly(base, baseBytes, vocabSize, hiddenDim, hidden,
                          bestTok, bestValOut);
    }

    const uint32_t expectedBytes = (uint32_t)gpuRange.byteCount;
    if (expectedBytes != (uint32_t)(cut * rowBytes) ||
        baseBytes < gpuRange.tensorRelativeOffset + gpuRange.byteCount) {
        return RunCpuOnly(base, baseBytes, vocabSize, hiddenDim, hidden,
                          bestTok, bestValOut);
    }

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
        gpuOk = MLA_GemvRangeArgmax(14, base, baseBytes, hidden, 0, cut,
                                    (uint32_t)hiddenDim, &gpuRange, 1, gpuBest);
        gpuUs = MLA_FusedQ4KT_NowUs() - t0;
    });
    {
        const uint64_t t0 = MLA_FusedQ4KT_NowUs();
        cpuOk = LogitsClimb_ArgmaxPackedRange(
            base, baseBytes, vocabSize, hiddenDim, cut, vocabSize, hidden,
            /*forceFloat=*/false, cpuTok, &cpuVal);
        cpuUs = MLA_FusedQ4KT_NowUs() - t0;
    }
    gpuTh.join();
    const uint64_t wallUs = MLA_FusedQ4KT_NowUs() - tWall0;

    if (!gpuOk || !cpuOk) {
        LogitsLineage_NoteCpuSourceRebuild();
        return RunCpuOnly(base, baseBytes, vocabSize, hiddenDim, hidden,
                          bestTok, bestValOut);
    }

    float bestV = gpuBest.value;
    int32_t best = (int32_t)gpuBest.row;
    if (cpuVal > bestV) {
        bestV = cpuVal;
        best = cpuTok;
    }
    bestTok = best;
    if (bestValOut) *bestValOut = bestV;
    LogitsLineage_CommitFreezeSample();

    NoteEma(cut, gpuUs, (uint32_t)(vocabSize - cut), cpuUs, wallUs,
            (uint32_t)vocabSize);
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
    std::memcpy(&bits, &cpuVal, 4);
    g_cpuBits.store(bits);
    std::memcpy(&bits, &gpuBest.value, 4);
    g_gpuBits.store(bits);
    std::memcpy(&bits, &bestV, 4);
    g_finalBits.store(bits);
    g_mode.store(1);
    g_pathSel.store(1, std::memory_order_relaxed);
    g_argmaxB.store(sizeof(PackedArgmax));
    g_rangeB.store((uint64_t)cut * 4ull);
    g_fullRb.store(0);

    // If this sample already lost, next tokens bail (keep this result).
    if (g_bailSticky)
        g_bailHits.fetch_add(1, std::memory_order_relaxed);
    return true;
}

} // namespace Deep2
