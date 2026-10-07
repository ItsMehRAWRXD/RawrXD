#include "K2C1C9.hpp"

namespace Deep2 {

K2CStatus K2ValidateLineage(const VwaLineageRange* fulfilled,
                            uint64_t fulfilledCount,
                            const VwaLineageRange* dispatched,
                            uint64_t dispatchedCount,
                            uint32_t gpuDispatch,
                            K2LineageVerdict* out) noexcept {
    if (!out) return K2C_E_NULL;
    *out = {};
    if (!fulfilled || !dispatched) return K2C_E_NULL;
    if (fulfilledCount == 0 || dispatchedCount == 0 ||
        fulfilledCount != dispatchedCount) {
        return K2C_E_COUNT;
    }
    if (!gpuDispatch) return K2C_E_NO_GPU_DISPATCH;

    out->fulfilledBytes = VwaRangeSetSumBytes64(fulfilled, fulfilledCount);
    out->dispatchedBytes = VwaRangeSetSumBytes64(dispatched, dispatchedCount);
    if (out->fulfilledBytes == UINT64_MAX ||
        out->dispatchedBytes == UINT64_MAX) {
        return K2C_E_BYTE_MISMATCH;
    }

    out->fulfilledHash = VwaRangeSetHash64(fulfilled, fulfilledCount);
    out->dispatchedHash = VwaRangeSetHash64(dispatched, dispatchedCount);
    out->rangeEqual = VwaRangeSetEqual64(
        fulfilled, dispatched, fulfilledCount);
    out->byteEqual = (out->fulfilledBytes == out->dispatchedBytes) ? 1u : 0u;
    out->hashEqual = (out->fulfilledHash == out->dispatchedHash) ? 1u : 0u;

    if (!out->rangeEqual) return K2C_E_RANGE_MISMATCH;
    if (!out->byteEqual) return K2C_E_BYTE_MISMATCH;
    if (!out->hashEqual) return K2C_E_HASH_MISMATCH;

    out->pass = 1;
    return K2C_OK;
}

K2CStatus K2BuildCutLadder(uint32_t vocabRows,
                           K2CutArm outArms[5]) noexcept {
    if (!outArms) return K2C_E_NULL;
    if (vocabRows == 0) return K2C_E_COUNT;

    static constexpr uint32_t pct[5] = {0, 25, 50, 75, 100};
    for (uint32_t i = 0; i < 5; ++i) {
        outArms[i] = {};
        outArms[i].gpuPercent = pct[i];

        // Experiment percentage is converted to exact logical rows.
        // Physical authority remains quant-block resolution downstream.
        const uint64_t rows =
            (static_cast<uint64_t>(vocabRows) * pct[i]) / 100ull;
        outArms[i].gpuRows = static_cast<uint32_t>(rows);
        outArms[i].cpuRows = vocabRows - outArms[i].gpuRows;
    }
    return K2C_OK;
}

K2CStatus K2ChooseCut(const K2CutArm* arms,
                      uint32_t armCount,
                      K2CutDecision* out) noexcept {
    if (!arms || !out) return K2C_E_NULL;
    if (armCount == 0) return K2C_E_COUNT;
    *out = {};

    uint64_t best = UINT64_MAX;
    uint32_t bestIndex = UINT32_MAX;

    for (uint32_t i = 0; i < armCount; ++i) {
        const K2CutArm& a = arms[i];
        if (!a.argmaxParity || !a.lineagePass ||
            !a.hotAllocZero || !a.shardIoZero) {
            continue;
        }
        if (a.gpuRows != 0 && !a.gpuDispatch) {
            continue;
        }
        if (a.wallUs == 0) continue;
        if (a.wallUs < best) {
            best = a.wallUs;
            bestIndex = i;
        }
    }

    if (bestIndex == UINT32_MAX) return K2C_E_NO_VALID_ARM;

    out->armIndex = bestIndex;
    out->gpuPercent = arms[bestIndex].gpuPercent;
    out->gpuRows = arms[bestIndex].gpuRows;
    out->cpuRows = arms[bestIndex].cpuRows;
    out->wallUs = best;
    out->pass = 1;
    return K2C_OK;
}

K2CStatus K2PlanExpertSlice(uint64_t expertRelativeOffset,
                            uint64_t expertBytes,
                            uint32_t blockBytes,
                            K2ExpertSlicePlan* out) noexcept {
    if (!out) return K2C_E_NULL;
    *out = {};
    if (blockBytes == 0 || expertBytes == 0) return K2C_E_COUNT;

    // ExpertId is a slice coordinate, not a new tensor.
    // Reject any slice that cannot be represented exactly in the
    // mounted tensor's physical quant-block language.
    if ((expertRelativeOffset % blockBytes) != 0 ||
        (expertBytes % blockBytes) != 0) {
        return K2C_E_RANGE_MISMATCH;
    }

    out->expertRelativeOffset = expertRelativeOffset;
    out->expertBytes = expertBytes;
    out->firstBlock = expertRelativeOffset / blockBytes;
    out->blockCount = expertBytes / blockBytes;
    return K2C_OK;
}

K2CStatus K2ComputeOverlap(uint64_t readUs,
                           uint64_t computeUs,
                           uint64_t overlappedWallUs,
                           K2OverlapWitness* out) noexcept {
    if (!out) return K2C_E_NULL;
    *out = {};
    if (!readUs || !computeUs || !overlappedWallUs) return K2C_E_COUNT;

    out->readUs = readUs;
    out->computeUs = computeUs;
    out->overlappedWallUs = overlappedWallUs;

    const uint64_t serial = readUs + computeUs;
    if (serial < readUs) return K2C_E_COUNT; // overflow
    out->hiddenUs = serial > overlappedWallUs
        ? serial - overlappedWallUs : 0;

    const uint64_t ideal = readUs > computeUs ? readUs : computeUs;
    out->stallUs = overlappedWallUs > ideal
        ? overlappedWallUs - ideal : 0;

    // "Prefetch=1" is not enough. Require measured wall improvement.
    out->pass = overlappedWallUs < serial ? 1u : 0u;
    return out->pass ? K2C_OK : K2C_E_OPEN_GATE;
}

K2CStatus K2ValidateBounded(uint64_t ramPeak,
                            uint64_t ramBudget,
                            uint64_t vramPeak,
                            uint64_t vramBudget,
                            uint64_t outstandingIoPeak,
                            uint64_t outstandingIoBudget,
                            K2BoundWitness* out) noexcept {
    if (!out) return K2C_E_NULL;
    *out = {};
    out->ramPeak = ramPeak;
    out->ramBudget = ramBudget;
    out->vramPeak = vramPeak;
    out->vramBudget = vramBudget;
    out->outstandingIoPeak = outstandingIoPeak;
    out->outstandingIoBudget = outstandingIoBudget;

    if (!ramBudget || !vramBudget || !outstandingIoBudget)
        return K2C_E_BUDGET;

    out->pass =
        (ramPeak <= ramBudget &&
         vramPeak <= vramBudget &&
         outstandingIoPeak <= outstandingIoBudget) ? 1u : 0u;
    return out->pass ? K2C_OK : K2C_E_BUDGET;
}

K2CStatus K2ValidateC9(K2C9Witness* w) noexcept {
    if (!w) return K2C_E_NULL;
    const uint32_t pass =
        w->c1Lineage &&
        w->c2CutSweep &&
        w->c3Freeze &&
        w->c4RealAsyncRead &&
        w->c5RealGpuTransfer &&
        w->c6ExpertSelective &&
        w->c7Overlap &&
        w->c8Bounded &&
        w->argmaxParity &&
        w->secondMountApiZero &&
        w->nameRelookupZero &&
        w->shardIoAfterWarmZero &&
        w->hotAllocZero &&
        w->gpuDispatchSeen &&
        w->sourceShortcutZero;
    w->pass = pass ? 1u : 0u;
    return pass ? K2C_OK : K2C_E_OPEN_GATE;
}

} // namespace Deep2
