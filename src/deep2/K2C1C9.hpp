#pragma once
#include <stdint.h>
#include <stddef.h>
#include "vwa/VwaRangeLineageAbi.hpp"

namespace Deep2 {

enum K2CStatus : uint32_t {
    K2C_OK = 0,
    K2C_E_NULL = 1,
    K2C_E_COUNT = 2,
    K2C_E_RANGE_MISMATCH = 3,
    K2C_E_BYTE_MISMATCH = 4,
    K2C_E_HASH_MISMATCH = 5,
    K2C_E_NO_GPU_DISPATCH = 6,
    K2C_E_PARITY = 7,
    K2C_E_NO_VALID_ARM = 8,
    K2C_E_BUDGET = 9,
    K2C_E_OPEN_GATE = 10
};

struct K2LineageVerdict {
    uint64_t fulfilledBytes;
    uint64_t dispatchedBytes;
    uint64_t fulfilledHash;
    uint64_t dispatchedHash;
    uint32_t rangeEqual;
    uint32_t byteEqual;
    uint32_t hashEqual;
    uint32_t pass;
};

struct K2CutArm {
    uint32_t gpuPercent;      // experiment label only
    uint32_t gpuRows;
    uint32_t cpuRows;
    uint32_t gpuDispatch;

    uint32_t lineagePass;
    uint32_t argmaxParity;
    uint32_t hotAllocZero;
    uint32_t shardIoZero;

    uint64_t cpuUs;
    uint64_t gpuUs;
    uint64_t joinUs;
    uint64_t wallUs;
};

struct K2CutDecision {
    uint32_t armIndex;
    uint32_t gpuPercent;
    uint32_t gpuRows;
    uint32_t cpuRows;
    uint64_t wallUs;
    uint32_t pass;
    uint32_t reserved;
};

struct K2ExpertSlicePlan {
    uint64_t expertRelativeOffset;
    uint64_t expertBytes;
    uint64_t firstBlock;
    uint64_t blockCount;
};

struct K2OverlapWitness {
    uint64_t readUs;
    uint64_t computeUs;
    uint64_t overlappedWallUs;
    uint64_t hiddenUs;
    uint64_t stallUs;
    uint32_t pass;
    uint32_t reserved;
};

struct K2BoundWitness {
    uint64_t ramPeak;
    uint64_t ramBudget;
    uint64_t vramPeak;
    uint64_t vramBudget;
    uint64_t outstandingIoPeak;
    uint64_t outstandingIoBudget;
    uint32_t pass;
    uint32_t reserved;
};

struct K2C9Witness {
    uint32_t c1Lineage;
    uint32_t c2CutSweep;
    uint32_t c3Freeze;
    uint32_t c4RealAsyncRead;
    uint32_t c5RealGpuTransfer;
    uint32_t c6ExpertSelective;
    uint32_t c7Overlap;
    uint32_t c8Bounded;
    uint32_t argmaxParity;
    uint32_t secondMountApiZero;
    uint32_t nameRelookupZero;
    uint32_t shardIoAfterWarmZero;
    uint32_t hotAllocZero;
    uint32_t gpuDispatchSeen;
    uint32_t sourceShortcutZero;
    uint32_t pass;
};

K2CStatus K2ValidateLineage(const VwaLineageRange* fulfilled,
                            uint64_t fulfilledCount,
                            const VwaLineageRange* dispatched,
                            uint64_t dispatchedCount,
                            uint32_t gpuDispatch,
                            K2LineageVerdict* out) noexcept;

K2CStatus K2BuildCutLadder(uint32_t vocabRows,
                           K2CutArm outArms[5]) noexcept;

K2CStatus K2ChooseCut(const K2CutArm* arms,
                      uint32_t armCount,
                      K2CutDecision* out) noexcept;

K2CStatus K2PlanExpertSlice(uint64_t expertRelativeOffset,
                            uint64_t expertBytes,
                            uint32_t blockBytes,
                            K2ExpertSlicePlan* out) noexcept;

K2CStatus K2ComputeOverlap(uint64_t readUs,
                           uint64_t computeUs,
                           uint64_t overlappedWallUs,
                           K2OverlapWitness* out) noexcept;

K2CStatus K2ValidateBounded(uint64_t ramPeak,
                            uint64_t ramBudget,
                            uint64_t vramPeak,
                            uint64_t vramBudget,
                            uint64_t outstandingIoPeak,
                            uint64_t outstandingIoBudget,
                            K2BoundWitness* out) noexcept;

K2CStatus K2ValidateC9(K2C9Witness* w) noexcept;

} // namespace Deep2
