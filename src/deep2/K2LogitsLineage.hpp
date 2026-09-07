// K2LogitsLineage.hpp — fulfilled↔dispatch range identity for C1
#pragma once
#include "VirtualTensorRange.hpp"
#include <cstdint>
#include <cstdio>

namespace Deep2 {

struct LogitsLineageSnap {
    uint32_t fulfilledCount = 0;
    uint32_t dispatchCount = 0;
    uint64_t fulfilledBytes = 0;
    uint64_t dispatchBytes = 0;
    uint64_t fulfilledHash = 0;
    uint64_t dispatchHash = 0;
    uint32_t logitsTotalBlocks = 0;
    uint32_t gpuFirstBlock = 0;
    uint32_t gpuBlockCount = 0;
    uint32_t cpuFirstBlock = 0;
    uint32_t cpuBlockCount = 0;
    uint32_t gpuExpectedBytes = 0;
    uint32_t matchTensor = 0;
    uint32_t matchShard = 0;
    uint32_t matchOffset = 0;
    uint32_t matchLength = 0;
    uint32_t matchOrder = 0;
    uint32_t matchHash = 0;
    uint32_t gpuDispatch = 0;
    uint32_t nameRelookup = 0;
    uint32_t secondResolve = 0;
    uint32_t secondMountApi = 0;
    uint32_t cpuSourceRebuild = 0;
    uint32_t freezeSamples = 0;
    uint32_t freezeRepeatable = 0;
    uint64_t freezeHashA = 0;
    uint64_t freezeHashB = 0;
};

void LogitsLineage_Reset();
void LogitsLineage_NoteFulfilled(const PhysicalTensorRange* ranges, size_t n,
                                 uint32_t gpuFirstBlock, uint32_t gpuBlockCount,
                                 uint32_t expectedBytes);
void LogitsLineage_NoteBlockMap(uint32_t logitsTotalBlocks,
                                uint32_t gpuFirstBlock, uint32_t gpuBlockCount,
                                uint32_t cpuFirstBlock, uint32_t cpuBlockCount);
void LogitsLineage_NoteDispatched(const PhysicalTensorRange* ranges, size_t n);
void LogitsLineage_NoteNameRelookup();
void LogitsLineage_NoteSecondResolve();
void LogitsLineage_NoteSecondMountApi();
void LogitsLineage_NoteCpuSourceRebuild();
void LogitsLineage_CommitFreezeSample();
LogitsLineageSnap LogitsLineage_Snapshot();
void LogitsLineage_Emit(FILE* f);
bool LogitsLineage_Pass();

} // namespace Deep2
