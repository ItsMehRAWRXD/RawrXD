#pragma once
#include <stdint.h>
#include <stddef.h>

// Observational ABI only.
// This is NOT a mount descriptor and is NOT a second physical authority.
// Populate it from an already-resolved PhysicalTensorRange at the exact
// fulfillment/dispatch seam.
extern "C" {

struct VwaLineageRange {
    uint64_t tensorLo;          // +0
    uint64_t tensorHi;          // +8
    uint64_t mountGeneration;   // +16; zero if current RMV has no generation
    uint64_t absoluteOffset;    // +24
    uint64_t byteCount;         // +32
    uint64_t firstBlock;        // +40
    uint64_t blockCount;        // +48
    uint32_t sourceId;          // +56; use canonical shard/source field
    uint32_t flags;             // +60
};

struct K2RowBlockRequest {
    uint64_t firstRow;
    uint64_t rowCount;
    uint64_t cols;
    uint64_t blockElements;
};

struct K2BlockRangeOut {
    uint64_t firstBlock;
    uint64_t blockCount;
    uint64_t blocksPerRow;
    uint64_t reserved;
};

uint64_t VwaRangeSetHash64(const VwaLineageRange* ranges, uint64_t count);
uint64_t VwaRangeSetSumBytes64(const VwaLineageRange* ranges, uint64_t count);
uint32_t VwaRangeSetEqual64(const VwaLineageRange* a,
                            const VwaLineageRange* b,
                            uint64_t count);

// 0 = success
// 1 = null
// 2 = empty/zero geometry
// 3 = row width is not an integral number of quant blocks
// 4 = uint64 overflow
uint32_t K2RowsToBlockRangeX64_Fixed(const K2RowBlockRequest* in,
                                     K2BlockRangeOut* out);
}

static_assert(sizeof(VwaLineageRange) == 64, "VwaLineageRange ABI drift");
static_assert(offsetof(VwaLineageRange, byteCount) == 32, "ABI drift");
static_assert(sizeof(K2RowBlockRequest) == 32, "K2RowBlockRequest ABI drift");
static_assert(sizeof(K2BlockRangeOut) == 32, "K2BlockRangeOut ABI drift");
