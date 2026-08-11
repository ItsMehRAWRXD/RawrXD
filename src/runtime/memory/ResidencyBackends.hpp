// ResidencyBackends.hpp — C++ ABI mirror of ResidencyBackends.asm structures
// Must match MASM layout byte-for-byte.
#pragma once
#include <cstdint>
#include <cstddef>

// Minimal Windows API declarations (avoid full windows.h dependency)
extern "C" __declspec(dllimport) void* __stdcall VirtualAlloc(void* lpAddress, size_t dwSize,
    uint32_t flAllocationType, uint32_t flProtect);
extern "C" __declspec(dllimport) int32_t __stdcall VirtualFree(void* lpAddress, size_t dwSize,
    uint32_t dwFreeType);

constexpr uint32_t MEM_COMMIT     = 0x1000;
constexpr uint32_t MEM_RESERVE    = 0x2000;
constexpr uint32_t PAGE_READWRITE = 0x04;

namespace rawrxd {

// Tier constants
constexpr uint8_t TIER_SSD  = 0;
constexpr uint8_t TIER_RAM  = 1;
constexpr uint8_t TIER_VRAM = 2;

// Block state constants
constexpr uint8_t BLOCK_STATE_CLEAN = 0;
constexpr uint8_t BLOCK_STATE_DIRTY = 1;
constexpr uint8_t BLOCK_STATE_FLUSH = 2;

// GPU type constants
constexpr uint32_t GPU_TYPE_NONE   = 0;
constexpr uint32_t GPU_TYPE_VULKAN = 1;
constexpr uint32_t GPU_TYPE_ROCM   = 2;

// ---------------------------------------------------------------------------
// DYNAMIC_BLOCK — must match MASM exactly (48 bytes packed)
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct DynamicBlock {
    uint32_t BlockID;       // +0
    uint8_t  Tier;          // +4
    uint8_t  State;         // +5
    uint16_t RefCount;      // +6
    uint64_t LastAccess;    // +8
    uint64_t DataPtr;       // +16
    uint64_t NextLRU;       // +24
    uint64_t PrevLRU;       // +32
    uint32_t AccessCount;   // +40
    uint8_t  Referenced;    // +44
    uint8_t  _pad[3];       // +45..47
};
static_assert(sizeof(DynamicBlock) == 48, "DynamicBlock size mismatch with MASM");
static_assert(offsetof(DynamicBlock, BlockID)     == 0,  "BlockID offset");
static_assert(offsetof(DynamicBlock, Tier)          == 4,  "Tier offset");
static_assert(offsetof(DynamicBlock, State)         == 5,  "State offset");
static_assert(offsetof(DynamicBlock, RefCount)      == 6,  "RefCount offset");
static_assert(offsetof(DynamicBlock, LastAccess)    == 8,  "LastAccess offset");
static_assert(offsetof(DynamicBlock, DataPtr)       == 16, "DataPtr offset");
static_assert(offsetof(DynamicBlock, NextLRU)       == 24, "NextLRU offset");
static_assert(offsetof(DynamicBlock, PrevLRU)       == 32, "PrevLRU offset");
static_assert(offsetof(DynamicBlock, AccessCount)   == 40, "AccessCount offset");
static_assert(offsetof(DynamicBlock, Referenced)    == 44, "Referenced offset");

// ---------------------------------------------------------------------------
// DYNAMIC_TIER — must match MASM exactly (52 bytes packed)
// ---------------------------------------------------------------------------
struct DynamicTier {
    uint64_t BasePtr;       // +0
    uint64_t Capacity;      // +8
    uint64_t Used;          // +16
    uint32_t BlockSize;     // +24
    uint32_t MaxBlocks;     // +28
    uint64_t FreeList;      // +32
    uint32_t SpinLock;      // +40
    uint64_t hFile;         // +44
};
static_assert(sizeof(DynamicTier) == 52, "DynamicTier size mismatch with MASM");
static_assert(offsetof(DynamicTier, BasePtr)   == 0,  "BasePtr offset");
static_assert(offsetof(DynamicTier, Capacity)  == 8,  "Capacity offset");
static_assert(offsetof(DynamicTier, Used)      == 16, "Used offset");
static_assert(offsetof(DynamicTier, BlockSize)  == 24, "BlockSize offset");
static_assert(offsetof(DynamicTier, MaxBlocks)  == 28, "MaxBlocks offset");
static_assert(offsetof(DynamicTier, FreeList)  == 32, "FreeList offset");
static_assert(offsetof(DynamicTier, SpinLock)   == 40, "SpinLock offset");
static_assert(offsetof(DynamicTier, hFile)      == 44, "hFile offset");

// ---------------------------------------------------------------------------
// RESIDENCY_POOL — must match MASM exactly (192 bytes packed)
// ---------------------------------------------------------------------------
struct ResidencyPool {
    DynamicTier SSD;        // +0   (52 bytes)
    DynamicTier RAM;        // +52  (52 bytes)
    DynamicTier VRAM;       // +104 (52 bytes)
    uint64_t    BlockTable;  // +156
    uint64_t    BlockIndex;  // +164
    uint32_t    TotalBlocks; // +172
    uint32_t    ClockHand;   // +176
    uint32_t    GlobalLock;  // +180
    uint64_t    CycleCounter;// +184
};
static_assert(sizeof(ResidencyPool) == 192, "ResidencyPool size mismatch with MASM");
static_assert(offsetof(ResidencyPool, SSD)          == 0,   "SSD offset");
static_assert(offsetof(ResidencyPool, RAM)          == 52,  "RAM offset");
static_assert(offsetof(ResidencyPool, VRAM)         == 104, "VRAM offset");
static_assert(offsetof(ResidencyPool, BlockTable)   == 156, "BlockTable offset");
static_assert(offsetof(ResidencyPool, BlockIndex)   == 164, "BlockIndex offset");
static_assert(offsetof(ResidencyPool, TotalBlocks)  == 172, "TotalBlocks offset");
static_assert(offsetof(ResidencyPool, ClockHand)    == 176, "ClockHand offset");
static_assert(offsetof(ResidencyPool, GlobalLock)    == 180, "GlobalLock offset");
static_assert(offsetof(ResidencyPool, CycleCounter) == 184, "CycleCounter offset");
#pragma pack(pop)

// ---------------------------------------------------------------------------
// MASM exports (cdecl / default x64 calling convention)
// ---------------------------------------------------------------------------
extern "C" {
    // Gate 1: Eviction
    uint64_t DRP_RunEvictionScan(ResidencyPool* pool, void* backend_ctx);

    // Gate 2: GPU upload
    int32_t DRP_InitGPUBackend(void* backend_ctx, uint32_t type, uint64_t device, uint64_t queue);
    uint64_t DRP_UploadVRAMBlocks(void* backend_ctx);

    // Gate 3: Async SSD flush
    int32_t DRP_StartFlushWorker(void* backend_ctx);
    int32_t DRP_StopFlushWorker(void* backend_ctx);
    int32_t DRP_EnqueueSSDFlush(void* backend_ctx, uint32_t block_id,
                                 uint64_t src_ptr, uint64_t dst_offset, uint32_t byte_size);

    // Hot path: metadata-only touch
    DynamicBlock* DRP_TouchWeight(ResidencyPool* pool, uint32_t block_id, uint64_t epoch);
}

} // namespace rawrxd
