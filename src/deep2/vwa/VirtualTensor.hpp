//=============================================================================
// VirtualTensor.hpp — IR-aware virtual tensor with next-use tracking
//
// Extends VirtualTensorRef with fields derived from kExecutionIRTable
// to enable optimal (Belady-style) eviction rather than LRU.
//
// Design principle: the model's logical address space is independent
// of physical memory. VirtualTensor tracks where bytes ARE vs. where
// they will be NEEDED next, according to the static IR execution order.
//=============================================================================

#pragma once
#include "VwaTypes.hpp"
#include <cstdint>
#include <atomic>

namespace Deep2 {
namespace vwa {

/**
 * Residency tier within the physical memory hierarchy.
 * Tier values are ordered so that lower = hotter/faster.
 */
enum class ResidencyTier : uint8_t {
    Cold = 0,      // On ROM/NVMe backing store only
    Warm = 1,      // In host RAM (mapped or staging)
    Hot  = 2,      // In GPU VRAM (active compute)
    Pinned = 3,    // Locked, cannot evict
};

/*---------------------------------------------------------------------------
 * VirtualTensor
 *
 * A tensor in the virtual address space. The logical identity (tensorId,
 * romOffset, encodedBytes) never changes; only residency state transitions.
 *
 * nextUseOp:      IR op index that will next consume this tensor's weights.
 *                 For repeated decode, this wraps around using token stride.
 * nextUseDistance: number of IR ops between now and nextUseOp.
 *                  Computed from circular token model.
 * refCount:       how many in-flight ops currently hold a lease on this
 *                 tensor's physical bytes.
 * tier:           current physical residency tier.
 * gpu:            which GPU (0/1) holds the hot copy, if resident.
 * pinned:         hard lock preventing eviction (e.g. shared weights,
 *                 router, norms).
 * inFlight:       async prefetch/DMA in progress.
 *---------------------------------------------------------------------------*/
struct VirtualTensor {
    // --- Immutable logical identity (from TensorROM / RMV mount) ---
    uint32_t tensorId = 0;
    uint64_t romOffset = 0;
    uint64_t encodedBytes = 0;
    uint32_t encoding = 0;  // GGMLType value from QuantTypeTable

    // --- Quant block geometry (from FillBlockGeometry or VwaBlockMath) ---
    uint32_t blockBytes = 0;
    uint32_t blockElements = 0;
    uint32_t numBlocks = 0;
    uint32_t expertCount = 0;        // 0 = dense
    uint64_t expertStrideBytes = 0;

    // --- IR-aware scheduling fields ---
    std::atomic<uint32_t> nextUseOp{0};
    std::atomic<uint32_t> nextUseDistance{0};
    std::atomic<int32_t>  refCount{0};
    std::atomic<ResidencyTier> tier{ResidencyTier::Cold};
    std::atomic<uint32_t> gpu{0xFFFFFFFF};   // 0xFFFFFFFF = not on GPU
    std::atomic<bool>     pinned{false};
    std::atomic<bool>     inFlight{false};

    // --- Physical backing (set when tier >= Warm) ---
    void* hostPtr = nullptr;        // RMV-mapped or malloc'd staging
    void* devicePtr = nullptr;      // GPU allocation or malloc'd device sim
    size_t hostBytes = 0;
    size_t deviceBytes = 0;
    uint32_t generation = 0;        // ROM mount epoch

    // --- Block-level granularity state ---
    Deep2::vwa::VwaState state = Deep2::vwa::VwaState::NotResident;

    VirtualTensor() = default;

    // Construct from a VirtualTensorRef (post-mount)
    explicit VirtualTensor(const vwa::VirtualTensorRef& ref)
        : tensorId(static_cast<uint32_t>(ref.desc.id))
        , romOffset(ref.desc.fileOffset)
        , encodedBytes(ref.desc.byteLength)
        , encoding(ref.desc.type)
        , blockBytes(ref.blockBytes)
        , blockElements(ref.blockElements)
        , numBlocks(ref.numBlocks)
        , expertCount(ref.expertCount)
        , expertStrideBytes(ref.expertStrideBytes)
        , hostPtr(ref.host)
        , devicePtr(ref.device)
        , hostBytes(ref.hostBytes)
        , deviceBytes(ref.deviceBytes)
        , generation(ref.generation)
        , state(ref.state)
    {}

    bool IsResident() const noexcept {
        return tier.load() == ResidencyTier::Hot ||
               tier.load() == ResidencyTier::Warm ||
               tier.load() == ResidencyTier::Pinned;
    }

    bool CanEvict() const noexcept {
        return !pinned.load() && refCount.load() == 0 &&
               tier.load() != ResidencyTier::Cold;
    }
};

} // namespace vwa
} // namespace Deep2
