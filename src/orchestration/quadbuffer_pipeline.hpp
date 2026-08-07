#pragma once
#include <atomic>
#include <string>
#include <vector>
#include <mutex>
#include <cstdint>

// ---------------------------------------------------------------------------
// Extern declarations for real MASM kernel functions
// ---------------------------------------------------------------------------
extern "C" {
    void    rawrxd_prefetch_tensor_async(void* tensor_data, uint32_t layer_id, uint32_t slot_index);
    uint64_t rawrxd_rotate_buffer_slots(void* current_active_ptr, void* next_ready_ptr, uint64_t rdtsc_threshold);
    int64_t QB_StreamTensor(uint64_t tensor_name_hash, void* p_dest, uint64_t max_bytes, uint32_t timeout_ms);
    int64_t QB_ReleaseTensor(uint64_t tensor_name_hash);
}

/**
 * @enum BufferStatus
 * @brief States for the QuadBuffer pipeline slots.
 */
enum class BufferStatus : uint32_t {
    EMPTY = 0,
    FETCHING = 1,
    READY = 2,
    ACTIVE_COMPUTE = 3,
    RECYCLING = 4
};

/**
 * @struct QuadBufferSlot
 * @brief Represents a single 4GB tensor shard slot.
 */
struct QuadBufferSlot {
    uint32_t layerId;
    BufferStatus status;
    void* tensorData; // 4GB Q4_K_M allocation
    uint64_t fetchStartTime;
    uint64_t fetchEndTime;
};

/**
 * @class QuadBufferPipeline
 * @brief 4-slot circular pipeline for 800B model shard execution.
 *        Wires to real MASM kernels: QB_StreamTensor + rawrxd_prefetch_tensor_async.
 */
class QuadBufferPipeline {
public:
    static const int SLOT_COUNT = 4;
    static constexpr uint64_t LAYER_HASH_SEED = 14695981039346656037ULL;
    static constexpr uint64_t LAYER_HASH_PRIME = 1099511628211ULL;

    QuadBufferPipeline() : m_activeSlotIndex(0), m_stallCount(0), m_totalRotations(0) {
        for (int i = 0; i < SLOT_COUNT; ++i) {
            m_slots[i].status = BufferStatus::EMPTY;
            m_slots[i].tensorData = nullptr;
            m_slots[i].layerId = 0xFFFFFFFF;
        }
    }

    /**
     * @brief Triggers an asynchronous pre-fetch for a specific layer.
     *        Calls rawrxd_prefetch_tensor_async MASM kernel with non-temporal hints.
     */
    bool prefetchLayer(uint32_t layerId, int slotIndex) {
        if (slotIndex < 0 || slotIndex >= SLOT_COUNT) return false;

        std::lock_guard<std::mutex> lock(m_slotMutex);
        if (m_slots[slotIndex].status != BufferStatus::EMPTY &&
            m_slots[slotIndex].status != BufferStatus::RECYCLING) {
            return false;
        }

        m_slots[slotIndex].layerId = layerId;
        m_slots[slotIndex].status = BufferStatus::FETCHING;
        m_slots[slotIndex].fetchStartTime = __rdtsc();

        // Call real MASM prefetch kernel with non-temporal hints
        if (m_slots[slotIndex].tensorData) {
            rawrxd_prefetch_tensor_async(m_slots[slotIndex].tensorData, layerId, static_cast<uint32_t>(slotIndex));
        }

        // Kick async DMA via QB_StreamTensor (non-blocking, timeout=0)
        uint64_t hash = fnv1a64_layer(layerId);
        QB_StreamTensor(hash, m_slots[slotIndex].tensorData, 0x1000000, 0);

        m_slots[slotIndex].fetchEndTime = __rdtsc();
        m_slots[slotIndex].status = BufferStatus::READY;
        return true;
    }

    /**
     * @brief Rotates the pipeline: Active -> Recycle, Ready -> Active.
     *        Calls rawrxd_rotate_buffer_slots for atomic slot migration.
     */
    void rotatePipeline() {
        std::lock_guard<std::mutex> lock(m_slotMutex);

        int prevActive = m_activeSlotIndex;
        int nextActive = (m_activeSlotIndex + 1) % SLOT_COUNT;

        // Atomic slot migration via MASM kernel
        void* prevPtr = m_slots[prevActive].tensorData;
        void* nextPtr = m_slots[nextActive].tensorData;
        uint64_t threshold = 10000000ULL; // ~10M cycles stall threshold
        uint64_t stallDebt = rawrxd_rotate_buffer_slots(&prevPtr, &nextPtr, threshold);

        m_slots[prevActive].status = BufferStatus::RECYCLING;

        if (m_slots[nextActive].status != BufferStatus::READY) {
            // PIPELINE STALL: Fetch > Compute
            handlePipelineStall(m_slots[nextActive].layerId, stallDebt);
        }

        m_activeSlotIndex = nextActive;
        m_slots[nextActive].status = BufferStatus::ACTIVE_COMPUTE;
        ++m_totalRotations;

        // Release previous layer tensor to allow eviction
        if (m_slots[prevActive].layerId != 0xFFFFFFFF) {
            uint64_t hash = fnv1a64_layer(m_slots[prevActive].layerId);
            QB_ReleaseTensor(hash);
        }
    }

    /**
     * @brief Query pipeline health.
     */
    struct PipelineStats {
        uint32_t activeSlot;
        uint32_t stallCount;
        uint32_t totalRotations;
        uint64_t lastStallDebt;
    };

    PipelineStats getStats() const {
        PipelineStats s;
        s.activeSlot = static_cast<uint32_t>(m_activeSlotIndex.load());
        s.stallCount = m_stallCount.load();
        s.totalRotations = m_totalRotations.load();
        s.lastStallDebt = m_lastStallDebt;
        return s;
    }

private:
    QuadBufferSlot m_slots[SLOT_COUNT];
    std::atomic<int> m_activeSlotIndex;
    std::atomic<uint32_t> m_stallCount;
    std::atomic<uint32_t> m_totalRotations;
    std::mutex m_slotMutex;
    uint64_t m_lastStallDebt = 0;

    /**
     * @brief FNV-1a64 hash for layer ID -> tensor name hash mapping.
     */
    static uint64_t fnv1a64_layer(uint32_t layerId) {
        uint64_t hash = LAYER_HASH_SEED;
        for (int i = 0; i < 4; ++i) {
            hash ^= (layerId >> (i * 8)) & 0xFF;
            hash *= LAYER_HASH_PRIME;
        }
        return hash;
    }

    void startAsyncDMA(uint32_t layerId, int slot) {
        // Deprecated: logic moved into prefetchLayer which calls QB_StreamTensor directly.
        (void)layerId;
        (void)slot;
    }

    void handlePipelineStall(uint32_t layerId, uint64_t stallDebt) {
        ++m_stallCount;
        m_lastStallDebt = stallDebt;
        // Stall telemetry is propagated via rawrxd_rotate_buffer_slots return value.
        // Caller can query getStats() and react (e.g., increase prefetch depth).
        (void)layerId;
    }
};
