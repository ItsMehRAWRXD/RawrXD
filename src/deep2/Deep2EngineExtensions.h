#pragma once

#include <cstdint>

static constexpr uint32_t STATUS_EMPTY = 0;
static constexpr uint32_t STATUS_DMA_PENDING = 1;
static constexpr uint32_t STATUS_READY_DECRYPT = 2;
static constexpr uint32_t STATUS_PLAINTEXT = 3;

// Mirrors the assembly RING_BUFFER_SLOT struct layout exactly
struct RingBufferSlot {
    uint8_t* bufferPtr;
    uint64_t payloadSize;
    volatile uint32_t slotStatus; 
    uint32_t reserved;
};

// Mirrors the assembly RING_CONTEXT struct layout exactly
struct RingContext {
    RingBufferSlot slots[4];
    uint32_t producerIndex;
    uint32_t consumerIndex;
    volatile uint32_t lockVariable;
    uint32_t totalSlots;
};

struct RingPublicationRecord {
    uint32_t slotIndex = 0;
    uint32_t producerSeq = 0;
    uint32_t generation = 0;
    uint32_t statusBefore = STATUS_EMPTY;
    uint32_t statusAfter = STATUS_EMPTY;
    const uint8_t* payloadPtr = nullptr;
    uint64_t payloadBytes = 0;
    uint64_t nonzeroBytes = 0;
    uint64_t publishTsc = 0;
    uint64_t acquireTsc = 0;
    bool submitted = false;
    bool published = false;
    bool acquired = false;
};

// External MASM linkings matching Microsoft x64 calling convention
extern "C" {
    void InitializeRingBuffer(RingContext* context, uint8_t* baseMemory, uint64_t windowSize);
    uint8_t* SubmitDmaToRing(RingContext* context, uint64_t payloadSize);
    void CompleteDmaAndSignal(RingContext* context, uint32_t slotIndex);
    uint64_t ProcessDecryptPipeline(RingContext* context, const uint8_t* preExpandedKeys);

    /**
     * High-throughput AVX-512 GEMV Assembly Kernel
     * @param outVector Destination array for calculated activations (FP32)
     * @param weightMatrix Base address of the decrypted, plaintext weight block
     * @param inVector Input activation vector (FP32)
     * @param columns Matrix column count (Must be a multiple of 16 for ZMM structural alignment)
     * @param rows Matrix row count passed over the Microsoft x64 stack frame structure
     */
    void Avx512_Gemv_Row_Stride(
        float* outVector, 
        const float* weightMatrix, 
        const float* inVector, 
        uint64_t columns, 
        uint64_t rows
    );

    // Host ring -> mapped VRAM aperture (AVX-512 non-temporal).
    // Returns 0 on success, nonzero on bad args / alignment.
    uint64_t StreamRingBufferToVramAperture(const void* src, void* dst, uint64_t bytes);
}

// NVMe dual-slot streamer: prefetch next shard while computing current.
void SovereignContinuousStreamingLoop(
    const wchar_t* rawModelPath,
    uint64_t sliceSize,
    uint32_t tokenSweepCount = 128);
