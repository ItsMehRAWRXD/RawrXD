// Sovereign_Substrate_Core_Primitives.h
#pragma once
#include <stdint.h>

extern "C" {
    // Synchronization & Pipeline Control
    void Sovereign_SpinLock_Acquire(volatile uint32_t* lock_address);
    void Sovereign_SpinLock_Release(volatile uint32_t* lock_address);
    void Sovereign_Yield_Processor(void);

    // Byte-Oriented Ring Buffer Configuration Structure
    typedef struct {
        uint8_t* storage_buffer_base;
        uint64_t  capacity_bitmask;
        volatile  uint64_t read_position_index;
        volatile  uint64_t write_position_index;
    } SovereignRingBufferContext;

    uint64_t Sovereign_RingBuffer_Write(SovereignRingBufferContext* ring_buffer_context_ptr, uint8_t input_byte_data);
    uint64_t Sovereign_RingBuffer_Read(SovereignRingBufferContext* ring_buffer_context_ptr, uint8_t* output_destination_ptr);

    // Advanced Matrix and Mathematical Accelerations
    void Titan_Tensor_Transpose_4x4_FP32(const float* source_matrix_ptr, float* destination_matrix_ptr);
    void Sovereign_Math_VectorRsqrt_FP32(const float* input_vector_array, float* output_vector_array);
}
