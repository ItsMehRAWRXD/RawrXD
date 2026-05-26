// Sovereign_Core_Substrate_Extension.h
#pragma once
#include <stdint.h>

extern "C" {
    uint32_t Sovereign_RingBuffer_Write(volatile uint64_t* write_idx, volatile uint64_t* read_idx, uint32_t* buffer_base, uint64_t capacity_mask, uint32_t value_to_write);
    uint32_t Sovereign_RingBuffer_Read(volatile uint64_t* write_idx, volatile uint64_t* read_idx, uint32_t* buffer_base, uint64_t capacity_mask, uint32_t* out_value_ptr);
    void Titan_Token_Stream_Push(uint32_t* token_buffer_ptr, uint64_t max_sequence_len, uint32_t new_token);
    void Sovereign_Yield_Execution(uint64_t iteration_count);
    void Sovereign_Hardware_Fence(void);
}
