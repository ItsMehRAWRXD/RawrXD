// Sovereign_Substrate_Extended_Primitives.h
#pragma once
#include <stdint.h>

extern "C" {
    // Structural Multi-Core Lock-Free Element Queue Mechanics
    typedef struct {
        uint64_t* storage_buffer_array_ptr;
        uint64_t   queue_capacity_bitmask;
        volatile   uint64_t head_position_index;
        volatile   uint64_t tail_position_index;
    } SovereignLockFreeQueueContext;

    uint64_t Sovereign_LockFree_Queue_Enqueue(SovereignLockFreeQueueContext* queue_context_ptr, uint64_t element_payload_value);
    uint64_t Sovereign_LockFree_Queue_Dequeue(SovereignLockFreeQueueContext* queue_context_ptr, uint64_t* destination_output_ptr);

    // Physical Hardware Core Allocation and Verification Tasks
    void Sovereign_Page_Table_PreTouch_Range(void* allocation_memory_base_address, uint64_t allocation_total_byte_size);
    uint64_t Sovereign_Memory_Validate_Range(void* target_memory_base_address, uint64_t range_byte_size_limit);

    // Generation Stream Primitives
    uint64_t Titan_Token_Stream_Buffer_Append(uint32_t* token_array_base_ptr, uint64_t current_sequence_length_val, uint32_t incoming_token_identifier_id, uint64_t maximum_sequence_capacity_bound);
    void Titan_Token_Stream_Buffer_Clear(uint32_t* token_array_base_ptr, uint64_t total_elements_count);

    // Privileged Layer Model-Specific Register Access Wrappers
    uint64_t Sovereign_MSR_Read_Register(uint32_t target_msr_index_address, uint64_t* external_output_data_ptr);
    uint64_t Sovereign_MSR_Write_Register(uint32_t target_msr_index_address, uint64_t input_payload_configuration_val);
}
