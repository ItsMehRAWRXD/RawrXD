// Titan_MoE_Orchestrator.h
// High-Frequency Mixture of Experts (MoE) Fused Forward Pipeline
// FIXED: Buffer sizing, accumulation math, and GEMV scalar reduction loop
// Option A: Scalar GEMV called per output dimension (correct, AVX2 inner loop)

#pragma once
#include <stdint.h>
#include <string.h>

extern "C" {
    void Titan_Route_Experts_Top2(const float* gate_logits, uint32_t* out_expert_indices, float* out_expert_weights);
    uint32_t Titan_GEMV_Interleaved_AVX2(const float* weights, const float* input, float* output_scalar, size_t k);
    uint32_t Titan_Dequantize_Block_AVX2(const void* packed_block_ptr, float* destination_float_array);
    uint32_t Titan_Vector_SiLU_AVX2(float* target_vector, size_t element_count);
    uint32_t Titan_RMS_Norm_AVX2(float* target_vector, const float* gamma_gain, float epsilon);
    uint32_t Titan_Vector_Scale_Add_AVX2(float* dest, const float* src, const float* bias, size_t count, float scale);
}

struct alignas(32) TitanMoEBlockQ4_1 {
    float scale;
    float bias;
    uint8_t packed_nibbles[16];
};

struct alignas(32) TitanExpertLayer {
    TitanMoEBlockQ4_1 expert_weights[8][1024];   // 8 experts, 1024 blocks each (32K weights/expert)
    alignas(32) float expert_biases[8][32];      // 32 outputs per expert
};

// Scratch sized for max dimension_k = 1024 blocks * 32 = 32768
// If your actual K is smaller, you can reduce this.
struct alignas(32) TitanScratchWorkspace {
    alignas(32) float normalized_input[32768];
    alignas(32) float dequantized_weights[32768];
    alignas(32) float expert_accumulator[32];
    alignas(32) float merged_output[32];
    alignas(32) uint32_t selected_experts[2];
    alignas(32) float routing_weights[2];
};

/**
 * Option A Forward Pass: Scalar GEMV per output dimension.
 * Correct, deterministic, and saturates memory bandwidth via AVX2 inner loops.
 * For a future Option B (8-wide batched GEMV), replace the j-loop with a batched kernel.
 */
inline bool Titan_MoE_Forward_Pass(
    const float* input_hidden_states,
    const float* rms_gamma,
    const float* gate_logits,
    const TitanExpertLayer* moe_layer,
    float* output_hidden_states,
    TitanScratchWorkspace* scratch,
    size_t dimension_k,          // Must be multiple of 32
    size_t output_dim,           // Typically 32
    float epsilon
) {
    if (((uintptr_t)input_hidden_states & 0x1F) || ((uintptr_t)moe_layer & 0x1F) || ((uintptr_t)output_hidden_states & 0x1F))
        return false;
    if ((dimension_k & 31) || (output_dim == 0) || (output_dim > 32))
        return false;

    // 1. RMSNorm
    memcpy(scratch->normalized_input, input_hidden_states, dimension_k * sizeof(float));
    if (!Titan_RMS_Norm_AVX2(scratch->normalized_input, rms_gamma, epsilon))
        return false;

    // 2. Top-2 routing
    Titan_Route_Experts_Top2(gate_logits, scratch->selected_experts, scratch->routing_weights);
    memset(scratch->merged_output, 0, output_dim * sizeof(float));

    // 3. Expert fusion loop
    const size_t num_blocks = dimension_k / 32;
    for (uint32_t i = 0; i < 2; ++i) {
        uint32_t expert_idx = scratch->selected_experts[i];
        float route_weight = scratch->routing_weights[i];
        if (expert_idx >= 8) return false;

        // Dequantize all blocks for this expert into scratch
        const TitanMoEBlockQ4_1* blocks = moe_layer->expert_weights[expert_idx];
        for (size_t b = 0; b < num_blocks; ++b) {
            Titan_Dequantize_Block_AVX2(&blocks[b], &scratch->dequantized_weights[b * 32]);
        }

        // Compute each output dimension with scalar GEMV (AVX2 inner dot product)
        for (size_t j = 0; j < output_dim; ++j) {
            // Weight row j starts at dequantized_weights[j * dimension_k] IF row-major.
            // NOTE: Adjust pointer math if your weight layout is column-major or interleaved.
            const float* row_ptr = &scratch->dequantized_weights[j * dimension_k];
            float dot = 0.0f;
            Titan_GEMV_Interleaved_AVX2(row_ptr, scratch->normalized_input, &dot, dimension_k);
            scratch->expert_accumulator[j] = dot;
        }

        // Activation
        if (!Titan_Vector_SiLU_AVX2(scratch->expert_accumulator, output_dim))
            return false;

        // Accumulate with scale and bias: merged += accumulator * route_weight + bias
        if (!Titan_Vector_Scale_Add_AVX2(
                scratch->merged_output,
                scratch->expert_accumulator,
                moe_layer->expert_biases[expert_idx],
                output_dim,
                route_weight))
            return false;
    }

    memcpy(output_hidden_states, scratch->merged_output, output_dim * sizeof(float));
    return true;
}
