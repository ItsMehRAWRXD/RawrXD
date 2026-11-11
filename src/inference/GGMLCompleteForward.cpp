/**
 * @file GGMLCompleteForward.cpp
 * @brief Complete GGML forward pass with compute graph execution
 * 
 * Part of Phase 5: Real Forward Pass Implementation
 * Integrates transformer layers into full inference pipeline.
 * 
 * @copyright RawrXD 2026
 */

#include "GGMLBackend.h"

#include <cstring>
#include <vector>

// GGML includes
extern "C" {
#include "../../3rdparty/ggml/include/ggml.h"
#include "../../3rdparty/ggml/include/ggml-backend.h"
#include "../../3rdparty/ggml/include/ggml-cpu.h"
}

namespace RawrXD {
namespace Inference {

// Forward declarations from GGMLTransformerLayer.cpp
extern struct ggml_rxd_tensor* BuildTransformerForward(
    struct ggml_rxd_context* ctx,
    struct ggml_rxd_tensor* input_tokens,
    const ModelArchitecture& arch);

// ============================================================================
// Forward Pass State
// ============================================================================

/**
 * @brief State for forward pass execution
 */
struct ForwardPassState {
    struct ggml_rxd_context* ctx = nullptr;
    struct ggml_rxd_cgraph* graph = nullptr;
    struct ggml_rxd_tensor* input_tensor = nullptr;
    struct ggml_rxd_tensor* output_tensor = nullptr;
    
    // Cached buffers
    std::vector<uint8_t> compute_buffer;
    bool is_initialized = false;
};

// ============================================================================
// Graph Building
// ============================================================================

/**
 * @brief Build compute graph for forward pass
 * 
 * @param state Forward pass state
 * @param arch Model architecture
 * @param max_tokens Maximum sequence length
 * @return true if successful
 */
static bool BuildForwardGraph(
    ForwardPassState& state,
    const ModelArchitecture& arch,
    int max_tokens) {
    
    if (!state.ctx) {
        return false;
    }
    
    // Create input tensor (will hold token IDs)
    state.input_tensor = ggml_rxd_new_tensor_1d(state.ctx, GGML_RXD_TYPE_I32, max_tokens);
    if (!state.input_tensor) {
        return false;
    }
    
    // Build transformer forward pass
    state.output_tensor = BuildTransformerForward(state.ctx, state.input_tensor, arch);
    if (!state.output_tensor) {
        return false;
    }
    
    // Create compute graph
    state.graph = ggml_rxd_new_graph(state.ctx);
    if (!state.graph) {
        return false;
    }
    
    // Build forward graph
    ggml_rxd_build_forward_expand(state.graph, state.output_tensor);
    
    return true;
}

// ============================================================================
// Graph Execution
// ============================================================================

/**
 * @brief Execute forward pass compute graph
 * 
 * @param state Forward pass state
 * @param tokens Input token IDs
 * @return true if successful
 */
static bool ExecuteForwardGraph(
    ForwardPassState& state,
    const std::vector<int>& tokens) {
    
    if (!state.ctx || !state.graph || !state.input_tensor) {
        return false;
    }
    
    // Copy input tokens to tensor
    int n_tokens = static_cast<int>(tokens.size());
    int32_t* input_data = (int32_t*)state.input_tensor->data;
    
    for (int i = 0; i < n_tokens && i < (int)state.input_tensor->ne[0]; i++) {
        input_data[i] = tokens[i];
    }
    
    // Set actual sequence length (if tensor supports dynamic shape)
    // Note: GGML tensors have fixed sizes, so we compute with max size
    // and extract only the relevant outputs
    
    // Create compute plan
    struct ggml_rxd_cplan cplan = ggml_rxd_graph_plan(state.graph, 1, nullptr);
    if (cplan.work_size == 0) {
        return false;
    }
    
    // Allocate or reuse compute buffer
    if (state.compute_buffer.size() < cplan.work_size) {
        state.compute_buffer.resize(cplan.work_size);
    }
    cplan.work_data = state.compute_buffer.data();
    
    // Execute graph
    int result = ggml_rxd_graph_compute(state.graph, &cplan);
    if (result != 0) {
        return false;
    }
    
    return true;
}

// ============================================================================
// Logits Extraction
// ============================================================================

/**
 * @brief Extract logits from output tensor
 * 
 * @param state Forward pass state
 * @param n_tokens Number of tokens in input
 * @param vocab_size Vocabulary size
 * @return Logits for last token
 */
static std::vector<float> ExtractLogits(
    ForwardPassState& state,
    int n_tokens,
    int vocab_size) {
    
    std::vector<float> logits(vocab_size, 0.0f);
    
    if (!state.output_tensor || !state.output_tensor->data) {
        return logits;
    }
    
    // Output shape: [vocab_size, max_tokens]
    // We want logits for the last input token (position n_tokens-1)
    float* output_data = (float*)state.output_tensor->data;
    
    // Calculate offset for last token
    int max_tokens = state.output_tensor->ne[1];
    int token_idx = (n_tokens - 1) % max_tokens;
    size_t offset = token_idx * vocab_size;
    
    // Copy logits
    size_t total_elements = (size_t)ggml_rxd_nelements(state.output_tensor);
    for (int i = 0; i < vocab_size && (offset + i) < total_elements; i++) {
        logits[i] = output_data[offset + i];
    }
    
    return logits;
}

// ============================================================================
// Public API
// ============================================================================

/**
 * @brief Initialize forward pass state
 * 
 * @param state State to initialize
 * @param ctx GGML context
 * @param arch Model architecture
 * @param max_context Maximum context length
 * @return true if successful
 */
bool GGMLForward_Init(
    ForwardPassState& state,
    struct ggml_rxd_context* ctx,
    const ModelArchitecture& arch,
    int max_context) {
    
    if (!ctx) {
        return false;
    }
    
    state.ctx = ctx;
    
    // Build compute graph
    if (!BuildForwardGraph(state, arch, max_context)) {
        return false;
    }
    
    state.is_initialized = true;
    return true;
}

/**
 * @brief Run forward pass
 * 
 * @param state Initialized forward pass state
 * @param tokens Input tokens
 * @param vocab_size Vocabulary size
 * @return Logits for next token prediction
 */
std::vector<float> GGMLForward_Run(
    ForwardPassState& state,
    const std::vector<int>& tokens,
    int vocab_size) {
    
    std::vector<float> logits;
    
    if (!state.is_initialized || tokens.empty()) {
        return logits;
    }
    
    // Execute forward pass
    if (!ExecuteForwardGraph(state, tokens)) {
        return logits;
    }
    
    // Extract logits
    logits = ExtractLogits(state, static_cast<int>(tokens.size()), vocab_size);
    
    return logits;
}

/**
 * @brief Cleanup forward pass state
 * 
 * @param state State to cleanup
 */
void GGMLForward_Cleanup(ForwardPassState& state) {
    // Graph and tensors are managed by GGML context
    // Just clear our references
    state.graph = nullptr;
    state.input_tensor = nullptr;
    state.output_tensor = nullptr;
    state.ctx = nullptr;
    state.is_initialized = false;
    state.compute_buffer.clear();
}

// ============================================================================
// Simple API for GGMLBackend Integration
// ============================================================================

/**
 * @brief Simple forward pass for GGMLBackend
 * 
 * This is the main entry point used by GGMLBackend::Forward()
 * 
 * @param ctx GGML context
 * @param arch Model architecture
 * @param tokens Input tokens
 * @return Logits vector
 */
std::vector<float> GGMLForward_SimplePass(
    struct ggml_rxd_context* ctx,
    const ModelArchitecture& arch,
    const std::vector<int>& tokens) {
    
    std::vector<float> logits;
    
    if (!ctx || tokens.empty()) {
        return logits;
    }
    
    // Create input tensor
    int n_tokens = static_cast<int>(tokens.size());
    struct ggml_rxd_tensor* input = ggml_rxd_new_tensor_1d(ctx, GGML_RXD_TYPE_I32, n_tokens);
    if (!input) {
        return logits;
    }
    
    // Copy tokens
    int32_t* input_data = (int32_t*)input->data;
    for (int i = 0; i < n_tokens; i++) {
        input_data[i] = tokens[i];
    }
    
    // Build forward pass
    struct ggml_rxd_tensor* output = BuildTransformerForward(ctx, input, arch);
    if (!output) {
        return logits;
    }
    
    // Create and build graph
    struct ggml_rxd_cgraph* graph = ggml_rxd_new_graph(ctx);
    if (!graph) {
        return logits;
    }
    
    ggml_rxd_build_forward_expand(graph, output);
    
    // Create compute plan
    struct ggml_rxd_cplan cplan = ggml_rxd_graph_plan(graph, 1, nullptr);
    if (cplan.work_size == 0) {
        return logits;
    }
    
    // Allocate work buffer
    std::vector<uint8_t> work_buffer(cplan.work_size);
    cplan.work_data = work_buffer.data();
    
    // Execute
    if (ggml_rxd_graph_compute(graph, &cplan) != 0) {
        return logits;
    }
    
    // Extract logits
    int vocab_size = arch.vocabSize > 0 ? arch.vocabSize : 32000;
    logits.resize(vocab_size);
    
    if (output->data) {
        float* output_data = (float*)output->data;
        // Get last token's logits
        size_t offset = (n_tokens - 1) * vocab_size;
        size_t total_elements = (size_t)ggml_rxd_nelements(output);
        
        for (int i = 0; i < vocab_size && (offset + i) < total_elements; i++) {
            logits[i] = output_data[offset + i];
        }
    }
    
    return logits;
}

} // namespace Inference
} // namespace RawrXD
