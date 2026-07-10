// ============================================================================
// Sovereign Graph Runner Implementation
// ============================================================================
// Canonical transformer decode step using execution contracts
// ============================================================================

#include "SovereignGraphRunner.hpp"
#include <iostream>
#include <chrono>
#include <algorithm>

namespace RawrXD {
namespace Execution {

// ============================================================================
// Construction / Destruction
// ============================================================================

SovereignGraphRunner::SovereignGraphRunner() = default;

SovereignGraphRunner::~SovereignGraphRunner() {
    if (initialized_) {
        Shutdown();
    }
}

// ============================================================================
// Initialization
// ============================================================================

bool SovereignGraphRunner::Initialize(std::shared_ptr<IExecutionBackend> backend,
                                      const TransformerLayerConfig& config) {
    if (initialized_) {
        return true;
    }
    
    backend_ = backend;
    config_ = config;
    
    if (!backend_ || !backend_->IsInitialized()) {
        std::cerr << "[GraphRunner] Backend not initialized\n";
        return false;
    }
    
    std::cout << "[GraphRunner] Initializing with config:\n";
    std::cout << "  Hidden size: " << config_.hidden_size << "\n";
    std::cout << "  Num heads: " << config_.num_heads << "\n";
    std::cout << "  Head dim: " << config_.head_dim << "\n";
    std::cout << "  Intermediate: " << config_.intermediate_size << "\n";
    
    // Allocate activation buffers
    if (!AllocateActivations()) {
        std::cerr << "[GraphRunner] Failed to allocate activations\n";
        return false;
    }
    
    // Initialize RoPE cache
    if (!InitializeRoPECache()) {
        std::cerr << "[GraphRunner] Failed to initialize RoPE cache\n";
        return false;
    }
    
    // Register default kernels
    RegisterKernel(KernelRole::EmbeddingLookup, "Sovereign_Embedding_Lookup");
    RegisterKernel(KernelRole::PreNorm, "Sovereign_RMSNorm_F32_AVX2");
    RegisterKernel(KernelRole::QKVProjection, "Sovereign_Attention_Projections");
    RegisterKernel(KernelRole::RoPE, "Sovereign_RoPE_Apply_F32_AVX2");
    RegisterKernel(KernelRole::SelfAttention, "Sovereign_Attention_Scoring");
    RegisterKernel(KernelRole::AttentionOutput, "Sovereign_Attention_Output");
    RegisterKernel(KernelRole::FFN, "Sovereign_FFN");
    RegisterKernel(KernelRole::FinalNorm, "Sovereign_RMSNorm_F32_AVX2");
    
    state_.max_seq_len = config_.max_seq_len;
    state_.current_seq_len = 0;
    
    initialized_ = true;
    std::cout << "[GraphRunner] Initialized successfully\n";
    return true;
}

void SovereignGraphRunner::Shutdown() {
    if (!initialized_) return;
    
    FreeActivations();
    FreeRoPECache();
    
    backend_.reset();
    kernel_registry_.clear();
    
    initialized_ = false;
    std::cout << "[GraphRunner] Shutdown complete\n";
}

// ============================================================================
// Core Forward Pass
// ============================================================================

ExecutionResult SovereignGraphRunner::Forward(const std::vector<int32_t>& input_tokens,
                                               uint32_t max_new_tokens) {
    if (!initialized_) {
        return ExecutionResult::Error(ExecutionStatus::RuntimeFailure,
                                      "GraphRunner not initialized");
    }
    
    auto start_time = std::chrono::steady_clock::now();
    
    ExecutionResult final_result;
    final_result.status = ExecutionStatus::Success;
    
    // Process each new token
    for (uint32_t i = 0; i < max_new_tokens; ++i) {
        int32_t next_token;
        
        if (i == 0 && !input_tokens.empty()) {
            // First token from input
            next_token = input_tokens[0];
        } else {
            // Sample next token (would call sampling kernel)
            next_token = 1; // Placeholder
        }
        
        // Single decode step
        auto step_result = ForwardSingleToken(next_token, state_.current_seq_len);
        
        if (!step_result.IsSuccess()) {
            return step_result;
        }
        
        state_.current_seq_len++;
        
        // Accumulate telemetry
        final_result.telemetry.latency_ms += step_result.telemetry.latency_ms;
        final_result.telemetry.generated_tokens++;
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    final_result.telemetry.latency_ms = duration.count();
    final_result.telemetry.CalculateDerived();
    
    last_telemetry_ = final_result.telemetry;
    
    return final_result;
}

ExecutionResult SovereignGraphRunner::ForwardSingleToken(int32_t input_token,
                                                          uint32_t position) {
    // Canonical transformer decode step:
    // Embedding → PreNorm → QKV → RoPE → Attention → Residual → FFN → Residual
    
    ExecutionResult result;
    result.status = ExecutionStatus::Success;
    
    auto step_start = std::chrono::steady_clock::now();
    
    // 1. Embedding lookup
    auto embed_result = RunEmbedding(input_token);
    if (!embed_result.IsSuccess()) return embed_result;
    
    // 2. Pre-normalization (RMSNorm)
    auto prenorm_result = RunPreNorm();
    if (!prenorm_result.IsSuccess()) return prenorm_result;
    
    // 3. Self-attention block
    auto attn_result = RunSelfAttention();
    if (!attn_result.IsSuccess()) return attn_result;
    
    // 4. Post-attention residual
    // (In-place: activation += residual)
    
    // 5. FFN block
    auto ffn_result = RunFFN();
    if (!ffn_result.IsSuccess()) return ffn_result;
    
    // 6. Post-FFN residual
    // (In-place: activation += residual)
    
    // 7. Final normalization
    auto finalnorm_result = RunFinalNorm();
    if (!finalnorm_result.IsSuccess()) return finalnorm_result;
    
    auto step_end = std::chrono::steady_clock::now();
    auto step_duration = std::chrono::duration_cast<std::chrono::milliseconds>(step_end - step_start);
    
    result.telemetry.latency_ms = step_duration.count();
    result.telemetry.generated_tokens = 1;
    result.telemetry.tokens_per_second = 1000.0 / step_duration.count();
    
    return result;
}

// ============================================================================
// Layer Operations
// ============================================================================

ExecutionResult SovereignGraphRunner::RunEmbedding(int32_t token_id) {
    ExecutionRequest request;
    request.command = "embedding";
    request.model = "sovereign_embedding";
    request.prompt = std::to_string(token_id);
    request.max_tokens = 1;
    
    return DispatchKernel(KernelRole::EmbeddingLookup, request);
}

ExecutionResult SovereignGraphRunner::RunPreNorm() {
    ExecutionRequest request;
    request.command = "rmsnorm";
    request.model = "sovereign_rmsnorm";
    request.prompt = "prenorm";
    request.max_tokens = 1;
    
    return DispatchKernel(KernelRole::PreNorm, request);
}

ExecutionResult SovereignGraphRunner::RunSelfAttention() {
    // QKV projection
    ExecutionRequest qkv_request;
    qkv_request.command = "qkv_projection";
    qkv_request.model = "sovereign_attention";
    
    auto qkv_result = DispatchKernel(KernelRole::QKVProjection, qkv_request);
    if (!qkv_result.IsSuccess()) return qkv_result;
    
    // RoPE
    ExecutionRequest rope_request;
    rope_request.command = "rope";
    rope_request.model = "sovereign_rope";
    
    auto rope_result = DispatchKernel(KernelRole::RoPE, rope_request);
    if (!rope_result.IsSuccess()) return rope_result;
    
    // Attention scoring
    ExecutionRequest attn_request;
    attn_request.command = "attention";
    attn_request.model = "sovereign_attention";
    
    auto attn_result = DispatchKernel(KernelRole::SelfAttention, attn_request);
    if (!attn_result.IsSuccess()) return attn_result;
    
    // Output projection
    ExecutionRequest out_request;
    out_request.command = "attention_output";
    out_request.model = "sovereign_attention";
    
    return DispatchKernel(KernelRole::AttentionOutput, out_request);
}

ExecutionResult SovereignGraphRunner::RunFFN() {
    ExecutionRequest request;
    request.command = "ffn";
    request.model = "sovereign_ffn";
    request.prompt = "ffn";
    request.max_tokens = 1;
    
    return DispatchKernel(KernelRole::FFN, request);
}

ExecutionResult SovereignGraphRunner::RunFinalNorm() {
    ExecutionRequest request;
    request.command = "rmsnorm";
    request.model = "sovereign_rmsnorm";
    request.prompt = "finalnorm";
    request.max_tokens = 1;
    
    return DispatchKernel(KernelRole::FinalNorm, request);
}

// ============================================================================
// Kernel Dispatch
// ============================================================================

ExecutionResult SovereignGraphRunner::DispatchKernel(KernelRole role,
                                                      const ExecutionRequest& request) {
    // Find kernel in registry
    auto it = std::find_if(kernel_registry_.begin(), kernel_registry_.end(),
                           [role](const KernelRegistryEntry& entry) {
                               return entry.role == role;
                           });
    
    if (it == kernel_registry_.end() || !it->available) {
        return ExecutionResult::Error(ExecutionStatus::RuntimeFailure,
                                      "Kernel not available for role: " + std::to_string(static_cast<int>(role)));
    }
    
    // Check backend support
    if (!BackendSupportsKernel(it->kernel_name)) {
        return ExecutionResult::Error(ExecutionStatus::BackendUnavailable,
                                      "Backend does not support kernel: " + it->kernel_name);
    }
    
    // Dispatch through backend
    return backend_->Execute(request);
}

// ============================================================================
// Registry Management
// ============================================================================

void SovereignGraphRunner::RegisterKernel(KernelRole role, const std::string& kernel_name) {
    // Check if already registered
    auto it = std::find_if(kernel_registry_.begin(), kernel_registry_.end(),
                           [role](const KernelRegistryEntry& entry) {
                               return entry.role == role;
                           });
    
    if (it != kernel_registry_.end()) {
        it->kernel_name = kernel_name;
        it->available = BackendSupportsKernel(kernel_name);
    } else {
        KernelRegistryEntry entry;
        entry.role = role;
        entry.kernel_name = kernel_name;
        entry.backend_type = "cpu";
        entry.available = BackendSupportsKernel(kernel_name);
        kernel_registry_.push_back(entry);
    }
}

bool SovereignGraphRunner::HasKernel(KernelRole role) const {
    auto it = std::find_if(kernel_registry_.begin(), kernel_registry_.end(),
                           [role](const KernelRegistryEntry& entry) {
                               return entry.role == role && entry.available;
                           });
    return it != kernel_registry_.end();
}

std::string SovereignGraphRunner::GetKernelName(KernelRole role) const {
    auto it = std::find_if(kernel_registry_.begin(), kernel_registry_.end(),
                           [role](const KernelRegistryEntry& entry) {
                               return entry.role == role;
                           });
    return (it != kernel_registry_.end()) ? it->kernel_name : "";
}

// ============================================================================
// Memory Management
// ============================================================================

bool SovereignGraphRunner::AllocateActivations() {
    // Allocate ping-pong buffers for activations
    size_t hidden_bytes = config_.hidden_size * sizeof(float);
    size_t intermediate_bytes = config_.intermediate_size * sizeof(float);
    state_.activation_size = std::max(hidden_bytes, intermediate_bytes);
    
    // Would use backend allocator in real implementation
    state_.activation_a = new char[state_.activation_size];
    state_.activation_b = new char[state_.activation_size];
    
    return state_.activation_a && state_.activation_b;
}

void SovereignGraphRunner::FreeActivations() {
    delete[] static_cast<char*>(state_.activation_a);
    delete[] static_cast<char*>(state_.activation_b);
    state_.activation_a = nullptr;
    state_.activation_b = nullptr;
}

bool SovereignGraphRunner::InitializeRoPECache() {
    // Precompute sin/cos tables for RoPE
    size_t cache_size = config_.max_seq_len * config_.head_dim * sizeof(float);
    
    state_.rope_cache_sin = new char[cache_size];
    state_.rope_cache_cos = new char[cache_size];
    
    // Would precompute actual values here
    
    return state_.rope_cache_sin && state_.rope_cache_cos;
}

void SovereignGraphRunner::FreeRoPECache() {
    delete[] static_cast<char*>(state_.rope_cache_sin);
    delete[] static_cast<char*>(state_.rope_cache_cos);
    state_.rope_cache_sin = nullptr;
    state_.rope_cache_cos = nullptr;
}

// ============================================================================
// KV Cache Management
// ============================================================================

void SovereignGraphRunner::ClearKVCache() {
    state_.current_seq_len = 0;
    // Would clear actual KV cache memory
}

void SovereignGraphRunner::ResizeKVCache(uint32_t new_max_seq_len) {
    // Would reallocate KV cache
    state_.max_seq_len = new_max_seq_len;
}

// ============================================================================
// Backend Support
// ============================================================================

bool SovereignGraphRunner::BackendSupportsKernel(const std::string& kernel_name) const {
    if (!backend_) return false;
    // Check if backend supports this specific kernel
    // For SovereignBackend, we need to check if kernel is loaded
    // For SimulatorBackend, it supports everything
    return backend_->SupportsModel(kernel_name);
}

// ============================================================================
// Telemetry
// ============================================================================

void SovereignGraphRunner::ResetTelemetry() {
    last_telemetry_ = ExecutionTelemetry();
}

// ============================================================================
// Factory
// ============================================================================

std::unique_ptr<SovereignGraphRunner> CreateGraphRunner(
    std::shared_ptr<IExecutionBackend> backend,
    const TransformerLayerConfig& config) {
    
    auto runner = std::make_unique<SovereignGraphRunner>();
    if (!runner->Initialize(backend, config)) {
        return nullptr;
    }
    return runner;
}

} // namespace Execution
} // namespace RawrXD
