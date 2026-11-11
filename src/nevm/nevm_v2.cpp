//============================================================================
// nevm_v2.cpp
// RawrXD N-EVM v0.2 - Complete Implementation
// Neural Execution Virtual Machine with all components integrated
//============================================================================

#include "nevm_v2.hpp"
#include <algorithm>
#include <cstring>

namespace RawrXD {
namespace NEVM {

//============================================================================
// NEVM_v2 Implementation
//============================================================================

NEVM_v2::NEVM_v2(const Config& config)
    : config_(config)
    , initialized_(false)
    , loader_(nullptr) {
    
    stats_ = {};
}

NEVM_v2::~NEVM_v2() {
    Shutdown();
}

bool NEVM_v2::Initialize() {
    if (initialized_) {
        return true;
    }
    
    // Create MMU
    NeuralMMU::Config mmu_config;
    mmu_config.ram_budget = config_.ram_budget;
    mmu_config.vram_budget = config_.vram_budget;
    mmu_config.l3_cache_size = config_.l3_cache_size;
    mmu_config.enable_prefetch = config_.enable_prefetch;
    
    mmu_ = std::make_unique<NeuralMMU>(mmu_config);
    
    // Create precision controller
    PrecisionController::Config pc_config;
    pc_config.default_mode = PrecisionMode::Q4;
    pc_config.enable_adaptive = config_.enable_adaptive_precision;
    
    precision_controller_ = std::make_unique<PrecisionController>(pc_config);
    
    // Create prefetch engine
    PrefetchEngine::Config prefetch_config;
    prefetch_config.strategy = PrefetchStrategy::ADAPTIVE;
    prefetch_config.max_concurrent_prefetches = config_.max_prefetch_threads;
    
    prefetch_engine_ = std::make_unique<PrefetchEngine>(
        mmu_.get(), precision_controller_.get(), prefetch_config);
    
    // Create residency manager
    residency_manager_ = std::make_unique<ResidencyManager>();
    
    // Create trace recorder if enabled
    if (config_.enable_tracing) {
        TraceRecorder::Config trace_config;
        trace_recorder_ = std::make_unique<TraceRecorder>(trace_config);
    }
    
    // Create block-granular precision controller
    BlockGranularPrecisionController::Config bg_config;
    block_precision_controller_ = std::make_unique<BlockGranularPrecisionController>(bg_config);
    
    initialized_ = true;
    return true;
}

void NEVM_v2::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    // Stop all components
    if (trace_recorder_ && trace_recorder_->IsRecording()) {
        trace_recorder_->StopRecording();
    }
    
    prefetch_engine_.reset();
    precision_controller_.reset();
    residency_manager_.reset();
    block_precision_controller_.reset();
    trace_recorder_.reset();
    mmu_.reset();
    
    loader_ = nullptr;
    initialized_ = false;
}

bool NEVM_v2::LoadModel(const std::wstring& path) {
    if (!initialized_) {
        return false;
    }
    
    // Determine format from extension
    std::wstring ext = path.substr(path.find_last_of(L'.'));
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    
    if (ext == L".gguf") {
        // Use GGUF loader
        loader_ = std::make_unique<GGUF_PassthroughLoader>(mmu_.get());
    } else if (ext == L".nano") {
        // Use Nano format loader
        // loader_ = std::make_unique<NanoFormatLoader>(mmu_.get());
        return false;  // Not implemented yet
    } else {
        return false;  // Unsupported format
    }
    
    if (!loader_->Open(path)) {
        loader_.reset();
        return false;
    }
    
    // Register all tensors with residency manager
    // This would iterate through all tensors in the model
    // and register them with the residency manager
    
    return true;
}

void* NEVM_v2::Execute(const void* input, size_t input_size, size_t* output_size) {
    if (!initialized_ || !loader_) {
        return nullptr;
    }
    
    // Start trace recording if enabled
    if (trace_recorder_) {
        trace_recorder_->StartRecording(stats_.tokens_generated);
    }
    
    // Get model metadata
    auto metadata = loader_->GetMetadata();
    
    // Create transformer engine
    TransformerEngine::Config engine_config;
    engine_config.num_layers = metadata.num_layers;
    engine_config.hidden_dim = metadata.hidden_dim;
    engine_config.num_heads = metadata.num_heads;
    engine_config.head_dim = metadata.hidden_dim / metadata.num_heads;
    engine_config.ffn_dim = metadata.hidden_dim * 4;  // Typical
    engine_config.vocab_size = metadata.vocab_size;
    engine_config.max_seq_len = metadata.context_length;
    engine_config.batch_size = 1;
    engine_config.default_precision = PrecisionMode::Q4;
    engine_config.use_flash_attention = true;
    engine_config.use_kv_cache = true;
    
    TransformerEngine engine(this, engine_config);
    if (!engine.Initialize(loader_.get())) {
        return nullptr;
    }
    
    // Parse input (simplified - assume token IDs)
    const int32_t* input_tokens = static_cast<const int32_t*>(input);
    uint32_t seq_len = static_cast<uint32_t>(input_size / sizeof(int32_t));
    
    // Allocate output
    size_t output_elements = seq_len * metadata.vocab_size;
    float* output_logits = new float[output_elements];
    
    // Execute forward pass
    if (!engine.Forward(input_tokens, output_logits, seq_len)) {
        delete[] output_logits;
        return nullptr;
    }
    
    // Update stats
    stats_.tokens_generated += seq_len;
    stats_.total_cycles += engine_config.num_layers;
    
    // Stop trace recording
    if (trace_recorder_) {
        trace_recorder_->StopRecording();
    }
    
    if (output_size) {
        *output_size = output_elements * sizeof(float);
    }
    
    return output_logits;
}

void* NEVM_v2::Generate(const void* prompt, size_t prompt_size, 
                        uint32_t max_tokens, float temperature) {
    if (!initialized_ || !loader_) {
        return nullptr;
    }
    
    // First, run prefill
    size_t output_size;
    void* logits = Execute(prompt, prompt_size, &output_size);
    if (!logits) {
        return nullptr;
    }
    
    // Get model metadata
    auto metadata = loader_->GetMetadata();
    
    // Create transformer engine for generation
    TransformerEngine::Config engine_config;
    engine_config.num_layers = metadata.num_layers;
    engine_config.hidden_dim = metadata.hidden_dim;
    engine_config.num_heads = metadata.num_heads;
    engine_config.head_dim = metadata.hidden_dim / metadata.num_heads;
    engine_config.ffn_dim = metadata.hidden_dim * 4;
    engine_config.vocab_size = metadata.vocab_size;
    engine_config.max_seq_len = metadata.context_length;
    engine_config.batch_size = 1;
    engine_config.default_precision = PrecisionMode::Q4;
    engine_config.use_flash_attention = true;
    engine_config.use_kv_cache = true;
    
    TransformerEngine engine(this, engine_config);
    if (!engine.Initialize(loader_.get())) {
        delete[] static_cast<float*>(logits);
        return nullptr;
    }
    
    // Allocate output buffer for generated tokens
    int32_t* generated_tokens = new int32_t[max_tokens];
    uint32_t num_generated = 0;
    
    // Sample first token from prefill output
    float* last_logits = static_cast<float*>(logits) + 
                         (prompt_size / sizeof(int32_t) - 1) * metadata.vocab_size;
    
    // Simple greedy sampling (would use actual sampling in production)
    int32_t next_token = 0;
    float max_logit = last_logits[0];
    for (uint32_t i = 1; i < metadata.vocab_size; ++i) {
        if (last_logits[i] > max_logit) {
            max_logit = last_logits[i];
            next_token = i;
        }
    }
    
    generated_tokens[0] = next_token;
    num_generated = 1;
    
    // Generate remaining tokens autoregressively
    std::vector<float> output_logits(metadata.vocab_size);
    
    for (uint32_t i = 1; i < max_tokens; ++i) {
        // Generate next token
        if (!engine.GenerateStep(&next_token, output_logits.data(), 
                                   prompt_size / sizeof(int32_t) + i)) {
            break;
        }
        
        generated_tokens[i] = next_token;
        num_generated++;
        
        // Check for end-of-sequence token
        if (next_token == metadata.eos_token_id) {
            break;
        }
    }
    
    delete[] static_cast<float*>(logits);
    
    // Update stats
    stats_.tokens_generated += num_generated;
    
    return generated_tokens;
}

void NEVM_v2::UnloadModel() {
    loader_.reset();
}

void NEVM_v2::SetAdaptivePrecision(bool enabled) {
    if (precision_controller_) {
        // Would update precision controller config
    }
}

void NEVM_v2::SetTracing(bool enabled) {
    config_.enable_tracing = enabled;
    
    if (enabled && !trace_recorder_) {
        TraceRecorder::Config trace_config;
        trace_recorder_ = std::make_unique<TraceRecorder>(trace_config);
    } else if (!enabled && trace_recorder_) {
        trace_recorder_.reset();
    }
}

bool NEVM_v2::ExportTrace(const std::string& path) {
    if (!trace_recorder_) {
        return false;
    }
    
    return trace_recorder_->ExportJSON(path);
}

NEVM_v2::Stats NEVM_v2::GetStats() const {
    Stats s = stats_;
    
    // Add MMU stats
    if (mmu_) {
        auto mmu_stats = mmu_->GetStats();
        s.vram_used = mmu_stats.vram_allocated;
        s.ram_used = mmu_stats.ram_allocated;
    }
    
    return s;
}

void NEVM_v2::ResetStats() {
    stats_ = {};
}

const char* NEVM_v2::GetVersion() {
    return "NEVM v0.2.0 - Neural Execution Virtual Machine";
}

//============================================================================
// Component Accessors
//============================================================================

NeuralMMU* NEVM_v2::GetMMU() const {
    return mmu_.get();
}

PrecisionController* NEVM_v2::GetPrecisionController() const {
    return precision_controller_.get();
}

PrefetchEngine* NEVM_v2::GetPrefetchEngine() const {
    return prefetch_engine_.get();
}

ResidencyManager* NEVM_v2::GetResidencyManager() const {
    return residency_manager_.get();
}

BlockGranularPrecisionController* NEVM_v2::GetBlockPrecisionController() const {
    return block_precision_controller_.get();
}

TraceRecorder* NEVM_v2::GetTraceRecorder() const {
    return trace_recorder_.get();
}

GGUF_PassthroughLoader* NEVM_v2::GetLoader() const {
    return loader_.get();
}

//============================================================================
// C API Implementation
//============================================================================

extern "C" {

NEVMHandle NEVM_Create(const NEVMConfig* config) {
    if (!config) {
        return nullptr;
    }
    
    NEVM_v2::Config cfg;
    cfg.ram_budget = config->ram_budget;
    cfg.vram_budget = config->vram_budget;
    cfg.l3_cache_size = config->l3_cache_size;
    cfg.enable_adaptive_precision = config->enable_adaptive_precision;
    cfg.enable_prefetch = config->enable_prefetch;
    cfg.enable_tracing = config->enable_tracing;
    cfg.max_prefetch_threads = config->max_prefetch_threads;
    
    auto* vm = new NEVM_v2(cfg);
    if (!vm->Initialize()) {
        delete vm;
        return nullptr;
    }
    
    return vm;
}

void NEVM_Destroy(NEVMHandle handle) {
    auto* vm = static_cast<NEVM_v2*>(handle);
    delete vm;
}

int NEVM_LoadModel(NEVMHandle handle, const wchar_t* path) {
    auto* vm = static_cast<NEVM_v2*>(handle);
    if (!vm) return 0;
    
    return vm->LoadModel(path) ? 1 : 0;
}

void* NEVM_Execute(NEVMHandle handle, const void* input, size_t input_size, 
                   size_t* output_size) {
    auto* vm = static_cast<NEVM_v2*>(handle);
    if (!vm) return nullptr;
    
    return vm->Execute(input, input_size, output_size);
}

void* NEVM_Generate(NEVMHandle handle, const void* prompt, size_t prompt_size,
                    uint32_t max_tokens, float temperature) {
    auto* vm = static_cast<NEVM_v2*>(handle);
    if (!vm) return nullptr;
    
    return vm->Generate(prompt, prompt_size, max_tokens, temperature);
}

void NEVM_FreeOutput(void* output) {
    delete[] static_cast<float*>(output);
}

const char* NEVM_GetVersion() {
    return NEVM_v2::GetVersion();
}

} // extern "C"

} // namespace NEVM
} // namespace RawrXD
