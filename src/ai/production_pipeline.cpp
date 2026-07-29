// production_pipeline.cpp - Implementation of production-ready Copilot-like pipeline
// Part of the Copilot-like inference pipeline.

#include "production_pipeline.h"

namespace RawrXD {

ProductionPipeline::ProductionPipeline() {
    // Initialize all components
}

ProductionPipeline::~ProductionPipeline() {
    // Cleanup
}

bool ProductionPipeline::Initialize(const ProductionConfig& config) {
    config_ = config;
    
    // Initialize model residency manager
    residency_manager_ = std::make_unique<ModelResidencyManager>();
    residency_manager_->SetPolicy(config.residency_policy);
    
    // Initialize kernel switcher
    kernel_switcher_ = std::make_unique<KernelSwitcher>();
    kernel_switcher_->SetConfig(config.kernel_config);
    
    // Initialize KV cache manager
    kv_cache_manager_ = std::make_unique<KVCacheManager>(
        config.kv_cache_max_entries,
        config.kv_cache_max_memory_mb
    );
    
    // Initialize adaptive debounce
    adaptive_debounce_ = std::make_unique<AdaptiveDebounce>();
    adaptive_debounce_->SetConfig(config.debounce_config);
    
    // Initialize cancellation manager
    cancellation_manager_ = std::make_unique<CancellationManager>();
    
    // Initialize early exit manager
    early_exit_manager_ = std::make_unique<EarlyExitManager>();
    early_exit_manager_->SetConfig(config.early_exit_config);
    
    // Initialize speculative decoder
    speculative_decoder_ = std::make_unique<DualStreamSpeculative>();
    speculative_decoder_->SetConfig(config.speculative_config);
    
    // Initialize prefix pinning
    prefix_pinning_ = std::make_unique<PrefixPinning>();
    prefix_pinning_->SetConfig(config.pinning_config);
    
    // Initialize token prefetch
    token_prefetch_ = std::make_unique<TokenPrefetch>();
    token_prefetch_->SetConfig(config.prefetch_config);
    token_prefetch_->Start();
    
    // Initialize latency profiler
    latency_profiler_ = std::make_unique<LatencyProfiler>();
    latency_profiler_->SetConfig(config.profiler_config);
    
    return true;
}

void ProductionPipeline::RequestCompletion(
    const CompletionRequest& request,
    std::function<void(const CompletionResult&)> callback
) {
    // Create cancellation handle
    uint64_t request_id = cancellation_manager_->CreateHandle();
    current_request_id_.store(request_id);
    generating_.store(true);
    
    // Start profiling
    latency_profiler_->StartGeneration();
    
    // Record keystroke for adaptive debounce
    adaptive_debounce_->RecordKeystroke();
    
    // Get debounce delay
    auto debounce_delay = adaptive_debounce_->GetDebounceDelay();
    
    // Check for prefetch result
    PrefetchResult prefetch_result;
    std::string context = request.file_content;
    if (token_prefetch_->TryGetPrefetchResult(context, prefetch_result)) {
        // Use prefetched result
        CompletionResult result;
        result.text = prefetch_result.completion;
        result.latency = prefetch_result.latency;
        result.kernel_used = prefetch_result.kernel_used;
        result.accepted = true;
        
        latency_profiler_->EndGeneration();
        generating_.store(false);
        callback(result);
        return;
    }
    
    // Process request in background
    std::thread([this, request, callback, request_id]() {
        ProcessRequest(request, callback);
    }).detach();
}

void ProductionPipeline::Cancel() {
    uint64_t request_id = current_request_id_.load();
    cancellation_manager_->Cancel(request_id, CancellationReason::USER_TYPING);
    generating_.store(false);
}

void ProductionPipeline::Accept() {
    if (ide_bridge_) {
        ide_bridge_->AcceptGhostText();
    }
}

void ProductionPipeline::Reject() {
    if (ide_bridge_) {
        ide_bridge_->RejectGhostText();
    }
}

GhostText ProductionPipeline::GetGhostText() const {
    if (ide_bridge_) {
        return ide_bridge_->GetGhostText();
    }
    return GhostText{};
}

void ProductionPipeline::ProcessRequest(
    const CompletionRequest& request,
    std::function<void(const CompletionResult&)> callback
) {
    // Apply all optimizations
    ApplyOptimizations(request, callback);
}

void ProductionPipeline::ApplyOptimizations(
    const CompletionRequest& request,
    std::function<void(const CompletionResult&)> callback
) {
    // 1. Check cancellation
    if (cancellation_manager_->IsCancelled(current_request_id_.load())) {
        generating_.store(false);
        return;
    }
    
    // 2. Start token profiling
    latency_profiler_->StartToken();
    
    // 3. Record debounce latency
    auto debounce_start = std::chrono::steady_clock::now();
    auto debounce_delay = adaptive_debounce_->GetDebounceDelay();
    latency_profiler_->RecordDebounce(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - debounce_start));
    
    // 4. Extract context and freeze prefix
    auto context_start = std::chrono::steady_clock::now();
    auto [frozen_prefix, mutable_suffix] = prefix_pinning_->SplitContext(
        request.file_content, request.cursor_line, request.cursor_column);
    latency_profiler_->RecordContextExtraction(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - context_start));
    
    // 5. Check KV cache
    auto kv_start = std::chrono::steady_clock::now();
    ContextHash context_hash = kv_cache_manager_->HashContext(
        request.file_path, frozen_prefix, request.cursor_line, request.cursor_column);
    const KVCacheEntry* cache_entry = kv_cache_manager_->GetCache(context_hash);
    latency_profiler_->RecordKVCacheLookup(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - kv_start));
    
    // 6. Get initial kernel
    int kernel = kernel_switcher_->GetInitialKernel(TaskType::AUTOCOMPLETE);
    
    // 7. Start speculative decoding
    if (config_.speculative_config.enable_streaming) {
        // Tokenize prompt context (prefix + mutable suffix)
        std::string full_prompt = frozen_prefix + mutable_suffix;
        std::vector<int32_t> prompt_tokens = tokenizer_ ? tokenizer_->Encode(full_prompt) : std::vector<int32_t>{};

        // Bind cache handles into decoder state
        speculative_decoder_->AttachKVCache(cache_entry ? cache_entry->gpu_handle : 0);

        speculative_decoder_->StartGeneration(
            prompt_tokens,
            request.max_tokens,
            [this, callback](const std::string& token, bool is_draft) {
                // Stream token to UI bridge
                if (ide_bridge_) {
                    GhostText ghost = ide_bridge_->GetGhostText();
                    ghost.text += token;
                    ide_bridge_->SetGhostText(ghost);
                }
            },
            [this, callback]() {
                // Generation complete
                latency_profiler_->EndGeneration();
                generating_.store(false);
            }
        );
    }
    
    // 8. Prefetch next completions on idle
    if (adaptive_debounce_->IsPaused()) {
        auto predictions = token_prefetch_->PredictPrefetches(
            request.file_content, request.cursor_line, request.cursor_column);
        token_prefetch_->QueuePrefetchBatch(predictions);
    }
    
    // 9. Record metrics for kernel switching
    TokenMetrics metrics;
    metrics.token_index = 0;
    // Stub: Confidence would come from inference engine softmax probabilities
    // When streaming_engine_->Generate() is implemented, extract from SampleResult.confidence
    metrics.confidence = 0.9f;
    metrics.kernel_used = kernel;
    kernel_switcher_->RecordMetrics(metrics);
    
    // 10. Check for early exit
    // Stub: Logits would come from streaming_engine_->ComputeLogits()
    // When implemented: logits = streaming_engine_->GetLastLogits()
    std::vector<float> logits;
    std::vector<float> confidence_history;
    EarlyExitDecision early_exit = early_exit_manager_->ShouldEarlyExit(
        logits.data(), logits.size(), 0, confidence_history);
    
    if (early_exit.should_exit) {
        early_exit_manager_->RecordEarlyExit(early_exit.confidence);
        latency_profiler_->EndToken(kernel);
        latency_profiler_->EndGeneration();
        generating_.store(false);
        
        CompletionResult result;
        // Stub: Completion text would come from streaming_engine_->Generate()
        // When implemented: result.text = streaming_engine_->GetGeneratedText()
        result.text = "";
        result.accepted = true;
        callback(result);
        return;
    }
    
    // 11. End token profiling
    latency_profiler_->EndToken(kernel);
    
    // 12. Store in KV cache
    // Stub: Token IDs and KV cache would come from streaming_engine_->GetKVCache()
    // When implemented: auto [token_ids, kv_cache_data] = streaming_engine_->ExtractKVCache()
    std::vector<uint32_t> token_ids;
    std::vector<float> kv_cache_data;
    kv_cache_manager_->StoreCache(context_hash, token_ids, kv_cache_data);
}

} // namespace RawrXD