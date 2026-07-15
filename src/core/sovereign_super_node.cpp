// =============================================================================
// sovereign_super_node.cpp
// Super-Node Architecture: Single-process, multi-worker high-performance engine
// Replaces 8-node distributed deployment with optimized single-machine execution
// =============================================================================

#include "sovereign_super_node_types.h"
#include "sovereign_interface_contract.h"
#include "sovereign_kernel_bridge.h"
#include "sovereign_transformer_forward.h"
#include "sovereign_detokenizer.h"
#include "sovereign_tokenizer.h"
#include "RawrXD_120B_Loader.h"
#include "sovereign_gguf_mapper.h"
#include "../streaming_gguf_loader.h"
#include <string>
#include <iostream>
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <io.h>
#include <conio.h>

// Helper to detect if stdin is a TTY (interactive) or pipe/file
bool IsStdinTty() {
    return _isatty(_fileno(stdin)) != 0;
}

// Global debug flag - set via --debug command line option
bool g_debug = false;

namespace Sovereign {

// Forward declarations for model weight mapping
bool MapModelWeightsFromHandle(void* handle, ModelWeights& weights, const char* model_path);
bool MapStubWeights(ModelWeights& weights);
void FreeModelWeights(ModelWeights& weights);

// =============================================================================
// Super-Node Configuration
// =============================================================================

thread_local int g_supernode_worker_slot = -1;

// =============================================================================
// Super-Node Engine
// =============================================================================

class SuperNodeEngine {
public:
    SuperNodeEngine(const SuperNodeConfig& config = SuperNodeConfig{});
    ~SuperNodeEngine();
    
    // Initialize the super-node
    bool Initialize();
    
    // Shutdown
    void Shutdown();
    
    // Process a token through the entire pipeline
    bool ProcessToken(uint32_t token_id, uint32_t* output_token);
    
    // Process a batch
    bool ProcessBatch(const std::vector<uint32_t>& input_tokens,
                      std::vector<uint32_t>& output_tokens);
    
    // Get performance metrics
    void GetMetrics(SuperNodeMetrics* metrics);
    
    // Get vocabulary for detokenization
    const std::vector<std::string>& GetVocabulary() const { return vocabulary_; }
    
    // Get model's actual vocab size (may be smaller than tokenizer vocab)
    uint32_t GetModelVocabSize() const { return model_weights_.vocab_size; }
    
    // Pin thread to specific CPU cores (NUMA-aware)
    static bool PinThreadToCores(int core1, int core2);
    
    // Grant test access friendship
    friend class SuperNodeEngineTestAccess;
    
private:
    SuperNodeConfig config_;
    std::vector<LogicalWorker> workers_;
    std::vector<std::unique_ptr<LockFreeRingBuffer<LayerRequest, 1024>>> request_queues_;
    std::vector<std::unique_ptr<LockFreeRingBuffer<LayerResponse, 1024>>> response_queues_;
    
    // Batch processing queues per worker
    std::vector<std::unique_ptr<LockFreeRingBuffer<BatchRequest, 1024>>> batch_request_queues_;
    std::vector<std::unique_ptr<LockFreeRingBuffer<BatchResponse, 1024>>> batch_response_queues_;
    std::vector<std::unique_ptr<PreallocatedTaskContextPool<1024>>> context_pools_;
    std::vector<std::unique_ptr<SharedIngressBuffer<1024, 4096>>> ingress_buffers_;
    
    // Head worker (orchestrator)
    LogicalWorker* head_worker_ = nullptr;
    
    // Shared memory pool
    void* memory_pool_ = nullptr;
    size_t memory_pool_size_ = 0;

    // Optional model handle for loader lifecycle validation
    RawrXD_Handle model_handle_ = nullptr;
    
    // Real transformer inference components
    ModelWeights model_weights_;
    KVCache kv_cache_;
    std::unique_ptr<TransformerForward> transformer_forward_;
    float* output_logits_ = nullptr;
    
    // FIX: Add mutex to protect transformer_forward_ access from multiple threads
    std::mutex forward_mutex_;
    
    // Vocabulary for detokenization
    std::vector<std::string> vocabulary_;
    
    // Inference engine (created from model handle)
    void* inference_engine_ = nullptr;          // RawrXD_InferenceHandle
    void* arena_committed_ = nullptr;          // Committed arena base
    size_t arena_committed_size_ = 0;          // Committed arena size
    size_t base_worker_window_size_ = 0;
    std::atomic<uint32_t> dispatch_worker_cursor_{0};
    
    // Statistics
    std::atomic<uint64_t> total_tokens_{0};
    std::atomic<uint64_t> total_latency_us_{0};
    
    // Token history for repetition penalty
    std::vector<uint32_t> generated_token_history_;
    std::mutex history_mutex_;
    
    // Worker thread function
    void WorkerLoop(LogicalWorker* worker);
    
    // Head thread function
    void HeadLoop();
    
    // Initialize memory pool with huge pages
    bool InitializeMemoryPool();
    
    // Initialize inference engine and arena (called after memory pool)
    bool InitializeEngine();

    const LogicalWorker* ResolveWorkerWindow();

    // Execute an arena-backed inference task via RawrXD_Inference_Generate.
    bool RunInferenceTask(const TaskContext& ctx,
                          const uint32_t* input_tokens,
                          uint32_t* output_tokens,
                          uint32_t* n_generated);
    
    // Submit a batch request to a specific worker's queue (non-blocking)
    bool SubmitBatchToWorker(int worker_id, const BatchRequest& request);
    
    // Collect a batch response from a specific worker's queue (non-blocking)
    bool CollectBatchFromWorker(int worker_id, BatchResponse& response);
    
    // Cleanup inference engine (called before shutdown)
    void ShutdownEngine();
    
    // Verify guard bands are intact (post-test diagnostic)
    bool VerifyGuardBands();
    
    // Runtime guard band check (optional, for debugging)
    bool CheckGuardBand(int worker_id);
};

// =============================================================================
// Implementation
// =============================================================================

SuperNodeEngine::SuperNodeEngine(const SuperNodeConfig& config) 
    : config_(config) {
    printf("[SuperNode] Engine created with %d logical workers\n", config.logical_workers);
}

SuperNodeEngine::~SuperNodeEngine() {
    Shutdown();
}

bool SuperNodeEngine::Initialize() {
    printf("[SuperNode] Initializing...\n");
    
    // Initialize memory pool
    if (!InitializeMemoryPool()) {
        fprintf(stderr, "[SuperNode] Failed to initialize memory pool\n");
        return false;
    }
    
    // Initialize inference engine and arena
    if (!InitializeEngine()) {
        fprintf(stderr, "[SuperNode] Failed to initialize engine\n");
        return false;
    }
    
    // Initialize MASM kernel
    if (Sovereign_Kernel_Initialize() != 0) {
        fprintf(stderr, "[SuperNode] Failed to initialize MASM kernel\n");
        ShutdownEngine();
        return false;
    }
    printf("[SuperNode] MASM kernel initialized (throughput: %u t/s)\n", 
           Sovereign_Kernel_GetThroughputEstimate());
    
    // Create communication queues
    request_queues_.resize(config_.logical_workers);
    response_queues_.resize(config_.logical_workers);
    batch_request_queues_.resize(config_.logical_workers);
    batch_response_queues_.resize(config_.logical_workers);
    context_pools_.resize(config_.logical_workers);
    ingress_buffers_.resize(config_.logical_workers);
    
    for (int i = 0; i < config_.logical_workers; i++) {
        request_queues_[i] = std::make_unique<LockFreeRingBuffer<LayerRequest, 1024>>();
        response_queues_[i] = std::make_unique<LockFreeRingBuffer<LayerResponse, 1024>>();
        batch_request_queues_[i] = std::make_unique<LockFreeRingBuffer<BatchRequest, 1024>>();
        batch_response_queues_[i] = std::make_unique<LockFreeRingBuffer<BatchResponse, 1024>>();
        context_pools_[i] = std::make_unique<PreallocatedTaskContextPool<1024>>();
        ingress_buffers_[i] = std::make_unique<SharedIngressBuffer<1024, 4096>>();
    }
    
    // Create logical workers with guard bands
    workers_.reserve(config_.logical_workers);

    const int worker_count = (config_.logical_workers > 0) ? config_.logical_workers : 1;
    
    // Calculate window size with guard bands (64 bytes per guard band)
    constexpr size_t GUARD_BAND_SIZE = 64; // One cache line
    const size_t total_guard_space = GUARD_BAND_SIZE * static_cast<size_t>(worker_count);
    const size_t usable_arena = (arena_committed_size_ > total_guard_space) 
        ? (arena_committed_size_ - total_guard_space) 
        : 0;
    
    base_worker_window_size_ = (worker_count > 0 && usable_arena > 0)
        ? (usable_arena / static_cast<size_t>(worker_count))
        : 0;
    const size_t arena_remainder = (worker_count > 0 && usable_arena > 0)
        ? (usable_arena % static_cast<size_t>(worker_count))
        : 0;
    
    // Initialize guard bands with canary pattern
    if (arena_committed_ && arena_committed_size_ > 0) {
        uint8_t* arena_base = static_cast<uint8_t*>(arena_committed_);
        for (int i = 0; i < worker_count; i++) {
            // Guard band is at the end of each window
            size_t guard_offset = (static_cast<size_t>(i) + 1) * base_worker_window_size_ 
                                + static_cast<size_t>(i) * GUARD_BAND_SIZE;
            if (guard_offset + GUARD_BAND_SIZE <= arena_committed_size_) {
                uint64_t* guard = reinterpret_cast<uint64_t*>(arena_base + guard_offset);
                for (size_t g = 0; g < GUARD_BAND_SIZE / sizeof(uint64_t); g++) {
                    guard[g] = 0xDEADBEEFCAFEBABEULL; // Canary pattern
                }
            }
        }
        printf("[SuperNode] Guard bands initialized (%zu bytes each)\n", GUARD_BAND_SIZE);
    }
    
    // Head worker (id=0)
    LogicalWorker head;
    head.id = 0;
    head.role = "HEAD";
    head.cpu_cores[0] = 0;
    head.cpu_cores[1] = 1;
    head.memory_offset = 0;
    head.arena_window_ptr = arena_committed_;
    head.arena_window_size = base_worker_window_size_ + ((worker_count == 1) ? arena_remainder : 0);
    head.has_gpu = true;
    head.has_amx = true;
    head.request_queue = request_queues_[0].get();
    head.response_queue = response_queues_[0].get();
    workers_.push_back(std::move(head));
    head_worker_ = &workers_[0];
    
    // Worker nodes (id=1-7) - account for guard bands in offset calculation
    for (int i = 1; i < config_.logical_workers; i++) {
        LogicalWorker worker;
        worker.id = i;
        worker.role = "WORKER";
        worker.cpu_cores[0] = i * 2;
        worker.cpu_cores[1] = i * 2 + 1;
        // Offset includes previous windows + guard bands
        worker.memory_offset = static_cast<size_t>(i) * base_worker_window_size_ 
                             + static_cast<size_t>(i) * GUARD_BAND_SIZE;
        worker.arena_window_ptr = static_cast<uint8_t*>(arena_committed_) + worker.memory_offset;
        worker.arena_window_size = base_worker_window_size_;
        if (i == worker_count - 1) {
            worker.arena_window_size += arena_remainder;
        }
        worker.has_gpu = (i <= 3); // First 4 workers have GPU
        worker.has_amx = true;
        worker.request_queue = request_queues_[i].get();
        worker.response_queue = response_queues_[i].get();
        worker.batch_request_queue = batch_request_queues_[i].get();
        worker.batch_response_queue = batch_response_queues_[i].get();
        workers_.push_back(std::move(worker));
    }
    
    // Start worker threads
    for (auto& worker : workers_) {
        if (worker.id == 0) {
            // Head worker
            worker.thread = std::thread(&SuperNodeEngine::HeadLoop, this);
        } else {
            // Regular workers
            worker.thread = std::thread([this, &worker]() {
                WorkerLoop(&worker);
            });
        }
        worker.running = true;
        
        // Pin thread to cores
        PinThreadToCores(worker.cpu_cores[0], worker.cpu_cores[1]);
    }
    
    printf("[SuperNode] Initialized with %zu workers\n", workers_.size());
    return true;
}

void SuperNodeEngine::Shutdown() {
    printf("[SuperNode] Shutting down...\n");
    
    // Shutdown MASM kernel
    Sovereign_Kernel_Shutdown();
    
    // Shutdown inference engine (before workers stop, in case they're using it)
    ShutdownEngine();
    
    // Signal all workers to stop
    for (auto& worker : workers_) {
        worker.running = false;
    }
    
    // Wait for threads to finish
    for (auto& worker : workers_) {
        if (worker.thread.joinable()) {
            worker.thread.join();
        }
    }
    
    // Cleanup memory pool
    if (memory_pool_) {
        VirtualFree(memory_pool_, 0, MEM_RELEASE);
        memory_pool_ = nullptr;
    }
    
    printf("[SuperNode] Shutdown complete\n");
}

void SuperNodeEngine::WorkerLoop(LogicalWorker* worker) {
    g_supernode_worker_slot = worker ? worker->id : -1;
    printf("[SuperNode] Worker %d started on cores %d-%d (window: %p, size: %zu MB)\n", 
           worker->id, worker->cpu_cores[0], worker->cpu_cores[1],
           worker->arena_window_ptr, worker->arena_window_size / (1024 * 1024));
    
    while (worker->running.load()) {
        // Check for batch requests first (higher priority for inference)
        BatchRequest batch_req;
        if (worker->batch_request_queue && worker->batch_request_queue->pop(batch_req)) {
            auto start = std::chrono::high_resolution_clock::now();
            
            // Process batch using worker's exclusive arena window
            BatchResponse batch_resp;
            batch_resp.request_id = batch_req.request_id;
            batch_resp.status = RingStatus::OK;
            const uint32_t* request_tokens = batch_req.TokenData();
            const uint32_t request_token_count = batch_req.TokenCount();
            
            TaskContext ctx;
            TaskContext* pooled_ctx = nullptr;
            if (batch_req.use_prebuilt_context && worker->id < static_cast<int>(context_pools_.size())) {
                pooled_ctx = context_pools_[worker->id] ? context_pools_[worker->id]->Get(batch_req.context_slot) : nullptr;
            }

            if (pooled_ctx) {
                ctx = *pooled_ctx;
            } else {
                ctx.arena_window_ptr = static_cast<uint8_t*>(worker->arena_window_ptr);
                ctx.arena_window_size = worker->arena_window_size;
                ctx.source_tokens = request_tokens;
                ctx.token_count = request_token_count;
                ctx.sequence_offset = batch_req.sequence_offset;
                ctx.position_offset = batch_req.position_offset;
                ctx.batch_input_offset = 0;

                const size_t input_bytes = static_cast<size_t>(ctx.token_count) * sizeof(uint32_t);
                ctx.batch_output_offset = (input_bytes + 63) & ~static_cast<size_t>(63);
                ctx.is_prevalidated = true;
            }
            
            // Ensure output fits in window
            uint32_t n_generated = 0;
            const size_t input_bytes = static_cast<size_t>(ctx.token_count) * sizeof(uint32_t);
            if (ctx.batch_output_offset + input_bytes > worker->arena_window_size) {
                fprintf(stderr, "[Worker %d] Batch too large for window\n", worker->id);
                batch_resp.status = RingStatus::BUFFER_OVERFLOW;
            } else {
                // Execute inference on this worker's window
                std::vector<uint32_t> output_tokens(request_token_count == 0 ? 1u : request_token_count, 0);
                
                if (request_tokens && RunInferenceTask(ctx, request_tokens,
                                     output_tokens.data(), &n_generated)) {
                    batch_resp.output_tokens = std::move(output_tokens);
                    batch_resp.output_tokens.resize(n_generated);
                } else {
                    batch_resp.status = RingStatus::RECOVERY_FAILED;
                }
            }
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            batch_resp.processing_time_us = duration.count();
            
            // Send response
            while (!worker->batch_response_queue->push(batch_resp)) {
                std::this_thread::yield();
            }

            if (batch_req.use_prebuilt_context && worker->id < static_cast<int>(context_pools_.size()) && context_pools_[worker->id]) {
                context_pools_[worker->id]->Release(batch_req.context_slot);
            }
            if (batch_req.use_shared_ingress && worker->id < static_cast<int>(ingress_buffers_.size()) && ingress_buffers_[worker->id]) {
                ingress_buffers_[worker->id]->Release(batch_req.ingress_slot);
            }
            
            // Update statistics and telemetry
            worker->tokens_processed += request_token_count;
            worker->metrics.tokens_generated += n_generated;
            worker->metrics.batches_processed++;
            worker->metrics.total_processing_time_us += static_cast<uint64_t>(duration.count());
            worker->metrics.avg_latency_us.store(
                (worker->metrics.avg_latency_us.load() * (worker->metrics.batches_processed - 1) 
                 + batch_resp.processing_time_us) / worker->metrics.batches_processed);
            
            // Runtime guard band check (optional, expensive)
            if (config_.guard_config.verify_on_batch_complete) {
                CheckGuardBand(worker->id);
            }
            
            continue;
        }
        
        // Check for layer requests (legacy path)
        LayerRequest request;
        if (worker->request_queue->pop(request)) {
            // Process the layer
            auto start = std::chrono::high_resolution_clock::now();
            
            // TODO: Actual layer processing
            LayerResponse response;
            response.status = RingStatus::OK;
            response.layer_idx = request.layer_idx;
            response.request_id = request.request_id;
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            response.processing_time_us = duration.count();
            
            // Send response
            while (!worker->response_queue->push(response)) {
                // Spin wait (queue full)
                std::this_thread::yield();
            }
            
            // Update statistics
            worker->layers_processed++;
            worker->tokens_processed++;
        } else {
            // No work available, yield
            std::this_thread::yield();
        }
    }
    
    printf("[SuperNode] Worker %d stopped\n", worker->id);
}

void SuperNodeEngine::HeadLoop() {
    g_supernode_worker_slot = head_worker_ ? head_worker_->id : -1;
    printf("[SuperNode] Head worker started\n");
    
    while (head_worker_->running.load()) {
        // Head orchestrator logic
        // Distribute work to workers, collect results
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    printf("[SuperNode] Head worker stopped\n");
}

bool SuperNodeEngine::InitializeMemoryPool() {
    memory_pool_size_ = config_.memory_pool_gb * 1024ULL * 1024 * 1024;
    
    printf("[SuperNode] Memory pool: %zu GB\n", config_.memory_pool_gb);
    memory_pool_ = VirtualAlloc(nullptr, memory_pool_size_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!memory_pool_) {
        fprintf(stderr, "[SuperNode] Failed to allocate %zu GB; attempting fallback to 512MB\n", config_.memory_pool_gb);
        // Fallback to smaller allocation for testing
        memory_pool_size_ = 512ULL * 1024 * 1024;  // 512MB
        memory_pool_ = VirtualAlloc(nullptr, memory_pool_size_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!memory_pool_) {
            fprintf(stderr, "[SuperNode] Fallback allocation failed\n");
            return false;
        }
        fprintf(stderr, "[SuperNode] Using fallback 512MB memory pool\n");
    }
    
    return true;
}

bool SuperNodeEngine::InitializeEngine() {
    // Commit arena from the allocated memory pool
    // Arena is used for KV cache and temporary buffers during inference
    // We commit a portion of the pool upfront for deterministic performance
    
    // Estimate: 2GB for KV cache (for 80 layers × 4096 hidden × 2 (K,V) × float32)
    size_t arena_size = 2ULL * 1024 * 1024 * 1024;
    
    // Ensure we don't overcommit
    if (arena_size > memory_pool_size_ / 2) {
        arena_size = memory_pool_size_ / 2;
    }
    
    // On Windows: VirtualAlloc for committed pages; on Linux: mmap + mlock
    // For now, just use the memory pool directly
    arena_committed_ = memory_pool_;
    arena_committed_size_ = arena_size;
    
    printf("[SuperNode] Arena committed: %zu MB from pool\n", arena_committed_size_ / (1024 * 1024));
    
    if (!config_.model_path.empty()) {
        model_handle_ = RawrXD_LoadModel(
            config_.model_path.c_str(),
            arena_committed_,
            arena_committed_size_);
        if (!model_handle_) {
            fprintf(stderr, "[SuperNode] Failed to load model: %s\n", config_.model_path.c_str());
            return false;
        }

        printf("[SuperNode] Model loaded: %s\n", config_.model_path.c_str());

        // Initialize real transformer inference
        // Step 1: Map GGUF tensors to ModelWeights
        if (!MapModelWeightsFromHandle(model_handle_, model_weights_, config_.model_path.c_str())) {
            fprintf(stderr, "[SuperNode] Failed to map model weights\n");
            RawrXD_UnloadModel(model_handle_);
            model_handle_ = nullptr;
            return false;
        }
        printf("[SuperNode] Model weights mapped: %u layers, %u heads, hidden=%u\n",
               model_weights_.n_layers, model_weights_.n_heads, model_weights_.hidden_dim);
        
        // Step 1b: Load vocabulary for detokenization
        {
            RawrXD::StreamingGGUFLoader vocab_loader;
            if (vocab_loader.Open(config_.model_path)) {
                if (vocab_loader.ParseHeader() && vocab_loader.ParseMetadata()) {
                    vocabulary_ = vocab_loader.GetVocabulary();
                    // Pad vocabulary to match model's vocab_size
                    size_t target_vocab_size = model_weights_.vocab_size;
                    if (vocabulary_.size() < target_vocab_size) {
                        size_t original_size = vocabulary_.size();
                        vocabulary_.reserve(target_vocab_size);
                        for (size_t i = original_size; i < target_vocab_size; ++i) {
                            vocabulary_.push_back("<unk>");
                        }
                        printf("[SuperNode] Vocabulary loaded: %zu tokens (padded to %zu)\n", 
                               original_size, vocabulary_.size());
                    } else {
                        printf("[SuperNode] Vocabulary loaded: %zu tokens\n", vocabulary_.size());
                    }
                } else {
                    printf("[SuperNode] Warning: Failed to parse GGUF metadata for vocabulary\n");
                }
                vocab_loader.Close();
            } else {
                printf("[SuperNode] Warning: Failed to open model for vocabulary loading\n");
            }
        }
        
        // Step 2: Initialize KV cache
        if (!kv_cache_.Initialize(model_weights_.n_layers, 2048, model_weights_.n_kv_heads, model_weights_.head_dim)) {
            fprintf(stderr, "[SuperNode] Failed to initialize KV cache\n");
            FreeModelWeights(model_weights_);
            RawrXD_UnloadModel(model_handle_);
            model_handle_ = nullptr;
            return false;
        }
        printf("[SuperNode] KV cache initialized: %u layers x 2048 seq\n", model_weights_.n_layers);
        
        // Step 3: Create TransformerForward instance
        transformer_forward_ = std::make_unique<TransformerForward>(model_weights_, kv_cache_);
        if (!transformer_forward_) {
            fprintf(stderr, "[SuperNode] Failed to create transformer forward\n");
            kv_cache_.Cleanup();
            FreeModelWeights(model_weights_);
            RawrXD_UnloadModel(model_handle_);
            model_handle_ = nullptr;
            return false;
        }
        
        // Step 4: Allocate output logits buffer
        output_logits_ = static_cast<float*>(VirtualAlloc(nullptr, model_weights_.vocab_size * sizeof(float), 
                                                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!output_logits_) {
            fprintf(stderr, "[SuperNode] Failed to allocate logits buffer\n");
            transformer_forward_.reset();
            kv_cache_.Cleanup();
            FreeModelWeights(model_weights_);
            RawrXD_UnloadModel(model_handle_);
            model_handle_ = nullptr;
            return false;
        }
        
        printf("[SuperNode] Sovereign transformer inference initialized\n");
        
        // Keep the stub engine for compatibility (will be removed once real inference is verified)
        inference_engine_ = RawrXD_Inference_Init(model_handle_, nullptr);
    } else {
        printf("[SuperNode] No model path provided; running kernel benchmark mode\n");
        inference_engine_ = nullptr;
    }
    
    printf("[SuperNode] Inference engine initialized\n");
    return true;
}

void SuperNodeEngine::ShutdownEngine() {
    if (inference_engine_) {
        RawrXD_Inference_Free(inference_engine_);
        inference_engine_ = nullptr;
    }

    if (model_handle_) {
        RawrXD_UnloadModel(model_handle_);
        model_handle_ = nullptr;
    }
    
    if (arena_committed_) {
        // In production: VirtualFree or munmap the arena
        // For now, it's part of the pool so it will be freed with the pool
        arena_committed_ = nullptr;
        arena_committed_size_ = 0;
    }
    
    printf("[SuperNode] Inference engine shutdown complete\n");
}

// =============================================================================
// Guard Band Verification (Canary Pattern)
// =============================================================================

bool SuperNodeEngine::VerifyGuardBands() {
    constexpr size_t GUARD_BAND_SIZE = 64;
    constexpr uint64_t CANARY_PATTERN = 0xDEADBEEFCAFEBABEULL;
    
    if (!arena_committed_ || workers_.empty()) {
        return true; // Nothing to verify
    }
    
    bool all_intact = true;
    uint8_t* arena_base = static_cast<uint8_t*>(arena_committed_);
    
    for (size_t i = 0; i < workers_.size(); i++) {
        // Guard band is at the end of each window
        size_t guard_offset = (i + 1) * base_worker_window_size_ + i * GUARD_BAND_SIZE;
        if (guard_offset + GUARD_BAND_SIZE > arena_committed_size_) {
            continue; // Last worker may not have a trailing guard
        }
        
        uint64_t* guard = reinterpret_cast<uint64_t*>(arena_base + guard_offset);
        bool guard_intact = true;
        
        for (size_t g = 0; g < GUARD_BAND_SIZE / sizeof(uint64_t); g++) {
            if (guard[g] != CANARY_PATTERN) {
                guard_intact = false;
                break;
            }
        }
        
        if (!guard_intact) {
            fprintf(stderr, "[GuardBand] WORKER %zu GUARD CORRUPTED at offset %zu!\n", 
                    i, guard_offset);
            all_intact = false;
        }
    }
    
    if (all_intact) {
        printf("[GuardBand] All guard bands intact - no memory overruns detected\n");
    } else {
        fprintf(stderr, "[GuardBand] CRITICAL: Memory overrun detected!\n");
    }
    
    return all_intact;
}

bool SuperNodeEngine::CheckGuardBand(int worker_id) {
    constexpr size_t GUARD_BAND_SIZE = 64;
    constexpr uint64_t CANARY_PATTERN = 0xDEADBEEFCAFEBABEULL;
    
    if (worker_id < 0 || worker_id >= static_cast<int>(workers_.size())) {
        return false;
    }
    
    if (!arena_committed_) {
        return true;
    }
    
    uint8_t* arena_base = static_cast<uint8_t*>(arena_committed_);
    size_t guard_offset = (static_cast<size_t>(worker_id) + 1) * base_worker_window_size_ 
                        + static_cast<size_t>(worker_id) * GUARD_BAND_SIZE;
    
    if (guard_offset + GUARD_BAND_SIZE > arena_committed_size_) {
        return true; // No guard band for last worker
    }
    
    uint64_t* guard = reinterpret_cast<uint64_t*>(arena_base + guard_offset);
    for (size_t g = 0; g < GUARD_BAND_SIZE / sizeof(uint64_t); g++) {
        if (guard[g] != CANARY_PATTERN) {
            fprintf(stderr, "[GuardBand] Worker %d guard band corrupted at qword %zu!\n",
                    worker_id, g);
            return false;
        }
    }
    
    return true;
}

bool SuperNodeEngine::RunInferenceTask(const TaskContext& ctx,
                                       const uint32_t* input_tokens,
                                       uint32_t* output_tokens,
                                       uint32_t* n_generated) {
    if (!inference_engine_ || !ctx.arena_window_ptr || !input_tokens || !output_tokens || ctx.token_count == 0) {
        return false;
    }

    const size_t input_bytes = static_cast<size_t>(ctx.token_count) * sizeof(uint32_t);
    const size_t output_bytes = input_bytes;

    if (ctx.batch_input_offset + input_bytes > ctx.arena_window_size ||
        ctx.batch_output_offset + output_bytes > ctx.arena_window_size) {
        fprintf(stderr, "[SuperNode] TaskContext offsets exceed committed arena bounds\n");
        return false;
    }

    uint8_t* arena_base = ctx.arena_window_ptr;
    uint32_t* arena_input = reinterpret_cast<uint32_t*>(arena_base + ctx.batch_input_offset);
    uint32_t* arena_output = reinterpret_cast<uint32_t*>(arena_base + ctx.batch_output_offset);

    memcpy(arena_input, input_tokens, input_bytes);

    uint32_t generated = RawrXD_Inference_Generate(
        static_cast<RawrXD_InferenceHandle>(inference_engine_),
        arena_input,
        ctx.token_count,
        arena_output,
        ctx.token_count);

    if (generated == 0) {
        return false;
    }

    memcpy(output_tokens, arena_output, static_cast<size_t>(generated) * sizeof(uint32_t));
    if (n_generated) {
        *n_generated = generated;
    }
    return true;
}

const LogicalWorker* SuperNodeEngine::ResolveWorkerWindow() {
    if (workers_.empty()) {
        return nullptr;
    }

    if (g_supernode_worker_slot >= 0 &&
        g_supernode_worker_slot < static_cast<int>(workers_.size())) {
        return &workers_[g_supernode_worker_slot];
    }

    uint32_t idx = dispatch_worker_cursor_.fetch_add(1, std::memory_order_relaxed);
    idx %= static_cast<uint32_t>(workers_.size());
    return &workers_[idx];
}

bool SuperNodeEngine::ProcessToken(uint32_t token_id, uint32_t* output_token) {
    if (!output_token) {
        return false;
    }

    // PRIORITY 1: Use real transformer inference if available
    // FIX: Lock mutex to protect transformer_forward_ from concurrent access
    std::lock_guard<std::mutex> lock(forward_mutex_);
    
    if (g_debug) {
        printf("[SuperNode] ProcessToken: transformer_forward_=%p, output_logits_=%p\n", 
               (void*)transformer_forward_.get(), (void*)output_logits_);
    }
    
    if (transformer_forward_ && output_logits_) {
        // Reset KV cache position for new sequence (or use cached position for continuation)
        uint32_t pos = kv_cache_.current_pos;
        
        if (g_debug) {
            fprintf(stderr, "[FWD] Processing token %u at position %u (kv_cache.current_pos=%u)\n", token_id, pos, kv_cache_.current_pos);
            fflush(stderr);
        }
        
        if (g_debug) {
            printf("[SuperNode] Running transformer forward pass for token %u at pos %u\n", token_id, pos);
        }
        
        // Run forward pass
        if (!transformer_forward_->ForwardToken(token_id, pos, output_logits_)) {
            fprintf(stderr, "[SuperNode] Transformer forward pass failed\n");
            return false;
        }
        
        if (g_debug) {
            printf("[SuperNode] Forward pass complete, sampling from %u logits\n", model_weights_.vocab_size);
        }
        
        // Sample token with repetition penalty
        // Get copy of history under lock
        std::vector<uint32_t> history_copy;
        {
            std::lock_guard<std::mutex> lock(history_mutex_);
            history_copy = generated_token_history_;
        }
        *output_token = transformer_forward_->SampleTokenWithHistory(output_logits_, history_copy);
        
        // Add to history
        {
            std::lock_guard<std::mutex> lock(history_mutex_);
            generated_token_history_.push_back(*output_token);
            // Keep history bounded (last 256 tokens)
            if (generated_token_history_.size() > 256) {
                generated_token_history_.erase(generated_token_history_.begin());
            }
        }
        
        if (g_debug) {
            printf("[SuperNode] Sampled token: %u (history_size=%zu)\n", *output_token, history_copy.size());
        }
        
        // Update position for next token
        kv_cache_.current_pos = pos + 1;
        
        total_tokens_.fetch_add(1, std::memory_order_relaxed);
        
        if (g_debug) {
            printf("[SuperNode] Token %u -> %u (pos=%u)\n", token_id, *output_token, pos);
        }
        return true;
    }

    // PRIORITY 2: Fall back to stub inference engine if available
    if (inference_engine_) {
        const LogicalWorker* window = ResolveWorkerWindow();
        if (!window || !window->arena_window_ptr || window->arena_window_size == 0) {
            fprintf(stderr, "[SuperNode] No worker arena window available\n");
            return false;
        }

        TaskContext ctx;
        ctx.arena_window_ptr = static_cast<uint8_t*>(window->arena_window_ptr);
        ctx.arena_window_size = window->arena_window_size;
        ctx.token_count = 1;
        ctx.batch_input_offset = 0;
        ctx.batch_output_offset = 64 * 1024;

        uint32_t generated_token = 0;
        uint32_t n_generated = 0;
        if (!RunInferenceTask(ctx, &token_id, &generated_token, &n_generated)) {
            fprintf(stderr, "[SuperNode] RawrXD inference returned no tokens\n");
            return false;
        }

        *output_token = generated_token;
        total_tokens_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // PRIORITY 3: Kernel stub mode (no model loaded)
    // Prepare inference context for kernel
    Sovereign_InferenceContext context = {};
    context.token_id = token_id;
    context.sequence_len = 1;
    context.batch_size = 1;
    context.hidden_size = 4096;
    context.vocab_size = 128000;
    context.num_layers = 80;
    context.weights = nullptr;
    context.kv_cache = nullptr;
    context.output_logits = nullptr;
    context.scratch_buffer = nullptr;
    
    // Call MASM kernel
    Sovereign_KernelResult result = {};
    int kernel_status = Sovereign_Kernel_ProcessToken(&context, &result, 0);
    
    if (kernel_status != 0) {
        fprintf(stderr, "[SuperNode] Kernel execution failed: %d\n", kernel_status);
        return false;
    }
    
    // Deterministic output for stub mode
    *output_token = token_id + 1;

    total_tokens_.fetch_add(1, std::memory_order_relaxed);
    total_latency_us_.fetch_add(result.latency_us, std::memory_order_relaxed);
    
    return true;
}

bool SuperNodeEngine::ProcessBatch(const std::vector<uint32_t>& input_tokens,
                                   std::vector<uint32_t>& output_tokens) {
    if (inference_engine_ && !input_tokens.empty()) {
        const LogicalWorker* window = ResolveWorkerWindow();
        if (!window || !window->arena_window_ptr || window->arena_window_size == 0) {
            fprintf(stderr, "[SuperNode] No worker arena window available\n");
            return false;
        }

        TaskContext ctx;
        ctx.arena_window_ptr = static_cast<uint8_t*>(window->arena_window_ptr);
        ctx.arena_window_size = window->arena_window_size;
        ctx.token_count = static_cast<uint32_t>(input_tokens.size());
        ctx.batch_input_offset = 0;

        const size_t batch_bytes = static_cast<size_t>(ctx.token_count) * sizeof(uint32_t);
        const size_t aligned_output_offset = (batch_bytes + 63) & ~static_cast<size_t>(63);
        ctx.batch_output_offset = aligned_output_offset;

        output_tokens.assign(input_tokens.size(), 0);
        uint32_t n_generated = 0;
        if (!RunInferenceTask(ctx, input_tokens.data(), output_tokens.data(), &n_generated)) {
            fprintf(stderr, "[SuperNode] RawrXD batch inference failed\n");
            return false;
        }

        output_tokens.resize(n_generated);
        total_tokens_.fetch_add(n_generated, std::memory_order_relaxed);
        return true;
    }

    // Fallback to token-by-token processing
    output_tokens.clear();
    output_tokens.reserve(input_tokens.size());

    for (uint32_t token : input_tokens) {
        uint32_t output_token = 0;
        if (!ProcessToken(token, &output_token)) {
            return false;
        }
        output_tokens.push_back(output_token);
    }

    return true;
}

bool SuperNodeEngine::SubmitBatchToWorker(int worker_id, const BatchRequest& request) {
    if (worker_id < 0 || worker_id >= static_cast<int>(workers_.size())) {
        fprintf(stderr, "[SuperNode] Invalid worker_id %d\n", worker_id);
        return false;
    }
    
    LogicalWorker& worker = workers_[worker_id];
    if (!worker.batch_request_queue) {
        fprintf(stderr, "[SuperNode] Worker %d has no batch request queue\n", worker_id);
        return false;
    }
    
    // Track telemetry before attempting submission
    const uint32_t token_count = request.TokenCount();
    worker.metrics.tokens_submitted += token_count;

    BatchRequest prepared_request = request;
    if (prepared_request.use_zero_copy_input) {
        if (!prepared_request.input_tokens_ptr || prepared_request.input_token_count == 0) {
            fprintf(stderr, "[SuperNode] Worker %d zero-copy request missing token span\n", worker_id);
            return false;
        }

        if (prepared_request.use_shared_ingress) {
            if (worker_id >= static_cast<int>(ingress_buffers_.size()) || !ingress_buffers_[worker_id]) {
                fprintf(stderr, "[SuperNode] Worker %d has no ingress buffer\n", worker_id);
                return false;
            }

            uint16_t ingress_slot = 0;
            const uint32_t* staged_tokens = nullptr;
            if (!ingress_buffers_[worker_id]->Stage(
                    ingress_slot,
                    prepared_request.input_tokens_ptr,
                    prepared_request.input_token_count,
                    staged_tokens)) {
                worker.metrics.queue_push_failures.fetch_add(1, std::memory_order_relaxed);
                return false;
            }

            prepared_request.ingress_slot = ingress_slot;
            prepared_request.input_tokens_ptr = staged_tokens;
        }

        if (worker_id >= static_cast<int>(context_pools_.size()) || !context_pools_[worker_id]) {
            fprintf(stderr, "[SuperNode] Worker %d has no TaskContext pool\n", worker_id);
            if (prepared_request.use_shared_ingress && worker_id < static_cast<int>(ingress_buffers_.size()) && ingress_buffers_[worker_id]) {
                ingress_buffers_[worker_id]->Release(prepared_request.ingress_slot);
            }
            return false;
        }

        TaskContext* pooled_ctx = nullptr;
        uint16_t slot_index = 0;
        if (!context_pools_[worker_id]->Acquire(slot_index, pooled_ctx) || !pooled_ctx) {
            if (prepared_request.use_shared_ingress && worker_id < static_cast<int>(ingress_buffers_.size()) && ingress_buffers_[worker_id]) {
                ingress_buffers_[worker_id]->Release(prepared_request.ingress_slot);
            }
            worker.metrics.queue_push_failures.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        pooled_ctx->arena_window_ptr = static_cast<uint8_t*>(worker.arena_window_ptr);
        pooled_ctx->arena_window_size = worker.arena_window_size;
        pooled_ctx->batch_input_offset = 0;
        pooled_ctx->token_count = prepared_request.input_token_count;
        pooled_ctx->source_tokens = prepared_request.input_tokens_ptr;
        pooled_ctx->sequence_offset = prepared_request.sequence_offset;
        pooled_ctx->position_offset = prepared_request.position_offset;
        const size_t input_bytes = static_cast<size_t>(pooled_ctx->token_count) * sizeof(uint32_t);
        pooled_ctx->batch_output_offset = (input_bytes + 63) & ~static_cast<size_t>(63);
        pooled_ctx->is_prevalidated = (pooled_ctx->batch_output_offset + input_bytes <= pooled_ctx->arena_window_size);

        if (!pooled_ctx->is_prevalidated) {
            context_pools_[worker_id]->Release(slot_index);
            if (prepared_request.use_shared_ingress && worker_id < static_cast<int>(ingress_buffers_.size()) && ingress_buffers_[worker_id]) {
                ingress_buffers_[worker_id]->Release(prepared_request.ingress_slot);
            }
            worker.metrics.queue_push_failures.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        prepared_request.context_slot = slot_index;
        prepared_request.use_prebuilt_context = true;
    }

    const uint64_t queue_occupancy = worker.batch_request_queue->size();
    uint64_t observed_peak = worker.metrics.max_queue_occupancy.load(std::memory_order_relaxed);
    while (queue_occupancy > observed_peak &&
           !worker.metrics.max_queue_occupancy.compare_exchange_weak(observed_peak, queue_occupancy, std::memory_order_relaxed)) {
    }
    
    // Non-blocking push - caller must retry if queue is full
    if (!worker.batch_request_queue->push(prepared_request)) {
        worker.metrics.queue_full_events++; // Track queue full events
        worker.metrics.queue_push_failures.fetch_add(1, std::memory_order_relaxed);
        if (prepared_request.use_prebuilt_context && worker_id < static_cast<int>(context_pools_.size()) && context_pools_[worker_id]) {
            context_pools_[worker_id]->Release(prepared_request.context_slot);
        }
        if (prepared_request.use_shared_ingress && worker_id < static_cast<int>(ingress_buffers_.size()) && ingress_buffers_[worker_id]) {
            ingress_buffers_[worker_id]->Release(prepared_request.ingress_slot);
        }
        return false; // Queue full
    }
    
    return true;
}

bool SuperNodeEngine::CollectBatchFromWorker(int worker_id, BatchResponse& response) {
    if (worker_id < 0 || worker_id >= static_cast<int>(workers_.size())) {
        fprintf(stderr, "[SuperNode] Invalid worker_id %d\n", worker_id);
        return false;
    }
    
    LogicalWorker& worker = workers_[worker_id];
    if (!worker.batch_response_queue) {
        fprintf(stderr, "[SuperNode] Worker %d has no batch response queue\n", worker_id);
        return false;
    }
    
    // Non-blocking pop - caller must poll if no response ready
    return worker.batch_response_queue->pop(response);
}

bool SuperNodeEngine::PinThreadToCores(int core1, int core2) {
    // Windows implementation
    #ifdef _WIN32
    DWORD_PTR mask = (1ULL << core1) | (1ULL << core2);
    if (SetThreadAffinityMask(GetCurrentThread(), mask) == 0) {
        return false;
    }
    #endif
    
    printf("[SuperNode] Thread pinned to cores %d-%d\n", core1, core2);
    return true;
}

void SuperNodeEngine::GetMetrics(SuperNodeMetrics* metrics) {
    if (!metrics) return;
    
    metrics->tokens_processed = total_tokens_.load();
    metrics->active_workers = config_.logical_workers;
    
    // Calculate throughput
    // TODO: Implement actual calculation
    metrics->tokens_per_second = config_.target_throughput;
    
    // Memory usage
    metrics->memory_usage_bytes = memory_pool_size_;
}

// =============================================================================
// Model Weights Mapping from GGUF Handle
// =============================================================================
bool MapModelWeightsFromHandle(void* handle, ModelWeights& weights, const char* model_path) {
    if (!handle) return false;
    
    printf("[MapModelWeights] Using real GGUF tensor mapping...\n");
    
    // Try to use the GGUF mapper with a fresh loader
    RawrXD::StreamingGGUFLoader loader;
    
    if (!model_path || model_path[0] == '\0') {
        printf("[MapModelWeights] No model path available, using stub weights\n");
        return MapStubWeights(weights);
    }
    
    if (!loader.Open(model_path)) {
        printf("[MapModelWeights] Failed to open GGUF, using stub weights\n");
        return MapStubWeights(weights);
    }
    
    if (!loader.ParseHeader()) {
        printf("[MapModelWeights] Failed to parse GGUF header, using stub weights\n");
        return MapStubWeights(weights);
    }
    
    if (!loader.BuildTensorIndex()) {
        printf("[MapModelWeights] Failed to build tensor index, using stub weights\n");
        return MapStubWeights(weights);
    }
    
    // Use the real GGUF mapper
    if (!MapGGUFTensorsToModelWeights(&loader, weights)) {
        printf("[MapModelWeights] GGUF mapping failed, using stub weights\n");
        return MapStubWeights(weights);
    }
    
    printf("[MapModelWeights] Real GGUF tensors mapped successfully!\n");
    PrintWeightMap(weights);
    
    return true;
}

// =============================================================================
// Stub Weight Mapping (fallback)
// =============================================================================
bool MapStubWeights(ModelWeights& weights) {
    printf("[MapModelWeights] Allocating STUB weights for testing...\n");
    
    // TINY MODEL for testing (not Llama 3.2 3B)
    weights.n_layers = 4;
    weights.n_heads = 4;
    weights.n_kv_heads = 2;
    weights.head_dim = 64;
    weights.hidden_dim = 256;
    weights.ffn_dim = 512;
    weights.vocab_size = 1000;
    weights.seq_len = 512;
    
    printf("[MapModelWeights] Config: %u layers, %u heads, hidden=%u, vocab=%u\n",
           weights.n_layers, weights.n_heads, weights.hidden_dim, weights.vocab_size);
    
    // Token embeddings
    weights.token_embeddings = static_cast<float*>(
        VirtualAlloc(nullptr, weights.vocab_size * weights.hidden_dim * sizeof(float), 
                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (weights.token_embeddings) {
        for (uint32_t i = 0; i < weights.vocab_size * weights.hidden_dim; i++) {
            weights.token_embeddings[i] = (float)(rand() % 100) / 10000.0f - 0.005f;
        }
    }
    
    // Allocate layer arrays
    weights.attn_norm = new float*[weights.n_layers];
    weights.wq = new float*[weights.n_layers];
    weights.wk = new float*[weights.n_layers];
    weights.wv = new float*[weights.n_layers];
    weights.wo = new float*[weights.n_layers];
    weights.ffn_norm = new float*[weights.n_layers];
    weights.w_up = new float*[weights.n_layers];
    weights.w_gate = new float*[weights.n_layers];
    weights.w_down = new float*[weights.n_layers];
    
    // Allocate per-layer weights (stub values)
    for (uint32_t i = 0; i < weights.n_layers; i++) {
        weights.attn_norm[i] = static_cast<float*>(
            VirtualAlloc(nullptr, weights.hidden_dim * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (weights.attn_norm[i]) {
            for (uint32_t j = 0; j < weights.hidden_dim; j++) weights.attn_norm[i][j] = 1.0f;
        }
        
        weights.wq[i] = static_cast<float*>(
            VirtualAlloc(nullptr, weights.hidden_dim * weights.n_heads * weights.head_dim * sizeof(float), 
                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (weights.wq[i]) {
            for (uint32_t j = 0; j < weights.hidden_dim * weights.n_heads * weights.head_dim; j++) {
                weights.wq[i][j] = (float)(rand() % 100) / 10000.0f - 0.005f;
            }
        }
        
        weights.wk[i] = static_cast<float*>(
            VirtualAlloc(nullptr, weights.hidden_dim * weights.n_kv_heads * weights.head_dim * sizeof(float), 
                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (weights.wk[i]) {
            for (uint32_t j = 0; j < weights.hidden_dim * weights.n_kv_heads * weights.head_dim; j++) {
                weights.wk[i][j] = (float)(rand() % 100) / 10000.0f - 0.005f;
            }
        }
        
        weights.wv[i] = static_cast<float*>(
            VirtualAlloc(nullptr, weights.hidden_dim * weights.n_kv_heads * weights.head_dim * sizeof(float), 
                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (weights.wv[i]) {
            for (uint32_t j = 0; j < weights.hidden_dim * weights.n_kv_heads * weights.head_dim; j++) {
                weights.wv[i][j] = (float)(rand() % 100) / 10000.0f - 0.005f;
            }
        }
        
        weights.wo[i] = static_cast<float*>(
            VirtualAlloc(nullptr, weights.hidden_dim * weights.hidden_dim * sizeof(float), 
                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (weights.wo[i]) {
            for (uint32_t j = 0; j < weights.hidden_dim * weights.hidden_dim; j++) {
                weights.wo[i][j] = (j % (weights.hidden_dim + 1) == 0) ? 1.0f : 0.0f;
            }
        }
        
        weights.ffn_norm[i] = static_cast<float*>(
            VirtualAlloc(nullptr, weights.hidden_dim * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (weights.ffn_norm[i]) {
            for (uint32_t j = 0; j < weights.hidden_dim; j++) weights.ffn_norm[i][j] = 1.0f;
        }
        
        weights.w_up[i] = static_cast<float*>(
            VirtualAlloc(nullptr, weights.hidden_dim * weights.ffn_dim * sizeof(float), 
                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        weights.w_gate[i] = static_cast<float*>(
            VirtualAlloc(nullptr, weights.hidden_dim * weights.ffn_dim * sizeof(float), 
                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        weights.w_down[i] = static_cast<float*>(
            VirtualAlloc(nullptr, weights.ffn_dim * weights.hidden_dim * sizeof(float), 
                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    }
    
    weights.output_norm = static_cast<float*>(
        VirtualAlloc(nullptr, weights.hidden_dim * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (weights.output_norm) {
        for (uint32_t j = 0; j < weights.hidden_dim; j++) weights.output_norm[j] = 1.0f;
    }
    
    weights.lm_head = static_cast<float*>(
        VirtualAlloc(nullptr, weights.vocab_size * weights.hidden_dim * sizeof(float), 
                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (weights.lm_head) {
        for (uint32_t i = 0; i < weights.vocab_size * weights.hidden_dim; i++) {
            weights.lm_head[i] = (float)(rand() % 100) / 10000.0f - 0.005f;
        }
    }
    
    printf("[MapModelWeights] Stub weight memory allocated\n");
    return true;
}

void FreeModelWeights(ModelWeights& weights) {
    // Free dequantized weight arrays
    if (weights.wq) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            if (weights.wq[i]) VirtualFree(weights.wq[i], 0, MEM_RELEASE);
        }
        delete[] weights.wq;
    }
    if (weights.wk) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            if (weights.wk[i]) VirtualFree(weights.wk[i], 0, MEM_RELEASE);
        }
        delete[] weights.wk;
    }
    if (weights.wv) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            if (weights.wv[i]) VirtualFree(weights.wv[i], 0, MEM_RELEASE);
        }
        delete[] weights.wv;
    }
    if (weights.wo) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            if (weights.wo[i]) VirtualFree(weights.wo[i], 0, MEM_RELEASE);
        }
        delete[] weights.wo;
    }
    if (weights.w_up) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            if (weights.w_up[i]) VirtualFree(weights.w_up[i], 0, MEM_RELEASE);
        }
        delete[] weights.w_up;
    }
    if (weights.w_gate) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            if (weights.w_gate[i]) VirtualFree(weights.w_gate[i], 0, MEM_RELEASE);
        }
        delete[] weights.w_gate;
    }
    if (weights.w_down) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            if (weights.w_down[i]) VirtualFree(weights.w_down[i], 0, MEM_RELEASE);
        }
        delete[] weights.w_down;
    }
    if (weights.attn_norm) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            if (weights.attn_norm[i]) VirtualFree(weights.attn_norm[i], 0, MEM_RELEASE);
        }
        delete[] weights.attn_norm;
    }
    if (weights.ffn_norm) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            if (weights.ffn_norm[i]) VirtualFree(weights.ffn_norm[i], 0, MEM_RELEASE);
        }
        delete[] weights.ffn_norm;
    }
    
    // Free quantized storage
    if (weights.q_wq) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            weights.q_wq[i].Free();
        }
        delete[] weights.q_wq;
    }
    if (weights.q_wk) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            weights.q_wk[i].Free();
        }
        delete[] weights.q_wk;
    }
    if (weights.q_wv) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            weights.q_wv[i].Free();
        }
        delete[] weights.q_wv;
    }
    if (weights.q_wo) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            weights.q_wo[i].Free();
        }
        delete[] weights.q_wo;
    }
    if (weights.q_w_up) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            weights.q_w_up[i].Free();
        }
        delete[] weights.q_w_up;
    }
    if (weights.q_w_gate) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            weights.q_w_gate[i].Free();
        }
        delete[] weights.q_w_gate;
    }
    if (weights.q_w_down) {
        for (uint32_t i = 0; i < weights.n_layers; i++) {
            weights.q_w_down[i].Free();
        }
        delete[] weights.q_w_down;
    }
    weights.q_token_embeddings.Free();
    weights.q_lm_head.Free();
    
    // Free other arrays
    if (weights.token_embeddings) VirtualFree(weights.token_embeddings, 0, MEM_RELEASE);
    if (weights.output_norm) VirtualFree(weights.output_norm, 0, MEM_RELEASE);
    if (weights.lm_head) VirtualFree(weights.lm_head, 0, MEM_RELEASE);
    
    // Reset structure
    weights = ModelWeights{};
}

} // namespace Sovereign

// =============================================================================
// C API for External Integration
// =============================================================================

extern "C" {

typedef void* SuperNodeHandle;

SuperNodeHandle SuperNode_CreateWithModel(int logical_workers, const char* model_path);

SuperNodeHandle SuperNode_Create(int logical_workers) {
    return SuperNode_CreateWithModel(logical_workers, nullptr);
}

SuperNodeHandle SuperNode_CreateWithModel(int logical_workers, const char* model_path) {
    Sovereign::SuperNodeConfig config;
    config.logical_workers = logical_workers;
    if (model_path && model_path[0] != '\0') {
        config.model_path = model_path;
    }
    
    auto* engine = new Sovereign::SuperNodeEngine(config);
    if (!engine->Initialize()) {
        delete engine;
        return nullptr;
    }
    return engine;
}

void SuperNode_Destroy(SuperNodeHandle handle) {
    if (handle) {
        delete static_cast<Sovereign::SuperNodeEngine*>(handle);
    }
}

int SuperNode_ProcessToken(SuperNodeHandle handle, uint32_t token_id, uint32_t* output) {
    if (!handle || !output) return -1;
    auto* engine = static_cast<Sovereign::SuperNodeEngine*>(handle);
    return engine->ProcessToken(token_id, output) ? 0 : -1;
}

void SuperNode_GetMetrics(SuperNodeHandle handle, Sovereign::SuperNodeMetrics* metrics) {
    if (!handle || !metrics) return;
    auto* engine = static_cast<Sovereign::SuperNodeEngine*>(handle);
    engine->GetMetrics(metrics);
}

} // extern "C"

// =============================================================================
// Test Access Implementation (for stress test)
// =============================================================================

namespace Sovereign {

bool SuperNodeEngineTestAccess::SubmitBatchToWorker(SuperNodeEngine* engine, int worker_id,
                                                     const BatchRequest& request) {
    return engine->SubmitBatchToWorker(worker_id, request);
}

bool SuperNodeEngineTestAccess::CollectBatchFromWorker(SuperNodeEngine* engine, int worker_id,
                                                        BatchResponse& response) {
    return engine->CollectBatchFromWorker(worker_id, response);
}

uint8_t* SuperNodeEngineTestAccess::GetWorkerWindowPtr(SuperNodeEngine* engine, int worker_id) {
    if (!engine || worker_id < 0 || worker_id >= static_cast<int>(engine->workers_.size())) {
        return nullptr;
    }
    return static_cast<uint8_t*>(engine->workers_[worker_id].arena_window_ptr);
}

size_t SuperNodeEngineTestAccess::GetWorkerWindowSize(SuperNodeEngine* engine, int worker_id) {
    if (!engine || worker_id < 0 || worker_id >= static_cast<int>(engine->workers_.size())) {
        return 0;
    }
    return engine->workers_[worker_id].arena_window_size;
}

LogicalWorker* SuperNodeEngineTestAccess::GetWorker(SuperNodeEngine* engine, int worker_id) {
    if (!engine || worker_id < 0 || worker_id >= static_cast<int>(engine->workers_.size())) {
        return nullptr;
    }
    return &engine->workers_[worker_id];
}

bool SuperNodeEngineTestAccess::VerifyGuardBands(SuperNodeEngine* engine) {
    if (!engine) return false;
    return engine->VerifyGuardBands();
}

bool SuperNodeEngineTestAccess::CheckGuardBand(SuperNodeEngine* engine, int worker_id) {
    if (!engine) return false;
    return engine->CheckGuardBand(worker_id);
}

} // namespace Sovereign

// =============================================================================
// Interactive Chat Mode
// =============================================================================
void RunChatMode(Sovereign::SuperNodeEngine* engine, int max_tokens_per_response) {
    printf("\n");
    printf("=================================================================\n");
    printf("  Sovereign Engine - Interactive Chat Mode\n");
    printf("  Type your message and press Enter. Type 'exit' to quit.\n");
    printf("=================================================================\n\n");
    
    // Initialize detokenizer with vocabulary from model
    Sovereign::Detokenizer detokenizer;
    const auto& vocab = engine->GetVocabulary();
    if (!vocab.empty()) {
        detokenizer.Initialize(vocab);
        printf("[Chat] Detokenizer initialized with %zu tokens\n\n", vocab.size());
    } else {
        printf("[Chat] Warning: No vocabulary loaded - detokenization will not work\n\n");
    }
    
    // Initialize BPE tokenizer with vocabulary
    Sovereign::SovereignTokenizer tokenizer;
    if (!vocab.empty()) {
        // FIX: Clamp vocabulary to model's actual vocab_size
        // The tokenizer vocab may be larger than what the model tensors support
        size_t effective_vocab_size = vocab.size();
        if (engine && effective_vocab_size > engine->GetModelVocabSize()) {
            effective_vocab_size = engine->GetModelVocabSize();
            printf("[Chat] Tokenizer vocab clamped from %zu to %zu (model limit)\n", 
                   vocab.size(), effective_vocab_size);
        }
        
        std::vector<float> scores(effective_vocab_size, 0.0f);
        Sovereign::TokenizerConfig config;
        config.vocab_size = static_cast<uint32_t>(effective_vocab_size);
        config.bos_token_id = 1;
        config.eos_token_id = 2;
        config.unk_token_id = 0;
        
        // Only load the first effective_vocab_size tokens
        std::vector<std::string> clamped_vocab(vocab.begin(), vocab.begin() + effective_vocab_size);
        tokenizer.LoadVocabulary(clamped_vocab, scores, config);
        printf("[Chat] BPE Tokenizer initialized with %zu tokens\n\n", effective_vocab_size);
    } else {
        printf("[Chat] Warning: No vocabulary loaded - tokenization will not work\n\n");
    }
    
    // Conversation history (token IDs)
    std::vector<uint32_t> conversation_history;
    uint32_t total_tokens_generated = 0;
    
    while (true) {
        printf("\nYou: ");
        fflush(stdout);
        
        // Read user input
        std::string user_input;
        if (!std::getline(std::cin, user_input)) {
            // EOF reached or error (e.g., when piping input)
            printf("\n[Chat] EOF reached, exiting.\n");
            break;
        }
        
        // Also check for EOF state after getline (some implementations don't return false)
        if (std::cin.eof()) {
            printf("\n[Chat] EOF detected, exiting.\n");
            break;
        }
        
        // Check for exit
        if (user_input == "exit" || user_input == "quit") {
            printf("\nGoodbye!\n");
            break;
        }
        
        // Skip empty input - but also check if we're in a pipe and got empty string
        // which could indicate EOF in some implementations
        if (user_input.empty()) {
            // If stdin is not a tty (piped), empty line likely means EOF
            if (!IsStdinTty()) {
                printf("\n[Chat] Empty input in pipe mode, exiting.\n");
                break;
            }
            continue;
        }
        
        // === CHAT TEMPLATE ===
        // Format the prompt with Llama-2 chat template for better responses
        // Llama-2 format: "[INST] {input} [/INST]\n"
        std::string formatted_prompt = "[INST] " + user_input + " [/INST]\n";
        
        // Use proper BPE tokenization on the formatted prompt
        std::vector<uint32_t> input_tokens = tokenizer.Encode(formatted_prompt);
        if (input_tokens.empty()) {
            printf("[Chat] Warning: Tokenization produced no tokens\n");
            continue;
        }
        printf("[Chat] Tokenized input into %zu tokens (with chat template)\n", input_tokens.size());
        
        // Add to conversation history
        conversation_history.insert(conversation_history.end(), input_tokens.begin(), input_tokens.end());
        
        printf("Assistant: ");
        fflush(stdout);
        
        // === FIX: Process ALL input tokens first to build KV cache ===
        // Then start generating from the last token
        if (g_debug) {
            fprintf(stderr, "[CHAT] Processing %zu input tokens to build context...\n", input_tokens.size());
            fflush(stderr);
        }
        
        // Process all but the last input token (they build the KV cache)
        for (size_t i = 0; i + 1 < input_tokens.size(); i++) {
            uint32_t dummy_output = 0;
            if (g_debug) {
                fprintf(stderr, "[CHAT] Pre-processing input token %zu/%zu: %u\n", i+1, input_tokens.size(), input_tokens[i]);
                fflush(stderr);
            }
            if (SuperNode_ProcessToken(engine, input_tokens[i], &dummy_output) != 0) {
                if (g_debug) {
                    fprintf(stderr, "[CHAT] Failed to process input token %zu\n", i);
                    fflush(stderr);
                }
                break;
            }
        }
        
        // Start generation from the LAST input token
        uint32_t next_token = input_tokens.empty() ? 100 : input_tokens.back();
        if (g_debug) {
            fprintf(stderr, "[CHAT] Starting generation from token %u\n", next_token);
            fflush(stderr);
        }
        
        int tokens_generated = 0;
        std::string response_text;
        
        // DEBUG: Print input tokens
        if (g_debug) {
            fprintf(stderr, "[CHAT] Input tokens (%zu): ", input_tokens.size());
            for (auto t : input_tokens) fprintf(stderr, "%u ", t);
            fprintf(stderr, "\n");
            fflush(stderr);
        }
        
        for (int i = 0; i < max_tokens_per_response; i++) {
            uint32_t generated = 0;
            if (g_debug) {
                fprintf(stderr, "[GEN] Step %d: next_token=%u, calling ProcessToken...\n", i, next_token);
                fflush(stderr);
            }
            if (SuperNode_ProcessToken(engine, next_token, &generated) != 0) {
                if (g_debug) {
                    fprintf(stderr, "[GEN] Step %d: ProcessToken failed\n", i);
                    fflush(stderr);
                }
                break;
            }
            if (g_debug) {
                fprintf(stderr, "[GEN] Step %d: generated token %u\n", i, generated);
                fflush(stderr);
            }
            
            // Add to history
            conversation_history.push_back(generated);
            next_token = generated;
            tokens_generated++;
            total_tokens_generated++;
            
            // Convert token to text and print immediately (streaming)
            std::string token_text = detokenizer.Detokenize(generated);
            if (g_debug) {
                fprintf(stderr, "[DETOKEN] id=%u vocab=%zu text='%s' empty=%d\n", 
                        generated, detokenizer.GetVocabSize(), 
                        token_text.empty() ? "(null)" : token_text.c_str(),
                        token_text.empty() ? 1 : 0);
                fflush(stderr);
            }
            if (!token_text.empty()) {
                printf("%s", token_text.c_str());
                fflush(stdout);
                response_text += token_text;
            }
            
            // Stop on EOS token (typically 2 for Llama)
            if (generated == 2 || generated == 0) {
                break;
            }
            
            // Safety limit
            if (conversation_history.size() > 2048) {
                printf("\n[Chat] Context limit reached, truncating...\n");
                // Keep last 1024 tokens
                conversation_history.erase(conversation_history.begin(), 
                    conversation_history.begin() + (conversation_history.size() - 1024));
            }
        }
        
        printf("\n");
    }
    
    printf("\n[Chat] Session complete. Total tokens generated: %u\n", total_tokens_generated);
}

// =============================================================================
// Bridge Mode - Connect to MASM Orchestrator via Shared Memory
// =============================================================================
void RunBridgeMode(Sovereign::SuperNodeEngine* engine, const char* model_path, int max_tokens) {
    printf("=================================================================\n");
    printf("  Sovereign Engine - Bridge Mode\n");
    printf("  Connecting to MASM Orchestrator via Shared Memory IPC\n");
    printf("=================================================================\n\n");
    
    // Shared memory offsets (must match MASM orchestrator)
    const DWORD OFF_STATE = 0x00;
    const DWORD OFF_CMD_ID = 0x04;
    const DWORD OFF_CMD_TYPE = 0x08;
    const DWORD OFF_PAYLOAD_LEN = 0x0C;
    const DWORD OFF_RESP_STATUS = 0x10;
    const DWORD OFF_RESP_LEN = 0x14;
    const DWORD OFF_CMD_PAYLOAD = 0x18;
    const DWORD OFF_RESP_PAYLOAD = 0x1018;
    const DWORD OFF_MODEL_STATE = 0x2030;
    const DWORD OFF_MAGIC_COOKIE = 0xFFF0;
    
    // Commands
    const DWORD CMD_LOAD_MODEL = 0x2000;
    const DWORD CMD_INFER = 0x3003;
    
    // States
    const DWORD MODEL_STATE_READY = 2;
    const DWORD RESP_OK = 0;
    
    // 1. Open shared memory created by MASM orchestrator
    printf("[Bridge] Opening shared memory (SOVEREIGN_BEACON_V1)...\n");
    HANDLE hShMem = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, "SOVEREIGN_BEACON_V1");
    if (!hShMem) {
        fprintf(stderr, "[Bridge] ERROR: Cannot open shared memory. Is orchestrator running? (err=%lu)\n", GetLastError());
        return;
    }
    
    BYTE* pShMem = (BYTE*)MapViewOfFile(hShMem, FILE_MAP_ALL_ACCESS, 0, 0, 0x10000);
    if (!pShMem) {
        fprintf(stderr, "[Bridge] ERROR: Cannot map view of shared memory (err=%lu)\n", GetLastError());
        CloseHandle(hShMem);
        return;
    }
    
    // 2. Open events
    HANDLE hCmdEvent = OpenEventA(EVENT_ALL_ACCESS, FALSE, "SOVEREIGN_CMD_EVENT");
    HANDLE hRespEvent = OpenEventA(EVENT_ALL_ACCESS, FALSE, "SOVEREIGN_RESP_EVENT");
    
    if (!hCmdEvent || !hRespEvent) {
        fprintf(stderr, "[Bridge] ERROR: Cannot open events (cmd=%p, resp=%p, err=%lu)\n", 
                (void*)hCmdEvent, (void*)hRespEvent, GetLastError());
        UnmapViewOfFile(pShMem);
        CloseHandle(hShMem);
        return;
    }
    
    // 3. Verify magic cookie
    uint64_t magic = *(uint64_t*)(pShMem + OFF_MAGIC_COOKIE);
    if (magic != 0xDEADBEEFCAFEBABEULL) {
        fprintf(stderr, "[Bridge] WARNING: Magic cookie mismatch (got %016llX, expected %016llX)\n", 
                magic, 0xDEADBEEFCAFEBABEULL);
    }
    
    // 4. Initialize detokenizer and tokenizer
    Sovereign::Detokenizer detokenizer;
    Sovereign::SovereignTokenizer tokenizer;
    const auto& vocab = engine->GetVocabulary();
    
    if (!vocab.empty()) {
        detokenizer.Initialize(vocab);
        std::vector<float> scores(vocab.size(), 0.0f);
        Sovereign::TokenizerConfig config;
        config.vocab_size = static_cast<uint32_t>(vocab.size());
        config.bos_token_id = 1;
        config.eos_token_id = 2;
        config.unk_token_id = 0;
        tokenizer.LoadVocabulary(vocab, scores, config);
        printf("[Bridge] Tokenizer initialized with %zu tokens\n", vocab.size());
    } else {
        printf("[Bridge] Warning: No vocabulary loaded\n");
    }
    
    // 5. Set model state to READY
    *(DWORD*)(pShMem + OFF_MODEL_STATE) = MODEL_STATE_READY;
    printf("[Bridge] Model state set to READY\n");
    printf("[Bridge] Listening for commands... (Press Ctrl+C to stop)\n\n");
    fflush(stdout);
    
    // 6. Main loop: wait for commands
    int request_count = 0;
    while (true) {
        // Wait for command event
        DWORD wait_result = WaitForSingleObject(hCmdEvent, 1000); // 1 second timeout
        if (wait_result == WAIT_TIMEOUT) {
            continue; // Check for exit condition
        }
        if (wait_result != WAIT_OBJECT_0) {
            fprintf(stderr, "[Bridge] Wait failed (err=%lu)\n", GetLastError());
            break;
        }
        
        // Reset command event
        ResetEvent(hCmdEvent);
        
        // Read command
        DWORD cmd_type = *(DWORD*)(pShMem + OFF_CMD_TYPE);
        DWORD payload_len = *(DWORD*)(pShMem + OFF_PAYLOAD_LEN);
        
        if (cmd_type == CMD_INFER) {
            request_count++;
            
            // Read prompt from shared memory
            char prompt[4096];
            if (payload_len >= sizeof(prompt)) payload_len = sizeof(prompt) - 1;
            memcpy(prompt, pShMem + OFF_CMD_PAYLOAD, payload_len);
            prompt[payload_len] = '\0';
            
            printf("[Bridge] Request #%d: %.80s...\n", request_count, prompt);
            fflush(stdout);
            
            // Tokenize input
            std::vector<uint32_t> input_tokens = tokenizer.Encode(prompt);
            if (input_tokens.empty()) {
                input_tokens.push_back(100); // Fallback token
            }
            
            // Generate response
            std::string response_text;
            uint32_t next_token = input_tokens.back();
            int tokens_generated = 0;
            
            for (int i = 0; i < max_tokens && tokens_generated < max_tokens; i++) {
                uint32_t generated = 0;
                if (SuperNode_ProcessToken(engine, next_token, &generated) != 0) {
                    fprintf(stderr, "[Bridge] Token generation failed at step %d\n", i);
                    break;
                }
                
                // Stop on EOS
                if (generated == 2 || generated == 0) {
                    break;
                }
                
                // Convert to text
                std::string token_text = detokenizer.Detokenize(generated);
                response_text += token_text;
                
                next_token = generated;
                tokens_generated++;
            }
            
            // Write response to shared memory
            int resp_len = response_text.size();
            if (resp_len > 61432) resp_len = 61432; // Max response size
            memcpy(pShMem + OFF_RESP_PAYLOAD, response_text.c_str(), resp_len);
            *(DWORD*)(pShMem + OFF_RESP_STATUS) = RESP_OK;
            *(DWORD*)(pShMem + OFF_RESP_LEN) = resp_len;
            
            printf("[Bridge] Response: %.80s... (%d tokens, %d bytes)\n", 
                   response_text.c_str(), tokens_generated, resp_len);
            fflush(stdout);
            
            // Signal response event
            SetEvent(hRespEvent);
        }
    }
    
    // Cleanup
    printf("\n[Bridge] Shutting down...\n");
    CloseHandle(hRespEvent);
    CloseHandle(hCmdEvent);
    UnmapViewOfFile(pShMem);
    CloseHandle(hShMem);
}

// =============================================================================
// Main Entry Point
// =============================================================================
int main(int argc, char* argv[]) {
    printf("=================================================================\n");
    printf("Sovereign Engine - Super-Node Architecture\n");
    printf("High-Performance Single-Machine Inference Engine\n");
    printf("=================================================================\n\n");
    
    // Parse arguments
    bool benchmark_mode = false;
    bool inference_mode = false;
    bool dry_test_mode = false;
    bool chat_mode = false;
    bool bridge_mode = false;  // NEW: Bridge mode for shared memory IPC
    int duration_seconds = 60;
    int logical_workers = 8;
    int max_tokens = 10;
    const char* model_path = nullptr;
    const char* prompt = nullptr;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--benchmark") == 0) {
            benchmark_mode = true;
        } else if (strcmp(argv[i], "--inference") == 0) {
            inference_mode = true;
        } else if (strcmp(argv[i], "--dry-test") == 0) {
            dry_test_mode = true;
        } else if (strcmp(argv[i], "--chat") == 0) {
            chat_mode = true;
        } else if (strcmp(argv[i], "--bridge") == 0) {  // NEW: Bridge mode
            bridge_mode = true;
        } else if (strcmp(argv[i], "--debug") == 0) {
            g_debug = true;
            printf("[Main] Debug mode enabled\n");
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            duration_seconds = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
            logical_workers = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            model_path = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--prompt") == 0 && i + 1 < argc) {
            prompt = argv[i + 1];
            inference_mode = true;  // Auto-enable inference when prompt is provided
            i++;
        } else if (strcmp(argv[i], "--max-tokens") == 0 && i + 1 < argc) {
            max_tokens = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--debug") == 0) {
            g_debug = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --benchmark          Run benchmark mode\n");
            printf("  --inference          Run inference mode with prompt\n");
            printf("  --chat               Run interactive chat mode\n");
            printf("  --bridge             Run bridge mode (shared memory IPC)\n");
            printf("  --dry-test           Run dry load test (no GGUF file needed)\n");
            printf("  --duration <sec>     Benchmark duration (default: 60)\n");
            printf("  --workers <n>        Number of logical workers (default: 8)\n");
            printf("  --model <path>       Model path to load\n");
            printf("  --prompt <text>      Prompt for inference mode\n");
            printf("  --max-tokens <n>     Max tokens to generate (default: 10)\n");
            printf("  --debug              Enable verbose debug output\n");
            printf("  --help               Show this help\n");
            return 0;
        }
    }
    
    // Run dry load test if requested
    if (dry_test_mode) {
        bool passed = Sovereign::RunDryLoadTest(true);
        return passed ? 0 : 1;
    }
    
    // Create SuperNode
    printf("[Main] Creating Super-Node with %d logical workers...\n", logical_workers);
    auto* engine = SuperNode_CreateWithModel(logical_workers, model_path);
    if (!engine) {
        fprintf(stderr, "[Main] Failed to create Super-Node\n");
        return 1;
    }
    
    printf("[Main] Super-Node initialized successfully!\n\n");
    
    if (benchmark_mode) {
        printf("[Benchmark] Running for %d seconds...\n", duration_seconds);
        printf("[Benchmark] Target throughput: 30,000-40,000 tokens/sec\n\n");
        
        // Run benchmark
        auto start = std::chrono::high_resolution_clock::now();
        uint64_t tokens_processed = 0;
        
        while (true) {
            auto now = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
            
            if (elapsed >= duration_seconds) break;
            
            // Simulate token processing
            uint32_t output_token;
            if (SuperNode_ProcessToken(engine, 1000 + (tokens_processed % 1000), &output_token) == 0) {
                tokens_processed++;
            }
            
            // Print progress every second
            if (tokens_processed % 10000 == 0) {
                double tps = tokens_processed / (double)(elapsed + 1);
                printf("[Benchmark] Time: %3llds | Tokens: %6llu | TPS: %6.0f\r", 
                       elapsed, tokens_processed, tps);
                fflush(stdout);
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double actual_tps = tokens_processed / (total_duration / 1000.0);
        
        printf("\n\n[Benchmark] Complete!\n");
        printf("[Benchmark] Total tokens: %llu\n", tokens_processed);
        printf("[Benchmark] Duration: %.2f seconds\n", total_duration / 1000.0);
        printf("[Benchmark] Throughput: %.0f tokens/sec\n", actual_tps);
        printf("[Benchmark] Target: 30,000-40,000 tokens/sec\n");
        
        if (actual_tps >= 30000) {
            printf("[Benchmark] Status: ✅ EXCELLENT (%.0f%% of target)\n", (actual_tps / 35000.0) * 100);
        } else if (actual_tps >= 20000) {
            printf("[Benchmark] Status: ✅ GOOD (%.0f%% of target)\n", (actual_tps / 35000.0) * 100);
        } else {
            printf("[Benchmark] Status: ⚠️ NEEDS OPTIMIZATION\n");
        }
    } else if (inference_mode && prompt) {
        printf("[Inference] Prompt: \"%s\"\n", prompt);
        printf("[Inference] Generating up to %d tokens...\n\n", max_tokens);
        
        // Simple tokenization: convert prompt to token IDs (stub for now)
        // In production: use actual tokenizer
        std::vector<uint32_t> input_tokens;
        for (int i = 0; i < 5; i++) {
            input_tokens.push_back(i);  // Stub tokens (0-4)
        }
        
        printf("[Inference] Input tokens: ");
        for (auto t : input_tokens) printf("%u ", t);
        printf("\n\n");
        
        // Generate tokens
        std::vector<uint32_t> output_tokens;
        uint32_t next_token = input_tokens.back();
        
        for (int i = 0; i < max_tokens; i++) {
            uint32_t generated = 0;
            if (SuperNode_ProcessToken(engine, next_token, &generated) != 0) {
                fprintf(stderr, "[Inference] Token generation failed at step %d\n", i);
                break;
            }
            output_tokens.push_back(generated);
            next_token = generated;
            printf("[Inference] Step %d: token=%u\n", i + 1, generated);
            
            // Stop on EOS token (typically token 2)
            if (generated == 2) {
                printf("[Inference] EOS token reached\n");
                break;
            }
        }
        
        printf("\n[Inference] Generated %zu tokens: ", output_tokens.size());
        for (auto t : output_tokens) printf("%u ", t);
        printf("\n");
    } else if (chat_mode) {
        // Run interactive chat mode
        RunChatMode(static_cast<Sovereign::SuperNodeEngine*>(engine), max_tokens);
    } else if (bridge_mode) {
        // NEW: Run bridge mode for shared memory IPC
        RunBridgeMode(static_cast<Sovereign::SuperNodeEngine*>(engine), model_path, max_tokens);
    } else {
        printf("[Main] Running in normal mode (use --benchmark for performance test)\n");
        printf("[Main] Use --chat for interactive mode\n");
        printf("[Main] Use --bridge for shared memory bridge mode\n");
        printf("[Main] Press Ctrl+C to stop...\n\n");
        
        // Run for 10 seconds in normal mode
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
    
    // Cleanup
    printf("\n[Main] Shutting down...\n");
    SuperNode_Destroy(engine);
    printf("[Main] Done!\n");
    
    return 0;
}
