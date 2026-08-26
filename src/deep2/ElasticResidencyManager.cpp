// ============================================================================
// ElasticResidencyManager.cpp
// VAL-051.7+ — Unified tensor residency implementation
// ============================================================================

#include "ElasticResidencyManager.hpp"
#include "QuantKernelRegistry.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include ?cntl.h>
#endif

namespace Deep2 {

// ============================================================================
// Lifecycle
// ============================================================================
ElasticResidencyManager::ElasticResidencyManager() = default;

ElasticResidencyManager::~ElasticResidencyManager() {
    Shutdown();
}

bool ElasticResidencyManager::Initialize(const ElasticResidencyConfig& config) {
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    if (initialized_.load()) {
        printf("[ElasticResidencyManager] Already initialized\n");
        return true;
    }
    config_ = config;
    initialized_.store(true);
    shutdownRequested_.store(false);

    // Start scheduler thread
    schedulerThread_ = std::thread(&ElasticResidencyManager::SchedulerThreadBody, this);

    printf("[ElasticResidencyManager] Initialized: warmCompressed=%zu MB, warmStaged=%zu MB, hot=%zu MB, lookahead=%u\n",
           config_.maxWarmCompressedBytes / (1024*1024),
           config_.maxWarmStagedBytes / (1024*1024),
           config_.maxHotBytes / (1024*1024),
           config_.prefetchLookahead);
    return true;
}

void ElasticResidencyManager::Shutdown() {
    if (!initialized_.load()) return;

    shutdownRequested_.store(true);
    queueCv_.notify_all();

    if (schedulerThread_.joinable()) {
        schedulerThread_.join();
    }

    std::lock_guard<std::mutex> lock(tensorsMutex_);

    // Assert clean state: no in-flight ops
    for (auto& kv : tensors_) {
        auto& t = *kv.second;
        uint32_t inFlight = t.inFlightOps.load();
        if (inFlight > 0) {
            fprintf(stderr, "[ElasticResidencyManager] WARNING: tensor '%s' has %u in-flight ops at shutdown\n",
                    t.name.c_str(), inFlight);
        }

        // Free all buffers
        if (t.compressedData) {
#ifdef _WIN32
            VirtualFree(t.compressedData, 0, MEM_RELEASE);
#else
            free(t.compressedData);
#endif
        }
        if (t.stagedData) {
#ifdef _WIN32
            VirtualFree(t.stagedData, 0, MEM_RELEASE);
#else
            free(t.stagedData);
#endif
        }
        // gpuData is owned by the GPU backend; just null it
        t.gpuData = nullptr;
    }

    tensors_.clear();
    warmCompressedUsed_ = 0;
    warmStagedUsed_ = 0;
    hotUsed_ = 0;
    initialized_.store(false);

    printf("[ElasticResidencyManager] Shutdown complete\n");
}

// ============================================================================
// Tensor Registration
// ============================================================================
bool ElasticResidencyManager::RegisterTensor(
    const std::string& name,
    uint32_t layerIndex,
    uint32_t expertIndex,
    size_t fileOffset,
    size_t compressedBytes,
    TensorFormat nativeFormat,
    const void* sourceData)
{
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    if (!initialized_.load()) {
        fprintf(stderr, "[ElasticResidencyManager] ERROR: not initialized\n");
        return false;
    }
    if (tensors_.find(name) != tensors_.end()) {
        fprintf(stderr, "[ElasticResidencyManager] WARNING: tensor '%s' already registered\n", name.c_str());
        return true;  // idempotent
    }

    auto tensor = std::make_shared<ElasticResidentTensor>();
    tensor->name = name;
    tensor->layerIndex = layerIndex;
    tensor->expertIndex = expertIndex;
    tensor->fileOffset = fileOffset;
    tensor->compressedBytes = compressedBytes;
    tensor->sourceData = sourceData;
    tensor->nativeFormat = nativeFormat;
    tensor->state.store(ResidencyState::Cold);
    tensor->generation.store(0);
    tensor->inFlightOps.store(0);
    tensor->lastUseSequence.store(0);
    tensor->predictedNextLayer.store(~0u);

    tensors_.emplace(name, tensor);
    return true;
}

// ============================================================================
// State Queries
// ============================================================================
ResidencyState ElasticResidencyManager::GetTensorState(const std::string& name) const {
    auto t = FindTensor(name);
    if (!t) return ResidencyState::Cold;
    return t->state.load();
}

bool ElasticResidencyManager::IsTensorReadyForCompute(const std::string& name) const {
    ResidencyState s = GetTensorState(name);
    return (s == ResidencyState::Hot ||
            s == ResidencyState::WarmStaged ||
            s == ResidencyState::WarmCompressed);
}

// ============================================================================
// Synchronous Acquire (CPU path)
// ============================================================================
const void* ElasticResidencyManager::AcquireForCpu(const std::string& name,
                                                    TensorFormat desiredFormat) {
    auto t = FindTensor(name);
    if (!t) {
        fprintf(stderr, "[ElasticResidencyManager] ERROR: tensor '%s' not found\n", name.c_str());
        return nullptr;
    }

    ResidencyState current = t->state.load();

    // Fast path: already in desired format
    if (desiredFormat == t->nativeFormat &&
        (current == ResidencyState::WarmCompressed || current == ResidencyState::Hot)) {
        t->lastUseSequence.fetch_add(1);
        return t->compressedData;
    }
    if (desiredFormat == t->stagedFormat && current == ResidencyState::WarmStaged) {
        t->lastUseSequence.fetch_add(1);
        return t->stagedData;
    }

    // Need to bring into RAM
    if (current == ResidencyState::Cold) {
        auto t0 = std::chrono::steady_clock::now();
        ExecuteNvmeToRam(*t);
        auto t1 = std::chrono::steady_clock::now();
        telemetry_.nvmeReadUs.fetch_add(
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
    }

    // Need staging?
    if (desiredFormat == TensorFormat::FP32 || desiredFormat == TensorFormat::FP16) {
        if (t->state.load() != ResidencyState::WarmStaged) {
            auto t0 = std::chrono::steady_clock::now();
            ExecuteDequantStage(*t);
            auto t1 = std::chrono::steady_clock::now();
            telemetry_.ramStageUs.fetch_add(
                std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
        }
        t->lastUseSequence.fetch_add(1);
        return t->stagedData;
    }

    // Return compressed for quantized CPU kernels
    t->lastUseSequence.fetch_add(1);
    return t->compressedData;
}

void ElasticResidencyManager::ReleaseFromCpu(const std::string& name) {
    // For now, CPU release is a no-op; LRU eviction handles cleanup.
    // In the future, this could decrement a use-count for eager eviction.
    (void)name;
}

// ============================================================================
// Async Prefetch (GPU path)
// ============================================================================
void ElasticResidencyManager::PrefetchToGpu(const std::string& name, uint32_t targetLayer) {
    auto t = FindTensor(name);
    if (!t) return;

    t->predictedNextLayer.store(targetLayer);

    ResidencyState current = t->state.load();
    if (current == ResidencyState::Hot || current == ResidencyState::Uploading) {
        telemetry_.prefetchHit.fetch_add(1);
        return;  // Already hot or on its way
    }

    telemetry_.prefetchMiss.fetch_add(1);

    // Determine path: if useQuantizedGpuPath is true and backend supports it,
    // we can upload compressed directly. Otherwise we need staging.
    if (config_.useQuantizedGpuPath) {
        // Path: Cold → WarmCompressed → Uploading → Hot
        if (current == ResidencyState::Cold) {
            EnqueueRequest(TransferRequest::Type::NvmeToRam, name, targetLayer);
        }
        EnqueueRequest(TransferRequest::Type::RamToVram, name, targetLayer);
    } else {
        // Path: Cold → WarmCompressed → WarmStaged → Uploading → Hot
        if (current == ResidencyState::Cold) {
            EnqueueRequest(TransferRequest::Type::NvmeToRam, name, targetLayer);
        }
        EnqueueRequest(TransferRequest::Type::DequantStage, name, targetLayer);
        EnqueueRequest(TransferRequest::Type::RamToVram, name, targetLayer);
    }
}

// ============================================================================
// GPU Compute Binding
// ============================================================================
const void* ElasticResidencyManager::BindForGpuCompute(const std::string& name) {
    auto t = FindTensor(name);
    if (!t) return nullptr;

    ResidencyState current = t->state.load();

    // Fast path: already hot
    if (current == ResidencyState::Hot) {
        t->lastUseSequence.fetch_add(1);
        return t->gpuData;
    }

    // If uploading, block efficiently until transfer completes or fails
    if (current == ResidencyState::Uploading) {
        auto waitT0 = std::chrono::steady_clock::now();
        {
            std::unique_lock<std::mutex> lock(tensorsMutex_);
            stateCv_.wait(lock, [&t]() {
                ResidencyState s = t->state.load();
                return s == ResidencyState::Hot || s == ResidencyState::WarmStaged ||
                       s == ResidencyState::WarmCompressed || s == ResidencyState::Cold ||
                       s == ResidencyState::Failed;
            });
        }
        auto waitT1 = std::chrono::steady_clock::now();
        telemetry_.gpuWaitUs.fetch_add(
            std::chrono::duration_cast<std::chrono::microseconds>(waitT1 - waitT0).count());
        current = t->state.load();
    }

    if (current == ResidencyState::Hot) {
        t->lastUseSequence.fetch_add(1);
        return t->gpuData;
    }

    // Prefetch missed — synchronous fallback
    fprintf(stderr, "[ElasticResidencyManager] WARNING: prefetch missed for '%s', synchronous staging\n",
            name.c_str());
    telemetry_.prefetchMiss.fetch_add(1);

    auto fallbackT0 = std::chrono::steady_clock::now();
    if (current == ResidencyState::Cold) {
        ExecuteNvmeToRam(*t);
    }
    if (!config_.useQuantizedGpuPath && t->state.load() != ResidencyState::WarmStaged) {
        ExecuteDequantStage(*t);
    }
    ExecuteRamToVram(*t);
    auto fallbackT1 = std::chrono::steady_clock::now();
    telemetry_.cpuFallbackUs.fetch_add(
        std::chrono::duration_cast<std::chrono::microseconds>(fallbackT1 - fallbackT0).count());

    if (t->state.load() == ResidencyState::Hot) {
        t->lastUseSequence.fetch_add(1);
        return t->gpuData;
    }
    return nullptr;
}

void ElasticResidencyManager::UnbindFromGpuCompute(const std::string& name) {
    (void)name;
    // No-op for now; eviction is lazy/LRU-driven
}

// ============================================================================
// Predictive Scheduling (MoE)
// ============================================================================
void ElasticResidencyManager::SetExpertPredictor(std::shared_ptr<IExpertPredictor> predictor) {
    std::lock_guard<std::mutex> lock(predictorMutex_);
    expertPredictor_ = predictor;
}

void ElasticResidencyManager::PredictLayerNeeds(uint32_t nextLayer,
                                                 const void* routerHiddenState,
                                                 size_t hiddenDim) {
    std::shared_ptr<IExpertPredictor> predictor;
    {
        std::lock_guard<std::mutex> lock(predictorMutex_);
        predictor = expertPredictor_;
    }
    if (!predictor || !routerHiddenState) return;

    auto experts = predictor->PredictNextExperts(nextLayer, routerHiddenState, hiddenDim,
                                                   config_.moeHotExpertCount);

    // Prefetch predicted experts with high priority
    for (uint32_t expertId : experts) {
        // Find tensors belonging to this layer+expert
        std::lock_guard<std::mutex> lock(tensorsMutex_);
        for (auto& kv : tensors_) {
            auto& t = *kv.second;
            if (t.layerIndex == nextLayer && t.expertIndex == expertId) {
                EnqueueRequest(TransferRequest::Type::RamToVram, t.name, 0);  // priority 0 = highest
            }
        }
    }
}

// ============================================================================
// Eviction
// ============================================================================
void ElasticResidencyManager::EvictLeastRecentlyUsed(size_t bytesNeeded) {
    std::vector<ElasticResidentTensor*> candidates;
    {
        std::lock_guard<std::mutex> lock(tensorsMutex_);
        for (auto& kv : tensors_) {
            auto& t = *kv.second;
            ResidencyState s = t.state.load();
            if (s == ResidencyState::Hot || s == ResidencyState::WarmStaged ||
                s == ResidencyState::WarmCompressed) {
                candidates.push_back(&t);
            }
        }
    }

    // Sort by lastUseSequence ascending (oldest first)
    std::sort(candidates.begin(), candidates.end(),
              [](ElasticResidentTensor* a, ElasticResidentTensor* b) {
                  return a->lastUseSequence.load() < b->lastUseSequence.load();
              });

    size_t freed = 0;
    for (auto* t : candidates) {
        if (freed >= bytesNeeded) break;

        ResidencyState s = t->state.load();
        if (s == ResidencyState::Hot) {
            auto t0 = std::chrono::steady_clock::now();
            if (TryTransition(t->name, ResidencyState::Hot, ResidencyState::Evicting)) {
                EnqueueRequest(TransferRequest::Type::VramToRam, t->name, 100);
            }
            auto t1 = std::chrono::steady_clock::now();
            telemetry_.vramEvictionUs.fetch_add(
                std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
            freed += t->gpuBytes;
        } else if (s == ResidencyState::WarmStaged) {
            if (TryTransition(t->name, ResidencyState::WarmStaged, ResidencyState::WarmCompressed)) {
                ExecuteFreeStaged(*t);
            }
            freed += t->stagedAllocated;
        } else if (s == ResidencyState::WarmCompressed) {
            if (TryTransition(t->name, ResidencyState::WarmCompressed, ResidencyState::Cold)) {
                if (t->compressedData) {
#ifdef _WIN32
                    VirtualFree(t->compressedData, 0, MEM_RELEASE);
#else
                    free(t->compressedData);
#endif
                    t->compressedData = nullptr;
                    t->compressedAllocated = 0;
                }
                ReleaseWarmCompressed(t->compressedBytes);
            }
            freed += t->compressedBytes;
        }
    }
}

void ElasticResidencyManager::EvictAllHot() {
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    for (auto& kv : tensors_) {
        auto& t = *kv.second;
        if (t.state.load() == ResidencyState::Hot) {
            if (TryTransition(t.name, ResidencyState::Hot, ResidencyState::Evicting)) {
                EnqueueRequest(TransferRequest::Type::VramToRam, t.name, 100);
            }
        }
    }
}

// ============================================================================
// Scheduler Thread
// ============================================================================
void ElasticResidencyManager::SchedulerThreadBody() {
    printf("[ElasticResidencyManager] Scheduler thread started\n");

    while (!shutdownRequested_.load()) {
        TransferRequest req;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCv_.wait(lock, [this] {
                return !requestQueue_.empty() || shutdownRequested_.load();
            });
            if (shutdownRequested_.load()) break;
            if (requestQueue_.empty()) continue;

            // Simple priority: lower priority value first, then FIFO
            req = requestQueue_.front();
            requestQueue_.pop();
        }

        auto t = FindTensor(req.tensorName);
        if (!t) continue;

        switch (req.type) {
            case TransferRequest::Type::NvmeToRam:
                ExecuteNvmeToRam(*t);
                break;
            case TransferRequest::Type::DequantStage:
                ExecuteDequantStage(*t);
                break;
            case TransferRequest::Type::RamToVram:
                ExecuteRamToVram(*t);
                break;
            case TransferRequest::Type::VramToRam:
                ExecuteVramToRam(*t);
                break;
            case TransferRequest::Type::FreeStaged:
                ExecuteFreeStaged(*t);
                break;
        }

        // Notify any waiters that state may have changed
        stateCv_.notify_all();
    }

    printf("[ElasticResidencyManager] Scheduler thread exiting\n");
}

// ============================================================================
// State Transitions
// ============================================================================
bool ElasticResidencyManager::TryTransition(const std::string& name,
                                               ResidencyState expected,
                                               ResidencyState desired) {
    auto t = FindTensor(name);
    if (!t) return false;

    ResidencyState current = expected;
    if (!t->state.compare_exchange_strong(current, desired)) {
        telemetry_.stateRaceBlocked.fetch_add(1);
        return false;
    }
    stateCv_.notify_all();
    return true;
}

// ============================================================================
// Transfer Implementations
// ============================================================================
void ElasticResidencyManager::ExecuteNvmeToRam(ElasticResidentTensor& t) {
    // Mark in-flight
    t.inFlightOps.fetch_add(1);

    // Transition: Cold → StreamingIn
    if (!TryTransition(t.name, ResidencyState::Cold, ResidencyState::StreamingIn)) {
        // Maybe already in progress
        t.inFlightOps.fetch_sub(1);
        return;
    }

    // Allocate aligned RAM for compressed data
    size_t allocSize = (t.compressedBytes + config_.pageAlignment - 1) & ~(config_.pageAlignment - 1);
    if (!ReserveWarmCompressed(allocSize)) {
        EvictLeastRecentlyUsed(allocSize);
        if (!ReserveWarmCompressed(allocSize)) {
            fprintf(stderr, "[ElasticResidencyManager] FATAL: cannot allocate %zu bytes for '%s'\n",
                    allocSize, t.name.c_str());
            t.state.store(ResidencyState::Cold);
            t.inFlightOps.fetch_sub(1);
            return;
        }
    }

#ifdef _WIN32
    t.compressedData = VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    t.compressedData = aligned_alloc(config_.pageAlignment, allocSize);
#endif
    t.compressedAllocated = allocSize;

    // Read from source (already-mapped GGUF data or file)
    if (t.compressedData) {
        if (t.sourceData) {
            memcpy(t.compressedData, t.sourceData, t.compressedBytes);
        } else {
            // No source pointer available — zero-fill as fallback (will fail validation)
            memset(t.compressedData, 0, t.compressedBytes);
        }
    }

    // Transition: StreamingIn → WarmCompressed
    t.state.store(ResidencyState::WarmCompressed);
    t.inFlightOps.fetch_sub(1);
}

void ElasticResidencyManager::ExecuteDequantStage(ElasticResidentTensor& t) {
    t.inFlightOps.fetch_add(1);

    if (!TryTransition(t.name, ResidencyState::WarmCompressed, ResidencyState::WarmStaged)) {
        t.inFlightOps.fetch_sub(1);
        return;
    }

    // Determine output element count and size
    // For now, assume FP32 staging. Real implementation should query
    // the tensor shape from metadata.
    size_t elementCount = t.compressedBytes * 2;  // rough: Q4_0 is 4 bits per weight
    size_t stagedBytes = elementCount * sizeof(float);
    size_t allocSize = (stagedBytes + config_.pageAlignment - 1) & ~(config_.pageAlignment - 1);

    if (!ReserveWarmStaged(allocSize)) {
        EvictLeastRecentlyUsed(allocSize);
        if (!ReserveWarmStaged(allocSize)) {
            fprintf(stderr, "[ElasticResidencyManager] FATAL: cannot stage %zu bytes for '%s'\n",
                    allocSize, t.name.c_str());
            t.state.store(ResidencyState::WarmCompressed);
            t.inFlightOps.fetch_sub(1);
            return;
        }
    }

#ifdef _WIN32
    t.stagedData = VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    t.stagedData = aligned_alloc(config_.pageAlignment, allocSize);
#endif
    t.stagedBytes = stagedBytes;
    t.stagedAllocated = allocSize;
    t.stagedFormat = TensorFormat::FP32;

    // Dequantize using QuantKernelRegistry
    // TODO: integrate with actual registry singleton
    // For now, stub: call the corrected dequant_q4_0 if format matches
    if (t.nativeFormat == TensorFormat::Q4_0 && t.compressedData) {
        // dequant_q4_0 expects block_q4_0 layout
        // This is a placeholder; real integration needs shape info
        // QuantKernelRegistry::Instance().Dequantize(t.compressedData, (float*)t.stagedData, ...);
    }

    t.inFlightOps.fetch_sub(1);
}

void ElasticResidencyManager::ExecuteRamToVram(ElasticResidentTensor& t) {
    t.inFlightOps.fetch_add(1);

    ResidencyState srcState = t.state.load();
    if (srcState != ResidencyState::WarmStaged && srcState != ResidencyState::WarmCompressed) {
        t.inFlightOps.fetch_sub(1);
        return;
    }

    if (!TryTransition(t.name, srcState, ResidencyState::Uploading)) {
        t.inFlightOps.fetch_sub(1);
        return;
    }

    size_t uploadBytes = config_.useQuantizedGpuPath ? t.compressedBytes : t.stagedBytes;
    if (!ReserveHot(uploadBytes)) {
        EvictLeastRecentlyUsed(uploadBytes);
        if (!ReserveHot(uploadBytes)) {
            fprintf(stderr, "[ElasticResidencyManager] FATAL: cannot reserve VRAM for '%s'\n",
                    t.name.c_str());
            t.state.store(srcState);
            t.inFlightOps.fetch_sub(1);
            return;
        }
    }

    // TODO: actual GPU upload via Vulkan/CUDA
    // void* gpuPtr = GpuBackend::Upload(t.stagedData or t.compressedData, uploadBytes);
    // t.gpuData = gpuPtr;
    // t.gpuBytes = uploadBytes;

    // Stub: just mark as hot
    t.gpuData = nullptr;  // placeholder
    t.gpuBytes = uploadBytes;
    t.state.store(ResidencyState::Hot);
    t.inFlightOps.fetch_sub(1);
}

void ElasticResidencyManager::ExecuteVramToRam(ElasticResidentTensor& t) {
    t.inFlightOps.fetch_add(1);

    if (!TryTransition(t.name, ResidencyState::Evicting, ResidencyState::WarmCompressed)) {
        t.inFlightOps.fetch_sub(1);
        return;
    }

    // TODO: actual GPU download or free
    // GpuBackend::Free(t.gpuData);
    t.gpuData = nullptr;
    ReleaseHot(t.gpuBytes);
    t.gpuBytes = 0;

    t.inFlightOps.fetch_sub(1);
}

void ElasticResidencyManager::ExecuteFreeStaged(ElasticResidentTensor& t) {
    if (t.stagedData) {
#ifdef _WIN32
        VirtualFree(t.stagedData, 0, MEM_RELEASE);
#else
        free(t.stagedData);
#endif
        ReleaseWarmStaged(t.stagedAllocated);
        t.stagedData = nullptr;
        t.stagedBytes = 0;
        t.stagedAllocated = 0;
    }
}

// ============================================================================
// Memory Accounting
// ============================================================================
bool ElasticResidencyManager::ReserveWarmCompressed(size_t bytes) {
    size_t current = warmCompressedUsed_.load();
    while (current + bytes <= config_.maxWarmCompressedBytes) {
        if (warmCompressedUsed_.compare_exchange_weak(current, current + bytes)) {
            return true;
        }
    }
    return false;
}

bool ElasticResidencyManager::ReserveWarmStaged(size_t bytes) {
    size_t current = warmStagedUsed_.load();
    while (current + bytes <= config_.maxWarmStagedBytes) {
        if (warmStagedUsed_.compare_exchange_weak(current, current + bytes)) {
            return true;
        }
    }
    return false;
}

bool ElasticResidencyManager::ReserveHot(size_t bytes) {
    size_t current = hotUsed_.load();
    while (current + bytes <= config_.maxHotBytes) {
        if (hotUsed_.compare_exchange_weak(current, current + bytes)) {
            return true;
        }
    }
    return false;
}

void ElasticResidencyManager::ReleaseWarmCompressed(size_t bytes) {
    warmCompressedUsed_.fetch_sub(bytes);
}
void ElasticResidencyManager::ReleaseWarmStaged(size_t bytes) {
    warmStagedUsed_.fetch_sub(bytes);
}
void ElasticResidencyManager::ReleaseHot(size_t bytes) {
    hotUsed_.fetch_sub(bytes);
}

// ============================================================================
// Helpers
// ============================================================================
std::shared_ptr<ElasticResidentTensor> ElasticResidencyManager::FindTensor(const std::string& name) {
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    auto it = tensors_.find(name);
    if (it != tensors_.end()) return it->second;
    return nullptr;
}

std::shared_ptr<const ElasticResidentTensor> ElasticResidencyManager::FindTensor(const std::string& name) const {
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    auto it = tensors_.find(name);
    if (it != tensors_.end()) return it->second;
    return nullptr;
}

void ElasticResidencyManager::EnqueueRequest(TransferRequest::Type type,
                                              const std::string& name,
                                              uint32_t priority) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    TransferRequest req;
    req.type = type;
    req.tensorName = name;
    req.priority = priority;
    req.enqueueTime = std::chrono::steady_clock::now();
    requestQueue_.push(req);
    queueCv_.notify_one();
}

// ============================================================================
// Telemetry Output
// ============================================================================
void ElasticResidencyManager::PrintTelemetry() const {
    printf("\n=== ElasticResidencyManager Telemetry ===\n");
    printf("NVMe read time:        %llu us\n", (unsigned long long)telemetry_.nvmeReadUs.load());
    printf("RAM stage time:        %llu us\n", (unsigned long long)telemetry_.ramStageUs.load());
    printf("RAM→VRAM upload time:  %llu us\n", (unsigned long long)telemetry_.ramToVramUs.load());
    printf("GPU wait time:         %llu us\n", (unsigned long long)telemetry_.gpuWaitUs.load());
    printf("GPU compute time:      %llu us\n", (unsigned long long)telemetry_.gpuComputeUs.load());
    printf("Prefetch hits:         %llu\n", (unsigned long long)telemetry_.prefetchHit.load());
    printf("Prefetch misses:       %llu\n", (unsigned long long)telemetry_.prefetchMiss.load());
    printf("VRAM eviction time:    %llu us\n", (unsigned long long)telemetry_.vramEvictionUs.load());
    printf("CPU fallback time:     %llu us\n", (unsigned long long)telemetry_.cpuFallbackUs.load());
    printf("State race blocks:     %llu\n", (unsigned long long)telemetry_.stateRaceBlocked.load());
    printf("Compute efficiency:    %.4f\n", telemetry_.ComputeEfficiency());
    printf("Memory: warmCompressed=%zu/%zu MB, warmStaged=%zu/%zu MB, hot=%zu/%zu MB\n",
           warmCompressedUsed_.load() / (1024*1024), config_.maxWarmCompressedBytes / (1024*1024),
           warmStagedUsed_.load() / (1024*1024), config_.maxWarmStagedBytes / (1024*1024),
           hotUsed_.load() / (1024*1024), config_.maxHotBytes / (1024*1024));
    printf("==========================================\n\n");
}

} // namespace Deep2
