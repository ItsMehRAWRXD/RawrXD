// ============================================================================
// ElasticResidencyManager.cpp
// VAL-051.7+ — Unified tensor residency implementation
// ============================================================================

#include "ElasticResidencyManager.hpp"
#include "lavapath/BatchD_UnifiedAsyncMove.hpp"
#include "lavapath/FreeTokenMicroZone.hpp"
#include "lavapath/FutureConsumerSpace.hpp"
#include "vwa/VwaPhysical.hpp"
#include "QuantKernelRegistry.hpp"
#include "ResidencyTrace.hpp"
#include "TelemetrySinks.hpp"
#include "StreamTransferCounters.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#include "VwaRangeAbi.hpp"
#include "VwaRangePopulate.hpp"
#include "QuantTypeTable.hpp"
namespace Deep2 {

namespace {
// Map Elastic TensorFormat → certified quant blockBytes (no second GGML table).
unsigned long BlockBytesForFormat(TensorFormat fmt) {
    uint32_t ggml = 0;
    switch (fmt) {
    case TensorFormat::FP32: ggml = 0; break;
    case TensorFormat::FP16: ggml = 1; break;
    case TensorFormat::Q4_0: ggml = 2; break;
    case TensorFormat::Q4_1: ggml = 3; break;
    case TensorFormat::Q5_0: ggml = 6; break;
    case TensorFormat::Q5_1: ggml = 7; break;
    case TensorFormat::Q8_0: ggml = 8; break;
    case TensorFormat::Q2_K: ggml = 10; break;
    case TensorFormat::Q3_K: ggml = 11; break;
    case TensorFormat::Q4_K: ggml = 12; break;
    case TensorFormat::Q5_K: ggml = 13; break;
    case TensorFormat::Q6_K: ggml = 14; break;
    default: return 0;
    }
    return static_cast<unsigned long>(QuantTypeBlockBytes(ggml));
}

// Host VirtualAlloc is not GPU DMA — B7 must not seal on this path.
std::atomic<uint64_t> g_vwaHostStagingHot{0};
std::atomic<uint64_t> g_vwaHotWithNullGpu{0};
} // namespace

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

    // Initialize Ghost Cache if enabled
    if (config_.useGhostCache) {
        ghostCache_ = std::make_unique<GhostCache>(config_.ghostCacheCapacity);
        printf("[ElasticResidencyManager] GhostCache enabled: capacity=%zu entries\n",
               config_.ghostCacheCapacity);
    }

    // Start scheduler thread
    schedulerThread_ = std::thread(&ElasticResidencyManager::SchedulerThreadBody, this);

    /* FreeToken micro-zones: fixed Hot sticks for 120B+ stream (never realloc). */
    {
        const char* ft = std::getenv("FREETOKEN_MICROZONE");
        if (!ft || ft[0] != '0') {
            size_t zb = FREETOKEN_ZONE_BYTES;
            if (config_.maxHotBytes && config_.maxHotBytes < zb * FREETOKEN_ZONE_COUNT)
                zb = config_.maxHotBytes / FREETOKEN_ZONE_COUNT;
            if (zb < (1ull << 20)) zb = (1ull << 20);
            freetoken::Init(zb, /*sticks=*/4); /* N-way >2 sticks rubbed */
            future::InitFromPhysicalPool();
            freetoken::EmitWitness(stderr);
            future::EmitLaw(stderr);
        }
    }

    printf("[ElasticResidencyManager] Initialized: warmCompressed=%zu MB, warmStaged=%zu MB, hot=%zu MB, lookahead=%u\n",
           config_.maxWarmCompressedBytes / (1024*1024),
           config_.maxWarmStagedBytes / (1024*1024),
           config_.maxHotBytes / (1024*1024),
           config_.prefetchLookahead);
    return true;
}

void ElasticResidencyManager::ApplyDynamicCaps(const ElasticResidencyConfig& caps) {
    // Keep used ≤ max; only publish fields that are dynamic budgets/lookahead.
    const size_t warmUsed = warmCompressedUsed_.load();
    const size_t stagedUsed = warmStagedUsed_.load();
    const size_t hotUsed = hotUsed_.load();
    if (caps.maxWarmCompressedBytes >= warmUsed)
        config_.maxWarmCompressedBytes = caps.maxWarmCompressedBytes;
    if (caps.maxWarmStagedBytes >= stagedUsed)
        config_.maxWarmStagedBytes = caps.maxWarmStagedBytes;
    if (caps.maxHotBytes >= hotUsed)
        config_.maxHotBytes = caps.maxHotBytes;
    config_.prefetchLookahead = caps.prefetchLookahead;
    if (caps.moeHotExpertCount)
        config_.moeHotExpertCount = caps.moeHotExpertCount;
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
    freetoken::Shutdown();
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
    const void* sourceData,
    uint32_t shardId)
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
    tensor->shardId = shardId;
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

void ElasticResidencyManager::SetPhysicalBackend(vwa::IPhysicalBackend* backend) {
    physicalBackend_ = backend;
}

bool ElasticResidencyManager::SetPlannedPlacement(const std::string& name,
                                                  int plannedGpu,
                                                  bool pinned) {
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    auto it = tensors_.find(name);
    if (it == tensors_.end() || !it->second) return false;
    it->second->plannedGpu = plannedGpu;
    it->second->policyPinned = pinned;
    return true;
}

std::vector<std::string> ElasticResidencyManager::ListTensorNames() const {
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    std::vector<std::string> out;
    out.reserve(tensors_.size());
    for (const auto& kv : tensors_)
        out.push_back(kv.first);
    return out;
}

int ElasticResidencyManager::GetPlannedGpu(const std::string& name) const {
    auto t = FindTensor(name);
    if (!t) return -2;
    return t->plannedGpu;
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
    (void)name;
}

// ============================================================================
// GhostCache Accounting Helpers
// ============================================================================
void ElasticResidencyManager::AccountGhostAccess(const std::string& name, uint32_t layerIndex) {
    if (!ghostCache_) return;
    // RecordHit returns true iff tensor was previously evicted (in ghost cache).
    // This is the single source of truth for hit/miss classification.
    bool wasGhostHit = ghostCache_->RecordHit(name, layerIndex);
    if (wasGhostHit) {
        telemetry_.ghostHits.fetch_add(1);
    } else {
        telemetry_.ghostMisses.fetch_add(1);
        // Establish ghost history so future reacquisitions become hits.
        ghostCache_->RecordEvict(name, layerIndex);
    }
}

// ============================================================================
// Cyclone Contract: AcquireTensor / ReleaseTensor
// ============================================================================
ElasticResidencyManager::AcquireStatus ElasticResidencyManager::AcquireTensor(
    const std::string& name,
    uint32_t priority,
    uint64_t deadlineTicks,
    ResidencyHandle& outHandle)
{
    auto t = FindTensor(name);
    if (!t) return AcquireStatus::NotFound;

    ResidencyState current = t->state.load();

    // Fast path: already Hot
    if (current == ResidencyState::Hot) {
        outHandle.id = t->layerIndex;
        outHandle.cpuPtr = t->compressedData;
        outHandle.gpuPtr = t->gpuData;
        outHandle.state = ResidencyState::Hot;
        outHandle.ready = true;
        t->lastUseSequence.fetch_add(1);
        return AcquireStatus::Ready;
    }

    // Fast path: WarmStaged (CPU-usable, can DMA)
    if (current == ResidencyState::WarmStaged) {
        outHandle.id = t->layerIndex;
        outHandle.cpuPtr = t->stagedData;
        outHandle.gpuPtr = nullptr;
        outHandle.state = ResidencyState::WarmStaged;
        outHandle.ready = true;
        t->lastUseSequence.fetch_add(1);
        return AcquireStatus::Ready;
    }

    // Fast path: WarmCompressed (CPU-usable quantized)
    if (current == ResidencyState::WarmCompressed) {
        outHandle.id = t->layerIndex;
        outHandle.cpuPtr = t->compressedData;
        outHandle.gpuPtr = nullptr;
        outHandle.state = ResidencyState::WarmCompressed;
        outHandle.ready = true;
        t->lastUseSequence.fetch_add(1);
        return AcquireStatus::Ready;
    }

    // Urgent path: priority == 0 means block until CPU-resident
    // For CPU inference, WarmCompressed (quantized) or WarmStaged (FP32) is sufficient.
    // Only push to VRAM if explicitly requested via deadlineTicks != 0.
    if (priority == 0) {
        auto start = std::chrono::steady_clock::now();

        // Stage synchronously: Cold → WarmCompressed
        if (current == ResidencyState::Cold) {
            ExecuteNvmeToRam(*t);
            current = t->state.load();
            // Cold load: classify as ghost hit (reacquire after eviction)
            // or ghost miss (first observation).
            AccountGhostAccess(t->name, t->layerIndex);
        }

        // If GPU path requested (deadlineTicks > 0), continue to Hot
        bool needVram = (deadlineTicks > 0);
        if (needVram) {
            if (current == ResidencyState::WarmCompressed && !config_.useQuantizedGpuPath) {
                ExecuteDequantStage(*t);
                current = t->state.load();
            }
            if (current == ResidencyState::WarmStaged || current == ResidencyState::WarmCompressed) {
                if (!ReserveHot(t->gpuBytes)) {
                    EvictLeastRecentlyUsed(t->gpuBytes);
                }
                ExecuteRamToVram(*t);
                current = t->state.load();
            }
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start).count();
        telemetry_.gpuWaitUs.fetch_add(elapsed);

        // Return appropriate handle based on final state
        if (current == ResidencyState::Hot) {
            outHandle.id = t->layerIndex;
            outHandle.cpuPtr = t->compressedData;
            outHandle.gpuPtr = t->gpuData;
            outHandle.state = ResidencyState::Hot;
            outHandle.ready = true;
            t->lastUseSequence.fetch_add(1);
            return AcquireStatus::Ready;
        }
        if (current == ResidencyState::WarmStaged) {
            outHandle.id = t->layerIndex;
            outHandle.cpuPtr = t->stagedData;
            outHandle.gpuPtr = nullptr;
            outHandle.state = ResidencyState::WarmStaged;
            outHandle.ready = true;
            t->lastUseSequence.fetch_add(1);
            return AcquireStatus::Ready;
        }
        if (current == ResidencyState::WarmCompressed) {
            outHandle.id = t->layerIndex;
            outHandle.cpuPtr = t->compressedData;
            outHandle.gpuPtr = nullptr;
            outHandle.state = ResidencyState::WarmCompressed;
            outHandle.ready = true;
            t->lastUseSequence.fetch_add(1);
            return AcquireStatus::Ready;
        }
        return AcquireStatus::Failed;
    }

    // Non-urgent: BATCH_D one async movement (not Nvme+Dequant+Ram as three).
    EnqueueUnifiedAsyncMove(name, priority);

    outHandle.ready = false;
    outHandle.state = ResidencyState::Cold;
    return AcquireStatus::Pending;
}

void ElasticResidencyManager::ReleaseTensor(const std::string& name) {
    auto t = FindTensor(name);
    if (!t) return;

    // Decrement implicit refcount; if zero and under pressure, evict
    // For now, just update LRU. Eviction is lazy.
    (void)t;

    // Periodic decay of ghost cache scores (every 64 releases)
    static std::atomic<uint64_t> releaseCounter{0};
    uint64_t cnt = releaseCounter.fetch_add(1);
    if (ghostCache_ && (cnt & 63) == 0) {
        ghostCache_->Decay();
    }
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
        StreamTransfer_RecordRead(t->compressedBytes ? t->compressedBytes : t->stagedBytes,
                                  /*cacheHit=*/true);
        return;  // Already hot or on its way
    }

    telemetry_.prefetchMiss.fetch_add(1);

    /* BATCH_D: single async path — Router/Expert priority rides on `targetLayer`. */
    EnqueueUnifiedAsyncMove(name, targetLayer);
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

void ElasticResidencyManager::PrefetchExperts(uint32_t layer,
                                              const uint32_t* expertIds,
                                              size_t expertCount) {
    if (!expertIds || expertCount == 0) return;
    /* B011 frame: router told us the working set — pay fetch only on miss.
     * Priority 0 = highest; UnifiedAsyncMove = one Cold→Hot path. */
    future::InitFromPhysicalPool();
    std::vector<std::string> toMove;
    {
        std::lock_guard<std::mutex> lock(tensorsMutex_);
        for (size_t i = 0; i < expertCount; ++i) {
            const uint32_t expertId = expertIds[i];
            future::Register(static_cast<uint16_t>(layer), /*op=*/2,
                             static_cast<uint8_t>(layer & 1u),
                             /*logicalBytes=*/1ull << 20,
                             static_cast<uint32_t>(layer + 1));
            for (auto& kv : tensors_) {
                auto& t = *kv.second;
                if (t.layerIndex != layer || t.expertIndex != expertId) continue;
                ResidencyState st = t.state.load();
                if (st == ResidencyState::Hot || st == ResidencyState::Uploading) {
                    telemetry_.prefetchHit.fetch_add(1);
                    future::NotePrefetchHit();
                    future::NoteConsumerHit();
                    continue;
                }
                telemetry_.prefetchMiss.fetch_add(1);
                future::NotePrefetchLate();
                future::NoteConsumerMiss();
                toMove.push_back(t.name);
            }
        }
    }
    for (const auto& name : toMove)
        EnqueueUnifiedAsyncMove(name, /*priority=*/0);
}

void ElasticResidencyManager::PredictLayerNeeds(uint32_t nextLayer,
                                                 const void* routerHiddenState,
                                                 size_t hiddenDim) {
    std::shared_ptr<IExpertPredictor> predictor;
    {
        std::lock_guard<std::mutex> lock(predictorMutex_);
        predictor = expertPredictor_;
    }
    if (!predictor || !routerHiddenState) {
        /* Dense / ownership handoff: raise priority for next layer tensors. */
        future::InitFromPhysicalPool();
        future::Register(static_cast<uint16_t>(nextLayer), /*op=*/3,
                         static_cast<uint8_t>(nextLayer & 1u),
                         1ull << 20, nextLayer + 1);
        std::vector<std::string> toMove;
        {
            std::lock_guard<std::mutex> lock(tensorsMutex_);
            for (auto& kv : tensors_) {
                auto& t = *kv.second;
                if (t.layerIndex != nextLayer) continue;
                ResidencyState st = t.state.load();
                if (st == ResidencyState::Hot || st == ResidencyState::Uploading) {
                    telemetry_.prefetchHit.fetch_add(1);
                    future::NotePrefetchHit();
                    continue;
                }
                telemetry_.prefetchMiss.fetch_add(1);
                future::NotePrefetchLate();
                toMove.push_back(t.name);
            }
        }
        for (const auto& name : toMove)
            EnqueueUnifiedAsyncMove(name, /*priority=*/0);
        return;
    }

    auto experts = predictor->PredictNextExperts(nextLayer, routerHiddenState, hiddenDim,
                                                   config_.moeHotExpertCount);
    if (!experts.empty())
        PrefetchExperts(nextLayer, experts.data(), experts.size());
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

    // Sort by composite score: LRU sequence + ghost reuse penalty
    // Lower score = better eviction candidate
    std::sort(candidates.begin(), candidates.end(),
              [this](ElasticResidentTensor* a, ElasticResidentTensor* b) {
                  uint64_t scoreA = a->lastUseSequence.load();
                  uint64_t scoreB = b->lastUseSequence.load();
                  if (ghostCache_) {
                      // Higher ghost score = more likely to be reused = worse victim
                      // Add penalty to LRU score: score += ghostScore * weight
                      uint32_t gA = ghostCache_->GetReuseScore(a->name);
                      uint32_t gB = ghostCache_->GetReuseScore(b->name);
                      scoreA += static_cast<uint64_t>(gA) * 1000000ULL;
                      scoreB += static_cast<uint64_t>(gB) * 1000000ULL;
                  }
                  return scoreA < scoreB;
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
            if (ghostCache_) ghostCache_->RecordEvict(t->name, t->layerIndex);
        } else if (s == ResidencyState::WarmStaged) {
            if (TryTransition(t->name, ResidencyState::WarmStaged, ResidencyState::WarmCompressed)) {
                ExecuteFreeStaged(*t);
            }
            freed += t->stagedAllocated;
            if (ghostCache_) ghostCache_->RecordEvict(t->name, t->layerIndex);
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
            if (ghostCache_) ghostCache_->RecordEvict(t->name, t->layerIndex);
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
            case TransferRequest::Type::UnifiedAsyncMove:
                ExecuteUnifiedAsyncMove(*t);
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

    auto freeCompressedFail = [&]() {
#ifdef _WIN32
        if (t.compressedData) VirtualFree(t.compressedData, 0, MEM_RELEASE);
#else
        if (t.compressedData) free(t.compressedData);
#endif
        t.compressedData = nullptr;
        t.compressedAllocated = 0;
        ReleaseWarmCompressed(allocSize);
        t.state.store(ResidencyState::Failed);
        t.inFlightOps.fetch_sub(1);
    };

    // Read from source (already-mapped GGUF data or resolved physical range).
    // LAW: zero-fill is forbidden (VWA_ELASTIC_ZERO_FILL=0).
    if (t.compressedData) {
        auto* ev = TraceBegin(0, t.layerIndex, t.expertIndex, t.compressedBytes, 0, 1); // COLD → RAM
        if (ev) {
            TraceSetDestination(ev, 1, reinterpret_cast<uint64_t>(t.compressedData), 0, 0, 0, 0);
        }

        if (t.sourceData) {
            // Mapped backing only — not a second resolver.
            const IoTransferId xfer = NoteNvmeRequest(t.compressedBytes, false);
            memcpy(t.compressedData, t.sourceData, t.compressedBytes);
            NoteNvmeConsumed(xfer, t.compressedBytes);
        } else if (physicalBackend_) {
            // Resolve whole-tensor span from audited RMV facts, then exact read.
            const unsigned long bb = BlockBytesForFormat(t.nativeFormat);
            VwaMountedPhysical mounted{};
            unsigned long vs = VwaPopulateMountedPhysicalFromRmvFacts(
                static_cast<unsigned __int64>(t.fileOffset),
                static_cast<unsigned __int64>(t.compressedBytes),
                bb ? bb : 1ul, // opaque blob: treat as 1-byte blocks if unknown
                t.shardId,
                static_cast<unsigned __int64>(t.generation.load()),
                /*fileBacked=*/true,
                mounted);
            if (vs != VWA_OK) {
                fprintf(stderr,
                    "[ElasticResidencyManager] FATAL: VwaPopulate failed '%s' code=%lu\n",
                    t.name.c_str(), vs);
                freeCompressedFail();
                return;
            }
            VwaBlockRange ask{};
            ask.firstBlock = 0;
            ask.blockCount = mounted.tensorByteSize / mounted.blockBytes;
            if (ask.blockCount == 0 ||
                (mounted.tensorByteSize % mounted.blockBytes) != 0) {
                // Non-integral geometry: fall back to single opaque span via backend
                // at registered absolute offset (still no zero-fill).
                ask.blockCount = 0;
            }
            VwaPhysicalRange span{};
            if (ask.blockCount) {
                vs = VwaResolveBlocks(&mounted, &ask, &span);
                if (vs != VWA_OK ||
                    span.absoluteFileOffset !=
                        static_cast<unsigned __int64>(t.fileOffset) ||
                    span.byteCount !=
                        static_cast<unsigned __int64>(t.compressedBytes)) {
                    fprintf(stderr,
                        "[ElasticResidencyManager] FATAL: VwaResolveBlocks "
                        "mismatch '%s' code=%lu\n",
                        t.name.c_str(), vs);
                    freeCompressedFail();
                    return;
                }
            } else {
                span.absoluteFileOffset =
                    static_cast<unsigned __int64>(t.fileOffset);
                span.byteCount =
                    static_cast<unsigned __int64>(t.compressedBytes);
                span.shardId = t.shardId;
            }

            const IoTransferId xfer = NoteNvmeRequest(t.compressedBytes, true);
            if (!physicalBackend_->Read(t.shardId,
                                        span.absoluteFileOffset,
                                        span.byteCount,
                                        t.compressedData)) {
                fprintf(stderr,
                    "[ElasticResidencyManager] FATAL: physical Read failed '%s' "
                    "shard=%u off=%llu bytes=%llu\n",
                    t.name.c_str(), t.shardId,
                    (unsigned long long)span.absoluteFileOffset,
                    (unsigned long long)span.byteCount);
                freeCompressedFail();
                return;
            }
            NoteNvmeConsumed(xfer, t.compressedBytes);
        } else {
            fprintf(stderr,
                "[ElasticResidencyManager] FATAL: tensor '%s' has no sourceData "
                "and no physicalBackend (fileOffset=%zu bytes=%zu) — zero-fill forbidden\n",
                t.name.c_str(), t.fileOffset, t.compressedBytes);
            freeCompressedFail();
            return;
        }

        if (ev) {
            TraceComplete(ev, 0, 0, 1);
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

    // Packed GPU path: keep quantized bytes; no whole-tensor FP32 expand.
    if (config_.useQuantizedGpuPath) {
        t.stagedData = nullptr;
        t.stagedBytes = 0;
        t.stagedAllocated = 0;
        t.stagedFormat = t.nativeFormat;
        t.inFlightOps.fetch_sub(1);
        return;
    }

    // Host path: stage opaque copy of compressed for DMA (not FP32 undigest).
    size_t stagedBytes = t.compressedBytes;
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
    t.stagedFormat = t.nativeFormat;
    if (t.stagedData && t.compressedData)
        memcpy(t.stagedData, t.compressedData, stagedBytes);
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

    const void* src = nullptr;
    size_t uploadBytes = 0;
    if (config_.useQuantizedGpuPath || !t.stagedData) {
        src = t.compressedData;
        uploadBytes = t.compressedBytes;
    } else {
        src = t.stagedData;
        uploadBytes = t.stagedBytes;
    }
    if (!src || uploadBytes == 0) {
        t.state.store(srcState);
        t.inFlightOps.fetch_sub(1);
        return;
    }

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

    // Host-side staging copy — NOT proven GPU DMA / vkCmdCopyBuffer.
    // B7 VWA_GPU_STAGE_001 must not PASS on this path (witness HOST_STAGING_HOT).
    // Real device upload binds later via Vulkan transfer; null-Hot remains forbidden.
#ifdef _WIN32
    t.gpuData = VirtualAlloc(nullptr, uploadBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    t.gpuData = aligned_alloc(config_.pageAlignment, uploadBytes);
#endif
    if (!t.gpuData) {
        g_vwaHotWithNullGpu.fetch_add(1, std::memory_order_relaxed);
        ReleaseHot(uploadBytes);
        t.state.store(srcState);
        t.inFlightOps.fetch_sub(1);
        return;
    }
    memcpy(t.gpuData, src, uploadBytes);
    t.gpuBytes = uploadBytes;
    if (!t.gpuData) {
        // Defense in depth: never publish Hot with null device object.
        g_vwaHotWithNullGpu.fetch_add(1, std::memory_order_relaxed);
        ReleaseHot(uploadBytes);
        t.state.store(srcState);
        t.inFlightOps.fetch_sub(1);
        return;
    }
    g_vwaHostStagingHot.fetch_add(1, std::memory_order_relaxed);
    t.state.store(ResidencyState::Hot);
    t.inFlightOps.fetch_sub(1);
}

void ElasticResidencyManager::ExecuteVramToRam(ElasticResidentTensor& t) {
    t.inFlightOps.fetch_add(1);

    if (!TryTransition(t.name, ResidencyState::Evicting, ResidencyState::WarmCompressed)) {
        t.inFlightOps.fetch_sub(1);
        return;
    }

    if (t.gpuData) {
#ifdef _WIN32
        VirtualFree(t.gpuData, 0, MEM_RELEASE);
#else
        free(t.gpuData);
#endif
        t.gpuData = nullptr;
    }
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
    // Saturate: unsigned fetch_sub underflow looks like "negative" used.
    size_t cur = warmCompressedUsed_.load();
    for (;;) {
        const size_t next = (bytes >= cur) ? 0u : (cur - bytes);
        if (warmCompressedUsed_.compare_exchange_weak(cur, next)) return;
    }
}
void ElasticResidencyManager::ReleaseWarmStaged(size_t bytes) {
    size_t cur = warmStagedUsed_.load();
    for (;;) {
        const size_t next = (bytes >= cur) ? 0u : (cur - bytes);
        if (warmStagedUsed_.compare_exchange_weak(cur, next)) return;
    }
}
void ElasticResidencyManager::ReleaseHot(size_t bytes) {
    size_t cur = hotUsed_.load();
    for (;;) {
        const size_t next = (bytes >= cur) ? 0u : (cur - bytes);
        if (hotUsed_.compare_exchange_weak(cur, next)) return;
    }
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

void ElasticResidencyManager::EnqueueUnifiedAsyncMove(const std::string& name,
                                                      uint32_t priority) {
    EnqueueRequest(TransferRequest::Type::UnifiedAsyncMove, name, priority);
}

void ElasticResidencyManager::ExecuteUnifiedAsyncMove(ElasticResidentTensor& t) {
    /* One scheduler hop: fuse Nvme→[Dequant]→RamToVram. VRAM size is not a
     * placement gate — readiness is what ownership transfer waits on. */
    ResidencyState st = t.state.load();
    if (st == ResidencyState::Hot || st == ResidencyState::Uploading) return;
    if (st == ResidencyState::Cold)
        ExecuteNvmeToRam(t);
    st = t.state.load();
    if (!config_.useQuantizedGpuPath && st == ResidencyState::WarmCompressed)
        ExecuteDequantStage(t);
    ExecuteRamToVram(t);
    /* PAST→FUTURE rebinding on the fixed FreeToken stick for this layer. */
    const uint32_t z = freetoken::PickZone(t.layerIndex & 1u);
    future::AdvanceOwnership(z, 0);
}

bool ElasticResidencyManager::WaitHotReady(const std::string& name,
                                           uint32_t timeoutMs) {
    auto t = FindTensor(name);
    if (!t) return false;
    if (t->state.load() == ResidencyState::Hot) return true;
    const auto t0 = std::chrono::steady_clock::now();
    const auto deadline = t0 + std::chrono::milliseconds(timeoutMs);
    std::unique_lock<std::mutex> lock(tensorsMutex_);
    while (t->state.load() != ResidencyState::Hot) {
        if (stateCv_.wait_until(lock, deadline) == std::cv_status::timeout) {
            const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::steady_clock::now() - t0)
                                .count();
            future::NoteStallNs((uint64_t)ns);
            return t->state.load() == ResidencyState::Hot;
        }
    }
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    if (ns > 0) future::NoteStallNs((uint64_t)ns);
    return true;
}

// ============================================================================
// Telemetry Output
// ============================================================================
double ElasticResidencyManager::PrefetchHitRatePct() const {
    const uint64_t h = telemetry_.prefetchHit.load();
    const uint64_t m = telemetry_.prefetchMiss.load();
    const uint64_t t = h + m;
    return t ? (100.0 * (double)h / (double)t) : 0.0;
}

void ElasticResidencyManager::PrintTelemetry() const {
    const double hitPct = PrefetchHitRatePct();
    printf("\n=== ElasticResidencyManager Telemetry ===\n");
    printf("NVMe read time:        %llu us\n", (unsigned long long)telemetry_.nvmeReadUs.load());
    printf("RAM stage time:        %llu us\n", (unsigned long long)telemetry_.ramStageUs.load());
    printf("RAM→VRAM upload time:  %llu us\n", (unsigned long long)telemetry_.ramToVramUs.load());
    printf("GPU wait time:         %llu us\n", (unsigned long long)telemetry_.gpuWaitUs.load());
    printf("GPU compute time:      %llu us\n", (unsigned long long)telemetry_.gpuComputeUs.load());
    printf("Prefetch hits:         %llu\n", (unsigned long long)telemetry_.prefetchHit.load());
    printf("Prefetch misses:       %llu\n", (unsigned long long)telemetry_.prefetchMiss.load());
    printf("Prefetch hit rate:     %.2f%%  (B011 ref ~%.2f%%)\n",
           hitPct, (double)BATCH_D_B011_HIT_RATE_REF_PCT);
    printf("VRAM eviction time:    %llu us\n", (unsigned long long)telemetry_.vramEvictionUs.load());
    printf("CPU fallback time:     %llu us\n", (unsigned long long)telemetry_.cpuFallbackUs.load());
    printf("State race blocks:     %llu\n", (unsigned long long)telemetry_.stateRaceBlocked.load());
    printf("Compute efficiency:    %.4f\n", telemetry_.ComputeEfficiency());
    printf("B011_FETCH_COST_FRAME  hit=%.2f%%  io_ref~%.1f%%  map_ref~%.1f%%  "
           "metric=fetch_not_fit\n",
           hitPct,
           (double)BATCH_D_B011_IO_REDUCTION_REF_PCT,
           (double)BATCH_D_B011_MAP_REDUCTION_REF_PCT);
    freetoken::EmitWitness(stdout);
    printf("Memory: warmCompressed=%zu/%zu MB, warmStaged=%zu/%zu MB, hot=%zu/%zu MB\n",
           warmCompressedUsed_.load() / (1024*1024), config_.maxWarmCompressedBytes / (1024*1024),
           warmStagedUsed_.load() / (1024*1024), config_.maxWarmStagedBytes / (1024*1024),
           hotUsed_.load() / (1024*1024), config_.maxHotBytes / (1024*1024));
    printf("==========================================\n\n");
}

} // namespace Deep2
