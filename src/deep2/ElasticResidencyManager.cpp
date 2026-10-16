// ============================================================================
// ElasticResidencyManager.cpp
// VAL-051.7+ � Unified tensor residency implementation
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
// Map Elastic TensorFormat ? certified quant blockBytes (no second GGML table).
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

// Host VirtualAlloc is not GPU DMA � B7 must not seal on this path.
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

    /* DualStick/Vulkan: weights already device-resident. Scheduler + GhostCache
     * raced FreeToken/FutureConsumer and AV'd at generate (STACK elastic=1).
     * Passiveive mode = registry + hit accounting only. */
    if (config_.suppressHostVramMoves) {
        ghostCache_.reset();
        printf("[ElasticResidencyManager] PASSIVE vulkan/DualStick "
               "(no scheduler, no GhostCache)\n");
    } else {
        if (config_.useGhostCache) {
            ghostCache_ = std::make_unique<GhostCache>(config_.ghostCacheCapacity);
            printf("[ElasticResidencyManager] GhostCache enabled: capacity=%zu entries\n",
                   config_.ghostCacheCapacity);
        }
        schedulerThread_ = std::thread(&ElasticResidencyManager::SchedulerThreadBody, this);
    }

    /* FreeToken micro-zones: fixed Hot sticks for 120B+ stream (never realloc). */
    {
        const char* ft = std::getenv("FREETOKEN_MICROZONE");
        if ((!ft || ft[0] != '0') && !freetoken::Pool().live) {
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
    // Keep used = max; only publish fields that are dynamic budgets/lookahead.
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
    std::lock_guard<std::mutex> lock(tensorsMutex_);
    auto t = FindTensor(name);
    if (!t) return;

    // Release CPU-side staging buffer and reclaim RAM. The native quantized
    // compressedData is retained so the tensor can be re-staged without a
    // NVMe reload. State returns to WarmCompressed so the next AcquireForCpu
    // with a dequantized format re-stages rather than returning a dangling ptr.
    if (t->stagedData) {
#ifdef _WIN32
        VirtualFree(t->stagedData, 0, MEM_RELEASE);
#else
        free(t->stagedData);
#endif
        ReleaseWarmStaged(t->stagedAllocated);
        t->stagedData = nullptr;
        t->stagedBytes = 0;
        t->stagedAllocated = 0;
        t->stagedFormat = TensorFormat::Unknown;
        t->state.store(ResidencyState::WarmCompressed);
    }

    telemetry_.cpuReleaseCount.fetch_add(1, std::memory_order_relaxed);
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

    /* Vulkan owns compute: refuse host staging Acquire (cyclone OnTensorUsed). */
    if (config_.suppressHostVramMoves)
        return AcquireStatus::NotFound;

    ResidencyState current = t->state.load();

    // Fast path: already Hot
    // G04 � hand-out is atomic (state re-check + pin + pointer capture) so a
    // concurrent eviction cannot reclaim the mapping in between.
    if (current == ResidencyState::Hot) {
        if (TakeLeaseAtomic(t, ResidencyState::Hot, outHandle))
            return AcquireStatus::Ready;
        current = t->state.load();  // lost the race; fall through to staging
    }

    // Fast path: WarmStaged (CPU-usable, can DMA)
    if (current == ResidencyState::WarmStaged) {
        if (TakeLeaseAtomic(t, ResidencyState::WarmStaged, outHandle))
            return AcquireStatus::Ready;
        current = t->state.load();
    }

    // Fast path: WarmCompressed (CPU-usable quantized)
    if (current == ResidencyState::WarmCompressed) {
        if (TakeLeaseAtomic(t, ResidencyState::WarmCompressed, outHandle))
            return AcquireStatus::Ready;
    }

    // Urgent path: priority == 0 means block until CPU-resident
    // For CPU inference, WarmCompressed (quantized) or WarmStaged (FP32) is sufficient.
    // Only push to VRAM if explicitly requested via deadlineTicks != 0.
    if (priority == 0) {
        auto start = std::chrono::steady_clock::now();

        // Stage synchronously: Cold ? WarmCompressed
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

        // Return appropriate handle based on final state.
        // G04 � the same atomic hand-out as the fast paths: the staging steps
        // above may have been interleaved with an eviction, so the final state
        // is re-validated and pinned before any pointer leaves this function.
        if (current == ResidencyState::Hot) {
            if (TakeLeaseAtomic(t, ResidencyState::Hot, outHandle))
                return AcquireStatus::Ready;
            current = t->state.load();
        }
        if (current == ResidencyState::WarmStaged) {
            if (TakeLeaseAtomic(t, ResidencyState::WarmStaged, outHandle))
                return AcquireStatus::Ready;
            current = t->state.load();
        }
        if (current == ResidencyState::WarmCompressed) {
            if (TakeLeaseAtomic(t, ResidencyState::WarmCompressed, outHandle))
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
// G04 � Generation leases (concurrent-safe residency)
// ============================================================================
//
// A lease binds a caller's handle to the residency mapping (generation) that
// was live when the handle was issued. Two distinct hazards are closed here:
//
//   1. Use-after-evict on the caller side: if the tensor was evicted and
//      re-mapped between acquire and release, the handle's generation no longer
//      matches the live mapping. Releasing such a handle would decrement pin
//      state belonging to a *different* mapping, letting a later eviction free
//      memory the caller is still reading. The release is refused instead and
//      counted, so a stale lease is evidence of a scheduling bug, never a
//      silent state corruption.
//
//   2. Evicting a pinned mapping: leases pin the current generation, so
//      EvictLeastRecentlyUsed skips tensors with live leases (see the eviction
//      gate). A tensor that cannot be evicted is not a deadlock: the caller
//      holds it for a bounded compute window and releases it.
//
// Generation rules (RAWRXD_G04_GEN_001):
//   * A new generation is assigned whenever a physical mapping is retired and
//     recreated � never recycled for the same tensor identity.
//   * Ordinary cache hits do NOT advance the generation, so a handle stays
//     valid for the whole of a normal reuse window.
//   * The counter is advanced by AdvanceGeneration(), which saturates at
//     UINT32_MAX rather than wrapping to 0. A wrap would silently revalidate a
//     handle that was issued long after the first mapping was retired, so the
//     saturation is the overflow guard.
//
// No PASS without the counter reconciliation: leaseCount must return to zero
// after every caller releases, and a rejected lease must never leave the
// counter elevated (which would pin the tensor forever and wedge residency).

// Advance a tensor's generation, saturating at UINT32_MAX so the counter can
// never wrap back to a value an older handle already used.
void ElasticResidencyManager::AdvanceGeneration(ElasticResidentTensor& t) {
    uint32_t g = t.generation.load();
    for (;;) {
        if (g == UINT32_MAX) {
            // Saturated: all leases on any earlier mapping are already stale,
            // so refusing to advance is safe and revalidation stays impossible.
            return;
        }
        if (t.generation.compare_exchange_weak(g, g + 1)) return;
    }
}

bool ElasticResidencyManager::ValidateLease(const std::string& name,
                                            uint32_t generation) const {
    auto t = FindTensor(name);
    if (!t) return false;

    // Generation is incremented on every eviction/re-map, so a matching
    // generation is exactly "the mapping the caller acquired is still live".
    if (t->generation.load() != generation) return false;

    // The lease-pin record must also agree: leases held are attributed to a
    // single generation, so a mismatch means the counter belongs to a mapping
    // that no longer exists.
    return t->leasedGeneration.load() == generation;
}

bool ElasticResidencyManager::IsLeasePinned(const std::string& name) const {
    auto t = FindTensor(name);
    if (!t) return false;

    const uint32_t live = t->generation.load();
    const uint32_t leased = t->leasedGeneration.load();
    if (leased != live) return false;  // stale pins belong to a dead mapping

    return t->leaseCount.load() > 0;
}

bool ElasticResidencyManager::ReleaseTensorLease(const std::string& name,
                                                 uint32_t generation) {
    auto t = FindTensor(name);
    if (!t) return false;

    const uint32_t live = t->generation.load();
    if (live != generation) {
        // Stale lease: the mapping this handle named is gone. Refuse the
        // release and record it � the counter must NOT be decremented.
        t->staleLeaseRejected.fetch_add(1);
        telemetry_.staleLeaseRejected.fetch_add(1);
        if (cbOnStaleLease_) cbOnStaleLease_();
        return false;
    }

    // Decrement the pin for the live mapping, saturating at zero so a
    // double-release can never underflow the counter into "pinned forever".
    uint32_t cur = t->leaseCount.load();
    for (;;) {
        if (cur == 0) {
            // No live pin to release for this generation. Not an error for a
            // caller that already released via the plain path, but it must not
            // be able to make the counter negative.
            t->staleLeaseRejected.fetch_add(1);
            telemetry_.staleLeaseRejected.fetch_add(1);
            return false;
        }
        if (t->leaseCount.compare_exchange_weak(cur, cur - 1)) return true;
    }
}

void ElasticResidencyManager::PrefetchForCpu(const std::string& name,
                                              uint32_t targetLayer) {
    auto t = FindTensor(name);
    if (!t) return;
    t->predictedNextLayer.store(targetLayer, std::memory_order_relaxed);
    const ResidencyState current = t->state.load(std::memory_order_acquire);
    if (current == ResidencyState::Hot || current == ResidencyState::WarmStaged ||
        current == ResidencyState::WarmCompressed ||
        current == ResidencyState::StreamingIn) {
        telemetry_.prefetchHit.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (current != ResidencyState::Cold) return;
    telemetry_.prefetchMiss.fetch_add(1, std::memory_order_relaxed);
    EnqueueRequest(TransferRequest::Type::NvmeToRam, name, targetLayer);
}

// ============================================================================
// Async Prefetch (GPU path)
// ============================================================================
void ElasticResidencyManager::PrefetchToGpu(const std::string& name, uint32_t targetLayer) {
    auto t = FindTensor(name);
    if (!t) return;

    t->predictedNextLayer.store(targetLayer);

    ResidencyState current = t->state.load();
    if (current == ResidencyState::Hot || current == ResidencyState::Uploading ||
        config_.suppressHostVramMoves) {
        telemetry_.prefetchHit.fetch_add(1);
        StreamTransfer_RecordRead(t->compressedBytes ? t->compressedBytes : t->stagedBytes,
                                  /*cacheHit=*/true);
        return;  // Already hot, on its way, or Vulkan owns VRAM
    }

    telemetry_.prefetchMiss.fetch_add(1);

    /* BATCH_D: single async path � Router/Expert priority rides on `targetLayer`.
     * RAWRXD_TICKLATCH_001: admitted only after warm-up has accepted a
     * tick-driven load; a pre-latch request is deferred and counted, never
     * staged. */
    EnqueueLatchGatedPrefetch(name, targetLayer);
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

    // Prefetch missed � synchronous fallback
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
    /* B011 frame: router told us the working set � pay fetch only on miss.
     * Priority 0 = highest; UnifiedAsyncMove = one Cold?Hot path. */
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
        EnqueueLatchGatedPrefetch(name, /*priority=*/0);
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
        if (config_.suppressHostVramMoves) {
            /* Vulkan DualStick: weights already device-resident; hit-only. */
            std::lock_guard<std::mutex> lock(tensorsMutex_);
            for (auto& kv : tensors_) {
                if (kv.second->layerIndex != nextLayer) continue;
                telemetry_.prefetchHit.fetch_add(1);
                future::NotePrefetchHit();
            }
            return;
        }
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
            EnqueueLatchGatedPrefetch(name, /*priority=*/0);
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
    // G04 — the victim score is a SNAPSHOT taken once, under the lock, and the
    // sort compares only those immutable values.
    //
    // The previous implementation read `t->lastUseSequence` (a live atomic that
    // concurrent acquirers keep incrementing) and called the stateful GhostCache
    // lookup from INSIDE the comparator. Because that state changes between two
    // invocations of the comparator, the relation was not a strict weak
    // ordering: comp(a, b) and comp(b, a) could both be true at once. std::sort
    // is only defined for a strict weak ordering, and with a non-conforming one
    // std::_Insertion_sort_unchecked walks `*--_Prev` off the FRONT of the
    // range, reading one element before the buffer — an out-of-bounds read on
    // the candidate vector (AddressSanitizer: heap-buffer-overflow READ of size
    // 8, 8 bytes before the vector's allocation). Snapshotting removes the
    // dependence on mutable state entirely, which also means the comparator
    // takes no lock and cannot invert the lock order.
    struct EvictionCandidate {
        ElasticResidentTensor* tensor;
        uint64_t score;
    };

    std::vector<EvictionCandidate> candidates;
    size_t pinnedCount = 0;
    {
        std::lock_guard<std::mutex> lock(tensorsMutex_);
        for (auto& kv : tensors_) {
            auto& t = *kv.second;
            const ResidencyState s = t.state.load();
            if (s == ResidencyState::Hot || s == ResidencyState::WarmStaged ||
                s == ResidencyState::WarmCompressed) {
                // G04 — fence-safe eviction. A tensor with a live generation
                // lease is pinned by a caller reading it RIGHT NOW; a tensor
                // with an in-flight transfer owns a buffer that the transfer
                // thread is writing. Neither may be freed, and neither is
                // advertised as available capacity.
                const bool leasePinned =
                    (t.leasedGeneration.load() == t.generation.load()) &&
                    (t.leaseCount.load() > 0);
                const bool transferInFlight = (t.inFlightOps.load() > 0);
                if (leasePinned || transferInFlight) {
                    telemetry_.evictionLeaseSkips.fetch_add(1, std::memory_order_relaxed);
                    pinnedCount++;
                    continue;
                }

                uint64_t score = t.lastUseSequence.load();
                if (ghostCache_) {
                    // Higher ghost score = more likely to be reused = worse
                    // victim. Read on this pass only; the sorted order then
                    // reflects a single, self-consistent snapshot.
                    const uint32_t g = ghostCache_->GetReuseScore(t.name);
                    score += static_cast<uint64_t>(g) * 1000000ULL;
                }
                candidates.push_back({&t, score});
            }
        }
    }

    // Strict weak ordering over immutable snapshot scores.
    std::sort(candidates.begin(), candidates.end(),
              [](const EvictionCandidate& a, const EvictionCandidate& b) {
                  if (a.score != b.score) return a.score < b.score;
                  // Tie-break on a stable identity so the comparator is a total
                  // order even when two snapshots happen to be equal.
                  return a.tensor < b.tensor;
              });

    size_t freed = 0;
    {
        std::lock_guard<std::mutex> lock(tensorsMutex_);
        for (const auto& c : candidates) {
            if (freed >= bytesNeeded) break;
            ElasticResidentTensor* t = c.tensor;

            // G04 — re-validate the pin in the SAME critical section as the
            // free. The scan above and this loop are separate critical
            // sections, so a worker can legitimately acquire a lease on a
            // candidate in between. Freeing it would hand out a pointer to
            // reclaimed memory — the exact defect this gate exists to remove.
            const bool leasePinned =
                (t->leasedGeneration.load() == t->generation.load()) &&
                (t->leaseCount.load() > 0);
            const bool transferInFlight = (t->inFlightOps.load() > 0);
            if (leasePinned || transferInFlight) {
                telemetry_.evictionLeaseSkips.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            const ResidencyState s = t->state.load();
            if (s == ResidencyState::Hot) {
                auto t0 = std::chrono::steady_clock::now();
                if (TryTransitionLocked(*t, ResidencyState::Hot, ResidencyState::Evicting)) {
                    EnqueueRequest(TransferRequest::Type::VramToRam, t->name, 100);
                }
                auto t1 = std::chrono::steady_clock::now();
                telemetry_.vramEvictionUs.fetch_add(
                    std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
                freed += t->gpuBytes;
                // The device->host path is asynchronous; the generation is
                // advanced here so a caller that already read the VRAM mapping
                // cannot keep using it after the eviction is scheduled.
                // Saturating (never wraps back to 0): a wrap would revalidate
                // handles issued against the very first mapping.
                AdvanceGeneration(*t);
                t->leasedGeneration.store(t->generation.load());
                if (ghostCache_) ghostCache_->RecordEvict(t->name, t->layerIndex);
            } else if (s == ResidencyState::WarmStaged) {
                if (TryTransitionLocked(*t, ResidencyState::WarmStaged,
                                        ResidencyState::WarmCompressed)) {
                    freed += t->stagedAllocated;
                    ExecuteFreeStaged(*t);
                } else {
                    continue;
                }
                AdvanceGeneration(*t);
                t->leasedGeneration.store(t->generation.load());
                if (ghostCache_) ghostCache_->RecordEvict(t->name, t->layerIndex);
            } else if (s == ResidencyState::WarmCompressed) {
                if (TryTransitionLocked(*t, ResidencyState::WarmCompressed,
                                        ResidencyState::Cold)) {
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
                    freed += t->compressedBytes;
                } else {
                    continue;
                }
                // G04 — the mapping is gone. Advance the generation so every
                // lease handed out against the previous mapping becomes stale,
                // and re-anchor the pin counter so a late release from the old
                // generation is refused instead of corrupting the new one.
                AdvanceGeneration(*t);
                t->leasedGeneration.store(t->generation.load());
                if (ghostCache_) ghostCache_->RecordEvict(t->name, t->layerIndex);
            }
        }
    }

    // G04 / RAWRXD_EVICT_LIVELOCK_001 — the free still did not satisfy the
    // request and the only remaining residents are lease-pinned or mid-transfer.
    // This is recorded as a DEFERRED eviction, never retried in a loop and
    // never resolved by freeing a pinned mapping. Callers re-check their
    // reservation and fail closed, so a fully-pinned working set is reported as
    // a hard error instead of livelocking or silently freeing live data.
    if (freed < bytesNeeded && pinnedCount > 0) {
        telemetry_.evictionsDeferred.fetch_add(1, std::memory_order_relaxed);
        // The counter increments on EVERY deferred eviction so the evidence is
        // complete; the human-readable line is emitted once per process so a
        // long run cannot drown its own log in the same diagnostic.
        static std::atomic<bool> reported{false};
        if (!reported.exchange(true)) {
            fprintf(stderr,
                    "[ElasticResidencyManager] EVICTION DEFERRED: need=%zu freed=%zu, "
                    "but %zu resident tensor(s) are lease-pinned or have in-flight "
                    "transfers (skips=%llu). No pinned mapping will be freed - the "
                    "caller's reservation fails closed.\n",
                    bytesNeeded, freed, pinnedCount,
                    (unsigned long long)telemetry_.evictionLeaseSkips.load());
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

// G04 � lock-free CAS for callers that already hold tensorsMutex_. Kept
// deliberately parallel to TryTransition (same telemetry, same notification) so
// the locked and unlocked paths cannot drift apart in observable behaviour.
bool ElasticResidencyManager::TryTransitionLocked(ElasticResidentTensor& t,
                                                  ResidencyState expected,
                                                  ResidencyState desired) {
    ResidencyState current = expected;
    if (!t.state.compare_exchange_strong(current, desired)) {
        telemetry_.stateRaceBlocked.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    // stateCv_ is guarded by its own mutex acquisition inside wait_pred, not by
    // tensorsMutex_, so notifying here is legal while tensorsMutex_ is held by
    // this call's caller.
    stateCv_.notify_all();
    return true;
}

// G04 � atomic lease hand-out. Everything a caller needs from a handle (the
// buffer pointers, the residency state and the generation pin) is captured in
// one critical section, so an eviction cannot interleave between the check and
// the hand-out. This is the counterpart to the locked eviction free above; the
// pair is what makes the generation lease sound under real concurrency.
bool ElasticResidencyManager::TakeLeaseAtomic(
    const std::shared_ptr<ElasticResidentTensor>& t,
    ResidencyState expected,
    ResidencyHandle& outHandle)
{
    if (!t) return false;

    std::lock_guard<std::mutex> lock(tensorsMutex_);

    // Re-validate under the lock: the caller loaded `expected` before a
    // concurrent eviction may have reclaimed the mapping.
    if (t->state.load() != expected) return false;

    const uint32_t leaseGen = t->generation.load();

    outHandle.id = t->layerIndex;
    outHandle.state = expected;
    outHandle.generation = leaseGen;
    outHandle.ready = true;

    // Buffer pointers are only valid for the residency tiers that actually hold
    // a usable buffer; captured in the same critical section as the state check.
    switch (expected) {
        case ResidencyState::Hot:
            outHandle.cpuPtr = t->compressedData;
            outHandle.gpuPtr = t->gpuData;
            break;
        case ResidencyState::WarmStaged:
            outHandle.cpuPtr = t->stagedData;
            outHandle.gpuPtr = nullptr;
            break;
        case ResidencyState::WarmCompressed:
            outHandle.cpuPtr = t->compressedData;
            outHandle.gpuPtr = nullptr;
            break;
        default:
            outHandle.ready = false;
            return false;
    }

    // Pin the live mapping. Eviction's candidate scan observes this under the
    // same mutex, so a pinned tensor is never selected as a victim.
    t->leasedGeneration.store(leaseGen);
    t->leaseCount.fetch_add(1, std::memory_order_relaxed);
    t->lastUseSequence.fetch_add(1, std::memory_order_relaxed);
    telemetry_.leasePinsIssued.fetch_add(1, std::memory_order_relaxed);

    return true;
}

// ============================================================================
// Transfer Implementations
// ============================================================================
void ElasticResidencyManager::ExecuteNvmeToRam(ElasticResidentTensor& t) {
    // Mark in-flight
    t.inFlightOps.fetch_add(1);

    // Transition: Cold ? StreamingIn
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
        auto* ev = TraceBegin(0, t.layerIndex, t.expertIndex, t.compressedBytes, 0, 1); // COLD ? RAM
        if (ev) {
            TraceSetDestination(ev, 1, reinterpret_cast<uint64_t>(t.compressedData), 0, 0, 0, 0);
        }

        if (t.sourceData) {
            // Mapped backing only � not a second resolver.
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
                "and no physicalBackend (fileOffset=%zu bytes=%zu) � zero-fill forbidden\n",
                t.name.c_str(), t.fileOffset, t.compressedBytes);
            freeCompressedFail();
            return;
        }

        if (ev) {
            TraceComplete(ev, 0, 0, 1);
        }
    }

    // Transition: StreamingIn ? WarmCompressed
    t.state.store(ResidencyState::WarmCompressed);
    t.inFlightOps.fetch_sub(1);

    // RAWRXD_TICKLATCH_001 � the ONLY place the latch is set true: an NVMe?RAM
    // load has genuinely completed. Everything before this point is a scheduled
    // or failed transfer, which must not open the prefetch gate.
    tickDrivenWarmupAccepted_ = true;
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

    // Host-side staging copy � NOT proven GPU DMA / vkCmdCopyBuffer.
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
    /* RAWRXD_RENT_PIN_001 � bounded admission; see ReserveHot. */
    constexpr int kMaxCasRetries = 64;
    size_t current = warmCompressedUsed_.load();
    for (int i = 0; i < kMaxCasRetries; ++i) {
        if (current + bytes > config_.maxWarmCompressedBytes) return false;
        if (warmCompressedUsed_.compare_exchange_weak(current, current + bytes)) {
            return true;
        }
    }
    return false;
}

bool ElasticResidencyManager::ReserveWarmStaged(size_t bytes) {
    /* RAWRXD_RENT_PIN_001 � bounded admission; see ReserveHot. */
    constexpr int kMaxCasRetries = 64;
    size_t current = warmStagedUsed_.load();
    for (int i = 0; i < kMaxCasRetries; ++i) {
        if (current + bytes > config_.maxWarmStagedBytes) return false;
        if (warmStagedUsed_.compare_exchange_weak(current, current + bytes)) {
            return true;
        }
    }
    return false;
}
bool ElasticResidencyManager::ReserveHot(size_t bytes) {
    /* RAWRXD_RENT_PIN_001 � bounded admission. The retry loop exists only to
     * absorb a losing compare_exchange, which is a handful of iterations under
     * contention; it is NOT a wait on in-flight transfers and it never touches
     * memory. When the tier is full, the function returns false immediately so
     * the caller can fail closed or attempt pin-aware eviction, instead of
     * spinning until a concurrent frees a slot. */
    constexpr int kMaxCasRetries = 64;
    size_t current = hotUsed_.load();
    for (int i = 0; i < kMaxCasRetries; ++i) {
        if (current + bytes > config_.maxHotBytes) return false;
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

bool ElasticResidencyManager::EnqueueLatchGatedPrefetch(const std::string& name,
                                                        uint32_t priority) {
    /* RAWRXD_TICKLATCH_001 � prefetch enqueue is admitted only after the
     * warm-up sink has proven it accepts tick-driven loads (one completed
     * NVMe?RAM). Before the latch opens, the request is DEFERRED and counted;
     * it is never allowed to enter the staging path. */
    if (!tickDrivenWarmupAccepted_) {
        telemetry_.prefetchDeferredBeforeWarmup.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    telemetry_.prefetchRequests.fetch_add(1, std::memory_order_relaxed);
    EnqueueRequest(TransferRequest::Type::UnifiedAsyncMove, name, priority);
    return true;
}


void ElasticResidencyManager::ExecuteUnifiedAsyncMove(ElasticResidentTensor& t) {
    /* One scheduler hop: fuse Nvme?[Dequant]?RamToVram. VRAM size is not a
     * placement gate � readiness is what ownership transfer waits on. */
    ResidencyState st = t.state.load();
    if (st == ResidencyState::Hot || st == ResidencyState::Uploading) return;
    if (st == ResidencyState::Cold)
        ExecuteNvmeToRam(t);
    st = t.state.load();
    if (!config_.useQuantizedGpuPath && st == ResidencyState::WarmCompressed)
        ExecuteDequantStage(t);
    ExecuteRamToVram(t);
    /* PAST?FUTURE rebinding on the fixed FreeToken stick for this layer. */
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
    printf("RAM?VRAM upload time:  %llu us\n", (unsigned long long)telemetry_.ramToVramUs.load());
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
    /* G04 � concurrent-safe residency receipts. lease_pins_issued and
     * stale_lease_rejected must reconcile: every pin issued by AcquireTensor is
     * released exactly once, and any rejection is a detected stale lease rather
     * than a silent pin leak. eviction_lease_skips / evictions_deferred show the
     * fence-safe path refusing to free live mappings. */
    printf("G04 lease pins issued:  %llu\n", (unsigned long long)telemetry_.leasePinsIssued.load());
    printf("G04 stale leases rej:   %llu\n", (unsigned long long)telemetry_.staleLeaseRejected.load());
    printf("G04 evict lease skips:  %llu\n", (unsigned long long)telemetry_.evictionLeaseSkips.load());
    printf("G04 evictions deferred: %llu\n", (unsigned long long)telemetry_.evictionsDeferred.load());
    /* RAWRXD_TICKLATCH_001 � the warm-up gate. prefetch_deferred_before_warmup
     * must be zero once tickDrivenWarmupAccepted() is true, otherwise a prefetch
     * was admitted through the staging path without a completed NVMe?RAM. */
    printf("RAWRXD_TICKLATCH_001 warmup_accepted=%d prefetch_requests=%llu "
           "prefetch_deferred_before_warmup=%llu\n",
           TickDrivenWarmupAccepted() ? 1 : 0,
           (unsigned long long)telemetry_.prefetchRequests.load(),
           (unsigned long long)telemetry_.prefetchDeferredBeforeWarmup.load());
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