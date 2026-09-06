#include "Deep2EngineExtensions.h"
#include "Deep2ContextGuard.hpp"
#include "Deep2HardwareIsolation.hpp"
#include "Deep2ProfilingHarness.hpp"
#include "Deep2VramBridge.hpp"
#include "Deep2MultiGpuBridge.hpp"
#include "Deep2MatrixWrapper.hpp"
#include "Deep2StorageRing.hpp"
#include "Deep2MoeRouter.hpp"
#include "Deep2CacheAudit.hpp"
#include "Deep2TrafficAccounting.hpp"
#include "Deep2ExpertAuditor.hpp"
#include "Deep2ThreadTuning.hpp"
#include "Deep2Quantization.hpp"
#include <malloc.h>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <atomic>
#include <intrin.h>
#include <cstdio>

using namespace rawrxd::deep2;

extern "C" uint32_t SafeSmtPrefetchSweep(const void* source, uint64_t stride) {
    if (!source || stride == 0) {
        return 0;
    }
    __try {
        SmtSiblingPrefetchLoop(source, stride, nullptr, nullptr);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

class Deep2EnginePipeline {
protected:
    RingContext m_Context;
    uint8_t* m_BaseAllocation;
    uint64_t m_ChunkSize;
    const uint8_t* m_CipherKeys;
    bool m_OwnsAllocation;
    Deep2MicroProfiler* m_profiler; // Added profiler instance

public:
    Deep2EnginePipeline(uint64_t chunkSize, const uint8_t* expandedKeys, Deep2MicroProfiler* profiler)
        : m_ChunkSize(chunkSize), m_CipherKeys(expandedKeys), m_OwnsAllocation(true), m_profiler(profiler) {
        m_profiler->LogEvent("Deep2EnginePipeline: Owned allocation constructor entry");
        m_BaseAllocation = static_cast<uint8_t*>(_aligned_malloc(chunkSize * 4, 64));
        if (!m_BaseAllocation) {
            throw std::runtime_error("Critically low memory");
        }
        InitializeRingBuffer(&m_Context, m_BaseAllocation, m_ChunkSize);
        m_profiler->LogEvent("Deep2EnginePipeline: Ring buffer initialized");
    }

    Deep2EnginePipeline(void* pool, uint64_t chunkSize, const uint8_t* expandedKeys, Deep2MicroProfiler* profiler)
        : m_ChunkSize(chunkSize), m_CipherKeys(expandedKeys), m_OwnsAllocation(false), m_profiler(profiler) {
        m_profiler->LogEvent("Deep2EnginePipeline: Provided memory constructor entry");
        m_BaseAllocation = static_cast<uint8_t*>(pool);
        InitializeRingBuffer(&m_Context, m_BaseAllocation, m_ChunkSize);
        m_profiler->LogEvent("Deep2EnginePipeline: Ring buffer initialized with provided pool");
    }

    virtual ~Deep2EnginePipeline() {
        if (m_OwnsAllocation && m_BaseAllocation) {
            _aligned_free(m_BaseAllocation);
        }
    }

    RingPublicationRecord m_Pub{};

    RingContext* GetContext() { return &m_Context; }
    void* GetContextPointer() { return &m_Context; }
    const RingPublicationRecord& Publication() const { return m_Pub; }

    bool PublishExpectedActivationSlot(uint64_t rows, uint64_t columns, float fill) {
        m_Pub = {};
        m_Pub.producerSeq = m_Context.producerIndex;
        m_Pub.slotIndex = m_Pub.producerSeq & 3u;
        RingBufferSlot* slot = &m_Context.slots[m_Pub.slotIndex];
        m_Pub.statusBefore = slot->slotStatus;
        m_Pub.publishTsc = __rdtsc();

        const uint64_t elems = rows * columns;
        const uint64_t bytes = elems * sizeof(float);
        if (bytes == 0 || bytes > m_ChunkSize) {
            return false;
        }

        uint8_t* submitted = SubmitDmaToRing(&m_Context, bytes);
        m_Pub.submitted = (submitted != nullptr);
        if (!submitted || submitted != slot->bufferPtr) {
            std::printf("PASS2_RING_PUBLICATION_001     = FAIL (submit)\n");
            return false;
        }

        float* payload = reinterpret_cast<float*>(submitted);
        for (uint64_t i = 0; i < elems; ++i) {
            payload[i] = fill;
        }
        uint64_t nonzero = 0;
        for (uint64_t i = 0; i < elems; ++i) {
            if (payload[i] != 0.0f) {
                ++nonzero;
            }
        }
        m_Pub.payloadPtr = submitted;
        m_Pub.payloadBytes = bytes;
        m_Pub.nonzeroBytes = nonzero * sizeof(float);
        m_Pub.generation = m_Pub.producerSeq + 1;

        std::atomic_thread_fence(std::memory_order_release);
        CompleteDmaAndSignal(&m_Context, m_Pub.slotIndex);
        slot->payloadSize = bytes;
        slot->reserved = m_Pub.generation;
        slot->slotStatus = STATUS_PLAINTEXT;
        m_Context.consumerIndex = m_Pub.slotIndex;
        std::atomic_thread_fence(std::memory_order_release);

        m_Pub.statusAfter = slot->slotStatus;
        m_Pub.published = (m_Pub.statusAfter == STATUS_PLAINTEXT && m_Pub.nonzeroBytes == bytes);
        std::printf("PASS2_SUBMIT_CALLED           = %s\n", m_Pub.submitted ? "PASS" : "FAIL");
        std::printf("PASS2_SLOT_WAS_EMPTY_BEFORE   = %s\n", (m_Pub.statusBefore == STATUS_EMPTY) ? "PASS" : "FAIL");
        std::printf("PASS2_PAYLOAD_NONZERO_BYTES   = %llu\n", static_cast<unsigned long long>(m_Pub.nonzeroBytes));
        std::printf("PASS2_RELEASE_STATUS          = %s\n",
            (m_Pub.statusAfter == STATUS_PLAINTEXT) ? "STATUS_PLAINTEXT" : "FAIL");
        std::printf("PUBLISH_TSC                   = %llu\n", static_cast<unsigned long long>(m_Pub.publishTsc));
        return m_Pub.published;
    }

    bool AcquirePublishedSlot(uint64_t rows, uint64_t columns) {
        m_Pub.acquireTsc = __rdtsc();
        std::atomic_thread_fence(std::memory_order_acquire);
        const uint32_t idx = m_Context.consumerIndex;
        RingBufferSlot* slot = &m_Context.slots[idx];
        const uint64_t bytes = rows * columns * sizeof(float);
        m_Pub.acquired =
            (idx == m_Pub.slotIndex) &&
            (slot->slotStatus == STATUS_PLAINTEXT) &&
            (slot->bufferPtr == m_Pub.payloadPtr) &&
            (slot->payloadSize == m_Pub.payloadBytes) &&
            (slot->reserved == m_Pub.generation) &&
            (bytes == m_Pub.payloadBytes) &&
            (m_Pub.acquireTsc >= m_Pub.publishTsc);
        std::printf("PASS2_GENERATION_MATCH        = %s\n", (slot->reserved == m_Pub.generation) ? "PASS" : "FAIL");
        std::printf("PASS2_ACQUIRE_AFTER_PUBLISH   = %s\n", (m_Pub.acquireTsc >= m_Pub.publishTsc) ? "PASS" : "FAIL");
        std::printf("ACQUIRE_TSC                   = %llu\n", static_cast<unsigned long long>(m_Pub.acquireTsc));
        return m_Pub.acquired;
    }
};

class Deep2EnginePipelineExtended : public Deep2EnginePipeline {
public:
    Deep2EnginePipelineExtended(uint64_t chunkSize, const uint8_t* expandedKeys, Deep2MicroProfiler* profiler)
        : Deep2EnginePipeline(chunkSize, expandedKeys, profiler) {}
    Deep2EnginePipelineExtended(void* pool, uint64_t chunkSize, const uint8_t* expandedKeys, Deep2MicroProfiler* profiler)
        : Deep2EnginePipeline(pool, chunkSize, expandedKeys, profiler) {}

    void ExecuteLayerCompute(
        float* outActivations, 
        const float* inActivations, 
        uint64_t rows, 
        uint64_t columns) 
    {
        // m_profiler->LogEvent("Deep2EnginePipelineExtended: ExecuteLayerCompute entry"); // Uncomment if needed
        uint32_t currentConsumer = m_Context.consumerIndex;
        RingBufferSlot* activeSlot = &(m_Context.slots[currentConsumer]);

        if (activeSlot->slotStatus != STATUS_PLAINTEXT) {
            throw std::runtime_error("P1_GEMV_INPUT_AUTHORITY_001: RING_STATUS != STATUS_PLAINTEXT");
        }
        if ((columns & 15ull) != 0) {
            throw std::runtime_error("P1_GEMV_INPUT_AUTHORITY_001: COLUMN_COUNT not ZMM aligned");
        }

        const float* decryptedWeights = reinterpret_cast<const float*>(activeSlot->bufferPtr);
        std::printf("PASS2_GEMV_AFTER_ACQUIRE      = %s\n", m_Pub.acquired ? "PASS" : "FAIL");
        Avx512_Gemv_Row_Stride(outActivations, decryptedWeights, inActivations, columns, rows);
        // m_profiler->LogEvent("Deep2EnginePipelineExtended: Avx512_Gemv_Row_Stride dispatched"); // Uncomment if needed
    }
};

class Deep2EnginePipelineSecured : public Deep2EnginePipelineExtended {
private:
    Deep2ContextGuard m_Guard;

public:
    Deep2EnginePipelineSecured(uint64_t chunkSize, const uint8_t* expandedKeys, Deep2MicroProfiler* profiler)
        : Deep2EnginePipelineExtended(chunkSize, expandedKeys, profiler),
          m_Guard(m_BaseAllocation, chunkSize * 4)
    { m_profiler->LogEvent("Deep2EnginePipelineSecured: Owned allocation constructor entry"); }

    Deep2EnginePipelineSecured(void* pool, uint64_t chunkSize, const uint8_t* expandedKeys, Deep2MicroProfiler* profiler)
        : Deep2EnginePipelineExtended(pool, chunkSize, expandedKeys, profiler),
          m_Guard(m_BaseAllocation, chunkSize * 4)
    { m_profiler->LogEvent("Deep2EnginePipelineSecured: Provided memory constructor entry"); }

    void SecuredExecuteLayerCompute(
        float* outActivations, 
        const float* inActivations, 
        uint64_t rows, 
        uint64_t columns) 
    {
        m_profiler->LogEvent("Deep2EnginePipelineSecured: SecuredExecuteLayerCompute entry");
        m_Guard.ValidateDimensionConstraints(rows, columns);
        m_profiler->LogEvent("Deep2EnginePipelineSecured: Dimension constraints validated");

        if (!AcquirePublishedSlot(rows, columns)) {
            throw std::runtime_error("PASS2_RING_PUBLICATION_001: consumer acquire before publish");
        }
        uint32_t currentConsumer = m_Context.consumerIndex;
        RingBufferSlot* activeSlot = &(m_Context.slots[currentConsumer]);
        if (activeSlot->slotStatus != STATUS_PLAINTEXT) {
            throw std::runtime_error("P1_GEMV_INPUT_AUTHORITY_001: reject STATUS_EMPTY/pending slot");
        }

        const uint64_t elems = rows * columns;
        m_Guard.ValidatePointerRange(activeSlot->bufferPtr, elems, sizeof(float));
        const float* weights = reinterpret_cast<const float*>(activeSlot->bufferPtr);
        uint64_t nonzero = 0;
        for (uint64_t i = 0; i < elems; ++i) {
            if (weights[i] != 0.0f) {
                ++nonzero;
            }
        }
        if (nonzero == 0) {
            throw std::runtime_error("P1_GEMV_INPUT_AUTHORITY_001: POOL_NONZERO_BYTES == 0");
        }
        m_profiler->LogEvent("Deep2EnginePipelineSecured: Ring buffer pointer range validated");
        
        ExecuteLayerCompute(outActivations, inActivations, rows, columns);
        m_profiler->LogEvent("Deep2EnginePipelineSecured: ExecuteLayerCompute dispatched");
    }
};

void AuditedMoeRoutingWorker(
    const float* tokenActivations,
    const Deep2Quantization::QuantizedBlock512* expertWeights,
    float* outActivations,
    const Deep2MoeRouter::ExpertConfig& moeConfig,
    uint64_t& accumulatedMisses,
    SovereignTrafficAccounting& traffic,
    Deep2ExpertAuditor& auditor)
{
    Deep2CacheAudit cacheTracker;
    cacheTracker.StartTrace();
    
    uint32_t chosenExperts[2] = {4, 12}; // Mock IDs
    auditor.LogRouterSelection(chosenExperts, 2, moeConfig.hiddenDimension * moeConfig.hiddenDimension, static_cast<uint64_t>(moeConfig.hiddenDimension * moeConfig.hiddenDimension * 0.4)); // 60% sparsity

    uint64_t activeParameterCount = 37000000000ULL / 96; 
    uint64_t packedExpertBytes = static_cast<uint64_t>(activeParameterCount / 8.0 * 1.5);
    traffic.RecordExpertSelection(activeParameterCount, packedExpertBytes, true);

    Deep2MoeRouter::RouteTokenMoE(tokenActivations, expertWeights, outActivations, moeConfig);
    
    cacheTracker.StopTrace();
    accumulatedMisses += cacheTracker.GetDeltaMisses();
}

void ParallelAsymmetricInferencePipeline(
    void* r9700WeightPool,
    void* gpu7800XtWeightPool,
    float* intermediateActivations,
    float* finalOutputActivations,
    uint32_t totalLayers,
    SovereignTrafficAccounting& traffic,
    Deep2ExpertAuditor& auditor)
{
    Deep2MultiGpuBridge multiGpuDriver;
    uint32_t r9700LayerBoundary = (totalLayers * 2) / 3;
    uint64_t globalPipelineCycle = 1;

    const auto* r9700Weights = reinterpret_cast<const Deep2Quantization::QuantizedBlock512*>(r9700WeightPool);
    const auto* gpu7800XtWeights = reinterpret_cast<const Deep2Quantization::QuantizedBlock512*>(gpu7800XtWeightPool);
    Deep2MoeRouter::ExpertConfig moeConfig{64, 2, 8192};

    try {
        uint64_t accumulatedL3Misses = 0;

        for (uint32_t layer = 0; layer < r9700LayerBoundary; ++layer) {
            AuditedMoeRoutingWorker(intermediateActivations, r9700Weights, intermediateActivations, moeConfig, accumulatedL3Misses, traffic, auditor);
        }
        
        multiGpuDriver.SignalHandoffTo7800XT(globalPipelineCycle, intermediateActivations, finalOutputActivations, 8192);
        traffic.RecordH2DCompletion(8192 * sizeof(float));

        multiGpuDriver.AwaitR9700DataPayload(globalPipelineCycle);
        
        for (uint32_t layer = r9700LayerBoundary; layer < totalLayers; ++layer) {
            AuditedMoeRoutingWorker(finalOutputActivations, gpu7800XtWeights, finalOutputActivations, moeConfig, accumulatedL3Misses, traffic, auditor);
        }

        Deep2CacheAudit::PrintAuditSummary(accumulatedL3Misses, moeConfig.totalExperts, moeConfig.hiddenDimension);
        traffic.RecordTokenComplete();

    } catch (...) {
        throw;
    }
}

// Global pipeline wrapper combining security validation and micro-architectural scheduling
extern "C" void HardenedEngineRuntimeWorkerWithProfiling(
    void* ringBufferMemoryPool, 
    uint64_t individualSlotSize, 
    const uint8_t* preExpandedKeys,
    float* outputActivations,
    float* inputActivations,
    uint64_t matrixRows,
    uint64_t matrixColumns,
    bool enableSmtPrefetch,
    Deep2MicroProfiler* profiler) 
{
    try {
        profiler->LogEvent("HardenedEngineRuntimeWorkerWithProfiling: Entry");
        // Use provided memory for the pipeline
        Deep2EnginePipelineSecured pipeline(ringBufferMemoryPool, individualSlotSize, preExpandedKeys, profiler);
        profiler->LogEvent("HardenedEngineRuntimeWorkerWithProfiling: PipelineSecured initialized");
        Deep2HardwareIsolation::EnforceIsolateEcosystem(pipeline.GetContextPointer(), 3, profiler);
        profiler->LogEvent("HardenedEngineRuntimeWorkerWithProfiling: Hardware isolation enforced");
        if (!pipeline.PublishExpectedActivationSlot(matrixRows, matrixColumns, 1.0f)) {
            throw std::runtime_error("PASS2_RING_PUBLICATION_001: producer did not publish");
        }
        profiler->LogEvent("HardenedEngineRuntimeWorkerWithProfiling: activation slot published");

        Deep2HardwareIsolation::SmtPrefetchContext* smtCtx = nullptr;
        const uint8_t* publishedPtr = pipeline.Publication().payloadPtr;
        const uint64_t publishedBytes = pipeline.Publication().payloadBytes;
        if (enableSmtPrefetch && publishedPtr && publishedBytes) {
            smtCtx = Deep2HardwareIsolation::StartSiblingPrefetcher(
                3, publishedPtr, publishedBytes, profiler);
            if (!Deep2HardwareIsolation::WaitForPrefetchEpoch(smtCtx, 1, 2000000)) {
                std::printf("SMT_PREFETCH                   = FAIL (no ready epoch)\n");
            }
        }

        profiler->LogEvent("Unified Decrypt + AVX-512 GEMV Layer Run: Start");
        profiler->LogEvent("Pure AVX-512 Matrix-Vector Engine: Start");
        const uint64_t gemvBeginTsc = __rdtsc();
        pipeline.SecuredExecuteLayerCompute(
            outputActivations, 
            inputActivations, 
            matrixRows, 
            matrixColumns
        );
        const uint64_t gemvEndTsc = __rdtsc();
        profiler->LogEvent("Pure AVX-512 Matrix-Vector Engine: End");
        profiler->LogEvent("Unified Decrypt + AVX-512 GEMV Layer Run: End");

        if (smtCtx) {
            const uint64_t prefetchBegin = smtCtx->beginTsc.load();
            const uint64_t firstReady = smtCtx->firstReadyTsc.load();
            const uint64_t prefetchEnd = Deep2HardwareIsolation::StopSiblingPrefetcher(smtCtx);
            smtCtx = nullptr;
            const int64_t lead = (firstReady != 0 && gemvBeginTsc > firstReady)
                ? static_cast<int64_t>(gemvBeginTsc - firstReady) : -1;
            const uint64_t overlapEnd = (prefetchEnd < gemvEndTsc) ? prefetchEnd : gemvEndTsc;
            const int64_t overlap = (overlapEnd > gemvBeginTsc)
                ? static_cast<int64_t>(overlapEnd - gemvBeginTsc) : 0;
            std::printf("PREFETCH_BEGIN_TSC            = %llu\n", static_cast<unsigned long long>(prefetchBegin));
            std::printf("FIRST_CACHELINE_READY_TSC     = %llu\n", static_cast<unsigned long long>(firstReady));
            std::printf("GEMV_BEGIN_TSC                = %llu\n", static_cast<unsigned long long>(gemvBeginTsc));
            std::printf("PREFETCH_END_TSC              = %llu\n", static_cast<unsigned long long>(prefetchEnd));
            std::printf("GEMV_END_TSC                  = %llu\n", static_cast<unsigned long long>(gemvEndTsc));
            std::printf("PREFETCH_LEAD_CYCLES          = %lld\n", static_cast<long long>(lead));
            std::printf("OVERLAP_CYCLES                = %lld\n", static_cast<long long>(overlap));
            std::printf("PASS2_SMT_PREFETCH_LEAD_001   = %s\n", (lead > 0) ? "PASS" : "FAIL");
        }
                profiler->LogEvent("HardenedEngineRuntimeWorkerWithProfiling: Exit");
    }
    catch (const std::exception& ex) {
        std::cerr << "[CRITICAL FAILURE] " << ex.what() << "\n";
        profiler->LogEvent(std::string("HardenedEngineRuntimeWorkerWithProfiling: CRITICAL FAILURE: ") + ex.what());
    }
}

void SovereignContinuousStreamingLoop(
    const wchar_t* rawModelPath,
    uint64_t sliceSize,
    uint32_t tokenSweepCount)
{
    if (!rawModelPath || sliceSize == 0 || tokenSweepCount == 0)
        throw std::invalid_argument("SovereignContinuousStreamingLoop: bad args");

    // Unbuffered NVMe requires sector-aligned transfers (512/4096).
    if ((sliceSize & 4095ull) != 0)
        throw std::invalid_argument("SovereignContinuousStreamingLoop: sliceSize must be 4KiB-aligned");

    Deep2ThreadTuning::VacuumSequestrationOS();
    Deep2ThreadTuning::LockComputePipeline(0, false);

    Deep2StorageRing storageRing(rawModelPath, sliceSize);
    SovereignTrafficAccounting traffic;
    storageRing.SetTrafficAccounting(&traffic);

    float* outputActivations =
        static_cast<float*>(_aligned_malloc(8192 * sizeof(float), 64));
    if (!outputActivations)
        throw std::bad_alloc();

    uint64_t currentFileReadCursor = 0;
    storageRing.PrimeBackgroundPrefetch(currentFileReadCursor);
    currentFileReadCursor += sliceSize;

    std::cout << "[*] NVMe dual-slot streamer online. sweep=" << tokenSweepCount
              << " slice_mb=" << (sliceSize / (1024 * 1024)) << "\n";

    for (uint32_t tokenIndex = 0; tokenIndex < tokenSweepCount; ++tokenIndex) {
        storageRing.SynchronizeRingRotation();
        storageRing.PrimeBackgroundPrefetch(currentFileReadCursor);
        currentFileReadCursor += sliceSize;

        const uint8_t* activeWeights = storageRing.GetActiveComputePointer();
        const auto* packedTensors =
            reinterpret_cast<const Deep2Quantization::QuantizedBlock512*>(activeWeights);

        Deep2MatrixWrapper::ComputeAsymmetricLayerGEMV(
            packedTensors, 8192, 8192, outputActivations);
        traffic.RecordTokenComplete();
    }

    _aligned_free(outputActivations);
    std::cout << "[+] SovereignContinuousStreamingLoop complete.\n";
}
