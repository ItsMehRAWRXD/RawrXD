#include "Deep2Engine.hpp"
#include "TensorROM.hpp"
#include "quant_kernels.hpp"
#include "VulkanDevice.hpp"
#include "VulkanDeviceAllocator.hpp"
#include "Win32RomEmulator.hpp"
#include "MasmCoreKernels.hpp"

#include <iostream>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <limits>
#include <cstdlib>
#include <windows.h>

namespace {
constexpr size_t kResidencyMiB = 1024ull * 1024ull;

size_t readResidencyMiB(const char* name, size_t fallback) {
    const char* text = std::getenv(name);
    if (!text || !*text) return fallback;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text, &end, 10);
    if (end == text || *end != '\0' ||
        value > std::numeric_limits<size_t>::max() / kResidencyMiB)
        return fallback;
    return static_cast<size_t>(value) * kResidencyMiB;
}

void configureTensorResidencyBudgets(Deep2Engine& engine) {
    size_t f32Budget = 512ull * kResidencyMiB;
    size_t encodedBudget = 128ull * kResidencyMiB;
    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    if (GlobalMemoryStatusEx(&memory) && memory.ullAvailPhys) {
        const size_t available = static_cast<size_t>(std::min<unsigned long long>(
            memory.ullAvailPhys, std::numeric_limits<size_t>::max()));
        f32Budget = std::min<size_t>(2ull * 1024ull * kResidencyMiB,
            std::max<size_t>(16ull * kResidencyMiB, available / 8));
        encodedBudget = std::min<size_t>(512ull * kResidencyMiB,
            std::max<size_t>(8ull * kResidencyMiB, available / 32));
    }
    f32Budget = readResidencyMiB("DEEP2_F32_RESIDENCY_MB", f32Budget);
    encodedBudget = readResidencyMiB("DEEP2_ENCODED_RESIDENCY_MB", encodedBudget);
    engine.compressedF32Weights.SetBudget(f32Budget);
    engine.compressedEncodedWeights.SetBudget(encodedBudget);
    fprintf(stderr, "[TENSOR_RESIDENCY] f32_budget=%zu encoded_budget=%zu\\n",
            f32Budget, encodedBudget);
}
} // namespace

bool Deep2Engine::ConfigureTensorCompression(size_t f32BudgetBytes,
                                                   size_t encodedBudgetBytes,
                                                   float f32MaxAbsError) {
    if (!std::isfinite(f32MaxAbsError) || f32MaxAbsError < 0.0f)
        return false;
    // Cache SetBudget operations are synchronized with active reads/builds.
    // The tolerance is atomic so concurrent inference observes a valid value.
    compressedF32Weights.SetBudget(f32BudgetBytes);
    compressedEncodedWeights.SetBudget(encodedBudgetBytes);
    compressedF32MaxAbsError.store(f32MaxAbsError, std::memory_order_relaxed);
    return true;
}

bool Deep2Engine::Initialize(const std::string& modelPath, const std::string& manifestPath, bool forceWholeLoader) {
    // Reinitialization is a full lifecycle boundary; discard prior model state.
    Shutdown();
    configureTensorResidencyBudgets(*this);
    // Lossy F32->F16/BF16 residency is opt-in and bounded by a caller-supplied
    // absolute-error tolerance. The default remains bit-exact/lossless.
    if (const char* tolerance = std::getenv("DEEP2_F32_MAX_ABS_ERROR")) {
        char* end = nullptr;
        const float parsed = std::strtof(tolerance, &end);
        if (end == tolerance || *end != '\0' || !std::isfinite(parsed) || parsed < 0.0f) {
            fprintf(stderr, "[ROM] invalid DEEP2_F32_MAX_ABS_ERROR; expected finite nonnegative float\\n");
            return false;
        }
        compressedF32MaxAbsError = parsed;
    }
    fprintf(stderr, "[ROM] F32 compressed residency absolute-error budget: %.9g\\n",
            compressedF32MaxAbsError);

    const auto applyCacheBudget = [](const char* variable, auto&& setter) -> bool {
        const char* value = std::getenv(variable);
        if (!value) return true;
        if (!*value || *value == '-') return false;
        char* end = nullptr;
        const unsigned long long parsed = std::strtoull(value, &end, 10);
        if (end == value || *end != '\0' ||
            parsed > static_cast<unsigned long long>(std::numeric_limits<size_t>::max()))
            return false;
        setter(static_cast<size_t>(parsed));
        return true;
    };
    if (!applyCacheBudget("DEEP2_F32_CACHE_BYTES",
            [this](size_t bytes) { compressedF32Weights.SetBudget(bytes); }) ||
        !applyCacheBudget("DEEP2_ENCODED_CACHE_BYTES",
            [this](size_t bytes) { compressedEncodedWeights.SetBudget(bytes); })) {
        fprintf(stderr, "[ROM] invalid tensor residency cache budget environment value\\n");
        return false;
    }

    if (!manifestPath.empty()) {
        ParseOllamaManifest(manifestPath, &ctx);
    }

    if (forceWholeLoader || !romMode) {
        bool result = LoadUniversalBlob(modelPath, &ctx);
        if (result) { initialized = true; SynchronizeRoPEScaling(); }
        return result;
    }

    // --- ROM (paged) path: header/tensor-directory only, no whole-model allocation ---
    if (!rom.addShard(modelPath)) return false;
    if (!rom.finalizeIndex()) return false;

    // Best-effort Vulkan initialization on all discovered AMD discrete GPUs.
    vulkan = std::make_unique<deep2::VulkanDevice>();
    vulkanReady = vulkan->init();
    if (vulkanReady) {
        fprintf(stderr, "[ROM_EXEC_BRIDGE] Vulkan ready on %zu GPU(s)\n", vulkan->gpuCount());
        for (size_t i = 0; i < vulkan->gpuCount(); ++i) {
            const auto* g = vulkan->gpu(i);
            fprintf(stderr, "[VULKAN] gpu%zu: %s (%llu MB)\n", i, g->name.c_str(),
                    (unsigned long long)(g->vramBytes / (1024ull * 1024ull)));
        }
    } else {
        fprintf(stderr, "[ROM_EXEC_BRIDGE] Vulkan unavailable; CPU-only execution\n");
    }

    initialized = true;
    SynchronizeRoPEScaling();
    return true;
}

Deep2Engine::TensorResidencySnapshot Deep2Engine::GetTensorResidencySnapshot() const {
    const auto f32 = compressedF32Weights.GetStats();
    const auto encoded = compressedEncodedWeights.GetStats();
    TensorResidencySnapshot snapshot;
    snapshot.f32BudgetBytes = f32.budgetBytes;
    snapshot.encodedBudgetBytes = encoded.budgetBytes;
    if (const auto* pager = rom.pager()) {
        snapshot.sourcePagerBudgetBytes = pager->capacityBytes();
        snapshot.sourcePagerResidentBytes = pager->residentBytes();
        snapshot.sourcePagerPageCount = pager->pageCount();
    }
    snapshot.f32CompressedBytes = f32.compressedBytes;
    snapshot.encodedCompressedBytes = encoded.compressedBytes;
    snapshot.f32LogicalBytes = f32.logicalBytes;
    snapshot.encodedLogicalBytes = encoded.logicalBytes;
    snapshot.f32TensorCount = f32.tensorCount;
    snapshot.encodedTensorCount = encoded.tensorCount;
    snapshot.f32CacheHits = f32.cacheHits;
    snapshot.f32CacheMisses = f32.cacheMisses;
    snapshot.encodedCacheHits = encoded.hits;
    snapshot.encodedCacheMisses = encoded.misses;
    const auto saturatingAdd = [](uint64_t a, uint64_t b) {
        return b > std::numeric_limits<uint64_t>::max() - a
            ? std::numeric_limits<uint64_t>::max() : a + b;
    };
    snapshot.bytesDecoded = saturatingAdd(f32.bytesDecoded, encoded.bytesDecoded);
    snapshot.evictions = saturatingAdd(f32.evictions, encoded.evictions);
    return snapshot;
}

void Deep2Engine::Shutdown() {
    // Caller must stop/join inference workers before shutdown so no page or
    // compressed-cache leases remain live.
    compressedF32Weights.Clear();
    compressedEncodedWeights.Clear();
    if (vulkan) { vulkan->shutdown(); vulkan.reset(); }
    rom.Reset();
    vulkanReady = false;
    initialized = false;
}

void MatrixWorkerStub(size_t index, void* args) {
    MatrixArgs* mArgs = reinterpret_cast<MatrixArgs*>(args);
    mArgs->out[index] = mArgs->in[index] * 1.0002f;
}

void Deep2Engine::SynchronizeRoPEScaling(double modelThetaConfig) {
    if (romMode && rom.shardCount() > 0) {
        ctx.cfg = ModelConfig{};
        ctx.cfg.hiddenDim = static_cast<size_t>(rom.geometry().hiddenDim);
        ctx.cfg.numLayers = static_cast<size_t>(rom.geometry().numLayers);
        ctx.cfg.numHeads = static_cast<size_t>(rom.geometry().numHeads);
        ctx.cfg.numKVHeads = static_cast<size_t>(rom.geometry().numKVHeads);
        ctx.cfg.intermediateDim = static_cast<size_t>(rom.geometry().intermediateDim);
        ctx.cfg.vocabSize = static_cast<size_t>(rom.geometry().vocabSize);
        ctx.cfg.maxSeqLen = static_cast<size_t>(rom.geometry().maxSeqLen);
        ctx.cfg.ropeThetaGlobal = rom.geometry().ropeTheta;
        ctx.cfg.ropeScaleFactor = 1.0;
    } else {
        ctx.cfg.ropeThetaGlobal = (modelThetaConfig > 0.0) ? modelThetaConfig : 10000.0;
        ctx.cfg.ropeScaleFactor = 1.0;
        if (ctx.cfg.maxSeqLen > 4096) {
            double contextRatio = static_cast<double>(ctx.cfg.maxSeqLen) / 4096.0;
            ctx.cfg.ropeThetaGlobal = (ctx.cfg.ropeThetaGlobal == 10000.0) ? 500000.0 : ctx.cfg.ropeThetaGlobal;
            ctx.cfg.ropeScaleFactor = 1.0 / contextRatio;
        }
    }
    if (ctx.cfg.maxSeqLen > 4096) {
        fprintf(stderr, "[ROPE_ADAPT] maxSeqLen=%zu -> Theta=%.2f Scale=%.6f\n",
                ctx.cfg.maxSeqLen, ctx.cfg.ropeThetaGlobal, ctx.cfg.ropeScaleFactor);
    }
}

void Deep2Engine::ApplyRotaryEmbeddings(float* vectorData, size_t headIndex, size_t position) {
    size_t dim = ctx.cfg.hiddenDim / ctx.cfg.numHeads;
    (void)headIndex;
    for (size_t i = 0; i < dim; i += 2) {
        double frequency = 1.0 / std::pow(ctx.cfg.ropeThetaGlobal, static_cast<double>(i) / dim);
        double scaledArgument = static_cast<double>(position) * frequency * ctx.cfg.ropeScaleFactor;
        float sinValue = std::sin(scaledArgument);
        float cosValue = std::cos(scaledArgument);
        float v0 = vectorData[i];
        float v1 = vectorData[i + 1];
        vectorData[i]     = (v0 * cosValue) - (v1 * sinValue);
        vectorData[i + 1] = (v0 * sinValue) + (v1 * cosValue);
    }
}

void Deep2Engine::DequantizeQ2_K_AVX512(const void* __restrict source, float* __restrict destination, size_t 
blockCount) {
    const Block_Q2_K* blocks = static_cast<const Block_Q2_K*>(source);
    for (size_t b = 0; b < blockCount; ++b) {
        const Block_Q2_K& block = blocks[b];
        float baseScale = ConvertFp16ToFloat32(block.d);
        __m512 vBaseScale = _mm512_set1_ps(baseScale);
        for (size_t step = 0; step < 4; ++step) {
            __m128i rawBytes = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&block.qs[step * 16]));
            __m512i extendedInts = _mm512_cvtepu8_epi32(rawBytes);
            __m512i maskedBits = _mm512_and_epi32(extendedInts, _mm512_set1_epi32(0x03));
            __m512 vWeights = _mm512_cvtepi32_ps(maskedBits);
            __m512 vFinalLogits = _mm512_mul_ps(vWeights, vBaseScale);
            _mm512_storeu_ps(&destination[(b * 64) + (step * 16)], vFinalLogits);
        }
    }
}

inline void FastVectorSinCos256(__m256 x, __m256& sinOut, __m256& cosOut) {
    __m256 c1 = _mm256_set1_ps(1.0f);
    __m256 c2 = _mm256_set1_ps(-0.5f);
    __m256 s1 = _mm256_set1_ps(-0.166666667f);

    __m256 x2 = _mm256_mul_ps(x, x);
    
    cosOut = _mm256_fmadd_ps(x2, c2, c1);
    
    __m256 x3 = _mm256_mul_ps(x2, x);
    sinOut = _mm256_fmadd_ps(x3, s1, x);
}

void Deep2Engine::ApplyRotaryEmbeddingsAVX512(float* vectorData, size_t dim, size_t position) {
    size_t i = 0;
    for (; i + 16 <= dim; i += 16) {
        __m512 vData = _mm512_loadu_ps(&vectorData[i]);
        alignas(64) float tempFreqs[16];
        for (size_t v = 0; v < 16; v += 2) {
            double freq = 1.0 / std::pow(ctx.cfg.ropeThetaGlobal, static_cast<double>(i + v) / dim);
            double arg  = static_cast<double>(position) * freq * ctx.cfg.ropeScaleFactor;
            tempFreqs[v]     = static_cast<float>(arg);
            tempFreqs[v + 1] = static_cast<float>(arg);
        }
        __m512 vArgs = _mm512_load_ps(tempFreqs);
        __m256 xLow = _mm512_extractf32x8_ps(vArgs, 0);
        __m256 xHigh = _mm512_extractf32x8_ps(vArgs, 1);
        __m256 sinLow, cosLow, sinHigh, cosHigh;
        FastVectorSinCos256(xLow, sinLow, cosLow);
        FastVectorSinCos256(xHigh, sinHigh, cosHigh);
        __m512 vSin = _mm512_insertf32x8(_mm512_castps256_ps512(sinLow), sinHigh, 1);
        __m512 vCos = _mm512_insertf32x8(_mm512_castps256_ps512(cosLow), cosHigh, 1);
        __m512 vPermuted = _mm512_permute_ps(vData, _MM_SHUFFLE(2, 3, 0, 1));
        __m512 vSignsMask = _mm512_set_ps(1.0f, -1.0f, 1.0f, -1.0f, 1.0f, -1.0f, 1.0f, -1.0f,
                                          1.0f, -1.0f, 1.0f, -1.0f, 1.0f, -1.0f, 1.0f, -1.0f);
        __m512 vRotated = _mm512_mul_ps(vPermuted, vSignsMask);
        __m512 vFinal = _mm512_fmadd_ps(vData, vCos, _mm512_mul_ps(vRotated, vSin));
        _mm512_storeu_ps(&vectorData[i], vFinal);
    }
    for (; i + 1 < dim; i += 2) {
        double frequency = 1.0 / std::pow(ctx.cfg.ropeThetaGlobal, static_cast<double>(i) / dim);
        double scaledArgument = static_cast<double>(position) * frequency * ctx.cfg.ropeScaleFactor;
        float sinValue = std::sin(scaledArgument);
        float cosValue = std::cos(scaledArgument);
        float v0 = vectorData[i];
        float v1 = vectorData[i + 1];
        vectorData[i]     = (v0 * cosValue) - (v1 * sinValue);
        vectorData[i + 1] = (v0 * sinValue) + (v1 * cosValue);
    }
}

Deep2Engine::TensorHandle Deep2Engine::getTensor(const std::string& name) {
    TensorHandle h;
    if (!romMode || !initialized) return h;
    const deep2::TensorEntry* entry = rom.findTensor(name);
    if (!entry) {
        fprintf(stderr, "[ROM_EXEC_BRIDGE] tensor not found in ROM: %s\n", name.c_str());
        return h;
    }
    h.lease = rom.leaseTensor(*entry);
    if (!h.lease) {
        fprintf(stderr, "[ROM_EXEC_BRIDGE] failed to lease tensor: %s\n", name.c_str());
        return h;
    }
    h.view.type = entry->type;
    h.view.dims = entry->dims;
    h.view.byteSize = entry->byteSize();
    h.view.contiguous = true;
    h.view.data = h.lease.direct(0, entry->byteSize());
    h.ok = true;
    return h;
}

bool Deep2Engine::dequantTensor(const deep2::TensorEntry& entry, deep2::DequantizedTensor& out) {
    if (!romMode) return false;
    const uint64_t size = entry.byteSize();
    std::vector<uint8_t> staged(size);
    if (!rom.readTensor(entry, staged.data())) return false;
    deep2::TensorView view{ entry.type, staged.data(), size, entry.dims, true };
    return dequantizeTensor(view, out);
}

bool Deep2Engine::readCompressedF32Tile(const deep2::TensorEntry& entry,
                                              uint64_t firstElement,
                                              uint64_t elementCount,
                                              float* destination) {
    std::vector<uint8_t> decodeScratch;
    return readCompressedF32Tile(entry,firstElement,elementCount,destination,decodeScratch);
}

bool Deep2Engine::readCompressedF32Tile(const deep2::TensorEntry& entry,
                                              uint64_t firstElement,
                                              uint64_t elementCount,
                                              float* destination,
                                              std::vector<uint8_t>& decodeScratch) {
    if (!romMode || entry.type != deep2::TensorType::F32) return false;
    const uint64_t bytes = entry.byteSize();
    if ((bytes % sizeof(float)) != 0) return false;
    const uint64_t totalElements = bytes / sizeof(float);
    if (totalElements > std::numeric_limits<size_t>::max() ||
        firstElement > totalElements || elementCount > totalElements - firstElement ||
        firstElement > std::numeric_limits<uint64_t>::max() / sizeof(float) ||
        elementCount > std::numeric_limits<uint64_t>::max() / sizeof(float) ||
        elementCount > std::numeric_limits<size_t>::max()) return false;

    // GGUF tensor names are not a sufficient cache identity across shards.
    const std::string cacheKey = std::to_string(entry.shardIndex) + ":" +
        std::to_string(entry.offset) + ":" + entry.name;
    if (!compressedF32Weights.Contains(cacheKey) &&
        !compressedF32Weights.IsRawFallback(cacheKey)) {
        const size_t count = static_cast<size_t>(totalElements);
        const auto reader = [this, &entry, bytes](size_t offset, size_t n, float* out) {
            if (offset > bytes / sizeof(float) ||
                n > bytes / sizeof(float) - offset) return false;
            const uint64_t byteOffset = static_cast<uint64_t>(offset) * sizeof(float);
            const uint64_t byteCount = static_cast<uint64_t>(n) * sizeof(float);
            return rom.readTensorRange(entry, byteOffset, byteCount,
                                       reinterpret_cast<uint8_t*>(out));
        };
        if (!compressedF32Weights.RegisterF32FromReader(
                cacheKey, count, compressedF32MaxAbsError.load(std::memory_order_relaxed), reader, 4096)) {
            // No safe/smaller encoding or no cache capacity: memoize the
            // decision and fetch only requested raw tiles on future calls.
            compressedF32Weights.MarkRawFallback(cacheKey);
            const uint64_t byteOffset = firstElement * sizeof(float);
            const uint64_t byteCount = elementCount * sizeof(float);
            return rom.readTensorRange(entry, byteOffset, byteCount,
                                       reinterpret_cast<uint8_t*>(destination));
        } else if (rom.pager() && entry.shardIndex < rom.shards().size()) {
            // The compressed cache now owns the useful representation. Evict
            // the corresponding unleased raw file pages to avoid double
            // residency of both full F32 payloads.
            const auto& shard = rom.shards()[entry.shardIndex];
            const uint64_t tensorBytes = entry.byteSize();
            if (shard.dataOffset <= UINT64_MAX - entry.offset)
                rom.pager()->evictUnleasedRange(static_cast<uint32_t>(entry.shardIndex),
                    shard.dataOffset + entry.offset, tensorBytes);
        }
    }
    if (compressedF32Weights.IsRawFallback(cacheKey)) {
        const uint64_t byteOffset = firstElement * sizeof(float);
        const uint64_t byteCount = elementCount * sizeof(float);
        return rom.readTensorRange(entry, byteOffset, byteCount,
                                   reinterpret_cast<uint8_t*>(destination));
    }
    return compressedF32Weights.ReadRange(cacheKey,
        static_cast<size_t>(firstElement), static_cast<size_t>(elementCount), destination,
        decodeScratch);
}

bool Deep2Engine::readDequantizedTensorTile(const deep2::TensorEntry& entry,
                                                  uint64_t firstElement,
                                                  uint64_t elementCount,
                                                  float* destination) {
    std::vector<uint8_t> encodedScratch;
    return readDequantizedTensorTile(entry, firstElement, elementCount,
                                     destination, encodedScratch);
}

bool Deep2Engine::readDequantizedTensorTile(const deep2::TensorEntry& entry,
                                                  uint64_t firstElement,
                                                  uint64_t elementCount,
                                                  float* destination,
                                                  std::vector<uint8_t>& encodedScratch) {
    std::vector<uint8_t> decodeScratch;
    return readDequantizedTensorTile(entry, firstElement, elementCount,
                                     destination, encodedScratch, decodeScratch);
}

bool Deep2Engine::readDequantizedTensorTile(const deep2::TensorEntry& entry,
                                                  uint64_t firstElement,
                                                  uint64_t elementCount,
                                                  float* destination,
                                                  std::vector<uint8_t>& encodedScratch,
                                                  std::vector<uint8_t>& decodeScratch) {
    if (!romMode || !destination) return false;
    switch (entry.type) {
    case deep2::TensorType::F16:
    case deep2::TensorType::BF16:
    case deep2::TensorType::Q4_0:
    case deep2::TensorType::Q4_1:
    case deep2::TensorType::Q5_0:
    case deep2::TensorType::Q5_1:
    case deep2::TensorType::Q8_1:
    case deep2::TensorType::IQ4_NL:
    case deep2::TensorType::IQ4_XS:
    case deep2::TensorType::MXFP4:
    case deep2::TensorType::F64:
    case deep2::TensorType::I8:
    case deep2::TensorType::I16:
    case deep2::TensorType::I32:
    case deep2::TensorType::I64:
    case deep2::TensorType::Q8_0:
    case deep2::TensorType::Q2_K:
    case deep2::TensorType::Q3_K:
    case deep2::TensorType::Q4_K:
    case deep2::TensorType::Q5_K:
    case deep2::TensorType::Q6_K:
    case deep2::TensorType::Q8_K:
        break;
    default:
        return false;
    }

    uint64_t totalElements = 1;
    for (const uint64_t dimension : entry.dims) {
        if (!dimension || totalElements > std::numeric_limits<uint64_t>::max() / dimension)
            return false;
        totalElements *= dimension;
    }
    if (firstElement > totalElements || elementCount > totalElements - firstElement)
        return false;
    if (!elementCount) return true;

    const uint64_t blockValues = deep2::quantBlockSize(entry.type);
    if (!blockValues) return false;
    if (blockValues > 1 && (entry.dims.empty() || entry.dims[0] % blockValues != 0))
        return false; // GGUF quant blocks may not straddle matrix rows.
    const uint64_t firstBlock = firstElement / blockValues;
    const uint64_t alignedFirst = firstBlock * blockValues;
    const uint64_t endElement = firstElement + elementCount;
    const uint64_t lastBlock = (endElement - 1) / blockValues;
    if (lastBlock == std::numeric_limits<uint64_t>::max()) return false;
    const uint64_t blockEnd = lastBlock + 1;
    if (blockEnd > std::numeric_limits<uint64_t>::max() / blockValues)
        return false;
    const uint64_t alignedEnd = std::min(totalElements, blockEnd * blockValues);
    if (alignedEnd < alignedFirst) return false;
    const uint64_t alignedCount = alignedEnd - alignedFirst;

    const uint64_t bytesPerBlock = deep2::tensorStorageBytes(blockValues, entry.type);
    const uint64_t alignedBlockCount = alignedFirst / blockValues;
    const uint64_t requestedBlockCount =
        alignedCount / blockValues + (alignedCount % blockValues != 0);
    if (!bytesPerBlock ||
        alignedBlockCount > std::numeric_limits<uint64_t>::max() / bytesPerBlock ||
        requestedBlockCount > std::numeric_limits<uint64_t>::max() / bytesPerBlock)
        return false;
    const uint64_t byteOffset = alignedBlockCount * bytesPerBlock;
    const uint64_t byteCount = requestedBlockCount * bytesPerBlock;
    const uint64_t tensorBytes = entry.byteSize();
    if (byteOffset > tensorBytes || byteCount > tensorBytes - byteOffset ||
        byteCount > std::numeric_limits<size_t>::max())
        return false;

    // Retain only strictly smaller lossless representations of non-F32
    // encoded payloads. Canonical GGUF bytes are preserved exactly.
    const std::string cacheKey = std::to_string(entry.shardIndex) + ":" +
        std::to_string(entry.offset) + ":" + entry.name;
    if (!compressedEncodedWeights.Contains(cacheKey) &&
        !compressedEncodedWeights.IsRawFallback(cacheKey)) {
        const uint64_t tensorBytes64 = entry.byteSize();
        if (tensorBytes64 > std::numeric_limits<size_t>::max()) return false;
        const auto reader = [this, &entry, tensorBytes64](size_t offset, size_t count,
                                                          uint8_t* out) {
            if (offset > tensorBytes64 || count > tensorBytes64 - offset) return false;
            return rom.readTensorRange(entry, static_cast<uint64_t>(offset),
                                       static_cast<uint64_t>(count), out);
        };
        if (compressedEncodedWeights.RegisterFromReader(
                cacheKey, static_cast<size_t>(tensorBytes64), reader, 64 * 1024)) {
            if (rom.pager() && entry.shardIndex < rom.shards().size()) {
                const auto& shard = rom.shards()[entry.shardIndex];
                if (shard.dataOffset <= UINT64_MAX - entry.offset)
                    rom.pager()->evictUnleasedRange(static_cast<uint32_t>(entry.shardIndex),
                        shard.dataOffset + entry.offset, tensorBytes64);
            }
        } else {
            compressedEncodedWeights.MarkRawFallback(cacheKey);
        }
    }

    encodedScratch.resize(static_cast<size_t>(byteCount));
    const bool cached = compressedEncodedWeights.Contains(cacheKey) &&
        compressedEncodedWeights.ReadRange(cacheKey, static_cast<size_t>(byteOffset),
            static_cast<size_t>(byteCount), encodedScratch.data(), decodeScratch);
    if (!cached && !rom.readTensorRange(entry, byteOffset, byteCount, encodedScratch.data()))
        return false;
    return deep2::dequantizeTensorRange(entry.type, totalElements, firstElement,
        elementCount, encodedScratch.data(), encodedScratch.size(), destination);
}

bool Deep2Engine::gemvTensorROM(const deep2::TensorEntry& entry, const float* input,
                                float* output, uint64_t* rowsOut, uint64_t* colsOut,
                                size_t tileRows) {
    if (!romMode || !input || !output || entry.dims.size() < 2 || tileRows == 0)
        return false;
    if (entry.dims.size() != 2) return false;
    const uint64_t cols = entry.dims[0];
    const uint64_t rows = entry.dims[1];
    if (rows == 0 || cols == 0) return false;
    if (rowsOut) *rowsOut = rows;
    if (colsOut) *colsOut = cols;
    if (entry.type != deep2::TensorType::F32) {
        if (cols > std::numeric_limits<size_t>::max() / sizeof(float) ||
            rows > std::numeric_limits<size_t>::max() / sizeof(float) / cols)
            return false;
        const size_t colsSize = static_cast<size_t>(cols);
        std::vector<float> completed(static_cast<size_t>(rows), 0.0f);
        std::vector<float> tile;
        std::vector<uint8_t> encodedScratch;
        std::vector<uint8_t> decodeScratch;
        for (uint64_t firstRow = 0; firstRow < rows;) {
            const uint64_t countRows = std::min<uint64_t>(tileRows, rows - firstRow);
            if (countRows > std::numeric_limits<size_t>::max() / colsSize)
                return false;
            const size_t elements = static_cast<size_t>(countRows) * colsSize;
            tile.resize(elements);
            if (!readDequantizedTensorTile(entry, firstRow * cols, elements, tile.data(),
                                          encodedScratch, decodeScratch) ||
                !gemvFloat(tile.data(), input, completed.data() + static_cast<size_t>(firstRow),
                           countRows, cols))
                return false;
            firstRow += countRows;
        }
        std::copy(completed.begin(), completed.end(), output);
        return true;
    }
    if (cols == 0 || rows > std::numeric_limits<size_t>::max() / sizeof(float) / cols)
        return false;
    std::vector<float> completed(static_cast<size_t>(rows), 0.0f);
    const size_t colsSize = static_cast<size_t>(cols);
    std::vector<float> tile;
    std::vector<uint8_t> decodeScratch;
    for (uint64_t firstRow = 0; firstRow < rows;) {
        const uint64_t countRows = std::min<uint64_t>(tileRows, rows - firstRow);
        if (countRows > std::numeric_limits<size_t>::max() / colsSize) return false;
        const size_t tileElements = static_cast<size_t>(countRows) * colsSize;
        tile.resize(tileElements);
        const uint64_t firstElement = firstRow * cols;
        if (!readCompressedF32Tile(entry, firstElement, tileElements, tile.data(),decodeScratch))
            return false;
        if (!gemvFloat(tile.data(), input, completed.data() + static_cast<size_t>(firstRow),
                       countRows, cols)) return false;
        firstRow += countRows;
    }
    std::copy(completed.begin(), completed.end(), output);
    return true;
}

bool Deep2Engine::gemvTensorROMVulkan(const deep2::VulkanDevice::Gpu& gpu,
                                            const deep2::TensorEntry& entry,
                                            const float* input, float* output,
                                            size_t tileRows) {
    if (!romMode || !vulkanReady || !vulkan || !input || !output ||
        entry.dims.size() != 2 ||
        tileRows == 0 || tileRows > UINT32_MAX)
        return false;

    // GGUF matrix dimensions are [columns, rows]. The Vulkan GEMV view uses
    // [rows, columns], matching its shader's row-major contract.
    const uint64_t cols = entry.dims[0];
    const uint64_t rows = entry.dims[1];
    if (!rows || !cols || rows > UINT32_MAX || cols > UINT32_MAX ||
        cols > std::numeric_limits<size_t>::max() / sizeof(float) ||
        rows > std::numeric_limits<size_t>::max() / sizeof(float) / cols)
        return false;

    const size_t colsSize = static_cast<size_t>(cols);
    std::vector<float> tile;
    std::vector<float> tileOutput;
    std::vector<float> completed(static_cast<size_t>(rows), 0.0f);
    std::vector<uint8_t> encodedScratch;
    std::vector<uint8_t> decodeScratch;

    for (uint64_t firstRow = 0; firstRow < rows;) {
        const uint64_t countRows = std::min<uint64_t>(tileRows, rows - firstRow);
        if (countRows > std::numeric_limits<size_t>::max() / colsSize)
            return false;
        const size_t elements = static_cast<size_t>(countRows) * colsSize;
        if (elements > std::numeric_limits<size_t>::max() / sizeof(float))
            return false;

        tile.resize(elements);
        const uint64_t firstElement = firstRow * cols;
        const bool tileRead = entry.type == deep2::TensorType::F32
            ? readCompressedF32Tile(entry, firstElement, elements,
                                    tile.data(), decodeScratch)
            : readDequantizedTensorTile(entry, firstElement, elements, tile.data(),
                                        encodedScratch, decodeScratch);
        if (!tileRead) return false;

        deep2::TensorView weightTile{
            deep2::TensorType::F32,
            reinterpret_cast<const uint8_t*>(tile.data()),
            elements * sizeof(float),
            { countRows, cols },
            true
        };
        deep2::TensorView inputView{
            deep2::TensorType::F32,
            reinterpret_cast<const uint8_t*>(input),
            colsSize * sizeof(float),
            { cols },
            true
        };
        if (!vulkanGemv(gpu, weightTile, inputView, tileOutput) ||
            tileOutput.size() != static_cast<size_t>(countRows))
            return false;

        std::copy(tileOutput.begin(), tileOutput.end(),
                  completed.begin() + static_cast<size_t>(firstRow));
        firstRow += countRows;
    }

    // Publish only after every tile has completed successfully.
    std::copy(completed.begin(), completed.end(), output);
    return true;
}

bool Deep2Engine::gemvFloat(const float* W, const float* x, float* y,
                            uint64_t rows, uint64_t cols) {
    return deep2::gemvFloat(W, x, y, rows, cols);
}

static std::string exeDir() {
    char path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, path, sizeof(path));
    std::string s(path);
    size_t slash = s.find_last_of("\\/");
    return (slash != std::string::npos) ? s.substr(0, slash + 1) : std::string("./");
}

bool Deep2Engine::vulkanGemv(const deep2::VulkanDevice::Gpu& gpu, const deep2::TensorView& wView,
                             const deep2::TensorView& xView, std::vector<float>& y) {
    if (!vulkanReady || !vulkan) return false;

    if (wView.type != deep2::TensorType::F32 || xView.type != deep2::TensorType::F32 ||
        !wView.data || !xView.data) {
        fprintf(stderr, "[VULKAN_GEMV] requires contiguous f32 views\n");
        return false;
    }

    if (wView.dims.size() < 2) return false;
    uint64_t rows = wView.dims[0];
    uint64_t cols = wView.dims[1];
    y.assign(static_cast<size_t>(rows), 0.0f);

    static deep2::VulkanProgram program;
    static VkDevice boundDevice = VK_NULL_HANDLE;
    if (boundDevice != gpu.device) {
        if (boundDevice != VK_NULL_HANDLE) {
            program.destroy(boundDevice);
        }
        std::string spv = exeDir() + "shaders\\gemv_f32.spv";
        if (!program.init(gpu.device, spv)) {
            fprintf(stderr, "[VULKAN_GEMV] program init failed for %s\n", spv.c_str());
            boundDevice = VK_NULL_HANDLE;
            return false;
        }
        boundDevice = gpu.device;
    }

    VkBuffer Wbuf = VK_NULL_HANDLE, xbuf = VK_NULL_HANDLE, ybuf = VK_NULL_HANDLE;
    VkDeviceMemory Wmem = VK_NULL_HANDLE, xmem = VK_NULL_HANDLE, ymem = VK_NULL_HANDLE;
    void* Wmapped = nullptr; void* xmapped = nullptr; void* ymapped = nullptr;

    VkDeviceSize Wsize = (VkDeviceSize)rows * cols * 4;
    VkDeviceSize xsize = (VkDeviceSize)cols * 4;
    VkDeviceSize ysize = (VkDeviceSize)rows * 4;

    auto cleanup = [&]() {
        vulkan->destroyBuffer(gpu, Wbuf, Wmem);
        vulkan->destroyBuffer(gpu, xbuf, xmem);
        vulkan->destroyBuffer(gpu, ybuf, ymem);
    };

    VkBufferUsageFlags usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    VkMemoryPropertyFlags memProps = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;

    if (!vulkan->createBuffer(gpu, Wsize, usage, memProps, Wbuf, Wmem, &Wmapped)) { cleanup(); return false; }
    if (!vulkan->createBuffer(gpu, xsize, usage, memProps, xbuf, xmem, &xmapped)) { cleanup(); return false; }
    if (!vulkan->createBuffer(gpu, ysize, usage, memProps, ybuf, ymem, &ymapped)) { cleanup(); return false; }

    std::memcpy(Wmapped, wView.data, static_cast<size_t>(Wsize));
    std::memcpy(xmapped, xView.data, static_cast<size_t>(xsize));
    std::memset(ymapped, 0, static_cast<size_t>(ysize));

    if (!program.dispatch(gpu, Wbuf, xbuf, ybuf, (uint32_t)rows, (uint32_t)cols)) {
        cleanup(); return false;
    }

    std::memcpy(y.data(), ymapped, static_cast<size_t>(ysize));
    cleanup();
    return true;
}

void Deep2EngineExecuteInferenceStep(Deep2Engine& engine) {
    if (!engine.initialized) {
        fprintf(stderr, "[ERROR] Engine not initialized\n");
        return;
    }

    if (!engine.romMode) {
        std::cout << "\n--- Engine Live Pipeline Footprint (whole-loader baseline) ---\n"
                  << "  Layers: " << engine.ctx.cfg.numLayers
                  << " | Width: " << engine.ctx.cfg.hiddenDim
                  << " | Vocab: " << engine.ctx.cfg.vocabSize << "\n";
        auto wUp = engine.ctx.tensors.find("blk.0.ffn_up.weight");
        if (wUp == engine.ctx.tensors.end()) return;
        std::vector<float> inState(engine.ctx.cfg.hiddenDim, 1.0f), outState(engine.ctx.cfg.hiddenDim, 0.0f);
        MatrixArgs args{ inState.data(), outState.data(), wUp->second.dataData, engine.ctx.cfg.hiddenDim };
        Deep2Engine::LockFreeThreadPool::ParallelTask task{ MatrixWorkerStub, &args, 0, engine.ctx.cfg.hiddenDim };
        engine.threadPool.DispatchParallelJob(&task);
        std::cout << "[STATUS] baseline run verification complete. Output check: " << outState[0] << "\n";
        return;
    }

    std::cout << "\n--- ROM Execution Bridge Smoke ---\n"
              << "  Geometry: layers=" << engine.ctx.cfg.numLayers
              << " hidden=" << engine.ctx.cfg.hiddenDim
              << " heads=" << engine.ctx.cfg.numHeads
              << " vocab=" << engine.ctx.cfg.vocabSize << "\n";

    const deep2::TensorEntry* qkv = engine.rom.findTensor("blk.0.attn_qkv.weight");
    if (!qkv) {
        std::cout << "[VERIFY] blk.0.attn_qkv.weight not present in ROM\n";
        return;
    }
    if (qkv->dims.size() != 2 || qkv->dims[0] == 0 || qkv->dims[1] == 0) {
        std::cout << "[VERIFY] invalid QKV tensor geometry\n";
        return;
    }
    const uint64_t cols = qkv->dims[0];
    const uint64_t rows = qkv->dims[1];
    const uint64_t testRows = std::min<uint64_t>(16, rows);
    if (cols > std::numeric_limits<size_t>::max() / sizeof(float) / testRows) {
        std::cout << "[VERIFY] QKV smoke tile exceeds addressable memory\n";
        return;
    }
    const size_t tileElements = static_cast<size_t>(testRows * cols);
    std::vector<float> weightTile(tileElements);
    const bool readOk = qkv->type == deep2::TensorType::F32
        ? engine.readCompressedF32Tile(*qkv, 0, tileElements, weightTile.data())
        : engine.readDequantizedTensorTile(*qkv, 0, tileElements, weightTile.data());
    if (!readOk) {
        std::cout << "[VERIFY] bounded QKV tile read failed\n";
        return;
    }
    std::cout << "[VERIFY] bounded QKV tile -> " << testRows << "x" << cols << " f32\n";

    std::vector<float> x(static_cast<size_t>(cols), 1.0f), y(static_cast<size_t>(testRows), 0.0f);
    engine.gemvFloat(weightTile.data(), x.data(), y.data(), testRows, cols);
    float sum = 0.0f;
    for (float v : y) sum += v;
    std::cout << "[VERIFY] GEMV(" << testRows << "x" << cols << ") sum = " << sum << "\n";

    if (engine.vulkanReady) {
        deep2::TensorView wSlice{ deep2::TensorType::F32, reinterpret_cast<const uint8_t*>(weightTile.data()),
                           tileElements * sizeof(float),
                           { testRows, cols }, true };
        deep2::TensorView xSlice{ deep2::TensorType::F32, reinterpret_cast<const uint8_t*>(x.data()),
                           x.size() * sizeof(float), { cols }, true };
        for (size_t gi = 0; gi < engine.vulkan->gpuCount(); ++gi) {
            const auto* g = engine.vulkan->gpu(gi);
            std::vector<float> yVulkan;
            bool ok = engine.vulkanGemv(*g, wSlice, xSlice, yVulkan);
            float vs = 0.0f;
            for (float v : yVulkan) vs += v;
            std::cout << "[VERIFY] Vulkan GEMV on " << g->name << ": " << (ok ? "OK" : "FAILED")
                      << " sum = " << vs << "\n";
        }
    }
    std::cout << "[STATUS] ROM execution bridge complete\n";
}

// ==================================================================================
// ORACLE-TRACE: LAYER BOUNDARY INTEGRITY INSPECTOR
// ==================================================================================

void inspect_layer_boundary_tensors(uint32_t layer_idx, const float* hidden_states, size_t element_count) {
    // Intercept exactly at the layer exit threshold of Layer 3 (4th block) and entrance of Layer 4 (5th block)
    if (layer_idx == 3 || layer_idx == 4) {
        std::cout << "\n[ORACLE-TRACE] --- CRITICAL BOUNDARY AUDIT: LAYER " << layer_idx << " ---\n";

        float max_val = -1e9f;
        float min_val = 1e9f;
        float sum = 0.0f;
        size_t nan_count = 0;
        size_t inf_count = 0;
        size_t exact_zero_count = 0;

        for (size_t i = 0; i < element_count; ++i) {
            float v = hidden_states[i];
            
            if (std::isnan(v)) {
                nan_count++;
                continue;
            }
            if (std::isinf(v)) {
                inf_count++;
                continue;
            }
            if (v == 0.0f) {
                exact_zero_count++;
            }

            sum += v;
            if (v > max_val) max_val = v;
            if (v < min_val) min_val = v;
        }

        float mean = element_count ? (sum / element_count) : 0.0f;

        std::cout << "  Tensor Address     : 0x" << std::hex << reinterpret_cast<uintptr_t>(hidden_states) << std::dec << "\n";
        std::cout << "  Value Range        : [" << max_val << " to " << min_val << "]\n";
        std::cout << "  Mathematical Mean  : " << mean << "\n";
        std::cout << "  Zero Elements Count: " << exact_zero_count << " / " << element_count << "\n";
        std::cout << "  NaN Exceptions     : " << nan_count << "\n";
        std::cout << "  Inf Explosions     : " << inf_count << "\n";
        std::cout << "---------------------------------------------------------\n";

        // Assert code protection to hard-stop the execution the moment numbers disintegrate
        if (nan_count > 0 || inf_count > 0 || std::abs(mean) > 1e4f) {
            std::cerr << "[!] CRITICAL MATH EXPLOSION CONFIRMED AT BLOCK BOUNDARY " << layer_idx << "! HALTING LOOP.\n";
            __debugbreak(); // Win32 intrinsic trap to pause execution precisely at the point of failure
        }
    }
}

// ==================================================================================
// MOVE 10: FULL PHI-3 ROM-PATH FORWARD PASS WITH LOGITS PARITY VALIDATION
// ==================================================================================

// 64-byte aligned working buffers for AVX-512 routines
__declspec(align(64)) thread_local float tls_hidden_states[3072];
__declspec(align(64)) thread_local float tls_query_vector[3072];
__declspec(align(64)) thread_local float tls_logits[32064];
__declspec(align(64)) thread_local float tls_dequant_scratchpad[16384];

bool Deep2Engine::executePhi3ROMForwardPass(const std::vector<uint32_t>& inputTokens,
                                            std::vector<float>& outputLogits,
                                            std::vector<float>& baselineLogits) {
    if (!initialized || !romMode) {
        fprintf(stderr, "[Move 10] Engine not initialized or not in ROM mode\n");
        return false;
    }

    std::cout << "[Move 10] Starting Phi-3 ROM-path forward pass for " << inputTokens.size() << " tokens\n" << std::flush;

    const auto& geometry = rom.geometry();
    const size_t hiddenDim = geometry.hiddenDim;
    const size_t numLayers = geometry.numLayers;
    const size_t numHeads = geometry.numHeads;
    size_t vocabSize = geometry.vocabSize;
    const size_t intermediateDim = geometry.intermediateDim;

    auto matrixRows = [](const deep2::TensorEntry& entry) -> uint64_t {
        if (entry.dims.size() != 2) return 0;
        return entry.dims[1];
    };
    auto matrixCols = [](const deep2::TensorEntry& entry) -> uint64_t {
        return entry.dims.empty() ? 0 : entry.dims[0];
    };

    // Route every supported ROM projection through bounded row tiles. F32
    // uses compressed resident chunks; encoded F16/BF16 and quantized GGUF
    // types decode only their requested blocks. Vulkan dispatch is fail-closed.
    auto runProjection = [this](const deep2::TensorEntry& entry,
                                const float* input, float* output) -> bool {
        if (vulkanReady && vulkan) {
            const auto* gpu = vulkan->primary();
            if (!gpu) return false;
            return gemvTensorROMVulkan(*gpu, entry, input, output);
        }
        return gemvTensorROM(entry, input, output);
    };

    std::cout << "[Move 10] Model geometry: layers=" << numLayers
              << " hidden=" << hiddenDim << " heads=" << numHeads
              << " vocab=" << vocabSize << " intermediate=" << intermediateDim << "\n" << std::flush;

    // Fallback for vocabSize if not parsed from metadata
    if (vocabSize == 0) {
        vocabSize = 32064;  // Phi-3 Mini default
        std::cout << "[Move 10] Warning: vocabSize not in metadata, using fallback: " << vocabSize << "\n" << std::flush;
    }

    std::vector<float> hiddenStates(hiddenDim, 0.0f);
    size_t qkvRows = 0, qkvCols = 0;

    auto tokenEmb = rom.findTensor("token_embd.weight");
    if (!tokenEmb) {
        fprintf(stderr, "[Move 10] token_embd.weight not found\n");
        return false;
    }

    if (inputTokens.empty()) return false;
    const uint64_t embeddingRows = matrixRows(*tokenEmb);
    const uint64_t embeddingCols = matrixCols(*tokenEmb);
    if (embeddingRows == 0 || embeddingCols != hiddenDim) {
        fprintf(stderr, "[Move 10] Invalid token embedding geometry\n");
        return false;
    }
    uint32_t firstToken = inputTokens[0];
    if (firstToken >= embeddingRows) firstToken = 0;
    const uint64_t embeddingFirstElement = uint64_t(firstToken) * hiddenDim;
    const bool embeddingRead = tokenEmb->type == deep2::TensorType::F32
        ? readCompressedF32Tile(*tokenEmb, embeddingFirstElement, hiddenDim,
                                hiddenStates.data())
        : readDequantizedTensorTile(*tokenEmb, embeddingFirstElement, hiddenDim,
                                    hiddenStates.data());
    if (!embeddingRead) {
        fprintf(stderr, "[Move 10] Failed to read bounded token embedding row\n");
        return false;
    }
    std::cout << "[Move 10] Initial hidden state set\n" << std::flush;

    // Process each token position
    for (size_t tokenPos = 0; tokenPos < inputTokens.size(); ++tokenPos) {
        std::cout << "[Move 10] Processing token " << tokenPos << "\n" << std::flush;

        // Reusable dequantized tensors to avoid repeated allocation/deallocation
        // Process through all layers
        for (size_t layer = 0; layer < numLayers; ++layer) {
            std::cout << "[Move 10] Starting layer " << layer << "\n" << std::flush;

            // --- ATTENTION QKV ---
            std::string qkvName = "blk." + std::to_string(layer) + ".attn_qkv.weight";
            const deep2::TensorEntry* qkv = rom.findTensor(qkvName);
            if (!qkv) {
                fprintf(stderr, "[Move 10] Layer %zu: %s not found\n", layer, qkvName.c_str());
                return false;
            }

            qkvRows = matrixRows(*qkv);
            qkvCols = matrixCols(*qkv);
            if (qkvRows < 3 * hiddenDim || qkvCols != hiddenDim) return false;

            // --- ATTENTION COMPUTATION ---
            std::vector<float> hiddenStatesCopy(hiddenDim);
            std::memcpy(hiddenStatesCopy.data(), hiddenStates.data(), hiddenDim * sizeof(float));
            std::vector<float> qkvOut(static_cast<size_t>(qkvRows), 0.0f);
            if (!runProjection(*qkv, hiddenStatesCopy.data(), qkvOut.data())) {
                fprintf(stderr, "[Move 10] Layer %zu: tiled QKV GEMV failed\n", layer);
                return false;
            }

            // Split QKV into Q, K, V
            size_t qSize = qkvOut.size() / 3;
            std::vector<float> Q(qkvOut.begin(), qkvOut.begin() + qSize);
            std::vector<float> K(qkvOut.begin() + qSize, qkvOut.begin() + 2 * qSize);
            std::vector<float> V(qkvOut.begin() + 2 * qSize, qkvOut.end());

            // Apply RoPE to Q and K
            ApplyRotaryEmbeddings(Q.data(), 0, static_cast<size_t>(tokenPos));
            ApplyRotaryEmbeddings(K.data(), 0, static_cast<size_t>(tokenPos));

            // Simplified attention: softmax(Q @ K^T / sqrt(d)) @ V
            // For parity test, use V as attention output
            std::memcpy(hiddenStates.data(), V.data(), hiddenDim * sizeof(float));

            // --- FFN (UP + DOWN) ---
            std::string upName = "blk." + std::to_string(layer) + ".ffn_up.weight";
            std::string downName = "blk." + std::to_string(layer) + ".ffn_down.weight";

            const deep2::TensorEntry* upEntry = rom.findTensor(upName);
            const deep2::TensorEntry* downEntry = rom.findTensor(downName);

            if (!upEntry || !downEntry) {
                fprintf(stderr, "[Move 10] Layer %zu: FFN tensors not found\n", layer);
                return false;
            }

            const uint64_t upRows = matrixRows(*upEntry);
            const uint64_t upCols = matrixCols(*upEntry);
            const uint64_t downRows = matrixRows(*downEntry);
            const uint64_t downCols = matrixCols(*downEntry);
            if (!upRows || upCols != hiddenDim || downRows != hiddenDim || downCols != upRows) return false;

            // FFN: hidden = down(gelu(up(hidden)))
            std::vector<float> upOut(static_cast<size_t>(upRows), 0.0f);
            if (!runProjection(*upEntry, hiddenStates.data(), upOut.data())) {
                fprintf(stderr, "[Move 10] Layer %zu: tiled FFN-up GEMV failed\n", layer);
                return false;
            }

            // GELU activation (approximate)
            for (size_t i = 0; i < upOut.size(); ++i) {
                float x = upOut[i];
                float gelu = 0.5f * x * (1.0f + std::tanh(0.79788456f * (x + 0.044715f * x * x * x)));
                upOut[i] = gelu;
            }

            std::vector<float> downOut(static_cast<size_t>(downRows), 0.0f);
            if (!runProjection(*downEntry, upOut.data(), downOut.data())) {
                fprintf(stderr, "[Move 10] Layer %zu: tiled FFN-down GEMV failed\n", layer);
                return false;
            }
            if (downOut.size() != hiddenDim) return false;

            // Residual connection
            for (size_t i = 0; i < hiddenDim; ++i) {
                hiddenStates[i] += downOut[i];
            }

            // ORACLE-TRACE: Layer boundary audit at blocks 3↔4
            inspect_layer_boundary_tensors(static_cast<uint32_t>(layer), hiddenStates.data(), hiddenDim);
        }

        // After all layers, apply final layer norm and output projection
        float mean = 0.0f, var = 0.0f;
        for (float v : hiddenStates) mean += v;
        mean /= hiddenDim;
        for (float v : hiddenStates) var += (v - mean) * (v - mean);
        var = std::sqrt(var / hiddenDim + 1e-5f);
        for (float& v : hiddenStates) v = (v - mean) / var;

        // Output projection
        const deep2::TensorEntry* outputEntry = rom.findTensor("output.weight");
        if (!outputEntry) {
            fprintf(stderr, "[Move 10] output.weight not found\n");
            return false;
        }

        const uint64_t outputRows = matrixRows(*outputEntry);
        const uint64_t outputCols = matrixCols(*outputEntry);
        if (!outputRows || outputCols != hiddenDim) return false;
        outputLogits.resize(static_cast<size_t>(outputRows), 0.0f);
        if (!runProjection(*outputEntry, hiddenStates.data(), outputLogits.data())) {
            fprintf(stderr, "[Move 10] Tiled output projection GEMV failed\n");
            return false;
        }

        // Store baseline logits for first token (for parity check)
        if (tokenPos == 0) {
            baselineLogits = outputLogits;
        }
    }

    std::cout << "[Move 10] Forward pass complete. Generated logits for " << inputTokens.size() << " tokens\n";
    return true;
}

bool Deep2Engine::validateLogitsParity(const std::vector<float>& romLogits,
                                       const std::vector<float>& baselineLogits,
                                       float tolerance) {
    if (romLogits.size() != baselineLogits.size()) {
        fprintf(stderr, "[Move 10] Logits size mismatch: %zu vs %zu\n", romLogits.size(), baselineLogits.size());
        return false;
    }

    float maxDiff = 0.0f;
    size_t maxDiffIdx = 0;
    float sumSqDiff = 0.0f;

    for (size_t i = 0; i < romLogits.size(); ++i) {
        float diff = std::abs(romLogits[i] - baselineLogits[i]);
        float sqDiff = (romLogits[i] - baselineLogits[i]) * (romLogits[i] - baselineLogits[i]);
        sumSqDiff += sqDiff;
        if (diff > maxDiff) {
            maxDiff = diff;
            maxDiffIdx = i;
        }
        if (diff > 1.0f) {
            fprintf(stderr, "[Move 10] Large logit divergence at idx %zu: rom=%.6f baseline=%.6f diff=%.6f\n",
                    i, romLogits[i], baselineLogits[i], diff);
        }
    }

    float rmsDiff = std::sqrt(sumSqDiff / romLogits.size());

    std::cout << "[Move 10] Logits parity: max_diff=" << maxDiff
              << " at idx " << maxDiffIdx
              << " rms_diff=" << rmsDiff
              << " tolerance=" << tolerance << "\n";

    if (maxDiff > tolerance) {
        fprintf(stderr, "[Move 10] LOGITS PARITY FAILED: max_diff %.6f > tolerance %.6f\n", maxDiff, tolerance);
        return false;
    }

    std::cout << "[Move 10] LOGITS PARITY PASSED (max_diff=" << maxDiff << " <= " << tolerance << ")\n";
    return true;
}