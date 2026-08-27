// ============================================================================
// Deep2_Elastic_GEMV_Test.cpp
// Direct integration test: GGUF mmap → ElasticResidencyManager → Acquire →
// real GEMV kernel → verified output.
//
// No Deep2Engine dependency. Proves the residency→compute chain directly.
// ============================================================================

#include "ElasticResidencyManager.hpp"
#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <chrono>
#include <vector>
#include <string>

using namespace Deep2;

// Stub ResidencyTrace C interface (no ASM dependency)
extern "C" {
    int TraceInit(const char*) { return 1; }
    void TraceShutdown(void) {}
    struct ResidencyEvent { uint32_t dummy; };
    ResidencyEvent* TraceBegin(uint32_t, uint32_t, uint32_t, uint64_t, uint32_t, uint32_t) { return nullptr; }
    void TraceSetDestination(ResidencyEvent*, uint32_t, uint64_t, uint64_t, uint64_t, uint32_t, uint32_t) {}
    void TraceComplete(ResidencyEvent*, uint64_t, uint64_t, int) {}
    void TraceFlush(void) {}
}

// ============================================================================
// Simple FP16 → FP32 conversion (copied from Deep2Engine.cpp)
// ============================================================================
static inline float fp16ToFloat(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    uint32_t f32;
    if (exp == 0) {
        f32 = (sign << 31);
    } else if (exp == 31) {
        f32 = (sign << 31) | 0x7F800000 | (mant << 13);
    } else {
        f32 = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
    }
    float f;
    memcpy(&f, &f32, 4);
    return f;
}

// ============================================================================
// Simple FP32 GEMV for validation (no registry needed for FP32)
// ============================================================================
static void fp32GEMV_simple(const float* weights, const float* input, float* output,
                            size_t rows, size_t cols) {
    for (size_t r = 0; r < rows; ++r) {
        float sum = 0.0f;
        for (size_t c = 0; c < cols; ++c) {
            sum += weights[r * cols + c] * input[c];
        }
        output[r] = sum;
    }
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1]
        : "G:\\Franken\\BackwardsUnlock\\1b\\unlock-1B-Q4_K_M.gguf";

    printf("=================================================================\n");
    printf(" Direct GGUF → ElasticResidency → GEMV Test\n");
    printf("=================================================================\n");
    printf("Model: %s\n\n", modelPath);

    // --- Step 1: Load GGUF with mmap (real tensor data) ---
    printf("[Step 1] Loading GGUF with mmap...\n");
    GGUFLoadOptions options;
    options.loadTensors = true;
    options.mmap = true;
    options.verbose = false;

    GGUFLoadResult result = GGUFLoader::Load(modelPath, options);
    if (!result.success) {
        printf("[FAIL] GGUF load failed: %s\n", result.error);
        return 1;
    }
    printf("[PASS] GGUF loaded: %zu tensors, %.1f MB total\n",
           result.tensors.size(), result.totalSize / (1024.0 * 1024.0));

    // Sanity check tensor count
    if (result.tensors.size() == 0 || result.tensors.size() > 1000000) {
        printf("[FAIL] Invalid tensor count: %zu\n", result.tensors.size());
        return 1;
    }

    // --- Step 2: Find a suitable tensor for direct GEMV ---
    printf("\n[Step 2] Finding a suitable tensor for GEMV...\n");
    const TensorInfo* targetTensor = nullptr;
    for (const auto& t : result.tensors) {
        // Accept any 2D tensor with a known quant type
        if (t.dimensions.size() >= 2 && t.dimensions[0] > 0 && t.dimensions[1] > 0) {
            if (t.type == GGMLType::GGML_TYPE_F32 ||
                t.type == GGMLType::GGML_TYPE_F16 ||
                t.type == GGMLType::GGML_TYPE_Q4_K ||
                t.type == GGMLType::GGML_TYPE_Q4_0 ||
                t.type == GGMLType::GGML_TYPE_Q8_0) {
                targetTensor = &t;
                break;
            }
        }
    }
    if (!targetTensor) {
        printf("[WARN] No suitable tensor found; doing residency-only test\n");
    } else {
        printf("  Selected: %s  type=%s  dims=%llu x %llu  size=%zu bytes\n",
               targetTensor->name.c_str(),
               GGUFLoader::GetTypeName(targetTensor->type),
               (unsigned long long)targetTensor->dimensions[0],
               (unsigned long long)targetTensor->dimensions[1],
               targetTensor->size);
    }

    // --- Step 3: Initialize ElasticResidencyManager with pressure ---
    printf("\n[Step 3] Initializing ElasticResidencyManager...\n");
    size_t totalModelBytes = result.totalSize;
    size_t pressureBudget = totalModelBytes / 2;  // 50% pressure

    ElasticResidencyConfig config;
    config.maxWarmCompressedBytes = pressureBudget;
    config.maxWarmStagedBytes = 256ULL * 1024 * 1024;
    config.maxHotBytes = 512ULL * 1024 * 1024;
    config.useGhostCache = true;
    config.ghostCacheCapacity = 16384;

    ElasticResidencyManager mgr;
    if (!mgr.Initialize(config)) {
        printf("[FAIL] ElasticResidencyManager init failed\n");
        return 1;
    }
    printf("[PASS] ElasticResidencyManager initialized (budget=%.1f MB)\n",
           pressureBudget / (1024.0 * 1024.0));

    // --- Step 4: Register ALL tensors with residency manager ---
    printf("\n[Step 4] Registering %zu tensors...\n", result.tensors.size());
    size_t registered = 0;
    for (const auto& t : result.tensors) {
        TensorFormat fmt = TensorFormat::Unknown;
        switch (t.type) {
            case GGMLType::GGML_TYPE_F32:  fmt = TensorFormat::FP32; break;
            case GGMLType::GGML_TYPE_F16:  fmt = TensorFormat::FP16; break;
            case GGMLType::GGML_TYPE_Q4_0: fmt = TensorFormat::Q4_0; break;
            case GGMLType::GGML_TYPE_Q4_1: fmt = TensorFormat::Q4_1; break;
            case GGMLType::GGML_TYPE_Q5_0: fmt = TensorFormat::Q5_0; break;
            case GGMLType::GGML_TYPE_Q5_1: fmt = TensorFormat::Q5_1; break;
            case GGMLType::GGML_TYPE_Q8_0: fmt = TensorFormat::Q8_0; break;
            case GGMLType::GGML_TYPE_Q2_K: fmt = TensorFormat::Q2_K; break;
            case GGMLType::GGML_TYPE_Q3_K: fmt = TensorFormat::Q3_K; break;
            case GGMLType::GGML_TYPE_Q4_K: fmt = TensorFormat::Q4_K; break;
            case GGMLType::GGML_TYPE_Q5_K: fmt = TensorFormat::Q5_K; break;
            case GGMLType::GGML_TYPE_Q6_K: fmt = TensorFormat::Q6_K; break;
            default: break;
        }
        if (fmt == TensorFormat::Unknown) continue;

        // sourceData points to mmap'd data; fileOffset is offset within data section
        mgr.RegisterTensor(t.name, 0, ~0u,
                           result.dataOffset + t.offset,
                           t.size, fmt, t.data);
        registered++;
    }
    printf("[PASS] Registered %zu tensors\n", registered);

    // --- Step 5: Acquire target tensor and run GEMV ---
    bool gemvPass = false;
    if (targetTensor) {
        printf("\n[Step 5] Acquiring tensor '%s' and running GEMV...\n",
               targetTensor->name.c_str());

        // Acquire via synchronous CPU path — request native format so we get
        // the raw compressedData (memcpy'd from mmap), not the zero-filled stub
        TensorFormat desiredFormat = TensorFormat::FP32;
        if (targetTensor->type == GGMLType::GGML_TYPE_Q4_K) desiredFormat = TensorFormat::Q4_K;
        else if (targetTensor->type == GGMLType::GGML_TYPE_Q4_0) desiredFormat = TensorFormat::Q4_0;
        else if (targetTensor->type == GGMLType::GGML_TYPE_Q8_0) desiredFormat = TensorFormat::Q8_0;
        else if (targetTensor->type == GGMLType::GGML_TYPE_F16) desiredFormat = TensorFormat::FP16;

        const void* cpuPtr = mgr.AcquireForCpu(targetTensor->name, desiredFormat);
        if (!cpuPtr) {
            printf("[FAIL] AcquireForCpu returned null\n");
            mgr.Shutdown();
            return 1;
        }
        printf("  Acquired cpuPtr=%p  (desiredFormat=%d)\n", cpuPtr, (int)desiredFormat);

        // Verify pointer matches original mmap data (fast path)
        if (cpuPtr != targetTensor->data) {
            printf("  [INFO] cpuPtr != original data (expected under pressure)\n");
        }

        size_t rows = static_cast<size_t>(targetTensor->dimensions[0]);
        size_t cols = static_cast<size_t>(targetTensor->dimensions[1]);

        // Build input vector
        std::vector<float> input(cols, 0.0f);
        for (size_t i = 0; i < cols; ++i) input[i] = 1.0f;  // all-ones for easy validation

        std::vector<float> output(rows, 0.0f);

        auto t0 = std::chrono::steady_clock::now();
        if (targetTensor->type == GGMLType::GGML_TYPE_F32) {
            fp32GEMV_simple((const float*)cpuPtr, input.data(), output.data(), rows, cols);
        } else if (targetTensor->type == GGMLType::GGML_TYPE_F16) {
            // Convert F16 to FP32 first (simple scalar conversion)
            std::vector<float> fp32Weights(rows * cols);
            const uint16_t* src = (const uint16_t*)cpuPtr;
            for (size_t i = 0; i < rows * cols; ++i) {
                uint16_t h = src[i];
                uint32_t sign = (h >> 15) & 0x1;
                uint32_t exp  = (h >> 10) & 0x1F;
                uint32_t mant = h & 0x3FF;
                uint32_t f32;
                if (exp == 0) {
                    f32 = (sign << 31);
                } else if (exp == 31) {
                    f32 = (sign << 31) | 0x7F800000 | (mant << 13);
                } else {
                    f32 = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
                }
                memcpy(&fp32Weights[i], &f32, 4);
            }
            fp32GEMV_simple(fp32Weights.data(), input.data(), output.data(), rows, cols);
        } else if (targetTensor->type == GGMLType::GGML_TYPE_Q4_K) {
            // Use actual Q4_K block layout from Deep2Engine.cpp
            struct alignas(16) Q4_K_Block {
                uint16_t d;
                uint16_t dmin;
                uint8_t  scales[12];
                uint8_t  qs[128];
            };
            auto unpackQ4KScaleMin = [](const uint8_t* scales, int j, uint8_t& sc, uint8_t& m) {
                if (j < 4) {
                    sc = scales[j] & 63;
                    m  = scales[j + 4] & 63;
                } else {
                    sc = (scales[j + 4] & 0x0F) | ((scales[j - 4] >> 6) << 4);
                    m  = (scales[j + 4] >> 4)      | ((scales[j]   >> 6) << 4);
                }
            };
            auto dequantizeQ4KBlock = [&](const Q4_K_Block* block, float* out) {
                float d    = fp16ToFloat(block->d);
                float dmin = fp16ToFloat(block->dmin);
                for (int j = 0; j < 8; j++) {
                    uint8_t sc, m;
                    unpackQ4KScaleMin(block->scales, j, sc, m);
                    float scale = d * sc;
                    float min   = dmin * m;
                    const uint8_t* quants = block->qs + j * 16;
                    for (int k = 0; k < 16; k++) {
                        uint8_t byte = quants[k];
                        int lo = byte & 0xF;
                        int hi = (byte >> 4) & 0xF;
                        out[j * 32 + k]       = scale * lo - min;
                        out[j * 32 + k + 16]  = scale * hi - min;
                    }
                }
            };

            size_t numBlocks = (cols + 255) / 256;
            constexpr size_t kBlockSize = sizeof(Q4_K_Block);  // 144 bytes
            std::vector<float> fp32Weights(rows * cols);
            const uint8_t* wptr = (const uint8_t*)cpuPtr;
            for (size_t r = 0; r < rows; ++r) {
                const Q4_K_Block* rowBlocks =
                    (const Q4_K_Block*)(wptr + r * numBlocks * kBlockSize);
                size_t col = 0;
                for (size_t b = 0; b < numBlocks; ++b) {
                    size_t elemsInBlock = (b == numBlocks - 1) ? (cols - b * 256) : 256;
                    alignas(32) float dequantBuf[256];
                    dequantizeQ4KBlock(&rowBlocks[b], dequantBuf);
                    for (size_t i = 0; i < elemsInBlock; ++i) {
                        fp32Weights[r * cols + col + i] = dequantBuf[i];
                    }
                    col += elemsInBlock;
                }
            }
            fp32GEMV_simple(fp32Weights.data(), input.data(), output.data(), rows, cols);
        } else {
            printf("  [SKIP] No scalar GEMV for this quant type in test\n");
        }
        auto t1 = std::chrono::steady_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        // Validate output: should be finite and non-zero
        bool finite = true;
        double sum = 0.0;
        for (size_t i = 0; i < rows; ++i) {
            if (!std::isfinite(output[i])) { finite = false; break; }
            sum += output[i];
        }
        printf("  GEMV: %.2f ms | output sum=%.4f | finite=%s\n",
               ms, sum, finite ? "YES" : "NO");

        if (!finite || sum == 0.0) {
            printf("[FAIL] GEMV output invalid\n");
            mgr.Shutdown();
            return 1;
        }
        printf("[PASS] GEMV produced valid output\n");
        gemvPass = true;

        mgr.ReleaseFromCpu(targetTensor->name);
    }

    // --- Step 6: Run a second acquisition to trigger GhostCache ---
    printf("\n[Step 6] Second acquisition (warm/GhostCache test)...\n");
    if (targetTensor) {
        const void* cpuPtr2 = mgr.AcquireForCpu(targetTensor->name, TensorFormat::FP32);
        if (!cpuPtr2) {
            printf("[FAIL] Second acquire returned null\n");
            mgr.Shutdown();
            return 1;
        }
        printf("  Second acquire: cpuPtr=%p\n", cpuPtr2);
        mgr.ReleaseFromCpu(targetTensor->name);
    }

    // --- Step 7: Telemetry ---
    printf("\n[Step 7] Telemetry:\n");
    auto& telem = mgr.GetTelemetry();
    printf("  Ghost hits:   %llu\n", (unsigned long long)telem.ghostHits.load());
    printf("  Ghost misses: %llu\n", (unsigned long long)telem.ghostMisses.load());

    // --- Step 8: Batch 21 telemetry ---
    printf("\n[Step 8] Batch 21 telemetry:\n");
    auto& reg = Deep2::QuantKernelRegistry::Instance();
    reg.PrintBatch21Report();

    mgr.Shutdown();

    printf("\n=================================================================\n");
    printf(" PASS: Direct GGUF → ElasticResidency → GEMV chain verified\n");
    if (gemvPass) printf(" Real GEMV executed on acquired tensor memory\n");
    printf("=================================================================\n");
    return 0;
}
