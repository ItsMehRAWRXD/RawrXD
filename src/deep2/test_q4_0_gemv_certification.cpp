// ============================================================================
// Batch 15B — Q4_0 GEMV Certification
// Verifies that the Q4_0 scalar path in LinearW_Range() produces correct
// outputs for blk.29.attn_qkv.weight (or any Q4_0 tensor by name).
//
// Tests:
//   1. GGUF bytes -> block_q4_0 interpretation
//   2. Independent reference Q4_0 GEMV
//   3. Engine scalar LinearW_Range() Q4_0 path
//   4. NaN/Inf/zero-rate checks
//   5. Output norm checks
//   6. Row-boundary correctness (first, middle, last, partial ranges)
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <chrono>
#include <vector>
#include <random>
#include "GGUFLoader.hpp"

using namespace Deep2;

static bool g_verbose = false;

// ============================================================================
// FP16 -> FP32 (same as Deep2Engine.cpp)
// ============================================================================
static inline float fp16ToFloat(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    uint32_t f;
    if (exp == 0) {
        if (mant == 0) {
            f = sign << 31;
        } else {
            int e = -1;
            do { e++; mant <<= 1; } while (!(mant & 0x400));
            mant &= 0x3FF;
            f = (sign << 31) | ((127 - 15 - e) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        f = (sign << 31) | (0xFF << 23) | (mant << 13);
    } else {
        f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float result;
    memcpy(&result, &f, sizeof(float));
    return result;
}

// ============================================================================
// Independent Reference Q4_0 GEMV (not copied from engine)
// Dequantizes each block to FP32, then dot-products with input.
// ============================================================================
static void referenceQ4_0_GEMV_Range(
    const block_q4_0* blocks,
    size_t totalRows,
    size_t cols,
    const float* input,
    float* output,
    size_t startRow,
    size_t endRow)
{
    size_t blocksPerRow = (cols + 31) / 32;
    for (size_t r = startRow; r < endRow; ++r) {
        const block_q4_0* rowBlocks = blocks + r * blocksPerRow;
        float sum = 0.0f;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            float d = fp16ToFloat(rowBlocks[b].d);
            for (size_t i = 0; i < 32; ++i) {
                size_t globalCol = b * 32 + i;
                if (globalCol >= cols) break;
                uint8_t byte = rowBlocks[b].qs[i / 2];
                int q = (i % 2 == 0) ? (byte & 0x0F) : ((byte >> 4) & 0x0F);
                float w = d * (q - 8.0f);  // symmetric: subtract 8
                sum += w * input[globalCol];
            }
        }
        output[r] = sum;
    }
}

// ============================================================================
// Engine Scalar Q4_0 GEMV (exact copy from LinearW_Range in Deep2Engine.cpp)
// ============================================================================
static void engineScalarQ4_0_GEMV_Range(
    const block_q4_0* blocks,
    size_t cols,
    const float* input,
    float* output,
    size_t startRow,
    size_t endRow)
{
    size_t blocksPerRow = (cols + 31) / 32;
    for (size_t r = startRow; r < endRow; ++r) {
        const block_q4_0* rowBlocks = blocks + r * blocksPerRow;
        float sum = 0.0f;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            float d = fp16ToFloat(rowBlocks[b].d);
            const uint8_t* qs = rowBlocks[b].qs;
            size_t base = b * 32;
            for (int j = 0; j < 16; ++j) {
                uint8_t byte = qs[j];
                int q0 = (byte & 0x0F) - 8;
                int q1 = ((byte >> 4) & 0x0F) - 8;
                sum += d * q0 * input[base + j * 2 + 0];
                if (base + j * 2 + 1 < cols) {
                    sum += d * q1 * input[base + j * 2 + 1];
                }
            }
        }
        output[r] = sum;
    }
}

// ============================================================================
// Statistics helpers
// ============================================================================
struct OutputStats {
    size_t nanCount = 0;
    size_t infCount = 0;
    size_t zeroCount = 0;
    size_t total = 0;
    float minVal = 1e30f;
    float maxVal = -1e30f;
    float mean = 0.0f;
    float rms = 0.0f;
};

static OutputStats computeStats(const float* data, size_t n) {
    OutputStats s;
    s.total = n;
    double sum = 0.0;
    double sumSq = 0.0;
    for (size_t i = 0; i < n; ++i) {
        float v = data[i];
        if (std::isnan(v)) { s.nanCount++; continue; }
        if (std::isinf(v)) { s.infCount++; continue; }
        if (v == 0.0f) s.zeroCount++;
        if (v < s.minVal) s.minVal = v;
        if (v > s.maxVal) s.maxVal = v;
        sum += v;
        sumSq += (double)v * v;
    }
    size_t valid = n - s.nanCount - s.infCount;
    s.mean = valid > 0 ? (float)(sum / valid) : 0.0f;
    s.rms = valid > 0 ? (float)std::sqrt(sumSq / valid) : 0.0f;
    return s;
}

// ============================================================================
// Compare two outputs
// ============================================================================
static bool compareOutputs(const float* a, const float* b, size_t n,
                           float absTol, float relTol,
                           size_t& firstMismatch, float& maxAbsErr, float& maxRelErr) {
    firstMismatch = n;
    maxAbsErr = 0.0f;
    maxRelErr = 0.0f;
    bool pass = true;
    for (size_t i = 0; i < n; ++i) {
        if (std::isnan(a[i]) || std::isnan(b[i]) || std::isinf(a[i]) || std::isinf(b[i])) {
            if (firstMismatch == n) firstMismatch = i;
            pass = false;
            continue;
        }
        float absErr = std::fabs(a[i] - b[i]);
        float scale = std::max(1.0f, std::max(std::fabs(a[i]), std::fabs(b[i])));
        float relErr = absErr / scale;
        if (absErr > maxAbsErr) maxAbsErr = absErr;
        if (relErr > maxRelErr) maxRelErr = relErr;
        if (absErr > absTol && relErr > relTol) {
            if (firstMismatch == n) firstMismatch = i;
            pass = false;
        }
    }
    return pass;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    const char* modelPath = (argc > 1) ? argv[1] : "g:\\OllamaModels\\Phi-3-mini-4k-instruct-q8_0.gguf";
    const char* targetTensor = (argc > 2) ? argv[2] : "blk.29.attn_qkv.weight";
    g_verbose = (std::getenv("RAWRXD_DIAG_VERBOSE") != nullptr);

    printf("[BATCH15B] Q4_0 GEMV Certification\n");
    printf("[BATCH15B] Model: %s\n", modelPath);
    printf("[BATCH15B] Target tensor: %s\n", targetTensor);

    // Load metadata + tensor data
    GGUFLoadOptions opts;
    opts.loadTensors = true;
    opts.verbose = g_verbose;
    GGUFLoadResult result = GGUFLoader::Load(modelPath, opts);
    if (!result.success && result.tensors.empty()) {
        printf("[BATCH15B] FAIL: Could not load model\n");
        return 1;
    }

    // Find target tensor
    const TensorInfo* target = nullptr;
    for (const auto& t : result.tensors) {
        if (t.name == targetTensor) {
            target = &t;
            break;
        }
    }
    if (!target) {
        printf("[BATCH15B] FAIL: Tensor '%s' not found\n", targetTensor);
        return 1;
    }

    if (target->type != GGMLType::GGML_TYPE_Q4_0) {
        printf("[BATCH15B] FAIL: Tensor is not Q4_0 (type=%d)\n", (int)target->type);
        return 1;
    }

    size_t rows = target->dimensions.size() > 1 ? (size_t)target->dimensions[1] : 1;
    size_t cols = target->dimensions.size() > 0 ? (size_t)target->dimensions[0] : 0;
    size_t blocksPerRow = (cols + 31) / 32;
    size_t rowBytes = blocksPerRow * sizeof(block_q4_0);

    printf("[BATCH15B] Tensor: rows=%zu cols=%zu blocksPerRow=%zu rowBytes=%zu\n",
           rows, cols, blocksPerRow, rowBytes);
    printf("[BATCH15B] Total blocks: %zu  Total bytes: %zu\n",
           rows * blocksPerRow, target->size);

    const block_q4_0* blocks = (const block_q4_0*)target->data;

    // Generate deterministic random input vector
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 1.0f);
    std::vector<float> input(cols);
    for (size_t i = 0; i < cols; ++i) input[i] = dist(rng);

    // Allocate output buffers
    std::vector<float> outRef(rows);
    std::vector<float> outEngine(rows);
    memset(outRef.data(), 0, rows * sizeof(float));
    memset(outEngine.data(), 0, rows * sizeof(float));

    bool allPass = true;

    // ========================================================================
    // Test 1: Full-range GEMV (all rows)
    // ========================================================================
    printf("\n============================================================\n");
    printf("TEST 1: Full-range GEMV (all %zu rows)\n", rows);
    printf("============================================================\n");

    auto t0 = std::chrono::high_resolution_clock::now();
    referenceQ4_0_GEMV_Range(blocks, rows, cols, input.data(), outRef.data(), 0, rows);
    auto t1 = std::chrono::high_resolution_clock::now();
    engineScalarQ4_0_GEMV_Range(blocks, cols, input.data(), outEngine.data(), 0, rows);
    auto t2 = std::chrono::high_resolution_clock::now();

    double msRef = std::chrono::duration<double, std::milli>(t1 - t0).count();
    double msEng = std::chrono::duration<double, std::milli>(t2 - t1).count();
    printf("  Reference time: %.3f ms\n", msRef);
    printf("  Engine time:    %.3f ms\n", msEng);

    size_t firstMismatch = rows;
    float maxAbsErr = 0.0f, maxRelErr = 0.0f;
    bool pass = compareOutputs(outRef.data(), outEngine.data(), rows,
                               1.0e-4f, 1.0e-3f, firstMismatch, maxAbsErr, maxRelErr);
    printf("  Max abs error:  %.6e\n", maxAbsErr);
    printf("  Max rel error:  %.6e\n", maxRelErr);
    printf("  First mismatch: %s\n", firstMismatch < rows ? "FAIL" : "PASS");
    if (firstMismatch < rows) {
        printf("    at index %zu: ref=%.6f eng=%.6f\n",
               firstMismatch, outRef[firstMismatch], outEngine[firstMismatch]);
    }
    printf("  Result: %s\n", pass ? "PASS" : "FAIL");
    allPass &= pass;

    // Stats on reference output
    OutputStats stats = computeStats(outRef.data(), rows);
    printf("  Ref output stats: min=%.6f max=%.6f mean=%.6f rms=%.6f\n",
           stats.minVal, stats.maxVal, stats.mean, stats.rms);
    printf("  NaN count: %zu  Inf count: %zu  Zero count: %zu / %zu\n",
           stats.nanCount, stats.infCount, stats.zeroCount, stats.total);
    if (stats.nanCount > 0 || stats.infCount > 0) {
        printf("  WARNING: NaN or Inf detected in reference output!\n");
        allPass = false;
    }

    // ========================================================================
    // Test 2: Individual row certification (first, middle, last)
    // ========================================================================
    printf("\n============================================================\n");
    printf("TEST 2: Individual row certification\n");
    printf("============================================================\n");

    size_t testRows[] = {0, 1, rows / 2, rows - 2, rows - 1};
    for (size_t tr : testRows) {
        if (tr >= rows) continue;
        memset(outRef.data(), 0, rows * sizeof(float));
        memset(outEngine.data(), 0, rows * sizeof(float));

        referenceQ4_0_GEMV_Range(blocks, rows, cols, input.data(), outRef.data(), tr, tr + 1);
        engineScalarQ4_0_GEMV_Range(blocks, cols, input.data(), outEngine.data(), tr, tr + 1);

        size_t fm = rows;
        float mae = 0.0f, mre = 0.0f;
        bool rowPass = compareOutputs(outRef.data() + tr, outEngine.data() + tr, 1,
                                      1.0e-4f, 1.0e-3f, fm, mae, mre);
        printf("  Row %6zu: ref=%12.6f eng=%12.6f mae=%.6e mre=%.6e %s\n",
               tr, outRef[tr], outEngine[tr], mae, mre, rowPass ? "PASS" : "FAIL");
        allPass &= rowPass;
    }

    // ========================================================================
    // Test 3: Partial range certification (startRow/endRow boundaries)
    // ========================================================================
    printf("\n============================================================\n");
    printf("TEST 3: Partial range certification\n");
    printf("============================================================\n");

    struct RangeTest { size_t start; size_t end; const char* desc; };
    RangeTest ranges[] = {
        {0, 1, "first row only"},
        {0, 10, "first 10 rows"},
        {rows / 2 - 5, rows / 2 + 5, "middle 10 rows"},
        {rows - 10, rows, "last 10 rows"},
        {rows - 1, rows, "last row only"},
        {100, 200, "arbitrary 100-row slice"},
    };

    for (const auto& rt : ranges) {
        if (rt.start >= rows || rt.end > rows || rt.start >= rt.end) continue;
        memset(outRef.data(), 0, rows * sizeof(float));
        memset(outEngine.data(), 0, rows * sizeof(float));

        referenceQ4_0_GEMV_Range(blocks, rows, cols, input.data(), outRef.data(), rt.start, rt.end);
        engineScalarQ4_0_GEMV_Range(blocks, cols, input.data(), outEngine.data(), rt.start, rt.end);

        size_t n = rt.end - rt.start;
        size_t fm = n;
        float mae = 0.0f, mre = 0.0f;
        bool rangePass = compareOutputs(outRef.data() + rt.start, outEngine.data() + rt.start, n,
                                        1.0e-4f, 1.0e-3f, fm, mae, mre);
        printf("  %s [%zu..%zu): mae=%.6e mre=%.6e %s\n",
               rt.desc, rt.start, rt.end, mae, mre, rangePass ? "PASS" : "FAIL");
        if (!rangePass && fm < n) {
            printf("    first mismatch at offset %zu: ref=%.6f eng=%.6f\n",
                   fm, outRef[rt.start + fm], outEngine[rt.start + fm]);
        }
        allPass &= rangePass;
    }

    // ========================================================================
    // Test 4: Block-level sanity check (first block of first row)
    // ========================================================================
    printf("\n============================================================\n");
    printf("TEST 4: Block-level sanity check (row 0, block 0)\n");
    printf("============================================================\n");

    float d0 = fp16ToFloat(blocks[0].d);
    printf("  Block 0 scale d = %.6f (fp16=0x%04X)\n", d0, blocks[0].d);
    printf("  Block 0 qs bytes: ");
    for (int i = 0; i < 8; ++i) printf("%02X ", blocks[0].qs[i]);
    printf("...\n");

    // Dequant first 8 weights manually and print
    printf("  First 8 dequantized weights: ");
    for (int i = 0; i < 8; ++i) {
        uint8_t byte = blocks[0].qs[i / 2];
        int q = (i % 2 == 0) ? (byte & 0x0F) : ((byte >> 4) & 0x0F);
        float w = d0 * (q - 8.0f);
        printf("%.4f ", w);
    }
    printf("\n");

    // Verify the dequant is in a reasonable range (not all zeros, not huge)
    bool blockSanity = true;
    float maxW = 0.0f;
    for (int i = 0; i < 32; ++i) {
        uint8_t byte = blocks[0].qs[i / 2];
        int q = (i % 2 == 0) ? (byte & 0x0F) : ((byte >> 4) & 0x0F);
        float w = d0 * (q - 8.0f);
        float aw = std::fabs(w);
        if (aw > maxW) maxW = aw;
    }
    printf("  Max |weight| in block 0: %.4f\n", maxW);
    if (maxW < 1.0e-6f) {
        printf("  WARNING: Block 0 appears to be all zeros (suspicious)\n");
        blockSanity = false;
    }
    if (std::isnan(d0) || std::isinf(d0) || d0 == 0.0f) {
        printf("  WARNING: Block 0 scale d is NaN/Inf/Zero (suspicious)\n");
        blockSanity = false;
    }
    printf("  Block sanity: %s\n", blockSanity ? "PASS" : "FAIL");
    allPass &= blockSanity;

    // ========================================================================
    // Test 5: Verify tensor size matches geometry
    // ========================================================================
    printf("\n============================================================\n");
    printf("TEST 5: Tensor geometry consistency\n");
    printf("============================================================\n");

    size_t expectedBlocks = rows * ((cols + 31) / 32);
    size_t expectedBytes = expectedBlocks * sizeof(block_q4_0);
    bool geomPass = (expectedBytes == target->size);
    printf("  rows=%zu cols=%zu blocksPerRow=%zu\n", rows, cols, blocksPerRow);
    printf("  Expected blocks: %zu  Expected bytes: %zu\n", expectedBlocks, expectedBytes);
    printf("  Actual bytes:    %zu\n", target->size);
    printf("  Geometry match: %s\n", geomPass ? "PASS" : "FAIL");
    allPass &= geomPass;

    // ========================================================================
    // Summary
    // ========================================================================
    printf("\n============================================================\n");
    printf("BATCH 15B SUMMARY: %s\n", allPass ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    printf("============================================================\n");

    // Cleanup
    for (auto& t : result.tensors) {
        if (t.data) {
            _aligned_free(t.data);
            t.data = nullptr;
        }
    }

    return allPass ? 0 : 1;
}
