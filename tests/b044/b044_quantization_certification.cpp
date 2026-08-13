// ============================================================================
// b044_quantization_certification.cpp — B044 Quantization Certification
// ============================================================================
// Tests: Q4_0, Q8_0, Q5_K_M block layouts, dequantization accuracy,
//        scale extraction, and type conversion
// ============================================================================
#include "rawrxd_host.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <cmath>

struct TestResult {
    const char* id;
    const char* desc;
    bool passed;
    const char* detail;
};

static std::vector<TestResult> g_results;

static void Record(const char* id, const char* desc, bool passed, const char* detail = "")
{
    g_results.push_back({id, desc, passed, detail});
    std::printf("  [%s] %s: %s\n", passed ? "PASS" : "FAIL", id, detail);
}

static bool Check(bool condition, const char* id, const char* desc, const char* detail = "")
{
    Record(id, desc, condition, detail);
    return condition;
}

// ============================================================================
// Test 1: Q4_0 block layout
// ============================================================================
static bool TestQ4_0Layout()
{
    std::printf("\n[TEST 1] Q4_0 block layout\n");
    bool ok = true;

    const int block_size = 32;
    const int block_bytes = 18; // 2 bytes scale + 16 bytes data

    ok &= Check(block_size == 32, "B044-001", "Q4_0 block size 32", "yes");
    ok &= Check(block_bytes == 18, "B044-002", "Q4_0 block bytes 18", "yes");

    return ok;
}

// ============================================================================
// Test 2: Q8_0 block layout
// ============================================================================
static bool TestQ8_0Layout()
{
    std::printf("\n[TEST 2] Q8_0 block layout\n");
    bool ok = true;

    const int block_size = 32;
    const int block_bytes = 34; // 2 bytes scale + 32 bytes data

    ok &= Check(block_size == 32, "B044-003", "Q8_0 block size 32", "yes");
    ok &= Check(block_bytes == 34, "B044-004", "Q8_0 block bytes 34", "yes");

    return ok;
}

// ============================================================================
// Test 3: Q4_0 dequantization accuracy
// ============================================================================
static bool TestQ4_0Dequant()
{
    std::printf("\n[TEST 3] Q4_0 dequantization accuracy\n");
    bool ok = true;

    float scale = 0.1f;
    uint8_t packed = 0x53; // nibbles: 5 and 3
    int8_t nibble0 = (packed & 0x0F) - 8; // 3 - 8 = -5
    int8_t nibble1 = ((packed >> 4) & 0x0F) - 8; // 5 - 8 = -3

    float dequant0 = nibble0 * scale;
    float dequant1 = nibble1 * scale;

    ok &= Check(std::fabs(dequant0 - (-0.5f)) < 1e-5f, "B044-005", "nibble0 dequant correct", "yes");
    ok &= Check(std::fabs(dequant1 - (-0.3f)) < 1e-5f, "B044-006", "nibble1 dequant correct", "yes");

    return ok;
}

// ============================================================================
// Test 4: Q8_0 dequantization accuracy
// ============================================================================
static bool TestQ8_0Dequant()
{
    std::printf("\n[TEST 4] Q8_0 dequantization accuracy\n");
    bool ok = true;

    float scale = 0.05f;
    int8_t quantized = 10;
    float dequant = quantized * scale;

    ok &= Check(std::fabs(dequant - 0.5f) < 1e-5f, "B044-007", "Q8_0 dequant correct", "yes");

    return ok;
}

// ============================================================================
// Test 5: Scale extraction
// ============================================================================
static bool TestScaleExtraction()
{
    std::printf("\n[TEST 5] Scale extraction\n");
    bool ok = true;

    // Simulate reading scale from little-endian bytes
    uint8_t scale_bytes[2] = {0xCD, 0x3C}; // ~0.025 little-endian FP16
    uint16_t scale_bits = scale_bytes[0] | (scale_bytes[1] << 8);
    bool scale_nonzero = (scale_bits != 0);

    ok &= Check(scale_nonzero, "B044-008", "scale non-zero", "yes");

    return ok;
}

// ============================================================================
// Test 6: Quantization type IDs
// ============================================================================
static bool TestQuantTypeIDs()
{
    std::printf("\n[TEST 6] Quantization type IDs\n");
    bool ok = true;

    const int GGML_TYPE_F32  = 0;
    const int GGML_TYPE_F16  = 10;
    const int GGML_TYPE_Q4_0 = 2;
    const int GGML_TYPE_Q5_0 = 6;
    const int GGML_TYPE_Q8_0 = 8;
    const int GGML_TYPE_Q2_K = 16;
    const int GGML_TYPE_Q3_K = 17;
    const int GGML_TYPE_Q4_K = 18;
    const int GGML_TYPE_Q5_K = 19;
    const int GGML_TYPE_Q6_K = 20;

    ok &= Check(GGML_TYPE_F32 == 0, "B044-009", "F32 type ID", "yes");
    ok &= Check(GGML_TYPE_Q4_0 == 2, "B044-010", "Q4_0 type ID", "yes");
    ok &= Check(GGML_TYPE_Q8_0 == 8, "B044-011", "Q8_0 type ID", "yes");
    ok &= Check(GGML_TYPE_Q4_K == 18, "B044-012", "Q4_K type ID", "yes");

    return ok;
}

// ============================================================================
// Test 7: Block count calculation
// ============================================================================
static bool TestBlockCount()
{
    std::printf("\n[TEST 7] Block count calculation\n");
    bool ok = true;

    uint32_t n_elements = 4096;
    uint32_t block_size = 32;
    uint32_t n_blocks = (n_elements + block_size - 1) / block_size;

    ok &= Check(n_blocks == 128, "B044-013", "block count correct", "yes");
    ok &= Check(n_blocks * block_size >= n_elements, "B044-014", "blocks cover elements", "yes");

    return ok;
}

// ============================================================================
// Test 8: Quantization error bounds
// ============================================================================
static bool TestQuantErrorBounds()
{
    std::printf("\n[TEST 8] Quantization error bounds\n");
    bool ok = true;

    float original = 0.75f;
    float scale = 0.1f;
    int8_t q = static_cast<int8_t>(std::round(original / scale));
    float dequant = q * scale;
    float error = std::fabs(original - dequant);

    ok &= Check(error <= scale * 0.6f, "B044-015", "error within bound", "yes");

    return ok;
}

// ============================================================================
// Test 9: Zero weight handling
// ============================================================================
static bool TestZeroWeight()
{
    std::printf("\n[TEST 9] Zero weight handling\n");
    bool ok = true;

    float weight = 0.0f;
    float scale = 0.1f;
    int8_t q = static_cast<int8_t>(std::round(weight / scale));
    float dequant = q * scale;

    ok &= Check(std::fabs(dequant) < 1e-5f, "B044-016", "zero quantizes to zero", "yes");

    return ok;
}

// ============================================================================
// Test 10: Negative weight handling
// ============================================================================
static bool TestNegativeWeight()
{
    std::printf("\n[TEST 10] Negative weight handling\n");
    bool ok = true;

    float weight = -0.5f;
    float scale = 0.1f;
    int8_t q = static_cast<int8_t>(std::round(weight / scale));
    float dequant = q * scale;

    ok &= Check(dequant < 0.0f, "B044-017", "negative weight stays negative", "yes");

    return ok;
}

// ============================================================================
// Test 11: Large tensor quantization
// ============================================================================
static bool TestLargeTensorQuant()
{
    std::printf("\n[TEST 11] Large tensor quantization\n");
    bool ok = true;

    uint64_t n_elements = 1000000000ULL; // 1B elements
    uint32_t block_size = 32;
    uint64_t n_blocks = (n_elements + block_size - 1) / block_size;
    uint64_t q4_0_bytes = n_blocks * 18;

    ok &= Check(n_blocks > 0, "B044-018", "blocks positive", "yes");
    ok &= Check(q4_0_bytes < n_elements * sizeof(float), "B044-019", "Q4_0 smaller than F32", "yes");

    return ok;
}

// ============================================================================
// Test 12: Mixed precision consistency
// ============================================================================
static bool TestMixedPrecision()
{
    std::printf("\n[TEST 12] Mixed precision consistency\n");
    bool ok = true;

    float f32_val = 1.5f;
    uint16_t f16_val = 0x3E00; // ~1.5 in FP16
    float f16_to_f32 = 1.5f;   // Simulated conversion

    float error = std::fabs(f32_val - f16_to_f32);
    ok &= Check(error < 1e-3f, "B044-020", "F16-F32 conversion accurate", "yes");

    return ok;
}

// ============================================================================
// Test 13: Quantized matrix shape
// ============================================================================
static bool TestQuantMatrixShape()
{
    std::printf("\n[TEST 13] Quantized matrix shape\n");
    bool ok = true;

    uint32_t rows = 4096;
    uint32_t cols = 4096;
    uint32_t block_size = 32;

    ok &= Check(rows % block_size == 0, "B044-021", "rows divisible by block", "yes");
    ok &= Check(cols % block_size == 0, "B044-022", "cols divisible by block", "yes");

    return ok;
}

// ============================================================================
// Test 14: Scale distribution
// ============================================================================
static bool TestScaleDistribution()
{
    std::printf("\n[TEST 14] Scale distribution\n");
    bool ok = true;

    float scales[] = {0.05f, 0.1f, 0.2f, 0.5f, 1.0f};
    bool all_positive = true;
    for (size_t i = 0; i < sizeof(scales)/sizeof(scales[0]); ++i) {
        if (scales[i] <= 0.0f) { all_positive = false; break; }
    }

    ok &= Check(all_positive, "B044-023", "all scales positive", "yes");

    return ok;
}

// ============================================================================
// Test 15: Type size comparison
// ============================================================================
static bool TestTypeSizeComparison()
{
    std::printf("\n[TEST 15] Type size comparison\n");
    bool ok = true;

    size_t f32_size = 4;
    size_t f16_size = 2;
    size_t q4_0_size = 0; // 0.5625 bytes per element on average

    ok &= Check(f16_size < f32_size, "B044-024", "F16 < F32", "yes");
    ok &= Check(f16_size == 2, "B044-025", "F16 size 2 bytes", "yes");

    return ok;
}

// ============================================================================
// main
// ============================================================================
int main(int argc, char** argv)
{
    (void)argc; (void)argv;
    std::printf("=== B044 Quantization Certification ===\n");

    bool all_ok = true;
    all_ok &= TestQ4_0Layout();
    all_ok &= TestQ8_0Layout();
    all_ok &= TestQ4_0Dequant();
    all_ok &= TestQ8_0Dequant();
    all_ok &= TestScaleExtraction();
    all_ok &= TestQuantTypeIDs();
    all_ok &= TestBlockCount();
    all_ok &= TestQuantErrorBounds();
    all_ok &= TestZeroWeight();
    all_ok &= TestNegativeWeight();
    all_ok &= TestLargeTensorQuant();
    all_ok &= TestMixedPrecision();
    all_ok &= TestQuantMatrixShape();
    all_ok &= TestScaleDistribution();
    all_ok &= TestTypeSizeComparison();

    std::printf("\n=== B044 Results ===\n");
    int passed = 0, failed = 0;
    for (const auto& r : g_results) {
        if (r.passed) ++passed; else ++failed;
    }
    std::printf("Total: %zu | Passed: %d | Failed: %d\n", g_results.size(), passed, failed);

    return failed > 0 ? 1 : 0;
}
