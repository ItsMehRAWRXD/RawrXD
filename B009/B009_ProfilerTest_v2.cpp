// ================================================================================================
// Negative Space Profiler Test Harness v2
// Demonstrates detection of superficial batching in B009-style architecture.
// ================================================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>

// --- Profiler API (exported from NegativeSpaceProfiler_v2.asm) ---
extern "C" {
    void Profiler_Initialize();
    void Profiler_SetBatchContext(unsigned long long batchSize);
    unsigned long long Profiler_ReadTsc();
    void Profiler_TrackCall(unsigned long long startCycles);
    void Profiler_AnalyzeBottlenecks();
}

// --- Simulated B009 Anti-Pattern: StreamingMatMul called T times per batch ---
void StreamingMatMul_Simulated(const float* weights, const float* input, float* output,
                                int hidden_dim) {
    volatile float sum = 0.0f;
    for (int i = 0; i < hidden_dim; ++i) {
        sum += weights[i] * input[i];
    }
    *output = sum;
}

// --- Profiled wrapper for the simulated kernel ---
void Profiled_StreamingMatMul(const float* weights, const float* input, float* output,
                               int hidden_dim) {
    unsigned long long start = Profiler_ReadTsc();
    StreamingMatMul_Simulated(weights, input, output, hidden_dim);
    Profiler_TrackCall(start);
}

// --- B009 Anti-Pattern: ForwardBatch that loops over tokens ---
void ForwardBatch_AntiPattern(const float* weights, const float* input_batch,
                               float* output_batch, int hidden_dim, int out_dim, int T) {
    Profiler_SetBatchContext(T);

    for (int row = 0; row < out_dim; ++row) {
        for (int t = 0; t < T; ++t) {
            const float* input_token = input_batch + (t * hidden_dim);
            float* output_scalar = output_batch + (t * out_dim) + row;
            Profiled_StreamingMatMul(weights + (row * hidden_dim), input_token, output_scalar, hidden_dim);
        }
    }
}

// --- Correct Pattern: True Batched GEMM (for comparison) ---
void ForwardBatch_TrueBatched(const float* weights, const float* input_batch,
                               float* output_batch, int hidden_dim, int out_dim, int T) {
    Profiler_SetBatchContext(T);

    for (int row = 0; row < out_dim; ++row) {
        unsigned long long start = Profiler_ReadTsc();

        for (int t = 0; t < T; ++t) {
            const float* input_token = input_batch + (t * hidden_dim);
            float* output_scalar = output_batch + (t * out_dim) + row;

            volatile float sum = 0.0f;
            for (int i = 0; i < hidden_dim; ++i) {
                sum += weights[row * hidden_dim + i] * input_token[i];
            }
            *output_scalar = sum;
        }

        Profiler_TrackCall(start);
    }
}

// --- Main Test Harness ---
int main() {
    printf("B009 Negative Space Profiler Test Harness v2\n");
    printf("=============================================\n\n");

    Profiler_Initialize();

    const int hidden_dim = 128;
    const int out_dim = 4;
    const int T = 32;

    float* weights = (float*)malloc(hidden_dim * out_dim * sizeof(float));
    float* input_batch = (float*)malloc(hidden_dim * T * sizeof(float));
    float* output_batch = (float*)malloc(out_dim * T * sizeof(float));

    for (int i = 0; i < hidden_dim * out_dim; ++i) weights[i] = 0.01f;
    for (int i = 0; i < hidden_dim * T; ++i) input_batch[i] = 0.5f;
    memset(output_batch, 0, out_dim * T * sizeof(float));

    // === TEST 1: Anti-Pattern (Superficial Batching) ===
    printf("[TEST 1] Running ANTI-PATTERN: ForwardBatch with token-by-token loop...\n");
    printf("         Expected: T=32, call_count=%d (32 tokens * 4 rows)\n\n", T * out_dim);
    ForwardBatch_AntiPattern(weights, input_batch, output_batch, hidden_dim, out_dim, T);
    Profiler_AnalyzeBottlenecks();

    // === TEST 2: True Batched (for comparison) ===
    printf("\n[TEST 2] Running TRUE BATCHED: Amortized GEMM pattern...\n");
    printf("         Expected: T=32, call_count=%d (one per output row)\n\n", out_dim);
    ForwardBatch_TrueBatched(weights, input_batch, output_batch, hidden_dim, out_dim, T);
    Profiler_AnalyzeBottlenecks();

    free(weights);
    free(input_batch);
    free(output_batch);

    return 0;
}
