// ================================================================================================
// Production Path Simulation Test
// Simulates the actual RawrXD ExecuteLayerMatMulBatch / ExecuteLayerMatMul path
// with Negative Space Profiler instrumentation.
// ================================================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>

// --- Profiler API (from NegativeSpaceProfiler_v2.asm) ---
extern "C" {
    void Profiler_Initialize();
    void Profiler_SetBatchContext(unsigned long long batchSize);
    unsigned long long Profiler_ReadTsc();
    void Profiler_TrackCall(unsigned long long startCycles);
    void Profiler_AnalyzeBottlenecks();
}

// --- Simulated StreamingMatMul (single token) ---
// This is what ExecuteLayerMatMul calls for each token in the fallback path
void StreamingMatMul(const float* weights, const float* input, float* output,
                      int K, int N) {
    volatile float sum = 0.0f;
    for (int n = 0; n < N; ++n) {
        sum = 0.0f;
        for (int k = 0; k < K; ++k) {
            sum += weights[n * K + k] * input[k];
        }
        output[n] = sum;
    }
}

// --- Profiled ExecuteLayerMatMul (single token) ---
// Matches the actual production integration point
bool ExecuteLayerMatMul(const char* tensorName, const float* input, float* output,
                        int inputDim, int outputDim) {
    // Profiler: Track each single-token matmul call
    unsigned long long start = Profiler_ReadTsc();
    StreamingMatMul(nullptr, input, output, inputDim, outputDim);
    Profiler_TrackCall(start);
    return true;
}

// --- Profiled ExecuteLayerMatMulBatch (batched) ---
// Matches the actual production integration point
bool ExecuteLayerMatMulBatch(const char* tensorName, const float* inputBatch, float* outputBatch,
                             int inputDim, int outputDim, int T) {
    // Profiler: Set batch context for this matmul operation
    Profiler_SetBatchContext(T);

    // Simulate B015 weight residency FAST PATH (true batched GEMM)
    // In production, this would check m_weightResidencyPool->acquire()
    bool useResidencyPool = true;  // Simulate fast path

    if (useResidencyPool) {
        // True batched GEMM: One profiler call covers all T tokens
        unsigned long long start = Profiler_ReadTsc();
        for (int t = 0; t < T; ++t) {
            const float* inRow = inputBatch + t * inputDim;
            float* outRow = outputBatch + t * outputDim;
            for (int n = 0; n < outputDim; ++n) {
                float sum = 0.0f;
                for (int k = 0; k < inputDim; ++k) {
                    sum += 0.01f * inRow[k];  // Simulated weight
                }
                outRow[n] = sum;
            }
        }
        Profiler_TrackCall(start);
        return true;
    }

    // FALLBACK PATH: Token-serial (preserves correctness, slower)
    // Each ExecuteLayerMatMul call tracks individually, resulting in T calls
    for (int t = 0; t < T; ++t) {
        if (!ExecuteLayerMatMul(tensorName, inputBatch + t * inputDim,
                                outputBatch + t * outputDim, inputDim, outputDim))
            return false;
    }
    return true;
}

// --- Simulated ForwardBatch (layer-outer loop) ---
void ForwardBatch(int T, int n_layers, int dim, int hidden_dim) {
    printf("[ForwardBatch] ENTRY: tokens=%d layers=%d dim=%d hidden=%d\n", T, n_layers, dim, hidden_dim);

    float* hidden = (float*)malloc(T * dim * sizeof(float));
    float* q = (float*)malloc(T * dim * sizeof(float));
    float* k = (float*)malloc(T * dim * sizeof(float));
    float* v = (float*)malloc(T * dim * sizeof(float));
    float* h1 = (float*)malloc(T * hidden_dim * sizeof(float));

    for (int i = 0; i < T * dim; ++i) hidden[i] = 0.5f;

    for (int l = 0; l < n_layers; ++l) {
        // QKV projections (true batched matmul)
        ExecuteLayerMatMulBatch("attn_q.weight", hidden, q, dim, dim, T);
        ExecuteLayerMatMulBatch("attn_k.weight", hidden, k, dim, dim, T);
        ExecuteLayerMatMulBatch("attn_v.weight", hidden, v, dim, dim, T);

        // FFN gate + up (true batched matmul)
        ExecuteLayerMatMulBatch("ffn_gate.weight", hidden, h1, dim, hidden_dim, T);
        ExecuteLayerMatMulBatch("ffn_up.weight", hidden, h1, dim, hidden_dim, T);
    }

    printf("[ForwardBatch] complete: tokens=%d layers=%d\n", T, n_layers);

    free(hidden);
    free(q);
    free(k);
    free(v);
    free(h1);
}

// --- Simulated ForwardBatch with FALLBACK (no residency pool) ---
void ForwardBatch_Fallback(int T, int n_layers, int dim, int hidden_dim) {
    printf("[ForwardBatch] ENTRY (FALLBACK PATH): tokens=%d layers=%d\n", T, n_layers);

    float* hidden = (float*)malloc(T * dim * sizeof(float));
    float* output = (float*)malloc(T * dim * sizeof(float));

    for (int i = 0; i < T * dim; ++i) hidden[i] = 0.5f;

    for (int l = 0; l < n_layers; ++l) {
        // FALLBACK: Token-serial path — calls ExecuteLayerMatMul T times
        for (int t = 0; t < T; ++t) {
            ExecuteLayerMatMul("attn_q.weight", hidden + t * dim, output + t * dim, dim, dim);
        }
    }

    printf("[ForwardBatch] complete (FALLBACK): tokens=%d layers=%d\n", T, n_layers);

    free(hidden);
    free(output);
}

int main() {
    printf("RawrXD Negative Space Profiler — Production Path Simulation\n");
    printf("===========================================================\n\n");

    Profiler_Initialize();

    const int T = 32;
    const int n_layers = 2;
    const int dim = 128;
    const int hidden_dim = 256;

    // === TEST 1: Fast Path (B015 Weight Residency) ===
    printf("=== TEST 1: Fast Path (True Batched GEMM) ===\n");
    ForwardBatch(T, n_layers, dim, hidden_dim);
    Profiler_AnalyzeBottlenecks();

    // === TEST 2: Fallback Path (Token-Serial) ===
    printf("\n=== TEST 2: Fallback Path (Token-Serial) ===\n");
    ForwardBatch_Fallback(T, n_layers, dim, hidden_dim);
    Profiler_AnalyzeBottlenecks();

    return 0;
}
