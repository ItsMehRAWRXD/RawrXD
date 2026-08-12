// Simple fallback path test
#include <cstdio>
#include <cstdlib>

extern "C" {
    void Profiler_Initialize();
    void Profiler_SetBatchContext(unsigned long long batchSize);
    unsigned long long Profiler_ReadTsc();
    void Profiler_TrackCall(unsigned long long startCycles);
    void Profiler_AnalyzeBottlenecks();
}

void StreamingMatMul(const float* weights, const float* input, float* output, int K, int N) {
    volatile float sum = 0.0f;
    for (int n = 0; n < N; ++n) {
        sum = 0.0f;
        for (int k = 0; k < K; ++k) {
            sum += 0.01f * input[k];
        }
        output[n] = sum;
    }
}

bool ExecuteLayerMatMul(const char* name, const float* input, float* output, int K, int N) {
    unsigned long long start = Profiler_ReadTsc();
    StreamingMatMul(nullptr, input, output, K, N);
    Profiler_TrackCall(start);
    return true;
}

int main() {
    printf("Fallback Path Test\n");
    printf("==================\n\n");

    Profiler_Initialize();

    const int T = 8;
    const int dim = 16;

    float* hidden = (float*)malloc(T * dim * sizeof(float));
    float* output = (float*)malloc(T * dim * sizeof(float));
    for (int i = 0; i < T * dim; ++i) hidden[i] = 0.5f;

    printf("Running token-serial fallback (T=%d)...\n", T);
    Profiler_SetBatchContext(T);

    for (int t = 0; t < T; ++t) {
        ExecuteLayerMatMul("test", hidden + t * dim, output + t * dim, dim, dim);
    }

    printf("Done. Running analysis...\n\n");
    Profiler_AnalyzeBottlenecks();

    free(hidden);
    free(output);

    return 0;
}
