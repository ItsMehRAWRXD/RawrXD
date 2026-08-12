// Minimal test to verify the C++ loop structure works
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
    void Profiler_Initialize();
    void Profiler_SetBatchContext(unsigned int batchSize);
    unsigned long long Profiler_ReadTsc();
    void* Profiler_BeginTrack(const char* funcName);
    void Profiler_EndTrack(void* metricEntry, unsigned long long startCycles);
    void Profiler_AnalyzeBottlenecks();
}

void StreamingMatMul_Simulated(const float* weights, const float* input, float* output,
                                int hidden_dim) {
    volatile float sum = 0.0f;
    for (int i = 0; i < hidden_dim; ++i) {
        sum += weights[i] * input[i];
    }
    *output = sum;
}

int main() {
    printf("Initializing profiler...\n");
    Profiler_Initialize();
    printf("Profiler initialized.\n");

    const int hidden_dim = 128;
    const int out_dim = 4;
    const int T = 32;

    float* weights = (float*)malloc(hidden_dim * out_dim * sizeof(float));
    float* input_batch = (float*)malloc(hidden_dim * T * sizeof(float));
    float* output_batch = (float*)malloc(out_dim * T * sizeof(float));

    for (int i = 0; i < hidden_dim * out_dim; ++i) weights[i] = 0.01f;
    for (int i = 0; i < hidden_dim * T; ++i) input_batch[i] = 0.5f;
    memset(output_batch, 0, out_dim * T * sizeof(float));

    printf("Running anti-pattern loop...\n");
    Profiler_SetBatchContext(T);

    int call_count = 0;
    for (int row = 0; row < out_dim; ++row) {
        for (int t = 0; t < T; ++t) {
            const float* input_token = input_batch + (t * hidden_dim);
            float* output_scalar = output_batch + (t * out_dim) + row;

            void* metric = Profiler_BeginTrack("StreamingMatMul");
            unsigned long long start = Profiler_ReadTsc();
            StreamingMatMul_Simulated(weights + (row * hidden_dim), input_token, output_scalar, hidden_dim);
            Profiler_EndTrack(metric, start);

            call_count++;
        }
    }

    printf("Loop complete. Calls: %d\n", call_count);
    printf("Running analysis...\n");
    Profiler_AnalyzeBottlenecks();
    printf("Done.\n");

    free(weights);
    free(input_batch);
    free(output_batch);

    return 0;
}
