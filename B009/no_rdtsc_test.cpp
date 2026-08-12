// Test without rdtsc to isolate the issue
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
    void Profiler_Initialize();
    void Profiler_SetBatchContext(unsigned int batchSize);
    void* Profiler_BeginTrack(const char* funcName);
    void Profiler_EndTrack(void* metricEntry, unsigned long long startCycles);
    void Profiler_AnalyzeBottlenecks();
}

int main() {
    printf("Initializing profiler...\n");
    Profiler_Initialize();

    printf("Setting batch context to T=8...\n");
    Profiler_SetBatchContext(8);

    printf("Tracking 16 calls...\n");
    for (int i = 0; i < 16; i++) {
        void* metric = Profiler_BeginTrack("StreamingMatMul");
        printf("  Call %d: metric=%p\n", i, metric);
        Profiler_EndTrack(metric, 100);  // dummy start value
    }

    printf("Running analysis...\n");
    Profiler_AnalyzeBottlenecks();
    printf("Done.\n");

    return 0;
}
