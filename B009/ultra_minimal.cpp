// Ultra-minimal test
#include <cstdio>

extern "C" {
    void Profiler_Initialize();
    void* Profiler_BeginTrack(const char* funcName);
    void Profiler_EndTrack(void* metricEntry, unsigned long long startCycles);
    void Profiler_AnalyzeBottlenecks();
    unsigned long long Profiler_ReadTsc();
}

int main() {
    printf("Init...\n");
    Profiler_Initialize();
    printf("BeginTrack...\n");
    void* m = Profiler_BeginTrack("Test");
    printf("m=%p\n", m);
    printf("ReadTsc...\n");
    unsigned long long t = Profiler_ReadTsc();
    printf("t=%llu\n", t);
    printf("EndTrack...\n");
    Profiler_EndTrack(m, t);
    printf("Analyze...\n");
    Profiler_AnalyzeBottlenecks();
    printf("Done.\n");
    return 0;
}
