// Minimal test for the profiler
#include <cstdio>

extern "C" {
    void Profiler_Initialize();
    void Profiler_AnalyzeBottlenecks();
}

int main() {
    printf("Before init\n");
    Profiler_Initialize();
    printf("After init\n");
    Profiler_AnalyzeBottlenecks();
    printf("After analyze\n");
    return 0;
}
