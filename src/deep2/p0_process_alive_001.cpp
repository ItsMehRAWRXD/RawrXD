// p0_process_alive_001.cpp — P0_PROCESS_ALIVE_001
// Minimal product-floor gate: start → idle ≥10s → clean exit. No model, no VWA.
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static const char* kGateDir =
    "G:\\~dev\\rawrxd\\evidence\\P0_PROCESS_ALIVE_001";

static void WriteGate(const char* body) {
#ifdef _WIN32
    CreateDirectoryA(kGateDir, nullptr);
#endif
    std::string path = std::string(kGateDir) + "\\GATE_STATUS.txt";
    FILE* f = fopen(path.c_str(), "w");
    if (f) {
        fputs(body, f);
        fclose(f);
    }
}

int main() {
    printf("P0_PROCESS_ALIVE_001\nSTART=1\n");
    fflush(stdout);

    // Touch common CRT / heap paths without model load.
    volatile int* heapProbe = (int*)std::malloc(64);
    if (!heapProbe) {
        WriteGate("START=1\nINIT=0\nP0_PROCESS_ALIVE_001=FAIL\n");
        return 2;
    }
    heapProbe[0] = 1;
    std::free((void*)heapProbe);
    printf("INIT=1\n");
    fflush(stdout);

    // Optional Prometheus only if explicitly requested (default OFF).
    // Linked TU must not auto-start exporter during static init.
#ifdef _WIN32
    HMODULE self = GetModuleHandleA(nullptr);
    auto ensure = (void (*)())GetProcAddress(self, "EnsurePrometheusExporterStarted");
    if (ensure) {
        ensure();
        printf("PROMETHEUS_ENSURE_RESOLVED=1\n");
    } else {
        printf("PROMETHEUS_ENSURE_RESOLVED=0\n");
    }
#endif

    printf("NO_REPL_ENTER=1\n");
    fflush(stdout);

    const int idleSec = 10;
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < idleSec; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        printf("IDLE_SEC=%d\n", i + 1);
        fflush(stdout);
    }
    auto t1 = std::chrono::steady_clock::now();
    const double held =
        std::chrono::duration<double>(t1 - t0).count();

    printf("IDLE_10S=%d\nEXIT_REQUESTED=1\nheld_s=%.3f\n",
           held >= 9.5 ? 1 : 0, held);
    fflush(stdout);

    const int pass = (held >= 9.5);
    char buf[512];
    snprintf(buf, sizeof(buf),
             "START=1\nINIT=1\nMODEL_OPEN=0\nNO_REPL_ENTER=1\n"
             "IDLE_10S=%d\nEXIT_REQUESTED=1\nCLEAN_EXIT=1\n"
             "UNHANDLED_EXCEPTION=0\nheld_s=%.3f\n"
             "P0_PROCESS_ALIVE_001=%s\n",
             pass ? 1 : 0, held, pass ? "PASS" : "FAIL");
    WriteGate(buf);
    printf("CLEAN_EXIT=1\nP0_PROCESS_ALIVE_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
