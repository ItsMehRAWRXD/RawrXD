/* ==============================================================================
   tps_bench.c — Sovereign Framework Token-Per-Second Smoke Benchmark
   ==============================================================================
   Measures raw token throughput through the Model Streamer → Ghost Engine
   pipeline. No actual inference — just token push + flush latency.
   
   Build: cl.exe /O2 /TC /W3 /nologo /Fe:tps_bench.exe tps_bench.c
   Run:   .\tps_bench.exe
   ==============================================================================*/

#include <stdio.h>
#include <windows.h>

/* Sovereign DLL function pointers */
typedef int  (*fn_SovereignInitAll)(void);
typedef int  (*fn_StreamerInit)(void);
typedef int  (*fn_StreamerPushToken)(unsigned char, unsigned int);
typedef int  (*fn_StreamerFlush)(void);
typedef void (*fn_SovereignShutdown)(void);
typedef unsigned long long (*fn_RunTelemetryStress)(unsigned int);

/* GGUF loader */
typedef void* (*fn_SovereignLoadModel)(const char*);
typedef int   (*fn_SovereignUnloadModel)(void*);
typedef int   (*fn_SovereignIsModelReady)(void);

int main(void)
{
    HMODULE hDll;
    fn_SovereignInitAll    pfnInitAll    = NULL;
    fn_StreamerInit        pfnStrInit    = NULL;
    fn_StreamerPushToken   pfnStrPush    = NULL;
    fn_StreamerFlush       pfnStrFlush   = NULL;
    fn_SovereignShutdown   pfnShutdown   = NULL;
    fn_RunTelemetryStress  pfnStress     = NULL;
    fn_SovereignLoadModel  pfnLoad       = NULL;
    fn_SovereignUnloadModel pfnUnload    = NULL;
    fn_SovereignIsModelReady pfnReady    = NULL;

    LARGE_INTEGER freq, start, end;
    double elapsed_ms, tps;
    unsigned int i;
    const unsigned int TOKEN_BURST = 10000;

    printf("=== SOVEREIGN TPS SMOKE BENCH ===\n\n");

    /* Load DLL */
    hDll = LoadLibraryA("sovereign.dll");
    if (!hDll) {
        printf("FAIL: LoadLibrary(sovereign.dll) = %lu\n", GetLastError());
        return 1;
    }
    printf("DLL loaded OK\n");

    /* Resolve exports */
    pfnInitAll  = (fn_SovereignInitAll)GetProcAddress(hDll, "SovereignInitAll");
    pfnStrInit  = (fn_StreamerInit)GetProcAddress(hDll, "StreamerInit");
    pfnStrPush  = (fn_StreamerPushToken)GetProcAddress(hDll, "StreamerPushToken");
    pfnStrFlush = (fn_StreamerFlush)GetProcAddress(hDll, "StreamerFlush");
    pfnShutdown = (fn_SovereignShutdown)GetProcAddress(hDll, "SovereignShutdown");
    pfnStress   = (fn_RunTelemetryStress)GetProcAddress(hDll, "RunTelemetryStress");
    pfnLoad     = (fn_SovereignLoadModel)GetProcAddress(hDll, "SovereignLoadModel");
    pfnUnload   = (fn_SovereignUnloadModel)GetProcAddress(hDll, "SovereignUnloadModel");
    pfnReady    = (fn_SovereignIsModelReady)GetProcAddress(hDll, "SovereignIsModelReady");

    if (!pfnInitAll || !pfnStrInit || !pfnStrPush || !pfnStrFlush) {
        printf("FAIL: Core exports missing\n");
        return 1;
    }

    /* Init */
    pfnInitAll();
    pfnStrInit();
    printf("Subsystems initialized\n\n");

    /* Optional: Load real model */
    if (pfnLoad) {
        void* hModel = pfnLoad("d:\\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf");
        if (hModel && pfnReady && pfnReady()) {
            printf("Model loaded: TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf\n");
        } else {
            printf("Model not loaded (running dry benchmark)\n");
        }
        if (hModel) pfnUnload(hModel);
    }

    /* --- Benchmark 1: Raw token push (no flush) --- */
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    for (i = 0; i < TOKEN_BURST; i++) {
        pfnStrPush((unsigned char)('A' + (i % 26)), 0);
    }

    QueryPerformanceCounter(&end);
    elapsed_ms = ((double)(end.QuadPart - start.QuadPart) * 1000.0) / freq.QuadPart;
    tps = (TOKEN_BURST * 1000.0) / elapsed_ms;

    printf("--- Token Push Only (%u tokens) ---\n", TOKEN_BURST);
    printf("  Elapsed: %.3f ms\n", elapsed_ms);
    printf("  TPS:     %.0f\n", tps);
    printf("  Latency: %.3f us/token\n", (elapsed_ms * 1000.0) / TOKEN_BURST);

    /* --- Benchmark 2: Token push + periodic flush --- */
    pfnStrFlush();  /* Clear buffer from benchmark 1 */
    QueryPerformanceCounter(&start);

    for (i = 0; i < TOKEN_BURST; i++) {
        pfnStrPush((unsigned char)('A' + (i % 26)), 0);
        if ((i + 1) % 64 == 0) {  /* Flush every 64 tokens */
            pfnStrFlush();
        }
    }
    pfnStrFlush();  /* Final flush */

    QueryPerformanceCounter(&end);
    elapsed_ms = ((double)(end.QuadPart - start.QuadPart) * 1000.0) / freq.QuadPart;
    tps = (TOKEN_BURST * 1000.0) / elapsed_ms;

    printf("\n--- Token Push + Flush every 64 (%u tokens) ---\n", TOKEN_BURST);
    printf("  Elapsed: %.3f ms\n", elapsed_ms);
    printf("  TPS:     %.0f\n", tps);
    printf("  Latency: %.3f us/token\n", (elapsed_ms * 1000.0) / TOKEN_BURST);

    /* --- Benchmark 3: Telemetry stress --- */
    if (pfnStress) {
        unsigned long long avg_cycles = pfnStress(10000);
        printf("\n--- Telemetry Stress (10000 iterations) ---\n");
        printf("  Avg latency: %llu cycles\n", avg_cycles);
        printf("  At 3.0 GHz:  %.3f us\n", avg_cycles / 3000.0);
    }

    /* Shutdown */
    pfnShutdown();
    FreeLibrary(hDll);

    printf("\n=== BENCH COMPLETE ===\n");
    return 0;
}
