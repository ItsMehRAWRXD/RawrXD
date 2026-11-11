/* ==============================================================================
   tps_smoke.c — Tokens-Per-Second Pipeline Benchmark
   ==============================================================================
   Measures the end-to-end latency of:
     LoadLibrary → Init → LoadModel → StreamerPushToken loop → Render
   
   This is a SMOKE test — it validates the pipeline can sustain token flow
   without actual inference (kernel not yet implemented).
   ==============================================================================*/

#include <stdio.h>
#include <windows.h>
#include <intrin.h>    /* For __rdtsc() intrinsic */

/* Sovereign API typedefs */
typedef int  (*fn_SovereignInitAll)(void);
typedef void (*fn_SovereignShutdown)(void);
typedef int  (*fn_StreamerInit)(void);
typedef int  (*fn_StreamerPushToken)(unsigned char, unsigned int);
typedef int  (*fn_StreamerFlush)(void);
typedef void* (*fn_SovereignLoadModel)(const char*);
typedef int   (*fn_SovereignUnloadModel)(void*);
typedef int   (*fn_SovereignIsModelReady)(void);
typedef int   (*fn_InitGhostBuffer)(void);
typedef int   (*fn_PushGhostPrediction)(const char*, size_t, unsigned int);
typedef int   (*fn_RenderGhostPredictive)(void*);

/* High-resolution timer */
static unsigned long long GetTSC(void)
{
    return __rdtsc();
}

static double TscToMs(unsigned long long cycles)
{
    /* Assume 3.0 GHz base clock */
    return (double)cycles / 3.0e6;
}

int main(void)
{
    HMODULE hDll;
    fn_SovereignInitAll    pfnInit;
    fn_SovereignShutdown   pfnShutdown;
    fn_StreamerInit        pfnStrInit;
    fn_StreamerPushToken   pfnPush;
    fn_StreamerFlush       pfnFlush;
    fn_SovereignLoadModel  pfnLoad;
    fn_SovereignUnloadModel pfnUnload;
    fn_SovereignIsModelReady pfnReady;
    fn_InitGhostBuffer     pfnGhostInit;
    fn_PushGhostPrediction pfnGhostPush;
    fn_RenderGhostPredictive pfnGhostRender;

    printf("=== SOVEREIGN TPS SMOKE TEST ===\n\n");

    /* Load DLL */
    unsigned long long t0 = GetTSC();
    hDll = LoadLibraryA("sovereign.dll");
    unsigned long long t1 = GetTSC();
    if (!hDll) {
        printf("FAIL: LoadLibrary = %lu\n", GetLastError());
        return 1;
    }
    printf("LoadLibrary(sovereign.dll): %.3f ms\n", TscToMs(t1 - t0));

    /* Resolve exports */
    pfnInit       = (fn_SovereignInitAll)   GetProcAddress(hDll, "SovereignInitAll");
    pfnShutdown   = (fn_SovereignShutdown)  GetProcAddress(hDll, "SovereignShutdown");
    pfnStrInit    = (fn_StreamerInit)       GetProcAddress(hDll, "StreamerInit");
    pfnPush       = (fn_StreamerPushToken)  GetProcAddress(hDll, "StreamerPushToken");
    pfnFlush      = (fn_StreamerFlush)     GetProcAddress(hDll, "StreamerFlush");
    pfnLoad       = (fn_SovereignLoadModel) GetProcAddress(hDll, "SovereignLoadModel");
    pfnUnload     = (fn_SovereignUnloadModel)GetProcAddress(hDll, "SovereignUnloadModel");
    pfnReady      = (fn_SovereignIsModelReady)GetProcAddress(hDll, "SovereignIsModelReady");
    pfnGhostInit  = (fn_InitGhostBuffer)    GetProcAddress(hDll, "InitGhostBuffer");
    pfnGhostPush  = (fn_PushGhostPrediction) GetProcAddress(hDll, "PushGhostPrediction");
    pfnGhostRender= (fn_RenderGhostPredictive)GetProcAddress(hDll, "RenderGhostPredictive");

    if (!pfnInit || !pfnPush || !pfnFlush || !pfnLoad) {
        printf("FAIL: Missing exports\n");
        return 1;
    }

    /* Init all subsystems */
    t0 = GetTSC();
    int rc = pfnInit();
    t1 = GetTSC();
    printf("SovereignInitAll(): %.3f ms (rc=%d)\n", TscToMs(t1 - t0), rc);

    pfnStrInit();
    pfnGhostInit();

    /* Load model */
    t0 = GetTSC();
    void* hModel = pfnLoad("d:\\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf");
    t1 = GetTSC();
    printf("SovereignLoadModel(TinyLlama): %.3f ms\n", TscToMs(t1 - t0));
    if (!hModel) {
        printf("WARN: Model load failed — running pipeline test without model\n");
    } else {
        int ready = pfnReady();
        printf("SovereignIsModelReady() = %d\n", ready);
    }

    /* === TPS BENCHMARK === */
    printf("\n--- Token Pipeline Benchmark ---\n");

    const unsigned int BATCH_SIZES[] = {1, 10, 100, 1000, 10000};
    const int NUM_BATCHES = 5;

    for (int b = 0; b < NUM_BATCHES; b++) {
        unsigned int n = BATCH_SIZES[b];

        /* Warmup */
        for (unsigned int i = 0; i < 100; i++) {
            pfnPush((unsigned char)(i % 256), 0);
        }
        pfnFlush();

        /* Benchmark */
        t0 = GetTSC();
        for (unsigned int i = 0; i < n; i++) {
            pfnPush((unsigned char)(i % 256), 0);
        }
        pfnFlush();
        t1 = GetTSC();

        double ms = TscToMs(t1 - t0);
        double tps = (double)n / (ms / 1000.0);
        double us_per_token = (ms * 1000.0) / (double)n;

        printf("Batch %5u: %8.3f ms | %10.0f TPS | %6.3f us/token\n",
               n, ms, tps, us_per_token);
    }

    /* Ghost render benchmark */
    printf("\n--- Ghost Render Benchmark ---\n");
    pfnGhostPush("Benchmark prediction text", 25, 0x3F733333);

    t0 = GetTSC();
    int rendered = pfnGhostRender(NULL);  /* NULL = test mode, no GDI */
    t1 = GetTSC();
    printf("RenderGhostPredictive(NULL): %.3f ms (rendered=%d)\n",
           TscToMs(t1 - t0), rendered);

    /* Cleanup */
    if (hModel) {
        pfnUnload(hModel);
    }
    pfnShutdown();
    FreeLibrary(hDll);

    printf("\n=== TPS SMOKE TEST COMPLETE ===\n");
    return 0;
}
