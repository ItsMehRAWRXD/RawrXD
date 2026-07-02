/* ==============================================================================
   sovereign_wrapper.c — C Wrapper for MASM DLL Exports
   ==============================================================================
   Implements high-level lifecycle functions that orchestrate the raw MASM
   components.  Compiled with cl.exe /c /O2 /TC.
   No __declspec(dllexport) here — exports are driven by sovereign.def.
   No windows.h include — minimal types defined inline for no-CRT build.
   ==============================================================================*/

#ifdef _WIN64
    #define SOV_API
#else
    #error "x64 only"
#endif

/* ------------------------------------------------------------------------------
   Minimal Windows types (no windows.h dependency)
   ------------------------------------------------------------------------------ */
typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef void*               HMODULE;
typedef void*               LPVOID;
#define TRUE  1
#define FALSE 0
#define DLL_PROCESS_ATTACH 1
#define DLL_THREAD_ATTACH  2
#define DLL_THREAD_DETACH  3
#define DLL_PROCESS_DETACH 0

/* ------------------------------------------------------------------------------
   Minimal DllMain stub (required for /DLL linkage without CRT)
   ------------------------------------------------------------------------------ */
BOOL DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;
    return (reason == DLL_PROCESS_ATTACH || reason == DLL_THREAD_ATTACH ||
            reason == DLL_THREAD_DETACH || reason == DLL_PROCESS_DETACH) ? TRUE : FALSE;
}

/* ------------------------------------------------------------------------------
   MASM function prototypes (cdecl / default x64 ABI)
   NOTE: Float parameters are passed as unsigned int (raw IEEE-754 bits)
   to avoid XMM0/RCX ABI mismatch between C and MASM.
   ------------------------------------------------------------------------------ */
extern int  INIT_GHOST_BUFFER(void);
extern int  PUSH_GHOST_PREDICTION(const char* text, unsigned long long length, unsigned int confidenceBits);
extern int  RENDER_GHOST_PREDICTIVE(void* hWnd);
extern int  FLUSH_GHOST_BUFFER(void);
extern int  GHOST_HEARTBEAT(void* hWnd);
extern unsigned long long GET_GHOST_LATENCY(void);
extern int  GET_GHOST_STATS(void* outStats);
extern void SET_CONFIDENCE_THRESHOLD(unsigned int thresholdBits);
extern unsigned int GET_CONFIDENCE_THRESHOLD(void);

extern int  STREAMER_INIT(void);
extern int  STREAMER_PUSH_TOKEN(unsigned char token, unsigned int confidenceBits);
extern int  STREAMER_FLUSH(void);
extern void STREAMER_SET_CONFIDENCE(unsigned int confidenceBits);

extern int  INSTALL_HOOK(void* target, void* handler);
extern int  UNINSTALL_HOOK(void);
extern void GET_LATENCY_STATS(void* outStats);

extern int  VALIDATE_TOKEN_SIMD(const char* token, unsigned long long len);
extern unsigned long long FNV1A_64(const void* data, unsigned long long len);
extern int  BUILD_SYMBOL_HASH_TABLE(void* hModule);
extern void* RESOLVE_SYMBOL_FROM_PE(void* hModule, unsigned long long hash);

extern void WRITE_LATENCY(unsigned long long cycles);
extern unsigned long long READ_LATENCY(void);
extern void PIN_THREAD(unsigned long long mask);

/* ------------------------------------------------------------------------------
   Version string
   ------------------------------------------------------------------------------ */
static const char* g_version = "1.0.0";

/* ------------------------------------------------------------------------------
   Lifecycle: Init All
   ------------------------------------------------------------------------------ */
SOV_API int SovereignInitAll(void)
{
    int rc;

    rc = INIT_GHOST_BUFFER();
    if (rc != 1) return -1;

    rc = STREAMER_INIT();
    if (rc != 1) return -2;

    return 0; /* SOV_OK */
}

/* ------------------------------------------------------------------------------
   Lifecycle: Shutdown
   ------------------------------------------------------------------------------ */
SOV_API void SovereignShutdown(void)
{
    FLUSH_GHOST_BUFFER();
    UNINSTALL_HOOK();
}

/* ------------------------------------------------------------------------------
   Version query
   ------------------------------------------------------------------------------ */
SOV_API const char* SovereignVersion(void)
{
    return g_version;
}

/* ------------------------------------------------------------------------------
   Telemetry Stress Harness (C implementation)
   ------------------------------------------------------------------------------ */
SOV_API unsigned long long RunTelemetryStress(unsigned int iterations)
{
    unsigned int i;
    unsigned long long total = 0;
    unsigned long long start, end;

    for (i = 0; i < iterations; ++i)
    {
        /* Simulate work */
        start = __rdtsc();
        /* Minimal nop work */
        end = __rdtsc();

        WRITE_LATENCY(end - start);
        total += (end - start);
    }

    return total / iterations;
}

/* ------------------------------------------------------------------------------
   Threading helper
   ------------------------------------------------------------------------------ */
SOV_API void PinThreadToCore(unsigned int coreIndex)
{
    unsigned long long mask = 1ULL << coreIndex;
    PIN_THREAD(mask);
}
