/* ==============================================================================
   test_sdk.c — Minimal C client validating sovereign.dll LoadLibrary
   ==============================================================================
   Build: cl.exe /O2 /TC /W3 /nologo /Fe:test_sdk.exe test_sdk.c
   Run:   .\test_sdk.exe
   ==============================================================================*/

#include <stdio.h>
#include <windows.h>

/* Typedefs matching sovereign.h — NOTE: float params passed as unsigned int bits */
typedef int  (*fn_InitGhostBuffer)(void);
typedef int  (*fn_PushGhostPrediction)(const char*, size_t, unsigned int);
typedef int  (*fn_RenderGhostPredictive)(void*);
typedef int  (*fn_FlushGhostBuffer)(void);
typedef int  (*fn_GhostHeartbeat)(void*);
typedef unsigned long long (*fn_GetGhostLatency)(void);
typedef int  (*fn_GetGhostStats)(void*);
typedef void (*fn_SetConfidenceThreshold)(unsigned int);
typedef unsigned int (*fn_GetConfidenceThreshold)(void);

typedef int  (*fn_StreamerInit)(void);
typedef int  (*fn_StreamerPushToken)(unsigned char, unsigned int);
typedef int  (*fn_StreamerFlush)(void);
typedef void (*fn_StreamerSetConfidence)(unsigned int);

typedef int  (*fn_InstallHook)(void*, void*);
typedef int  (*fn_UninstallHook)(void);
typedef void (*fn_GetHookLatencyStats)(void*);

typedef int  (*fn_ValidateTokenSIMD)(const char*, size_t);
typedef unsigned long long (*fn_FNV1A_64)(const void*, size_t);
typedef int  (*fn_BuildSymbolHashTable)(void*);
typedef void* (*fn_ResolveSymbolFromPE)(void*, unsigned long long);

typedef void (*fn_TelemetryPush)(unsigned long long);
typedef unsigned long long (*fn_TelemetryRead)(void);
typedef unsigned long long (*fn_RunTelemetryStress)(unsigned int);

typedef const char* (*fn_SovereignVersion)(void);
typedef int  (*fn_SovereignInitAll)(void);
typedef void (*fn_SovereignShutdown)(void);
typedef void (*fn_PinThreadToCore)(unsigned int);

/* GGUF Loader APIs */
typedef void* (*fn_SovereignLoadModel)(const char*);
typedef int   (*fn_SovereignUnloadModel)(void*);
typedef int   (*fn_SovereignIsModelReady)(void);
typedef int   (*fn_SovereignGetModelInfo)(void*);

/* Tensor APIs */
typedef unsigned long long (*fn_SovereignGetTensorCount)(void);
typedef int   (*fn_SovereignGetTensorByIndex)(unsigned long long, void*);
typedef unsigned long long (*fn_SovereignGetTensorOffset)(const char*);

/* Sovereign Switch APIs */
typedef void (*fn_SovereignSetMode)(unsigned long long);
typedef unsigned long long (*fn_SovereignGetMode)(void);
typedef void (*fn_SovereignInitHashes)(void);
typedef unsigned long long (*fn_SovereignHash)(const char*);
typedef void* (*fn_SovereignFindNtdll)(void);
typedef void* (*fn_SovereignGetExport)(unsigned long long);
typedef unsigned long long (*fn_SovereignGetSyscallID)(void*);
typedef unsigned long long (*fn_SovereignCall)(unsigned long long, unsigned long long, unsigned long long, unsigned long long);

/* Tensor info structure (matches MASM TENSOR_INFO) */
typedef struct _TENSOR_INFO {
    unsigned long long NameHash;
    unsigned long long DataOffset;
    unsigned long long DataSize;
    unsigned int  Dims[4];
    unsigned int  NDim;
    unsigned int  QuantType;
    char          NameStr[64];
} TENSOR_INFO;

/* Model info structure (matches MODEL_INFO in MASM) */
typedef struct _MODEL_INFO {
    unsigned int  Magic;
    unsigned int  Version;
    unsigned long long TensorCount;
    unsigned long long KVCount;
    unsigned int  VocabSize;
    unsigned int  ContextLength;
    unsigned int  EmbeddingDim;
    unsigned int  HeadCount;
    unsigned int  LayerCount;
    unsigned int  QuantType;
    char          ArchName[32];
} MODEL_INFO;

/* ------------------------------------------------------------------------------
   Helper: resolve and print
   ------------------------------------------------------------------------------ */
static void* resolve(HMODULE h, const char* name)
{
    void* p = (void*)GetProcAddress(h, name);
    printf("  %-24s %s\n", name, p ? "OK" : "MISSING");
    return p;
}

/* ------------------------------------------------------------------------------
   Main
   ------------------------------------------------------------------------------ */
int main(void)
{
    HMODULE hDll;
    int ok = 1;

    printf("=== Sovereign SDK Smoke Test ===\n\n");

    hDll = LoadLibraryA("sovereign.dll");
    if (!hDll) {
        printf("FAIL: LoadLibrary(sovereign.dll) failed: %lu\n", GetLastError());
        return 1;
    }
    printf("LoadLibrary(sovereign.dll) OK\n\n");

    printf("Ghost Engine APIs:\n");
    resolve(hDll, "InitGhostBuffer");
    resolve(hDll, "PushGhostPrediction");
    resolve(hDll, "RenderGhostPredictive");
    resolve(hDll, "FlushGhostBuffer");
    resolve(hDll, "GhostHeartbeat");
    resolve(hDll, "GetGhostLatency");
    resolve(hDll, "GetGhostStats");
    resolve(hDll, "SetConfidenceThreshold");
    resolve(hDll, "GetConfidenceThreshold");

    printf("\nModel Streamer APIs:\n");
    resolve(hDll, "StreamerInit");
    resolve(hDll, "StreamerPushToken");
    resolve(hDll, "StreamerFlush");
    resolve(hDll, "StreamerSetConfidence");

    printf("\nHook Simulator APIs:\n");
    resolve(hDll, "InstallHook");
    resolve(hDll, "UninstallHook");
    resolve(hDll, "GetHookLatencyStats");

    printf("\nSymbolic Validator APIs:\n");
    resolve(hDll, "ValidateTokenSIMD");
    resolve(hDll, "FNV1A_64");
    resolve(hDll, "BuildSymbolHashTable");
    resolve(hDll, "ResolveSymbolFromPE");

    printf("\nTelemetry APIs:\n");
    resolve(hDll, "TelemetryPush");
    resolve(hDll, "TelemetryRead");
    resolve(hDll, "RunTelemetryStress");

    printf("\nLifecycle APIs:\n");
    resolve(hDll, "SovereignVersion");
    resolve(hDll, "SovereignInitAll");
    resolve(hDll, "SovereignShutdown");
    resolve(hDll, "PinThreadToCore");

    printf("\nGGUF Loader APIs:\n");
    resolve(hDll, "SovereignLoadModel");
    resolve(hDll, "SovereignUnloadModel");
    resolve(hDll, "SovereignIsModelReady");
    resolve(hDll, "SovereignGetModelInfo");
    resolve(hDll, "SovereignGetTensorCount");
    resolve(hDll, "SovereignGetTensorByIndex");
    resolve(hDll, "SovereignGetTensorOffset");

    printf("\nSovereign Switch APIs (Hook Bypass):\n");
    resolve(hDll, "SovereignSetMode");
    resolve(hDll, "SovereignGetMode");
    resolve(hDll, "SovereignInitHashes");
    resolve(hDll, "SovereignHash");
    resolve(hDll, "SovereignFindNtdll");
    resolve(hDll, "SovereignGetExport");
    resolve(hDll, "SovereignGetSyscallID");
    resolve(hDll, "SovereignCall");

    /* Functional smoke test */
    printf("\n=== Functional Smoke ===\n");

    fn_SovereignVersion    pfnVersion    = (fn_SovereignVersion)   GetProcAddress(hDll, "SovereignVersion");
    fn_SovereignInitAll    pfnInit       = (fn_SovereignInitAll)   GetProcAddress(hDll, "SovereignInitAll");
    fn_SovereignShutdown   pfnShutdown   = (fn_SovereignShutdown)  GetProcAddress(hDll, "SovereignShutdown");
    fn_StreamerInit        pfnStrInit    = (fn_StreamerInit)       GetProcAddress(hDll, "StreamerInit");
    fn_StreamerPushToken   pfnStrPush    = (fn_StreamerPushToken)  GetProcAddress(hDll, "StreamerPushToken");
    fn_StreamerFlush       pfnStrFlush   = (fn_StreamerFlush)      GetProcAddress(hDll, "StreamerFlush");
    fn_InitGhostBuffer     pfnGhostInit  = (fn_InitGhostBuffer)    GetProcAddress(hDll, "InitGhostBuffer");
    fn_PushGhostPrediction pfnGhostPush  = (fn_PushGhostPrediction)GetProcAddress(hDll, "PushGhostPrediction");
    fn_FlushGhostBuffer    pfnGhostFlush = (fn_FlushGhostBuffer)   GetProcAddress(hDll, "FlushGhostBuffer");
    fn_RunTelemetryStress  pfnStress     = (fn_RunTelemetryStress) GetProcAddress(hDll, "RunTelemetryStress");

    if (pfnVersion) {
        printf("Version: %s\n", pfnVersion());
    }

    if (pfnInit) {
        int rc = pfnInit();
        printf("SovereignInitAll() = %d (%s)\n", rc, rc == 0 ? "OK" : "FAIL");
        if (rc != 0) ok = 0;
    }

    if (pfnStrInit) {
        int rc = pfnStrInit();
        printf("StreamerInit() = %d (%s)\n", rc, rc == 1 ? "OK" : "FAIL");
        if (rc != 1) ok = 0;
    }

    if (pfnStrPush && pfnStrFlush) {
        pfnStrPush('H', 0);
        pfnStrPush('i', 0);
        int rc = pfnStrFlush();
        printf("StreamerPushToken + Flush = %d (%s)\n", rc, rc == 1 ? "OK" : "FAIL");
        if (rc != 1) ok = 0;
    }

    if (pfnGhostInit) {
        int rc = pfnGhostInit();
        printf("InitGhostBuffer() = %d (%s)\n", rc, rc == 1 ? "OK" : "FAIL");
        if (rc != 1) ok = 0;
    }

    if (pfnGhostPush && pfnGhostFlush) {
        /* 0.95f as raw IEEE-754 bits = 0x3F733333 */
        int rc = pfnGhostPush("Hello SDK", 9, 0x3F733333);
        printf("PushGhostPrediction() = %d (%s)\n", rc, rc == 1 ? "OK" : "FAIL");
        pfnGhostFlush();
    }

    if (pfnStress) {
        unsigned long long avg = pfnStress(1000);
        printf("RunTelemetryStress(1000) avg = %llu cycles\n", avg);
    }

    if (pfnShutdown) {
        pfnShutdown();
        printf("SovereignShutdown() OK\n");
    }

    /* GGUF Loader functional test */
    printf("\n=== GGUF Loader Smoke ===\n");

    fn_SovereignLoadModel    pfnLoad    = (fn_SovereignLoadModel)   GetProcAddress(hDll, "SovereignLoadModel");
    fn_SovereignUnloadModel  pfnUnload  = (fn_SovereignUnloadModel) GetProcAddress(hDll, "SovereignUnloadModel");
    fn_SovereignIsModelReady pfnReady   = (fn_SovereignIsModelReady)GetProcAddress(hDll, "SovereignIsModelReady");
    fn_SovereignGetModelInfo pfnGetInfo = (fn_SovereignGetModelInfo)GetProcAddress(hDll, "SovereignGetModelInfo");

    if (pfnLoad && pfnReady && pfnUnload) {
        /* Try loading a non-existent file first */
        printf("  About to call SovereignLoadModel(nonexistent)...\n");
        void* handle = pfnLoad("d:\\nonexistent_test_file.gguf");
        printf("  SovereignLoadModel(nonexistent) returned %p\n", handle);
        if (!handle) {
            printf("  SovereignLoadModel(nonexistent) = NULL (expected)\n");
        }

        /* Try loading TinyLlama model */
        printf("  About to call SovereignLoadModel(TinyLlama)...\n");
        handle = pfnLoad("d:\\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf");
        printf("  SovereignLoadModel(TinyLlama) returned %p\n", handle);
        if (handle) {
            printf("  SovereignLoadModel() = %p (OK)\n", handle);

            printf("  About to call SovereignIsModelReady...\n");
            int ready = pfnReady();
            printf("  SovereignIsModelReady returned %d\n", ready);
            printf("SovereignIsModelReady() = %d (%s)\n", ready, ready ? "OK" : "FAIL");
            if (!ready) ok = 0;

            if (pfnGetInfo) {
                printf("  About to call SovereignGetModelInfo...\n");
                MODEL_INFO info = {0};
                pfnGetInfo(&info);
                printf("  SovereignGetModelInfo returned\n");
                printf("  Magic:        0x%08X\n", info.Magic);
                printf("  Version:      %d\n", info.Version);
                printf("  Tensors:      %llu\n", info.TensorCount);
                printf("  KV Pairs:     %llu\n", info.KVCount);
                printf("  VocabSize:    %u\n", info.VocabSize);
                printf("  ContextLen:   %u\n", info.ContextLength);
                printf("  EmbedDim:     %u\n", info.EmbeddingDim);
                printf("  HeadCount:    %u\n", info.HeadCount);
                printf("  LayerCount:   %u\n", info.LayerCount);
                printf("  Arch:         %s\n", info.ArchName);

                /* Tensor API functional test */
                printf("\n=== Tensor API Smoke ===\n");
                fn_SovereignGetTensorCount   pfnTensorCount = (fn_SovereignGetTensorCount)  GetProcAddress(hDll, "SovereignGetTensorCount");
                fn_SovereignGetTensorByIndex pfnTensorByIdx = (fn_SovereignGetTensorByIndex)GetProcAddress(hDll, "SovereignGetTensorByIndex");
                fn_SovereignGetTensorOffset  pfnTensorOff   = (fn_SovereignGetTensorOffset) GetProcAddress(hDll, "SovereignGetTensorOffset");

                if (pfnTensorCount) {
                    unsigned long long tc = pfnTensorCount();
                    printf("TensorCount = %llu (%s)\n", tc, tc == info.TensorCount ? "OK" : "MISMATCH");
                    if (tc != info.TensorCount) ok = 0;
                }

                if (pfnTensorByIdx) {
                    TENSOR_INFO tinfo = {0};
                    int rc = pfnTensorByIdx(0, &tinfo);
                    printf("TensorByIndex(0) = %d, name=%s (%s)\n", rc, tinfo.NameStr, rc == 1 ? "OK" : "FAIL");
                    if (rc != 1) ok = 0;
                }

                if (pfnTensorOff) {
                    unsigned long long off = pfnTensorOff("token_embd.weight");
                    printf("TensorOffset(token_embd.weight) = 0x%llX (%s)\n", off, off != 0xFFFFFFFFFFFFFFFFull ? "OK" : "FAIL");
                    if (off == 0xFFFFFFFFFFFFFFFFull) ok = 0;
                }
            }

            printf("  About to call SovereignUnloadModel...\n");
            pfnUnload(handle);
            printf("  SovereignUnloadModel returned\n");
            printf("SovereignUnloadModel() OK\n");

            /* 10k-cycle load/unload soak */
            printf("\n=== Load/Unload Soak (10000 cycles) ===\n");
            int soak_ok = 1;
            for (int i = 0; i < 10000; ++i) {
                void* h = pfnLoad("d:\\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf");
                if (!h) { soak_ok = 0; break; }
                pfnUnload(h);
            }
            printf("Soak result: %s\n", soak_ok ? "PASS" : "FAIL");
            if (!soak_ok) ok = 0;
        } else {
            printf("SovereignLoadModel() = NULL (model not found or invalid)\n");
            /* Not a hard failure — model may not be present */
        }
    }

    /* Sovereign Switch functional test */
    printf("\n=== Sovereign Switch Smoke (Hook Bypass) ===\n");
    fn_SovereignSetMode      pfnSetMode   = (fn_SovereignSetMode)     GetProcAddress(hDll, "SovereignSetMode");
    fn_SovereignGetMode      pfnGetMode   = (fn_SovereignGetMode)     GetProcAddress(hDll, "SovereignGetMode");
    fn_SovereignInitHashes   pfnInitHash  = (fn_SovereignInitHashes)  GetProcAddress(hDll, "SovereignInitHashes");
    fn_SovereignHash         pfnHash      = (fn_SovereignHash)        GetProcAddress(hDll, "SovereignHash");
    fn_SovereignFindNtdll    pfnFindNtdll = (fn_SovereignFindNtdll)   GetProcAddress(hDll, "SovereignFindNtdll");
    fn_SovereignGetExport    pfnGetExport = (fn_SovereignGetExport)   GetProcAddress(hDll, "SovereignGetExport");
    fn_SovereignGetSyscallID pfnGetScID   = (fn_SovereignGetSyscallID)GetProcAddress(hDll, "SovereignGetSyscallID");
    fn_SovereignCall         pfnCall      = (fn_SovereignCall)        GetProcAddress(hDll, "SovereignCall");

    if (pfnSetMode && pfnGetMode) {
        unsigned long long mode_before = pfnGetMode();
        printf("Default mode = %llu (%s)\n", mode_before, mode_before == 1 ? "Manual (expected)" : "Hybrid");
        pfnSetMode(0);
        unsigned long long mode_after = pfnGetMode();
        printf("SetMode(0) -> GetMode() = %llu (%s)\n", mode_after, mode_after == 0 ? "OK" : "FAIL");
        if (mode_after != 0) ok = 0;
        pfnSetMode(1); /* Restore manual mode */
    }

    if (pfnInitHash && pfnHash) {
        pfnInitHash();
        unsigned long long h1 = pfnHash("NtCreateFile");
        unsigned long long h2 = pfnHash("NtCreateFile");
        printf("Hash consistency: %llX == %llX (%s)\n", h1, h2, h1 == h2 ? "OK" : "FAIL");
        if (h1 != h2) ok = 0;
    }

    if (pfnFindNtdll) {
        void* ntdll = pfnFindNtdll();
        printf("FindNtdll() = %p (%s)\n", ntdll, ntdll ? "OK" : "FAIL");
        if (!ntdll) ok = 0;

        if (ntdll && pfnGetExport && pfnGetScID) {
            /* Resolve NtCreateFile by hash */
            unsigned long long hash = pfnHash("NtCreateFile");
            void* addr = pfnGetExport(hash);
            printf("GetExport(NtCreateFile) = %p (%s)\n", addr, addr ? "OK" : "FAIL");
            if (!addr) ok = 0;

            if (addr) {
                unsigned long long scid = pfnGetScID(addr);
                printf("GetSyscallID(NtCreateFile) = 0x%llX (%s)\n", scid, scid ? "OK" : "FAIL");
                if (!scid) ok = 0;
            }
        }
    }

    if (pfnCall) {
        /* Test SovereignCall in hybrid mode (mode 0) with a safe hash */
        pfnSetMode(0);
        unsigned long long result = pfnCall(0, 0, 0, 0); /* hash=0 should fail gracefully */
        printf("SovereignCall(0) = 0x%llX (%s)\n", result, result == 0xFFFFFFFFFFFFFFFFull ? "OK (expected fail)" : "UNEXPECTED");
        pfnSetMode(1); /* Restore manual mode */
    }

    FreeLibrary(hDll);

    printf("\n=== RESULT: %s ===\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
