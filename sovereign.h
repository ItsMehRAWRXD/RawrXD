/* ==============================================================================
   sovereign.h — RawrXD Sovereign Framework SDK
   Version: 1.0.0
   Platform: Windows x64
   ABI: Microsoft x64 calling convention (RCX, RDX, R8, R9, stack)
   
   Purpose:
     Expose the 18-component Sovereign Framework as a loadable DLL platform.
     Any C/C++/C# or Rust application can LoadLibrary("sovereign.dll")
     and render predictive ghost text, install hooks, stream AI tokens,
     and collect sub-millisecond telemetry.
   
   License: Proprietary / Commercial — See INTEGRATION_HANDOFF.md
   ============================================================================== */

#ifndef SOVEREIGN_H
#define SOVEREIGN_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------------
   Platform & Calling Convention
   ------------------------------------------------------------------------------ */
#ifdef _WIN64
    #define SOV_API __cdecl
    #ifdef SOVEREIGN_BUILDING_DLL
        #define SOV_EXPORT __declspec(dllexport)
    #else
        #define SOV_EXPORT __declspec(dllimport)
    #endif
#else
    #error "Sovereign SDK supports Windows x64 only."
#endif

/* ------------------------------------------------------------------------------
   Version
   ------------------------------------------------------------------------------ */
#define SOVEREIGN_VERSION_MAJOR 1
#define SOVEREIGN_VERSION_MINOR 0
#define SOVEREIGN_VERSION_PATCH 0
#define SOVEREIGN_VERSION_STR  "1.0.0"

/* ------------------------------------------------------------------------------
   Error / Status Codes
   ------------------------------------------------------------------------------ */
#define SOV_OK                  0
#define SOV_ERR_INIT           -1
#define SOV_ERR_BUFFER_FULL    -2
#define SOV_ERR_NOT_INITIALIZED -3
#define SOV_ERR_HOOK_FAILED    -4
#define SOV_ERR_INVALID_PARAM  -5
#define SOV_ERR_TIMEOUT        -6

/* Ghost-specific status codes */
#define GHOST_OK                0
#define GHOST_STALE             1
#define GHOST_LOW_CONFIDENCE    2
#define GHOST_BUFFER_FULL       3

/* ------------------------------------------------------------------------------
   Constants
   ------------------------------------------------------------------------------ */
#define GHOST_RING_SLOTS        64
#define GHOST_BUFFER_SIZE       4096
#define STREAMER_BUFFER_SIZE    1024
#define LATENCY_BUDGET_US       500     /* 0.5 ms */
#define FLUSH_TIMEOUT_MS        150

/* ------------------------------------------------------------------------------
   Structures (packed to match MASM layout exactly)
   ------------------------------------------------------------------------------ */
#pragma pack(push, 8)

/* 32-byte cache-line-friendly ghost prediction slot */
typedef struct _GHOST_DATA {
    void*       BufferPtr;      /* Pointer to text content */
    size_t      TextLen;        /* Text length in bytes */
    unsigned __int64 Timestamp; /* TSC timestamp at creation */
    float       Confidence;     /* AI confidence score */
    unsigned int Status;      /* GHOST_OK / GHOST_STALE / ... */
} GHOST_DATA;

/* Ring buffer control block (40 bytes) */
typedef struct _GHOST_RING {
    unsigned __int64 Head;        /* Write index (AI producer) */
    unsigned __int64 Tail;        /* Read index (UI consumer) */
    unsigned __int64 SlotCount;   /* Active slots */
    unsigned __int64 DropCount;   /* Dropped frames (stale) */
    unsigned __int64 RenderCount; /* Successfully rendered frames */
    float            Threshold;   /* Current confidence threshold */
    unsigned int     Padding;     /* Align to 40 bytes */
} GHOST_RING;

/* 32-byte statistics block returned by GetGhostStats */
typedef struct _GHOST_STATS {
    unsigned __int64 RenderedFrames;
    unsigned __int64 DroppedFrames;
    unsigned __int64 ActiveSlots;
    unsigned __int64 LastLatencyCycles;
} GHOST_STATS;

/* Hook latency statistics */
typedef struct _HOOK_LATENCY_STATS {
    unsigned __int64 TotalCalls;
    unsigned __int64 TotalCycles;
    unsigned __int64 MinCycles;
    unsigned __int64 MaxCycles;
    double           AverageCycles;
} HOOK_LATENCY_STATS;

#pragma pack(pop)

/* ------------------------------------------------------------------------------
   Ghost Engine API
   ------------------------------------------------------------------------------ */

/* Initialize shared memory ring buffer. Returns 1 on success, 0 on failure. */
SOV_EXPORT int SOV_API InitGhostBuffer(void);

/* Push an AI prediction into the ring buffer.
   text     — Pointer to UTF-8 text content.
   length   — Length in bytes.
   confidence — Float confidence score (0.0–1.0).
   Returns 1 on success, GHOST_BUFFER_FULL if ring is full. */
SOV_EXPORT int SOV_API PushGhostPrediction(
    const char* text,
    size_t      length,
    float       confidence
);

/* Render the next pending prediction to the given HWND.
   hWnd — Editor window handle (0 = test mode, no GDI calls).
   Returns 1 if rendered, 0 if dropped or empty. */
SOV_EXPORT int SOV_API RenderGhostPredictive(void* hWnd);

/* Flush (clear) all pending predictions. Returns number of slots flushed. */
SOV_EXPORT int SOV_API FlushGhostBuffer(void);

/* Periodic maintenance — call from UI thread every frame.
   hWnd — Editor window handle.
   Returns 1 if a prediction was rendered this call. */
SOV_EXPORT int SOV_API GhostHeartbeat(void* hWnd);

/* Query last render latency in TSC cycles. */
SOV_EXPORT unsigned __int64 SOV_API GetGhostLatency(void);

/* Retrieve rendering statistics into outStats. Returns 1 always. */
SOV_EXPORT int SOV_API GetGhostStats(GHOST_STATS* outStats);

/* Set confidence threshold (YOLO mode). Default = 0.8f. */
SOV_EXPORT void SOV_API SetConfidenceThreshold(float threshold);

/* Get current confidence threshold. */
SOV_EXPORT float SOV_API GetConfidenceThreshold(void);

/* ------------------------------------------------------------------------------
   Model Streamer API  (AI Inference → Ghost Engine Bridge)
   ------------------------------------------------------------------------------ */

/* Initialize the model streamer bridge. Returns 1 on success. */
SOV_EXPORT int SOV_API StreamerInit(void);

/* Push a single token character from inference.
   token      — ASCII/UTF-8 byte value.
   confidence — Optional float bits (0 = skip update).
   Returns 1 on success. */
SOV_EXPORT int SOV_API StreamerPushToken(
    unsigned char token,
    float         confidence
);

/* Flush accumulated tokens to the Ghost Engine. Returns 1 on success. */
SOV_EXPORT int SOV_API StreamerFlush(void);

/* Set default confidence for streamed tokens. */
SOV_EXPORT void SOV_API StreamerSetConfidence(float confidence);

/* ------------------------------------------------------------------------------
   Hook Simulator API  (Atomic Detour + Telemetry)
   ------------------------------------------------------------------------------ */

/* Install a 5-byte JMP detour at targetAddress → hookHandler.
   Returns 1 on success, 0 on failure. */
SOV_EXPORT int SOV_API InstallHook(
    void* targetAddress,
    void* hookHandler
);

/* Uninstall hook and restore original bytes.
   Returns 1 on success. */
SOV_EXPORT int SOV_API UninstallHook(void);

/* Retrieve hook latency statistics. */
SOV_EXPORT void SOV_API GetHookLatencyStats(HOOK_LATENCY_STATS* outStats);

/* ------------------------------------------------------------------------------
   Symbolic Validator API  (SIMD + Hash Table)
   ------------------------------------------------------------------------------ */

/* Validate a token string using AVX2 SIMD (vpcmpeqb + vpmovmskb).
   token — Pointer to token bytes.
   len   — Length in bytes.
   Returns 1 if valid, 0 if invalid. */
SOV_EXPORT int SOV_API ValidateTokenSIMD(
    const char* token,
    size_t      len
);

/* 64-bit FNV-1a hash. */
SOV_EXPORT unsigned __int64 SOV_API FNV1A_64(
    const void* data,
    size_t      len
);

/* Build a symbol hash table from a PE module base.
   hModule — Base address of loaded module (from LoadLibrary).
   Returns 1 on success. */
SOV_EXPORT int SOV_API BuildSymbolHashTable(void* hModule);

/* Resolve a symbol address from a PE module by hash.
   hModule — Base address.
   hash    — FNV-1a hash of symbol name.
   Returns symbol RVA or 0 if not found. */
SOV_EXPORT void* SOV_API ResolveSymbolFromPE(
    void*               hModule,
    unsigned __int64    hash
);

/* ------------------------------------------------------------------------------
   Telemetry & Stress Harness API
   ------------------------------------------------------------------------------ */

/* Push a latency sample (in TSC cycles) to the telemetry ring buffer. */
SOV_EXPORT void SOV_API TelemetryPush(unsigned __int64 cycles);

/* Read the oldest latency sample from the telemetry ring buffer.
   Returns 0 if empty. */
SOV_EXPORT unsigned __int64 SOV_API TelemetryRead(void);

/* Run the built-in stress harness for N iterations.
   iterations — Number of telemetry push/read cycles.
   Returns average latency in cycles. */
SOV_EXPORT unsigned __int64 SOV_API RunTelemetryStress(unsigned int iterations);

/* ------------------------------------------------------------------------------
   Framework Lifecycle API
   ------------------------------------------------------------------------------ */

/* Returns SOVEREIGN_VERSION_STR. */
SOV_EXPORT const char* SOV_API SovereignVersion(void);

/* One-shot initialization of all subsystems (Ghost + Streamer + Hook).
   Returns SOV_OK or first error encountered. */
SOV_EXPORT int SOV_API SovereignInitAll(void);

/* Graceful shutdown — flush buffers, uninstall hooks, reset state. */
SOV_EXPORT void SOV_API SovereignShutdown(void);

/* ------------------------------------------------------------------------------
   Threading Helpers (optional — exposed for advanced integrators)
   ------------------------------------------------------------------------------ */

/* Pin current thread to a specific CPU core (0-based). */
SOV_EXPORT void SOV_API PinThreadToCore(unsigned int coreIndex);

/* ------------------------------------------------------------------------------
   GGUF Model Loader API
   ------------------------------------------------------------------------------ */

/* Model info structure (packed to match MASM MODEL_INFO exactly) */
#pragma pack(push, 8)
typedef struct _SOV_MODEL_INFO {
    unsigned int  Magic;
    unsigned int  Version;
    unsigned __int64 TensorCount;
    unsigned __int64 KVCount;
    unsigned int  VocabSize;
    unsigned int  ContextLength;
    unsigned int  EmbeddingDim;
    unsigned int  HeadCount;
    unsigned int  LayerCount;
    unsigned int  QuantType;
    char          ArchName[32];
} SOV_MODEL_INFO;

/* Tensor info structure (packed to match MASM TENSOR_INFO exactly) */
typedef struct _SOV_TENSOR_INFO {
    unsigned __int64 NameHash;
    unsigned __int64 DataOffset;
    unsigned __int64 DataSize;
    unsigned int  Dims[4];
    unsigned int  NDim;
    unsigned int  QuantType;
    char          NameStr[64];
} SOV_TENSOR_INFO;
#pragma pack(pop)

/* Map a .gguf model file and parse header + tensor index.
   path — UTF-8 file path.
   Returns opaque handle (mapped base) on success, NULL on failure. */
SOV_EXPORT void* SOV_API SovereignLoadModel(const char* path);

/* Unmap and close a previously loaded model.
   handle — Value returned by SovereignLoadModel.
   Returns 1 always. */
SOV_EXPORT int SOV_API SovereignUnloadModel(void* handle);

/* Check if a model is loaded and valid.
   Returns 1 if ready, 0 if not. */
SOV_EXPORT int SOV_API SovereignIsModelReady(void);

/* Copy metadata into caller buffer.
   outInfo — Pointer to SOV_MODEL_INFO (at least 80 bytes).
   Returns 1 always. */
SOV_EXPORT int SOV_API SovereignGetModelInfo(SOV_MODEL_INFO* outInfo);

/* Return number of tensors in loaded model. */
SOV_EXPORT unsigned __int64 SOV_API SovereignGetTensorCount(void);

/* Get tensor info by index.
   index   — 0-based tensor index.
   outInfo — Pointer to SOV_TENSOR_INFO buffer.
   Returns 1 if found, 0 if not. */
SOV_EXPORT int SOV_API SovereignGetTensorByIndex(
    unsigned __int64 index,
    SOV_TENSOR_INFO* outInfo
);

/* Lookup tensor data offset by name.
   name — Tensor name string.
   Returns data offset, or (unsigned __int64)-1 if not found. */
SOV_EXPORT unsigned __int64 SOV_API SovereignGetTensorOffset(const char* name);

/* ------------------------------------------------------------------------------
   Sovereign Switch API (Hook Bypass Dispatcher)
   ------------------------------------------------------------------------------ */

/* Set dispatcher mode: 0 = Hybrid (API call), 1 = Manual (direct syscall) */
SOV_EXPORT void SOV_API SovereignSetMode(unsigned long long mode);

/* Get current dispatcher mode */
SOV_EXPORT unsigned long long SOV_API SovereignGetMode(void);

/* Initialize precomputed API hashes */
SOV_EXPORT void SOV_API SovereignInitHashes(void);

/* FNV-1a hash of null-terminated string */
SOV_EXPORT unsigned long long SOV_API SovereignHash(const char* str);

/* Find ntdll.dll base address via PEB walk */
SOV_EXPORT void* SOV_API SovereignFindNtdll(void);

/* Resolve function address by hash via EAT parsing */
SOV_EXPORT void* SOV_API SovereignGetExport(unsigned long long hash);

/* Extract syscall ID from ntdll stub */
SOV_EXPORT unsigned long long SOV_API SovereignGetSyscallID(void* funcAddr);

/* Unified dispatcher: calls API or executes direct syscall based on mode */
SOV_EXPORT unsigned long long SOV_API SovereignCall(unsigned long long hash,
    unsigned long long arg1, unsigned long long arg2, unsigned long long arg3);

/* ------------------------------------------------------------------------------
   Inline Helpers (C-only convenience)
   ------------------------------------------------------------------------------ */
#ifdef __cplusplus
}
#endif

/* Convenience: push a null-terminated string prediction. */
static inline int SovPushPrediction(const char* text, float confidence) {
    size_t len = 0;
    const char* p = text;
    while (*p++) ++len;
    return PushGhostPrediction(text, len, confidence);
}

/* Convenience: push a token with default confidence. */
static inline int SovPushToken(unsigned char token) {
    return StreamerPushToken(token, 0.0f);
}

#endif /* SOVEREIGN_H */
