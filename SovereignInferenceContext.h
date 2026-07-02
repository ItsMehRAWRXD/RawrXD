// ==============================================================================
// SovereignInferenceContext.h — C/C++ Bridge Header for the Inference Pipeline
// ==============================================================================
// Defines the context structure and function prototypes that connect the
// Sovereign_Inference_Dispatcher.asm (MASM) to the C++ IDE host.
//
// Usage:
//   #include "SovereignInferenceContext.h"
//   SovereignInferenceContext ctx = {0};
//   ctx.pMappedModelBase = DISPATCHER_INIT_MODEL("model.gguf");
//   DISPATCHER_INIT_STREAMER();
//   // ... inference loop ...
//   DISPATCHER_SHUTDOWN();
// ==============================================================================

#ifndef SOVEREIGN_INFERENCE_CONTEXT_H
#define SOVEREIGN_INFERENCE_CONTEXT_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==============================================================================
// Error Codes (must match equates in Sovereign_Inference_Dispatcher.asm)
// ==============================================================================
#define DISPATCHER_OK               0
#define DISPATCHER_ERR_INIT         1
#define DISPATCHER_ERR_OPEN_FILE    2
#define DISPATCHER_ERR_MAP_FILE     3
#define DISPATCHER_ERR_STREAMER     4
#define DISPATCHER_ERR_NOT_INIT     5

// ==============================================================================
// Dispatcher State (must match equates in Sovereign_Inference_Dispatcher.asm)
// ==============================================================================
#define DISPATCHER_STATE_UNINIT     0
#define DISPATCHER_STATE_MODEL_OK   1
#define DISPATCHER_STATE_STREAM_OK  2
#define DISPATCHER_STATE_RUNNING    3

// ==============================================================================
// Sovereign Inference Context
// ==============================================================================
typedef struct SovereignInferenceContext {
    void*       pMappedModelBase;   // Provided by DISPATCHER_INIT_MODEL (PAGE_READONLY)
    uint64_t    modelSize;          // Total file size in bytes
    uint64_t    streamerHandle;     // Opaque handle to Ghost Engine connection
    bool        isAuthorized;       // Model integrity verified (GGUF magic + optional hash)
    int         dispatcherState;    // Current DISPATCHER_STATE_*
    int         lastError;          // Last DISPATCHER_ERR_* code
} SovereignInferenceContext;

// ==============================================================================
// Dispatcher API (implemented in Sovereign_Inference_Dispatcher.asm)
// ==============================================================================

/**
 * Load a GGUF model via memory-mapped I/O.
 * @param path  Null-terminated ASCII file path.
 * @return      pMappedBase on success, NULL on failure.
 *              Check lastError in context for specific error code.
 */
void*   DISPATCHER_INIT_MODEL(const char* path);

/**
 * Initialize the token streamer (must call after DISPATCHER_INIT_MODEL).
 * @return  1 on success, 0 on failure.
 */
int     DISPATCHER_INIT_STREAMER(void);

/**
 * Get the current inference context (pMappedBase, modelSize, state).
 * @return  pMappedBase in RAX, modelSize in RDX, state in R8.
 */
void*   DISPATCHER_GET_CONTEXT(void);

/**
 * Push a generated token to the streamer.
 * @param token      Token byte value.
 * @param confidence Optional confidence float bits (0 = use default).
 * @return           1 on success, 0 on failure.
 */
int     DISPATCHER_PUSH_TOKEN(uint8_t token, uint32_t confidence);

/**
 * Force flush of accumulated tokens to Ghost Engine.
 * @return  1 on success, 0 on failure.
 */
int     DISPATCHER_FLUSH(void);

/**
 * Cleanup: unmap model, close handles, flush remaining tokens.
 */
void    DISPATCHER_SHUTDOWN(void);

// ==============================================================================
// Convenience C++ Wrapper (inline, no ABI dependency)
// ==============================================================================
#ifdef __cplusplus

class SovereignInferencePipeline {
public:
    SovereignInferencePipeline() : m_ctx({0}) {}
    ~SovereignInferencePipeline() { if (m_ctx.pMappedModelBase) Shutdown(); }

    bool LoadModel(const char* path) {
        m_ctx.pMappedModelBase = DISPATCHER_INIT_MODEL(path);
        if (!m_ctx.pMappedModelBase) return false;
        m_ctx.isAuthorized = true; // GGUF magic verified by dispatcher
        return true;
    }

    bool InitStreamer() {
        bool ok = DISPATCHER_INIT_STREAMER() != 0;
        if (ok) m_ctx.dispatcherState = DISPATCHER_STATE_STREAM_OK;
        return ok;
    }

    bool PushToken(uint8_t token, float confidence = 0.8f) {
        uint32_t confBits = *reinterpret_cast<uint32_t*>(&confidence);
        return DISPATCHER_PUSH_TOKEN(token, confBits) != 0;
    }

    bool Flush() { return DISPATCHER_FLUSH() != 0; }

    void Shutdown() {
        DISPATCHER_SHUTDOWN();
        m_ctx = {0};
    }

    const SovereignInferenceContext* GetContext() const { return &m_ctx; }

private:
    SovereignInferenceContext m_ctx;
};

} // extern "C"
#endif // __cplusplus

#endif // SOVEREIGN_INFERENCE_CONTEXT_H
