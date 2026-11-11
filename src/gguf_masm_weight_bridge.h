// ============================================================================
// gguf_masm_weight_bridge.h
// Header for GGUF to MASM weight loading bridge
// ============================================================================

#pragma once

#include "masm/rawrxd_masm_bridge.h"
#include <memory>
#include <string>
#include <vector>

// Forward declaration
class RawrXDModelLoader;

// ============================================================================
// C++ Bridge Class
// ============================================================================

class GGUF_MASM_WeightBridge {
public:
    GGUF_MASM_WeightBridge();
    ~GGUF_MASM_WeightBridge();

    // Load all weights from GGUF into MASM context
    bool LoadFromGGUF(RawrXDModelLoader& loader, RawrXDInferenceCtx& ctx);
    
    // Load specific tensor by name
    bool LoadTensor(RawrXDModelLoader& loader, RawrXDInferenceCtx& ctx, 
                    const std::string& name, float** target, int rows, int cols);
    
    // Cleanup allocated weights
    void Cleanup();
    
    // Get last error message
    const std::string& GetLastError() const { return m_lastError; }

private:
    std::vector<float*> m_allocatedBuffers;
    std::string m_lastError;
    
    bool AllocateAndCopy(float** target, const float* source, size_t count);
    bool LoadLayerWeights(RawrXDModelLoader& loader, RawrXDInferenceCtx& ctx, int layer);
};

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Load weights from GGUF file into MASM context
__declspec(dllexport) bool MASM_LoadGGUFWeights(
    const wchar_t* ggufPath,
    RawrXDInferenceCtx* ctx
);

// Free all loaded weights
__declspec(dllexport) void MASM_FreeWeights(RawrXDInferenceCtx* ctx);

// Initialize context with model dimensions from GGUF
__declspec(dllexport) bool MASM_InitContextFromGGUF(
    const wchar_t* ggufPath,
    RawrXDInferenceCtx* ctx
);

} // extern "C"
