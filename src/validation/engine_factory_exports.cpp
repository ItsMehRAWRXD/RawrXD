// ============================================================================
// RawrXD Factory Exports for External Validation Tools
// Provides C-compatible factory functions for creating/destroying engines
// Minimal version - avoids full header inclusion
// ============================================================================

// Forward declaration only - avoid including full headers
namespace RawrXD {
    class InferenceEngine;
    class CPUInferenceEngine;
}

// Declare factory functions implemented elsewhere (in RawrXD library)
// These should be exported from RawrXD_Gold.lib
extern "C" {
    // Factory functions - implemented in RawrXD library
    __declspec(dllimport) RawrXD::InferenceEngine* CreateCPUInferenceEngine();
    __declspec(dllimport) void DestroyCPUInferenceEngine(RawrXD::InferenceEngine* engine);
}

// Wrapper functions for validation tool
extern "C" {
    // Export wrapper functions
    __declspec(dllexport) RawrXD::InferenceEngine* RawrXD_CreateEngine() {
        return CreateCPUInferenceEngine();
    }
    
    __declspec(dllexport) void RawrXD_DestroyEngine(RawrXD::InferenceEngine* engine) {
        DestroyCPUInferenceEngine(engine);
    }
}