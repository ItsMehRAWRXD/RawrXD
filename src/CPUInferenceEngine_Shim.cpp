// ============================================================================
// CPUInferenceEngine_Shim.cpp - Compatibility shim for GetSharedInstance
// Provides GetSharedInstance() that aliases to getInstance()
// ============================================================================

#include "cpu_inference_engine.h"

namespace RawrXD {

// Compatibility shim - GetSharedInstance aliases to getInstance
CPUInferenceEngine* CPUInferenceEngine::GetSharedInstance() {
    return getInstance();
}

} // namespace RawrXD