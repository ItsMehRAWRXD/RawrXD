//==============================================================================
// LegacyAdapterStub.cpp - Stub for CreateLegacyInferenceAdapter
// Phase 15B: Quick implementation to unblock build
//==============================================================================

#include "InferenceEngine.h"
#include <memory>

namespace RawrXD {
namespace Inference {

std::unique_ptr<InferenceEngine> CreateLegacyInferenceAdapter(void* engine, const EngineConfig& cfg) {
    // Stub: returns a basic InferenceEngine
    return InferenceEngine::Create(cfg);
}

} // namespace Inference
} // namespace RawrXD
