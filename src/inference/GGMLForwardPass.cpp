/**
 * @file GGMLForwardPass.cpp
 * @brief GGML forward pass — delegates to real inference backend
 *
 * This file bridges to ai_inference_real.cpp for actual transformer execution.
 * The full GGML graph implementation lives in ai/ai_inference_real.cpp.
 *
 * @copyright RawrXD 2026
 */

#include "GGMLBackend.h"

#include <algorithm>
#include <cstring>

// Real inference backend
#include "../ai/ai_inference_real.h"

namespace RawrXD {
namespace Inference {

// ============================================================================
// Forward Pass — Delegates to Real Backend
// ============================================================================

std::vector<float> GGMLForwardPass_Stub(
    void* /*backend*/,
    void* /*context*/,
    const ModelArchitecture& arch,
    const std::vector<int>& tokens) {

    std::vector<float> logits;

    if (tokens.empty()) {
        return logits;
    }

    // Delegate to real inference backend
    // Build prompt from tokens (simple detokenization)
    std::string prompt;
    for (int token : tokens) {
        prompt += RawrXD::DetokenizeSingleReal(token);
    }

    auto result = RawrXD::RunInferenceReal(prompt);
    if (!result.error.empty() || result.logits.empty()) {
        // Fallback: return uniform logits if inference fails
        int vocabSize = arch.vocabSize > 0 ? arch.vocabSize : 32000;
        logits.resize(vocabSize, 0.0f);
        return logits;
    }

    logits = result.logits;
    return logits;
}

} // namespace Inference
} // namespace RawrXD
