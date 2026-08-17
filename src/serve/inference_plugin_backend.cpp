// ============================================================================
// inference_plugin_backend.cpp
// ============================================================================
// Directly links CPUInferenceEngine for built-in inference.
// No DLL plugin required — rawrxd-serve is self-contained.
// ============================================================================
#include "inference_plugin_backend.h"
#include "cpu_inference_engine.h"

namespace RawrXD {
namespace Serve {

bool InferencePluginBackend::loadModel(const std::string& path) {
    auto eng = CPUInferenceEngine::GetSharedInstance();
    if (!eng) {
        return false;
    }
    return eng->LoadModel(path);
}

void InferencePluginBackend::unloadModel() {
    auto eng = CPUInferenceEngine::GetSharedInstance();
    if (eng) {
        // CPUInferenceEngine has no separate unload; next LoadModel replaces weights.
    }
}

bool InferencePluginBackend::ready() const {
    auto eng = CPUInferenceEngine::GetSharedInstance();
    return eng && eng->IsModelLoaded();
}

std::string InferencePluginBackend::generate(const GenerateRequest& request,
                                             RawrXD::Serve::StreamTokenFn stream) {
    auto eng = CPUInferenceEngine::GetSharedInstance();
    if (!eng || !eng->IsModelLoaded()) {
        if (stream) stream("[ERROR] No model loaded", true);
        return "[ERROR] No model loaded";
    }

    std::string accumulated;
    try {
        std::string promptText = request.prompt;
        if (promptText.empty() && !request.messages.empty()) {
            // Build prompt from chat messages
            for (const auto& msg : request.messages) {
                promptText += msg.role + ": " + msg.content + "\n";
            }
        }
        auto toks = eng->Tokenize(promptText);
        int maxTokens = request.num_predict > 0 ? request.num_predict : 512;

        eng->GenerateStreaming(
            toks, maxTokens,
            [&](const std::string& piece) {
                accumulated += piece;
                if (stream) stream(piece, false);
            },
            [&]() {
                if (stream) stream("", true);
            });
    } catch (const std::exception& e) {
        std::string err = std::string("[ERROR] Generation failed: ") + e.what();
        if (stream) stream(err, true);
        return err;
    }
    return accumulated;
}

} // namespace Serve
} // namespace RawrXD
