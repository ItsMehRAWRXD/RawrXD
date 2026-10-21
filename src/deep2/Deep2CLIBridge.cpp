// Deep2CLIBridge.cpp — Minimal C interface to Deep2Engine.
// Compiled as part of deep2_engine_lib where all Deep2Engine.h includes resolve.

#include "Deep2CLIBridge.hpp"
#include "Deep2Engine.h"

struct Deep2EngineHandle {
    Deep2::Deep2Engine engine;
};

extern "C" Deep2EngineHandle* deep2_load_model(const char* ggufPath) {
    if (!ggufPath) return nullptr;
    auto* h = new Deep2EngineHandle();
    if (!h->engine.loadModel(ggufPath)) {
        delete h;
        return nullptr;
    }
    return h;
}

extern "C" bool deep2_generate(Deep2EngineHandle* engine,
                               const char* prompt,
                               size_t maxTokens,
                               std::string& outText) {
    if (!engine || !prompt) return false;
    outText = engine->engine.generateText(prompt, maxTokens);
    return !outText.empty();
}

extern "C" bool deep2_generate_stream(Deep2EngineHandle* engine,
                                       const char* prompt,
                                       size_t maxTokens,
                                       Deep2TokenCallback callback,
                                       void* user,
                                       std::string& outText) {
    if (!engine || !prompt || !callback) return false;
    Deep2::GenerationOptions options{};
    options.maxTokens = maxTokens;
    options.temperature = 0.0f;
    options.topK = 1;
    options.topP = 1.0f;
    options.seed = 42;
    const auto result = engine->engine.generateStream(
        prompt, options,
        [&](int32_t tokenId, const std::string& text) -> bool {
            outText += text;
            return callback(tokenId, text.data(), text.size(), user);
        });
    return result.completed && !outText.empty();
}

extern "C" void deep2_free(Deep2EngineHandle* engine) {
    delete engine;
}

extern "C" unsigned deep2_hidden_dim(Deep2EngineHandle* engine) {
    if (!engine) return 0;
    return engine->engine.getConfig().hiddenDim;
}

extern "C" unsigned deep2_vocab_size(Deep2EngineHandle* engine) {
    if (!engine) return 0;
    return engine->engine.getModelWeights().vocabSize;
}

extern "C" size_t deep2_num_layers(Deep2EngineHandle* engine) {
    if (!engine) return 0;
    return engine->engine.getModelWeights().layers.size();
}
