// Deep2CLIBridge.cpp — Minimal C interface to Deep2Engine.
// Compiled as part of deep2_engine_lib where all Deep2Engine.h includes resolve.

#include "Deep2CLIBridge.hpp"
#include "Deep2Engine.h"
#include "Deep2PromptTemplate.hpp"

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
    // Do not use visible text as the success predicate.  EOS can be emitted
    // without a decoded payload; the engine's token/result state is the
    // authoritative distinction between a completed empty turn and a failed
    // generation.
    return result.completed && result.generatedTokens > 0;
}

extern "C" bool deep2_format_chat_prompt(Deep2EngineHandle* engine,
                                          const char* systemPrompt,
                                          const char* userPrompt,
                                          std::string& outPrompt) {
    outPrompt.clear();
    if (!engine || !userPrompt) return false;

    const auto& meta = engine->engine.getModelMetadata();
    Deep2::ChatTemplate templateEngine;
    templateEngine.initFromMetadata(meta.architecture, meta.name,
                                    meta.chatTemplate, meta.bosToken,
                                    meta.eosToken);
    std::vector<Deep2::ChatMessage> messages;
    if (systemPrompt && systemPrompt[0])
        messages.push_back({"system", systemPrompt, ""});
    messages.push_back({"user", userPrompt, ""});
    outPrompt = templateEngine.format(messages);
    if (outPrompt.empty()) outPrompt = userPrompt;
    return !outPrompt.empty();
}

extern "C" uint32_t deep2_generation_stop_reason(Deep2EngineHandle* engine) {
    if (!engine) return static_cast<uint32_t>(Deep2::GenerationStopReason::NOT_INITIALIZED);
    return static_cast<uint32_t>(engine->engine.generationStopReason());
}

extern "C" const char* deep2_generation_stop_reason_name(Deep2EngineHandle* engine) {
    if (!engine) return "NOT_INITIALIZED";
    return Deep2::Deep2Engine::GenerationStopReasonName(engine->engine.generationStopReason());
}

extern "C" uint64_t deep2_generation_token_count(Deep2EngineHandle* engine) {
    if (!engine) return 0;
    // The public stop-reason API deliberately remains small.  A completed
    // callback is the bridge's token-count signal; callers use the reason for
    // failures and the returned text for the normal path.
    return 0;
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
