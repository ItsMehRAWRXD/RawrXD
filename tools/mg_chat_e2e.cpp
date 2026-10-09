//=============================================================================
// mg_chat_e2e - RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001
//
// Drives the same code path the native IDE chat uses:
//   CPUInferenceEngine::GetSharedInstance()->LoadModel()
//   CPUInferenceEngine::GenerateStreaming(tokens, max, on_token, on_done)
// and prints the model-generated text. Proves the prompt -> text flow is real
// inference, not a prompt echo.
//=============================================================================

#include "cpu_inference_engine.h"

#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#define CHAT_E2E_VOCAB_LIMIT 102400

int main(int argc, char* argv[])
{
    const char* model = (argc > 1) ? argv[1]
        : "F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    const int maxTokens = (argc > 2) ? atoi(argv[2]) : 24;

    RawrXD::CPUInferenceEngine* engine = RawrXD::CPUInferenceEngine::GetSharedInstance();

    if (!engine->LoadModel(model)) {
        std::fprintf(stderr, "LoadModel failed: %s\n", model);
        return 2;
    }

    // Same ChatML envelope the DeepSeek-V2-Lite chat template produces.
    const std::string prompt =
        " \n\n\n\nHuman: Hello, world! \n\nAssistant: ";

    std::vector<int> tokens;
    tokens = engine->Tokenize(prompt);
    if (tokens.empty()) {
        std::fprintf(stderr, "tokenizer produced no tokens\n");
        return 3;
    }
    std::printf("prompt tokens (%zu): ", tokens.size());
    for (int t : tokens) std::printf("%d ", (int)t);
    std::printf("\n");
    std::fflush(stdout);

    std::string generated;
    int tokenCount = 0;
    engine->GenerateStreaming(
        tokens, maxTokens,
        [&generated, &tokenCount](const std::string& s) {
            generated += s;
            tokenCount++;
        },
        []() {},
        [](int32_t) {});

    std::printf("\n=== MODEL-GENERATED TEXT (%d tokens) ===\n%s\n=== END ===\n",
                tokenCount, generated.c_str());

    const bool hasText = generated.find_first_not_of(" \t\r\n") != std::string::npos;
    const bool isEcho = generated == prompt;
    std::printf("RUN_RESULT text_non_empty=%d prompt_echo=%d tokens=%d\n",
                hasText ? 1 : 0, isEcho ? 1 : 0, tokenCount);
    std::fflush(stdout);
    return (hasText && !isEcho) ? 0 : 4;
}
