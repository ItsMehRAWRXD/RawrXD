// ============================================================================
// LlamaNativeBridge.hpp — Stub header for LlamaNativeBridge
// ============================================================================

#ifndef LLAMA_NATIVE_BRIDGE_HPP
#define LLAMA_NATIVE_BRIDGE_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

class LlamaNativeBridge {
public:
    struct GenerationResult {
        std::string text;
        int tokensGenerated = 0;
        double generationTimeMs = 0.0;
    };

    LlamaNativeBridge();
    ~LlamaNativeBridge();

    bool Initialize(const wchar_t* dllPath);
    bool LoadModel(const wchar_t* modelPath, int contextSize, unsigned int seed);
    void UnloadModel();

    GenerationResult Generate(const std::string& prompt, int maxTokens,
                              float temperature, float topP, int topK);
};

#endif // LLAMA_NATIVE_BRIDGE_HPP
