#pragma once
#include <string>
#include <vector>
#include <functional>

namespace RawrXD {

struct InferenceResult {
    std::string text;
    std::string error;
    std::vector<int> tokens;
    std::vector<float> logits;
    float confidence = 0.0f;
    float perplexity = 0.0f;
};

struct ModelInfoReal {
    std::string path;
    std::string architecture;
    int vocabSize = 0;
    int numLayers = 0;
    int embeddingDim = 0;
    int numHeads = 0;
    int contextLength = 0;
    size_t modelSizeBytes = 0;
};

// Forward declaration of functions from ai_inference_real.cpp
bool RunVulkanTruthPreflight();
bool LoadModelReal(const char* path);
void UnloadModelReal();
bool IsModelLoadedReal();
ModelInfoReal GetModelInfoReal();

InferenceResult RunInferenceReal(const std::string& prompt);
InferenceResult RunInferenceMultiToken(const std::string& prompt, int maxTokens,
                                        float temperature, float topP, int topK);

std::vector<int> TokenizeReal(const std::string& text);
std::string DetokenizeReal(const std::vector<int>& tokens);
std::string DetokenizeSingleReal(int token);

void GenerateStreamReal(const std::string& prompt, int maxTokens,
                        float temperature, float topP, int topK,
                        std::function<bool(const std::string& token, bool finished)> callback);

} // namespace RawrXD
