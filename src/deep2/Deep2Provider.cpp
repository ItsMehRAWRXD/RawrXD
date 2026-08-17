#include "Deep2Provider.h"
#include <chrono>
#include <sstream>

namespace RawrXD {

Deep2Provider::Deep2Provider() = default;

Deep2Provider::~Deep2Provider() {
    Shutdown();
}

bool Deep2Provider::Initialize(const std::string& modelPath) {
    modelPath_ = modelPath;
    
    if (!engine_.LoadModel(modelPath)) {
        return false;
    }
    
    tokenizer_.LoadFromGGUF(modelPath);
    sampler_.Configure(0.7f, 0.9f, 50);
    contextSize_ = engine_.GetMaxContextSize();
    initialized_ = true;
    return true;
}

bool Deep2Provider::IsReady() const {
    return initialized_;
}

void Deep2Provider::Shutdown() {
    if (initialized_) {
        engine_.UnloadModel();
        initialized_ = false;
    }
}

size_t Deep2Provider::GetVRAMUsage() const {
    return engine_.GetVRAMUsage();
}

std::string Deep2Provider::BuildPrompt(const AIRequest& request) {
    std::ostringstream oss;
    
    switch (request.type) {
        case AIRequestType::Completion:
            oss << "<|fim_prefix|>" << request.prompt 
                << "<|fim_suffix|>" << request.context 
                << "<|fim_middle|>";
            break;
        case AIRequestType::Chat:
            oss << "<|system|>\nYou are an expert " << request.language 
                << " developer.\n<|user|>\n" << request.prompt << "\n<|assistant|>\n";
            break;
        case AIRequestType::Explain:
            oss << "Explain this " << request.language << " code:\n```" 
                << request.language << "\n" << request.prompt << "\n```\n\nExplanation:";
            break;
        case AIRequestType::Debug:
            oss << "The following " << request.language 
                << " code has an error:\n```\n" << request.prompt 
                << "\n```\n\nCompiler error:\n" << request.context 
                << "\n\nFix:";
            break;
        case AIRequestType::Optimize:
            oss << "Optimize this " << request.language << " code:\n```\n" 
                << request.prompt << "\n```\n\nOptimized version:";
            break;
        default:
            oss << request.prompt;
    }
    return oss.str();
}

std::string Deep2Provider::PostProcess(const std::string& raw, AIRequestType type) {
    // Extract code blocks from markdown if needed
    auto result = raw;
    
    // Trim stop sequences
    size_t pos = result.find("<|endoftext|>");
    if (pos != std::string::npos) result = result.substr(0, pos);
    
    pos = result.find("<|assistant|>");
    if (pos != std::string::npos) result = result.substr(pos + 13);
    
    return result;
}

AIResponse Deep2Provider::Execute(const AIRequest& request) {
    AIResponse response;
    if (!initialized_) {
        response.success = false;
        return response;
    }

    auto start = std::chrono::high_resolution_clock::now();

    std::string fullPrompt = BuildPrompt(request);
    
    // Configure sampling
    Deep2::SamplingConfig config;
    config.maxTokens = static_cast<int>(request.maxTokens);
    config.temperature = request.temperature;
    config.topP = request.topP;
    
    // Generate
    auto result = engine_.Generate(fullPrompt, config);

    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;

    response.success = result.success;
    
    // Build output from tokens
    std::string output;
    for (const auto& token : result.tokens) {
        output += token.text;
    }
    
    response.text = PostProcess(output, request.type);
    response.tokensGenerated = result.totalTokens;
    response.latencyMs = ms;
    if (ms > 0) {
        response.tokensPerSecond = result.tokensPerSecond;
    }
    response.backend = "Deep2";
    response.modelUsed = modelPath_;

    return response;
}

void Deep2Provider::ExecuteStream(const AIRequest& request, StreamCallback onToken) {
    if (!initialized_) return;

    std::string fullPrompt = BuildPrompt(request);
    
    // Configure sampling
    Deep2::SamplingConfig config;
    config.maxTokens = static_cast<int>(request.maxTokens);
    config.temperature = request.temperature;
    config.topP = request.topP;
    
    // Stream generation
    engine_.GenerateStream(fullPrompt, config,
        [onToken](const std::string& token, bool finished) {
            if (onToken) {
                onToken(token);
            }
        });
}

} // namespace RawrXD
