#pragma once
#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace RawrXD {

enum class AIRequestType {
    Completion,
    Chat,
    Explain,
    Refactor,
    Debug,
    Optimize,
    GenerateTests,
    Review
};

struct AIRequest {
    AIRequestType type;
    std::string prompt;
    std::string context;         // Full file/project context
    std::string language;        // C++, ASM, etc.
    uint32_t maxTokens = 256;
    float temperature = 0.7f;
    float topP = 0.9f;
    std::vector<std::string> stopSequences;
};

struct AIResponse {
    bool success = false;
    std::string text;
    uint64_t tokensGenerated = 0;
    double tokensPerSecond = 0.0;
    double latencyMs = 0.0;
    std::string backend;         // "Deep2", "CPU", "GPU", etc.
    std::string modelUsed;
};

using StreamCallback = std::function<void(const std::string& token)>;

class AIProvider {
public:
    virtual ~AIProvider() = default;
    
    virtual bool Initialize(const std::string& modelPath) = 0;
    virtual bool IsReady() const = 0;
    virtual AIResponse Execute(const AIRequest& request) = 0;
    virtual void ExecuteStream(const AIRequest& request, StreamCallback onToken) = 0;
    virtual void Shutdown() = 0;
    
    virtual std::string GetModelName() const = 0;
    virtual size_t GetVRAMUsage() const = 0;
    virtual size_t GetContextSize() const = 0;
};

} // namespace RawrXD
