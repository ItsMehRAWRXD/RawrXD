// ============================================================================
// deep2_openai_server.h
// OpenAI-compatible HTTP server for Deep2 local model inference.
// Supports: POST /v1/chat/completions (streaming + non-streaming)
//           GET  /v1/models
//           GET  /health
//           POST /v1/chat/completions (with tool calls)
// ============================================================================

#pragma once

#include "Deep2Engine.h"
#include <cstdint>
#include <string>
#include <functional>
#include <memory>
#include <vector>
#include <thread>
#include <atomic>

namespace Deep2 {

// Per-request context that survives across streaming chunks
struct ChatCompletionRequest {
    std::string               model;
    std::vector<std::pair<std::string, std::string>> messages; // role, content
    std::string               systemPrompt;
    float                     temperature = 0.8f;
    float                     topP = 0.95f;
    uint32_t                  maxTokens = 2048;
    uint32_t                  topK = 40;
    float                     repeatPenalty = 1.0f;
    bool                      stream = false;
    std::vector<std::string>  stopSequences;
    uint64_t                  seed = 0;
    bool                      presencePenalties = false;
    float                     frequencyPenalty = 0.0f;
};

struct ChatCompletionResponse {
    std::string id;
    std::string object = "chat.completion";
    uint64_t    created = 0;
    std::string model;
    struct Choice {
        uint32_t    index = 0;
        std::string role = "assistant";
        std::string content;
        std::string finishReason;
    };
    std::vector<Choice> choices;
    struct Usage {
        uint64_t promptTokens = 0;
        uint64_t completionTokens = 0;
        uint64_t totalTokens = 0;
    };
    Usage usage;
};

struct ChatCompletionStreamChunk {
    std::string id;
    std::string object = "chat.completion.chunk";
    uint64_t    created = 0;
    std::string model;
    struct Choice {
        uint32_t    index = 0;
        struct Delta {
            std::string role;
            std::string content;
        };
        Delta delta;
        std::string finishReason;
    };
    std::vector<Choice> choices;
};

class OpenAIServer {
public:
    OpenAIServer();
    ~OpenAIServer();

    // Load a GGUF model before starting the server.
    // Returns false if model load fails.
    bool loadModel(const std::string& ggufPath);

    // Unload current model (allows hot-swapping).
    void unloadModel();

    // Start the HTTP server on the given port.
    // Blocks until stop() is called.
    bool run(uint16_t port);

    // Graceful shutdown.
    void stop();

    // Is the server currently running?
    bool isRunning() const;

    // Engine access for advanced callers.
    Deep2Engine& engine() { return *engine_; }

    // Set a callback for per-request logging.
    using RequestLogCallback = std::function<void(const std::string& method,
                                                   const std::string& path,
                                                   int statusCode,
                                                   double elapsedMs)>;
    void setRequestLogCallback(RequestLogCallback cb);

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
    std::unique_ptr<Deep2Engine> engine_;
    std::atomic<bool> running_{false};
    std::thread listenerThread_;
    RequestLogCallback logCallback_;
};

} // namespace Deep2
