// ============================================================================
// AgentOllamaClient.h — Ollama LLM client for agent subsystem
// Extracted from unlinked_symbols_batch_018.cpp / link_stubs_production.cpp
// ============================================================================
#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include <nlohmann/json_fwd.hpp>

namespace RawrXD {
namespace Agent {

struct ChatMessage {
    std::string role;
    std::string content;
    std::string name;
};

struct InferenceResult {
    bool    success = false;
    std::string content;
    std::string error;
    uint64_t tokensGenerated = 0;
    uint64_t tokensPrompt    = 0;
};

struct OllamaConfig {
    std::string host         = "localhost";
    int         port         = 11434;
    std::string defaultModel = "llama3";
    int         timeoutMs    = 30000;
    bool        useGPU       = true;
    int         contextLength = 4096;
};

class AgentOllamaClient {
public:
    explicit AgentOllamaClient(const OllamaConfig& config);
    ~AgentOllamaClient();

    bool TestConnection();
    std::vector<std::string> ListModels();

    InferenceResult ChatSync(const std::vector<ChatMessage>& messages,
                             const nlohmann::json& options);

private:
    OllamaConfig config_;
    bool         m_connected = false;
    bool         m_streaming = false;

    void CancelStream();
};

} // namespace Agent
} // namespace RawrXD
