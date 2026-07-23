// AgentOllamaClient_stubs.cpp - Stub implementations for AgentOllamaClient
// Provides C++ fallbacks when full Ollama client is not available

#include "AgentOllamaClient.h"
#include <cstring>

namespace RawrXD {
namespace Agent {

// Constructor
AgentOllamaClient::AgentOllamaClient(const OllamaConfig& config) 
    : m_config(config), m_totalDurationMs(0.0), m_consecutiveErrors(0) {
}

// Destructor
AgentOllamaClient::~AgentOllamaClient() {
}

// Connection test
bool AgentOllamaClient::TestConnection() {
    return false;  // Stub - no actual connection
}

OllamaHealth AgentOllamaClient::TestConnectionWithStats() {
    OllamaHealth health;
    health.ok = false;
    health.model_count = 0;
    health.latency_ms = 0;
    health.version = "stub";
    return health;
}

// Get version
std::string AgentOllamaClient::GetVersion() {
    return "stub-0.0.0";
}

// List models
std::vector<std::string> AgentOllamaClient::ListModels() {
    return {};  // Empty list in stub
}

// Chat sync
InferenceResult AgentOllamaClient::ChatSync(const std::vector<ChatMessage>& messages,
                                               const json& tools) {
    (void)messages; (void)tools;
    return InferenceResult::error("AgentOllamaClient is stubbed - no Ollama backend available");
}

// Chat stream
bool AgentOllamaClient::ChatStream(const std::vector<ChatMessage>& messages,
                                     const json& tools,
                                     TokenCallback on_token,
                                     ToolCallCallback on_tool_call,
                                     DoneCallback on_done,
                                     ErrorCallback on_error) {
    (void)messages; (void)tools; (void)on_token; (void)on_tool_call; (void)on_done;
    if (on_error) {
        on_error("AgentOllamaClient is stubbed - no Ollama backend available");
    }
    return false;
}

// FIM sync
InferenceResult AgentOllamaClient::FIMSync(const std::string& prefix,
                                           const std::string& suffix,
                                           const std::string& filename) {
    (void)prefix; (void)suffix; (void)filename;
    return InferenceResult::error("AgentOllamaClient is stubbed - no Ollama backend available");
}

// FIM stream
bool AgentOllamaClient::FIMStream(const std::string& prefix,
                                   const std::string& suffix,
                                   const std::string& filename,
                                   TokenCallback on_token,
                                   DoneCallback on_done,
                                   ErrorCallback on_error) {
    (void)prefix; (void)suffix; (void)filename; (void)on_token; (void)on_done;
    if (on_error) {
        on_error("AgentOllamaClient is stubbed - no Ollama backend available");
    }
    return false;
}

// Cancel stream
void AgentOllamaClient::CancelStream() {
    m_cancelRequested.store(true);
}

// Set config
void AgentOllamaClient::SetConfig(const OllamaConfig& config) {
    m_config = config;
}

// Get average tokens per second
double AgentOllamaClient::GetAvgTokensPerSec() const {
    return 0.0;
}

// Warmup connection
bool AgentOllamaClient::WarmupConnection() {
    return false;
}

// Check model health
bool AgentOllamaClient::CheckModelHealth(const std::string& modelName) {
    (void)modelName;
    return false;
}

// Chat sync with retry
InferenceResult AgentOllamaClient::ChatSyncWithRetry(
    const std::vector<ChatMessage>& messages,
    const json& tools,
    int maxRetries) {
    (void)maxRetries;
    return ChatSync(messages, tools);
}

// Get metrics snapshot
AgentOllamaClient::MetricsSnapshot AgentOllamaClient::GetMetricsSnapshot() const {
    MetricsSnapshot snapshot;
    snapshot.totalRequests = m_totalRequests.load();
    snapshot.totalTokens = m_totalTokens.load();
    snapshot.avgTokensPerSec = GetAvgTokensPerSec();
    snapshot.isStreaming = m_streaming.load();
    snapshot.consecutiveErrors = m_consecutiveErrors;
    snapshot.chatModel = m_config.chat_model;
    snapshot.fimModel = m_config.fim_model;
    snapshot.host = m_config.host;
    snapshot.port = m_config.port;
    return snapshot;
}

// Private helpers
std::string AgentOllamaClient::BuildPromptFromMessages(const std::vector<ChatMessage>& messages,
                                                       const json& tools) const {
    (void)tools;
    std::string prompt;
    for (const auto& msg : messages) {
        prompt += msg.role + ": " + msg.content + "\n";
    }
    return prompt;
}

void AgentOllamaClient::ParseToolCallsFromResponse(const std::string& response, InferenceResult& result) const {
    (void)response; (void)result;
    // No tool calls in stub
}

bool AgentOllamaClient::ShouldEmitError(const std::string& msg) {
    (void)msg;
    return true;
}

} // namespace Agent
} // namespace RawrXD
