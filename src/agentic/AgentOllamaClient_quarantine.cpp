// Fail-closed AgentOllamaClient — linked only when RAWRXD_OPTIONAL_OLLAMA=OFF.
// Replaces AgentOllamaClient.cpp so the HTTP/Ollama-named TU is not in the default link.
#include "AgentOllamaClient.h"

using RawrXD::Agent::AgentOllamaClient;
using RawrXD::Agent::InferenceResult;
using RawrXD::Agent::OllamaHealth;
using RawrXD::Agent::OllamaConfig;
using RawrXD::Agent::ChatMessage;

static constexpr const char* kOff =
    "OPTIONAL_PROVIDER=OFF: remote inference adapter not linked";

AgentOllamaClient::AgentOllamaClient(const OllamaConfig& config) : m_config(config)
{
    m_config.port = 0;
    m_config.host.clear();
}

AgentOllamaClient::~AgentOllamaClient() { CancelStream(); }

bool AgentOllamaClient::TestConnection() { return false; }

OllamaHealth AgentOllamaClient::TestConnectionWithStats()
{
    return {};
}

std::string AgentOllamaClient::GetVersion() { return {}; }

std::vector<std::string> AgentOllamaClient::ListModels() { return {}; }

InferenceResult AgentOllamaClient::ChatSync(const std::vector<ChatMessage>&,
                                            const nlohmann::json&)
{
    return InferenceResult::error(kOff);
}

bool AgentOllamaClient::ChatStream(const std::vector<ChatMessage>&, const nlohmann::json&,
                                   TokenCallback, ToolCallCallback, DoneCallback,
                                   ErrorCallback on_error)
{
    if (on_error)
        on_error(kOff);
    return false;
}

InferenceResult AgentOllamaClient::FIMSync(const std::string&, const std::string&,
                                           const std::string&)
{
    return InferenceResult::error(kOff);
}

bool AgentOllamaClient::FIMStream(const std::string&, const std::string&, const std::string&,
                                  TokenCallback, DoneCallback, ErrorCallback on_error)
{
    if (on_error)
        on_error(kOff);
    return false;
}

void AgentOllamaClient::CancelStream()
{
    m_cancelRequested.store(true);
    m_streaming.store(false);
}

void AgentOllamaClient::SetConfig(const OllamaConfig& config)
{
    m_config = config;
    m_config.port = 0;
    m_config.host.clear();
}

double AgentOllamaClient::GetAvgTokensPerSec() const { return 0.0; }

bool AgentOllamaClient::WarmupConnection() { return false; }

bool AgentOllamaClient::CheckModelHealth(const std::string&) { return false; }

InferenceResult AgentOllamaClient::ChatSyncWithRetry(const std::vector<ChatMessage>& messages,
                                                     const nlohmann::json& tools, int)
{
    return ChatSync(messages, tools);
}

AgentOllamaClient::MetricsSnapshot AgentOllamaClient::GetMetricsSnapshot() const
{
    MetricsSnapshot s;
    s.chatModel = m_config.chat_model;
    s.fimModel = m_config.fim_model;
    return s;
}

std::string AgentOllamaClient::BuildPromptFromMessages(const std::vector<ChatMessage>&,
                                                       const nlohmann::json&) const
{
    return {};
}

void AgentOllamaClient::ParseToolCallsFromResponse(const std::string&,
                                                   InferenceResult&) const
{
}

bool AgentOllamaClient::ShouldEmitError(const std::string&) { return true; }
