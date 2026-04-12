#include "AgenticChatSession.h"

#include "AgentOllamaClient.h"
#include "AgentToolHandlers.h"
#include "core/scoped_instructions_provider.hpp"
#include "indexing/incremental_indexer.hpp"
#include "slash_command_parser.hpp"

#include <algorithm>
#include <sstream>
#include <thread>

using json = nlohmann::json;

namespace RawrXD
{
namespace Agentic
{

namespace
{
std::vector<RawrXD::Agent::ChatMessage> BuildAgentMessages(const json& payload)
{
    std::vector<RawrXD::Agent::ChatMessage> messages;
    if (!payload.is_array())
    {
        return messages;
    }
    messages.reserve(payload.size());
    for (const auto& item : payload)
    {
        if (!item.is_object())
        {
            continue;
        }
        RawrXD::Agent::ChatMessage msg;
        msg.role = item.value("role", std::string());
        msg.content = item.value("content", std::string());
        if (msg.role.empty())
        {
            continue;
        }
        messages.push_back(std::move(msg));
    }
    return messages;
}
}  // namespace

AgenticChatSession::AgenticChatSession() = default;

void AgenticChatSession::SetChatModel(std::string ollamaModelTag)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!ollamaModelTag.empty())
    {
        m_model = std::move(ollamaModelTag);
    }
}

AgenticChatSession::~AgenticChatSession()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_cancelled = true;
    if (m_repoMonitoringStarted)
    {
        RawrXD::Indexing::IncrementalRepositoryIndexer::instance().stopMonitoring();
        m_repoMonitoringStarted = false;
    }
}

void AgenticChatSession::Reset()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_history.clear();
    m_streamBuffer.clear();
    m_cancelled = false;
    m_isProcessing = false;
}

void AgenticChatSession::Initialize(const std::string& workspace_root, const std::vector<std::string>& open_files)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_workspaceRoot = workspace_root;
    m_openFiles = open_files;

    RawrXD::Core::ScopedInstructionsProvider::instance().setProjectRoot(workspace_root);
    auto& incrementalIndexer = RawrXD::Indexing::IncrementalRepositoryIndexer::instance();
    incrementalIndexer.initialize(workspace_root);
    if (!m_repoMonitoringStarted)
    {
        incrementalIndexer.startMonitoring();
        m_repoMonitoringStarted = true;
    }

    RawrXD::Agent::ToolGuardrails guardrails;
    guardrails.allowedRoots.push_back(workspace_root);
    guardrails.maxFileSizeBytes = 1024 * 1024;
    guardrails.commandTimeoutMs = 60000;
    guardrails.requireBackupOnWrite = true;
    RawrXD::Agent::AgentToolHandlers::SetGuardrails(guardrails);
}

void AgenticChatSession::RefreshContext(const std::string& workspace_root, const std::vector<std::string>& open_files)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const bool rootChanged = (workspace_root != m_workspaceRoot);
    m_workspaceRoot = workspace_root;
    m_openFiles = open_files;

    RawrXD::Core::ScopedInstructionsProvider::instance().setProjectRoot(workspace_root);
    if (rootChanged)
    {
        auto& incrementalIndexer = RawrXD::Indexing::IncrementalRepositoryIndexer::instance();
        incrementalIndexer.initialize(workspace_root);
        if (!m_repoMonitoringStarted)
        {
            incrementalIndexer.startMonitoring();
            m_repoMonitoringStarted = true;
        }
    }

    RawrXD::Agent::ToolGuardrails guardrails;
    guardrails.allowedRoots.push_back(workspace_root);
    guardrails.maxFileSizeBytes = 1024 * 1024;
    guardrails.commandTimeoutMs = 60000;
    guardrails.requireBackupOnWrite = true;
    RawrXD::Agent::AgentToolHandlers::SetGuardrails(guardrails);
}

void AgenticChatSession::AddToHistory(const ChatMessage& msg)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_history.push_back(msg);
    TrimHistory();
}

void AgenticChatSession::TrimHistory()
{
    if (m_history.size() <= m_maxHistorySize)
    {
        return;
    }
    const size_t start = m_history.size() - m_maxHistorySize;
    m_history.erase(m_history.begin(), m_history.begin() + static_cast<std::ptrdiff_t>(start));
}

std::string AgenticChatSession::BuildSystemPrompt()
{
    std::vector<std::string> scopedSources;
    std::string prompt = RawrXD::Agent::AgentToolHandlers::GetSystemPrompt(
        m_workspaceRoot.empty() ? "." : m_workspaceRoot, m_openFiles, &scopedSources);

    std::ostringstream sessionBlock;
    sessionBlock << "\n\nSession Mode:\n"
                 << "- agentic_mode=" << (m_agenticMode ? "true" : "false") << "\n"
                 << "- processing_async=true\n";
    prompt += sessionBlock.str();
    return prompt;
}

json AgenticChatSession::BuildMessagesPayload()
{
    json messages = json::array();
    messages.push_back({{"role", "system"}, {"content", BuildSystemPrompt()}});
    for (const auto& m : m_history)
    {
        messages.push_back({{"role", m.role}, {"content", m.content}});
    }
    return messages;
}

LLMResponse AgenticChatSession::ParseOpenAIResponse(const json& response)
{
    LLMResponse out;
    if (response.is_object() && response.contains("content") && response["content"].is_string())
    {
        out.content = response["content"].get<std::string>();
    }
    return out;
}

LLMResponse AgenticChatSession::ParseOllamaResponse(const json& response)
{
    LLMResponse out;
    if (response.is_object() && response.contains("response") && response["response"].is_string())
    {
        out.content = response["response"].get<std::string>();
    }
    return out;
}

LLMResponse AgenticChatSession::ParseStreamingResponse(const std::string& chunk)
{
    LLMResponse out;
    out.content = chunk;
    out.finish_reason = "stop";
    return out;
}

std::string AgenticChatSession::FormatToolResultForLLM(const std::string& tool_name, const json& result)
{
    const bool success = result.value("success", false);
    if (!success)
    {
        return "Tool '" + tool_name + "' failed: " + result.value("error", std::string("unknown error"));
    }

    std::string output = result.value("output", std::string());
    constexpr size_t kMax = 2000;
    if (output.size() > kMax)
    {
        output = output.substr(0, kMax) + "... [truncated]";
    }
    return "Tool '" + tool_name + "' succeeded\n" + output;
}

json AgenticChatSession::ExecuteTool(const std::string& name, const json& args)
{
    auto result = RawrXD::Agent::AgentToolHandlers::Instance().Execute(name, args);
    return result.toJson();
}

void AgenticChatSession::RunTurn(const std::string& user_message,
                                 std::function<void(const std::string&)> on_content_chunk,
                                 std::function<void(const std::string&)> on_tool_start,
                                 std::function<void(const std::string&, const std::string&)> on_tool_result,
                                 std::function<void(const std::string&)> on_complete)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_isProcessing)
        {
            on_complete("Busy processing another request.");
            return;
        }
        m_isProcessing = true;
    }

    auto releaseProcessing = [this]()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_isProcessing = false;
    };

    AddToHistory({"user", user_message, "", json()});

    std::string finalText;
    bool executedTool = false;
    if (m_agenticMode && RawrXD::Agentic::SlashCommandParser::IsSlashCommand(user_message))
    {
        const auto parsed = RawrXD::Agentic::SlashCommandParser::Parse(user_message);
        if (!parsed.valid)
        {
            finalText =
                "Slash command parse error: " + parsed.error + "\n\n" + RawrXD::Agentic::SlashCommandParser::GetHelp();
        }
        else if (parsed.command == "help")
        {
            const std::string topic = parsed.args.empty() ? std::string() : parsed.args.front();
            finalText = RawrXD::Agentic::SlashCommandParser::GetHelp(topic);
        }
        else
        {
            const json toolCall = parsed.ToToolCall();
            const std::string toolName = toolCall.value("tool", std::string());
            const json toolArgs = toolCall.value("args", json::object());
            if (toolName.empty())
            {
                finalText = "Slash command did not map to a tool.";
            }
            else
            {
                on_tool_start(toolName);
                const json toolResult = ExecuteTool(toolName, toolArgs);
                finalText = FormatToolResultForLLM(toolName, toolResult);
                on_tool_result(toolName, finalText);
                executedTool = true;
            }
        }
    }

    if (m_agenticMode && user_message.rfind("TOOL_CALL:", 0) == 0)
    {
        const size_t start = user_message.find('{');
        if (start != std::string::npos)
        {
            try
            {
                json toolCall = json::parse(user_message.substr(start));
                const std::string toolName = toolCall.value("name", std::string());
                const json args = toolCall.value("arguments", json::object());
                if (!toolName.empty())
                {
                    on_tool_start(toolName);
                    const json toolResult = ExecuteTool(toolName, args);
                    finalText = FormatToolResultForLLM(toolName, toolResult);
                    on_tool_result(toolName, finalText);
                    executedTool = true;
                }
            }
            catch (const std::exception&)
            {
                finalText = "Malformed TOOL_CALL payload.";
            }
        }
    }

    if (finalText.empty())
    {
        auto payload = BuildMessagesPayload();
        auto messages = BuildAgentMessages(payload);

        RawrXD::Agent::OllamaConfig cfg;
        cfg.chat_model = m_model;
        RawrXD::Agent::AgentOllamaClient client(cfg);

        const json tools = m_agenticMode ? RawrXD::Agent::AgentToolHandlers::GetAllSchemas() : json::array();
        auto inference = client.ChatSync(messages, tools);

        if (!inference.success)
        {
            finalText = "Model inference failed: " + inference.error_message;
        }
        else
        {
            finalText = inference.response;

            if (m_agenticMode && inference.has_tool_calls && !inference.tool_calls.empty())
            {
                const auto& firstTool = inference.tool_calls.front();
                on_tool_start(firstTool.first);
                const json toolResult = ExecuteTool(firstTool.first, firstTool.second);
                const std::string toolSummary = FormatToolResultForLLM(firstTool.first, toolResult);
                on_tool_result(firstTool.first, toolSummary);

                if (finalText.empty())
                {
                    finalText = toolSummary;
                }
                else
                {
                    finalText += "\n\n" + toolSummary;
                }
                executedTool = true;
            }

            if (finalText.empty())
            {
                finalText = "Model returned an empty response.";
            }
        }
    }

    AddToHistory({"assistant", finalText, "", json()});
    if (executedTool && on_content_chunk)
    {
        on_content_chunk("\n");
    }
    on_complete(finalText);
    releaseProcessing();
}

void AgenticChatSession::RunTurnAsync(const std::string& user_message,
                                      std::function<void(const std::string&)> on_content_chunk,
                                      std::function<void(const std::string&)> on_tool_start,
                                      std::function<void(const std::string&, const std::string&)> on_tool_result,
                                      std::function<void(const std::string&)> on_complete)
{
    std::thread worker([=]() { RunTurn(user_message, on_content_chunk, on_tool_start, on_tool_result, on_complete); });
    worker.detach();
}

}  // namespace Agentic
}  // namespace RawrXD
