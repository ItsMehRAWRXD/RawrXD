#include "AgenticSubmitInference_Fix.h"

#include "NativeInferenceClient.h"
#include "AgentToolHandlers.h"
#include "ToolCallResult.h"

#include <algorithm>
#include <cctype>
#include <limits>

namespace RawrXD {
namespace Agentic {

using json = nlohmann::json;

namespace {

std::string TrimAscii(std::string value) {
    const auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

bool ValidateQualityGate(const AgenticInferenceBridge::InferenceResult& result,
                        const std::string& latestResponse,
                        std::string& reason) {
    const std::string trimmed = TrimAscii(latestResponse);
    if (trimmed.empty()) {
        reason = "empty_response";
        return false;
    }

    if (!result.usedTools) {
        return true;
    }

    int successCount = 0;
    int failureCount = 0;
    for (const auto& record : result.toolTrace) {
        if (record.success) {
            ++successCount;
        } else {
            ++failureCount;
        }
    }

    if (successCount == 0 && failureCount > 0) {
        reason = "all_tool_calls_failed";
        return false;
    }

    return true;
}

Agent::ChatMessage BuildQualityRecoveryMessage(const std::string& reason) {
    Agent::ChatMessage qualityMessage;
    qualityMessage.role = "user";
    qualityMessage.content =
        "QUALITY_VALIDATION_FAILED: " + reason +
        ". Continue autonomously: inspect the last tool outputs, pick valid registered tools only, and"
        " produce either (a) corrected tool calls or (b) a final answer that explicitly reports unresolved failures.";
    qualityMessage.tool_call_id.clear();
    qualityMessage.tool_calls = json();
    return qualityMessage;
}

std::string BuildToolMessageContent(const RawrXD::Agent::ToolCallResult& result) {
    if (result.isSuccess()) {
        return result.output.empty() ? "Tool completed successfully." : result.output;
    }

    if (!result.error.empty()) {
        return "Error: " + result.error;
    }

    if (!result.output.empty()) {
        return "Error: " + result.output;
    }

    return "Error: Tool execution failed.";
}

int ClampMaxTokens(size_t maxTokens) {
    if (maxTokens == 0) {
        return 4096;
    }

    if (maxTokens > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return std::numeric_limits<int>::max();
    }

    return static_cast<int>(maxTokens);
}

} // namespace

AgenticInferenceBridge::InferenceResult AgenticInferenceBridge::SubmitInferenceWithTools(
    const std::string& userMessage,
    const std::string& modelName,
    size_t max_tokens,
    const RuntimeConfig& runtime)
{
    InferenceResult bridgeResult;

    Agent::NativeInferenceConfig clientConfig;
    clientConfig.host = runtime.host.empty() ? "127.0.0.1" : runtime.host;
    clientConfig.port = runtime.port == 0 ? 11435 : runtime.port;
    clientConfig.chat_model = modelName.empty() ? "headless-default" : modelName;
    clientConfig.temperature = runtime.temperature;
    clientConfig.max_tokens = ClampMaxTokens(max_tokens);

    Agent::NativeInferenceClient client(clientConfig);

    std::vector<Agent::ChatMessage> messages;
    messages.push_back({"system",
                        Agent::AgentToolHandlers::GetSystemPrompt(
                            runtime.workingDirectory.empty() ? "." : runtime.workingDirectory,
                            {}),
                        "",
                        json()});
    messages.push_back({"user", userMessage, "", json()});

    const json tools = Agent::AgentToolHandlers::GetAllSchemas();
    const int maxIterations = std::max(1, runtime.maxToolIterations);
    std::string latestResponse;

    for (int step = 0; step < maxIterations; ++step) {
        bridgeResult.toolIterations = step + 1;

        Agent::InferenceResult llmResult = client.ChatSync(messages, tools);
        if (!llmResult.success) {
            bridgeResult.error = llmResult.error_message.empty() ? "agentic inference failed"
                                                                 : llmResult.error_message;
            return bridgeResult;
        }

        if (!llmResult.response.empty()) {
            latestResponse = llmResult.response;
            bridgeResult.response = llmResult.response;
        }

        if (!llmResult.has_tool_calls || llmResult.tool_calls.empty()) {
            std::string qualityReason;
            if (!ValidateQualityGate(bridgeResult, latestResponse, qualityReason)) {
                if (step + 1 < maxIterations) {
                    messages.push_back(BuildQualityRecoveryMessage(qualityReason));
                    continue;
                }

                bridgeResult.error = "quality validation failed: " + qualityReason;
                return bridgeResult;
            }

            bridgeResult.success = true;
            if (bridgeResult.response.empty()) {
                bridgeResult.response = latestResponse;
            }
            return bridgeResult;
        }

        bridgeResult.usedTools = true;

        Agent::ChatMessage assistantMessage;
        assistantMessage.role = "assistant";
        assistantMessage.content = llmResult.response;
        assistantMessage.tool_calls = json::array();

        for (size_t i = 0; i < llmResult.tool_calls.size(); ++i) {
            const auto& toolCall = llmResult.tool_calls[i];
            const std::string callId = "call_" + std::to_string(step) + "_" + std::to_string(i);

            json toolCallJson;
            toolCallJson["id"] = callId;
            toolCallJson["type"] = "function";
            toolCallJson["function"] = {{"name", toolCall.first}, {"arguments", toolCall.second}};
            assistantMessage.tool_calls.push_back(toolCallJson);
        }

        messages.push_back(std::move(assistantMessage));

        for (size_t i = 0; i < llmResult.tool_calls.size(); ++i) {
            const auto& toolCall = llmResult.tool_calls[i];
            const std::string callId = "call_" + std::to_string(step) + "_" + std::to_string(i);

            Agent::ToolCallResult toolResult =
                Agent::AgentToolHandlers::Instance().Execute(toolCall.first, toolCall.second);

            InferenceResult::ToolCallRecord record;
            record.toolName = toolCall.first;
            record.callId = callId;
            record.success = toolResult.isSuccess();
            record.output = toolResult.isSuccess()
                                ? (toolResult.output.empty() ? "Tool completed successfully." : toolResult.output)
                                : (toolResult.error.empty() ? toolResult.output : toolResult.error);
            bridgeResult.toolTrace.push_back(std::move(record));

            Agent::ChatMessage toolMessage;
            toolMessage.role = "tool";
            toolMessage.content = BuildToolMessageContent(toolResult);
            toolMessage.tool_call_id = callId;
            toolMessage.tool_calls = json();
            messages.push_back(std::move(toolMessage));
        }
    }

    if (!latestResponse.empty()) {
        std::string qualityReason;
        if (ValidateQualityGate(bridgeResult, latestResponse, qualityReason)) {
            bridgeResult.success = true;
            bridgeResult.response = latestResponse + "\n\n[INFO] Agent step limit reached.";
            return bridgeResult;
        }

        bridgeResult.error = "quality validation failed after step limit: " + qualityReason;
        return bridgeResult;
    }

    bridgeResult.error = "agent step limit reached without a final response";
    return bridgeResult;
}

} // namespace Agentic
} // namespace RawrXD
