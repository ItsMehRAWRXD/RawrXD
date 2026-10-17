#include "ai_implementation.h"
#include <iostream>
#include <chrono>
#include <algorithm>
#include <nlohmann/json.hpp>

AIImplementation::AIImplementation(
    std::shared_ptr<Logger> logger,
    std::shared_ptr<Metrics> metrics,
    std::shared_ptr<HTTPClient> httpClient,
    std::shared_ptr<ResponseParser> responseParser,
    std::shared_ptr<ModelTester> modelTester
) : m_logger(logger), m_metrics(metrics), m_httpClient(httpClient),
    m_responseParser(responseParser), m_modelTester(modelTester) {
    if (m_logger) {
        m_logger->info("AIImplementation", "Initialized");
    }
}

bool AIImplementation::initialize(const LLMConfig& config) {
    m_config = config;
    if (m_logger) {
        m_logger->info("AIImplementation", "Initializing with backend: " + config.backend);
    }
    return testConnectivity();
}

CompletionResponse AIImplementation::complete(const CompletionRequest& request) {
    auto startTime = std::chrono::high_resolution_clock::now();
    CompletionResponse response;

    try {
        using json = nlohmann::json;

        if (m_config.backend == "ollama") {
            // Build Ollama request
            json ollamaBody;
            ollamaBody["model"] = m_config.modelName;
            ollamaBody["prompt"] = request.prompt;
            ollamaBody["stream"] = false;
            ollamaBody["options"] = json::object();
            ollamaBody["options"]["temperature"] = m_config.temperature;
            ollamaBody["options"]["top_p"] = m_config.topP;
            ollamaBody["options"]["top_k"] = m_config.topK;
            ollamaBody["options"]["num_predict"] = m_config.maxTokens;

            if (!request.messages.empty()) {
                json messages = json::array();
                for (const auto& [role, content] : request.messages) {
                    json msg;
                    msg["role"] = role;
                    msg["content"] = content;
                    messages.push_back(msg);
                }
                ollamaBody["messages"] = messages;
            }

            HTTPRequest httpReq;
            httpReq.method = "POST";
            httpReq.url = m_config.endpoint + "/api/generate";
            httpReq.body = ollamaBody.dump();
            httpReq.headers.push_back({"Content-Type", "application/json"});
            httpReq.timeoutSeconds = m_config.maxTokens / 10 + 30; // Estimate based on tokens

            auto httpResp = m_httpClient->sendRequest(httpReq);

            if (httpResp.success) {
                try {
                    json respJson = json::parse(httpResp.body);
                    response.completion = respJson.value("response", std::string(""));
                    response.totalTokens = respJson.value("eval_count", 0);
                    response.promptTokens = respJson.value("prompt_eval_count", 0);
                    response.completionTokens = respJson.value("eval_count", 0);
                    response.success = true;
                } catch (const json::parse_error& e) {
                    response.success = false;
                    response.errorMessage = "Failed to parse Ollama response: " + std::string(e.what());
                }
            } else {
                response.success = false;
                response.errorMessage = httpResp.errorMessage;
            }
        } else if (m_config.backend == "openai") {
            // Build OpenAI chat completion request
            json openaiBody;
            openaiBody["model"] = m_config.modelName;
            openaiBody["temperature"] = m_config.temperature;
            openaiBody["top_p"] = m_config.topP;
            openaiBody["max_tokens"] = m_config.maxTokens;
            openaiBody["stream"] = false;

            json messages = json::array();
            if (!request.messages.empty()) {
                for (const auto& [role, content] : request.messages) {
                    json msg;
                    msg["role"] = role;
                    msg["content"] = content;
                    messages.push_back(msg);
                }
            } else {
                json sysMsg;
                sysMsg["role"] = "system";
                sysMsg["content"] = "You are a helpful assistant.";
                messages.push_back(sysMsg);
                json userMsg;
                userMsg["role"] = "user";
                userMsg["content"] = request.prompt;
                messages.push_back(userMsg);
            }
            openaiBody["messages"] = messages;

            HTTPRequest httpReq;
            httpReq.method = "POST";
            httpReq.url = m_config.endpoint + "/v1/chat/completions";
            httpReq.body = openaiBody.dump();
            httpReq.headers.push_back({"Content-Type", "application/json"});
            if (!m_config.apiKey.empty()) {
                httpReq.headers.push_back({"Authorization", "Bearer " + m_config.apiKey});
            }
            httpReq.timeoutSeconds = m_config.maxTokens / 10 + 30;

            auto httpResp = m_httpClient->sendRequest(httpReq);

            if (httpResp.success) {
                try {
                    json respJson = json::parse(httpResp.body);
                    if (respJson.contains("choices") && respJson["choices"].is_array() &&
                        !respJson["choices"].empty()) {
                        response.completion = respJson["choices"][0].value("message", json::object()).value("content", std::string(""));
                    }
                    if (respJson.contains("usage")) {
                        response.totalTokens = respJson["usage"].value("total_tokens", 0);
                        response.promptTokens = respJson["usage"].value("prompt_tokens", 0);
                        response.completionTokens = respJson["usage"].value("completion_tokens", 0);
                    }
                    response.success = true;
                } catch (const json::parse_error& e) {
                    response.success = false;
                    response.errorMessage = "Failed to parse OpenAI response: " + std::string(e.what());
                }
            } else {
                response.success = false;
                response.errorMessage = httpResp.errorMessage;
            }
        } else if (m_config.backend == "anthropic") {
            // Build Anthropic Messages API request
            json anthropicBody;
            anthropicBody["model"] = m_config.modelName;
            anthropicBody["temperature"] = m_config.temperature;
            anthropicBody["top_p"] = m_config.topP;
            anthropicBody["max_tokens"] = m_config.maxTokens;

            json messages = json::array();
            if (!request.messages.empty()) {
                for (const auto& [role, content] : request.messages) {
                    json msg;
                    msg["role"] = role;
                    msg["content"] = content;
                    messages.push_back(msg);
                }
            } else {
                json userMsg;
                userMsg["role"] = "user";
                userMsg["content"] = request.prompt;
                messages.push_back(userMsg);
            }
            anthropicBody["messages"] = messages;

            HTTPRequest httpReq;
            httpReq.method = "POST";
            httpReq.url = m_config.endpoint + "/v1/messages";
            httpReq.body = anthropicBody.dump();
            httpReq.headers.push_back({"Content-Type", "application/json"});
            httpReq.headers.push_back({"x-api-key", m_config.apiKey});
            httpReq.headers.push_back({"anthropic-version", "2023-06-01"});
            httpReq.timeoutSeconds = m_config.maxTokens / 10 + 30;

            auto httpResp = m_httpClient->sendRequest(httpReq);

            if (httpResp.success) {
                try {
                    json respJson = json::parse(httpResp.body);
                    if (respJson.contains("content") && respJson["content"].is_array() &&
                        !respJson["content"].empty()) {
                        response.completion = respJson["content"][0].value("text", std::string(""));
                    }
                    if (respJson.contains("usage")) {
                        response.totalTokens = respJson["usage"].value("output_tokens", 0) +
                                                respJson["usage"].value("input_tokens", 0);
                        response.promptTokens = respJson["usage"].value("input_tokens", 0);
                        response.completionTokens = respJson["usage"].value("output_tokens", 0);
                    }
                    response.success = true;
                } catch (const json::parse_error& e) {
                    response.success = false;
                    response.errorMessage = "Failed to parse Anthropic response: " + std::string(e.what());
                }
            } else {
                response.success = false;
                response.errorMessage = httpResp.errorMessage;
            }
        } else {
            response.success = false;
            response.errorMessage = "Unsupported backend: " + m_config.backend;
        }

        // Track metrics
        auto endTime = std::chrono::high_resolution_clock::now();
        response.latencyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime
        ).count();

        m_totalLatency += response.latencyMs;
        m_totalTokensUsed += response.totalTokens;

        if (m_metrics) {
            m_metrics->recordHistogram("ai_completion_latency_ms", static_cast<double>(response.latencyMs));
            m_metrics->incrementCounter("ai_total_tokens", response.totalTokens);
            m_metrics->incrementCounter("ai_requests", 1);
        }

        if (m_logger && response.success) {
            m_logger->info("AIImplementation",
                "Completion successful: " + std::to_string(response.latencyMs) + "ms, " +
                std::to_string(response.totalTokens) + " tokens");
        }

    } catch (const std::exception& e) {
        response.success = false;
        response.errorMessage = std::string("Exception: ") + e.what();
        if (m_logger) {
            m_logger->error("AIImplementation", "Complete failed: " + response.errorMessage);
        }
    }

    return response;
}

CompletionResponse AIImplementation::streamComplete(
    const CompletionRequest& request,
    std::function<void(const ParsedCompletion&)> chunkCallback
) {
    auto startTime = std::chrono::high_resolution_clock::now();
    CompletionResponse response;

    try {
        // Get the full completion first
        auto fullResp = complete(request);

        if (!fullResp.success) {
            response.success = false;
            response.errorMessage = fullResp.errorMessage;
            return response;
        }

        // Parse the completion into chunks using statement/line/token boundaries
        std::string text = fullResp.completion;
        if (text.empty()) {
            response.success = true;
            response.completion = "";
            response.totalTokens = 0;
            return response;
        }

        // Chunk the response by statement boundaries first, then by lines
        std::vector<ParsedCompletion> chunks;
        size_t pos = 0;

        while (pos < text.size()) {
            // Find the next statement boundary
            size_t boundaryPos = text.size();
            std::string boundary = "END_OF_STREAM";
            bool foundBoundary = false;

            // Check for statement boundaries (;, }, {, ), ])
            for (char c : {';', '}', '{', ')', ']'}) {
                size_t found = text.find(c, pos);
                if (found != std::string::npos && found < boundaryPos) {
                    boundaryPos = found;
                    boundary = std::string(1, c);
                    foundBoundary = true;
                }
            }

            // Check for newline
            size_t newlinePos = text.find('\n', pos);
            if (newlinePos != std::string::npos && newlinePos < boundaryPos) {
                boundaryPos = newlinePos;
                boundary = "LINE";
                foundBoundary = true;
            }

            // Extract the chunk
            size_t chunkEnd = foundBoundary ? boundaryPos + 1 : text.size();
            std::string chunkText = text.substr(pos, chunkEnd - pos);

            // Skip empty chunks
            if (!chunkText.empty() && chunkText.find_first_not_of(" \t\n") != std::string::npos) {
                ParsedCompletion chunk;
                chunk.text = chunkText;
                chunk.tokenCount = static_cast<int>(chunkText.size() / 4); // rough estimate
                chunk.confidence = 0.9;
                chunk.boundary = boundary;
                chunk.isComplete = foundBoundary && (boundary == ";" || boundary == "}" || boundary == ")");

                chunks.push_back(chunk);

                // Call the callback for this chunk
                if (chunkCallback) {
                    chunkCallback(chunk);
                }
            }

            pos = chunkEnd;
        }

        // Build the response
        response.completion = fullResp.completion;
        response.chunks = chunks;
        response.totalTokens = fullResp.totalTokens;
        response.completionTokens = fullResp.completionTokens;
        response.promptTokens = fullResp.promptTokens;
        response.success = true;

        // Track metrics
        auto endTime = std::chrono::high_resolution_clock::now();
        response.latencyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime
        ).count();

        m_totalLatency += response.latencyMs;
        m_totalTokensUsed += response.totalTokens;

        if (m_metrics) {
            m_metrics->recordHistogram("ai_stream_completion_latency_ms", static_cast<double>(response.latencyMs));
            m_metrics->incrementCounter("ai_stream_requests", 1);
            m_metrics->incrementCounter("ai_stream_tokens", static_cast<int>(chunks.size()));
        }

        if (m_logger) {
            m_logger->info("AIImplementation",
                "Stream completion successful: " + std::to_string(response.latencyMs) + "ms, " +
                std::to_string(chunks.size()) + " chunks");
        }

    } catch (const std::exception& e) {
        response.success = false;
        response.errorMessage = std::string("Exception: ") + e.what();
        if (m_logger) {
            m_logger->error("AIImplementation", "Stream complete failed: " + response.errorMessage);
        }
    }

    return response;
}

void AIImplementation::registerTool(const ToolDefinition& tool) {
    m_registeredTools[tool.name] = tool;
    if (m_logger) {
        m_logger->info("AIImplementation", "Registered tool: " + tool.name);
    }
}

json AIImplementation::executeTool(const std::string& toolName, const json& parameters) {
    auto it = m_registeredTools.find(toolName);
    if (it == m_registeredTools.end()) {
        if (m_logger) {
            m_logger->error("AIImplementation", "Tool not found: " + toolName);
        }
        json result;
        return result;
    }

    try {
        auto result = it->second.handler(parameters);
        if (m_metrics) {
            m_metrics->incrementCounter("ai_tool_calls", 1);
        }
        return result;
    } catch (const std::exception& e) {
        if (m_logger) {
            m_logger->error("AIImplementation", "Tool execution failed: " + std::string(e.what()));
        }
        json result;
        return result;
    }
}

CompletionResponse AIImplementation::agenticLoop(
    const CompletionRequest& request,
    int maxIterations
) {
    CompletionResponse finalResponse;
    int iteration = 0;

    CompletionRequest currentRequest = request;
    currentRequest.useToolCalling = !m_registeredTools.empty();

    while (iteration < maxIterations) {
        if (m_logger) {
            m_logger->info("AIImplementation", "Agentic loop iteration " + std::to_string(iteration + 1));
        }

        auto response = complete(currentRequest);

        if (!response.success) {
            return response;
        }

        finalResponse = response;
        iteration++;
        if (response.completion.empty()) {
            break;
        }
    }

    if (iteration >= maxIterations && m_logger) {
        m_logger->warn("AIImplementation", "Agentic loop hit max iterations");
    }

    return finalResponse;
}

void AIImplementation::addToHistory(const std::string& role, const std::string& content) {
    m_conversationHistory.push_back({role, content});
}

void AIImplementation::clearHistory() {
    m_conversationHistory.clear();
}

std::vector<std::pair<std::string, std::string>> AIImplementation::getHistory() const {
    return m_conversationHistory;
}

int AIImplementation::estimateTokenCount(const std::string& text) {
    return static_cast<int>(text.length() / 4) + 1;
}

bool AIImplementation::supportsToolCalling() const {
    return (m_config.backend == "openai" || m_config.backend == "anthropic");
}

bool AIImplementation::testConnectivity() {
    try {
        if (m_config.backend == "ollama") {
            auto response = m_httpClient->get(m_config.endpoint + "/api/tags");
            return response.success && response.statusCode == 200;
        } else if (m_config.backend == "openai" || m_config.backend == "anthropic") {
            return !m_config.apiKey.empty();
        }
        return false;
    } catch (...) {
        return false;
    }
}

LLMConfig AIImplementation::getConfig() const {
    return m_config;
}

json AIImplementation::getUsageStats() const {
    json stats = json::object_type();
    return stats;
}

namespace PromptTemplates {
    std::string codeGeneration(const std::string& codeContext, const std::string& requirement) {
        return "Context:\n" + codeContext + "\n\nRequirement:\n" + requirement + "\n\nGenerate code:";
    }

    std::string codeReview(const std::string& code, const std::string& language) {
        return "Review " + language + " code:\n\n" + code + "\n\nProvide feedback:";
    }

    std::string bugFix(const std::string& code, const std::string& errorMessage, const std::string& stackTrace) {
        return "Fix bug:\n\n" + code + "\n\nError: " + errorMessage + "\n\nStack trace:\n" + stackTrace;
    }

    std::string refactoring(const std::string& code, const std::string& language, const std::string& objective) {
        return "Refactor " + language + " code for " + objective + ":\n\n" + code;
    }

    std::string documentation(const std::string& code, const std::string& language) {
        return "Document " + language + " code:\n\n" + code;
    }
}
