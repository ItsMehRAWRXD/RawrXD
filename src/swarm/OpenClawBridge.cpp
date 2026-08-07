#include "OpenClawBridge.hpp"
#include <sstream>
#include <chrono>
#include <algorithm>

namespace rawrxd {
namespace swarm {

OpenClawBridge::OpenClawBridge() = default;
OpenClawBridge::~OpenClawBridge() = default;

void OpenClawBridge::registerProvider(const std::string& name, const ProviderConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    providers_[name] = config;
}

void OpenClawBridge::unregisterProvider(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    providers_.erase(name);
}

bool OpenClawBridge::hasProvider(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return providers_.find(name) != providers_.end();
}

std::vector<std::string> OpenClawBridge::listProviders() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> names;
    for (const auto& [name, _] : providers_) {
        names.push_back(name);
    }
    return names;
}

ProtocolType OpenClawBridge::detectProtocol(const std::string& url) {
    if (url.find("api.openai.com") != std::string::npos) return ProtocolType::OPENAI;
    if (url.find("api.anthropic.com") != std::string::npos) return ProtocolType::ANTHROPIC;
    if (url.find("localhost:11434") != std::string::npos) return ProtocolType::OLLAMA;
    if (url.find("llamacpp") != std::string::npos) return ProtocolType::LLAMACPP;
    if (url.find("together.xyz") != std::string::npos) return ProtocolType::TOGETHER;
    if (url.find("cohere.com") != std::string::npos) return ProtocolType::COHERE;
    if (url.find("mistral.ai") != std::string::npos) return ProtocolType::MISTRAL;
    if (url.find("groq.com") != std::string::npos) return ProtocolType::GROQ;
    return ProtocolType::CUSTOM;
}

ProtocolCapabilities OpenClawBridge::getCapabilities(ProtocolType type) const {
    ProtocolCapabilities caps;
    
    switch (type) {
        case ProtocolType::OPENAI:
            caps.supportsStreaming = true;
            caps.supportsTools = true;
            caps.supportsVision = true;
            caps.supportsJSONMode = true;
            caps.maxContextLength = 128000; // GPT-4
            break;
        case ProtocolType::ANTHROPIC:
            caps.supportsStreaming = true;
            caps.supportsTools = true;
            caps.supportsVision = true;
            caps.supportsJSONMode = true;
            caps.maxContextLength = 200000; // Claude 3
            break;
        case ProtocolType::OLLAMA:
            caps.supportsStreaming = true;
            caps.supportsTools = false;
            caps.supportsVision = true;
            caps.supportsJSONMode = false;
            caps.maxContextLength = 32768;
            break;
        case ProtocolType::LLAMACPP:
            caps.supportsStreaming = true;
            caps.supportsTools = true;
            caps.supportsVision = false;
            caps.supportsJSONMode = true;
            caps.maxContextLength = 32768;
            break;
        default:
            caps.supportsStreaming = true;
            caps.maxContextLength = 8192;
            break;
    }
    
    return caps;
}

std::string OpenClawBridge::translateRequest(const UnifiedRequest& request, ProtocolType target) {
    switch (target) {
        case ProtocolType::OPENAI:
            return formatOpenAIRequest(request);
        case ProtocolType::ANTHROPIC:
            return formatAnthropicRequest(request);
        case ProtocolType::OLLAMA:
            return formatOllamaRequest(request);
        case ProtocolType::LLAMACPP:
            return formatLlamaCppRequest(request);
        default:
            return formatOpenAIRequest(request); // Default to OpenAI format
    }
}

UnifiedResponse OpenClawBridge::translateResponse(const std::string& response, ProtocolType source) {
    nlohmann::json root;
    
    try {
        root = nlohmann::json::parse(response);
    } catch (const std::exception& e) {
        return createErrorResponse("Failed to parse JSON response: " + std::string(e.what()), -1);
    }
    
    switch (source) {
        case ProtocolType::OPENAI:
            return parseOpenAIResponse(root);
        case ProtocolType::ANTHROPIC:
            return parseAnthropicResponse(root);
        case ProtocolType::OLLAMA:
            return parseOllamaResponse(root);
        case ProtocolType::LLAMACPP:
            return parseLlamaCppResponse(root);
        default:
            return parseOpenAIResponse(root);
    }
}

UnifiedResponse OpenClawBridge::complete(const std::string& provider, const UnifiedRequest& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = providers_.find(provider);
    if (it == providers_.end()) {
        return createErrorResponse("Provider not found: " + provider, 404);
    }
    
    const auto& config = it->second;
    std::string requestBody = translateRequest(request, config.type);
    
    auto start = std::chrono::steady_clock::now();
    
    // Build headers
    std::map<std::string, std::string> headers = config.headers;
    headers["Content-Type"] = "application/json";
    if (!config.apiKey.empty()) {
        headers["Authorization"] = "Bearer " + config.apiKey;
    }
    
    // Make HTTP request (placeholder - would use actual HTTP client)
    std::string response = httpPost(config.baseUrl + "/v1/chat/completions", 
                                     requestBody, headers, config.timeoutMs);
    
    auto end = std::chrono::steady_clock::now();
    int latencyMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    UnifiedResponse result = translateResponse(response, config.type);
    result.latency = std::chrono::milliseconds(latencyMs);
    
    recordRequest(provider, result.success, result.totalTokens, latencyMs);
    
    return result;
}

std::string OpenClawBridge::formatOpenAIRequest(const UnifiedRequest& req) {
    nlohmann::json root;
    root["model"] = req.model;
    root["messages"] = convertMessagesToOpenAI(req.messages);
    root["temperature"] = req.temperature;
    root["top_p"] = req.topP;
    if (req.maxTokens > 0) {
        root["max_tokens"] = req.maxTokens;
    }
    root["stream"] = req.stream;
    
    if (!req.stopSequences.empty()) {
        nlohmann::json stops = nlohmann::json::array();
        for (const auto& s : req.stopSequences) {
            stops.push_back(s);
        }
        root["stop"] = stops;
    }
    
    if (!req.tools.empty()) {
        root["tools"] = convertToolsToOpenAI(req.tools);
        root["tool_choice"] = req.toolChoice;
    }
    
    return root.dump();
}

std::string OpenClawBridge::formatAnthropicRequest(const UnifiedRequest& req) {
    nlohmann::json root;
    root["model"] = req.model;
    root["messages"] = convertMessagesToAnthropic(req.messages);
    root["max_tokens"] = req.maxTokens > 0 ? req.maxTokens : 4096;
    root["temperature"] = req.temperature;
    root["top_p"] = req.topP;
    root["stream"] = req.stream;
    
    if (!req.tools.empty()) {
        root["tools"] = convertToolsToAnthropic(req.tools);
    }
    
    return root.dump();
}

std::string OpenClawBridge::formatOllamaRequest(const UnifiedRequest& req) {
    nlohmann::json root;
    root["model"] = req.model;
    
    // Build prompt from messages
    std::string prompt;
    for (const auto& msg : req.messages) {
        auto roleIt = msg.find("role");
        auto contentIt = msg.find("content");
        if (roleIt != msg.end() && contentIt != msg.end()) {
            prompt += roleIt->second + ": " + contentIt->second + "\n";
        }
    }
    root["prompt"] = prompt;
    root["stream"] = req.stream;
    
    nlohmann::json options;
    options["temperature"] = req.temperature;
    options["top_p"] = req.topP;
    if (req.maxTokens > 0) {
        options["num_predict"] = req.maxTokens;
    }
    root["options"] = options;
    
    return root.dump();
}

std::string OpenClawBridge::formatLlamaCppRequest(const UnifiedRequest& req) {
    // Similar to OpenAI format
    return formatOpenAIRequest(req);
}

nlohmann::json OpenClawBridge::convertMessagesToOpenAI(const std::vector<std::map<std::string, std::string>>& messages) {
    nlohmann::json result = nlohmann::json::array();
    for (const auto& msg : messages) {
        nlohmann::json obj;
        auto roleIt = msg.find("role");
        auto contentIt = msg.find("content");
        if (roleIt != msg.end()) obj["role"] = roleIt->second;
        if (contentIt != msg.end()) obj["content"] = contentIt->second;
        result.push_back(obj);
    }
    return result;
}

nlohmann::json OpenClawBridge::convertMessagesToAnthropic(const std::vector<std::map<std::string, std::string>>& messages) {
    // Anthropic uses similar format but with some differences
    return convertMessagesToOpenAI(messages);
}

nlohmann::json OpenClawBridge::convertToolsToOpenAI(const std::vector<std::map<std::string, nlohmann::json>>& tools) {
    nlohmann::json result = nlohmann::json::array();
    for (const auto& tool : tools) {
        nlohmann::json obj;
        auto typeIt = tool.find("type");
        auto funcIt = tool.find("function");
        if (typeIt != tool.end()) obj["type"] = typeIt->second.get<std::string>();
        if (funcIt != tool.end()) obj["function"] = funcIt->second;
        result.push_back(obj);
    }
    return result;
}

nlohmann::json OpenClawBridge::convertToolsToAnthropic(const std::vector<std::map<std::string, nlohmann::json>>& tools) {
    nlohmann::json result = nlohmann::json::array();
    for (const auto& tool : tools) {
        nlohmann::json obj;
        auto nameIt = tool.find("name");
        auto descIt = tool.find("description");
        auto paramsIt = tool.find("parameters");
        if (nameIt != tool.end()) obj["name"] = nameIt->second.get<std::string>();
        if (descIt != tool.end()) obj["description"] = descIt->second.get<std::string>();
        if (paramsIt != tool.end()) obj["input_schema"] = paramsIt->second;
        result.push_back(obj);
    }
    return result;
}

UnifiedResponse OpenClawBridge::parseOpenAIResponse(const nlohmann::json& json) {
    UnifiedResponse resp;
    
    if (json.contains("error")) {
        resp.success = false;
        resp.errorMessage = json["error"]["message"].get<std::string>();
        resp.errorCode = json["error"].contains("code") && json["error"]["code"].is_number_integer() 
                         ? json["error"]["code"].get<int>() : -1;
        return resp;
    }
    
    resp.id = json.value("id", "");
    
    if (json.contains("choices") && json["choices"].is_array() && !json["choices"].empty()) {
        const auto& choice = json["choices"][0];
        if (choice.contains("message")) {
            resp.content = choice["message"].value("content", "");
            resp.role = choice["message"].value("role", "");
        }
        resp.finishReason = choice.value("finish_reason", "");
    }
    
    if (json.contains("usage")) {
        resp.promptTokens = json["usage"].value("prompt_tokens", 0);
        resp.completionTokens = json["usage"].value("completion_tokens", 0);
        resp.totalTokens = json["usage"].value("total_tokens", 0);
    }
    
    return resp;
}

UnifiedResponse OpenClawBridge::parseAnthropicResponse(const nlohmann::json& json) {
    UnifiedResponse resp;
    
    if (json.contains("error")) {
        resp.success = false;
        resp.errorMessage = json["error"].value("message", "");
        return resp;
    }
    
    resp.id = json.value("id", "");
    
    if (json.contains("content") && json["content"].is_array() && !json["content"].empty()) {
        // Concatenate all content blocks
        std::string content;
        for (const auto& block : json["content"]) {
            if (block.value("type", "") == "text") {
                content += block.value("text", "");
            }
        }
        resp.content = content;
    }
    
    resp.role = json.value("role", "");
    resp.finishReason = json.value("stop_reason", "");
    
    if (json.contains("usage")) {
        resp.promptTokens = json["usage"].value("input_tokens", 0);
        resp.completionTokens = json["usage"].value("output_tokens", 0);
        resp.totalTokens = resp.promptTokens + resp.completionTokens;
    }
    
    return resp;
}

UnifiedResponse OpenClawBridge::parseOllamaResponse(const nlohmann::json& json) {
    UnifiedResponse resp;
    
    if (json.contains("error")) {
        resp.success = false;
        resp.errorMessage = json["error"].get<std::string>();
        return resp;
    }
    
    resp.content = json.value("response", "");
    resp.finishReason = json.value("done", false) ? "stop" : "";
    
    if (json.contains("prompt_eval_count")) {
        resp.promptTokens = json["prompt_eval_count"].get<int>();
    }
    if (json.contains("eval_count")) {
        resp.completionTokens = json["eval_count"].get<int>();
    }
    resp.totalTokens = resp.promptTokens + resp.completionTokens;
    
    return resp;
}

UnifiedResponse OpenClawBridge::parseLlamaCppResponse(const nlohmann::json& json) {
    // Similar to OpenAI
    return parseOpenAIResponse(json);
}

UnifiedResponse OpenClawBridge::createErrorResponse(const std::string& message, int code) {
    UnifiedResponse resp;
    resp.success = false;
    resp.errorMessage = message;
    resp.errorCode = code;
    return resp;
}

bool OpenClawBridge::isRetryableError(int code) {
    return code == 429 || code == 500 || code == 502 || code == 503 || code == 504;
}

void OpenClawBridge::recordRequest(const std::string& provider, bool success, int tokens, int latencyMs) {
    metrics_.totalRequests++;
    if (success) {
        metrics_.successfulRequests++;
    } else {
        metrics_.failedRequests++;
    }
    metrics_.totalTokens += tokens;
    metrics_.requestsByProvider[provider]++;
    
    // Update rolling average latency
    metrics_.avgLatencyMs = (metrics_.avgLatencyMs * (metrics_.totalRequests - 1) + latencyMs) 
                            / metrics_.totalRequests;
}

OpenClawBridge::Metrics OpenClawBridge::getMetrics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return metrics_;
}

void OpenClawBridge::resetMetrics() {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_ = Metrics{};
}

// Placeholder HTTP implementation
std::string OpenClawBridge::httpPost(const std::string& url, const std::string& body,
                                      const std::map<std::string, std::string>& headers, int timeoutMs) {
    // Would use actual HTTP client like libcurl or similar
    // For now return empty JSON
    return "{}";
}

} // namespace swarm
} // namespace rawrxd
