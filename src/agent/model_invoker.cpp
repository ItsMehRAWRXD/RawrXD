/**
 * @file model_invoker.cpp
 * @brief LLM invocation layer for wish-to-plan transformation (Qt-free)
 *
 * HTTP transport delegated to StlHttpClient (llm_http_client.hpp)
 * which handles WinHTTP on Windows and curl on POSIX.
 * Supports Ollama, Claude, and OpenAI backends.
 *
 * Post-Qt fix: futures are now retained via StlHttpClient/ChainStep
 * to prevent premature destruction that Qt's event loop hid.
 */
#include "model_invoker.hpp"
<<<<<<< HEAD
#include "llm_http_client.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <regex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

// Model Invoker - Production Implementation

namespace fs = std::filesystem;
using json = nlohmann::json;

// ---------------------------------------------------------------------------
// HTTP helper — thin wrapper over StlHttpClient for backward compat
// ---------------------------------------------------------------------------
namespace {

/// Synchronous HTTP POST returning the response body (empty on error).
/// Delegates to StlHttpClient singleton for proper async/future support.
std::string httpPost(const std::string& url, const std::string& body,
                     const std::string& apiKey = {},
                     const std::string& extraHeaderKey = {},
                     const std::string& extraHeaderVal = {},
                     int timeoutMs = 30000) {
    HttpRequest req;
    req.method         = "POST";
    req.url            = url;
    req.body           = body;
    req.apiKey         = apiKey;
    req.extraHeaderKey = extraHeaderKey;
    req.extraHeaderVal = extraHeaderVal;
    req.timeoutMs      = timeoutMs;

    HttpResponse resp = StlHttpClient::instance().send(req);
    if (resp.success) return resp.body;

    fprintf(stderr, "[WARN] [ModelInvoker] HTTP POST failed: %s (HTTP %d, %dms)\n",
            resp.error.c_str(), resp.statusCode, resp.latencyMs);
    return {};
=======
#include <regex>
#include <future>
#include <algorithm>
#include <iostream>
#include <vector>
#include <windows.h>
#include <winhttp.h>
#include <fstream>
#include <filesystem>
#include <mutex>

// Explicit Logic Integration: Bring in the real CPU Inference Engine
#include "../cpu_inference_engine.h"

// Global static instance for embedded inference (Lazy initialized)
// Using native raw pointer or unique_ptr to avoid header dependency issues if unique_ptr undefined
static std::unique_ptr<RawrXD::CPUInferenceEngine> g_embeddedEngine;
static std::mutex g_engineMutex;  

#pragma comment(lib, "winhttp.lib")

/**
 * @brief Constructor
 */
ModelInvoker::ModelInvoker()
{
    m_backend = "ollama";
    m_endpoint = "http://localhost:11434";
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

} // namespace

<<<<<<< HEAD
// ---------------------------------------------------------------------------
// ModelInvoker
// ---------------------------------------------------------------------------

void ModelInvoker::setLLMBackend(const std::string& backend,
                                  const std::string& endpoint,
                                  const std::string& apiKey) {
    m_backend  = backend;
=======
/**
 * @brief Set the LLM backend and endpoint
 */
void ModelInvoker::setLLMBackend(const std::string& backend,
                                  const std::string& endpoint,
                                  const std::string& apiKey)
{
    m_backend = backend;
    std::transform(m_backend.begin(), m_backend.end(), m_backend.begin(), ::tolower);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    m_endpoint = endpoint;
    m_apiKey   = apiKey;

<<<<<<< HEAD
    std::string be = backend;
    std::transform(be.begin(), be.end(), be.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (be == "ollama")       m_model = "mistral";
    else if (be == "claude")  m_model = "claude-3-sonnet-20240229";
    else if (be == "openai")  m_model = "gpt-4o";
    else if (be == "openai-turbo") m_model = "gpt-4-turbo";

    fprintf(stderr, "[INFO] [ModelInvoker] Backend: %s @ %s (model: %s)\n",
            backend.c_str(), endpoint.c_str(), m_model.c_str());
}

void ModelInvoker::setSystemPromptTemplate(const std::string& t) {
    m_customSystemPrompt = t;
}

void ModelInvoker::setCodebaseEmbeddings(const std::map<std::string, float>& e) {
    m_codebaseEmbeddings = e;
=======
    // Set default model based on backend
    if (m_backend == "ollama") {
        m_model = "mistral";
    } else if (m_backend == "claude") {
        m_model = "claude-3-sonnet-20240229";
    } else if (m_backend == "openai") {
        m_model = "gpt-4-turbo";
    }
}

/**
 * @brief Set custom system prompt template
 */
void ModelInvoker::setSystemPromptTemplate(const std::string& template_)
{
    m_customSystemPrompt = template_;
}

/**
 * @brief Set codebase embeddings for RAG
 */
void ModelInvoker::setCodebaseEmbeddings(const std::map<std::string, float>& embeddings)
{
    m_codebaseEmbeddings = embeddings;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ---------------------------------------------------------------------------
LLMResponse ModelInvoker::invoke(const InvocationParams& params) {
    // Cache
    if (m_cachingEnabled) {
<<<<<<< HEAD
        std::string key = getCacheKey(params);
        LLMResponse cached = getCachedResponse(key);
        if (cached.success) {
            fprintf(stderr, "[INFO] [ModelInvoker] Cache hit: %s\n",
                    params.wish.substr(0, 60).c_str());
=======
        std::string cacheKey = getCacheKey(params);
        LLMResponse cached = getCachedResponse(cacheKey);
        if (cached.success) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            return cached;
        }
    }

<<<<<<< HEAD
    fprintf(stderr, "[INFO] [ModelInvoker] Invoking LLM: %s\n",
            params.wish.substr(0, 80).c_str());
    m_isInvoking = true;
    if (onPlanGenerationStarted) onPlanGenerationStarted(params.wish);
=======
    m_isInvoking = true;
    if (onPlanGenerationStarted) {
        onPlanGenerationStarted(params.wish);
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    LLMResponse response;

    try {
<<<<<<< HEAD
        std::string userMsg = buildUserMessage(params);
        json llmResp;

        std::string be = m_backend;
        std::transform(be.begin(), be.end(), be.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (be == "ollama")
            llmResp = sendOllamaRequest(m_model, userMsg, params.maxTokens, params.temperature);
        else if (be == "claude")
            llmResp = sendClaudeRequest(userMsg, params.maxTokens, params.temperature);
        else if (be == "openai" || be == "openai-turbo")
            llmResp = sendOpenAIRequest(userMsg, params.maxTokens, params.temperature);
        else {
=======
        // Build prompts
        std::string systemPrompt = m_customSystemPrompt.empty()
                                   ? buildSystemPrompt(params.availableTools)
                                   : m_customSystemPrompt;
        std::string userMessage = buildUserMessage(params);

        nlohmann::json llmResponse;

        // Invoke appropriate backend
        if (m_backend == "ollama") {
            llmResponse = sendOllamaRequest(m_model, userMessage, params.maxTokens, params.temperature);
        } else if (m_backend == "claude") {
            llmResponse = sendClaudeRequest(userMessage, params.maxTokens, params.temperature);
        } else if (m_backend == "openai") {
            llmResponse = sendOpenAIRequest(userMessage, params.maxTokens, params.temperature);
        } else if (m_backend == "embedded") {
            // Explicit Logic: Use local Titan Engine
            std::lock_guard<std::mutex> lock(g_engineMutex);
            if (!g_embeddedEngine) {
                g_embeddedEngine = std::make_unique<RawrXD::CPUInferenceEngine>();
                // Treat m_endpoint as model path if provided
                std::string modelPath = m_endpoint;
                if (modelPath.starts_with("http") || modelPath.empty()) modelPath = "models/titan-model.gguf"; 
                
                if (!g_embeddedEngine->loadModel(modelPath)) {
                     response.error = "Failed to load embedded model: " + modelPath;
                     m_isInvoking = false;
                     if (onInvocationError) onInvocationError(response.error, true);
                     return response;
                }
            }
            
            // Perform Inference
            response.rawOutput = g_embeddedEngine->infer(userMessage);
            response.tokensUsed = (int)response.rawOutput.length() / 4; 
            
            // Use dummy JSON to bypass empty check below, but we will check backend type 
            llmResponse = nlohmann::json::object(); 
            llmResponse["content"] = response.rawOutput; 
        } else if (m_backend == "rawrxd") {
            // [NEW] RawrXD_Agent.exe IPC Backend
             llmResponse = sendRawrXDRequest(userMessage, params.maxTokens, params.temperature);
        } else {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            response.error = "Unknown backend: " + m_backend;
            m_isInvoking = false;
            return response;
        }

<<<<<<< HEAD
        // --- Fallback chain: if primary backend returned empty, try alternatives ---
        if (llmResp.empty() && !m_apiKey.empty()) {
            fprintf(stderr, "[WARN] [ModelInvoker] Primary backend '%s' failed, attempting fallback chain\n",
                    be.c_str());

            // Fallback 1: OpenAI GPT-4o
            if (be != "openai") {
                std::string savedModel = m_model;
                m_model = "gpt-4o";
                llmResp = sendOpenAIRequest(userMsg, params.maxTokens, params.temperature);
                if (!llmResp.empty()) {
                    be = "openai"; // Update for response parsing below
                    fprintf(stderr, "[INFO] [ModelInvoker] Fallback to GPT-4o succeeded\n");
                } else {
                    m_model = savedModel;
                }
            }

            // Fallback 2: GPT-4-turbo if GPT-4o also failed
            if (llmResp.empty() && m_model != "gpt-4-turbo") {
                std::string savedModel = m_model;
                m_model = "gpt-4-turbo";
                llmResp = sendOpenAIRequest(userMsg, params.maxTokens, params.temperature);
                if (!llmResp.empty()) {
                    be = "openai";
                    fprintf(stderr, "[INFO] [ModelInvoker] Fallback to GPT-4-turbo succeeded\n");
                } else {
                    m_model = savedModel;
                }
            }

            // Fallback 3: Ollama local
            if (llmResp.empty() && be != "ollama" && !m_endpoint.empty()) {
                std::string savedModel = m_model;
                m_model = "mistral";
                llmResp = sendOllamaRequest(m_model, userMsg, params.maxTokens, params.temperature);
                if (!llmResp.empty()) {
                    be = "ollama";
                    fprintf(stderr, "[INFO] [ModelInvoker] Fallback to Ollama/mistral succeeded\n");
                } else {
                    m_model = savedModel;
                }
            }
        }

        if (llmResp.empty()) {
=======
        // Extract response text
        if (llmResponse.empty()) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            response.error = "Empty response from LLM";
            m_isInvoking = false;
            if (onInvocationError) onInvocationError(response.error, true);
            return response;
        }

<<<<<<< HEAD
        // Parse backend-specific format
        if (be == "ollama") {
            response.rawOutput  = llmResp.value("response", "");
            response.tokensUsed = llmResp.value("eval_count", 0)
                                + llmResp.value("prompt_eval_count", 0);
        } else if (be == "claude") {
            auto content = llmResp.value("content", json::array());
            if (!content.empty())
                response.rawOutput = content.at(0).value("text", "");
            if (llmResp.contains("usage"))
                response.tokensUsed = llmResp.at("usage").value("output_tokens", 0);
        } else if (be == "openai") {
            auto choices = llmResp.value("choices", json::array());
            if (!choices.empty())
                response.rawOutput = choices.at(0).value("message", json{}).value("content", "");
            if (llmResp.contains("usage"))
                response.tokensUsed = llmResp.at("usage").value("completion_tokens", 0);
        }

        fprintf(stderr, "[INFO] [ModelInvoker] Response (%d tokens): %.200s\n",
                response.tokensUsed, response.rawOutput.c_str());

        response.parsedPlan = parsePlan(response.rawOutput);

        if (!validatePlanSanity(response.parsedPlan)) {
            response.error   = "Plan failed sanity checks";
            response.success = false;
            m_isInvoking = false;
            if (onInvocationError) onInvocationError(response.error, true);
            return response;
        }

        response.success   = true;
        response.reasoning = llmResp.value("reasoning", "");

        if (m_cachingEnabled) cacheResponse(getCacheKey(params), response);

    } catch (const std::exception& e) {
        response.error   = std::string("Exception: ") + e.what();
=======
        // Parse backend-specific response format
        if (m_backend == "ollama") {
            if (llmResponse.contains("response")) response.rawOutput = llmResponse["response"].get<std::string>();
            if (llmResponse.contains("eval_count") && llmResponse.contains("prompt_eval_count")) {
                response.tokensUsed = llmResponse["eval_count"].get<int>() + 
                                      llmResponse["prompt_eval_count"].get<int>();
            }
        } else if (m_backend == "claude") {
            if (llmResponse.contains("content") && llmResponse["content"].is_array() && !llmResponse["content"].empty()) {
                response.rawOutput = llmResponse["content"][0]["text"].get<std::string>();
            }
            if (llmResponse.contains("usage")) {
                response.tokensUsed = llmResponse["usage"]["output_tokens"].get<int>();
            }
        } else if (m_backend == "openai") {
            if (llmResponse.contains("choices") && llmResponse["choices"].is_array() && !llmResponse["choices"].empty()) {
                response.rawOutput = llmResponse["choices"][0]["message"]["content"].get<std::string>();
            }
            if (llmResponse.contains("usage")) {
                response.tokensUsed = llmResponse["usage"]["completion_tokens"].get<int>();
            }
        } else if (m_backend == "rawrxd") {
            // RawrXD returns direct text in "response"
            if (llmResponse.contains("response")) {
                response.rawOutput = llmResponse["response"].get<std::string>();
            }
        }

        if (params.enforceJsonFormat) {
            // Parse into structured plan
            response.parsedPlan = parsePlan(response.rawOutput);

            // Validate sanity
            if (!validatePlanSanity(response.parsedPlan)) {
                response.error = "Plan failed sanity checks";
                response.success = false;
                m_isInvoking = false;
                if (onInvocationError) onInvocationError(response.error, true);
                return response;
            }
        }

        response.success = true;
        if (llmResponse.contains("reasoning")) response.reasoning = llmResponse["reasoning"].get<std::string>();

        // Cache successful response
        if (m_cachingEnabled) {
            cacheResponse(getCacheKey(params), response);
        }

    } catch (const std::exception& e) {
        response.error = "Exception: " + std::string(e.what());
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        response.success = false;
        if (onInvocationError) onInvocationError(response.error, false);
    }

    m_isInvoking = false;
    return response;
}

<<<<<<< HEAD
void ModelInvoker::invokeAsync(const InvocationParams& params) {
    // Post-Qt fix: Use std::async + retain the future as member.
    // Qt's deleteLater() auto-managed reply lifetime; STL requires explicit
    // future retention or the destructor blocks/cancels the async operation.
    m_asyncFuture = std::async(std::launch::async, [this, params]() {
        LLMResponse resp = invoke(params);
        if (onPlanGenerated) onPlanGenerated(resp);
    });
=======
/**
 * @brief Asynchronous invocation (non-blocking)
 */
void ModelInvoker::invokeAsync(const InvocationParams& params)
{
    std::thread([this, params]() {
        LLMResponse response = invoke(params);
        if (onPlanGenerated) {
            onPlanGenerated(response);
        }
    }).detach();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void ModelInvoker::cancelPendingRequest() {
    m_isInvoking = false;
<<<<<<< HEAD
    fprintf(stderr, "[INFO] [ModelInvoker] Request cancelled\n");
}

// ---------------------------------------------------------------------------
// Prompt building
// ---------------------------------------------------------------------------
std::string ModelInvoker::buildSystemPrompt(const std::vector<std::string>& tools) {
    std::string p = R"(You are an intelligent IDE agent for the RawrXD code generation framework.
=======
}

/**
 * @brief Build system prompt with tool descriptions
 */
std::string ModelInvoker::buildSystemPrompt(const std::vector<std::string>& tools)
{
    std::string prompt = R"(You are an intelligent IDE agent for the RawrXD code generation framework.
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

Your role is to transform natural language wishes into structured action plans that can be executed by an automated system.

# Available Tools
)";
    for (const auto& t : tools) p += "- " + t + "\n";

<<<<<<< HEAD
    p += R"(
=======
    for (const auto& tool : tools) {
        prompt += "- " + tool + "\n";
    }

    prompt += R"(
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
# Response Format
Respond with a valid JSON array of actions. Each action must have:
- type: string (action type name)
- target: string (file, command, or target)
- params: object (action-specific parameters)
- description: string (human-readable description)

<<<<<<< HEAD
=======
Example:
```json
[
  {
    "type": "search_files",
    "target": "src/",
    "params": { "pattern": "*.{cpp,hpp,h,c}", "query": "TODO|FIXME|XXX" },
    "description": "Scan C/C++ source files for temporary markers and technical debt."
  }
]
```

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
# Constraints
- Do NOT suggest destructive operations without explicit user intent
- Always break complex tasks into manageable steps
- Use existing patterns found in the codebase
)";
    return p;
}

<<<<<<< HEAD
std::string ModelInvoker::buildUserMessage(const InvocationParams& params) {
    std::string msg = "User Wish: " + params.wish + "\n\n";
    if (!params.context.empty())
        msg += "Context: " + params.context + "\n\n";
    if (!params.codebaseContext.empty())
        msg += "Relevant Codebase:\n" + params.codebaseContext + "\n\n";
    msg += "Please generate a structured action plan. Respond with ONLY valid JSON array.";
    return msg;
}

// ---------------------------------------------------------------------------
// Backend-specific HTTP calls
// ---------------------------------------------------------------------------
json ModelInvoker::sendOllamaRequest(const std::string& model,
                                      const std::string& prompt,
                                      int maxTokens, double temperature) {
    json payload = nlohmann::json::object({
        {"model",       model},
        {"prompt",      prompt},
        {"temperature", temperature},
        {"num_predict", maxTokens},
        {"stream",      false}
    });

    std::string url = m_endpoint + "/api/generate";
    fprintf(stderr, "[INFO] [ModelInvoker] POST %s\n", url.c_str());
    std::string resp = httpPost(url, payload.dump(), {}, {}, {}, 30000);

    if (resp.empty()) return {};
    try { return json::parse(resp); }
    catch (const std::exception& e) {
        fprintf(stderr, "[WARN] [ModelInvoker] Ollama JSON parse error: %s\n", e.what());
        return {};
    }
}

json ModelInvoker::sendClaudeRequest(const std::string& prompt,
                                      int maxTokens, double temperature) {
    json payload = nlohmann::json::object({
        {"model",      m_model},
        {"max_tokens", maxTokens},
        {"temperature", temperature},
        {"messages",   json::array({nlohmann::json::object({{"role", "user"}, {"content", prompt}})}) }
    });

    std::string resp = httpPost("https://api.anthropic.com/v1/messages",
                                payload.dump(), m_apiKey,
                                "x-api-key", m_apiKey, 30000);
    // Note: Claude uses x-api-key header, not Bearer token; we send both

    if (resp.empty()) return {};
    try { return json::parse(resp); }
    catch (const std::exception& e) {
        fprintf(stderr, "[WARN] [ModelInvoker] Claude JSON parse error: %s\n", e.what());
        return {};
    }
}

json ModelInvoker::sendOpenAIRequest(const std::string& prompt,
                                      int maxTokens, double temperature) {
    json payload = nlohmann::json::object({
        {"model",      m_model},
        {"max_tokens", maxTokens},
        {"temperature", temperature},
        {"messages",   json::array({nlohmann::json::object({{"role", "user"}, {"content", prompt}})}) }
    });

    std::string resp = httpPost("https://api.openai.com/v1/chat/completions",
                                payload.dump(), m_apiKey, {}, {}, 30000);

    if (resp.empty()) return {};
    try { return json::parse(resp); }
    catch (const std::exception& e) {
        fprintf(stderr, "[WARN] [ModelInvoker] OpenAI JSON parse error: %s\n", e.what());
        return {};
    }
}

// ---------------------------------------------------------------------------
// Plan parsing
// ---------------------------------------------------------------------------
json ModelInvoker::parsePlan(const std::string& llmOutput) {
    // Strategy 1: Extract ```json ... ``` block
    std::regex jsonBlock(R"(```(?:json)?\s*\n?([\s\S]*?)\n?```)");
    std::smatch match;
    if (std::regex_search(llmOutput, match, jsonBlock)) {
        try {
            auto doc = json::parse(match[1].str());
            if (doc.is_array()) return doc;
        } catch (...) {}
    }

    // Strategy 2: Parse entire output
    try {
        auto doc = json::parse(llmOutput);
        if (doc.is_array()) return doc;
    } catch (...) {}

    // Strategy 3: Fallback
    fprintf(stderr, "[WARN] [ModelInvoker] Failed to parse plan from LLM output\n");
    return json::array({nlohmann::json::object({
        {"type",        "user_input"},
        {"description", llmOutput.substr(0, 500)}
    })});
}

bool ModelInvoker::validatePlanSanity(const json& plan) {
    if (!plan.is_array() || plan.empty()) {
        fprintf(stderr, "[WARN] [ModelInvoker] Empty plan\n");
        return false;
    }

    int count = 0;
    std::vector<std::string> seen;
    for (size_t i = 0; i < plan.size(); ++i) {
        const auto& action = plan.at(i);
        if (!action.is_object()) return false;
        std::string type = action.value("type", "");

        if (type == "file_delete" || type == "format_drive" || type == "system_reboot") {
            fprintf(stderr, "[WARN] [ModelInvoker] Dangerous op: %s\n", type.c_str());
            return false;
        }

        std::string target = action.value("target", "");
        if (!target.empty() &&
            std::find(seen.begin(), seen.end(), target) != seen.end()) {
            fprintf(stderr, "[WARN] [ModelInvoker] Circular dep on: %s\n", target.c_str());
            return false;
        }
        seen.push_back(target);

        if (++count > 100) {
            fprintf(stderr, "[WARN] [ModelInvoker] Plan too large\n");
            return false;
        }
    }
=======
/**
 * @brief Build user message with wish and context
 */
std::string ModelInvoker::buildUserMessage(const InvocationParams& params)
{
    std::string message = "User Wish: " + params.wish + "\n\n";

    if (!params.context.empty()) {
        message += "Context: " + params.context + "\n\n";
    }

    if (!params.codebaseContext.empty()) {
        message += "Relevant Codebase:\n" + params.codebaseContext + "\n\n";
    }

    if (params.enforceJsonFormat) {
        message += "Please generate a structured action plan to fulfill this wish. "
                   "Respond with ONLY valid JSON array, no additional text.";
    } else {
        // Raw text mode (e.g. for code completion)
        message += "Please complete the code. Respond with ONLY the code, no markdown block markers.";
    }

    return message;
}

nlohmann::json ModelInvoker::sendOllamaRequest(const std::string& model,
                                                const std::string& prompt,
                                                int maxTokens,
                                                double temperature)
{
    nlohmann::json payload;
    payload["model"] = model;
    payload["prompt"] = prompt;
    payload["temperature"] = temperature;
    payload["num_predict"] = maxTokens;
    payload["stream"] = false;

    std::string url = m_endpoint + "/api/generate";
    std::string responseData = performHttpRequest(url, "POST", payload.dump(), {{"Content-Type", "application/json"}});

    try {
        return nlohmann::json::parse(responseData);
    } catch (...) {
        return nlohmann::json::object();
    }
}

nlohmann::json ModelInvoker::sendClaudeRequest(const std::string& prompt,
                                                int maxTokens,
                                                double temperature)
{
    nlohmann::json payload;
    payload["model"] = m_model;
    payload["max_tokens"] = maxTokens;
    payload["temperature"] = temperature;
    payload["messages"] = nlohmann::json::array({{{"role", "user"}, {"content", prompt}}});

    std::string url = (m_endpoint == "https://api.anthropic.com") ? m_endpoint + "/v1/messages" : m_endpoint + "/v1/messages";
    std::string responseData = performHttpRequest(url, "POST", payload.dump(), {
        {"Content-Type", "application/json"},
        {"x-api-key", m_apiKey},
        {"anthropic-version", "2023-06-01"}
    });

    try {
        return nlohmann::json::parse(responseData);
    } catch (...) {
        return nlohmann::json::object();
    }
}

nlohmann::json ModelInvoker::sendOpenAIRequest(const std::string& prompt,
                                                int maxTokens,
                                                double temperature)
{
    nlohmann::json payload;
    payload["model"] = m_model;
    payload["messages"] = nlohmann::json::array({{{"role", "user"}, {"content", prompt}}});
    payload["max_tokens"] = maxTokens;
    payload["temperature"] = temperature;

    std::string url = (m_endpoint == "https://api.openai.com") ? m_endpoint + "/v1/chat/completions" : m_endpoint + "/v1/chat/completions";
    std::string responseData = performHttpRequest(url, "POST", payload.dump(), {
        {"Content-Type", "application/json"},
        {"Authorization", "Bearer " + m_apiKey}
    });

    try {
        return nlohmann::json::parse(responseData);
    } catch (...) {
        return nlohmann::json::object();
    }
}

    // [NEW] RawrXD IPC Implementation
nlohmann::json ModelInvoker::sendRawrXDRequest(const std::string& messageBlock, int maxTokens, float temperature) {
    nlohmann::json result;
    result["response"] = "";

    HANDLE hPipe = CreateFileA(
        "\\\\.\\pipe\\RawrXD_IPC",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        // Fallback or silent fail
        return result; 
    }

    // Tokenize Locally (Simple ASCII/Byte Packing for now)
    // We convert std::string chars to int32 tokens so the ASM backend receives the expected format.
    std::vector<int32_t> tokens;
    for (unsigned char c : messageBlock) {
        tokens.push_back(static_cast<int32_t>(c));
    }

    // Send Prompt
    DWORD bytesWritten;
    bool success = WriteFile(hPipe, tokens.data(), tokens.size() * sizeof(int32_t), &bytesWritten, NULL);
    
    if (success) {
        int32_t buffer[2048]; // Read up to 2048 tokens
        DWORD bytesRead;
        if (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
            // Detokenize (Int32 -> Char)
            std::string resp;
            int count = bytesRead / sizeof(int32_t);
            for (int i = 0; i < count; ++i) {
                int32_t tok = buffer[i];
                if (tok < 256 && tok > 0) {
                    resp += static_cast<char>(tok);
                }
            }
             result["response"] = resp;
        }
    }

    CloseHandle(hPipe);
    return result;
}

/**
 * @brief Invoke Ollama API
 */
nlohmann::json ModelInvoker::sendOllamaRequest(const std::string& model, 
                                                const std::string& prompt,
                                                int maxTokens,
                                                double temperature)
{
    nlohmann::json payload;
    payload["model"] = model;
    payload["prompt"] = prompt;
    payload["temperature"] = temperature;
    payload["num_predict"] = maxTokens;
    payload["stream"] = false;

    std::string url = m_endpoint + "/api/generate";
    std::string responseData = performHttpRequest(url, "POST", payload.dump(), {{"Content-Type", "application/json"}});

    try {
        return nlohmann::json::parse(responseData);
    } catch (...) {
        return nlohmann::json::object();
    }
}

nlohmann::json ModelInvoker::sendClaudeRequest(const std::string& prompt,
                                                int maxTokens,
                                                double temperature)
{
    nlohmann::json payload;
    payload["model"] = m_model;
    payload["max_tokens"] = maxTokens;
    payload["temperature"] = temperature;
    payload["messages"] = nlohmann::json::array({{{"role", "user"}, {"content", prompt}}});

    std::string url = (m_endpoint == "https://api.anthropic.com") ? m_endpoint + "/v1/messages" : m_endpoint + "/v1/messages";
    std::string responseData = performHttpRequest(url, "POST", payload.dump(), {
        {"Content-Type", "application/json"},
        {"x-api-key", m_apiKey},
        {"anthropic-version", "2023-06-01"}
    });

    try {
        return nlohmann::json::parse(responseData);
    } catch (...) {
        return nlohmann::json::object();
    }
}

nlohmann::json ModelInvoker::sendOpenAIRequest(const std::string& prompt,
                                                int maxTokens,
                                                double temperature)
{
    nlohmann::json payload;
    payload["model"] = m_model;
    payload["messages"] = nlohmann::json::array({{{"role", "user"}, {"content", prompt}}});
    payload["max_tokens"] = maxTokens;
    payload["temperature"] = temperature;

    std::string url = (m_endpoint == "https://api.openai.com") ? m_endpoint + "/v1/chat/completions" : m_endpoint + "/v1/chat/completions";
    std::string responseData = performHttpRequest(url, "POST", payload.dump(), {
        {"Content-Type", "application/json"},
        {"Authorization", "Bearer " + m_apiKey}
    });

    try {
        return nlohmann::json::parse(responseData);
    } catch (...) {
        return nlohmann::json::object();
    }
}

// Helper: HTTP Request implementation via WinHTTP
std::string ModelInvoker::performHttpRequest(const std::string& url, 
                                            const std::string& method, 
                                            const std::string& body, 
                                            const std::map<std::string, std::string>& headers)
{
    // Basic URL parsing (assuming full URL in var)
    // Actually we need to split host/path/port
    std::string hostName;
    std::string path;
    int port = 443;
    bool isHttps = true;

    // Really naive parsing for the sake of example given context constraints
    size_t protocolPos = url.find("://");
    if (protocolPos != std::string::npos) {
        std::string protocol = url.substr(0, protocolPos);
        if (protocol == "http") { isHttps = false; port = 80; }
        
        size_t pathPos = url.find('/', protocolPos + 3);
        if (pathPos != std::string::npos) {
            hostName = url.substr(protocolPos + 3, pathPos - (protocolPos + 3));
            path = url.substr(pathPos);
        } else {
            hostName = url.substr(protocolPos + 3);
            path = "/";
        }
    } else {
        hostName = "localhost";
        path = url;
    }

    size_t colon = hostName.find(':');
    if (colon != std::string::npos) {
        try {
            port = std::stoi(hostName.substr(colon + 1));
            hostName = hostName.substr(0, colon);
        } catch(...) {}
    }

    HINTERNET hSession = WinHttpOpen(L"RawrXD Agent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    std::wstring wHost(hostName.begin(), hostName.end());
    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::wstring wPath(path.begin(), path.end());
    std::wstring wMethod(method.begin(), method.end());
    
    DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, wMethod.c_str(), wPath.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Add headers
    for (const auto& [key, val] : headers) {
        std::wstring wKey(key.begin(), key.end());
        std::wstring wVal(val.begin(), val.end());
        std::wstring wHeader = wKey + L": " + wVal;
        WinHttpAddRequestHeaders(hRequest, wHeader.c_str(), (DWORD)wHeader.length(), WINHTTP_ADDREQ_FLAG_ADD);
    }

    // Retry loop for robustness
    int maxRetries = 3;
    for (int i = 0; i <= maxRetries; ++i) {
    }

    std::string response;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;

        std::vector<char> buffer(dwSize + 1);
        if (!WinHttpReadData(hRequest, &buffer[0], dwSize, &dwDownloaded)) break;
        
        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)body.c_str(), (DWORD)body.length(), (DWORD)body.length(), 0)) {   response.append(buffer.data(), dwDownloaded);
            if (i == maxRetries) {    } while (dwSize > 0);
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);e(hRequest);
                WinHttpCloseHandle(hSession);nect);
                return "";WinHttpCloseHandle(hSession);
            }
            Sleep(1000 * (i + 1)); // Backoff;
            continue;
        }
        nlohmann::json ModelInvoker::parsePlan(const std::string& llmOutput)
        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            if (i == maxRetries) {
                WinHttpCloseHandle(hRequest);{
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return "";
            } blocks
            Sleep(1000 * (i + 1));on\s*([\s\S]*?)\s*```)");
            continue;
        }if (std::regex_search(llmOutput, match, jsonBlock)) {

        // Success           return nlohmann::json::parse(match[1].str());
        break;        } catch (...) {}
    }

    std::string response;ray brackets [ ... ]
    DWORD dwSize = 0;t start = llmOutput.find('[');
    DWORD dwDownloaded = 0;
    ::string::npos && end != std::string::npos && end > start) {
    do {        try {
        dwSize = 0;(llmOutput.substr(start, end - start + 1));
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;

        std::vector<char> buffer(dwSize + 1);ohmann::json::array();
        if (!WinHttpReadData(hRequest, &buffer[0], dwSize, &dwDownloaded)) break;
        
        response.append(buffer.data(), dwDownloaded);ModelInvoker::validatePlanSanity(const nlohmann::json& plan)
    } while (dwSize > 0);{

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);invalid (sometimes valid)
    WinHttpCloseHandle(hSession);
    
    return response;
}bject()) return false;
   if (!action.contains("type")) return false;
nlohmann::json ModelInvoker::parsePlan(const std::string& llmOutput)        if (!action.contains("target")) return false;
{
    // Try raw JSON parse first
    try {    return true;
        return nlohmann::json::parse(llmOutput);
    } catch (...) {}
onst InvocationParams& params) const
    // Extract from markdown code blocks
    std::regex jsonBlock(R"(```json\s*([\s\S]*?)\s*```)");
    std::smatch match;
    if (std::regex_search(llmOutput, match, jsonBlock)) {    size_t seed = 0;
        try {e3779b9 + (seed<<6) + (seed>>2);
            return nlohmann::json::parse(match[1].str());+ ... (too large?)
        } catch (...) {}
    }

    // Fallback: Try to find array brackets [ ... ]static std::string getCacheDir() {
    size_t start = llmOutput.find('[');tem::path p("cache");
    size_t end = llmOutput.rfind(']');   if (!std::filesystem::exists(p)) {
    if (start != std::string::npos && end != std::string::npos && end > start) {        std::filesystem::create_directories(p);
        try {
            return nlohmann::json::parse(llmOutput.substr(start, end - start + 1));   return p.string();
        } catch (...) {}
    }
oker::getCachedResponse(const std::string& key) const
    return nlohmann::json::array();
}

bool ModelInvoker::validatePlanSanity(const nlohmann::json& plan)
{    std::filesystem::path cacheFile = std::filesystem::path(getCacheDir()) / (key + ".json");
    if (!plan.is_array()) return false;cheFile)) {
    
    // Check for empty plan if that's invalid (sometimes valid);
    if (plan.empty()) return true;
       f >> j;
    for (const auto& action : plan) {nt = j["content"];
        if (!action.is_object()) return false;           resp.model = j["model"];
        if (!action.contains("type")) return false;            resp.durationMs = j["durationMs"];
        if (!action.contains("target")) return false;
    }       } catch(...) {}

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}    return resp;

<<<<<<< HEAD
// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------
std::string ModelInvoker::getCacheKey(const InvocationParams& params) const {
    return params.wish.substr(0, 100);
}

LLMResponse ModelInvoker::getCachedResponse(const std::string& key) const {
    auto it = m_responseCache.find(key);
    if (it != m_responseCache.end()) return it->second;
    return {};
=======
std::string ModelInvoker::getCacheKey(const InvocationParams& params) const
{oker::cacheResponse(const std::string& key, const LLMResponse& response)
    // Simple hash of wish + codebase context
    std::hash<std::string> hasher;turn;
    size_t seed = 0;
    seed ^= hasher(params.wish) + 0x9e3779b9 + (seed<<6) + (seed>>2);d::filesystem::path(getCacheDir()) / (key + ".json");
    // seed ^= hasher(params.codebaseContext) + ... (too large?)
    return std::to_string(seed);
}content;
sponse.model;
static std::string getCacheDir() {   j["durationMs"] = response.durationMs;
    std::filesystem::path p("cache");    
    if (!std::filesystem::exists(p)) {tream f(cacheFile);
        std::filesystem::create_directories(p);       f << j.dump(2);
    }    } catch (...) {}
    return p.string();
}
(const std::string& systemPrompt, const std::string& userPrompt, int maxTokens)
LLMResponse ModelInvoker::getCachedResponse(const std::string& key) const
{
    LLMResponse resp;nvoking = true;
    resp.success = false; 

    std::filesystem::path cacheFile = std::filesystem::path(getCacheDir()) / (key + ".json");
    if (std::filesystem::exists(cacheFile)) {
        try {// Construct prompt based on backend capabilities
            std::ifstream f(cacheFile);em prompt for simplicity across backends
            nlohmann::json j;lPrompt = systemPrompt;
            f >> j;mpt.empty()) fullPrompt += "\n\n";
            resp.content = j["content"];       fullPrompt += userPrompt;
            resp.model = j["model"];
            resp.durationMs = j["durationMs"];
            resp.success = true;           llmResponse = sendOllamaRequest(m_model, fullPrompt, maxTokens, 0.7);
        } catch(...) {}end == "claude") {
    }pically supports system prompt in top level, but our helper is simple.
                // We'll wrap in user message for now.
    return resp;   llmResponse = sendClaudeRequest(fullPrompt, maxTokens, 0.7);
}enai") {
    llmResponse = sendOpenAIRequest(fullPrompt, maxTokens, 0.7);
void ModelInvoker::cacheResponse(const std::string& key, const LLMResponse& response)
{
    if (!response.success) return;
    
    std::filesystem::path cacheFile = std::filesystem::path(getCacheDir()) / (key + ".json");ains("response")) response.rawOutput = llmResponse["response"].get<std::string>();
    try {        } else if (m_backend == "claude") {
        nlohmann::json j;("content") && llmResponse["content"].is_array() && !llmResponse["content"].empty()) {
        j["content"] = response.content;tring>();
        j["model"] = response.model;
        j["durationMs"] = response.durationMs;
        & llmResponse["choices"].is_array() && !llmResponse["choices"].empty()) {
        std::ofstream f(cacheFile);]["content"].get<std::string>();
        f << j.dump(2);
    } catch (...) {}
}
        response.success = !response.rawOutput.empty();
LLMResponse ModelInvoker::queryRaw(const std::string& systemPrompt, const std::string& userPrompt, int maxTokens)
{) {
    LLMResponse response;
    m_isInvoking = true;

    try {
        nlohmann::json llmResponse;ing = false;
        
        // Construct prompt based on backend capabilities
        // For now, we prepend system prompt for simplicity across backends
        std::string fullPrompt = systemPrompt;odelInvoker::buildSystemPrompt(const std::vector<std::string>& tools)
        if (!fullPrompt.empty()) fullPrompt += "\n\n";
        fullPrompt += userPrompt;    // Basic system prompt for agent
ramming agent named RawrXD. "
        if (m_backend == "ollama") {                         "You are capable of editing code, running builds, and executing tests on your own environment.\n\n"
            llmResponse = sendOllamaRequest(m_model, fullPrompt, maxTokens, 0.7);JSON action plans to fulfill user wishes.\n"
        } else if (m_backend == "claude") {le tools:\n";
            // Claude typically supports system prompt in top level, but our helper is simple.
            // We'll wrap in user message for now.   prompt += "- " + t + "\n";
            llmResponse = sendClaudeRequest(fullPrompt, maxTokens, 0.7);    }
        } else if (m_backend == "openai") {
            llmResponse = sendOpenAIRequest(fullPrompt, maxTokens, 0.7);pond with a valid JSON array of action objects. "
        }             "Example: [{\"type\": \"edit_source\", \"target\": \"main.cpp\", \"old_code\": \"...\", \"new_code\": \"...\"}]";
    
        // Extract raw output
        if (m_backend == "ollama") {
             if (llmResponse.contains("response")) response.rawOutput = llmResponse["response"].get<std::string>();
        } else if (m_backend == "claude") {
            if (llmResponse.contains("content") && llmResponse["content"].is_array() && !llmResponse["content"].empty()) {
                response.rawOutput = llmResponse["content"][0]["text"].get<std::string>();
            }
        } else if (m_backend == "openai") {
             if (llmResponse.contains("choices") && llmResponse["choices"].is_array() && !llmResponse["choices"].empty()) {
                response.rawOutput = llmResponse["choices"][0]["message"]["content"].get<std::string>();            }        }        response.success = !response.rawOutput.empty();    } catch (const std::exception& e) {        response.success = false;        response.error = e.what();    }    m_isInvoking = false;    return response;}
std::string ModelInvoker::buildSystemPrompt(const std::vector<std::string>& tools)
{
    // Basic system prompt for agent
    std::string prompt = "You are an autonomous AI programming agent named RawrXD. "
                         "You are capable of editing code, running builds, and executing tests on your own environment.\n\n"
                         "You generate JSON action plans to fulfill user wishes.\n"
                         "Available tools:\n";
    for(const auto& t : tools) {
        prompt += "- " + t + "\n";
    }
    
    prompt += "\nRespond with a valid JSON array of action objects. "
              "Example: [{\"type\": \"edit_source\", \"target\": \"main.cpp\", \"old_code\": \"...\", \"new_code\": \"...\"}]";
    
    return prompt;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}
        response.error = e.what();
        response.success = false;
    }

<<<<<<< HEAD
void ModelInvoker::cacheResponse(const std::string& key, const LLMResponse& resp) {
    m_responseCache[key] = resp;
=======
    m_isInvoking = false;
    return response;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}
