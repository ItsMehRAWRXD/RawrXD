/**
 * @file model_invoker.hpp
 * @brief LLM invocation layer for wish-to-plan transformation (Qt-free)
 */
#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
<<<<<<< HEAD
#include <future>
#include <nlohmann/json.hpp>
=======
#include <nlohmann/json.hpp>
#include <windows.h>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

struct InvocationParams {
<<<<<<< HEAD
    std::string wish;
    std::string context;
    std::vector<std::string> availableTools;
    std::string codebaseContext;
    int maxTokens = 2000;
    double temperature = 0.7;
    int timeoutMs = 30000;
=======
    std::string wish;                           ///< User's natural language request
    std::string context;                        ///< IDE state/environment context
    std::vector<std::string> availableTools;    ///< Tools accessible to agent
    std::string codebaseContext;                ///< Relevant codebase snippets (RAG)
    int maxTokens = 2000;                       ///< Output token limit
    double temperature = 0.7;                   ///< Sampling temperature (0-1)
    int timeoutMs = 30000;                      ///< Request timeout
    bool enforceJsonFormat = true;              ///< Whether to enforce JSON output format
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};

struct LLMResponse {
    bool success = false;
<<<<<<< HEAD
    std::string rawOutput;
    nlohmann::json parsedPlan;
    std::string reasoning;
=======
    std::string rawOutput;                      ///< Full LLM response text
    nlohmann::json parsedPlan;                  ///< Structured action plan
    std::string reasoning;                      ///< Agent's reasoning (for logging)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    int tokensUsed = 0;
    std::string error;
};

<<<<<<< HEAD
class ModelInvoker {
public:
    ModelInvoker() = default;
    ~ModelInvoker() = default;

    void setLLMBackend(const std::string& backend, const std::string& endpoint, const std::string& apiKey = "");
    std::string getLLMBackend() const { return m_backend; }
    LLMResponse invoke(const InvocationParams& params);
=======
/**
 * @class ModelInvoker
 * @brief Bridges natural language wishes to structured action plans via LLM
 */
class ModelInvoker {
public:
    /**
     * @brief Constructor
     */
    explicit ModelInvoker();

    /**
     * @brief Destructor
     */
    virtual ~ModelInvoker();

    /**
     * @brief Set the LLM backend and endpoint
     */
    void setLLMBackend(const std::string& backend,
                       const std::string& endpoint,
                       const std::string& apiKey = "");

    /**
     * @brief Get current LLM backend type
     */
    std::string getLLMBackend() const { return m_backend; }

    /**
     * @brief Synchronous wish→plan transformation (blocks caller)
     */
    LLMResponse invoke(const InvocationParams& params);

    /**
     * @brief Asynchronous wish→plan transformation (non-blocking)
     */
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    void invokeAsync(const InvocationParams& params);
    void cancelPendingRequest();
<<<<<<< HEAD
    bool isInvoking() const { return m_isInvoking; }
    void setSystemPromptTemplate(const std::string& template_);
    void setCodebaseEmbeddings(const std::map<std::string, float>& embeddings);
    void setCachingEnabled(bool enabled) { m_cachingEnabled = enabled; }

    // Callbacks (replace Qt signals)
    std::function<void(const std::string&)> onPlanGenerationStarted;
    std::function<void(const LLMResponse&)> onPlanGenerated;
    std::function<void(const std::string&, bool)> onInvocationError;
    std::function<void(const std::string&)> onStatusUpdated;

private:
    std::string buildSystemPrompt(const std::vector<std::string>& tools);
    std::string buildUserMessage(const InvocationParams& params);
    nlohmann::json sendOllamaRequest(const std::string& model, const std::string& prompt, int maxTokens, double temperature);
    nlohmann::json sendClaudeRequest(const std::string& prompt, int maxTokens, double temperature);
    nlohmann::json sendOpenAIRequest(const std::string& prompt, int maxTokens, double temperature);
    nlohmann::json parsePlan(const std::string& llmOutput);
    bool validatePlanSanity(const nlohmann::json& plan);
    std::string getCacheKey(const InvocationParams& params) const;
    LLMResponse getCachedResponse(const std::string& key) const;
    void cacheResponse(const std::string& key, const LLMResponse& response);

    std::string m_backend;
    std::string m_endpoint;
    std::string m_apiKey;
    std::string m_model = "mistral";
    bool m_isInvoking = false;
    bool m_cachingEnabled = true;
    std::map<std::string, LLMResponse> m_responseCache;
    std::string m_customSystemPrompt;
    std::map<std::string, float> m_codebaseEmbeddings;
    std::future<void> m_asyncFuture;  // Post-Qt: retained to prevent premature destruction
=======

    /**
     * @brief Check if request is in progress
     */
    bool isInvoking() const { return m_isInvoking; }

    /**
     * @brief Set custom system prompt template
     */
    void setSystemPromptTemplate(const std::string& template_);

    /**
     * @brief Set RAG codebase embeddings
     */
    void setCodebaseEmbeddings(const std::map<std::string, float>& embeddings);

    /**
     * @brief Raw query without plan parsing (for code completion/chat)
     */
    LLMResponse queryRaw(const std::string& systemPrompt, const std::string& userPrompt, int maxTokens = 2000);

    /**
     * @brief Enable/disable request caching
     */
    void setCachingEnabled(bool enabled) { m_cachingEnabled = enabled; }

    /**
     * @brief Set endpoint URL directly (for hot patching)
     */
    void setEndpoint(const std::string& endpoint) { m_endpoint = endpoint; }

    nlohmann::json sendOllamaRequest(const std::string& model,
                                   const std::string& prompt,
                                   int maxTokens,
                                   double temperature);

    nlohmann::json sendClaudeRequest(const std::string& prompt,
                                   int maxTokens,
                                   double temperature);

    nlohmann::json sendOpenAIRequest(const std::string& prompt,
                                   int maxTokens,
                                   double temperature);

    nlohmann::json sendRawrXDRequest(const std::string& messageBlock, int maxTokens, float temperature);

private:
    /**
     * @brief Build system prompt with tool descriptions
     */
    std::string buildSystemPrompt(const std::vector<std::string>& tools);

    /**
     * @brief Build user message with wish and context
     */
    std::string buildUserMessage(const InvocationParams& params);

    nlohmann::json parsePlan(const std::string& llmOutput);

    bool validatePlanSanity(const nlohmann::json& plan);

    std::string getCacheKey(const InvocationParams& params) const;

    LLMResponse getCachedResponse(const std::string& key) const;

    void cacheResponse(const std::string& key, const LLMResponse& response);

    // Helper method for HTTP requests
    std::string performHttpRequest(const std::string& url, 
                                  const std::string& method, 
                                  const std::string& body, 
                                  const std::map<std::string, std::string>& headers);

    nlohmann::json m_cache;
    bool m_cachingEnabled = true;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};
