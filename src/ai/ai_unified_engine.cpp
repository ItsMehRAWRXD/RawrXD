// ai_unified_engine.cpp - Full implementation
#include "ai_unified_engine.h"
#include "inference_engine.h"
#include "ollama_client.h"
#include <windows.h>
#include <queue>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace AI {

// Implementation details
class UnifiedAIEngine::Impl {
public:
    bool m_initialized = false;
    std::string m_defaultModel = "codellama:latest";
    std::string m_apiEndpoint = "http://localhost:11434/api";
    std::string m_apiKey;
    
    // Cache
    bool m_cacheEnabled = true;
    size_t m_maxCacheSize = 1000;
    std::unordered_map<std::string, CacheEntry> m_cache;
    std::mutex m_cacheMutex;
    
    // Rate limiting
    int m_rateLimit = 60;  // requests per minute
    std::queue<std::chrono::steady_clock::time_point> m_requestTimes;
    std::mutex m_rateMutex;
    
    // Metrics
    std::atomic<size_t> m_totalRequests{0};
    std::atomic<float> m_totalLatencyMs{0.0f};
    std::atomic<size_t> m_totalTokens{0};
    
    // Context management
    std::unordered_map<std::string, std::vector<std::string>> m_contexts;
    std::mutex m_contextMutex;
    int m_nextContextId = 1;
    
    // Configuration
    int m_timeoutMs = 30000;
    int m_retryCount = 3;
    
    // Model management
    std::unordered_map<std::string, ModelInfo> m_loadedModels;
    std::mutex m_modelMutex;
    
    // Thread pool for async operations
    std::vector<std::thread> m_threadPool;
    std::queue<std::function<void()>> m_taskQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_cv;
    bool m_shutdown = false;
    
    Impl() {
        // Initialize thread pool
        size_t numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4;
        
        for (size_t i = 0; i < numThreads; ++i) {
            m_threadPool.emplace_back([this]() {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(m_queueMutex);
                        m_cv.wait(lock, [this]() { return m_shutdown || !m_taskQueue.empty(); });
                        if (m_shutdown && m_taskQueue.empty()) return;
                        task = std::move(m_taskQueue.front());
                        m_taskQueue.pop();
                    }
                    task();
                }
            });
        }
    }
    
    ~Impl() {
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_shutdown = true;
        }
        m_cv.notify_all();
        for (auto& thread : m_threadPool) {
            if (thread.joinable()) thread.join();
        }
    }
    
    void enqueueTask(std::function<void()> task) {
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_taskQueue.push(std::move(task));
        }
        m_cv.notify_one();
    }
};

UnifiedAIEngine::UnifiedAIEngine() : m_impl(std::make_unique<Impl>()) {}
UnifiedAIEngine::~UnifiedAIEngine() = default;

bool UnifiedAIEngine::initialize(const std::string& defaultModel) {
    m_impl->m_defaultModel = defaultModel;
    
    // Try to connect to Ollama
    // In real implementation, this would check if the server is running
    // and load the default model
    
    // Register built-in models
    {
        std::unique_lock<std::mutex> lock(m_impl->m_modelMutex);
        m_impl->m_loadedModels["codellama:latest"] = {
            "codellama:latest", "CodeLlama", 16384, true, false, 0.0f,
            {"code-generation", "code-completion", "infilling"}
        };
        m_impl->m_loadedModels["llama3:latest"] = {
            "llama3:latest", "Llama 3", 8192, true, true, 0.0f,
            {"chat", "code", "general"}
        };
        m_impl->m_loadedModels["codellama:13b"] = {
            "codellama:13b", "CodeLlama 13B", 16384, true, false, 0.0f,
            {"code-generation", "code-completion"}
        };
    }
    
    m_impl->m_initialized = true;
    return true;
}

void UnifiedAIEngine::shutdown() {
    m_impl->m_initialized = false;
    clearCache();
}

bool UnifiedAIEngine::isReady() const {
    return m_impl->m_initialized;
}

InferenceResponse UnifiedAIEngine::complete(const InferenceRequest& request) {
    if (!m_impl->m_initialized) {
        return {"", 0, 0, 0.0f, true, "engine_not_ready", ""};
    }
    
    // Check rate limit
    if (!checkRateLimit()) {
        return {"", 0, 0, 0.0f, true, "rate_limited", ""};
    }
    
    // Check cache
    if (m_impl->m_cacheEnabled) {
        std::string cacheKey = generateCacheKey(request);
        {
            std::unique_lock<std::mutex> lock(m_impl->m_cacheMutex);
            auto it = m_impl->m_cache.find(cacheKey);
            if (it != m_impl->m_cache.end()) {
                it->second.hitCount++;
                it->second.timestamp = std::chrono::steady_clock::now();
                return it->second.response;
            }
        }
    }
    
    // Build full prompt with context
    std::string fullPrompt = request.systemPrompt + "\n\n" + request.prompt;
    
    // Add conversation context if provided
    if (!request.contextId.empty()) {
        auto context = getContext(request.contextId);
        for (const auto& msg : context) {
            fullPrompt = msg + "\n" + fullPrompt;
        }
    }
    
    // Truncate if too long
    fullPrompt = truncateContext(fullPrompt, request.maxTokens);
    
    // Call Ollama for actual inference
    auto startTime = std::chrono::steady_clock::now();
    
    RawrXD::Backend::NativeClient ollamaClient("http://localhost:11434");
    RawrXD::Backend::OllamaGenerateRequest ollamaReq;
    ollamaReq.model = request.model.empty() ? m_impl->m_defaultModel : request.model;
    ollamaReq.prompt = fullPrompt;
    ollamaReq.stream = false;
    ollamaReq.options["num_predict"] = request.maxTokens;
    ollamaReq.options["temperature"] = request.temperature;
    
    InferenceResponse response;
    auto ollamaResponse = ollamaClient.generateSync(ollamaReq);
    
    if (ollamaResponse.error) {
        response.text = "Error: " + ollamaResponse.error_message;
        response.tokensGenerated = 0;
        response.finishReason = "error";
    } else {
        response.text = ollamaResponse.response;
        response.tokensGenerated = static_cast<int>(ollamaResponse.eval_count);
        response.finishReason = ollamaResponse.done ? "stop" : "length";
    }
    
    response.tokensPrompt = static_cast<int>(fullPrompt.length() / 4);  // Rough estimate
    response.truncated = false;
    response.modelUsed = ollamaReq.model;
    
    auto endTime = std::chrono::steady_clock::now();
    response.generationTimeMs = std::chrono::duration<float, std::milli>(endTime - startTime).count();
    
    // Update metrics
    updateMetrics(response);
    
    // Cache response
    if (m_impl->m_cacheEnabled) {
        std::string cacheKey = generateCacheKey(request);
        {
            std::unique_lock<std::mutex> lock(m_impl->m_cacheMutex);
            if (m_impl->m_cache.size() >= m_impl->m_maxCacheSize) {
                // Evict oldest entry
                auto oldest = m_impl->m_cache.begin();
                for (auto it = m_impl->m_cache.begin(); it != m_impl->m_cache.end(); ++it) {
                    if (it->second.timestamp < oldest->second.timestamp) {
                        oldest = it;
                    }
                }
                m_impl->m_cache.erase(oldest);
            }
            m_impl->m_cache[cacheKey] = {cacheKey, response, std::chrono::steady_clock::now(), 1};
        }
    }
    
    return response;
}

std::future<InferenceResponse> UnifiedAIEngine::completeAsync(
    const InferenceRequest& request) {
    auto promise = std::make_shared<std::promise<InferenceResponse>>();
    auto future = promise->get_future();
    
    auto req = request;  // Copy for lambda
    m_impl->enqueueTask([this, promise, req]() {
        auto response = complete(req);
        promise->set_value(response);
    });
    
    return future;
}

void UnifiedAIEngine::completeStream(
    const InferenceRequest& request,
    TokenCallback onToken,
    ProgressCallback onProgress) {
    
    if (!m_impl->m_initialized) {
        if (onToken) onToken("", true);
        return;
    }
    
    // Simulate streaming (in real implementation, use SSE from Ollama)
    std::string simulatedResponse = complete(request).text;
    
    // Stream tokens
    size_t pos = 0;
    while (pos < simulatedResponse.length()) {
        size_t nextPos = simulatedResponse.find(' ', pos);
        if (nextPos == std::string::npos) {
            nextPos = simulatedResponse.length();
        } else {
            nextPos++;  // Include the space
        }
        
        std::string token = simulatedResponse.substr(pos, nextPos - pos);
        if (onToken) {
            onToken(token, nextPos >= simulatedResponse.length());
        }
        
        if (onProgress) {
            onProgress(static_cast<float>(nextPos) / simulatedResponse.length());
        }
        
        pos = nextPos;
        
        // Simulate token generation delay
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

std::vector<ModelInfo> UnifiedAIEngine::listAvailableModels() {
    std::unique_lock<std::mutex> lock(m_impl->m_modelMutex);
    std::vector<ModelInfo> models;
    for (const auto& [name, info] : m_impl->m_loadedModels) {
        models.push_back(info);
    }
    return models;
}

bool UnifiedAIEngine::loadModel(const std::string& modelName) {
    // In real implementation, this would load the model into memory
    // For now, just mark it as available
    std::unique_lock<std::mutex> lock(m_impl->m_modelMutex);
    if (m_impl->m_loadedModels.find(modelName) == m_impl->m_loadedModels.end()) {
        // Add as generic model
        m_impl->m_loadedModels[modelName] = {
            modelName, modelName, 4096, true, false, 0.0f, {}
        };
    }
    return true;
}

void UnifiedAIEngine::unloadModel(const std::string& modelName) {
    std::unique_lock<std::mutex> lock(m_impl->m_modelMutex);
    m_impl->m_loadedModels.erase(modelName);
}

bool UnifiedAIEngine::isModelLoaded(const std::string& modelName) const {
    std::unique_lock<std::mutex> lock(m_impl->m_modelMutex);
    return m_impl->m_loadedModels.find(modelName) != m_impl->m_loadedModels.end();
}

void UnifiedAIEngine::setDefaultModel(const std::string& modelName) {
    m_impl->m_defaultModel = modelName;
}

std::string UnifiedAIEngine::getDefaultModel() const {
    return m_impl->m_defaultModel;
}

void UnifiedAIEngine::enableCache(bool enable) {
    m_impl->m_cacheEnabled = enable;
    if (!enable) {
        clearCache();
    }
}

void UnifiedAIEngine::clearCache() {
    std::unique_lock<std::mutex> lock(m_impl->m_cacheMutex);
    m_impl->m_cache.clear();
}

void UnifiedAIEngine::setCacheSize(size_t maxEntries) {
    m_impl->m_maxCacheSize = maxEntries;
}

size_t UnifiedAIEngine::getCacheSize() const {
    std::unique_lock<std::mutex> lock(m_impl->m_cacheMutex);
    return m_impl->m_cache.size();
}

void UnifiedAIEngine::setRateLimit(int requestsPerMinute) {
    m_impl->m_rateLimit = requestsPerMinute;
}

int UnifiedAIEngine::getRateLimit() const {
    return m_impl->m_rateLimit;
}

int UnifiedAIEngine::getRemainingRequests() const {
    std::unique_lock<std::mutex> lock(m_impl->m_rateMutex);
    
    auto now = std::chrono::steady_clock::now();
    while (!m_impl->m_requestTimes.empty()) {
        auto age = std::chrono::duration<float>(now - m_impl->m_requestTimes.front()).count();
        if (age > 60.0f) {
            m_impl->m_requestTimes.pop();
        } else {
            break;
        }
    }
    
    return m_impl->m_rateLimit - static_cast<int>(m_impl->m_requestTimes.size());
}

float UnifiedAIEngine::getAverageLatency() const {
    size_t total = m_impl->m_totalRequests.load();
    if (total == 0) return 0.0f;
    return m_impl->m_totalLatencyMs.load() / total;
}

float UnifiedAIEngine::getThroughput() const {
    float latency = getAverageLatency();
    if (latency == 0.0f) return 0.0f;
    size_t totalTokens = m_impl->m_totalTokens.load();
    return (totalTokens / latency) * 1000.0f;  // tokens/sec
}

size_t UnifiedAIEngine::getTotalRequests() const {
    return m_impl->m_totalRequests.load();
}

std::string UnifiedAIEngine::createContext() {
    std::unique_lock<std::mutex> lock(m_impl->m_contextMutex);
    std::string contextId = "ctx_" + std::to_string(m_impl->m_nextContextId++);
    m_impl->m_contexts[contextId] = {};
    return contextId;
}

void UnifiedAIEngine::appendToContext(const std::string& contextId, 
                                       const std::string& message) {
    std::unique_lock<std::mutex> lock(m_impl->m_contextMutex);
    m_impl->m_contexts[contextId].push_back(message);
}

void UnifiedAIEngine::clearContext(const std::string& contextId) {
    std::unique_lock<std::mutex> lock(m_impl->m_contextMutex);
    m_impl->m_contexts[contextId].clear();
}

std::vector<std::string> UnifiedAIEngine::getContext(
    const std::string& contextId) const {
    std::unique_lock<std::mutex> lock(m_impl->m_contextMutex);
    auto it = m_impl->m_contexts.find(contextId);
    if (it != m_impl->m_contexts.end()) {
        return it->second;
    }
    return {};
}

void UnifiedAIEngine::setTimeout(int milliseconds) {
    m_impl->m_timeoutMs = milliseconds;
}

void UnifiedAIEngine::setRetryCount(int count) {
    m_impl->m_retryCount = count;
}

void UnifiedAIEngine::setApiEndpoint(const std::string& endpoint) {
    m_impl->m_apiEndpoint = endpoint;
}

void UnifiedAIEngine::setApiKey(const std::string& apiKey) {
    m_impl->m_apiKey = apiKey;
}

std::string UnifiedAIEngine::generateCacheKey(const InferenceRequest& request) {
    // Simple hash of prompt + model + temperature
    std::stringstream ss;
    ss << request.prompt << "|" << request.model << "|" << request.temperature;
    
    // Simple hash function
    std::string str = ss.str();
    size_t hash = 0;
    for (char c : str) {
        hash = hash * 31 + c;
    }
    return std::to_string(hash);
}

bool UnifiedAIEngine::checkRateLimit() {
    std::unique_lock<std::mutex> lock(m_impl->m_rateMutex);
    
    auto now = std::chrono::steady_clock::now();
    
    // Remove old requests (> 1 minute)
    while (!m_impl->m_requestTimes.empty()) {
        auto age = std::chrono::duration<float>(now - m_impl->m_requestTimes.front()).count();
        if (age > 60.0f) {
            m_impl->m_requestTimes.pop();
        } else {
            break;
        }
    }
    
    // Check if under limit
    if (m_impl->m_requestTimes.size() >= static_cast<size_t>(m_impl->m_rateLimit)) {
        return false;
    }
    
    // Record this request
    m_impl->m_requestTimes.push(now);
    return true;
}

void UnifiedAIEngine::updateMetrics(const InferenceResponse& response) {
    m_impl->m_totalRequests++;
    m_impl->m_totalLatencyMs += response.generationTimeMs;
    m_impl->m_totalTokens += response.tokensGenerated + response.tokensPrompt;
}

// Global instance
UnifiedAIEngine& GetAIEngine() {
    static UnifiedAIEngine instance;
    return instance;
}

// Utility functions
std::string buildPromptTemplate(const std::string& task,
                                 const std::string& code,
                                 const std::string& language) {
    std::stringstream ss;
    ss << "Task: " << task << "\n\n";
    ss << "Language: " << language << "\n\n";
    ss << "Code:\n```" << language << "\n";
    ss << code << "\n```\n\n";
    ss << "Response:";
    return ss.str();
}

std::string sanitizeCode(const std::string& code) {
    std::string result = code;
    // Remove null bytes
    result.erase(std::remove(result.begin(), result.end(), '\0'), result.end());
    // Limit length
    if (result.length() > 100000) {
        result = result.substr(0, 100000) + "\n... [truncated]";
    }
    return result;
}

std::string truncateContext(const std::string& context, size_t maxTokens) {
    // Rough estimate: 4 chars per token
    size_t maxChars = maxTokens * 4;
    if (context.length() <= maxChars) {
        return context;
    }
    
    // Keep the end (most recent context)
    return "... [truncated]\n" + context.substr(context.length() - maxChars);
}

} // namespace AI
} // namespace RawrXD
