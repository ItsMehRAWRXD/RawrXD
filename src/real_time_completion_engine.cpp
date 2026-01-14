#include "real_time_completion_engine.h"
#include <algorithm>
#include <iostream>
#include <chrono>

// Constructor
RealTimeCompletionEngine::RealTimeCompletionEngine(
    std::shared_ptr<Logger> logger,
    std::shared_ptr<Metrics> metrics
) : m_logger(logger), m_metrics(metrics), m_inferenceEngine(nullptr) {
    if (m_logger) {
        m_logger->info("RealTimeCompletionEngine initialized");
    }
}

// Core completion interface
std::vector<CodeCompletion> RealTimeCompletionEngine::getCompletions(
    const std::string& prefix,
    const std::string& suffix,
    const std::string& fileType,
    const std::string& context
) {
    auto startTime = std::chrono::high_resolution_clock::now();
    m_totalRequests++;
    
    // Check cache first
    std::string cacheKey = prefix + "|" + fileType;
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        auto it = m_completionCache.find(cacheKey);
        if (it != m_completionCache.end()) {
            m_cacheHits++;
            return it->second;
        }
    }
    
    // Generate completions using model
    std::vector<CodeCompletion> completions = generateCompletionsWithModel(prefix, 5);
    
    // Cache the results
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        m_completionCache[cacheKey] = completions;
    }
    
    // Track latency
    auto endTime = std::chrono::high_resolution_clock::now();
    double latencyMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    {
        std::lock_guard<std::mutex> lock(m_latencyMutex);
        m_latencyHistory.push_back(latencyMs);
        if (m_latencyHistory.size() > 1000) {
            m_latencyHistory.erase(m_latencyHistory.begin());
        }
    }
    
    return completions;
}

// Advanced features
std::vector<CodeCompletion> RealTimeCompletionEngine::getInlineCompletions(
    const std::string& currentLine,
    int cursorColumn,
    const std::string& filePath
) {
    auto startTime = std::chrono::high_resolution_clock::now();
    m_totalRequests++;
    
    // Extract context around cursor
    std::string prefix = currentLine.substr(0, cursorColumn);
    std::string suffix = currentLine.substr(cursorColumn);
    
    // Generate inline completions
    std::vector<CodeCompletion> completions = generateCompletionsWithModel(prefix, 3);
    
    // Track latency
    auto endTime = std::chrono::high_resolution_clock::now();
    double latencyMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    {
        std::lock_guard<std::mutex> lock(m_latencyMutex);
        m_latencyHistory.push_back(latencyMs);
    }
    
    return completions;
}

std::vector<CodeCompletion> RealTimeCompletionEngine::getMultiLineCompletions(
    const std::string& prefix,
    int maxLines
) {
    auto startTime = std::chrono::high_resolution_clock::now();
    m_totalRequests++;
    
    // Generate multi-line completions
    std::vector<CodeCompletion> completions = generateCompletionsWithModel(prefix, maxLines * 10);
    
    // Track latency
    auto endTime = std::chrono::high_resolution_clock::now();
    double latencyMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    {
        std::lock_guard<std::mutex> lock(m_latencyMutex);
        m_latencyHistory.push_back(latencyMs);
    }
    
    return completions;
}

// Performance optimization
void RealTimeCompletionEngine::clearCache() {
    std::lock_guard<std::mutex> lock(m_cacheMutex);
    m_completionCache.clear();
}

PerformanceMetrics RealTimeCompletionEngine::getMetrics() const {
    std::lock_guard<std::mutex> lockLatency(m_latencyMutex);
    
    PerformanceMetrics metrics;
    metrics.requestCount = m_totalRequests;
    metrics.errorCount = 0; // Simplified for now
    
    if (!m_latencyHistory.empty()) {
        // Calculate average latency
        double sum = 0;
        for (double latency : m_latencyHistory) {
            sum += latency;
        }
        metrics.avgLatencyMs = sum / m_latencyHistory.size();
        
        // Calculate p95 and p99
        std::vector<double> sorted = m_latencyHistory;
        std::sort(sorted.begin(), sorted.end());
        metrics.p95LatencyMs = sorted[sorted.size() * 95 / 100];
        metrics.p99LatencyMs = sorted[sorted.size() * 99 / 100];
    }
    
    if (m_totalRequests > 0) {
        metrics.cacheHitRate = static_cast<double>(m_cacheHits) / m_totalRequests;
    }
    
    return metrics;
}

// Private implementation methods
std::vector<CodeCompletion> RealTimeCompletionEngine::generateCompletionsWithModel(
    const std::string& prompt,
    int maxTokens
) {
    std::vector<CodeCompletion> results;
    
    // If we have an inference engine, use it
    if (m_inferenceEngine) {
        // Call inference engine to get predictions
        // For now, return stub results
    }
    
    // Stub completions for demonstration
    CodeCompletion completion;
    completion.text = "void sample_function() {\n    // Generated completion\n}";
    completion.detail = "sample_function";
    completion.confidence = 0.85;
    completion.kind = "Function";
    completion.insertTextLength = completion.text.length();
    completion.cursorOffset = 0;
    
    results.push_back(completion);
    
    return results;
}

std::string RealTimeCompletionEngine::buildCompletionPrompt(
    const std::string& prefix,
    const std::string& suffix,
    const std::string& context
) {
    return prefix + suffix;
}

std::vector<CodeCompletion> RealTimeCompletionEngine::postProcessCompletions(
    const std::string& modelOutput,
    const std::string& prefix
) {
    std::vector<CodeCompletion> results;
    CodeCompletion completion;
    completion.text = modelOutput;
    completion.detail = "Completion";
    completion.confidence = 0.75;
    completion.kind = "Text";
    results.push_back(completion);
    return results;
}

double RealTimeCompletionEngine::calculateConfidence(
    const std::string& completion,
    const std::string& context
) {
    return 0.8;
}
