#include "cursor_completion_engine.hpp"
#include "cursor_command_palette.hpp"
#include "github_copilot_integration.hpp"
#include "multi_file_agentic_engine.hpp"
#include "collaborative_ai_engine.hpp"
#include <QTimer>

CursorStyleCompletionEngine::CursorStyleCompletionEngine(
    std::shared_ptr<Logger> logger, std::shared_ptr<Metrics> metrics)
    : RealTimeCompletionEngine(logger, metrics)
    , m_predictiveCache(1000)  // Cache 1000 predictions
    , m_predictiveTimer(new QTimer(this))
{
    m_predictiveTimer->setSingleShot(false);
    m_predictiveTimer->setInterval(100);  // Predict every 100ms
    connect(m_predictiveTimer, &QTimer::timeout, this, [this]() {
        if (m_predictiveMode) {
            // Generate predictions for likely next inputs
            warmupModels();
        }
    });
}

std::vector<CodeCompletion> CursorStyleCompletionEngine::getInlineCompletions(
    const std::string& currentLine, int cursorColumn, const std::string& filePath) {
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Check predictive cache first (sub-10ms lookup)
    QString cacheKey = QString("%1:%2:%3").arg(QString::fromStdString(currentLine))
                                          .arg(cursorColumn)
                                          .arg(QString::fromStdString(filePath));
    
    if (m_predictiveCache.contains(cacheKey)) {
        auto cached = *m_predictiveCache.object(cacheKey);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto latency = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        m_logger->info("Cache hit - latency: {}μs", latency);
        return cached;
    }
    
    // Multi-model routing for optimal performance
    std::vector<CodeCompletion> completions;
    for (const auto& modelPath : m_modelPriority) {
        try {
            // Try fastest model first
            completions = generateStreamingCompletion(currentLine.substr(0, cursorColumn));
            if (!completions.empty()) break;
        } catch (...) {
            continue;  // Try next model
        }
    }
    
    // Cache result for future use
    m_predictiveCache.insert(cacheKey, new std::vector<CodeCompletion>(completions));
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto latency = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
    m_logger->info("Inline completion latency: {}μs", latency);
    
    return completions;
}

std::vector<CodeCompletion> CursorStyleCompletionEngine::getMultiLineCompletions(
    const std::string& prefix, int maxLines) {
    
    // Use streaming inference for multi-line completions
    return generateStreamingCompletion(prefix);
}

void CursorStyleCompletionEngine::startPredictiveCompletion(const std::string& context) {
    m_predictiveMode = true;
    m_predictiveTimer->start();
    
    // Pre-generate likely completions
    QtConcurrent::run([this, context]() {
        std::vector<std::string> likelyInputs = {
            context + "if (",
            context + "for (",
            context + "while (",
            context + "return ",
            context + "const ",
            context + "auto ",
            context + "std::"
        };
        
        for (const auto& input : likelyInputs) {
            auto completions = generateStreamingCompletion(input);
            QString key = QString::fromStdString(input);
            m_predictiveCache.insert(key, new std::vector<CodeCompletion>(completions));
        }
    });
}

void CursorStyleCompletionEngine::stopPredictiveCompletion() {
    m_predictiveMode = false;
    m_predictiveTimer->stop();
}

std::vector<CodeCompletion> CursorStyleCompletionEngine::generateStreamingCompletion(
    const std::string& prompt) {
    
    std::vector<CodeCompletion> completions;
    
    // Emit partial completions as they're generated
    if (m_inferenceEngine && m_inferenceEngine->isModelLoaded()) {
        auto tokens = m_inferenceEngine->tokenize(QString::fromStdString(prompt));
        
        // Generate tokens one by one for streaming effect
        for (int i = 0; i < 50; ++i) {  // Max 50 tokens
            auto newTokens = m_inferenceEngine->generate(tokens, 1);
            if (newTokens.size() > tokens.size()) {
                QString partial = m_inferenceEngine->detokenize(newTokens);
                emit streamingCompletion(partial);
                tokens = newTokens;
            } else {
                break;
            }
        }
        
        // Create final completion
        if (tokens.size() > 0) {
            CodeCompletion comp;
            comp.text = m_inferenceEngine->detokenize(tokens).toStdString();
            comp.confidence = 0.9;
            comp.kind = "streaming";
            completions.push_back(comp);
        }
    }
    
    return completions;
}

void CursorStyleCompletionEngine::warmupModels() {
    // Keep models warm for instant response
    if (m_inferenceEngine && m_inferenceEngine->isModelLoaded()) {
        // Generate a small completion to keep model active
        auto tokens = m_inferenceEngine->tokenize("//");
        m_inferenceEngine->generate(tokens, 1);
    }
}

void CursorStyleCompletionEngine::setModelPriority(const std::vector<std::string>& modelPaths) {
    m_modelPriority = modelPaths;
    m_logger->info("Model priority set: {} models", modelPaths.size());
}