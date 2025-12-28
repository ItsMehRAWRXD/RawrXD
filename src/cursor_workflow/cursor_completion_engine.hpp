#pragma once
#include "real_time_completion_engine.h"
#include "../agentic/agentic_engine.h"
#include <QTimer>
#include <QCache>

class CursorStyleCompletionEngine : public RealTimeCompletionEngine {
    Q_OBJECT
public:
    CursorStyleCompletionEngine(std::shared_ptr<Logger> logger, std::shared_ptr<Metrics> metrics);
    
    // Cursor-style inline completions with <50ms latency
    std::vector<CodeCompletion> getInlineCompletions(
        const std::string& currentLine, int cursorColumn, const std::string& filePath) override;
    
    // Multi-line completions with context awareness
    std::vector<CodeCompletion> getMultiLineCompletions(
        const std::string& prefix, int maxLines) override;
    
    // Predictive completions (pre-generate likely next completions)
    void startPredictiveCompletion(const std::string& context);
    void stopPredictiveCompletion();
    
    // Multi-model routing for optimal performance
    void setModelPriority(const std::vector<std::string>& modelPaths);
    
signals:
    void streamingCompletion(const QString& partialCompletion);
    void completionCancelled();

private:
    // Performance optimizations
    QCache<QString, std::vector<CodeCompletion>> m_predictiveCache;
    QTimer* m_predictiveTimer;
    std::vector<std::string> m_modelPriority;
    
    // Streaming inference
    std::vector<CodeCompletion> generateStreamingCompletion(const std::string& prompt);
    void warmupModels();
    
    bool m_predictiveMode = false;
};