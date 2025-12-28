#include "agentic_learning_system.h"
#include <QDateTime>
#include <QDebug>
#include <algorithm>

AgenticLearningSystem::AgenticLearningSystem(QObject* parent)
    : QObject(parent) {
}

void AgenticLearningSystem::recordCompressionPerformance(
    const QString& method,
    size_t inputSize,
    size_t outputSize,
    qint64 timeMs) {
    
    PerformanceRecord record;
    record.method = method;
    record.inputSize = inputSize;
    record.outputSize = outputSize;
    record.timeMs = timeMs;
    record.ratio = inputSize > 0 ? (double)outputSize / inputSize : 1.0;
    record.timestamp = QDateTime::currentMSecsSinceEpoch();
    
    m_performanceHistory[method].append(record);
    
    // Keep only recent records (last 1000)
    if (m_performanceHistory[method].size() > 1000) {
        m_performanceHistory[method].removeFirst();
    }
    
    qDebug() << "[AgenticLearning] Recorded performance:" << method 
             << "ratio:" << record.ratio << "time:" << timeMs << "ms";
}

QString AgenticLearningSystem::predictOptimalCompression(size_t dataSize, const QString& dataType) {
    // Simple prediction based on historical performance
    
    QString bestMethod = "brutal_gzip"; // Default
    double bestScore = 0.0;
    
    for (auto it = m_performanceHistory.begin(); it != m_performanceHistory.end(); ++it) {
        const QString& method = it.key();
        const QList<PerformanceRecord>& records = it.value();
        
        if (records.isEmpty()) continue;
        
        // Calculate average performance for similar data sizes
        double avgRatio = 0.0;
        double avgTime = 0.0;
        int count = 0;
        
        for (const auto& record : records) {
            // Consider records with similar data size (within 50% range)
            if (record.inputSize > dataSize * 0.5 && record.inputSize < dataSize * 1.5) {
                avgRatio += record.ratio;
                avgTime += record.timeMs;
                count++;
            }
        }
        
        if (count > 0) {
            avgRatio /= count;
            avgTime /= count;
            
            // Score = compression ratio / time (higher is better)
            double score = (1.0 - avgRatio) / (avgTime + 1.0);
            
            if (score > bestScore) {
                bestScore = score;
                bestMethod = method;
            }
        }
    }
    
    qInfo() << "[AgenticLearning] Predicted optimal compression:" << bestMethod 
            << "for size:" << dataSize << "score:" << bestScore;
    
    return bestMethod;
}

void AgenticLearningSystem::recordUserFeedback(const QString& operation, bool positive) {
    if (m_successRates.contains(operation)) {
        // Update running average
        double currentRate = m_successRates[operation];
        m_successRates[operation] = currentRate * 0.9 + (positive ? 0.1 : 0.0);
    } else {
        m_successRates[operation] = positive ? 1.0 : 0.0;
    }
    
    qDebug() << "[AgenticLearning] User feedback:" << operation 
             << (positive ? "positive" : "negative")
             << "new rate:" << m_successRates[operation];
}