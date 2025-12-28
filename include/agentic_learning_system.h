#pragma once

#include <QObject>
#include <QString>
#include <QMap>
#include <QList>

struct PerformanceRecord {
    QString method;
    size_t inputSize;
    size_t outputSize;
    qint64 timeMs;
    double ratio;
    qint64 timestamp;
};

class AgenticLearningSystem : public QObject {
    Q_OBJECT
    
public:
    explicit AgenticLearningSystem(QObject* parent = nullptr);
    
    // Learn from compression performance
    void recordCompressionPerformance(
        const QString& method,
        size_t inputSize,
        size_t outputSize,
        qint64 timeMs
    );
    
    // Predict optimal compression for new data
    QString predictOptimalCompression(size_t dataSize, const QString& dataType);
    
    // Learn from user feedback
    void recordUserFeedback(const QString& operation, bool positive);
    
    // Get learning statistics
    QMap<QString, double> getSuccessRates() const { return m_successRates; }
    
private:
    QMap<QString, QList<PerformanceRecord>> m_performanceHistory;
    QMap<QString, double> m_successRates;
};