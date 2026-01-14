#ifndef AGENTIC_LEARNING_SYSTEM_H
#define AGENTIC_LEARNING_SYSTEM_H

#include <QObject>
#include <QString>
#include <QTimer>
#include <QMap>
#include <QJsonObject>
#include <QReadWriteLock>
#include <QList>

// PerformanceRecord struct
struct PerformanceRecord {
    QString method;
    size_t inputSize;
    size_t outputSize;
    qint64 timeMs;
    double ratio;
    qint64 timestamp;
};

/**
 * @class AgenticLearningSystem
 * @brief Advanced machine learning system for IDE optimization and user behavior learning     
 */
class AgenticLearningSystem : public QObject {
    Q_OBJECT

public:
    explicit AgenticLearningSystem(QObject* parent = nullptr);
    ~AgenticLearningSystem();

    /**
     * @brief Initialize the learning system
     */
    void initialize();

    /**
     * @brief Record user action for learning
     */
    void recordUserAction(const QString& action, const QJsonObject& context = QJsonObject());

    /**
     * @brief Analyze current IDE state for optimization opportunities
     */
    QJsonObject analyzeForOptimizations();

    /**
     * @brief Get learning statistics
     */
    QJsonObject getLearningStatistics() const;

    /**
     * @brief Record inference efficiency metrics
     */
    void recordInferenceEfficiency(const QString& component, qint64 tokens, double efficiency, bool success = true);

    /**
     * @brief Record compression performance metrics
     */
    void recordCompressionPerformance(const QString& component, size_t inputSize, size_t outputSize, double performance);

    /**
     * @brief Record user feedback
     */
    void recordUserFeedback(const QString& feedback, double rating);

    /**
     * @brief Load knowledge base from file
     */
    void loadKnowledgeBase(const QString& filename);

    /**
     * @brief Save knowledge base to file
     */
    void saveKnowledgeBase(const QString& filename);

    /**
     * @brief Calculate exponential moving average
     */
    double calculateEMA(double newValue, double oldValue, double alpha = 0.1);

    /**
     * @brief Predict optimal compression method
     */
    QString predictOptimalCompression(const QString& fileType, size_t fileSize);

signals:
    /**
     * @brief Emitted when suggestion is accepted by user
     */
    void onSuggestionAccepted(const QString& suggestion, double improvement);

    /**
     * @brief Emitted when anomaly is detected
     */
    void anomalyDetected(const QString& type, const QJsonObject& details);

    /**
     * @brief Emitted when optimization is suggested
     */
    void optimizationSuggested(const QString& change, double improvement);

    /**
     * @brief Learning progress update
     */
    void learningProgress(int current, int total);

    /**
     * @brief Learning system status
     */
    void statusUpdate(const QString& message);

public slots:
    /**
     * @brief Start learning session
     */
    void startLearning();

    /**
     * @brief Stop learning session
     */
    void stopLearning();

    /**
     * @brief Process optimization suggestion
     */
    void processOptimizationSuggestion(const QString& change, double improvement);

private slots:
    void onTimerTimeout();
    void onAnalysisComplete();
    void onOptimizationApplied(const QString& change, double improvement);

private:
    void initializeModel();
    void processUserBehavior();
    void updateOptimizationSuggestions();
    void generateInsights();

    // Member variables
    bool m_initialized;
    QTimer* m_learningTimer;
    QTimer* m_analysisTimer;
    QMap<QString, int> m_actionCounts;
    QJsonObject m_behaviorData;
    QJsonObject m_optimizationSuggestions;
    int m_learningSessionCount;
    int m_optimizationCount;
    double m_averageImprovement;

    // Internal state
    QString m_currentState;
    QJsonObject m_analyticsData;

    // Performance tracking
    QReadWriteLock m_lock;
    QMap<QString, QList<PerformanceRecord>> m_performanceHistory;
    QMap<QString, double> m_averageLatencies;
    QMap<QString, double> m_successRates;
    int m_maxRecordsPerMethod = 1000;
};

#endif // AGENTIC_LEARNING_SYSTEM_H

