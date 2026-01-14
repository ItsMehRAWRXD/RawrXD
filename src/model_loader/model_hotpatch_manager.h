// model_hotpatch_manager.h - Runtime Model Swapping & Inference Hotpatching
#pragma once

#include <QObject>
#include <QString>
#include <QVector>
#include <QMap>
#include <QMutex>
#include <QDateTime>
#include <QJsonObject>
#include <QSharedPointer>
#include <QAtomicInt>
#include <functional>

namespace ModelHotpatch {

/**
 * @brief Model metadata and status information
 */
struct ModelInfo {
    QString modelId;
    QString modelName;
    QString modelPath;
    QString modelType;          // "gguf", "onnx", "pytorch", "tensorflow"
    QString version;
    qint64 sizeBytes;
    QString checksum;
    QDateTime loadedAt;
    bool isActive;
    bool isValidated;
    int referenceCount;
    QJsonObject metadata;
    QJsonObject performanceStats;
    
    ModelInfo() : sizeBytes(0), isActive(false), isValidated(false), referenceCount(0) {}
};

/**
 * @brief Hotpatch operation result
 */
struct HotpatchResult {
    bool success;
    QString modelId;
    QString previousModelId;
    qint64 swapDurationMs;
    QString errorMessage;
    QDateTime completedAt;
    QJsonObject metrics;
};

/**
 * @brief Model loading strategy
 */
enum class LoadStrategy {
    Lazy,               // Load on first use
    Eager,              // Load immediately
    Background,         // Load in background thread
    Preemptive,         // Preload based on prediction
    OnDemand            // Load only when requested
};

/**
 * @brief Model versioning information
 */
struct HotpatchModelVersion {
    QString version;
    QString modelPath;
    QDateTime releasedAt;
    QStringList changes;
    bool isStable;
    bool deprecated;
    QString deprecationReason;
};

/**
 * @brief Canary deployment configuration
 */
struct CanaryConfig {
    QString testModelId;
    double trafficPercentage;   // 0.0 to 1.0
    int minRequests;
    double successThreshold;
    int durationSeconds;
    QDateTime startedAt;
};

/**
 * @brief A/B test configuration
 */
struct ABTestConfig {
    QString testId;
    QString modelAId;
    QString modelBId;
    double splitRatio;          // 0.0 to 1.0 (fraction going to A)
    QDateTime startTime;
    QDateTime endTime;
    QJsonObject successCriteria;
};

/**
 * @brief Model performance tracking
 */
struct ModelPerformanceMetrics {
    qint64 totalInferences;
    double averageLatencyMs;
    double p95LatencyMs;
    double p99LatencyMs;
    qint64 errorCount;
    double errorRate;
    double throughput;          // inferences per second
    QDateTime lastUpdated;
};

/**
 * @brief Model Hotpatch Manager
 * 
 * Enables zero-downtime model swapping with:
 * - Atomic model switching
 * - Version management and rollback
 * - Canary deployments
 * - A/B testing
 * - Performance tracking
 */
class ModelHotpatchManager : public QObject {
    Q_OBJECT

public:
    explicit ModelHotpatchManager(QObject* parent = nullptr);
    ~ModelHotpatchManager();

    // Initialization
    void initialize(const QString& modelsDirectory);
    void shutdown();

    // Model loading and registration
    bool registerModel(const QString& modelPath, const QJsonObject& metadata = QJsonObject());
    bool unregisterModel(const QString& modelId);
    QVector<ModelInfo> listModels() const;
    ModelInfo getModelInfo(const QString& modelId) const;
    
    // Hotpatching operations
    HotpatchResult swapModel(const QString& newModelId, bool validateFirst = true);
    HotpatchResult swapModelAsync(const QString& newModelId, std::function<void(HotpatchResult)> callback);
    bool preloadModel(const QString& modelId, LoadStrategy strategy = LoadStrategy::Background);
    bool unloadModel(const QString& modelId);
    
    // Versioning
    bool setModelVersion(const QString& modelId, const HotpatchModelVersion& version);
    QVector<HotpatchModelVersion> getModelVersions(const QString& modelId) const;
    HotpatchResult rollbackToVersion(const QString& modelId, const QString& version);
    QString getCurrentModelVersion() const;
    
    // Validation
    bool validateModel(const QString& modelId);
    bool verifyChecksum(const QString& modelId);
    QJsonObject runHealthCheck(const QString& modelId);
    
    // Canary deployments
    bool startCanaryDeployment(const CanaryConfig& config);
    void stopCanaryDeployment();
    QJsonObject getCanaryMetrics() const;
    bool promoteCanaryToProduction();
    bool rollbackCanary();
    
    // A/B testing
    bool startABTest(const ABTestConfig& config);
    void stopABTest(const QString& testId);
    QJsonObject getABTestResults(const QString& testId) const;
    QString selectModelForRequest(const QString& requestId);
    
    // Performance monitoring
    void recordInference(const QString& modelId, double latencyMs, bool success);
    ModelPerformanceMetrics getPerformanceMetrics(const QString& modelId) const;
    QString getBestPerformingModel() const;
    
    // Active model management
    QString getActiveModelId() const;
    ModelInfo getActiveModel() const;
    bool setActiveModel(const QString& modelId);
    
    // Configuration
    void setMaxConcurrentLoads(int max);
    void setValidationTimeout(int seconds);
    void setModelCacheSize(int maxModels);
    void enableAutomaticRollback(bool enable);
    
    // Persistence
    bool saveModelRegistry(const QString& path = QString());
    bool loadModelRegistry(const QString& path = QString());

signals:
    void modelSwapped(const QString& newModelId, const QString& previousModelId);
    void modelLoaded(const QString& modelId);
    void modelUnloaded(const QString& modelId);
    void hotpatchFailed(const QString& modelId, const QString& error);
    void canaryPromoted(const QString& modelId);
    void performanceThresholdExceeded(const QString& modelId, const QString& metric, double value);

private:
    // Internal methods
    bool loadModelInternal(const QString& modelId);
    bool unloadModelInternal(const QString& modelId);
    QString calculateChecksum(const QString& filePath) const;
    bool atomicSwitch(const QString& fromModelId, const QString& toModelId);
    void updatePerformanceMetrics(const QString& modelId, double latencyMs, bool success);
    void pruneModelCache();
    bool shouldRouteToCanary() const;
    QString selectABTestModel(const QString& testId, const QString& requestId);
    
    // Thread safety
    mutable QMutex m_mutex;
    QAtomicInt m_activeInferences;
    
    // Model storage
    QString m_modelsDirectory;
    QMap<QString, ModelInfo> m_registeredModels;
    QMap<QString, HotpatchModelVersion> m_modelVersions;
    QString m_activeModelId;
    QVector<QString> m_loadedModels;
    
    // Performance tracking
    QMap<QString, ModelPerformanceMetrics> m_performanceMetrics;
    QMap<QString, QVector<double>> m_latencyHistory;
    
    // Canary deployment
    bool m_canaryActive;
    CanaryConfig m_canaryConfig;
    ModelPerformanceMetrics m_canaryMetrics;
    qint64 m_canaryRequests;
    qint64 m_canarySuccesses;
    
    // A/B testing
    QMap<QString, ABTestConfig> m_activeABTests;
    QMap<QString, QMap<QString, ModelPerformanceMetrics>> m_abTestMetrics;
    
    // Configuration
    int m_maxConcurrentLoads;
    int m_validationTimeoutSeconds;
    int m_maxCachedModels;
    bool m_automaticRollbackEnabled;
    
    // State
    bool m_initialized;
    QDateTime m_lastSwapTime;
    QVector<HotpatchResult> m_swapHistory;
    
    // Allow InferenceRouter and ModelReference to access private members
    friend class InferenceRouter;
    friend class ModelReference;
};

/**
 * @brief RAII model reference holder
 */
class ModelReference {
public:
    ModelReference(ModelHotpatchManager* manager, const QString& modelId);
    ~ModelReference();
    
    QString modelId() const { return m_modelId; }
    bool isValid() const { return m_valid; }

private:
    ModelHotpatchManager* m_manager;
    QString m_modelId;
    bool m_valid;
};

/**
 * @brief Inference router with automatic model selection
 */
class InferenceRouter : public QObject {
    Q_OBJECT

public:
    explicit InferenceRouter(ModelHotpatchManager* manager, QObject* parent = nullptr);
    
    // Routing strategies
    enum class RoutingStrategy {
        ActiveOnly,         // Use only active model
        LoadBalanced,       // Balance across loaded models
        PerformanceBased,   // Route to best performing model
        Canary,             // Include canary deployment
        ABTest              // Route for A/B testing
    };
    
    void setRoutingStrategy(RoutingStrategy strategy);
    QString routeRequest(const QString& requestId);
    
private:
    ModelHotpatchManager* m_manager;
    RoutingStrategy m_strategy;
};

} // namespace ModelHotpatch
