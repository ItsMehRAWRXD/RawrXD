// Production Readiness Integration - Enterprise standards header
#pragma once

#include <QObject>
#include <QJsonObject>
#include <QJsonArray>
#include <QVariantMap>
#include <QStringList>
#include <QDateTime>
#include <QTimer>
#include <QElapsedTimer>
#include <QMutex>
#include <QReadWriteLock>
#include <memory>

// Forward declarations for all AI systems
class AgenticExecutor;
class InferenceEngine;
class AdvancedPlanningEngine;
class ToolCompositionFramework;
class ErrorAnalysisSystem;
class DependencyDetector;
class ModelTrainingPipeline;
class DistributedTracer;
class MemoryPersistence;

/**
 * @brief Production Readiness Orchestrator
 * 
 * Implements the AI Toolkit Production Readiness standards:
 * - 🚀 AI Toolkit Production Readiness Plan
 * - 🔍 Observability and Monitoring
 * - 🛡️ Non-Intrusive Error Handling
 * - ⚙️ Configuration Management
 * - 🧪 Comprehensive Testing
 * - 🐳 Deployment and Isolation
 */
class ProductionReadinessOrchestrator : public QObject {
    Q_OBJECT

public:
    explicit ProductionReadinessOrchestrator(QObject* parent = nullptr);
    ~ProductionReadinessOrchestrator();

    // System initialization following production standards
    bool initializeAllSystems(AgenticExecutor* executor, InferenceEngine* inference);
    bool isInitialized() const { return m_initialized; }

    // Production readiness assessment
    QJsonObject getSystemHealthStatus() const;
    QString generateSystemReport() const;
    double getOverallHealthScore() const { return calculateOverallHealthScore(); }
    QStringList getSystemRecommendations() const;

    // Observability and monitoring
    QJsonObject getCurrentMetrics() const { return m_metrics; }
    QJsonObject getPerformanceTrends() const;
    QStringList getActiveAlerts() const;
    void enableDetailedMonitoring(bool enabled);

    // Configuration management
    void loadProductionConfiguration(const QString& configPath);
    void saveProductionConfiguration(const QString& configPath) const;
    void updateFeatureToggle(const QString& feature, bool enabled);
    QJsonObject getConfigurationStatus() const;

    // Resource management and limits
    void setResourceLimits(const QVariantMap& limits);
    QJsonObject getResourceUsage() const;
    void enforceResourceConstraints(bool enforce);

    // Component access (for integration)
    AdvancedPlanningEngine* planningEngine() const { return m_planningEngine; }
    ToolCompositionFramework* toolFramework() const { return m_toolFramework; }
    ErrorAnalysisSystem* errorAnalysis() const { return m_errorAnalysis; }
    DependencyDetector* dependencyDetector() const { return m_dependencyDetector; }
    ModelTrainingPipeline* modelTraining() const { return m_modelTraining; }
    DistributedTracer* distributedTracer() const { return m_distributedTracer; }
    MemoryPersistence* memoryPersistence() const { return m_memoryPersistence; }

public slots:
    void performHealthCheck();
    void performMaintenanceTasks();
    void optimizeSystemPerformance();
    void onCriticalError(const QString& errorId, const QString& message);
    void onSystemHealthChanged(double healthScore);
    void onBottleneckDetected(const QString& description);
    void onPlanningExecutionCompleted(const QJsonObject& results);

signals:
    void allSystemsInitialized();
    void systemHealthChanged(double healthScore);
    void criticalAlertTriggered(const QString& alert);
    void resourceLimitExceeded(const QString& resource, double current, double limit);
    void performanceOptimizationSuggested(const QStringList& suggestions);
    void metricsUpdated(const QJsonObject& metrics);
    void maintenanceCompleted();

private slots:
    void performMonitoringTasks();
    void collectMetrics();
    void monitorResources();
    void updateSystemHealth();

private:
    // Core AI system components
    AgenticExecutor* m_agenticExecutor = nullptr;
    InferenceEngine* m_inferenceEngine = nullptr;
    AdvancedPlanningEngine* m_planningEngine = nullptr;
    ToolCompositionFramework* m_toolFramework = nullptr;
    ErrorAnalysisSystem* m_errorAnalysis = nullptr;
    DependencyDetector* m_dependencyDetector = nullptr;
    ModelTrainingPipeline* m_modelTraining = nullptr;
    DistributedTracer* m_distributedTracer = nullptr;
    MemoryPersistence* m_memoryPersistence = nullptr;

    // Production readiness state
    bool m_initialized = false;
    QDateTime m_startupTime;
    QElapsedTimer m_uptimeTimer;
    QString m_applicationTraceId;

    // Configuration and monitoring
    QJsonObject m_currentConfig;
    QJsonObject m_metrics;
    QVariantMap m_resourceLimits;
    QStringList m_activeAlerts;

    // Production standards implementation
    void applyProductionStandards();
    
    // 🔍 Observability and Monitoring
    void configureAdvancedLogging();
    void setupAdvancedStructuredLogging();
    void setupMetricsGeneration();
    void configureMetricsInstrumentation();
    void enableDistributedTracing();
    void initializeDistributedTracing();
    
    // 🛡️ Non-Intrusive Error Handling
    void setupCentralizedErrorCapture();
    void configureResourceGuards();
    
    // ⚙️ Configuration Management
    void setupExternalConfiguration();
    void enableFeatureToggles();
    
    // 🧪 Comprehensive Testing
    void setupBehavioralTests();
    void enableFuzzTesting();
    
    // 🐳 Deployment and Isolation
    void configureContainerization();
    void setupResourceLimits();

    // Internal helpers
    void initializeComponents();
    void setupMonitoring();
    void loadConfiguration();
    void connectSystemSignals();
    void startHealthMonitoring();
    
    // Metrics and monitoring
    qint64 getCurrentMemoryUsageMB() const;
    qint64 getTotalSystemMemoryMB() const;
    QJsonObject getDiskUsageInfo() const;
    double calculateOverallHealthScore() const;
    QString getHealthGrade(double healthScore) const;
    
    // Production utilities
    void saveProductionMetrics();
    void generateShutdownReport();
};
