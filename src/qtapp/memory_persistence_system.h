#pragma once

#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>
#include <QDir>
#include <memory>

/**
 * @class MemoryPersistenceSystem
 * @brief Provides context persistence and intelligent memory management
 * 
 * Features:
 * - Automatic context snapshots and restoration
 * - Session persistence across IDE restarts
 * - Intelligent memory optimization
 * - Knowledge graph of code relationships
 * - Context-aware suggestions based on history
 * - Memory leak detection and cleanup
 */
class MemoryPersistenceSystem : public QObject {
    Q_OBJECT
public:
    explicit MemoryPersistenceSystem(QObject* parent = nullptr);
    virtual ~MemoryPersistenceSystem();

    // Memory statistics structure
    struct MemoryStats {
        qint64 totalSize;
        int activeSnapshots;
        int totalSessions;
        double compressionRatio;
    };

    // Context management
    void saveContextSnapshot(const QString& sessionId, const QJsonObject& context);
    QJsonObject loadContextSnapshot(const QString& sessionId);
    QJsonArray listSnapshots();
    void deleteSnapshot(const QString& sessionId);
    
    // Session persistence
    void saveSessionState(const QString& sessionName, const QJsonObject& state);
    QJsonObject loadSessionState(const QString& sessionName);
    void saveCurrentSession();
    void restoreLastSession();
    
    // Knowledge graph
    void addCodeRelationship(const QString& filePath, const QString& symbol, const QJsonObject& metadata);
    QJsonArray findRelatedCode(const QString& symbol);
    QJsonObject buildKnowledgeGraph(const QString& projectPath);
    
    // Memory optimization
    void optimizeMemoryUsage();
    QJsonObject getMemoryUsageStats();
    void cleanupExpiredData();
    
    // Context suggestions
    QJsonArray suggestContextBasedOnHistory(const QString& currentContext);
    QJsonArray suggestRelevantFiles(const QString& currentFile);
    QString suggestNextAction(const QJsonObject& currentState);

public slots:
    void onSessionStarted(const QString& sessionId);
    void onSessionEnded(const QString& sessionId);
    void onCodeFileOpened(const QString& filePath);
    void onCodeFileModified(const QString& filePath);
    void onBuildCompleted(const QString& buildId, bool success);
    void enableAutoSnapshot(bool enable);
    void setSnapshotInterval(int minutes);

signals:
    void snapshotSaved(const QString& sessionId);
    void sessionRestored(const QString& sessionName);
    void memoryOptimized(const QJsonObject& stats);
    void suggestionGenerated(const QJsonArray& suggestions);
    void memoryAlert(const QString& level, const QString& message);

private:
    // Internal helpers
    QString generateSnapshotId();
    QString getStoragePath();
    QJsonObject serializeContext(const QJsonObject& context);
    QJsonObject deserializeContext(const QJsonObject& data);
    QJsonObject createCurrentContext();
    void applyContext(const QJsonObject& context);
    void saveKnowledgeGraph();
    QString findFileForSymbol(const QString& symbol);
    MemoryStats calculateMemoryStats();
    QJsonObject serializeMemoryStats(const MemoryStats& stats);
    
    // Data structures
    struct SessionData {
        QString sessionId;
        QString timestamp;
        QJsonObject context;
        QString projectPath;
        QStringList openFiles;
        QJsonObject buildHistory;
        QJsonObject settings;
    };
    
    QHash<QString, std::shared_ptr<SessionData>> m_activeSessions;
    QHash<QString, std::shared_ptr<SessionData>> m_persistentSessions;
    QJsonObject m_knowledgeGraph;
    QTimer* m_optimizationTimer;
    QTimer* m_snapshotTimer;
    
    // Configuration
    bool m_autoSnapshot = true;
    int m_snapshotIntervalMinutes = 30;
    int m_maxSnapshots = 50;
    qint64 m_maxStorageMB = 1024; // 1GB limit
    
    // Storage paths
    QString m_baseStoragePath;
    QString m_snapshotsPath;
    QString m_sessionsPath;
    QString m_knowledgePath;
};
