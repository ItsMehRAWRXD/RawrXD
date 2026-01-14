#pragma once
#include "../agentic/agentic_engine.h"
#include <QFileSystemWatcher>
#include <QThread>

class MultiFileAgenticEngine : public QObject {
    Q_OBJECT
public:
    MultiFileAgenticEngine(AgenticEngine* core, QObject* parent = nullptr);
    
    // Multi-file operations
    void analyzeRepository(const QString& repoPath);
    void refactorAcrossFiles(const QString& pattern, const QString& replacement);
    void generateMultiFileFeature(const QString& featureSpec);
    void propagateChanges(const QString& changedFile);
    
    // Cross-file context
    void buildRepositoryContext();
    QJsonObject getFileRelationships(const QString& filePath);
    QStringList findRelatedFiles(const QString& filePath);
    
    // Agentic workflows
    void executeWorkflow(const QString& workflowName, const QJsonObject& params);
    void createCustomWorkflow(const QString& name, const QJsonArray& steps);
    
    // Real-time file monitoring
    void startFileWatching(const QString& repoPath);
    void stopFileWatching();
    
signals:
    void repositoryAnalyzed(const QJsonObject& analysis);
    void multiFileRefactorComplete(const QStringList& modifiedFiles);
    void workflowProgress(const QString& step, int progress);
    void fileChanged(const QString& filePath);
    
private slots:
    void onFileChanged(const QString& path);
    void onDirectoryChanged(const QString& path);
    void processWorkflowStep(const QJsonObject& step);
    
private:
    AgenticEngine* m_coreEngine;
    QFileSystemWatcher* m_fileWatcher;
    QThread* m_workerThread;
    
    // Repository context
    QJsonObject m_repoContext;
    QMap<QString, QStringList> m_fileDependencies;
    QMap<QString, QJsonObject> m_fileMetadata;
    
    // Workflow execution
    struct WorkflowStep {
        QString action;
        QJsonObject parameters;
        QString condition;
    };
    QMap<QString, QVector<WorkflowStep>> m_workflows;
    
    // Multi-file analysis
    void analyzeFileDependencies(const QString& repoPath);
    void extractSymbolReferences(const QString& filePath);
    void buildCallGraph();
    
    // Parallel processing
    void processFilesInParallel(const QStringList& files, 
                               std::function<void(const QString&)> processor);
};
