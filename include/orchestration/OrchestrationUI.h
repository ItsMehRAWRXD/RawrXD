<<<<<<< HEAD
#pragma once
/*  OrchestrationUI.h  -  User Interface for Task Orchestration (C++20, no Qt)
    
    Clean UI for natural language task input and orchestration results.
*/

#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include "TaskOrchestrator.h"

namespace RawrXD {

class OrchestrationUI {
public:
    explicit OrchestrationUI(TaskOrchestrator* orchestrator, void* parent = nullptr);

    void setupUI();
    void updateTaskList();
    void showResults(const std::vector<OrchestrationResult>& results);

private:
    void onOrchestrateClicked();
    void onTaskSplitCompleted(const std::vector<TaskDefinition>& tasks);
    void onModelSelectionCompleted(const std::map<std::string, std::string>& modelAssignments);
    void onTabCreated(const std::string& tabName, const std::string& model);
    void onTaskStarted(const std::string& taskId, const std::string& model);
    void onTaskProgress(const std::string& taskId, int progress);
    void onTaskCompleted(const OrchestrationResult& result);
    void onOrchestrationCompleted(const std::vector<OrchestrationResult>& results);
    void onErrorOccurred(const std::string& errorMessage);

    void createInputSection();
    void createProgressSection();
    void createResultsSection();
    void createMemorySettingsSection();
    std::string formatMemorySize(int64_t bytes) const;

    TaskOrchestrator* m_orchestrator = nullptr;

    void* m_taskInput = nullptr;
    void* m_orchestrateButton = nullptr;
    void* m_resultsDisplay = nullptr;
    void* m_taskList = nullptr;
    void* m_overallProgress = nullptr;
    void* m_statusLabel = nullptr;
    void* m_memoryProfileCombo = nullptr;
    void* m_memoryStrategyCombo = nullptr;
    void* m_memoryUsageLabel = nullptr;
    void* m_memoryUsageBar = nullptr;
};

} // namespace RawrXD
=======
#pragma once
/*  OrchestrationUI.h  -  User Interface for Task Orchestration
    
    Provides a clean UI for natural language task input and orchestration results.
    Integrates with MainWindow to provide seamless user experience.
*/

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QLabel>
#include <QProgressBar>
#include <QListWidget>
#include <QTabWidget>
#include <QComboBox>
#include "TaskOrchestrator.h"

namespace RawrXD {

class OrchestrationUI : public QWidget
{
    Q_OBJECT

public:
    explicit OrchestrationUI(TaskOrchestrator* orchestrator, QWidget* parent = nullptr);
    
    void setupUI();
    void updateTaskList();
    void showResults(const QList<OrchestrationResult>& results);

private slots:
    void onOrchestrateClicked();
    void onTaskSplitCompleted(const QList<TaskDefinition>& tasks);
    void onModelSelectionCompleted(const QHash<QString, QString>& modelAssignments);
    void onTabCreated(const QString& tabName, const QString& model);
    void onTaskStarted(const QString& taskId, const QString& model);
    void onTaskProgress(const QString& taskId, int progress);
    void onTaskCompleted(const OrchestrationResult& result);
    void onOrchestrationCompleted(const QList<OrchestrationResult>& results);
    void onErrorOccurred(const QString& errorMessage);

private:
    TaskOrchestrator* m_orchestrator;
    
    // UI Components
    QLineEdit* m_taskInput;
    QPushButton* m_orchestrateButton;
    QTextEdit* m_resultsDisplay;
    QListWidget* m_taskList;
    QProgressBar* m_overallProgress;
    QLabel* m_statusLabel;
    
    // Memory Management UI
    QComboBox* m_memoryProfileCombo;
    QComboBox* m_memoryStrategyCombo;
    QLabel* m_memoryUsageLabel;
    QProgressBar* m_memoryUsageBar;
    
    void createInputSection();
    void createProgressSection();
    void createResultsSection();
    void createMemorySettingsSection();
    QString formatMemorySize(qint64 bytes) const;
};

} // namespace RawrXD
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
