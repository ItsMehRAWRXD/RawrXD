#include "execution_visualizer.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QTreeWidget>
#include <QHeaderView>
#include <QProgressBar>
#include <QLabel>
#include <QTextEdit>
#include <QTableWidget>
#include <QDateTime>
#include <QDebug>
#include <QColor>

ExecutionVisualizer::ExecutionVisualizer(QWidget* parent) : QWidget(parent) {}
ExecutionVisualizer::~ExecutionVisualizer() = default;

void ExecutionVisualizer::initialize() {
    setupUI();
}

void ExecutionVisualizer::setupUI() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(10, 10, 10, 10);
    mainLayout->setSpacing(10);

    // Header: Workflow Info
    QWidget* headerWidget = new QWidget(this);
    QHBoxLayout* headerLayout = new QHBoxLayout(headerWidget);
    m_workflowTitleLabel = new QLabel("No Active Workflow", this);
    m_workflowTitleLabel->setStyleSheet("font-size: 16pt; font-weight: bold; color: #2c3e50;");
    m_currentPhaseLabel = new QLabel("Phase: Idle", this);
    m_currentPhaseLabel->setStyleSheet("font-weight: bold; color: #7f8c8d;");
    
    headerLayout->addWidget(m_workflowTitleLabel);
    headerLayout->addStretch();
    headerLayout->addWidget(m_currentPhaseLabel);
    mainLayout->addWidget(headerWidget);

    // Progress Bar
    m_overallProgressBar = new QProgressBar(this);
    m_overallProgressBar->setRange(0, 100);
    m_overallProgressBar->setValue(0);
    m_overallProgressBar->setFormat("Overall Progress: %p%");
    mainLayout->addWidget(m_overallProgressBar);

    // Main Content: Splitter for Tree and Log
    QSplitter* splitter = new QSplitter(Qt::Vertical, this);
    
    // Top: Step Tree
    m_stepTree = new QTreeWidget(this);
    m_stepTree->setHeaderLabels({"Step Description", "Type", "Status", "Duration", "Timestamp"});
    m_stepTree->setColumnWidth(0, 400);
    m_stepTree->setColumnWidth(1, 100);
    m_stepTree->setColumnWidth(2, 100);
    m_stepTree->setAlternatingRowColors(true);
    splitter->addWidget(m_stepTree);

    // Bottom: Step Detail / Log
    m_stepDetailLog = new QTextEdit(this);
    m_stepDetailLog->setReadOnly(true);
    m_stepDetailLog->setPlaceholderText("Select a step to see detailed output/logs...");
    m_stepDetailLog->setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; font-family: 'Consolas', monospace;");
    splitter->addWidget(m_stepDetailLog);

    mainLayout->addWidget(splitter, 1);

    // Metrics Table Footer
    m_metricsTable = new QTableWidget(1, 4, this);
    m_metricsTable->setHorizontalHeaderLabels({"Total Steps", "Successful", "Failed", "Elapsed Time"});
    m_metricsTable->verticalHeader()->setVisible(false);
    m_metricsTable->setFixedHeight(60);
    m_metricsTable->horizontalHeader()->setStretchLastSection(true);
    mainLayout->addWidget(m_metricsTable);

    setLayout(mainLayout);
}

void ExecutionVisualizer::startWorkflow(const QString& id, const QString& goal) {
    m_activeWorkflowId = id;
    m_steps.clear();
    m_stepIds.clear();
    m_stepTree->clear();
    m_workflowStartTime = QDateTime::currentDateTime();
    m_workflowTitleLabel->setText("Workflow: " + goal);
    m_overallProgressBar->setValue(0);
    m_metricsTable->setItem(0, 0, new QTableWidgetItem("0"));
    m_metricsTable->setItem(0, 1, new QTableWidgetItem("0"));
    m_metricsTable->setItem(0, 2, new QTableWidgetItem("0"));
}

void ExecutionVisualizer::onStepStarted(const QString& description) {
    if (description.isEmpty()) return;

    ExecutionStep step;
    step.id = QString::number(m_steps.size());
    step.description = description;
    step.status = StepStatus::Running;
    step.startTime = QDateTime::currentDateTime();
    
    m_steps[step.id] = step;
    m_stepIds.append(step.id);

    QTreeWidgetItem* item = new QTreeWidgetItem(m_stepTree);
    item->setData(0, Qt::UserRole, step.id);
    item->setText(0, description);
    item->setText(1, "Task");
    item->setText(2, "Running...");
    item->setText(4, step.startTime.toString("hh:mm:ss"));
    item->setForeground(2, QBrush(Qt::blue));
    
    m_stepTree->scrollToBottom();
}

void ExecutionVisualizer::onStepCompleted(const QString& description, bool success) {
    // Find the running step with this description (simplified)
    for (auto& step : m_steps) {
        if (step.description == description && step.status == StepStatus::Running) {
            step.status = success ? StepStatus::Success : StepStatus::Failed;
            step.endTime = QDateTime::currentDateTime();
            step.durationMs = step.startTime.msecsTo(step.endTime);
            
            // Update UI item
            for (int i = 0; i < m_stepTree->topLevelItemCount(); ++i) {
                QTreeWidgetItem* item = m_stepTree->topLevelItem(i);
                if (item->data(0, Qt::UserRole).toString() == step.id) {
                    item->setText(2, statusToString(step.status));
                    item->setText(3, QString("%1ms").arg(step.durationMs));
                    item->setForeground(2, QBrush(statusToColor(step.status)));
                    break;
                }
            }
            break;
        }
    }
}

void ExecutionVisualizer::onExecutionPhaseChanged(const QString& phase) {
    m_currentPhaseLabel->setText("Phase: " + phase.toUpper());
    onLogMessage("System Phase Transition: " + phase);
}

void ExecutionVisualizer::onTaskProgress(int current, int total) {
    if (total > 0) {
        int percent = (current * 100) / total;
        m_overallProgressBar->setValue(percent);
        m_metricsTable->setItem(0, 0, new QTableWidgetItem(QString::number(total)));
        m_metricsTable->setItem(0, 1, new QTableWidgetItem(QString::number(current)));
    }
}

void ExecutionVisualizer::onLogMessage(const QString& message) {
    m_stepDetailLog->append(QString("[%1] %2").arg(QDateTime::currentDateTime().toString("hh:mm:ss.zzz"), message));
}

void ExecutionVisualizer::onErrorOccurred(const QString& error) {
    m_stepDetailLog->append("<font color='red'><b>[ERROR]</b> " + error + "</font>");
    m_metricsTable->setItem(0, 2, new QTableWidgetItem("1+"));
}

QString ExecutionVisualizer::statusToString(StepStatus status) const {
    switch(status) {
        case StepStatus::Pending: return "Pending";
        case StepStatus::Running: return "Running";
        case StepStatus::Success: return "Success";
        case StepStatus::Failed: return "Failed";
        case StepStatus::Retrying: return "Retrying";
        default: return "Unknown";
    }
}

QColor ExecutionVisualizer::statusToColor(StepStatus status) const {
    switch(status) {
        case StepStatus::Success: return Qt::darkGreen;
        case StepStatus::Failed: return Qt::darkRed;
        case StepStatus::Running: return Qt::blue;
        case StepStatus::Retrying: return QColor(255, 140, 0);
        default: return Qt::black;
    }
}
