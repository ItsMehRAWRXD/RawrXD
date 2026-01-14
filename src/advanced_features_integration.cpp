/**
 * @file advanced_features_integration.cpp
 * @brief Implementation of advanced features integration
 */

#include "advanced_features_integration.h"
#include "agentic_executor.h"
#include "autonomous_intelligence_orchestrator.h"
#include <QMainWindow>
#include <QDockWidget>
#include <QMenuBar>
#include <QStatusBar>
#include <QTimer>
#include <QDebug>
#include <QJsonObject>

AdvancedFeaturesIntegration::AdvancedFeaturesIntegration(QMainWindow* mainWindow, QObject* parent)
    : QObject(parent)
    , m_mainWindow(mainWindow)
{
    qInfo() << "[AdvancedFeaturesIntegration] Initializing...";
}

AdvancedFeaturesIntegration::~AdvancedFeaturesIntegration() {
    qInfo() << "[AdvancedFeaturesIntegration] Shutting down";
}

void AdvancedFeaturesIntegration::initializeAllFeatures() {
    if (m_initialized) {
        qWarning() << "[AdvancedFeaturesIntegration] Already initialized";
        return;
    }
    
    qInfo() << "[AdvancedFeaturesIntegration] Initializing all features...";
    
    initializeDistributedTracing();
    initializeMemorySnapshots();
    initializeRealtimeRefactoring();
    initializeTestGeneration();
    initializeVisualDashboard();
    
    createDockWidgets();
    setupSignalConnections();
    
    m_initialized = true;
    emit allFeaturesReady();
    
    qInfo() << "[AdvancedFeaturesIntegration] ✓ All features initialized";
}

void AdvancedFeaturesIntegration::initializeDistributedTracing() {
    m_traceWidget = std::make_unique<DistributedTracing::TraceVisualizationWidget>();
    m_traceWidget->initialize();
    m_traceWidget->setAutoRefresh(true, 1000);
    
    // Also create execution visualizer
    m_executionVisualizer = std::make_unique<ExecutionVisualizer>();
    m_executionVisualizer->initialize();
    
    emit distributedTracingReady();
    qInfo() << "[AdvancedFeaturesIntegration] ✓ Distributed Tracing ready";
}

void AdvancedFeaturesIntegration::initializeMemorySnapshots() {
    m_snapshotWidget = std::make_unique<MemorySnapshotWidget>();
    m_snapshotWidget->initialize();
    m_snapshotWidget->setSessionPersistence(&RawrXD::SessionPersistence::instance());
    
    emit memorySnapshotsReady();
    qInfo() << "[AdvancedFeaturesIntegration] ✓ Memory Snapshots ready";
}

void AdvancedFeaturesIntegration::initializeRealtimeRefactoring() {
    m_refactoringWidget = std::make_unique<RealtimeRefactoringWidget>();
    m_refactoringWidget->initialize();
    
    emit realtimeRefactoringReady();
    qInfo() << "[AdvancedFeaturesIntegration] ✓ Real-time Refactoring ready";
}

void AdvancedFeaturesIntegration::initializeTestGeneration() {
    m_testGenWidget = std::make_unique<TestGenerationWidget>();
    m_testGenWidget->initialize();
    
    emit testGenerationReady();
    qInfo() << "[AdvancedFeaturesIntegration] ✓ Test Generation ready";
}

void AdvancedFeaturesIntegration::initializeVisualDashboard() {
    m_dashboardWidget = std::make_unique<CapabilityMonitorDashboard>();
    m_dashboardWidget->initialize();
    m_dashboardWidget->startMonitoring();
    
    emit visualDashboardReady();
    qInfo() << "[AdvancedFeaturesIntegration] ✓ Visual Dashboard ready";
}

void AdvancedFeaturesIntegration::createDockWidgets() {
    if (!m_mainWindow) return;
    
    // Distributed Tracing dock
    m_traceDock = new QDockWidget(tr("Distributed Tracing"), m_mainWindow);
    m_traceDock->setWidget(m_traceWidget.get());
    m_traceDock->setObjectName("DistributedTracingDock");
    m_mainWindow->addDockWidget(Qt::BottomDockWidgetArea, m_traceDock);
    m_traceDock->hide();
    
    // Execution Visualizer dock
    m_executionVisualizerDock = new QDockWidget(tr("Execution Visualizer"), m_mainWindow);
    m_executionVisualizerDock->setWidget(m_executionVisualizer.get());
    m_executionVisualizerDock->setObjectName("ExecutionVisualizerDock");
    m_mainWindow->addDockWidget(Qt::RightDockWidgetArea, m_executionVisualizerDock);
    m_executionVisualizerDock->hide();
    
    // Memory Snapshots dock
    m_snapshotDock = new QDockWidget(tr("Memory Snapshots"), m_mainWindow);
    m_snapshotDock->setWidget(m_snapshotWidget.get());
    m_snapshotDock->setObjectName("MemorySnapshotsDock");
    m_mainWindow->addDockWidget(Qt::RightDockWidgetArea, m_snapshotDock);
    m_snapshotDock->hide();
    
    // Real-time Refactoring dock
    m_refactoringDock = new QDockWidget(tr("Code Refactoring"), m_mainWindow);
    m_refactoringDock->setWidget(m_refactoringWidget.get());
    m_refactoringDock->setObjectName("RefactoringDock");
    m_mainWindow->addDockWidget(Qt::RightDockWidgetArea, m_refactoringDock);
    m_refactoringDock->hide();
    
    // Test Generation dock
    m_testGenDock = new QDockWidget(tr("Test Generation"), m_mainWindow);
    m_testGenDock->setWidget(m_testGenWidget.get());
    m_testGenDock->setObjectName("TestGenerationDock");
    m_mainWindow->addDockWidget(Qt::RightDockWidgetArea, m_testGenDock);
    m_testGenDock->hide();
    
    // Visual Dashboard dock
    m_dashboardDock = new QDockWidget(tr("Performance Dashboard"), m_mainWindow);
    m_dashboardDock->setWidget(m_dashboardWidget.get());
    m_dashboardDock->setObjectName("DashboardDock");
    m_mainWindow->addDockWidget(Qt::BottomDockWidgetArea, m_dashboardDock);
    m_dashboardDock->hide();
    
    qInfo() << "[AdvancedFeaturesIntegration] ✓ Dock widgets created";
}

void AdvancedFeaturesIntegration::setupSignalConnections() {
    wireDistributedTracing();
    wireMemorySnapshots();
    wireRealtimeRefactoring();
    wireTestGeneration();
    wireVisualDashboard();
    
    qInfo() << "[AdvancedFeaturesIntegration] ✓ Signal connections established";
}

void AdvancedFeaturesIntegration::wireDistributedTracing() {
    // Internal wiring already done in initialize methods
    
    // Connect to this integration's public slots
    connect(m_traceWidget.get(), &DistributedTracing::TraceVisualizationWidget::exportRequested,
            this, &AdvancedFeaturesIntegration::traceExported);
}

void AdvancedFeaturesIntegration::wireMemorySnapshots() {
    connect(m_snapshotWidget.get(), &MemorySnapshotWidget::snapshotCreated,
            this, &AdvancedFeaturesIntegration::snapshotCreated);
}

void AdvancedFeaturesIntegration::wireRealtimeRefactoring() {
    connect(m_refactoringWidget.get(), &RealtimeRefactoringWidget::suggestionApplied,
            this, &AdvancedFeaturesIntegration::onRefactoringSuggestionApplied);
    
    connect(m_refactoringWidget.get(), &RealtimeRefactoringWidget::codeRefactored,
            this, &AdvancedFeaturesIntegration::refactoringApplied);
}

void AdvancedFeaturesIntegration::wireTestGeneration() {
    connect(m_testGenWidget.get(), &TestGenerationWidget::testsGenerated,
            this, &AdvancedFeaturesIntegration::testsGenerated);
}

void AdvancedFeaturesIntegration::wireVisualDashboard() {
    connect(m_dashboardWidget.get(), &CapabilityMonitorDashboard::alertTriggered,
            this, &AdvancedFeaturesIntegration::performanceAlertTriggered);
    
    connect(m_dashboardWidget.get(), &CapabilityMonitorDashboard::performanceThresholdExceeded,
            this, &AdvancedFeaturesIntegration::onResourceAlert);
}

void AdvancedFeaturesIntegration::connectToAgenticExecutor(AgenticExecutor* executor) {
    m_agenticExecutor = executor;
    
    if (!executor) return;
    
    // Connect execution visualizer
    if (m_executionVisualizer) {
        connect(executor, &AgenticExecutor::stepStarted,
                m_executionVisualizer.get(), &ExecutionVisualizer::onStepStarted);
        connect(executor, &AgenticExecutor::stepCompleted,
                m_executionVisualizer.get(), &ExecutionVisualizer::onStepCompleted);
        connect(executor, &AgenticExecutor::executionPhaseChanged,
                m_executionVisualizer.get(), &ExecutionVisualizer::onExecutionPhaseChanged);
        connect(executor, &AgenticExecutor::taskProgress,
                m_executionVisualizer.get(), &ExecutionVisualizer::onTaskProgress);
    }
    
    qInfo() << "[AdvancedFeaturesIntegration] ✓ Connected to AgenticExecutor";
}

void AdvancedFeaturesIntegration::connectToAutonomousOrchestrator(AutonomousIntelligenceOrchestrator* orchestrator) {
    m_orchestrator = orchestrator;
    
    if (!orchestrator) return;
    
    // Connect orchestrator events to distributed tracing
    // (Would need orchestrator to expose appropriate signals)
    
    qInfo() << "[AdvancedFeaturesIntegration] ✓ Connected to AutonomousOrchestrator";
}

// Feature access
DistributedTracing::TraceVisualizationWidget* AdvancedFeaturesIntegration::traceWidget() const {
    return m_traceWidget.get();
}

MemorySnapshotWidget* AdvancedFeaturesIntegration::snapshotWidget() const {
    return m_snapshotWidget.get();
}

RealtimeRefactoringWidget* AdvancedFeaturesIntegration::refactoringWidget() const {
    return m_refactoringWidget.get();
}

TestGenerationWidget* AdvancedFeaturesIntegration::testGenWidget() const {
    return m_testGenWidget.get();
}

CapabilityMonitorDashboard* AdvancedFeaturesIntegration::dashboardWidget() const {
    return m_dashboardWidget.get();
}

// Enable/disable features
void AdvancedFeaturesIntegration::enableDistributedTracing(bool enable) {
    if (m_traceWidget) {
        m_traceWidget->setAutoRefresh(enable);
        if (enable) {
            m_traceWidget->refreshView();
        }
    }
}

void AdvancedFeaturesIntegration::enableMemorySnapshots(bool enable) {
    if (m_snapshotWidget && enable) {
        m_snapshotWidget->refreshSnapshotList();
    }
}

void AdvancedFeaturesIntegration::enableRealtimeRefactoring(bool enable) {
    Q_UNUSED(enable);
    // Refactoring widget is passive, no explicit enable/disable needed
}

void AdvancedFeaturesIntegration::enableTestGeneration(bool enable) {
    Q_UNUSED(enable);
    // Test generation widget is passive
}

void AdvancedFeaturesIntegration::enableVisualDashboard(bool enable) {
    if (m_dashboardWidget) {
        if (enable) {
            m_dashboardWidget->startMonitoring();
        } else {
            m_dashboardWidget->stopMonitoring();
        }
    }
}

// Integration slots
void AdvancedFeaturesIntegration::onAgenticTaskStarted(const QString& taskId, const QString& description) {
    // Start a new trace for this task
    using namespace DistributedTracing;
    
    SpanBuilder builder(description);
    builder.setServiceName("AgenticExecutor")
           .setOperationType("agentic.task.execution")
           .setKind(SpanKind::Server)
           .addAttribute("task.id", taskId);
    
    QString spanId = Tracer::instance().startSpan(builder);
    m_currentTraces[taskId] = spanId;
    
    // Update execution visualizer
    if (m_executionVisualizer) {
        m_executionVisualizer->startWorkflow(taskId, description);
    }
    
    qDebug() << "[AdvancedFeaturesIntegration] Started trace for task:" << taskId;
}

void AdvancedFeaturesIntegration::onAgenticTaskCompleted(const QString& taskId, bool success) {
    using namespace DistributedTracing;
    
    if (m_currentTraces.contains(taskId)) {
        QString spanId = m_currentTraces[taskId];
        Tracer::instance().endSpan(
            spanId,
            success ? SpanStatus::Ok : SpanStatus::Error,
            success ? "Task completed successfully" : "Task failed"
        );
        m_currentTraces.remove(taskId);
        
        qDebug() << "[AdvancedFeaturesIntegration] Ended trace for task:" << taskId;
    }
}

void AdvancedFeaturesIntegration::onAgenticPhaseChanged(const QString& phase) {
    using namespace DistributedTracing;
    
    // Add event to current active spans
    for (const QString& spanId : m_currentTraces.values()) {
        Tracer::instance().addSpanEvent(spanId, "phase.changed", {
            {"phase", phase}
        });
    }
}

void AdvancedFeaturesIntegration::onSessionStateChanged() {
    // Automatically create snapshot on major state changes if enabled
    // (Configuration would be managed by MemorySnapshotWidget)
}

void AdvancedFeaturesIntegration::createAutoSnapshot() {
    if (m_snapshotWidget) {
        m_snapshotWidget->createSnapshot();
        
        if (m_mainWindow) {
            m_mainWindow->statusBar()->showMessage("Memory snapshot created", 3000);
        }
    }
}

void AdvancedFeaturesIntegration::loadSessionFromSnapshot(const QString& snapshotId) {
    if (m_snapshotWidget) {
        m_snapshotWidget->loadSnapshot();
    }
}

void AdvancedFeaturesIntegration::onCodeEditorTextChanged(const QString& code, const QString& filePath) {
    if (m_refactoringWidget) {
        m_refactoringWidget->analyzeCode(code, filePath);
    }
}

void AdvancedFeaturesIntegration::onRefactoringSuggestionApplied(const RefactoringProposal& proposal) {
    qInfo() << "[AdvancedFeaturesIntegration] Refactoring applied:" << proposal.patternType;
}

void AdvancedFeaturesIntegration::onFileOpened(const QString& filePath) {
    if (m_testGenWidget) {
        // Could auto-generate tests for opened files if enabled
        // m_testGenWidget->generateTestsForFile(filePath);
    }
}

void AdvancedFeaturesIntegration::generateTestsForCurrentFile() {
    if (m_testGenWidget) {
        m_testGenWidget->onGenerateTests();
    }
}

void AdvancedFeaturesIntegration::runGeneratedTests() {
    if (m_testGenWidget) {
        m_testGenWidget->onRunTests();
    }
}

void AdvancedFeaturesIntegration::onPerformanceMetricsUpdated(const QJsonObject& metrics) {
    if (m_dashboardWidget) {
        m_dashboardWidget->onCapabilityMetricsUpdated(metrics);
    }
}

void AdvancedFeaturesIntegration::onResourceAlert(const QString& alertType, const QString& message) {
    emit performanceAlertTriggered(QString("%1: %2").arg(alertType, message));
    
    if (m_mainWindow) {
        m_mainWindow->statusBar()->showMessage(
            QString("⚠ Performance Alert: %1").arg(message), 5000);
    }
    
    qWarning() << "[AdvancedFeaturesIntegration] Resource alert:" << alertType << message;
}
