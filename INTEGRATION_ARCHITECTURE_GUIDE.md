# Architectural Integration Guide: Complete Systems

**Date**: December 8, 2025  
**Systems**: AgentHotPatcher, PlanOrchestrator, InterpretabilityPanel  
**Build Status**: ✅ Ready for Integration

---

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         MainWindow (Qt IDE)                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │           AI Agent Correction Pipeline                  │      │
│  ├──────────────────────────────────────────────────────────┤      │
│  │                                                          │      │
│  │  Model Output → AgentHotPatcher → Corrected Output      │      │
│  │                 ├─ Detect Hallucination                 │      │
│  │                 ├─ Validate Navigation                  │      │
│  │                 ├─ Apply Behavior Patches               │      │
│  │                 └─ Emit Signals                         │      │
│  │                                                          │      │
│  └──────────────────────────────────────────────────────────┘      │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │          Multi-File Orchestration Pipeline              │      │
│  ├──────────────────────────────────────────────────────────┤      │
│  │                                                          │      │
│  │  User Prompt → PlanOrchestrator → Multi-File Edits      │      │
│  │               ├─ Generate Plan (LSP+Inference)          │      │
│  │               ├─ Analyze Dependencies                   │      │
│  │               ├─ Execute Tasks                          │      │
│  │               └─ Rollback on Error                      │      │
│  │                                                          │      │
│  └──────────────────────────────────────────────────────────┘      │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │      Model Interpretability Visualization Pipeline      │      │
│  ├──────────────────────────────────────────────────────────┤      │
│  │                                                          │      │
│  │  Activation Data → InterpretabilityPanel → Visualized   │      │
│  │                  ├─ Attention Heads                      │      │
│  │                  ├─ Layer Activations                    │      │
│  │                  ├─ Embeddings Analysis                  │      │
│  │                  ├─ Feature Attribution                  │      │
│  │                  └─ Token Importance                     │      │
│  │                                                          │      │
│  └──────────────────────────────────────────────────────────┘      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow Diagram

### Flow 1: Inference + Correction

```
Inference Engine
     ↓
   Output JSON
     ↓
AgentHotPatcher
├─ Parse JSON
├─ Detect Issues
├─ Correct Output
├─ Emit Signals
     ↓
   Corrected JSON
     ↓
Display to User
```

### Flow 2: Planning + Execution

```
User Input Prompt
     ↓
PlanOrchestrator.planAndExecute()
├─ Generate Plan
│  ├─ Gather Context Files
│  ├─ Call Inference Engine
│  ├─ Decompose into Tasks
│  └─ Analyze Dependencies
├─ Get User Approval
├─ Execute Plan
│  ├─ Backup Files
│  ├─ Execute Tasks
│  ├─ Track Progress
│  └─ Commit/Rollback
     ↓
Execution Result
     ↓
Update Status Bar
```

### Flow 3: Visualization

```
Inference Output
(with activations)
     ↓
Extract Activation Data
     ↓
InterpretabilityPanel.updateVisualization()
├─ Format Data
├─ Render Visualization
├─ Update Statistics
     ↓
Display in Dock
     ↓
User Interaction
├─ Change Layer Range
├─ Select Heads
├─ Export Data
```

---

## Component Dependencies

```
MainWindow
├── AgentHotPatcher (independent)
│   ├── Knowledge Base
│   └── Pattern Database
│
├── PlanOrchestrator (depends on)
│   ├── LSPClient
│   ├── InferenceEngine
│   └── Filesystem
│
└── InterpretabilityPanel (independent)
    └── QTableWidget
        └── QJsonObject
```

---

## Integration Points in MainWindow

### 1. Constructor Integration

```cpp
MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    // ... existing initialization ...
    
    // Initialize Agent Hot Patcher
    m_patcher = new AgentHotPatcher(this);
    if (!m_patcher->initialize("./gguf_loader", 8080)) {
        qWarning() << "Failed to initialize patcher";
    }
    
    // Initialize Plan Orchestrator  
    m_orchestrator = new PlanOrchestrator(this);
    m_orchestrator->initialize();
    m_orchestrator->setLSPClient(m_lspClient);
    m_orchestrator->setInferenceEngine(m_inferenceEngine);
    m_orchestrator->setWorkspaceRoot(QDir::currentPath());
    
    // Initialize Interpretability Panel
    m_interpPanel = new InterpretabilityPanel(this);
    m_interpPanelDock = addDockWidget(Qt::RightDockWidgetArea, m_interpPanel);
    m_interpPanel->setVisible(false);  // Hidden by default
    
    // Setup signal connections
    setupIntegrationSignals();
}
```

### 2. Signal/Slot Connections

```cpp
void MainWindow::setupIntegrationSignals()
{
    // AgentHotPatcher signals
    connect(m_patcher, &AgentHotPatcher::hallucinationDetected,
            this, &MainWindow::onHallucinationDetected);
    connect(m_patcher, &AgentHotPatcher::hallucinationCorrected,
            this, &MainWindow::onHallucinationCorrected);
    connect(m_patcher, &AgentHotPatcher::navigationErrorFixed,
            this, &MainWindow::onNavigationErrorFixed);
    
    // PlanOrchestrator signals
    connect(m_orchestrator, &PlanOrchestrator::planningStarted,
            this, &MainWindow::onPlanningStarted);
    connect(m_orchestrator, &PlanOrchestrator::progressUpdated,
            this, &MainWindow::onPlanProgress);
    connect(m_orchestrator, &PlanOrchestrator::planningCompleted,
            this, &MainWindow::onPlanningCompleted);
    connect(m_orchestrator, &PlanOrchestrator::executionStarted,
            this, &MainWindow::onExecutionStarted);
    connect(m_orchestrator, &PlanOrchestrator::taskCompleted,
            this, &MainWindow::onTaskCompleted);
    connect(m_orchestrator, &PlanOrchestrator::executionCompleted,
            this, &MainWindow::onExecutionCompleted);
    connect(m_orchestrator, &PlanOrchestrator::executionRolledBack,
            this, &MainWindow::onExecutionRolledBack);
}
```

### 3. Inference Output Processing

```cpp
void MainWindow::onInferenceComplete(const QString& output)
{
    // Show progress indicator
    statusBar()->showMessage("Processing inference output...", 0);
    
    // [STEP 1] Intercept and correct via patcher
    QJsonObject result = m_patcher->interceptModelOutput(
        output,
        getCurrentContext()
    );
    
    bool wasModified = result["wasModified"].toBool();
    QString correctedOutput = result["modified"].toString();
    
    // [STEP 2] Display corrected output
    displayOutput(correctedOutput);
    
    // [STEP 3] Log if hallucinations were detected
    int hallucinationCount = result["hallucinationsDetected"].toInt();
    if (hallucinationCount > 0) {
        statusBar()->showMessage(
            QString("Corrected %1 hallucinations").arg(hallucinationCount),
            3000
        );
    }
    
    // [STEP 4] Update visualizations if in debug mode
    if (m_debugMode) {
        QJsonObject activations = m_inferenceEngine->getActivations();
        if (!activations.isEmpty()) {
            m_interpPanel->setVisible(true);
            m_interpPanel->updateVisualization(
                VisualizationType::LayerActivations,
                activations
            );
        }
    }
}
```

### 4. Plan Execution from Menu

```cpp
void MainWindow::onPlanRefactoringTriggered()
{
    // Get user input
    bool ok;
    QString prompt = QInputDialog::getText(
        this,
        "Code Refactoring",
        "What refactoring would you like to perform?",
        QLineEdit::Normal,
        "",
        &ok
    );
    
    if (!ok || prompt.isEmpty()) {
        return;
    }
    
    // Show preview dialog before executing
    QMessageBox::StandardButton btn = QMessageBox::question(
        this,
        "Plan Preview",
        QString("Plan to:\n%1\n\nContinue?").arg(prompt),
        QMessageBox::Yes | QMessageBox::No
    );
    
    if (btn != QMessageBox::Yes) {
        return;
    }
    
    // Execute plan (NOT dry-run)
    statusBar()->showMessage("Generating refactoring plan...", 0);
    
    ExecutionResult result = m_orchestrator->planAndExecute(
        prompt,
        m_workspaceRoot,
        false  // Not a dry-run, actually modify files
    );
    
    // Handle result
    if (result.success) {
        statusBar()->showMessage(
            QString("Refactored %1 files successfully")
                .arg(result.filesModified),
            5000
        );
        
        // Refresh file tree
        refreshProjectExplorer();
    } else {
        int response = QMessageBox::critical(
            this,
            "Refactoring Failed",
            QString("Error: %1\n\nRollback changes?")
                .arg(result.errorMessage),
            QMessageBox::Yes | QMessageBox::No
        );
        
        if (response == QMessageBox::Yes) {
            // Rollback is automatic, just update UI
            m_orchestrator->rollbackChanges(result.affectedFiles);
            statusBar()->showMessage("Changes rolled back", 3000);
            refreshProjectExplorer();
        }
    }
}
```

### 5. Debug View Integration

```cpp
void MainWindow::setupDebugMenu()
{
    QMenu* debugMenu = menuBar()->addMenu("&Debug");
    
    QAction* showInterpAction = debugMenu->addAction("Show Model Interpretability");
    connect(showInterpAction, &QAction::triggered, this, [this]() {
        m_interpPanel->setVisible(true);
        m_interpPanelDock->raise();
    });
    
    QAction* showActivationsAction = debugMenu->addAction("Show Layer Activations");
    connect(showActivationsAction, &QAction::triggered, this, [this]() {
        QJsonObject activations = m_inferenceEngine->getActivations();
        m_interpPanel->updateVisualization(
            VisualizationType::LayerActivations,
            activations
        );
        m_interpPanel->setVisible(true);
    });
    
    QAction* showAttentionAction = debugMenu->addAction("Show Attention Heads");
    connect(showAttentionAction, &QAction::triggered, this, [this]() {
        QJsonObject attention = m_inferenceEngine->getAttention();
        m_interpPanel->updateVisualization(
            VisualizationType::AttentionHeads,
            attention
        );
        m_interpPanel->setVisible(true);
    });
}
```

---

## Member Variables Required in MainWindow

```cpp
class MainWindow : public QMainWindow
{
    Q_OBJECT
    
private:
    // AI Systems
    AgentHotPatcher*        m_patcher = nullptr;
    PlanOrchestrator*       m_orchestrator = nullptr;
    InterpretabilityPanel*  m_interpPanel = nullptr;
    QDockWidget*            m_interpPanelDock = nullptr;
    
    // Supporting components
    InferenceEngine*        m_inferenceEngine = nullptr;
    LSPClient*              m_lspClient = nullptr;
    QString                 m_workspaceRoot;
    bool                    m_debugMode = false;
    
    // ... existing members ...
};
```

---

## Error Handling Strategy

```cpp
void MainWindow::handleIntegrationError(const QString& component, const QString& error)
{
    qWarning() << "[MainWindow]" << component << "error:" << error;
    
    // Log to status bar
    statusBar()->showMessage(
        QString("%1 error: %2").arg(component, error),
        5000
    );
    
    // Log to user-visible error log
    appendToErrorLog(QDateTime::currentDateTime(), component, error);
    
    // Optionally show detailed error dialog if critical
    if (error.contains("fatal") || error.contains("critical")) {
        QMessageBox::critical(
            this,
            QString("%1 Error").arg(component),
            error
        );
    }
}
```

---

## Configuration and Settings

```cpp
void MainWindow::loadIntegrationSettings()
{
    QSettings settings("RawrXD", "RawrXD-QtShell");
    
    // AgentHotPatcher settings
    double hallucinationThreshold = settings.value(
        "patcher/threshold", 0.65
    ).toDouble();
    m_patcher->setHallucinationThreshold(hallucinationThreshold);
    
    // PlanOrchestrator settings
    bool autoApprove = settings.value(
        "orchestrator/autoApprove", false
    ).toBool();
    m_orchestrator->setAutoApproveEnabled(autoApprove);
    
    // InterpretabilityPanel settings
    bool showByDefault = settings.value(
        "interpretability/showByDefault", false
    ).toBool();
    m_interpPanel->setVisible(showByDefault);
}

void MainWindow::saveIntegrationSettings()
{
    QSettings settings("RawrXD", "RawrXD-QtShell");
    
    // Save configuration
    settings.setValue("patcher/threshold", 0.65);
    settings.setValue("orchestrator/autoApprove", false);
    settings.setValue("interpretability/showByDefault", 
                      m_interpPanel->isVisible());
}
```

---

## Testing Checklist for Integration

### AgentHotPatcher Integration
- [ ] Constructor initializes successfully
- [ ] Signals connected and firing
- [ ] Intercepting inference output correctly
- [ ] Hallucinations detected and corrected
- [ ] No performance degradation (<50ms overhead)
- [ ] Handles concurrent operations safely

### PlanOrchestrator Integration
- [ ] Constructor initializes successfully
- [ ] LSP client and inference engine connected
- [ ] Plan generation from user prompt works
- [ ] Progress signals update UI
- [ ] File operations execute correctly
- [ ] Rollback restores original files
- [ ] Handles workspace without projects

### InterpretabilityPanel Integration
- [ ] Panel creates and displays in dock
- [ ] All 5 visualizations render
- [ ] Layer range filtering works
- [ ] Head selection works
- [ ] Data export functions
- [ ] No crashes with empty data
- [ ] Performance smooth with large datasets

---

## Performance Optimization Tips

1. **AgentHotPatcher**
   - Cache knowledge base on startup
   - Batch multiple outputs for processing
   - Disable behavior patching if not needed

2. **PlanOrchestrator**
   - Limit context files to 20-30 for faster planning
   - Use dry-run before large executions
   - Parallelize independent task execution

3. **InterpretabilityPanel**
   - Limit data table to 50-100 rows
   - Cache visualization renderings
   - Lazy-load data when panel becomes visible

---

## Deployment Checklist

- [ ] All three implementations copied to source tree
- [ ] CMakeLists.txt updated with new .cpp files
- [ ] No compilation errors or warnings
- [ ] All header files included in MainWindow
- [ ] Member variables declared
- [ ] Initialization code in constructor
- [ ] Signal connections established
- [ ] Menu items added
- [ ] Settings save/load implemented
- [ ] Error handling tested
- [ ] Integration tests pass
- [ ] Performance benchmarks meet targets
- [ ] Documentation updated
- [ ] Release build tested

---

## Next Steps

1. **Integration** (30 minutes)
   - Copy implementation files
   - Update CMakeLists.txt
   - Add member variables
   - Add initialization code

2. **Build & Test** (45 minutes)
   - Build Release configuration
   - Unit tests for each component
   - Integration testing
   - Performance validation

3. **Deployment** (15 minutes)
   - Generate final release build
   - Create changelog
   - Prepare release notes
   - Deploy to production

**Total Integration Time**: ~2 hours

---

**Status**: ✅ Ready for integration into MainWindow

