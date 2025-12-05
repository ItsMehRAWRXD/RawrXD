#include "agentic_ide.h"
#include "agentic_engine.h"
#include "chat_interface.h"
#include "chat_workspace.h"
#include "multi_tab_editor.h"
#include "terminal_pool.h"
#include "file_browser.h"
#include "inference_engine.h"
#include "settings.h"
#include "telemetry.h"
#include "planning_agent.h"
#include "todo_manager.h"
#include "todo_dock.h"
#include <QApplication>
#include <QMainWindow>
#include <QTabWidget>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QFileSystemModel>
#include <QTreeView>
#include <QStatusBar>
#include <QMenuBar>
#include <QToolBar>
#include <QDockWidget>
#include <QMessageBox>
#include <QFileDialog>
#include <QInputDialog>
#include <QSettings>
#include <QDir>
#include <QProcess>
#include <QThread>
#include <QTimer>
#include <QDebug>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QSpinBox>
#include <QScrollBar>

AgenticIDE::AgenticIDE(QWidget *parent) 
    : QMainWindow(parent)
    , m_agenticEngine(new AgenticEngine(this))
    , m_inferenceEngine(new InferenceEngine(this))
    , m_planningAgent(new PlanningAgent(this))
    , m_todoManager(new TodoManager(this))
    , m_settings(new Settings())
    , m_telemetry(new Telemetry())
{
    setWindowTitle("RawrXD Agentic IDE");
    setMinimumSize(1200, 800);
    
    setupUI();
    setupConnections();
    loadSettings();
    
    // Initialize engines
    m_agenticEngine->initialize();
    m_planningAgent->initialize();
    
    // Create TODO dock
    m_todoDock = new TodoDock(m_todoManager, this);
    
    // Add TODO dock to the IDE
    m_todoDockWidget = new QDockWidget("TODO List", this);
    m_todoDockWidget->setWidget(m_todoDock);
    addDockWidget(Qt::RightDockWidgetArea, m_todoDockWidget);
    
    qDebug() << "Agentic IDE initialized successfully";
}

AgenticIDE::~AgenticIDE()
{
    saveSettings();
}

void AgenticIDE::setupUI()
{
    // Create central widget with splitter
    QSplitter *centralSplitter = new QSplitter(Qt::Horizontal, this);
    setCentralWidget(centralSplitter);
    
    // Left panel: File browser
    m_fileBrowser = new FileBrowser(this);
    m_fileDock = new QDockWidget("Files", this);
    m_fileDock->setWidget(m_fileBrowser);
    addDockWidget(Qt::LeftDockWidgetArea, m_fileDock);
    
    // Center: Multi-tab editor
    m_multiTabEditor = new MultiTabEditor(this);
    centralSplitter->addWidget(m_multiTabEditor);
    
    // Right panel: Chat interface
    m_chatInterface = new ChatInterface(this);
    m_chatDock = new QDockWidget("Agent Chat", this);
    m_chatDock->setWidget(m_chatInterface);
    addDockWidget(Qt::RightDockWidgetArea, m_chatDock);
    
    // Bottom: Terminal pool
    m_terminalPool = new TerminalPool(3, this);
    m_terminalDock = new QDockWidget("Terminals", this);
    m_terminalDock->setWidget(m_terminalPool);
    addDockWidget(Qt::BottomDockWidgetArea, m_terminalDock);
    
    // Create menus
    setupMenus();
    
    // Create toolbar
    setupToolbar();
    
    // Status bar
    statusBar()->showMessage("Ready");
}

void AgenticIDE::setupMenus()
{
    QMenuBar *menuBar = this->menuBar();
    
    // File menu
    QMenu *fileMenu = menuBar->addMenu("File");
    fileMenu->addAction("New File", this, &AgenticIDE::newFile);
    fileMenu->addAction("Open File", this, &AgenticIDE::openFile);
    fileMenu->addAction("Save", this, &AgenticIDE::saveFile);
    fileMenu->addSeparator();
    fileMenu->addAction("Exit", this, &AgenticIDE::close);
    
    // Edit menu
    QMenu *editMenu = menuBar->addMenu("Edit");
    editMenu->addAction("Undo", this, &AgenticIDE::undo);
    editMenu->addAction("Redo", this, &AgenticIDE::redo);
    editMenu->addSeparator();
    editMenu->addAction("Find", this, &AgenticIDE::find);
    editMenu->addAction("Replace", this, &AgenticIDE::replace);
    
    // View menu
    QMenu *viewMenu = menuBar->addMenu("View");
    viewMenu->addAction("Toggle File Browser", this, &AgenticIDE::toggleFileBrowser);
    viewMenu->addAction("Toggle Chat", this, &AgenticIDE::toggleChat);
    viewMenu->addAction("Toggle Terminals", this, &AgenticIDE::toggleTerminals);
    viewMenu->addAction("Toggle Todos", this, &AgenticIDE::toggleTodos);
    
    // Agent menu
    QMenu *agentMenu = menuBar->addMenu("Agent");
    agentMenu->addAction("Start Chat", this, &AgenticIDE::startChat);
    agentMenu->addAction("Analyze Code", this, &AgenticIDE::analyzeCode);
    agentMenu->addAction("Generate Code", this, &AgenticIDE::generateCode);
    agentMenu->addAction("Create Plan", this, &AgenticIDE::createPlan);
    agentMenu->addAction("Hot-Patch Model", this, &AgenticIDE::hotPatchModel);
    agentMenu->addSeparator();
    agentMenu->addAction("Settings", this, &AgenticIDE::showSettings);
}

void AgenticIDE::setupToolbar()
{
    QToolBar *toolbar = addToolBar("Main Toolbar");
    toolbar->addAction("New", this, &AgenticIDE::newFile);
    toolbar->addAction("Open", this, &AgenticIDE::openFile);
    toolbar->addAction("Save", this, &AgenticIDE::saveFile);
    toolbar->addSeparator();
    toolbar->addAction("Chat", this, &AgenticIDE::startChat);
    toolbar->addAction("Analyze", this, &AgenticIDE::analyzeCode);
}

void AgenticIDE::setupConnections()
{
    // Connect file browser to editor
    connect(m_fileBrowser, &FileBrowser::fileSelected, 
            m_multiTabEditor, &MultiTabEditor::openFile);
    
    // Connect chat interface to agentic engine
    connect(m_chatInterface, &ChatInterface::messageSent,
            m_agenticEngine, &AgenticEngine::processMessage);
    connect(m_agenticEngine, &AgenticEngine::responseReady,
            m_chatInterface, &ChatInterface::displayResponse);
    
    // Connect model selector to agentic engine
    connect(m_chatInterface, &ChatInterface::modelSelected,
            m_agenticEngine, &AgenticEngine::setModel);
    
    // Connect model loading finished to chat interface
    connect(m_agenticEngine, &AgenticEngine::modelLoadingFinished,
            m_chatInterface, [this](bool success, const QString& modelPath) {
                if (success) {
                    m_chatInterface->addMessage("System", "Model loaded: " + modelPath);
                } else {
                    m_chatInterface->addMessage("System", "Failed to load model: " + modelPath);
                }
            });
    
    // Connect terminal to inference engine
    connect(m_terminalPool, &TerminalPool::commandExecuted,
            m_inferenceEngine, &InferenceEngine::processCommand);
    
    // Connect planning agent signals
    connect(m_planningAgent, &PlanningAgent::planCreated,
            this, [this](const QString& plan) {
                m_chatInterface->addMessage("Planner", "Plan created: " + plan);
            });
    connect(m_planningAgent, &PlanningAgent::taskStatusChanged,
            this, [this](const QString& taskId, const QString& status) {
                m_chatInterface->addMessage("Planner", "Task " + taskId + " is now " + status);
            });
    connect(m_planningAgent, &PlanningAgent::planCompleted,
            this, [this]() {
                m_chatInterface->addMessage("Planner", "Plan completed successfully!");
            });
    connect(m_planningAgent, &PlanningAgent::planFailed,
            this, [this](const QString& error) {
                m_chatInterface->addMessage("Planner", "Plan failed: " + error);
            });
}

void AgenticIDE::loadSettings()
{
    QSettings settings("RawrXD", "AgenticIDE");
    
    // Load window geometry
    restoreGeometry(settings.value("geometry").toByteArray());
    restoreState(settings.value("windowState").toByteArray());
    
    // Load recent files
    m_recentFiles = settings.value("recentFiles").toStringList();
    
    qDebug() << "Settings loaded";
}

void AgenticIDE::saveSettings()
{
    QSettings settings("RawrXD", "AgenticIDE");
    
    // Save window geometry
    settings.setValue("geometry", saveGeometry());
    settings.setValue("windowState", saveState());
    
    // Save recent files
    settings.setValue("recentFiles", m_recentFiles);
    
    qDebug() << "Settings saved";
}

// File operations
void AgenticIDE::newFile()
{
    m_multiTabEditor->newFile();
    statusBar()->showMessage("New file created");
}

void AgenticIDE::openFile()
{
    QString filePath = QFileDialog::getOpenFileName(this, "Open File");
    if (!filePath.isEmpty()) {
        m_multiTabEditor->openFile(filePath);
        addToRecentFiles(filePath);
        statusBar()->showMessage("Opened: " + filePath);
    }
}

void AgenticIDE::saveFile()
{
    m_multiTabEditor->saveCurrentFile();
    statusBar()->showMessage("File saved");
}

// Agent operations
void AgenticIDE::startChat()
{
    m_chatInterface->setVisible(true);
    m_chatInterface->focusInput();
    statusBar()->showMessage("Chat started");
}

void AgenticIDE::analyzeCode()
{
    QString currentCode = m_multiTabEditor->getCurrentText();
    if (!currentCode.isEmpty()) {
        m_agenticEngine->analyzeCode(currentCode);
        statusBar()->showMessage("Code analysis started");
    }
}

void AgenticIDE::generateCode()
{
    QString prompt = QInputDialog::getText(this, "Generate Code", "Enter prompt:");
    if (!prompt.isEmpty()) {
        m_agenticEngine->generateCode(prompt);
        statusBar()->showMessage("Code generation started");
    }
}

void AgenticIDE::createPlan()
{
    QString goal = QInputDialog::getText(this, "Create Plan", "Enter goal:");
    if (!goal.isEmpty()) {
        m_planningAgent->createPlan(goal);
        statusBar()->showMessage("Plan creation started");
    }
}

void AgenticIDE::hotPatchModel()
{
    QString modelPath = QFileDialog::getOpenFileName(this, "Select Model File", "", "GGUF Files (*.gguf)");
    if (!modelPath.isEmpty()) {
        // Hot-patch the model
        if (m_inferenceEngine->HotPatchModel(modelPath.toStdString())) {
            m_chatInterface->addMessage("System", "Model hot-patched successfully: " + modelPath);
            statusBar()->showMessage("Model hot-patched successfully");
        } else {
            m_chatInterface->addMessage("System", "Failed to hot-patch model: " + modelPath);
            statusBar()->showMessage("Failed to hot-patch model");
        }
    }
}

// View operations
void AgenticIDE::toggleFileBrowser()
{
    if (m_fileDock) {
        m_fileDock->setVisible(!m_fileDock->isVisible());
        statusBar()->showMessage(m_fileDock->isVisible() ? "File Browser shown" : "File Browser hidden");
    }
}

void AgenticIDE::toggleChat()
{
    if (m_chatDock) {
        m_chatDock->setVisible(!m_chatDock->isVisible());
        statusBar()->showMessage(m_chatDock->isVisible() ? "Chat shown" : "Chat hidden");
    }
}

void AgenticIDE::toggleTerminals()
{
    if (m_terminalDock) {
        m_terminalDock->setVisible(!m_terminalDock->isVisible());
        statusBar()->showMessage(m_terminalDock->isVisible() ? "Terminals shown" : "Terminals hidden");
    }
}

void AgenticIDE::toggleTodos()
{
    if (m_todoDockWidget) {
        m_todoDockWidget->setVisible(!m_todoDockWidget->isVisible());
        statusBar()->showMessage(m_todoDockWidget->isVisible() ? "TODO List shown" : "TODO List hidden");
    }
}

void AgenticIDE::showSettings()
{
    QDialog settingsDialog(this);
    settingsDialog.setWindowTitle("RawrXD Agentic IDE - Settings");
    settingsDialog.setMinimumWidth(450);
    settingsDialog.setMinimumHeight(350);
    
    QVBoxLayout* mainLayout = new QVBoxLayout(&settingsDialog);
    
    // Model Settings Group
    QGroupBox* modelGroup = new QGroupBox("Model Settings", &settingsDialog);
    QVBoxLayout* modelLayout = new QVBoxLayout(modelGroup);
    
    QLabel* modelPathLabel = new QLabel("Default Model Path:", &settingsDialog);
    QLineEdit* modelPathEdit = new QLineEdit(&settingsDialog);
    modelPathEdit->setText(m_settings->getValue("defaultModelPath", "").toString());
    modelPathEdit->setPlaceholderText("Path to GGUF model file");
    modelLayout->addWidget(modelPathLabel);
    modelLayout->addWidget(modelPathEdit);
    
    QCheckBox* autoLoadModelCheck = new QCheckBox("Auto-load model on startup", &settingsDialog);
    autoLoadModelCheck->setChecked(m_settings->getValue("autoLoadModel", false).toBool());
    modelLayout->addWidget(autoLoadModelCheck);
    
    mainLayout->addWidget(modelGroup);
    
    // Terminal Settings Group
    QGroupBox* terminalGroup = new QGroupBox("Terminal Settings", &settingsDialog);
    QVBoxLayout* terminalLayout = new QVBoxLayout(terminalGroup);
    
    QLabel* shellLabel = new QLabel("Shell Command:", &settingsDialog);
    QLineEdit* shellEdit = new QLineEdit(&settingsDialog);
    shellEdit->setText(m_settings->getValue("shellCommand", "cmd.exe").toString());
    terminalLayout->addWidget(shellLabel);
    terminalLayout->addWidget(shellEdit);
    
    QLabel* poolSizeLabel = new QLabel("Terminal Pool Size:", &settingsDialog);
    QSpinBox* poolSizeSpinBox = new QSpinBox(&settingsDialog);
    poolSizeSpinBox->setMinimum(1);
    poolSizeSpinBox->setMaximum(10);
    poolSizeSpinBox->setValue(m_settings->getValue("terminalPoolSize", 3).toInt());
    terminalLayout->addWidget(poolSizeLabel);
    terminalLayout->addWidget(poolSizeSpinBox);
    
    mainLayout->addWidget(terminalGroup);
    
    // UI Settings Group
    QGroupBox* uiGroup = new QGroupBox("UI Settings", &settingsDialog);
    QVBoxLayout* uiLayout = new QVBoxLayout(uiGroup);
    
    QCheckBox* darkModeCheck = new QCheckBox("Dark Mode", &settingsDialog);
    darkModeCheck->setChecked(m_settings->getValue("darkMode", true).toBool());
    uiLayout->addWidget(darkModeCheck);
    
    QCheckBox* autoSaveCheck = new QCheckBox("Auto-save files", &settingsDialog);
    autoSaveCheck->setChecked(m_settings->getValue("autoSave", true).toBool());
    uiLayout->addWidget(autoSaveCheck);
    
    mainLayout->addWidget(uiGroup);
    
    mainLayout->addStretch();
    
    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    QPushButton* okBtn = new QPushButton("OK", &settingsDialog);
    QPushButton* cancelBtn = new QPushButton("Cancel", &settingsDialog);
    QPushButton* applyBtn = new QPushButton("Apply", &settingsDialog);
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(applyBtn);
    buttonLayout->addWidget(okBtn);
    buttonLayout->addWidget(cancelBtn);
    
    connect(okBtn, &QPushButton::clicked, [&]() {
        // Save settings
        m_settings->setValue("defaultModelPath", modelPathEdit->text());
        m_settings->setValue("autoLoadModel", autoLoadModelCheck->isChecked());
        m_settings->setValue("shellCommand", shellEdit->text());
        m_settings->setValue("terminalPoolSize", poolSizeSpinBox->value());
        m_settings->setValue("darkMode", darkModeCheck->isChecked());
        m_settings->setValue("autoSave", autoSaveCheck->isChecked());
        saveSettings();
        settingsDialog.accept();
    });
    
    connect(applyBtn, &QPushButton::clicked, [&]() {
        // Save settings without closing
        m_settings->setValue("defaultModelPath", modelPathEdit->text());
        m_settings->setValue("autoLoadModel", autoLoadModelCheck->isChecked());
        m_settings->setValue("shellCommand", shellEdit->text());
        m_settings->setValue("terminalPoolSize", poolSizeSpinBox->value());
        m_settings->setValue("darkMode", darkModeCheck->isChecked());
        m_settings->setValue("autoSave", autoSaveCheck->isChecked());
        saveSettings();
        statusBar()->showMessage("Settings applied");
    });
    
    connect(cancelBtn, &QPushButton::clicked, &settingsDialog, &QDialog::reject);
    
    mainLayout->addLayout(buttonLayout);
    
    settingsDialog.exec();
}

void AgenticIDE::addToRecentFiles(const QString &filePath)
{
    m_recentFiles.removeAll(filePath);
    m_recentFiles.prepend(filePath);
    
    // Keep only last 10 files
    while (m_recentFiles.size() > 10) {
        m_recentFiles.removeLast();
    }
}

// Edit operations
void AgenticIDE::undo() { m_multiTabEditor->undo(); }
void AgenticIDE::redo() { m_multiTabEditor->redo(); }
void AgenticIDE::find() { m_multiTabEditor->find(); }
void AgenticIDE::replace() { m_multiTabEditor->replace(); }