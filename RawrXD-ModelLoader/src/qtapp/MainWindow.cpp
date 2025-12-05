// RawrXD IDE MainWindow Implementation
// "One IDE to rule them all" - comprehensive development environment
#include "MainWindow.h"
#include "TerminalWidget.h"
#include "Subsystems.h"
#include "ActivityBar.h"
#include "widgets/masm_editor_widget.h"
#include "widgets/hotpatch_panel.h"
#include "inference_engine.hpp"
#include "gguf_server.hpp"
#include "streaming_inference.hpp"
#include "model_monitor.hpp"
#include "command_palette.hpp"
#include "ai_chat_panel.hpp"
#include "../agent/auto_bootstrap.hpp"
#include "../agent/hot_reload.hpp"
#include "../agent/self_test_gate.hpp"

// ----------------  brutal-gzip glue  ----------------
#include "deflate_brutal_qt.hpp"     // compress / decompress

#include <QApplication>
#include <QAction>
#include <QActionGroup>
#include <QFileSystemModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QShortcut>
#include <QSplitter>
#include <QStatusBar>
#include <QTabWidget>
#include <QTextEdit>
#include <QToolBar>
#include <QTreeView>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>
#include <QTextStream>
#include <QMimeData>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QCloseEvent>
#include <QJsonArray>
#include <QJsonDocument>
#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QComboBox>
#include <QDockWidget>
#include <QColor>
#include <QUrl>
#include <QStackedWidget>
#include <QFrame>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QPalette>
#include <QFont>
#include <QThread>
#include <QDateTime>
#include <QInputDialog>
#include <QMetaObject>
#include <QVariant>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("RawrXD IDE - Quantization Ready");
    resize(1600, 1000);

    // Create the complete VS Code-like layout
    createVSCodeLayout();
    
    setupMenuBar();
    setupToolBars();
    setupStatusBar();
    
    initSubsystems();
    
    // Initialize inference engine in worker thread
    m_engineThread = new QThread(this);
    m_inferenceEngine = new InferenceEngine();
    m_inferenceEngine->moveToThread(m_engineThread);
    
    // Connect signals
    connect(m_engineThread, &QThread::finished, m_inferenceEngine, &QObject::deleteLater);
    connect(m_inferenceEngine, &InferenceEngine::resultReady, this, &MainWindow::showInferenceResult);
    connect(m_inferenceEngine, &InferenceEngine::error, this, &MainWindow::showInferenceError);
    connect(m_inferenceEngine, &InferenceEngine::modelLoadedChanged, this, &MainWindow::onModelLoadedChanged);
    
    m_engineThread->start();
    
    // Initialize GGUF server (auto-starts if port 11434 is available)
    m_ggufServer = new GGUFServer(m_inferenceEngine, this);
    connect(m_ggufServer, &GGUFServer::serverStarted, this, [this](quint16 port) {
        statusBar()->showMessage(tr("GGUF Server running on port %1").arg(port), 5000);
        qDebug() << "GGUF Server started on port" << port;
    });
    connect(m_ggufServer, &GGUFServer::error, this, [](const QString& err) {
        qWarning() << "GGUF Server error:" << err;
    });
    
    // Start server after a short delay to ensure engine thread is fully initialized
    QTimer::singleShot(500, this, [this]() {
        m_ggufServer->start(11434);
    });
    
    // Initialize streaming inference
    m_streamer = new StreamingInference(m_hexMagConsole, this);
    m_streamingMode = false;
    m_currentStreamId = 0;
    
        // Connect streaming signals (adapt signature qint64,QString -> QString)
        connect(m_inferenceEngine, &InferenceEngine::streamToken,
            this, [this](qint64 /*reqId*/, const QString& token) { m_streamer->pushToken(token); });
        connect(m_inferenceEngine, &InferenceEngine::streamFinished,
            this, [this](qint64 /*reqId*/) { m_streamer->finishStream(); });
    
    // Set dark theme
    applyDarkTheme();
    
    // Setup AI/agent components
    setupAIBackendSwitcher();
    setupLayerQuantWidget();
    setupSwarmEditing();
    setupAgentSystem();
    setupCommandPalette();
    setupAIChatPanel();
    setupMASMEditor();
    
    // Setup Ctrl+Shift+P for command palette
    QShortcut* commandPaletteShortcut = new QShortcut(QKeySequence("Ctrl+Shift+P"), this);
    connect(commandPaletteShortcut, &QShortcut::activated, this, [this]() {
        if (m_commandPalette) m_commandPalette->show();
    });

    // Enable zero-touch triggers so the agent auto-starts without manual input
    // AutoBootstrap::installZeroTouch();

    // Optional: initialize per-layer quantization UI
    setupLayerQuantWidget();

    // Auto-load GGUF from env var if provided (e.g., RAWRXD_GGUF=D:\\OllamaModels\\BigDaddyG-Q2_K-ULTRA.gguf)
    QString ggufEnv = qEnvironmentVariable("RAWRXD_GGUF");
    if (!ggufEnv.isEmpty()) {
        statusBar()->showMessage(tr("Auto-loading GGUF: %1").arg(ggufEnv), 3000);
        QMetaObject::invokeMethod(m_inferenceEngine, "loadModel", Qt::QueuedConnection,
                                  Q_ARG(QString, ggufEnv));
    }
}

void MainWindow::createVSCodeLayout()
{
    /*
     * VS Code Layout Structure:
     * 
     * +--------+----------+---------------------+
     * | Activity  Primary    Central Editor       |
     * |   Bar      Sidebar      (Tabs)            |
     * | (50px)   (260px)                         |
     * +--------+----------+---------------------+
     * |                                          |
     * | Terminal/Output/Problems/Debug Console   |
     * | (Bottom Panel - Tabbed)                  |
     * +--------+----------+---------------------+
     * | Enhanced Status Bar                      |
     * +--------+----------+---------------------+
     */
    
    // Create main container widget
    QWidget* mainContainer = new QWidget(this);
    QHBoxLayout* mainLayout = new QHBoxLayout(mainContainer);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);
    
    // ============= LEFT: Activity Bar (50px) =============
    m_activityBar = new ActivityBar(mainContainer);
    mainLayout->addWidget(m_activityBar, 0);
    
    // ============= CENTER: Vertical Splitter (Sidebar + Editor) =============
    QSplitter* centerSplitter = new QSplitter(Qt::Horizontal, mainContainer);
    centerSplitter->setOpaqueResize(true);
    centerSplitter->setStyleSheet("QSplitter::handle { background-color: #2d2d2d; }");
    
    // --------- Primary Sidebar (260px) ---------
    m_primarySidebar = new QFrame(mainContainer);
    m_primarySidebar->setFixedWidth(260);
    m_primarySidebar->setStyleSheet("QFrame { background-color: #252526; border: none; }");
    
    QVBoxLayout* sidebarLayout = new QVBoxLayout(m_primarySidebar);
    sidebarLayout->setContentsMargins(0, 0, 0, 0);
    sidebarLayout->setSpacing(0);
    
    // Create sidebar header
    QLabel* sidebarHeader = new QLabel("Explorer", m_primarySidebar);
    sidebarHeader->setStyleSheet("QLabel { color: #e0e0e0; background-color: #2d2d30; padding: 8px; font-weight: bold; }");
    sidebarLayout->addWidget(sidebarHeader);
    
    // Create stacked widget for sidebar views
    m_sidebarStack = new QStackedWidget(m_primarySidebar);
    m_sidebarStack->setStyleSheet("QStackedWidget { background-color: #252526; }");
    
    // Create Explorer view (placeholder - tree widget)
    QTreeWidget* explorerView = new QTreeWidget(m_primarySidebar);
    explorerView->setStyleSheet("QTreeWidget { background-color: #252526; color: #e0e0e0; }");
    QTreeWidgetItem* rootItem = new QTreeWidgetItem();
    rootItem->setText(0, "Project Folder");
    explorerView->addTopLevelItem(rootItem);
    m_sidebarStack->addWidget(explorerView);
    
    // Create Search view (placeholder)
    QWidget* searchView = new QWidget(m_primarySidebar);
    QVBoxLayout* searchLayout = new QVBoxLayout(searchView);
    QLineEdit* searchInput = new QLineEdit(m_primarySidebar);
    searchInput->setPlaceholderText("Search files...");
    searchInput->setStyleSheet("QLineEdit { background-color: #3c3c3c; color: #e0e0e0; border: 1px solid #555; padding: 5px; }");
    searchLayout->addWidget(searchInput);
    m_sidebarStack->addWidget(searchView);
    
    // Create Source Control view (placeholder)
    QWidget* scmView = new QWidget(m_primarySidebar);
    QVBoxLayout* scmLayout = new QVBoxLayout(scmView);
    QLabel* scmLabel = new QLabel("Source Control\n\nNo folder open", m_primarySidebar);
    scmLabel->setStyleSheet("QLabel { color: #e0e0e0; }");
    scmLabel->setAlignment(Qt::AlignCenter);
    scmLayout->addWidget(scmLabel);
    m_sidebarStack->addWidget(scmView);
    
    // Create Debug view (placeholder)
    QWidget* debugView = new QWidget(m_primarySidebar);
    QVBoxLayout* debugLayout = new QVBoxLayout(debugView);
    QLabel* debugLabel = new QLabel("Run and Debug\n\nNo launch configuration", m_primarySidebar);
    debugLabel->setStyleSheet("QLabel { color: #e0e0e0; }");
    debugLabel->setAlignment(Qt::AlignCenter);
    debugLayout->addWidget(debugLabel);
    m_sidebarStack->addWidget(debugView);
    
    // Create Extensions view (placeholder)
    QWidget* extView = new QWidget(m_primarySidebar);
    QVBoxLayout* extLayout = new QVBoxLayout(extView);
    QLineEdit* extSearch = new QLineEdit(m_primarySidebar);
    extSearch->setPlaceholderText("Search extensions...");
    extSearch->setStyleSheet("QLineEdit { background-color: #3c3c3c; color: #e0e0e0; border: 1px solid #555; padding: 5px; }");
    extLayout->addWidget(extSearch);
    m_sidebarStack->addWidget(extView);
    
    sidebarLayout->addWidget(m_sidebarStack, 1);
    
    centerSplitter->addWidget(m_primarySidebar);
    
    // --------- Central Editor Area (Tabbed) ---------
    QFrame* editorFrame = new QFrame(mainContainer);
    editorFrame->setStyleSheet("QFrame { background-color: #1e1e1e; border: none; }");
    QVBoxLayout* editorLayout = new QVBoxLayout(editorFrame);
    editorLayout->setContentsMargins(0, 0, 0, 0);
    editorLayout->setSpacing(0);
    
    editorTabs_ = new QTabWidget(editorFrame);
    editorTabs_->setStyleSheet(
        "QTabBar { background-color: #252526; }"
        "QTabBar::tab { background-color: #1e1e1e; color: #e0e0e0; padding: 8px; margin: 0px; border: 1px solid #3e3e42; }"
        "QTabBar::tab:selected { background-color: #252526; border-bottom: 2px solid #007acc; }"
        "QTabWidget::pane { border: none; }"
    );
    
    codeView_ = new QTextEdit(editorFrame);
    codeView_->setStyleSheet("QTextEdit { background-color: #1e1e1e; color: #e0e0e0; font-family: 'Consolas', monospace; font-size: 11pt; }");
    codeView_->setLineWrapMode(QTextEdit::NoWrap);
    editorTabs_->addTab(codeView_, "Untitled");
    
    editorLayout->addWidget(editorTabs_, 1);
    
    centerSplitter->addWidget(editorFrame);
    centerSplitter->setStretchFactor(0, 0);  // Sidebar doesn't stretch
    centerSplitter->setStretchFactor(1, 1);  // Editor stretches
    
    mainLayout->addWidget(centerSplitter, 1);
    
    // ============= BOTTOM: Panel Dock (Terminal/Output/Problems/Debug) =============
    m_bottomPanel = new QFrame(mainContainer);
    m_bottomPanel->setFixedHeight(200);  // Initial height
    m_bottomPanel->setStyleSheet("QFrame { background-color: #252526; border-top: 1px solid #3e3e42; }");
    
    QVBoxLayout* panelLayout = new QVBoxLayout(m_bottomPanel);
    panelLayout->setContentsMargins(0, 0, 0, 0);
    panelLayout->setSpacing(0);
    
    // Panel tabs header
    QFrame* panelHeader = new QFrame(m_bottomPanel);
    panelHeader->setFixedHeight(35);
    panelHeader->setStyleSheet("QFrame { background-color: #2d2d30; border: none; }");
    QHBoxLayout* panelHeaderLayout = new QHBoxLayout(panelHeader);
    panelHeaderLayout->setContentsMargins(5, 0, 5, 0);
    
    // Panel tab buttons
    QPushButton* terminalTabBtn = new QPushButton("Terminal", panelHeader);
    QPushButton* outputTabBtn = new QPushButton("Output", panelHeader);
    QPushButton* problemsTabBtn = new QPushButton("Problems", panelHeader);
    QPushButton* debugTabBtn = new QPushButton("Debug Console", panelHeader);
    
    for (QPushButton* btn : {terminalTabBtn, outputTabBtn, problemsTabBtn, debugTabBtn}) {
        btn->setStyleSheet(
            "QPushButton { background-color: transparent; color: #e0e0e0; border: none; padding: 8px; }"
            "QPushButton:hover { background-color: #3e3e42; }"
            "QPushButton:pressed { border-bottom: 2px solid #007acc; }"
        );
        panelHeaderLayout->addWidget(btn);
    }
    
    panelHeaderLayout->addStretch();
    
    // Minimize/maximize buttons
    QPushButton* panelMinBtn = new QPushButton("−", panelHeader);
    panelMinBtn->setFixedSize(30, 30);
    panelMinBtn->setStyleSheet("QPushButton { background-color: transparent; color: #e0e0e0; }");
    panelHeaderLayout->addWidget(panelMinBtn);
    
    QPushButton* panelMaxBtn = new QPushButton("□", panelHeader);
    panelMaxBtn->setFixedSize(30, 30);
    panelMaxBtn->setStyleSheet("QPushButton { background-color: transparent; color: #e0e0e0; }");
    panelHeaderLayout->addWidget(panelMaxBtn);
    
    QPushButton* panelCloseBtn = new QPushButton("✕", panelHeader);
    panelCloseBtn->setFixedSize(30, 30);
    panelCloseBtn->setStyleSheet("QPushButton { background-color: transparent; color: #e0e0e0; }");
    panelHeaderLayout->addWidget(panelCloseBtn);
    
    panelLayout->addWidget(panelHeader);
    
    // Panel content (stacked widget for tabs)
    m_panelStack = new QStackedWidget(m_bottomPanel);
    m_panelStack->setStyleSheet("QStackedWidget { background-color: #1e1e1e; }");
    
    // Terminal tab
    QPlainTextEdit* terminalView = new QPlainTextEdit(m_bottomPanel);
    terminalView->setStyleSheet("QPlainTextEdit { background-color: #1e1e1e; color: #0dff00; font-family: 'Consolas', monospace; font-size: 10pt; }");
    terminalView->appendPlainText("PS E:\\> ");
    m_panelStack->addWidget(terminalView);
    
    // Output tab
    QPlainTextEdit* outputView = new QPlainTextEdit(m_bottomPanel);
    outputView->setStyleSheet("QPlainTextEdit { background-color: #1e1e1e; color: #e0e0e0; font-family: 'Consolas', monospace; font-size: 10pt; }");
    outputView->appendPlainText("[INFO] Ready to process...");
    m_panelStack->addWidget(outputView);
    
    // Problems tab
    QWidget* problemsView = new QWidget(m_bottomPanel);
    QVBoxLayout* problemsLayout = new QVBoxLayout(problemsView);
    problemsLayout->setContentsMargins(10, 10, 10, 10);
    QLabel* problemsLabel = new QLabel("No problems detected", problemsView);
    problemsLabel->setStyleSheet("QLabel { color: #e0e0e0; }");
    problemsLayout->addWidget(problemsLabel);
    problemsLayout->addStretch();
    m_panelStack->addWidget(problemsView);
    
    // Debug Console tab
    QPlainTextEdit* debugConsole = new QPlainTextEdit(m_bottomPanel);
    debugConsole->setStyleSheet("QPlainTextEdit { background-color: #1e1e1e; color: #e0e0e0; font-family: 'Consolas', monospace; font-size: 10pt; }");
    debugConsole->appendPlainText("Debug console ready");
    m_panelStack->addWidget(debugConsole);
    
    // ----------  HexMag inference console  ----------
    m_hexMagConsole = new QPlainTextEdit(m_bottomPanel);
    m_hexMagConsole->setStyleSheet(
        "QPlainTextEdit { background-color: #1e1e1e; color: #0dff00; "
        "font-family: 'Consolas', monospace; font-size: 10pt; }");
    m_hexMagConsole->appendPlainText("HexMag inference console ready...");
    m_panelStack->addWidget(m_hexMagConsole);        // index 4
    
    panelLayout->addWidget(m_panelStack, 1);
    
    // ============= Connect Activity Bar to Sidebar Views =============
    connect(m_activityBar, &ActivityBar::viewChanged, this, [this](ActivityBar::ViewType view) {
        m_sidebarStack->setCurrentIndex(static_cast<int>(view));
        // Update sidebar header label
        const char* titles[] = {"Explorer", "Search", "Source Control", "Run and Debug", "Extensions"};
        // Update the header label (would need to store it as member)
    });
    
    // ============= Create Vertical Splitter (Editor + Panel) =============
    QSplitter* verticalSplitter = new QSplitter(Qt::Vertical, mainContainer);
    verticalSplitter->setOpaqueResize(true);
    verticalSplitter->addWidget(mainLayout->takeAt(0)->widget());  // Adjust layout if needed
    
    // Better approach: Create a proper vertical splitter at the root
    QWidget* centerWidget = new QWidget(this);
    QVBoxLayout* centerLayout = new QVBoxLayout(centerWidget);
    centerLayout->setContentsMargins(0, 0, 0, 0);
    centerLayout->setSpacing(0);
    
    QSplitter* vertSplitter = new QSplitter(Qt::Vertical, centerWidget);
    vertSplitter->setOpaqueResize(true);
    vertSplitter->setStyleSheet("QSplitter::handle { background-color: #2d2d2d; height: 4px; }");
    
    // Create horizontal splitter for activity bar + sidebar + editor
    QWidget* topWidget = new QWidget(centerWidget);
    topWidget->setLayout(mainLayout);
    
    vertSplitter->addWidget(topWidget);
    vertSplitter->addWidget(m_bottomPanel);
    vertSplitter->setStretchFactor(0, 1);  // Top stretches
    vertSplitter->setStretchFactor(1, 0);  // Bottom doesn't stretch initially
    
    centerLayout->addWidget(vertSplitter);
    setCentralWidget(centerWidget);
    
    // Connect panel buttons
    connect(panelCloseBtn, &QPushButton::clicked, this, [this]() {
        m_bottomPanel->hide();
    });
    
    connect(panelMinBtn, &QPushButton::clicked, this, [this]() {
        m_bottomPanel->setFixedHeight(m_bottomPanel->height() > 50 ? 35 : 200);
    });
    
    // Connect terminal tab buttons
    connect(terminalTabBtn, &QPushButton::clicked, this, [this]() { m_panelStack->setCurrentIndex(0); });
    connect(outputTabBtn, &QPushButton::clicked, this, [this]() { m_panelStack->setCurrentIndex(1); });
    connect(problemsTabBtn, &QPushButton::clicked, this, [this]() { m_panelStack->setCurrentIndex(2); });
    connect(debugTabBtn, &QPushButton::clicked, this, [this]() { 
        if (m_hexMagConsole) m_panelStack->setCurrentWidget(m_hexMagConsole); 
        else m_panelStack->setCurrentIndex(3); 
    });
}

void MainWindow::applyDarkTheme()
{
    QPalette darkPalette;
    
    // Window colors
    darkPalette.setColor(QPalette::Window, QColor(0x1e, 0x1e, 0x1e));
    darkPalette.setColor(QPalette::WindowText, QColor(0xe0, 0xe0, 0xe0));
    
    // Button colors
    darkPalette.setColor(QPalette::Button, QColor(0x3c, 0x3c, 0x3c));
    darkPalette.setColor(QPalette::ButtonText, QColor(0xe0, 0xe0, 0xe0));
    
    // Base colors
    darkPalette.setColor(QPalette::Base, QColor(0x25, 0x25, 0x26));
    darkPalette.setColor(QPalette::AlternateBase, QColor(0x1e, 0x1e, 0x1e));
    
    // Highlight colors
    darkPalette.setColor(QPalette::Highlight, QColor(0x00, 0x7a, 0xcc));
    darkPalette.setColor(QPalette::HighlightedText, QColor(0xff, 0xff, 0xff));
    
    QApplication::setPalette(darkPalette);
}

MainWindow::~MainWindow()
{
    // Cleanup
}

void MainWindow::setAppState(std::shared_ptr<void> state)
{
    // Stub for state management
    (void)state;
}

void MainWindow::setupMenuBar()
{
    QMenu* fileMenu = menuBar()->addMenu(tr("&File"));
    fileMenu->addAction(tr("&New"), this, &MainWindow::handleNewEditor, QKeySequence::New);
    fileMenu->addAction(tr("&Open..."), this, &MainWindow::handleNewWindow, QKeySequence::Open);
    fileMenu->addAction(tr("&Save"), this, &MainWindow::handleSaveState, QKeySequence::Save);
    fileMenu->addSeparator();
    fileMenu->addAction(tr("E&xit"), qApp, &QApplication::quit, QKeySequence::Quit);

    QMenu* editMenu = menuBar()->addMenu(tr("&Edit"));
    editMenu->addAction(tr("Cu&t"), QKeySequence::Cut);
    editMenu->addAction(tr("&Copy"), QKeySequence::Copy);
    editMenu->addAction(tr("&Paste"), QKeySequence::Paste);

    QMenu* viewMenu = menuBar()->addMenu(tr("&View"));
    viewMenu->addAction(tr("Project Explorer"), this, &MainWindow::toggleProjectExplorer)->setCheckable(true);
    viewMenu->addAction(tr("Build System"), this, &MainWindow::toggleBuildSystem)->setCheckable(true);
    viewMenu->addAction(tr("Version Control"), this, &MainWindow::toggleVersionControl)->setCheckable(true);
    viewMenu->addAction(tr("Run & Debug"), this, &MainWindow::toggleRunDebug)->setCheckable(true);
    viewMenu->addAction(tr("AI Chat"), this, &MainWindow::toggleAIChat)->setCheckable(true);
    viewMenu->addAction(tr("Terminal Cluster"), this, &MainWindow::toggleTerminalCluster)->setCheckable(true);
    viewMenu->addSeparator();
    
    // Model Monitor
    QAction* monAct = viewMenu->addAction(tr("Model Monitor"));
    monAct->setCheckable(true);
    connect(monAct, &QAction::toggled, this, [this](bool on){
        if (on && !m_modelMonitorDock) {
            m_modelMonitorDock = new QDockWidget(tr("Model Monitor"), this);
            m_modelMonitorDock->setWidget(new ModelMonitor(m_inferenceEngine, m_modelMonitorDock));
            addDockWidget(Qt::RightDockWidgetArea, m_modelMonitorDock);
        } else if (m_modelMonitorDock) {
            m_modelMonitorDock->setVisible(on);
        }
    });

    // AI/GGUF menu with brutal_gzip integration
    QMenu* aiMenu = menuBar()->addMenu(tr("&AI"));
    aiMenu->addAction(tr("Load GGUF Model..."), this, &MainWindow::loadGGUFModel);
    aiMenu->addAction(tr("Run Inference..."), this, &MainWindow::runInference);
    aiMenu->addAction(tr("Unload Model"), this, &MainWindow::unloadGGUFModel);
    aiMenu->addSeparator();
    
    // Streaming mode toggle
    QAction* streamAct = aiMenu->addAction(tr("Streaming Mode"));
    streamAct->setCheckable(true);
    connect(streamAct, &QAction::toggled, this, [this](bool on){
        m_streamingMode = on;
        statusBar()->showMessage(on ? tr("Streaming inference ON")
                                    : tr("Streaming inference OFF"), 2000);
    });
    
    // Batch compress folder
    aiMenu->addSeparator();
    QAction* batchAct = aiMenu->addAction(tr("Batch Compress Folder..."));
    connect(batchAct, &QAction::triggered, this, &MainWindow::batchCompressFolder);
    setupQuantizationMenu(aiMenu);

    QMenu* agentMenu = menuBar()->addMenu(tr("&Agent"));
    QActionGroup* agentModeGroup = new QActionGroup(this);
    m_agentModeGroup = agentModeGroup;
    agentModeGroup->setExclusive(true);
    struct AgentMode { const char* label; const char* id; } agentModes[] = {
        {"Plan Mode", "Plan"},
        {"Agent Mode", "Agent"},
        {"Ask Mode", "Ask"},
    };
    for (const auto& mode : agentModes) {
        QAction* action = agentMenu->addAction(QString::fromUtf8(mode.label));
        action->setCheckable(true);
        action->setData(QString::fromUtf8(mode.id));
        agentModeGroup->addAction(action);
        if (QString::fromUtf8(mode.id) == m_agentMode) {
            action->setChecked(true);
        }
    }
    connect(agentModeGroup, &QActionGroup::triggered, this, [this](QAction* action) {
        changeAgentMode(action->data().toString());
    });

    QMenu* modelMenu = menuBar()->addMenu(tr("&Model"));
    modelMenu->addAction(tr("Load Local GGUF..."), this, &MainWindow::loadGGUFModel);
    modelMenu->addAction(tr("Unload Model"), this, &MainWindow::unloadGGUFModel);
    modelMenu->addSeparator();
    m_backendGroup = new QActionGroup(this);
    m_backendGroup->setExclusive(true);
    struct BackendOption { const char* id; const char* label; } backendOptions[] = {
        {"local", "Local GGUF"},
        {"ollama", "Remote Ollama"},
        {"custom", "Custom Backend"}
    };
    for (const auto& backend : backendOptions) {
        QString backendId = QString::fromUtf8(backend.id);
        QAction* backendAction = modelMenu->addAction(QString::fromUtf8(backend.label));
        backendAction->setCheckable(true);
        backendAction->setData(backendId);
        m_backendGroup->addAction(backendAction);
        if (backendId == m_currentBackend) {
            backendAction->setChecked(true);
        }
    }
    connect(m_backendGroup, &QActionGroup::triggered, this, &MainWindow::handleBackendSelection);

    modelMenu->addSeparator();
    modelMenu->addAction(tr("Manage Backends..."), this, &MainWindow::setupAIBackendSwitcher);

    QMenu* helpMenu = menuBar()->addMenu(tr("&Help"));
    helpMenu->addAction(tr("&About"), this, &MainWindow::onAbout);
}

void MainWindow::setupToolBars()
{
    QToolBar* toolbar = addToolBar(tr("Main"));
    toolbar->addAction(tr("New"));
    toolbar->addAction(tr("Open"));
    toolbar->addAction(tr("Save"));
    toolbar->addSeparator();
    toolbar->addAction(tr("Run"), this, &MainWindow::onRunScript);
    toolbar->addSeparator();
    
    // Model selector
    QLabel* modelLabel = new QLabel(tr("Model: "), toolbar);
    toolbar->addWidget(modelLabel);
    
    m_modelSelector = new QComboBox(toolbar);
    m_modelSelector->setToolTip(tr("Select GGUF model to load"));
    m_modelSelector->setMinimumWidth(300);
    m_modelSelector->addItem(tr("No model loaded"));
    // Add recent models (populated from settings/cache)
    m_modelSelector->addItem(tr("Load model from file..."));
    toolbar->addWidget(m_modelSelector);
    
    connect(m_modelSelector, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int idx) {
        if (idx <= 0) return;  // Skip "No model loaded" and separators
        QString modelPath = m_modelSelector->itemData(idx).toString();
        if (!modelPath.isEmpty() && modelPath != "LOAD") {
            // Direct model selection - would need to implement overload or set path first
            loadGGUFModel();
        } else if (modelPath == "LOAD") {
            loadGGUFModel();  // File dialog
        }
    });
    
    toolbar->addSeparator();
    
    // Agent mode switcher
    m_agentModeSwitcher = new QComboBox(toolbar);
    m_agentModeSwitcher->setToolTip(tr("Switch agentic mode"));
    m_agentModeSwitcher->addItem(tr("Plan Mode"), QStringLiteral("Plan"));
    m_agentModeSwitcher->addItem(tr("Agent Mode"), QStringLiteral("Agent"));
    m_agentModeSwitcher->addItem(tr("Ask Mode"), QStringLiteral("Ask"));
    toolbar->addWidget(m_agentModeSwitcher);
    connect(m_agentModeSwitcher, &QComboBox::currentTextChanged, this, [this](const QString&) {
        if (!m_agentModeSwitcher) return;
        QVariant data = m_agentModeSwitcher->currentData();
        if (data.isValid()) changeAgentMode(data.toString());
    });
    changeAgentMode(m_agentMode); // sync UI state
}

void MainWindow::changeAgentMode(const QString& mode)
{
    if (mode.isEmpty()) return;
    if (mode == m_agentMode) return;
    m_agentMode = mode;
    if (m_agentModeSwitcher) {
        int index = m_agentModeSwitcher->findData(mode);
        bool blocked = m_agentModeSwitcher->blockSignals(true);
        if (index >= 0) {
            m_agentModeSwitcher->setCurrentIndex(index);
        }
        m_agentModeSwitcher->blockSignals(blocked);
    }
    if (m_agentModeGroup) {
        for (QAction* action : m_agentModeGroup->actions()) {
            if (action->data().toString() == mode) {
                bool blocked = action->blockSignals(true);
                action->setChecked(true);
                action->blockSignals(blocked);
                break;
            }
        }
    }
    statusBar()->showMessage(tr("Agent mode set to %1").arg(mode), 2000);
}

void MainWindow::handleBackendSelection(QAction* action)
{
    if (!action) return;
    QString backendId = action->data().toString();
    if (backendId.isEmpty() || backendId == m_currentBackend) return;
    m_currentBackend = backendId;
    statusBar()->showMessage(tr("Backend switched to %1").arg(action->text()), 2000);
    onAIBackendChanged(backendId, {});
}

void MainWindow::createCentralEditor()
{
    QWidget* central = new QWidget(this);
    QVBoxLayout* layout = new QVBoxLayout(central);
    
    editorTabs_ = new QTabWidget(central);
    codeView_ = new QTextEdit();
    editorTabs_->addTab(codeView_, "Untitled");
    
    layout->addWidget(editorTabs_);
    setCentralWidget(central);
}

void MainWindow::setupStatusBar()
{
    statusBar()->showMessage(tr("Ready | ggml Q4_0/Q8_0 quantization available"));
}

void MainWindow::initSubsystems()
{
    // Initialize all subsystems - stubs for now
}

// Stub implementations for original slots
void MainWindow::handleGoalSubmit() {}
void MainWindow::handleAgentMockProgress() {}
void MainWindow::updateSuggestion(const QString& chunk) { (void)chunk; }
void MainWindow::appendModelChunk(const QString& chunk) { (void)chunk; }
void MainWindow::handleGenerationFinished() {}
void MainWindow::handleQShellReturn() {}
void MainWindow::handleArchitectChunk(const QString& chunk) { (void)chunk; }
void MainWindow::handleArchitectFinished() {}
void MainWindow::handleTaskStatusUpdate(const QString& taskId, const QString& status, const QString& agentType) { (void)taskId; (void)status; (void)agentType; }
void MainWindow::handleTaskCompleted(const QString& agentType, const QString& summary) { (void)agentType; (void)summary; }
void MainWindow::handleWorkflowFinished(bool success) { (void)success; }
void MainWindow::handleTaskStreaming(const QString& taskId, const QString& chunk, const QString& agentType) { (void)taskId; (void)chunk; (void)agentType; }
void MainWindow::handleSaveState() {}
void MainWindow::handleLoadState() {}
void MainWindow::handleNewChat() {}
void MainWindow::handleNewEditor() {}
void MainWindow::handleNewWindow() {}
void MainWindow::handleAddFile() {}
void MainWindow::handleAddFolder() {}
void MainWindow::handleAddSymbol() {}
void MainWindow::showContextMenu(const QPoint& pos) { (void)pos; }
void MainWindow::loadContextItemIntoEditor(QListWidgetItem* item) { (void)item; }
void MainWindow::handleTabClose(int index) { (void)index; }
void MainWindow::handlePwshCommand() { statusBar()->showMessage(tr("PowerShell executing...")); }
void MainWindow::handleCmdCommand() { statusBar()->showMessage(tr("CMD executing...")); }
void MainWindow::readPwshOutput() { qDebug() << "Reading PowerShell output"; }
void MainWindow::readCmdOutput() { qDebug() << "Reading CMD output"; }
void MainWindow::clearDebugLog() { if (m_hexMagConsole) m_hexMagConsole->clear(); statusBar()->showMessage(tr("Debug log cleared"), 2000); }
void MainWindow::saveDebugLog() { statusBar()->showMessage(tr("Saving debug log...")); }
void MainWindow::filterLogLevel(const QString& level) { statusBar()->showMessage(tr("Filtering by: %1").arg(level), 2000); }
void MainWindow::showEditorContextMenu(const QPoint& pos) { qDebug() << "Context menu at" << pos; }
void MainWindow::explainCode() 
{ 
    QString sel = codeView_->textCursor().selectedText(); 
    if (!sel.isEmpty() && m_aiChatPanel) statusBar()->showMessage(tr("AI explaining code...")); 
    else statusBar()->showMessage(tr("Select code first"), 2000);
}

void MainWindow::fixCode() 
{ 
    QString sel = codeView_->textCursor().selectedText(); 
    if (!sel.isEmpty() && m_aiChatPanel) statusBar()->showMessage(tr("AI fixing code...")); 
    else statusBar()->showMessage(tr("Select code first"), 2000);
}

void MainWindow::refactorCode() 
{ 
    QString sel = codeView_->textCursor().selectedText(); 
    if (!sel.isEmpty() && m_aiChatPanel) statusBar()->showMessage(tr("AI refactoring...")); 
    else statusBar()->showMessage(tr("Select code first"), 2000);
}

void MainWindow::generateTests() 
{ 
    QString sel = codeView_->textCursor().selectedText(); 
    if (!sel.isEmpty() && m_aiChatPanel) statusBar()->showMessage(tr("Generating tests...")); 
    else statusBar()->showMessage(tr("Select code first"), 2000);
}

void MainWindow::generateDocs() 
{ 
    if (documentation_) statusBar()->showMessage(tr("Generating docs...")); 
    else statusBar()->showMessage(tr("Generating docs..."));
}

// Stub implementations for new slots
void MainWindow::onProjectOpened(const QString& path) { statusBar()->showMessage(tr("Project: %1").arg(path), 5000); }
void MainWindow::onBuildStarted() { statusBar()->showMessage(tr("Build started...")); }
void MainWindow::onBuildFinished(bool success) { statusBar()->showMessage(success ? tr("Build OK") : tr("Build FAILED"), 3000); }
void MainWindow::onVcsStatusChanged() { statusBar()->showMessage(tr("VCS updated"), 2000); }
void MainWindow::onDebuggerStateChanged(bool running) { statusBar()->showMessage(running ? tr("Debugger ON") : tr("Debugger OFF"), 2000); }
void MainWindow::onTestRunStarted() { statusBar()->showMessage(tr("Running tests...")); }
void MainWindow::onTestRunFinished() { statusBar()->showMessage(tr("Tests done"), 3000); }
void MainWindow::onDatabaseConnected() { statusBar()->showMessage(tr("DB connected"), 2000); }
void MainWindow::onDockerContainerListed() { statusBar()->showMessage(tr("Docker ready"), 2000); }
void MainWindow::onCloudResourceListed() { statusBar()->showMessage(tr("Cloud resources loaded"), 2000); }
void MainWindow::onPackageInstalled(const QString& pkg) { statusBar()->showMessage(tr("Package: %1").arg(pkg), 2000); }
void MainWindow::onDocumentationQueried(const QString& keyword) { statusBar()->showMessage(tr("Searching: %1").arg(keyword), 2000); }
void MainWindow::onUMLGenerated(const QString& plantUml) { statusBar()->showMessage(tr("UML generated"), 2000); }
void MainWindow::onImageEdited(const QString& path) { statusBar()->showMessage(tr("Image: %1").arg(path), 2000); }
void MainWindow::onTranslationChanged(const QString& lang) { statusBar()->showMessage(tr("Language: %1").arg(lang), 2000); }
void MainWindow::onDesignImported(const QString& file) { statusBar()->showMessage(tr("Design from %1").arg(file), 2000); }
void MainWindow::onAIChatMessage(const QString& msg) { if (m_aiChatPanel) statusBar()->showMessage(tr("AI Chat ready"), 2000); }
void MainWindow::onNotebookExecuted() { statusBar()->showMessage(tr("Notebook executed"), 2000); }
void MainWindow::onMarkdownRendered() { statusBar()->showMessage(tr("Markdown rendered"), 2000); }
void MainWindow::onSheetCalculated() { statusBar()->showMessage(tr("Spreadsheet calculated"), 2000); }
void MainWindow::onTerminalCommand(const QString& cmd) { statusBar()->showMessage(tr("Terminal: %1").arg(cmd), 2000); }
void MainWindow::onSnippetInserted(const QString& id) { statusBar()->showMessage(tr("Snippet: %1").arg(id), 2000); }
void MainWindow::onRegexTested(const QString& pattern) { statusBar()->showMessage(tr("Regex: %1").arg(pattern), 2000); }
void MainWindow::onDiffMerged() { statusBar()->showMessage(tr("Diff merged"), 2000); }
void MainWindow::onColorPicked(const QColor& c) { statusBar()->showMessage(tr("Color: %1").arg(c.name()), 2000); }
void MainWindow::onIconSelected(const QString& name) { statusBar()->showMessage(tr("Icon: %1").arg(name), 2000); }
void MainWindow::onPluginLoaded(const QString& name) { statusBar()->showMessage(tr("Plugin loaded: %1").arg(name), 2000); }
void MainWindow::onSettingsSaved() { statusBar()->showMessage(tr("Settings saved"), 2000); }
void MainWindow::onNotificationClicked(const QString& id) { statusBar()->showMessage(tr("Notification: %1").arg(id), 2000); }
void MainWindow::onShortcutChanged(const QString& id, const QKeySequence& key) { statusBar()->showMessage(tr("Shortcut set: %1").arg(id), 2000); }
void MainWindow::onTelemetryReady() { qDebug() << "Telemetry system ready"; }
void MainWindow::onUpdateAvailable(const QString& version) { statusBar()->showMessage(tr("Update available: %1").arg(version), 5000); }
void MainWindow::onWelcomeProjectChosen(const QString& path) { onProjectOpened(path); }
void MainWindow::onCommandPaletteTriggered(const QString& cmd) { statusBar()->showMessage(tr("Command: %1").arg(cmd), 2000); }
void MainWindow::onProgressCancelled(const QString& taskId) { statusBar()->showMessage(tr("Cancelled: %1").arg(taskId), 2000); }
void MainWindow::onQuickFixApplied(const QString& fix) { statusBar()->showMessage(tr("Quick fix applied"), 2000); }
void MainWindow::onMinimapClicked(qreal ratio) { statusBar()->showMessage(tr("Minimap: %1%").arg(int(ratio*100)), 1000); }
void MainWindow::onBreadcrumbClicked(const QString& symbol) { statusBar()->showMessage(tr("Navigate: %1").arg(symbol), 2000); }
void MainWindow::onStatusFieldClicked(const QString& field) { statusBar()->showMessage(tr("Status: %1").arg(field), 2000); }
void MainWindow::onTerminalEmulatorCommand(const QString& cmd) { statusBar()->showMessage(tr("Emulator: %1").arg(cmd), 2000); }
void MainWindow::onSearchResultActivated(const QString& file, int line) { statusBar()->showMessage(tr("Goto %1:%2").arg(file).arg(line), 2000); }
void MainWindow::onBookmarkToggled(const QString& file, int line) { statusBar()->showMessage(tr("Bookmark: %1:%2").arg(file).arg(line), 2000); }
void MainWindow::onTodoClicked(const QString& file, int line) { statusBar()->showMessage(tr("TODO: %1:%2").arg(file).arg(line), 2000); }
void MainWindow::onMacroReplayed() { statusBar()->showMessage(tr("Macro executed"), 2000); }
void MainWindow::onCompletionCacheHit(const QString& key) { qDebug() << "Completion cache hit:" << key; }
void MainWindow::onLSPDiagnostic(const QString& file, const QJsonArray& diags) { statusBar()->showMessage(tr("Diagnostics: %1").arg(file), 2000); }
void MainWindow::onCodeLensClicked(const QString& command) { statusBar()->showMessage(tr("CodeLens: %1").arg(command), 2000); }
void MainWindow::onInlayHintShown(const QString& file) { qDebug() << "Inlay hints for:" << file; }
void MainWindow::onInlineChatRequested(const QString& text) { if (m_aiChatPanel) statusBar()->showMessage(tr("Inline chat active"), 2000); }
void MainWindow::onAIReviewComment(const QString& comment) { statusBar()->showMessage(tr("AI review"), 2000); }
void MainWindow::onCodeStreamEdit(const QString& patch) { statusBar()->showMessage(tr("CodeStream sync"), 2000); }
void MainWindow::onAudioCallStarted() { statusBar()->showMessage(tr("Audio call active"), 5000); }
void MainWindow::onScreenShareStarted() { statusBar()->showMessage(tr("Screen sharing"), 5000); }
void MainWindow::onWhiteboardDraw(const QByteArray& svg) { qDebug() << "Whiteboard drawing"; }
void MainWindow::onTimeEntryAdded(const QString& task) { statusBar()->showMessage(tr("Time logged: %1").arg(task), 2000); }
void MainWindow::onKanbanMoved(const QString& taskId) { statusBar()->showMessage(tr("Task: %1").arg(taskId), 2000); }
void MainWindow::onPomodoroTick(int remaining) { statusBar()->showMessage(tr("Pomodoro: %1s").arg(remaining), 1000); }
void MainWindow::onWallpaperChanged(const QString& path) { statusBar()->showMessage(tr("Theme updated"), 2000); }
void MainWindow::onAccessibilityToggled(bool on) { statusBar()->showMessage(on ? tr("Accessibility ON") : tr("Accessibility OFF"), 2000); }

// Toggle slots - generic implementation with macro
#define IMPLEMENT_TOGGLE(Func, Member, Type) \
void MainWindow::Func(bool visible) { \
    if (visible) { \
        if (!Member) { \
            Member = new Type(this); \
            QDockWidget* dock = new QDockWidget(tr(#Type), this); \
            dock->setWidget(Member); \
            addDockWidget(Qt::RightDockWidgetArea, dock); \
        } \
        Member->show(); \
    } else if (Member) { \
        Member->hide(); \
    } \
}

IMPLEMENT_TOGGLE(toggleProjectExplorer, projectExplorer_, ProjectExplorerWidget)
IMPLEMENT_TOGGLE(toggleBuildSystem, buildWidget_, BuildSystemWidget)
IMPLEMENT_TOGGLE(toggleVersionControl, vcsWidget_, VersionControlWidget)
IMPLEMENT_TOGGLE(toggleRunDebug, debugWidget_, RunDebugWidget)
IMPLEMENT_TOGGLE(toggleProfiler, profilerWidget_, ProfilerWidget)
IMPLEMENT_TOGGLE(toggleTestExplorer, testWidget_, TestExplorerWidget)
IMPLEMENT_TOGGLE(toggleDatabaseTool, database_, DatabaseToolWidget)
IMPLEMENT_TOGGLE(toggleDockerTool, docker_, DockerToolWidget)
IMPLEMENT_TOGGLE(toggleCloudExplorer, cloud_, CloudExplorerWidget)
IMPLEMENT_TOGGLE(togglePackageManager, pkgManager_, PackageManagerWidget)
IMPLEMENT_TOGGLE(toggleDocumentation, documentation_, DocumentationWidget)
IMPLEMENT_TOGGLE(toggleUMLView, umlView_, UMLLViewWidget)
IMPLEMENT_TOGGLE(toggleImageTool, imageTool_, ImageToolWidget)
IMPLEMENT_TOGGLE(toggleTranslation, translator_, TranslationWidget)
IMPLEMENT_TOGGLE(toggleDesignToCode, designImport_, DesignToCodeWidget)
IMPLEMENT_TOGGLE(toggleNotebook, notebook_, NotebookWidget)
IMPLEMENT_TOGGLE(toggleMarkdownViewer, markdownViewer_, MarkdownViewer)
IMPLEMENT_TOGGLE(toggleSpreadsheet, spreadsheet_, SpreadsheetWidget)
IMPLEMENT_TOGGLE(toggleTerminalCluster, terminalCluster_, TerminalClusterWidget)
IMPLEMENT_TOGGLE(toggleSnippetManager, snippetManager_, SnippetManagerWidget)
IMPLEMENT_TOGGLE(toggleRegexTester, regexTester_, RegexTesterWidget)
IMPLEMENT_TOGGLE(toggleDiffViewer, diffViewer_, DiffViewerWidget)
IMPLEMENT_TOGGLE(toggleColorPicker, colorPicker_, ColorPickerWidget)
IMPLEMENT_TOGGLE(toggleIconFont, iconFont_, IconFontWidget)
IMPLEMENT_TOGGLE(togglePluginManager, pluginManager_, PluginManagerWidget)
IMPLEMENT_TOGGLE(toggleSettings, settingsWidget_, SettingsWidget)
IMPLEMENT_TOGGLE(toggleNotificationCenter, notificationCenter_, NotificationCenter)
IMPLEMENT_TOGGLE(toggleShortcutsConfigurator, shortcutsConfig_, ShortcutsConfigurator)
IMPLEMENT_TOGGLE(toggleTelemetry, telemetry_, TelemetryWidget)
IMPLEMENT_TOGGLE(toggleUpdateChecker, updateChecker_, UpdateCheckerWidget)
IMPLEMENT_TOGGLE(toggleWelcomeScreen, welcomeScreen_, WelcomeScreenWidget)
IMPLEMENT_TOGGLE(toggleCommandPalette, commandPalette_, CommandPalette)
IMPLEMENT_TOGGLE(toggleProgressManager, progressManager_, ProgressManager)
IMPLEMENT_TOGGLE(toggleAIQuickFix, quickFix_, AIQuickFixWidget)
IMPLEMENT_TOGGLE(toggleCodeMinimap, minimap_, CodeMinimap)
IMPLEMENT_TOGGLE(toggleBreadcrumbBar, breadcrumb_, BreadcrumbBar)
IMPLEMENT_TOGGLE(toggleStatusBarManager, statusBarManager_, StatusBarManager)
IMPLEMENT_TOGGLE(toggleTerminalEmulator, terminalEmulator_, TerminalEmulator)
IMPLEMENT_TOGGLE(toggleSearchResult, searchResults_, SearchResultWidget)
IMPLEMENT_TOGGLE(toggleBookmark, bookmarks_, BookmarkWidget)
IMPLEMENT_TOGGLE(toggleTodo, todos_, TodoWidget)
IMPLEMENT_TOGGLE(toggleMacroRecorder, macroRecorder_, MacroRecorderWidget)
IMPLEMENT_TOGGLE(toggleAICompletionCache, completionCache_, AICompletionCache)
IMPLEMENT_TOGGLE(toggleLanguageClientHost, lspHost_, LanguageClientHost)

// Special handling for AI Chat (no dedicated pointer, but we can create dynamically)
void MainWindow::toggleAIChat(bool visible) { (void)visible; }

// Other required methods
bool MainWindow::eventFilter(QObject* watched, QEvent* event) 
{
    // Custom event filtering logic can be added here
    return QMainWindow::eventFilter(watched, event);
}

void MainWindow::closeEvent(QCloseEvent* event) 
{
    // Save session state before closing application
    handleSaveState();
    event->accept();
}

void MainWindow::dragEnterEvent(QDragEnterEvent* event) 
{
    // Accept drag events for file drops
    event->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent* event)
{
    const QMimeData* mime = event->mimeData();
    if (!mime->hasUrls()) return;

    for (const QUrl& u : mime->urls()) {
        QString path = u.toLocalFile();
        if (!path.endsWith(".gguf", Qt::CaseInsensitive)) {
            // Non-GGUF file - open in editor
            QFile file(path);
            if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QTextStream in(&file);
                codeView_->setText(in.readAll());
                file.close();
            }
            continue;
        }

        // GGUF file - compress with brutal_gzip
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) {
            QMessageBox::warning(this, tr("GGUF open"), tr("Cannot read %1").arg(path));
            continue;
        }
        QByteArray raw = f.readAll();          // whole file for demo
        f.close();
        
        QByteArray gz  = brutal::compress(raw);
        if (gz.isEmpty()) {
            QMessageBox::critical(this, tr("GGUF compress"), tr("Brutal deflate failed"));
            continue;
        }
        
        QString outName = path + ".gz";
        QFile og(outName);
        if (og.open(QIODevice::WriteOnly)) {
            og.write(gz);
            og.close();
            statusBar()->showMessage(
                tr("Compressed %1 → %2  (ratio %3%)")
                    .arg(QLocale().formattedDataSize(raw.size()))
                    .arg(QLocale().formattedDataSize(gz.size()))
                    .arg(QString::number(100.0 * gz.size() / raw.size(), 'f', 1)),
                5000);
        }
    }
    event->acceptProposedAction();
}

// UI Creators stubs
QWidget* MainWindow::createGoalBar() { 
    return new QWidget(this); 
}

QWidget* MainWindow::createAgentPanel() { 
    return new QWidget(this); 
}

QWidget* MainWindow::createProposalReview() { 
    return new QWidget(this); 
}

QWidget* MainWindow::createEditorArea() { 
    return new QWidget(this); 
}

QWidget* MainWindow::createQShellTab() { 
    return new QWidget(this); 
}

QJsonDocument MainWindow::getMockArchitectJson() const { 
    return QJsonDocument(); 
}

void MainWindow::populateFolderTree(QTreeWidgetItem* parent, const QString& path) { 
    // Populate folder tree with directory structure
    (void)parent;
    (void)path;
}

QWidget* MainWindow::createTerminalPanel() { 
    return new QWidget(this); 
}

QWidget* MainWindow::createDebugPanel() { 
    return new QWidget(this); 
}

void MainWindow::setupDockWidgets() {
    // Initialize dock widgets for various subsystems
}

void MainWindow::setupSystemTray() {
    // Setup system tray icon and menu
}

 

void MainWindow::restoreSession() {
    // Restore previous session state from persistent storage
}

void MainWindow::saveSession() {
    // Save current session state to persistent storage
}

void MainWindow::onRunScript() 
{
    statusBar()->showMessage(tr("Run script invoked"));
}

void MainWindow::onAbout() 
{
    QMessageBox::about(this, tr("About RawrXD IDE"),
        tr("<b>RawrXD IDE</b><br>"
           "Quantization-Ready AI Development Environment<br>"
           "Built with Qt 6.7.3 + MSVC 2022<br>"
           "Features brutal_gzip MASM/NEON compression"));
}

// ============================================================
// AI/GGUF/InferenceEngine Implementation
// ============================================================

void MainWindow::loadGGUFModel()
{
    QString filePath = QFileDialog::getOpenFileName(
        this,
        tr("Select GGUF Model"),
        QString(),
        tr("GGUF Files (*.gguf);;All Files (*.*)")
    );
    
    if (filePath.isEmpty()) {
        return;
    }
    
    statusBar()->showMessage(tr("Loading GGUF model..."));
    
    // Call loadModel in the worker thread
    QMetaObject::invokeMethod(m_inferenceEngine, "loadModel", Qt::QueuedConnection,
                              Q_ARG(QString, filePath));
}

 

void MainWindow::unloadGGUFModel()
{
    QMetaObject::invokeMethod(m_inferenceEngine, "unloadModel", Qt::QueuedConnection);
    statusBar()->showMessage(tr("Unloading model..."));
}

void MainWindow::showInferenceResult(qint64 reqId, const QString& result)
{
    // If streaming mode is active, skip full result (tokens already streamed)
    if (m_streamingMode && reqId == m_currentStreamId) {
        return;
    }
    
    if (m_hexMagConsole) {
        m_hexMagConsole->appendPlainText(QString("[%1] %2").arg(reqId).arg(result));
    }
    statusBar()->showMessage(tr("Inference complete"), 3000);
}

void MainWindow::showInferenceError(qint64 reqId, const QString& errorMsg)
{
    if (m_hexMagConsole) {
        m_hexMagConsole->appendPlainText(QString("[%1] ERROR: %2").arg(reqId).arg(errorMsg));
    }
    statusBar()->showMessage(tr("Inference failed"), 3000);
}

void MainWindow::onModelLoadedChanged(bool loaded, const QString& modelName)
{
    QString msg = loaded ? tr("GGUF loaded: %1").arg(modelName) : tr("GGUF unloaded");
    statusBar()->showMessage(msg, 3000);
    if (m_hexMagConsole) {
        m_hexMagConsole->appendPlainText(msg);
    }
    
    if (loaded) {
        // Log how many tensors we saw in the loader
        QStringList names = m_inferenceEngine ? m_inferenceEngine->tensorNames() : QStringList();
        qInfo() << "Model loaded with" << names.size() << "tensors";
        if (m_hexMagConsole) {
            m_hexMagConsole->appendPlainText(QString("Detected %1 tensors").arg(names.size()));
        }

        // If developer wants auto per-layer set, use environment variable RAWRXD_AUTO_SET_LAYER
        QString devCmd = qEnvironmentVariable("RAWRXD_AUTO_SET_LAYER");
        if (!devCmd.isEmpty() && !names.isEmpty()) {
            QString target = names.first();
            QString quant = devCmd.isEmpty() ? "Q6_K" : devCmd; // default to Q6_K
            qInfo() << "Auto-setting layer quant for" << target << "->" << quant;
            if (m_hexMagConsole) m_hexMagConsole->appendPlainText(QString("Auto-set %1 -> %2").arg(target, quant));
            QMetaObject::invokeMethod(m_inferenceEngine, "setLayerQuant", Qt::QueuedConnection,
                                      Q_ARG(QString, target), Q_ARG(QString, quant));
        }
    }
}

void MainWindow::batchCompressFolder()
{
    QString dir = QFileDialog::getExistingDirectory(
        this,
        tr("Select GGUF Folder"),
        QString(),
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks
    );
    
    if (dir.isEmpty()) {
        return;
    }
    
    QDirIterator it(dir, QStringList() << "*.gguf", QDir::Files, QDirIterator::Subdirectories);
    int total = 0, ok = 0;
    
    while (it.hasNext()) {
        QString inPath = it.next();
        QString outPath = inPath + ".gz";
        
        QFile inFile(inPath);
        if (!inFile.open(QIODevice::ReadOnly)) {
            ++total;
            continue;
        }
        
        QByteArray raw = inFile.readAll();
        inFile.close();
        
        QByteArray gz = brutal::compress(raw);
        if (gz.isEmpty()) {
            ++total;
            continue;
        }
        
        QFile outFile(outPath);
        if (outFile.open(QIODevice::WriteOnly)) {
            outFile.write(gz);
            outFile.close();
            ++ok;
        }
        
        ++total;
        statusBar()->showMessage(tr("Batch: %1/%2 compressed").arg(ok).arg(total), 500);
        QCoreApplication::processEvents();  // Keep UI responsive
    }
    
    QString finalMsg = tr("Batch compression complete: %1/%2 files").arg(ok).arg(total);
    statusBar()->showMessage(finalMsg, 5000);
    QMessageBox::information(this, tr("Batch Compress"), finalMsg);
}

// ---------- Ctrl+Shift+A inside the editor ----------
void MainWindow::onCtrlShiftA() {
    QString wish = codeView_->textCursor().selectedText().trimmed();
    if (wish.isEmpty()) return;
    AutoBootstrap::startWithWish(wish);
}

// ---------- self-test gate before every release ----------
bool MainWindow::canRelease() {
    return runSelfTestGate();
}

// ---------- hot-reload after agent edits ----------
void MainWindow::onHotReload() {
    if (m_hotReload) {
        m_hotReload->reloadQuant(m_currentQuantMode);
    }
    statusBar()->showMessage("Hot-reloaded", 2000);
}

// ============================================================
// Agent System Setup and Integration
// ============================================================

void MainWindow::setupAgentSystem() {
    // Initialize AutoBootstrap (autonomous agent orchestration) - uses singleton pattern
    m_agentBootstrap = AutoBootstrap::instance();
    
    // Initialize HotReload (quantization library hot-reload)
    m_hotReload = new HotReload(this);
    
    // Connect HotReload signals to status bar for feedback
    connect(m_hotReload, &HotReload::quantReloaded, this, [this](const QString& quantType) {
        statusBar()->showMessage(tr("✓ Quantization reloaded: %1").arg(quantType), 3000);
    });
    
    connect(m_hotReload, &HotReload::moduleReloaded, this, [this](const QString& moduleName) {
        statusBar()->showMessage(tr("✓ Module reloaded: %1").arg(moduleName), 3000);
    });
    
    connect(m_hotReload, &HotReload::reloadFailed, this, [this](const QString& error) {
        statusBar()->showMessage(tr("✗ Reload failed: %1").arg(error), 5000);
    });
    
    // Add Tools menu for agent/hotpatch operations
    QMenu* toolsMenu = menuBar()->findChild<QMenu*>("ToolsMenu");
    if (!toolsMenu) {
        toolsMenu = menuBar()->addMenu("Tools");
        toolsMenu->setObjectName("ToolsMenu");
    }
    
    // Add Hot Reload action with Ctrl+Shift+R shortcut
    QAction* hotReloadAction = toolsMenu->addAction("Hot Reload Quantization");
    hotReloadAction->setShortcut(QKeySequence("Ctrl+Shift+R"));
    connect(hotReloadAction, &QAction::triggered, this, &MainWindow::onHotReload);
    
    // Add separator
    toolsMenu->addSeparator();
    
    // Add Agent Mode actions
    QMenu* agentModeMenu = toolsMenu->addMenu("Agent Mode");
    
    m_agentModeGroup = new QActionGroup(this);
    
    QAction* planModeAction = agentModeMenu->addAction("Plan");
    planModeAction->setCheckable(true);
    planModeAction->setChecked(true);
    planModeAction->setData("Plan");
    m_agentModeGroup->addAction(planModeAction);
    
    QAction* agentModeAction = agentModeMenu->addAction("Agent");
    agentModeAction->setCheckable(true);
    agentModeAction->setData("Agent");
    m_agentModeGroup->addAction(agentModeAction);
    
    QAction* askModeAction = agentModeMenu->addAction("Ask");
    askModeAction->setCheckable(true);
    askModeAction->setData("Ask");
    m_agentModeGroup->addAction(askModeAction);
    
    // Connect mode selection to changeAgentMode
    connect(m_agentModeGroup, &QActionGroup::triggered, this, [this](QAction* action) {
        QString mode = action->data().toString();
        changeAgentMode(mode);
    });
    
    // Add separator
    toolsMenu->addSeparator();
    
    // Add Self-Test Gate action
    QAction* selfTestAction = toolsMenu->addAction("Run Self-Test Gate");
    selfTestAction->setShortcut(QKeySequence("Ctrl+Shift+T"));
    connect(selfTestAction, &QAction::triggered, this, [this]() {
        if (canRelease()) {
            statusBar()->showMessage("✓ Self-test gate passed - ready to release", 3000);
        } else {
            statusBar()->showMessage("✗ Self-test gate failed - fix issues before release", 5000);
        }
    });
    
    // Setup hotpatch panel for real-time event visualization
    setupHotpatchPanel();
}

// ============================================================
// Hotpatch Panel Setup and Integration
// ============================================================

void MainWindow::setupHotpatchPanel() {
    // Create Hotpatch Panel widget
    m_hotpatchPanel = new HotpatchPanel(this);
    
    // Create dock widget
    m_hotpatchPanelDock = new QDockWidget("Hotpatch Events", this);
    m_hotpatchPanelDock->setWidget(m_hotpatchPanel);
    m_hotpatchPanelDock->setObjectName("HotpatchPanelDock");
    m_hotpatchPanelDock->setAllowedAreas(Qt::AllDockWidgetAreas);
    m_hotpatchPanelDock->setFeatures(QDockWidget::DockWidgetMovable |
                                      QDockWidget::DockWidgetFloatable |
                                      QDockWidget::DockWidgetClosable);
    
    // Add to bottom dock area by default
    addDockWidget(Qt::BottomDockWidgetArea, m_hotpatchPanelDock);
    
    // Wire HotReload signals to hotpatch panel for event logging
    connect(m_hotReload, &HotReload::quantReloaded, this, [this](const QString& quantType) {
        m_hotpatchPanel->logEvent("Quantization Reloaded", quantType, true);
    });
    
    connect(m_hotReload, &HotReload::moduleReloaded, this, [this](const QString& moduleName) {
        m_hotpatchPanel->logEvent("Module Reloaded", moduleName, true);
    });
    
    connect(m_hotReload, &HotReload::reloadFailed, this, [this](const QString& error) {
        m_hotpatchPanel->logEvent("Reload Failed", error, false);
    });
    
    // Connect manual reload button in hotpatch panel to onHotReload
    connect(m_hotpatchPanel, &HotpatchPanel::manualReloadRequested, this, [this](const QString& quantType) {
        m_currentQuantMode = quantType;
        onHotReload();
    });
    
    // Add View menu toggle for Hotpatch Panel
    QMenu* viewMenu = menuBar()->findChild<QMenu*>();
    if (!viewMenu) {
        viewMenu = menuBar()->addMenu("View");
    }
    
    QAction* toggleHotpatchAction = viewMenu->addAction("Hotpatch Events");
    toggleHotpatchAction->setCheckable(true);
    toggleHotpatchAction->setChecked(true);
    connect(toggleHotpatchAction, &QAction::triggered, this, [this](bool visible) {
        toggleHotpatchPanel(visible);
    });
}

void MainWindow::toggleHotpatchPanel(bool visible) {
    if (m_hotpatchPanelDock) {
        if (visible) {
            m_hotpatchPanelDock->show();
        } else {
            m_hotpatchPanelDock->hide();
        }
    }
}

// ============================================================
// MASM Text Editor Setup and Integration
// ============================================================

void MainWindow::setupMASMEditor() {
    // Create MASM Editor widget
    m_masmEditor = new MASMEditorWidget(this);
    
    // Create dock widget
    m_masmEditorDock = new QDockWidget("MASM Assembly Editor", this);
    m_masmEditorDock->setWidget(m_masmEditor);
    m_masmEditorDock->setObjectName("MASMEditorDock");
    m_masmEditorDock->setAllowedAreas(Qt::AllDockWidgetAreas);
    m_masmEditorDock->setFeatures(QDockWidget::DockWidgetMovable |
                                   QDockWidget::DockWidgetFloatable |
                                   QDockWidget::DockWidgetClosable);
    
    // Add to right dock area by default
    addDockWidget(Qt::RightDockWidgetArea, m_masmEditorDock);
    
    // Connect editor signals to main window
    connect(m_masmEditor, &MASMEditorWidget::tabChanged, this, [this](int index) {
        statusBar()->showMessage(tr("Switched to: %1").arg(m_masmEditor->getTabName(index)), 2000);
    });
    
    connect(m_masmEditor, &MASMEditorWidget::contentModified, this, [this](int index) {
        QString modified = m_masmEditor->isModified(index) ? " *" : "";
        statusBar()->showMessage(tr("Modified: %1%2").arg(m_masmEditor->getTabName(index)).arg(modified), 1000);
    });
    
    connect(m_masmEditor, &MASMEditorWidget::cursorPositionChanged, this, [this](int line, int col) {
        statusBar()->showMessage(tr("Line %1, Column %2").arg(line).arg(col), 1000);
    });
    
    // Add View menu toggle for MASM Editor
    QMenu* viewMenu = menuBar()->findChild<QMenu*>();
    if (!viewMenu) {
        viewMenu = menuBar()->addMenu("View");
    }
    
    QAction* toggleMASMAction = viewMenu->addAction("MASM Assembly Editor");
    toggleMASMAction->setCheckable(true);
    toggleMASMAction->setChecked(true);
    connect(toggleMASMAction, &QAction::triggered, this, [this](bool visible) {
        toggleMASMEditor(visible);
    });
}

void MainWindow::toggleMASMEditor(bool visible) {
    if (m_masmEditorDock) {
        if (visible) {
            m_masmEditorDock->show();
        } else {
            m_masmEditorDock->hide();
        }
    }
}
