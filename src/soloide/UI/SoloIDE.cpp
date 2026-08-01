#include "SoloIDE.hpp"
#include "Panels/EditorPanel.hpp"
#include "Panels/ChatPanel.hpp"
#include "Panels/DebugPanel.hpp"
#include "Panels/TerminalPanel.hpp"
#include "Panels/ProjectPanel.hpp"
#include "Panels/StatusPanel.hpp"

#include <QMenuBar>
#include <QFileDialog>
#include <QMessageBox>
#include <QCloseEvent>
#include <QSettings>
#include <QKeySequence>
#include <QVBoxLayout>
#include <QDebug>

namespace SoloIDE {

// ============================================================================
// Constructor / Destructor
// ============================================================================
SoloIDE::SoloIDE(QWidget* parent) : QMainWindow(parent) {
    setupUI();
    setupMenus();
    setupToolBar();
    setupDocking();
    wireBus();
    initializeSubsystems();
    loadSettings();
}

SoloIDE::~SoloIDE() {
    QSettings s("RawrXD", "SoloIDE");
    s.setValue("geometry", saveGeometry());
    s.setValue("windowState", saveState());
}

// ============================================================================
// UI Setup
// ============================================================================
void SoloIDE::setupUI() {
    setWindowTitle("RawrXD SoloIDE — Sovereign Agentic Environment");
    resize(1920, 1080);

    // Central editor tabs
    editorTabs = new QTabWidget(this);
    editorTabs->setTabsClosable(true);
    editorTabs->setMovable(true);
    editorTabs->setDocumentMode(true);
    setCentralWidget(editorTabs);

    // Create first editor
    activeEditor = new EditorPanel(this);
    editorTabs->addTab(activeEditor, "untitled");
    connect(activeEditor, &EditorPanel::textChanged, this, &SoloIDE::onEditorTextChanged);
    connect(activeEditor, &QPlainTextEdit::cursorPositionChanged, this, [this]() {
        BusMessage msg{Channel::CursorMoved, "Editor", "", QVariant(), 0};
        IntegrationBus::instance()->publish(msg);
    });

    // Status bar
    statusLabel = new QLabel("Ready | Sovereign Mode");
    tpsLabel = new QLabel("TPS: --");
    inferenceProgress = new QProgressBar();
    inferenceProgress->setMaximumWidth(200);
    inferenceProgress->setRange(0, 100);
    inferenceProgress->setVisible(false);

    statusBar()->addWidget(statusLabel, 1);
    statusBar()->addWidget(tpsLabel);
    statusBar()->addWidget(inferenceProgress);
}

// ============================================================================
// Menus
// ============================================================================
void SoloIDE::setupMenus() {
    // File
    auto* fileMenu = menuBar()->addMenu("&File");
    fileMenu->addAction("&New", this, [this]() {
        auto* ed = new EditorPanel(this);
        editorTabs->addTab(ed, "untitled");
        editorTabs->setCurrentWidget(ed);
        activeEditor = ed;
        connect(ed, &EditorPanel::textChanged, this, &SoloIDE::onEditorTextChanged);
    }, QKeySequence::New);
    fileMenu->addAction("&Open...", this, [this]() { loadProject(); }, QKeySequence::Open);
    fileMenu->addAction("&Save", this, [this]() {
        if (activeEditor) {
            // In production: write to currentFile
        }
    }, QKeySequence::Save);
    fileMenu->addSeparator();
    fileMenu->addAction("E&xit", this, &QWidget::close, QKeySequence::Quit);

    // Edit
    auto* editMenu = menuBar()->addMenu("&Edit");
    editMenu->addAction("&Accept Ghost Text", this, [this]() {
        if (activeEditor) activeEditor->acceptGhostText();
    }, QKeySequence("Tab"));
    editMenu->addAction("&Reject Ghost Text", this, [this]() {
        if (activeEditor) activeEditor->rejectGhostText();
    }, QKeySequence("Esc"));

    // AI
    auto* aiMenu = menuBar()->addMenu("&AI");
    aiMenu->addAction("Toggle &Inferencer", this, [this]() {
        inferencerActive = !inferencerActive;
        inferencerAction->setChecked(inferencerActive);
        statusLabel->setText(inferencerActive ? "AI: Active" : "AI: Paused");
    });
    aiMenu->addAction("&Explain Selection", this, [this]() {
        if (!activeEditor) return;
        QString code = activeEditor->selectedText();
        if (code.isEmpty()) return;
        BusMessage msg{Channel::AgentAction, "UI", "Agent",
            QVariantMap{{"action","explain"},{"code",code}}, 0};
        IntegrationBus::instance()->publish(msg);
    });
    aiMenu->addAction("&Generate Tests", this, [this]() {
        if (!activeEditor) return;
        QString code = activeEditor->selectedText();
        if (code.isEmpty()) return;
        BusMessage msg{Channel::AgentAction, "UI", "Agent",
            QVariantMap{{"action","generate_tests"},{"code",code}}, 0};
        IntegrationBus::instance()->publish(msg);
    });
    aiMenu->addAction("&Optimize", this, [this]() {
        if (!activeEditor) return;
        QString code = activeEditor->selectedText();
        if (code.isEmpty()) return;
        BusMessage msg{Channel::AgentAction, "UI", "Agent",
            QVariantMap{{"action","optimize"},{"code",code}}, 0};
        IntegrationBus::instance()->publish(msg);
    });

    // Debug
    auto* debugMenu = menuBar()->addMenu("&Debug");
    debugMenu->addAction("Start &Debugging", this, [this]() {
        if (activeEditor && dapClient) {
            dapClient->startDebugging(activeEditor->currentFile());
        }
    }, QKeySequence("F5"));
    debugMenu->addAction("Toggle &Breakpoint", this, [this]() {
        if (activeEditor && dapClient) {
            int line = activeEditor->currentLine();
            dapClient->toggleBreakpoint(activeEditor->currentFile(), line);
        }
    }, QKeySequence("F9"));
    debugMenu->addAction("Step &Over", this, [this]() {
        if (dapClient) dapClient->stepOver();
    }, QKeySequence("F10"));
    debugMenu->addAction("Step &Into", this, [this]() {
        if (dapClient) dapClient->stepInto();
    }, QKeySequence("F11"));

    // View
    auto* viewMenu = menuBar()->addMenu("&View");
    viewMenu->addAction(projectDock->toggleViewAction());
    viewMenu->addAction(chatDock->toggleViewAction());
    viewMenu->addAction(debugDock->toggleViewAction());
    viewMenu->addAction(terminalDock->toggleViewAction());
}

// ============================================================================
// Toolbar
// ============================================================================
void SoloIDE::setupToolBar() {
    auto* tb = addToolBar("Main");
    tb->setMovable(false);

    modelSelector = new QComboBox(this);
    modelSelector->setMinimumWidth(250);
    modelSelector->setToolTip("Active Inference Model");
    tb->addWidget(new QLabel(" Model: "));
    tb->addWidget(modelSelector);

    inferencerAction = tb->addAction("Inferencer");
    inferencerAction->setCheckable(true);
    inferencerAction->setChecked(true);
    connect(inferencerAction, &QAction::toggled, this, &SoloIDE::onInferencerToggled);

    tb->addSeparator();
    tb->addAction("Chat", this, [this]() { chatDock->raise(); });
    tb->addAction("Debug", this, [this]() { debugDock->raise(); });
}

// ============================================================================
// Docking
// ============================================================================
void SoloIDE::setupDocking() {
    setCorner(Qt::TopLeftCorner, Qt::LeftDockWidgetArea);
    setCorner(Qt::BottomLeftCorner, Qt::LeftDockWidgetArea);
    setCorner(Qt::TopRightCorner, Qt::RightDockWidgetArea);
    setCorner(Qt::BottomRightCorner, Qt::RightDockWidgetArea);

    // Project Explorer (left)
    projectPanel = new ProjectPanel(this);
    projectDock = new QDockWidget("Project", this);
    projectDock->setWidget(projectPanel);
    projectDock->setMinimumWidth(200);
    addDockWidget(Qt::LeftDockWidgetArea, projectDock);

    // Chat (right)
    chatPanel = new ChatPanel(this);
    chatDock = new QDockWidget("Agent Chat", this);
    chatDock->setWidget(chatPanel);
    chatDock->setMinimumWidth(300);
    addDockWidget(Qt::RightDockWidgetArea, chatDock);
    connect(chatPanel, &ChatPanel::messageSubmitted, this, &SoloIDE::onChatSubmitted);

    // Debug (bottom)
    debugPanel = new DebugPanel(this);
    debugDock = new QDockWidget("Debug", this);
    debugDock->setWidget(debugPanel);
    addDockWidget(Qt::BottomDockWidgetArea, debugDock);

    // Terminal (bottom, tabbed with debug)
    terminalPanel = new TerminalPanel(this);
    terminalDock = new QDockWidget("Terminal", this);
    terminalDock->setWidget(terminalPanel);
    addDockWidget(Qt::BottomDockWidgetArea, terminalDock);
    tabifyDockWidget(debugDock, terminalDock);

    // Default visibility
    chatDock->raise();
}

// ============================================================================
// Integration Bus Wiring
// ============================================================================
void SoloIDE::wireBus() {
    auto* bus = IntegrationBus::instance();

    // Editor -> CompletionEngine
    bus->subscribe(Channel::EditorTextChanged, [this](const BusMessage&) {
        if (!inferencerActive || !activeEditor) return;
        QString text = activeEditor->toPlainText();
        QPoint pos = activeEditor->cursorPosition();
        completionEngine->requestCompletion(text, pos);
    });

    // CompletionEngine -> Editor (ghost text)
    bus->subscribe(Channel::CompletionReady, this, &SoloIDE::onCompletionReady);

    // Agent -> Chat panel
    bus->subscribe(Channel::ChatMessage, [this](const BusMessage& msg) {
        auto map = msg.payload.toMap();
        chatPanel->appendMessage(map["role"].toString(), map["content"].toString());
    });

    // Agent actions
    bus->subscribe(Channel::AgentAction, this, &SoloIDE::onAgentAction);

    // Debug
    bus->subscribe(Channel::DebugBreak, this, &SoloIDE::onDebugBreak);

    // Model loading
    bus->subscribe(Channel::ModelLoadComplete, [this](const BusMessage& msg) {
        statusLabel->setText("Model: " + msg.payload.toString());
        inferenceProgress->setVisible(false);
    });

    // GPU inference metrics
    bus->subscribe(Channel::GPUInferenceStart, [this](const BusMessage&) {
        inferenceProgress->setVisible(true);
        inferenceProgress->setRange(0, 0); // indeterminate
        statusLabel->setText("Processing...");
    });

    bus->subscribe(Channel::GPUInferenceDone, [this](const BusMessage& msg) {
        inferenceProgress->setVisible(false);
        auto map = msg.payload.toMap();
        double tps = map["tps"].toDouble();
        tpsLabel->setText(QString("TPS: %1").arg(tps, 0, 'f', 1));
        statusLabel->setText("Ready");
    });
}

// ============================================================================
// Subsystem Initialization
// ============================================================================
void SoloIDE::initializeSubsystems() {
    // AI Systems
    modelRouter = new MultiModalModelRouter(this);
    completionEngine = new CompletionEngine(modelRouter, this);
    codingAgent = new AdvancedCodingAgent(modelRouter, this);

    // Populate model selector from router
    for (const auto& model : modelRouter->availableModels()) {
        modelSelector->addItem(model.name, model.identifier);
    }
    connect(modelSelector, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SoloIDE::onModelSelected);

    // Debug / LSP
    dapClient = new DAPClient(this);
    lspClient = new LSPClient(this);

    // Start with default model
    if (modelSelector->count() > 0) {
        modelRouter->loadModel(modelSelector->currentData().toString());
    }
}

// ============================================================================
// Slots
// ============================================================================
void SoloIDE::onEditorTextChanged() {
    if (!inferencerActive) return;
    QString text = activeEditor->toPlainText();
    BusMessage msg{Channel::EditorTextChanged, "Editor", "", QVariant(text), 0};
    IntegrationBus::instance()->publish(msg);
}

void SoloIDE::onCompletionReady(const BusMessage& msg) {
    if (!activeEditor) return;
    QString completion = msg.payload.toString();
    activeEditor->showGhostText(completion);
}

void SoloIDE::onAgentAction(const BusMessage& msg) {
    auto map = msg.payload.toMap();
    QString action = map["action"].toString();
    QString code = map["code"].toString();

    if (action == "explain") {
        codingAgent->explain(code);
    } else if (action == "generate_tests") {
        codingAgent->generateTests(code);
    } else if (action == "optimize") {
        codingAgent->optimize(code);
    }
}

void SoloIDE::onDebugBreak(const BusMessage& msg) {
    auto map = msg.payload.toMap();
    QString file = map["file"].toString();
    int line = map["line"].toInt();
    if (activeEditor) {
        activeEditor->highlightLine(line);
    }
    debugPanel->showStackTrace(map["stack"].toStringList());
}

void SoloIDE::onModelSelected(int index) {
    QString modelId = modelSelector->itemData(index).toString();
    inferenceProgress->setVisible(true);
    BusMessage msg{Channel::ModelLoadRequest, "UI", "Router", QVariant(modelId), 0};
    IntegrationBus::instance()->publish(msg);
    modelRouter->loadModel(modelId);
}

void SoloIDE::onInferencerToggled(bool active) {
    inferencerActive = active;
    statusLabel->setText(active ? "AI: Active" : "AI: Paused");
}

void SoloIDE::onChatSubmitted() {
    QString text = chatPanel->takeInputText();
    if (text.isEmpty()) return;

    chatPanel->appendUserMessage(text);

    BusMessage msg{Channel::ChatMessage, "UI", "Agent",
        QVariantMap{{"role","user"},{"content",text}}, 0};
    IntegrationBus::instance()->publish(msg);

    codingAgent->chat(text);
}

// ============================================================================
// Project Loading
// ============================================================================
void SoloIDE::loadProject(const QString& path) {
    QString dir = path.isEmpty()
        ? QFileDialog::getExistingDirectory(this, "Open Project", "D:\\rawrxd\\")
        : path;
    if (dir.isEmpty()) return;

    projectPanel->setRootPath(dir);
    lspClient->initialize(dir);
    setWindowTitle("RawrXD SoloIDE — " + dir);
}

// ============================================================================
// Settings
// ============================================================================
void SoloIDE::loadSettings() {
    QSettings s("RawrXD", "SoloIDE");
    restoreGeometry(s.value("geometry").toByteArray());
    restoreState(s.value("windowState").toByteArray());
    QString lastProject = s.value("lastProject").toString();
    if (!lastProject.isEmpty()) {
        projectPanel->setRootPath(lastProject);
    }
}

void SoloIDE::closeEvent(QCloseEvent* event) {
    QSettings s("RawrXD", "SoloIDE");
    s.setValue("geometry", saveGeometry());
    s.setValue("windowState", saveState());
    event->accept();
}

} // namespace SoloIDE
