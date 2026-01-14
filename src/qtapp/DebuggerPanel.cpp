#include "DebuggerPanel.h"
#include "integration/ProdIntegration.h"
#include <QHeaderView>
#include <QTreeWidgetItem>

DebuggerPanel::DebuggerPanel(QWidget* parent) : QWidget(parent), m_isPaused(false) {
    RAWRXD_INIT_TIMED("DebuggerPanel");
    setupUI();
}

void DebuggerPanel::setupUI() {
    RAWRXD_TIMED_FUNC();
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // Toolbar
    m_toolBar = new QToolBar(this);
    m_continueAction = m_toolBar->addAction("▶ Continue");
    m_stepOverAction = m_toolBar->addAction("⟿ Step Over");
    m_stepIntoAction = m_toolBar->addAction("↓ Step Into");
    m_stepOutAction = m_toolBar->addAction("↑ Step Out");
    m_toolBar->addSeparator();
    m_stopAction = m_toolBar->addAction("⏹ Stop");

    connect(m_continueAction, &QAction::triggered, this, &DebuggerPanel::continueRequested);
    connect(m_stepOverAction, &QAction::triggered, this, &DebuggerPanel::stepOverRequested);
    connect(m_stepIntoAction, &QAction::triggered, this, &DebuggerPanel::stepIntoRequested);
    connect(m_stepOutAction, &QAction::triggered, this, &DebuggerPanel::stepOutRequested);
    connect(m_stopAction, &QAction::triggered, this, &DebuggerPanel::stopRequested);

    mainLayout->addWidget(m_toolBar);

    // Status bar
    m_statusLabel = new QLabel("Debugger: Ready", this);
    m_statusLabel->setStyleSheet("padding: 5px; background-color: #333; color: white;");
    mainLayout->addWidget(m_statusLabel);

    // Tab Widget for panels
    m_tabWidget = new QTabWidget(this);
    
    // Variables
    m_variablesTree = new QTreeWidget(this);
    m_variablesTree->setHeaderLabels({"Name", "Value", "Type"});
    m_variablesTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tabWidget->addTab(m_variablesTree, "Variables");

    // Watch
    m_watchList = new QTreeWidget(this);
    m_watchList->setHeaderLabels({"Expression", "Value", "Type"});
    m_tabWidget->addTab(m_watchList, "Watch");

    // Call Stack
    m_callStackList = new QListWidget(this);
    m_tabWidget->addTab(m_callStackList, "Call Stack");

    // Breakpoints
    m_breakpointsList = new QListWidget(this);
    m_tabWidget->addTab(m_breakpointsList, "Breakpoints");

    mainLayout->addWidget(m_tabWidget);

    setPaused(false);
}

void DebuggerPanel::updateVariables(const QVector<DebugVariable>& variables) {
    RAWRXD_TIMED_FUNC();
    m_variablesTree->clear();
    populateVariables(nullptr, variables);
}

void DebuggerPanel::populateVariables(QTreeWidgetItem* parent, const QVector<DebugVariable>& variables) {
    for (const auto& var : variables) {
        QTreeWidgetItem* item = new QTreeWidgetItem();
        item->setText(0, var.name);
        item->setText(1, var.value);
        item->setText(2, var.type);
        
        if (parent) {
            parent->addChild(item);
        } else {
            m_variablesTree->addTopLevelItem(item);
        }

        if (!var.children.isEmpty()) {
            populateVariables(item, var.children);
            if (var.expanded) {
                item->setExpanded(true);
            }
        }
    }
}

void DebuggerPanel::updateCallStack(const QVector<DebugStackFrame>& stack) {
    RAWRXD_TIMED_FUNC();
    m_callStackList->clear();
    for (const auto& frame : stack) {
        QString text = QString("%1 (%2:%3) @ 0x%4")
            .arg(frame.function)
            .arg(frame.file)
            .arg(frame.line)
            .arg(frame.address, 0, 16);
        m_callStackList->addItem(text);
    }
}

void DebuggerPanel::setStatus(const QString& status) {
    m_statusLabel->setText("Debugger: " + status);
}

void DebuggerPanel::setPaused(bool paused) {
    m_isPaused = paused;
    m_continueAction->setEnabled(paused);
    m_stepOverAction->setEnabled(paused);
    m_stepIntoAction->setEnabled(paused);
    m_stepOutAction->setEnabled(paused);
    
    if (paused) {
        setStatus("Paused");
    } else {
        setStatus("Running");
    }
}

void DebuggerPanel::onVariablesItemExpanded(QTreeWidgetItem* item) {
    // Optional: lazy load children
}
