#pragma once
#include <QMainWindow>
#include <QSplitter>
#include <QTabWidget>
#include <QDockWidget>
#include <QToolBar>
#include <QStatusBar>
#include <QComboBox>
#include <QLabel>
#include <QProgressBar>
#include <QAction>

#include "Core/Bus.hpp"
#include "AI/CompletionEngine.hpp"
#include "AI/AdvancedCodingAgent.hpp"
#include "AI/MultiModalModelRouter.hpp"
#include "Debug/DAPClient.hpp"
#include "LSP/LSPClient.hpp"
#include "UI/Panels/EditorPanel.hpp"
#include "UI/Panels/ChatPanel.hpp"
#include "UI/Panels/DebugPanel.hpp"
#include "UI/Panels/TerminalPanel.hpp"
#include "UI/Panels/ProjectPanel.hpp"
#include "UI/Panels/StatusPanel.hpp"

namespace SoloIDE {

class SoloIDE : public QMainWindow {
    Q_OBJECT
public:
    explicit SoloIDE(QWidget* parent = nullptr);
    ~SoloIDE() override;

    void initializeSubsystems();
    void loadProject(const QString& path = QString());

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onEditorTextChanged();
    void onCompletionReady(const BusMessage& msg);
    void onAgentAction(const BusMessage& msg);
    void onDebugBreak(const BusMessage& msg);
    void onModelSelected(int index);
    void onInferencerToggled(bool active);
    void onChatSubmitted();

private:
    void setupUI();
    void setupMenus();
    void setupToolBar();
    void setupDocking();
    void wireBus();
    void loadSettings();

    // Central area
    QTabWidget* editorTabs;
    EditorPanel* activeEditor;

    // Docks
    QDockWidget* projectDock;
    QDockWidget* chatDock;
    QDockWidget* debugDock;
    QDockWidget* terminalDock;

    // Panels
    ProjectPanel* projectPanel;
    ChatPanel* chatPanel;
    DebugPanel* debugPanel;
    TerminalPanel* terminalPanel;
    StatusPanel* statusPanel;

    // AI Systems
    CompletionEngine* completionEngine;
    AdvancedCodingAgent* codingAgent;
    MultiModalModelRouter* modelRouter;

    // Debug / LSP
    DAPClient* dapClient;
    LSPClient* lspClient;

    // Toolbar controls
    QComboBox* modelSelector;
    QProgressBar* inferenceProgress;
    QLabel* statusLabel;
    QLabel* tpsLabel;
    QAction* inferencerAction;

    bool inferencerActive = true;
};

} // namespace SoloIDE
