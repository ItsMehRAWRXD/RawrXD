#pragma once
#include <windows.h>
#include <string>
#include <memory>
#include <functional>
#include "ide_orchestrator.h"
#include "monaco_integration.h"
#include "utils/Expected.h"

namespace RawrXD {

class GUIMain {
public:
    GUIMain();
    ~GUIMain();

    RawrXD::Expected<void, std::string> initialize(HINSTANCE hInstance);
    RawrXD::Expected<void, std::string> run();
    void shutdown();

    HWND getMainWindow() const { return m_mainWindow; }
    HWND getEditorWindow() const { return m_editorWindow; }
    HMENU getMainMenu() const { return m_mainMenu; }

private:
    // Window creation
    RawrXD::Expected<void, std::string> registerWindowClass();
    RawrXD::Expected<void, std::string> createMainWindow();
    RawrXD::Expected<void, std::string> createEditorWindow();
    RawrXD::Expected<void, std::string> setupLayout();

    // Message handling
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT handleMessageInternal(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void handleMenuCommand(int commandId);

    // UI Creation
    void createMenus();
    void createToolbar();
    void createStatusBar();
    void createDockingPanels();
    void updateDockingLayout();
    void updateToolbar();
    void updateStatusBar(const std::string& message);

    // Menu handlers
    void onFileNewInternal();
    void onFileOpenInternal();
    void onFileSaveInternal();
    void onEditUndoInternal();
    void onEditRedoInternal();
    void onEditCutInternal();
    void onEditCopyInternal();
    void onEditPasteInternal();
    void onBuildInternal();
    void onRunInternal();
    void onDebugInternal();
    
    // Sovereign Coordination System handlers
    void onSovereignBuild();
    void onSovereignCancelBuild();
    void onSpawnEditorAgent();
    void onSpawnBuildAgent();
    void onSpawnDebugAgent();
    void onShowActiveAgents();
    void onShowSystemHealth();
    
    // Panel handles for Sovereign integration
    HWND m_terminalPanel{NULL};
    HWND m_buildPanel{NULL};

    // Member variables
    HINSTANCE m_hInstance{NULL};
    HWND m_mainWindow{NULL};
    HWND m_editorWindow{NULL};
    HWND m_statusBar{NULL};
    HMENU m_mainMenu{NULL};
    
    // IDE components
    std::unique_ptr<IDEOrchestrator> m_ide;
    std::shared_ptr<MonacoEditor> m_editor;
};

} // namespace RawrXD
