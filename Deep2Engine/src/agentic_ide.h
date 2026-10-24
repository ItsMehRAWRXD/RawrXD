#pragma once
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <memory>
#include "code_editor.h"
#include "ide_hooks.h"

// AgenticIDE - native Win32/C++20 main window for RawrXD.
//
// Wires together: multi-tab editor, file browser, terminal, AI chat,
// agentic engine, model router, tool registry, plan orchestrator,
// LSP client, and file operations with Keep/Undo. This is the graphical
// front end for the same inference + agent pipeline that `rawr` exposes
// on the command line.
//
// No Qt. No Electron. Pure Win32 API.
class AgenticIDE {
public:
    AgenticIDE(HINSTANCE hInstance, int nCmdShow);
    ~AgenticIDE();

    int run();

    // Hook system access (for tests and extensions)
    RawrXD::IdeHooks::HookSystem& hooks() { return m_hooks; }

private:
    HINSTANCE m_hInstance = nullptr;
    HWND m_hwnd = nullptr;
    HWND m_hStatusBar = nullptr;
    HMENU m_hMenu = nullptr;

    // Customizable hook system (IDE_HOOKS.md in workspace root)
    RawrXD::IdeHooks::HookSystem m_hooks;

    // Dock-like child areas
    HWND m_hFileBrowser = nullptr;
    HWND m_hTerminal = nullptr;
    HWND m_hChat = nullptr;
    HWND m_hChatInput = nullptr;
    HWND m_hChatSend = nullptr;

    // Multi-tab editor container
    HWND m_hTabCtrl = nullptr;
    std::vector<std::unique_ptr<CodeEditor>> m_editorTabs;
    int m_activeTab = -1;

    // Splitter positions
    int m_leftPaneWidth = 260;
    int m_rightPaneWidth = 320;

    bool initWindow();
    bool initMenu();
    bool initLayout();
    bool initHooks();
    LRESULT CALLBACK wndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK s_wndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

    void onSize(UINT type, int cx, int cy);
    void onCommand(WORD id, WORD cmd, HWND hwndCtl);
    void onDestroy();
    void layoutChildren(int cx, int cy);

    // Editor tab management
    int addEditorTab(const std::wstring& title = L"Untitled");
    void closeEditorTab(int index);
    void setActiveTab(int index);
    CodeEditor* activeEditor() { return m_activeTab >= 0 && m_activeTab < (int)m_editorTabs.size() ? m_editorTabs[m_activeTab].get() : nullptr; }
    void loadFileIntoEditor(const std::wstring& path);

    // File browser tree helpers
    void populateTreeDrives();
    void populateTreeChildren(HTREEITEM hParent, const std::wstring& path);
    std::wstring getTreeItemPath(HTREEITEM hItem) const;
    void onTreeDoubleClick(HTREEITEM hItem);

    // Menu command IDs
    static constexpr int kCmdFileNew = 1001;
    static constexpr int kCmdFileOpen = 1002;
    static constexpr int kCmdFileSave = 1003;
    static constexpr int kCmdFileExit = 1004;
    static constexpr int kCmdViewFileBrowser = 2001;
    static constexpr int kCmdViewChat = 2002;
    static constexpr int kCmdViewTerminal = 2003;
    static constexpr int kCmdAgentRun = 3001;
    static constexpr int kCmdHelpAbout = 4001;
};
