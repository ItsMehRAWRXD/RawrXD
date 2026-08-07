#include "gui_main.h"
#include <commctrl.h>
#include <richedit.h>
#include <fstream>
#include <sstream>
#include <format> // Added for std::format

// ── Browser Integration ───────────────────────────────────────────────────
#define RAWRXD_GUI_BUILD
#include "browser/BrowserIntegration.hpp"

// ── Sovereign Coordination System Integration ───────────────────────────────
#include "sovereign/SovereignIDEBridge.hpp"

namespace RawrXD {

GUIMain::GUIMain() {
    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icex);
}

GUIMain::~GUIMain() {
    shutdown();
}

RawrXD::Expected<void, std::string> GUIMain::initialize(HINSTANCE hInstance) {
    m_hInstance = hInstance;
    
    // Register window class
    auto classResult = registerWindowClass();
    if (!classResult) {
        return classResult;
    }
    
    // Create main window
    auto windowResult = createMainWindow();
    if (!windowResult) {
        return windowResult;
    }
    
    // Create editor window
    auto editorResult = createEditorWindow();
    if (!editorResult) {
        return editorResult;
    }
    
    // Create menus
    createMenus();
    
    // Create toolbar
    createToolbar();
    
    // Create status bar
    createStatusBar();
    
    // Create docking panels
    createDockingPanels();
    
    // Initialize Sovereign Coordination System
    // This wires all 10 coordination primitives into the IDE
    auto sovereignResult = RawrXD::SovereignBridge::InitializeSovereignSystem(
        m_mainWindow, m_editorWindow, m_terminalPanel, m_buildPanel, m_statusBar
    );
    if (!sovereignResult) {
        return RawrXD::unexpected(std::string("Sovereign system initialization failed"));
    }
    spdlog::info("Sovereign Coordination System initialized");
    
    // Initialize browser panel
    RAWRXD_BROWSER_GUI_INIT();
    
    // Setup layout
    auto layoutResult = setupLayout();
    if (!layoutResult) {
        return layoutResult;
    }
    
    // Show main window
    ShowWindow(m_mainWindow, SW_SHOW);
    UpdateWindow(m_mainWindow);
    
    // Initialize IDE orchestrator
    IDEConfig config;
    config.modelsPath = "./models";
    config.toolsPath = "./tools";
    config.maxWorkers = 8;
    config.enableNetwork = true;
    config.enableSwarm = true;
    config.enableChainOfThought = true;
    config.enableTokenization = true;
    config.enableMonaco = true;
    config.logLevel = "info";
    
    m_ide = std::make_unique<IDEOrchestrator>(config);
    auto ideResult = m_ide->initialize();
    if (!ideResult) {
        return RawrXD::unexpected(std::string("IDE initialization failed"));
    }
    
    // Initialize Monaco editor
    MonacoConfig editorConfig;
    editorConfig.variant = MonacoVariant::Enterprise;
    editorConfig.themePreset = MonacoThemePreset::Default;
    editorConfig.enableIntelliSense = true;
    editorConfig.enableDebugging = true;
    editorConfig.workspaceRoot = "./workspace";
    
    m_editor = MonacoFactory::createEditor(MonacoVariant::Enterprise);
    auto editorResult = m_editor->initialize(m_mainWindow);
    if (!editorResult) {
        return editorResult;
    }
    
    // Wire IDE and editor - use the editor from IDE orchestrator
    m_editor = m_ide->getEditor();
    
    spdlog::info("GUI initialized successfully");
    
    return {};
}

RawrXD::Expected<void, std::string> GUIMain::registerWindowClass() {
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WindowProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = m_hInstance;
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszMenuName = nullptr;
    wc.lpszClassName = L"RawrXDMainWindow";
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
    
    if (!RegisterClassExW(&wc)) {
        return RawrXD::unexpected(std::string("Failed to register window class"));
    }
    
    return {};
}

RawrXD::Expected<void, std::string> GUIMain::createMainWindow() {
    m_mainWindow = CreateWindowExW(
        0,
        L"RawrXDMainWindow",
        L"RawrXD v3.0 - Agentic IDE",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1280, 800,
        nullptr,
        nullptr,
        m_hInstance,
        this
    );
    
    if (!m_mainWindow) {
        return RawrXD::unexpected(std::string("Failed to create main window"));
    }
    
    SetWindowLongPtrW(m_mainWindow, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    
    return {};
}

LRESULT CALLBACK GUIMain::WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GUIMain* gui = reinterpret_cast<GUIMain*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    
    if (gui) {
        return gui->handleMessageInternal(hwnd, msg, wParam, lParam);
    }
    
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT GUIMain::handleMessageInternal(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            return 0;
            
        case WM_COMMAND:
            handleMenuCommand(LOWORD(wParam));
            return 0; // Fixed: Was missing return
            
        case WM_SIZE:
            updateDockingLayout();
            return 0;
            
        case WM_PAINT:
            {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hwnd, &ps);
                EndPaint(hwnd, &ps);
            }
            return 0;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void GUIMain::createMenus() {
    m_mainMenu = CreateMenu();
    
    // File menu
    HMENU fileMenu = CreatePopupMenu();
    AppendMenuW(fileMenu, MF_STRING, 1001, L"&New\tCtrl+N");
    AppendMenuW(fileMenu, MF_STRING, 1002, L"&Open...\tCtrl+O");
    AppendMenuW(fileMenu, MF_STRING, 1003, L"&Save\tCtrl+S");
    AppendMenuW(fileMenu, MF_STRING, 1004, L"Save &As...\tCtrl+Shift+S");
    AppendMenuW(fileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(fileMenu, MF_STRING, 1005, L"E&xit\tAlt+F4");
    AppendMenuW(m_mainMenu, MF_POPUP, (UINT_PTR)fileMenu, L"&File");
    
    // Edit menu
    HMENU editMenu = CreatePopupMenu();
    AppendMenuW(editMenu, MF_STRING, 2001, L"&Undo\tCtrl+Z");
    AppendMenuW(editMenu, MF_STRING, 2002, L"&Redo\tCtrl+Y");
    AppendMenuW(editMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(editMenu, MF_STRING, 2003, L"Cu&t\tCtrl+X");
    AppendMenuW(editMenu, MF_STRING, 2004, L"&Copy\tCtrl+C");
    AppendMenuW(editMenu, MF_STRING, 2005, L"&Paste\tCtrl+V");
    AppendMenuW(m_mainMenu, MF_POPUP, (UINT_PTR)editMenu, L"&Edit");
    
    // Build menu
    HMENU buildMenu = CreatePopupMenu();
    AppendMenuW(buildMenu, MF_STRING, 3001, L"&Build\tCtrl+B");
    AppendMenuW(buildMenu, MF_STRING, 3002, L"&Run\tF5");
    AppendMenuW(buildMenu, MF_STRING, 3003, L"&Debug\tF11");
    AppendMenuW(m_mainMenu, MF_POPUP, (UINT_PTR)buildMenu, L"&Build");
    
    // AI menu
    HMENU aiMenu = CreatePopupMenu();
    AppendMenuW(aiMenu, MF_STRING, 4001, L"&Generate\tCtrl+G");
    AppendMenuW(aiMenu, MF_STRING, 4002, L"&Debug with AI\tCtrl+D");
    AppendMenuW(aiMenu, MF_STRING, 4003, L"&Optimize\tCtrl+O");
    AppendMenuW(aiMenu, MF_STRING, 4004, L"Analyze &Codebase\tCtrl+A");
    AppendMenuW(m_mainMenu, MF_POPUP, (UINT_PTR)aiMenu, L"&AI");
    
    // Sovereign menu (Coordination System)
    HMENU sovereignMenu = CreatePopupMenu();
    AppendMenuW(sovereignMenu, MF_STRING, 3004, L"&Build with Sovereign\tCtrl+Shift+B");
    AppendMenuW(sovereignMenu, MF_STRING, 3005, L"&Cancel Build\tCtrl+Break");
    AppendMenuW(sovereignMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(sovereignMenu, MF_STRING, 5001, L"Spawn &Editor Agent");
    AppendMenuW(sovereignMenu, MF_STRING, 5002, L"Spawn &Build Agent");
    AppendMenuW(sovereignMenu, MF_STRING, 5003, L"Spawn &Debug Agent");
    AppendMenuW(sovereignMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(sovereignMenu, MF_STRING, 5004, L"Show &Active Agents");
    AppendMenuW(sovereignMenu, MF_STRING, 5005, L"System &Health");
    AppendMenuW(m_mainMenu, MF_POPUP, (UINT_PTR)sovereignMenu, L"&Sovereign");
    
    SetMenu(m_mainWindow, m_mainMenu);
}

void GUIMain::handleMenuCommand(int commandId) {
    switch (commandId) {
        case 1001: // File New
            onFileNewInternal();
            break;
        case 1002: // File Open
            onFileOpenInternal();
            break;
        case 1003: // File Save
            onFileSaveInternal();
            break;
        case 1004: // File Save As
            // Implementation
            break;
        case 1005: // File Exit
            PostQuitMessage(0);
            break;
            
        case 2001: // Edit Undo
            onEditUndoInternal();
            break;
        case 2002: // Edit Redo
            onEditRedoInternal();
            break;
        case 2003: // Edit Cut
            onEditCutInternal();
            break;
        case 2004: // Edit Copy
            onEditCopyInternal();
            break;
        case 2005: // Edit Paste
            onEditPasteInternal();
            break;
            
        case 3001: // Build
            onBuildInternal();
            break;
        case 3002: // Run
            onRunInternal();
            break;
        case 3003: // Debug
            onDebugInternal();
            break;
        case 3004: // Build with Sovereign
            onSovereignBuild();
            break;
        case 3005: // Cancel Build
            onSovereignCancelBuild();
            break;
            
        case 4001: // AI Generate
            // Implementation
            break;
        case 4002: // AI Debug
            // Implementation
            break;
        case 4003: // AI Optimize
            // Implementation
            break;
        case 4004: // AI Analyze
            // Implementation
            break;
            
        case 5001: // Spawn Editor Agent
            onSpawnEditorAgent();
            break;
        case 5002: // Spawn Build Agent
            onSpawnBuildAgent();
            break;
        case 5003: // Spawn Debug Agent
            onSpawnDebugAgent();
            break;
        case 5004: // Show Active Agents
            onShowActiveAgents();
            break;
        case 5005: // System Health
            onShowSystemHealth();
            break;
    }
}

void GUIMain::onFileNewInternal() {
    if (m_editor) {
        m_editor->setText("");
        updateStatusBar("New file created");
    }
}

void GUIMain::onFileOpenInternal() {
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_mainWindow;
    ofn.lpstrFilter = L"All Files\0*.*\0C++ Files\0*.cpp;*.h\0";
    ofn.lpstrFile = new WCHAR[MAX_PATH];
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST;
    
    if (GetOpenFileNameW(&ofn)) {
        std::wstring ws(ofn.lpstrFile);
        std::string path(ws.begin(), ws.end());
        
        if (m_editor) {
            auto result = m_editor->loadFile(path);
            if (result) {
                updateStatusBar(std::format("Loaded: {}", path));
            } else {
                updateStatusBar(std::format("Failed to load: {}", result.error()));
            }
        }
        
        delete[] ofn.lpstrFile;
    }
}

void GUIMain::onFileSaveInternal() {
    if (!m_editor) return;
    
    std::string currentFile = m_editor->getCurrentFile();
    if (currentFile.empty()) {
        // Show save dialog
        OPENFILENAMEW ofn = {0};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = m_mainWindow;
        ofn.lpstrFilter = L"All Files\0*.*\0C++ Files\0*.cpp;*.h\0";
        ofn.lpstrFile = new WCHAR[MAX_PATH];
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_OVERWRITEPROMPT;
        
        if (GetSaveFileNameW(&ofn)) {
            std::wstring ws(ofn.lpstrFile);
            currentFile = std::string(ws.begin(), ws.end());
            delete[] ofn.lpstrFile;
        } else {
            return;
        }
    }
    
    auto result = m_editor->saveFile(currentFile);
    if (result) {
        updateStatusBar(std::format("Saved: {}", currentFile));
    } else {
        updateStatusBar(std::format("Failed to save: {}", result.error()));
    }
}

void GUIMain::updateStatusBar(const std::string& message) {
    if (m_statusBar) {
        SetWindowTextA(m_statusBar, message.c_str());
    }
}

RawrXD::Expected<void, std::string> GUIMain::run() {
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return {};
}

void GUIMain::shutdown() {
    // Shutdown Sovereign Coordination System
    RawrXD::SovereignBridge::ShutdownSovereignSystem();
    spdlog::info("Sovereign Coordination System shutdown");
    
    if (m_ide) {
        m_ide->stop();
    }
    
    // m_editor is a shared_ptr, will clean itself up when GUIMain is destroyed
    m_editor.reset();
    
    if (m_mainWindow) {
        DestroyWindow(m_mainWindow);
        m_mainWindow = nullptr;
    }
}

// Real Win32 Implementations for GUI
RawrXD::Expected<void, std::string> GUIMain::createEditorWindow() {
    // Create Monaco-like editor using RichEdit or WebView
    // Using RichEdit for simpler Win32 "RawrXD" feel
    LoadLibrary(TEXT("Msftedit.dll")); 
    
    RECT rcClient;
    GetClientRect(m_mainWindow, &rcClient);
    
    m_editorWindow = CreateWindowEx(
        0, 
        TEXT("RICHEDIT50W"), 
        TEXT(""), 
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL, 
        0, 28, rcClient.right, rcClient.bottom - 48, // Adjust for toolbar/status
        m_mainWindow, 
        (HMENU)1001, 
        m_hInstance, 
        NULL
    );
    
    if (!m_editorWindow) return RawrXD::unexpected(std::string("Failed to create editor window"));
    
    // Set font
    HFONT hFont = CreateFont(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, 
      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, 
      FIXED_PITCH | FF_MODERN, TEXT("Consolas"));
    SendMessage(m_editorWindow, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    return {};
}

RawrXD::Expected<void, std::string> GUIMain::setupLayout() {
    // Simple layout management handled in WM_SIZE usually
    return {};
}

void GUIMain::createToolbar() {
    // Basic Toolbar
    HWND hTool = CreateWindowEx(0, TOOLBARCLASSNAME, NULL, 
        WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, 
        m_mainWindow, (HMENU)1002, m_hInstance, NULL);
        
    SendMessage(hTool, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);
    
    TBBUTTON tbb[3];
    ZeroMemory(tbb, sizeof(tbb));
    
    tbb[0].iBitmap = I_IMAGENONE; 
    tbb[0].fsState = TBSTATE_ENABLED; 
    tbb[0].fsStyle = BTNS_BUTTON; 
    tbb[0].idCommand = 2001; // CMD_RUN
    tbb[0].iString = (INT_PTR)TEXT("Run");
    
    tbb[1].iBitmap = I_IMAGENONE; 
    tbb[1].fsState = TBSTATE_ENABLED; 
    tbb[1].fsStyle = BTNS_BUTTON; 
    tbb[1].idCommand = 2002; // CMD_DEBUG
    tbb[1].iString = (INT_PTR)TEXT("Debug");
    
    tbb[2].iBitmap = I_IMAGENONE; 
    tbb[2].fsState = TBSTATE_ENABLED; 
    tbb[2].fsStyle = BTNS_BUTTON; 
    tbb[2].idCommand = 2003; // CMD_BUILD
    tbb[2].iString = (INT_PTR)TEXT("Build");
    
    SendMessage(hTool, TB_ADDBUTTONS, 3, (LPARAM)&tbb);
    SendMessage(hTool, TB_AUTOSIZE, 0, 0);
}

void GUIMain::createStatusBar() {
    HWND hStatus = CreateWindowEx(0, STATUSCLASSNAME, NULL, 
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0, 
        m_mainWindow, (HMENU)1003, m_hInstance, NULL);
    
    int statwidths[] = {100, 200, -1};
    SendMessage(hStatus, SB_SETPARTS, sizeof(statwidths)/sizeof(int), (LPARAM)statwidths);
    SendMessage(hStatus, SB_SETTEXT, 0, (LPARAM)TEXT("Ready"));
}

void GUIMain::createDockingPanels() {
    // Create docking panels for terminal, build output, and debug output
    // These are child windows that can be docked/undocked

    // Terminal panel
    m_terminalPanel = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        TEXT("EDIT"),
        TEXT("Terminal Output"),
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
        0, 400, 800, 150,
        m_mainWindow,
        (HMENU)2001,
        m_hInstance,
        NULL
    );

    // Build output panel
    m_buildPanel = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        TEXT("EDIT"),
        TEXT("Build Output"),
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
        0, 550, 800, 100,
        m_mainWindow,
        (HMENU)2002,
        m_hInstance,
        NULL
    );

    // Set monospace font for panels
    HFONT hFont = CreateFont(
        14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN,
        TEXT("Consolas")
    );

    if (m_terminalPanel) SendMessage(m_terminalPanel, WM_SETFONT, (WPARAM)hFont, TRUE);
    if (m_buildPanel) SendMessage(m_buildPanel, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Initialize panels with welcome text
    if (m_terminalPanel) {
        SetWindowText(m_terminalPanel, TEXT("RawrXD Terminal Ready\r\n"));
    }
    if (m_buildPanel) {
        SetWindowText(m_buildPanel, TEXT("Build Output Panel\r\n"));
    }
}

void GUIMain::updateDockingLayout() {
    // Update layout when window is resized
    if (!m_mainWindow) return;

    RECT rcClient;
    GetClientRect(m_mainWindow, &rcClient);

    int width = rcClient.right - rcClient.left;
    int height = rcClient.bottom - rcClient.top;

    // Reserve space for menu and toolbar (approx 60px)
    int topOffset = 60;
    // Reserve space for status bar (approx 25px)
    int bottomOffset = 25;

    int availableHeight = height - topOffset - bottomOffset;

    // Editor takes top 60% of available space
    int editorHeight = (availableHeight * 60) / 100;

    // Terminal takes 25% of available space
    int terminalHeight = (availableHeight * 25) / 100;

    // Build panel takes remaining 15%
    int buildHeight = availableHeight - editorHeight - terminalHeight;

    // Position windows
    if (m_editorWindow) {
        SetWindowPos(m_editorWindow, NULL,
            0, topOffset, width, editorHeight,
            SWP_NOZORDER);
    }

    if (m_terminalPanel) {
        SetWindowPos(m_terminalPanel, NULL,
            0, topOffset + editorHeight, width, terminalHeight,
            SWP_NOZORDER);
    }

    if (m_buildPanel) {
        SetWindowPos(m_buildPanel, NULL,
            0, topOffset + editorHeight + terminalHeight, width, buildHeight,
            SWP_NOZORDER);
    }

    // Force redraw
    if (m_mainWindow) {
        InvalidateRect(m_mainWindow, NULL, TRUE);
        UpdateWindow(m_mainWindow);
    }
}

void GUIMain::onDebugInternal() {
    // Open debug panel or start debugging session
    if (m_terminalPanel) {
        SetWindowText(m_terminalPanel, TEXT("Debug Session Started\r\n"));
    }

    // Show debug menu or panel
    MessageBox(m_mainWindow, TEXT("Debug session initialized"), TEXT("RawrXD Debug"), MB_OK);
}

// Sovereign Coordination System handlers
void GUIMain::onSovereignBuild() {
    // Trigger build through Sovereign Build State Graph
    bool result = RawrXD::SovereignBridge::TriggerBuild("all");
    if (result) {
        updateStatusBar("Build triggered via Sovereign system");
    } else {
        updateStatusBar("Failed to trigger Sovereign build");
    }
}

void GUIMain::onSovereignCancelBuild() {
    bool result = RawrXD::SovereignBridge::CancelBuild();
    if (result) {
        updateStatusBar("Build cancelled via Sovereign system");
    } else {
        updateStatusBar("Failed to cancel build");
    }
}

void GUIMain::onSpawnEditorAgent() {
    std::string agentId = RawrXD::SovereignBridge::SpawnEditorAgent("Editor assistance");
    if (!agentId.empty()) {
        updateStatusBar("Editor agent spawned: " + agentId);
    } else {
        updateStatusBar("Failed to spawn editor agent");
    }
}

void GUIMain::onSpawnBuildAgent() {
    std::string agentId = RawrXD::SovereignBridge::SpawnBuildAgent("Build automation");
    if (!agentId.empty()) {
        updateStatusBar("Build agent spawned: " + agentId);
    } else {
        updateStatusBar("Failed to spawn build agent");
    }
}

void GUIMain::onSpawnDebugAgent() {
    std::string agentId = RawrXD::SovereignBridge::SpawnDebugAgent("Debug assistance");
    if (!agentId.empty()) {
        updateStatusBar("Debug agent spawned: " + agentId);
    } else {
        updateStatusBar("Failed to spawn debug agent");
    }
}

void GUIMain::onShowActiveAgents() {
    std::vector<std::string> agents = RawrXD::SovereignBridge::GetActiveAgents();
    std::string message = "Active Agents: " + std::to_string(agents.size()) + "\n";
    for (const auto& agent : agents) {
        message += "- " + agent + "\n";
    }
    MessageBoxA(m_mainWindow, message.c_str(), "Sovereign Agents", MB_OK);
}

void GUIMain::onShowSystemHealth() {
    auto snapshot = RawrXD::SovereignBridge::GetSystemSnapshot();
    std::string health = (snapshot.overall_health == Sovereign::HealthStatus::HEALTHY) ? "HEALTHY" :
                         (snapshot.overall_health == Sovereign::HealthStatus::DEGRADED) ? "DEGRADED" : "UNHEALTHY";
    std::string message = "System Health: " + health + "\n" +
                          "Active Agents: " + std::to_string(snapshot.active_agents) + "\n" +
                          "Active Terminals: " + std::to_string(snapshot.active_terminals) + "\n" +
                          "Active Builds: " + std::to_string(snapshot.active_builds) + "\n" +
                          "Memory: " + std::to_string(snapshot.used_memory_mb) + "/" + std::to_string(snapshot.total_memory_mb) + " MB";
    MessageBoxA(m_mainWindow, message.c_str(), "Sovereign System Health", MB_OK);
}

} // namespace RawrXD
