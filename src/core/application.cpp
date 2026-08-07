#include "application.h"
#include "event_bus.h"
#include "../extensions/extension_host.h"
#include "../workspace/workspace_manager.h"
#include "../tasks/task_runner.h"
#include "../settings/settings_manager.h"
#include "../lsp/LspClient.h"
#include "../debugger/DAPAdapter.h"
#include "../terminal/embedded_terminal.h"
#include "../vcs/git_integration.h"

#include <windows.h>
#include <shlwapi.h>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")

namespace RawrXD {

// Service Container implementation
ServiceContainer& ServiceContainer::Instance() {
    static ServiceContainer instance;
    return instance;
}

void ServiceContainer::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    services_.clear();
}

size_t ServiceContainer::Count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return services_.size();
}

Application& Application::Instance() {
    static Application instance;
    return instance;
}

bool Application::Initialize(const AppConfig& config) {
    if (state_ != AppState::Uninitialized) {
        return false;
    }
    
    SetState(AppState::Initializing);
    config_ = config;
    
    // Initialize COM for shell operations
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    
    // Initialize common controls
    INITCOMMONCONTROLSEX iccex;
    iccex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    iccex.dwICC = ICC_WIN95_CLASSES | ICC_COOL_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&iccex);
    
    // Initialize all subsystems
    if (!InitializeSubsystems()) {
        ShowError("Initialization Failed", "Failed to initialize core subsystems.");
        return false;
    }
    
    // Initialize UI
    if (!InitializeUI()) {
        ShowError("Initialization Failed", "Failed to initialize user interface.");
        return false;
    }
    
    // Initialize extensions
    if (config_.enableExtensions) {
        if (!InitializeExtensions()) {
            ShowNotification("Extension initialization partially failed", 5000);
        }
    }
    
    SetState(AppState::Ready);
    return true;
}

bool Application::InitializeSubsystems() {
    // Initialize Event Bus first (used by all subsystems)
    EventBus::Instance(); // Ensure singleton is created
    
    // Register core services in Service Container
    g_Services.Register<EventBus>(std::shared_ptr<EventBus>(&EventBus::Instance(), [](EventBus*){}));
    g_Services.Register<CommandRegistry>(std::shared_ptr<CommandRegistry>(&CommandRegistry::Instance(), [](CommandRegistry*){}));
    
    // Settings (must be first - other systems depend on it)
    settingsManager_ = std::make_unique<Settings::SettingsManager>();
    if (!settingsManager_->Initialize()) {
        ShowError("Initialization Failed", "Failed to initialize Settings Manager.");
        return false;
    }
    
    // Register settings in service container
    g_Services.Register<Settings::SettingsManager>(
        std::shared_ptr<Settings::SettingsManager>(settingsManager_.get(), [](Settings::SettingsManager*){})
    );
    
    // Load settings into config
    config_.windowWidth = settingsManager_->GetInteger("window.width", config_.windowWidth);
    config_.windowHeight = settingsManager_->GetInteger("window.height", config_.windowHeight);
    config_.maximized = settingsManager_->GetBoolean("window.maximized", config_.maximized);
    config_.enableLSP = settingsManager_->GetBoolean("features.lsp", config_.enableLSP);
    config_.enableDebugger = settingsManager_->GetBoolean("features.debugger", config_.enableDebugger);
    config_.enableTerminal = settingsManager_->GetBoolean("features.terminal", config_.enableTerminal);
    config_.enableGit = settingsManager_->GetBoolean("features.git", config_.enableGit);
    config_.enableExtensions = settingsManager_->GetBoolean("features.extensions", config_.enableExtensions);
    config_.enableAI = settingsManager_->GetBoolean("features.ai", config_.enableAI);
    
    // Wire settings change events
    settingsManager_->SetChangeCallback([](const std::string& key, const Settings::SettingValue& newVal, const Settings::SettingValue& oldVal) {
        SettingsEventData data;
        data.key = key;
        data.oldValue = oldVal.AsString();
        data.newValue = newVal.AsString();
        data.source = "SettingsManager";
        RAWRXD_PUBLISH_EVENT(EventType::SettingsChanged, data);
    });
    
    // Workspace
    workspaceManager_ = std::make_unique<Workspace::WorkspaceManager>();
    if (!workspaceManager_->Initialize()) {
        ShowError("Initialization Failed", "Failed to initialize Workspace Manager.");
        return false;
    }
    
    // Register workspace in service container
    g_Services.Register<Workspace::WorkspaceManager>(
        std::shared_ptr<Workspace::WorkspaceManager>(workspaceManager_.get(), [](Workspace::WorkspaceManager*){})
    );
    
    // Wire workspace events
    workspaceManager_->SetFileChangeCallback([](const std::string& path, const std::string& changeType) {
        FileEventData data;
        data.path = path;
        data.source = "WorkspaceManager";
        
        EventType type = EventType::FileModified;
        if (changeType == "created") type = EventType::FileCreated;
        else if (changeType == "deleted") type = EventType::FileDeleted;
        else if (changeType == "renamed") type = EventType::FileRenamed;
        
        RAWRXD_PUBLISH_EVENT(type, data);
    });
    
    // Task Runner
    taskRunner_ = std::make_unique<Tasks::TaskRunner>();
    if (!taskRunner_->Initialize()) {
        ShowError("Initialization Failed", "Failed to initialize Task Runner.");
        return false;
    }
    
    // Register task runner in service container
    g_Services.Register<Tasks::TaskRunner>(
        std::shared_ptr<Tasks::TaskRunner>(taskRunner_.get(), [](Tasks::TaskRunner*){})
    );
    
    // Wire task events
    taskRunner_->SetTaskEventCallback([](const std::string& taskId, Tasks::TaskStatus status) {
        TaskEventData data;
        data.taskId = taskId;
        data.source = "TaskRunner";
        
        EventType type = EventType::TaskStarted;
        if (status == Tasks::TaskStatus::Succeeded) type = EventType::TaskCompleted;
        else if (status == Tasks::TaskStatus::Failed) type = EventType::TaskFailed;
        else if (status == Tasks::TaskStatus::Cancelled) type = EventType::TaskCancelled;
        
        RAWRXD_PUBLISH_EVENT(type, data);
    });
    
    taskRunner_->SetOutputCallback([](const std::string& taskId, const std::string& output) {
        TaskEventData data;
        data.taskId = taskId;
        data.output = output;
        data.source = "TaskRunner";
        RAWRXD_PUBLISH_EVENT(EventType::TaskProgress, data);
    });
    
    // Extension Host
    if (config_.enableExtensions) {
        extensionHost_ = std::make_unique<Extensions::ExtensionHost>();
        if (!extensionHost_->Initialize()) {
            ShowNotification("Extension Host initialization failed - continuing without extensions", 5000);
            extensionHost_.reset();
            config_.enableExtensions = false;
        } else {
            // Register extension host in service container
            g_Services.Register<Extensions::ExtensionHost>(
                std::shared_ptr<Extensions::ExtensionHost>(extensionHost_.get(), [](Extensions::ExtensionHost*){})
            );
            // Wire extension events
            // TODO: Add extension event callbacks
        }
    }
    
    // LSP Client
    if (config_.enableLSP) {
        lspClient_ = std::make_unique<LSP::LspClient>();
        // LSP client initialization is deferred until workspace is opened
        g_Services.Register<LSP::LspClient>(
            std::shared_ptr<LSP::LspClient>(lspClient_.get(), [](LSP::LspClient*){})
        );
    }
    
    // Debugger
    if (config_.enableDebugger) {
        debugger_ = std::make_unique<Debugger::DAPAdapter>();
        // Debugger initialization is deferred until needed
        g_Services.Register<Debugger::DAPAdapter>(
            std::shared_ptr<Debugger::DAPAdapter>(debugger_.get(), [](Debugger::DAPAdapter*){})
        );
    }
    
    // Terminal
    if (config_.enableTerminal) {
        terminal_ = std::make_unique<Terminal::EmbeddedTerminal>();
        if (!terminal_->Initialize()) {
            ShowNotification("Terminal initialization failed - continuing without terminal", 5000);
            terminal_.reset();
            config_.enableTerminal = false;
        } else {
            g_Services.Register<Terminal::EmbeddedTerminal>(
                std::shared_ptr<Terminal::EmbeddedTerminal>(terminal_.get(), [](Terminal::EmbeddedTerminal*){})
            );
        }
    }
    
    // Git Integration
    if (config_.enableGit) {
        gitIntegration_ = std::make_unique<VCS::GitIntegration>();
        if (!gitIntegration_->Initialize()) {
            ShowNotification("Git integration initialization failed - continuing without Git", 5000);
            gitIntegration_.reset();
            config_.enableGit = false;
        } else {
            g_Services.Register<VCS::GitIntegration>(
                std::shared_ptr<VCS::GitIntegration>(gitIntegration_.get(), [](VCS::GitIntegration*){})
            );
        }
    }
    
    // Publish app ready event
    EventData readyData;
    readyData.source = "Application";
    RAWRXD_PUBLISH_EVENT(EventType::AppReady, readyData);
    
    return true;
}

bool Application::InitializeUI() {
    // Register window class
    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "RawrXDMainWindow";
    
    if (!RegisterClassExA(&wc)) {
        if (GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            return false;
        }
    }
    
    // Create main window
    DWORD style = WS_OVERLAPPEDWINDOW;
    if (config_.maximized) {
        style |= WS_MAXIMIZE;
    }
    
    HWND hwnd = CreateWindowExA(
        0,
        "RawrXDMainWindow",
        config_.windowTitle.c_str(),
        style,
        CW_USEDEFAULT, CW_USEDEFAULT,
        config_.windowWidth, config_.windowHeight,
        nullptr, nullptr,
        GetModuleHandleA(nullptr),
        nullptr
    );
    
    if (!hwnd) {
        return false;
    }
    
    ShowWindow(hwnd, config_.maximized ? SW_SHOWMAXIMIZED : SW_SHOW);
    UpdateWindow(hwnd);
    
    return true;
}

bool Application::InitializeExtensions() {
    if (!extensionHost_) return false;
    
    // Activate extensions by event
    extensionHost_->ActivateByEvent("*");
    
    return true;
}

bool Application::Shutdown() {
    if (state_ == AppState::Shutdown) {
        return true;
    }
    
    SetState(AppState::ShuttingDown);
    
    // Save settings
    if (settingsManager_) {
        settingsManager_->SetInteger("window.width", config_.windowWidth);
        settingsManager_->SetInteger("window.height", config_.windowHeight);
        settingsManager_->SetBoolean("window.maximized", config_.maximized);
    }
    
    // Shutdown subsystems in reverse order
    if (gitIntegration_) {
        gitIntegration_->Shutdown();
        gitIntegration_.reset();
    }
    
    if (terminal_) {
        terminal_->Shutdown();
        terminal_.reset();
    }
    
    if (debugger_) {
        debugger_->Shutdown();
        debugger_.reset();
    }
    
    if (lspClient_) {
        lspClient_->Shutdown();
        lspClient_.reset();
    }
    
    if (extensionHost_) {
        extensionHost_->Shutdown();
        extensionHost_.reset();
    }
    
    if (taskRunner_) {
        taskRunner_->Shutdown();
        taskRunner_.reset();
    }
    
    if (workspaceManager_) {
        workspaceManager_->Shutdown();
        workspaceManager_.reset();
    }
    
    if (settingsManager_) {
        settingsManager_->Shutdown();
        settingsManager_.reset();
    }
    
    CoUninitialize();
    
    SetState(AppState::Shutdown);
    return true;
}

int Application::Run() {
    if (state_ != AppState::Ready) {
        return -1;
    }
    
    SetState(AppState::Running);
    
    MSG msg;
    while (GetMessageA(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
        
        // Process event bus events after each message
        EventBus::Instance().ProcessEvents();
    }
    
    return exitCode_;
}

void Application::Quit(int exitCode) {
    exitCode_ = exitCode;
    PostQuitMessage(exitCode);
}

void Application::SetState(AppState state) {
    AppState oldState = state_;
    state_ = state;
    
    if (stateChangeCallback_) {
        stateChangeCallback_(oldState, state);
    }
}

void Application::UpdateConfig(const AppConfig& config) {
    config_ = config;
}

bool Application::OpenWorkspace(const std::string& path) {
    if (!workspaceManager_) return false;
    
    // Close current workspace if any
    CloseWorkspace();
    
    // Add folder to workspace
    if (!workspaceManager_->AddFolder(path)) {
        return false;
    }
    
    currentWorkspace_ = path;
    
    // Load workspace settings
    if (settingsManager_) {
        settingsManager_->LoadWorkspaceSettings(path);
    }
    
    // Load workspace tasks
    if (taskRunner_) {
        taskRunner_->LoadTasksConfiguration(path + "\\.vscode\\tasks.json");
    }
    
    // Initialize LSP for workspace
    if (lspClient_) {
        // TODO: Start LSP servers based on workspace content
    }
    
    // Activate extensions
    if (extensionHost_) {
        extensionHost_->ActivateByEvent("onWorkspaceOpen");
    }
    
    return true;
}

bool Application::CloseWorkspace() {
    if (currentWorkspace_.empty()) return true;
    
    // Save workspace settings
    if (settingsManager_) {
        settingsManager_->SaveWorkspaceSettings(currentWorkspace_);
    }
    
    // Shutdown LSP
    if (lspClient_) {
        lspClient_->Shutdown();
    }
    
    // Clear workspace
    if (workspaceManager_) {
        workspaceManager_->Shutdown();
        workspaceManager_->Initialize();
    }
    
    currentWorkspace_.clear();
    return true;
}

std::string Application::GetCurrentWorkspace() const {
    return currentWorkspace_;
}

void Application::ShowCommandPalette() {
    // Create command palette dialog
    // This is a searchable list of all available commands
    
    HWND hwndParent = GetForegroundWindow();
    
    // Create dialog window
    HWND hwndDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        L"EDIT", L"Command Palette",
        WS_VISIBLE | WS_POPUP | WS_BORDER | ES_AUTOHSCROLL,
        CW_USEDEFAULT, CW_USEDEFAULT, 600, 400,
        hwndParent, NULL, GetModuleHandle(NULL), NULL
    );
    
    if (!hwndDlg) {
        return;
    }
    
    // Center on screen
    RECT rc;
    GetWindowRect(hwndDlg, &rc);
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(hwndDlg, NULL, 
                 (screenWidth - width) / 2, (screenHeight - height) / 2,
                 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    
    // Build command list
    std::vector<std::string> commands = {
        "File: New",
        "File: Open",
        "File: Save",
        "File: Save As",
        "File: Exit",
        "Edit: Undo",
        "Edit: Redo",
        "Edit: Cut",
        "Edit: Copy",
        "Edit: Paste",
        "View: Toggle Sidebar",
        "View: Toggle Bottom Panel",
        "View: Toggle Dark Mode",
        "Debug: Start Debugging",
        "Debug: Stop Debugging",
        "Debug: Step Over",
        "Debug: Step Into",
        "AI: Trigger Completion",
        "AI: Open Chat",
        "LSP: Restart Server",
        "Git: Commit",
        "Git: Push",
        "Git: Pull",
        "Terminal: New Terminal",
        "Window: Close Editor",
        "Window: Next Editor",
        "Window: Previous Editor",
        "Help: About",
        "Help: Documentation"
    };
    
    // Add extension commands
    if (extensionHost_) {
        auto extCommands = extensionHost_->GetAvailableCommands();
        for (const auto& cmd : extCommands) {
            commands.push_back("Ext: " + cmd);
        }
    }
    
    // Create list box for commands
    HWND hwndList = CreateWindowExW(
        0, L"LISTBOX", NULL,
        WS_VISIBLE | WS_CHILD | LBS_NOTIFY | WS_VSCROLL | LBS_HASSTRINGS,
        10, 40, 580, 300,
        hwndDlg, (HMENU)1001, GetModuleHandle(NULL), NULL
    );
    
    // Populate list
    for (const auto& cmd : commands) {
        SendMessageA(hwndList, LB_ADDSTRING, 0, (LPARAM)cmd.c_str());
    }
    
    // Create search box
    HWND hwndSearch = CreateWindowExW(
        0, L"EDIT", L"",
        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
        10, 10, 580, 25,
        hwndDlg, (HMENU)1002, GetModuleHandle(NULL), NULL
    );
    
    SetFocus(hwndSearch);
    
    // Simple message loop for the dialog
    MSG msg;
    BOOL running = TRUE;
    while (running && GetMessage(&msg, NULL, 0, 0)) {
        if (msg.message == WM_KEYDOWN) {
            if (msg.wParam == VK_ESCAPE) {
                running = FALSE;
            } else if (msg.wParam == VK_RETURN) {
                // Execute selected command
                int sel = (int)SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                if (sel != LB_ERR) {
                    char buffer[256];
                    SendMessageA(hwndList, LB_GETTEXT, sel, (LPARAM)buffer);
                    ExecuteCommand(buffer);
                }
                running = FALSE;
            } else if (msg.wParam == VK_DOWN) {
                int sel = (int)SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                if (sel < (int)commands.size() - 1) {
                    SendMessage(hwndList, LB_SETCURSEL, sel + 1, 0);
                }
            } else if (msg.wParam == VK_UP) {
                int sel = (int)SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                if (sel > 0) {
                    SendMessage(hwndList, LB_SETCURSEL, sel - 1, 0);
                }
            }
        }
        
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    DestroyWindow(hwndDlg);
}

void Application::ExecuteCommand(const std::string& command) {
    if (extensionHost_) {
        extensionHost_->ActivateByCommand(command);
        // TODO: Execute the actual command
    }
}

void Application::ShowError(const std::string& title, const std::string& message) {
    MessageBoxA(nullptr, message.c_str(), title.c_str(), MB_OK | MB_ICONERROR);
}

void Application::ShowNotification(const std::string& message, int timeoutMs) {
    // Simple notification - could be enhanced with a proper notification system
    // Current implementation uses tooltip or status bar message
    HWND hwnd = GetForegroundWindow();
    if (hwnd) {
        // Show tooltip or update status bar
    }
}

} // namespace RawrXD
