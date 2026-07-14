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
class ServiceContainer {
public:
    template<typename T>
    void Register(std::unique_ptr<T> service) {
        std::lock_guard<std::mutex> lock(mutex_);
        services_[typeid(T).name()] = std::move(service);
    }
    
    template<typename T>
    T* Get() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = services_.find(typeid(T).name());
        if (it != services_.end()) {
            return static_cast<T*>(it->second.get());
        }
        return nullptr;
    }
    
private:
    std::map<std::string, std::unique_ptr<void, void(*)(void*)>> services_;
    std::mutex mutex_;
};

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
    
    // Settings (must be first - other systems depend on it)
    settingsManager_ = std::make_unique<Settings::SettingsManager>();
    if (!settingsManager_->Initialize()) {
        ShowError("Initialization Failed", "Failed to initialize Settings Manager.");
        return false;
    }
    
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
            // Wire extension events
            // TODO: Add extension event callbacks
        }
    }
    
    // LSP Client
    if (config_.enableLSP) {
        lspClient_ = std::make_unique<LSP::LspClient>();
        // LSP client initialization is deferred until workspace is opened
    }
    
    // Debugger
    if (config_.enableDebugger) {
        debugger_ = std::make_unique<Debugger::DAPAdapter>();
        // Debugger initialization is deferred until needed
    }
    
    // Terminal
    if (config_.enableTerminal) {
        terminal_ = std::make_unique<Terminal::EmbeddedTerminal>();
        if (!terminal_->Initialize()) {
            ShowNotification("Terminal initialization failed - continuing without terminal", 5000);
            terminal_.reset();
            config_.enableTerminal = false;
        }
    }
    
    // Git Integration
    if (config_.enableGit) {
        gitIntegration_ = std::make_unique<VCS::GitIntegration>();
        if (!gitIntegration_->Initialize()) {
            ShowNotification("Git integration initialization failed - continuing without Git", 5000);
            gitIntegration_.reset();
            config_.enableGit = false;
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
    // TODO: Implement command palette UI
    // This would show a searchable list of all available commands
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
    // For now, use a tooltip or status bar message
    HWND hwnd = GetForegroundWindow();
    if (hwnd) {
        // Show tooltip or update status bar
    }
}

} // namespace RawrXD