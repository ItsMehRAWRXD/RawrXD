#pragma once

#include "event_bus.h"
#include <memory>
#include <functional>
#include <string>

// Forward declarations for all subsystems
namespace RawrXD {
namespace Extensions { class ExtensionHost; }
namespace Workspace { class WorkspaceManager; }
namespace Tasks { class TaskRunner; }
namespace Settings { class SettingsManager; }
namespace LSP { class LspClient; }
namespace Debugger { class DAPAdapter; }
namespace Terminal { class EmbeddedTerminal; }
namespace VCS { class GitIntegration; }

// Service Container for dependency injection
class ServiceContainer {
public:
    static ServiceContainer& Instance();
    
    // Register a service (takes ownership)
    template<typename T>
    void Register(std::shared_ptr<T> service) {
        std::lock_guard<std::mutex> lock(mutex_);
        services_[typeid(T).name()] = service;
    }
    
    // Register with interface/implementation separation
    template<typename Interface, typename Implementation>
    void Register() {
        static_assert(std::is_base_of<Interface, Implementation>::value, 
                      "Implementation must derive from Interface");
        std::lock_guard<std::mutex> lock(mutex_);
        services_[typeid(Interface).name()] = std::make_shared<Implementation>();
    }
    
    // Resolve a service
    template<typename T>
    std::shared_ptr<T> Resolve() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = services_.find(typeid(T).name());
        if (it != services_.end()) {
            return std::static_pointer_cast<T>(it->second);
        }
        return nullptr;
    }
    
    // Resolve or create (factory pattern)
    template<typename T, typename... Args>
    std::shared_ptr<T> ResolveOrCreate(Args&&... args) {
        auto existing = Resolve<T>();
        if (existing) return existing;
        
        auto created = std::make_shared<T>(std::forward<Args>(args)...);
        Register<T>(created);
        return created;
    }
    
    // Check if service exists
    template<typename T>
    bool Has() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return services_.find(typeid(T).name()) != services_.end();
    }
    
    // Remove a service
    template<typename T>
    void Remove() {
        std::lock_guard<std::mutex> lock(mutex_);
        services_.erase(typeid(T).name());
    }
    
    // Clear all services
    void Clear();
    
    // Get count of registered services
    size_t Count() const;
    
private:
    ServiceContainer() = default;
    ~ServiceContainer() = default;
    
    std::map<std::string, std::shared_ptr<void>> services_;
    mutable std::mutex mutex_;
};

// Convenience macro for service access
#define g_Services RawrXD::ServiceContainer::Instance()

namespace RawrXD {

// Application configuration
struct AppConfig {
    // Window settings
    int windowWidth = 1600;
    int windowHeight = 900;
    bool maximized = false;
    std::string windowTitle = "RawrXD Agentic IDE";
    
    // Paths
    std::string workspacePath;
    std::string extensionsPath;
    std::string settingsPath;
    
    // Feature flags
    bool enableLSP = true;
    bool enableDebugger = true;
    bool enableTerminal = true;
    bool enableGit = true;
    bool enableExtensions = true;
    bool enableAI = true;
    
    // AI settings
    std::string defaultModel = "codestral-22b";
    int maxTokens = 2048;
    float temperature = 0.7f;
};

// Application lifecycle states
enum class AppState {
    Uninitialized,
    Initializing,
    Ready,
    Running,
    ShuttingDown,
    Shutdown
};

// Main application class - orchestrates all subsystems
class Application {
public:
    static Application& Instance();
    
    // Lifecycle
    bool Initialize(const AppConfig& config = AppConfig());
    bool Shutdown();
    
    // Main loop
    int Run();
    void Quit(int exitCode = 0);
    
    // Subsystem access
    Extensions::ExtensionHost* GetExtensionHost() { return extensionHost_.get(); }
    Workspace::WorkspaceManager* GetWorkspaceManager() { return workspaceManager_.get(); }
    Tasks::TaskRunner* GetTaskRunner() { return taskRunner_.get(); }
    Settings::SettingsManager* GetSettingsManager() { return settingsManager_.get(); }
    LSP::LspClient* GetLspClient() { return lspClient_.get(); }
    Debugger::DAPAdapter* GetDebugger() { return debugger_.get(); }
    Terminal::EmbeddedTerminal* GetTerminal() { return terminal_.get(); }
    VCS::GitIntegration* GetGitIntegration() { return gitIntegration_.get(); }
    
    // State
    AppState GetState() const { return state_; }
    bool IsReady() const { return state_ == AppState::Ready || state_ == AppState::Running; }
    
    // Configuration
    const AppConfig& GetConfig() const { return config_; }
    void UpdateConfig(const AppConfig& config);
    
    // Events
    using StateChangeCallback = std::function<void(AppState oldState, AppState newState)>;
    void SetStateChangeCallback(StateChangeCallback callback) { stateChangeCallback_ = callback; }
    
    // Workspace operations
    bool OpenWorkspace(const std::string& path);
    bool CloseWorkspace();
    std::string GetCurrentWorkspace() const;
    
    // Command palette
    void ShowCommandPalette();
    void ExecuteCommand(const std::string& command);
    
    // Error handling
    void ShowError(const std::string& title, const std::string& message);
    void ShowNotification(const std::string& message, int timeoutMs = 3000);
    
private:
    Application() = default;
    ~Application() = default;
    
    bool InitializeSubsystems();
    bool InitializeUI();
    bool InitializeExtensions();
    void SetState(AppState state);
    
    AppConfig config_;
    AppState state_ = AppState::Uninitialized;
    int exitCode_ = 0;
    
    // Subsystems
    std::unique_ptr<Extensions::ExtensionHost> extensionHost_;
    std::unique_ptr<Workspace::WorkspaceManager> workspaceManager_;
    std::unique_ptr<Tasks::TaskRunner> taskRunner_;
    std::unique_ptr<Settings::SettingsManager> settingsManager_;
    std::unique_ptr<LSP::LspClient> lspClient_;
    std::unique_ptr<Debugger::DAPAdapter> debugger_;
    std::unique_ptr<Terminal::EmbeddedTerminal> terminal_;
    std::unique_ptr<VCS::GitIntegration> gitIntegration_;
    
    StateChangeCallback stateChangeCallback_;
    
    std::string currentWorkspace_;
};

// Convenience macros
#define g_App RawrXD::Application::Instance()
#define g_Extensions RawrXD::Application::Instance().GetExtensionHost()
#define g_Workspace RawrXD::Application::Instance().GetWorkspaceManager()
#define g_Tasks RawrXD::Application::Instance().GetTaskRunner()
#define g_Settings RawrXD::Application::Instance().GetSettingsManager()
#define g_LSP RawrXD::Application::Instance().GetLspClient()
#define g_Debugger RawrXD::Application::Instance().GetDebugger()
#define g_Terminal RawrXD::Application::Instance().GetTerminal()
#define g_Git RawrXD::Application::Instance().GetGitIntegration()

} // namespace RawrXD