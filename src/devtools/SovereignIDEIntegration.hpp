// Phase D.8 Batch 3/5: IDE Integration
// VS Code Extension and Language Server
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace Sovereign {
namespace DevTools {

// ============================================================================
// Language Server Protocol (LSP) Types
// ============================================================================

struct Position {
    int line = 0;
    int character = 0;
};

struct Range {
    Position start;
    Position end;
};

struct Location {
    std::string uri;
    Range range;
};

struct TextDocument {
    std::string uri;
    std::string language_id;
    int version = 0;
    std::string text;
};

struct Diagnostic {
    Range range;
    int severity = 0;  // 1=Error, 2=Warning, 3=Information, 4=Hint
    std::string code;
    std::string source;
    std::string message;
    std::vector<std::string> related_information;
};

struct CompletionItem {
    std::string label;
    int kind = 0;  // 1=Text, 2=Method, 3=Function, etc.
    std::string detail;
    std::string documentation;
    std::string insert_text;
    Range text_edit;
};

struct SymbolInformation {
    std::string name;
    int kind = 0;
    Location location;
    std::string container_name;
};

// ============================================================================
// Language Server
// ============================================================================

class LanguageServer {
public:
    struct Config {
        std::string server_name = "sovereign-ls";
        std::string version = "1.0.0";
        int max_diagnostics = 100;
        bool enable_completion = true;
        bool enable_hover = true;
        bool enable_definition = true;
        bool enable_references = true;
        bool enable_formatting = true;
        bool enable_diagnostics = true;
    };
    
    explicit LanguageServer(const Config& config);
    ~LanguageServer();
    
    bool Initialize();
    void Shutdown();
    void Run();
    
    // LSP Methods
    void OnInitialize(const std::map<std::string, std::string>& params);
    void OnInitialized();
    void OnShutdown();
    void OnExit();
    
    // Text synchronization
    void OnDidOpen(const TextDocument& document);
    void OnDidChange(const std::string& uri, 
                     const std::vector<std::pair<Range, std::string>>& changes);
    void OnDidClose(const std::string& uri);
    void OnDidSave(const std::string& uri);
    
    // Language features
    std::vector<CompletionItem> OnCompletion(const std::string& uri, Position position);
    std::string OnHover(const std::string& uri, Position position);
    std::vector<Location> OnDefinition(const std::string& uri, Position position);
    std::vector<Location> OnReferences(const std::string& uri, Position position, bool include_declaration);
    std::vector<SymbolInformation> OnDocumentSymbol(const std::string& uri);
    std::vector<SymbolInformation> OnWorkspaceSymbol(const std::string& query);
    std::vector<TextEdit> OnFormatting(const std::string& uri, const FormattingOptions& options);
    
    // Diagnostics
    void PublishDiagnostics(const std::string& uri, const std::vector<Diagnostic>& diagnostics);
    void ClearDiagnostics(const std::string& uri);
    
    // Workspace
    void OnDidChangeWorkspaceFolders(const std::vector<std::string>& added,
                                     const std::vector<std::string>& removed);
    void OnDidChangeConfiguration(const std::map<std::string, std::string>& settings);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    struct DocumentState {
        TextDocument document;
        std::vector<Diagnostic> diagnostics;
        std::chrono::steady_clock::time_point last_analyzed;
    };
    
    std::map<std::string, DocumentState> open_documents_;
    std::mutex documents_mutex_;
    
    std::vector<std::string> workspace_folders_;
    
    void ProcessMessage(const std::string& json_rpc);
    void SendResponse(const std::string& id, const std::string& result);
    void SendNotification(const std::string& method, const std::string& params);
    
    std::vector<Diagnostic> AnalyzeDocument(const std::string& uri);
    std::vector<CompletionItem> GetCompletions(const std::string& uri, Position position);
};

// ============================================================================
// VS Code Extension API
// ============================================================================

class VSCodeExtension {
public:
    struct Config {
        std::string extension_id = "rawrxd.sovereign";
        std::string display_name = "Sovereign";
        std::string version = "1.0.0";
        std::string publisher = "RawrXD";
        std::vector<std::string> activation_events;
        std::map<std::string, std::string> contributes;
    };
    
    // Extension lifecycle
    bool Activate();
    void Deactivate();
    bool IsActive() const;
    
    // Commands
    using CommandHandler = std::function<void(const std::vector<std::string>& args)>;
    bool RegisterCommand(const std::string& command_id, CommandHandler handler);
    bool ExecuteCommand(const std::string& command_id, const std::vector<std::string>& args);
    
    // Tree views
    struct TreeItem {
        std::string id;
        std::string label;
        std::string description;
        std::string tooltip;
        std::string icon;
        std::string context_value;
        bool collapsible = false;
        std::vector<TreeItem> children;
        Command command;
    };
    
    using TreeDataProvider = std::function<std::vector<TreeItem>(const std::string& element_id)>;
    bool RegisterTreeDataProvider(const std::string& view_id, TreeDataProvider provider);
    void RefreshTree(const std::string& view_id);
    
    // Webviews
    struct WebviewPanel {
        std::string view_type;
        std::string title;
        std::string html;
        std::map<std::string, std::string> scripts;
        std::map<std::string, std::string> styles;
    };
    
    bool CreateWebviewPanel(const WebviewPanel& panel);
    void PostMessageToWebview(const std::string& view_type, const std::string& message);
    void OnWebviewMessage(const std::string& view_type, 
                          std::function<void(const std::string& message)> handler);
    
    // Status bar
    bool CreateStatusBarItem(const std::string& id, const std::string& text, 
                             int priority = 0);
    bool UpdateStatusBarItem(const std::string& id, const std::string& text);
    bool HideStatusBarItem(const std::string& id);
    
    // Notifications
    void ShowInformationMessage(const std::string& message);
    void ShowWarningMessage(const std::string& message);
    void ShowErrorMessage(const std::string& message);
    bool ShowQuickPick(const std::string& title, const std::vector<std::string>& items,
                       std::string& selected);
    bool ShowInputBox(const std::string& prompt, std::string& value);
    
    // File system
    std::string ReadFile(const std::string& path);
    bool WriteFile(const std::string& path, const std::string& content);
    bool WatchFile(const std::string& path, std::function<void(const std::string& event)> handler);
    
    // Terminal
    std::string CreateTerminal(const std::string& name, const std::string& shell_path = "");
    void SendTextToTerminal(const std::string& terminal_id, const std::string& text);
    void ShowTerminal(const std::string& terminal_id);
    
private:
    Config config_;
    std::atomic<bool> active_{false};
    
    std::map<std::string, CommandHandler> commands_;
    std::map<std::string, TreeDataProvider> tree_providers_;
    std::map<std::string, WebviewPanel> webviews_;
};

// ============================================================================
// Debug Adapter
// ============================================================================

class DebugAdapter {
public:
    struct Config {
        std::string type = "sovereign";
        std::string request = "launch";
        std::string name;
        std::string program;
        std::vector<std::string> args;
        std::map<std::string, std::string> env;
        std::string cwd;
        bool stop_on_entry = false;
    };
    
    struct Thread {
        int id = 0;
        std::string name;
    };
    
    struct StackFrame {
        int id = 0;
        std::string name;
        std::string source;
        int line = 0;
        int column = 0;
    };
    
    struct Variable {
        std::string name;
        std::string value;
        std::string type;
        std::vector<Variable> children;
    };
    
    struct Breakpoint {
        std::string source;
        int line = 0;
        std::string condition;
        bool enabled = true;
        std::string id;
    };
    
    bool Initialize();
    void Shutdown();
    
    // Launch/Attach
    bool Launch(const Config& config);
    bool Attach(const std::string& process_id);
    bool Disconnect();
    
    // Execution control
    bool Continue(int thread_id);
    bool Pause(int thread_id);
    bool StepOver(int thread_id);
    bool StepInto(int thread_id);
    bool StepOut(int thread_id);
    
    // Breakpoints
    std::string SetBreakpoint(const Breakpoint& breakpoint);
    bool RemoveBreakpoint(const std::string& breakpoint_id);
    bool UpdateBreakpoint(const std::string& breakpoint_id, const Breakpoint& breakpoint);
    std::vector<Breakpoint> GetBreakpoints();
    
    // Inspection
    std::vector<Thread> GetThreads();
    std::vector<StackFrame> GetStackTrace(int thread_id);
    std::vector<Variable> GetVariables(const std::string& variables_reference);
    Variable Evaluate(const std::string& expression, int frame_id = 0);
    
    // Events
    using StoppedHandler = std::function<void(int thread_id, const std::string& reason)>;
    using BreakpointHandler = std::function<void(const std::string& breakpoint_id, bool verified)>;
    using OutputHandler = std::function<void(const std::string& category, const std::string& output)>;
    using TerminatedHandler = std::function<void()>;
    
    void OnStopped(StoppedHandler handler);
    void OnBreakpoint(BreakpointHandler handler);
    void OnOutput(OutputHandler handler);
    void OnTerminated(TerminatedHandler handler);
    
private:
    Config config_;
    std::atomic<bool> connected_{false};
    
    std::vector<Breakpoint> breakpoints_;
    std::mutex breakpoints_mutex_;
    
    StoppedHandler on_stopped_;
    BreakpointHandler on_breakpoint_;
    OutputHandler on_output_;
    TerminatedHandler on_terminated_;
    
    void DebugEventLoop();
};

// ============================================================================
// IDE Runtime
// ============================================================================

class IDERuntime {
public:
    struct Config {
        LanguageServer::Config language_server;
        VSCodeExtension::Config vscode_extension;
        DebugAdapter::Config debug_adapter;
        bool enable_language_server = true;
        bool enable_vscode_extension = true;
        bool enable_debug_adapter = true;
    };
    
    explicit IDERuntime(const Config& config);
    ~IDERuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Language server
    LanguageServer* GetLanguageServer();
    
    // VS Code extension
    VSCodeExtension* GetVSCodeExtension();
    
    // Debug adapter
    DebugAdapter* GetDebugAdapter();
    
    // Unified features
    bool StartLanguageServer(int port = 8080);
    bool StartDebugServer(int port = 8081);
    
private:
    Config config_;
    std::unique_ptr<LanguageServer> language_server_;
    std::unique_ptr<VSCodeExtension> vscode_extension_;
    std::unique_ptr<DebugAdapter> debug_adapter_;
};

} // namespace DevTools
} // namespace Sovereign
