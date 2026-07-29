// ============================================================================
// IDEEngine.h - RawrXD IDE Core Integration Layer
// ============================================================================
// Orchestrates all production components: Editor, LSP, Git, Debugger, Terminal
// ============================================================================

#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

// Forward declarations from all subsystems
namespace RawrXD {
    namespace Editor { class ScintillaEditor; }
    namespace LSP { class LSPClient; }
    namespace SCM { class GitIntegration; }
    namespace Debugger { class DebuggerCore; }
    namespace Terminal { class ANSITerminalRenderer; }
    namespace Agentic { class AgenticToolIntegration; }
    namespace Model { class GGUFLoader; }
}

namespace RawrXD {
namespace Core {

// IDE Configuration
struct IDEConfig {
    // Paths
    std::string workspaceRoot;
    std::string gitPath;
    std::string clangdPath;
    std::string buildDir;
    
    // Editor settings
    std::string fontName = "Consolas";
    int fontSize = 11;
    bool wordWrap = false;
    bool showLineNumbers = true;
    bool showWhitespace = false;
    
    // LSP settings
    bool enableLSP = true;
    std::vector<std::string> lspArgs;
    
    // Terminal settings
    int terminalRows = 24;
    int terminalCols = 80;
    
    // Security
    std::vector<std::string> allowedToolDirs;
};

// Document state
struct Document {
    std::string path;
    std::string language;
    bool modified = false;
    bool readOnly = false;
    std::chrono::system_clock::time_point lastModified;
    void* editorHandle = nullptr;  // Scintilla handle
};

// Build configuration
struct BuildConfig {
    std::string name;
    std::string command;
    std::string workingDir;
    std::vector<std::string> envVars;
    bool captureOutput = true;
};

// IDE Event types
enum class IDEEventType {
    None,
    DocumentOpened,
    DocumentClosed,
    DocumentModified,
    DocumentSaved,
    BuildStarted,
    BuildFinished,
    DebugStarted,
    DebugStopped,
    BreakpointHit,
    GitStatusChanged,
    LSPConnected,
    LSPDisconnected,
    TerminalOutput,
    AgenticToolExecuted
};

// IDE Event
struct IDEEvent {
    IDEEventType type = IDEEventType::None;
    std::string documentPath;
    int line = 0;
    int column = 0;
    std::string message;
    bool success = false;
    int exitCode = 0;
};

// Callback types
using IDEEventCallback = std::function<void(const IDEEvent& event)>;
using DocumentCallback = std::function<void(const Document& doc)>;
using BuildOutputCallback = std::function<void(const std::string& output, bool isError)>;
using DebugEventCallback = std::function<void(const std::string& eventType, const std::string& data)>;

// ============================================================================
// IDEEngine - Central Integration Hub
// ============================================================================

class IDEEngine {
public:
    IDEEngine();
    ~IDEEngine();

    // Lifecycle
    bool Initialize(const IDEConfig& config);
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }

    // Configuration
    void SetConfig(const IDEConfig& config);
    const IDEConfig& GetConfig() const { return m_config; }

    // ============================================================================
    // Document Management
    // ============================================================================
    
    // Open/close documents
    bool OpenDocument(const std::string& path);
    bool OpenDocument(const std::string& path, void* editorHwnd);
    bool CloseDocument(const std::string& path);
    bool CloseAllDocuments();
    
    // Document queries
    bool IsDocumentOpen(const std::string& path) const;
    Document* GetDocument(const std::string& path);
    std::vector<Document*> GetOpenDocuments();
    Document* GetActiveDocument();
    void SetActiveDocument(const std::string& path);
    
    // Document operations
    bool SaveDocument(const std::string& path);
    bool SaveAllDocuments();
    bool ReloadDocument(const std::string& path);
    
    // Editor integration
    void* GetEditorHandle(const std::string& path);
    bool SetEditorContent(const std::string& path, const std::string& content);
    std::string GetEditorContent(const std::string& path);
    bool EditorInsertText(const std::string& path, int pos, const std::string& text);
    bool EditorDeleteText(const std::string& path, int start, int end);
    int EditorGetLength(const std::string& path);
    void EditorGotoLine(const std::string& path, int line);
    void EditorSetSelection(const std::string& path, int start, int end);

    // ============================================================================
    // LSP Integration
    // ============================================================================
    
    bool StartLSP(const std::string& language, const std::string& command);
    void StopLSP();
    bool IsLSPConnected() const;
    
    // LSP operations
    bool LSPDidOpen(const std::string& path);
    bool LSPDidChange(const std::string& path);
    bool LSPDidClose(const std::string& path);
    bool LSPDidSave(const std::string& path);
    void LSPRequestCompletion(const std::string& path, int line, int col);
    void LSPRequestHover(const std::string& path, int line, int col);
    void LSPRequestSignature(const std::string& path, int line, int col);
    void LSPGoToDefinition(const std::string& path, int line, int col);

    // ============================================================================
    // Git Integration
    // ============================================================================
    
    bool InitializeGit();
    bool IsGitRepo() const;
    
    // Git operations
    std::string GetGitBranch() const;
    int GetGitAheadCount() const;
    int GetGitBehindCount() const;
    bool GitStageFile(const std::string& path);
    bool GitUnstageFile(const std::string& path);
    bool GitCommit(const std::string& message);
    bool GitDiscardFile(const std::string& path);
    bool GitFetch();
    bool GitPull();
    bool GitPush();
    
    // Git queries
    std::string GetGitStatusJson() const;
    std::string GetGitDiff(const std::string& path, bool staged) const;
    std::string GetGitBlame(const std::string& path, int line) const;
    std::string GetGitLog(int maxCount) const;

    // ============================================================================
    // Debugger Integration
    // ============================================================================
    
    bool StartDebugger();
    void StopDebugger();
    bool IsDebugging() const;
    
    // Debug operations
    bool DebugLaunch(const std::string& executable, const std::string& args);
    bool DebugAttach(uint32_t pid);
    bool DebugDetach();
    bool DebugContinue();
    bool DebugStepInto();
    bool DebugStepOver();
    bool DebugStepOut();
    bool DebugBreak();
    
    // Breakpoints
    std::string DebugSetBreakpoint(const std::string& file, int line);
    std::string DebugSetBreakpointAddr(uint64_t address);
    bool DebugRemoveBreakpoint(const std::string& id);
    bool DebugEnableBreakpoint(const std::string& id, bool enable);
    std::string DebugGetBreakpointsJson() const;
    
    // Debug queries
    std::string DebugGetCallStackJson() const;
    std::string DebugGetLocalVariablesJson() const;
    std::string DebugGetThreadsJson() const;
    std::string DebugGetModulesJson() const;
    std::vector<uint8_t> DebugReadMemory(uint64_t address, size_t size);
    bool DebugWriteMemory(uint64_t address, const std::vector<uint8_t>& data);

    // ============================================================================
    // Terminal Integration
    // ============================================================================
    
    bool InitializeTerminal(void* hwnd);
    void ShutdownTerminal();
    bool IsTerminalReady() const;
    
    // Terminal operations
    void TerminalProcessOutput(const char* data, int len);
    void TerminalRender(HDC hdc);
    void TerminalResize(int width, int height);
    void TerminalScrollUp(int lines);
    void TerminalScrollDown(int lines);
    void TerminalClear();
    int TerminalGetCols() const;
    int TerminalGetRows() const;

    // ============================================================================
    // Agentic Tools Integration
    // ============================================================================
    
    bool InitializeAgenticTools();
    
    // Tool execution
    std::string ExecuteTool(const std::string& toolName, const std::string& jsonParams);
    std::string ExecuteToolAsync(const std::string& toolName, const std::string& jsonParams);
    bool CanUndoTool(const std::string& executionId);
    bool UndoTool(const std::string& executionId);
    std::string GetToolExecutionReport(const std::string& executionId);
    std::string GetAvailableToolsJson() const;

    // ============================================================================
    // Build System Integration
    // ============================================================================
    
    bool StartBuild(const BuildConfig& config);
    bool StopBuild();
    bool IsBuilding() const;
    int GetBuildExitCode() const;

    // ============================================================================
    // Event Handling
    // ============================================================================
    
    void SetEventCallback(IDEEventCallback callback);
    void SetBuildOutputCallback(BuildOutputCallback callback);
    void SetDebugEventCallback(DebugEventCallback callback);
    
    // Event triggering (for internal use)
    void FireEvent(const IDEEvent& event);

    // ============================================================================
    // C API for External Integration
    // ============================================================================
    
    static void* Create();
    static void Destroy(void* instance);
    static int Initialize(void* instance, const char* workspaceRoot);
    static void Shutdown(void* instance);
    
    static int OpenDocument(void* instance, const char* path);
    static int CloseDocument(void* instance, const char* path);
    static int SaveDocument(void* instance, const char* path);
    static int GetOpenDocuments(void* instance, char* buffer, int bufferSize);
    
    static int GitStageFile(void* instance, const char* path);
    static int GitCommit(void* instance, const char* message);
    static const char* GitGetStatus(void* instance);
    
    static int DebugLaunch(void* instance, const char* executable, const char* args);
    static int DebugStepInto(void* instance);
    static int DebugStepOver(void* instance);
    static int DebugSetBreakpoint(void* instance, const char* file, int line);
    static const char* DebugGetCallStack(void* instance);
    
    static const char* ExecuteTool(void* instance, const char* toolName, const char* jsonParams);
    static int UndoTool(void* instance, const char* executionId);

private:
    bool m_initialized = false;
    IDEConfig m_config;
    std::string m_activeDocument;
    
    // Subsystem instances
    std::unique_ptr<Editor::ScintillaEditor> m_editor;
    std::unique_ptr<LSP::LSPClient> m_lspClient;
    std::unique_ptr<SCM::GitIntegration> m_git;
    std::unique_ptr<Debugger::DebuggerCore> m_debugger;
    std::unique_ptr<Terminal::ANSITerminalRenderer> m_terminal;
    std::unique_ptr<Agentic::AgenticToolIntegration> m_agenticTools;
    
    // Document management
    std::unordered_map<std::string, std::unique_ptr<Document>> m_documents;
    
    // Build state
    HANDLE m_buildProcess = nullptr;
    HANDLE m_buildThread = nullptr;
    int m_buildExitCode = 0;
    bool m_isBuilding = false;
    
    // Callbacks
    IDEEventCallback m_eventCallback;
    BuildOutputCallback m_buildOutputCallback;
    DebugEventCallback m_debugEventCallback;
    
    // Internal helpers
    void SetupLSPCallbacks();
    void SetupGitCallbacks();
    void SetupDebuggerCallbacks();
    void SetupTerminalCallbacks();
    void SetupAgenticCallbacks();
    
    std::string GetLanguageFromExtension(const std::string& path);
    std::string EscapeJson(const std::string& str);
    
    // Build thread
    static DWORD WINAPI BuildThreadProc(LPVOID param);
    void BuildLoop(const BuildConfig& config);
};

// ============================================================================
// C API
// ============================================================================

extern "C" {
    void* RawrXD_IDE_Create();
    void RawrXD_IDE_Destroy(void* instance);
    int RawrXD_IDE_Initialize(void* instance, const char* workspaceRoot);
    void RawrXD_IDE_Shutdown(void* instance);
    
    int RawrXD_IDE_OpenDocument(void* instance, const char* path);
    int RawrXD_IDE_CloseDocument(void* instance, const char* path);
    int RawrXD_IDE_SaveDocument(void* instance, const char* path);
    
    int RawrXD_IDE_GitStage(void* instance, const char* path);
    int RawrXD_IDE_GitCommit(void* instance, const char* message);
    const char* RawrXD_IDE_GitStatus(void* instance);
    
    int RawrXD_IDE_DebugLaunch(void* instance, const char* executable, const char* args);
    int RawrXD_IDE_DebugStepInto(void* instance);
    int RawrXD_IDE_DebugStepOver(void* instance);
    int RawrXD_IDE_DebugSetBreakpoint(void* instance, const char* file, int line);
    const char* RawrXD_IDE_DebugGetCallStack(void* instance);
    
    const char* RawrXD_IDE_ExecuteTool(void* instance, const char* toolName, const char* jsonParams);
    int RawrXD_IDE_UndoTool(void* instance, const char* executionId);
    
    int RawrXD_IDE_BuildStart(void* instance, const char* command);
    int RawrXD_IDE_BuildStop(void* instance);
    int RawrXD_IDE_IsBuilding(void* instance);
}

} // namespace Core
} // namespace RawrXD
