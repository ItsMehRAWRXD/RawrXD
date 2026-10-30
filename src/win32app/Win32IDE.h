#pragma once

#include <windows.h>

// ---------------------------------------------------------------------------
// Document tab strip (VS Code style). IDC_DOC_TABS identifies the control in
// WM_COMMAND/WM_NOTIFY; DOC_TAB_HEIGHT is the tab bar height used by the window
// layout so the editor is positioned below it. Declared here because both the
// lifecycle TU (which owns the WindowProc) and the main TU create/reference it.
// ---------------------------------------------------------------------------
#ifndef IDC_DOC_TABS
#define IDC_DOC_TABS 1030
#endif
#ifndef DOC_TAB_HEIGHT
#define DOC_TAB_HEIGHT 26
#endif

// Activity-bar IDs are shared by the VS Code-style UI implementation and the
// lifecycle command router.  Keep them in the common header so the live
// startup path can route activity-bar clicks without relying on TU-local
// defines.
#ifndef IDC_ACTIVITY_BAR
#define IDC_ACTIVITY_BAR 1100
#endif
#ifndef IDC_ACTBAR_EXPLORER
#define IDC_ACTBAR_EXPLORER 1101
#endif
#ifndef IDC_ACTBAR_SEARCH
#define IDC_ACTBAR_SEARCH 1102
#endif
#ifndef IDC_ACTBAR_SCM
#define IDC_ACTBAR_SCM 1103
#endif
#ifndef IDC_ACTBAR_DEBUG
#define IDC_ACTBAR_DEBUG 1104
#endif
#ifndef IDC_ACTBAR_EXTENSIONS
#define IDC_ACTBAR_EXTENSIONS 1105
#endif
#ifndef IDC_ACTBAR_SETTINGS
#define IDC_ACTBAR_SETTINGS 1106
#endif
#ifndef IDC_ACTBAR_ACCOUNTS
#define IDC_ACTBAR_ACCOUNTS 1107
#endif
#ifndef IDC_TITLE_TEXT
#define IDC_TITLE_TEXT 1018
#endif

// Chat session tabs are created by Win32IDE.cpp but their TCN_SELCHANGE
// notification is owned by the lifecycle/window-procedure translation unit.
// Keep the control ID in the shared header so both translation units use the
// same routing contract.
#ifndef IDC_CHAT_SESSIONS
#define IDC_CHAT_SESSIONS 1208
#endif
#ifndef IDC_NEW_CHAT
#define IDC_NEW_CHAT 1209
#endif
#ifndef IDC_CLOSE_CHAT
#define IDC_CLOSE_CHAT 1214
#endif
#ifndef IDC_RESTORE_CHAT
#define IDC_RESTORE_CHAT 1215
#endif
#ifndef IDC_ROLLBACK_CHAT
#define IDC_ROLLBACK_CHAT 1216
#endif
#ifndef IDC_COPILOT_REASONING_SELECTOR
#define IDC_COPILOT_REASONING_SELECTOR 1217
#endif
#ifndef IDC_COPILOT_WEB_BROWSE
#define IDC_COPILOT_WEB_BROWSE 1218
#endif
#ifndef IDC_COPILOT_MAX_TOKENS_SELECTOR
#define IDC_COPILOT_MAX_TOKENS_SELECTOR 1219
#endif
#ifndef IDC_COPILOT_CONTEXT_SELECTOR
#define IDC_COPILOT_CONTEXT_SELECTOR 1220
#endif

// Undefine Windows macros that conflict with our code
#ifdef ERROR
#undef ERROR
#endif

#include <commctrl.h>
#include <shlobj.h>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include "IDELogger.h"
#include "Win32TerminalManager.h"
#include "TransparentRenderer.h"
#include "gguf_loader.h"
#include "streaming_gguf_loader.h"
#include "cpu_inference_engine.h"
#include "Win32IDE_AgenticBridge.h"
#include "Win32IDE_Autonomy.h"
#include "Win32IDE_AgenticLoopBridge.h"
#include "agent_esp.hpp"
#include "Win32IDE_GhostText.h"

// Forward declaration for Deep2Bridge
class Deep2Bridge;

struct ChatModelEntry {
    enum class Source {
        LocalFile,
        Ollama,
        KiloFree
    };

    Source source = Source::LocalFile;
    std::string breadcrumb;
    std::string identifier;
};

// Discovery results are fenced to the UI request that created them.  The
// generation is carried with the owned payload so a queued WM_APP+106 from an
// older worker can never overwrite a newer model catalog.
struct ModelDiscoveryPayload {
    uint64_t generationID = 0;
    std::vector<ChatModelEntry> models;
    // The first payload replaces the old discovered catalog; later scoped
    // payloads merge into it so the fast Ollama catalog is never regressed
    // while local GGUF scanning finishes.
    bool mergeOnly = false;
};

enum class GhostTextMode { Disabled, AutoLocal, FollowChat, Independent };

// Ollama's native API currently exposes reasoning as a boolean on the
// /api/generate route.  These UI modes are deliberately client-side policies:
// Instant disables reasoning; the remaining levels enable it and reserve a
// bounded amount of the generation budget for the model's thinking stream.
// This keeps the control honest across Ollama versions instead of sending
// unsupported provider-specific strings such as "high" to /api/generate.
enum class ReasoningMode { Instant, Low, Medium, High, Max };

struct ChatSessionCheckpoint {
    std::string reason;
    ChatModelEntry model;
    ChatModelEntry ghostTextModel;
    GhostTextMode ghostTextMode = GhostTextMode::AutoLocal;
    ReasoningMode reasoningMode = ReasoningMode::Instant;
    bool allowCloudGhostText = false;
    bool webBrowsingEnabled = false;
    int maxTokens = 4096;
    int contextTokens = 65536;
    std::vector<std::pair<std::string, std::string>> history;
    std::string responseBuffer;
};

// A chat session owns its route, transcript, and bounded rollback history
// independently. The workspace/file snapshot system remains separate: chat
// rollback never writes or restores project files.
struct ChatSessionState {
    int id = 0;
    std::string title;
    ChatModelEntry model;
    std::vector<std::pair<std::string, std::string>> history;
    std::string responseBuffer;
    bool running = false;
    ReasoningMode reasoningMode = ReasoningMode::Instant;
    bool webBrowsingEnabled = false;
    std::vector<ChatSessionCheckpoint> checkpoints;
};

// Inference workers post owned updates to the UI thread instead of touching
// Win32 controls or chat-session containers directly.
struct CopilotChatUiUpdate {
    int sessionId = 0;
    std::string response;
    bool complete = false;
};

inline constexpr UINT kRawrxdCopilotUiUpdate = WM_APP + 107;

// Dedicated PowerShell terminal callbacks originate on reader/monitor threads.
// Own the payload and marshal it through the main window before touching any
// RichEdit or status-bar control.
struct PowerShellUiUpdate {
    enum class Kind { Output, Error, Finished };
    Kind kind = Kind::Output;
    std::string text;
    COLORREF color = RGB(200, 200, 200);
    int exitCode = 0;
};

inline constexpr UINT kRawrxdPowerShellUiUpdate = WM_APP + 108;

// Define LOG_FUNCTION macro if not already defined
#ifndef LOG_FUNCTION
#define LOG_FUNCTION() LOG_DEBUG(std::string("ENTER ") + __FUNCTION__)
#endif
#include "Win32TerminalManager.h"
#include "TransparentRenderer.h"
#include "gguf_loader.h"
#include "streaming_gguf_loader.h"

// Theme and customization structures
struct IDETheme {
    COLORREF backgroundColor;
    COLORREF textColor;
    COLORREF keywordColor;
    COLORREF commentColor;
    COLORREF stringColor;
    COLORREF numberColor;
    COLORREF operatorColor;
    COLORREF selectionColor;
    COLORREF lineNumberColor;
    std::string fontName;
    int fontSize;
    bool darkMode;
};

struct CodeSnippet {
    std::string name;
    std::string description;
    std::string code;
    std::string trigger;
    std::vector<std::string> placeholders;
};

struct ModuleInfo {
    std::string name;
    std::string version;
    std::string description;
    std::string path;
    bool loaded;
};

struct TerminalPane {
    int id;
    HWND hwnd;
    HWND input = nullptr;
    HWND execute = nullptr;
    HWND stop = nullptr;
    HWND clear = nullptr;
    std::unique_ptr<Win32TerminalManager> manager;
    std::string name;
    Win32TerminalManager::ShellType shellType;
    bool isActive;
    RECT bounds;
};

struct GitStatus {
    std::string branch;
    int ahead;
    int behind;
    int modified;
    int added;
    int deleted;
    int untracked;
    bool hasChanges;
    std::string lastCommit;
    std::string lastCommitMessage;
};

struct GitFile {
    std::string path;
    char status;  // M=modified, A=added, D=deleted, ?=untracked
    bool staged;
};

struct FileExplorerItem {
    std::string name;
    std::string fullPath;
    bool isDirectory;
    bool isModelFile;
    size_t fileSize;
    HTREEITEM hTreeItem;
    std::vector<FileExplorerItem> children;
};

struct Breakpoint {
    std::string file;
    int line;
    bool enabled;
    std::string condition;
    int hitCount;
};

struct StackFrame {
    std::string function;
    std::string file;
    int line;
    std::map<std::string, std::string> locals;
};

struct Variable {
    std::string name;
    std::string value;
    std::string type;
    bool expanded;
    std::vector<Variable> children;
};

struct WatchItem {
    std::string expression;
    std::string value;
    std::string type;
    bool enabled;
};

class Win32IDE
{
public:
    enum class OutputSeverity {
        Debug = 0,
        Info = 1,
        Warning = 2,
        Error = 3
    };

    Win32IDE(HINSTANCE hInstance);
    ~Win32IDE();

    bool createWindow();
    void showWindow();
    int runMessageLoop();
    bool loadModelForInference(const std::string& filepath);

    // Test agent access
    HWND getMainWindow() const { return m_hwndMain; }
    void runNativeCodexPrompt(const std::string& prompt);
    void requestNativeGhostText(const std::string& prompt,
                                std::function<void(const std::string&, bool, bool)> callback);
    void appendNativeDebugOutput(const std::string& text, bool error = false);

    // Agentic Framework
    std::unique_ptr<AgenticBridge> m_agenticBridge;
    void initializeAgenticBridge();
    void onAgentStartLoop();
    void onAgentExecuteCommand();
    void onAgentConfigureModel();
    void onAgentViewTools();
    void onAgentViewStatus();
    void onAgentStop();

    // Deep2 Inference Bridge (GPU-accelerated)
    Deep2Bridge* m_deep2Bridge = nullptr;
    void initializeDeep2Bridge();
    void onDeep2LoadModel();
    void onDeep2Generate();
    void onDeep2Cancel();
    void onDeep2ModelInfo();
    void onDeep2Configure();

    // Agentic Loop Bridge (connects to deep2_agentic_loop.exe)
    std::unique_ptr<AgenticLoopBridge> m_agenticLoopBridge;
    // Chat session receiving the canonical CLI agent's streamed stdout/stderr.
    // Keeping the origin session explicit prevents a later chat-tab switch
    // from attaching agent output to the wrong conversation.
    int m_agenticChatSessionId = 0;
    void initializeAgenticLoopBridge();
    void onAgenticLoopRunTask();
    void onAgenticLoopCancel();
    void onAgenticLoopStatus();

    // Autonomy Framework Controls
    std::unique_ptr<AutonomyManager> m_autonomyManager; // high-level autonomous orchestrator
    void onAutonomyStart();
    void onAutonomyStop();
    void onAutonomyToggle();
    void onAutonomySetGoal();
    void onAutonomyViewStatus();
    void onAutonomyViewMemory();

    // Comprehensive Logging System
    void initializeLogging();
    void shutdownLogging();
    void logMessage(const std::string& category, const std::string& message);
    void logFunction(const std::string& functionName);
    void logError(const std::string& functionName, const std::string& error);
    void logWarning(const std::string& functionName, const std::string& warning);
    void logInfo(const std::string& message);
    void logWindowCreate(const std::string& windowName, HWND hwnd);
    void logWindowDestroy(const std::string& windowName, HWND hwnd);
    void logFileOperation(const std::string& operation, const std::string& filePath, bool success);
    void logUIEvent(const std::string& event, const std::string& details);

private:
    // Window procedure
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK AgentModelDialogProc(HWND hwnd, UINT uMsg,
                                                 WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK ModelSelectorSubclassProc(HWND hwnd, UINT uMsg,
                                                       WPARAM wParam, LPARAM lParam,
                                                       UINT_PTR subclassId,
                                                       DWORD_PTR refData);
    void installModelSelectorProc(HWND combo);

    // Message handlers
    LRESULT handleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void onCreate(HWND hwnd);
    void onDestroy();
    void onSize(int width, int height);
    void onCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify);
    void onTerminalOutput(int paneId, const std::string& output);
    void onTerminalError(int paneId, const std::string& error);

    // UI creation
    void createMenuBar(HWND hwnd);
    void createToolbar(HWND hwnd);
    void createSidebar(HWND hwnd);
    void createTitleBarControls();
    void layoutTitleBar(int width);
    void updateTitleBarText();
    void updateEditorBreadcrumb();
    std::string extractLeafName(const std::string& path) const;
    void setCurrentDirectoryFromFile(const std::string& filePath);
    void createEditor(HWND hwnd);
    void createTerminal(HWND hwnd);
    void createStatusBar(HWND hwnd);

    // File operations (9 features)
    void newFile();
    void openFile();
    void openFileDialog();
    // Loads a file by path into the editor and registers it as the active
    // document. Used by the document tabs (which must switch buffers without
    // showing the open dialog). Returns false if the file cannot be read.
    bool loadFileIntoEditor(const std::string& path);
    void setEditorText(const std::string& text);
    void openRecentFile(int index);
    bool saveFile();
    bool saveFileAs();
    void saveAll();
    void closeFile();
    bool promptSaveChanges();
    void updateRecentFiles(const std::string& filePath);
    void loadRecentFiles();
    void saveRecentFiles();
    void clearRecentFiles();
    std::string getFileDialogPath(bool isSave = false);
    
    // GGUF Model operations
    bool loadGGUFModel(const std::string& filepath);
    std::string getModelInfo() const;
    bool loadTensorData(const std::string& tensorName, std::vector<uint8_t>& data);
    
    // AI Inference Engine - Local GGUF Model Chat
    struct InferenceConfig {
        int maxTokens = 512;
        float temperature = 0.7f;
        float topP = 0.9f;
        int topK = 40;
        float repetitionPenalty = 1.1f;
        std::string systemPrompt;
        bool streamOutput = true;
    };
    
    bool initializeInference();
    void shutdownInference();
    bool isModelLoaded() const;
    std::string generateResponse(const std::string& prompt);
    void generateResponseAsync(const std::string& prompt,
                               std::function<void(const std::string&, bool, bool)> callback);
    void stopInference();
    void setInferenceConfig(const InferenceConfig& config);
    InferenceConfig getInferenceConfig() const;
    std::string buildChatPrompt(const std::string& userMessage);
    void onInferenceToken(const std::string& token);
    void onInferenceComplete(const std::string& fullResponse);

    // Editor Operations
    void undo();
    void redo();
    void editCut();
    void editCopy();
    void editPaste();
    
    // View Operations
    void toggleOutputPanel();
    void toggleTerminal();
    void showAbout();

    // Terminal operations (original)
    void startPowerShell();
    void startCommandPrompt();
    void stopTerminal();
    void executeCommand();
    
    // ========================================================================
    // FULL POWERSHELL ACCESS - Complete PowerShell Integration
    // ========================================================================
    
    // PowerShell Execution
    std::string executePowerShellScript(const std::string& scriptPath, const std::vector<std::string>& args = {});
    std::string executePowerShellCommand(const std::string& command, bool async = false);
    std::string invokePowerShellCmdlet(const std::string& cmdlet, const std::map<std::string, std::string>& parameters = {});
    
    // PowerShell Pipeline Support
    std::string executePowerShellPipeline(const std::vector<std::string>& commands);
    std::string pipeToPowerShell(const std::string& input, const std::string& command);
    
    // PowerShell Module Management
    std::vector<std::string> getPowerShellModules();
    bool importPowerShellModule(const std::string& moduleName);
    bool removePowerShellModule(const std::string& moduleName);
    std::string getPowerShellModuleInfo(const std::string& moduleName);
    
    // PowerShell Variable Access
    std::string getPowerShellVariable(const std::string& varName);
    bool setPowerShellVariable(const std::string& varName, const std::string& value);
    std::map<std::string, std::string> getAllPowerShellVariables();
    
    // PowerShell Function Invocation
    std::string invokePowerShellFunction(const std::string& functionName, const std::vector<std::string>& args = {});
    bool definePowerShellFunction(const std::string& functionName, const std::string& functionBody);
    std::vector<std::string> listPowerShellFunctions();
    
    // PowerShell Remoting
    bool enterPowerShellRemoteSession(const std::string& computerName, const std::string& credential = "");
    void exitPowerShellRemoteSession();
    std::string invokePowerShellRemoteCommand(const std::string& computerName, const std::string& command);
    
    // PowerShell Object Manipulation
    std::string convertToPowerShellJson(const std::string& object);
    std::string convertFromPowerShellJson(const std::string& json);
    std::string selectPowerShellObject(const std::string& inputObject, const std::vector<std::string>& properties);
    std::string wherePowerShellObject(const std::string& inputObject, const std::string& filter);
    
    // PowerShell Script Analysis
    struct PSScriptAnalysis {
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
        std::vector<std::string> information;
        bool hasErrors;
        int errorCount;
        int warningCount;
    };
    PSScriptAnalysis analyzePowerShellScript(const std::string& scriptPath);
    std::vector<std::string> getPowerShellCommandSyntax(const std::string& cmdlet);
    
    // PowerShell Provider Access
    std::vector<std::string> getPowerShellProviders();
    std::string getPowerShellDrive(const std::string& driveName);
    std::vector<std::string> listPowerShellDrives();
    bool newPowerShellDrive(const std::string& name, const std::string& root, const std::string& provider = "FileSystem");
    
    // PowerShell Job Management
    int startPowerShellJob(const std::string& scriptBlock, const std::string& name = "");
    std::string getPowerShellJobStatus(int jobId);
    std::string receivePowerShellJob(int jobId);
    bool removePowerShellJob(int jobId);
    std::vector<int> listPowerShellJobs();
    bool waitPowerShellJob(int jobId, int timeoutMs = -1);
    
    // PowerShell Transcription
    bool startPowerShellTranscript(const std::string& path);
    bool stopPowerShellTranscript();
    std::string getPowerShellHistory(int count = 100);
    void clearPowerShellHistory();
    
    // PowerShell Debugger Integration
    bool setPowerShellBreakpoint(const std::string& scriptPath, int line);
    bool removePowerShellBreakpoint(int breakpointId);
    std::vector<int> listPowerShellBreakpoints();
    bool enablePowerShellDebugMode();
    void disablePowerShellDebugMode();
    
    // PowerShell Help System
    std::string getPowerShellHelp(const std::string& cmdlet, bool detailed = false, bool examples = false);
    std::vector<std::string> searchPowerShellHelp(const std::string& query);
    std::string getPowerShellAboutTopic(const std::string& topic);
    
    // PowerShell Configuration
    std::string getPowerShellVersion();
    std::string getPowerShellEdition(); // Core or Desktop
    std::string getPowerShellExecutionPolicy();
    bool setPowerShellExecutionPolicy(const std::string& policy);
    std::map<std::string, std::string> getPowerShellEnvironmentVariables();
    bool setPowerShellEnvironmentVariable(const std::string& name, const std::string& value);
    
    // PowerShell Event Handling
    bool registerPowerShellEvent(const std::string& sourceIdentifier, const std::string& eventName, const std::string& action);
    bool unregisterPowerShellEvent(const std::string& sourceIdentifier);
    std::vector<std::string> getPowerShellEvents();
    
    // PowerShell Profile Management
    std::string getPowerShellProfilePath();
    bool editPowerShellProfile();
    bool reloadPowerShellProfile();
    
    // PowerShell Output Formatting
    std::string formatPowerShellTable(const std::string& data, const std::vector<std::string>& properties = {});
    std::string formatPowerShellList(const std::string& data);
    std::string formatPowerShellWide(const std::string& data, int columns = 2);
    std::string formatPowerShellCustom(const std::string& data, const std::string& formatString);
    
    // PowerShell Workflow Integration
    bool importPowerShellWorkflow(const std::string& workflowPath);
    std::string executePowerShellWorkflow(const std::string& workflowName, const std::map<std::string, std::string>& parameters = {});
    
    // Direct RawrXD.ps1 Integration
    bool loadRawrXDPowerShellModule();
    std::string invokeRawrXDFunction(const std::string& functionName, const std::vector<std::string>& args = {});
    std::string getRawrXDAgentTools();
    bool executeRawrXDAgenticCommand(const std::string& command);
    std::string getRawrXDModelStatus();
    bool loadRawrXDGGUFModel(const std::string& modelPath, int maxZoneMB = 512);
    std::string invokeRawrXDInference(const std::string& prompt, int maxTokens = 100);
    
    // Terminal Integration (5 features - Split panes, multiple terminals)
    int createTerminalPane(Win32TerminalManager::ShellType shellType, const std::string& name = "");
    void splitTerminalHorizontal();
    void splitTerminalVertical();
    void switchTerminalPane(int paneId);
    void closeTerminalPane(int paneId);
    void resizeTerminalPanes();
    void clearAllTerminals();
    void sendToAllTerminals(const std::string& command);
    TerminalPane* getActiveTerminalPane();
    void layoutTerminalPanes(int width, int top, int height);
    
    // Git Integration (7 features - Status, commit, push, pull)
    void updateGitStatus();
    void showGitStatus();
    void gitCommit(const std::string& message);
    void gitPush();
    void gitPull();
    void gitStageFile(const std::string& filePath);
    void gitUnstageFile(const std::string& filePath);
    void showGitPanel();
    void refreshGitPanel();
    bool isGitRepository() const;
    std::string getCurrentGitBranch() const;
    std::vector<GitFile> getGitChangedFiles() const;
    bool executeGitCommand(const std::string& command, std::string& output);
    void showCommitDialog(); // simple commit message dialog (Ctrl+Shift+C)
    
    // Menu Command System (25 features)
    void handleFileCommand(int commandId);
    void handleEditCommand(int commandId);
    void handleViewCommand(int commandId);
    void handleTerminalCommand(int commandId);
    void handleToolsCommand(int commandId);
    void handleModulesCommand(int commandId);
    void handleHelpCommand(int commandId);
    
    // Command routing
    bool routeCommand(int commandId);
    void registerCommandHandler(int commandId, std::function<void()> handler);
    std::string getCommandDescription(int commandId) const;
    bool isCommandEnabled(int commandId) const;
    void updateCommandStates();
    void updateMenuEnableStates(); // dynamic enable/disable for Git & terminal items

    // Theme and customization
    void loadTheme(const std::string& themeName);
    void saveTheme(const std::string& themeName);
    void applyTheme();
    void showThemeEditor();
    void resetToDefaultTheme();

    // Code snippets
    void loadCodeSnippets();
    void saveCodeSnippets();
    void insertSnippet(const std::string& trigger);
    void showSnippetManager();
    void createSnippet();

    // Integrated help
    void showGetHelp(const std::string& cmdlet = "");
    void showCommandReference();
    void showPowerShellDocs();
    void searchHelp(const std::string& query);

    // Enhanced output panel
    void createOutputTabs();
    void addOutputTab(const std::string& name);
    void appendToOutput(const std::string& text, const std::string& tabName = "General", OutputSeverity severity = OutputSeverity::Info);
    void clearOutput(const std::string& tabName = "General");
    void formatOutput(const std::string& text, COLORREF color, const std::string& tabName = "");

    // Document tabs (VS Code style editor tabs)
    void createDocumentTabs();
    void addDocumentTab(const std::string& path);
    void removeDocumentTab(int index);
    void switchDocumentTab(int index);
    void updateDocumentTabs();
    int findDocumentTab(const std::string& path) const;

    // Enhanced clipboard
    void copyWithFormatting();
    void pasteWithoutFormatting();
    void copyLineNumbers();
    void showClipboardHistory();
    void clearClipboardHistory();

    // Minimap
    void createMinimap();
    void updateMinimap();
    void scrollToMinimapPosition(int y);
    void toggleMinimap();

    // Performance profiling
    void startProfiling();
    void stopProfiling();
    void showProfileResults();
    void analyzeScript();
    void measureExecutionTime();

    // Module management
    void refreshModuleList();
    void loadModule(const std::string& moduleName);
    void unloadModule(const std::string& moduleName);
    void showModuleBrowser();
    void importModule();
    void exportModule();

    // Command Palette (Ctrl+Shift+P)
    struct CommandPaletteItem {
        int id;
        std::string name;
        std::string shortcut;
        std::string category;
    };
    void showCommandPalette();
    void hideCommandPalette();
    void filterCommandPalette(const std::string& query);
    void executeCommandFromPalette(int index);
    void buildCommandRegistry();
    static LRESULT CALLBACK CommandPaletteProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    // Command palette UI handles and data
    HWND m_hwndCommandPalette = nullptr;
    HWND m_hwndCommandPaletteInput = nullptr;
    HWND m_hwndCommandPaletteList = nullptr;
    bool m_commandPaletteVisible;
    std::vector<CommandPaletteItem> m_commandRegistry;
    std::vector<CommandPaletteItem> m_filteredCommands;
    std::vector<int> m_commandPaletteFilteredIndices; // maps listbox index -> registry index
    std::unordered_map<int, std::function<void()>> m_commandHandlers;

    // Utility
    std::string getWindowText(HWND hwnd);
    // Explicit UTF-8 boundary for text that crosses into JSON/agent APIs.
    std::string getWindowTextUtf8(HWND hwnd);
    void appendCopilotChatUtf8(const std::string& text);
    void setWindowText(HWND hwnd, const std::string& text);
    void appendText(HWND hwnd, const std::string& text);
    void syncEditorToGpuSurface();
    void initializeEditorSurface();
    static LRESULT CALLBACK EditorSubclassProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static constexpr const wchar_t* kEditorWndProp = L"RawrXD_IDE_PTR";
    static constexpr const wchar_t* kEditorProcProp = L"RawrXD_EDITOR_PROC";
    TerminalPane* findTerminalPane(int paneId);
    void setActiveTerminalPane(int paneId);

    // Search and Replace
    void showFindDialog();
    void showReplaceDialog();
    void findNext();
    void findPrevious();
    void replaceNext();
    void replaceAll();
    bool findText(const std::string& searchText, bool forward, bool caseSensitive, bool wholeWord, bool useRegex);
    int replaceText(const std::string& searchText, const std::string& replaceText, bool all, bool caseSensitive, bool wholeWord, bool useRegex);
    static INT_PTR CALLBACK FindDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static INT_PTR CALLBACK ReplaceDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

    // Floating Panel
    void createFloatingPanel();
    void showFloatingPanel();
    void hideFloatingPanel();
    void toggleFloatingPanel();
    void updateFloatingPanelContent(const std::string& content);
    void setFloatingPanelTab(int tabIndex);
    static LRESULT CALLBACK FloatingPanelProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

    // Git/Module panel helpers
    int getPanelAreaWidth() const;
    static LRESULT CALLBACK GitPanelProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK ModulePanelProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK CommitDialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

    // File Explorer Sidebar
    void createFileExplorer(HWND hwndParent);
    void populateFileTree(HTREEITEM parentItem, const std::string& path);
    void onFileTreeExpand(HTREEITEM item, const std::string& path);
    void onFileTreeSelect(HTREEITEM item);
    void onFileTreeDoubleClick(HTREEITEM item);
    std::string getTreeItemPath(HTREEITEM item) const;
    void loadModelFromPath(const std::string& filepath);
    static LRESULT CALLBACK FileExplorerProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

    // Primary Sidebar (Left) - VS Code Activity Bar + Sidebar
    enum class SidebarView {
        None = 0,
        Explorer = 1,
        Search = 2,
        SourceControl = 3,
        RunDebug = 4,
        Extensions = 5
    };
    
    void createActivityBar(HWND hwndParent);
    void createPrimarySidebar(HWND hwndParent);
    void toggleSidebar(); // Ctrl+B
    void setSidebarView(SidebarView view);
    void updateSidebarContent();
    void resizeSidebar(int width, int height);
    static LRESULT CALLBACK ActivityBarProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK SidebarProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    
    // Explorer View
    void createExplorerView(HWND hwndParent);
    void refreshFileTree();
    void expandFolder(const std::string& path);
    void collapseAllFolders();
    void newFileInExplorer();
    void newFolderInExplorer();
    void deleteItemInExplorer();
    void renameItemInExplorer();
    void revealInExplorer(const std::string& filePath);
    void handleExplorerContextMenu(POINT pt);
    static LRESULT CALLBACK ExplorerTreeProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    
    // Search View
    void createSearchView(HWND hwndParent);
    void performWorkspaceSearch(const std::string& query, bool useRegex, bool caseSensitive, bool wholeWord);
    void updateSearchResults(const std::vector<std::string>& results);
    void applySearchFilters(const std::string& includePattern, const std::string& excludePattern);
    void searchInFiles(const std::string& query);
    void replaceInFiles(const std::string& searchText, const std::string& replaceText);
    void clearSearchResults();
    
    // Source Control View
    void createSourceControlView(HWND hwndParent);
    void refreshSourceControlView();
    void stageSelectedFiles();
    void unstageSelectedFiles();
    void discardChanges();
    void commitChangesFromSidebar();
    void syncRepository(); // push & pull
    void showSCMContextMenu(POINT pt);
    
    // Run and Debug View
    void createRunDebugView(HWND hwndParent);
    void createLaunchConfiguration();
    void startDebugging();
    void stopDebugging();
    void setBreakpoint(const std::string& file, int line);
    void removeBreakpoint(const std::string& file, int line);
    void stepOver();
    void stepInto();
    void stepOut();
    void continueExecution();
    void showDebugConsole();
    void updateDebugVariables();
    
    // Extensions View
    void createExtensionsView(HWND hwndParent);
    void searchExtensions(const std::string& query);
    void installExtension(const std::string& extensionId);
    void uninstallExtension(const std::string& extensionId);
    void enableExtension(const std::string& extensionId);
    void disableExtension(const std::string& extensionId);
    void updateExtension(const std::string& extensionId);
    void showExtensionDetails(const std::string& extensionId);
    void loadInstalledExtensions();

private:
    // ========================================================================
    // POWERSHELL ACCESS - Private State
    // ========================================================================
    
    // PowerShell Runtime State
    struct PowerShellState {
        bool initialized;
        bool remoteSessionActive;
        std::string remoteComputerName;
        std::string currentExecutionPolicy;
        bool debugModeEnabled;
        bool transcriptActive;
        std::string transcriptPath;
        std::map<std::string, std::string> sessionVariables;
        std::vector<int> activeJobs;
        std::vector<int> activeBreakpoints;
        std::map<std::string, std::string> loadedModules;
        std::string profilePath;
        std::string version;
        std::string edition;
    };
    PowerShellState m_psState;
    
    // PowerShell Command Queue
    struct PSCommand {
        int id;
        std::string command;
        bool async;
        std::function<void(const std::string&)> callback;
    };
    std::vector<PSCommand> m_psCommandQueue;
    int m_nextPSCommandId;
    
    // PowerShell Job Tracking
    struct PSJob {
        int id;
        std::string name;
        std::string scriptBlock;
        bool completed;
        std::string output;
        std::string error;
    };
    std::map<int, PSJob> m_psJobs;
    int m_nextPSJobId;
    
    // PowerShell Module Cache
    struct PSModule {
        std::string name;
        std::string version;
        std::string path;
        bool loaded;
        std::vector<std::string> exportedCmdlets;
        std::vector<std::string> exportedFunctions;
    };
    std::map<std::string, PSModule> m_psModuleCache;
    
    // PowerShell Function Registry
    std::map<std::string, std::string> m_psFunctions; // name -> body
    
    // PowerShell Event Handlers
    std::map<std::string, std::string> m_psEventHandlers; // sourceId -> action
    
    // RawrXD.ps1 Integration
    bool m_rawrXDModuleLoaded;
    std::string m_rawrXDModulePath;
    std::map<std::string, std::string> m_rawrXDFunctions;
    
    // PowerShell Helper Functions
    std::string escapePowerShellString(const std::string& str);
    std::string buildPowerShellCommand(const std::string& cmdlet, const std::map<std::string, std::string>& params);
    std::string buildPowerShellPipeline(const std::vector<std::string>& commands);
    bool parsePowerShellOutput(const std::string& output, std::vector<std::string>& lines);
    std::string extractPowerShellError(const std::string& output);
    bool isPowerShellCommandAvailable(const std::string& cmdlet);
    void initializePowerShellState();
    void updatePowerShellModuleCache();
    std::string getRawrXDPowerShellPath();
    
    // GGUF Model loader (initialized in constructor) - supports both streaming and standard implementations
    std::unique_ptr<RawrXD::IGGUFLoader> m_ggufLoader;
    std::string m_loadedModelPath;
    RawrXD::GGUFMetadata m_currentModelMetadata;
    std::vector<RawrXD::TensorInfo> m_modelTensors;
    bool m_useStreamingLoader; // preference to use streaming loader to minimize memory
    bool m_useVulkanRenderer; // preference to use Vulkan renderer if enabled

    // Native CPU inference fallback engine (see Win32IDE.cpp constructor).
    // Raw-owning pointer, released in the destructor.
    RawrXD::CPUInferenceEngine* m_nativeEngine = nullptr;
    bool m_nativeEngineLoaded = false;
    
    // AI Inference State
    InferenceConfig m_inferenceConfig;
    std::atomic_bool m_inferenceRunning{false};
    std::atomic_bool m_inferenceStopRequested{false};
    std::string m_currentInferencePrompt;
    std::string m_currentInferenceResponse;
    std::thread m_inferenceThread;
    std::mutex m_inferenceMutex;
    std::function<void(const std::string&, bool, bool)> m_inferenceCallback;

    // File Explorer Sidebar - tree view items
    HWND m_hwndFileTree = nullptr;
    std::map<HTREEITEM, std::string> m_treeItemPaths;

    HINSTANCE m_hInstance = nullptr;
    HWND m_hwndMain = nullptr;
    HWND m_hwndEditor = nullptr;
    HWND m_hwndEditorBreadcrumb = nullptr;
    HWND m_hwndCommandInput = nullptr;
    HWND m_hwndStatusBar = nullptr;
    HWND m_hwndOutputTabs = nullptr;
    HWND m_hwndMinimap = nullptr;
    HWND m_hwndHelp = nullptr;
    HWND m_hwndFloatingPanel = nullptr;
    HWND m_hwndFloatingContent = nullptr;

    HMENU m_hMenu = nullptr;
    HWND m_hwndToolbar = nullptr;
    HWND m_hwndTitleLabel = nullptr;
    HWND m_hwndBtnMinimize = nullptr;
    HWND m_hwndBtnMaximize = nullptr;
    HWND m_hwndBtnClose = nullptr;
    HWND m_hwndBtnGitHub = nullptr;
    HWND m_hwndBtnMicrosoft = nullptr;
    HWND m_hwndBtnSettings = nullptr;
    std::string m_lastTitleBarText;

    // Document tabs (VS Code style). m_openDocuments holds the file path of every
    // open editor buffer; an empty entry is the scratch "Untitled" buffer.
    HWND m_hwndDocTabs = nullptr;
    std::vector<std::string> m_openDocuments;
    int m_activeDocument = -1;

    // Per-pane terminal managers replace the previous single manager
    std::string m_currentFile;
    bool m_fileModified;
    bool m_suppressEditorDirty = false;
    
    // Multi-terminal support
    std::vector<TerminalPane> m_terminalPanes;
    int m_nextTerminalId;
    int m_activeTerminalId;
    bool m_terminalSplitHorizontal;
    
    // Git integration
    GitStatus m_gitStatus;
    HWND m_hwndGitPanel = nullptr;
    HWND m_hwndGitStatusText = nullptr;
    HWND m_hwndGitFileList = nullptr;
    std::vector<GitFile> m_currentGitFiles;
    bool m_gitPanelVisible;
    WNDPROC m_gitPanelProc;
    std::string m_gitRepoPath;
    bool m_gitAutoRefresh;
    HWND m_hwndCommitDialog = nullptr; // commit dialog handle
    
    // File operations
    std::vector<std::string> m_recentFiles;
    static const size_t MAX_RECENT_FILES = 10;
    std::string m_currentDirectory;
    std::string m_defaultFileExtension;
    bool m_autoSaveEnabled;
    
    // Menu command system
    std::map<int, std::string> m_commandDescriptions;
    std::map<int, bool> m_commandStates;

    // Theme system
    IDETheme m_currentTheme;
    std::map<std::string, IDETheme> m_themes;
    HBRUSH m_backgroundBrush = nullptr;
    HFONT m_editorFont = nullptr;

    // Code snippets
    std::vector<CodeSnippet> m_codeSnippets;
    std::unordered_map<std::string, size_t> m_snippetTriggers;

    // Output tabs
    std::map<std::string, HWND> m_outputWindows;
    std::string m_activeOutputTab;
    bool m_outputPanelVisible;
    int m_selectedOutputTab;
    HWND m_hwndSeverityFilter = nullptr;
    int m_severityFilterLevel; // 0=All, 1=Info+, 2=Warn+, 3=Error only

    // Clipboard history
    std::vector<std::string> m_clipboardHistory;
    static const size_t MAX_CLIPBOARD_HISTORY = 50;

    // Minimap
    bool m_minimapVisible;
    int m_minimapWidth;
    std::vector<std::string> m_minimapLines;
    std::vector<int> m_minimapLineStarts;

    // Profiling
    bool m_profilingActive;
    std::vector<std::pair<std::string, double>> m_profilingResults;
    LARGE_INTEGER m_profilingStart;
    LARGE_INTEGER m_profilingFreq;

    // Module management
    HWND m_hwndModuleBrowser = nullptr;
    HWND m_hwndModuleList = nullptr;
    HWND m_hwndModuleLoadButton = nullptr;
    HWND m_hwndModuleUnloadButton = nullptr;
    HWND m_hwndModuleRefreshButton = nullptr;
    bool m_moduleBrowserVisible;
    WNDPROC m_modulePanelProc;
    std::vector<ModuleInfo> m_modules;
    bool m_moduleListDirty;

    // Window dimensions
    int m_editorHeight;
    int m_terminalHeight;
    int m_minimapX;
    int m_outputTabHeight;
    RECT m_editorRect;
    bool m_gpuTextEnabled;
    bool m_editorHooksInstalled;
    
    // Splitter bar for terminal/output resize
    HWND m_hwndSplitter = nullptr;
    bool m_splitterDragging;
    int m_splitterY;
    
    std::unique_ptr<IRenderer> m_renderer;
    bool m_rendererReady;

    // Search and Replace state
    std::string m_lastSearchText;
    std::string m_lastReplaceText;
    bool m_searchCaseSensitive;
    bool m_searchWholeWord;
    bool m_searchUseRegex;
    int m_lastFoundPos;
    HWND m_hwndFindDialog = nullptr;
    HWND m_hwndReplaceDialog = nullptr;
    HWND m_hwndFindInput = nullptr;
    HWND m_hwndReplaceInput = nullptr;
    
    // Primary Sidebar state
    HWND m_hwndActivityBar = nullptr;
    HWND m_hwndSidebar = nullptr;
    HWND m_hwndSidebarContent = nullptr;
    bool m_sidebarVisible;
    int m_sidebarWidth;
    SidebarView m_currentSidebarView;
    
    // Explorer View
    HWND m_hwndExplorerTree = nullptr;
    HWND m_hwndExplorerToolbar = nullptr;
    HIMAGELIST m_hImageListExplorer = nullptr;
    std::string m_explorerRootPath;
    WNDPROC m_explorerTreeOriginalProc = nullptr;
    
    // Search View
    HWND m_hwndSearchInput = nullptr;
    HWND m_hwndSearchResults = nullptr;
    HWND m_hwndSearchOptions = nullptr;
    HWND m_hwndIncludePattern = nullptr;
    HWND m_hwndExcludePattern = nullptr;
    std::vector<std::string> m_searchResults;
    bool m_searchInProgress;
    
    // Source Control View (extends existing Git)
    HWND m_hwndSCMFileList = nullptr;
    HWND m_hwndSCMToolbar = nullptr;
    HWND m_hwndSCMMessageBox = nullptr;
    
    // Run and Debug View
    HWND m_hwndDebugConfigs = nullptr;
    HWND m_hwndDebugToolbar = nullptr;
    HWND m_hwndDebugVariables = nullptr;
    HWND m_hwndDebugCallStack = nullptr;
    HWND m_hwndDebugConsole = nullptr;
    bool m_debuggingActive;
    // m_breakpoints defined in Debugger State section with Breakpoint struct
    
    // Extensions View
    HWND m_hwndExtensionsList = nullptr;
    HWND m_hwndExtensionSearch = nullptr;
    HWND m_hwndExtensionDetails = nullptr;
    struct Extension {
        std::string id;
        std::string name;
        std::string version;
        std::string description;
        std::string author;
        bool installed;
        bool enabled;
    };
    std::vector<Extension> m_extensions;
    bool m_extensionsLoadInProgress = false;
    
    // Outline View (code structure)
    HWND m_hwndOutlineTree = nullptr;
    struct OutlineItem {
        std::string name;
        std::string type;  // function, class, variable, etc.
        int line;
        int column;
        std::vector<OutlineItem> children;
    };
    std::vector<OutlineItem> m_outlineItems;
    void createOutlineView(HWND hwndParent);
    void updateOutlineView();
    void parseCodeForOutline();
    void goToOutlineItem(int index);
    
    // Timeline View (file history)
    HWND m_hwndTimelineList = nullptr;
    struct TimelineEntry {
        std::string message;
        std::string author;
        std::string date;
        std::string commitHash;
        bool isGitCommit;
    };
    std::vector<TimelineEntry> m_timelineEntries;
    void createTimelineView(HWND hwndParent);
    void updateTimelineView();
    void loadGitHistory();
    void goToTimelineEntry(int index);
    
    // =========================================================================
    // VS Code-like UI Components
    // =========================================================================
    
    // Activity Bar (Far Left) - vertical icon bar for switching sidebar views
    static const int ACTIVITY_BAR_WIDTH = 48;
    HWND m_activityBarButtons[7]{};  // Explorer, Search, SCM, Debug, Extensions, Settings, Accounts
    int m_activeActivityBarButton;
    HBRUSH m_actBarBackgroundBrush = nullptr;
    HBRUSH m_actBarHoverBrush = nullptr;
    HBRUSH m_actBarActiveBrush = nullptr;
    static LRESULT CALLBACK ActivityBarButtonProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    
    // Secondary Sidebar (Right) - AI Chat / Copilot area
    HWND m_hwndSecondarySidebar = nullptr;
    HWND m_hwndSecondarySidebarHeader = nullptr;
    HWND m_hwndCopilotChatInput = nullptr;
    HWND m_hwndCopilotChatOutput = nullptr;
    HWND m_hwndCopilotSendBtn = nullptr;
    HWND m_hwndCopilotStopBtn = nullptr;
    HWND m_hwndCopilotClearBtn = nullptr;
    HWND m_hwndModelLabel = nullptr;
    HWND m_hwndModelSelector = nullptr;
    HWND m_hwndGhostTextModelLabel = nullptr;
    HWND m_hwndGhostModelSelector = nullptr;
    HWND m_hwndAllowCloudGhostText = nullptr;
    HWND m_hwndMaxTokensCaption = nullptr;
    HWND m_hwndMaxTokensSlider = nullptr;
    HWND m_hwndMaxTokensSelector = nullptr;
    HWND m_hwndMaxTokensLabel = nullptr;
    HWND m_hwndContextCaption = nullptr;
    HWND m_hwndContextLabel = nullptr;
    HWND m_hwndContextSlider = nullptr;
    HWND m_hwndContextSelector = nullptr;
    HWND m_hwndReasoningLabel = nullptr;
    HWND m_hwndReasoningSelector = nullptr;
    HWND m_hwndWebBrowseToggle = nullptr;
    HWND m_hwndChatSessionTabs = nullptr;
    HWND m_hwndNewChatBtn = nullptr;
    HWND m_hwndCloseChatBtn = nullptr;
    HWND m_hwndRestoreChatBtn = nullptr;
    HWND m_hwndRollbackChatBtn = nullptr;
    bool m_secondarySidebarVisible;
    int m_secondarySidebarWidth;
    int m_currentMaxTokens;
    int m_currentContextTokens = 65536;
    ReasoningMode m_reasoningMode = ReasoningMode::Instant;
    bool m_webBrowsingEnabled = false;
    std::vector<ChatModelEntry> m_availableModels;
    ChatModelEntry m_selectedChatModel;
    ChatModelEntry m_ghostTextModel;
    ChatModelEntry m_pendingInferenceModel;
    GhostTextMode m_ghostTextMode = GhostTextMode::AutoLocal;
    bool m_allowCloudGhostText = false;
    std::unique_ptr<NativeGhostTextController> m_ghostText;
    std::vector<std::unique_ptr<NativeGhostTextController>> m_ghostTextInputs;
    std::string m_agenticChatLoadedModelPath;
    std::thread m_modelDiscoveryThread;
    uint64_t m_currentModelGenID = 0;
    std::shared_ptr<std::atomic_bool> m_modelDiscoveryCancel =
        std::make_shared<std::atomic_bool>(false);
    std::atomic_bool m_modelDiscoveryRunning{false};
    // Model discovery results are delivered on the UI thread.  Keep the
    // newest result staged while either model combo's popup is open so that
    // CB_RESETCONTENT cannot tear down an active native dropdown.
    std::unique_ptr<ModelDiscoveryPayload> m_deferredModelDiscovery;
    bool m_modelDiscoveryUpdateDeferred = false;
    std::vector<std::pair<std::string, std::string>> m_chatHistory; // role, message
    std::vector<ChatSessionState> m_chatSessions;
    std::vector<ChatSessionState> m_closedChatSessions;
    int m_activeChatSession = -1;
    int m_nextChatSessionId = 1;
    static LRESULT CALLBACK SecondarySidebarProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    
    // Panel (Bottom) - Terminal, Output, Problems, Debug Console
    enum class PanelTab {
        Terminal = 0,
        Output = 1,
        Problems = 2,
        DebugConsole = 3
    };
    HWND m_hwndPanelContainer = nullptr;
    HWND m_hwndPanelTabs = nullptr;
    HWND m_hwndPanelToolbar = nullptr;
    HWND m_hwndPanelNewTerminalBtn = nullptr;
    HWND m_hwndPanelSplitTerminalBtn = nullptr;
    HWND m_hwndPanelKillTerminalBtn = nullptr;
    HWND m_hwndPanelMaximizeBtn = nullptr;
    HWND m_hwndPanelCloseBtn = nullptr;
    HWND m_hwndProblemsListView = nullptr;
    PanelTab m_activePanelTab;
    bool m_panelVisible;
    bool m_panelMaximized;
    int m_panelHeight;
    
    // Problems tracking
    struct ProblemItem {
        std::string file;
        int line;
        int column;
        std::string message;
        int severity;  // 0=Error, 1=Warning, 2=Info
    };
    std::vector<ProblemItem> m_problems;
    int m_errorCount;
    int m_warningCount;
    
    // Enhanced Status Bar items
    struct StatusBarInfo {
        std::string remoteName;       // e.g., "WSL: Ubuntu" or empty
        std::string branchName;       // e.g., "main"
        int syncAhead;                // commits ahead
        int syncBehind;               // commits behind
        int errors;
        int warnings;
        int line;
        int column;
        int spacesOrTabWidth;
        bool useSpaces;
        std::string encoding;         // e.g., "UTF-8"
        std::string eolSequence;      // e.g., "LF" or "CRLF"
        std::string languageMode;     // e.g., "C++", "Python"
        bool copilotActive;
        int copilotSuggestions;       // number of available suggestions
    };
    StatusBarInfo m_statusBarInfo;
    HWND m_statusBarParts[12]{};  // Individual status bar items for custom drawing
    
    // VS Code UI Creation/Update functions
    void createActivityBarUI(HWND hwndParent);
    void createSecondarySidebar(HWND hwndParent);
    void createPanel(HWND hwndParent);
    void createEnhancedStatusBar(HWND hwndParent);
    
    // Agent ESP Panel
    void createESPPanel(HWND hwndParent);
    void updateESPPanel();
    void onESPEvent(const rawrxd::esp::Event& event);
    void toggleESPPanel();  // Ctrl+Shift+E

    void updateActivityBarState();
    void updateSecondarySidebarContent();
    void updatePanelContent();
    void updateEnhancedStatusBar();
    void updateProblemsPanel();
    
    void toggleSecondarySidebar();      // Ctrl+Alt+B
    void togglePanel();                  // Ctrl+J
    void maximizePanel();
    void restorePanel();
    
    void switchPanelTab(PanelTab tab);
    void addProblem(const std::string& file, int line, int col, const std::string& msg, int severity);
    void clearProblems();
    void goToProblem(int index);
    
    void sendCopilotMessage(const std::string& message);
    void clearCopilotChat();
    void appendCopilotResponse(const std::string& response);
    
    void updateCursorPosition();
    void updateLanguageMode();
    void detectLanguageFromFile(const std::string& filePath);
    
    // File Explorer
    void createFileExplorer();
    void populateFileTree();
    void refreshFileExplorer();
    void expandTreeNode(HTREEITEM hItem);
    void onFileExplorerDoubleClick();
    void onFileExplorerRightClick();
    void showFileContextMenu(const std::string& filePath, bool isDirectory);
    void loadModelFromExplorer(const std::string& filePath);
    bool isModelFile(const std::string& filePath);
    HTREEITEM addTreeItem(HTREEITEM hParent, const std::string& text, const std::string& fullPath, bool isDirectory);
    void scanDirectory(const std::string& dirPath, HTREEITEM hParent);
    std::string getSelectedFilePath();

    // Model Chat Interface
    std::string sendMessageToModel(const std::string& message);
    void toggleChatMode();
    void appendChatMessage(const std::string& user, const std::string& message);
    bool trySendToOllama(const std::string& prompt, std::string& outResponse);

    // Ollama config
    std::string m_ollamaBaseUrl;      // e.g., http://localhost:11434
    std::string m_ollamaModelOverride; // if set, use this tag instead of deriving from filename

    // File Explorer members (additional)
    HIMAGELIST m_hImageList = nullptr;
    std::vector<FileExplorerItem> m_rootItems;
    std::string m_currentExplorerPath;
    HWND m_hwndFileExplorer = nullptr;  // Primary file explorer window
    
    // Model Chat state
    bool m_chatMode;
    
    // ========================================================================
    // DEDICATED POWERSHELL PANEL - Always Available PowerShell Console
    // ========================================================================
    
    // PowerShell Panel Window Handles
    HWND m_hwndPowerShellPanel = nullptr;           // Main PowerShell panel container
    HWND m_hwndPowerShellOutput = nullptr;          // PowerShell output/console area
    HWND m_hwndPowerShellInput = nullptr;           // PowerShell command input
    HWND m_hwndPowerShellToolbar = nullptr;         // PowerShell panel toolbar
    HWND m_hwndPowerShellStatusBar = nullptr;       // PowerShell status (version, execution policy)
    
    // PowerShell Panel Buttons
    HWND m_hwndPSBtnExecute = nullptr;              // Execute button
    HWND m_hwndPSBtnClear = nullptr;                // Clear console
    HWND m_hwndPSBtnStop = nullptr;                 // Stop execution
    HWND m_hwndPSBtnHistory = nullptr;              // Command history
    HWND m_hwndPSBtnRestart = nullptr;              // Restart PowerShell session
    HWND m_hwndPSBtnLoadRawrXD = nullptr;           // Load RawrXD.ps1 module
    HWND m_hwndPSBtnToggle = nullptr;               // Toggle panel visibility
    
    // PowerShell Panel State
    bool m_powerShellPanelVisible;
    bool m_powerShellPanelDocked;         // true=docked, false=floating
    bool m_powerShellSessionActive;
    bool m_powerShellRawrXDLoaded;
    int m_powerShellPanelHeight;          // Height when docked
    int m_powerShellPanelWidth;           // Width when floating
    std::string m_powerShellCurrentCommand;
    std::vector<std::string> m_powerShellCommandHistory;
    int m_powerShellHistoryIndex;
    size_t m_maxPowerShellHistory;
    
    // PowerShell Execution State
    bool m_powerShellExecuting;
    std::string m_powerShellCurrentOutput;
    HANDLE m_powerShellProcessHandle = nullptr;
    std::unique_ptr<Win32TerminalManager> m_dedicatedPowerShellTerminal;
    
    // PowerShell Panel Functions
    void createPowerShellPanel();
    void createPowerShellToolbar();
    void showPowerShellPanel();
    void hidePowerShellPanel();
    void togglePowerShellPanel();         // Ctrl+`
    void dockPowerShellPanel();
    void floatPowerShellPanel();
    void resizePowerShellPanel(int width, int height);
    void layoutPowerShellPanel();
    
    // PowerShell Execution
    void executePowerShellInput();
    void executePowerShellPanelCommand(const std::string& command);
    void stopPowerShellExecution();
    void clearPowerShellConsole();
    void appendPowerShellOutput(const std::string& text, COLORREF color = RGB(200, 200, 200));
    
    // PowerShell History Management
    void addPowerShellHistory(const std::string& command);
    void navigatePowerShellHistoryUp();
    void navigatePowerShellHistoryDown();
    void showPowerShellHistory();
    
    // PowerShell Session Management
    void startPowerShellSession();
    void restartPowerShellSession();
    void stopPowerShellSession();
    bool isPowerShellSessionActive() const;
    void updatePowerShellStatus();
    
    // RawrXD.ps1 Integration
    void loadRawrXDModule();
    void unloadRawrXDModule();
    void executeRawrXDCommand(const std::string& command);
    void quickLoadGGUFModel();            // Quick model loader dialog
    void quickInference();                 // Quick inference dialog
    
    // PowerShell Panel Helpers
    void initializePowerShellPanel();
    void updatePowerShellPanelLayout(int mainWidth, int mainHeight);
    std::string getPowerShellPrompt();
    void scrollPowerShellOutputToBottom();
    static LRESULT CALLBACK PowerShellPanelProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK PowerShellInputProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK TerminalInputProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

    // ========================================================================
    // DEBUGGER IMPLEMENTATION
    // ========================================================================
    
    // Debugger UI Creation & Management
    void createDebuggerUI();
    void updateDebuggerUI();
    void toggleDebugger();
    void attachDebugger();
    void detachDebugger();
    
    // ========================================================================
    // AI CHAT PANEL IMPLEMENTATION
    // ========================================================================
    
    void createChatPanel();
    void HandleCopilotSend();
    void HandleCopilotStop();
    void HandleCopilotClear();
    void handleCopilotUiUpdate(int sessionId, const std::string& response,
                               bool complete);
    void HandleCopilotStreamUpdate(const char* token, size_t length = 0);
    void populateModelSelector();
    void onModelSelectionChanged();
    void onGhostTextSelectionChanged();
    void onGhostTextCloudConsentChanged();
    void onModelDiscoveryComplete(ModelDiscoveryPayload* discovered);
    void onMaxTokensChanged(int newValue);
    void onContextPresetChanged();
    void onReasoningModeChanged();
    void onWebBrowsingChanged();
    void updateReasoningControls();
    void updateContextControls();
    int effectiveMaxTokensForPrompt(const std::string& prompt) const;
    void initializeNativeGhostText();
    bool handleNativeGhostTextMessage(UINT message, WPARAM wParam, LPARAM lParam);
    void invalidateNativeGhostText();
    void notifyGhostTextInputChanged(HWND input);
    void createChatSession(const std::string& title = "");
    void switchChatSession(int index);
    void updateChatSessionTabs();
    void closeActiveChatSession();
    void restoreClosedChatSession();
    void checkpointActiveChat(const std::string& reason);
    void rollbackActiveChat();
    ChatSessionState* activeChatSession();
    
    // Debugger Execution Control
    void pauseExecution();
    void resumeExecution();
    void stepOverExecution();
    void stepIntoExecution();
    void stepOutExecution();
    void restartDebugger();
    void stopDebugger();
    
    // Breakpoint Management
    void addBreakpoint(const std::string& file, int line);
    void toggleBreakpoint(const std::string& file, int line);
    void updateBreakpointList();
    void clearAllBreakpoints();
    
    // Watch Expression Management
    void addWatchExpression(const std::string& expression);
    void removeWatchExpression(const std::string& expression);
    void updateWatchList();
    void evaluateWatch(WatchItem& item);
    
    // Variable & Stack Inspection
    void updateVariables();
    void updateCallStack();
    void updateMemoryView();
    void expandVariable(const std::string& name);
    void collapseVariable(const std::string& name);
    
    // Debugger Commands
    void debuggerStepCommand(const std::string& command);
    void debuggerSetVariable(const std::string& name, const std::string& value);
    void debuggerInspectMemory(uint64_t address, size_t bytes);
    void debuggerEvaluateExpression(const std::string& expression);
    
    // Debugger Callbacks
    void onDebuggerBreakpoint(const std::string& file, int line);
    void onDebuggerException(const std::string& message);
    void onDebuggerOutput(const std::string& text);
    void onDebuggerContinued();
    void onDebuggerTerminated();
    
    // Helper Methods
    std::string formatDebuggerValue(const std::string& value, const std::string& type);
    bool isBreakpointAtLine(const std::string& file, int line) const;
    void highlightDebuggerLine(const std::string& file, int line);
    void clearDebuggerHighlight();
    LRESULT handleESPEvent(WPARAM wParam, LPARAM lParam);
    LRESULT handleAgenticLoopProgress(WPARAM wParam, LPARAM lParam);
    LRESULT handleAgenticLoopToolResult(WPARAM wParam, LPARAM lParam);
    LRESULT handleAgenticLoopComplete(WPARAM wParam, LPARAM lParam);

private:
    // Agent ESP Telemetry
    rawrxd::esp::Bus m_espBus;
    std::unique_ptr<rawrxd::esp::Recorder> m_espRecorder;
    std::atomic<bool> m_espActive{false};
    HWND m_hwndESPPanel = nullptr;
    HWND m_hwndESPList = nullptr;
    std::vector<rawrxd::esp::Event> m_espEvents; // Recent events for display
    static constexpr size_t MAX_ESP_EVENTS = 1000;
    std::mutex m_espEventsMutex;
    // Presentation-level idempotence. Raw CLI output and the structured ESP
    // recorder can both reach the UI; a request/sequence pair is rendered
    // once while the raw JSONL evidence remains untouched on disk.
    std::unordered_set<std::string> m_espDisplayedKeys;
    uint64_t m_espRequestId = 1;

    // Debugger UI Components
    HWND m_hwndDebuggerContainer = nullptr;
    HWND m_hwndDebuggerTabs = nullptr;
    HWND m_hwndDebuggerBreakpoints = nullptr;
    HWND m_hwndDebuggerWatch = nullptr;
    HWND m_hwndDebuggerVariables = nullptr;
    HWND m_hwndDebuggerStackTrace = nullptr;
    HWND m_hwndDebuggerMemory = nullptr;
    HWND m_hwndDebuggerToolbar = nullptr;
    HWND m_hwndDebuggerInput = nullptr;
    HWND m_hwndDebuggerStatus = nullptr;
    
    // Debugger State
    bool m_debuggerEnabled;
    bool m_debuggerAttached;
    bool m_debuggerPaused;
    std::string m_debuggerCurrentFile;
    int m_debuggerCurrentLine;
    COLORREF m_debuggerBreakpointColor;
    COLORREF m_debuggerCurrentLineColor;
    
    // Breakpoints
    std::vector<Breakpoint> m_breakpoints;
    
    // Call Stack
    std::vector<StackFrame> m_callStack;
    
    // Variables
    std::vector<Variable> m_watchVariables;
    std::vector<Variable> m_localVariables;
    
    // Watch List
    std::vector<WatchItem> m_watchList;
    
    // Debugger Configuration
    bool m_debuggerBreakOnException;
    bool m_debuggerBreakOnError;
    bool m_debuggerBreakOnWarning;
    uint64_t m_debuggerMaxMemory;
    int m_debuggerRefreshRate;
    
    // Debugger History
    std::vector<std::string> m_debuggerCommandHistory;
    size_t m_debuggerHistoryIndex;
};
