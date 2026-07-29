// ============================================================================
// IDECore.h - RawrXD IDE Core Integration Layer
// ============================================================================
// Central hub that wires all production components together:
// - Scintilla Editor
// - Ghost Text Engine
// - LSP Client
// - Agentic Tool Integration
// - Git Integration
// - ANSI Terminal
// - Inference Engine
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include <functional>
#include <vector>
#include <unordered_map>

// Forward declarations
namespace RawrXD {
    namespace Editor { class ScintillaEditor; }
    namespace LSP { class LSPClient; }
    namespace Agentic { class AgenticToolIntegration; }
    namespace Git { class GitIntegration; }
    namespace Terminal { class ANSITerminalRenderer; }
    namespace Model { class GGUFLoader; }
}

namespace RawrXD {
namespace IDE {

// IDE Configuration
struct IDEConfig {
    // Window settings
    int windowX = CW_USEDEFAULT;
    int windowY = CW_USEDEFAULT;
    int windowWidth = 1400;
    int windowHeight = 900;
    bool maximized = false;
    
    // Editor settings
    std::string fontName = "Consolas";
    int fontSize = 11;
    bool wordWrap = false;
    bool showLineNumbers = true;
    bool showWhitespace = false;
    
    // Theme
    std::string theme = "dark"; // "dark" or "light"
    
    // Paths
    std::string lastProjectPath;
    std::string modelPath;
    std::string clangdPath = "clangd.exe";
    
    // AI settings
    int maxTokens = 2048;
    float temperature = 0.7f;
    bool enableGhostText = true;
    bool enableAutocomplete = true;
    
    // LSP settings
    bool enableLSP = true;
    std::vector<std::string> lspCommands;
    
    // Security
    std::vector<std::string> allowedDirectories;
};

// IDE State
enum class IDEState {
    UNINITIALIZED = 0,
    INITIALIZING = 1,
    READY = 2,
    LOADING_MODEL = 3,
    MODEL_LOADED = 4,
    GENERATING = 5,
    ERROR = 6
};

// Ghost text state
struct GhostTextState {
    bool visible = false;
    std::string suggestion;
    int startPos = 0;
    int endPos = 0;
    std::string contextBefore;
    std::string contextAfter;
};

// Status bar info
struct StatusBarInfo {
    std::string lineCol;
    std::string encoding = "UTF-8";
    std::string gitBranch;
    std::string modelStatus;
    std::string tps;
    std::string language;
};

// ============================================================================
// IDECore - Central Integration Hub
// ============================================================================

class IDECore {
public:
    IDECore();
    ~IDECore();

    // Initialization
    bool Initialize(HINSTANCE hInstance, const std::string& configPath);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Window management
    bool CreateMainWindow(const std::string& title);
    HWND GetMainWindow() const { return hMainWindow_; }
    void ShowWindow(int nCmdShow);
    void SetWindowTitle(const std::string& title);

    // Component accessors
    RawrXD::Editor::ScintillaEditor* GetEditor() const { return editor_.get(); }
    RawrXD::LSP::LSPClient* GetLSPClient() const { return lspClient_.get(); }
    RawrXD::Agentic::AgenticToolIntegration* GetToolIntegration() const { return toolIntegration_.get(); }
    RawrXD::Git::GitIntegration* GetGitIntegration() const { return gitIntegration_.get(); }
    RawrXD::Terminal::ANSITerminalRenderer* GetTerminal() const { return terminal_.get(); }

    // Settings
    bool LoadSettings(const std::string& path);
    bool SaveSettings(const std::string& path);
    IDEConfig& GetConfig() { return config_; }
    const IDEConfig& GetConfig() const { return config_; }
    std::string GetSettingsPath() const;

    // Editor operations
    bool OpenFile(const std::string& path);
    bool SaveFile(const std::string& path);
    bool CloseFile();
    bool NewFile();
    std::string GetCurrentFile() const;
    bool IsModified() const;

    // Ghost text
    void ShowGhostText(const std::string& suggestion);
    void HideGhostText();
    void AcceptGhostText();
    void DismissGhostText();
    bool IsGhostTextVisible() const;
    const GhostTextState& GetGhostTextState() const { return ghostTextState_; }

    // AI generation
    bool StartGeneration(const std::string& prompt);
    void StopGeneration();
    bool IsGenerating() const { return state_ == IDEState::GENERATING; }
    void OnGenerationProgress(const std::string& token);
    void OnGenerationComplete(const std::string& result);

    // LSP operations
    bool InitializeLSP(const std::string& workspaceRoot);
    void ShutdownLSP();
    bool IsLSPConnected() const;

    // Terminal operations
    bool ExecuteCommand(const std::string& command, const std::string& workingDir);
    void ClearTerminal();
    void StopTerminalCommand();

    // Git operations
    bool InitializeGit(const std::string& repoPath);
    void ShowGitDiff(const std::string& filePath);
    void ShowGitBlame(const std::string& filePath);
    void ShowGitLog();

    // Status bar
    void UpdateStatusBar(const StatusBarInfo& info);
    void UpdateStatusBarText(int part, const std::string& text);

    // State
    IDEState GetState() const { return state_; }
    std::string GetStateString() const;
    void SetError(const std::string& error);
    std::string GetLastError() const { return lastError_; }

    // Menu commands
    void OnFileNew();
    void OnFileOpen();
    void OnFileSave();
    void OnFileSaveAs();
    void OnEditUndo();
    void OnEditRedo();
    void OnEditCut();
    void OnEditCopy();
    void OnEditPaste();
    void OnEditFind();
    void OnEditReplace();
    void OnViewToggleLineNumbers();
    void OnViewToggleWordWrap();
    void OnBuildBuild();
    void OnBuildRun();
    void OnBuildClean();
    void OnAIComplete();
    void OnAIExplain();
    void OnAIFix();
    void OnAIStop();
    void OnGitCommit();
    void OnGitPush();
    void OnGitPull();
    void OnHelpAbout();

    // Message loop
    int RunMessageLoop();
    void ProcessPendingMessages();

    // Window procedure (static)
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

private:
    // Window handles
    HWND hMainWindow_ = nullptr;
    HWND hEditorWindow_ = nullptr;
    HWND hStatusBar_ = nullptr;
    HWND hTerminalPanel_ = nullptr;
    HINSTANCE hInstance_ = nullptr;

    // Components
    std::unique_ptr<RawrXD::Editor::ScintillaEditor> editor_;
    std::unique_ptr<RawrXD::LSP::LSPClient> lspClient_;
    std::unique_ptr<RawrXD::Agentic::AgenticToolIntegration> toolIntegration_;
    std::unique_ptr<RawrXD::Git::GitIntegration> gitIntegration_;
    std::unique_ptr<RawrXD::Terminal::ANSITerminalRenderer> terminal_;
    std::unique_ptr<FindReplaceDialog> findDialog_;
    std::unique_ptr<GitCommitDialog> commitDialog_;

    // State
    IDEConfig config_;
    IDEState state_ = IDEState::UNINITIALIZED;
    GhostTextState ghostTextState_;
    std::string lastError_;
    bool initialized_ = false;
    bool generationCancelled_ = false;

    // Current file
    std::string currentFilePath_;
    bool isModified_ = false;

    // Menu IDs
    static constexpr int IDM_FILE_NEW = 100;
    static constexpr int IDM_FILE_OPEN = 101;
    static constexpr int IDM_FILE_SAVE = 102;
    static constexpr int IDM_FILE_SAVEAS = 103;
    static constexpr int IDM_FILE_EXIT = 104;
    static constexpr int IDM_EDIT_UNDO = 200;
    static constexpr int IDM_EDIT_REDO = 201;
    static constexpr int IDM_EDIT_CUT = 202;
    static constexpr int IDM_EDIT_COPY = 203;
    static constexpr int IDM_EDIT_PASTE = 204;
    static constexpr int IDM_EDIT_FIND = 205;
    static constexpr int IDM_EDIT_REPLACE = 206;
    static constexpr int IDM_VIEW_LINENUMBERS = 300;
    static constexpr int IDM_VIEW_WORDWRAP = 301;
    static constexpr int IDM_VIEW_THEME_DARK = 302;
    static constexpr int IDM_VIEW_THEME_LIGHT = 303;
    static constexpr int IDM_BUILD_BUILD = 400;
    static constexpr int IDM_BUILD_RUN = 401;
    static constexpr int IDM_BUILD_CLEAN = 402;
    static constexpr int IDM_AI_COMPLETE = 500;
    static constexpr int IDM_AI_EXPLAIN = 501;
    static constexpr int IDM_AI_FIX = 502;
    static constexpr int IDM_AI_STOP = 503;
    static constexpr int IDM_GIT_COMMIT = 600;
    static constexpr int IDM_GIT_PUSH = 601;
    static constexpr int IDM_GIT_PULL = 602;
    static constexpr int IDM_GIT_DIFF = 603;
    static constexpr int IDM_GIT_BLAME = 604;
    static constexpr int IDM_GIT_LOG = 605;
    static constexpr int IDM_HELP_ABOUT = 900;

    // Status bar parts
    static constexpr int SB_PART_LINE_COL = 0;
    static constexpr int SB_PART_ENCODING = 1;
    static constexpr int SB_PART_GIT = 2;
    static constexpr int SB_PART_MODEL = 3;
    static constexpr int SB_PART_TPS = 4;
    static constexpr int SB_PART_LANGUAGE = 5;
    static constexpr int SB_PART_COUNT = 6;

    // Internal methods
    bool InitializeComponents();
    void CreateMenus();
    void CreateStatusBar();
    void LayoutWindows();
    void UpdateTitle();
    void OnSize(int width, int height);
    void OnEditorModified();
    void OnEditorCaretMoved();
    void OnEditorCharAdded(char ch);
    void RequestGhostText();
    void OnGhostTextKeyDown(WPARAM key);
    bool LoadModel(const std::string& path);
    void UnloadModel();

    // Static instance for WndProc
    static IDECore* s_instance;
};

// ============================================================================
// C API for External Integration
// ============================================================================

extern "C" {
    void* IDECore_Create();
    void IDECore_Destroy(void* core);
    int IDECore_Initialize(void* core, void* hInstance, const char* configPath);
    void IDECore_Shutdown(void* core);
    int IDECore_CreateMainWindow(void* core, const char* title);
    void IDECore_ShowWindow(void* core, int nCmdShow);
    int IDECore_RunMessageLoop(void* core);
    
    int IDECore_OpenFile(void* core, const char* path);
    int IDECore_SaveFile(void* core, const char* path);
    void IDECore_OnFileNew(void* core);
    void IDECore_OnFileOpen(void* core);
    void IDECore_OnAIComplete(void* core);
    void IDECore_OnAIStop(void* core);
    
    int IDECore_IsGhostTextVisible(void* core);
    void IDECore_AcceptGhostText(void* core);
    void IDECore_DismissGhostText(void* core);
    
    int IDECore_StartGeneration(void* core, const char* prompt);
    void IDECore_StopGeneration(void* core);
    int IDECore_IsGenerating(void* core);
    
    void IDECore_SetError(void* core, const char* error);
    const char* IDECore_GetLastError(void* core);
}

} // namespace IDE
} // namespace RawrXD
