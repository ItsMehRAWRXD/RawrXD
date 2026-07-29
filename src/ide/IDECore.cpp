// ============================================================================
// IDECore.cpp - RawrXD IDE Core Integration Implementation
// ============================================================================
// Central hub that wires all production components together
// ============================================================================

#include "IDECore.h"
#include "../editor/ScintillaEditor.h"
#include "../lsp/LSPClient.h"
#include "../agentic/AgenticToolIntegration.h"
#include "../git/GitIntegration.h"
#include "../terminal/ANSITerminalRenderer.h"
#include "../model/GGUFLoader_Fixed.h"
#include "GitDiffViewer.hpp"
#include "FindReplaceDialog.hpp"
#include "GitCommitDialog.hpp"
#include <commctrl.h>
#include <shlobj.h>
#include <sstream>
#include <fstream>
#include <thread>
#include <chrono>
#include <json/json.h>

#pragma comment(lib, "comctl32.lib")

namespace RawrXD {
namespace IDE {

// Static instance for WndProc
IDECore* IDECore::s_instance = nullptr;

// ============================================================================
// Construction/Destruction
// ============================================================================

IDECore::IDECore() {
    s_instance = this;
}

IDECore::~IDECore() {
    Shutdown();
    s_instance = nullptr;
}

// ============================================================================
// Initialization
// ============================================================================

bool IDECore::Initialize(HINSTANCE hInstance, const std::string& configPath) {
    if (initialized_) {
        return true;
    }

    hInstance_ = hInstance;
    state_ = IDEState::INITIALIZING;

    // Load settings
    if (!configPath.empty()) {
        LoadSettings(configPath);
    } else {
        LoadSettings(GetSettingsPath());
    }

    // Initialize common controls
    INITCOMMONCONTROLSEX iccex;
    iccex.dwSize = sizeof(iccex);
    iccex.dwICC = ICC_BAR_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&iccex);

    // Initialize components
    if (!InitializeComponents()) {
        SetError("Failed to initialize components");
        state_ = IDEState::ERROR;
        return false;
    }

    initialized_ = true;
    state_ = IDEState::READY;
    return true;
}

void IDECore::Shutdown() {
    if (!initialized_) {
        return;
    }

    // Save settings
    SaveSettings(GetSettingsPath());

    // Shutdown components
    if (lspClient_) {
        lspClient_->Shutdown();
        lspClient_.reset();
    }

    if (toolIntegration_) {
        toolIntegration_->Shutdown();
        toolIntegration_.reset();
    }

    if (gitIntegration_) {
        gitIntegration_->Shutdown();
        gitIntegration_.reset();
    }

    if (terminal_) {
        terminal_->Shutdown();
        terminal_.reset();
    }

    if (editor_) {
        editor_->Destroy();
        editor_.reset();
    }

    // Destroy windows
    if (hMainWindow_) {
        DestroyWindow(hMainWindow_);
        hMainWindow_ = nullptr;
    }

    initialized_ = false;
    state_ = IDEState::UNINITIALIZED;
}

bool IDECore::InitializeComponents() {
    // Initialize editor
    editor_ = std::make_unique<RawrXD::Editor::ScintillaEditor>();
    if (!editor_->Initialize()) {
        SetError("Failed to initialize Scintilla editor");
        return false;
    }

    // Initialize LSP client
    if (config_.enableLSP) {
        lspClient_ = std::make_unique<RawrXD::LSP::LSPClient>();
        
        // Set up LSP callbacks
        lspClient_->SetDiagnosticsCallback([this](const std::string& uri, 
            const std::vector<RawrXD::LSP::Diagnostic>& diagnostics) {
            // Clear existing diagnostics
            editor_->ClearDiagnostics();
            
            // Add new diagnostics
            for (const auto& diag : diagnostics) {
                editor_->AddDiagnostic(diag.range.start.line, 
                    diag.range.start.character,
                    diag.range.end.line,
                    diag.range.end.character,
                    diag.message,
                    diag.severity);
            }
        });
    }

    // Initialize tool integration
    toolIntegration_ = std::make_unique<RawrXD::Agentic::AgenticToolIntegration>();
    if (!toolIntegration_->Initialize(config_.allowedDirectories)) {
        SetError("Failed to initialize tool integration");
        return false;
    }

    // Initialize Git integration
    gitIntegration_ = std::make_unique<RawrXD::Git::GitIntegration>();

    // Initialize terminal
    terminal_ = std::make_unique<RawrXD::Terminal::ANSITerminalRenderer>();
    if (!terminal_->Initialize()) {
        SetError("Failed to initialize terminal");
        return false;
    }

    return true;
}

// ============================================================================
// Window Management
// ============================================================================

bool IDECore::CreateMainWindow(const std::string& title) {
    // Register window class
    WNDCLASSEXW wcex = {};
    wcex.cbSize = sizeof(wcex);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = hInstance_;
    wcex.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = nullptr;
    wcex.lpszClassName = L"RawrXDIDE";
    wcex.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

    if (!RegisterClassExW(&wcex)) {
        SetError("Failed to register window class");
        return false;
    }

    // Create main window
    hMainWindow_ = CreateWindowExW(
        WS_EX_OVERLAPPEDWINDOW,
        L"RawrXDIDE",
        std::wstring(title.begin(), title.end()).c_str(),
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        config_.windowX, config_.windowY,
        config_.windowWidth, config_.windowHeight,
        nullptr, nullptr, hInstance_, nullptr
    );

    if (!hMainWindow_) {
        SetError("Failed to create main window");
        return false;
    }

    // Create menus
    CreateMenus();

    // Create status bar
    CreateStatusBar();

    // Create editor window
    hEditorWindow_ = editor_->Create(hMainWindow_, hInstance_);
    if (!hEditorWindow_) {
        SetError("Failed to create editor window");
        return false;
    }

    // Create terminal panel
    hTerminalPanel_ = terminal_->Create(hMainWindow_, hInstance_);
    if (!hTerminalPanel_) {
        SetError("Failed to create terminal panel");
        return false;
    }

    // Layout windows
    LayoutWindows();

    // Set up editor callbacks
    editor_->SetOnModifiedCallback([this]() { OnEditorModified(); });
    editor_->SetOnCaretMovedCallback([this]() { OnEditorCaretMoved(); });
    editor_->SetOnCharAddedCallback([this](char ch) { OnEditorCharAdded(ch); });

    // Apply initial settings
    editor_->SetFont(config_.fontName, config_.fontSize);
    editor_->ShowLineNumbers(config_.showLineNumbers);
    editor_->SetWordWrap(config_.wordWrap);
    editor_->SetTheme(config_.theme);

    return true;
}

void IDECore::ShowWindow(int nCmdShow) {
    if (hMainWindow_) {
        ShowWindow(hMainWindow_, nCmdShow);
        UpdateWindow(hMainWindow_);
    }
}

void IDECore::SetWindowTitle(const std::string& title) {
    if (hMainWindow_) {
        std::wstring wtitle(title.begin(), title.end());
        SetWindowTextW(hMainWindow_, wtitle.c_str());
    }
}

void IDECore::CreateMenus() {
    if (!hMainWindow_) return;

    HMENU hMenu = CreateMenu();
    HMENU hFileMenu = CreatePopupMenu();
    HMENU hEditMenu = CreatePopupMenu();
    HMENU hViewMenu = CreatePopupMenu();
    HMENU hBuildMenu = CreatePopupMenu();
    HMENU hAIMenu = CreatePopupMenu();
    HMENU hGitMenu = CreatePopupMenu();
    HMENU hHelpMenu = CreatePopupMenu();

    // File menu
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_NEW, L"&New\tCtrl+N");
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_OPEN, L"&Open...\tCtrl+O");
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_SAVE, L"&Save\tCtrl+S");
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_SAVEAS, L"Save &As...\tCtrl+Shift+S");
    AppendMenuW(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_EXIT, L"E&xit\tAlt+F4");

    // Edit menu
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_UNDO, L"&Undo\tCtrl+Z");
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_REDO, L"&Redo\tCtrl+Y");
    AppendMenuW(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_CUT, L"Cu&t\tCtrl+X");
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_COPY, L"&Copy\tCtrl+C");
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_PASTE, L"&Paste\tCtrl+V");
    AppendMenuW(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_FIND, L"&Find...\tCtrl+F");
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_REPLACE, L"&Replace...\tCtrl+H");

    // View menu
    AppendMenuW(hViewMenu, MF_STRING | (config_.showLineNumbers ? MF_CHECKED : 0), 
                IDM_VIEW_LINENUMBERS, L"Line &Numbers");
    AppendMenuW(hViewMenu, MF_STRING | (config_.wordWrap ? MF_CHECKED : 0), 
                IDM_VIEW_WORDWRAP, L"&Word Wrap");
    AppendMenuW(hViewMenu, MF_SEPARATOR, 0, nullptr);
    HMENU hThemeMenu = CreatePopupMenu();
    AppendMenuW(hThemeMenu, MF_STRING | (config_.theme == "dark" ? MF_CHECKED : 0), 
                IDM_VIEW_THEME_DARK, L"&Dark");
    AppendMenuW(hThemeMenu, MF_STRING | (config_.theme == "light" ? MF_CHECKED : 0), 
                IDM_VIEW_THEME_LIGHT, L"&Light");
    AppendMenuW(hViewMenu, MF_POPUP, (UINT_PTR)hThemeMenu, L"&Theme");

    // Build menu
    AppendMenuW(hBuildMenu, MF_STRING, IDM_BUILD_BUILD, L"&Build\tF7");
    AppendMenuW(hBuildMenu, MF_STRING, IDM_BUILD_RUN, L"&Run\tF5");
    AppendMenuW(hBuildMenu, MF_STRING, IDM_BUILD_CLEAN, L"&Clean");

    // AI menu
    AppendMenuW(hAIMenu, MF_STRING, IDM_AI_COMPLETE, L"&Complete\tCtrl+Space");
    AppendMenuW(hAIMenu, MF_STRING, IDM_AI_EXPLAIN, L"&Explain\tCtrl+Shift+E");
    AppendMenuW(hAIMenu, MF_STRING, IDM_AI_FIX, L"&Fix\tCtrl+Shift+F");
    AppendMenuW(hAIMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hAIMenu, MF_STRING, IDM_AI_STOP, L"&Stop Generation\tEscape");

    // Git menu
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_COMMIT, L"&Commit...");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_PUSH, L"&Push");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_PULL, L"&Pull");
    AppendMenuW(hGitMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_DIFF, L"&Diff");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_BLAME, L"&Blame");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_LOG, L"&Log");

    // Help menu
    AppendMenuW(hHelpMenu, MF_STRING, IDM_HELP_ABOUT, L"&About RawrXD");

    // Attach menus
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"&File");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hEditMenu, L"&Edit");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hViewMenu, L"&View");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hBuildMenu, L"&Build");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hAIMenu, L"&AI");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hGitMenu, L"&Git");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, L"&Help");

    SetMenu(hMainWindow_, hMenu);
}

void IDECore::CreateStatusBar() {
    if (!hMainWindow_) return;

    hStatusBar_ = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, hMainWindow_, nullptr, hInstance_, nullptr);

    // Set parts
    int parts[SB_PART_COUNT] = { 100, 200, 350, 500, 650, -1 };
    SendMessageW(hStatusBar_, SB_SETPARTS, SB_PART_COUNT, (LPARAM)parts);

    // Set initial text
    UpdateStatusBarText(SB_PART_LINE_COL, "Ln 1, Col 1");
    UpdateStatusBarText(SB_PART_ENCODING, "UTF-8");
    UpdateStatusBarText(SB_PART_GIT, "");
    UpdateStatusBarText(SB_PART_MODEL, "No model");
    UpdateStatusBarText(SB_PART_TPS, "");
    UpdateStatusBarText(SB_PART_LANGUAGE, "Text");
}

void IDECore::LayoutWindows() {
    if (!hMainWindow_) return;

    RECT rcClient;
    GetClientRect(hMainWindow_, &rcClient);

    int statusHeight = 22;
    int terminalHeight = 150;
    int editorHeight = rcClient.bottom - statusHeight - terminalHeight;

    // Position editor
    if (hEditorWindow_) {
        SetWindowPos(hEditorWindow_, nullptr, 0, 0, 
                     rcClient.right, editorHeight,
                     SWP_NOZORDER);
    }

    // Position terminal
    if (hTerminalPanel_) {
        SetWindowPos(hTerminalPanel_, nullptr, 0, editorHeight,
                     rcClient.right, terminalHeight,
                     SWP_NOZORDER);
    }

    // Position status bar
    if (hStatusBar_) {
        SendMessageW(hStatusBar_, WM_SIZE, 0, 0);
    }
}

// ============================================================================
// Settings
// ============================================================================

bool IDECore::LoadSettings(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        // Use defaults
        return false;
    }

    try {
        Json::Value root;
        file >> root;

        config_.windowX = root.get("windowX", CW_USEDEFAULT).asInt();
        config_.windowY = root.get("windowY", CW_USEDEFAULT).asInt();
        config_.windowWidth = root.get("windowWidth", 1400).asInt();
        config_.windowHeight = root.get("windowHeight", 900).asInt();
        config_.maximized = root.get("maximized", false).asBool();
        config_.fontName = root.get("fontName", "Consolas").asString();
        config_.fontSize = root.get("fontSize", 11).asInt();
        config_.wordWrap = root.get("wordWrap", false).asBool();
        config_.showLineNumbers = root.get("showLineNumbers", true).asBool();
        config_.theme = root.get("theme", "dark").asString();
        config_.lastProjectPath = root.get("lastProjectPath", "").asString();
        config_.modelPath = root.get("modelPath", "").asString();
        config_.clangdPath = root.get("clangdPath", "clangd.exe").asString();
        config_.maxTokens = root.get("maxTokens", 2048).asInt();
        config_.temperature = root.get("temperature", 0.7f).asFloat();
        config_.enableGhostText = root.get("enableGhostText", true).asBool();
        config_.enableLSP = root.get("enableLSP", true).asBool();

        // Load allowed directories
        const Json::Value& dirs = root["allowedDirectories"];
        if (dirs.isArray()) {
            for (const auto& dir : dirs) {
                config_.allowedDirectories.push_back(dir.asString());
            }
        }

        return true;
    } catch (...) {
        return false;
    }
}

bool IDECore::SaveSettings(const std::string& path) {
    Json::Value root;
    root["windowX"] = config_.windowX;
    root["windowY"] = config_.windowY;
    root["windowWidth"] = config_.windowWidth;
    root["windowHeight"] = config_.windowHeight;
    root["maximized"] = config_.maximized;
    root["fontName"] = config_.fontName;
    root["fontSize"] = config_.fontSize;
    root["wordWrap"] = config_.wordWrap;
    root["showLineNumbers"] = config_.showLineNumbers;
    root["theme"] = config_.theme;
    root["lastProjectPath"] = config_.lastProjectPath;
    root["modelPath"] = config_.modelPath;
    root["clangdPath"] = config_.clangdPath;
    root["maxTokens"] = config_.maxTokens;
    root["temperature"] = config_.temperature;
    root["enableGhostText"] = config_.enableGhostText;
    root["enableLSP"] = config_.enableLSP;

    Json::Value dirs(Json::arrayValue);
    for (const auto& dir : config_.allowedDirectories) {
        dirs.append(dir);
    }
    root["allowedDirectories"] = dirs;

    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }

    file << root.toStyledString();
    return true;
}

std::string IDECore::GetSettingsPath() const {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        return std::string(path) + "\\RawrXD\\settings.json";
    }
    return "settings.json";
}

// ============================================================================
// File Operations
// ============================================================================

bool IDECore::OpenFile(const std::string& path) {
    if (!editor_) return false;

    std::ifstream file(path);
    if (!file.is_open()) {
        SetError("Failed to open file: " + path);
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();

    editor_->SetText(content);
    currentFilePath_ = path;
    isModified_ = false;

    // Detect language
    size_t dot = path.find_last_of('.');
    if (dot != std::string::npos) {
        std::string ext = path.substr(dot + 1);
        if (ext == "cpp" || ext == "h" || ext == "hpp") {
            editor_->SetLanguage("cpp");
            UpdateStatusBarText(SB_PART_LANGUAGE, "C++");
        } else if (ext == "c") {
            editor_->SetLanguage("c");
            UpdateStatusBarText(SB_PART_LANGUAGE, "C");
        } else if (ext == "py") {
            editor_->SetLanguage("python");
            UpdateStatusBarText(SB_PART_LANGUAGE, "Python");
        } else if (ext == "js") {
            editor_->SetLanguage("javascript");
            UpdateStatusBarText(SB_PART_LANGUAGE, "JavaScript");
        } else if (ext == "json") {
            editor_->SetLanguage("json");
            UpdateStatusBarText(SB_PART_LANGUAGE, "JSON");
        } else {
            editor_->SetLanguage("text");
            UpdateStatusBarText(SB_PART_LANGUAGE, "Text");
        }
    }

    // Notify LSP
    if (lspClient_ && lspClient_->IsConnected()) {
        lspClient_->DidOpen("file:///" + path, editor_->GetLanguage(), content);
    }

    UpdateTitle();
    return true;
}

bool IDECore::SaveFile(const std::string& path) {
    if (!editor_) return false;

    std::string content = editor_->GetText();

    std::ofstream file(path);
    if (!file.is_open()) {
        SetError("Failed to save file: " + path);
        return false;
    }

    file << content;
    file.close();

    currentFilePath_ = path;
    isModified_ = false;

    // Notify LSP
    if (lspClient_ && lspClient_->IsConnected()) {
        lspClient_->DidSave("file:///" + path);
    }

    UpdateTitle();
    return true;
}

bool IDECore::CloseFile() {
    if (isModified_) {
        // Prompt to save
        int result = MessageBoxW(hMainWindow_, 
            L"Save changes before closing?",
            L"RawrXD",
            MB_YESNOCANCEL | MB_ICONQUESTION);
        
        if (result == IDCANCEL) {
            return false;
        } else if (result == IDYES) {
            if (!currentFilePath_.empty()) {
                SaveFile(currentFilePath_);
            } else {
                OnFileSaveAs();
            }
        }
    }

    // Notify LSP
    if (lspClient_ && lspClient_->IsConnected() && !currentFilePath_.empty()) {
        lspClient_->DidClose("file:///" + currentFilePath_);
    }

    editor_->ClearAll();
    currentFilePath_.clear();
    isModified_ = false;
    UpdateTitle();

    return true;
}

bool IDECore::NewFile() {
    if (!CloseFile()) {
        return false;
    }

    editor_->ClearAll();
    currentFilePath_.clear();
    isModified_ = false;
    UpdateTitle();

    return true;
}

std::string IDECore::GetCurrentFile() const {
    return currentFilePath_;
}

bool IDECore::IsModified() const {
    return isModified_;
}

void IDECore::UpdateTitle() {
    std::string title = "RawrXD";
    if (!currentFilePath_.empty()) {
        size_t slash = currentFilePath_.find_last_of("/\\");
        std::string filename = (slash != std::string::npos) ? 
                               currentFilePath_.substr(slash + 1) : currentFilePath_;
        title = filename + (isModified_ ? " *" : "") + " - RawrXD";
    }
    SetWindowTitle(title);
}

// ============================================================================
// Ghost Text
// ============================================================================

void IDECore::ShowGhostText(const std::string& suggestion) {
    if (!config_.enableGhostText || !editor_) return;

    ghostTextState_.visible = true;
    ghostTextState_.suggestion = suggestion;
    ghostTextState_.startPos = editor_->GetCurrentPos();
    ghostTextState_.endPos = ghostTextState_.startPos + suggestion.length();

    editor_->ShowGhostText(suggestion);
}

void IDECore::HideGhostText() {
    if (!editor_) return;

    ghostTextState_.visible = false;
    ghostTextState_.suggestion.clear();
    editor_->HideGhostText();
}

void IDECore::AcceptGhostText() {
    if (!ghostTextState_.visible || !editor_) return;

    editor_->InsertText(ghostTextState_.startPos, ghostTextState_.suggestion);
    HideGhostText();
}

void IDECore::DismissGhostText() {
    HideGhostText();
}

bool IDECore::IsGhostTextVisible() const {
    return ghostTextState_.visible;
}

void IDECore::RequestGhostText() {
    if (!config_.enableGhostText || state_ != IDEState::MODEL_LOADED) return;

    // Get context
    int pos = editor_->GetCurrentPos();
    std::string before = editor_->GetTextRange(std::max(0, pos - 500), pos);
    std::string after = editor_->GetTextRange(pos, std::min(pos + 100, editor_->GetLength()));

    // Build prompt for ghost text completion
    std::string prompt = before + "[CURSOR]" + after + "\n\nComplete the code at [CURSOR]:";
    
    // Start async generation
    StartGeneration(prompt);
}

void IDECore::OnGhostTextKeyDown(WPARAM key) {
    if (!ghostTextState_.visible) return;

    if (key == VK_TAB) {
        AcceptGhostText();
    } else if (key == VK_ESCAPE) {
        DismissGhostText();
    } else {
        // Any other key dismisses ghost text
        DismissGhostText();
    }
}

// ============================================================================
// AI Generation
// ============================================================================

bool IDECore::StartGeneration(const std::string& prompt) {
    if (state_ != IDEState::MODEL_LOADED) {
        SetError("No model loaded");
        return false;
    }

    if (state_ == IDEState::GENERATING) {
        SetError("Generation already in progress");
        return false;
    }

    state_ = IDEState::GENERATING;
    generationCancelled_ = false;

    // Start inference in background thread
    std::thread([this, prompt]() {
        // Simulate token generation
        std::string result = "// AI generated completion\n";
        
        // Stream tokens
        for (int i = 0; i < 10 && !generationCancelled_; i++) {
            std::string token = "token_" + std::to_string(i) + " ";
            result += token;
            
            // Update UI on main thread
            PostMessage(hMainWindow_, WM_USER + 100, 0, 
                reinterpret_cast<LPARAM>(new std::string(token)));
            
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        
        // Complete
        PostMessage(hMainWindow_, WM_USER + 101, 0, 
            reinterpret_cast<LPARAM>(new std::string(result)));
    }).detach();

    UpdateStatusBarText(SB_PART_MODEL, "Generating...");
    return true;
}

void IDECore::StopGeneration() {
    generationCancelled_ = true;
    state_ = IDEState::MODEL_LOADED;
    UpdateStatusBarText(SB_PART_MODEL, "Model loaded");
}

void IDECore::OnGenerationProgress(const std::string& token) {
    // Update ghost text with streaming token
    if (ghostTextState_.visible) {
        ghostTextState_.suggestion += token;
        ShowGhostText(ghostTextState_.suggestion);
    }
}

void IDECore::OnGenerationComplete(const std::string& result) {
    state_ = IDEState::MODEL_LOADED;
    UpdateStatusBarText(SB_PART_MODEL, "Model loaded");
}

// ============================================================================
// LSP Operations
// ============================================================================

bool IDECore::InitializeLSP(const std::string& workspaceRoot) {
    if (!lspClient_) return false;

    std::vector<std::string> args;
    return lspClient_->Initialize(config_.clangdPath, args, workspaceRoot);
}

void IDECore::ShutdownLSP() {
    if (lspClient_) {
        lspClient_->Shutdown();
    }
}

bool IDECore::IsLSPConnected() const {
    return lspClient_ && lspClient_->IsConnected();
}

// ============================================================================
// Terminal Operations
// ============================================================================

bool IDECore::ExecuteCommand(const std::string& command, const std::string& workingDir) {
    if (!terminal_) return false;
    return terminal_->ExecuteCommand(command, workingDir);
}

void IDECore::ClearTerminal() {
    if (terminal_) {
        terminal_->Clear();
    }
}

void IDECore::StopTerminalCommand() {
    if (terminal_) {
        terminal_->StopCommand();
    }
}

// ============================================================================
// Git Operations
// ============================================================================

bool IDECore::InitializeGit(const std::string& repoPath) {
    if (!gitIntegration_) return false;
    return gitIntegration_->Initialize(repoPath);
}

void IDECore::ShowGitDiff(const std::string& filePath) {
    if (!gitIntegration_) return;
    
    // Show the Git diff dialog
    GitDiffDialog::ShowForFile(hMainWindow_, filePath);
}

void IDECore::ShowGitBlame(const std::string& filePath) {
    if (!gitIntegration_) return;
    
    // Execute git blame and show results
    std::string blameOutput = gitIntegration_->GetBlame(filePath);
    if (!blameOutput.empty()) {
        // Show in output panel or dedicated blame view
        MessageBoxA(hMainWindow_, blameOutput.c_str(), 
                    ("Git Blame - " + filePath).c_str(), 
                    MB_OK | MB_ICONINFORMATION);
    }
}

void IDECore::ShowGitLog() {
    if (!gitIntegration_) return;
    
    // Execute git log and show results
    std::string logOutput = gitIntegration_->GetLog(20); // Last 20 commits
    if (!logOutput.empty()) {
        // Show in output panel or dedicated log view
        MessageBoxA(hMainWindow_, logOutput.c_str(), 
                    "Git Log", MB_OK | MB_ICONINFORMATION);
    }
}

// ============================================================================
// Status Bar
// ============================================================================

void IDECore::UpdateStatusBar(const StatusBarInfo& info) {
    UpdateStatusBarText(SB_PART_LINE_COL, info.lineCol);
    UpdateStatusBarText(SB_PART_ENCODING, info.encoding);
    UpdateStatusBarText(SB_PART_GIT, info.gitBranch);
    UpdateStatusBarText(SB_PART_MODEL, info.modelStatus);
    UpdateStatusBarText(SB_PART_TPS, info.tps);
    UpdateStatusBarText(SB_PART_LANGUAGE, info.language);
}

void IDECore::UpdateStatusBarText(int part, const std::string& text) {
    if (!hStatusBar_) return;
    std::wstring wtext(text.begin(), text.end());
    SendMessageW(hStatusBar_, SB_SETTEXTW, part, (LPARAM)wtext.c_str());
}

// ============================================================================
// State
// ============================================================================

std::string IDECore::GetStateString() const {
    switch (state_) {
        case IDEState::UNINITIALIZED: return "Uninitialized";
        case IDEState::INITIALIZING: return "Initializing";
        case IDEState::READY: return "Ready";
        case IDEState::LOADING_MODEL: return "Loading model...";
        case IDEState::MODEL_LOADED: return "Model loaded";
        case IDEState::GENERATING: return "Generating...";
        case IDEState::ERROR: return "Error: " + lastError_;
        default: return "Unknown";
    }
}

void IDECore::SetError(const std::string& error) {
    lastError_ = error;
    state_ = IDEState::ERROR;
}

// ============================================================================
// Menu Commands
// ============================================================================

void IDECore::OnFileNew() {
    NewFile();
}

void IDECore::OnFileOpen() {
    wchar_t filename[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMainWindow_;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"All Files (*.*)\0*.*\0C++ Files (*.cpp;*.h;*.hpp)\0*.cpp;*.h;*.hpp\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) {
        std::string path(filename, filename + wcslen(filename));
        OpenFile(path);
    }
}

void IDECore::OnFileSave() {
    if (currentFilePath_.empty()) {
        OnFileSaveAs();
    } else {
        SaveFile(currentFilePath_);
    }
}

void IDECore::OnFileSaveAs() {
    wchar_t filename[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMainWindow_;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"All Files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameW(&ofn)) {
        std::string path(filename, filename + wcslen(filename));
        SaveFile(path);
    }
}

void IDECore::OnEditUndo() {
    if (editor_) editor_->Undo();
}

void IDECore::OnEditRedo() {
    if (editor_) editor_->Redo();
}

void IDECore::OnEditCut() {
    if (editor_) editor_->Cut();
}

void IDECore::OnEditCopy() {
    if (editor_) editor_->Copy();
}

void IDECore::OnEditPaste() {
    if (editor_) editor_->Paste();
}

void IDECore::OnEditFind() {
    if (!findDialog_) {
        findDialog_ = std::make_unique<FindReplaceDialog>();
        findDialog_->Create(hMainWindow_, false);
        
        // Set callback
        findDialog_->SetFindCallback([this](const std::string& text, const FindOptions& opts) {
            if (editor_) {
                // Use editor's find functionality
                bool found = editor_->FindNext(text, opts.caseSensitive, 
                    opts.direction == FindDirection::Forward);
                return found;
            }
            return false;
        });
    } else {
        findDialog_->Create(hMainWindow_, false);
    }
    
    // Pre-populate with selected text
    if (editor_) {
        std::string sel = editor_->GetSelectedText();
        if (!sel.empty() && sel.find('\n') == std::string::npos) {
            findDialog_->SetFindText(sel);
        }
    }
}

void IDECore::OnEditReplace() {
    if (!findDialog_) {
        findDialog_ = std::make_unique<FindReplaceDialog>();
    }
    findDialog_->Create(hMainWindow_, true);
    
    // Set callbacks
    findDialog_->SetFindCallback([this](const std::string& text, const FindOptions& opts) {
        if (editor_) {
            return editor_->FindNext(text, opts.caseSensitive, 
                opts.direction == FindDirection::Forward);
        }
        return false;
    });
    
    findDialog_->SetReplaceCallback([this](const std::string& find, const std::string& replace, 
                                            const FindOptions& opts) {
        if (editor_) {
            return editor_->ReplaceAndFindNext(find, replace, opts.caseSensitive);
        }
        return false;
    });
    
    findDialog_->SetReplaceAllCallback([this](const std::string& find, const std::string& replace,
                                                const FindOptions& opts) {
        if (editor_) {
            return editor_->ReplaceAll(find, replace, opts.caseSensitive);
        }
        return 0;
    });
    
    // Pre-populate with selected text
    if (editor_) {
        std::string sel = editor_->GetSelectedText();
        if (!sel.empty() && sel.find('\n') == std::string::npos) {
            findDialog_->SetFindText(sel);
        }
    }
}

void IDECore::OnViewToggleLineNumbers() {
    config_.showLineNumbers = !config_.showLineNumbers;
    if (editor_) editor_->ShowLineNumbers(config_.showLineNumbers);
    
    HMENU hMenu = GetMenu(hMainWindow_);
    CheckMenuItem(hMenu, IDM_VIEW_LINENUMBERS, 
                  config_.showLineNumbers ? MF_CHECKED : MF_UNCHECKED);
}

void IDECore::OnViewToggleWordWrap() {
    config_.wordWrap = !config_.wordWrap;
    if (editor_) editor_->SetWordWrap(config_.wordWrap);
    
    HMENU hMenu = GetMenu(hMainWindow_);
    CheckMenuItem(hMenu, IDM_VIEW_WORDWRAP, 
                  config_.wordWrap ? MF_CHECKED : MF_UNCHECKED);
}

void IDECore::OnBuildBuild() {
    ExecuteCommand("cmake --build build", config_.lastProjectPath);
}

void IDECore::OnBuildRun() {
    // Execute the built executable
    std::string runCmd = config_.lastProjectPath.empty() ? 
        ".\\build\\RawrXD_IDE.exe" : 
        config_.lastProjectPath + "\\build\\RawrXD_IDE.exe";
    ExecuteCommand(runCmd, config_.lastProjectPath);
}

void IDECore::OnBuildClean() {
    ExecuteCommand("cmake --build build --target clean", config_.lastProjectPath);
}

void IDECore::OnAIComplete() {
    RequestGhostText();
}

void IDECore::OnAIExplain() {
    if (!editor_) return;
    
    std::string selected = editor_->GetSelectedText();
    if (selected.empty()) {
        MessageBoxA(hMainWindow_, "Please select code to explain.", "AI Explain",
                    MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    // Build prompt
    std::string prompt = "Explain this code:\n\n```\n" + selected + "\n```\n\n";
    prompt += "Provide a clear explanation of what this code does, including:\n";
    prompt += "- The purpose of each function/statement\n";
    prompt += "- Any important algorithms or patterns used\n";
    prompt += "- Potential edge cases or issues\n";
    
    StartGeneration(prompt);
}

void IDECore::OnAIFix() {
    if (!editor_) return;
    
    std::string selected = editor_->GetSelectedText();
    if (selected.empty()) {
        MessageBoxA(hMainWindow_, "Please select code to fix.", "AI Fix",
                    MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    // Build prompt
    std::string prompt = "Fix any issues in this code:\n\n```\n" + selected + "\n```\n\n";
    prompt += "Please:\n";
    prompt += "1. Identify any bugs, security issues, or code smells\n";
    prompt += "2. Provide the corrected version\n";
    prompt += "3. Explain what was fixed and why\n";
    
    StartGeneration(prompt);
}

void IDECore::OnAIStop() {
    StopGeneration();
}

void IDECore::OnGitCommit() {
    if (!gitIntegration_) return;
    
    // Get repository status
    auto files = gitIntegration_->GetStatus();
    if (files.empty()) {
        MessageBoxA(hMainWindow_, "No changes to commit.", "Git Commit", 
                      MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    // Create and show commit dialog
    commitDialog_ = std::make_unique<GitCommitDialog>();
    commitDialog_->Create(hMainWindow_);
    commitDialog_->SetBranchName(gitIntegration_->GetCurrentBranch());
    
    // Convert to dialog format
    std::vector<GitFileStatus> dialogFiles;
    for (const auto& f : files) {
        GitFileStatus gfs;
        gfs.path = f.path;
        gfs.status = f.status;
        gfs.staged = f.staged;
        dialogFiles.push_back(gfs);
    }
    commitDialog_->SetFiles(dialogFiles);
    
    // Set callbacks
    commitDialog_->SetStageFileCallback([this](const std::string& path, bool stage) {
        if (stage) {
            gitIntegration_->StageFile(path);
        } else {
            gitIntegration_->UnstageFile(path);
        }
    });
    
    commitDialog_->SetGetDiffCallback([this](const std::string& path) {
        return gitIntegration_->GetDiff(path);
    });
    
    commitDialog_->SetCommitCallback([this](const CommitResult& result) {
        if (result.amend) {
            return gitIntegration_->CommitAmend(result.message);
        } else {
            return gitIntegration_->Commit(result.message, result.signOff);
        }
    });
    
    // Show modal
    commitDialog_->ShowModal();
}

void IDECore::OnGitPush() {
    if (gitIntegration_) {
        gitIntegration_->Push("origin", gitIntegration_->GetCurrentBranch());
    }
}

void IDECore::OnGitPull() {
    if (gitIntegration_) {
        gitIntegration_->Pull("origin", gitIntegration_->GetCurrentBranch());
    }
}

void IDECore::OnHelpAbout() {
    MessageBoxW(hMainWindow_, 
        L"RawrXD Sovereign IDE v1.0\n\n"
        L"A native Win32 AI-assisted development environment\n"
        L"with local model inference and zero cloud dependency.",
        L"About RawrXD",
        MB_OK | MB_ICONINFORMATION);
}

// ============================================================================
// Editor Event Handlers
// ============================================================================

void IDECore::OnEditorModified() {
    isModified_ = true;
    UpdateTitle();

    // Notify LSP of change
    if (lspClient_ && lspClient_->IsConnected() && !currentFilePath_.empty()) {
        // Send incremental changes
        std::vector<RawrXD::LSP::TextEdit> changes;
        RawrXD::LSP::TextEdit edit;
        edit.range.start.line = 0;
        edit.range.start.character = 0;
        edit.range.end.line = editor_->GetLineCount();
        edit.range.end.character = 0;
        edit.newText = editor_->GetText();
        changes.push_back(edit);
        lspClient_->DidChange("file:///" + currentFilePath_, changes);
    }
}

void IDECore::OnEditorCaretMoved() {
    if (!editor_) return;

    int line = editor_->GetCurrentLine();
    int col = editor_->GetCurrentColumn();

    std::ostringstream oss;
    oss << "Ln " << (line + 1) << ", Col " << (col + 1);
    UpdateStatusBarText(SB_PART_LINE_COL, oss.str());
}

void IDECore::OnEditorCharAdded(char ch) {
    // Trigger ghost text on certain characters
    if (ch == ' ' || ch == '(' || ch == '.' || ch == '>' || ch == ':') {
        RequestGhostText();
    }

    // Trigger autocomplete
    if (config_.enableAutocomplete && lspClient_ && lspClient_->IsConnected()) {
        RawrXD::LSP::Position pos;
        pos.line = editor_->GetCurrentLine();
        pos.character = editor_->GetCurrentColumn();
        
        lspClient_->Completion("file:///" + currentFilePath_, pos,
            [this](const std::vector<RawrXD::LSP::CompletionItem>& items) {
                // Show autocomplete popup with completion items
                if (!items.empty() && editor_) {
                    editor_->ShowAutocomplete(items);
                }
            });
    }
}

// ============================================================================
// Message Loop
// ============================================================================

int IDECore::RunMessageLoop() {
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

void IDECore::ProcessPendingMessages() {
    MSG msg;
    while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

// ============================================================================
// Window Procedure
// ============================================================================

LRESULT CALLBACK IDECore::WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    IDECore* core = s_instance;

    switch (message) {
        case WM_CREATE:
            return 0;

        case WM_SIZE:
            if (core) {
                core->LayoutWindows();
            }
            return 0;

        case WM_COMMAND:
            if (core) {
                int wmId = LOWORD(wParam);
                switch (wmId) {
                    case IDM_FILE_NEW: core->OnFileNew(); break;
                    case IDM_FILE_OPEN: core->OnFileOpen(); break;
                    case IDM_FILE_SAVE: core->OnFileSave(); break;
                    case IDM_FILE_SAVEAS: core->OnFileSaveAs(); break;
                    case IDM_FILE_EXIT: DestroyWindow(hWnd); break;
                    case IDM_EDIT_UNDO: core->OnEditUndo(); break;
                    case IDM_EDIT_REDO: core->OnEditRedo(); break;
                    case IDM_EDIT_CUT: core->OnEditCut(); break;
                    case IDM_EDIT_COPY: core->OnEditCopy(); break;
                    case IDM_EDIT_PASTE: core->OnEditPaste(); break;
                    case IDM_EDIT_FIND: core->OnEditFind(); break;
                    case IDM_EDIT_REPLACE: core->OnEditReplace(); break;
                    case IDM_VIEW_LINENUMBERS: core->OnViewToggleLineNumbers(); break;
                    case IDM_VIEW_WORDWRAP: core->OnViewToggleWordWrap(); break;
                    case IDM_VIEW_THEME_DARK: core->config_.theme = "dark"; break;
                    case IDM_VIEW_THEME_LIGHT: core->config_.theme = "light"; break;
                    case IDM_BUILD_BUILD: core->OnBuildBuild(); break;
                    case IDM_BUILD_RUN: core->OnBuildRun(); break;
                    case IDM_BUILD_CLEAN: core->OnBuildClean(); break;
                    case IDM_AI_COMPLETE: core->OnAIComplete(); break;
                    case IDM_AI_EXPLAIN: core->OnAIExplain(); break;
                    case IDM_AI_FIX: core->OnAIFix(); break;
                    case IDM_AI_STOP: core->OnAIStop(); break;
                    case IDM_GIT_COMMIT: core->OnGitCommit(); break;
                    case IDM_GIT_PUSH: core->OnGitPush(); break;
                    case IDM_GIT_PULL: core->OnGitPull(); break;
                    case IDM_GIT_DIFF: core->ShowGitDiff(core->GetCurrentFile()); break;
                    case IDM_GIT_BLAME: core->ShowGitBlame(core->GetCurrentFile()); break;
                    case IDM_GIT_LOG: core->ShowGitLog(); break;
                    case IDM_HELP_ABOUT: core->OnHelpAbout(); break;
                    default:
                        return DefWindowProc(hWnd, message, wParam, lParam);
                }
            }
            return 0;

        case WM_KEYDOWN:
            if (core && core->IsGhostTextVisible()) {
                core->OnGhostTextKeyDown(wParam);
            }
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }
}

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

void* IDECore_Create() {
    return new IDECore();
}

void IDECore_Destroy(void* core) {
    delete static_cast<IDECore*>(core);
}

int IDECore_Initialize(void* core, void* hInstance, const char* configPath) {
    auto* c = static_cast<IDECore*>(core);
    return c->Initialize(static_cast<HINSTANCE>(hInstance), configPath ? configPath : "") ? 1 : 0;
}

void IDECore_Shutdown(void* core) {
    auto* c = static_cast<IDECore*>(core);
    c->Shutdown();
}

int IDECore_CreateMainWindow(void* core, const char* title) {
    auto* c = static_cast<IDECore*>(core);
    return c->CreateMainWindow(title ? title : "RawrXD") ? 1 : 0;
}

void IDECore_ShowWindow(void* core, int nCmdShow) {
    auto* c = static_cast<IDECore*>(core);
    c->ShowWindow(nCmdShow);
}

int IDECore_RunMessageLoop(void* core) {
    auto* c = static_cast<IDECore*>(core);
    return c->RunMessageLoop();
}

int IDECore_OpenFile(void* core, const char* path) {
    auto* c = static_cast<IDECore*>(core);
    return c->OpenFile(path ? path : "") ? 1 : 0;
}

int IDECore_SaveFile(void* core, const char* path) {
    auto* c = static_cast<IDECore*>(core);
    return c->SaveFile(path ? path : "") ? 1 : 0;
}

void IDECore_OnFileNew(void* core) {
    auto* c = static_cast<IDECore*>(core);
    c->OnFileNew();
}

void IDECore_OnFileOpen(void* core) {
    auto* c = static_cast<IDECore*>(core);
    c->OnFileOpen();
}

void IDECore_OnAIComplete(void* core) {
    auto* c = static_cast<IDECore*>(core);
    c->OnAIComplete();
}

void IDECore_OnAIStop(void* core) {
    auto* c = static_cast<IDECore*>(core);
    c->OnAIStop();
}

int IDECore_IsGhostTextVisible(void* core) {
    auto* c = static_cast<IDECore*>(core);
    return c->IsGhostTextVisible() ? 1 : 0;
}

void IDECore_AcceptGhostText(void* core) {
    auto* c = static_cast<IDECore*>(core);
    c->AcceptGhostText();
}

void IDECore_DismissGhostText(void* core) {
    auto* c = static_cast<IDECore*>(core);
    c->DismissGhostText();
}

int IDECore_StartGeneration(void* core, const char* prompt) {
    auto* c = static_cast<IDECore*>(core);
    return c->StartGeneration(prompt ? prompt : "") ? 1 : 0;
}

void IDECore_StopGeneration(void* core) {
    auto* c = static_cast<IDECore*>(core);
    c->StopGeneration();
}

int IDECore_IsGenerating(void* core) {
    auto* c = static_cast<IDECore*>(core);
    return c->IsGenerating() ? 1 : 0;
}

void IDECore_SetError(void* core, const char* error) {
    auto* c = static_cast<IDECore*>(core);
    c->SetError(error ? error : "");
}

const char* IDECore_GetLastError(void* core) {
    auto* c = static_cast<IDECore*>(core);
    static std::string error;
    error = c->GetLastError();
    return error.c_str();
}

} // extern "C"

} // namespace IDE
} // namespace RawrXD
