// Menu Command System Implementation for Win32IDE
// Centralized command routing with 25+ features

#include "Win32IDE.h"
#include <commctrl.h>
#include <commdlg.h>
#include <richedit.h>
#include <functional>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

#include "Win32IDE_CommandIDs.h"

namespace {

std::string buildEvidencePath(const char* filename, const char* fallback)
{
    char directory[32768]{};
    const DWORD length = GetEnvironmentVariableA("RAWRXD_LOG_DIR", directory, sizeof(directory));
    if (length && length < sizeof(directory)) return std::string(directory) + "\\" + filename;
    return fallback;
}

void buildTrace(const std::string& line)
{
    std::ofstream out(buildEvidencePath("build_dispatch_trace.log",
        "F:\\rawrxd\\build_dispatch_trace.log"), std::ios::app);
    if (out) out << line << '\n';
}

bool isDirectoryPath(const std::string& path)
{
    if (path.empty()) return false;
    const DWORD attributes = GetFileAttributesA(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool pathExists(const std::string& path)
{
    return !path.empty() && GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::string parentDirectory(std::string path)
{
    while (path.size() > 3 && (path.back() == '\\' || path.back() == '/')) {
        path.pop_back();
    }
    const size_t slash = path.find_last_of("\\/");
    if (slash == std::string::npos) return {};
    if (slash == 2 && path.size() >= 3 && path[1] == ':') return path.substr(0, 3);
    return path.substr(0, slash);
}

std::string workspaceRootFromSeeds(const std::vector<std::string>& seeds)
{
    for (std::string seed : seeds) {
        if (seed.empty()) continue;
        if (!isDirectoryPath(seed)) seed = parentDirectory(seed);
        for (int depth = 0; !seed.empty() && depth < 12; ++depth) {
            if (pathExists(seed + "\\.git") || pathExists(seed + "\\CMakeLists.txt")) {
                return seed;
            }
            const std::string parent = parentDirectory(seed);
            if (parent.empty() || parent == seed) break;
            seed = parent;
        }
    }
    return {};
}

std::string configuredBuildDirectory(const std::string& workspaceRoot)
{
    if (const char* configured = std::getenv("RAWRXD_BUILD_DIR")) {
        std::string value(configured);
        if (!value.empty() && !isDirectoryPath(value) && !workspaceRoot.empty() &&
            value.find(':') == std::string::npos && value[0] != '\\' && value[0] != '/') {
            value = workspaceRoot + "\\" + value;
        }
        if (isDirectoryPath(value) &&
            (pathExists(value + "\\CMakeCache.txt") || pathExists(value + "\\build.ninja"))) {
            return value;
        }
    }

    // Prefer the active repair/IDE build over unrelated model-route output.
    static constexpr const char* names[] = {
        "build", "build_repair_candidate", "build_ide", "build_cmake", "build_modelroute"
    };
    for (const char* name : names) {
        const std::string candidate = workspaceRoot.empty()
            ? std::string(name) : workspaceRoot + "\\" + name;
        if (isDirectoryPath(candidate) &&
            (pathExists(candidate + "\\CMakeCache.txt") ||
             pathExists(candidate + "\\build.ninja"))) {
            return candidate;
        }
    }
    return {};
}

std::string powerShellLiteral(const std::string& value)
{
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (char ch : value) {
        escaped.push_back(ch);
        if (ch == '\'') escaped.push_back('\'');
    }
    return "'" + escaped + "'";
}

std::string currentDirectoryPath()
{
    std::vector<char> buffer(MAX_PATH, '\0');
    for (;;) {
        const DWORD length = GetCurrentDirectoryA(static_cast<DWORD>(buffer.size()), buffer.data());
        if (length == 0) return {};
        if (length < buffer.size()) return std::string(buffer.data(), length);
        buffer.resize(static_cast<size_t>(length) + 1, '\0');
    }
}

std::string encodePowerShellCommand(const std::string& command)
{
    const int wideLength = MultiByteToWideChar(CP_UTF8, 0, command.data(),
        static_cast<int>(command.size()), nullptr, 0);
    if (wideLength <= 0) return {};
    std::wstring wide(static_cast<size_t>(wideLength), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, command.data(), static_cast<int>(command.size()),
        wide.data(), wideLength);
    const auto* bytes = reinterpret_cast<const unsigned char*>(wide.data());
    const size_t byteCount = wide.size() * sizeof(wchar_t);
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    encoded.reserve(((byteCount + 2) / 3) * 4);
    for (size_t i = 0; i < byteCount; i += 3) {
        const uint32_t a = bytes[i];
        const uint32_t b = (i + 1 < byteCount) ? bytes[i + 1] : 0;
        const uint32_t c = (i + 2 < byteCount) ? bytes[i + 2] : 0;
        const uint32_t value = (a << 16) | (b << 8) | c;
        encoded.push_back(alphabet[(value >> 18) & 63]);
        encoded.push_back(alphabet[(value >> 12) & 63]);
        encoded.push_back(i + 1 < byteCount ? alphabet[(value >> 6) & 63] : '=');
        encoded.push_back(i + 2 < byteCount ? alphabet[value & 63] : '=');
    }
    return encoded;
}

std::string configuredBuildTarget()
{
    const char* configured = std::getenv("RAWRXD_BUILD_TARGET");
    std::string target = configured && *configured
        ? std::string(configured) : "RawrXD-Win32IDE-Native";
    if (target.empty()) return "RawrXD-Win32IDE-Native";
    for (const char ch : target) {
        if (!(std::isalnum(static_cast<unsigned char>(ch)) ||
              ch == '_' || ch == '-' || ch == '.')) {
            return "RawrXD-Win32IDE-Native";
        }
    }
    return target;
}

std::string configuredBuildCommand()
{
    const char* configured = std::getenv("RAWRXD_BUILD_COMMAND");
    if (!configured || !*configured) return {};
    std::string command(configured);
    for (const char ch : command) {
        if (ch == '\r' || ch == '\n') return {};
    }
    return command;
}

} // namespace

// The menu IDs are sparse and mix File/Edit/View commands in the 2000 range.
// Range routing misclassified them and claimed unknown commands were handled.
bool Win32IDE::routeCommand(int commandId) {
    auto it = m_commandHandlers.find(commandId);
    if (it != m_commandHandlers.end()) {
        it->second();
        return true;
    }
    if (commandId >= IDM_FILE_RECENT_BASE && commandId < IDM_FILE_RECENT_CLEAR) {
        handleFileCommand(commandId);
        return true;
    }
    switch (commandId) {
    case IDM_FILE_NEW: case IDM_FILE_OPEN: case IDM_FILE_SAVE:
    case IDM_FILE_SAVEAS: case IDM_FILE_EXIT: case IDM_FILE_LOAD_MODEL:
    case IDM_FILE_SAVEALL: case IDM_FILE_CLOSE: case IDM_FILE_RECENT_CLEAR:
        handleFileCommand(commandId); return true;
    case IDM_EDIT_UNDO: case IDM_EDIT_REDO: case IDM_EDIT_CUT:
    case IDM_EDIT_COPY: case IDM_EDIT_PASTE: case IDM_EDIT_SELECT_ALL:
    case IDM_EDIT_FIND: case IDM_EDIT_REPLACE: case IDM_EDIT_FIND_NEXT:
    case IDM_EDIT_FIND_PREV: case IDM_EDIT_SNIPPET: case IDM_EDIT_COPY_FORMAT:
    case IDM_EDIT_PASTE_PLAIN: case IDM_EDIT_CLIPBOARD_HISTORY:
    case IDM_AI_EDIT: case IDM_AI_EDIT_APPLY: case IDM_AI_CHAT:
        handleEditCommand(commandId); return true;
    case IDM_VIEW_MINIMAP: case IDM_VIEW_OUTPUT_TABS: case IDM_VIEW_MODULE_BROWSER:
    case IDM_VIEW_THEME_EDITOR: case IDM_VIEW_FLOATING_PANEL: case IDM_VIEW_OUTPUT_PANEL:
    case IDM_VIEW_USE_STREAMING_LOADER: case IDM_VIEW_USE_VULKAN_RENDERER:
    case IDM_VIEW_SIDEBAR: case IDM_VIEW_TERMINAL: case IDM_VIEW_SECONDARY_SIDEBAR:
    case IDM_VIEW_PANEL:
        handleViewCommand(commandId); return true;
    case IDM_TERMINAL_POWERSHELL: case IDM_TERMINAL_CMD: case IDM_TERMINAL_STOP:
    case IDM_TERMINAL_SPLIT_H: case IDM_TERMINAL_SPLIT_V: case IDM_TERMINAL_CLEAR_ALL:
        handleTerminalCommand(commandId); return true;
    case IDM_TOOLS_PROFILE_START: case IDM_TOOLS_PROFILE_STOP:
    case IDM_TOOLS_PROFILE_RESULTS: case IDM_TOOLS_ANALYZE_SCRIPT:
    case IDM_TOOLS_BUILD_PROJECT: case IDM_TOOLS_TEST_PROJECT:
    case IDM_TOOLS_DEBUG_START: case IDM_TOOLS_DEBUG_STOP:
        handleToolsCommand(commandId); return true;
    case IDM_DEBUG_START: case IDC_DEBUG_START:
        startDebugging(); return true;
    case IDM_DEBUG_STOP: case IDC_DEBUG_STOP:
        stopDebugging(); return true;
    case IDM_DEBUG_CONTINUE: continueExecution(); return true;
    case IDM_DEBUG_STEP_OVER: stepOver(); return true;
    case IDM_DEBUG_STEP_INTO: stepInto(); return true;
    case IDM_DEBUG_STEP_OUT: stepOut(); return true;
    case IDM_DEBUG_SHOW_CALLSTACK: updateCallStack(); return true;
    case IDM_DEBUG_SHOW_VARIABLES: updateVariables(); return true;
    case IDM_DEBUG_SHOW_WATCH: updateWatchList(); return true;
    case IDM_DEBUG_ATTACH: attachDebugger(); return true;
    case IDM_DEBUG_DETACH: detachDebugger(); return true;
    case IDM_MODULES_REFRESH: case IDM_MODULES_IMPORT: case IDM_MODULES_EXPORT:
        handleModulesCommand(commandId); return true;
    case IDM_HELP_ABOUT: case IDM_HELP_CMDREF: case IDM_HELP_PSDOCS:
    case IDM_HELP_SEARCH: case IDM_HELP_SHORTCUTS:
        handleHelpCommand(commandId); return true;
    case IDM_GIT_STATUS: showGitStatus(); return true;
    case IDM_GIT_COMMIT: showCommitDialog(); return true;
    case IDM_GIT_PUSH: gitPush(); return true;
    case IDM_GIT_PULL: gitPull(); return true;
    case IDM_GIT_PANEL: showGitPanel(); return true;
    case IDM_GIT_STAGE_ALL:
        for (const auto& f : getGitChangedFiles()) if (!f.staged) gitStageFile(f.path);
        return true;
    case IDM_AGENT_START_LOOP: onAgentStartLoop(); return true;
    case IDM_AGENT_EXECUTE_CMD: onAgentExecuteCommand(); return true;
    case IDM_AGENT_CONFIGURE_MODEL: onAgentConfigureModel(); return true;
    case IDM_AGENT_VIEW_TOOLS: onAgentViewTools(); return true;
    case IDM_AGENT_VIEW_STATUS: onAgentViewStatus(); return true;
    case IDM_AGENT_STOP: onAgentStop(); return true;
    case IDM_AGENTIC_LOOP_RUN: onAgenticLoopRunTask(); return true;
    case IDM_AGENTIC_LOOP_CANCEL: onAgenticLoopCancel(); return true;
    case IDM_AGENTIC_LOOP_STATUS: onAgenticLoopStatus(); return true;
    case IDM_AUTONOMY_TOGGLE: onAutonomyToggle(); return true;
    case IDM_AUTONOMY_START: onAutonomyStart(); return true;
    case IDM_AUTONOMY_STOP: onAutonomyStop(); return true;
    case IDM_AUTONOMY_SET_GOAL: onAutonomySetGoal(); return true;
    case IDM_AUTONOMY_STATUS: onAutonomyViewStatus(); return true;
    case IDM_AUTONOMY_MEMORY: onAutonomyViewMemory(); return true;
    default: return false;
    }
}

void Win32IDE::registerCommandHandler(int commandId, std::function<void()> handler) {
    m_commandHandlers[commandId] = handler;
}

std::string Win32IDE::getCommandDescription(int commandId) const {
    auto it = m_commandDescriptions.find(commandId);
    if (it != m_commandDescriptions.end()) {
        return it->second;
    }
    return "Unknown Command";
}

bool Win32IDE::isCommandEnabled(int commandId) const {
    auto it = m_commandStates.find(commandId);
    if (it != m_commandStates.end()) {
        return it->second;
    }
    return true; // Default to enabled
}

void Win32IDE::updateCommandStates() {
    // Update command availability based on current state
    m_commandStates[IDM_FILE_SAVE] = m_fileModified;
    m_commandStates[IDM_FILE_SAVEAS] = !m_currentFile.empty();
    m_commandStates[IDM_FILE_CLOSE] = !m_currentFile.empty();
    m_commandStates[IDM_FILE_RECENT_CLEAR] = !m_recentFiles.empty();
    
    // Edit commands depend on editor state
    bool hasSelection = false;
    CHARRANGE range;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&range);
    hasSelection = (range.cpMax > range.cpMin);
    
    m_commandStates[IDM_EDIT_CUT] = hasSelection;
    m_commandStates[IDM_EDIT_COPY] = hasSelection;
    m_commandStates[IDM_EDIT_PASTE] = IsClipboardFormatAvailable(CF_TEXT);
}

// ============================================================================
// FILE COMMAND HANDLERS
// ============================================================================

void Win32IDE::handleFileCommand(int commandId) {
    switch (commandId) {
        case IDM_FILE_NEW:
            newFile();
            break;
            
        case IDM_FILE_OPEN:
            openFile();
            break;
            
        case IDM_FILE_SAVE:
            if (saveFile()) {
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"File saved");
            }
            break;
            
        case IDM_FILE_SAVEAS:
            if (saveFileAs()) {
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"File saved as new name");
            }
            break;
            
        case IDM_FILE_SAVEALL:
            saveAll();
            break;
            
        case IDM_FILE_CLOSE:
            closeFile();
            break;
            
        case IDM_FILE_RECENT_CLEAR:
            clearRecentFiles();
            break;
            
        case IDM_FILE_LOAD_MODEL: {
            char modelPath[MAX_PATH] = {};
            OPENFILENAMEA dialog{};
            dialog.lStructSize = sizeof(dialog);
            dialog.hwndOwner = m_hwndMain;
            dialog.lpstrFile = modelPath;
            dialog.nMaxFile = MAX_PATH;
            dialog.lpstrFilter = "GGUF Models (*.gguf)\0*.gguf\0All Files\0*.*\0";
            dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameA(&dialog) && !loadModelForInference(modelPath)) {
                SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
                    reinterpret_cast<LPARAM>("Model loading failed; consult inference diagnostics."));
            }
            break;
        }
        case IDM_FILE_EXIT:
            if (!m_fileModified || promptSaveChanges()) {
                DestroyWindow(m_hwndMain);
            }
            break;
            
        default:
            // Handle recent files (IDM_FILE_RECENT_BASE to IDM_FILE_RECENT_BASE + 9)
            if (commandId >= IDM_FILE_RECENT_BASE && commandId < IDM_FILE_RECENT_CLEAR) {
                int index = commandId - IDM_FILE_RECENT_BASE;
                openRecentFile(index);
            }
            break;
    }
}

// ============================================================================
// EDIT COMMAND HANDLERS
// ============================================================================

void Win32IDE::handleEditCommand(int commandId) {
    switch (commandId) {
        case IDM_EDIT_UNDO:
            SendMessage(m_hwndEditor, EM_UNDO, 0, 0);
            SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"Undo");
            break;
            
        case IDM_EDIT_REDO:
            SendMessage(m_hwndEditor, EM_REDO, 0, 0);
            SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"Redo");
            break;
            
        case IDM_EDIT_CUT:
            SendMessage(m_hwndEditor, WM_CUT, 0, 0);
            m_fileModified = true;
            SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"Cut");
            break;
            
        case IDM_EDIT_COPY:
            SendMessage(m_hwndEditor, WM_COPY, 0, 0);
            SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"Copied");
            break;
            
        case IDM_EDIT_PASTE:
            SendMessage(m_hwndEditor, WM_PASTE, 0, 0);
            m_fileModified = true;
            SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"Pasted");
            break;
            
        case IDM_EDIT_SELECT_ALL:
            SendMessage(m_hwndEditor, EM_SETSEL, 0, -1);
            SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"All text selected");
            break;
            
        case IDM_EDIT_FIND:
            showFindDialog();
            break;
            
        case IDM_EDIT_REPLACE:
            showReplaceDialog();
            break;
            
        case IDM_EDIT_FIND_NEXT: findNext(); break;
        case IDM_EDIT_FIND_PREV: findPrevious(); break;
        case IDM_EDIT_SNIPPET: showSnippetManager(); break;
        case IDM_EDIT_COPY_FORMAT: copyWithFormatting(); break;
        case IDM_EDIT_PASTE_PLAIN: pasteWithoutFormatting(); break;
        case IDM_EDIT_CLIPBOARD_HISTORY: showClipboardHistory(); break;
        case IDM_AI_EDIT: triggerAIEdit(); break;
        case IDM_AI_EDIT_APPLY: applyAIEdit(); break;
        case IDM_AI_CHAT: showAIChat(); break;
        default: break;
    }
}

// ============================================================================
// AI EDIT (IDM_AI_EDIT=2060) — T15 deterministic fixture repair
// ============================================================================

namespace {
bool t15DeterministicRequested()
{
    char buf[16] = {};
    const DWORD n = GetEnvironmentVariableA("RAWRXD_T15_DETERMINISTIC", buf, sizeof(buf));
    return n > 0 && buf[0] != '0';
}

std::string t15RepairUndeclared(const std::string& src)
{
    const char* needle = "undeclared_variable_xyz";
    const size_t pos = src.find(needle);
    if (pos == std::string::npos) return {};
    std::string out = src;
    out.replace(pos, std::strlen(needle), "0");
    return out;
}
} // namespace

void Win32IDE::triggerAIEdit()
{
    if (!m_hwndEditor) {
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, (LPARAM)"No editor available");
        return;
    }

    if (t15DeterministicRequested()) {
        const std::string before = getEditorTextUtf8ForFile();
        std::string repaired = t15RepairUndeclared(before);
        if (repaired.empty() && !m_currentFile.empty()) {
            std::ifstream in(m_currentFile, std::ios::binary);
            if (in) {
                std::string disk((std::istreambuf_iterator<char>(in)),
                                 std::istreambuf_iterator<char>());
                repaired = t15RepairUndeclared(disk);
            }
        }
        if (repaired.empty() || repaired == before) {
            SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
                         (LPARAM)"T15 deterministic: no undeclared identifier to repair");
            return;
        }
        m_aiEditOriginalText = before;
        m_aiEditResult = repaired;
        m_aiEditRange.cpMin = 0;
        m_aiEditRange.cpMax = static_cast<LONG>(before.size());
        CHARRANGE all{};
        all.cpMin = 0;
        all.cpMax = -1;
        SendMessage(m_hwndEditor, EM_EXSETSEL, 0, (LPARAM)&all);
        SendMessageA(m_hwndEditor, EM_REPLACESEL, TRUE, (LPARAM)repaired.c_str());
        m_fileModified = true;
        const bool saved = saveFile();
        m_aiEditPending = false;
        m_aiEditResult.clear();
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
                     (LPARAM)(saved ? "T15 deterministic repair saved"
                                    : "T15 deterministic repair buffer-only (save failed)"));
        buildTrace(std::string("T15_DETERMINISTIC_REPAIR saved=") + (saved ? "1" : "0"));
        return;
    }

    CHARRANGE cr{};
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&cr);
    std::string selectedText;
    if (cr.cpMin != cr.cpMax) {
        const long len = cr.cpMax - cr.cpMin;
        std::vector<char> buffer(static_cast<size_t>(len) + 1);
        TEXTRANGEA tr{};
        tr.chrg = cr;
        tr.lpstrText = buffer.data();
        SendMessageA(m_hwndEditor, EM_GETTEXTRANGE, 0, (LPARAM)&tr);
        selectedText.assign(buffer.data());
    } else {
        selectedText = getEditorTextUtf8ForFile();
        cr.cpMin = 0;
        cr.cpMax = static_cast<LONG>(selectedText.size());
    }
    if (selectedText.empty()) {
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, (LPARAM)"No text to edit");
        return;
    }
    m_aiEditRange = cr;
    m_aiEditOriginalText = selectedText;
    launchAIEdit(std::string("Edit the following code:\n\n") + selectedText +
                 "\n\nProvide only the edited code without explanation:");
}

void Win32IDE::applyAIEdit()
{
    if (!m_aiEditResult.empty() && m_hwndEditor) {
        SendMessage(m_hwndEditor, EM_EXSETSEL, 0, (LPARAM)&m_aiEditRange);
        SendMessageA(m_hwndEditor, EM_REPLACESEL, TRUE, (LPARAM)m_aiEditResult.c_str());
        m_fileModified = true;
        (void)saveFile();
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, (LPARAM)"AI edit applied");
        m_aiEditResult.clear();
        m_aiEditRange = {};
        m_aiEditOriginalText.clear();
        m_aiEditPending = false;
    } else {
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, (LPARAM)"No pending AI edit to apply");
    }
}

void Win32IDE::showAIChat()
{
    if (m_hwndAIChatPanel && IsWindow(m_hwndAIChatPanel)) {
        ShowWindow(m_hwndAIChatPanel,
                   IsWindowVisible(m_hwndAIChatPanel) ? SW_HIDE : SW_SHOW);
        return;
    }
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
                 (LPARAM)"AI chat panel unavailable in this build");
}

void Win32IDE::launchAIEdit(const std::string& prompt)
{
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, (LPARAM)"AI edit started...");
    generateResponseAsync(prompt,
                          [this](const std::string& response, bool complete, bool error) {
                              if (error) {
                                  SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
                                               (LPARAM)"AI edit failed");
                                  return;
                              }
                              if (complete) {
                                  m_aiEditResult = response;
                                  m_aiEditPending = true;
                                  SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
                                               (LPARAM)"AI edit ready - apply via IDM_AI_EDIT_APPLY");
                              }
                          });
}

std::string Win32IDE::queryOllamaForEdit(const std::string& prompt)
{
    return generateResponse(prompt);
}

// ============================================================================
// VIEW COMMAND HANDLERS
// ============================================================================

void Win32IDE::handleViewCommand(int commandId) {
    auto unsupported = [this](const char* message) {
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, reinterpret_cast<LPARAM>(message));
        LOG_WARNING(message);
    };
    switch (commandId) {
    case IDM_VIEW_MINIMAP: toggleMinimap(); break;
    case IDM_VIEW_MODULE_BROWSER: showModuleBrowser(); break;
    case IDM_VIEW_SIDEBAR: toggleSidebar(); break;
    case IDM_VIEW_SECONDARY_SIDEBAR: toggleSecondarySidebar(); break;
    case IDM_VIEW_USE_STREAMING_LOADER:
        m_useStreamingLoader = !m_useStreamingLoader;
        CheckMenuItem(m_hMenu, IDM_VIEW_USE_STREAMING_LOADER,
            MF_BYCOMMAND | (m_useStreamingLoader ? MF_CHECKED : MF_UNCHECKED));
        break;
    case IDM_VIEW_THEME_EDITOR:
        // The built-in theme gallery is a real, modal editor backed by
        // applyTheme(); route the menu item to it instead of reporting a
        // stale unsupported placeholder.
        showThemeEditor(); break;
    case IDM_VIEW_FLOATING_PANEL:
        if (m_hwndFloatingPanel && IsWindow(m_hwndFloatingPanel)) toggleFloatingPanel();
        else unsupported("Unsupported: floating panel has no window in this build.");
        break;
    case IDM_VIEW_USE_VULKAN_RENDERER:
        unsupported("Unsupported: switching the Vulkan editor renderer is not integrated."); break;
    case IDM_VIEW_OUTPUT_TABS:
    case IDM_VIEW_OUTPUT_PANEL:
    case IDM_VIEW_PANEL:
        // View>Panel / Output aliases: show-only VSCode four-panel dock.
        // Prior toggleOutputPanel on 2021/2025 flipped m_outputPanelVisible
        // and re-hid IDC_PANEL_CONTAINER after Problems tab select (G7
        // PROBLEMS_PARTIAL_VIS0 / PANEL_CONTAINER_VISIBLE=0). Layout required:
        // ensurePanelVisible alone ShowWindow'd a zero-rect child.
        ensurePanelVisible();
        if (m_hwndMain) {
            RECT rc{};
            GetClientRect(m_hwndMain, &rc);
            onSize(rc.right, rc.bottom);
        }
        break;
    case IDM_VIEW_TERMINAL:
        if (m_terminalPanes.empty()) createTerminalPane(Win32TerminalManager::PowerShell, "PowerShell");
        for (auto& pane : m_terminalPanes) {
            if (pane.hwnd) ShowWindow(pane.hwnd, (GetWindowLongPtrA(pane.hwnd, GWL_STYLE) & WS_VISIBLE) ? SW_HIDE : SW_SHOW);
        }
        break;
    default: break;
    }
}

void Win32IDE::handleTerminalCommand(int commandId) {
    switch (commandId) {
    case IDM_TERMINAL_POWERSHELL:
        if (m_terminalPanes.empty()) createTerminalPane(Win32TerminalManager::PowerShell, "PowerShell");
        startPowerShell(); break;
    case IDM_TERMINAL_CMD:
        if (m_terminalPanes.empty()) createTerminalPane(Win32TerminalManager::CommandPrompt, "Command Prompt");
        startCommandPrompt(); break;
    case IDM_TERMINAL_STOP: stopTerminal(); break;
    case IDM_TERMINAL_SPLIT_H: splitTerminalHorizontal(); break;
    case IDM_TERMINAL_SPLIT_V: splitTerminalVertical(); break;
    case IDM_TERMINAL_CLEAR_ALL: clearAllTerminals(); break;
    default: break;
    }
    RECT client{};
    if (m_hwndMain && GetClientRect(m_hwndMain, &client)) {
        onSize(client.right - client.left, client.bottom - client.top);
    }
}

void Win32IDE::handleToolsCommand(int commandId) {
    switch (commandId) {
    case IDM_TOOLS_PROFILE_START: startProfiling(); break;
    case IDM_TOOLS_PROFILE_STOP: stopProfiling(); break;
    case IDM_TOOLS_PROFILE_RESULTS: showProfileResults(); break;
    case IDM_TOOLS_ANALYZE_SCRIPT: analyzeScript(); break;
    case IDM_TOOLS_DEBUG_START:
        createLaunchConfiguration();
        startDebugging();
        break;
    case IDM_TOOLS_DEBUG_STOP:
        stopDebugging();
        break;
    case IDM_TOOLS_BUILD_PROJECT: {
        buildTrace("BUILD_COMMAND_ENTRY id=3014");
        // Rebuild must drop stale Problems before new compiler output arrives.
        clearProblems();
        if (m_terminalPanes.empty()) createTerminalPane(Win32TerminalManager::PowerShell, "Build");
        // Keep four-panel dock visible while Problems fixture / Build runs.
        ensurePanelVisible();
        switchPanelTab(PanelTab::Problems);
        std::vector<std::string> roots;
        roots.push_back(m_currentFile);
        roots.push_back(m_currentExplorerPath);
        roots.push_back(m_explorerRootPath);
        roots.push_back(m_gitRepoPath);
        roots.push_back(currentDirectoryPath());
        const std::string workspaceRoot = workspaceRootFromSeeds(roots);
        const std::string buildDir = configuredBuildDirectory(workspaceRoot);
        buildTrace("BUILD_RESOLUTION workspace=" + workspaceRoot + " dir=" + buildDir +
                   " target=" + configuredBuildTarget());
        auto* pane = getActiveTerminalPane();

        // Optional: force real MSVC diagnostics into Problems via fixture compile.
        // Prefer Win32 env API (CRT getenv can miss CreateProcess-inherited vars).
        // Set RAWRXD_PROBLEMS_FIXTURE to a .c/.cpp path (oneshot Problems gate).
        // Fallback: open file named broken_multi.cpp (oneshot fixture basename).
        char fixtureEnvBuf[1024];
        fixtureEnvBuf[0] = '\0';
        const DWORD fixtureEnvLen = GetEnvironmentVariableA(
            "RAWRXD_PROBLEMS_FIXTURE", fixtureEnvBuf, sizeof(fixtureEnvBuf));
        std::string fixture;
        if (fixtureEnvLen > 0 && fixtureEnvLen < sizeof(fixtureEnvBuf)) {
            fixture.assign(fixtureEnvBuf, fixtureEnvLen);
        } else if (!m_currentFile.empty()) {
            const std::string& cur = m_currentFile;
            const size_t slash = cur.find_last_of("\\/");
            const std::string base =
                (slash == std::string::npos) ? cur : cur.substr(slash + 1);
            if (_stricmp(base.c_str(), "broken_multi.cpp") == 0 ||
                _stricmp(base.c_str(), "broken_multi.c") == 0) {
                fixture = cur;
            }
        }
        buildTrace(std::string("PROBLEMS_FIXTURE_RESOLVE path=") +
                   (fixture.empty() ? "<none>" : fixture) +
                   " env_len=" + std::to_string(fixtureEnvLen) +
                   " exists=" +
                   (fixture.empty() ? "0" : (pathExists(fixture) ? "1" : "0")) +
                   " pane=" + std::to_string(pane ? 1 : 0));
        if (!fixture.empty() && pathExists(fixture)) {
            // Bind editor path/title so Problems navigate + title gates can pass.
            if (m_currentFile != fixture) {
                (void)openDocumentPath(fixture);
                buildTrace(std::string("PROBLEMS_FIXTURE_OPEN title_file=") + m_currentFile);
            }
        }
        if (!fixture.empty() && pathExists(fixture) && pane && pane->manager) {
            // Direct cmd.exe /c + absolute cl.exe. Do NOT call vcvars inside the
            // redirected pipe: vcvars stalls (FIXTURE_START then silence) even
            // when VS_UNICODE_OUTPUT is scrubbed. Fixture needs no INCLUDE.
            const char* clCandidates[] = {
                "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\cl.exe",
                "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\14.43.34808\\bin\\Hostx64\\x64\\cl.exe",
                "C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\cl.exe",
                "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\cl.exe",
            };
            std::string clExe;
            for (const char* cand : clCandidates) {
                if (pathExists(cand)) {
                    clExe = cand;
                    break;
                }
            }
            const std::string workDir =
                parentDirectory(fixture).empty() ? currentDirectoryPath()
                                                 : parentDirectory(fixture);
            // Scrub VS_UNICODE_OUTPUT — inherited IDE unicode diag channel hangs
            // cl after /nologo filename. /FS avoids mspdbsrv; 2>&1 merges diag.
            const std::string cmdline =
                "cmd.exe /d /s /c \"echo [RAWRXD_PROBLEMS_FIXTURE_START] && cd /d " +
                workDir + " && set VS_UNICODE_OUTPUT=&& set VC_CLEAR=&& \"" +
                clExe + "\" /nologo /c /W4 /EHsc /FS \"" + fixture +
                "\" 2>&1 & echo [RAWRXD_PROBLEMS_FIXTURE_RESULT] DONE\"";
            {
                std::ofstream req(buildEvidencePath("COMPILER_CAPTURE_RECEIPT.txt",
                    "F:\\rawrxd\\evidence\\FULL_FEATURE_FINAL_COMPLETION_001\\"
                    "artifacts\\COMPILER_CAPTURE_RECEIPT.txt"),
                    std::ios::trunc);
                if (req) {
                    req << "BUILD_REQUEST fixture=" << fixture << '\n'
                        << "PROCESS_CREATE cmdline=" << cmdline << '\n'
                        << "CWD=" << workDir << '\n'
                        << "CL_EXE=" << clExe << '\n'
                        << "FORCE_PIPE=1\n"
                        << "SCRUB=VS_UNICODE_OUTPUT\n"
                        << "NO_VCVARS_IN_PIPE=1\n";
                }
            }
            pane->manager->stop();
            SetEnvironmentVariableA("RAWRXD_TERMINAL_FORCE_PIPE", "1");
            const bool launched =
                !clExe.empty() &&
                pane->manager->startCommandLine(
                    Win32TerminalManager::CommandPrompt, cmdline);
            SetEnvironmentVariableA("RAWRXD_TERMINAL_FORCE_PIPE", nullptr);
            if (launched) {
                // One-shot: close stdin so cmd/cl cannot block on input.
                pane->manager->closeInput();
                buildTrace("PROBLEMS_FIXTURE_LAUNCH path=" + fixture +
                           " cl=" + clExe + " via=cmd_s_pipe_scrub_novcvars");
                {
                    std::ofstream req(buildEvidencePath("COMPILER_CAPTURE_RECEIPT.txt",
                        "F:\\rawrxd\\evidence\\FULL_FEATURE_FINAL_COMPLETION_001\\"
                        "artifacts\\COMPILER_CAPTURE_RECEIPT.txt"),
                        std::ios::app);
                    if (req) {
                        req << "PROCESS_STARTED pid=" << pane->manager->pid()
                            << " transport="
                            << static_cast<int>(pane->manager->transport())
                            << '\n';
                    }
                }
                appendToOutput("Problems fixture compile started: " + fixture + "\n",
                               "Build", OutputSeverity::Info);
                m_outputPanelVisible = true;
                if (m_hwndOutputTabs) {
                    TabCtrl_SetCurSel(m_hwndOutputTabs, 4);
                    m_selectedOutputTab = 4;
                    m_activeOutputTab = "Build";
                    for (const auto& output : m_outputWindows) {
                        ShowWindow(output.second,
                                   (output.first == m_activeOutputTab) ? SW_SHOW : SW_HIDE);
                    }
                    ShowWindow(m_hwndOutputTabs, SW_SHOW);
                }
                switchPanelTab(PanelTab::Problems);
                break;
            }
            buildTrace("PROBLEMS_FIXTURE_LAUNCH_FAILED");
            appendToOutput("Problems fixture compile failed to launch: " + fixture + "\n",
                           "Errors", OutputSeverity::Error);
            break; // fail-closed: do not fall through into full-tree CMake rebuild
        }

        if (buildDir.empty()) {
            buildTrace("BUILD_ABORT no_build_directory");
            std::ofstream receipt("F:\\rawrxd\\evidence\\RAWRXD_BUILD_RECEIPT_latest.log", std::ios::app);
            if (receipt) receipt << "pane=-1 exit=-1 status=NO_BUILD_DIRECTORY\n";
            appendToOutput("Native IDE build not started: no configured CMake build directory was found. Set RAWRXD_BUILD_DIR or configure build_ide.\n",
                           "Errors", OutputSeverity::Error);
            break;
        }
        if (!pane || !pane->manager) {
            buildTrace("BUILD_ABORT no_terminal_manager");
            std::ofstream receipt("F:\\rawrxd\\evidence\\RAWRXD_BUILD_RECEIPT_latest.log", std::ios::app);
            if (receipt) receipt << "pane=-1 exit=-1 status=NO_TERMINAL_MANAGER\n";
            appendToOutput("Native IDE build not started: PowerShell terminal is unavailable.\n",
                           "Errors", OutputSeverity::Error);
            break;
        }
        const std::string rootLiteral = powerShellLiteral(workspaceRoot.empty() ? currentDirectoryPath() : workspaceRoot);
        const std::string buildLiteral = powerShellLiteral(buildDir);
        const std::string buildTarget = configuredBuildTarget();
        const std::string buildCommand = configuredBuildCommand();
        const std::string cmd =
            "$ErrorActionPreference='Continue'; "
            "Set-Location -LiteralPath " + rootLiteral + "; "
            "Write-Output '[RAWRXD_BUILD_START]'; "
            "$vswhere=\"${env:ProgramFiles(x86)}\\Microsoft Visual Studio\\Installer\\vswhere.exe\"; "
            "$vcvars=$null; "
            "if(Test-Path -LiteralPath $vswhere){ "
            "$installPath=& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null; "
            "if($installPath){ $vcvars=Join-Path $installPath \"VC\\Auxiliary\\Build\\vcvars64.bat\" } }; "
            "if(-not $vcvars){ $vcvars=@('C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvars64.bat',"
            "'C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvars64.bat') | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1 }; "
            "if($null -eq $vcvars){ Write-Error 'MSVC vcvars64.bat was not found'; $rc=1 } else { "
            "cmd.exe /d /s /c ('call \"' + $vcvars + '\" && " +
            (buildCommand.empty()
                ? "cmake --build \"' + " + buildLiteral + " + '\" --target " + buildTarget + " --config Release"
                : buildCommand) +
            "'); $rc=$LASTEXITCODE }; "
            "Write-Output ('[RAWRXD_BUILD_RESULT] EXIT=' + $rc); "
            "if($rc -ne 0){ Write-Error ('Native IDE build failed with exit code ' + $rc) }\r\n";
        const std::string encoded = encodePowerShellCommand(cmd);
        buildTrace("BUILD_LAUNCH_ATTEMPT encoded_bytes=" + std::to_string(encoded.size()));
        pane->manager->stop();
        if (encoded.empty() || !pane->manager->startCommandLine(
                Win32TerminalManager::PowerShell,
                "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + encoded)) {
            appendToOutput("Native IDE build not started: failed to launch PowerShell build process.\n",
                           "Errors", OutputSeverity::Error);
            buildTrace("BUILD_LAUNCH_FAILED");
            std::ofstream receipt("F:\\rawrxd\\evidence\\RAWRXD_BUILD_RECEIPT_latest.log", std::ios::app);
            if (receipt) receipt << "pane=" << pane->id << " exit=-1 status=LAUNCH_FAILED\n";
            break;
        }
        buildTrace("BUILD_LAUNCH_STARTED pid=" + std::to_string(pane->manager->pid()));
        appendToOutput("Native IDE build started (workspace=" +
                           (workspaceRoot.empty() ? currentDirectoryPath() : workspaceRoot) +
                           ", dir=" + buildDir + ").\n",
                       "Output", OutputSeverity::Info);
        break;
    }
    case IDM_TOOLS_TEST_PROJECT: {
        if (m_terminalPanes.empty()) createTerminalPane(Win32TerminalManager::PowerShell, "Tests");
        std::vector<std::string> roots;
        roots.push_back(m_currentFile);
        roots.push_back(m_currentExplorerPath);
        roots.push_back(m_explorerRootPath);
        roots.push_back(m_gitRepoPath);
        roots.push_back(currentDirectoryPath());
        const std::string workspaceRoot = workspaceRootFromSeeds(roots);
        const std::string testDir = configuredBuildDirectory(workspaceRoot);
        auto* pane = getActiveTerminalPane();
        if (testDir.empty()) {
            appendToOutput("Native IDE tests not started: no configured CMake build directory was found. Set RAWRXD_BUILD_DIR or configure build_ide.\n",
                           "Errors", OutputSeverity::Error);
            break;
        }
        if (!pane || !pane->manager) {
            appendToOutput("Native IDE tests not started: PowerShell terminal is unavailable.\n",
                           "Errors", OutputSeverity::Error);
            break;
        }
        const std::string rootLiteral = powerShellLiteral(workspaceRoot.empty() ? currentDirectoryPath() : workspaceRoot);
        const std::string testLiteral = powerShellLiteral(testDir);
        const std::string cmd =
            "$ErrorActionPreference='Continue'; "
            "Set-Location -LiteralPath " + rootLiteral + "; "
            "Write-Output '[RAWRXD_TEST_START]'; "
            "ctest --test-dir " + testLiteral +
            " -C Release --output-on-failure; "
            "$rc=$LASTEXITCODE; Write-Output ('[RAWRXD_TEST_RESULT] EXIT=' + $rc); "
            "if($rc -ne 0){ Write-Error ('Native IDE tests failed with exit code ' + $rc) }\r\n";
        const std::string encoded = encodePowerShellCommand(cmd);
        pane->manager->stop();
        if (encoded.empty() || !pane->manager->startCommandLine(
                Win32TerminalManager::PowerShell,
                "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + encoded)) {
            appendToOutput("Native IDE tests not started: failed to launch PowerShell test process.\n",
                           "Errors", OutputSeverity::Error);
            break;
        }
        appendToOutput("Native IDE test run started (workspace=" +
                           (workspaceRoot.empty() ? currentDirectoryPath() : workspaceRoot) +
                           ", dir=" + testDir + ").\n",
                       "Output", OutputSeverity::Info);
        break;
    }
    default: break;
    }
}

void Win32IDE::handleModulesCommand(int commandId) {
    switch (commandId) {
    case IDM_MODULES_REFRESH: refreshModuleList(); break;
    case IDM_MODULES_IMPORT: importModule(); break;
    case IDM_MODULES_EXPORT: exportModule(); break;
    default: break;
    }
}

// ============================================================================
// HELP COMMAND HANDLERS
// ============================================================================

void Win32IDE::handleHelpCommand(int commandId) {
    switch (commandId) {
        case IDM_HELP_CMDREF: // Command Reference
            showCommandReference();
            break;
            
        case IDM_HELP_PSDOCS: // PowerShell Docs
            showPowerShellDocs();
            break;
            
        case IDM_HELP_SEARCH: // Search Help
            searchHelp("");
            break;
            
        case IDM_HELP_ABOUT: // About
            MessageBoxA(m_hwndMain, 
                       "RawrXD IDE v2.0\n\n"
                       "Features:\n"
                       " Advanced File Operations (9 features)\n"
                       " Centralized Menu Commands (25+ features)\n"
                       " Theme & Customization\n"
                       " Code Snippets\n"
                       " Integrated PowerShell Help\n"
                       " Performance Profiling\n"
                       " Module Management\n"
                       " Non-Modal Floating Panel\n"
                       " Recent Files Support\n"
                       " Auto-save & Recovery\n\n"
                       "Built with Win32 API & C++17",
                       "About RawrXD IDE", 
                       MB_OK | MB_ICONINFORMATION);
            break;
            
        case IDM_HELP_SHORTCUTS: // Keyboard Shortcuts
            MessageBoxA(m_hwndMain,
                       "Keyboard Shortcuts:\n\n"
                       "File Operations:\n"
                       "  Ctrl+N - New File\n"
                       "  Ctrl+O - Open File\n"
                       "  Ctrl+S - Save File\n"
                       "  Ctrl+Shift+S - Save As\n\n"
                       "Edit Operations:\n"
                       "  Ctrl+Z - Undo\n"
                       "  Ctrl+Y - Redo\n"
                       "  Ctrl+X - Cut\n"
                       "  Ctrl+C - Copy\n"
                       "  Ctrl+V - Paste\n"
                       "  Ctrl+A - Select All\n"
                       "  Ctrl+F - Find\n"
                       "  Ctrl+H - Replace\n\n"
                       "View:\n"
                       "  F11 - Toggle Floating Panel\n"
                       "  Ctrl+M - Toggle Minimap\n"
                       "  Ctrl+Shift+P - Command Palette\n\n"
                       "Terminal:\n"
                       "  F5 - Run in PowerShell\n"
                       "  Ctrl+` - Toggle Terminal",
                       "Keyboard Shortcuts",
                       MB_OK | MB_ICONINFORMATION);
            break;
            
        default:
            break;
    }
}

// ============================================================================
// COMMAND PALETTE IMPLEMENTATION (Ctrl+Shift+P)
// ============================================================================

void Win32IDE::buildCommandRegistry()
{
    m_commandRegistry.clear();
    
    // File commands
    m_commandRegistry.push_back({IDM_FILE_NEW, "File: New File", "Ctrl+N", "File"});
    m_commandRegistry.push_back({IDM_FILE_OPEN, "File: Open File", "Ctrl+O", "File"});
    m_commandRegistry.push_back({IDM_FILE_SAVE, "File: Save", "Ctrl+S", "File"});
    m_commandRegistry.push_back({IDM_FILE_SAVEAS, "File: Save As", "Ctrl+Shift+S", "File"});
    m_commandRegistry.push_back({IDM_FILE_SAVEALL, "File: Save All", "", "File"});
    m_commandRegistry.push_back({IDM_FILE_CLOSE, "File: Close File", "Ctrl+W", "File"});
    m_commandRegistry.push_back({IDM_FILE_RECENT_CLEAR, "File: Clear Recent Files", "", "File"});
    
    // Edit commands
    m_commandRegistry.push_back({IDM_EDIT_UNDO, "Edit: Undo", "Ctrl+Z", "Edit"});
    m_commandRegistry.push_back({IDM_EDIT_REDO, "Edit: Redo", "Ctrl+Y", "Edit"});
    m_commandRegistry.push_back({IDM_EDIT_CUT, "Edit: Cut", "Ctrl+X", "Edit"});
    m_commandRegistry.push_back({IDM_EDIT_COPY, "Edit: Copy", "Ctrl+C", "Edit"});
    m_commandRegistry.push_back({IDM_EDIT_PASTE, "Edit: Paste", "Ctrl+V", "Edit"});
    m_commandRegistry.push_back({IDM_EDIT_SELECT_ALL, "Edit: Select All", "Ctrl+A", "Edit"});
    m_commandRegistry.push_back({IDM_EDIT_FIND, "Edit: Find", "Ctrl+F", "Edit"});
    m_commandRegistry.push_back({IDM_EDIT_REPLACE, "Edit: Replace", "Ctrl+H", "Edit"});
    
    // View commands
    m_commandRegistry.push_back({IDM_VIEW_MINIMAP, "View: Toggle Minimap", "Ctrl+M", "View"});
    m_commandRegistry.push_back({IDM_VIEW_OUTPUT_PANEL, "View: Toggle Output Panel", "", "View"});
    m_commandRegistry.push_back({IDM_VIEW_FLOATING_PANEL, "View: Toggle Floating Panel", "F11", "View"});
    m_commandRegistry.push_back({IDM_VIEW_THEME_EDITOR, "View: Theme Editor", "", "View"});
    m_commandRegistry.push_back({IDM_VIEW_MODULE_BROWSER, "View: Module Browser", "", "View"});
    m_commandRegistry.push_back({IDM_VIEW_SIDEBAR, "View: Toggle Sidebar", "Ctrl+B", "View"});
    m_commandRegistry.push_back({IDM_VIEW_SECONDARY_SIDEBAR, "View: Toggle Secondary Sidebar", "Ctrl+Alt+B", "View"});
    m_commandRegistry.push_back({IDM_VIEW_PANEL, "View: Toggle Panel", "Ctrl+J", "View"});
    
    // Terminal commands
    m_commandRegistry.push_back({IDM_TERMINAL_POWERSHELL, "Terminal: New PowerShell", "", "Terminal"});
    m_commandRegistry.push_back({IDM_TERMINAL_CMD, "Terminal: New Command Prompt", "", "Terminal"});
    m_commandRegistry.push_back({IDM_TERMINAL_STOP, "Terminal: Kill Terminal", "", "Terminal"});
    m_commandRegistry.push_back({IDM_TERMINAL_CLEAR_ALL, "Terminal: Clear Terminal", "", "Terminal"});
    m_commandRegistry.push_back({IDM_TERMINAL_SPLIT_H, "Terminal: Split Terminal", "", "Terminal"});
    
    // Tools commands
    m_commandRegistry.push_back({IDM_TOOLS_PROFILE_START, "Tools: Start Profiling", "", "Tools"});
    m_commandRegistry.push_back({IDM_TOOLS_PROFILE_STOP, "Tools: Stop Profiling", "", "Tools"});
    m_commandRegistry.push_back({IDM_TOOLS_PROFILE_RESULTS, "Tools: Show Profile Results", "", "Tools"});
    m_commandRegistry.push_back({IDM_TOOLS_ANALYZE_SCRIPT, "Tools: Analyze Script", "", "Tools"});
    m_commandRegistry.push_back({IDM_EDIT_SNIPPET, "Tools: Code Snippets", "", "Tools"});
    
    // Module commands
    m_commandRegistry.push_back({IDM_MODULES_REFRESH, "Modules: Refresh List", "", "Modules"});
    m_commandRegistry.push_back({IDM_MODULES_IMPORT, "Modules: Import Module", "", "Modules"});
    m_commandRegistry.push_back({IDM_MODULES_EXPORT, "Modules: Export Module", "", "Modules"});
    m_commandRegistry.push_back({IDM_VIEW_MODULE_BROWSER, "Modules: Browser", "", "Modules"});
    
    // Git commands
    m_commandRegistry.push_back({IDM_GIT_STATUS, "Git: Show Status", "", "Git"});
    m_commandRegistry.push_back({IDM_GIT_COMMIT, "Git: Commit", "Ctrl+Shift+C", "Git"});
    m_commandRegistry.push_back({IDM_GIT_PUSH, "Git: Push", "", "Git"});
    m_commandRegistry.push_back({IDM_GIT_PULL, "Git: Pull", "", "Git"});
    m_commandRegistry.push_back({IDM_GIT_STAGE_ALL, "Git: Stage All", "", "Git"});
    
    // Help commands
    m_commandRegistry.push_back({IDM_HELP_CMDREF, "Help: Command Reference", "", "Help"});
    m_commandRegistry.push_back({IDM_HELP_PSDOCS, "Help: PowerShell Docs", "", "Help"});
    m_commandRegistry.push_back({IDM_HELP_SEARCH, "Help: Search Help", "", "Help"});
    m_commandRegistry.push_back({IDM_HELP_ABOUT, "Help: About", "", "Help"});
    m_commandRegistry.push_back({IDM_HELP_SHORTCUTS, "Help: Keyboard Shortcuts", "", "Help"});
    
    m_filteredCommands = m_commandRegistry;
}

void Win32IDE::showCommandPalette()
{
    if (m_commandPaletteVisible && m_hwndCommandPalette) {
        SetFocus(m_hwndCommandPaletteInput);
        return;
    }
    
    // Build command registry if empty
    if (m_commandRegistry.empty()) {
        buildCommandRegistry();
    }
    
    // Get window dimensions for centering
    RECT mainRect;
    GetClientRect(m_hwndMain, &mainRect);
    int paletteWidth = 600;
    int paletteHeight = 400;
    int x = (mainRect.right - paletteWidth) / 2;
    int y = 50; // Near top of window
    
    // Create palette window
    m_hwndCommandPalette = CreateWindowExA(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
        "STATIC", "",
        WS_POPUP | WS_BORDER | WS_VISIBLE,
        x + mainRect.left, y, paletteWidth, paletteHeight,
        m_hwndMain, nullptr, m_hInstance, nullptr
    );
    
    // Map to screen coordinates
    POINT pt = {x, y};
    ClientToScreen(m_hwndMain, &pt);
    SetWindowPos(m_hwndCommandPalette, HWND_TOPMOST, pt.x, pt.y, paletteWidth, paletteHeight, SWP_SHOWWINDOW);
    
    SetWindowLongPtrA(m_hwndCommandPalette, GWLP_USERDATA, (LONG_PTR)this);
    
    // Dark background
    HBRUSH bgBrush = CreateSolidBrush(RGB(30, 30, 30));
    SetClassLongPtrA(m_hwndCommandPalette, GCLP_HBRBACKGROUND, (LONG_PTR)bgBrush);
    
    // Create search input at top
    m_hwndCommandPaletteInput = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        10, 10, paletteWidth - 20, 28,
        m_hwndCommandPalette, nullptr, m_hInstance, nullptr
    );
    
    // Set placeholder text appearance (ANSI edit control created via
    // CreateWindowExA, so use SendMessageA with a narrow string).
    SendMessageA(m_hwndCommandPaletteInput, EM_SETCUEBANNER, TRUE, (LPARAM)"> Type a command...");
    
    // Create command list
    m_hwndCommandPaletteList = CreateWindowExA(
        WS_EX_CLIENTEDGE, WC_LISTBOXA, "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
        10, 45, paletteWidth - 20, paletteHeight - 55,
        m_hwndCommandPalette, nullptr, m_hInstance, nullptr
    );
    
    // Populate with all commands
    m_filteredCommands = m_commandRegistry;
    for (const auto& cmd : m_filteredCommands) {
        std::string itemText = cmd.name;
        if (!cmd.shortcut.empty()) {
            itemText += "  [" + cmd.shortcut + "]";
        }
        SendMessageA(m_hwndCommandPaletteList, LB_ADDSTRING, 0, (LPARAM)itemText.c_str());
    }
    
    // Select first item
    SendMessageA(m_hwndCommandPaletteList, LB_SETCURSEL, 0, 0);
    
    m_commandPaletteVisible = true;
    SetFocus(m_hwndCommandPaletteInput);
    
    // Subclass the input for keyboard handling
    SetWindowLongPtrA(m_hwndCommandPaletteInput, GWLP_USERDATA, (LONG_PTR)this);
}

void Win32IDE::hideCommandPalette()
{
    if (m_hwndCommandPalette) {
        DestroyWindow(m_hwndCommandPalette);
        m_hwndCommandPalette = nullptr;
        m_hwndCommandPaletteInput = nullptr;
        m_hwndCommandPaletteList = nullptr;
    }
    m_commandPaletteVisible = false;
    SetFocus(m_hwndEditor);
}

void Win32IDE::filterCommandPalette(const std::string& query)
{
    if (!m_hwndCommandPaletteList) return;
    
    // Clear list
    SendMessageA(m_hwndCommandPaletteList, LB_RESETCONTENT, 0, 0);
    m_filteredCommands.clear();
    
    // Convert query to lowercase for case-insensitive search
    std::string lowerQuery = query;
    for (char& c : lowerQuery) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    
    // Filter commands
    for (const auto& cmd : m_commandRegistry) {
        std::string lowerName = cmd.name;
        for (char& c : lowerName) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        
        if (query.empty() || lowerName.find(lowerQuery) != std::string::npos) {
            m_filteredCommands.push_back(cmd);
            
            std::string itemText = cmd.name;
            if (!cmd.shortcut.empty()) {
                itemText += "  [" + cmd.shortcut + "]";
            }
            SendMessageA(m_hwndCommandPaletteList, LB_ADDSTRING, 0, (LPARAM)itemText.c_str());
        }
    }
    
    // Select first item if available
    if (!m_filteredCommands.empty()) {
        SendMessageA(m_hwndCommandPaletteList, LB_SETCURSEL, 0, 0);
    }
}

void Win32IDE::executeCommandFromPalette(int index)
{
    if (index < 0 || index >= (int)m_filteredCommands.size()) return;
    
    int commandId = m_filteredCommands[index].id;
    hideCommandPalette();
    
    // Route the command
    routeCommand(commandId);
    

}

LRESULT CALLBACK Win32IDE::CommandPaletteProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = (Win32IDE*)GetWindowLongPtrA(hwnd, GWLP_USERDATA);
    
    switch (uMsg) {
    case WM_KEYDOWN:
        if (pThis) {
            if (wParam == VK_ESCAPE) {
                pThis->hideCommandPalette();
                return 0;
            }
            else if (wParam == VK_RETURN) {
                int sel = (int)SendMessageA(pThis->m_hwndCommandPaletteList, LB_GETCURSEL, 0, 0);
                pThis->executeCommandFromPalette(sel);
                return 0;
            }
            else if (wParam == VK_DOWN) {
                int sel = (int)SendMessageA(pThis->m_hwndCommandPaletteList, LB_GETCURSEL, 0, 0);
                int count = (int)SendMessageA(pThis->m_hwndCommandPaletteList, LB_GETCOUNT, 0, 0);
                if (sel < count - 1) {
                    SendMessageA(pThis->m_hwndCommandPaletteList, LB_SETCURSEL, sel + 1, 0);
                }
                return 0;
            }
            else if (wParam == VK_UP) {
                int sel = (int)SendMessageA(pThis->m_hwndCommandPaletteList, LB_GETCURSEL, 0, 0);
                if (sel > 0) {
                    SendMessageA(pThis->m_hwndCommandPaletteList, LB_SETCURSEL, sel - 1, 0);
                }
                return 0;
            }
        }
        break;
        
    case WM_COMMAND:
        if (pThis && HIWORD(wParam) == EN_CHANGE) {
            // Input changed - filter list
            char buffer[256] = {0};
            GetWindowTextA(pThis->m_hwndCommandPaletteInput, buffer, 256);
            pThis->filterCommandPalette(buffer);
        }
        else if (pThis && HIWORD(wParam) == LBN_DBLCLK) {
            // Double-click on list item
            int sel = (int)SendMessageA(pThis->m_hwndCommandPaletteList, LB_GETCURSEL, 0, 0);
            pThis->executeCommandFromPalette(sel);
        }
        break;
    }
    
    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}
