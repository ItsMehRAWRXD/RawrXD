// Menu Command System Implementation for Win32IDE
// Centralized command routing with 25+ features

#include "Win32IDE.h"
#include <commctrl.h>
#include <commdlg.h>
#include <richedit.h>
#include <functional>
#include <algorithm>
#include <cctype>

#include "Win32IDE_CommandIDs.h"

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
        handleToolsCommand(commandId); return true;
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
        default: break;
    }
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
    case IDM_VIEW_OUTPUT_TABS: case IDM_VIEW_OUTPUT_PANEL: case IDM_VIEW_PANEL:
        // Output tabs, PowerShell, terminals, and the debugger all share the
        // live docked bottom surface.  Toggle that surface through the real
        // layout path so these menu aliases cannot create overlapping panes.
        toggleOutputPanel(); break;
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
    
    // Set placeholder text appearance
    SendMessageA(m_hwndCommandPaletteInput, EM_SETCUEBANNER, TRUE, (LPARAM)L"> Type a command...");
    
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
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    // Filter commands
    for (const auto& cmd : m_commandRegistry) {
        std::string lowerName = cmd.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        
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
