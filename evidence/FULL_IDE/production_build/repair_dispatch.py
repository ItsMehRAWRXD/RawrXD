from pathlib import Path
root=Path(r'F:\rawrxd')
p=root/'src/win32app/Win32IDE_Commands.cpp'
s=p.read_text(encoding='utf-8-sig')
a=s.index('// Menu command IDs')
b=s.index('void Win32IDE::registerCommandHandler')
s=s[:a]+'''#include "Win32IDE_CommandIDs.h"

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

'''+s[b:]
s=s.replace('MessageBoxA(m_hwndMain, "Find dialog - Feature available", "Find", MB_OK);','showFindDialog();').replace('MessageBoxA(m_hwndMain, "Replace dialog - Feature available", "Replace", MB_OK);','showReplaceDialog();')
s=s.replace('        default:\n            break;\n    }\n}\n\n// ============================================================================\n// VIEW COMMAND HANDLERS', '''        case IDM_EDIT_FIND_NEXT: findNext(); break;
        case IDM_EDIT_FIND_PREV: findPrevious(); break;
        case IDM_EDIT_SNIPPET: showSnippetManager(); break;
        case IDM_EDIT_COPY_FORMAT: copyWithFormatting(); break;
        case IDM_EDIT_PASTE_PLAIN: pasteWithoutFormatting(); break;
        case IDM_EDIT_CLIPBOARD_HISTORY: showClipboardHistory(); break;
        default: break;
    }
}

// ============================================================================
// VIEW COMMAND HANDLERS''',1)
a=s.index('void Win32IDE::handleViewCommand')
b=s.index('// ============================================================================\n// HELP COMMAND HANDLERS',a)
s=s[:a]+'''void Win32IDE::handleViewCommand(int commandId) {
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
        unsupported("Unsupported: interactive theme editing is unavailable in this build."); break;
    case IDM_VIEW_FLOATING_PANEL:
        if (m_hwndFloatingPanel && IsWindow(m_hwndFloatingPanel)) toggleFloatingPanel();
        else unsupported("Unsupported: floating panel has no window in this build.");
        break;
    case IDM_VIEW_USE_VULKAN_RENDERER:
        unsupported("Unsupported: switching the Vulkan editor renderer is not integrated."); break;
    case IDM_VIEW_OUTPUT_TABS: case IDM_VIEW_OUTPUT_PANEL: case IDM_VIEW_PANEL:
        unsupported("Unsupported: output-panel layout is not integrated in this build."); break;
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

'''+s[b:]
for old,new in [('case 7001:', 'case IDM_HELP_CMDREF:'),('case 7002:', 'case IDM_HELP_PSDOCS:'),('case 7003:', 'case IDM_HELP_SEARCH:'),('case 7004:', 'case IDM_HELP_ABOUT:'),('case 7005:', 'case IDM_HELP_SHORTCUTS:')]: s=s.replace(old,new)
# Canonical IDs for palette entries; no second dispatch with overlapping old IDs.
a=s.index('void Win32IDE::buildCommandRegistry()');b=s.index('void Win32IDE::showCommandPalette()',a)
region=s[a:b]
lookup={'1001':'IDM_FILE_NEW','1002':'IDM_FILE_OPEN','1003':'IDM_FILE_SAVE','1004':'IDM_FILE_SAVEAS','1005':'IDM_FILE_SAVEALL','1006':'IDM_FILE_CLOSE','1020':'IDM_FILE_RECENT_CLEAR','2001':'IDM_EDIT_UNDO','2002':'IDM_EDIT_REDO','2003':'IDM_EDIT_CUT','2004':'IDM_EDIT_COPY','2005':'IDM_EDIT_PASTE','2006':'IDM_EDIT_SELECT_ALL','2007':'IDM_EDIT_FIND','2008':'IDM_EDIT_REPLACE','3001':'IDM_VIEW_MINIMAP','3002':'IDM_VIEW_OUTPUT_PANEL','3003':'IDM_VIEW_FLOATING_PANEL','3004':'IDM_VIEW_THEME_EDITOR','3005':'IDM_VIEW_MODULE_BROWSER','3006':'IDM_VIEW_SIDEBAR','3007':'IDM_VIEW_SECONDARY_SIDEBAR','3008':'IDM_VIEW_PANEL','4001':'IDM_TERMINAL_POWERSHELL','4002':'IDM_TERMINAL_CMD','4003':'IDM_TERMINAL_STOP','4004':'IDM_TERMINAL_CLEAR_ALL','4005':'IDM_TERMINAL_SPLIT_H','5001':'IDM_TOOLS_PROFILE_START','5002':'IDM_TOOLS_PROFILE_STOP','5003':'IDM_TOOLS_PROFILE_RESULTS','5004':'IDM_TOOLS_ANALYZE_SCRIPT','5005':'IDM_EDIT_SNIPPET','6001':'IDM_MODULES_REFRESH','6002':'IDM_MODULES_IMPORT','6003':'IDM_MODULES_EXPORT','6004':'IDM_VIEW_MODULE_BROWSER','8001':'IDM_GIT_STATUS','8002':'IDM_GIT_COMMIT','8003':'IDM_GIT_PUSH','8004':'IDM_GIT_PULL','8005':'IDM_GIT_STAGE_ALL','7001':'IDM_HELP_CMDREF','7002':'IDM_HELP_PSDOCS','7003':'IDM_HELP_SEARCH','7004':'IDM_HELP_ABOUT','7005':'IDM_HELP_SHORTCUTS'}
import re
region=re.sub(r'push_back\(\{(\d+),',lambda m:'push_back({'+lookup[m[1]]+',',region)
s=s[:a]+region+s[b:]
a=s.index('    // Handle special view commands',s.index('void Win32IDE::executeCommandFromPalette'))
b=s.index('\n}\n\nLRESULT CALLBACK Win32IDE::CommandPaletteProc',a)
s=s[:a]+s[b:]
# Model chooser executes the same native loader used by inference, and reports failure.
needle='        case IDM_FILE_EXIT:'
pos=s.index(needle,s.index('void Win32IDE::handleFileCommand'))
s=s[:pos]+'''        case IDM_FILE_LOAD_MODEL: {
            char modelPath[MAX_PATH] = {};
            OPENFILENAMEA dialog{};
            dialog.lStructSize = sizeof(dialog);
            dialog.hwndOwner = m_hwndMain;
            dialog.lpstrFile = modelPath;
            dialog.nMaxFile = MAX_PATH;
            dialog.lpstrFilter = "GGUF Models (*.gguf)\\0*.gguf\\0All Files\\0*.*\\0";
            dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameA(&dialog) && !loadModelForInference(modelPath)) {
                SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
                    reinterpret_cast<LPARAM>("Model loading failed; consult inference diagnostics."));
            }
            break;
        }
'''+s[pos:]
s=s.replace('            PostQuitMessage(0);','            if (!m_fileModified || promptSaveChanges()) DestroyWindow(m_hwndMain);',1)
p.write_text(s,encoding='utf-8')
# Replace duplicate menu/control definitions in the main TU, retain unrelated IDs.
p=root/'src/win32app/Win32IDE.cpp';s=p.read_text(encoding='utf-8-sig')
names=set(re.findall(r'^#define (\w+) ',(root/'src/win32app/Win32IDE_CommandIDs.h').read_text(),re.M))
s=re.sub(r'^#define (\w+) [^\n]*\n',lambda m:'' if m[1] in names else m[0],s,flags=re.M)
s=s.replace('#include "Win32IDE.h"','#include "Win32IDE.h"\n#include "Win32IDE_CommandIDs.h"',1)
p.write_text(s,encoding='utf-8')
