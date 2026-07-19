#pragma once
#include <windows.h>
#include <string>
#include <functional>
#include <vector>

namespace IDE {

// Ghost text (inline completion) structure
struct GhostText {
    std::wstring text;
    int line;
    int column;
    bool visible;
    std::wstring source;  // AI model that provided it
};

// Context menu item
struct ContextMenuItem {
    std::wstring label;
    std::wstring shortcut;
    int id;
    bool enabled;
    std::function<void()> callback;
};

// Monaco-like Editor Panel - Pure Win32/MASM64 integration
class MonacoEditorPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static void Toggle();
    static bool IsVisible();
    static const char* Id();
    
    // File operations
    static void OpenFile(const char* path);
    static void SaveFile();
    static void SaveAsFile();
    static void CloseFile();
    
    // Edit operations
    static void Cut();
    static void Copy();
    static void Paste();
    static void Undo();
    static void Redo();
    static void SelectAll();
    
    // AI-powered features
    static void ShowGhostText(const std::wstring& text);
    static void HideGhostText();
    static void AcceptGhostText();
    static void RequestCompletion();
    static void RequestExplanation();
    static void RequestReview();
    static void RequestRefactor();
    
    // Navigation
    static void GoToDefinition();
    static void GoToLine(int line);
    static void Find(const std::string& text);
    static void Replace(const std::string& find, const std::string& replace);
    
    // Context menu
    static void ShowContextMenu(int x, int y);
    static void HideContextMenu();
    
    // Enterprise features
    static void EnableEnterpriseMode(bool enable);
    static void SetAuditMode(bool enable);
    static void SetSecureMode(bool enable);
    
    // MASM Monaco integration
    static void InitializeMASMMonaco();
    static bool IsMASMMonacoReady();
    
private:
    static void RenderEditor();
    static void RenderGhostText();
    static void RenderContextMenu();
    static void HandleKeyboard();
    static void HandleMouse();
    static void UpdateLSPDiagnostics();
    
    // Context menu callbacks
    static void OnExplainCode();
    static void OnReviewCode();
    static void OnRefactorCode();
    static void OnCopy();
    static void OnPaste();
    static void OnCut();
    static void OnGoToDefinition();
    static void OnFindReferences();
    static void OnRenameSymbol();
};

// Enterprise menu bar IDs
#define IDM_FILE_NEW            1001
#define IDM_FILE_OPEN           1002
#define IDM_FILE_SAVE           1003
#define IDM_FILE_SAVE_AS        1004
#define IDM_FILE_CLOSE          1005
#define IDM_FILE_EXIT           1099

#define IDM_EDIT_UNDO           2001
#define IDM_EDIT_REDO           2002
#define IDM_EDIT_CUT            2003
#define IDM_EDIT_COPY           2004
#define IDM_EDIT_PASTE          2005
#define IDM_EDIT_SELECT_ALL     2006
#define IDM_EDIT_FIND           2007
#define IDM_EDIT_REPLACE        2008
#define IDM_EDIT_GOTO           2009

#define IDM_VIEW_LINE_NUMBERS   3001
#define IDM_VIEW_MINIMAP        3002
#define IDM_VIEW_GHOST_TEXT     3003
#define IDM_VIEW_TERMINAL       3004
#define IDM_VIEW_EXPLORER       3005
#define IDM_VIEW_SEARCH         3006
#define IDM_VIEW_GIT            3007
#define IDM_VIEW_TELEMETRY      3008

#define IDM_BUILD_COMPILE       4001
#define IDM_BUILD_BUILD         4002
#define IDM_BUILD_RUN           4003
#define IDM_BUILD_DEBUG         4004
#define IDM_BUILD_CLEAN         4005

#define IDM_TOOLS_LSP_RESTART   5001
#define IDM_TOOLS_AI_COMPLETION 5002
#define IDM_TOOLS_AI_EXPLAIN    5003
#define IDM_TOOLS_AI_REVIEW     5004
#define IDM_TOOLS_AI_REFACTOR   5005
#define IDM_TOOLS_COMMAND_PALETTE 5006

#define IDM_SECURITY_AUDIT      6001
#define IDM_SECURITY_SANDBOX    6002
#define IDM_SECURITY_ENCRYPT    6003

#define IDM_MODULES_EXTENSION   7001
#define IDM_MODULES_MARKETPLACE 7002

#define IDM_HELP_DOCUMENTATION  8001
#define IDM_HELP_SHORTCUTS      8002
#define IDM_HELP_ABOUT          8003

#define IDM_AUDIT_FULL          9001
#define IDM_AUDIT_CODEBASE      9002
#define IDM_AUDIT_PERFORMANCE   9003

#define IDM_GIT_COMMIT          10001
#define IDM_GIT_PUSH            10002
#define IDM_GIT_PULL            10003
#define IDM_GIT_BRANCH          10004
#define IDM_GIT_MERGE           10005
#define IDM_GIT_BLAME           10006

#define IDM_AGENT_START         11001
#define IDM_AGENT_STOP          11002
#define IDM_AGENT_CONFIGURE     11003

#define IDM_TELEMETRY_VIEW      12001
#define IDM_TELEMETRY_EXPORT    12002

#define IDM_HOTPATCH_APPLY      13001
#define IDM_HOTPATCH_ROLLBACK   13002

#define IDM_AUTONOMY_ENABLE     14001
#define IDM_AUTONOMY_CONFIGURE  14002

#define IDM_REVENG_DECOMPILE    15001
#define IDM_REVENG_ANALYZE      15002

#define IDM_GAME_LAUNCH         16001
#define IDM_GAME_BUILD          16002

#define IDM_CRUCIBLE_START      17001

#define IDM_GAP_ANALYZE         18001
#define IDM_GAP_FIX             18002

#define IDM_FEATURES_AI_CHAT      19001
#define IDM_FEATURES_AI_EDIT        19002
#define IDM_FEATURES_AI_GENERATE    19003

#define IDM_COMMANDS_PALETTE    20001

#define IDM_ENTERPRISE_LICENSE  21001
#define IDM_ENTERPRISE_AUDIT    21002
#define IDM_ENTERPRISE_ADMIN    21003

} // namespace IDE
