#pragma once
#ifndef RAWRXD_RESOURCE_H
#define RAWRXD_RESOURCE_H

// ============================================================================
// resource.h — Unified Menu/Command Resource IDs for RawrXD Win32 IDE
// ============================================================================
// All ID_* constants live here. Include this header instead of defining
// constexpr / #define duplicates in individual .cpp files.
// Ranges:
//   1001–1099  File menu
//   2001–2099  Edit menu
//   3001–3099  View menu
//   4001–4099  File browser / misc panels
//   5001–5099  Quick-open
//   6001–6099  Dialogs
//   7001–7099  Build menu
//   8001–8099  Tools menu
//   9001–9099  Help menu
// ============================================================================

// --- File menu (1001–1099) ---------------------------------------------------
#define ID_FILE_NEW             1001
#define ID_FILE_OPEN            1002
#define ID_FILE_SAVE            1003
#define ID_FILE_SAVEAS          1004
#define ID_FILE_SAVE_AS         1004   // alias (used in LinkFixes)
#define ID_FILE_EXIT            1005
#define ID_FILE_CLOSE           1006
#define ID_FILE_BROWSER_LIST    1010

// --- Edit menu (2001–2099) ---------------------------------------------------
#define ID_EDIT_UNDO            2001
#define ID_EDIT_REDO            2002
#define ID_EDIT_CUT             2003
#define ID_EDIT_COPY            2004
#define ID_EDIT_PASTE           2005
#define ID_EDIT_SELECT_ALL      2006
#define ID_EDIT_FIND            2007
#define ID_EDIT_REPLACE         2008
#define ID_EDIT_GOTO            2009

// --- View menu (3001–3099) ---------------------------------------------------
#define ID_VIEW_EXPLORER        3001
#define ID_VIEW_SEARCH          3002
#define ID_VIEW_TERMINAL        3003
#define ID_VIEW_SOVEREIGN_CLI   3004  // Sovereign CLI IDE tab
#define ID_VIEW_OUTPUT          3004
#define ID_VIEW_PROBLEMS        3005
#define ID_VIEW_SIDEBAR         3010
#define ID_VIEW_TOOLBAR         3011
#define ID_VIEW_STATUS_BAR      3012
#define ID_VIEW_ZOOM_IN         3020
#define ID_VIEW_ZOOM_OUT        3021
#define ID_VIEW_ZOOM_RESET      3022
#define ID_VIEW_SYNTAX_HIGHLIGHTING_TOGGLE 3030
#define ID_VIEW_VISION_ENCODER 3031
#define ID_VIEW_SEMANTIC_INDEX 3032

// --- Quick-open / dialogs (5001–6099) ----------------------------------------
#define ID_QUICKOPEN_SEARCH     5001
#define ID_QUICKOPEN_RESULTS    5002
#define IDD_QUICKOPEN           6001
#define IDD_INPUT_DIALOG        6002
#define IDC_INPUT_EDIT          6003

// --- Build menu (7001–7099) --------------------------------------------------
#define ID_BUILD_COMPILE        7001
#define ID_BUILD_BUILD          7002
#define ID_BUILD_REBUILD        7003
#define ID_BUILD_CLEAN          7004
#define ID_BUILD_RUN            7005
#define ID_BUILD_DEBUG          7006

// --- Tools menu (8001–8099) --------------------------------------------------
#define ID_TOOLS_OPTIONS        8001
#define ID_TOOLS_PLUGINS        8002
#define ID_TOOLS_EXTENSIONS     8003
#define ID_TOOLS_SETTINGS       8004
#define ID_TOOLS_HOTPATCH       8050  // Phase 5: Live model hotpatch
#define ID_TOOLS_HOTPATCH_STATUS 8051  // Phase 5: Hotpatch status dialog

// --- Help menu (9001–9099) ---------------------------------------------------
#define ID_HELP_CONTENTS        9001
#define ID_HELP_INDEX           9002
#define ID_HELP_SEARCH          9003
#define ID_HELP_ABOUT           9004

// --- VSCode extension (handled via vscode_extension_api.h, alias here) -------
// IDM_VSCEXT_API_STATUS et al. are defined in ../modules/vscode_extension_api.h

// --- Icons (10001–10099) ----------------------------------------------------
#define IDI_APP_ICON            10001
#define IDI_FILE_NEW            10002
#define IDI_FILE_OPEN           10003
#define IDI_FILE_SAVE           10004

// --- Bitmaps (10101–10199) --------------------------------------------------
#define IDB_TOOLBAR             10101
#define IDB_SIDEBAR             10102

// --- Voice Assistant Panel (12000–12099) ------------------------------------
#define IDC_VOICE_ASSISTANT_PANEL   12000
#define IDC_ASSISTANT_COMBO         12001
#define IDC_VOICE_INPUT_EDIT        12002
#define IDC_RESPONSE_EDIT           12003
#define IDC_SEND_BUTTON             12004
#define IDC_CLEAR_BUTTON            12005
#define IDC_MIC_BUTTON              12006
#define IDC_HISTORY_LIST            12007
#define IDC_STATUS_TEXT             12008

// --- Voice Assistant Menu Commands (12100–12199) ----------------------------
#define IDM_VOICE_ASSISTANT_PANEL   12100
#define IDM_VOICE_SIRI_MODE         12101
#define IDM_VOICE_ALEXA_MODE        12102
#define IDM_VOICE_HYBRID_MODE       12103
#define IDM_VOICE_SETTINGS          12104
#define IDM_VOICE_HISTORY           12105
#define IDM_VOICE_CLEAR_HISTORY     12106
// Phase 3: RAG Semantic Query Commands
#define IDM_VOICE_EXPLAIN_SYMBOL    12107  // "Explain this function"
#define IDM_VOICE_FIND_REFERENCES   12108  // "Who calls this?"
#define IDM_VOICE_GET_DEPENDENCIES  12109  // "What depends on this?"
#define IDM_VOICE_SUGGEST_FIX       12110  // "How do I fix this?"
#define IDM_VOICE_ARCHITECTURE_QUERY 12111 // "How does this module work?"

// Phase 4: Reference Graph Control IDs
#define IDC_REFGRAPH_PANEL          12200
#define IDC_REFGRAPH_TOOLBAR        12201
#define IDC_REFGRAPH_SYMLIST        12202
#define IDC_REFGRAPH_CANVAS         12203
#define IDC_REFGRAPH_DETAIL         12204
#define IDC_REFGRAPH_STATUS         12205

// Reference Graph Toolbar Commands
#define IDM_REFGRAPH_ZOOM_IN        12210
#define IDM_REFGRAPH_ZOOM_OUT       12211
#define IDM_REFGRAPH_LAYOUT_FORCE   12212
#define IDM_REFGRAPH_LAYOUT_HIERARCHY 12213
#define IDM_REFGRAPH_FILTER_ALL     12214
#define IDM_REFGRAPH_FILTER_FUNCTIONS 12215

// --- Voice Assistant Panel Menu Aliases (12300–12399) -----------------------
// Aliases for existing commands used by Voice Assistant Panel
#define IDM_BUILD_SOLUTION          ID_BUILD_BUILD
#define IDM_DBG_LAUNCH              ID_BUILD_DEBUG
#define IDM_GOTO_LINE               ID_EDIT_GOTO
#define IDM_VIEW_THEME_EDITOR       ID_VIEW_SYNTAX_HIGHLIGHTING_TOGGLE
#define IDM_VIEW_OUTPUT_PANEL       ID_VIEW_OUTPUT
#define IDM_VIEW_TERMINAL           ID_VIEW_TERMINAL
#define IDM_TOOLS_SETTINGS          ID_TOOLS_SETTINGS

// --- Agent / LSP Control IDs (13000–13099) --------------------------------
#define IDC_AGENT_CHAT_PANEL        13000
#define IDC_AGENT_DIFF_PANEL          13001
#define IDC_LSP_STATUS                13002
#define ID_AGENT_APPLY_FIX            13003

#endif // RAWRXD_RESOURCE_H
