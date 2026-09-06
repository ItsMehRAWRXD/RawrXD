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

// --- View menu (3001–3099) ---------------------------------------------------
#define ID_VIEW_EXPLORER        3001
#define ID_VIEW_SEARCH          3002
#define ID_VIEW_TERMINAL        3003
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
#define IDD_FIND                6002
#define IDC_FIND_TEXT           6010
#define IDC_REPLACE_TEXT        6011
#define IDC_CASE_SENSITIVE      6020
#define IDC_WHOLE_WORD          6021
#define IDC_USE_REGEX           6022
#define IDC_BTN_FIND_NEXT       6030
#define IDC_BTN_REPLACE         6031
#define IDC_BTN_REPLACE_ALL     6032
#define IDC_BTN_CLOSE           6033

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

// --- Help menu (9001–9099) ---------------------------------------------------
#define ID_HELP_CONTENTS        9001
#define ID_HELP_INDEX           9002
#define ID_HELP_SEARCH          9003
#define ID_HELP_ABOUT           9004

// --- VSCode extension (handled via vscode_extension_api.h, alias here) -------
// IDM_VSCEXT_API_STATUS et al. are defined in ../modules/vscode_extension_api.h

// --- GGUF Inspector (4201-4299) ----------------------------------------------
#define IDM_GGUF_LOAD           4201
#define IDM_GGUF_EXPORT         4202
#define IDM_GGUF_ANALYZE        4203
#define IDM_GGUF_TREE           4204
#define IDM_GGUF_DETAILS        4205

// --- Command surface controls (12501–12599) ----------------------------------
#define IDC_CMD_COMPOSER_INPUT  12501
#define IDC_CMD_SEND_BTN        12502
#define IDC_CMD_STOP_BTN        12503
#define IDC_CMD_MODEL_COMBO     12504
#define IDC_CMD_MODE_COMBO      12505
#define IDC_CMD_WORKSPACE_LIST  12506
#define IDC_CMD_CONVERSATION    12507
#define IDC_CMD_ACTIVITY_TEXT   12508
#define IDC_CMD_STEERING_BELT   12509
#define IDC_CMD_WORK_MODE_BTN   12510
#define IDC_CMD_APPROVAL_BADGE  12511
#define IDC_CMD_APPROVE_BTN     12512
#define IDC_CMD_DENY_BTN        12513
#define IDC_CMD_MODEL_HUB_HDR   12530
#define IDC_CMD_MODEL_REC_LIST  12531
#define IDC_CMD_MODEL_LOCAL_LIST 12532
#define IDC_CMD_MODEL_LOAD_BTN  12533
#define IDC_CMD_MODEL_BROWSE_BTN 12534
#define IDC_CMD_MODEL_HUB_STATUS 12535
#define IDC_CMD_MODEL_UNLOAD_BTN 12536
#define IDC_CMD_MODEL_RELOAD_BTN 12537
#define IDC_CMD_MODEL_CANCEL_BTN 12538
#define IDC_CMD_OUTPUT_HDR      12539
#define IDC_CMD_OUTPUT          12540
#define IDM_CMD_ENTER_WORK      12520
#define IDM_CMD_ENTER_COMMAND   12521
#define IDM_CMD_NEW_TASK        12522

#endif // RAWRXD_RESOURCE_H
