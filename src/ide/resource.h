// ============================================================================
// resource.h - Resource IDs for RawrXD IDE
// ============================================================================

#ifndef RAWRXD_RESOURCE_H
#define RAWRXD_RESOURCE_H

// ============================================================================
// Icons
// ============================================================================
#define IDI_APPICON                     100
#define IDI_SMALL                       101

// ============================================================================
// Menus
// ============================================================================
#define IDR_MAINMENU                    200
#define IDR_MAINACCEL                   201

// ============================================================================
// File Menu
// ============================================================================
#define IDM_FILE_NEW                    0x0100
#define IDM_FILE_OPEN                   0x0101
#define IDM_FILE_SAVE                   0x0102
#define IDM_FILE_SAVEAS                 0x0103
#define IDM_FILE_EXIT                   0x0104

// ============================================================================
// Edit Menu
// ============================================================================
#define IDM_EDIT_UNDO                   0x0200
#define IDM_EDIT_REDO                   0x0201
#define IDM_EDIT_CUT                    0x0202
#define IDM_EDIT_COPY                   0x0203
#define IDM_EDIT_PASTE                  0x0204
#define IDM_EDIT_FIND                   0x0205
#define IDM_EDIT_REPLACE                0x0206
#define IDM_EDIT_FIND_NEXT              0x0207

// ============================================================================
// AI Menu (Ghost Text Integration)
// ============================================================================
#define IDM_AI_SHOW_COMPLETION          0xE100  // Ctrl+Space - Trigger completion
#define IDM_AI_ACCEPT_COMPLETION          0xE101  // Tab - Accept ghost text
#define IDM_AI_DISMISS_COMPLETION         0xE102  // Esc - Dismiss ghost text
#define IDM_AI_STOP_GENERATION            0xE103  // Ctrl+Break - Cancel generation
#define IDM_AI_PREFERENCES                0xE104  // AI settings

// ============================================================================
// Build Menu
// ============================================================================
#define IDM_BUILD_BUILD                 0x0300
#define IDM_BUILD_RUN                   0x0301
#define IDM_BUILD_BUILD_AND_RUN         0x0302
#define IDM_BUILD_CLEAN                 0x0303

// ============================================================================
// View Menu
// ============================================================================
#define IDM_VIEW_TERMINAL               0x0400
#define IDM_VIEW_GIT                    0x0401
#define IDM_VIEW_LSP_DIAGNOSTICS         0x0402
#define IDM_VIEW_STATUSBAR              0x0403
#define IDM_VIEW_TOOLBAR                0x0404

// ============================================================================
// Help Menu
// ============================================================================
#define IDM_HELP_ABOUT                  0x0500

// ============================================================================
// String Table IDs
// ============================================================================
#define IDS_APP_TITLE                   1000
#define IDS_GHOST_TEXT_ACCEPT           1001
#define IDS_GHOST_TEXT_DISMISS          1002
#define IDS_AI_GENERATING               1003
#define IDS_AI_READY                    1004
#define IDS_AI_CANCELLED                1005
#define IDS_AI_ERROR                    1006

// ============================================================================
// Dialog IDs
// ============================================================================
#define IDD_ABOUTBOX                    300
#define IDD_PREFERENCES                 301
#define IDD_GOTO_LINE                   302

// ============================================================================
// Control IDs
// ============================================================================
#define IDC_STATIC                      -1
#define IDC_EDIT_LINE                   1000
#define IDC_CHECK_ENABLE_AI             1001
#define IDC_EDIT_MAX_TOKENS             1002
#define IDC_COMBO_MODEL                 1003

// ============================================================================
// Status Bar Parts
// ============================================================================
#define SB_PART_MESSAGE                 0
#define SB_PART_LINE_COL                1
#define SB_PART_AI_STATUS               2
#define SB_PART_ENCODING                3

#endif // RAWRXD_RESOURCE_H
