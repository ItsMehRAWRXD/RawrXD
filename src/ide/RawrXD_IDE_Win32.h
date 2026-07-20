/*=============================================================================
 * RawrXD_IDE_Win32.h
 * Complete Win32 GUI IDE Shell - Header
 *
 * ZERO external dependencies: Win32 API + Common Controls only.
 * Target: Windows 7+ / MSVC cl.exe or MinGW g++
 *
 * (C) RawrXD Project
 *===========================================================================*/
#pragma once

#ifndef RAWRXD_IDE_WIN32_H
#define RAWRXD_IDE_WIN32_H

/* ── Lean Win32 ─────────────────────────────────────────────────────────── */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <richedit.h>
#include <strsafe.h>
#include <stdint.h>

/* ── Prometheus Bridge Integration ─────────────────────────────────────── */
#include "prometheus_bridge.h"

/* ── Version ────────────────────────────────────────────────────────────── */
#define RAWRXD_IDE_VERSION_MAJOR    1
#define RAWRXD_IDE_VERSION_MINOR    0
#define RAWRXD_IDE_VERSION_PATCH    0
#define RAWRXD_IDE_VERSION_STRING   L"1.0.0"

/* ── Window Class ───────────────────────────────────────────────────────── */
#define RAWRXD_IDE_CLASS            L"RawrXD_IDE_Win32_Class"
#define RAWRXD_IDE_TITLE            L"RawrXD IDE"
#define RAWRXD_IDE_DEFAULT_WIDTH    1400
#define RAWRXD_IDE_DEFAULT_HEIGHT   900

/* ── IPC ────────────────────────────────────────────────────────────────── */
#define RAWRXD_PIPE_NAME            L"\\\\.\\pipe\\RawrXD_WidgetIntelligence"
#define RAWRXD_PIPE_BUFFER_SIZE     4096

/* ── Control IDs ────────────────────────────────────────────────────────── */
#define IDC_FILE_TREE               1001
#define IDC_CODE_EDITOR             1002
#define IDC_OUTPUT_PANEL            1003
#define IDC_WIDGET_PANEL            1004
#define IDC_STATUS_BAR              1005
#define IDC_TAB_CONTROL             1006
#define IDC_HSPLITTER               1007
#define IDC_VSPLITTER               1008

/* ── Application Messages ──────────────────────────────────────────────── */
#define WM_APP_BUILD_COMPLETE       (WM_APP + 100)
#define WM_APP_COMPLETION_READY     (WM_APP + 101)
#define WM_APP_DEBUG_STATE_UPDATE   (WM_APP + 102)

/* ── Debugger Messages ───────────────────────────────────────────────────── */
#define WM_DEBUG_EVENT              (WM_USER + 100)
#define WM_DEBUG_UPDATE             (WM_USER + 101)

/* ── Menu IDs ───────────────────────────────────────────────────────────── */
/* File: 1000-1099 */
#define IDM_FILE_NEW                1001
#define IDM_FILE_OPEN               1002
#define IDM_FILE_SAVE               1003
#define IDM_FILE_SAVEAS             1004
#define IDM_FILE_CLOSE              1005
#define IDM_FILE_EXIT               1006

/* Edit: 1100-1199 */
#define IDM_EDIT_UNDO               1101
#define IDM_EDIT_REDO               1102
#define IDM_EDIT_CUT                1103
#define IDM_EDIT_COPY               1104
#define IDM_EDIT_PASTE              1105
#define IDM_EDIT_SELECTALL          1106
#define IDM_EDIT_FIND               1107
#define IDM_EDIT_REPLACE            1108
#define IDM_EDIT_GOTO               1109

/* Build: 1200-1299 */
#define IDM_BUILD_BUILD             1201
#define IDM_BUILD_REBUILD           1202
#define IDM_BUILD_RUN               1203
#define IDM_BUILD_CLEAN             1204
#define IDM_BUILD_STOP              1205

/* Debug: 1250-1299 */
#define IDM_DEBUG_START             1251
#define IDM_DEBUG_ATTACH              1252
#define IDM_DEBUG_STOP                1253
#define IDM_DEBUG_BREAKPOINT          1254
#define IDM_DEBUG_STEP_OVER           1255
#define IDM_DEBUG_STEP_INTO           1256
#define IDM_DEBUG_STEP_OUT            1257
#define IDM_DEBUG_CONTINUE            1258
#define IDM_DEBUG_RESTART             1259

/* Error Navigation: 1260-1269 */
#define IDM_ERROR_NEXT                1261
#define IDM_ERROR_PREV                1262
#define IDM_ERROR_CLEAR               1263

/* Tools: 1300-1399 */
#define IDM_TOOLS_PE_INSPECTOR      1301
#define IDM_TOOLS_INSTR_ENCODER     1302
#define IDM_TOOLS_EXT_MANAGER       1303
#define IDM_TOOLS_OPTIONS           1304
#define IDM_TOOLS_SOVEREIGN_RUN     1305
#define IDM_TOOLS_VIEW_EVIDENCE     1306
#define IDM_TOOLS_DEBUG_TELEMETRY   1307

/* View: 1400-1499 */
#define IDM_VIEW_FILEBROWSER        1401
#define IDM_VIEW_OUTPUT             1402
#define IDM_VIEW_WIDGET             1403
#define IDM_VIEW_FULLSCREEN         1404
#define IDM_VIEW_DARK_THEME         1405
#define IDM_VIEW_LIGHT_THEME        1406
#define IDM_VIEW_LINE_NUMBERS       1407
#define IDM_VIEW_WORD_WRAP          1408

/* Help: 1500-1599 */
#define IDM_HELP_ABOUT              1501
#define IDM_HELP_DOCS               1502

/* Modules: 1600-1699 */
#define IDM_MODULES_REFRESH         1601
#define IDM_MODULES_IMPORT          1602
#define IDM_MODULES_EXPORT          1603

/* Terminal: 1700-1799 */
#define IDM_TERMINAL_POWERSHELL     1701
#define IDM_TERMINAL_CMD            1702
#define IDM_TERMINAL_STOP           1703
#define IDM_TERMINAL_SPLIT_H        1704
#define IDM_TERMINAL_SPLIT_V        1705
#define IDM_TERMINAL_CLEAR_ALL      1706

/* Git: 1800-1899 */
#define IDM_GIT_STATUS              1801
#define IDM_GIT_COMMIT              1802
#define IDM_GIT_PUSH                1803
#define IDM_GIT_PULL                1804
#define IDM_GIT_PANEL               1805

/* Agent: 1900-1999 */
#define IDM_AGENT_START_LOOP        1901
#define IDM_AGENT_EXECUTE_CMD       1902
#define IDM_AGENT_CONFIGURE_MODEL   1903
#define IDM_AGENT_VIEW_TOOLS        1904
#define IDM_AGENT_VIEW_STATUS       1905
#define IDM_AGENT_STOP              1906

/* Security: 2000-2099 */
#define IDM_SECURITY_SCAN           2001
#define IDM_SECURITY_AUDIT          2002
#define IDM_SECURITY_SANDBOX        2003

/* Audit: 2100-2199 */
#define IDM_AUDIT_RUN               2101
#define IDM_AUDIT_VIEW_REPORT       2102

/* Telemetry: 2200-2299 */
#define IDM_TELEMETRY_VIEW          2201
#define IDM_TELEMETRY_EXPORT        2202

/* Hotpatch: 2300-2399 */
#define IDM_HOTPATCH_APPLY          2301
#define IDM_HOTPATCH_CREATE         2302
#define IDM_HOTPATCH_STATUS         2303

/* Autonomy: 2400-2499 */
#define IDM_AUTONOMY_TOGGLE         2401
#define IDM_AUTONOMY_START          2402
#define IDM_AUTONOMY_STOP           2403
#define IDM_AUTONOMY_SET_GOAL       2404
#define IDM_AUTONOMY_STATUS         2405
#define IDM_AUTONOMY_MEMORY         2406

/* RevEng: 2500-2599 */
#define IDM_REVENG_DISASM           2501
#define IDM_REVENG_DECOMPILE        2502

/* Crucible: 2600-2699 */
#define IDM_CRUCIBLE_RUN            2601
#define IDM_CRUCIBLE_BENCHMARK      2602

/* Gap Closer: 2700-2799 */
#define IDM_GAP_ANALYZE             2701
#define IDM_GAP_FIX                 2702

/* Features: 2800-2899 */
#define IDM_FEATURES_ENABLE           2801
#define IDM_FEATURES_DISABLE        2802

/* Commands: 2900-2999 */
#define IDM_COMMANDS_PALETTE        2901

/* Enterprise: 3000-3099 */
#define IDM_ENTERPRISE_LICENSE      3001
#define IDM_ENTERPRISE_SYNC         3002

/* Game Engines: 3100-3199 */
#define IDM_GAME_UNITY              3101
#define IDM_GAME_UNREAL             3102

/* MoE Models: 3200-3299 */
#define IDM_MOE_LOAD                3201
#define IDM_MOE_UNLOAD              3202
#define IDM_MOE_PROBE               3203
#define IDM_MOE_STATUS              3204
#define IDM_MOE_DEEPSEEK_V3         3205
#define IDM_MOE_ROUTE_TEST          3206

/* Platform: 3300-3399 */
#define IDM_PLATFORM_EXT_CREATOR    3301
#define IDM_PLATFORM_MODEL_CREATOR  3302
#define IDM_PLATFORM_NATIVE_INTEL   3303
#define IDM_PLATFORM_MASM_LEXER     3304
#define IDM_PLATFORM_AST_BRIDGE     3305
#define IDM_PLATFORM_RT_ENGINE      3306

/* Compilers: 3400-3499 */
#define IDM_COMPILER_ASSEMBLY       3401
#define IDM_COMPILER_EON            3402
#define IDM_COMPILER_UNIVERSAL      3403
#define IDM_COMPILER_CROSS          3404
#define IDM_COMPILER_QUANTUM         3405
#define IDM_COMPILER_C              3410
#define IDM_COMPILER_CPP            3411
#define IDM_COMPILER_RUST           3412
#define IDM_COMPILER_ZIG            3413
#define IDM_COMPILER_GO             3414
#define IDM_COMPILER_SWIFT          3415
#define IDM_COMPILER_HASKELL        3420
#define IDM_COMPILER_OCAML          3421
#define IDM_COMPILER_ERLANG         3422
#define IDM_COMPILER_ELIXIR         3423
#define IDM_COMPILER_CLOJURE        3424
#define IDM_COMPILER_LISP           3425
#define IDM_COMPILER_JS             3430
#define IDM_COMPILER_TS             3431
#define IDM_COMPILER_DART           3432
#define IDM_COMPILER_WASM           3433
#define IDM_COMPILER_FORTRAN        3440
#define IDM_COMPILER_COBOL          3441
#define IDM_COMPILER_PASCAL         3442
#define IDM_COMPILER_DELPHI         3443
#define IDM_COMPILER_VB             3444
#define IDM_COMPILER_ADA            3445
#define IDM_COMPILER_JVM            3450
#define IDM_COMPILER_PYTHON         3451
#define IDM_COMPILER_LUA            3452
#define IDM_COMPILER_RUBY           3453
#define IDM_COMPILER_PERL           3454
#define IDM_COMPILER_PHP            3455
#define IDM_COMPILER_POWERSHELL     3456
#define IDM_COMPILER_JULIA          3457
#define IDM_COMPILER_MATLAB         3458
#define IDM_COMPILER_R              3459
#define IDM_COMPILER_CRYSTAL        3460
#define IDM_COMPILER_NIM            3461
#define IDM_COMPILER_CARBON         3462
#define IDM_COMPILER_JAI            3463
#define IDM_COMPILER_ODIN           3464
#define IDM_COMPILER_VALA           3465
#define IDM_COMPILER_KOTLIN         3466
#define IDM_COMPILER_SCALA          3467
#define IDM_COMPILER_GROOVY         3468
#define IDM_COMPILER_D              3469
#define IDM_COMPILER_F              3470
#define IDM_COMPILER_SOLIDITY       3471
#define IDM_COMPILER_VYPER          3472
#define IDM_COMPILER_MOVE           3473
#define IDM_COMPILER_MOTOKO         3474
#define IDM_COMPILER_BASH           3475
#define IDM_COMPILER_LLVM           3476

/* RevEng: 3500-3599 */
#define IDM_REVENG_DECRYPT          3503
#define IDM_REVENG_ANALYZE          3504
#define IDM_REVENG_RECOVER          3505
#define IDM_REVENG_DUMPBIN          3510
#define IDM_REVENG_OBJDUMP          3511
#define IDM_REVENG_NM               3512
#define IDM_REVENG_STRINGS          3513
#define IDM_REVENG_HEXEDIT          3514
#define IDM_REVENG_PATCH            3520
#define IDM_REVENG_INJECT           3521
#define IDM_REVENG_UNPACK           3522
#define IDM_REVENG_DIFF             3523
#define IDM_REVENG_SIGNATURE        3524

/* Recent Files: 9000-9099 */
#define IDM_FILE_RECENT_BASE        9000
#define IDM_FILE_RECENT_CLEAR       9099
#define MAX_RECENT_FILES            10

/* ── Accelerator IDs ────────────────────────────────────────────────────── */
#define IDA_MAIN_ACCEL              3001

/* ── Timer IDs ──────────────────────────────────────────────────────────── */
#define IDT_STATUS_UPDATE           4001
#define IDT_IPC_POLL                4002
#define IDT_AUTOSAVE                4003
#define IDT_COMPLETION_DEBOUNCE     4004  /* 150ms debounce for completion (tuned for 301+ t/s backend) */
#define IDT_GHOSTTEXT_DEBOUNCE      4005  /* Ghost text debounce timer */
#define IDT_TELEMETRY_HEARTBEAT     4006  /* 1s heartbeat for DebugBridge telemetry (VAL-025) */

/* ── Ghost Text Configuration ───────────────────────────────────────────── */
#define GHOSTTEXT_DELAY_MS          150     /* Debounce delay in milliseconds (tuned for 301+ t/s) */
#define GHOSTTEXT_MAX_CONTEXT       4096    /* Maximum context bytes for inference */

/* ── Custom Window Messages ──────────────────────────────────────────────── */
/* Note: WM_APP_COMPLETION_READY already defined above as (WM_APP + 101) */
#define WM_APP_GHOSTTEXT_DISMISS    (WM_APP + 103)  /* Dismiss ghost text */

/* ── Inference Context Structure (Zero-Copy Snapshot) ──────────────────── */
typedef struct InferenceContext {
    uint32_t    version;                    /* Editor version at capture time */
    size_t      length;                     /* Actual bytes in buffer */
    char        buffer[GHOSTTEXT_MAX_CONTEXT]; /* Context snapshot arena */
} InferenceContext;

/* ── Completion Result Structure ─────────────────────────────────────────── */
typedef struct CompletionResult {
    uint32_t    version;                  /* Must match editorVersion to be valid */
    WCHAR       text[512];                /* Suggestion text (Unicode) */
    float       confidence;                 /* Model confidence score */
    DWORD       timestamp;                /* When result was generated */
} CompletionResult;

/* ── Status bar parts ───────────────────────────────────────────────────── */
#define SB_PART_FILE                0
#define SB_PART_LINECOL             1
#define SB_PART_ENCODING            2
#define SB_PART_BUILD               3
#define SB_PART_IPC                 4
#define SB_NUM_PARTS                5

/* ── Layout constants ───────────────────────────────────────────────────── */
#define FILETREE_MIN_WIDTH          180
#define FILETREE_DEFAULT_WIDTH      250
#define FILE_TREE_WIDTH             250
#define OUTPUT_MIN_HEIGHT           80
#define OUTPUT_DEFAULT_HEIGHT       200
#define OUTPUT_HEIGHT               200
#define WIDGET_MIN_WIDTH            200
#define WIDGET_DEFAULT_WIDTH        280
#define WIDGET_WIDTH                280
#define SPLITTER_WIDTH              4
#define STATUS_HEIGHT               24

/* IDE_SCALE macro for DPI-aware scaling */
#define IDE_SCALE(ide, val) RawrXD_IDE_DPIScale(ide, val)

/* ── Color theme ────────────────────────────────────────────────────────── */
typedef struct RawrXD_Theme {
    COLORREF bgWindow;
    COLORREF bgEditor;
    COLORREF bgOutput;
    COLORREF bgTree;
    COLORREF bgWidget;
    COLORREF bgStatus;
    COLORREF fgText;
    COLORREF fgComment;
    COLORREF fgKeyword;
    COLORREF fgString;
    COLORREF fgNumber;
    COLORREF fgOperator;
    COLORREF fgPreprocessor;
    COLORREF fgLineNumber;
    COLORREF bgSelection;
    COLORREF fgSelection;
    COLORREF borderColor;
    COLORREF splitterColor;
    COLORREF menuBg;
    COLORREF menuFg;
} RawrXD_Theme;

/* ── Build state ────────────────────────────────────────────────────────── */
typedef enum RawrXD_BuildState {
    BUILD_IDLE      = 0,
    BUILD_RUNNING   = 1,
    BUILD_SUCCESS   = 2,
    BUILD_FAILED    = 3
} RawrXD_BuildState;

/* ── IPC connection state ───────────────────────────────────────────────── */
typedef enum RawrXD_IPCState {
    IPC_DISCONNECTED = 0,
    IPC_CONNECTING   = 1,
    IPC_CONNECTED    = 2,
    IPC_ERROR        = 3
} RawrXD_IPCState;

/* ── Ghost Text Engine Forward Declaration ──────────────────────────────── */
#ifdef __cplusplus
class GhostTextEngine;
#endif

/* ── MoE Model state ────────────────────────────────────────────────────── */
typedef enum RawrXD_MoEState {
    MOE_NONE = 0,
    MOE_PROBING,
    MOE_LOADING,
    MOE_LOADED,
    MOE_ERROR
} RawrXD_MoEState;

typedef struct RawrXD_MoEInfo {
    RawrXD_MoEState state;
    WCHAR           modelPath[MAX_PATH];
    WCHAR           modelName[256];
    uint32_t        numExperts;
    uint32_t        expertsPerToken;
    uint32_t        numLayers;
    uint32_t        hiddenDim;
    uint64_t        totalParams;
    uint64_t        activeParams;
    uint64_t        modelSizeGB;
    BOOL            isDeepSeekV3;
    PB_MoEConfig    bridgeConfig;     // Cached config from Prometheus bridge
} RawrXD_MoEInfo;

/* ── Find/Replace dialog state ──────────────────────────────────────────── */
typedef struct RawrXD_FindState {
    WCHAR searchText[512];
    WCHAR replaceText[512];
    BOOL  matchCase;
    BOOL  wholeWord;
    BOOL  searchUp;
    BOOL  useRegex;
    HWND  hFindDlg;
} RawrXD_FindState;

/* ── Main IDE state ─────────────────────────────────────────────────────── */
typedef struct RawrXD_IDE {
    /* Win32 handles */
    HINSTANCE       hInstance;
    HWND            hWndMain;
    HWND            hWndFileTree;
    HWND            hWndEditor;
    HWND            hWndOutput;
    HWND            hWndWidget;
    HWND            hWndStatusBar;
    HWND            hWndTabCtrl;
    HMENU           hMenuBar;
    HACCEL          hAccelTable;

    /* Fonts */
    HFONT           hFontCode;
    HFONT           hFontUI;

    /* Brushes */
    HBRUSH          hBrushBg;
    HBRUSH          hBrushEditor;
    HBRUSH          hBrushOutput;
    HBRUSH          hBrushTree;
    HBRUSH          hBrushWidget;

    /* Rich edit module */
    HMODULE         hRichEditLib;

    /* Layout */
    int             fileTreeWidth;
    int             outputHeight;
    int             widgetWidth;
    BOOL            showFileTree;
    BOOL            showOutput;
    BOOL            showWidget;
    BOOL            isFullscreen;
    RECT            restoreRect;

    /* File state */
    WCHAR           currentFilePath[MAX_PATH];
    WCHAR           currentDir[MAX_PATH];
    BOOL            isModified;
    BOOL            isUntitled;
    DWORD           fileEncoding; /* 0=ANSI, 1=UTF8, 2=UTF16LE */

    /* Editor settings */
    BOOL            showLineNumbers;
    BOOL            wordWrapEnabled;

    /* Recent files */
    WCHAR           recentFiles[10][MAX_PATH];
    int             recentFilesCount;

    /* Theme */
    RawrXD_Theme    theme;
    BOOL            isDarkTheme;

    /* Build */
    RawrXD_BuildState buildState;
    HANDLE          hBuildProcess;
    HANDLE          hBuildThread;

    /* IPC */
    RawrXD_IPCState ipcState;
    HANDLE          hPipe;
    HANDLE          hIPCThread;
    volatile BOOL   ipcRunning;

    /* Find / Replace */
    RawrXD_FindState findState;

    /* DPI */
    UINT            dpi;
    float           dpiScale;

    /* RichEdit DLL path (for logging) */
    WCHAR           richEditDll[MAX_PATH];

    /* Ghost Text Engine - Sovereign Runtime Integration */
    GhostTextEngine* ghostEngine;

    /* Ghost Text Timer Infrastructure */
    volatile LONG   editorVersion;      /* Atomic version stamp for lock-free concurrency */
    UINT_PTR        ghostTimerId;       /* Active debounce timer handle */
    BOOL            ghostTimerActive;   /* Timer state flag */

    /* PrometheusMoE Integration */
    RawrXD_MoEInfo  moeInfo;

    /* MoE Completion Engine State */
    struct {
        BOOL        active;             /* Completion suggestion showing */
        BOOL        ghostVisible;       /* Ghost text visible */
        WCHAR       suggestion[4096]; /* Current suggestion text */
        WCHAR       context[2048];    /* Code context sent to model */
        DWORD       requestTime;      /* When request was made */
        HANDLE      hThread;          /* Completion thread handle */
        volatile BOOL threadRunning;  /* Thread active flag */
        float       confidence;       /* Model confidence score */
    } completion;

    /* Debugger Adapter (opaque pointer to C++ object) */
    void*           debuggerAdapter;

} RawrXD_IDE;

/* ── Function prototypes ────────────────────────────────────────────────── */

#ifdef __cplusplus
extern "C" {
#endif

/* Initialization / shutdown */
BOOL    RawrXD_IDE_Init(RawrXD_IDE* ide, HINSTANCE hInst);
int     RawrXD_IDE_Run(RawrXD_IDE* ide);
void    RawrXD_IDE_Shutdown(RawrXD_IDE* ide);

/* Window creation */
BOOL    RawrXD_IDE_RegisterClass(RawrXD_IDE* ide);
BOOL    RawrXD_IDE_CreateMainWindow(RawrXD_IDE* ide);
void    RawrXD_IDE_CreateControls(RawrXD_IDE* ide);
HMENU   RawrXD_IDE_CreateMenuBar(RawrXD_IDE* ide);
HACCEL  RawrXD_IDE_CreateAccelerators(RawrXD_IDE* ide);
void    RawrXD_IDE_CreateStatusBar(RawrXD_IDE* ide);

/* Window procedure */
LRESULT CALLBACK RawrXD_IDE_WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

/* Message handlers */
LRESULT RawrXD_IDE_OnCreate(RawrXD_IDE* ide, HWND hWnd, LPCREATESTRUCT lpcs);
void    RawrXD_IDE_OnSize(RawrXD_IDE* ide, int cx, int cy);
void    RawrXD_IDE_OnPaint(RawrXD_IDE* ide, HWND hWnd);
void    RawrXD_IDE_OnCommand(RawrXD_IDE* ide, WORD cmdId, WORD notifyCode, HWND hCtrl);
LRESULT RawrXD_IDE_OnNotify(RawrXD_IDE* ide, NMHDR* pnmh);
void    RawrXD_IDE_OnClose(RawrXD_IDE* ide);
void    RawrXD_IDE_OnDestroy(RawrXD_IDE* ide);
void    RawrXD_IDE_OnTimer(RawrXD_IDE* ide, UINT_PTR timerId);
LRESULT RawrXD_IDE_OnCtlColorEdit(RawrXD_IDE* ide, HDC hdc, HWND hCtrl);
LRESULT RawrXD_IDE_OnCtlColorStatic(RawrXD_IDE* ide, HDC hdc, HWND hCtrl);

/* Layout */
void    RawrXD_IDE_LayoutPanes(RawrXD_IDE* ide);
int     RawrXD_IDE_DPIScale(RawrXD_IDE* ide, int value);

/* File operations */
BOOL    RawrXD_IDE_FileNew(RawrXD_IDE* ide);
BOOL    RawrXD_IDE_FileOpen(RawrXD_IDE* ide);
BOOL    RawrXD_IDE_FileSave(RawrXD_IDE* ide);
BOOL    RawrXD_IDE_FileSaveAs(RawrXD_IDE* ide);
void    RawrXD_IDE_AddRecentFile(RawrXD_IDE* ide, const WCHAR* filePath);
void    RawrXD_IDE_ClearRecentFiles(RawrXD_IDE* ide);
void    RawrXD_IDE_PopulateRecentMenu(RawrXD_IDE* ide);
void    RawrXD_IDE_OpenRecentFile(RawrXD_IDE* ide, int index);
void    RawrXD_IDE_ToggleLineNumbers(RawrXD_IDE* ide);
void    RawrXD_IDE_ToggleWordWrap(RawrXD_IDE* ide);
BOOL    RawrXD_IDE_FileClose(RawrXD_IDE* ide);
BOOL    RawrXD_IDE_LoadFile(RawrXD_IDE* ide, const WCHAR* path);
BOOL    RawrXD_IDE_SaveFile(RawrXD_IDE* ide, const WCHAR* path);
BOOL    RawrXD_IDE_PromptSaveChanges(RawrXD_IDE* ide);

/* Edit operations */
void    RawrXD_IDE_EditUndo(RawrXD_IDE* ide);
void    RawrXD_IDE_EditRedo(RawrXD_IDE* ide);
void    RawrXD_IDE_EditCut(RawrXD_IDE* ide);
void    RawrXD_IDE_EditCopy(RawrXD_IDE* ide);
void    RawrXD_IDE_EditPaste(RawrXD_IDE* ide);
void    RawrXD_IDE_EditSelectAll(RawrXD_IDE* ide);
void    RawrXD_IDE_EditFind(RawrXD_IDE* ide);
void    RawrXD_IDE_EditReplace(RawrXD_IDE* ide);
void    RawrXD_IDE_EditGotoLine(RawrXD_IDE* ide);

/* Build operations */
void    RawrXD_IDE_BuildProject(RawrXD_IDE* ide);
void    RawrXD_IDE_RebuildProject(RawrXD_IDE* ide);
void    RawrXD_IDE_RunProject(RawrXD_IDE* ide);
void    RawrXD_IDE_CleanProject(RawrXD_IDE* ide);
void    RawrXD_IDE_StopBuild(RawrXD_IDE* ide);
DWORD WINAPI RawrXD_IDE_BuildThread(LPVOID param);

/* Debug operations */
void    RawrXD_IDE_DebugStart(RawrXD_IDE* ide);
void    RawrXD_IDE_DebugAttach(RawrXD_IDE* ide);
void    RawrXD_IDE_DebugStop(RawrXD_IDE* ide);
void    RawrXD_IDE_DebugToggleBreakpoint(RawrXD_IDE* ide);
void    RawrXD_IDE_DebugStepOver(RawrXD_IDE* ide);
void    RawrXD_IDE_DebugStepInto(RawrXD_IDE* ide);
void    RawrXD_IDE_DebugStepOut(RawrXD_IDE* ide);
void    RawrXD_IDE_DebugContinue(RawrXD_IDE* ide);
void    RawrXD_IDE_DebugRestart(RawrXD_IDE* ide);

/* C Wrapper functions for C++ IDEDebuggerAdapter */
#ifdef __cplusplus
extern "C" {
#endif
void*   IDEDebugger_Create(void);
void    IDEDebugger_Destroy(void* adapter);
BOOL    IDEDebugger_Initialize(void* adapter, RawrXD_IDE* ide);
BOOL    IDEDebugger_Start(void* adapter, const WCHAR* executable);
BOOL    IDEDebugger_Attach(void* adapter, uint32_t pid);
BOOL    IDEDebugger_Stop(void* adapter);
BOOL    IDEDebugger_Restart(void* adapter);
BOOL    IDEDebugger_IsDebugging(void* adapter);
BOOL    IDEDebugger_Continue(void* adapter);
BOOL    IDEDebugger_StepOver(void* adapter);
BOOL    IDEDebugger_StepInto(void* adapter);
BOOL    IDEDebugger_StepOut(void* adapter);
BOOL    IDEDebugger_ToggleBreakpoint(void* adapter, const WCHAR* filePath, uint32_t lineNumber);
#ifdef __cplusplus
}
#endif

/* Error navigation */
void    RawrXD_IDE_ErrorNavigate(RawrXD_IDE* ide, BOOL next);
void    RawrXD_IDE_ErrorClear(RawrXD_IDE* ide);

/* Debug panel updates (thread-safe via WM_APP) */
struct DebugStatePayload;
void    RawrXD_IDE_UpdateDebugPanels(RawrXD_IDE* ide, DebugStatePayload* payload);

/* Tools */
void    RawrXD_IDE_LaunchPEInspector(RawrXD_IDE* ide);
void    RawrXD_IDE_LaunchInstrEncoder(RawrXD_IDE* ide);
void    RawrXD_IDE_LaunchExtManager(RawrXD_IDE* ide);
void    RawrXD_IDE_RunSovereignValidation(RawrXD_IDE* ide);
void    RawrXD_IDE_ViewEvidenceBundle(RawrXD_IDE* ide);
void    RawrXD_IDE_ShowDebugTelemetry(RawrXD_IDE* ide);

/* IPC */
BOOL    RawrXD_IDE_IPCConnect(RawrXD_IDE* ide);
void    RawrXD_IDE_IPCDisconnect(RawrXD_IDE* ide);
BOOL    RawrXD_IDE_IPCSend(RawrXD_IDE* ide, const WCHAR* message);
DWORD WINAPI RawrXD_IDE_IPCThread(LPVOID param);

/* Theme */
void    RawrXD_IDE_SetDarkTheme(RawrXD_IDE* ide);
void    RawrXD_IDE_SetLightTheme(RawrXD_IDE* ide);
void    RawrXD_IDE_ApplyTheme(RawrXD_IDE* ide);
void    RawrXD_IDE_CreateThemeBrushes(RawrXD_IDE* ide);
void    RawrXD_IDE_DestroyThemeBrushes(RawrXD_IDE* ide);

/* Status bar */
void    RawrXD_IDE_UpdateStatusBar(RawrXD_IDE* ide);
void    RawrXD_IDE_UpdateLineCol(RawrXD_IDE* ide);
void    RawrXD_IDE_SetBuildStatus(RawrXD_IDE* ide, const WCHAR* text);

/* File browser tree */
void    RawrXD_IDE_PopulateTree(RawrXD_IDE* ide, const WCHAR* rootPath);
void    RawrXD_IDE_PopulateTreeItem(RawrXD_IDE* ide, HTREEITEM hParent, const WCHAR* path);
void    RawrXD_IDE_OnTreeSelChanged(RawrXD_IDE* ide, NMTREEVIEWW* pnmtv);
void    RawrXD_IDE_OnTreeDblClick(RawrXD_IDE* ide);

/* Output panel */
void    RawrXD_IDE_OutputAppend(RawrXD_IDE* ide, const WCHAR* text);
void    RawrXD_IDE_OutputClear(RawrXD_IDE* ide);

/* Widget panel */
void    RawrXD_IDE_WidgetAppend(RawrXD_IDE* ide, const WCHAR* text);
void    RawrXD_IDE_WidgetClear(RawrXD_IDE* ide);

/*===========================================================================
 * PROMETHEUS MoE FUNCTIONS
 *=========================================================================*/
BOOL    RawrXD_IDE_MoEProbe(RawrXD_IDE* ide, const WCHAR* path);
BOOL    RawrXD_IDE_MoELoad(RawrXD_IDE* ide, const WCHAR* path);
void    RawrXD_IDE_MoEUnload(RawrXD_IDE* ide);
void    RawrXD_IDE_MoEShowStatus(RawrXD_IDE* ide);
BOOL    RawrXD_IDE_MoELoadDeepSeekV3(RawrXD_IDE* ide);
void    RawrXD_IDE_UpdateMoEStatus(RawrXD_IDE* ide);

/* MoE Completion Engine */
void    RawrXD_IDE_RequestMoECompletion(RawrXD_IDE* ide);
void    RawrXD_IDE_InsertCompletion(RawrXD_IDE* ide, const WCHAR* completionText);
void    RawrXD_IDE_ShowCompletionGhost(RawrXD_IDE* ide, const WCHAR* ghostText);
void    RawrXD_IDE_AcceptCompletion(RawrXD_IDE* ide);
void    RawrXD_IDE_DismissCompletion(RawrXD_IDE* ide);
BOOL    RawrXD_IDE_IsCompletionActive(RawrXD_IDE* ide);

/* Ghost text rendering */
void    RawrXD_IDE_PaintGhostText(RawrXD_IDE* ide, HDC hdc);

/* Ghost text timer infrastructure */
void    RawrXD_IDE_GhostText_OnKeystroke(RawrXD_IDE* ide);
void    RawrXD_IDE_GhostText_OnTimer(RawrXD_IDE* ide);
void    RawrXD_IDE_GhostText_CaptureSnapshot(RawrXD_IDE* ide, InferenceContext* ctx);
void    RawrXD_IDE_GhostText_RequestInference(RawrXD_IDE* ide, const InferenceContext* ctx);
void    RawrXD_IDE_GhostText_OnCompletionReady(RawrXD_IDE* ide, CompletionResult* result);
void    RawrXD_IDE_GhostText_Dismiss(RawrXD_IDE* ide);
BOOL    RawrXD_IDE_GhostText_IsActive(RawrXD_IDE* ide);

/* Ghost text smoke test */
void    RawrXD_IDE_TestGhostText(RawrXD_IDE* ide);

/* Completion thread */
DWORD WINAPI RawrXD_IDE_CompletionThread(LPVOID param);

/* Terminal */
void    RawrXD_IDE_LaunchTerminal(RawrXD_IDE* ide, const WCHAR* shell);
void    RawrXD_IDE_TerminalSendInput(RawrXD_IDE* ide, const WCHAR* text);
void    RawrXD_IDE_TerminalKill(RawrXD_IDE* ide);
BOOL    RawrXD_IDE_IsTerminalRunning(RawrXD_IDE* ide);

/* Compilers & Reverse Engineering */
void    RawrXD_IDE_LaunchCompiler(RawrXD_IDE* ide, const WCHAR* langName, const WCHAR* objFile);
void    RawrXD_IDE_LaunchRevEng(RawrXD_IDE* ide, const WCHAR* toolName);
void    RawrXD_IDE_LaunchRevEngTool(RawrXD_IDE* ide, const WCHAR* toolName, const WCHAR* exeName);

/* Git */
void    RawrXD_IDE_GitStatus(RawrXD_IDE* ide);
void    RawrXD_IDE_GitCommit(RawrXD_IDE* ide);
void    RawrXD_IDE_GitPush(RawrXD_IDE* ide);
void    RawrXD_IDE_GitPull(RawrXD_IDE* ide);
void    RawrXD_IDE_GitShowPanel(RawrXD_IDE* ide);
BOOL    RawrXD_IDE_IsGitRepo(RawrXD_IDE* ide);
void    RawrXD_IDE_RunGitCommand(RawrXD_IDE* ide, const WCHAR* args, const WCHAR* description);

/* Agent */
void    RawrXD_IDE_AgentStartLoop(RawrXD_IDE* ide);
void    RawrXD_IDE_AgentExecuteCommand(RawrXD_IDE* ide);
void    RawrXD_IDE_AgentConfigureModel(RawrXD_IDE* ide);
void    RawrXD_IDE_AgentViewTools(RawrXD_IDE* ide);
void    RawrXD_IDE_AgentViewStatus(RawrXD_IDE* ide);
void    RawrXD_IDE_AgentStop(RawrXD_IDE* ide);

/* Telemetry */
void    RawrXD_IDE_ShowTelemetryPanel(RawrXD_IDE* ide);
void    RawrXD_IDE_ExportTelemetry(RawrXD_IDE* ide);

/* Security */
void    RawrXD_IDE_SecurityScanSecrets(RawrXD_IDE* ide);
void    RawrXD_IDE_SecuritySASTAudit(RawrXD_IDE* ide);
void    RawrXD_IDE_SecurityToggleSandbox(RawrXD_IDE* ide);

/* Audit */
void    RawrXD_IDE_AuditRunFull(RawrXD_IDE* ide);
void    RawrXD_IDE_AuditViewReport(RawrXD_IDE* ide);

/* Modules */
void    RawrXD_IDE_ModulesRefresh(RawrXD_IDE* ide);
void    RawrXD_IDE_ModulesImport(RawrXD_IDE* ide);
void    RawrXD_IDE_ModulesExport(RawrXD_IDE* ide);

/* Autonomy */
void    RawrXD_IDE_AutonomyToggle(RawrXD_IDE* ide);
void    RawrXD_IDE_AutonomyStart(RawrXD_IDE* ide);
void    RawrXD_IDE_AutonomyStop(RawrXD_IDE* ide);
void    RawrXD_IDE_AutonomyStatus(RawrXD_IDE* ide);

/* Hotpatch */
void    RawrXD_IDE_HotpatchApply(RawrXD_IDE* ide);
void    RawrXD_IDE_HotpatchCreate(RawrXD_IDE* ide);
void    RawrXD_IDE_HotpatchStatus(RawrXD_IDE* ide);

/* RevEng */
void    RawrXD_IDE_RevEngDisasm(RawrXD_IDE* ide);
void    RawrXD_IDE_RevEngDecompile(RawrXD_IDE* ide);

/* Crucible */
void    RawrXD_IDE_CrucibleRunTest(RawrXD_IDE* ide);
void    RawrXD_IDE_CrucibleBenchmark(RawrXD_IDE* ide);

/* Gap Closer */
void    RawrXD_IDE_GapAnalyze(RawrXD_IDE* ide);
void    RawrXD_IDE_GapGenerateFix(RawrXD_IDE* ide);

/* DPI */
void    RawrXD_IDE_InitDPI(RawrXD_IDE* ide);

/* Utility */
void    RawrXD_IDE_UpdateTitle(RawrXD_IDE* ide);
void    RawrXD_IDE_ShowAbout(RawrXD_IDE* ide);
BOOL    RawrXD_IDE_IsSourceFile(const WCHAR* path);

/* Platform */
void    RawrXD_IDE_LaunchExtensionCreator(RawrXD_IDE* ide);
void    RawrXD_IDE_LaunchModelCreator(RawrXD_IDE* ide);
void    RawrXD_IDE_LaunchNativeIntelliSense(RawrXD_IDE* ide);
void    RawrXD_IDE_LaunchMASMLexer(RawrXD_IDE* ide);
void    RawrXD_IDE_LaunchASTBridge(RawrXD_IDE* ide);
void    RawrXD_IDE_LaunchRealTimeCompletion(RawrXD_IDE* ide);

#ifdef __cplusplus
}
#endif

#endif /* RAWRXD_IDE_WIN32_H */
