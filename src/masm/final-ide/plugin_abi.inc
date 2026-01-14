;==============================================================================
; plugin_abi.inc - Plugin Application Binary Interface
; Defines structures and constants for IDE plugin system
;==============================================================================

;==============================================================================
; PLUGIN METADATA STRUCTURE
;==============================================================================
PLUGIN_META STRUCT
    Magic           DWORD   ?       ; 'RXDP' magic number
    Version         DWORD   ?       ; ABI version
    PluginName      QWORD   ?       ; Plugin display name
    PluginVersion   QWORD   ?       ; Plugin version string
    Author          QWORD   ?       ; Author name
    Description     QWORD   ?       ; Plugin description
    ToolCount       DWORD   ?       ; Number of tools provided
    PaneCount       DWORD   ?       ; Number of panes provided
    ToolsArrayPtr   QWORD   ?       ; Pointer to AGENT_TOOL array
    PanesArrayPtr   QWORD   ?       ; Pointer to PLUGIN_PANE array
    InitFunc        QWORD   ?       ; Plugin initialization function
    CleanupFunc     QWORD   ?       ; Plugin cleanup function
PLUGIN_META ENDS

;==============================================================================
; AGENT TOOL STRUCTURE (for plugin tools)
;==============================================================================
AGENT_TOOL STRUCT
    NamePtr         QWORD   ?       ; Tool name string
    DescriptionPtr  QWORD   ?       ; Tool description
    HandlerFunc     QWORD   ?       ; Function pointer: char* handler(char* json)
    Category        DWORD   ?       ; Tool category (FILE, SYSTEM, etc.)
    Flags           DWORD   ?       ; Tool flags
AGENT_TOOL ENDS

;==============================================================================
; PLUGIN PANE STRUCTURE
;==============================================================================
PLUGIN_PANE STRUCT
    PaneType        DWORD   ?       ; Custom pane type (>= 1000)
    PaneName        QWORD   ?       ; Display name
    CreateFunc      QWORD   ?       ; HWND create(IDE_PANE* pane)
    UpdateFunc      QWORD   ?       ; void update(IDE_PANE* pane)
    DestroyFunc     QWORD   ?       ; void destroy(IDE_PANE* pane)
    MessageFunc     QWORD   ?       ; LRESULT message(HWND, UINT, WPARAM, LPARAM)
    MinWidth        DWORD   ?       ; Minimum dimensions
    MinHeight       DWORD   ?
    DefaultWidth    DWORD   ?       ; Default dimensions
    DefaultHeight   DWORD   ?
    DockPosition    DWORD   ?       ; Preferred dock position
    Flags           DWORD   ?       ; Pane flags
PLUGIN_PANE ENDS

;==============================================================================
; TOOL CATEGORIES
;==============================================================================
TOOL_CATEGORY_FILE      equ 1
TOOL_CATEGORY_SYSTEM    equ 2
TOOL_CATEGORY_BUILD     equ 3
TOOL_CATEGORY_DEBUG     equ 4
TOOL_CATEGORY_AI        equ 5
TOOL_CATEGORY_CUSTOM    equ 100

;==============================================================================
; PANE DOCK POSITIONS
;==============================================================================
DOCK_LEFT       equ 1
DOCK_RIGHT      equ 2
DOCK_TOP        equ 3
DOCK_BOTTOM     equ 4
DOCK_CENTER     equ 5
DOCK_FLOATING   equ 6

;==============================================================================
; PANE FLAGS
;==============================================================================
PANE_FLAG_CLOSABLE      equ 1
PANE_FLAG_RESIZABLE     equ 2
PANE_FLAG_DOCKABLE      equ 4
PANE_FLAG_SINGLETON     equ 8

;==============================================================================
; IDE CALLBACK FUNCTIONS (provided to plugins)
;==============================================================================
IDE_CALLBACKS STRUCT
    RegisterPane    QWORD   ?       ; int register_pane(PLUGIN_PANE*)
    RegisterTool    QWORD   ?       ; int register_tool(AGENT_TOOL*)
    GetMainWindow   QWORD   ?       ; HWND get_main_window()
    LogMessage      QWORD   ?       ; void log_message(char* msg)
    ShowNotification QWORD  ?       ; void show_notification(char* msg)
    GetActiveEditor QWORD   ?       ; HWND get_active_editor()
    GetFileTree     QWORD   ?       ; HWND get_file_tree()
    ExecuteCommand  QWORD   ?       ; int execute_command(char* cmd)
IDE_CALLBACKS ENDS

