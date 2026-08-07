; =============================================================================
; PanelRegistry.asm — Native Panel Manifest Database
; Static table of all panels with metadata
; =============================================================================

OPTION CASEMAP:NONE

; ---------------------------------------------------------------------------
; Panel Descriptor Structure
; ---------------------------------------------------------------------------
PANEL_DESC STRUCT
    IdPtr           QWORD ?     ; Panel ID string
    TitlePtr        QWORD ?     ; Display title
    IconId          DWORD ?     ; Resource icon ID
    Flags           DWORD ?     ; Panel flags
    InitProc        QWORD ?     ; Initialization function pointer
    ShutdownProc    QWORD ?     ; Shutdown function pointer
    Dependencies    QWORD ?     ; Pointer to dependency ID array (null-terminated)
PANEL_DESC ENDS

; Panel flags
PANEL_FLAG_VISIBLE        EQU 00000001h
PANEL_FLAG_DOCKABLE       EQU 00000002h
PANEL_FLAG_RESIZABLE      EQU 00000004h
PANEL_FLAG_CLOSABLE       EQU 00000008h
PANEL_FLAG_DEFAULT_VISIBLE EQU 00000010h

; ---------------------------------------------------------------------------
; .data
; ---------------------------------------------------------------------------
.DATA
ALIGN 8

; String literals
szPanelSystemDiag    DB "system-diagnostics", 0
szPanelInference     DB "inference-monitor", 0
szPanelTokenHeat     DB "token-heatmap", 0
szPanelAgentConsole  DB "agent-console", 0
szPanelModelBrowser  DB "model-browser", 0

szTitleSystemDiag    DB "System Diagnostics", 0
szTitleInference     DB "Inference Monitor", 0
szTitleTokenHeat     DB "Token Heatmap", 0
szTitleAgentConsole  DB "Agent Console", 0
szTitleModelBrowser  DB "Model Browser", 0

; Dependency arrays (null-terminated)
PanelDepsNone       QWORD 0
PanelDepsEngine     QWORD OFFSET szPanelSystemDiag, 0
PanelDepsAgent      QWORD OFFSET szPanelInference, OFFSET szPanelSystemDiag, 0

; External panel function references
EXTERNDEF Panel_SystemDiag_Init:PROC
EXTERNDEF Panel_SystemDiag_Shutdown:PROC
EXTERNDEF Panel_Inference_Init:PROC
EXTERNDEF Panel_Inference_Shutdown:PROC
EXTERNDEF Panel_TokenHeatmap_Init:PROC
EXTERNDEF Panel_TokenHeatmap_Shutdown:PROC
EXTERNDEF Panel_AgentConsole_Init:PROC
EXTERNDEF Panel_AgentConsole_Shutdown:PROC
EXTERNDEF Panel_ModelBrowser_Init:PROC
EXTERNDEF Panel_ModelBrowser_Shutdown:PROC

; ---------------------------------------------------------------------------
; Panel Registry Table
; ---------------------------------------------------------------------------
ALIGN 8
PUBLIC g_PanelRegistry
PUBLIC g_PanelCount

g_PanelRegistry LABEL QWORD
    PANEL_DESC <OFFSET szPanelSystemDiag, OFFSET szTitleSystemDiag, 101, \
                PANEL_FLAG_VISIBLE OR PANEL_FLAG_DOCKABLE OR PANEL_FLAG_DEFAULT_VISIBLE, \
                OFFSET Panel_SystemDiag_Init, OFFSET Panel_SystemDiag_Shutdown, \
                OFFSET PanelDepsNone>

    PANEL_DESC <OFFSET szPanelInference, OFFSET szTitleInference, 102, \
                PANEL_FLAG_VISIBLE OR PANEL_FLAG_DOCKABLE, \
                OFFSET Panel_Inference_Init, OFFSET Panel_Inference_Shutdown, \
                OFFSET PanelDepsEngine>

    PANEL_DESC <OFFSET szPanelTokenHeat, OFFSET szTitleTokenHeat, 103, \
                PANEL_FLAG_VISIBLE OR PANEL_FLAG_DOCKABLE, \
                OFFSET Panel_TokenHeatmap_Init, OFFSET Panel_TokenHeatmap_Shutdown, \
                OFFSET PanelDepsEngine>

    PANEL_DESC <OFFSET szPanelAgentConsole, OFFSET szTitleAgentConsole, 104, \
                PANEL_FLAG_VISIBLE OR PANEL_FLAG_DOCKABLE OR PANEL_FLAG_RESIZABLE, \
                OFFSET Panel_AgentConsole_Init, OFFSET Panel_AgentConsole_Shutdown, \
                OFFSET PanelDepsAgent>

    PANEL_DESC <OFFSET szPanelModelBrowser, OFFSET szTitleModelBrowser, 105, \
                PANEL_FLAG_VISIBLE OR PANEL_FLAG_DOCKABLE, \
                OFFSET Panel_ModelBrowser_Init, OFFSET Panel_ModelBrowser_Shutdown, \
                OFFSET PanelDepsNone>

g_PanelCount DWORD 5

; ---------------------------------------------------------------------------
; .code
; ---------------------------------------------------------------------------
.CODE

; =============================================================================
; Panel_SystemDiag_Init — Stub
; =============================================================================
Panel_SystemDiag_Init PROC
    xor     eax, eax
    ret
Panel_SystemDiag_Init ENDP

Panel_SystemDiag_Shutdown PROC
    xor     eax, eax
    ret
Panel_SystemDiag_Shutdown ENDP

; =============================================================================
; Panel_Inference_Init — Stub
; =============================================================================
Panel_Inference_Init PROC
    xor     eax, eax
    ret
Panel_Inference_Init ENDP

Panel_Inference_Shutdown PROC
    xor     eax, eax
    ret
Panel_Inference_Shutdown ENDP

; =============================================================================
; Panel_TokenHeatmap_Init — Stub
; =============================================================================
Panel_TokenHeatmap_Init PROC
    xor     eax, eax
    ret
Panel_TokenHeatmap_Init ENDP

Panel_TokenHeatmap_Shutdown PROC
    xor     eax, eax
    ret
Panel_TokenHeatmap_Shutdown ENDP

; =============================================================================
; Panel_AgentConsole_Init — Stub
; =============================================================================
Panel_AgentConsole_Init PROC
    xor     eax, eax
    ret
Panel_AgentConsole_Init ENDP

Panel_AgentConsole_Shutdown PROC
    xor     eax, eax
    ret
Panel_AgentConsole_Shutdown ENDP

; =============================================================================
; Panel_ModelBrowser_Init — Stub
; =============================================================================
Panel_ModelBrowser_Init PROC
    xor     eax, eax
    ret
Panel_ModelBrowser_Init ENDP

Panel_ModelBrowser_Shutdown PROC
    xor     eax, eax
    ret
Panel_ModelBrowser_Shutdown ENDP

END
