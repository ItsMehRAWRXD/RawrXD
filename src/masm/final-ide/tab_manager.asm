;==========================================================================
; tab_manager.asm - Tab System for Editor, Chat, and Panels
; ==========================================================================
; Manages:
; - Editor file tabs (create, close, switch)
; - Agent chat modes (Ask, Edit, Plan, Configure)
; - Panel tabs (Terminal, Output, Problems, Debug Console)
;==========================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib

;==========================================================================
; CONSTANTS
;==========================================================================
MAX_TABS            EQU 64
TAB_LABEL_LEN       EQU 256
TAB_CONTENT_HANDLE  EQU 0   ; Offset in tab entry
TAB_LABEL           EQU 8   ; Offset in tab entry
TAB_IS_ACTIVE       EQU 264 ; Offset in tab entry
TAB_IS_MODIFIED     EQU 265 ; Offset in tab entry
TAB_FILE_PATH       EQU 266 ; Offset in tab entry

; Agent modes
AGENT_MODE_ASK      EQU 0
AGENT_MODE_EDIT     EQU 1
AGENT_MODE_PLAN     EQU 2
AGENT_MODE_CONFIG   EQU 3

; Tab types
TAB_TYPE_FILE       EQU 1
TAB_TYPE_CHAT       EQU 2
TAB_TYPE_OUTPUT     EQU 3
TAB_TYPE_TERMINAL   EQU 4

;==========================================================================
; STRUCTURES
;==========================================================================
TAB STRUCT
    hwnd            QWORD ?         ; HWND of tab content
    label           BYTE 256 DUP (?) ; Tab label
    is_active       DWORD ?         ; Active tab flag
    is_modified     DWORD ?         ; Modified flag (shows * in label)
    file_path       BYTE 512 DUP (?) ; Full file path
    tab_type        DWORD ?         ; File, Chat, Output, Terminal
TAB ENDS

;==========================================================================
; DATA
;==========================================================================
.data
    ; Tab control class
    szTabControlClass BYTE "SysTabControl32",0
    
    ; Agent mode labels
    szAgentAsk      BYTE "Ask",0
    szAgentEdit     BYTE "Edit",0
    szAgentPlan     BYTE "Plan",0
    szAgentConfig   BYTE "Configure",0
    
    ; Chat mode descriptions
    szAskDesc       BYTE "Ask: General Q&A about code",0
    szEditDesc      BYTE "Edit: Modify highlighted code",0
    szPlanDesc      BYTE "Plan: Generate refactoring plan",0
    szConfigDesc    BYTE "Configure: Adjust hotpatch settings",0
    
    ; Panel tab labels
    szTerminalTab   BYTE "Terminal",0
    szOutputTab     BYTE "Output",0
    szProblemsTab   BYTE "Problems",0
    szDebugTab      BYTE "Debug Console",0
    
    ; Messages
    szTabCreated    BYTE "Tab created: ",0
    szTabClosed     BYTE "Tab closed: ",0
    szTabSwitched   BYTE "Switched to tab: ",0

.data?
    ; Tab arrays
    EditorTabs      TAB MAX_TABS DUP (<>)
    EditorTabCount  DWORD ?
    CurrentEditorTab DWORD ?
    
    ChatTabs        TAB 4 DUP (<>)  ; Fixed: Ask, Edit, Plan, Configure
    CurrentChatMode DWORD ?
    
    PanelTabs       TAB 4 DUP (<>)  ; Fixed: Terminal, Output, Problems, Debug
    CurrentPanelTab DWORD ?
    
    ; Tab control handles
    hEditorTabControl QWORD ?
    hChatTabControl   QWORD ?
    hPanelTabControl  QWORD ?

;==========================================================================
; CODE
;==========================================================================
.code

;==========================================================================
; PUBLIC: tab_manager_init(hParent: rcx, tabtype: edx) -> rax (hwnd)
; Initialize tab control
; tabtype: 0=editor, 1=chat, 2=panel
;==========================================================================
PUBLIC tab_manager_init
tab_manager_init PROC
    push rbx

    push rsi
    push rdi
    sub rsp, 48
    
    mov rbx, rcx        ; hParent
    mov r8d, edx        ; tabtype
    
    ; Create tab control with proper styles
    xor rcx, rcx        ; dwExStyle
    lea rdx, szTabControlClass
    xor r9, r9          ; lpWindowName
    mov eax, WS_CHILD or WS_VISIBLE or WS_TABSTOP
    mov [rsp + 32], rax ; dwStyle
    
    xor r10d, r10d      ; x
    mov [rsp + 40], r10 ; y
    xor r11d, r11d      ; width (will be sized later)
    mov [rsp + 48], r11 ; height
    
    mov [rsp + 56], rbx ; hWndParent
    xor r12d, r12d      ; hMenu (will set based on type)
    mov [rsp + 64], r12 ; hInstance
    
    ; Dispatch based on tab type
    cmp r8d, 0
    je init_editor_tabs
    cmp r8d, 1
    je init_chat_tabs
    
    ; Panel tabs
    lea rcx, hPanelTabControl
    call create_panel_tabs
    jmp init_done
    
init_editor_tabs:
    lea rcx, hEditorTabControl
    call create_editor_tabs
    jmp init_done
    
init_chat_tabs:
    lea rcx, hChatTabControl
    call create_chat_tabs
    
init_done:
    mov eax, dword ptr [rax]
    add rsp, 48

    pop rsi pop rdi

    pop rbx

tab_manager_init ENDP

;==========================================================================
; PUBLIC: tab_create_editor(filename: rcx, filepath: rdx) -> eax (tab_id)
; Create a new editor tab
;==========================================================================
PUBLIC tab_create_editor
tab_create_editor PROC
    push rbx

    push rsi
    push rdi

    push r12
    sub rsp, 32
    
    mov rsi, rcx        ; filename
    mov rdi, rdx        ; filepath
    
    ; Check if tab already exists (by filepath)
    xor ebx, ebx
find_existing:
    cmp ebx, EditorTabCount
    jae tab_not_exists
    
    mov eax, ebx
    mov ecx, SIZEOF TAB
    imul eax, ecx
    lea rax, [EditorTabs + rax]
    
    ; Compare filepath (skip if empty)
    lea rcx, [rax + TAB.file_path]
    mov rdx, rdi
    call strcmp_masm
    test eax, eax
    je tab_exists_reuse
    
    inc ebx
    jmp find_existing
    
tab_exists_reuse:
    ; Tab already open - switch to it
    mov CurrentEditorTab, ebx
    mov eax, ebx
    jmp create_editor_done
    
tab_not_exists:
    ; Create new tab entry
    cmp EditorTabCount, MAX_TABS
    jae tab_create_full
    
    mov eax, EditorTabCount
    mov r12d, eax       ; r12d = tab_id
    
    mov ecx, SIZEOF TAB
    imul eax, ecx
    lea rax, [EditorTabs + rax]
    
    ; Initialize tab
    mov [rax + TAB.is_active], 1
    mov [rax + TAB.is_modified], 0
    mov [rax + TAB.tab_type], TAB_TYPE_FILE
    
    ; Copy label (filename)
    lea rdi, [rax + TAB.label]
    mov rsi, rcx
    mov ecx, TAB_LABEL_LEN
    rep movsb
    
    ; Copy filepath
    lea rdi, [rax + TAB.file_path]
    mov rsi, rdx
    mov ecx, 512
    rep movsb
    
    ; Increment tab count
    inc EditorTabCount
    mov CurrentEditorTab, r12d
    
    mov eax, r12d
    jmp create_editor_done
    
tab_create_full:
    mov eax, -1
    
create_editor_done:
    add rsp, 32

    pop rdi pop r12


    pop rsi
    pop tab
    pop rbx_create_editor ENDP

;==========================================================================
; PUBLIC: tab_close_editor(tab_id: ecx) -> eax
; Close editor tab
;==========================================================================
PUBLIC tab_close_editor
tab_close_editor PROC
    push rbx

    push rsi
    push rdi
    sub rsp, 32
    
    mov ebx, ecx        ; tab_id
    
    ; Validate tab_id
    cmp ebx, EditorTabCount
    jae close_editor_fail
    cmp ebx, 0
    jl close_editor_fail
    
    ; Mark for deletion (shift remaining tabs)
    mov eax, ebx
    mov ecx, SIZEOF TAB
    imul eax, ecx
    lea rsi, [EditorTabs + rax]
    
    ; If closing active tab, switch to previous or next
    cmp CurrentEditorTab, ebx
    jne skip_active_switch
    
    ; Try previous tab
    test ebx, ebx
    jz switch_to_next
    
    dec CurrentEditorTab
    jmp switch_done
    
switch_to_next:
    ; Try next tab
    mov eax, EditorTabCount
    dec eax
    cmp ebx, eax
    jae no_tabs_left
    inc CurrentEditorTab
    jmp switch_done
    
no_tabs_left:
    mov CurrentEditorTab, 0
    
switch_done:
    ; Shift remaining tabs down (simple memmove)
    mov rsi, [rsi]      ; source = current tab
    mov eax, ebx
    mov ecx, SIZEOF TAB
    imul eax, ecx
    add rsi, rax
    
    mov rdi, rsi        ; dest = next tab
    add rdi, SIZEOF TAB
    
    mov ecx, EditorTabCount
    sub ecx, ebx
    dec ecx
    mov eax, SIZEOF TAB
    imul ecx, eax
    
    cmp ecx, 0
    jle skip_memcpy
    
    rep movsb
    
skip_memcpy:
    dec EditorTabCount
    mov eax, 1
    jmp close_editor_done
    
skip_active_switch:
    ; Just shift tabs
    mov eax, ebx
    mov ecx, SIZEOF TAB
    imul eax, ecx
    lea rsi, [EditorTabs + rax + SIZEOF TAB]
    lea rdi, [EditorTabs + rax]
    
    mov ecx, EditorTabCount
    sub ecx, ebx
    dec ecx
    mov eax, SIZEOF TAB
    imul ecx, eax
    
    cmp ecx, 0
    jle skip_memcpy2
    
    rep movsb
    
skip_memcpy2:
    dec EditorTabCount
    mov eax, 1
    jmp close_editor_done
    
close_editor_fail:
    xor eax, eax
    
close_editor_done:
    add rsp, 32

    pop rsi pop rdi

    pop rbx

tab_close_editor ENDP

;==========================================================================
; PUBLIC: tab_set_agent_mode(mode: ecx) -> eax
; Set active agent chat mode
; mode: 0=Ask, 1=Edit, 2=Plan, 3=Configure
;==========================================================================
PUBLIC tab_set_agent_mode
tab_set_agent_mode PROC
    push rbx
    sub rsp, 32
    
    cmp ecx, 3
    jg mode_invalid
    
    mov CurrentChatMode, ecx
    mov eax, 1
    jmp mode_done
    
mode_invalid:
    xor eax, eax
    
mode_done:
    add rsp, 32
    pop rbx

tab_set_agent_mode ENDP

;==========================================================================
; PUBLIC: tab_get_agent_mode() -> eax
; Get current agent chat mode
;==========================================================================
PUBLIC tab_get_agent_mode
tab_get_agent_mode PROC
    mov eax, CurrentChatMode
    ret
tab_get_agent_mode ENDP

;==========================================================================
; PUBLIC: tab_set_panel_tab(tab_id: ecx) -> eax
; Set active panel tab (0=Terminal, 1=Output, 2=Problems, 3=Debug)
;==========================================================================
PUBLIC tab_set_panel_tab
tab_set_panel_tab PROC
    cmp ecx, 3
    jg panel_tab_invalid
    
    mov CurrentPanelTab, ecx
    mov eax, 1
    ret
    
panel_tab_invalid:
    xor eax, eax
    ret
tab_set_panel_tab ENDP

;==========================================================================
; PUBLIC: tab_mark_modified(tab_id: ecx) -> eax
; Mark editor tab as modified (adds * to label)
;==========================================================================
PUBLIC tab_mark_modified
tab_mark_modified PROC
    push rbx
    sub rsp, 32
    
    mov ebx, ecx
    cmp ebx, EditorTabCount
    jae mark_fail
    
    mov eax, ebx
    mov ecx, SIZEOF TAB
    imul eax, ecx
    lea rax, [EditorTabs + rax]
    
    mov [rax + TAB.is_modified], 1
    mov eax, 1
    jmp mark_done
    
mark_fail:
    xor eax, eax
    
mark_done:
    add rsp, 32
    pop rbx

tab_mark_modified ENDP

;==========================================================================
; INTERNAL: create_editor_tabs() - Initialize editor tab system
;==========================================================================
create_editor_tabs PROC
    mov EditorTabCount, 0
    mov CurrentEditorTab, 0
    mov eax, 1
    ret
create_editor_tabs ENDP

;==========================================================================
; INTERNAL: create_chat_tabs() - Initialize chat tab system with 4 modes
;==========================================================================
create_chat_tabs PROC
    ; Chat tabs are fixed: Ask, Edit, Plan, Configure
    mov ChatTabs[0].label[0], 'A'
    mov ChatTabs[0].label[1], 's'
    mov ChatTabs[0].label[2], 'k'
    mov ChatTabs[0].label[3], 0
    mov ChatTabs[0].tab_type, TAB_TYPE_CHAT
    
    mov ChatTabs[SIZEOF TAB].label[0], 'E'
    mov ChatTabs[SIZEOF TAB].label[1], 'd'
    mov ChatTabs[SIZEOF TAB].label[2], 'i'
    mov ChatTabs[SIZEOF TAB].label[3], 't'
    mov ChatTabs[SIZEOF TAB].label[4], 0
    mov ChatTabs[SIZEOF TAB].tab_type, TAB_TYPE_CHAT
    
    mov ChatTabs[2*SIZEOF TAB].label[0], 'P'
    mov ChatTabs[2*SIZEOF TAB].label[1], 'l'
    mov ChatTabs[2*SIZEOF TAB].label[2], 'a'
    mov ChatTabs[2*SIZEOF TAB].label[3], 'n'
    mov ChatTabs[2*SIZEOF TAB].label[4], 0
    mov ChatTabs[2*SIZEOF TAB].tab_type, TAB_TYPE_CHAT
    
    mov ChatTabs[3*SIZEOF TAB].label[0], 'C'
    mov ChatTabs[3*SIZEOF TAB].label[1], 'o'
    mov ChatTabs[3*SIZEOF TAB].label[2], 'n'
    mov ChatTabs[3*SIZEOF TAB].label[3], 'f'
    mov ChatTabs[3*SIZEOF TAB].label[4], 'i'
    mov ChatTabs[3*SIZEOF TAB].label[5], 'g'
    mov ChatTabs[3*SIZEOF TAB].label[6], 0
    mov ChatTabs[3*SIZEOF TAB].tab_type, TAB_TYPE_CHAT
    
    mov CurrentChatMode, 0
    mov eax, 1
    ret
create_chat_tabs ENDP

;==========================================================================
; INTERNAL: create_panel_tabs() - Initialize panel tab system
;==========================================================================
create_panel_tabs PROC
    ; Panel tabs: Terminal, Output, Problems, Debug
    mov PanelTabs[0].label[0], 'T'
    mov PanelTabs[0].label[1], 'E'
    mov PanelTabs[0].label[2], 'R'
    mov PanelTabs[0].label[3], 'M'
    mov PanelTabs[0].label[4], 0
    mov PanelTabs[0].tab_type, TAB_TYPE_TERMINAL
    
    mov PanelTabs[SIZEOF TAB].label[0], 'O'
    mov PanelTabs[SIZEOF TAB].label[1], 'U'
    mov PanelTabs[SIZEOF TAB].label[2], 'T'
    mov PanelTabs[SIZEOF TAB].label[3], 0
    mov PanelTabs[SIZEOF TAB].tab_type, TAB_TYPE_OUTPUT
    
    mov PanelTabs[2*SIZEOF TAB].label[0], 'P'
    mov PanelTabs[2*SIZEOF TAB].label[1], 'R'
    mov PanelTabs[2*SIZEOF TAB].label[2], 'O'
    mov PanelTabs[2*SIZEOF TAB].label[3], 0
    mov PanelTabs[2*SIZEOF TAB].tab_type, 0
    
    mov PanelTabs[3*SIZEOF TAB].label[0], 'D'
    mov PanelTabs[3*SIZEOF TAB].label[1], 'B'
    mov PanelTabs[3*SIZEOF TAB].label[2], 'G'
    mov PanelTabs[3*SIZEOF TAB].label[3], 0
    mov PanelTabs[3*SIZEOF TAB].tab_type, 0
    
    mov CurrentPanelTab, 1  ; Default to Output
    mov eax, 1
    ret
create_panel_tabs ENDP

;==========================================================================
; Helper: strcmp_masm - Compare two strings (external or define here)
;==========================================================================
EXTERN strcmp_masm:PROC

;==========================================================================
; PUBLIC: tab_reorder(source: ecx, target: edx) -> eax
; Physically reorder tabs in the EditorTabs array
;==========================================================================
PUBLIC tab_reorder
tab_reorder PROC
    push rbx

    push rsi
    push rdi
    sub rsp, 32
    
    mov r8d, ecx        ; source index
    mov r9d, edx        ; target index
    
    cmp r8d, r9d
    je reorder_done
    
    ; Save source tab
    mov rax, r8
    imul rax, 264       ; sizeof(TAB)
    lea rsi, EditorTabs[rax]
    sub rsp, 264        ; temp storage
    mov rdi, rsp
    mov rcx, 264
    rep movsb
    
    ; Shift tabs
    cmp r8d, r9d
    jg shift_down
    
    ; Shift up (source < target)
    mov eax, r8d
shift_up_loop:
    cmp eax, r9d
    jae shift_done
    
    mov rbx, rax
    inc rbx
    imul rbx, 264
    lea rsi, EditorTabs[rbx]
    
    mov rbx, rax
    imul rbx, 264
    lea rdi, EditorTabs[rbx]
    
    mov rcx, 264
    rep movsb
    
    inc eax
    jmp shift_up_loop
    
shift_down:
    ; Shift down (source > target)
    mov eax, r8d
shift_down_loop:
    cmp eax, r9d
    jbe shift_done
    
    mov rbx, rax
    dec rbx
    imul rbx, 264
    lea rsi, EditorTabs[rbx]
    
    mov rbx, rax
    imul rbx, 264
    lea rdi, EditorTabs[rbx]
    
    mov rcx, 264
    rep movsb
    
    dec eax
    jmp shift_down_loop
    
shift_done:
    ; Restore source tab to target position
    mov rsi, rsp
    mov rax, r9
    imul rax, 264
    lea rdi, EditorTabs[rax]
    mov rcx, 264
    rep movsb
    
    add rsp, 264
    
reorder_done:
    mov eax, 1
    add rsp, 32

    pop rsi pop rdi

    pop rbx

tab_reorder ENDP

END




