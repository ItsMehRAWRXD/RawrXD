;==========================================================================
; keyboard_shortcuts.asm - Keyboard Shortcut System
; ==========================================================================
; Implements global keyboard shortcuts:
; - Ctrl+N   : New file
; - Ctrl+O   : Open file
; - Ctrl+S   : Save file
; - Ctrl+W   : Close tab
; - Ctrl+Tab : Next tab
; - Shift+Tab: Previous tab
; - Ctrl+Shift+F: Find in output
; - Ctrl+H   : Find/Replace
;
; Integration Points:
; - menu_hooks.asm (file operations)
; - tab_manager.asm (tab switching)
; - output_pane_logger.asm (search)
;==========================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib

;==========================================================================
; EXTERN DECLARATIONS
;==========================================================================
EXTERN menu_file_new:PROC
EXTERN menu_file_open:PROC
EXTERN menu_file_save:PROC
EXTERN menu_file_close_tab:PROC

EXTERN tab_get_agent_mode:PROC
EXTERN tab_set_agent_mode:PROC

EXTERN output_pane_find_next:PROC
EXTERN output_pane_find_prev:PROC

EXTERN ui_show_dialog:PROC

;==========================================================================
; CONSTANTS
;==========================================================================
VK_TAB              EQU 09h
VK_N                EQU 4Eh
VK_O                EQU 4Fh
VK_S                EQU 53h
VK_W                EQU 57h
VK_H                EQU 48h
VK_F                EQU 46h

MOD_CTRL            EQU 0002h
MOD_SHIFT           EQU 0004h
MOD_ALT             EQU 0001h

;==========================================================================
; DATA
;==========================================================================
.data
    ; Shortcut descriptions
    szCtrlN             BYTE "Ctrl+N - New File",0
    szCtrlO             BYTE "Ctrl+O - Open File",0
    szCtrlS             BYTE "Ctrl+S - Save File",0
    szCtrlW             BYTE "Ctrl+W - Close Tab",0
    szCtrlTab           BYTE "Ctrl+Tab - Next Tab",0
    szShiftTab          BYTE "Shift+Tab - Previous Tab",0
    szCtrlH             BYTE "Ctrl+H - Find/Replace",0
    szCtrlShiftF        BYTE "Ctrl+Shift+F - Search Output",0

.data?
    ; Shortcut state
    LastKeyCode         DWORD ?
    CtrlPressed         DWORD ?
    ShiftPressed        DWORD ?
    AltPressed          DWORD ?

;==========================================================================
; CODE
;==========================================================================
.code

;==========================================================================
; PUBLIC: keyboard_shortcut_init() -> eax
; Initialize keyboard shortcut system
;==========================================================================
PUBLIC keyboard_shortcut_init
keyboard_shortcut_init PROC
    mov CtrlPressed, 0
    mov ShiftPressed, 0
    mov AltPressed, 0
    mov eax, 1
    ret
keyboard_shortcut_init ENDP

;==========================================================================
; PUBLIC: keyboard_shortcut_handler(keyCode: ecx, flags: edx) -> eax
; Handle WM_KEYDOWN messages
; ecx = virtual key code
; edx = key flags (shift, ctrl, alt)
; Returns: 1 if handled, 0 if not
;==========================================================================
PUBLIC keyboard_shortcut_handler
keyboard_shortcut_handler PROC
    push rbx
    push rsi
    sub rsp, 32
    
    mov r8d, ecx        ; key code
    mov r9d, edx        ; flags
    
    ; Update modifier state
    cmp r8d, VK_CONTROL
    jne check_shift
    mov CtrlPressed, 1
    jmp handler_done
    
check_shift:
    cmp r8d, VK_SHIFT
    jne check_alt
    mov ShiftPressed, 1
    jmp handler_done
    
check_alt:
    cmp r8d, VK_MENU
    jne check_shortcuts
    mov AltPressed, 1
    jmp handler_done
    
check_shortcuts:
    ; Check if Ctrl is held
    mov eax, CtrlPressed
    test eax, eax
    jz check_shift_only
    
    ; Ctrl+N = New File
    cmp r8d, VK_N
    je shortcut_new_file
    
    ; Ctrl+O = Open File
    cmp r8d, VK_O
    je shortcut_open_file
    
    ; Ctrl+S = Save File
    cmp r8d, VK_S
    je shortcut_save_file
    
    ; Ctrl+W = Close Tab
    cmp r8d, VK_W
    je shortcut_close_tab
    
    ; Ctrl+Tab = Next Tab
    cmp r8d, VK_TAB
    je shortcut_next_tab
    
    ; Ctrl+H = Find/Replace
    cmp r8d, VK_H
    je shortcut_find_replace
    
    ; Ctrl+Shift+F = Search Output
    mov eax, ShiftPressed
    test eax, eax
    jz check_shift_only
    
    cmp r8d, VK_F
    je shortcut_search_output
    
    jmp check_shift_only
    
check_shift_only:
    ; Shift+Tab = Previous Tab (without Ctrl)
    mov eax, CtrlPressed
    test eax, eax
    jnz handler_done
    
    mov eax, ShiftPressed
    test eax, eax
    jz handler_done
    
    cmp r8d, VK_TAB
    je shortcut_prev_tab
    
    jmp handler_done
    
;==========================================================================
; SHORTCUT HANDLERS
;==========================================================================

shortcut_new_file:
    call menu_file_new
    mov eax, 1
    jmp handler_done
    
shortcut_open_file:
    call menu_file_open
    mov eax, 1
    jmp handler_done
    
shortcut_save_file:
    call menu_file_save
    mov eax, 1
    jmp handler_done
    
shortcut_close_tab:
    call menu_file_close_tab
    mov eax, 1
    jmp handler_done
    
shortcut_next_tab:
    ; Cycle through tabs
    call tab_get_agent_mode
    inc eax
    cmp eax, 4
    jl next_tab_valid
    xor eax, eax
    
next_tab_valid:
    mov ecx, eax
    call tab_set_agent_mode
    mov eax, 1
    jmp handler_done
    
shortcut_prev_tab:
    ; Cycle backwards through tabs
    call tab_get_agent_mode
    dec eax
    cmp eax, 0
    jge prev_tab_valid
    mov eax, 3
    
prev_tab_valid:
    mov ecx, eax
    call tab_set_agent_mode
    mov eax, 1
    jmp handler_done
    
shortcut_find_replace:
    ; Open find/replace dialog
    lea rcx, szCtrlH
    lea rdx, szCtrlH
    call ui_show_dialog
    mov eax, 1
    jmp handler_done
    
shortcut_search_output:
    ; Search in output pane
    call output_pane_find_next
    mov eax, 1
    jmp handler_done
    
handler_done:
    add rsp, 32
    pop rsi
    pop rbx
    ret
keyboard_shortcut_handler ENDP

;==========================================================================
; PUBLIC: keyboard_shortcut_keyup(keyCode: ecx) -> eax
; Handle WM_KEYUP messages to clear modifier flags
;==========================================================================
PUBLIC keyboard_shortcut_keyup
keyboard_shortcut_keyup PROC
    push rbx
    sub rsp, 32
    
    cmp ecx, VK_CONTROL
    jne check_shift_up
    mov CtrlPressed, 0
    jmp keyup_done
    
check_shift_up:
    cmp ecx, VK_SHIFT
    jne check_alt_up
    mov ShiftPressed, 0
    jmp keyup_done
    
check_alt_up:
    cmp ecx, VK_MENU
    jne keyup_done
    mov AltPressed, 0
    
keyup_done:
    mov eax, 1
    add rsp, 32
    pop rbx
    ret
keyboard_shortcut_keyup ENDP

;==========================================================================
; PUBLIC: keyboard_shortcut_get_description(keyCode: ecx) -> rax (string)
; Return human-readable shortcut description
;==========================================================================
PUBLIC keyboard_shortcut_get_description
keyboard_shortcut_get_description PROC
    cmp ecx, VK_N
    je desc_ctrl_n
    cmp ecx, VK_O
    je desc_ctrl_o
    cmp ecx, VK_S
    je desc_ctrl_s
    cmp ecx, VK_W
    je desc_ctrl_w
    cmp ecx, VK_TAB
    je desc_ctrl_tab
    cmp ecx, VK_H
    je desc_ctrl_h
    cmp ecx, VK_F
    je desc_ctrl_shift_f
    
    xor rax, rax
    ret
    
desc_ctrl_n:
    lea rax, [szCtrlN]
    ret
    
desc_ctrl_o:
    lea rax, [szCtrlO]
    ret
    
desc_ctrl_s:
    lea rax, [szCtrlS]
    ret
    
desc_ctrl_w:
    lea rax, [szCtrlW]
    ret
    
desc_ctrl_tab:
    lea rax, [szCtrlTab]
    ret
    
desc_ctrl_h:
    lea rax, [szCtrlH]
    ret
    
desc_ctrl_shift_f:
    lea rax, [szCtrlShiftF]
    ret
keyboard_shortcut_get_description ENDP

END

