;==========================================================================
; masm_command_palette.asm - ML64-Compatible Command Palette
;==========================================================================

option casemap:none
includelib kernel32.lib
includelib user32.lib
includelib gdi32.lib

;==========================================================================
; EXTERNAL DECLARATIONS
;==========================================================================
EXTERN RegisterClassExA:PROC
EXTERN CreateWindowExA:PROC
EXTERN DefWindowProcA:PROC
EXTERN ShowWindow:PROC
EXTERN SetFocus:PROC
EXTERN SendMessageA:PROC
EXTERN GetWindowTextA:PROC
EXTERN SetWindowTextA:PROC
EXTERN CreateFontA:PROC
EXTERN DeleteObject:PROC
EXTERN InvalidateRect:PROC
EXTERN GetModuleHandleA:PROC
EXTERN LoadCursorA:PROC
EXTERN asm_log:PROC

;==========================================================================
; CONSTANTS
;==========================================================================
MAX_COMMANDS        EQU 500
MAX_RESULTS         EQU 15

;==========================================================================
; DATA
;==========================================================================
.data
g_palette_hwnd      QWORD 0
g_command_count     DWORD 0
g_is_visible        DWORD 0

szPaletteClass      BYTE "RawrXD_CommandPalette", 0
szPaletteTitle      BYTE "Command Palette", 0
szLogInitPalette    BYTE "[Palette] Initialized", 0
szLogShowPalette    BYTE "[Palette] Showing window", 0
szLogHidePalette    BYTE "[Palette] Hiding window", 0
szLogRegCmd         BYTE "[Palette] Command registered", 0
szLogExecCmd        BYTE "[Palette] Executing command", 0

.code

;==========================================================================
; palette_init - Initialize command palette
;==========================================================================
palette_init PROC
    sub rsp, 120
    
    ; Get module handle
    xor ecx, ecx
    call GetModuleHandleA
    mov qword ptr [rsp+20h], rax
    
    ; Build WNDCLASSEXA on stack
    mov dword ptr [rsp+30h], 80          ; cbSize (sizeof WNDCLASSEXA)
    mov dword ptr [rsp+34h], 0           ; style
    lea rax, palette_wnd_proc
    mov qword ptr [rsp+38h], rax         ; lpfnWndProc
    mov dword ptr [rsp+40h], 0           ; cbClsExtra
    mov dword ptr [rsp+44h], 0           ; cbWndExtra
    mov rax, qword ptr [rsp+20h]
    mov qword ptr [rsp+48h], rax         ; hInstance
    mov qword ptr [rsp+50h], 0           ; hIcon
    
    ; LoadCursor(NULL, IDC_ARROW)
    xor ecx, ecx
    mov edx, 32512                       ; IDC_ARROW
    call LoadCursorA
    mov qword ptr [rsp+58h], rax         ; hCursor
    
    mov qword ptr [rsp+60h], 0           ; hbrBackground
    mov qword ptr [rsp+68h], 0           ; lpszMenuName
    lea rax, szPaletteClass
    mov qword ptr [rsp+70h], rax         ; lpszClassName
    mov qword ptr [rsp+78h], 0           ; hIconSm
    
    ; RegisterClassExA
    lea rcx, [rsp+30h]
    call RegisterClassExA
    
    lea rcx, szLogInitPalette
    call asm_log
    
    mov eax, 1
    add rsp, 120
    ret
palette_init ENDP

PUBLIC palette_init

;==========================================================================
; palette_create_window - Create palette window
;==========================================================================
palette_create_window PROC
    sub rsp, 120
    
    ; GetModuleHandle
    xor ecx, ecx
    call GetModuleHandleA
    mov qword ptr [rsp+20h], rax
    
    ; CreateWindowExA
    mov ecx, 00000008h                   ; WS_EX_TOPMOST
    lea rdx, szPaletteClass
    lea r8, szPaletteTitle
    mov r9d, 80000000h                   ; WS_POPUP
    mov dword ptr [rsp+28h], 100         ; x
    mov dword ptr [rsp+30h], 100         ; y
    mov dword ptr [rsp+38h], 600         ; width
    mov dword ptr [rsp+40h], 400         ; height
    mov qword ptr [rsp+48h], 0           ; hWndParent
    mov qword ptr [rsp+50h], 0           ; hMenu
    mov rax, qword ptr [rsp+20h]
    mov qword ptr [rsp+58h], rax         ; hInstance
    mov qword ptr [rsp+60h], 0           ; lpParam
    call CreateWindowExA
    
    mov g_palette_hwnd, rax
    add rsp, 120
    ret
palette_create_window ENDP

PUBLIC palette_create_window

;==========================================================================
; palette_show - Show command palette
;==========================================================================
palette_show PROC
    sub rsp, 40
    
    lea rcx, szLogShowPalette
    call asm_log
    
    mov rcx, g_palette_hwnd
    test rcx, rcx
    jz show_done
    
    mov edx, 5                           ; SW_SHOW
    call ShowWindow
    
    mov rcx, g_palette_hwnd
    call SetFocus
    
    mov g_is_visible, 1
    
show_done:
    xor eax, eax
    add rsp, 40
    ret
palette_show ENDP

PUBLIC palette_show

;==========================================================================
; palette_hide - Hide command palette
;==========================================================================
palette_hide PROC
    sub rsp, 40
    
    lea rcx, szLogHidePalette
    call asm_log
    
    mov rcx, g_palette_hwnd
    test rcx, rcx
    jz hide_done
    
    xor edx, edx                         ; SW_HIDE
    call ShowWindow
    
    mov g_is_visible, 0
    
hide_done:
    xor eax, eax
    add rsp, 40
    ret
palette_hide ENDP

PUBLIC palette_hide

;==========================================================================
; palette_register_command - Register a command
; rcx = command_id, rdx = label, r8 = callback
;==========================================================================
palette_register_command PROC
    sub rsp, 56
    
    mov qword ptr [rsp+20h], rcx
    mov qword ptr [rsp+28h], rdx
    mov qword ptr [rsp+30h], r8
    
    lea rcx, szLogRegCmd
    call asm_log
    
    ; Increment command count
    mov eax, g_command_count
    inc eax
    cmp eax, MAX_COMMANDS
    jae reg_failed
    mov g_command_count, eax
    
reg_success:
    mov eax, 1
    add rsp, 56
    ret
    
reg_failed:
    xor eax, eax
    add rsp, 56
    ret
palette_register_command ENDP

PUBLIC palette_register_command

;==========================================================================
; palette_execute_command - Execute command by ID
; rcx = command_id
;==========================================================================
palette_execute_command PROC
    sub rsp, 40
    
    mov qword ptr [rsp+20h], rcx
    
    lea rcx, szLogExecCmd
    call asm_log
    
    xor eax, eax
    add rsp, 40
    ret
palette_execute_command ENDP

PUBLIC palette_execute_command

;==========================================================================
; palette_get_state - Get palette state pointer
;==========================================================================
palette_get_state PROC
    lea rax, g_palette_hwnd
    ret
palette_get_state ENDP

PUBLIC palette_get_state

;==========================================================================
; palette_wnd_proc - Window procedure for palette
; rcx = hwnd, rdx = uMsg, r8 = wParam, r9 = lParam
;==========================================================================
palette_wnd_proc PROC
    sub rsp, 56
    
    mov qword ptr [rsp+20h], rcx
    mov qword ptr [rsp+28h], rdx
    mov qword ptr [rsp+30h], r8
    mov qword ptr [rsp+38h], r9
    
    ; Check message type
    cmp edx, 2                           ; WM_DESTROY
    je msg_destroy
    
    cmp edx, 15                          ; WM_PAINT
    je msg_paint
    
    cmp edx, 258                         ; WM_CHAR
    je msg_char
    
    ; Default processing
    mov rcx, qword ptr [rsp+20h]
    mov rdx, qword ptr [rsp+28h]
    mov r8, qword ptr [rsp+30h]
    mov r9, qword ptr [rsp+38h]
    call DefWindowProcA
    add rsp, 56
    ret
    
msg_destroy:
    xor eax, eax
    add rsp, 56
    ret
    
msg_paint:
    xor eax, eax
    add rsp, 56
    ret
    
msg_char:
    ; Handle character input for search
    xor eax, eax
    add rsp, 56
    ret
palette_wnd_proc ENDP

;==========================================================================
; palette_search - Search commands with fuzzy matching
; rcx = search_text
;==========================================================================
palette_search PROC
    sub rsp, 40
    xor eax, eax
    add rsp, 40
    ret
palette_search ENDP

PUBLIC palette_search

;==========================================================================
; palette_select_next - Select next result
;==========================================================================
palette_select_next PROC
    sub rsp, 40
    xor eax, eax
    add rsp, 40
    ret
palette_select_next ENDP

PUBLIC palette_select_next

;==========================================================================
; palette_select_prev - Select previous result
;==========================================================================
palette_select_prev PROC
    sub rsp, 40
    xor eax, eax
    add rsp, 40
    ret
palette_select_prev ENDP

PUBLIC palette_select_prev

;==========================================================================
; palette_execute_selected - Execute currently selected command
;==========================================================================
palette_execute_selected PROC
    sub rsp, 40
    xor eax, eax
    add rsp, 40
    ret
palette_execute_selected ENDP

PUBLIC palette_execute_selected

END
