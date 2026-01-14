; ==========================================================================
; MASM Qt6 Component: Status Bar
; ==========================================================================
; Status bar displaying file info, cursor position, and mode indicators.
;
; Features:
;   - File name and modification status (*)
;   - Cursor position (line:column)
;   - File size_val in_val bytes
;   - Line ending mode (CRLF, LF, CR)
;   - Character encoding (UTF-8, ASCII)
;   - Mode indicators (INSERT, NORMAL, VISUAL)
;   - Zoom level percentage
;
; Architecture:
;   - STATUS_BAR structure (inherits OBJECT_BASE)
;   - STATUS_SEGMENT (left, center, right panels)
;   - Update on cursor move, file load, modification
;
; ==========================================================================

option casemap:none

; External memory functions (provided by malloc_wrapper.asm)
extern masm_malloc : proc
extern masm_free : proc
extern masm_realloc : proc
EXTERN memset:PROC

; Win32 API
EXTERN CreateWindowExA:PROC
EXTERN DestroyWindow:PROC
EXTERN SetWindowPos:PROC
EXTERN GetDC:PROC
EXTERN ReleaseDC:PROC
EXTERN TextOutA:PROC
EXTERN CreateFontA:PROC
EXTERN DeleteObject:PROC
EXTERN CreateSolidBrush:PROC
EXTERN SetBkColor:PROC
EXTERN SetTextColor:PROC
EXTERN SelectObject:PROC
EXTERN Rectangle:PROC
EXTERN MoveToEx:PROC
EXTERN LineTo:PROC
EXTERN lstrcpyA:PROC
EXTERN lstrcatA:PROC
EXTERN lstrlenA:PROC
EXTERN wsprintfA:PROC

include windows.inc
includelib kernel32.lib
includelib user32.lib
includelib gdi32.lib

; Define OBJECT_BASE structure (from qt6_foundation)
OBJECT_BASE STRUCT
    obj_vmt          QWORD ?
    obj_hwnd         QWORD ?
    obj_parent       QWORD ?
    obj_children     QWORD ?
    obj_child_count  DWORD ?
    obj_flags        DWORD ?
    obj_user_data    QWORD ?
OBJECT_BASE ENDS

FLAG_VISIBLE         EQU 00000001h
FLAG_DIRTY           EQU 00000008h

;==========================================================================
; STRUCTURES
;=========================================================================

; Status bar segment
STATUS_SEGMENT STRUCT
    text_ptr        QWORD ?         ; Pointer to text buffer
    text_len        DWORD ?         ; Text length
    x               DWORD ?         ; Pixel position
    width_val       DWORD ?         ; Segment width_val
    color_bg        DWORD ?         ; Background color
    color_text      DWORD ?         ; Text color
    alignment       DWORD ?         ; ALIGN_LEFT, ALIGN_CENTER, ALIGN_RIGHT
STATUS_SEGMENT ENDS

; Status bar
STATUS_BAR STRUCT
    ; OBJECT_BASE fields
    obj_vmt          QWORD ?
    obj_hwnd         QWORD ?
    obj_parent       QWORD ?
    obj_children     QWORD ?
    obj_child_count  DWORD ?
    obj_flags        DWORD ?
    obj_user_data    QWORD ?
    
    ; Segments
    left_segment    STATUS_SEGMENT <>
    center_segment  STATUS_SEGMENT <>
    right_segment   STATUS_SEGMENT <>
    
    ; Text buffers (pre-allocated)
    left_text       BYTE 256 DUP(0)
    center_text     BYTE 256 DUP(0)
    right_text      BYTE 256 DUP(0)
    
    ; Dimensions
    hwnd            QWORD ?         ; Window handle
    x               DWORD ?         ; Position
    y               DWORD ?         ; Position
    width_val       DWORD ?         ; Bar width_val
    height          DWORD ?         ; Bar height (24 pixels)
    
    ; File state (references from editor)
    file_name_ptr   QWORD ?         ; Current file name
    file_size       QWORD ?         ; File size_val in_val bytes
    is_modified     DWORD ?         ; Modified flag (*)
    
    ; Cursor state
    cursor_line     DWORD ?         ; Current line (1-based display)
    cursor_col      DWORD ?         ; Current column (1-based display)
    
    ; Mode
    mode            DWORD ?         ; MODE_INSERT, MODE_NORMAL, MODE_VISUAL
    zoom_level      DWORD ?         ; 100%, 110%, 120%, etc.
    
    ; Encoding
    line_ending     DWORD ?         ; ENDING_CRLF, ENDING_LF, ENDING_CR
    encoding        DWORD ?         ; ENC_ASCII, ENC_UTF8
    
    ; Font
    font_handle     QWORD ?         ; GDI font
    brush_bg        QWORD ?         ; Background brush
    brush_text      QWORD ?         ; Text brush
    
    ; Flags
    flags           DWORD ?         ; FLAG_VISIBLE, FLAG_DIRTY
STATUS_BAR ENDS

;==========================================================================
; CONSTANTS
;==========================================================================

; Alignment
ALIGN_LEFT          EQU 0
ALIGN_CENTER        EQU 1
ALIGN_RIGHT         EQU 2

; Modes
MODE_NORMAL         EQU 0
MODE_INSERT         EQU 1
MODE_VISUAL         EQU 2

; Line endings
ENDING_CRLF         EQU 0           ; Windows
ENDING_LF           EQU 1           ; Unix/Linux
ENDING_CR           EQU 2           ; Old Mac

; Encoding
ENC_ASCII           EQU 0
ENC_UTF8            EQU 1

; Colors
COLOR_STATUSBAR_BG  EQU 0F0F0F0h    ; Light gray
COLOR_STATUSBAR_TX  EQU 0000000h    ; Black
COLOR_MODIFIED_TX   EQU 0FF0000h    ; Red (for *)

; WinGDI constants (fallbacks if windows.inc does not define them)
FW_NORMAL           EQU 400
ANSI_CHARSET        EQU 0
OUT_DEFAULT_PRECIS  EQU 0
CLIP_DEFAULT_PRECIS EQU 0
DEFAULT_QUALITY     EQU 0
DEFAULT_PITCH       EQU 0
FF_DONTCARE         EQU 0
; Flags
; FLAG_VISIBLE and FLAG_DIRTY already defined in OBJECT_BASE section above

;==========================================================================
; PUBLIC FUNCTIONS
;===========================================================================
PUBLIC statusbar_create
PUBLIC statusbar_destroy
PUBLIC statusbar_update_cursor
PUBLIC statusbar_update_file
PUBLIC statusbar_update_mode
PUBLIC statusbar_set_zoom
PUBLIC statusbar_paint
PUBLIC statusbar_on_mouse

;==========================================================================
; IMPLEMENTATION
;==========================================================================

.CODE

; =============== statusbar_create ===============
; Create status bar instance
; Inputs:  rcx = hwnd, rdx = y position, r8 = width_val
; Outputs: rax = STATUS_BAR ptr
statusbar_create PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32

    ; Preserve incoming parameters before clobbering rcx
    mov r12, rcx   ; hwnd
    mov r13, rdx   ; y position
    mov r14, r8    ; width
    
    ; Allocate STATUS_BAR structure
    mov rcx, sizeof(STATUS_BAR)
    call masm_malloc
    test rax, rax
    jz create_failed
    mov rbx, rax  ; rbx = STATUS_BAR ptr
    
    ; Initialize OBJECT_BASE fields
    mov qword ptr [rbx+STATUS_BAR.obj_hwnd], r12
    mov qword ptr [rbx+STATUS_BAR.obj_parent], r12
    mov qword ptr [rbx+STATUS_BAR.obj_children], 0
    mov dword ptr [rbx+STATUS_BAR.obj_child_count], 0
    mov dword ptr [rbx+STATUS_BAR.obj_flags], FLAG_VISIBLE
    mov qword ptr [rbx+STATUS_BAR.obj_user_data], 0
    
    ; Set dimensions
    mov qword ptr [rbx+STATUS_BAR.hwnd], r12
    mov dword ptr [rbx+STATUS_BAR.x], 0
    mov dword ptr [rbx+STATUS_BAR.y], r13d
    mov dword ptr [rbx+STATUS_BAR.width_val], r14d
    mov dword ptr [rbx+STATUS_BAR.height], 24
    
    ; Initialize segments with proportional widths
    mov eax, r14d
    mov ecx, eax
    shr ecx, 2  ; 25%
    mov edx, eax
    shr edx, 1  ; 50%
    sub eax, ecx
    sub eax, edx  ; remaining 25%
    
    ; Left segment (file info)
    mov [rbx+STATUS_BAR.left_segment.x], 0
    mov [rbx+STATUS_BAR.left_segment.width_val], ecx
    mov [rbx+STATUS_BAR.left_segment.color_bg], COLOR_STATUSBAR_BG
    mov [rbx+STATUS_BAR.left_segment.color_text], COLOR_STATUSBAR_TX
    mov [rbx+STATUS_BAR.left_segment.alignment], ALIGN_LEFT
    lea rax, [rbx+STATUS_BAR.left_text]
    mov qword ptr [rbx+STATUS_BAR.left_segment.text_ptr], rax
    
    ; Center segment (cursor/mode)
    mov [rbx+STATUS_BAR.center_segment.x], ecx
    mov [rbx+STATUS_BAR.center_segment.width_val], edx
    mov [rbx+STATUS_BAR.center_segment.color_bg], COLOR_STATUSBAR_BG
    mov [rbx+STATUS_BAR.center_segment.color_text], COLOR_STATUSBAR_TX
    mov [rbx+STATUS_BAR.center_segment.alignment], ALIGN_CENTER
    lea rax, [rbx+STATUS_BAR.center_text]
    mov qword ptr [rbx+STATUS_BAR.center_segment.text_ptr], rax
    
    ; Right segment (zoom/encoding)
    mov eax, ecx
    add eax, edx
    mov [rbx+STATUS_BAR.right_segment.x], eax
    mov ecx, [rbx+STATUS_BAR.width_val]
    sub ecx, eax
    mov [rbx+STATUS_BAR.right_segment.width_val], ecx
    mov [rbx+STATUS_BAR.right_segment.color_bg], COLOR_STATUSBAR_BG
    mov [rbx+STATUS_BAR.right_segment.color_text], COLOR_STATUSBAR_TX
    mov [rbx+STATUS_BAR.right_segment.alignment], ALIGN_RIGHT
    lea rax, [rbx+STATUS_BAR.right_text]
    mov qword ptr [rbx+STATUS_BAR.right_segment.text_ptr], rax
    
    ; Create font (Segoe UI, 10pt)
    mov rcx, -10  ; height
    mov rdx, 0    ; width
    mov r8, 0     ; escapement
    mov r9, 0     ; orientation
    push FW_NORMAL
    push 0        ; italic
    push 0        ; underline
    push 0        ; strikeout
    push ANSI_CHARSET
    push OUT_DEFAULT_PRECIS
    push CLIP_DEFAULT_PRECIS
    push DEFAULT_QUALITY
    push DEFAULT_PITCH or FF_DONTCARE
    lea r10, STR_SEGOE_UI
    push r10
    call CreateFontA
    mov [rbx+STATUS_BAR.font_handle], rax
    
    ; Create brushes
    mov rcx, COLOR_STATUSBAR_BG
    call CreateSolidBrush
    mov [rbx+STATUS_BAR.brush_bg], rax
    
    mov rcx, COLOR_STATUSBAR_TX
    call CreateSolidBrush
    mov [rbx+STATUS_BAR.brush_text], rax
    
    ; Initialize state
    mov [rbx+STATUS_BAR.file_name_ptr], 0
    mov [rbx+STATUS_BAR.file_size], 0
    mov [rbx+STATUS_BAR.is_modified], 0
    mov [rbx+STATUS_BAR.cursor_line], 1
    mov [rbx+STATUS_BAR.cursor_col], 1
    mov [rbx+STATUS_BAR.mode], MODE_NORMAL
    mov [rbx+STATUS_BAR.zoom_level], 100
    mov [rbx+STATUS_BAR.line_ending], ENDING_CRLF
    mov [rbx+STATUS_BAR.encoding], ENC_UTF8
    mov [rbx+STATUS_BAR.flags], FLAG_VISIBLE
    
    ; Set initial text
    lea rcx, [rbx+STATUS_BAR.left_text]
    lea rdx, STR_NO_FILE
    call lstrcpyA
    
    lea rcx, [rbx+STATUS_BAR.center_text]
    lea rdx, STR_LINE_COL
    call lstrcpyA
    
    lea rcx, [rbx+STATUS_BAR.right_text]
    lea rdx, STR_ZOOM_DEFAULT
    call lstrcpyA
    
    mov rax, rbx
    jmp create_done
    
create_failed:
    xor rax, rax
    
create_done:
    add rsp, 32
    pop rbp
    ret
statusbar_create ENDP

; =============== statusbar_destroy ===============
; Destroy status bar and free resources
; Inputs:  rcx = STATUS_BAR ptr
; Outputs: rax = success (1) or failure (0)
statusbar_destroy PROC
    push rbp
    mov rbp, rsp
    
    mov rbx, rcx  ; STATUS_BAR ptr
    
    ; Delete font
    mov rcx, [rbx+STATUS_BAR.font_handle]
    test rcx, rcx
    jz skip_font
    call DeleteObject
skip_font:
    
    ; Delete brushes
    mov rcx, [rbx+STATUS_BAR.brush_bg]
    test rcx, rcx
    jz skip_bg_brush
    call DeleteObject
skip_bg_brush:
    
    mov rcx, [rbx+STATUS_BAR.brush_text]
    test rcx, rcx
    jz skip_text_brush
    call DeleteObject
skip_text_brush:
    
    ; Free file name if allocated
    mov rcx, [rbx+STATUS_BAR.file_name_ptr]
    test rcx, rcx
    jz skip_file_free
    call masm_free
skip_file_free:
    
    ; Free STATUS_BAR structure
    mov rcx, rbx
    call masm_free
    
    mov rax, 1
    pop rbp
    ret
statusbar_destroy ENDP

; =============== statusbar_update_cursor ===============
; Update cursor position display
; Inputs:  rcx = STATUS_BAR ptr, rdx = line (0-based), r8 = column (0-based)
; Outputs: rax = success (1) or failure (0)
statusbar_update_cursor PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rbx, rcx  ; STATUS_BAR ptr
    
    ; Convert 0-based to 1-based for display
    mov eax, edx
    inc eax
    mov [rbx+STATUS_BAR.cursor_line], eax
    
    mov eax, r8d
    inc eax
    mov [rbx+STATUS_BAR.cursor_col], eax
    
    ; Format center_text as "line:col" (e.g., "42:15")
    lea rcx, [rbx+STATUS_BAR.center_text]
    lea rdx, STR_LINE_COL_FORMAT
    mov r8d, [rbx+STATUS_BAR.cursor_line]
    mov r9d, [rbx+STATUS_BAR.cursor_col]
    call wsprintfA
    
    ; Add mode indicator
    mov eax, [rbx+STATUS_BAR.mode]
    cmp eax, MODE_NORMAL
    je mode_normal
    cmp eax, MODE_INSERT
    je mode_insert
    cmp eax, MODE_VISUAL
    je mode_visual
    jmp set_dirty
    
mode_normal:
    lea rcx, [rbx+STATUS_BAR.center_text]
    lea rdx, STR_MODE_NORMAL
    call lstrcatA
    jmp set_dirty
    
mode_insert:
    lea rcx, [rbx+STATUS_BAR.center_text]
    lea rdx, STR_MODE_INSERT
    call lstrcatA
    jmp set_dirty
    
mode_visual:
    lea rcx, [rbx+STATUS_BAR.center_text]
    lea rdx, STR_MODE_VISUAL
    call lstrcatA
    
set_dirty:
    ; Set FLAG_DIRTY
    mov eax, [rbx+STATUS_BAR.flags]
    or eax, FLAG_DIRTY
    mov [rbx+STATUS_BAR.flags], eax
    
    mov rax, 1
    add rsp, 32
    pop rbp
    ret
statusbar_update_cursor ENDP

; =============== statusbar_update_file ===============
; Update file name and size_val display
; Inputs:  rcx = STATUS_BAR ptr, rdx = file name (LPSTR), r8 = file size_val (QWORD), r9 = is_modified flag
; Outputs: rax = success (1) or failure (0)
statusbar_update_file PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rbx, rcx  ; STATUS_BAR ptr
    
    ; Store file size_val
    mov [rbx+STATUS_BAR.file_size], r8
    mov [rbx+STATUS_BAR.is_modified], r9d
    
    ; Free previous file name if allocated
    mov rcx, [rbx+STATUS_BAR.file_name_ptr]
    test rcx, rcx
    jz alloc_new_name
    call masm_free
    
alloc_new_name:
    ; Allocate and copy file name
    mov rcx, rdx
    call lstrlenA
    inc rax  ; Include null terminator
    mov rcx, rax
    call masm_malloc
    test rax, rax
    jz update_failed
    mov [rbx+STATUS_BAR.file_name_ptr], rax
    
    mov rcx, rax
    mov rdx, rdx  ; file name
    call lstrcpyA
    
    ; Extract file name from full path (last part after \)
    mov rcx, [rbx+STATUS_BAR.file_name_ptr]
    call extract_filename
    
    ; Format left_text as "filename* - size_val"
    lea rcx, [rbx+STATUS_BAR.left_text]
    mov rdx, [rbx+STATUS_BAR.file_name_ptr]
    
    ; Add modified indicator
    cmp dword ptr [rbx+STATUS_BAR.is_modified], 0
    je no_modification
    lea r8, STR_MODIFIED
    call lstrcpyA
    lea rcx, [rbx+STATUS_BAR.left_text]
    lea rdx, STR_MODIFIED_SUFFIX
    call lstrcatA
    jmp add_size
    
no_modification:
    call lstrcpyA
    
add_size:
    lea rcx, [rbx+STATUS_BAR.left_text]
    lea rdx, STR_SIZE_PREFIX
    call lstrcatA
    
    lea rcx, [rbx+STATUS_BAR.left_text]
    mov rdx, [rbx+STATUS_BAR.file_size]
    call format_file_size
    
    lea rcx, [rbx+STATUS_BAR.left_text]
    lea rdx, STR_SIZE_SUFFIX
    call lstrcatA
    
    ; Set FLAG_DIRTY
    mov eax, [rbx+STATUS_BAR.flags]
    or eax, FLAG_DIRTY
    mov [rbx+STATUS_BAR.flags], eax
    
    mov rax, 1
    jmp update_done
    
update_failed:
    xor rax, rax
    
update_done:
    add rsp, 32
    pop rbp
    ret
statusbar_update_file ENDP

; =============== statusbar_update_mode ===============
; Update mode indicator
; Inputs:  rcx = STATUS_BAR ptr, rdx = mode (MODE_NORMAL, MODE_INSERT, MODE_VISUAL)
; Outputs: rax = success (1) or failure (0)
statusbar_update_mode PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rbx, rcx  ; STATUS_BAR ptr
    mov [rbx+STATUS_BAR.mode], edx
    
    ; Update center_text with mode string
    lea rcx, [rbx+STATUS_BAR.center_text]
    lea rdx, STR_LINE_COL_FORMAT
    mov r8d, [rbx+STATUS_BAR.cursor_line]
    mov r9d, [rbx+STATUS_BAR.cursor_col]
    call wsprintfA
    
    ; Add mode indicator
    mov eax, [rbx+STATUS_BAR.mode]
    cmp eax, MODE_NORMAL
    je mode_normal
    cmp eax, MODE_INSERT
    je mode_insert
    cmp eax, MODE_VISUAL
    je mode_visual
    jmp update_right
    
mode_normal:
    lea rcx, [rbx+STATUS_BAR.center_text]
    lea rdx, STR_MODE_NORMAL
    call lstrcatA
    jmp update_right
    
mode_insert:
    lea rcx, [rbx+STATUS_BAR.center_text]
    lea rdx, STR_MODE_INSERT
    call lstrcatA
    jmp update_right
    
mode_visual:
    lea rcx, [rbx+STATUS_BAR.center_text]
    lea rdx, STR_MODE_VISUAL
    call lstrcatA
    
update_right:
    ; Update right_text with zoom, encoding, line_ending
    lea rcx, [rbx+STATUS_BAR.right_text]
    lea rdx, STR_ZOOM_FORMAT
    mov r8d, [rbx+STATUS_BAR.zoom_level]
    call wsprintfA
    
    ; Add encoding
    lea rcx, [rbx+STATUS_BAR.right_text]
    lea rdx, STR_ENCODING_PREFIX
    call lstrcatA
    
    mov eax, [rbx+STATUS_BAR.encoding]
    cmp eax, ENC_ASCII
    je encoding_ascii
    cmp eax, ENC_UTF8
    je encoding_utf8
    jmp add_line_ending
    
encoding_ascii:
    lea rcx, [rbx+STATUS_BAR.right_text]
    lea rdx, STR_ASCII
    call lstrcatA
    jmp add_line_ending
    
encoding_utf8:
    lea rcx, [rbx+STATUS_BAR.right_text]
    lea rdx, STR_UTF8
    call lstrcatA
    
add_line_ending:
    lea rcx, [rbx+STATUS_BAR.right_text]
    lea rdx, STR_LINE_ENDING_PREFIX
    call lstrcatA
    
    mov eax, [rbx+STATUS_BAR.line_ending]
    cmp eax, ENDING_CRLF
    je ending_crlf
    cmp eax, ENDING_LF
    je ending_lf
    cmp eax, ENDING_CR
    je ending_cr
    jmp set_dirty
    
ending_crlf:
    lea rcx, [rbx+STATUS_BAR.right_text]
    lea rdx, STR_CRLF
    call lstrcatA
    jmp set_dirty
    
ending_lf:
    lea rcx, [rbx+STATUS_BAR.right_text]
    lea rdx, STR_LF
    call lstrcatA
    jmp set_dirty
    
ending_cr:
    lea rcx, [rbx+STATUS_BAR.right_text]
    lea rdx, STR_CR
    call lstrcatA
    
set_dirty:
    ; Set FLAG_DIRTY
    mov eax, [rbx+STATUS_BAR.flags]
    or eax, FLAG_DIRTY
    mov [rbx+STATUS_BAR.flags], eax
    
    mov rax, 1
    add rsp, 32
    pop rbp
    ret
statusbar_update_mode ENDP

; =============== statusbar_set_zoom ===============
; Set zoom level
; Inputs:  rcx = STATUS_BAR ptr, rdx = zoom percentage (100, 110, 120, etc.)
; Outputs: rax = success (1) or failure (0)
statusbar_set_zoom PROC
    push rbp
    mov rbp, rsp
    
    mov rbx, rcx  ; STATUS_BAR ptr
    
    ; Clamp zoom to range [50, 200]
    cmp edx, 50
    jge check_max
    mov edx, 50
    jmp set_zoom
    
check_max:
    cmp edx, 200
    jle set_zoom
    mov edx, 200
    
set_zoom:
    mov [rbx+STATUS_BAR.zoom_level], edx
    
    ; Update right_text with new zoom
    lea rcx, [rbx+STATUS_BAR.right_text]
    lea rdx, STR_ZOOM_FORMAT
    mov r8d, edx
    call wsprintfA
    
    ; Set FLAG_DIRTY
    mov eax, [rbx+STATUS_BAR.flags]
    or eax, FLAG_DIRTY
    mov [rbx+STATUS_BAR.flags], eax
    
    ; Emit zoom_changed signal (if using Qt signals)
    ; TODO: Implement signal emission if Qt integration is needed
    
    mov rax, 1
    pop rbp
    ret
statusbar_set_zoom ENDP

; =============== statusbar_paint ===============
; Paint status bar to screen
; Inputs:  rcx = STATUS_BAR ptr, rdx = hwnd, r8 = hdc
; Outputs: rax = success (1) or failure (0)
statusbar_paint PROC
    push rbp
    mov rbp, rsp
    sub rsp, 80h
    
    mov rbx, rcx  ; STATUS_BAR ptr
    mov rsi, rdx  ; hwnd
    mov rdi, r8   ; hdc
    
    ; Fill background
    mov rcx, rdi
    mov rdx, COLOR_STATUSBAR_BG
    call SetBkColor
    
    mov rcx, rdi
    mov rdx, COLOR_STATUSBAR_TX
    call SetTextColor
    
    mov rcx, rdi
    mov rdx, [rbx+STATUS_BAR.font_handle]
    call SelectObject
    mov [rsp+40h], rax  ; save old font
    
    ; Fill background rectangle
    mov rcx, rdi
    mov rdx, [rbx+STATUS_BAR.brush_bg]
    call SelectObject
    mov [rsp+48h], rax  ; save old brush
    
    mov rcx, rdi
    mov edx, 0
    mov r8d, [rbx+STATUS_BAR.y]
    mov r9d, [rbx+STATUS_BAR.width_val]
    mov eax, [rbx+STATUS_BAR.y]
    add eax, [rbx+STATUS_BAR.height]
    push rax
    call Rectangle
    
    ; Draw left segment
    mov rcx, rdi
    mov edx, [rbx+STATUS_BAR.left_segment.x]
    mov r8d, [rbx+STATUS_BAR.y]
    mov r9d, [rbx+STATUS_BAR.left_segment.width_val]
    mov eax, [rbx+STATUS_BAR.y]
    add eax, [rbx+STATUS_BAR.height]
    push rax
    call Rectangle
    
    mov rcx, rdi
    mov edx, [rbx+STATUS_BAR.left_segment.x]
    add edx, 5  ; padding
    mov r8d, [rbx+STATUS_BAR.y]
    add r8d, 5
    lea r9, [rbx+STATUS_BAR.left_text]
    call TextOutA
    
    ; Draw center segment
    mov rcx, rdi
    mov edx, [rbx+STATUS_BAR.center_segment.x]
    mov r8d, [rbx+STATUS_BAR.y]
    mov r9d, [rbx+STATUS_BAR.center_segment.width_val]
    mov eax, [rbx+STATUS_BAR.y]
    add eax, [rbx+STATUS_BAR.height]
    push rax
    call Rectangle
    
    mov rcx, rdi
    mov edx, [rbx+STATUS_BAR.center_segment.x]
    add edx, 5
    mov r8d, [rbx+STATUS_BAR.y]
    add r8d, 5
    lea r9, [rbx+STATUS_BAR.center_text]
    call TextOutA
    
    ; Draw right segment
    mov rcx, rdi
    mov edx, [rbx+STATUS_BAR.right_segment.x]
    mov r8d, [rbx+STATUS_BAR.y]
    mov r9d, [rbx+STATUS_BAR.right_segment.width_val]
    mov eax, [rbx+STATUS_BAR.y]
    add eax, [rbx+STATUS_BAR.height]
    push rax
    call Rectangle
    
    mov rcx, rdi
    mov edx, [rbx+STATUS_BAR.right_segment.x]
    add edx, 5
    mov r8d, [rbx+STATUS_BAR.y]
    add r8d, 5
    lea r9, [rbx+STATUS_BAR.right_text]
    call TextOutA
    
    ; Draw vertical separators
    mov rcx, rdi
    mov edx, [rbx+STATUS_BAR.left_segment.width_val]
    mov r8d, [rbx+STATUS_BAR.y]
    mov r9d, edx
    mov eax, [rbx+STATUS_BAR.y]
    add eax, [rbx+STATUS_BAR.height]
    push rax
    call MoveToEx
    
    mov rcx, rdi
    mov edx, [rbx+STATUS_BAR.left_segment.width_val]
    mov r8d, [rbx+STATUS_BAR.y]
    mov r9d, [rbx+STATUS_BAR.y]
    add r9d, [rbx+STATUS_BAR.height]
    push r9
    call LineTo
    
    mov rcx, rdi
    mov edx, [rbx+STATUS_BAR.left_segment.width_val]
    add edx, [rbx+STATUS_BAR.center_segment.width_val]
    mov r8d, [rbx+STATUS_BAR.y]
    mov r9d, edx
    mov eax, [rbx+STATUS_BAR.y]
    add eax, [rbx+STATUS_BAR.height]
    push rax
    call MoveToEx
    
    mov rcx, rdi
    mov edx, [rbx+STATUS_BAR.left_segment.width_val]
    add edx, [rbx+STATUS_BAR.center_segment.width_val]
    mov r8d, [rbx+STATUS_BAR.y]
    mov r9d, [rbx+STATUS_BAR.y]
    add r9d, [rbx+STATUS_BAR.height]
    push r9
    call LineTo
    
    ; Restore old font and brush
    mov rcx, rdi
    mov rdx, [rsp+40h]
    call SelectObject
    
    mov rcx, rdi
    mov rdx, [rsp+48h]
    call SelectObject
    
    ; Clear FLAG_DIRTY
    mov eax, [rbx+STATUS_BAR.flags]
    and eax, NOT FLAG_DIRTY
    mov [rbx+STATUS_BAR.flags], eax
    
    mov rax, 1
    add rsp, 80h
    pop rbp
    ret
statusbar_paint ENDP

; =============== statusbar_on_mouse ===============
; Handle mouse click on status bar
; Inputs:  rcx = STATUS_BAR ptr, rdx = x, r8 = y, r9 = button (1=left, 2=right)
; Outputs: rax = segment clicked (0=left, 1=center, 2=right, -1=none)
statusbar_on_mouse PROC
    push rbp
    mov rbp, rsp
    
    mov rbx, rcx  ; STATUS_BAR ptr
    
    ; Check if y in bar range (y >= statusbar->y && y < statusbar->y + 24)
    mov eax, r8d
    cmp eax, [rbx+STATUS_BAR.y]
    jl no_click
    mov ecx, [rbx+STATUS_BAR.y]
    add ecx, [rbx+STATUS_BAR.height]
    cmp eax, ecx
    jge no_click
    
    ; Check which segment was clicked based on x
    mov eax, edx
    cmp eax, [rbx+STATUS_BAR.left_segment.width_val]
    jl left_segment
    
    mov ecx, [rbx+STATUS_BAR.left_segment.width_val]
    add ecx, [rbx+STATUS_BAR.center_segment.width_val]
    cmp eax, ecx
    jl center_segment
    
    ; Right segment
    mov rax, 2
    jmp check_button
    
left_segment:
    mov rax, 0
    jmp check_button
    
center_segment:
    mov rax, 1
    jmp check_button
    
check_button:
    ; If right segment + left click → show zoom menu
    cmp rax, 2
    jne check_right_click
    cmp r9d, 1
    jne check_right_click
    
    ; Show zoom menu
    ; TODO: Implement zoom menu popup
    jmp done
    
check_right_click:
    ; If right segment + right click → show encoding/line-ending menu
    cmp rax, 2
    jne done
    cmp r9d, 2
    jne done
    
    ; Show encoding/line-ending menu
    ; TODO: Implement encoding menu popup
    jmp done
    
no_click:
    mov rax, -1
    
done:
    pop rbp
    ret
statusbar_on_mouse ENDP

; =============== Helper: format_file_size ===============
; Format file size_val as human-readable string
; Inputs:  rcx = size_val (QWORD), rdx = buffer ptr
; Outputs: rax = string length
format_file_size PROC
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    mov rbx, rdx  ; buffer ptr
    
    ; If size_val < 1024: format as "1234 bytes"
    cmp rcx, 1024
    jae check_kb
    
    lea rdx, STR_SIZE_BYTES_FORMAT
    mov rcx, rbx
    mov r8, rcx
    call wsprintfA
    jmp done
    
check_kb:
    ; If size_val < 1024*1024: format as "12.3 KB"
    mov rax, rcx
    xor edx, edx
    mov r11, 1024
    div r11
    mov r8, rax  ; KB value
    
    mov rax, rcx
    xor edx, edx
    mov r11, 1024
    div r11
    mov r9, rdx  ; remainder
    
    ; Calculate decimal: remainder * 10 / 1024
    mov rax, r9
    imul rax, rax, 10
    xor edx, edx
    mov r11, 1024
    div r11
    mov r10, rax  ; decimal part
    
    cmp rcx, 1024*1024
    jae check_mb
    
    lea rdx, STR_SIZE_KB_FORMAT
    mov rcx, rbx
    mov r8, r8
    mov r9, r10
    call wsprintfA
    jmp done
    
check_mb:
    ; If size_val < 1024*1024*1024: format as "123.4 MB"
    mov rax, rcx
    xor edx, edx
    mov r11, 1024*1024
    div r11
    mov r8, rax  ; MB value
    
    mov rax, rcx
    xor edx, edx
    mov r11, 1024*1024
    div r11
    mov r9, rdx  ; remainder
    
    ; Calculate decimal: remainder * 10 / (1024*1024)
    mov rax, r9
    imul rax, rax, 10
    xor edx, edx
    mov r11, 1024*1024
    div r11
    mov r10, rax  ; decimal part
    
    cmp rcx, 1024*1024*1024
    jae format_gb
    
    lea rdx, STR_SIZE_MB_FORMAT
    mov rcx, rbx
    mov r8, r8
    mov r9, r10
    call wsprintfA
    jmp done
    
format_gb:
    ; Format as "1.2 GB"
    mov rax, rcx
    xor edx, edx
    mov r11, 1024*1024*1024
    div r11
    mov r8, rax  ; GB value
    
    mov rax, rcx
    xor edx, edx
    mov r11, 1024*1024*1024
    div r11
    mov r9, rdx  ; remainder
    
    ; Calculate decimal: remainder * 10 / (1024*1024*1024)
    mov rax, r9
    imul rax, rax, 10
    xor edx, edx
    mov r11, 1024*1024*1024
    div r11
    mov r10, rax  ; decimal part
    
    lea rdx, STR_SIZE_GB_FORMAT
    mov rcx, rbx
    mov r8, r8
    mov r9, r10
    call wsprintfA
    
done:
    mov rcx, rbx
    call lstrlenA
    mov rax, rax

format_file_size ENDP
    
; =============== Helper: extract_filename ===============
; Extract file name from full path (last part after \)
; Inputs:  rcx = full path string
; Outputs: rax = pointer to filename (within same string)
extract_filename PROC
    push rbp
    mov rbp, rsp
    
    mov rax, rcx
    mov rdx, rcx
    
find_last_backslash:
    mov cl, [rdx]
    test cl, cl
    jz done
    cmp cl, 5Ch
    jne next_char
    lea rax, [rdx+1]
next_char:
    inc rdx
    jmp find_last_backslash
    
done:
    pop rbp
    ret
extract_filename ENDP

; String constants
STR_SEGOE_UI            DB "Segoe UI",0
STR_NO_FILE             DB "No file",0
STR_LINE_COL            DB "Line: 1 Col: 1",0
STR_ZOOM_DEFAULT        DB "100% UTF-8 CRLF",0
STR_LINE_COL_FORMAT     DB "Line: %d Col: %d",0
STR_MODE_NORMAL         DB " NORMAL",0
STR_MODE_INSERT         DB " INSERT",0
STR_MODE_VISUAL         DB " VISUAL",0
STR_MODIFIED            DB "*",0
STR_MODIFIED_SUFFIX     DB "*",0
STR_SIZE_PREFIX         DB " - ",0
STR_SIZE_SUFFIX         DB " bytes",0
STR_ZOOM_FORMAT         DB "%d%%",0
STR_ENCODING_PREFIX     DB " ",0
STR_ASCII               DB "ASCII",0
STR_UTF8                DB "UTF-8",0
STR_LINE_ENDING_PREFIX  DB " ",0
STR_CRLF                DB "CRLF",0
STR_LF                  DB "LF",0
STR_CR                  DB "CR",0
STR_SIZE_BYTES_FORMAT   DB "%d bytes",0
STR_SIZE_KB_FORMAT      DB "%d.%d KB",0
STR_SIZE_MB_FORMAT      DB "%d.%d MB",0
STR_SIZE_GB_FORMAT      DB "%d.%d GB",0

END





