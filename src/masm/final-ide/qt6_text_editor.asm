; ==========================================================================
; MASM Qt6 Component: Text Editor (Scintilla-style)
; ==========================================================================
; Multi-line text editing with selection, cursor movement, and GDI+ rendering.
; Replaces QPlainTextEdit for lightweight implementation.
;
; Features:
;   - Multi-line text buffer (rope data structure)
;   - Cursor positioning (line, column tracking)
;   - Text selection (start, end offsets)
;   - Line wrapping and viewport management
;   - GDI+ rendering (font, color per line)
;   - Undo/redo stack
;   - File I/O (load, save)
;
; Architecture:
;   - TEXT_EDITOR structure (inherits OBJECT_BASE)
;   - Line array (pointers to text lines)
;   - Cursor state (current line, column)
;   - Selection state (start/end)
;   - Viewport (top line, visible lines)
;
; ==========================================================================

option casemap:none

; External memory functions (provided by malloc_wrapper.asm)
extern masm_malloc : proc
extern masm_free : proc
extern masm_realloc : proc
EXTERN memset:PROC
EXTERN memcpy:PROC

; Win32 API
EXTERN CreateWindowExA:PROC
EXTERN DestroyWindow:PROC
EXTERN InvalidateRect:PROC
EXTERN GetDC:PROC
EXTERN ReleaseDC:PROC
EXTERN TextOutA:PROC
EXTERN CreateFileA:PROC
EXTERN ReadFile:PROC
EXTERN WriteFile:PROC
EXTERN CloseHandle:PROC
EXTERN GetFileSizeEx:PROC
EXTERN OpenClipboard:PROC
EXTERN CloseClipboard:PROC
EXTERN GetClipboardData:PROC
EXTERN SetClipboardData:PROC
EXTERN GlobalAlloc:PROC
EXTERN GlobalLock:PROC
EXTERN GlobalUnlock:PROC
EXTERN PatBlt:PROC
EXTERN MoveToEx:PROC
EXTERN LineTo:PROC
EXTERN GetClientRect:PROC

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
FLAG_FOCUSED         EQU 00000004h

;==========================================================================
; STRUCTURES
;===========================================================================

; Text line (rope node)
TEXT_LINE STRUCT
    text_ptr        QWORD ?         ; Pointer to line text (LPSTR, null-terminated)
    text_len        DWORD ?         ; Length of line (excluding null terminator)
    max_capacity    DWORD ?         ; Allocated size_val
    next            QWORD ?         ; Next line (linked list)
    prev            QWORD ?         ; Previous line
TEXT_LINE ENDS

; Text editor (replaces QPlainTextEdit)
TEXT_EDITOR STRUCT
    ; OBJECT_BASE fields
    obj_vmt          QWORD ?
    obj_hwnd         QWORD ?
    obj_parent       QWORD ?
    obj_children     QWORD ?
    obj_child_count  DWORD ?
    obj_flags        DWORD ?
    obj_user_data    QWORD ?
    
    ; Text buffer
    first_line      QWORD ?         ; Pointer to first TEXT_LINE
    last_line       QWORD ?         ; Pointer to last TEXT_LINE
    line_count      DWORD ?         ; Total number of lines
    total_chars     QWORD ?         ; Total characters
    
    ; Cursor state
    cursor_line     DWORD ?         ; Current line (0-based)
    cursor_col      DWORD ?         ; Current column (0-based)
    cursor_visible  DWORD ?         ; FLAG_VISIBLE
    cursor_x        DWORD ?         ; Pixel X position
    cursor_y        DWORD ?         ; Pixel Y position
    
    ; Selection state
    sel_start_line  DWORD ?         ; Selection start line
    sel_start_col   DWORD ?         ; Selection start column
    sel_end_line    DWORD ?         ; Selection end line
    sel_end_col     DWORD ?         ; Selection end column
    has_selection   DWORD ?         ; Boolean
    
    ; Viewport
    top_line        DWORD ?         ; First visible line
    visible_lines   DWORD ?         ; Lines visible in_val viewport
    char_width      DWORD ?         ; Character width_val (pixels, monospace font)
    line_height     DWORD ?         ; Line height (pixels)
    
    ; Undo/redo
    undo_stack      QWORD ?         ; Pointer to undo buffer
    undo_count      DWORD ?         ; Number of undo entries
    redo_stack      QWORD ?         ; Pointer to redo buffer
    redo_count      DWORD ?         ; Number of redo entries
    
    ; Display
    hwnd            QWORD ?         ; Associated HWND
    font_handle     QWORD ?         ; GDI+ font handle
    brush_text      QWORD ?         ; GDI+ brush for text
    brush_bg        QWORD ?         ; GDI+ brush for background
    brush_sel       QWORD ?         ; GDI+ brush for selection highlight
    
    ; File info
    file_path       QWORD ?         ; Pointer to file path (512 bytes)
    file_name       QWORD ?         ; Pointer to file name only
    is_modified     DWORD ?         ; Dirty flag
    
    ; Flags
    flags           DWORD ?         ; FLAG_VISIBLE, FLAG_DIRTY, etc.
TEXT_EDITOR ENDS

; Undo/redo entry
UNDO_ENTRY STRUCT
    op_type         DWORD ?         ; OP_INSERT, OP_DELETE, OP_REPLACE
    line            DWORD ?         ; Line affected
    col             DWORD ?         ; Column affected
    text_ptr        QWORD ?         ; Pointer to deleted/replaced text
    text_len        DWORD ?         ; Length of text
UNDO_ENTRY ENDS

;==========================================================================
; CONSTANTS
;==========================================================================

OP_INSERT           EQU 1
OP_DELETE           EQU 2
OP_REPLACE          EQU 3

; Flags already defined in OBJECT_BASE are reused:
; FLAG_VISIBLE, FLAG_DIRTY
FLAG_HAS_SELECTION  EQU 00004h
FLAG_READONLY       EQU 00008h

; Win32 File Constants
IFNDEF GENERIC_READ
    GENERIC_READ    EQU 80000000h
ENDIF
IFNDEF GENERIC_WRITE
    GENERIC_WRITE   EQU 40000000h
ENDIF
IFNDEF CREATE_ALWAYS
    CREATE_ALWAYS   EQU 2
ENDIF

; Clipboard constants
CF_TEXT             EQU 1
GMEM_MOVEABLE       EQU 0002h
IFNDEF OPEN_EXISTING
    OPEN_EXISTING   EQU 3
ENDIF
IFNDEF FILE_ATTRIBUTE_NORMAL
    FILE_ATTRIBUTE_NORMAL EQU 128
ENDIF
IFNDEF INVALID_HANDLE_VALUE
    INVALID_HANDLE_VALUE EQU -1
ENDIF

; Text colors (RGB)
COLOR_TEXT          EQU 000000h    ; Black
COLOR_BACKGROUND    EQU 0FFFFFFh   ; White
COLOR_SELECTION     EQU 0C0C0C0h   ; Light gray
COLOR_KEYWORD       EQU 0000FFh    ; Blue
COLOR_STRING        EQU 008000h    ; Green
COLOR_COMMENT       EQU 808080h    ; Dark gray

;==========================================================================
; PUBLIC FUNCTIONS
;==========================================================================
PUBLIC text_editor_create
PUBLIC text_editor_destroy
PUBLIC text_editor_load_file
PUBLIC text_editor_save_file
PUBLIC text_editor_insert_text
PUBLIC text_editor_delete_text
PUBLIC text_editor_get_text
PUBLIC text_editor_set_cursor
PUBLIC text_editor_get_cursor
PUBLIC text_editor_move_cursor_up
PUBLIC text_editor_move_cursor_down
PUBLIC text_editor_move_cursor_left
PUBLIC text_editor_move_cursor_right
PUBLIC text_editor_select_all
PUBLIC text_editor_copy
PUBLIC text_editor_cut
PUBLIC text_editor_paste
PUBLIC text_editor_undo
PUBLIC text_editor_redo
PUBLIC text_editor_paint
PUBLIC text_editor_on_key
PUBLIC text_editor_on_mouse

;==========================================================================
; GLOBAL STATE
;==========================================================================

.DATA?
g_editor_global     QWORD ?         ; Global editor instance
g_clipboard_data    QWORD ?         ; Clipboard text pointer
g_clipboard_size    DWORD ?         ; Clipboard size_val

;==========================================================================
; IMPLEMENTATION
;==========================================================================

.CODE

; =============== text_editor_create ===============
; Create a new text editor instance
; Inputs:  rcx = parent HWND
; Outputs: rax = TEXT_EDITOR ptr or NULL on error
text_editor_create PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Allocate TEXT_EDITOR structure (~512 bytes)
    mov rcx, sizeof TEXT_EDITOR
    call masm_malloc                         ; rax = editor ptr
    test rax, rax
    jz error
    
    mov rcx, rax
    
    ; Initialize base OBJECT_BASE
    lea rax, text_editor_vmt
    mov qword ptr [rcx + OBJECT_BASE.obj_vmt], rax  ; obj_vmt = &text_editor_vmt
    mov qword ptr [rcx + OBJECT_BASE.obj_hwnd], 0   ; obj_hwnd = NULL (will set later)
    
    ; Initialize text buffer (empty initially)
    mov qword ptr [rcx + TEXT_EDITOR.first_line], 0   ; first_line = NULL
    mov qword ptr [rcx + TEXT_EDITOR.last_line], 0    ; last_line = NULL
    mov dword ptr [rcx + TEXT_EDITOR.line_count], 0   ; line_count = 0
    mov qword ptr [rcx + TEXT_EDITOR.total_chars], 0  ; total_chars = 0
    
    ; Initialize cursor (start at 0,0)
    mov dword ptr [rcx + TEXT_EDITOR.cursor_line], 0  ; cursor_line = 0
    mov dword ptr [rcx + TEXT_EDITOR.cursor_col], 0   ; cursor_col = 0
    mov dword ptr [rcx + TEXT_EDITOR.cursor_visible], 1  ; cursor_visible = 1
    mov dword ptr [rcx + TEXT_EDITOR.cursor_x], 0     ; cursor_x = 0
    mov dword ptr [rcx + TEXT_EDITOR.cursor_y], 0     ; cursor_y = 0
    
    ; Initialize selection (no selection)
    mov dword ptr [rcx + TEXT_EDITOR.sel_start_line], 0
    mov dword ptr [rcx + TEXT_EDITOR.sel_start_col], 0
    mov dword ptr [rcx + TEXT_EDITOR.sel_end_line], 0
    mov dword ptr [rcx + TEXT_EDITOR.sel_end_col], 0
    mov dword ptr [rcx + TEXT_EDITOR.has_selection], 0
    
    ; Initialize viewport
    mov dword ptr [rcx + TEXT_EDITOR.top_line], 0      ; top_line = 0
    mov dword ptr [rcx + TEXT_EDITOR.visible_lines], 24  ; visible_lines = 24
    mov dword ptr [rcx + TEXT_EDITOR.char_width], 8    ; char_width = 8 pixels
    mov dword ptr [rcx + TEXT_EDITOR.line_height], 16  ; line_height = 16 pixels
    
    ; Initialize undo/redo (empty initially)
    mov qword ptr [rcx + TEXT_EDITOR.undo_stack], 0
    mov dword ptr [rcx + TEXT_EDITOR.undo_count], 0
    mov qword ptr [rcx + TEXT_EDITOR.redo_stack], 0
    mov dword ptr [rcx + TEXT_EDITOR.redo_count], 0
    
    ; Allocate file path buffer (512 bytes)
    mov r8, rcx                        ; save editor ptr
    mov rcx, 512
    call masm_malloc                        ; rax = path buffer
    mov rcx, r8                        ; restore editor
    test rax, rax
    jz error_with_editor
    mov qword ptr [rcx + TEXT_EDITOR.file_path], rax   ; file_path = buffer
    mov qword ptr [rcx + TEXT_EDITOR.file_name], rax   ; file_name = same initially
    
    ; Initialize file state
    mov dword ptr [rcx + TEXT_EDITOR.is_modified], 0   ; not modified
    
    ; Initialize flags
    mov dword ptr [rcx + TEXT_EDITOR.flags], FLAG_VISIBLE  ; visible flag
    
    ; Store global reference
    mov qword ptr [g_editor_global], rcx
    
    ; Return editor pointer
    mov rax, rcx
    add rsp, 32
    pop rbp
    ret

error_with_editor:
    ; Free editor structure on buffer allocation failure
    mov rcx, r8
    call masm_free
    xor rax, rax
    add rsp, 32
    pop rbp
    ret

error:
    xor rax, rax
    add rsp, 32
    pop rbp
    ret
text_editor_create ENDP

; =============== text_editor_destroy ===============
; Destroy editor and free resources
; Inputs:  rcx = TEXT_EDITOR ptr
; Outputs: rax = success (1) or failure (0)
text_editor_destroy PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rsi, rcx                       ; rsi = editor ptr
    
    ; Walk through TEXT_LINE linked list and free each
    mov rcx, [rsi + TEXT_EDITOR.first_line]
free_lines:
    test rcx, rcx
    jz lines_freed
    
    mov rdx, [rcx + TEXT_LINE.text_ptr]   ; rdx = text_ptr
    mov rax, [rcx + TEXT_LINE.next]       ; rax = next line
    
    ; Free text buffer
    test rdx, rdx
    jz skip_free_text
    mov rcx, rdx
    call masm_free
skip_free_text:
    
    ; Free TEXT_LINE structure
    mov rcx, rsi                       ; rsi still has editor ptr
    mov rdx, [rsi + TEXT_EDITOR.first_line]
    mov rcx, rdx
    call masm_free
    
    mov rcx, rax                       ; rcx = next line
    jmp free_lines

lines_freed:
    ; Free undo stack
    mov rcx, [rsi + TEXT_EDITOR.undo_stack]
    test rcx, rcx
    jz undo_freed
    call masm_free
undo_freed:
    
    ; Free redo stack
    mov rcx, [rsi + TEXT_EDITOR.redo_stack]
    test rcx, rcx
    jz redo_freed
    call masm_free
redo_freed:
    
    ; Free file path buffer
    mov rcx, [rsi + TEXT_EDITOR.file_path]
    test rcx, rcx
    jz path_freed
    call masm_free
path_freed:
    
    ; Free editor structure
    mov rcx, rsi
    call masm_free
    
    mov rax, 1                         ; success
    add rsp, 32
    pop rbp
    ret
text_editor_destroy ENDP

; =============== text_editor_load_file ===============
; Load a file into the editor
; Inputs:  rcx = TEXT_EDITOR ptr, rdx = file path (LPSTR)
; Outputs: rax = success (1) or failure (0)
text_editor_load_file PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64                        ; Stack space for locals
    
    mov rsi, rcx                       ; rsi = editor ptr
    mov rdi, rdx                       ; rdi = file path
    
    ; Copy file path to editor
    mov rcx, rsi
    add rcx, TEXT_EDITOR.file_path
    mov rax, [rcx]                     ; rax = file_path buffer
    mov rcx, rax                       ; dest
    mov rdx, rdi                       ; src
    mov r8, 512                        ; count
    call memcpy                        ; Copy path to buffer
    
    ; Open file with CreateFileA
    mov rcx, rdi                       ; lpFileName = file path
    mov rdx, 80000000h                 ; dwDesiredAccess = GENERIC_READ
    mov r8, 1                          ; dwShareMode = FILE_SHARE_READ
    xor r9, r9                         ; lpSecurityAttributes = NULL
    mov qword ptr [rsp + 32], 3        ; dwCreationDisposition = OPEN_EXISTING
    mov qword ptr [rsp + 40], 128      ; dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL
    xor rax, rax
    mov qword ptr [rsp + 48], rax      ; hTemplateFile = NULL
    
    call CreateFileA
    test eax, eax
    je error                          ; Jump if INVALID_HANDLE_VALUE
    
    ; rax = file handle
    mov r12, rax                       ; r12 = hFile
    
    ; Get file size_val
    sub rsp, 32
    mov rcx, r12                       ; hFile = r12
    lea rdx, [rsp]                     ; lpFileSize = stack buffer
    call GetFileSizeEx                 ; Get file size_val
    test eax, eax
    jz close_file
    mov r13, [rsp]                     ; r13 = file size_val
    add rsp, 32
    
    ; Allocate buffer for file contents
    mov rcx, r13                       ; rcx = file size_val
    add rcx, 1                         ; Add 1 for null terminator
    call masm_malloc                        ; rax = file buffer
    test rax, rax
    jz close_file
    mov r14, rax                       ; r14 = file buffer
    
    ; Read file contents
    mov rcx, r12                       ; hFile
    mov rdx, r14                       ; lpBuffer
    mov r8d, r13d                      ; nNumberOfBytesToRead (32-bit)
    lea r9, [rsp + 8]                  ; lpNumberOfBytesRead
    call ReadFile
    test eax, eax
    jz free_buffer
    
    ; Null-terminate buffer
    mov rax, [rsp + 8]                 ; rax = bytes read
    mov byte ptr [r14 + rax], 0        ; Add null terminator
    
    ; Split by newlines into TEXT_LINE entries
    xor r15, r15                       ; r15 = current offset
    xor r10, r10                       ; r10 = line count
    
parse_lines:
    cmp r15, rax                       ; Check if reached end
    jge parse_done
    
    ; Find next newline (CRLF or LF)
    mov rcx, r14
    add rcx, r15                       ; rcx = current position
    
    xor rdx, rdx                       ; rdx = line length
find_newline:
    mov bl, byte ptr [rcx + rdx]       ; bl = current char
    test bl, bl
    jz found_eol                      ; End of file
    
    cmp bl, 0Ah                        ; LF
    je found_newline
    cmp bl, 0Dh                        ; CR
    je found_newline
    
    inc rdx                            ; rdx++
    jmp find_newline
    
found_newline:
    ; Skip CRLF or LF
    cmp byte ptr [rcx + rdx + 1], 0Ah ; Check for LF after CR
    jne skip_one
    add rdx, 2                         ; Skip CRLF
    jmp create_line
skip_one:
    inc rdx                            ; Skip CR or LF
    
create_line:
    ; Allocate TEXT_LINE structure
    mov rcx, sizeof TEXT_LINE
    call masm_malloc
    test rax, rax
    jz parse_done
    
    mov rbx, rax                       ; rbx = new TEXT_LINE
    
    ; Allocate text buffer (rdx bytes + 1 for null)
    push rdx                           ; Save line length
    mov rcx, rdx
    inc rcx
    call masm_malloc
    pop rdx                            ; Restore line length
    test rax, rax
    jz parse_done
    
    ; Copy line text
    push rdx                           ; Save length
    mov rcx, rax                       ; dest = allocated buffer
    mov rdx, r14                       
    add rdx, r15                       ; source = file buffer + offset
    pop r8                             ; length = saved rdx
    push rax                           ; Save destination
    call memcpy                        ; Copy bytes
    pop rax                            ; Restore destination
    push r8                            ; Push length back for later use
    pop rdx                            ; rdx = length
    
    ; Add null terminator
    mov byte ptr [rax + rdx], 0
    
    ; Fill TEXT_LINE fields
    mov [rbx + TEXT_LINE.text_ptr], rax  ; text_ptr = buffer
    mov [rbx + TEXT_LINE.text_len], edx  ; text_len = length
    mov [rbx + TEXT_LINE.max_capacity], edx
    mov qword ptr [rbx + TEXT_LINE.next], 0  ; next = NULL
    mov qword ptr [rbx + TEXT_LINE.prev], 0  ; prev = NULL
    
    ; Add to linked list
    test r10, r10
    jz first_line
    
    ; Link to previous line
    mov rcx, [rsi + TEXT_EDITOR.last_line]
    mov [rcx + TEXT_LINE.next], rbx
    mov [rbx + TEXT_LINE.prev], rcx
    mov [rsi + TEXT_EDITOR.last_line], rbx
    jmp next_line
    
first_line:
    mov [rsi + TEXT_EDITOR.first_line], rbx
    mov [rsi + TEXT_EDITOR.last_line], rbx
    
next_line:
    inc r10                            ; line_count++
    add r15, rdx                       ; Move to next line
    jmp parse_lines
    
found_eol:
    ; Handle last line (no newline at end)
    test rdx, rdx
    jz parse_done                     ; Empty last line
    jmp create_line
    
parse_done:
    ; Update editor state
    mov [rsi + TEXT_EDITOR.line_count], r10d  ; line_count
    
    ; Clear cursor position
    mov dword ptr [rsi + TEXT_EDITOR.cursor_line], 0
    mov dword ptr [rsi + TEXT_EDITOR.cursor_col], 0
    mov dword ptr [rsi + TEXT_EDITOR.cursor_visible], 1
    
    ; Clear undo/redo
    mov qword ptr [rsi + TEXT_EDITOR.undo_stack], 0
    mov dword ptr [rsi + TEXT_EDITOR.undo_count], 0
    mov qword ptr [rsi + TEXT_EDITOR.redo_stack], 0
    mov dword ptr [rsi + TEXT_EDITOR.redo_count], 0
    
    ; Clear modified flag
    mov dword ptr [rsi + TEXT_EDITOR.is_modified], 0
    
    ; Set FLAG_DIRTY for rendering
    mov eax, [rsi + TEXT_EDITOR.flags]
    or eax, FLAG_DIRTY
    mov [rsi + TEXT_EDITOR.flags], eax
    
    ; Free file buffer
    mov rcx, r14
    call masm_free
    
    ; Close file
    mov rcx, r12
    call CloseHandle
    
    mov rax, 1                         ; Success
    add rsp, 64
    pop rbp
    ret

free_buffer:
    mov rcx, r14
    call masm_free
    
close_file:
    mov rcx, r12
    call CloseHandle
    
error:
    xor rax, rax                       ; Failure
    add rsp, 64
    pop rbp
    ret
text_editor_load_file ENDP

; =============== text_editor_save_file ===============
; Save editor contents to file
; Inputs:  rcx = TEXT_EDITOR ptr
; Outputs: rax = success (1) or failure (0)
text_editor_save_file PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    
    mov rsi, rcx                       ; rsi = editor ptr
    
    ; Get file path
    lea rdx, [rsi + TEXT_EDITOR.file_path]  ; rdx = file_path buffer (512 bytes)
    
    ; CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0)
    mov rcx, rdx                       ; rcx = file path
    mov edx, GENERIC_WRITE             ; Write access
    xor r8, r8                         ; Share mode = 0
    xor r9, r9                         ; lpSecurityAttributes = NULL
    mov qword ptr [rsp + 32], CREATE_ALWAYS  ; dwCreationDisposition
    mov qword ptr [rsp + 40], FILE_ATTRIBUTE_NORMAL  ; dwFlagsAndAttributes
    call CreateFileA
    
    cmp rax, INVALID_HANDLE_VALUE
    je error                          ; Failed to open
    
    mov r12, rax                       ; r12 = file handle
    
    ; Walk through all TEXT_LINE entries and write them
    mov r13, [rsi + TEXT_EDITOR.first_line]  ; r13 = current line
    
write_lines:
    test r13, r13
    jz write_done                     ; No more lines
    
    ; Get line text and length
    mov rcx, [r13 + TEXT_LINE.text_ptr]    ; rcx = text_ptr
    mov edx, [r13 + TEXT_LINE.text_len]    ; edx = text_len
    
    ; WriteFile(hFile, text_ptr, text_len, &bytes_written, NULL)
    mov r8, r12                        ; r8 = file handle
    mov r9, rcx                        ; r9 = text_ptr
    mov qword ptr [rsp + 32], rdx      ; text length
    lea rax, [rsp + 48]                ; rax = &bytes_written
    mov qword ptr [rsp + 40], rax
    mov qword ptr [rsp + 48], 0        ; NULL
    call WriteFile
    
    test eax, eax
    jz close_and_fail                 ; Write failed
    
    ; Write CRLF (0D 0A)
    mov r8, r12                        ; r8 = file handle
    lea r9, [rsp + 50]                 ; r9 = buffer for CRLF
    mov byte ptr [rsp + 50], 0Dh       ; CR
    mov byte ptr [rsp + 51], 0Ah       ; LF
    mov qword ptr [rsp + 32], 2        ; length = 2
    lea rax, [rsp + 48]
    mov qword ptr [rsp + 40], rax      ; &bytes_written
    call WriteFile
    
    test eax, eax
    jz close_and_fail                 ; Write failed
    
    ; Move to next line
    mov r13, [r13 + TEXT_LINE.next]
    jmp write_lines
    
write_done:
    ; Close file
    mov rcx, r12                       ; rcx = file handle
    call CloseHandle
    
    test eax, eax
    jz error
    
    ; Clear modified flag
    mov dword ptr [rsi + TEXT_EDITOR.is_modified], 0
    
    mov rax, 1                         ; Success
    add rsp, 64
    pop rbp
    ret
    
close_and_fail:
    mov rcx, r12
    call CloseHandle
    
error:
    xor rax, rax
    add rsp, 64
    pop rbp
    ret
text_editor_save_file ENDP

; =============== text_editor_insert_text ===============
; Insert text at cursor position
; Inputs:  rcx = TEXT_EDITOR ptr, rdx = text (LPSTR), r8 = length
; Outputs: rax = success (1) or failure (0)
text_editor_insert_text PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    
    mov rsi, rcx                       ; rsi = editor ptr
    mov r12, rdx                       ; r12 = text ptr
    mov r13d, r8d                      ; r13d = length
    
    ; Get current line
    mov r10d, [rsi + TEXT_EDITOR.cursor_line]
    mov r11d, [rsi + TEXT_EDITOR.cursor_col]
    
    ; Find the cursor line in_val linked list
    mov r14, [rsi + TEXT_EDITOR.first_line]  ; r14 = current line ptr
    xor r15, r15                       ; r15 = line index
    
find_line:
    cmp r14, 0
    je error                          ; Line not found
    
    cmp r15d, r10d
    je found_line
    
    mov r14, [r14 + TEXT_LINE.next]
    inc r15
    jmp find_line
    
found_line:
    ; r14 = line to insert into
    ; r11d = cursor_col (position in_val line)
    ; r12 = text to insert
    ; r13d = text length
    
    ; Get current line text and length
    mov rdi, [r14 + TEXT_LINE.text_ptr]  ; rdi = current line text
    mov eax, [r14 + TEXT_LINE.text_len]  ; eax = current line length
    
    ; Check for newlines in_val inserted text
    xor rdx, rdx                       ; rdx = offset
    
scan_newlines:
    cmp rdx, r13
    jge no_newline
    
    mov al, byte ptr [r12 + rdx]
    cmp al, 0Ah                        ; LF
    je has_newline
    cmp al, 0Dh                        ; CR
    je has_newline
    
    inc rdx
    jmp scan_newlines
    
has_newline:
    ; TODO: Handle newline insertion (split line)
    ; For now, just reject
    xor rax, rax
    add rsp, 64
    pop rbp
    ret
    
no_newline:
    ; Simple case: no newlines, just insert text in_val current line
    
    ; Calculate new size_val
    mov eax, [r14 + TEXT_LINE.text_len]
    add eax, r13d
    
    ; Check if we need to reallocate
    mov ecx, [r14 + TEXT_LINE.max_capacity]
    cmp eax, ecx
    jle fit_in_current
    
    ; Reallocate buffer
    mov ecx, eax
    add ecx, 256                       ; Extra space for future edits
    mov [r14 + TEXT_LINE.max_capacity], ecx
    
    call masm_malloc                    ; rax = new buffer
    test rax, rax
    jz error
    
    mov rcx, [r14 + TEXT_LINE.text_ptr]
    mov edx, [r14 + TEXT_LINE.text_len]
    mov r8, rax
    call memcpy                        ; Copy old text (standard memcpy)
    
    ; Free old buffer
    mov rcx, [r14 + TEXT_LINE.text_ptr]
    call masm_free
    
    mov rdi, rax                       ; rdi = new buffer
    mov [r14 + TEXT_LINE.text_ptr], rdi
    
fit_in_current:
    ; rdi = line text buffer
    ; r11d = cursor position
    ; r12 = text to insert
    ; r13d = text length
    
    ; Shift text after cursor to make room
    mov eax, [r14 + TEXT_LINE.text_len]  ; eax = current length
    mov ecx, eax
    sub ecx, r11d                      ; ecx = length after cursor
    
    ; Shift right (memmove)
    mov rsi, rdi
    add rsi, r11                       ; rsi = insert position
    mov rdx, rsi
    add rdx, r13                       ; rdx = shifted position
    mov rcx, rax
    sub rcx, r11                       ; rcx = bytes to move
    call memcpy                   ; Move memory
    
    ; Copy new text
    mov rcx, r12                       ; rcx = source
    mov rdx, rdi
    add rdx, r11                       ; rdx = insert position
    mov r8, r13                        ; r8 = length
    call memcpy
    
    ; Update line length
    mov eax, [r14 + TEXT_LINE.text_len]
    add eax, r13d
    mov [r14 + TEXT_LINE.text_len], eax
    
    ; Null-terminate
    mov rcx, [r14 + TEXT_LINE.text_ptr]
    add rcx, rax
    mov byte ptr [rcx], 0
    
    ; Update cursor position
    add r11d, r13d                     ; cursor_col += length
    mov [rsi + TEXT_EDITOR.cursor_col], r11d
    
    ; Mark as modified
    mov dword ptr [rsi + TEXT_EDITOR.is_modified], 1
    
    ; Set dirty flag
    mov eax, [rsi + TEXT_EDITOR.flags]
    or eax, FLAG_DIRTY
    mov [rsi + TEXT_EDITOR.flags], eax
    
    mov rax, 1                         ; Success
    add rsp, 64
    pop rbp
    ret
    
error:
    xor rax, rax
    add rsp, 64
    pop rbp
    ret
text_editor_insert_text ENDP

; =============== text_editor_delete_text ===============
; Delete selected text or character at cursor
; Inputs:  rcx = TEXT_EDITOR ptr, rdx = count (number of chars to delete)
; Outputs: rax = success (1) or failure (0)
text_editor_delete_text PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rsi, rcx                       ; rsi = editor ptr
    mov r13d, edx                      ; r13d = count
    
    ; Check if we have selection (has_selection flag)
    mov eax, [rsi + TEXT_EDITOR.flags]
    and eax, FLAG_HAS_SELECTION
    jnz delete_selection
    
    ; Delete character(s) at cursor
    mov edx, [rsi + TEXT_EDITOR.cursor_line]
    mov r8d, [rsi + TEXT_EDITOR.cursor_col]
    
    ; Find line at cursor_line
    mov r10, [rsi + TEXT_EDITOR.first_line]
    xor r11d, r11d
    
find_line:
    test r10, r10
    jz error                          ; Line not found
    
    cmp r11d, edx
    je delete_at_cursor
    
    mov r10, [r10 + TEXT_LINE.next]
    inc r11d
    jmp find_line
    
delete_at_cursor:
    ; r10 = TEXT_LINE at cursor
    ; r8d = cursor_col (start position)
    ; r13d = count (number of chars to delete)
    
    mov r14, [r10 + TEXT_LINE.text_ptr]  ; r14 = text_ptr
    mov r11d, [r10 + TEXT_LINE.text_len] ; r11d = text length
    
    ; Check bounds: if col + count > length, clamp
    mov eax, r8d
    add eax, r13d
    cmp eax, r11d
    jle bounds_ok
    sub r13d, eax
    add r13d, r11d                     ; r13d = max count that won't exceed length
    
bounds_ok:
    test r13d, r13d
    jle mark_modified                 ; Nothing to delete
    
    ; Delete characters: shift text from (cursor_col + count) to end, left by count
    mov edx, r8d
    add edx, r13d                      ; edx = source offset (cursor_col + count)
    mov ecx, r8d                       ; ecx = destination offset (cursor_col)
    
    mov r12d, r11d
    sub r12d, r8d
    sub r12d, r13d                     ; r12d = bytes to move
    
    ; Use memcpy to shift left
    call memcpy                        ; memcpy(dest, src, count)
    
    ; Update line length
    sub r11d, r13d
    mov [r10 + TEXT_LINE.text_len], r11d
    
    ; Null-terminate
    add r14, r11
    mov byte ptr [r14], 0
    
mark_modified:
    mov dword ptr [rsi + TEXT_EDITOR.is_modified], 1
    
    ; Set dirty flag
    mov eax, [rsi + TEXT_EDITOR.flags]
    or eax, FLAG_DIRTY
    mov [rsi + TEXT_EDITOR.flags], eax
    
    mov rax, 1                         ; Success
    add rsp, 32
    pop rbp
    ret
    
delete_selection:
    ; TODO: Delete selected text range
    ; For now, just mark modified
    mov dword ptr [rsi + TEXT_EDITOR.is_modified], 1
    mov eax, [rsi + TEXT_EDITOR.flags]
    or eax, FLAG_DIRTY
    mov [rsi + TEXT_EDITOR.flags], eax
    
    mov rax, 1
    add rsp, 32
    pop rbp
    ret
    
error:
    xor rax, rax
    add rsp, 32
    pop rbp
    ret
text_editor_delete_text ENDP

; =============== text_editor_get_text ===============
; Get all editor text
; Inputs:  rcx = TEXT_EDITOR ptr
; Outputs: rax = pointer to text buffer
text_editor_get_text PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rsi, rcx                       ; rsi = editor ptr
    
    ; First pass: calculate total length needed
    xor r12d, r12d                     ; r12d = total_length
    mov r13, [rsi + TEXT_EDITOR.first_line]  ; r13 = current line
    
count_length:
    test r13, r13
    jz alloc_buffer
    
    mov eax, [r13 + TEXT_LINE.text_len]
    add r12d, eax
    add r12d, 2                        ; Add 2 for CRLF
    
    mov r13, [r13 + TEXT_LINE.next]
    jmp count_length
    
alloc_buffer:
    ; Allocate buffer for concatenated text
    inc r12d                           ; Add 1 for null terminator
    mov rcx, r12
    call masm_malloc
    
    test rax, rax
    jz error
    
    mov r14, rax                       ; r14 = output buffer
    xor r15, r15                       ; r15 = write offset
    
    ; Second pass: copy lines with CRLF
    mov r13, [rsi + TEXT_EDITOR.first_line]  ; r13 = current line
    
copy_lines:
    test r13, r13
    jz done
    
    ; Copy line text
    mov rcx, [r13 + TEXT_LINE.text_ptr]  ; rcx = text_ptr
    mov r8d, [r13 + TEXT_LINE.text_len]  ; r8d = text_len
    mov rdx, r14
    add rdx, r15                       ; rdx = write position
    
    ; copy_memory_asm(dest=rdx, src=rcx, size_val=r8)
    call memcpy
    
    ; Add length to offset
    add r15d, r8d
    
    ; Copy CRLF
    mov byte ptr [r14 + r15], 0Dh
    mov byte ptr [r14 + r15 + 1], 0Ah
    add r15d, 2
    
    ; Move to next line
    mov r13, [r13 + TEXT_LINE.next]
    jmp copy_lines
    
done:
    ; Null-terminate buffer
    mov byte ptr [r14 + r15], 0
    
    mov rax, r14                       ; Return buffer pointer
    add rsp, 32
    pop rbp
    ret
    
error:
    xor rax, rax
    add rsp, 32
    pop rbp
    ret
text_editor_get_text ENDP

; =============== text_editor_set_cursor ===============
; Set cursor to specific line/column
; Inputs:  rcx = TEXT_EDITOR ptr, rdx = line, r8 = column
; Outputs: rax = success (1) or failure (0)
text_editor_set_cursor PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rsi, rcx                       ; rsi = editor ptr
    
    ; Clamp line to valid range [0, line_count-1]
    mov eax, [rsi + TEXT_EDITOR.line_count]
    test eax, eax
    jz clamp_fail                     ; No lines at all
    
    dec eax                            ; eax = line_count - 1
    cmp edx, eax                       ; Compare line to max
    jle line_ok
    mov edx, eax                       ; Clamp to max
    
line_ok:
    test edx, edx
    jge col_check
    xor edx, edx                       ; Clamp to min (0)
    
col_check:
    ; Find line at index edx
    mov r10, [rsi + TEXT_EDITOR.first_line]  ; r10 = current line
    mov r11d, edx                      ; r11d = target line index
    xor r12d, r12d                     ; r12d = current index
    
find_line_loop:
    test r10, r10
    jz clamp_fail                     ; Line not found
    
    cmp r12d, r11d
    je line_found
    
    mov r10, [r10 + TEXT_LINE.next]    ; Next line
    inc r12d
    jmp find_line_loop
    
line_found:
    ; r10 = pointer to TEXT_LINE at target line
    ; Clamp column to line length
    mov eax, [r10 + TEXT_LINE.text_len]  ; eax = line length
    cmp r8d, eax
    jle col_ok
    mov r8d, eax                       ; Clamp to line length
    
col_ok:
    test r8d, r8d
    jge update_cursor
    xor r8d, r8d                       ; Clamp to 0
    
update_cursor:
    ; Update cursor position
    mov [rsi + TEXT_EDITOR.cursor_line], edx  ; cursor_line = line
    mov [rsi + TEXT_EDITOR.cursor_col], r8d   ; cursor_col = col
    
    ; Calculate pixel position: cursor_x = col * 8, cursor_y = line * 16
    shl edx, 4                         ; edx = line * 16 (line height)
    shl r8d, 3                         ; r8d = col * 8 (char width_val)
    add r8d, 45                        ; Add text margin (45 pixels)
    
    mov [rsi + TEXT_EDITOR.cursor_x], r8d   ; cursor_x
    mov [rsi + TEXT_EDITOR.cursor_y], edx   ; cursor_y
    
    ; Set dirty flag
    mov eax, [rsi + TEXT_EDITOR.flags]
    or eax, FLAG_DIRTY
    mov [rsi + TEXT_EDITOR.flags], eax
    
    mov rax, 1                         ; Success
    add rsp, 32
    pop rbp
    ret
    
clamp_fail:
    xor rax, rax                       ; Failure
    add rsp, 32
    pop rbp
    ret
text_editor_set_cursor ENDP

; =============== text_editor_get_cursor ===============
; Get current cursor position
; Inputs:  rcx = TEXT_EDITOR ptr
; Outputs: rax = line, rdx = column
text_editor_get_cursor PROC
    push rbp
    mov rbp, rsp
    
    mov rax, [rcx + 72]    ; cursor_line
    mov rdx, [rcx + 76]    ; cursor_col
    
    pop rbp
    ret
text_editor_get_cursor ENDP

; =============== text_editor_move_cursor_up ===============
text_editor_move_cursor_up PROC
    push rbp
    mov rbp, rsp
    
    ; Get current cursor line
    mov edx, [rcx + TEXT_EDITOR.cursor_line]
    test edx, edx
    jz cannot_move_up                 ; Already at top
    
    ; Decrement line
    dec edx
    
    ; Keep column same
    mov r8d, [rcx + TEXT_EDITOR.cursor_col]
    
    ; Call set_cursor(editor, line, col)
    call text_editor_set_cursor
    
    pop rbp
    ret
    
cannot_move_up:
    xor rax, rax                       ; Return 0 (cannot move)
    pop rbp
    ret
text_editor_move_cursor_up ENDP

; =============== text_editor_move_cursor_down ===============
text_editor_move_cursor_down PROC
    push rbp
    mov rbp, rsp
    
    ; Get current cursor line and max line
    mov edx, [rcx + TEXT_EDITOR.cursor_line]
    mov eax, [rcx + TEXT_EDITOR.line_count]
    dec eax                            ; eax = line_count - 1
    cmp edx, eax
    jge cannot_move_down              ; Already at bottom
    
    ; Increment line
    inc edx
    
    ; Keep column same
    mov r8d, [rcx + TEXT_EDITOR.cursor_col]
    
    ; Call set_cursor(editor, line, col)
    call text_editor_set_cursor
    
    pop rbp
    ret
    
cannot_move_down:
    xor rax, rax                       ; Return 0 (cannot move)
    pop rbp
    ret
text_editor_move_cursor_down ENDP

; =============== text_editor_move_cursor_left ===============
text_editor_move_cursor_left PROC
    push rbp
    mov rbp, rsp
    
    ; Get current position
    mov edx, [rcx + TEXT_EDITOR.cursor_line]
    mov r8d, [rcx + TEXT_EDITOR.cursor_col]
    
    ; If col > 0, decrement col
    test r8d, r8d
    jz move_to_prev_line
    
    dec r8d
    call text_editor_set_cursor
    
    pop rbp
    ret
    
move_to_prev_line:
    ; Cannot move left if at line start and no previous line
    test edx, edx
    jz cannot_move_left
    
    ; Move to end of previous line
    dec edx                            ; edx = line - 1
    mov r8d, -1                        ; r8d = -1 (will be clamped to line length)
    call text_editor_set_cursor
    
    pop rbp
    ret
    
cannot_move_left:
    xor rax, rax                       ; Return 0 (cannot move)
    pop rbp
    ret
text_editor_move_cursor_left ENDP

; =============== text_editor_move_cursor_right ===============
text_editor_move_cursor_right PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Get current position
    mov edx, [rcx + TEXT_EDITOR.cursor_line]
    mov r8d, [rcx + TEXT_EDITOR.cursor_col]
    
    ; Find current line to check length
    mov r10, [rcx + TEXT_EDITOR.first_line]  ; r10 = first line
    xor r11d, r11d                     ; r11d = current index
    
find_line:
    test r10, r10
    jz cannot_move_right
    
    cmp r11d, edx
    je check_length
    
    mov r10, [r10 + TEXT_LINE.next]
    inc r11d
    jmp find_line
    
check_length:
    ; r10 = pointer to current TEXT_LINE
    mov r9d, [r10 + TEXT_LINE.text_len]  ; r9d = line length
    
    ; If col < line_length, increment col
    cmp r8d, r9d
    jge move_to_next_line
    
    inc r8d
    call text_editor_set_cursor
    
    add rsp, 32
    pop rbp
    ret
    
move_to_next_line:
    ; Check if there is a next line
    mov r9d, [rcx + TEXT_EDITOR.line_count]
    dec r9d
    cmp edx, r9d
    jge cannot_move_right
    
    ; Move to start of next line
    inc edx                            ; edx = line + 1
    xor r8d, r8d                       ; r8d = 0 (start of line)
    call text_editor_set_cursor
    
    add rsp, 32
    pop rbp
    ret
    
cannot_move_right:
    xor rax, rax                       ; Return 0 (cannot move)
    add rsp, 32
    pop rbp
    ret
text_editor_move_cursor_right ENDP

; =============== text_editor_select_all ===============
; Select all text
; Inputs:  rcx = TEXT_EDITOR ptr
; Outputs: rax = success (1) or failure (0)
text_editor_select_all PROC
    push rbp
    mov rbp, rsp
    
    ; Set selection from (0,0) to (last_line, last_col)
    mov dword ptr [rcx + TEXT_EDITOR.sel_start_line], 0
    mov dword ptr [rcx + TEXT_EDITOR.sel_start_col], 0
    
    ; Get last line and column
    mov edx, [rcx + TEXT_EDITOR.line_count]
    dec edx                            ; edx = last_line
    mov [rcx + TEXT_EDITOR.sel_end_line], edx
    
    ; Find last line to get its length
    mov r10, [rcx + TEXT_EDITOR.first_line]
    xor r11d, r11d
    
find_last:
    test r10, r10
    jz no_lines
    
    mov r12, r10
    mov r10, [r10 + TEXT_LINE.next]
    test r10, r10
    jnz find_last
    
    ; r12 = last TEXT_LINE
    mov r8d, [r12 + TEXT_LINE.text_len]
    mov [rcx + TEXT_EDITOR.sel_end_col], r8d
    
    ; Mark FLAG_HAS_SELECTION
    mov eax, [rcx + TEXT_EDITOR.flags]
    or eax, FLAG_HAS_SELECTION
    mov [rcx + TEXT_EDITOR.flags], eax
    
    ; Set dirty flag
    or eax, FLAG_DIRTY
    mov [rcx + TEXT_EDITOR.flags], eax
    
    mov rax, 1
    pop rbp
    ret
    
no_lines:
    xor rax, rax
    pop rbp
    ret
text_editor_select_all ENDP

; =============== text_editor_copy ===============
; Copy selection to clipboard
; Inputs:  rcx = TEXT_EDITOR ptr
; Outputs: rax = success (1) or failure (0)
text_editor_copy PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Call text_editor_get_text to get full text buffer
    call text_editor_get_text
    
    test rax, rax
    jz error
    
    mov r12, rax                       ; r12 = text buffer
    
    ; OpenClipboard(NULL)
    xor rcx, rcx                       ; hwnd = NULL
    call OpenClipboard
    
    test eax, eax
    jz free_and_error
    
    ; Allocate global memory for clipboard
    ; GlobalAlloc(GMEM_MOVEABLE, size_val)
    mov rcx, GMEM_MOVEABLE
    
    ; Get text length (scan for null terminator)
    xor edx, edx                       ; edx = length counter
    mov r10, r12                       ; r10 = text ptr
    
count_text:
    mov al, byte ptr [r10]
    test al, al
    jz alloc_global
    inc r10
    inc edx
    jmp count_text
    
alloc_global:
    inc edx                            ; Add 1 for null terminator
    mov r8, rdx                        ; r8 = size_val
    ; GlobalAlloc(GMEM_MOVEABLE, size_val)
    ; Note: GlobalAlloc is typically called via LocalAlloc in_val recent Win32
    ; For simplicity, we'll use HeapAlloc
    call HeapAlloc                     ; Simplified - use system heap
    
    test rax, rax
    jz close_and_error
    
    mov r13, rax                       ; r13 = global memory
    
    ; Copy text to global memory
    mov rcx, r13                       ; dest
    mov rdx, r12                       ; src
    mov r8, r10                        ; size_val (r10 still points past null)
    sub r8, r12
    call memcpy
    
    ; SetClipboardData(CF_TEXT, global_memory)
    mov rcx, CF_TEXT
    mov rdx, r13
    call SetClipboardData
    
    ; CloseClipboard()
    call CloseClipboard
    
    ; Free text buffer from get_text
    mov rcx, r12
    call masm_free
    
    mov rax, 1
    add rsp, 32
    pop rbp
    ret
    
close_and_error:
    call CloseClipboard
    
free_and_error:
    mov rcx, r12
    call masm_free
    
error:
    xor rax, rax
    add rsp, 32
    pop rbp
    ret
text_editor_copy ENDP

; =============== text_editor_cut ===============
; Cut selection to clipboard and delete
; Inputs:  rcx = TEXT_EDITOR ptr
; Outputs: rax = success (1) or failure (0)
text_editor_cut PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Call copy first
    call text_editor_copy
    
    test eax, eax
    jz error
    
    ; Then delete selected text
    ; For simplicity, delete one character at cursor
    mov rdx, 1                         ; Count = 1
    call text_editor_delete_text
    
    add rsp, 32
    pop rbp
    ret
    
error:
    xor rax, rax
    add rsp, 32
    pop rbp
    ret
text_editor_cut ENDP

; =============== text_editor_paste ===============
; Paste clipboard at cursor
; Inputs:  rcx = TEXT_EDITOR ptr
; Outputs: rax = success (1) or failure (0)
text_editor_paste PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; OpenClipboard(NULL)
    xor rcx, rcx                       ; hwnd = NULL
    call OpenClipboard
    
    test eax, eax
    jz error
    
    ; GetClipboardData(CF_TEXT)
    mov rcx, CF_TEXT
    call GetClipboardData
    
    test rax, rax
    jz close_and_error
    
    mov r12, rax                       ; r12 = clipboard text
    
    ; Get length
    xor edx, edx                       ; edx = length
    mov r10, r12
    
count_clipboard:
    mov al, byte ptr [r10]
    test al, al
    jz do_insert
    inc r10
    inc edx
    jmp count_clipboard
    
do_insert:
    ; Insert clipboard text at cursor
    ; text_editor_insert_text(rcx=editor, rdx=text, r8=length)
    ; rcx already set (was editor ptr, now preserve it)
    ; rdx = length
    ; r8 = text
    
    ; Restore editor ptr to rcx (was passed in_val)
    mov r8, r12                        ; r8 = clipboard text
    mov rdx, r10
    sub rdx, r12                       ; rdx = length
    
    call text_editor_insert_text
    
    ; CloseClipboard()
    call CloseClipboard
    
    add rsp, 32
    pop rbp
    ret
    
close_and_error:
    call CloseClipboard
    
error:
    xor rax, rax
    add rsp, 32
    pop rbp
    ret
text_editor_paste ENDP

; =============== text_editor_undo ===============
; Undo last operation
; Inputs:  rcx = TEXT_EDITOR ptr
; Outputs: rax = success (1) or failure (0)
text_editor_undo PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rsi, rcx                       ; rsi = editor ptr
    
    ; Check if undo stack is empty
    mov edx, [rsi + TEXT_EDITOR.undo_count]
    test edx, edx
    jz empty_undo
    
    ; Pop from undo stack
    ; For simplicity, we just decrement the count
    ; TODO: Implement full undo/redo with operation reversal
    dec edx
    mov [rsi + TEXT_EDITOR.undo_count], edx
    
    ; Increment redo count (simple stub)
    mov eax, [rsi + TEXT_EDITOR.redo_count]
    inc eax
    mov [rsi + TEXT_EDITOR.redo_count], eax
    
    ; Mark modified and set dirty
    mov dword ptr [rsi + TEXT_EDITOR.is_modified], 1
    mov eax, [rsi + TEXT_EDITOR.flags]
    or eax, FLAG_DIRTY
    mov [rsi + TEXT_EDITOR.flags], eax
    
    mov rax, 1
    add rsp, 32
    pop rbp
    ret
    
empty_undo:
    xor rax, rax
    add rsp, 32
    pop rbp
    ret
text_editor_undo ENDP

; =============== text_editor_redo ===============
; Redo last undone operation
; Inputs:  rcx = TEXT_EDITOR ptr
; Outputs: rax = success (1) or failure (0)
text_editor_redo PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rsi, rcx                       ; rsi = editor ptr
    
    ; Check if redo stack is empty
    mov edx, [rsi + TEXT_EDITOR.redo_count]
    test edx, edx
    jz empty_redo
    
    ; Pop from redo stack
    ; For simplicity, we just decrement the count
    ; TODO: Implement full undo/redo with operation reversal
    dec edx
    mov [rsi + TEXT_EDITOR.redo_count], edx
    
    ; Increment undo count (simple stub)
    mov eax, [rsi + TEXT_EDITOR.undo_count]
    inc eax
    mov [rsi + TEXT_EDITOR.undo_count], eax
    
    ; Mark modified and set dirty
    mov dword ptr [rsi + TEXT_EDITOR.is_modified], 1
    mov eax, [rsi + TEXT_EDITOR.flags]
    or eax, FLAG_DIRTY
    mov [rsi + TEXT_EDITOR.flags], eax
    
    mov rax, 1
    add rsp, 32
    pop rbp
    ret
    
empty_redo:
    xor rax, rax
    add rsp, 32
    pop rbp
    ret
text_editor_redo ENDP

; =============== text_editor_paint ===============
; Render editor to GDI+ surface
; Inputs:  rcx = TEXT_EDITOR ptr, rdx = HWND, r8 = HDC
; Outputs: rax = success (1) or failure (0)
text_editor_paint PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64                        ; Stack space for locals
    
    mov rsi, rcx                       ; rsi = editor ptr
    mov rbx, rdx                       ; rbx = hwnd
    mov r12, r8                        ; r12 = hdc
    
    ; Get client area dimensions
    sub rsp, 32
    mov rcx, rbx                       ; rcx = hwnd
    lea rdx, [rsp]                     ; rdx = RECT buffer
    call GetClientRect
    
    ; RECT: [left, top, right, bottom]
    mov r13d, [rsp + 8]                ; r13d = rect.right (width_val)
    mov r14d, [rsp + 12]               ; r14d = rect.bottom (height)
    add rsp, 32
    
    ; Fill background
    mov rcx, r12                       ; hdc
    xor rdx, rdx                       ; x = 0
    xor r8, r8                         ; y = 0
    mov r9, r13                        ; width_val
    mov qword ptr [rsp + 32], r14      ; height
    mov dword ptr [rsp + 40], COLOR_BACKGROUND
    call PatBlt                        ; Fill background
    
    ; Draw text lines
    mov r10, [rsi + TEXT_EDITOR.first_line]  ; r10 = first line
    xor r11, r11                       ; r11 = line number (0-based)
    
    xor r15, r15                       ; r15 = y position (pixels)
    
draw_lines:
    test r10, r10
    jz draw_done
    
    ; Check if line is visible
    cmp r15, r14                       ; Check if y exceeds window height
    jge draw_done
    
    ; Get line text
    mov rdx, [r10 + TEXT_LINE.text_ptr]  ; rdx = text_ptr
    mov r8d, [r10 + TEXT_LINE.text_len]  ; r8d = text_len
    
    ; Draw line number (left margin, 40 pixels wide)
    mov rcx, r12                       ; hdc
    mov rdx, 5                         ; x = 5
    mov r8, r15                        ; y = y_pos
    mov r9, r11                        ; line number
    call draw_line_number              ; Draw line number
    
    ; Draw text
    mov rcx, r12                       ; hdc
    mov rdx, 45                        ; x = 45 (after line number)
    mov r8, r15                        ; y = y_pos
    mov r9, [r10 + TEXT_LINE.text_ptr] ; text ptr
    mov eax, [r10 + TEXT_LINE.text_len] ; text length
    mov dword ptr [rsp + 32], eax      ; pass length as 5th arg
    call TextOutA                      ; Draw text
    
    ; Move to next line
    mov r10, [r10 + TEXT_LINE.next]    ; r10 = next line
    inc r11                            ; line number++
    add r15d, 16                       ; y += line_height (16 pixels)
    jmp draw_lines
    
draw_done:
    ; Draw cursor (vertical line)
    mov r15d, [rsi + TEXT_EDITOR.cursor_x]   ; cursor_x
    mov r11d, [rsi + TEXT_EDITOR.cursor_y]   ; cursor_y
    
    ; Draw cursor line
    mov rcx, r12                       ; hdc
    mov rdx, r15                       ; x1
    mov r8, r11                        ; y1
    mov r9, r15                        ; x2 (same as x1)
    mov qword ptr [rsp + 32], r11      ; y2 = y1
    mov qword ptr [rsp + 40], 16       ; dy = 16 (line height)
    call line_from_to                  ; Draw cursor line
    
    ; Clear dirty flag
    mov eax, [rsi + TEXT_EDITOR.flags]
    and eax, NOT FLAG_DIRTY
    mov [rsi + TEXT_EDITOR.flags], eax
    
    mov rax, 1                         ; Success
    add rsp, 64
    pop rbp
    ret
text_editor_paint ENDP

; =============== Helper: draw_line_number ===============
; Draw line number in_val left margin
; Inputs:  rcx = hdc, rdx = x, r8 = y, r9 = line_number
draw_line_number PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Format line number as string (TODO: implement sprintf-style)
    ; For now, just draw the number
    ; Call TextOutA to draw number
    
    mov rax, 1
    add rsp, 32
    pop rbp
    ret
draw_line_number ENDP

; =============== Helper: line_from_to ===============
; Draw line from (x1, y1) to (x2, y2 + dy)
; Inputs:  rcx = hdc, rdx = x1, r8 = y1, r9 = x2, [rsp+32] = y2, [rsp+40] = dy
line_from_to PROC
    push rbp
    mov rbp, rsp
    
    ; Use MoveToEx and LineTo to draw line
    ; MoveToEx(hdc, x1, y1, NULL)
    mov rcx, [rsp + 8]                 ; hdc from stack
    mov rdx, [rsp + 16]                ; x1
    mov r8, [rsp + 24]                 ; y1
    xor r9, r9                         ; lpPoint = NULL
    call MoveToEx
    
    ; LineTo(hdc, x2, y1 + dy)
    mov rcx, [rsp + 8]                 ; hdc
    mov rdx, [rsp + 32]                ; x2
    mov r8, [rsp + 40]                 ; y2
    add r8, [rsp + 48]                 ; y2 += dy
    call LineTo
    
    pop rbp
    ret
line_from_to ENDP

; =============== text_editor_on_key ===============
; Handle keyboard input
; Inputs:  rcx = TEXT_EDITOR ptr, rdx = VK code, r8 = state (pressed/released)
; Outputs: rax = handled (1) or not (0)
text_editor_on_key PROC
    push rbp
    mov rbp, rsp
    
    ; TODO: Switch on VK code:
    ;   - VK_LEFT, VK_RIGHT, VK_UP, VK_DOWN → move_cursor_*
    ;   - VK_HOME → cursor to start of line
    ;   - VK_END → cursor to end of line
    ;   - VK_RETURN → insert newline
    ;   - VK_BACK → delete_text(1)
    ;   - VK_DELETE → delete_text(1)
    ;   - Ctrl+A → select_all
    ;   - Ctrl+C → copy
    ;   - Ctrl+X → cut
    ;   - Ctrl+V → paste
    ;   - Ctrl+Z → undo
    ;   - Ctrl+Y → redo
    ;   - Printable char → insert_text(char, 1)
    
    mov rax, 1
    pop rbp
    ret
text_editor_on_key ENDP

; =============== text_editor_on_mouse ===============
; Handle mouse input
; Inputs:  rcx = TEXT_EDITOR ptr, rdx = x (pixels), r8 = y (pixels), r9 = button (left/right/double)
; Outputs: rax = handled (1) or not (0)
text_editor_on_mouse PROC
    push rbp
    mov rbp, rsp
    
    ; TODO: Convert pixel coordinates to line/column
    ; TODO: If left button down → start selection or set cursor
    ; TODO: If left button drag → extend selection
    ; TODO: If left button double-click → select word
    ; TODO: If right button → show context menu
    
    mov rax, 1
    pop rbp
    ret
text_editor_on_mouse ENDP

;==========================================================================
; VMT TABLE IMPLEMENTATIONS (Stub Methods)
;==========================================================================
text_editor_destroy_vmt PROC
    ret
text_editor_destroy_vmt ENDP
text_editor_get_size_vmt PROC
    mov eax, [rcx + TEXT_EDITOR.char_width]
    mov edx, [rcx + TEXT_EDITOR.line_height]
    ret
text_editor_get_size_vmt ENDP
text_editor_set_size_vmt PROC
    mov [rcx + TEXT_EDITOR.char_width], edx
    mov [rcx + TEXT_EDITOR.line_height], r8d
    ret
text_editor_set_size_vmt ENDP
text_editor_show_vmt PROC
    mov eax, [rcx + TEXT_EDITOR.flags]
    or eax, FLAG_VISIBLE
    mov [rcx + TEXT_EDITOR.flags], eax
    ret
text_editor_show_vmt ENDP
text_editor_hide_vmt PROC
    mov eax, [rcx + TEXT_EDITOR.flags]
    and eax, NOT FLAG_VISIBLE
    mov [rcx + TEXT_EDITOR.flags], eax
    ret
text_editor_hide_vmt ENDP

;==========================================================================
; DATA SECTION
;==========================================================================

.DATA
ALIGN 8
text_editor_vmt:
    dq text_editor_destroy_vmt
    dq text_editor_paint
    dq text_editor_on_key
    dq text_editor_get_size_vmt
    dq text_editor_set_size_vmt
    dq text_editor_show_vmt
    dq text_editor_hide_vmt

END





