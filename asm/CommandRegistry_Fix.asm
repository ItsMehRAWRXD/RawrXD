; ==============================================================================
; Command Registry Renderer Fix - RawrXD Win32IDE
; Fixes pointer offset corruption in sidebar button text rendering
; ==============================================================================
OPTION CASemap:NONE
OPTION WIN64:3

; External Win32 APIs
extrn DrawTextA:proc
extrn TextOutA:proc
extrn SetBkMode:proc
extrn SetTextColor:proc
extrn CreateSolidBrush:proc
extrn FillRect:proc
extrn DeleteObject:proc

; Constants
TRANSPARENT equ 1
DT_CENTER equ 00000001h
DT_VCENTER equ 00000004h
DT_SINGLELINE equ 00000020h

; ==============================================================================
; STRUCTURE DEFINITION - CRITICAL: Must match C++ side exactly
; ==============================================================================

; WRONG - This causes the "lew Folde" bug due to padding
; CommandEntry_Bad STRUCT
;     commandId   DWORD ?         ; 4 bytes
;     namePtr     QWORD ?         ; 8 bytes - but compiler adds 4 bytes padding!
;     shortcutPtr QWORD ?         ; 8 bytes
;     categoryPtr QWORD ?         ; 8 bytes
;     handlerPtr  QWORD ?         ; 8 bytes
; CommandEntry_Bad ENDS
; ; Size = 4 + 4(pad) + 8 + 8 + 8 + 8 = 40 bytes
; ; If you use "sizeof CommandEntry_Bad" you get 36 (wrong!)

; CORRECT - Explicitly pack or account for padding
CommandEntry STRUCT ALIGN(8)
    commandId   DWORD ?         ; 4 bytes
    _padding    DWORD ?         ; 4 bytes explicit padding
    namePtr     QWORD ?         ; 8 bytes - now aligned
    shortcutPtr QWORD ?         ; 8 bytes
    categoryPtr QWORD ?         ; 8 bytes
    handlerPtr  QWORD ?         ; 8 bytes
CommandEntry ENDS
; Size = 40 bytes with proper alignment

; Alternative: Packed structure (no padding)
CommandEntry_Packed STRUCT
    commandId   DWORD ?         ; 4 bytes
    namePtr     QWORD ?         ; 8 bytes at offset 4 (misaligned!)
    ; This version requires special handling
CommandEntry_Packed ENDS

; ==============================================================================
; DATA SECTION
; ==============================================================================
.data
align 16

; Debug buffer for verifying pointers
debugBuffer db 256 dup(0)
debugFmt db "Command[%d]: ptr=0x%p, first byte='%c' (0x%02X)",0Dh,0Ah,0

; Error message for misaligned access
alignErrorMsg db "ERROR: Misaligned pointer detected in command registry!",0Dh,0Ah,0

; ==============================================================================
; CODE SECTION
; ==============================================================================
.code

align 16
; ==============================================================================
; RenderCommandButtons - Fixed version with proper pointer validation
; ==============================================================================
; Parameters:
;   RCX = HWND (window handle)
;   RDX = HDC (device context)
;   R8  = pointer to command registry array
;   R9  = number of commands (183)
; ==============================================================================
RenderCommandButtons PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    sub rsp, 88                 ; Shadow space + local variables
    .allocstack 88
    .endprolog

    mov r12, rcx                ; r12 = HWND
    mov r13, rdx                ; r13 = HDC
    mov rsi, r8                 ; rsi = command array pointer
    mov r14d, r9d               ; r14 = command count (183)
    xor ebx, ebx                ; ebx = loop counter (0 to 182)

    ; Set up DC for drawing
    mov rcx, r13
    mov edx, TRANSPARENT
    call SetBkMode

    ; Calculate button dimensions
    mov r8d, 200                ; button width
    mov r9d, 30                 ; button height

button_loop:
    cmp ebx, r14d
    jge button_loop_done

    ; ==================================================================
    ; CRITICAL: Verify pointer alignment and offset
    ; ==================================================================
    
    ; Calculate entry address: base + (index * sizeof(CommandEntry))
    ; sizeof(CommandEntry) = 40 bytes (not 36!)
    mov rax, rbx
    mov rcx, 40                 ; CORRECT stride - includes padding
    mul rcx                     ; rax = index * 40
    mov rdi, rsi                ; rdi = base pointer
    add rdi, rax                ; rdi = current entry address
    
    ; ------------------------------------------------------------------
    ; DEBUG BREAKPOINT - Verify the pointer before using it
    ; ------------------------------------------------------------------
    ; Check if we're pointing to the right place
    mov rcx, [rdi+8]            ; rcx = namePtr (offset 8, not 4!)
    
    ; Validate pointer is not null
    test rcx, rcx
    jz skip_button
    
    ; Check first byte of string (should be printable ASCII)
    mov al, byte ptr [rcx]
    test al, al
    jz skip_button              ; null byte - invalid string
    
    ; Optional: Verify it's a printable character
    cmp al, 20h                 ; < space?
    jb possible_corruption
    cmp al, 7Eh                 ; > ~?
    ja possible_corruption
    jmp pointer_ok

possible_corruption:
    ; String doesn't start with printable char - pointer is likely off
    ; Break here for debugging
    int 3
    jmp skip_button

pointer_ok:
    ; ==================================================================
    ; Calculate button position
    ; ==================================================================
    mov eax, ebx
    xor edx, edx
    mov ecx, 5                  ; 5 buttons per column
    div ecx                     ; eax = row, edx = col
    
    push rax
    push rdx
    
    ; Calculate Y position
    mov eax, r9d                ; button height
    mul dword ptr [rsp+8]       ; * row
    add eax, 10                 ; top margin
    mov r10d, eax               ; r10 = y position
    
    ; Calculate X position  
    mov eax, r8d                ; button width
    mul dword ptr [rsp]         ; * col
    add eax, 10                 ; left margin
    mov r11d, eax               ; r11 = x position
    
    add rsp, 16
    
    ; ==================================================================
    ; Draw button background
    ; ==================================================================
    ; Create RECT on stack
    sub rsp, 16
    mov dword ptr [rsp+0], r11d           ; left
    mov eax, r11d
    add eax, r8d
    mov dword ptr [rsp+8], eax          ; right
    mov dword ptr [rsp+4], r10d           ; top
    mov eax, r10d
    add eax, r9d
    mov dword ptr [rsp+12], eax         ; bottom
    
    ; Fill background
    mov ecx, 333333h              ; dark gray
    call CreateSolidBrush
    mov rcx, r13
    mov rdx, rsp                  ; RECT pointer
    mov r8, rax                   ; brush
    call FillRect
    call DeleteObject
    
    add rsp, 16
    
    ; ==================================================================
    ; Draw text - THIS IS WHERE THE BUG WAS
    ; ==================================================================
    ; Load string pointer from CORRECT offset
    mov rax, rbx
    mov rcx, 40
    mul rcx
    mov rdi, rsi
    add rdi, rax
    
    ; Get string pointer at offset 8 (after DWORD id + DWORD padding)
    mov r8, [rdi+8]               ; r8 = namePtr (CORRECT OFFSET)
    
    ; Verify pointer one more time before DrawText
    test r8, r8
    jz skip_button
    
    ; Check string starts with expected character
    mov al, byte ptr [r8]
    cmp al, 'N'                   ; Expecting "New Folder" etc.
    jb skip_button
    
    ; Set text color
    mov rcx, r13
    mov edx, 0FFFFFFh             ; white
    call SetTextColor
    
    ; Calculate text rect (inset from button edges)
    sub rsp, 16
    mov eax, r11d
    add eax, 5
    mov dword ptr [rsp+0], eax    ; left + padding
    mov eax, r11d
    add eax, r8d
    sub eax, 5
    mov dword ptr [rsp+8], eax    ; right - padding
    mov eax, r10d
    add eax, 5
    mov dword ptr [rsp+4], eax    ; top + padding
    mov eax, r10d
    add eax, r9d
    sub eax, 5
    mov dword ptr [rsp+12], eax   ; bottom - padding
    
    ; Draw the text
    mov rcx, r13                  ; HDC
    mov rdx, r8                   ; lpString (verified)
    mov r8, -1                    ; nCount (-1 = null terminated)
    mov r9, rsp                   ; lpRect
    mov eax, DT_CENTER or DT_VCENTER or DT_SINGLELINE
    mov dword ptr [rsp+16], eax   ; uFormat (on stack for x64 calling convention)
    call DrawTextA
    
    add rsp, 16

skip_button:
    inc ebx
    jmp button_loop

button_loop_done:
    add rsp, 88
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
RenderCommandButtons ENDP

align 16
; ==============================================================================
; ValidateCommandRegistry - Diagnostic function to check registry integrity
; ==============================================================================
; Parameters:
;   RCX = pointer to command registry array
;   RDX = number of commands
; Returns:
;   EAX = 0 if valid, 1 if corruption detected
; ==============================================================================
ValidateCommandRegistry PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rsi, rcx                ; rsi = registry base
    mov ebx, edx                ; ebx = count
    xor edi, edi                ; edi = index

validate_loop:
    cmp edi, ebx
    jge validate_done
    
    ; Calculate entry address
    mov rax, rdi
    mov rcx, 40                 ; sizeof(CommandEntry)
    mul rcx
    mov r8, rsi
    add r8, rax                 ; r8 = current entry
    
    ; Check command ID (should be non-zero for valid entries)
    mov eax, dword ptr [r8]
    test eax, eax
    jz possible_error
    
    ; Check name pointer (should be non-null)
    mov rax, [r8+8]             ; offset 8 for namePtr
    test rax, rax
    jz possible_error
    
    ; Check string starts with printable character
    mov al, byte ptr [rax]
    cmp al, 20h
    jb possible_error
    cmp al, 7Eh
    ja possible_error
    
    inc edi
    jmp validate_loop

possible_error:
    ; Output debug message
    lea rcx, alignErrorMsg
    call OutputDebugStringA
    
    mov eax, 1                  ; Return error
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret

validate_done:
    xor eax, eax                ; Return success
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret
ValidateCommandRegistry ENDP

; ==============================================================================
; Quick Reference: Common Offsets for CommandEntry
; ==============================================================================
; With ALIGN(8):
;   commandId:   offset 0,  size 4
;   _padding:    offset 4,  size 4
;   namePtr:     offset 8,  size 8
;   shortcutPtr: offset 16, size 8
;   categoryPtr: offset 24, size 8
;   handlerPtr:  offset 32, size 8
;   Total size:  40 bytes
;
; If you see "lew Folde", your offset is +1 (using offset 9 instead of 8)
; If you see "ew Folder", your offset is -1 (using offset 7 instead of 8)
; ==============================================================================

END
