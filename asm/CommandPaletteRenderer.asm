; ==============================================================================
; Command Palette Renderer - MASM64 Implementation
; Renders the command palette using the C-compatible CommandPaletteEntry structure
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
extrn OutputDebugStringA:proc
extrn wsprintfA:proc

; Constants
TRANSPARENT equ 1
DT_CENTER equ 00000001h
DT_VCENTER equ 00000004h
DT_SINGLELINE equ 00000020h
DT_LEFT equ 00000000h

; ==============================================================================
; STRUCTURE DEFINITION - Must match CommandPaletteBridge.h exactly
; ==============================================================================

CommandPaletteEntry STRUCT ALIGN(8)
    id          DWORD ?         ; +0  (4 bytes)
    _padding    DWORD ?         ; +4  (4 bytes explicit padding)
    namePtr     QWORD ?         ; +8  (8 bytes)
    shortcutPtr QWORD ?         ; +16 (8 bytes)
    categoryPtr QWORD ?         ; +24 (8 bytes)
CommandPaletteEntry ENDS

; Size and offset constants - USE THESE, NOT MAGIC NUMBERS!
COMMAND_ENTRY_SIZE equ 32       ; sizeof(CommandPaletteEntry)
NAME_PTR_OFFSET equ 8           ; offsetof(name)
SHORTCUT_PTR_OFFSET equ 16      ; offsetof(shortcut)
CATEGORY_PTR_OFFSET equ 24      ; offsetof(category)

; ==============================================================================
; DATA SECTION
; ==============================================================================
.data
align 16

; Debug strings
debugFmt db "Command[%d]: entry=0x%p, namePtr=0x%p, name='%s'",0Dh,0Ah,0
errorNullPtr db "ERROR: Null pointer in command entry!",0Dh,0Ah,0
errorInvalidChar db "ERROR: Invalid first character in command name!",0Dh,0Ah,0
errorStride db "ERROR: Stride calculation mismatch!",0Dh,0Ah,0

; ==============================================================================
; CODE SECTION
; ==============================================================================
.code

align 16
; ==============================================================================
; RenderCommandPalette - Renders command palette buttons
; ==============================================================================
; Parameters:
;   RCX = HDC (device context)
;   RDX = pointer to CommandPaletteEntry array
;   R8  = number of entries
;   R9  = pointer to RECT (client area)
; ==============================================================================
RenderCommandPalette PROC FRAME
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
    push r15
    .pushreg r15
    sub rsp, 104                ; Shadow space + local variables
    .allocstack 104
    .endprolog

    mov r12, rcx                ; r12 = HDC
    mov rsi, rdx                ; rsi = entry array base (DON'T MODIFY)
    mov r13d, r8d               ; r13 = entry count
    mov r14, r9                 ; r14 = client rect
    xor ebx, ebx                ; ebx = loop counter

    ; Set up DC
    mov rcx, r12
    mov edx, TRANSPARENT
    call SetBkMode

    ; Button layout constants
    mov r15d, 280               ; button width
    mov dword ptr [rsp+64], 28  ; button height

button_loop:
    cmp ebx, r13d
    jge button_loop_done

    ; ==================================================================
    ; Calculate entry address: base + (index * COMMAND_ENTRY_SIZE)
    ; CRITICAL: Use the constant, not a hardcoded value!
    ; ==================================================================
    mov rax, rbx
    mov rcx, COMMAND_ENTRY_SIZE ; 32 bytes
    mul rcx                     ; rax = index * 32
    mov rdi, rsi                ; rdi = entry address
    add rdi, rax
    
    ; ------------------------------------------------------------------
    ; Validate the entry before using it
    ; ------------------------------------------------------------------
    mov r8, [rdi + NAME_PTR_OFFSET]     ; r8 = namePtr (offset 8)
    
    ; Check for null pointer
    test r8, r8
    jz null_pointer_error
    
    ; Check first character is printable
    mov al, byte ptr [r8]
    test al, al
    jz invalid_string_error
    cmp al, 20h                 ; < space?
    jb invalid_char_error
    cmp al, 7Eh                 ; > ~?
    ja invalid_char_error
    
    jmp entry_valid

null_pointer_error:
    lea rcx, errorNullPtr
    call OutputDebugStringA
    jmp skip_button

invalid_string_error:
    lea rcx, errorInvalidChar
    call OutputDebugStringA
    jmp skip_button

invalid_char_error:
    push rax
    lea rcx, errorInvalidChar
    call OutputDebugStringA
    pop rax
    int 3                       ; Break for debugging
    jmp skip_button

entry_valid:
    ; ==================================================================
    ; Calculate button position (single column layout)
    ; ==================================================================
    mov eax, ebx
    xor edx, edx
    mov ecx, 1                  ; 1 column
    div ecx                     ; eax = row, edx = col (always 0)
    
    ; Y position
    mov r9d, dword ptr [rsp+64] ; button height
    mul r9d                     ; eax = row * height
    add eax, 5                  ; top margin
    mov r10d, eax               ; r10 = y
    
    ; X position (single column, left-aligned)
    mov r11d, 5                 ; x = left margin
    
    ; ==================================================================
    ; Draw button background
    ; ==================================================================
    sub rsp, 16
    mov dword ptr [rsp+0], r11d           ; left
    mov eax, r11d
    add eax, r15d
    mov dword ptr [rsp+8], eax            ; right
    mov dword ptr [rsp+4], r10d           ; top
    mov eax, r10d
    add eax, dword ptr [rsp+64+16]        ; bottom
    mov dword ptr [rsp+12], eax
    
    ; Background color based on index (alternating)
    test ebx, 1
    jz @F
    mov ecx, 2D2D30h              ; darker gray
    jmp bg_color_set
@@:
    mov ecx, 252526h              ; dark gray
bg_color_set:
    call CreateSolidBrush
    mov rcx, r12
    mov rdx, rsp
    mov r8, rax
    call FillRect
    call DeleteObject
    
    add rsp, 16
    
    ; ==================================================================
    ; Draw command name
    ; ==================================================================
    ; Reload entry address (may have been clobbered)
    mov rax, rbx
    mov rcx, COMMAND_ENTRY_SIZE
    mul rcx
    mov rdi, rsi
    add rdi, rax
    
    ; Get name pointer at correct offset
    mov r8, [rdi + NAME_PTR_OFFSET]       ; offset 8
    
    ; Set text color
    mov rcx, r12
    mov edx, 0E0E0E0h             ; light gray text
    call SetTextColor
    
    ; Text rect
    sub rsp, 16
    mov eax, r11d
    add eax, 8                    ; left padding
    mov dword ptr [rsp+0], eax
    mov eax, r11d
    add eax, r15d
    sub eax, 8                    ; right padding
    mov dword ptr [rsp+8], eax
    mov eax, r10d
    add eax, 4                    ; top padding
    mov dword ptr [rsp+4], eax
    mov eax, r10d
    add eax, dword ptr [rsp+64+16]
    sub eax, 4                    ; bottom padding
    mov dword ptr [rsp+12], eax
    
    ; Draw text
    mov rcx, r12
    mov rdx, r8
    mov r8, -1
    mov r9, rsp
    mov eax, DT_LEFT or DT_VCENTER or DT_SINGLELINE
    mov dword ptr [rsp+16], eax
    call DrawTextA
    
    add rsp, 16

skip_button:
    inc ebx
    jmp button_loop

button_loop_done:
    add rsp, 104
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
RenderCommandPalette ENDP

align 16
; ==============================================================================
; ValidateCommandPalette - Validates the entry array before rendering
; ==============================================================================
; Parameters:
;   RCX = pointer to CommandPaletteEntry array
;   RDX = number of entries
; Returns:
;   EAX = 0 if valid, 1 if error
; ==============================================================================
ValidateCommandPalette PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rsi, rcx
    mov ebx, edx
    xor edi, edi

validate_loop:
    cmp edi, ebx
    jge validate_done
    
    ; Calculate entry address
    mov rax, rdi
    mov rcx, COMMAND_ENTRY_SIZE
    mul rcx
    mov r8, rsi
    add r8, rax
    
    ; Check ID
    mov eax, dword ptr [r8]
    test eax, eax
    jz validation_error
    
    ; Check name pointer at offset 8
    mov rax, [r8 + NAME_PTR_OFFSET]
    test rax, rax
    jz validation_error
    
    ; Check first character
    mov al, byte ptr [rax]
    cmp al, 20h
    jb validation_error
    cmp al, 7Eh
    ja validation_error
    
    inc edi
    jmp validate_loop

validation_error:
    mov eax, 1
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret

validate_done:
    xor eax, eax
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret
ValidateCommandPalette ENDP

; ==============================================================================
; Quick Reference: Memory Layout
; ==============================================================================
; CommandPaletteEntry (32 bytes):
;   Offset 0:   id          (DWORD)
;   Offset 4:   _padding    (DWORD)
;   Offset 8:   namePtr     (QWORD)
;   Offset 16:  shortcutPtr (QWORD)
;   Offset 24:  categoryPtr (QWORD)
;
; CORRECT USAGE:
;   mov rax, index
;   mov rcx, COMMAND_ENTRY_SIZE    ; 32
;   mul rcx
;   mov rdi, base
;   add rdi, rax                    ; rdi = entry address
;   mov rax, [rdi + NAME_PTR_OFFSET]  ; rax = namePtr (offset 8)
;
; INCORRECT USAGE (causes corruption):
;   mov rcx, 36                     ; Wrong size!
;   mul rcx
;   mov rax, [rdi + 4]              ; Wrong offset!
; ==============================================================================

END
