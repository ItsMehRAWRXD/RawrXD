; frontend_api.asm - Frontend Adapter API
; Defines the contract that every language frontend must implement

; Frontend type constants
FRONTEND_PHP      EQU 1
FRONTEND_C        EQU 2
FRONTEND_PYTHON   EQU 3
FRONTEND_RUST     EQU 4
FRONTEND_ZIG      EQU 5

; FRONTEND_CONTEXT - Per-frontend state
FRONTEND_CONTEXT STRUCT
    frontend_type   DWORD ?     ; FRONTEND_* constant
    source_ptr      QWORD ?     ; Source code pointer
    source_len      DWORD ?     ; Source length
    line            DWORD ?     ; Current line
    column          DWORD ?     ; Current column
    error_code      DWORD ?     ; Last error
    error_msg       QWORD ?     ; Error message pointer
FRONTEND_CONTEXT ENDS

; FrontendCompile - Main entry point for all frontends
; RCX = source buffer
; RDX = source size  
; R8  = UIR output buffer
; R9  = frontend type (FRONTEND_*)
; Returns: RAX = UIR node count, or -1 on error
; 
; This is the stable ABI contract. Every frontend implements this.
FrontendCompile PROTO

; FrontendDetect - Auto-detect language from source
; RCX = source buffer
; RDX = source size
; Returns: RAX = FRONTEND_* constant, or 0 if unknown
FrontendDetect PROC
    push rbx
    push rsi
    push rdi
    
    mov rsi, rcx
    mov rdi, rdx
    
    ; Check for PHP: <?php
    cmp rdi, 5
    jb check_c
    
    mov eax, [rsi]
    cmp eax, 03F3C7068h      ; '<?ph' little-endian
    jne check_c
    mov al, [rsi+4]
    cmp al, 'p'
    je detected_php
    
check_c:
    ; Check for Python: print, def, import
    cmp rdi, 5
    jb check_python
    
    mov eax, [rsi]
    cmp eax, 02746E6970h     ; 'prin' 
    jne check_python
    mov ax, [rsi+4]
    cmp ax, 0274h            ; 't'
    je detected_python
    
check_python:
    ; Check for C: #include, int main, void
    cmp rdi, 8
    jb check_rust
    
    mov rax, [rsi]
    cmp rax, 065646E69706323h ; '#includ'
    je detected_c
    
check_rust:
    ; Check for Rust: fn main, use std
    cmp rdi, 7
    jb check_zig
    
    mov eax, [rsi]
    cmp eax, 0206E66066Eh    ; 'fn m'
    je detected_rust
    
check_zig:
    ; Check for Zig: const std
    cmp rdi, 10
    jb unknown
    
    mov rax, [rsi]
    cmp rax, 02074736E6F63h  ; 'const '
    je detected_zig
    
unknown:
    xor eax, eax
    jmp detect_done
    
detected_php:
    mov eax, FRONTEND_PHP
    jmp detect_done
    
detected_c:
    mov eax, FRONTEND_C
    jmp detect_done
    
detected_python:
    mov eax, FRONTEND_PYTHON
    jmp detect_done
    
detected_rust:
    mov eax, FRONTEND_RUST
    jmp detect_done
    
detected_zig:
    mov eax, FRONTEND_ZIG
    
detect_done:
    pop rdi
    pop rsi
    pop rbx
    ret
FrontendDetect ENDP

END
