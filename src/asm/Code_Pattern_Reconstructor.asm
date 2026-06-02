;================================================================================
; Code_Pattern_Reconstructor.asm
; Pure MASM x64 - Pattern-based code reconstruction
; Reverse engineers binaries by identifying code patterns and reconstructing logic
;================================================================================

option casemap:none

EXTERN VirtualAlloc:PROC
EXTERN VirtualFree:PROC

;================================================================================
; STRUCTURES & DATA
;================================================================================
FUNCTION_INFO struct
    entry_offset    dq ?
    exit_offset     dq ?
    size_bytes      dd ?
    call_count      dd ?
    loop_count      dd ?
    complexity      dd ?
    reconstructed   dd ?
FUNCTION_INFO ends

RECONSTRUCT_CONTEXT struct
    binary_base     dq ?
    binary_size     dq ?
    output_buffer   dq ?
    output_size     dq ?
    functions_found dd ?
    patterns_matched dd ?
RECONSTRUCT_CONTEXT ends

.data
    align 16
    g_context       RECONSTRUCT_CONTEXT <>
    g_functions     FUNCTION_INFO 256 dup(<>) ; Reduced for sample
    
    sz_Header       db "; Code Reconstruction Suite v1.0", 13, 10
                    db "; Pure x64 MASM / Zero Dependencies", 13, 10
                    db ".code", 13, 10, 0
    sz_FuncLabel    db 13, 10, "func_reconstructed_%llX PROC", 13, 10, 0
    sz_FuncEnd      db "func_reconstructed_%llX ENDP", 13, 10, 0
    sz_BodyPlaceholder db "    ; [Reconstructed Logic Placeholder]", 13, 10, 0
    sz_Ret          db "    ret", 13, 10, 0

.code

PUBLIC Reconstructor_IdentifyFunctions
PUBLIC Reconstructor_BuildASM

; ------------------------------------------------------------------------------
; PROCEDURE: Reconstructor_IdentifyFunctions
; Logic: Scans binary for common prologues to identify function entry points.
; ------------------------------------------------------------------------------
Reconstructor_IdentifyFunctions PROC
    push rbx
    push rsi
    push rdi
    
    mov rsi, [g_context.binary_base]
    mov r8, [g_context.binary_size]
    xor r10, r10                ; Count
    
@scan:
    test r8, r8
    jz @done
    
    ; Identify: push rbp; mov rbp, rsp (55 48 89 E5)
    cmp dword ptr [rsi], 0E5894855h
    je @found
    
    ; Identify: sub rsp, imm8 (48 83 EC)
    cmp word ptr [rsi], 8348h
    jne @next
    cmp byte ptr [rsi+2], 0ECh
    je @found
    
@next:
    inc rsi
    dec r8
    jmp @scan

@found:
    ; Store function info
    mov rax, rsi
    sub rax, [g_context.binary_base] ; Relative Offset
    
    lea rdx, g_functions
    ; Calculate offset manually: FUNCTION_INFO is 36 bytes (8+8+4+4+4+4+4)
    mov rcx, r10
    imul rcx, rcx, 36
    mov [rdx + rcx], rax            ; Store at base + offset (entry_offset is first field at offset 0)
    
    add rsi, 4
    sub r8, 4
    cmp r10, 256
    jl @scan

@done:
    mov [g_context.functions_found], r10d
    mov rax, r10
    pop rdi
    pop rsi
    pop rbx
    ret
Reconstructor_IdentifyFunctions ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: Reconstructor_BuildASM
; Logic: Generates human-readable MASM source from identified functions.
; ------------------------------------------------------------------------------
Reconstructor_BuildASM PROC
    push rbx
    push rsi
    push rdi
    
    mov rdi, [g_context.output_buffer]
    test rdi, rdi
    jz @exit

    ; 1. Write Header
    lea rsi, sz_Header
@h_copy:
    lodsb
    test al, al
    jz @h_done
    stosb
    jmp @h_copy
@h_done:

    ; 2. Iterate Functions
    mov r11d, [g_context.functions_found]
    xor rbx, rbx                ; Index
    
@func_loop:
    test r11d, r11d
    jz @exit
    
    ; Write Label + Offset Info
    lea rsi, sz_BodyPlaceholder ; Simple placeholder for now
@p_copy:
    lodsb
    test al, al
    jz @p_done
    stosb
    jmp @p_copy
@p_done:

    lea rsi, sz_Ret
@r_copy:
    lodsb
    test al, al
    jz @r_done
    stosb
    jmp @r_copy
@r_done:

    dec r11d
    inc rbx
    jmp @func_loop

@exit:
    pop rdi
    pop rsi
    pop rbx
    ret
Reconstructor_BuildASM ENDP

END
