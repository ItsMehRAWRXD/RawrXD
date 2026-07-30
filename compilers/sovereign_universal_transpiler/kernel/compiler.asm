; compiler.asm - Main compiler orchestration for Sovereign Universal Transpiler
; Entry point: CompileSource
; Flow: Load -> Detect -> Frontend -> UIR -> Optimize -> Emit -> PE

include uir.asm
include token.asm

.data
    ; Compiler context
    CompilerContext STRUCT
        source_ptr      QWORD ?
        source_size     QWORD ?
        ir_ptr          QWORD ?
        ir_count        QWORD ?
        output_ptr      QWORD ?
        output_size     QWORD ?
    CompilerContext ENDS
    
    ctx CompilerContext <>
    
    ; Buffers
    source_buffer   db 65536 dup(0)
    ir_buffer       db 65536 dup(0)
    text_buffer     db 65536 dup(0)
    rdata_buffer    db 65536 dup(0)
    pe_buffer       db 65536 dup(0)
    
    ; Language detection
    LANG_UNKNOWN    equ 0
    LANG_PHP        equ 1
    LANG_C          equ 2
    LANG_PYTHON     equ 3
    
    detected_lang   dd 0

.code

; DetectLanguage - Detect source language from content
; RCX = source, RDX = size
; Returns: EAX = language ID
DetectLanguage PROC
    ; Check for <?php
    cmp dword ptr [rcx], 3C3F7068h   ; "<?ph"
    jne check_c
    cmp byte ptr [rcx + 4], 70h       ; "p"
    jne check_c
    mov eax, LANG_PHP
    ret
check_c:
    ; Check for #include or int main
    cmp byte ptr [rcx], 23h           ; "#"
    je is_c
    cmp dword ptr [rcx], 696E7420h    ; "int "
    je is_c
check_python:
    ; Check for print( or import
    cmp dword ptr [rcx], 7072696Eh    ; "prin"
    jne unknown
    mov eax, LANG_PYTHON
    ret
is_c:
    mov eax, LANG_C
    ret
unknown:
    mov eax, LANG_UNKNOWN
    ret
DetectLanguage ENDP

; CompileSource - Main compilation entry point
; RCX = source buffer
; RDX = source size
; R8  = output filename (wide string)
; Returns: RAX = 0 on success, nonzero on error
CompileSource PROC
    push rbx
    sub rsp, 28h
    
    ; Store in context
    mov [ctx.source_ptr], rcx
    mov [ctx.source_size], rdx
    lea rax, [ir_buffer]
    mov [ctx.ir_ptr], rax
    
    ; Detect language
    call DetectLanguage
    mov [detected_lang], eax
    
    ; Select frontend and compile to UIR
    cmp eax, LANG_PHP
    je compile_php
    cmp eax, LANG_C
    je compile_c
    cmp eax, LANG_PYTHON
    je compile_python
    
    ; Unknown language
    mov rax, 1
    jmp compile_done
    
compile_php:
    ; Call PHP frontend
    ; RCX = source, RDX = size, R8 = UIR buffer
    mov rcx, [ctx.source_ptr]
    mov rdx, [ctx.source_size]
    mov r8, [ctx.ir_ptr]
    ; EXTERN PHPCompile:proc
    ; call PHPCompile
    mov [ctx.ir_count], rax
    jmp optimize
    
compile_c:
    ; Call C frontend
    mov rcx, [ctx.source_ptr]
    mov rdx, [ctx.source_size]
    mov r8, [ctx.ir_ptr]
    ; EXTERN CCompile:proc
    ; call CCompile
    mov [ctx.ir_count], rax
    jmp optimize
    
compile_python:
    ; Call Python frontend
    mov rcx, [ctx.source_ptr]
    mov rdx, [ctx.source_size]
    mov r8, [ctx.ir_ptr]
    ; EXTERN PythonCompile:proc
    ; call PythonCompile
    mov [ctx.ir_count], rax
    jmp optimize
    
optimize:
    ; Optimize UIR
    mov rcx, [ctx.ir_ptr]
    mov rdx, [ctx.ir_count]
    ; EXTERN OptimizeIR:proc
    ; call OptimizeIR
    mov [ctx.ir_count], rax
    
    ; Emit x64 code
    lea r8, [text_buffer]
    lea r9, [rdata_buffer]
    mov rcx, [ctx.ir_ptr]
    mov rdx, [ctx.ir_count]
    ; EXTERN EmitX64:proc
    ; call EmitX64
    mov [ctx.output_size], rax
    
    ; Write PE
    mov rcx, r8              ; output filename
    lea rdx, [text_buffer]
    mov r8, [ctx.output_size]
    lea r9, [rdata_buffer]
    ; EXTERN PEWriteFile:proc
    ; call PEWriteFile
    
    xor rax, rax             ; success
    
compile_done:
    add rsp, 28h
    pop rbx
    ret
CompileSource ENDP

; CompileFile - Compile a file
; RCX = input filename (wide string)
; RDX = output filename (wide string)
; Returns: RAX = 0 on success
CompileFile PROC
    ; 1. Read source file
    ; 2. Call CompileSource
    ; 3. Return result
    ; (Stub for v0.1 - full implementation uses CreateFile/ReadFile)
    xor rax, rax
    ret
CompileFile ENDP

end