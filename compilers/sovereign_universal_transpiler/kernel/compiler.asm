; compiler.asm - Main compiler orchestration for Sovereign Universal Transpiler
; v0.2 - Production: stack alignment, error checking, LexerInit, phase tracking
; Entry point: CompileSource
; Flow: Load -> Detect -> Frontend -> UIR -> Optimize -> Emit -> PE

; External declarations from uir.asm
extrn UIRCreateContext:proc
extrn UIRCreateNode:proc
extrn UIRGetNode:proc
extrn UIRAddConstant:proc
extrn UIRGetConstant:proc
extrn UIRAddRelocation:proc
extrn UIRAllocVReg:proc
extrn UIRReset:proc
extrn UIRGetNodeCount:proc
extrn UIRValidateHeader:proc

; External declarations from token.asm
extrn TokenInit:proc
extrn TokenCreate:proc
extrn TokenGet:proc
extrn TokenGetCount:proc
extrn TokenTypeToString:proc

; External declarations from lexer.asm
extrn LexerInit:proc
extrn LexerNext:proc
extrn LexerPeek:proc
extrn LexerAdvance:proc

; External declarations from frontends
extrn PHPCompile:proc
extrn CCompile:proc
extrn PythonCompile:proc

; External declarations from optimizer.asm
extrn OptimizeIR:proc

; External declarations from emitter_x64.asm
extrn EmitX64:proc
extrn EmitGetRdataSize:proc

; External declarations from pe_writer.asm
extrn PEWriteFile:proc

; Windows API functions
extrn CreateFileA:proc
extrn CreateFileW:proc
extrn ReadFile:proc
extrn WriteFile:proc
extrn CloseHandle:proc
extrn GetStdHandle:proc
extrn GetCommandLineA:proc
extrn VirtualAlloc:proc
extrn VirtualFree:proc
extrn ExitProcess:proc

.data
    ; Compiler context
    CompilerContext STRUCT
        source_ptr      QWORD ?
        source_size     QWORD ?
        ir_ptr          QWORD ?
        ir_count        QWORD ?
        output_ptr      QWORD ?
        output_size     QWORD ?
        output_name     QWORD ?      ; output filename (preserved for PE writer)
        phase           DWORD ?      ; current compilation phase
        language        DWORD ?      ; detected language
    CompilerContext ENDS

    ctx CompilerContext <>
    
    ; Error handling
    error_buffer    BYTE 512 DUP(0)
    error_code      DWORD 0
    
    ; Messages
    msg_banner      db "Sovereign Universal Transpiler v0.2", 0Dh, 0Ah, 0
    msg_compiling   db "Compiling: ", 0
    msg_success     db "Build successful: ", 0
    msg_failed      db "Build failed", 0Dh, 0Ah, 0
    msg_error_usage db "Error: Invalid arguments", 0Dh, 0Ah
                   db "Usage: sut.exe <input> <output.exe>", 0Dh, 0Ah, 0
    msg_error_file  db "Error: Cannot open input file", 0Dh, 0Ah, 0
    msg_error_mem   db "Error: Memory allocation failed", 0Dh, 0Ah, 0
    msg_error_lang  db "Error: Unknown language", 0Dh, 0Ah, 0
    msg_error_front db "Error: Frontend compilation failed", 0Dh, 0Ah, 0
    msg_error_opt   db "Error: Optimization failed", 0Dh, 0Ah, 0
    msg_error_emit  db "Error: Code emission failed", 0Dh, 0Ah, 0
    msg_error_pe    db "Error: PE generation failed", 0Dh, 0Ah, 0

    ; Language detection
    LANG_UNKNOWN    equ 0
    LANG_PHP        equ 1
    LANG_C          equ 2
    LANG_PYTHON     equ 3

    ; Compilation phases
    PHASE_DETECT    equ 1
    PHASE_PARSE     equ 2
    PHASE_OPT       equ 3
    PHASE_EMIT      equ 4
    PHASE_PE        equ 5

    detected_lang   dd 0

    usage_msg       db "Usage: sut.exe <input.php> <output.exe>", 0Dh, 0Ah
                   db "       sut.exe --sme2-certify", 0Dh, 0Ah, 0
    certify_flag    db "--sme2-certify", 0
    default_output  db "output.exe", 0
    test_php_source db "<?php echo ", 22h, "Hello from Sovereign PHP", 22h, "; ?>"
    test_php_len    EQU $ - test_php_source

; Large buffers in .data (small enough to not corrupt PE)
.data
    source_buffer   db 1024 dup(0)
    ir_buffer       db 4096 dup(0)      ; 4KB for UIR (128 nodes * 32 bytes)
    text_buffer     db 1024 dup(0)
    rdata_buffer    db 256 dup(0)
    pe_buffer       db 2048 dup(0)

.code

; DetectLanguage - Detect source language from content
; RCX = source, RDX = size
; Returns: EAX = language ID
DetectLanguage PROC
    ; Check for <?php (needs at least 5 bytes)
    cmp rdx, 5
    jl check_php_too_short
    cmp dword ptr [rcx], 68703F3Ch
    jne check_c
    mov al, [rcx+4]
    cmp al, ' '
    je  is_php
    cmp al, 9   ; tab
    je  is_php
    cmp al, 10  ; newline
    je  is_php
    cmp al, 13  ; carriage return
    je  is_php
    cmp al, 'p' ; in case it's <?php without space
    je  is_php
    jne check_c
check_php_too_short:
    jmp check_c
is_php:
    mov eax, LANG_PHP
    ret

check_c:
    ; Check for #include or int main
    cmp byte ptr [rcx], 23h           ; "#"
    je is_c
    ; Check for int ... (we need at least 4 bytes for "int ")
    cmp rdx, 4
    jl check_python
    cmp dword ptr [rcx], 20746E69h    ; "int " in little-endian
    je is_c
    jmp check_python

is_c:
    mov eax, LANG_C
    ret

check_python:
    ; Check for print( or import
    cmp rdx, 5
    jl unknown
    cmp dword ptr [rcx], 6E697270h    ; "prin" in little-endian
    jne unknown
    cmp byte ptr [rcx + 4], 74h       ; "t"
    jne unknown
    mov eax, LANG_PYTHON
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
    push rsi
    sub rsp, 28h                ; 2 pushes (16) + 28h (40) = 56, need 8 more for alignment

    mov rbx, r8                 ; save output filename in rbx (non-volatile)

    ; Store in context
    mov [ctx.source_ptr], rcx
    mov [ctx.source_size], rdx
    mov [ctx.output_name], r8
    mov dword ptr [ctx.phase], PHASE_DETECT

    ; Initialize UIR context
    call UIRCreateContext
    test rax, rax
    jz compile_error
    ; UIR context is global (uir_ctx), no pointer to save

    ; Initialize lexer with source
    mov rcx, [ctx.source_ptr]
    mov rdx, [ctx.source_size]
    call LexerInit

    ; Detect language
    mov rcx, [ctx.source_ptr]
    mov rdx, [ctx.source_size]
    call DetectLanguage
    mov [detected_lang], eax
    mov [ctx.language], eax
    mov dword ptr [ctx.phase], PHASE_PARSE

    ; Select frontend and compile to UIR
    cmp eax, LANG_PHP
    je compile_php
    cmp eax, LANG_C
    je compile_c
    cmp eax, LANG_PYTHON
    je compile_python

    ; Unknown language
    mov rax, 2                  ; error: unknown language
    jmp compile_done

compile_php:
    mov rcx, [ctx.source_ptr]
    mov rdx, [ctx.source_size]
    lea r8, [ir_buffer]
    call PHPCompile
    cmp rax, -1
    je compile_error
    mov [ctx.ir_count], rax
    jmp optimize

compile_c:
    mov rcx, [ctx.source_ptr]
    mov rdx, [ctx.source_size]
    lea r8, [ir_buffer]
    call CCompile
    cmp rax, -1
    je compile_error
    mov [ctx.ir_count], rax
    jmp optimize

compile_python:
    mov rcx, [ctx.source_ptr]
    mov rdx, [ctx.source_size]
    lea r8, [ir_buffer]
    call PythonCompile
    cmp rax, -1
    je compile_error
    mov [ctx.ir_count], rax
    jmp optimize

optimize:
    mov dword ptr [ctx.phase], PHASE_OPT
    ; Optimize UIR - pass raw node array
    lea rcx, [ir_buffer]
    mov rdx, [ctx.ir_count]
    call OptimizeIR
    mov [ctx.ir_count], rax     ; update count after optimization

    ; Emit x64 code - pass raw node array
    mov dword ptr [ctx.phase], PHASE_EMIT
    lea rcx, [ir_buffer]
    mov rdx, [ctx.ir_count]
    lea r8, [text_buffer]
    lea r9, [rdata_buffer]
    call EmitX64
    mov [ctx.output_size], rax

    ; Write PE
    mov dword ptr [ctx.phase], PHASE_PE
    mov rcx, rbx                ; output filename (from saved rbx)
    lea rdx, [text_buffer]
    mov r8, [ctx.output_size]
    xor r9d, r9d                ; rdata = NULL (no rdata for now)
    call PEWriteFile
    test rax, rax
    jz compile_error

    xor rax, rax                ; success
    jmp compile_done

compile_error:
    mov rax, 1                  ; generic error

compile_done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
CompileSource ENDP

; CompileFile - Compile a file
; RCX = input filename (ANSI string)
; RDX = output filename (ANSI string)
; Returns: RAX = 0 on success
CompileFile PROC
    push rbx
    push r12
    push r13
    sub rsp, 50h                ; 3 pushes (24) + 50h (80) = 104 = 0 mod 16 ✓

    mov r12, rdx                ; save output filename
    mov r13, rcx                ; input filename

    ; Read source file using Win32 ReadFile
    ; CreateFileA(input, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)
    mov rcx, r13                ; lpFileName = ANSI string
    mov edx, 80000000h          ; GENERIC_READ
    mov r8d, 1                  ; FILE_SHARE_READ
    xor r9d, r9d                ; lpSecurityAttributes = NULL
    mov qword ptr [rsp + 20h], 3  ; OPEN_EXISTING (5th param)
    mov qword ptr [rsp + 28h], 0  ; dwFlagsAndAttributes (6th param)
    mov qword ptr [rsp + 30h], 0  ; hTemplateFile (7th param)
    call CreateFileA
    cmp rax, -1                 ; INVALID_HANDLE_VALUE
    je cf_error
    mov rbx, rax                ; save file handle

    ; ReadFile(handle, source_buffer, 4096, &bytesRead, NULL)
    mov rcx, rbx                ; hFile
    lea rdx, [source_buffer]    ; lpBuffer
    mov r8d, 4096               ; nNumberOfBytesToRead
    lea r9, [ctx.source_size]   ; lpNumberOfBytesRead
    mov qword ptr [rsp + 20h], 0  ; lpOverlapped = NULL (5th param)
    call ReadFile
    test rax, rax
    jz cf_close_error

    ; CloseHandle
    mov rcx, rbx
    call CloseHandle

    ; Call CompileSource with source_buffer, size, output filename
    lea rcx, [source_buffer]
    mov rdx, [ctx.source_size]
    mov r8, r12                 ; output filename
    call CompileSource
    jmp cf_done

cf_close_error:
    mov rcx, rbx
    call CloseHandle

cf_error:
    mov rax, 1

cf_done:
    add rsp, 50h
    pop r13
    pop r12
    pop rbx
    ret
CompileFile ENDP

; ============================================================================
; Data for command line parsing
; ============================================================================
.data
    input_path_ptr  dq 0
    output_path_ptr dq 0
    
    error_no_input  db "Error: Could not read input file", 0Dh, 0Ah, 0
    error_compile   db "Error: Compilation failed", 0Dh, 0Ah, 0

.code

; PrintUsage - Display usage information
PrintUsage PROC
    push rbp
    mov rbp, rsp
    sub rsp, 30h
    
    ; Get stdout handle
    mov ecx, -11              ; STD_OUTPUT_HANDLE
    call GetStdHandle
    
    ; Write usage message
    mov rcx, rax              ; hConsoleOutput
    lea rdx, [usage_msg]      ; lpBuffer
    mov r8d, sizeof usage_msg ; nNumberOfCharsToWrite
    xor r9d, r9d              ; lpReserved
    call WriteFile
    
    add rsp, 30h
    pop rbp
    ret
PrintUsage ENDP

; ParseCommandLineAndRun - Parse command line and run compilation
; RCX = command line string
; Returns: EAX = 0 on success, 1 on failure
ParseCommandLineAndRun PROC frame
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 30h
    .allocstack 30h
    .endprolog

    mov rsi, rcx                     ; rsi = command line string

    ; Step 1: Skip executable path/name (handles quoted executable paths)
    cmp byte ptr [rsi], '"'
    jne skip_exe_no_quotes

    inc rsi                          ; Skip opening quote
skip_exe_quote:
    mov al, [rsi]
    test al, al
    jz no_args
    inc rsi
    cmp al, '"'
    jne skip_exe_quote
    jmp skip_spaces

skip_exe_no_quotes:
    mov al, [rsi]
    test al, al
    jz no_args
    cmp al, ' '
    je skip_spaces
    cmp al, 9                        ; Tab
    je skip_spaces
    inc rsi
    jmp skip_exe_no_quotes

skip_spaces:
    mov al, [rsi]
    cmp al, ' '
    je next_space
    cmp al, 9
    je next_space
    jmp parse_input_arg
next_space:
    inc rsi
    jmp skip_spaces

parse_input_arg:
    cmp byte ptr [rsi], 0
    je no_args

    ; Check for --sme2-certify flag (little-endian byte order)
    ; String: '-' '-' 's' 'm' 'e' '2' '-' 'c' 'e' 'r' 't' 'i' 'f' 'y'
    ; Hex:    2D  2D  73  6D  65  32  2D  63  65  72  74  69  66  79
    cmp dword ptr [rsi], 6D732D2Dh  ; bytes 0-3: "--sm"
    jne not_certify
    cmp dword ptr [rsi + 4], 632D3265h  ; bytes 4-7: "e2-c"
    jne not_certify
    cmp dword ptr [rsi + 8], 69747265h  ; bytes 8-11: "erti"
    jne not_certify
    cmp word ptr [rsi + 12], 7966h      ; bytes 12-13: "fy"
    jne not_certify

    ; --sme2-certify flag detected (stub - certification not included in core build)
    ; call RunSME2Certification
    mov ecx, 0
    call ExitProcess

not_certify:
    mov [input_path_ptr], rsi        ; Store input file path

; Find space separator between input and output args
find_output_arg:
    mov al, [rsi]
    test al, al
    jz no_output_arg
    cmp al, ' '
    je split_args
    cmp al, 9
    je split_args
    inc rsi
    jmp find_output_arg

split_args:
    mov byte ptr [rsi], 0            ; Null-terminate input path string
    inc rsi

skip_spaces_output:
    mov al, [rsi]
    cmp al, ' '
    je next_space_out
    cmp al, 9
    je next_space_out
    jmp store_output_arg
next_space_out:
    inc rsi
    jmp skip_spaces_output

store_output_arg:
    cmp byte ptr [rsi], 0
    je no_output_arg

    mov [output_path_ptr], rsi       ; Store output file path

    ; Run transpilation pipeline
    mov rcx, [input_path_ptr]
    mov rdx, [output_path_ptr]
    call CompileFile
    jmp done

no_args:
    call PrintUsage
    mov eax, 1
    jmp done

no_output_arg:
    call PrintUsage
    mov eax, 1

done:
    add rsp, 30h
    pop rdi
    pop rsi
    pop rbp
    ret
ParseCommandLineAndRun ENDP

; ============================================================================
; mainCRTStartup - Entry point for the transpiler
; ============================================================================
mainCRTStartup PROC frame
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 40h                    ; 32-byte shadow space + 16-byte alignment
    .allocstack 40h
    .endprolog

    ; Fetch raw command line pointer from OS
    call GetCommandLineA            ; Returns char* in RAX
    test rax, rax
    jz exit_failure

    mov rcx, rax                    ; Pass command line string to parser
    call ParseCommandLineAndRun

    mov ecx, eax                    ; Return code from compiler
    call ExitProcess

exit_failure:
    mov ecx, 1
    call ExitProcess
mainCRTStartup ENDP

end