; Diagnostic IDE integration test
option casemap:none

EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN ExitProcess:PROC

STD_OUTPUT_HANDLE EQU -11
MAX_LANGUAGES EQU 69

.data
align 8
hStdOut         QWORD 0
bytesWritten    QWORD 0

COMPILER_ENTRY STRUCT
    LangID DWORD ?
    Tier DWORD ?
    pLangName QWORD ?
    pCompilerPath QWORD ?
    pLexerName QWORD ?
    Status DWORD ?
    LastCompileTime QWORD ?
    CompileCount QWORD ?
    ErrorCount QWORD ?
COMPILER_ENTRY ENDS

CompilerRegistry COMPILER_ENTRY MAX_LANGUAGES DUP(<>)

szInit          BYTE "Registry init...", 13, 10, 0
szDone          BYTE "Registry done!", 13, 10, 0
szAuditStart    BYTE "Audit start...", 13, 10, 0
szAuditLoop     BYTE "Audit loop ", 0
szColon         BYTE ": ", 0
szAuditEnd      BYTE "Audit end!", 13, 10, 0
szCrlf          BYTE 13, 10, 0
szMASM          BYTE "MASM", 0
szNASM          BYTE "NASM", 0
szC             BYTE "C", 0
szCPP           BYTE "CPP", 0
szRust          BYTE "Rust", 0
szGo            BYTE "Go", 0
szPS            BYTE "PowerShell", 0
szBash          BYTE "Bash", 0
szPath          BYTE "path", 0
szLexer         BYTE "lexer", 0

.code
align 8

PrintString PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    mov r10, rcx
    xor rdx, rdx
    mov r11, r10
PrintString_count_loop:
    cmp byte ptr [r11], 0
    je PrintString_count_done
    inc rdx
    inc r11
    jmp PrintString_count_loop
PrintString_count_done:
    
    test rdx, rdx
    jz PrintString_done
    
    mov rcx, hStdOut
    mov r8, rdx
    mov rdx, r10
    lea r9, bytesWritten
    mov qword ptr [rsp + 20h], 0
    call WriteFile
    
PrintString_done:
    add rsp, 40h
    pop rbp
    ret
PrintString ENDP

PrintInt PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 50h
    .ENDPROLOG
    
    mov rax, rcx
    lea rdi, [rsp + 40h]
    mov byte ptr [rdi], 0
    
    mov rcx, 10
PrintInt_convert_loop:
    xor rdx, rdx
    div rcx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz PrintInt_convert_loop
    
    mov rcx, rdi
    call PrintString
    
    add rsp, 50h
    pop rbp
    ret
PrintInt ENDP

mainCRTStartup PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
    lea rcx, szInit
    call PrintString
    
    ; Init all entries
    xor rbx, rbx
    lea rsi, CompilerRegistry
Init_loop:
    cmp ebx, MAX_LANGUAGES
    jge Init_done
    
    mov rax, rbx
    imul rax, SIZEOF COMPILER_ENTRY
    lea rdi, [rsi + rax]
    
    mov [rdi].COMPILER_ENTRY.LangID, ebx
    
    cmp ebx, 8
    jl Init_tier1
    cmp ebx, 48
    jl Init_tier2
    jmp Init_tier3
    
Init_tier1:
    mov [rdi].COMPILER_ENTRY.Tier, 1
    jmp Init_set_name
    
Init_tier2:
    mov [rdi].COMPILER_ENTRY.Tier, 2
    jmp Init_set_name
    
Init_tier3:
    mov [rdi].COMPILER_ENTRY.Tier, 3
    
Init_set_name:
    lea rax, szMASM
    cmp ebx, 0
    je Init_name_done
    lea rax, szNASM
    cmp ebx, 1
    je Init_name_done
    lea rax, szC
    cmp ebx, 2
    je Init_name_done
    lea rax, szCPP
    cmp ebx, 3
    je Init_name_done
    lea rax, szRust
    cmp ebx, 4
    je Init_name_done
    lea rax, szGo
    cmp ebx, 5
    je Init_name_done
    lea rax, szPS
    cmp ebx, 6
    je Init_name_done
    lea rax, szBash
Init_name_done:
    mov [rdi].COMPILER_ENTRY.pLangName, rax
    lea rax, szPath
    mov [rdi].COMPILER_ENTRY.pCompilerPath, rax
    lea rax, szLexer
    mov [rdi].COMPILER_ENTRY.pLexerName, rax
    mov [rdi].COMPILER_ENTRY.Status, 1
    
    inc ebx
    jmp Init_loop
    
Init_done:
    lea rcx, szDone
    call PrintString
    
    ; Audit all entries
    lea rcx, szAuditStart
    call PrintString
    
    xor rbx, rbx
Audit_loop:
    cmp ebx, MAX_LANGUAGES
    jge Audit_done
    
    lea rcx, szAuditLoop
    call PrintString
    mov ecx, ebx
    call PrintInt
    lea rcx, szColon
    call PrintString
    
    mov rax, rbx
    imul rax, SIZEOF COMPILER_ENTRY
    lea rsi, CompilerRegistry
    lea rdi, [rsi + rax]
    
    mov rcx, [rdi].COMPILER_ENTRY.pLangName
    call PrintString
    lea rcx, szCrlf
    call PrintString
    
    inc ebx
    jmp Audit_loop
    
Audit_done:
    lea rcx, szAuditEnd
    call PrintString
    
    xor rcx, rcx
    call ExitProcess
    
mainCRTStartup ENDP

END
