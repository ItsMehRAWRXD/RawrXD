; Minimal IDE integration test
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
szEntry         BYTE "Entry 0 name: ", 0
szCrlf          BYTE 13, 10, 0
szMASM          BYTE "MASM", 0
szPath          BYTE "ml64.exe", 0
szLexer         BYTE "Custom", 0

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
    
    ; Init entry 0
    lea rdi, CompilerRegistry
    mov [rdi].COMPILER_ENTRY.LangID, 0
    mov [rdi].COMPILER_ENTRY.Tier, 1
    lea rax, szMASM
    mov [rdi].COMPILER_ENTRY.pLangName, rax
    lea rax, szPath
    mov [rdi].COMPILER_ENTRY.pCompilerPath, rax
    lea rax, szLexer
    mov [rdi].COMPILER_ENTRY.pLexerName, rax
    mov [rdi].COMPILER_ENTRY.Status, 1
    
    lea rcx, szDone
    call PrintString
    
    ; Print entry 0 name
    lea rcx, szEntry
    call PrintString
    mov rcx, [rdi].COMPILER_ENTRY.pLangName
    call PrintString
    lea rcx, szCrlf
    call PrintString
    
    xor rcx, rcx
    call ExitProcess
    
mainCRTStartup ENDP

END
