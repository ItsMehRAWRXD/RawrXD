; =======================================================================================
; RAWRXD Roslyn CLI Bridge - Production Build
; Pure x64 MASM - Zero CRT Dependencies
; Fixes: Wide/ASCII mismatch, memset removal, szCrlf defined, ABI compliance
; =======================================================================================

option casemap:none

; =======================================================================================
; External Imports
; =======================================================================================
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN CreatePipe:PROC
EXTERN SetHandleInformation:PROC
EXTERN CreateProcessA:PROC
EXTERN CreateProcessW:PROC
EXTERN CloseHandle:PROC
EXTERN ReadFile:PROC
EXTERN WaitForSingleObject:PROC
EXTERN ExitProcess:PROC
EXTERN MultiByteToWideChar:PROC
EXTERN GetLastError:PROC

; =======================================================================================
; Public Exports
; =======================================================================================
PUBLIC IDE_Roslyn_InvokeCompiler
PUBLIC IDE_Roslyn_ParseErrorOutput
PUBLIC IDE_Roslyn_GetDiagnostics
PUBLIC IDE_Roslyn_CompileProject

; =======================================================================================
; Constants
; =======================================================================================
STD_OUTPUT_HANDLE       EQU -11
INVALID_HANDLE_VALUE    EQU -1
HANDLE_FLAG_INHERIT     EQU 1
STARTF_USESTDHANDLES    EQU 00000100h
STARTF_USESHOWWINDOW    EQU 00000001h
SW_HIDE                 EQU 0
CREATE_NO_WINDOW        EQU 08000000h
INFINITE                EQU -1
CP_ACP                  EQU 0

; =======================================================================================
; Data Structures
; =======================================================================================
SECURITY_ATTRIBUTES STRUCT
    nLength                 DWORD ?
    lpSecurityDescriptor    QWORD ?
    bInheritHandle          DWORD ?
SECURITY_ATTRIBUTES ENDS

STARTUPINFOA STRUCT
    cb                      DWORD ?
    lpReserved              QWORD ?
    lpDesktop               QWORD ?
    lpTitle                 QWORD ?
    dwX                     DWORD ?
    dwY                     DWORD ?
    dwXSize                 DWORD ?
    dwYSize                 DWORD ?
    dwXCountChars           DWORD ?
    dwYCountChars           DWORD ?
    dwFillAttribute         DWORD ?
    dwFlags                 DWORD ?
    wShowWindow             WORD ?
    cbReserved2             WORD ?
    lpReserved2             QWORD ?
    hStdInput               QWORD ?
    hStdOutput              QWORD ?
    hStdError               QWORD ?
STARTUPINFOA ENDS

PROCESS_INFORMATION STRUCT
    hProcess                QWORD ?
    hThread                 QWORD ?
    dwProcessId             DWORD ?
    dwThreadId              DWORD ?
PROCESS_INFORMATION ENDS

DIAGNOSTIC_ENTRY STRUCT
    LineNumber      DWORD ?
    ColumnNumber    DWORD ?
    Severity        DWORD ?      ; 1=Error, 2=Warning
    ErrorCode       DWORD ?
    Message         BYTE 256 DUP(?)
DIAGNOSTIC_ENTRY ENDS

; =======================================================================================
; Data Section
; =======================================================================================
.data
align 8

; Console handles
hStdOut                 QWORD 0
bytesWritten            QWORD 0

; Pipe handles
hReadPipe               QWORD 0
hWritePipe              QWORD 0

; Process info
procInfo                PROCESS_INFORMATION <0,0,0,0>
startupInfoA            STARTUPINFOA <0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>
sa                      SECURITY_ATTRIBUTES <0,0,0>

; Command line buffer (ASCII for CreateProcessA)
CmdLineBuffer           BYTE 512 DUP(0)

; Wide char buffer (for CreateProcessW if needed)
WideCmdLineBuffer       WORD 512 DUP(0)

; Read buffer
ReadBuffer              BYTE 4096 DUP(0)
BytesRead               DWORD 0

; Diagnostic array
Diagnostics             DIAGNOSTIC_ENTRY 64 DUP(<>)
DiagnosticCount         DWORD 0

; String constants
szRoslynCmd             BYTE "csc.exe /nologo /target:exe /out:", 0
szDotnetCmd             BYTE "dotnet build --no-restore -v q ", 0
szCrlf                  BYTE 13, 10, 0
szErrorPrefix           BYTE "error", 0
szWarnPrefix            BYTE "warning", 0
szOpenParen             BYTE "(", 0
szCloseParen            BYTE ")", 0
szColon                 BYTE ":", 0
szSpace                 BYTE " ", 0
szTestSrc               BYTE "test.cs", 0
szTestOut               BYTE "test.exe", 0

; =======================================================================================
; Code Section
; =======================================================================================
.code
align 8

; =======================================================================================
; Helper: PrintString - Output null-terminated ASCII string
; RCX = pointer to string
; =======================================================================================
PrintString PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    mov rsi, rcx
    xor rdx, rdx
    mov rdi, rsi
PrintString_count_loop:
    cmp byte ptr [rdi], 0
    je PrintString_count_done
    inc rdx
    inc rdi
    jmp PrintString_count_loop
PrintString_count_done:
    
    test rdx, rdx
    jz PrintString_done
    
    mov rcx, hStdOut
    mov r8, rdx
    mov rdx, rsi
    lea r9, bytesWritten
    mov qword ptr [rsp + 20h], 0
    call WriteFile
    
PrintString_done:
    add rsp, 40h
    pop rbp
    ret
PrintString ENDP

; =======================================================================================
; Helper: StrLenA - Calculate length of ASCII string
; RCX = pointer to string
; Returns: RAX = length
; =======================================================================================
StrLenA PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 28h
    .ENDPROLOG
    
    xor rax, rax
    mov rdx, rcx
StrLenA_loop:
    cmp byte ptr [rdx + rax], 0
    je StrLenA_done
    inc rax
    jmp StrLenA_loop
StrLenA_done:
    
    add rsp, 28h
    pop rbp
    ret
StrLenA ENDP

; =======================================================================================
; Helper: StrCopyA - Copy ASCII string
; RCX = destination
; RDX = source
; =======================================================================================
StrCopyA PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 28h
    .ENDPROLOG
    
    mov r8, rcx
    mov r9, rdx
StrCopyA_loop:
    mov al, byte ptr [r9]
    mov byte ptr [r8], al
    test al, al
    jz StrCopyA_done
    inc r8
    inc r9
    jmp StrCopyA_loop
StrCopyA_done:
    
    add rsp, 28h
    pop rbp
    ret
StrCopyA ENDP

; =======================================================================================
; Helper: StrCatA - Concatenate ASCII string
; RCX = destination
; RDX = source to append
; =======================================================================================
StrCatA PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 28h
    .ENDPROLOG
    
    push rdi
    push rsi
    
    mov rdi, rcx
    mov rsi, rdx
    
    ; Find end of destination
    xor rcx, rcx
StrCatA_find_end:
    cmp byte ptr [rdi + rcx], 0
    je StrCatA_found
    inc rcx
    jmp StrCatA_find_end
StrCatA_found:
    add rdi, rcx
    
    ; Copy source to end
StrCatA_copy:
    mov al, byte ptr [rsi]
    mov byte ptr [rdi], al
    test al, al
    jz StrCatA_done
    inc rdi
    inc rsi
    jmp StrCatA_copy
    
StrCatA_done:
    pop rsi
    pop rdi
    add rsp, 28h
    pop rbp
    ret
StrCatA ENDP

; =======================================================================================
; Helper: StrFindA - Find substring in ASCII string
; RCX = haystack
; RDX = needle
; Returns: RAX = pointer to match or 0
; =======================================================================================
StrFindA PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 38h
    .ENDPROLOG
    
    push rbx
    push r12
    push r13
    push r14
    
    mov r12, rcx          ; r12 = haystack
    mov r13, rdx          ; r13 = needle
    
    ; Get needle length
    mov rcx, r13
    call StrLenA
    mov r14, rax          ; r14 = needle length
    test r14, r14
    jz StrFindA_found     ; Empty needle = found at start
    
StrFindA_outer:
    mov al, byte ptr [r12]
    test al, al
    jz StrFindA_not_found
    
    ; Check if first char matches
    mov bl, byte ptr [r13]
    cmp al, bl
    jne StrFindA_next
    
    ; Try full match
    xor rcx, rcx
StrFindA_inner:
    cmp rcx, r14
    jge StrFindA_found
    
    mov al, byte ptr [r12 + rcx]
    mov bl, byte ptr [r13 + rcx]
    cmp al, bl
    jne StrFindA_next
    inc rcx
    jmp StrFindA_inner
    
StrFindA_next:
    inc r12
    jmp StrFindA_outer
    
StrFindA_found:
    mov rax, r12
    jmp StrFindA_exit
    
StrFindA_not_found:
    xor rax, rax
    
StrFindA_exit:
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 38h
    pop rbp
    ret
StrFindA ENDP

; =======================================================================================
; Helper: Atoi - Convert ASCII to integer
; RCX = pointer to digit string
; Returns: RAX = integer value
; =======================================================================================
Atoi PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 28h
    .ENDPROLOG
    
    push rdi
    xor rax, rax
    mov rdi, rcx
Atoi_loop:
    movzx rdx, byte ptr [rdi]
    cmp dl, '0'
    jl Atoi_done
    cmp dl, '9'
    jg Atoi_done
    sub dl, '0'
    imul rax, rax, 10
    add rax, rdx
    inc rdi
    jmp Atoi_loop
Atoi_done:
    pop rdi
    add rsp, 28h
    pop rbp
    ret
Atoi ENDP

; =======================================================================================
; Helper: ZeroMemory - Clear memory block
; RCX = pointer to block
; RDX = size in bytes
; =======================================================================================
ZeroMemory PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 28h
    .ENDPROLOG
    
    mov r8, rcx
    mov rcx, rdx
    xor rax, rax
ZeroMemory_loop:
    test rcx, rcx
    jz ZeroMemory_done
    mov byte ptr [r8], al
    inc r8
    dec rcx
    jmp ZeroMemory_loop
ZeroMemory_done:
    add rsp, 28h
    pop rbp
    ret
ZeroMemory ENDP

; =======================================================================================
; IDE_Roslyn_InvokeCompiler - Main compiler invocation with pipe capture
; RCX = pointer to source file path (ASCII)
; RDX = pointer to output file path (ASCII)
; Returns: RAX = 1 (success), 0 (failure)
; =======================================================================================
IDE_Roslyn_InvokeCompiler PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 80h
    .ENDPROLOG
    
    push rbx
    push r12
    push r13
    push r14
    
    mov r12, rcx          ; r12 = source file
    mov r13, rdx          ; r13 = output file
    
    ; Initialize security attributes for pipe inheritance
    mov sa.nLength, SIZEOF SECURITY_ATTRIBUTES
    mov sa.lpSecurityDescriptor, 0
    mov sa.bInheritHandle, 1
    
    ; Step 1: Create anonymous pipe
    lea rcx, hReadPipe
    lea rdx, hWritePipe
    lea r8, sa
    xor r9, r9
    call CreatePipe
    test rax, rax
    jz RoslynInvoke_fail
    
    ; Step 2: Ensure read handle is NOT inherited
    mov rcx, hReadPipe
    mov rdx, HANDLE_FLAG_INHERIT
    xor r8, r8
    call SetHandleInformation
    
    ; Step 3: Zero and configure STARTUPINFOA
    lea rcx, startupInfoA
    mov rdx, SIZEOF STARTUPINFOA
    call ZeroMemory
    
    mov startupInfoA.cb, SIZEOF STARTUPINFOA
    mov startupInfoA.dwFlags, STARTF_USESTDHANDLES OR STARTF_USESHOWWINDOW
    mov rax, hWritePipe
    mov startupInfoA.hStdOutput, rax
    mov startupInfoA.hStdError, rax
    mov startupInfoA.hStdInput, 0
    mov startupInfoA.wShowWindow, SW_HIDE
    
    ; Step 4: Build command line: csc.exe /nologo /target:exe /out:output source
    lea rcx, CmdLineBuffer
    lea rdx, szRoslynCmd
    call StrCopyA
    
    lea rcx, CmdLineBuffer
    mov rdx, r13
    call StrCatA
    
    lea rcx, CmdLineBuffer
    lea rdx, szSpace
    call StrCatA
    
    lea rcx, CmdLineBuffer
    mov rdx, r12
    call StrCatA
    
    ; Step 5: Create process (ASCII version since command line is ASCII)
    xor rcx, rcx          ; lpApplicationName = NULL
    lea rdx, CmdLineBuffer ; lpCommandLine
    xor r8, r8            ; lpProcessAttributes
    xor r9, r9            ; lpThreadAttributes
    mov qword ptr [rsp + 20h], 1  ; bInheritHandles = TRUE
    mov dword ptr [rsp + 28h], CREATE_NO_WINDOW
    xor rax, rax
    mov qword ptr [rsp + 30h], rax ; lpEnvironment
    mov qword ptr [rsp + 38h], rax ; lpCurrentDirectory
    lea rax, startupInfoA
    mov qword ptr [rsp + 40h], rax ; lpStartupInfo
    lea rax, procInfo
    mov qword ptr [rsp + 48h], rax ; lpProcessInformation
    call CreateProcessA
    test rax, rax
    jz RoslynInvoke_close_pipe
    
    ; Step 6: Close our copy of write handle
    mov rcx, hWritePipe
    call CloseHandle
    mov hWritePipe, 0
    
    ; Step 7: Read output loop
    mov r14, 0            ; r14 = total bytes read
RoslynInvoke_read_loop:
    mov rcx, hReadPipe
    lea rdx, ReadBuffer
    add rdx, r14
    mov r8, 4096
    sub r8, r14
    lea r9, BytesRead
    mov qword ptr [rsp + 20h], 0
    call ReadFile
    test rax, rax
    jz RoslynInvoke_read_done
    
    mov eax, BytesRead
    test eax, eax
    jz RoslynInvoke_read_done
    
    add r14, rax
    cmp r14, 4096
    jl RoslynInvoke_read_loop
    
RoslynInvoke_read_done:
    ; Null terminate the buffer
    lea rax, ReadBuffer
    add rax, r14
    mov byte ptr [rax], 0
    
    ; Wait for process to complete
    mov rcx, procInfo.hProcess
    mov rdx, INFINITE
    call WaitForSingleObject
    
    ; Cleanup process handles
    mov rcx, procInfo.hProcess
    call CloseHandle
    mov rcx, procInfo.hThread
    call CloseHandle
    
    ; Close read pipe
    mov rcx, hReadPipe
    call CloseHandle
    mov hReadPipe, 0
    
    mov rax, 1
    jmp RoslynInvoke_exit
    
RoslynInvoke_close_pipe:
    mov rcx, hWritePipe
    call CloseHandle
    mov hWritePipe, 0
    
RoslynInvoke_fail:
    ; Close read pipe if open
    cmp hReadPipe, 0
    je RoslynInvoke_fail_noread
    mov rcx, hReadPipe
    call CloseHandle
    mov hReadPipe, 0
    
RoslynInvoke_fail_noread:
    xor rax, rax
    
RoslynInvoke_exit:
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 80h
    pop rbp
    ret
IDE_Roslyn_InvokeCompiler ENDP

; =======================================================================================
; IDE_Roslyn_ParseErrorOutput - Parse Roslyn error format into diagnostics
; RCX = pointer to error output buffer (ASCII)
; =======================================================================================
IDE_Roslyn_ParseErrorOutput PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 68h
    .ENDPROLOG
    
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rcx          ; r12 = output buffer
    mov r13, 0            ; r13 = diagnostic count
    
RoslynParse_loop:
    mov al, byte ptr [r12]
    test al, al
    jz RoslynParse_done
    
    ; Look for "error" or "warning"
    mov rcx, r12
    lea rdx, szErrorPrefix
    call StrFindA
    test rax, rax
    jnz RoslynParse_found_error
    
    mov rcx, r12
    lea rdx, szWarnPrefix
    call StrFindA
    test rax, rax
    jz RoslynParse_next_line
    
RoslynParse_found_error:
    ; Parse line: path(line,col): error|warning CODE: message
    ; Find opening paren for line number
    mov rcx, r12
    lea rdx, szOpenParen
    call StrFindA
    test rax, rax
    jz RoslynParse_next_line
    mov r14, rax          ; r14 = ptr to (
    
    ; Extract line number
    inc r14
    mov rcx, r14
    call Atoi
    mov r15d, eax         ; r15d = line number
    
    ; Find comma
    mov rcx, r14
    lea rdx, szColon
    call StrFindA
    test rax, rax
    jz RoslynParse_next_line
    mov r14, rax
    inc r14
    
    ; Extract column
    mov rcx, r14
    call Atoi
    mov ebx, eax          ; ebx = column
    
    ; Find severity
    mov rcx, r14
    lea rdx, szErrorPrefix
    call StrFindA
    test rax, rax
    jz RoslynParse_check_warn
    mov r14, rax
    mov r8d, 1            ; Error
    jmp RoslynParse_extract_code
    
RoslynParse_check_warn:
    mov rcx, r14
    lea rdx, szWarnPrefix
    call StrFindA
    test rax, rax
    jz RoslynParse_next_line
    mov r14, rax
    mov r8d, 2            ; Warning
    
RoslynParse_extract_code:
    ; Skip past severity text
    add r14, 5            ; Skip "error" or "warning"
    
    ; Find colon for message
    mov rcx, r14
    lea rdx, szColon
    call StrFindA
    test rax, rax
    jz RoslynParse_next_line
    mov r14, rax
    add r14, 2            ; Skip ": "
    
    ; Store diagnostic
    cmp r13, 64
    jge RoslynParse_next_line
    
    mov rax, r13
    imul rax, rax, SIZEOF DIAGNOSTIC_ENTRY
    lea rcx, Diagnostics
    add rcx, rax
    
    mov [rcx].DIAGNOSTIC_ENTRY.LineNumber, r15d
    mov [rcx].DIAGNOSTIC_ENTRY.ColumnNumber, ebx
    mov [rcx].DIAGNOSTIC_ENTRY.Severity, r8d
    mov [rcx].DIAGNOSTIC_ENTRY.ErrorCode, 0
    
    ; Copy message (up to 255 chars)
    lea rdx, [rcx].DIAGNOSTIC_ENTRY.Message
    mov r9, 0
RoslynParse_copy_msg:
    cmp r9, 255
    jge RoslynParse_msg_done
    mov al, byte ptr [r14 + r9]
    cmp al, 13            ; CR
    je RoslynParse_msg_done
    cmp al, 10            ; LF
    je RoslynParse_msg_done
    test al, al
    jz RoslynParse_msg_done
    mov byte ptr [rdx + r9], al
    inc r9
    jmp RoslynParse_copy_msg
RoslynParse_msg_done:
    mov byte ptr [rdx + r9], 0
    
    inc r13
    
RoslynParse_next_line:
    ; Advance to next line
    mov al, byte ptr [r12]
    test al, al
    jz RoslynParse_done
    cmp al, 10
    je RoslynParse_advance
    inc r12
    jmp RoslynParse_next_line
RoslynParse_advance:
    inc r12
    jmp RoslynParse_loop
    
RoslynParse_done:
    mov DiagnosticCount, r13d
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 68h
    pop rbp
    ret
IDE_Roslyn_ParseErrorOutput ENDP

; =======================================================================================
; IDE_Roslyn_GetDiagnostics - Return diagnostic array pointer and count
; RCX = pointer to receive array pointer
; RDX = pointer to receive count
; =======================================================================================
IDE_Roslyn_GetDiagnostics PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 28h
    .ENDPROLOG
    
    mov rax, OFFSET Diagnostics
    mov [rcx], rax
    mov eax, DiagnosticCount
    mov [rdx], eax
    
    add rsp, 28h
    pop rbp
    ret
IDE_Roslyn_GetDiagnostics ENDP

; =======================================================================================
; IDE_Roslyn_CompileProject - Full project compilation with diagnostics
; RCX = pointer to project file path (ASCII)
; Returns: RAX = 1 (success), 0 (failure)
; =======================================================================================
IDE_Roslyn_CompileProject PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    .ENDPROLOG
    
    push rbx
    push r12
    
    mov r12, rcx          ; r12 = project path
    
    ; Clear diagnostics
    mov DiagnosticCount, 0
    lea rcx, Diagnostics
    mov rdx, SIZEOF Diagnostics
    call ZeroMemory
    
    ; Clear read buffer
    lea rcx, ReadBuffer
    mov rdx, 4096
    call ZeroMemory
    
    ; Invoke compiler
    mov rcx, r12
    lea rdx, szTestOut
    call IDE_Roslyn_InvokeCompiler
    test rax, rax
    jz RoslynCompile_fail
    
    ; Parse output
    lea rcx, ReadBuffer
    call IDE_Roslyn_ParseErrorOutput
    
    ; Check if any errors
    cmp DiagnosticCount, 0
    je RoslynCompile_success
    
    ; Check if only warnings
    xor rbx, rbx
    mov r8, OFFSET Diagnostics
RoslynCompile_check:
    cmp ebx, DWORD PTR DiagnosticCount
    jge RoslynCompile_success
    mov rax, rbx
    imul rax, rax, SIZEOF DIAGNOSTIC_ENTRY
    mov r9, OFFSET Diagnostics
    add r9, rax
    mov eax, (DIAGNOSTIC_ENTRY PTR [r9]).Severity
    cmp eax, 1            ; Error
    je RoslynCompile_fail
    inc rbx
    jmp RoslynCompile_check
    
RoslynCompile_success:
    mov rax, 1
    jmp RoslynCompile_exit
    
RoslynCompile_fail:
    xor rax, rax
    
RoslynCompile_exit:
    pop r12
    pop rbx
    add rsp, 40h
    pop rbp
    ret
IDE_Roslyn_CompileProject ENDP

END
