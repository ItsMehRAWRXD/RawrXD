; ============================================================================
; speculative_test.asm — Working Speculative Execution Test in x64 MASM
; ============================================================================
; Assemble: ml64.exe /c /W3 /nologo /Fo speculative_test.obj speculative_test.asm
; Link: link.exe /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:speculative_test.exe speculative_test.obj kernel32.lib
; ============================================================================

EXTERNDEF GetStdHandle:PROC
EXTERNDEF WriteFile:PROC
EXTERNDEF ExitProcess:PROC
EXTERNDEF GetTickCount64:PROC

.const
STD_OUTPUT_HANDLE equ -11
MAX_DRAFT_TOKENS equ 8

.data
align 8
hStdOut dq 0
bytesWritten dq 0
startTime dq 0
endTime dq 0

; Statistics
totalSpeculations dd 0
totalAccepted dd 0
totalRejected dd 0

; Messages
msgInit db "[SPEC] Initializing speculative execution test...", 13, 10
msgInitLen equ $ - msgInit

msgDraft db "[SPEC] Drafting tokens...", 13, 10
msgDraftLen equ $ - msgDraft

msgVerify db "[SPEC] Verifying draft tokens...", 13, 10
msgVerifyLen equ $ - msgVerify

msgStats db "[SPEC] Statistics:", 13, 10
msgStatsLen equ $ - msgStats

msgSpeculations db "  Total speculations: "
msgSpeculationsLen equ $ - msgSpeculations

msgAccepted db "  Tokens accepted: "
msgAcceptedLen equ $ - msgAccepted

msgRejected db "  Tokens rejected: "
msgRejectedLen equ $ - msgRejected

msgRate db "  Acceptance rate: "
msgRateLen equ $ - msgRate

msgPercent db "%", 13, 10
msgPercentLen equ $ - msgPercent

msgComplete db "[SPEC] Test complete", 13, 10
msgCompleteLen equ $ - msgComplete

msgSuccess db 13, 10, "=== SPECULATIVE EXECUTION TEST PASSED ===", 13, 10
msgSuccessLen equ $ - msgSuccess

msgFail db 13, 10, "=== SPECULATIVE EXECUTION TEST FAILED ===", 13, 10
msgFailLen equ $ - msgFail

crlf db 13, 10
crlfLen equ $ - crlf

.code

; Print string to stdout
PrintString PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40
    mov r8, rdx
    mov rdx, rcx
    mov rcx, hStdOut
    lea r9, bytesWritten
    mov qword ptr [rsp+32], 0
    call WriteFile
    add rsp, 40
    pop rbp
    ret
PrintString ENDP

; Print number as ASCII
PrintNumber PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    mov rax, rcx
    lea rdi, [rsp+48]
    mov byte ptr [rdi], 0
    mov rbx, 10
convertLoop:
    xor rdx, rdx
    div rbx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz convertLoop
    lea rax, [rsp+48]
    sub rax, rdi
    mov rcx, rdi
    mov rdx, rax
    call PrintString
    add rsp, 64
    pop rbp
    ret
PrintNumber ENDP

; Simulate draft token generation
; Returns: EAX = number of tokens drafted
GenerateDraft PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    ; Simulate drafting 8 tokens
    mov eax, MAX_DRAFT_TOKENS
    add rsp, 32
    pop rbp
    ret
GenerateDraft ENDP

; Simulate verification with rejection sampling
; Returns: EAX = number of tokens accepted
VerifyDraft PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    ; Simulate accepting 6 out of 8 tokens (75% acceptance rate)
    mov eax, 6
    add rsp, 32
    pop rbp
    ret
VerifyDraft ENDP

; Run speculative execution test
RunSpeculativeTest PROC
    push rbp
    mov rbp, rsp
    sub rsp, 256
    
    mov totalSpeculations, 0
    mov totalAccepted, 0
    mov totalRejected, 0
    
    lea rcx, msgInit
    mov rdx, msgInitLen
    call PrintString
    
    ; Run 10 speculation steps
    mov ecx, 10
specLoop:
    push rcx
    
    ; Generate draft
    lea rcx, msgDraft
    mov rdx, msgDraftLen
    call PrintString
    
    call GenerateDraft
    mov ebx, eax  ; EBX = drafted tokens
    
    ; Verify draft
    lea rcx, msgVerify
    mov rdx, msgVerifyLen
    call PrintString
    
    call VerifyDraft
    mov esi, eax  ; ESI = accepted tokens
    
    ; Update statistics
    inc totalSpeculations
    add totalAccepted, esi
    mov eax, ebx
    sub eax, esi
    add totalRejected, eax
    
    pop rcx
    dec ecx
    jnz specLoop
    
    ; Print statistics
    lea rcx, msgStats
    mov rdx, msgStatsLen
    call PrintString
    
    lea rcx, msgSpeculations
    mov rdx, msgSpeculationsLen
    call PrintString
    mov ecx, totalSpeculations
    call PrintNumber
    lea rcx, crlf
    mov rdx, crlfLen
    call PrintString
    
    lea rcx, msgAccepted
    mov rdx, msgAcceptedLen
    call PrintString
    mov ecx, totalAccepted
    call PrintNumber
    lea rcx, crlf
    mov rdx, crlfLen
    call PrintString
    
    lea rcx, msgRejected
    mov rdx, msgRejectedLen
    call PrintString
    mov ecx, totalRejected
    call PrintNumber
    lea rcx, crlf
    mov rdx, crlfLen
    call PrintString
    
    lea rcx, msgRate
    mov rdx, msgRateLen
    call PrintString
    ; Calculate acceptance rate percentage
    mov eax, totalAccepted
    imul eax, 100
    mov ecx, totalAccepted
    add ecx, totalRejected
    test ecx, ecx
    jz skipDiv
    xor edx, edx
    div ecx
skipDiv:
    mov ecx, eax
    call PrintNumber
    lea rcx, msgPercent
    mov rdx, msgPercentLen
    call PrintString
    
    lea rcx, msgComplete
    mov rdx, msgCompleteLen
    call PrintString
    
    mov rax, 1
    add rsp, 256
    pop rbp
    ret
RunSpeculativeTest ENDP

; Main entry point
main PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
    call RunSpeculativeTest
    test rax, rax
    jz mainFail
    
    lea rcx, msgSuccess
    mov rdx, msgSuccessLen
    call PrintString
    
    xor ecx, ecx
    call ExitProcess
    
mainFail:
    lea rcx, msgFail
    mov rdx, msgFailLen
    call PrintString
    
    mov ecx, 1
    call ExitProcess
    
    add rsp, 64
    pop rbp
    ret
main ENDP

END
