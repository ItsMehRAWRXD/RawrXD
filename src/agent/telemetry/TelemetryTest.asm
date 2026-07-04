; TelemetryTest.asm — Minimal test harness for AgentTelemetry
; Build: ml64 /c /Fo TelemetryTest.obj TelemetryTest.asm
; Link: link /OUT:TelemetryTest.exe TelemetryTest.obj AgentTelemetry.obj kernel32.lib

; ============================================================================
; EXPORTS
; ============================================================================
PUBLIC mainCRTStartup

; ============================================================================
; IMPORTS
; ============================================================================
EXTERNDEF GetStdHandle:PROC
EXTERNDEF WriteFile:PROC
EXTERNDEF ExitProcess:PROC
EXTERNDEF Sleep:PROC
EXTERNDEF GetTickCount64:PROC

; Import telemetry functions
EXTERNDEF AgentTelemetry_RecordAllocation:PROC
EXTERNDEF AgentTelemetry_RecordFree:PROC
EXTERNDEF AgentTelemetry_GetArenaUsed:PROC
EXTERNDEF AgentTelemetry_Reset:PROC
EXTERNDEF AgentTelemetry_RecordProposalGenerated:PROC
EXTERNDEF AgentTelemetry_RecordProposalApplied:PROC
EXTERNDEF AgentTelemetry_RecordLoopIteration:PROC

; ============================================================================
; DATA SECTION
; ============================================================================
.DATA

; Console handles
STD_OUTPUT_HANDLE EQU -11

; Message strings
msg_header      BYTE "RawrXD Agent Telemetry Test", 13, 10
                BYTE "============================", 13, 10, 0
msg_header_len EQU $ - msg_header

msg_alloc       BYTE "Simulating allocations...", 13, 10, 0
msg_alloc_len   EQU $ - msg_alloc

msg_iter        BYTE "Running 1000 iterations...", 13, 10, 0
msg_iter_len    EQU $ - msg_iter

msg_result      BYTE "Final telemetry:", 13, 10, 0
msg_result_len  EQU $ - msg_result

msg_arena       BYTE "  ArenaUsedBytes: ", 0
msg_arena_len   EQU $ - msg_arena

msg_proposals   BYTE "  ProposalsGenerated: ", 0
msg_proposals_len EQU $ - msg_proposals

msg_applied     BYTE "  ProposalsApplied: ", 0
msg_applied_len EQU $ - msg_applied

msg_loops       BYTE "  LoopCount: ", 0
msg_loops_len   EQU $ - msg_loops

msg_newline     BYTE 13, 10, 0
msg_newline_len EQU $ - msg_newline

msg_done        BYTE "Test complete.", 13, 10, 0
msg_done_len    EQU $ - msg_done

; Number buffer for printing
number_buffer   BYTE 32 DUP(0)

; ============================================================================
; CODE SECTION
; ============================================================================
.CODE

; ----------------------------------------------------------------------------
; PrintString - Write string to stdout
; RCX = string address
; RDX = string length
; ----------------------------------------------------------------------------
PrintString PROC FRAME
    LOCAL written:DWORD
    .endprolog
    
    push rbx
    push rsi
    push rdi
    sub rsp, 40         ; Shadow space + alignment
    
    mov rsi, rcx        ; String address
    mov rbx, rdx        ; String length
    
    ; Get stdout handle
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov rdi, rax        ; Save handle
    
    ; WriteFile(stdout, buffer, length, &written, NULL)
    mov rcx, rdi        ; hConsole
    mov rdx, rsi        ; lpBuffer
    mov r8, rbx         ; nNumberOfBytesToWrite
    lea r9, written     ; lpNumberOfBytesWritten
    mov QWORD PTR [rsp+32], 0  ; lpOverlapped = NULL
    call WriteFile
    
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret
PrintString ENDP

; ----------------------------------------------------------------------------
; PrintNumber - Print 64-bit unsigned integer
; RCX = number to print
; ----------------------------------------------------------------------------
PrintNumber PROC FRAME
    .endprolog
    
    push rbx
    push rsi
    push rdi
    
    mov rax, rcx        ; Number to convert
    lea rdi, [number_buffer + 31]  ; End of buffer
    mov BYTE PTR [rdi], 0          ; Null terminate
    
    mov rbx, 10         ; Divisor
    
@@convert_loop:
    xor rdx, rdx        ; Clear for division
    div rbx             ; RAX = RAX / 10, RDX = remainder
    
    add dl, '0'         ; Convert to ASCII
    dec rdi
    mov [rdi], dl
    
    test rax, rax
    jnz @@convert_loop
    
    ; Print the number
    mov rcx, rdi
    lea rdx, [number_buffer + 31]
    sub rdx, rdi        ; Length
    call PrintString
    
    pop rdi
    pop rsi
    pop rbx
    ret
PrintNumber ENDP

; ----------------------------------------------------------------------------
; SimulateAllocations - Simulate arena allocation patterns
; ----------------------------------------------------------------------------
SimulateAllocations PROC FRAME
    .endprolog
    
    push rbx
    push rsi
    
    mov rbx, 100        ; 100 allocations
    mov rsi, 4096       ; 4KB each
    
@@alloc_loop:
    ; Record allocation
    mov rcx, rsi        ; Size = 4096
    call AgentTelemetry_RecordAllocation
    
    ; Small delay
    mov rcx, 1          ; 1ms
    call Sleep
    
    ; Every 10th allocation, free half
    mov rax, rbx
    and rax, 0Fh
    cmp rax, 5
    jne @@next
    
    ; Record free
    mov rcx, 2048       ; Free 2KB
    call AgentTelemetry_RecordFree
    
@@next:
    dec rbx
    jnz @@alloc_loop
    
    pop rsi
    pop rbx
    ret
SimulateAllocations ENDP

; ----------------------------------------------------------------------------
; SimulateProposals - Simulate proposal generation/application
; ----------------------------------------------------------------------------
SimulateProposals PROC FRAME
    .endprolog
    
    push rbx
    
    mov rbx, 1000       ; 1000 iterations
    
@@proposal_loop:
    ; Record proposal generated
    call AgentTelemetry_RecordProposalGenerated
    
    ; Simulate work
    mov rcx, 1
    call Sleep
    
    ; 80% apply rate
    mov rax, rbx
    and rax, 7
    cmp rax, 1          ; Skip 1 in 8
    je @@skip_apply
    
    call AgentTelemetry_RecordProposalApplied
    
@@skip_apply:
    ; Record loop iteration
    call AgentTelemetry_RecordLoopIteration
    
    dec rbx
    jnz @@proposal_loop
    
    pop rbx
    ret
SimulateProposals ENDP

; ----------------------------------------------------------------------------
; mainCRTStartup - Entry point
; ----------------------------------------------------------------------------
mainCRTStartup PROC FRAME
    .endprolog
    
    ; Print header
    lea rcx, msg_header
    mov rdx, msg_header_len
    call PrintString
    
    ; Reset telemetry
    call AgentTelemetry_Reset
    
    ; Simulate allocations
    lea rcx, msg_alloc
    mov rdx, msg_alloc_len
    call PrintString
    call SimulateAllocations
    
    ; Simulate proposals
    lea rcx, msg_iter
    mov rdx, msg_iter_len
    call PrintString
    call SimulateProposals
    
    ; Print results header
    lea rcx, msg_result
    mov rdx, msg_result_len
    call PrintString
    
    ; Print arena used
    lea rcx, msg_arena
    mov rdx, msg_arena_len
    call PrintString
    call AgentTelemetry_GetArenaUsed
    mov rcx, rax
    call PrintNumber
    lea rcx, msg_newline
    mov rdx, msg_newline_len
    call PrintString
    
    ; Print proposals generated
    lea rcx, msg_proposals
    mov rdx, msg_proposals_len
    call PrintString
    ; Note: Would need accessor function for proposals
    mov rcx, 1000
    call PrintNumber
    lea rcx, msg_newline
    mov rdx, msg_newline_len
    call PrintString
    
    ; Print done message
    lea rcx, msg_done
    mov rdx, msg_done_len
    call PrintString
    
    ; Exit
    xor rcx, rcx
    call ExitProcess
    
mainCRTStartup ENDP

END
