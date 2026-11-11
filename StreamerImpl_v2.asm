; StreamerImpl.asm - Actual implementation of streamer functions
; Writes tokens to OFF_RESP_PAYLOAD in shared memory

OPTION CASEMAP:NONE

; ----------------------------------------------------------------
; External data from orchestrator
; ----------------------------------------------------------------
EXTERN g_pShMem : QWORD

; ----------------------------------------------------------------
; Constants
; ----------------------------------------------------------------
OFF_RESP_PAYLOAD EQU 1018h
MAX_RESPONSE_SIZE EQU 0EFD8h

; ----------------------------------------------------------------
; DATA - Must come after EXTERN declarations
; ----------------------------------------------------------------
.DATA
    g_RespOffset    DD 0

; ----------------------------------------------------------------
; CODE
; ----------------------------------------------------------------
.CODE

; ----------------------------------------------------------------
; STREAMER_INIT - Initialize streaming output
; Resets response buffer offset
; Returns: rax = 0 (success)
; ----------------------------------------------------------------
STREAMER_INIT PROC EXPORT FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    ; Reset response offset
    mov dword ptr [g_RespOffset], 0
    
    ; Clear response buffer
    mov rbx, [g_pShMem]
    test rbx, rbx
    jz init_done
    
    lea rdi, [rbx + OFF_RESP_PAYLOAD]
    mov rcx, MAX_RESPONSE_SIZE
    shr rcx, 3              ; Divide by 8 for QWORD stores
    xor eax, eax
    rep stosq

init_done:
    xor eax, eax        ; Return success
    leave
    ret
STREAMER_INIT ENDP

; ----------------------------------------------------------------
; STREAMER_PUSH_TOKEN - Push a token to output
; rcx = token byte
; rdx = confidence (unused for now)
; Returns: rax = 0 (success), 1 (buffer full)
; ----------------------------------------------------------------
STREAMER_PUSH_TOKEN PROC EXPORT FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov r12d, ecx        ; Save token (use 32-bit to avoid rex prefix)
    
    ; Check bounds
    mov eax, [g_RespOffset]
    cmp eax, MAX_RESPONSE_SIZE
    jae push_full
    
    ; Write token to response buffer
    mov rbx, [g_pShMem]
    test rbx, rbx
    jz push_done
    
    mov rdi, rbx
    add rdi, OFF_RESP_PAYLOAD
    mov eax, [g_RespOffset]
    add rdi, rax
    mov byte ptr [rdi], r12b
    
    ; Increment offset
    inc dword ptr [g_RespOffset]

push_done:
    xor eax, eax        ; Return success
    leave
    ret

push_full:
    mov eax, 1          ; Return buffer full
    leave
    ret
STREAMER_PUSH_TOKEN ENDP

; ----------------------------------------------------------------
; STREAMER_FLUSH - Flush buffered tokens
; Sets response length in shared memory
; Returns: rax = 0 (success)
; ----------------------------------------------------------------
STREAMER_FLUSH PROC EXPORT FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    ; Set response length
    mov rbx, [g_pShMem]
    test rbx, rbx
    jz flush_done
    
    mov eax, [g_RespOffset]
    mov [rbx + 14h], eax    ; OFF_RESP_LEN = 0x14

flush_done:
    xor eax, eax        ; Return success
    leave
    ret
STREAMER_FLUSH ENDP

END
