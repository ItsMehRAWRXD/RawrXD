; rawr_native_receipt_x64.asm
option casemap:none
EXTERN QueryPerformanceCounter:PROC

RNRC_REQUEST_ID           EQU 0
RNRC_QPC_BEGIN            EQU 8
RNRC_QPC_ENGINE           EQU 16
RNRC_QPC_FIRST            EQU 24
RNRC_QPC_END              EQU 32
RNRC_PROFILE_ID           EQU 40
RNRC_REQUESTED_FLAGS      EQU 44
RNRC_PREPARED_FLAGS       EQU 48
RNRC_ENGINE_FLAGS         EQU 52
RNRC_BACKEND_ID           EQU 56
RNRC_ENGINE_STATUS        EQU 60
RNRC_GENERATED_TOKENS     EQU 64
RNRC_SIZE                 EQU 72
RNRC_COUNT                EQU 128

.data
align 16
g_next_id qword 0
g_receipts byte (RNRC_SIZE * RNRC_COUNT) dup(0)

.code
RN_ReceiptPtr proc
    mov rax, rcx
    and eax, RNRC_COUNT-1
    imul rax, RNRC_SIZE
    lea rdx, g_receipts
    add rax, rdx
    ret
RN_ReceiptPtr endp

RawrNative_ReceiptBegin proc public
    push rbx
    push rsi
    push rdi
    sub rsp, 30h
    mov ebx, ecx
    mov esi, edx
    mov edi, r8d
    mov rax, 1
    lock xadd qword ptr [g_next_id], rax
    inc rax
    mov qword ptr [rsp+20h], rax
    mov rcx, rax
    call RN_ReceiptPtr
    mov rdx, rax
    xor eax, eax
    mov qword ptr [rdx+0], rax
    mov qword ptr [rdx+8], rax
    mov qword ptr [rdx+16], rax
    mov qword ptr [rdx+24], rax
    mov qword ptr [rdx+32], rax
    mov qword ptr [rdx+40], rax
    mov qword ptr [rdx+48], rax
    mov qword ptr [rdx+56], rax
    mov qword ptr [rdx+64], rax
    mov rax, qword ptr [rsp+20h]
    mov qword ptr [rdx+RNRC_REQUEST_ID], rax
    mov dword ptr [rdx+RNRC_PROFILE_ID], ebx
    mov dword ptr [rdx+RNRC_REQUESTED_FLAGS], esi
    mov dword ptr [rdx+RNRC_PREPARED_FLAGS], edi
    lea rcx, [rdx+RNRC_QPC_BEGIN]
    call QueryPerformanceCounter
    mov rax, qword ptr [rsp+20h]
    add rsp, 30h
    pop rdi
    pop rsi
    pop rbx
    ret
RawrNative_ReceiptBegin endp

RawrNative_ReceiptEngineEnter proc public
    push rbx
    push rsi
    sub rsp, 28h
    mov rbx, rcx
    mov esi, edx
    mov r10d, r8d
    call RN_ReceiptPtr
    cmp qword ptr [rax+RNRC_REQUEST_ID], rbx
    jne short REE_Done
    mov dword ptr [rax+RNRC_BACKEND_ID], esi
    mov dword ptr [rax+RNRC_ENGINE_FLAGS], r10d
    lea rcx, [rax+RNRC_QPC_ENGINE]
    call QueryPerformanceCounter
REE_Done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
RawrNative_ReceiptEngineEnter endp

RawrNative_ReceiptFirstToken proc public
    push rbx
    sub rsp, 20h
    mov rbx, rcx
    call RN_ReceiptPtr
    cmp qword ptr [rax+RNRC_REQUEST_ID], rbx
    jne short RFT_Done
    cmp qword ptr [rax+RNRC_QPC_FIRST], 0
    jne short RFT_Done
    lea rcx, [rax+RNRC_QPC_FIRST]
    call QueryPerformanceCounter
RFT_Done:
    add rsp, 20h
    pop rbx
    ret
RawrNative_ReceiptFirstToken endp

RawrNative_ReceiptComplete proc public
    push rbx
    push rsi
    push rdi
    sub rsp, 20h
    mov rbx, rcx
    mov rsi, rdx
    mov edi, r8d
    call RN_ReceiptPtr
    cmp qword ptr [rax+RNRC_REQUEST_ID], rbx
    jne short RC_Done
    mov qword ptr [rax+RNRC_GENERATED_TOKENS], rsi
    mov dword ptr [rax+RNRC_ENGINE_STATUS], edi
    lea rcx, [rax+RNRC_QPC_END]
    call QueryPerformanceCounter
RC_Done:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
RawrNative_ReceiptComplete endp

RawrNative_ReceiptGet proc public
    push rbx
    push rsi
    push rdi
    sub rsp, 20h
    mov rbx, rcx
    mov rdi, rdx
    test rdi, rdi
    jz short RG_Fail
    call RN_ReceiptPtr
    cmp qword ptr [rax+RNRC_REQUEST_ID], rbx
    jne short RG_Fail
    mov rsi, rax
    mov ecx, RNRC_SIZE/8
RG_Copy:
    mov rax, qword ptr [rsi]
    mov qword ptr [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz short RG_Copy
    xor eax, eax
    jmp short RG_Done
RG_Fail:
    mov eax, 1
RG_Done:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
RawrNative_ReceiptGet endp

RawrNative_ReceiptLatestId proc public
    mov rax, qword ptr [g_next_id]
    ret
RawrNative_ReceiptLatestId endp
end
