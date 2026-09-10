; KN_O3KKEN_smoke.asm — E2E: VENTI→prefetch→handoff→consumer→receipt.
; Exit code = receipt.result (10+20+12=42). Links KN_O3KKEN.obj.
option casemap:none
include KN_O3KKEN.inc

ExitProcess PROTO :QWORD
KN_O3KKEN PROTO

.data
SmokeSource db 10,20,12
ALIGN 8
SmokeChair  KN_CHAIR <>
SmokeVenti  KN_VENTI <>
SmokeReceipt KN_RECEIPT <>
.data?
SmokeBuffer db 64 dup(?)

.code
; rcx=chair rdx=venti r8=&result ; rax!=0 ok
SmokeConsume PROC
    xor     rax, rax
    mov     r9, [rcx].KN_CHAIR.payload_ptr
    mov     r10, [rdx].KN_VENTI.copy_bytes
    xor     r11, r11
sc_loop:
    cmp     r11, r10
    jae     sc_done
    movzx   eax, BYTE PTR [r9+r11]
    add     rax, QWORD PTR [r8]
    mov     QWORD PTR [r8], rax
    inc     r11
    jmp     sc_loop
sc_done:
    mov     rax, 1
    ret
SmokeConsume ENDP

main PROC
    sub     rsp, 28h
    mov     QWORD PTR [SmokeChair].KN_CHAIR.object_id, 1
    mov     QWORD PTR [SmokeChair].KN_CHAIR.generation, 1
    mov     QWORD PTR [SmokeChair].KN_CHAIR.owner, 1
    xor     rax, rax
    mov     QWORD PTR [SmokeChair].KN_CHAIR.state, rax
    lea     rax, SmokeBuffer
    mov     QWORD PTR [SmokeChair].KN_CHAIR.payload_ptr, rax
    mov     QWORD PTR [SmokeChair].KN_CHAIR.payload_bytes, 64
    lea     rax, SmokeChair
    mov     QWORD PTR [SmokeVenti].KN_VENTI.chair_ptr, rax
    mov     QWORD PTR [SmokeVenti].KN_VENTI.object_id, 1
    mov     QWORD PTR [SmokeVenti].KN_VENTI.generation, 1
    mov     QWORD PTR [SmokeVenti].KN_VENTI.owner_from, 1
    mov     QWORD PTR [SmokeVenti].KN_VENTI.owner_to, 2
    lea     rax, SmokeConsume
    mov     QWORD PTR [SmokeVenti].KN_VENTI.consumer_fn, rax
    lea     rax, SmokeSource
    mov     QWORD PTR [SmokeVenti].KN_VENTI.src_ptr, rax
    mov     QWORD PTR [SmokeVenti].KN_VENTI.copy_bytes, 3
    xor     rax, rax
    mov     QWORD PTR [SmokeVenti].KN_VENTI.need_qpc, rax
    mov     QWORD PTR [SmokeVenti].KN_VENTI.flags, KN_FLAG_PREFETCH_HOST
    lea     rcx, SmokeVenti
    lea     rdx, SmokeReceipt
    call    KN_O3KKEN
    cmp     rax, KN_OK
    jne     fail
    mov     rcx, QWORD PTR [SmokeReceipt].KN_RECEIPT.result
    call    ExitProcess
fail:
    mov     rcx, rax
    call    ExitProcess
main ENDP
END
