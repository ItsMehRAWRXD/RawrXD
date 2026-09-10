option casemap:none
include KN_O3KKEN.inc

QueryPerformanceCounter   PROTO :QWORD
QueryPerformanceFrequency PROTO :QWORD

.code
PUBLIC KN_O3KKEN

KN_Stamp PROC
    sub rsp, 28h
    call QueryPerformanceCounter
    add rsp, 28h
    ret
KN_Stamp ENDP

KN_Frequency PROC
    sub rsp, 28h
    call QueryPerformanceFrequency
    add rsp, 28h
    ret
KN_Frequency ENDP

; rax = qpc delta
; rcx = qpc frequency
; rax = nanoseconds
KN_DeltaNs PROC
    test rcx, rcx
    jz short kdn_zero

    xor rdx, rdx
    div rcx
    mov r8, rax
    imul r8, 1000000000

    mov rax, rdx
    mov r9, 1000000000
    mul r9
    div rcx
    add rax, r8
    ret

kdn_zero:
    xor eax, eax
    ret
KN_DeltaNs ENDP

; rcx = KN_VENTI*
; rdx = KN_RECEIPT*
; consumer ABI:
;   rcx = KN_CHAIR*
;   rdx = KN_VENTI*
;   r8  = &KN_RECEIPT.result
;   rax != 0 success
KN_O3KKEN PROC
    test rcx, rcx
    jz kn_null_direct
    test rdx, rdx
    jz kn_null_direct

    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 40h

    mov rbx, rcx
    mov r12, rdx
    xor r15d, r15d

    xor eax, eax
    mov ecx, SIZEOF KN_RECEIPT / 8
    mov rdi, r12
    rep stosq

    lea rcx, [r12].KN_RECEIPT.qpc_freq
    call KN_Frequency
    test eax, eax
    jz kn_clock

    lea rcx, [r12].KN_RECEIPT.start_qpc
    call KN_Stamp
    test eax, eax
    jz kn_clock

    mov r13, [rbx].KN_VENTI.chair_ptr
    test r13, r13
    jz kn_null

    lock bts qword ptr [r13].KN_CHAIR.state, KN_BUSY_BIT
    jc kn_busy
    mov r15d, 1

    mov rax, [r13].KN_CHAIR.object_id
    cmp rax, [rbx].KN_VENTI.object_id
    jne kn_object
    mov [r12].KN_RECEIPT.object_id, rax

    mov rax, [r13].KN_CHAIR.generation
    cmp rax, [rbx].KN_VENTI.generation
    jne kn_generation
    mov [r12].KN_RECEIPT.generation, rax

    mov rax, [rbx].KN_VENTI.flags
    test rax, KN_FLAG_PREFETCH_HOST
    jz kn_require_ready

    mov r10, [rbx].KN_VENTI.src_ptr
    test r10, r10
    jz kn_prefetch

    mov rcx, [rbx].KN_VENTI.copy_bytes
    cmp rcx, [r13].KN_CHAIR.payload_bytes
    ja kn_prefetch

    mov r11, [r13].KN_CHAIR.payload_ptr
    test r11, r11
    jz kn_prefetch

kn_copy8:
    cmp rcx, 8
    jb kn_copy1
    mov rax, [r10]
    mov [r11], rax
    add r10, 8
    add r11, 8
    sub rcx, 8
    jmp kn_copy8

kn_copy1:
    test rcx, rcx
    jz kn_publish_ready
    mov al, [r10]
    mov [r11], al
    inc r10
    inc r11
    dec rcx
    jmp kn_copy1

kn_publish_ready:
    lea rcx, [r13].KN_CHAIR.ready_qpc
    call KN_Stamp
    test eax, eax
    jz kn_clock
    mov rax, [r13].KN_CHAIR.ready_qpc
    mov [r12].KN_RECEIPT.ready_qpc, rax
    lock or qword ptr [r13].KN_CHAIR.state, KN_STATE_READY
    jmp kn_handoff

kn_require_ready:
    mov rax, [r13].KN_CHAIR.state
    test rax, KN_STATE_READY
    jz kn_not_ready
    mov rax, [r13].KN_CHAIR.ready_qpc
    test rax, rax
    jz kn_not_ready
    mov [r12].KN_RECEIPT.ready_qpc, rax

kn_handoff:
    mov rax, [rbx].KN_VENTI.owner_from
    mov r10, [rbx].KN_VENTI.owner_to
    lock cmpxchg qword ptr [r13].KN_CHAIR.owner, r10
    jne kn_owner

    mov [r12].KN_RECEIPT.owner_to, r10
    lock or qword ptr [r13].KN_CHAIR.state, KN_STATE_HANDED_OFF

    lea rcx, [r12].KN_RECEIPT.handoff_qpc
    call KN_Stamp
    test eax, eax
    jz kn_clock

    mov r14, [rbx].KN_VENTI.consumer_fn
    test r14, r14
    jz kn_consumer

    lea rcx, [r12].KN_RECEIPT.consumer_start_qpc
    call KN_Stamp
    test eax, eax
    jz kn_clock

    sub rsp, 20h
    mov rcx, r13
    mov rdx, rbx
    lea r8, [r12].KN_RECEIPT.result
    call r14
    add rsp, 20h
    test rax, rax
    jz kn_consumer_timed

    lea rcx, [r12].KN_RECEIPT.consumer_end_qpc
    call KN_Stamp
    test eax, eax
    jz kn_clock

    lock or qword ptr [r13].KN_CHAIR.state, KN_STATE_CONSUMED
    mov qword ptr [r12].KN_RECEIPT.status, KN_OK
    jmp kn_finalize

kn_consumer_timed:
    lea rcx, [r12].KN_RECEIPT.consumer_end_qpc
    call KN_Stamp
kn_consumer:
    lock or qword ptr [r13].KN_CHAIR.state, KN_STATE_FAILED
    mov qword ptr [r12].KN_RECEIPT.status, KN_ERR_CONSUMER
    jmp kn_finalize

kn_object:
    mov qword ptr [r12].KN_RECEIPT.status, KN_ERR_OBJECT
    jmp kn_finalize

kn_generation:
    mov qword ptr [r12].KN_RECEIPT.status, KN_ERR_GENERATION
    jmp kn_finalize

kn_busy:
    mov qword ptr [r12].KN_RECEIPT.status, KN_ERR_BUSY
    jmp kn_finalize

kn_owner:
    mov qword ptr [r12].KN_RECEIPT.status, KN_ERR_OWNER
    jmp kn_finalize

kn_not_ready:
    mov qword ptr [r12].KN_RECEIPT.status, KN_ERR_NOT_READY
    jmp kn_finalize

kn_prefetch:
    mov qword ptr [r12].KN_RECEIPT.status, KN_ERR_PREFETCH
    jmp kn_finalize

kn_null:
    mov qword ptr [r12].KN_RECEIPT.status, KN_ERR_NULL
    jmp kn_finalize

kn_clock:
    mov qword ptr [r12].KN_RECEIPT.status, KN_ERR_CLOCK

kn_finalize:
    lea rcx, [r12].KN_RECEIPT.commit_qpc
    call KN_Stamp

    mov rax, [r12].KN_RECEIPT.commit_qpc
    sub rax, [r12].KN_RECEIPT.start_qpc
    mov rcx, [r12].KN_RECEIPT.qpc_freq
    call KN_DeltaNs
    mov [r12].KN_RECEIPT.token_wall_ns, rax

    mov r10, [rbx].KN_VENTI.need_qpc
    test r10, r10
    jz kn_release

    mov rax, [r12].KN_RECEIPT.ready_qpc
    cmp rax, r10
    jbe kn_release

    sub rax, r10
    mov rcx, [r12].KN_RECEIPT.qpc_freq
    call KN_DeltaNs
    mov [r12].KN_RECEIPT.exposed_wait_ns, rax

kn_release:
    test r15d, r15d
    jz kn_return
    lock btr qword ptr [r13].KN_CHAIR.state, KN_BUSY_BIT

kn_return:
    mov rax, [r12].KN_RECEIPT.status

    add rsp, 40h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

kn_null_direct:
    mov rax, KN_ERR_NULL
    ret
KN_O3KKEN ENDP

; rcx=KN_CHAIR* rdx=KN_VENTI* r8=&result ; rax!=0 ok
; Sums payload[0..copy_bytes) into *r8 (receipt.result).
PUBLIC K3C_ConsumeResolved
K3C_ConsumeResolved PROC
    test    rcx, rcx
    jz      k3_fail
    test    rdx, rdx
    jz      k3_fail
    test    r8, r8
    jz      k3_fail
    mov     r9, [rcx].KN_CHAIR.payload_ptr
    test    r9, r9
    jz      k3_fail
    mov     r10, [rdx].KN_VENTI.copy_bytes
    xor     eax, eax
    mov     [r8], rax
    xor     r11, r11
k3_loop:
    cmp     r11, r10
    jae     k3_ok
    movzx   eax, BYTE PTR [r9+r11]
    add     [r8], rax
    inc     r11
    jmp     k3_loop
k3_ok:
    mov     rax, 1
    ret
k3_fail:
    xor     eax, eax
    ret
K3C_ConsumeResolved ENDP

END
