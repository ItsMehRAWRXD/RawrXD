; KN_O3KKEN.asm
;
; Real resolved-event path:
;
; VENTI
;   -> exact Chair
;   -> reserve ownership
;   -> host prefetch
;   -> resident
;   -> ownership handoff
;   -> K3-C consumer
;   -> token receipt
;   -> chair release
;   -> nanosecond token wall
;
; No token lookup.
; No decode lookup.
; No global scan.
; No external runtime.

option casemap:none

include KN_O3KKEN.inc

QueryPerformanceCounter   PROTO :QWORD
QueryPerformanceFrequency PROTO :QWORD
ExitProcess               PROTO :QWORD

.data

SmokeSource db 10,20,12       ; consumer receipt = 42

.data?

SmokeBuffer db 64 dup(?)
SmokeChair  KN_CHAIR <>
SmokeVenti  KN_VENTI <>

.code

; ------------------------------------------------------------
; rcx = QPC delta
; rdx = QPC frequency
; rax = nanoseconds
; ------------------------------------------------------------

KN_TicksToNs PROC
    test    rdx, rdx
    jz      ttn_fail

    mov     r9, rdx
    mov     rax, rcx
    mov     r8, 1000000000
    mul     r8
    div     r9
    ret

ttn_fail:
    xor     rax, rax
    ret
KN_TicksToNs ENDP


; ------------------------------------------------------------
; Resolved K3-C consumer witness.
;
; rcx = resident bytes
; rdx = byte count
; r8  = consumer context
; r9  = object id
;
; This is execution, not discovery.
; ------------------------------------------------------------

K3C_ConsumeResolved PROC
    xor     rax, rax
    xor     r10, r10

k3_loop:
    cmp     r10, rdx
    jae     k3_done

    movzx   r11d, BYTE PTR [rcx+r10]
    add     rax, r11
    inc     r10
    jmp     k3_loop

k3_done:
    ret
K3C_ConsumeResolved ENDP


; ------------------------------------------------------------
; rcx = KN_VENTI*
;
; rax = token receipt on success
;       0 on failure
; ------------------------------------------------------------

KN_O3KKEN PROC

    push    rbx
    push    rsi
    push    rdi
    push    r12
    sub     rsp, 28h

    mov     rbx, rcx
    test    rbx, rbx
    jz      kn_null

    mov     DWORD PTR [rbx].KN_VENTI.status, KN_OK

    ; --------------------------------------------------------
    ; Resolve exact chair directly from VENTI.
    ; No lookup and no scan.
    ; --------------------------------------------------------

    mov     r12, QWORD PTR [rbx].KN_VENTI.chair_ptr
    test    r12, r12
    jz      kn_null

    mov     rax, QWORD PTR [rbx].KN_VENTI.source_ptr
    test    rax, rax
    jz      kn_null

    mov     rax, QWORD PTR [rbx].KN_VENTI.consumer_ptr
    test    rax, rax
    jz      kn_null

    ; generation protects against stale VENTI -> chair mapping

    mov     rax, QWORD PTR [r12].KN_CHAIR.generation
    cmp     rax, QWORD PTR [rbx].KN_VENTI.generation
    jne     kn_generation

    ; exact capacity validation

    mov     rax, QWORD PTR [rbx].KN_VENTI.bytes
    cmp     rax, QWORD PTR [r12].KN_CHAIR.capacity
    ja      kn_capacity

    mov     rax, QWORD PTR [r12].KN_CHAIR.data_ptr
    test    rax, rax
    jz      kn_null

    ; --------------------------------------------------------
    ; QPC frequency + token-wall origin
    ; --------------------------------------------------------

    lea     rcx, [rbx].KN_VENTI.qpf_hz
    call    QueryPerformanceFrequency
    test    eax, eax
    jz      kn_clock

    lea     rcx, [rbx].KN_VENTI.token_start_qpc
    call    QueryPerformanceCounter
    test    eax, eax
    jz      kn_clock

    ; --------------------------------------------------------
    ; Atomic chair reservation:
    ;
    ; owner_from -> OWNER_TRANSIT
    ;
    ; Nobody else can consume this chair while bytes move.
    ; --------------------------------------------------------

    mov     eax, DWORD PTR [rbx].KN_VENTI.owner_from
    mov     edx, OWNER_TRANSIT

    lock cmpxchg DWORD PTR [r12].KN_CHAIR.owner, edx
    jne     kn_owner

    mov     DWORD PTR [r12].KN_CHAIR.state, CHAIR_PREFETCH

    lea     rcx, [rbx].KN_VENTI.prefetch_qpc
    call    QueryPerformanceCounter

    ; --------------------------------------------------------
    ; Real host -> physical-chair prefetch.
    ; --------------------------------------------------------

    mov     rsi, QWORD PTR [rbx].KN_VENTI.source_ptr
    mov     rdi, QWORD PTR [r12].KN_CHAIR.data_ptr
    mov     rcx, QWORD PTR [rbx].KN_VENTI.bytes

    rep movsb

    mov     rax, QWORD PTR [rbx].KN_VENTI.object_id
    mov     QWORD PTR [r12].KN_CHAIR.object_id, rax

    mov     rax, QWORD PTR [rbx].KN_VENTI.bytes
    mov     QWORD PTR [r12].KN_CHAIR.bytes, rax

    mov     DWORD PTR [r12].KN_CHAIR.state, CHAIR_RESIDENT

    lea     rcx, [rbx].KN_VENTI.ready_qpc
    call    QueryPerformanceCounter

    ; --------------------------------------------------------
    ; Ownership handoff:
    ;
    ; TRANSIT -> exact resolved consumer owner
    ; --------------------------------------------------------

    mov     eax, DWORD PTR [rbx].KN_VENTI.owner_to
    xchg    DWORD PTR [r12].KN_CHAIR.owner, eax

    lea     rcx, [rbx].KN_VENTI.handoff_qpc
    call    QueryPerformanceCounter

    mov     DWORD PTR [r12].KN_CHAIR.state, CHAIR_CONSUMING

    ; --------------------------------------------------------
    ; Execute already-resolved consumer.
    ;
    ; Decode does not search.
    ; Token does not search.
    ; --------------------------------------------------------

    mov     rcx, QWORD PTR [r12].KN_CHAIR.data_ptr
    mov     rdx, QWORD PTR [r12].KN_CHAIR.bytes
    mov     r8,  QWORD PTR [rbx].KN_VENTI.consumer_ctx
    mov     r9,  QWORD PTR [r12].KN_CHAIR.object_id

    call    QWORD PTR [rbx].KN_VENTI.consumer_ptr

    mov     QWORD PTR [rbx].KN_VENTI.token_receipt, rax

    lea     rcx, [rbx].KN_VENTI.consume_qpc
    call    QueryPerformanceCounter

    ; --------------------------------------------------------
    ; Release exact chair.
    ;
    ; owner_to -> FREE
    ; --------------------------------------------------------

    mov     eax, DWORD PTR [rbx].KN_VENTI.owner_to
    xor     edx, edx

    lock cmpxchg DWORD PTR [r12].KN_CHAIR.owner, edx
    jne     kn_release

    mov     DWORD PTR [r12].KN_CHAIR.state, CHAIR_RELEASED

    inc     QWORD PTR [r12].KN_CHAIR.generation

    lea     rcx, [rbx].KN_VENTI.release_qpc
    call    QueryPerformanceCounter

    ; --------------------------------------------------------
    ; Nanosecond accounting
    ; --------------------------------------------------------

    ; prefetch_ns = ready - prefetch

    mov     rcx, QWORD PTR [rbx].KN_VENTI.ready_qpc
    sub     rcx, QWORD PTR [rbx].KN_VENTI.prefetch_qpc
    mov     rdx, QWORD PTR [rbx].KN_VENTI.qpf_hz
    call    KN_TicksToNs

    mov     QWORD PTR [rbx].KN_VENTI.prefetch_ns, rax

    ; handoff_ns = handoff - ready

    mov     rcx, QWORD PTR [rbx].KN_VENTI.handoff_qpc
    sub     rcx, QWORD PTR [rbx].KN_VENTI.ready_qpc
    mov     rdx, QWORD PTR [rbx].KN_VENTI.qpf_hz
    call    KN_TicksToNs

    mov     QWORD PTR [rbx].KN_VENTI.handoff_ns, rax

    ; consume_ns = consume - handoff

    mov     rcx, QWORD PTR [rbx].KN_VENTI.consume_qpc
    sub     rcx, QWORD PTR [rbx].KN_VENTI.handoff_qpc
    mov     rdx, QWORD PTR [rbx].KN_VENTI.qpf_hz
    call    KN_TicksToNs

    mov     QWORD PTR [rbx].KN_VENTI.consume_ns, rax

    ; total token wall

    mov     rcx, QWORD PTR [rbx].KN_VENTI.release_qpc
    sub     rcx, QWORD PTR [rbx].KN_VENTI.token_start_qpc
    mov     rdx, QWORD PTR [rbx].KN_VENTI.qpf_hz
    call    KN_TicksToNs

    mov     QWORD PTR [rbx].KN_VENTI.token_wall_ns, rax

    mov     DWORD PTR [rbx].KN_VENTI.status, KN_OK

    mov     rax, QWORD PTR [rbx].KN_VENTI.token_receipt
    jmp     kn_exit


kn_null:
    mov     eax, KN_E_NULL
    jmp     kn_fail

kn_capacity:
    mov     eax, KN_E_CAPACITY
    jmp     kn_fail

kn_owner:
    mov     eax, KN_E_OWNER
    jmp     kn_fail

kn_generation:
    mov     eax, KN_E_GENERATION
    jmp     kn_fail

kn_release:
    mov     eax, KN_E_RELEASE
    jmp     kn_fail

kn_clock:
    mov     eax, KN_E_CLOCK

kn_fail:
    test    rbx, rbx
    jz      kn_fail_return

    mov     DWORD PTR [rbx].KN_VENTI.status, eax

kn_fail_return:
    xor     rax, rax

kn_exit:

    add     rsp, 28h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

KN_O3KKEN ENDP


; ------------------------------------------------------------
; End-to-end source smoke.
; ------------------------------------------------------------

main PROC

    sub     rsp, 28h

    ; physical reusable chair

    mov     DWORD PTR [SmokeChair].KN_CHAIR.owner, OWNER_HOST
    mov     DWORD PTR [SmokeChair].KN_CHAIR.state, CHAIR_FREE

    mov     QWORD PTR [SmokeChair].KN_CHAIR.generation, 1
    mov     QWORD PTR [SmokeChair].KN_CHAIR.capacity, 64

    lea     rax, SmokeBuffer
    mov     QWORD PTR [SmokeChair].KN_CHAIR.data_ptr, rax

    ; resolved event

    lea     rax, SmokeSource
    mov     QWORD PTR [SmokeVenti].KN_VENTI.source_ptr, rax

    mov     QWORD PTR [SmokeVenti].KN_VENTI.bytes, 3

    lea     rax, SmokeChair
    mov     QWORD PTR [SmokeVenti].KN_VENTI.chair_ptr, rax

    mov     QWORD PTR [SmokeVenti].KN_VENTI.object_id, 1
    mov     QWORD PTR [SmokeVenti].KN_VENTI.generation, 1

    mov     DWORD PTR [SmokeVenti].KN_VENTI.owner_from, OWNER_HOST
    mov     DWORD PTR [SmokeVenti].KN_VENTI.owner_to, OWNER_K3C

    lea     rax, K3C_ConsumeResolved
    mov     QWORD PTR [SmokeVenti].KN_VENTI.consumer_ptr, rax

    xor     rax, rax
    mov     QWORD PTR [SmokeVenti].KN_VENTI.consumer_ctx, rax

    ; run entire path

    lea     rcx, SmokeVenti
    call    KN_O3KKEN

    ; receipt is generated from bytes 10+20+12 = 42

    mov     rcx, rax
    call    ExitProcess

main ENDP

END
