option casemap:none

; Win64 ABI:
; entry RSP:
;   +00h return address
;   +08h..+27h shadow space
;   +28h fifth argument
;
; Current r671_tensor_acquire prologue:
;   push rbx,rsi,rdi,r12 = 20h
;   sub rsp,50h          = 50h
;   total stack delta    = 70h
;
R671_ENTRY_ARG5_OFFSET        equ 28h
R671_ACQUIRE_PUSH_BYTES       equ 20h
R671_ACQUIRE_LOCAL_BYTES      equ 50h
R671_ACQUIRE_STACK_DELTA      equ (R671_ACQUIRE_PUSH_BYTES + R671_ACQUIRE_LOCAL_BYTES)
R671_ACQUIRE_ARG5_OFFSET      equ (R671_ENTRY_ARG5_OFFSET + R671_ACQUIRE_STACK_DELTA)

IF R671_ACQUIRE_ARG5_OFFSET NE 98h
    .ERR <R671 acquire fifth-argument offset drifted from audited Win64 layout>
ENDIF

R671_RESIDENCY_OK             equ 0
R671_RESIDENCY_E_BOUND        equ 20
R671_RESIDENCY_E_ACCOUNTING   equ 21
R671_RESIDENCY_E_RELEASE      equ 22

R671ResidencyGuard STRUCT
    configured_bound          QWORD ?
    mapped_bytes_live         QWORD ?
    mapped_bytes_peak         QWORD ?
    acquire_success_count     QWORD ?
    release_success_count     QWORD ?
    invalid_release_count     QWORD ?
    bound_reject_count        QWORD ?
    accounting_fault_count    QWORD ?
R671ResidencyGuard ENDS

R671ResidencyReserve PROTO :PTR R671ResidencyGuard, :QWORD
R671ResidencyRelease PROTO :PTR R671ResidencyGuard, :QWORD
