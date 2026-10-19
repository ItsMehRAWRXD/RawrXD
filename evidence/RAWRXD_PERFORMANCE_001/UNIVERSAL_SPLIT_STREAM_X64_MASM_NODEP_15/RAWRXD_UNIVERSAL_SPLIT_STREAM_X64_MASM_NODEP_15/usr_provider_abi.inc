option casemap:none

; Universal provider ABI. Provider resolves/reads bytes only.
; It has no USRRegion pointer and therefore cannot transition residency state.
USRProvider STRUCT
    provider_ctx       QWORD ?
    read_exact_fn      QWORD ? ; int fn(ctx, file_offset, bytes, dst)
USRProvider ENDS

; Universal device backend ABI. Backend allocates/copies/waits/frees only.
; It has no right to call a state transition implicitly; caller commits HOT
; through usr_hot_commit only after backend completion is observed.
USRDeviceBackend STRUCT
    device_ctx         QWORD ?
    alloc_fn           QWORD ?
    copy_fn            QWORD ?
    wait_fn            QWORD ?
    free_fn            QWORD ?
USRDeviceBackend ENDS
