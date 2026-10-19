; PATCH PATTERN FOR r671_tensor_acquire
;
; Existing audited prologue:
;
;   push rbx
;   push rsi
;   push rdi
;   push r12
;   sub rsp,50h
;
; Replace:
;
;   mov r10,r9
;   mov rdi,[rsp+98h]
;
; With:
;
;   mov r12,r8                         ; request bytes
;   mov r11,r9                         ; generation, before helper calls
;   mov rdi,[rsp+R671_ACQUIRE_ARG5_OFFSET]
;   test rdi,rdi
;   jz ra_invalid
;   mov [rsp+38h],r11                  ; preserve generation across calls
;
; After zero_lease:
;
;   mov r10,[rsp+38h]
;
; Before MapViewOfFile:
;
;   ; view_bytes already computed in lease.view_bytes
;   lea rcx,residency_guard
;   mov rdx,[rdi].R671Lease.view_bytes
;   call R671ResidencyReserve
;   test eax,eax
;   jnz ra_fail_residency
;
; If MapViewOfFile fails after reserve:
;
;   lea rcx,residency_guard
;   mov rdx,[rdi].R671Lease.view_bytes
;   call R671ResidencyRelease
;   ; then increment failed_acquires and return R671_E_VIEW
;
; On successful r671_release after UnmapViewOfFile:
;
;   lea rcx,residency_guard
;   mov rdx,[rdi].R671Lease.view_bytes
;   call R671ResidencyRelease
;   test eax,eax
;   jnz rr_state
;
; IMPORTANT:
; The preferred production integration is still to route the real-tensor ABI
; through the already locked a00eceb8... r671 slot/window manager instead of
; maintaining a second mapper. This guard is the minimum fail-closed overlay.
