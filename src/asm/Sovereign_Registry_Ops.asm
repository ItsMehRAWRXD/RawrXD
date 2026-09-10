; Sovereign_Registry_Ops.asm — atomic 100-slot allocate (x64, no deps)
INCLUDE Sovereign_Master_Matrix.inc

PUBLIC Allocate_Registry_Slot
PUBLIC Free_Registry_Slot
PUBLIC g_Master_Registry
PUBLIC g_Registry_Bitfield

.data
ALIGN 16
g_Master_Registry SOVEREIGN_MASTER_POOL MAX_SLOTS DUP(<>)
; 128-bit map covers 100 slots (2 qwords)
g_Registry_Bitfield dq 2 DUP(0)

.code
; RCX = Component_Type (1/2/3)
; RAX = slot index, or -1 if exhausted
Allocate_Registry_Slot PROC
    push rbx
    xor  rax, rax
FindFree:
    lock bts qword ptr [g_Registry_Bitfield], rax
    jnc  SlotSecured
    inc  rax
    cmp  rax, MAX_SLOTS
    jl   FindFree
    mov  rax, -1
    pop  rbx
    ret
SlotSecured:
    mov  rbx, SIZEOF SOVEREIGN_MASTER_POOL
    imul rbx, rax
    lea  rdx, g_Master_Registry
    mov  qword ptr [rdx+rbx].SOVEREIGN_MASTER_POOL.Slot_ID, rax
    mov  qword ptr [rdx+rbx].SOVEREIGN_MASTER_POOL.Component_Type, rcx
    mov  qword ptr [rdx+rbx].SOVEREIGN_MASTER_POOL.State_Flags, SF_ACTIVE
    xor  rcx, rcx
    mov  qword ptr [rdx+rbx].SOVEREIGN_MASTER_POOL.Base_Address, rcx
    mov  qword ptr [rdx+rbx].SOVEREIGN_MASTER_POOL.Virtual_Offset, rcx
    pop  rbx
    ret
Allocate_Registry_Slot ENDP

; RCX = slot index
Free_Registry_Slot PROC
    cmp  rcx, MAX_SLOTS
    jae  FreeDone
    lock btr qword ptr [g_Registry_Bitfield], rcx
    mov  rax, SIZEOF SOVEREIGN_MASTER_POOL
    imul rax, rcx
    lea  rdx, g_Master_Registry
    xor  r8, r8
    mov  qword ptr [rdx+rax].SOVEREIGN_MASTER_POOL.State_Flags, r8
    mov  qword ptr [rdx+rax].SOVEREIGN_MASTER_POOL.Component_Type, r8
FreeDone:
    ret
Free_Registry_Slot ENDP

END
