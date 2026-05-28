; ==================================================================================
; SOVEREIGN MEMORY ARENA
; File: Sovereign_Memory_Arena.asm
; Role: NUMA-aware streaming allocator + universal ingestion substrate
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

EXTERN Sovereign_Registry_Insert:PROC
EXTERN Sovereign_Registry_Lookup:PROC

.DATA

ALIGN 64

g_ArenaBase        QWORD 0
g_ArenaSize        QWORD 0
g_ArenaCursor      QWORD 0
g_NUMA_NodeMask    QWORD 0FFFFFFFFFFFFFFFFh

.CODE

; ==================================================================================
; Sovereign_Arena_Init
; RCX = Base Ptr
; RDX = Size
; R8  = NUMA Node Mask
; ==================================================================================
PUBLIC Sovereign_Arena_Init
Sovereign_Arena_Init PROC
    ENTER_FRAME

    mov [g_ArenaBase], rcx
    mov [g_ArenaSize], rdx
    mov [g_NUMA_NodeMask], r8

    mov rax, rcx
    mov [g_ArenaCursor], rax

    xor rax, rax
    EXIT_FRAME
    ret
Sovereign_Arena_Init ENDP

; ==================================================================================
; Sovereign_Arena_Alloc
; RCX = Size
; RDX = Alignment (power of 2)
; Returns RAX = Pointer
; ==================================================================================
PUBLIC Sovereign_Arena_Alloc
Sovereign_Arena_Alloc PROC
    ENTER_FRAME

    mov rax, [g_ArenaCursor]

    ; Align forward
    dec rdx
    add rax, rdx
    not rdx
    and rax, rdx

    mov r8, rax
    add r8, rcx

    mov r9, [g_ArenaBase]
    mov r10, [g_ArenaSize]
    add r9, r10

    cmp r8, r9
    ja @@Fail

    mov [g_ArenaCursor], r8

    EXIT_FRAME
    ret

@@Fail:
    xor rax, rax
    EXIT_FRAME
    ret
Sovereign_Arena_Alloc ENDP

; ==================================================================================
; Sovereign_Arena_BeaconBind
; RCX = Ptr
; RDX = Hash
; R8  = Size
; ==================================================================================
PUBLIC Sovereign_Arena_BeaconBind
Sovereign_Arena_BeaconBind PROC
    ENTER_FRAME

    ; Insert into global registry as a live "beaconed region"
    ; Registry expects RCX=Hash, RDX=Ptr (R8=Size passes through naturally if needed)
    mov r9, rcx
    mov rcx, rdx
    mov rdx, r9
    call Sovereign_Registry_Insert

    EXIT_FRAME
    ret
Sovereign_Arena_BeaconBind ENDP

; ==================================================================================
; Sovereign_Arena_StreamCommit
; RCX = Input Stream Ptr
; RDX = Size
; R8  = Type Tag
; Returns RAX = Arena Ptr
; ==================================================================================
PUBLIC Sovereign_Arena_StreamCommit
Sovereign_Arena_StreamCommit PROC
    ; Push non-volatiles to persist variables across external allocator call
    push r12
    push r13
    ENTER_FRAME

    ; Save origin Stream Ptr (RCX) and Size (RDX) into non-volatiles
    mov r12, rcx
    mov r13, rdx

    ; Allocate persistent region
    mov rcx, rdx  ; RCX = Size
    mov rdx, 64   ; RDX = Alignment
    call Sovereign_Arena_Alloc
    test rax, rax
    jz @@Fail

    mov r10, rax  ; Save allocated Arena Ptr
    mov r8, r12   ; Src
    mov r9, rax   ; Dst
    mov rcx, r13  ; Count

@@CopyLoop:
    test rcx, rcx
    jz @@Done
    mov dl, [r8]
    mov [r9], dl
    inc r8
    inc r9
    dec rcx
    jmp @@CopyLoop

@@Done:
    mov rax, r10  ; Restore allocation base pointer as return value

    EXIT_FRAME
    pop r13
    pop r12
    ret

@@Fail:
    xor rax, rax
    EXIT_FRAME
    pop r13
    pop r12
    ret
Sovereign_Arena_StreamCommit ENDP

; ==================================================================================
; Sovereign_Arena_GetBeacon
; RCX = Hash
; Returns RAX = Pointer
; ==================================================================================
PUBLIC Sovereign_Arena_GetBeacon
Sovereign_Arena_GetBeacon PROC
    ; Direct jump serves as perfect wrapper
    jmp Sovereign_Registry_Lookup
Sovereign_Arena_GetBeacon ENDP

END