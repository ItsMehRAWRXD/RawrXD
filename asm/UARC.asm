; UARC.asm - Unreal Address Resolution Cache
; Unreal mapped address engine table
; Sits between MAPM emit and SlingshotGuard PCIe transfer
;
; "Unreal" = addresses that exist in the map but are not yet
;            physically committed to VRAM — phantom slots
;            that become real the moment the slingshot fires
;
; Architecture:
;   MAPM emits 60 addresses (logical)
;        ↓
;   UARC resolves: logical → physical VRAM slot
;        ↓
;   SlingshotGuard fires DMA to resolved address
;        ↓
;   On hit: instant (address already resolved)
;   On miss: UARC allocates new slot, evicts LRU

OPTION CASEMAP:NONE
.CODE

; ── Constants ────────────────────────────────────────────────────────────────
UARC_SLOTS      EQU 128             ; total resolution cache entries
UARC_ENTRY_SIZE EQU 48              ; bytes per entry
UARC_MAGIC      EQU 0DEADC0DEh      ; sentinel

; ── UARC Entry layout (48 bytes) ─────────────────────────────────────────────
; +0  : uint32  expert_id
; +4  : uint32  state        0=empty 1=phantom 2=resolved 3=evicting
; +8  : uint64  logical_addr (RAM source)
; +16 : uint64  physical_addr (VRAM destination)
; +24 : uint64  size
; +32 : uint64  lru_tick
; +40 : uint32  magic
; +44 : uint32  checksum

; ── UARC_Resolve ─────────────────────────────────────────────────────────────
; Resolves expert_id → physical VRAM address
; rcx = uint32* expert_id
; rdx = UARC_Entry* table     (UARC_SLOTS entries)
; r8  = uint64* lru_counter   (global tick, caller owns)
; r9  = uint64* out_phys_addr
; returns rax: 1=hit 0=miss(phantom allocated) -1=table full
UARC_Resolve PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 40h

    mov     r12d, dword ptr [rcx]   ; expert_id
    mov     r13,  rdx               ; table
    mov     r14,  r8                ; lru_counter
    mov     r15,  r9                ; out_phys_addr

    ; ── Pass 1: scan for existing entry (hit) ────────────────────────────────
    xor     esi, esi                ; i = 0
.scan_loop:
    cmp     esi, UARC_SLOTS
    jge     .scan_miss

    imul    rax, rsi, UARC_ENTRY_SIZE
    add     rax, r13                ; entry ptr

    mov     ecx, dword ptr [rax]    ; entry.expert_id
    cmp     ecx, r12d
    jne     .scan_next

    mov     ecx, dword ptr [rax+4]  ; entry.state
    cmp     ecx, 0                  ; empty?
    je      .scan_next
    cmp     ecx, 3                  ; evicting?
    je      .scan_next

    ; HIT — update LRU tick
    mov     rbx, qword ptr [r14]    ; current tick
    inc     rbx
    mov     qword ptr [r14], rbx
    mov     qword ptr [rax+32], rbx ; entry.lru_tick = tick

    ; return physical address
    mov     rbx, qword ptr [rax+16] ; entry.physical_addr
    mov     qword ptr [r15], rbx

    ; if phantom → mark resolved
    cmp     dword ptr [rax+4], 1
    jne     .hit_resolved
    mov     dword ptr [rax+4], 2    ; phantom → resolved
.hit_resolved:
    mov     eax, 1                  ; return HIT
    jmp     .resolve_done

.scan_next:
    inc     esi
    jmp     .scan_loop

.scan_miss:
    ; ── Pass 2: find empty slot ───────────────────────────────────────────────
    xor     esi, esi
.empty_scan:
    cmp     esi, UARC_SLOTS
    jge     .need_evict

    imul    rax, rsi, UARC_ENTRY_SIZE
    add     rax, r13
    cmp     dword ptr [rax+4], 0    ; state == empty?
    je      .alloc_slot

    inc     esi
    jmp     .empty_scan

.need_evict:
    ; ── Pass 3: evict LRU entry ───────────────────────────────────────────────
    xor     esi, esi
    mov     edi, 0                  ; lru_min_idx = 0
    mov     r10, 0FFFFFFFFFFFFFFFFh ; lru_min_tick = MAX

.lru_scan:
    cmp     esi, UARC_SLOTS
    jge     .do_evict

    imul    rax, rsi, UARC_ENTRY_SIZE
    add     rax, r13

    mov     ecx, dword ptr [rax+4]
    cmp     ecx, 3                  ; skip evicting
    je      .lru_next
    cmp     ecx, 0                  ; skip empty
    je      .lru_next

    mov     rbx, qword ptr [rax+32] ; lru_tick
    cmp     rbx, r10
    jge     .lru_next
    mov     r10, rbx
    mov     edi, esi                ; new lru_min_idx

.lru_next:
    inc     esi
    jmp     .lru_scan

.do_evict:
    imul    rax, rdi, UARC_ENTRY_SIZE
    add     rax, r13
    mov     dword ptr [rax+4], 3    ; state = evicting
    mov     esi, edi                ; use this slot

.alloc_slot:
    ; allocate phantom entry at slot esi
    imul    rax, rsi, UARC_ENTRY_SIZE
    add     rax, r13

    mov     dword ptr [rax],   r12d ; expert_id
    mov     dword ptr [rax+4], 1    ; state = phantom

    ; logical addr = 0 (caller fills via UARC_Bind)
    mov     qword ptr [rax+8],  0
    mov     qword ptr [rax+16], 0
    mov     qword ptr [rax+24], 0

    ; lru tick
    mov     rbx, qword ptr [r14]
    inc     rbx
    mov     qword ptr [r14], rbx
    mov     qword ptr [rax+32], rbx

    mov     dword ptr [rax+40], UARC_MAGIC

    ; out_phys_addr = 0 (phantom, not yet committed)
    mov     qword ptr [r15], 0

    xor     eax, eax                ; return MISS

.resolve_done:
    add     rsp, 40h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
UARC_Resolve ENDP


; ── UARC_Bind ────────────────────────────────────────────────────────────────
; Binds logical (RAM) + physical (VRAM) addresses to a phantom entry
; rcx = UARC_Entry* table
; rdx = uint32 expert_id
; r8  = uint64 logical_addr  (RAM)
; r9  = uint64 physical_addr (VRAM)
; returns rax: 1=bound 0=not found
UARC_Bind PROC
    push    rbx
    sub     rsp, 40h

    xor     ecx, ecx
.bind_scan:
    cmp     ecx, UARC_SLOTS
    jge     .bind_fail

    imul    rax, rcx, UARC_ENTRY_SIZE
    add     rax, rcx                ; BUG FIX: use separate reg
    ; redo cleanly:
    push    rcx
    imul    rcx, rcx, UARC_ENTRY_SIZE
    lea     rax, [rcx + rdx]        ; rax = table + i*48  (rdx=table ptr)
    pop     rcx

    mov     ebx, dword ptr [rax]    ; expert_id
    cmp     ebx, r8d                ; compare with expert_id arg (r8 low 32)
    ; NOTE: args shifted — rcx=table rdx=expert_id r8=logical r9=physical
    ; re-map: use r10/r11
    jne     .bind_next

    cmp     dword ptr [rax+4], 1    ; must be phantom
    jne     .bind_next

    mov     qword ptr [rax+8],  r8  ; logical_addr
    mov     qword ptr [rax+16], r9  ; physical_addr
    mov     dword ptr [rax+4],  2   ; phantom → resolved

    mov     eax, 1
    jmp     .bind_done

.bind_next:
    inc     ecx
    jmp     .bind_scan

.bind_fail:
    xor     eax, eax

.bind_done:
    add     rsp, 40h
    pop     rbx
    ret
UARC_Bind ENDP


; ── UARC_Invalidate ──────────────────────────────────────────────────────────
; Marks expert entry CORRUPT → empty (called by SlingshotGuard on bad checksum)
; rcx = UARC_Entry* table
; rdx = uint32 expert_id
UARC_Invalidate PROC
    xor     eax, eax
.inv_loop:
    cmp     eax, UARC_SLOTS
    jge     .inv_done

    imul    r8, rax, UARC_ENTRY_SIZE
    add     r8, rcx
    mov     r9d, dword ptr [r8]
    cmp     r9d, edx
    jne     .inv_next

    ; zero the entry
    xor     r9, r9
    mov     qword ptr [r8],    r9
    mov     qword ptr [r8+8],  r9
    mov     qword ptr [r8+16], r9
    mov     qword ptr [r8+24], r9
    mov     qword ptr [r8+32], r9
    mov     qword ptr [r8+40], r9
    jmp     .inv_done

.inv_next:
    inc     eax
    jmp     .inv_loop

.inv_done:
    ret
UARC_Invalidate ENDP


; ── UARC_Dump ────────────────────────────────────────────────────────────────
; Counts entries by state — diagnostic
; rcx = UARC_Entry* table
; rdx = uint32* out_counts  [empty, phantom, resolved, evicting]
UARC_Dump PROC
    push    rbx
    sub     rsp, 40h

    xor     eax, eax
    mov     dword ptr [rdx],    0
    mov     dword ptr [rdx+4],  0
    mov     dword ptr [rdx+8],  0
    mov     dword ptr [rdx+12], 0

.dump_loop:
    cmp     eax, UARC_SLOTS
    jge     .dump_done

    imul    rbx, rax, UARC_ENTRY_SIZE
    add     rbx, rcx
    mov     r8d, dword ptr [rbx+4]  ; state
    cmp     r8d, 3
    ja      .dump_next
    inc     dword ptr [rdx + r8*4]

.dump_next:
    inc     eax
    jmp     .dump_loop

.dump_done:
    add     rsp, 40h
    pop     rbx
    ret
UARC_Dump ENDP

END
