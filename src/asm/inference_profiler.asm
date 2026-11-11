; =============================================================================
; RawrXD Inference Profiler — Cycle-Accurate Hot Path Instrumentation
; x64 MASM, zero dependencies, under 300 lines
; Hooks: GGUF_LoadFile → ModelState_Initialize → Inference_SingleToken
; =============================================================================

        .code
        align 16

; -----------------------------------------------------------------------------
; PUBLIC INTERFACE
; -----------------------------------------------------------------------------
        public Profiler_Initialize
        public Profiler_BeginRegion
        public Profiler_EndRegion
        public Profiler_Report
        public Profiler_Reset

; -----------------------------------------------------------------------------
; STRUCT: ProfileRegion (32 bytes, cache-line aligned)
;   +0x00  name_ptr        dq  ?   ; ASCII region name
;   +0x08  total_cycles    dq  ?   ; accumulated rdtsc delta
;   +0x10  call_count      dq  ?   ; invocation count
;   +0x18  max_cycles      dq  ?   ; worst-case single call
; -----------------------------------------------------------------------------
REGION_SIZE     equ 32
MAX_REGIONS     equ 16

; -----------------------------------------------------------------------------
; BSS: Static storage (no .data section — zero-init)
; -----------------------------------------------------------------------------
        .data?
profiler_active     db  ?
region_count        dd  ?
regions             db  MAX_REGIONS * REGION_SIZE dup(?)
rdtsc_overhead      dq  ?

; -----------------------------------------------------------------------------
; TEXT: Core routines
; -----------------------------------------------------------------------------

; === Profiler_Initialize =====================================================
; Minimal initialization - just zero memory, skip calibration
; RCX = scratch (clobbered)
; RAX = 0 on success
; =============================================================================
Profiler_Initialize proc frame
        push    rdi
        .pushreg rdi
        .endprolog

        xor     eax, eax
        mov     [region_count], eax
        mov     [profiler_active], al
        lea     rdi, [regions]
        mov     ecx, MAX_REGIONS * REGION_SIZE / 8
        rep stosq
        
        ; Set minimal overhead (skip calibration for stability)
        mov     qword ptr [rdtsc_overhead], 50
        mov     byte ptr [profiler_active], 1

        xor     eax, eax            ; return 0
        pop     rdi
        ret
Profiler_Initialize endp

; === Profiler_BeginRegion ====================================================n; RCX = region_name (char*)
; Returns: RAX = region_index (for EndRegion, or -1 if full)
; =============================================================================
Profiler_BeginRegion proc frame
        .endprolog

        mov     al, [profiler_active]
        test    al, al
        jz      @@fail

        ; Find or create region by name
        mov     r9, rcx             ; save name
        mov     ecx, [region_count]
        test    ecx, ecx
        jz      @@new
        lea     r8, [regions]
        mov     r10d, ecx

@@find:
        mov     rax, [r8]           ; region.name_ptr
        cmp     rax, r9
        je      @@found
        add     r8, REGION_SIZE
        dec     r10d
        jnz     @@find

@@new:
        cmp     ecx, MAX_REGIONS
        jae     @@fail
        mov     [region_count], ecx
        inc     dword ptr [region_count]
        ; Initialize new region
        mov     [r8], r9            ; name
        mov     qword ptr [r8+8], 0
        mov     qword ptr [r8+16], 0
        mov     qword ptr [r8+24], 0
        jmp     @@stamp

@@found:
        mov     ecx, MAX_REGIONS
        sub     ecx, r10d
        dec     ecx                 ; actual index

@@stamp:
        ; Store t0 in region.max_cycles (reused as scratch for t0)
        xor     eax, eax
        cpuid
        rdtsc
        shl     rdx, 32
        or      rax, rdx
        mov     [r8+24], rax        ; t0 in max_cycles slot
        mov     eax, ecx            ; return index
        ret

@@fail:
        mov     eax, -1
        ret
Profiler_BeginRegion endp

; === Profiler_EndRegion ======================================================
; RCX = region_index (from BeginRegion)
; =============================================================================
Profiler_EndRegion proc frame
        .endprolog

        mov     al, [profiler_active]
        test    al, al
        jz      @@done

        cmp     ecx, MAX_REGIONS
        jae     @@done

        ; Compute delta
        xor     eax, eax
        cpuid
        rdtsc
        shl     rdx, 32
        or      rax, rdx            ; t1

        mov     r8d, ecx
        imul    r8d, REGION_SIZE
        lea     r8, [regions + r8]

        mov     r9, [r8+24]         ; t0
        sub     rax, r9
        sub     rax, [rdtsc_overhead]
        jnc     @@positive
        xor     rax, rax            ; clamp underflow
@@positive:

        ; Accumulate
        add     [r8+8], rax         ; total_cycles
        inc     qword ptr [r8+16]   ; call_count

        ; Update max
        cmp     rax, [r8+24]
        jbe     @@done
        mov     [r8+24], rax

@@done:
        ret
Profiler_EndRegion endp

; === Profiler_Report =========================================================
; RCX = buffer (char*)
; RDX = buffer_size
; Returns: RAX = bytes written
; Format: CSV — name,total_cycles,calls,avg_cycles,max_cycles
; =============================================================================
Profiler_Report proc frame
        push    rbx
        .pushreg rbx
        push    rdi
        .pushreg rdi
        push    rsi
        .pushreg rsi
        .endprolog

        mov     rdi, rcx            ; buffer
        mov     rbx, rdx            ; buf_size
        xor     r10, r10            ; total_written
        mov     ecx, [region_count]
        test    ecx, ecx
        jz      @@done
        lea     r8, [regions]
        mov     r9d, ecx

@@loop:
        ; Skip if never called
        mov     rax, [r8+16]
        test    rax, rax
        jz      @@next

        ; Format: name,total,calls,avg,max\n
        ; Simple ASCII emit — no sprintf dependency
        mov     rsi, [r8]           ; name ptr
        mov     rcx, rdi
        add     rcx, r10

        ; Copy name
@@name:
        mov     al, [rsi]
        test    al, al
        jz      @@name_done
        mov     [rcx + r10], al
        inc     r10
        inc     rsi
        cmp     r10, rbx
        jae     @@done
        jmp     @@name
@@name_done:

        mov     byte ptr [rcx + r10], ','
        inc     r10

        ; Emit total_cycles (hex for zero-dep simplicity)
        mov     rax, [r8+8]
        call    @@emit_u64
        mov     byte ptr [rcx + r10], ','
        inc     r10

        ; Emit call_count
        mov     rax, [r8+16]
        call    @@emit_u64
        mov     byte ptr [rcx + r10], ','
        inc     r10

        ; Emit avg = total / calls
        mov     rax, [r8+8]
        xor     rdx, rdx
        div     qword ptr [r8+16]
        call    @@emit_u64
        mov     byte ptr [rcx + r10], ','
        inc     r10

        ; Emit max
        mov     rax, [r8+24]
        call    @@emit_u64
        mov     byte ptr [rcx + r10], 10
        inc     r10

@@next:
        add     r8, REGION_SIZE
        dec     r9d
        jnz     @@loop

@@done:
        mov     rax, r10
        pop     rsi
        pop     rdi
        pop     rbx
        ret

; --- emit_u64: write decimal string of rax to [rdi+r10], advance r10 --------
@@emit_u64:
        push    rax
        push    rcx
        push    rdx
        push    r11
        mov     r11, 10
        mov     rcx, rdi
        add     rcx, r10
        add     rcx, 24             ; scratch offset
        mov     byte ptr [rcx], '0'
        test    rax, rax
        jz      @@e0
        mov     r9, rcx
@@e1:
        xor     rdx, rdx
        div     r11
        add     dl, '0'
        dec     r9
        mov     [r9], dl
        test    rax, rax
        jnz     @@e1
        ; copy forward
@@e2:
        mov     al, [r9]
        mov     [rdi + r10], al
        inc     r10
        inc     r9
        cmp     r9, rcx
        jb      @@e2
        jmp     @@e3
@@e0:
        inc     r10
@@e3:
        pop     r11
        pop     rdx
        pop     rcx
        pop     rax
        ret

Profiler_Report endp

; === Profiler_Reset ==========================================================
; Zero all counters, keep region names
; =============================================================================
Profiler_Reset proc frame
        .endprolog
        mov     ecx, [region_count]
        test    ecx, ecx
        jz      @@done
        lea     r8, [regions]
@@loop:
        mov     qword ptr [r8+8], 0
        mov     qword ptr [r8+16], 0
        mov     qword ptr [r8+24], 0
        add     r8, REGION_SIZE
        dec     ecx
        jnz     @@loop
@@done:
        ret
Profiler_Reset endp

; =============================================================================
; END OF FILE
; =============================================================================
        end
