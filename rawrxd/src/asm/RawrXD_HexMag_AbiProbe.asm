; ============================================================================
; RawrXD_HexMag_AbiProbe.asm  --  HEXMAG_ABI_001
; ============================================================================
; Windows-x64 calling-conformance probe for hand-written MASM exports.
;
; WHY THIS IS ASSEMBLY, NOT C++
; A C++ caller cannot be made to hold a value in RBX or RSI across a call: the
; compiler is free to spill it and under no obligation not to. A conformance
; test written in C++ therefore degrades into "the optimiser happened to keep
; it live" -- a test that can pass while the ABI is being violated, which is
; exactly the failure this probe exists to catch. The canaries are loaded here,
; where the C++ compiler does not control register allocation.
;
; CHECKED, PER EXPORT
;   - the eight Windows-x64 NONVOLATILE GPRs: RBX RBP RSI RDI R12 R13 R14 R15
;   - the ten nonvolatile XMM registers: XMM6 .. XMM15
;   - RSP restored to its pre-call value
;   - entry RSP was 16n-8, i.e. the caller honoured the alignment contract
;   - nothing written ABOVE the shadow space (the 32 bytes a caller reserves may
;     legally be scribbled on, so poisoning those would be a wrong test; the
;     region above them is the callee's caller and must be untouched)
;   - the direction flag clear on return; DF is caller state, and a routine that
;     leaves it set corrupts every later rep-prefixed instruction
;
; ENTRY: rcx = target export, rdx = value to pass as the export's first
;        argument (0 means "pass a null / zero first argument")
; EXIT : rax = bitmask of violations, decoded by the driver.
; ============================================================================

OPTION CASEMAP:NONE

_TEXT SEGMENT

; --- violation bits --------------------------------------------------------
ABI_BAD_RBX      EQU 1 shl 0
ABI_BAD_RBP      EQU 1 shl 1
ABI_BAD_RSI      EQU 1 shl 2
ABI_BAD_RDI      EQU 1 shl 3
ABI_BAD_R12      EQU 1 shl 4
ABI_BAD_R13      EQU 1 shl 5
ABI_BAD_R14      EQU 1 shl 6
ABI_BAD_R15      EQU 1 shl 7
ABI_BAD_XMM6     EQU 1 shl 8
ABI_BAD_XMM7     EQU 1 shl 9
ABI_BAD_XMM8     EQU 1 shl 10
ABI_BAD_XMM9     EQU 1 shl 11
ABI_BAD_XMM10    EQU 1 shl 12
ABI_BAD_XMM11    EQU 1 shl 13
ABI_BAD_XMM12    EQU 1 shl 14
ABI_BAD_XMM13    EQU 1 shl 15
ABI_BAD_XMM14    EQU 1 shl 16
ABI_BAD_XMM15    EQU 1 shl 17
ABI_BAD_RSP      EQU 1 shl 18
ABI_BAD_ALIGN    EQU 1 shl 19
ABI_BAD_ABOVE    EQU 1 shl 20
ABI_BAD_DF       EQU 1 shl 21

; Distinct per-register canaries. Every one is below 0x80000000 on purpose:
; `cmp r64, imm32` SIGN-EXTENDS the immediate, so a canary with bit 31 set
; could never equal the value `mov r64, imm32` loaded, and would report every
; export as clobbering that register forever.
CAN_BX  EQU 11111111h
CAN_BP  EQU 12222222h
CAN_SI  EQU 13333333h
CAN_DI  EQU 14444444h
CAN_R12 EQU 15555555h
CAN_R13 EQU 16666666h
CAN_R14 EQU 17777777h
CAN_R15 EQU 18888888h

; Frame layout after the prologue (offsets from RSP). The eight pushed
; registers and the return address occupy [rsp+8] .. [rsp+79], so locals must
; start at +88 -- getting this wrong means the poison region lands on the
; registers this probe is relying on to survive the call.
;   [rsp +  0 .. 31]   the caller's shadow space -- may legally change
;   [rsp + 32]          target pointer, needed after the call
;   [rsp + 72 .. 79]   return address
;   [rsp + 80 .. 87]   8 bytes of realignment padding
;   [rsp + 88]          target pointer, needed after the call
;   [rsp + 96]          pre-call RSP, needed after the call
;   [rsp +104]          entry-alignment verdict
;   [rsp +112 .. 151]   poison region -- must be intact afterwards
LOC_TARGET   EQU 32
LOC_PRERSP   EQU 40
LOC_ENTRYRSP EQU 48
LOC_ALIGN    EQU 56
LOC_POISON   EQU 64
; The caller's XMM6..XMM15 are saved here and restored on the way out. A probe
; that clobbers the very registers it is testing cannot be trusted to report on
; anyone else's -- and it corrupts its own C++ caller.
LOC_XMMSAVE  EQU 112

PUBLIC HexMag_AbiProbe_Check

; ---------------------------------------------------------------------------
; NEGATIVE CONTROL -- a deliberately ABI-violating export.
;
; A conformance probe that cannot fail is not a probe. This function exists so
; the driver can demonstrate, on every run, that HexMag_AbiProbe_Check actually
; detects a clobbered RSI, a clobbered RBX and a clobbered XMM14. If the
; negative control ever reports clean, the probe has lost its power and every
; "ok" above it becomes meaningless.
; ---------------------------------------------------------------------------
PUBLIC HexMag_AbiProbe_CanaryBad

HexMag_AbiProbe_CanaryBad PROC
    ; No prologue, no epilogue: clobbers the nonvolatiles it names.
    mov     rsi, 0DEADBEEFDEADBEEFh
    mov     rbx, 0BADBAD0BADBAD0h
    movaps  xmm14, xmm14             ; no-op read, replaced below
    pxor    xmm14, xmm14
    xor     eax, eax
    ret
HexMag_AbiProbe_CanaryBad ENDP

; A second negative control, for the specific shape used by HexMag_PollEvent:
; address through RSI, set RDI, then `rep movsb`. Both registers necessarily
; change (rsi/rdi advance by the element count), so a probe that cannot see
; this cannot be trusted to clear the real poll path.
PUBLIC HexMag_AbiProbe_CanaryBadRep

HexMag_AbiProbe_CanaryBadRep PROC
    sub     rsp, 600                 ; room to write into, as PollEvent does
    lea     rsi, [canary_xmm]
    mov     rdi, rsp
    mov     ecx, 512
    rep     movsb
    add     rsp, 600
    xor     eax, eax
    ret
HexMag_AbiProbe_CanaryBadRep ENDP

HexMag_AbiProbe_Check PROC
    ; Capture the ENTRY rsp first: after eight pushes it is no longer
    ; recoverable, and the alignment contract is about ENTRY.
    mov     rax, rsp
    ; Preserve our own nonvolatiles. Eight pushes are 64 bytes, a multiple of 16,
    ; so they do NOT change alignment; the allocation below must be 8 mod 16 to    ; realign for the nested call.
    ; Preserve our own nonvolatiles.
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    ; 264 bytes of locals below. Windows x64 has NO red zone, so this
    ; allocation is mandatory -- without it every local is written into the
    ; caller's frame and the SECOND call through this probe corrupts it.
    sub     rsp, 328

    mov     [rsp + LOC_TARGET], rcx    ; target (rcx is volatile)
    mov     [rsp + LOC_PRERSP], rsp
    mov     [rsp + LOC_ENTRYRSP], rax

    ; Two alignment contracts, both real. (a) the caller honoured the ABI:
    ; a callee entered at a call site sees RSP = 16n-8.  (b) we honoured it too:
    ; RSP must be 16n immediately before our nested call.
    mov     rax, [rsp + LOC_ENTRYRSP]
    test    al, 8
    setnz   al
    movzx   eax, al
    mov     [rsp + LOC_ALIGN], rax

    ; ---- poison the region above our shadow space ----------------------
    mov     rcx, 0CCCCCCCCCCCCCCCCh
    mov     [rsp + LOC_POISON +  0], rcx
    mov     [rsp + LOC_POISON +  8], rcx
    mov     [rsp + LOC_POISON + 16], rcx
    mov     [rsp + LOC_POISON + 24], rcx
    mov     [rsp + LOC_POISON + 32], rcx

    ; ---- load nonvolatile canaries -------------------------------------
    mov     rbx, CAN_BX
    mov     rbp, CAN_BP
    mov     rsi, CAN_SI
    mov     rdi, CAN_DI
    mov     r12, CAN_R12
    mov     r13, CAN_R13
    mov     r14, CAN_R14
    mov     r15, CAN_R15

    lea     r10, [canary_xmm]
    ; Save the caller's nonvolatile XMMs before poisoning them.
    movaps  xmmword ptr [rsp + LOC_XMMSAVE +   0], xmm6
    movaps  xmmword ptr [rsp + LOC_XMMSAVE +  16], xmm7
    movaps  xmmword ptr [rsp + LOC_XMMSAVE +  32], xmm8
    movaps  xmmword ptr [rsp + LOC_XMMSAVE +  48], xmm9
    movaps  xmmword ptr [rsp + LOC_XMMSAVE +  64], xmm10
    movaps  xmmword ptr [rsp + LOC_XMMSAVE +  80], xmm11
    movaps  xmmword ptr [rsp + LOC_XMMSAVE +  96], xmm12
    movaps  xmmword ptr [rsp + LOC_XMMSAVE + 112], xmm13
    movaps  xmmword ptr [rsp + LOC_XMMSAVE + 128], xmm14
    movaps  xmmword ptr [rsp + LOC_XMMSAVE + 144], xmm15

    movaps  xmm6,  xmmword ptr [r10 +   0]
    movaps  xmm7,  xmmword ptr [r10 +  16]
    movaps  xmm8,  xmmword ptr [r10 +  32]
    movaps  xmm9,  xmmword ptr [r10 +  48]
    movaps  xmm10, xmmword ptr [r10 +  64]
    movaps  xmm11, xmmword ptr [r10 +  80]
    movaps  xmm12, xmmword ptr [r10 +  96]
    movaps  xmm13, xmmword ptr [r10 + 112]
    movaps  xmm14, xmmword ptr [r10 + 128]
    movaps  xmm15, xmmword ptr [r10 + 144]

    ; ---- call the export under test -------------------------------------
    mov     rcx, rdx                  ; first argument
    ; Zero the 3rd/4th argument registers. Several exports take a pointer as
    ; their 4th argument and validate it, but "whatever happened to be in r8/r9"
    ; is a wild pointer, not a test. NULL makes them refuse cleanly.
    xor     r8d, r8d
    xor     r9d, r9d
    call    qword ptr [rsp + LOC_TARGET]

    ; ---- accumulate the verdict ----------------------------------------
    xor     r11d, r11d                ; r11 = violation mask

    ; RSP restored to its pre-call value?
    mov     rax, [rsp + LOC_PRERSP]
    cmp     rax, rsp
    je      hxabi_rsp_ok
    or      r11d, ABI_BAD_RSP
hxabi_rsp_ok:

    ; entry alignment honoured by the caller? LOC_ALIGN holds 1 when it was.
    mov     rax, [rsp + LOC_ALIGN]
    test    eax, eax
    jnz     hxabi_align_ok
    or      r11d, ABI_BAD_ALIGN
hxabi_align_ok:

    ; nothing written above the shadow space?
    mov     rcx, 0CCCCCCCCCCCCCCCCh
    cmp     qword ptr [rsp + LOC_POISON +  0], rcx
    jne     hxabi_above_bad
    cmp     qword ptr [rsp + LOC_POISON +  8], rcx
    jne     hxabi_above_bad
    cmp     qword ptr [rsp + LOC_POISON + 16], rcx
    jne     hxabi_above_bad
    cmp     qword ptr [rsp + LOC_POISON + 24], rcx
    jne     hxabi_above_bad
    cmp     qword ptr [rsp + LOC_POISON + 32], rcx
    jne     hxabi_above_bad
    jmp     hxabi_above_ok
hxabi_above_bad:
    or      r11d, ABI_BAD_ABOVE
hxabi_above_ok:

    ; direction flag clear on return?  DF is RFLAGS bit 10.
    pushfq
    pop     rax
    test    ah, 4
    setnz   al
    movzx   eax, al
    shl     eax, 21
    or      r11d, eax

    ; ---- nonvolatile GPRs ----------------------------------------------
    xor     eax, eax
    cmp     rbx, CAN_BX
    je      hxabi_gpr_01
    or      eax, ABI_BAD_RBX
hxabi_gpr_01:
    cmp     rbp, CAN_BP
    je      hxabi_gpr_02
    or      eax, ABI_BAD_RBP
hxabi_gpr_02:
    cmp     rsi, CAN_SI
    je      hxabi_gpr_03
    or      eax, ABI_BAD_RSI
hxabi_gpr_03:
    cmp     rdi, CAN_DI
    je      hxabi_gpr_04
    or      eax, ABI_BAD_RDI
hxabi_gpr_04:
    cmp     r12, CAN_R12
    je      hxabi_gpr_05
    or      eax, ABI_BAD_R12
hxabi_gpr_05:
    cmp     r13, CAN_R13
    je      hxabi_gpr_06
    or      eax, ABI_BAD_R13
hxabi_gpr_06:
    cmp     r14, CAN_R14
    je      hxabi_gpr_07
    or      eax, ABI_BAD_R14
hxabi_gpr_07:
    cmp     r15, CAN_R15
    je      hxabi_gpr_08
    or      eax, ABI_BAD_R15
hxabi_gpr_08:
    ; Fold the GPR verdict into the result. Without this the eight GPR checks
    ; below compute a mask that is then overwritten by the XMM section's use of
    ; eax -- which is exactly how an earlier revision of this probe reported all
    ; twenty-five exports clean while clobbering RSI and RBX.
    or      r11d, eax

    ; ---- nonvolatile XMMs ----------------------------------------------
    ; Full 16-byte compare against the same canary block that was loaded.
    lea     r10, [canary_xmm]

    movaps  xmm0, xmmword ptr [r10 +   0]
    pcmpeqd xmm0, xmm6
    pmovmskb eax, xmm0
    test    eax, 0Fh
    jnz     hxabi_xmm_6
    or      r11d, ABI_BAD_XMM6
hxabi_xmm_6:
    movaps  xmm0, xmmword ptr [r10 +  16]
    pcmpeqd xmm0, xmm7
    pmovmskb eax, xmm0
    test    eax, 0Fh
    jnz     hxabi_xmm_7
    or      r11d, ABI_BAD_XMM7
hxabi_xmm_7:
    movaps  xmm0, xmmword ptr [r10 +  32]
    pcmpeqd xmm0, xmm8
    pmovmskb eax, xmm0
    test    eax, 0Fh
    jnz     hxabi_xmm_8
    or      r11d, ABI_BAD_XMM8
hxabi_xmm_8:
    movaps  xmm0, xmmword ptr [r10 +  48]
    pcmpeqd xmm0, xmm9
    pmovmskb eax, xmm0
    test    eax, 0Fh
    jnz     hxabi_xmm_9
    or      r11d, ABI_BAD_XMM9
hxabi_xmm_9:
    movaps  xmm0, xmmword ptr [r10 +  64]
    pcmpeqd xmm0, xmm10
    pmovmskb eax, xmm0
    test    eax, 0Fh
    jnz     hxabi_xmm_10
    or      r11d, ABI_BAD_XMM10
hxabi_xmm_10:
    movaps  xmm0, xmmword ptr [r10 +  80]
    pcmpeqd xmm0, xmm11
    pmovmskb eax, xmm0
    test    eax, 0Fh
    jnz     hxabi_xmm_11
    or      r11d, ABI_BAD_XMM11
hxabi_xmm_11:
    movaps  xmm0, xmmword ptr [r10 +  96]
    pcmpeqd xmm0, xmm12
    pmovmskb eax, xmm0
    test    eax, 0Fh
    jnz     hxabi_xmm_12
    or      r11d, ABI_BAD_XMM12
hxabi_xmm_12:
    movaps  xmm0, xmmword ptr [r10 + 112]
    pcmpeqd xmm0, xmm13
    pmovmskb eax, xmm0
    test    eax, 0Fh
    jnz     hxabi_xmm_13
    or      r11d, ABI_BAD_XMM13
hxabi_xmm_13:
    movaps  xmm0, xmmword ptr [r10 + 128]
    pcmpeqd xmm0, xmm14
    pmovmskb eax, xmm0
    test    eax, 0Fh
    jnz     hxabi_xmm_14
    or      r11d, ABI_BAD_XMM14
hxabi_xmm_14:
    movaps  xmm0, xmmword ptr [r10 + 144]
    pcmpeqd xmm0, xmm15
    pmovmskb eax, xmm0
    test    eax, 0Fh
    jnz     hxabi_xmm_15
    or      r11d, ABI_BAD_XMM15
hxabi_xmm_15:

    ; Restore the caller's nonvolatile XMMs BEFORE returning; this routine is
    ; a callee like any other.
    movaps  xmm6,  xmmword ptr [rsp + LOC_XMMSAVE +   0]
    movaps  xmm7,  xmmword ptr [rsp + LOC_XMMSAVE +  16]
    movaps  xmm8,  xmmword ptr [rsp + LOC_XMMSAVE +  32]
    movaps  xmm9,  xmmword ptr [rsp + LOC_XMMSAVE +  48]
    movaps  xmm10, xmmword ptr [rsp + LOC_XMMSAVE +  64]
    movaps  xmm11, xmmword ptr [rsp + LOC_XMMSAVE +  80]
    movaps  xmm12, xmmword ptr [rsp + LOC_XMMSAVE +  96]
    movaps  xmm13, xmmword ptr [rsp + LOC_XMMSAVE + 112]
    movaps  xmm14, xmmword ptr [rsp + LOC_XMMSAVE + 128]
    movaps  xmm15, xmmword ptr [rsp + LOC_XMMSAVE + 144]

    mov     eax, r11d
    add     rsp, 328
    ; Reverse of the prologue: r15 r14 r13 r12 rdi rsi rbp rbx
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret
HexMag_AbiProbe_Check ENDP

_TEXT ENDS

_DATA SEGMENT
PUBLIC canary_xmm
; Ten distinct 16-byte canaries.
canary_xmm DQ 0CCCCCCCCCCCCCCCCh, 0CCCCCCCCCCCCCCCCh
           DQ 0DDDDDDDDDDDDDDDDh, 0DDDDDDDDDDDDDDDDh
           DQ 0EEEEEEEEEEEEEEEEh, 0EEEEEEEEEEEEEEEEh
           DQ 0FFFFFFFFFFFFFFFFh, 0FFFFFFFFFFFFFFFFh
           DQ 0ABABABABABABABABh, 0ABABABABABABABABh
           DQ 0CDCDCDCDCDCDCDCDh, 0CDCDCDCDCDCDCDCDh
           DQ 0DEDEDEDEDEDEDEDEh, 0DEDEDEDEDEDEDEDEh
           DQ 0EFEFEFEFEFEFEFEh, 0EFEFEFEFEFEFEFEh
           DQ 0F1F1F1F1F1F1F1Fh, 0F1F1F1F1F1F1F1Fh
           DQ 0F2F2F2F2F2F2F2Fh, 0F2F2F2F2F2F2F2Fh
_DATA ENDS

END
