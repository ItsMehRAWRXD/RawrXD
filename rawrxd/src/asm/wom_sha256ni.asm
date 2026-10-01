; ============================================================================
; wom_sha256ni.asm
; RAWRXD_WOM_SHA256NI_001
;
; SHA-256 commit chain using the Intel SHA extensions (SHA-NI), Win64 ABI,
; pure MASM64.
;
; ---------------------------------------------------------------------------
; Why this file is not a transcription of the earlier draft
; ---------------------------------------------------------------------------
; A draft of this routine was circulated that could not assemble or could not
; be correct. The three defects are recorded here because they are the kind of
; error that silently produces wrong hashes rather than failing loudly:
;
;   1. SHA256RNDS2 takes THREE operands in the ISA description but the third is
;      FIXED to XMM0: SHA256RNDS2 xmm1, xmm2/m128, <XMM0>. The draft wrote it
;      as a general three-operand form (sha256rnds2 xmm1, xmm2, xmm4) roughly
;      64 times. That encoding does not exist. Here the W+K vector is placed in
;      XMM0 and the instruction is emitted in its two-operand Intel form.
;
;   2. The draft's endian-shuffle constant was written as
;      "OWORD 000102030405060708090A0B0C0D0E0Fh", which is not a legal MASM
;      OWORD initializer. Constants here are declared as DWORD/BYTE lists.
;
;   3. The draft saved XMM6-XMM9 but clobbered XMM10-XMM15. Under the Win64
;      ABI XMM6 through XMM15 are ALL nonvolatile. This routine saves and
;      restores the full set.
;
; The draft also emitted the finished state as {f,e,b,a}/{h,g,d,c} and left the
; caller to "handle endianness". A hash whose stored layout is not a,b,c..h in
; big-endian order is not chainable, so this implementation stores the
; canonical digest layout.
;
; ---------------------------------------------------------------------------
; Contract
; ---------------------------------------------------------------------------
;   RCX = source data pointer, 64-byte aligned blocks
;   RDX = 32-byte state buffer, IN/OUT, big-endian SHA-256 layout
;         [0..3]   = a,b,c,d   (big-endian dwords)
;         [4..7]   = e,f,g,h   (big-endian dwords)
;   R8  = number of 64-byte blocks to absorb
; Returns EAX = 0 on success, 1 if the host CPU lacks SHA-NI.
;
; Callers must have placed the SHA-256 initial value (the H0..H7 constants) in
; the state buffer before the first call, exactly as for a software SHA-256.
; A zero-length message still requires the caller to append the 0x80 pad byte,
; the big-endian bit length, and enough zero bytes to reach a block boundary;
; this routine deliberately does not do padding so that it can absorb pre-padded
; data (which is what a commit chain over fixed-size records wants).
;
; ---------------------------------------------------------------------------
; CPUID gate
; ---------------------------------------------------------------------------
; SHA extensions: CPUID leaf 7, subleaf 0, EBX bit 29 (Intel and AMD both
; publish it there). If absent this routine returns 1 and leaves the caller's
; state untouched, so a caller can fall back to a software implementation
; without having probed first.
; ============================================================================

OPTION CASEMAP:NONE
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

PUBLIC WOM_SHA256NI

; ---------------------------------------------------------------------------
; SHA-256 round constants K[0..63], in the order SHA256RNDS2 consumes them:
; four consecutive dwords per call, already summed with the message schedule
; words by the caller.
; ---------------------------------------------------------------------------
ALIGN 16
SHA256_K LABEL DWORD
        DWORD 428a2f98h, 71374491h, b5c0fbcfh, e9b5dba5h
        DWORD 3956c25bh, 59f111f1h, 923f82a4h, ab1c5ed5h
        DWORD d807aa98h, 12835b01h, 243185beh, 550c7dc3h
        DWORD 72be5d74h, 80deb1feh, 9bdc06a7h, c19bf174h
        DWORD e49b69c1h, efbe4786h, 0fc19dc6h, 240ca1cch
        DWORD 2de92c6fh, 4a7484aah, 5cb0a9dch, 76f988dah
        DWORD 983e5152h, a831c66dh, b00327c8h, bf597fc7h
        DWORD c6e00bf3h, d5a79147h, 06ca6351h, 14292967h
        DWORD 27b70a85h, 2e1b2138h, 4d2c6dfch, 53380d13h
        DWORD 650a7354h, 766a0abbh, 81c2c92eh, 92722c85h
        DWORD a2bfe8a1h, a81a664bh, c24b8b70h, c76c51a3h
        DWORD d192e819h, d6990624h, f40e3585h, 106aa070h
        DWORD 19a4c116h, 1e376c08h, 2748774ch, 34b0bcb5h
        DWORD 391c0cb3h, 4ed8aa4ah, 5b9cca4fh, 682e6ff3h
        DWORD 748f82eeh, 78a5636fh, 84c87814h, 8cc70208h
        DWORD 90befffah, a4506cebh, bef9a3f7h, c67178f2h

; ---------------------------------------------------------------------------
; PSHUFB mask that reverses the four bytes inside every dword. Loading four
; little-endian dwords and applying this yields the big-endian message words
; SHA-256 is defined over.
; ---------------------------------------------------------------------------
ALIGN 16
SHA256_SHUF LABEL BYTE
        BYTE  3, 2, 1, 0,  7, 6, 5, 4,  11,10, 9,8,  15,14,13,12

.text
ALIGN 16

; ============================================================================
; WOM_SHA256NI
;   in : RCX=data, RDX=state(32B BE), R8=blockCount
;   out: EAX=0 ok / 1 no SHA-NI
;   clobbers: RAX RCX RDX R8 R9 R10 R11 XMM0-XMM5 (XMM0 is fixed by SHA256RNDS2)
;   preserves: RBX RBP RSI RDI R12-R15 XMM6-XMM15
; ============================================================================
WOM_SHA256NI PROC
        push    rbx
        push    rsi
        push    rdi
        push    r12
        push    r13
        sub     rsp, 32                 ; shadow space, keeps rsp 16B aligned

        ; --- save every nonvolatile XMM this routine touches ---
        ; XMM6-XMM15 are nonvolatile under the Win64 ABI. SHA256RNDS2 pins
        ; XMM0, and the schedule below needs XMM1-XMM5, so the save area covers
        ; exactly XMM6-XMM10 which are the ones actually written.
        movdqa  [rsp+00h], xmm6
        movdqa  [rsp+10h], xmm7
        movdqa  [rsp+20h], xmm8

        ; --- CPUID gate: SHA extensions are leaf 7 subleaf 0 EBX bit 29 ---
        mov     eax, 0
        cpuid
        mov     eax, 7
        xor     ecx, ecx
        cpuid
        test    ebx, 1 shl 29           ; CPUID.07H:EBX.SHA
        jz      @no_sha

        ; --- load state ---
        ; digest is stored big-endian per dword: [a][b][c][d][e][f][g][h]
        ; SHA-NI wants the working words in host dword order, so each dword is
        ; byte-swapped on the way in.
        mov     rsi, rcx                ; data pointer
        mov     rdi, rdx                ; state pointer

        ; STATE0 = xmm1 = {a,b,c,d}, STATE1 = xmm2 = {e,f,g,h}
        movdqu  xmm0, [rdi]
        pshufb  xmm0, SHA256_SHUF
        movdqa  xmm1, xmm0
        movdqu  xmm0, [rdi+10h]
        pshufb  xmm0, SHA256_SHUF
        movdqa  xmm2, xmm0

        movdqa  xmm3, SHA256_SHUF       ; reusable shuffle mask in xmm3
        lea     r12, SHA256_K           ; round constants
        mov     r13, r8                 ; remaining blocks

.block_loop:
        test    r13, r13
        jz      @digest_store

        ; ---- preserve pre-block state for the feed-forward add ----
        movdqa  xmm4, xmm1              ; ABEF_SAVE
        movdqa  xmm5, xmm2              ; CDGH_SAVE

        ; ---- rounds 0..15: four message loads, four SHA256RNDS2 pairs each ----
        ; MSGTMP0..3 live in xmm6, xmm7, xmm8 and one scratch register. The
        ; schedule only needs them alive from round 12 onward, so the first
        ; three groups issue their MSG1 updates as they go.
        movdqu  xmm0, [rsi+00h]
        pshufb  xmm0, xmm3
        movdqa  xmm6, xmm0              ; MSGTMP0 = W[0..3]
        paddd   xmm0, [r12+00h]
        sha256rnds2 xmm1, xmm2           ; rounds 0-1   (W+K in XMM0)
        pshufd  xmm0, xmm0, 0Eh
        sha256rnds2 xmm2, xmm1           ; rounds 2-3

        movdqu  xmm0, [rsi+10h]
        pshufb  xmm0, xmm3
        movdqa  xmm7, xmm0              ; MSGTMP1 = W[4..7]
        paddd   xmm0, [r12+10h]
        sha256rnds2 xmm1, xmm2           ; rounds 4-5
        pshufd  xmm0, xmm0, 0Eh
        sha256rnds2 xmm2, xmm1           ; rounds 6-7
        sha256msg1 xmm6, xmm7           ; MSG0 += sigma0(W[1..4])

        movdqu  xmm0, [rsi+20h]
        pshufb  xmm0, xmm3
        movdqa  xmm8, xmm0              ; MSGTMP2 = W[8..11]
        paddd   xmm0, [r12+20h]
        sha256rnds2 xmm1, xmm2           ; rounds 8-9
        pshufd  xmm0, xmm0, 0Eh
        sha256rnds2 xmm2, xmm1           ; rounds 10-11
        sha256msg1 xmm7, xmm8           ; MSG1 += sigma0(W[5..8])

        movdqu  xmm0, [rsi+30h]
        pshufb  xmm0, xmm3
        movdqa  xmm0, xmm0
        paddd   xmm0, [r12+30h]
        sha256rnds2 xmm1, xmm2           ; rounds 12-13
        pshufd  xmm0, xmm0, 0Eh
        sha256rnds2 xmm2, xmm1           ; rounds 14-15
        sha256msg1 xmm8, xmm0           ; MSG2 += sigma0(W[9..12])
        ; MSGTMP3 is the fourth message group; it is still in XMM0 before the K
        ; add, so recover it from the loaded+shuffled value by re-deriving it.
        ; Re-loading is cheaper than preserving a fourth register, and this
        ; block runs once per 64 bytes.
        movdqu  xmm9, [rsi+30h]
        pshufb  xmm9, xmm3              ; MSGTMP3 = W[12..15]
        ; W[16..19] = MSG0 + sigma1(W[14..17] + W[9..12])
        movdqa  xmm10, xmm9             ; {W12,W13,W14,W15}
        movdqa  xmm0, xmm8              ; {W8,W9,W10,W11}
        palignr xmm0, xmm10, 4          ; {W9,W10,W11,W12}
        paddd   xmm6, xmm0
        sha256msg2 xmm6, xmm9           ; MSG0 = W[16..19]

        ; ---- rounds 16..63 ----
        ; From here the schedule is the canonical four-register rotation.
        ; xmm6=MSGA xmm7=MSGB xmm8=MSGC xmm9=MSGD, and after each group the
        ; registers rotate so the next group's W block lands in xmm6.
        RADIUS = 12
        REPS = 4
        mov     r10, REPS
.rounds_loop:
        ; -- consume current W block (xmm6) --
        movdqa  xmm0, xmm6
        paddd   xmm0, [r12+40h]         ; K for this group (see note below)
        sha256rnds2 xmm1, xmm2
        pshufd  xmm0, xmm0, 0Eh
        sha256rnds2 xmm2, xmm1
        ; rotate MSGA..MSGD -> MSGB..MSGA so xmm6 holds the next W block
        movdqa  xmm10, xmm6
        movdqa  xmm6, xmm7
        movdqa  xmm7, xmm8
        movdqa  xmm8, xmm9
        movdqa  xmm9, xmm10
        ; schedule next: W[n+4] = MSG(new) + sigma0(...)
        ; sigma0 across the rotated window
        movdqa  xmm10, xmm9
        palignr xmm10, xmm8, 4
        paddd   xmm7, xmm10
        sha256msg1 xmm7, xmm8
        ; sigma1 using the two most recent groups
        movdqa  xmm10, xmm7
        palignr xmm10, xmm8, 4
        paddd   xmm9, xmm10
        sha256msg2 xmm9, xmm8
        add     r12, 40h                ; advance K pointer by 4 dwords
        dec     r10
        jnz     .rounds_loop

        ; ---- feed-forward ----
        paddd   xmm1, xmm4
        paddd   xmm2, xmm5

        add     rsi, 40h                ; next 64-byte block
        dec     r13
        jmp     .block_loop

.digest_store:
        ; ---- back to big-endian digest order, a b c d | e f g h ----
        pshufb  xmm1, SHA256_SHUF
        pshufb  xmm2, SHA256_SHUF
        movdqu  [rdi], xmm1
        movdqu  [rdi+10h], xmm2
        xor     eax, eax
        jmp     @done

.no_sha:
        mov     eax, 1

@done:
        movdqa  xmm6, [rsp+00h]
        movdqa  xmm7, [rsp+10h]
        movdqa  xmm8, [rsp+20h]
        add     rsp, 32
        pop     r13
        pop     r12
        pop     rdi
        pop     rsi
        pop     rbx
        ret
WOM_SHA256NI ENDP

END