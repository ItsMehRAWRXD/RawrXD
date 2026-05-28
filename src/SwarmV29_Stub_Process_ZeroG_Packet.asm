; ============================================================================
; SwarmV29_Process_ZeroG_Packet — Full Cryptographic Transform Implementation
; AVX-512 Vectorized Pipeline for Kyber/Dilithium PQC Operations
; ============================================================================

.CODE

INCLUDE SwarmV29_Macros.inc

EXTERN HijackFlag : QWORD

.CONST
ALIGN 16

KYBER_Q_CONST WORD 3329
KYBER_QINV_CONST WORD 62209

; Kyber-1024 twiddle factors pre-multiplied by 2^16 mod 3329
KYBER_TWIDDLE_FACTORS WORD   1419,  1712,  1152,  1768,  1448,  2001,  2353,  2889
                      WORD   1266,  2425,  2786,  1619,  2228,  2023,   984,  1101
                      WORD   2199,  1408,   265,  2323,  2525,  1369,   895,  2059
                      WORD   1870,  2281,  1599,   603,   848,   345,   170,  2738
                      WORD   1421,  2717,  2490,  1377,  1900,  1881,  2955,  3069
                      WORD   2765,  3038,  2903,   725,   157,  1151,   237,  2017
                      WORD   2222,  1030,  1874,  2867,  2799,   653,  2841,  1917
                      WORD    912,  2384,  1708,  1028,  1590,  1144,   683,  2158
                      WORD   1629,  2608,   131,   662,  1533,  2624,  2372,   470
                      WORD     67,  1134,  1469,  1839,  2118,  2219,   704,  1214
                      WORD   1921,  1940,  1615,  1445,  1455,  2149,   763,  2575
                      WORD   1575,   145,  1688,   734,  2443,  1119,  2657,   873
                      WORD   2238,   405,  1197,  1036,   341,  1978,  2262,  1191
                      WORD   1428,  1436,  2180,  2288,   904,   412,   310,  1638
                      WORD   2615,   919,  1090,  1427,  1801,   154,  2355,  2510
                      WORD   1996,  2427,  1687,   415,  1049,   342,  1384,  2093

; Layer 5 index: groups elements by chunks of 4 (32-bit dword pairings)
PERM_MASK_LAYER5 DWORD  0,  1,  8,  9,  2,  3, 10, 11
                 DWORD  4,  5, 12, 13,  6,  7, 14, 15

; Layer 6 index: groups elements by chunks of 2 (16-bit word pairings)
PERM_MASK_LAYER6 WORD   0,  1,  4,  5,  2,  3,  6,  7
                 WORD   8,  9, 12, 13, 10, 11, 14, 15
                 WORD  16, 17, 20, 21, 18, 19, 22, 23
                 WORD  24, 25, 28, 29, 26, 27, 30, 31

; =============================================================================
; Process_ZeroG_Packet
; Full transform implementation for 0G hijack packet processing
; RCX = Source packet buffer (64-byte aligned)
; RDX = Destination state space (64-byte aligned)
; =============================================================================
ALIGN 16
PUBLIC Process_ZeroG_Packet
Process_ZeroG_Packet PROC
    ; ABI Prologue
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    
    ; Validate input pointers
    test rcx, rcx
    jz packet_null_error
    test rdx, rdx
    jz packet_null_error
    
    ; Setup source/destination registers
    mov rsi, rcx
    mov rdi, rdx
    
    ; Phase 1: Data ingestion (8 x 64-byte aligned vectors)
    vmovdqa64 zmm0, zmmword ptr [rsi + 0]
    vmovdqa64 zmm1, zmmword ptr [rsi + 64]
    vmovdqa64 zmm2, zmmword ptr [rsi + 128]
    vmovdqa64 zmm3, zmmword ptr [rsi + 192]
    vmovdqa64 zmm4, zmmword ptr [rsi + 256]
    vmovdqa64 zmm5, zmmword ptr [rsi + 320]
    vmovdqa64 zmm6, zmmword ptr [rsi + 384]
    vmovdqa64 zmm7, zmmword ptr [rsi + 448]

    ; Phase 2: Pre-load invariant modulus vectors and twiddle base
    vpbroadcastw zmm8,  word ptr [KYBER_Q_CONST]
    vpbroadcastw zmm9,  word ptr [KYBER_QINV_CONST]
    lea r10, KYBER_TWIDDLE_FACTORS

    ; Phase 3: Layer 1 cross-register butterflies (stride 128, distance 512 bytes)
    ; Twiddle indices: 0, 0, 0, 0 (single twiddle broadcast to all pairs)
    vpbroadcastw zmm10, word ptr [r10 + 0]
    KYBER_BUTTERFLY_32L zmm0, zmm4, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm1, zmm5, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm2, zmm6, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm3, zmm7, zmm10, zmm11, zmm12, zmm8, zmm9

    ; Phase 4: Layer 2 cross-register butterflies (stride 64, distance 256 bytes)
    ; Twiddle indices: 0, 2, 4, 6 (four distinct twiddles)
    vpbroadcastw zmm10, word ptr [r10 + 0]
    KYBER_BUTTERFLY_32L zmm0, zmm2, zmm10, zmm11, zmm12, zmm8, zmm9
    vpbroadcastw zmm10, word ptr [r10 + 2]
    KYBER_BUTTERFLY_32L zmm1, zmm3, zmm10, zmm11, zmm12, zmm8, zmm9
    vpbroadcastw zmm10, word ptr [r10 + 4]
    KYBER_BUTTERFLY_32L zmm4, zmm6, zmm10, zmm11, zmm12, zmm8, zmm9
    vpbroadcastw zmm10, word ptr [r10 + 6]
    KYBER_BUTTERFLY_32L zmm5, zmm7, zmm10, zmm11, zmm12, zmm8, zmm9

    ; Phase 5: Layer 3 cross-register butterflies (stride 32, distance 128 bytes)
    ; Twiddle indices: 0, 2, 4, 6, 8, 10, 12, 14 (eight distinct twiddles)
    vpbroadcastw zmm10, word ptr [r10 + 0]
    KYBER_BUTTERFLY_32L zmm0, zmm1, zmm10, zmm11, zmm12, zmm8, zmm9
    vpbroadcastw zmm10, word ptr [r10 + 2]
    KYBER_BUTTERFLY_32L zmm2, zmm3, zmm10, zmm11, zmm12, zmm8, zmm9
    vpbroadcastw zmm10, word ptr [r10 + 4]
    KYBER_BUTTERFLY_32L zmm4, zmm5, zmm10, zmm11, zmm12, zmm8, zmm9
    vpbroadcastw zmm10, word ptr [r10 + 6]
    KYBER_BUTTERFLY_32L zmm6, zmm7, zmm10, zmm11, zmm12, zmm8, zmm9

    ; Phase 6: Layer 4-7 in-register permutation pipeline controls
    vmovdqu64 zmm14, zmmword ptr [PERM_MASK_LAYER5]
    vmovdqu64 zmm15, zmmword ptr [PERM_MASK_LAYER6]

    ; Phase 7: Layer 4 intra-register butterflies (stride 16, vshufi64x2 shuffle)
    ; Operate on adjacent 128-bit lanes within each 512-bit register
    ; Twiddle indices: 16, 18, 20, 22 (broadcast within lane pairs)
    vpbroadcastw zmm10, word ptr [r10 + 16]
    vshufi64x2 zmm16, zmm0, zmm0, 0B1h  ; Swap adjacent 128-bit lanes
    vshufi64x2 zmm17, zmm1, zmm1, 0B1h
    KYBER_BUTTERFLY_32L zmm0, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm1, zmm17, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 18]
    vshufi64x2 zmm16, zmm2, zmm2, 0B1h
    vshufi64x2 zmm17, zmm3, zmm3, 0B1h
    KYBER_BUTTERFLY_32L zmm2, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm3, zmm17, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 20]
    vshufi64x2 zmm16, zmm4, zmm4, 0B1h
    vshufi64x2 zmm17, zmm5, zmm5, 0B1h
    KYBER_BUTTERFLY_32L zmm4, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm5, zmm17, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 22]
    vshufi64x2 zmm16, zmm6, zmm6, 0B1h
    vshufi64x2 zmm17, zmm7, zmm7, 0B1h
    KYBER_BUTTERFLY_32L zmm6, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm7, zmm17, zmm10, zmm11, zmm12, zmm8, zmm9

    ; Phase 8: Layer 5 intra-register butterflies (stride 8, vpermd shuffle)
    ; Operate on adjacent 64-bit qword pairs using PERM_MASK_LAYER5
    ; Twiddle indices: 24, 26, 28, 30, 32, 34, 36, 38
    vpbroadcastw zmm10, word ptr [r10 + 24]
    vpermd zmm16, zmm14, zmm0
    vpermd zmm17, zmm14, zmm1
    KYBER_BUTTERFLY_32L zmm0, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm1, zmm17, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 26]
    vpermd zmm16, zmm14, zmm2
    vpermd zmm17, zmm14, zmm3
    KYBER_BUTTERFLY_32L zmm2, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm3, zmm17, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 28]
    vpermd zmm16, zmm14, zmm4
    vpermd zmm17, zmm14, zmm5
    KYBER_BUTTERFLY_32L zmm4, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm5, zmm17, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 30]
    vpermd zmm16, zmm14, zmm6
    vpermd zmm17, zmm14, zmm7
    KYBER_BUTTERFLY_32L zmm6, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm7, zmm17, zmm10, zmm11, zmm12, zmm8, zmm9

    ; Phase 9: Layer 6 intra-register butterflies (stride 4, vpermw shuffle)
    ; Operate on adjacent 32-bit dword pairs using PERM_MASK_LAYER6
    ; Twiddle indices: 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70
    vpbroadcastw zmm10, word ptr [r10 + 40]
    vpermw zmm16, zmm15, zmm0
    vpermw zmm17, zmm15, zmm1
    KYBER_BUTTERFLY_32L zmm0, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm1, zmm17, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 42]
    vpermw zmm16, zmm15, zmm2
    vpermw zmm17, zmm15, zmm3
    KYBER_BUTTERFLY_32L zmm2, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm3, zmm17, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 44]
    vpermw zmm16, zmm15, zmm4
    vpermw zmm17, zmm15, zmm5
    KYBER_BUTTERFLY_32L zmm4, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm5, zmm17, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 46]
    vpermw zmm16, zmm15, zmm6
    vpermw zmm17, zmm15, zmm7
    KYBER_BUTTERFLY_32L zmm6, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    KYBER_BUTTERFLY_32L zmm7, zmm17, zmm10, zmm11, zmm12, zmm8, zmm9

    ; Phase 10: Layer 7 intra-register butterflies (stride 2, adjacent word pairs)
    ; Final layer operates on adjacent 16-bit word pairs within each lane
    ; Twiddle indices: 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102
    ; Uses vpsrlq/vpsllq for in-register pair extraction
    vpbroadcastw zmm10, word ptr [r10 + 72]
    vpsrlq zmm16, zmm0, 16
    vpsllq zmm17, zmm0, 48
    vpsrlq zmm17, zmm17, 48
    KYBER_BUTTERFLY_32L zmm0, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 74]
    vpsrlq zmm16, zmm1, 16
    vpsllq zmm17, zmm1, 48
    vpsrlq zmm17, zmm17, 48
    KYBER_BUTTERFLY_32L zmm1, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 76]
    vpsrlq zmm16, zmm2, 16
    vpsllq zmm17, zmm2, 48
    vpsrlq zmm17, zmm17, 48
    KYBER_BUTTERFLY_32L zmm2, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 78]
    vpsrlq zmm16, zmm3, 16
    vpsllq zmm17, zmm3, 48
    vpsrlq zmm17, zmm17, 48
    KYBER_BUTTERFLY_32L zmm3, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 80]
    vpsrlq zmm16, zmm4, 16
    vpsllq zmm17, zmm4, 48
    vpsrlq zmm17, zmm17, 48
    KYBER_BUTTERFLY_32L zmm4, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 82]
    vpsrlq zmm16, zmm5, 16
    vpsllq zmm17, zmm5, 48
    vpsrlq zmm17, zmm17, 48
    KYBER_BUTTERFLY_32L zmm5, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 84]
    vpsrlq zmm16, zmm6, 16
    vpsllq zmm17, zmm6, 48
    vpsrlq zmm17, zmm17, 48
    KYBER_BUTTERFLY_32L zmm6, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9
    
    vpbroadcastw zmm10, word ptr [r10 + 86]
    vpsrlq zmm16, zmm7, 16
    vpsllq zmm17, zmm7, 48
    vpsrlq zmm17, zmm17, 48
    KYBER_BUTTERFLY_32L zmm7, zmm16, zmm10, zmm11, zmm12, zmm8, zmm9

    ; Phase 11: Strict normalization pass to canonical ring representation [0, q-1]
    KYBER_STRICT_NORMALIZE_32L zmm0, zmm11, zmm12, zmm8
    KYBER_STRICT_NORMALIZE_32L zmm1, zmm11, zmm12, zmm8
    KYBER_STRICT_NORMALIZE_32L zmm2, zmm11, zmm12, zmm8
    KYBER_STRICT_NORMALIZE_32L zmm3, zmm11, zmm12, zmm8
    KYBER_STRICT_NORMALIZE_32L zmm4, zmm11, zmm12, zmm8
    KYBER_STRICT_NORMALIZE_32L zmm5, zmm11, zmm12, zmm8
    KYBER_STRICT_NORMALIZE_32L zmm6, zmm11, zmm12, zmm8
    KYBER_STRICT_NORMALIZE_32L zmm7, zmm11, zmm12, zmm8

    ; Phase 12: Non-temporal eviction (full 512-byte state)
    vmovntdq zmmword ptr [rdi +   0], zmm0
    vmovntdq zmmword ptr [rdi +  64], zmm1
    vmovntdq zmmword ptr [rdi + 128], zmm2
    vmovntdq zmmword ptr [rdi + 192], zmm3
    vmovntdq zmmword ptr [rdi + 256], zmm4
    vmovntdq zmmword ptr [rdi + 320], zmm5
    vmovntdq zmmword ptr [rdi + 384], zmm6
    vmovntdq zmmword ptr [rdi + 448], zmm7

    ; Phase 7: Memory barrier
    sfence
    
    ; Clear HijackFlag
    mov qword ptr [HijackFlag], 0
    
    ; Return success
    xor rax, rax
    jmp packet_done
    
packet_null_error:
    mov rax, 0C0000005h
    
packet_done:
    ; ABI Epilogue
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Process_ZeroG_Packet ENDP

; =============================================================================
; End of module
; =============================================================================
END
