; ============================================================================
; SwarmV29_Process_ZeroG_Packet.asm
; Kyber-1024 Twiddle and Permutation Schedule Layout
; ============================================================================
;
; This module provides read-only constants used by the 0G packet transform
; pipeline in SwarmV29_Stub_Process_ZeroG_Packet.asm.
;
; NOTE: Labels are module-local unless explicitly exported.
; ============================================================================

.CONST
ALIGN 16

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

END
