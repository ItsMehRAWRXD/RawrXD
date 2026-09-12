; Deep2 per-token dual-GPU finish-time balancer
; Pure x64 MASM include. No CRT, heap, OS, Vulkan, or external dependencies.

D2DB_Q16_ONE                 EQU 65536
D2DB_DEFAULT_GPU1_SHARE_Q16  EQU 21234       ; ~32.4%
D2DB_MIN_GPU1_SHARE_Q16      EQU 6554        ; 10%
D2DB_MAX_GPU1_SHARE_Q16      EQU 29491       ; 45%
D2DB_EWMA_SHIFT              EQU 3           ; alpha = 1/8
D2DB_DEADBAND_NS             EQU 50000       ; 50 us
D2DB_REGRESS_PM              EQU 1050        ; rollback if > 5% worse
D2DB_VALID_MAGIC             EQU 32424444h    ; 'DDB2'

; D2DB_STATE offsets (caller-owned, zero allocation)
D2S_MAGIC                    EQU 0            ; dq
D2S_COST0_Q16                EQU 8            ; dq ns/effective-row Q16
D2S_COST1_Q16                EQU 16           ; dq
D2S_START_SKEW_EWMA_NS       EQU 24           ; dq signed: GPU1_START-GPU0_START
D2S_FINISH_SKEW_EWMA_NS      EQU 32           ; dq signed: GPU1_END-GPU0_END
D2S_BEST_CRITICAL_NS         EQU 40           ; dq
D2S_BEST_SHARE1_Q16          EQU 48           ; dd
D2S_SHARE1_Q16               EQU 52           ; dd
D2S_VALID_SAMPLES            EQU 56           ; dd
D2S_BAD_SAMPLES              EQU 60           ; dd
D2S_TOKEN_INDEX              EQU 64           ; dq
D2S_LAST_CRITICAL_NS         EQU 72           ; dq
D2S_LAST_FINISH_SKEW_NS      EQU 80           ; dq signed
D2S_LAST_START_SKEW_NS       EQU 88           ; dq signed
D2S_FLAGS                    EQU 96           ; dq
D2S_SIZE                     EQU 104

; D2DB_PLAN offsets
D2P_ROWS0                    EQU 0            ; dd
D2P_ROWS1                    EQU 4            ; dd
D2P_SHARE1_Q16               EQU 8            ; dd
D2P_MODE                     EQU 12           ; dd 0=seed,1=model,2=rollback
D2P_PRED_END0_NS             EQU 16           ; dq relative predicted end
D2P_PRED_END1_NS             EQU 24           ; dq relative predicted end
D2P_SIZE                     EQU 32

; D2DB_SAMPLE offsets
D2M_ROWS0                    EQU 0            ; dd
D2M_ROWS1                    EQU 4            ; dd
D2M_START0_NS                EQU 8            ; dq
D2M_END0_NS                  EQU 16           ; dq
D2M_START1_NS                EQU 24           ; dq
D2M_END1_NS                  EQU 32           ; dq
D2M_CRITICAL_NS              EQU 40           ; dq
D2M_OVERLAP_NS               EQU 48           ; dq
D2M_OUTPUT_PARITY            EQU 56           ; dd
D2M_DEVICE_OK                EQU 60           ; dd
D2M_SAME_TOKEN               EQU 64           ; dd
D2M_PRODUCT_LINKED           EQU 68           ; dd
D2M_PACKED_LIVE              EQU 72           ; dd
D2M_SERIAL_CHAIN             EQU 76           ; dd
D2M_WEIGHT_MIGRATION         EQU 80           ; dd
D2M_RESERVED                 EQU 84           ; dd
D2M_SIZE                     EQU 88

; state flags
D2DB_F_MODEL_READY           EQU 1
D2DB_F_ROLLBACK_LAST         EQU 2
D2DB_F_AUTH_VALID            EQU 4
