;==============================================================================
; quantization.inc - Quantization Include File
; ==============================================================================
; Provides declarations for quantization functions.
;==============================================================================

; Quantization formats
RAWRQ_FORMAT_INT4     EQU 1
RAWRQ_FORMAT_INT8     EQU 2
RAWRQ_FORMAT_FP16     EQU 3
RAWRQ_FORMAT_BF16     EQU 4
RAWRQ_FORMAT_RAW      EQU 5
RAWRZ_FORMAT_INT2     EQU 6
RAWRZ_FORMAT_INT4     EQU 7
RAWRZ_FORMAT_MIXED    EQU 8
RAWRX_FORMAT_DYNAMIC  EQU 9
RAWRX_FORMAT_ADAPTIVE EQU 10

; External function declarations
EXTERN QuantizeModel:PROC
EXTERN RawrZ_AVX512_Quantize:PROC
EXTERN RawrX_AVX512_Quantize:PROC

